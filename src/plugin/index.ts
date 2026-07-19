// Plugin entry: wires the API surface, loads rules, registers the
// before_tool_call hook. The hook fires for every tool call across the
// gateway (built-in tools and any plugin-registered tool) at priority 100
// (higher than any plugin we expect to coexist with).
//
// We don't import from `openclaw` directly. `openclaw` is an OPTIONAL peer
// dep — gateway provides it at runtime, but it isn't installed at build
// time. Local interfaces below describe the SDK surface we actually use,
// matching what the gateway passes to register() at load time. Same
// pattern used by other Clawnify-published plugins (e.g. clawflow).

import { AGENT_PERMISSIONS_API_SYMBOL } from "../api/symbol.js";
import type {
  AgentPermissionsApi,
  AllowAlwaysEvent,
  AllowAlwaysListener,
  GateRequest,
  PolicyBucket,
  ResolveFn,
  ResolverRegistration,
  RuleDestination,
} from "../api/types.js";
import {
  DEFAULT_DANGEROUS_PATTERNS,
  isDangerousRuleContent,
} from "../engine/dangerous-patterns.js";
import {
  evaluatePolicy,
  type DefaultMode,
  type RuleSet,
} from "../engine/rule-matcher.js";
import { parseRuleString, serializeRule } from "../engine/rule-parser.js";
import {
  defaultSourcePaths,
  fileMtimeStamp,
  loadAllRules,
  persistRule,
  removeRule,
  SessionRuleStore,
  type SourcePaths,
} from "../engine/rule-sources.js";

// ---------------------------------------------------------------------------
// Plugin-SDK surface we depend on (subset of openclaw's full PluginApi).
// ---------------------------------------------------------------------------

interface BeforeToolCallEvent {
  toolName: string;
  params?: unknown;
  context?: {
    sessionKey?: string;
    [k: string]: unknown;
  };
  [k: string]: unknown;
}

interface RequireApprovalDecision {
  title: string;
  description: string;
  severity?: "info" | "warning" | "critical";
  timeoutMs?: number;
  timeoutBehavior?: "allow" | "deny";
  onResolution?: (decision: string) => Promise<void> | void;
}

interface BeforeToolCallResult {
  block?: boolean;
  blockReason?: string;
  requireApproval?: RequireApprovalDecision;
}

interface PluginLogger {
  info: (msg: string) => void;
  warn: (msg: string) => void;
}

interface ToolResult {
  content: { type: "text"; text: string }[];
  isError?: boolean;
}

interface ToolRegistration {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  execute: (id: string, params: unknown) => Promise<ToolResult> | ToolResult;
}

interface PluginApi {
  pluginConfig?: unknown;
  logger: PluginLogger;
  on(
    event: "before_tool_call",
    handler: (
      event: BeforeToolCallEvent,
    ) =>
      | Promise<BeforeToolCallResult | undefined | void>
      | BeforeToolCallResult
      | undefined
      | void,
    options?: { priority?: number; timeoutMs?: number },
  ): void;
  registerTool(reg: ToolRegistration): void;
}

// ---------------------------------------------------------------------------
// Plugin config (configSchema-validated by openclaw at load time)
// ---------------------------------------------------------------------------

interface PluginConfig {
  defaultMode?: DefaultMode;
  allow?: string[];
  deny?: string[];
  ask?: string[];
  dangerousPatterns?: string[];
  paramKeys?: Record<string, string>;
  userRulesPath?: string;
  localRulesPath?: string;
  approvalTimeoutMs?: number;
  skipSessionPatterns?: string[];
  protectPermissions?: boolean;
}

// ---------------------------------------------------------------------------
// Generic GateRequest builder for tools without a registered resolver.
// ---------------------------------------------------------------------------
//
// Resolverless mode is the default — operators add rules in openclaw.json
// that target tool names; the engine evaluates without any consumer plugin
// needing to call registerResolver. The generic builder pulls a meaningful
// ruleContent so wildcard rules can match (e.g. `Bash(curl *)` matches the
// actual shell command) and generates a JSON-preview prompt.

function previewJson(value: unknown, max = 200): string {
  try {
    return JSON.stringify(value ?? {}, null, 2).slice(0, max);
  } catch {
    return "[unserializable]";
  }
}

// The gateway's plugin.approval.request schema rejects title > 80 or
// description > 256 chars with INVALID_REQUEST — surfaced to the agent as a
// misleading "gateway unavailable" and no approval UI is ever shown. Clamp
// both to stay under the caps.
function clampChars(s: string, max: number): string {
  return s.length <= max ? s : s.slice(0, max - 1) + "…";
}

// ---------------------------------------------------------------------------
// Tool helpers (permissions_set / permissions_propose_hardening)
// ---------------------------------------------------------------------------

function toolResult(value: unknown): ToolResult {
  const text =
    typeof value === "string" ? value : JSON.stringify(value, null, 2);
  return { content: [{ type: "text", text }] };
}

function serializeBuckets(rules: RuleSet): {
  allow: string[];
  deny: string[];
  ask: string[];
} {
  const ser = (arr: RuleSet["allow"]) => arr.map((s) => serializeRule(s.rule));
  return { allow: ser(rules.allow), deny: ser(rules.deny), ask: ser(rules.ask) };
}

// The matcher is case-sensitive and exact on tool name, and OpenClaw surfaces
// the shell as both `bash` and `exec` (lowercase — the generic extractor keys
// off exactly these). So hardening suggestions are rendered against the shell
// tool name(s) this agent actually uses (from the usage tally), defaulting to
// both when nothing's been observed yet. A capital `Bash(...)` rule would match
// nothing.
const SHELL_TOOL_NAMES = ["bash", "exec"];

// Curated, low-false-positive shell verbs the propose tool recommends gating
// when not already covered. Deliberately small — the genuinely high-risk verbs,
// not every interpreter (those are high-volume and better judged against the
// observed usage the tool also returns).
const HARDENING_VERBS: { verb: string; why: string }[] = [
  { verb: "sudo", why: "privilege escalation" },
  { verb: "ssh", why: "remote command execution / pivot" },
  { verb: "curl", why: "network fetch — exfiltration / remote payload" },
  { verb: "wget", why: "network fetch — exfiltration / remote payload" },
  { verb: "eval", why: "evaluates arbitrary code" },
];

function buildGenericGateRequest(
  toolName: string,
  params: Record<string, unknown>,
  paramKeys: Record<string, string> | undefined,
): GateRequest {
  // 1. Operator-configured paramKey: if openclaw.json says which param
  // carries the policy-relevant content for this tool, use that. Lets
  // wildcard rules like `clawnify_action(GMAIL_EMAIL_*)` work without
  // the consumer plugin needing to register a resolver.
  const paramKey = paramKeys?.[toolName];
  if (paramKey) {
    const raw = params[paramKey];
    if (typeof raw === "string" && raw.length > 0) {
      return {
        ruleContent: raw,
        title: "Run `" + toolName + "` (" + raw + ")?",
        description: "Params: ```json\n" + previewJson(params) + "\n```",
      };
    }
  }

  // 2. Shell tools: pull the actual command into ruleContent so wildcard
  // rules can match it (e.g. `Bash(curl *)` against `curl https://foo`).
  // OpenClaw's built-in shell tool surfaces as `bash` in some paths and
  // `exec` in others; cover both.
  if (toolName === "bash" || toolName === "exec") {
    const cmd =
      typeof params.command === "string" ? params.command.trim() : "";
    if (cmd) {
      return {
        ruleContent: cmd,
        title: "Run shell command?",
        description: "```bash\n" + cmd.slice(0, 200) + "\n```",
      };
    }
  }

  // 3. Default: tool-wide rule matching (ruleContent undefined → only `Tool`
  // or `Tool(*)` rules apply) + a generic JSON-preview prompt.
  return {
    title: "Run `" + toolName + "`?",
    description: "Params: ```json\n" + previewJson(params) + "\n```",
  };
}

// ---------------------------------------------------------------------------
// Plugin default export — openclaw's loader calls register(api).
// ---------------------------------------------------------------------------

function register(api: PluginApi): void {
  const cfg = (api.pluginConfig ?? {}) as PluginConfig;
  const defaultMode: DefaultMode = cfg.defaultMode ?? "default";
  const approvalTimeoutMs = cfg.approvalTimeoutMs ?? 9 * 60 * 1000;
  const dangerousPatterns =
    cfg.dangerousPatterns && cfg.dangerousPatterns.length > 0
      ? cfg.dangerousPatterns
      : DEFAULT_DANGEROUS_PATTERNS;
  const skipSessionPatterns = cfg.skipSessionPatterns ?? [];
  const protectPermissions = cfg.protectPermissions !== false;

  // Lightweight since-boot tool-usage tally. The gate sees every tool call, so
  // this is free signal for permissions_propose_hardening — no session-history
  // access needed. In-memory only; resets on gateway restart.
  const usage = new Map<string, number>();

  const paths: SourcePaths = defaultSourcePaths({
    local: cfg.localRulesPath,
    user: cfg.userRulesPath,
  });

  const resolvers = new Map<string, ResolveFn>();
  const allowAlwaysListeners: AllowAlwaysListener[] = [];
  const sessionStore = new SessionRuleStore();

  // Rule set is cached but rebuilt whenever the permission files change on disk
  // — so edits (via our own tool, an operator, or a direct write) take effect
  // without a gateway restart. Session-store mutations set cachedRules=null
  // explicitly (they don't touch a file, so the mtime stamp wouldn't catch
  // them). Config rules are static.
  let cachedRules: RuleSet | null = null;
  let cachedStamp = "";
  const getRules = (): RuleSet => {
    const stamp = fileMtimeStamp(paths);
    if (!cachedRules || stamp !== cachedStamp) {
      cachedRules = loadAllRules({
        config: {
          allow: cfg.allow,
          deny: cfg.deny,
          ask: cfg.ask,
        },
        paths,
        sessionStore,
        logger: api.logger,
      });
      cachedStamp = stamp;
    }
    return cachedRules;
  };

  // ---------- API surface published on globalThis ----------

  const apiSurface: AgentPermissionsApi = {
    registerResolver(reg: ResolverRegistration) {
      if (!reg || typeof reg.toolName !== "string" || !reg.toolName) {
        throw new Error(
          "agent-permissions.registerResolver: toolName is required",
        );
      }
      if (typeof reg.resolve !== "function") {
        throw new Error(
          "agent-permissions.registerResolver: resolve must be a function",
        );
      }
      if (resolvers.has(reg.toolName)) {
        api.logger.warn(
          `agent-permissions: replacing existing resolver for tool "${reg.toolName}"`,
        );
      }
      resolvers.set(reg.toolName, reg.resolve);
    },
    onAllowAlwaysPersisted(cb: AllowAlwaysListener) {
      if (typeof cb !== "function") return;
      allowAlwaysListeners.push(cb);
    },
  };

  (globalThis as Record<symbol, unknown>)[AGENT_PERMISSIONS_API_SYMBOL] =
    apiSurface;

  // ---------- before_tool_call hook ----------

  api.on(
    "before_tool_call",
    async (event: BeforeToolCallEvent): Promise<BeforeToolCallResult | undefined> => {
      try {
        usage.set(event.toolName, (usage.get(event.toolName) ?? 0) + 1);
        const params = (event.params as Record<string, unknown>) ?? {};

        // Self-protection: permissions_set is the sanctioned way to change the
        // rule set, so changing permissions IS a gated tool call. Force an
        // approval on every call and never persist it (allow-always is a no-op
        // here — one approval must not open the door forever), so an agent can
        // only *request* a permission change, not self-grant one. Deny still
        // wins for a human who wrote a deny rule against it. Disable with
        // config.protectPermissions=false.
        if (event.toolName === "permissions_set" && protectPermissions) {
          const denyDecision = evaluatePolicy({
            toolName: event.toolName,
            ruleContent: undefined,
            rules: getRules(),
            defaultMode,
          });
          if (denyDecision.bucket === "deny") {
            return {
              block: true,
              blockReason: `${event.toolName} blocked by ${denyDecision.reason ?? "policy"}`,
            };
          }

          const p = params as {
            allow?: string[];
            deny?: string[];
            ask?: string[];
            remove?: string[];
            scope?: string;
          };
          const parts: string[] = [];
          for (const b of ["deny", "ask", "allow"] as const) {
            const rs = p[b];
            if (rs && rs.length) parts.push(`+${b}: ${rs.join(", ")}`);
          }
          if (p.remove && p.remove.length) parts.push(`−remove: ${p.remove.join(", ")}`);
          const scope = p.scope === "local" ? "local" : "user";
          const summary =
            (parts.length ? parts.join(" | ") : "no rules specified") +
            ` → ${scope} scope`;
          return {
            requireApproval: {
              title: "Modify permission rules?",
              description: clampChars(
                `${summary}\n\n_Changes what the agent may do; approve once (not remembered)._`,
                256,
              ),
              severity: "warning",
              timeoutMs: approvalTimeoutMs,
              timeoutBehavior: "deny",
              // Intentionally no onResolution persist path.
            },
          };
        }

        // Build a GateRequest for the call. If a resolver was registered
        // for this toolName we use its rich prompt; otherwise fall back to
        // a generic extractor (bash command for shell tools, JSON-preview
        // for everything else). Resolverless mode is the default — it
        // makes agent-permissions usable by any plugin's tools without
        // requiring the consumer plugin to know about us.
        const resolve = resolvers.get(event.toolName);
        let req: GateRequest;
        if (resolve) {
          const resolved = resolve(params);
          if (!resolved) return undefined; // resolver opted out
          req = resolved;
        } else {
          req = buildGenericGateRequest(event.toolName, params, cfg.paramKeys);
        }

        const decision = evaluatePolicy({
          toolName: event.toolName,
          ruleContent: req.ruleContent,
          rules: getRules(),
          defaultMode,
        });

        if (decision.bucket === "deny") {
          return {
            block: true,
            blockReason: `${event.toolName} blocked by ${decision.reason ?? "policy"}`,
          };
        }

        if (decision.bucket === "ask") {
          const sessionKey = event.context?.sessionKey;

          // Unattended sessions (inbound email, webhooks, cron) have no
          // operator to answer a prompt. When the operator has opted in by
          // listing a matching pattern, auto-allow 'ask' decisions rather
          // than hanging until timeout. 'deny' rules are still enforced
          // (handled above), so this only relaxes the ask bucket.
          if (
            sessionKey &&
            skipSessionPatterns.some((p) => sessionKey.includes(p))
          ) {
            return undefined;
          }

          // Determine the rule string that "allow-always" will persist.
          // If a rule matched (operator wrote an ask pattern that caught
          // this call), persist THAT rule's pattern — so one "always"
          // click grants the breadth the operator already declared. Falls
          // back to the exact call content when no rule matched (only
          // happens in strict mode where everything asks by default).
          const ruleStringForPersist = (() => {
            const mr = decision.matchedRule;
            if (mr) {
              return mr.ruleContent
                ? `${mr.toolName}(${mr.ruleContent})`
                : mr.toolName;
            }
            return req.ruleContent
              ? `${event.toolName}(${req.ruleContent})`
              : event.toolName;
          })();

          // For the dangerous-pattern check, evaluate against the content
          // that WOULD be persisted (the rule pattern, not the exact
          // call). That way `Bash(curl *)` rule → allow-always refused,
          // not just `Bash(curl https://x.com/y)`.
          const dangerousContent =
            decision.matchedRule?.ruleContent ?? req.ruleContent;
          const dangerous = isDangerousRuleContent(
            dangerousContent,
            dangerousPatterns,
          );

          // Lead with the decision-relevant note (what 'always' grants, or
          // the danger warning) so it survives the 256-char clamp; the raw
          // command/params preview trails and absorbs any truncation.
          const note = dangerous
            ? "⚠ Runs arbitrary code; allow-always is disabled."
            : `_'Always' will allow: \`${ruleStringForPersist}\`_` +
              (decision.reason ? `\nMatched: ${decision.reason}` : "");
          const description = clampChars(`${note}\n\n${req.description}`, 256);

          return {
            requireApproval: {
              title: clampChars(req.title, 80),
              description,
              severity: dangerous ? "critical" : "warning",
              timeoutMs: approvalTimeoutMs,
              timeoutBehavior: "deny",
              onResolution: async (resolution: string) => {
                if (resolution !== "allow-always") return;
                if (dangerous) {
                  api.logger.warn(
                    `agent-permissions: refused to persist allow-always for dangerous rule ` +
                      `${ruleStringForPersist} — pattern is on the dangerous list`,
                  );
                  return;
                }
                const parsed = parseRuleString(ruleStringForPersist);
                if (!parsed) {
                  api.logger.warn(
                    `agent-permissions: could not parse rule for persist: ${ruleStringForPersist}`,
                  );
                  return;
                }

                try {
                  persistRule({
                    rule: parsed,
                    bucket: "allow",
                    destination: "user",
                    paths,
                    sessionStore,
                  });
                } catch (err) {
                  api.logger.warn(
                    `agent-permissions: persist to user file failed — ${String(err)}`,
                  );
                  return;
                }

                cachedRules = null; // invalidate

                // Report the actual persisted rule's content (matched-rule
                // pattern when applicable), not the exact call — listeners
                // should see what was learned, not what triggered it.
                const persistedContent = ((): string | undefined => {
                  switch (parsed.content.type) {
                    case "any":
                      return undefined;
                    case "exact":
                      return parsed.content.value;
                    case "prefix":
                      return `${parsed.content.value}:*`;
                    case "wildcard":
                      return parsed.content.pattern;
                  }
                })();
                const persistedEvent: AllowAlwaysEvent = {
                  rule: {
                    toolName: parsed.toolName,
                    ruleContent: persistedContent,
                  },
                  destination: "user",
                  sessionKey,
                };
                for (const cb of allowAlwaysListeners) {
                  try {
                    await cb(persistedEvent);
                  } catch (err) {
                    api.logger.warn(
                      `agent-permissions: onAllowAlwaysPersisted listener threw — ${String(err)}`,
                    );
                  }
                }
              },
            },
          };
        }

        // bucket === "allow" → no gate
        return undefined;
      } catch (err) {
        // OpenClaw's hook runner catches exceptions and lets the tool
        // proceed (fail-open) — turn any unexpected error into an explicit
        // block so a bug in this engine can't silently bypass approval.
        api.logger.warn(
          `agent-permissions: before_tool_call gate threw on ${event.toolName} — ${String(err)}`,
        );
        return {
          block: true,
          blockReason: `agent-permissions engine failed unexpectedly for ${event.toolName}`,
        };
      }
    },
    { priority: 100 },
  );

  // ---------- permissions_propose_hardening (read-only) ----------
  // Gives the agent structured raw material to propose a hardening plan to the
  // operator: what the agent has actually been doing (since-boot usage), what's
  // already gated, and a curated baseline of high-risk gates not yet in place.
  // The agent reasons over this with the operator, then applies via
  // permissions_set (which is itself approval-gated).
  api.registerTool({
    name: "permissions_propose_hardening",
    description:
      "Propose permission-hardening rules for this agent. Returns observed tool usage, the current rule set, and a suggested set of gates (in ToolName / ToolName(pattern) syntax). Read-only — apply the approved subset with permissions_set.",
    parameters: {
      type: "object",
      additionalProperties: false,
      properties: {
        scope: {
          type: "string",
          enum: ["user", "local"],
          description:
            "Scope the proposal targets. Defaults to 'user' (~/.openclaw/permissions.json).",
        },
      },
    },
    execute(_id, params) {
      const scope =
        (params as { scope?: string })?.scope === "local" ? "local" : "user";
      const current = serializeBuckets(getRules());
      const covered = new Set([...current.ask, ...current.deny, ...current.allow]);
      // Target the shell tool(s) actually in use; fall back to both when the
      // agent hasn't run a shell command since boot.
      const observedShell = SHELL_TOOL_NAMES.filter((t) => usage.has(t));
      const shellTools = observedShell.length ? observedShell : SHELL_TOOL_NAMES;
      const suggestedAsk: string[] = [];
      const rationale: string[] = [];
      for (const tool of shellTools) {
        for (const { verb, why } of HARDENING_VERBS) {
          const rule = `${tool}(${verb} *)`;
          if (!covered.has(rule)) {
            suggestedAsk.push(rule);
            rationale.push(`${rule} — ${why}`);
          }
        }
      }
      const observed = Object.fromEntries(
        [...usage.entries()].sort((a, b) => b[1] - a[1]),
      );
      return toolResult({
        scope,
        observedToolUsageSinceBoot: observed,
        currentRules: current,
        suggested: { ask: suggestedAsk, deny: [], allow: [] },
        rationale,
        howToApply:
          "Review with the operator, then call permissions_set with the approved subset. Each apply requires approval.",
      });
    },
  });

  // ---------- permissions_set (mutation, self-gated) ----------
  // The sanctioned way to change the rule set. A rule lives in exactly ONE
  // bucket: setting it in allow/deny/ask moves it there (removing it from the
  // others), so e.g. downgrading allow→ask actually takes effect instead of the
  // old allow lingering and winning. `remove` deletes rules outright. Other
  // rules are untouched (merge, not replace). Defaults to user scope. The
  // before_tool_call gate above forces approval when protectPermissions is on.
  api.registerTool({
    name: "permissions_set",
    description:
      "Add, move, or remove permission rules. Setting a rule in allow/deny/ask MOVES it there (a rule is only ever in one bucket). `remove` deletes rules. Other rules are left as-is. Rules use ToolName or ToolName(pattern) syntax (e.g. 'bash(curl *)'). Defaults to user scope (~/.openclaw/permissions.json). Requires approval unless the operator disabled protectPermissions.",
    parameters: {
      type: "object",
      additionalProperties: false,
      properties: {
        allow: {
          type: "array",
          items: { type: "string" },
          description: "Rules to allow (moved out of deny/ask), e.g. 'bash(git *)'.",
        },
        deny: {
          type: "array",
          items: { type: "string" },
          description: "Rules to hard-block, e.g. 'bash(sudo *)'.",
        },
        ask: {
          type: "array",
          items: { type: "string" },
          description: "Rules to gate behind approval, e.g. 'bash(curl *)'.",
        },
        remove: {
          type: "array",
          items: { type: "string" },
          description: "Rules to delete from every bucket, e.g. 'clawnify_update_app'.",
        },
        scope: {
          type: "string",
          enum: ["user", "local"],
          description:
            "Where to persist. Defaults to 'user' (~/.openclaw/permissions.json).",
        },
      },
    },
    execute(_id, params) {
      const p = (params ?? {}) as {
        allow?: string[];
        deny?: string[];
        ask?: string[];
        remove?: string[];
        scope?: string;
      };
      const destination: RuleDestination = p.scope === "local" ? "local" : "user";
      const buckets = ["allow", "deny", "ask"] as PolicyBucket[];
      const applied: string[] = [];
      const removed: string[] = [];
      const skipped: string[] = [];

      // Explicit removals first — take the rule out of every bucket.
      for (const s of p.remove ?? []) {
        const rule = parseRuleString(s);
        if (!rule) {
          skipped.push(`${s} (unparseable)`);
          continue;
        }
        if (removeRule({ rule, buckets, destination, paths, sessionStore })) {
          removed.push(serializeRule(rule));
        }
      }

      // Sets — remove from the other buckets first so the rule ends up in
      // exactly the one requested (this is the allow→ask "move" fix).
      for (const bucket of buckets) {
        for (const s of p[bucket] ?? []) {
          const rule = parseRuleString(s);
          if (!rule) {
            skipped.push(`${s} (unparseable)`);
            continue;
          }
          const others = buckets.filter((b) => b !== bucket);
          removeRule({ rule, buckets: others, destination, paths, sessionStore });
          try {
            persistRule({ rule, bucket, destination, paths, sessionStore });
            applied.push(`${bucket}: ${serializeRule(rule)}`);
          } catch (err) {
            skipped.push(`${s} (${String(err)})`);
          }
        }
      }
      cachedRules = null; // invalidate — next evaluate re-reads the file
      return toolResult({ scope: destination, applied, removed, skipped });
    },
  });

  const ruleCount =
    (cfg.allow?.length ?? 0) +
    (cfg.deny?.length ?? 0) +
    (cfg.ask?.length ?? 0);
  api.logger.info(
    `agent-permissions registered (defaultMode=${defaultMode}, ` +
      `config rules=${ruleCount}, protectPermissions=${protectPermissions}, ` +
      `tools=[permissions_propose_hardening, permissions_set], ` +
      `userRules=${paths.user}, localRules=${paths.local})`,
  );
}

export default {
  id: "agent-permissions",
  name: "Agent Permissions",
  description:
    "Permission and approval engine for OpenClaw agents. Three-bucket policy with rule sources, in-chat approval, and per-tool resolvers registered by consumer plugins.",
  register,
};
