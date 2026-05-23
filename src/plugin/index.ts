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
  ResolveFn,
  ResolverRegistration,
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
import { parseRuleString } from "../engine/rule-parser.js";
import {
  defaultSourcePaths,
  loadAllRules,
  persistRule,
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

function previewJson(value: unknown, max = 600): string {
  try {
    return JSON.stringify(value ?? {}, null, 2).slice(0, max);
  } catch {
    return "[unserializable]";
  }
}

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
        description: "```bash\n" + cmd.slice(0, 600) + "\n```",
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

  const paths: SourcePaths = defaultSourcePaths({
    local: cfg.localRulesPath,
    user: cfg.userRulesPath,
  });

  const resolvers = new Map<string, ResolveFn>();
  const allowAlwaysListeners: AllowAlwaysListener[] = [];
  const sessionStore = new SessionRuleStore();

  // Build the rule set once at register time. v1 has no file watchers —
  // restart the gateway after editing the JSON files. Session rules are
  // re-read on every evaluate() because the store is appended to live.
  let cachedRules: RuleSet | null = null;
  const getRules = (): RuleSet => {
    if (!cachedRules) {
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
        const params = (event.params as Record<string, unknown>) ?? {};

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

          const description = dangerous
            ? `${req.description}\n\n_⚠ This pattern can run arbitrary code; allow-always is disabled._`
            : (decision.reason
                ? `${req.description}\n\nMatched: ${decision.reason}`
                : req.description) +
              `\n\n_'Always' will allow: \`${ruleStringForPersist}\`_`;

          const sessionKey = event.context?.sessionKey;

          return {
            requireApproval: {
              title: req.title,
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

  const ruleCount =
    (cfg.allow?.length ?? 0) +
    (cfg.deny?.length ?? 0) +
    (cfg.ask?.length ?? 0);
  api.logger.info(
    `agent-permissions registered (defaultMode=${defaultMode}, ` +
      `config rules=${ruleCount}, ` +
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
