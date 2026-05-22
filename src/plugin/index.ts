// Plugin entry: wires the API surface, loads rules, registers the
// before_tool_call hook. The hook itself is the integration point — it
// fires for every tool call across the gateway (built-in tools and any
// plugin-registered tool) at priority 100 (higher than any plugin we
// expect to coexist with).

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { AGENT_PERMISSIONS_API_SYMBOL } from "../api/symbol.js";
import type {
  AgentPermissionsApi,
  AllowAlwaysEvent,
  AllowAlwaysListener,
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

interface PluginConfig {
  defaultMode?: DefaultMode;
  allow?: string[];
  deny?: string[];
  ask?: string[];
  dangerousPatterns?: string[];
  userRulesPath?: string;
  localRulesPath?: string;
  approvalTimeoutMs?: number;
}

export default definePluginEntry({
  id: "agent-permissions",
  name: "Agent Permissions",
  description:
    "Permission and approval engine for OpenClaw agents. Three-bucket policy with rule sources, in-chat approval, and per-tool resolvers registered by consumer plugins.",

  register(api) {
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
      async (event) => {
        try {
          const resolve = resolvers.get(event.toolName);
          if (!resolve) return; // no resolver registered → not gated

          const params = (event.params as Record<string, unknown>) ?? {};
          const req = resolve(params);
          if (!req) return; // resolver opted out (e.g. read-only HTTP method)

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
            const dangerous = isDangerousRuleContent(req.ruleContent, dangerousPatterns);
            const description = dangerous
              ? `${req.description}\n\n_⚠ This pattern can run arbitrary code; allow-always is disabled._`
              : decision.reason
                ? `${req.description}\n\nWhy: ${decision.reason}`
                : req.description;

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
                        `${event.toolName}(${req.ruleContent ?? ""}) — pattern is on the dangerous list`,
                    );
                    return;
                  }
                  const ruleString = req.ruleContent
                    ? `${event.toolName}(${req.ruleContent})`
                    : event.toolName;
                  const parsed = parseRuleString(ruleString);
                  if (!parsed) {
                    api.logger.warn(
                      `agent-permissions: could not parse rule for persist: ${ruleString}`,
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

                  // Invalidate the cache so the new rule is visible next call.
                  cachedRules = null;

                  const persistedEvent: AllowAlwaysEvent = {
                    rule: {
                      toolName: parsed.toolName,
                      ruleContent: req.ruleContent,
                    },
                    destination: "user",
                    sessionKey: event.context?.sessionKey,
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
          return;
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
  },
});
