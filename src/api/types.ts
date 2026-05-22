// Public types for @clawnify/agent-permissions.
//
// These types are the contract for consumers (other plugins that register
// resolvers). Keep stable across patch versions; widen with care, never
// break shapes without bumping the Symbol version (see ./symbol.ts).

/** Three-bucket policy outcome. */
export type PolicyBucket = "allow" | "deny" | "ask";

/** Where a rule was loaded from. Sources are walked in this priority order. */
export type RuleSource = "session" | "local" | "user" | "config";

/** Where a learned "allow-always" rule can be persisted. */
export type RuleDestination = "session" | "local" | "user";

/**
 * Resolver output. Tells agent-permissions:
 * - which rule (`ToolName(ruleContent)`) this call maps to, and
 * - how to present the approval prompt if the decision is "ask".
 *
 * Returning `null` means "this resolver has no opinion on this call" — the
 * engine moves on (typically: no gate, tool proceeds). Use this for
 * resolvers that filter (e.g. only gate non-GET HTTP methods).
 */
export interface GateRequest {
  /**
   * The `(content)` portion of the policy rule. Omit (or set empty) for
   * a tool-wide rule like `ClawnifyDeleteApp`. Otherwise the call is
   * matched against rules of shape `ToolName(ruleContent)`.
   */
  ruleContent?: string;
  /** Headline shown in the in-chat approval prompt. */
  title: string;
  /** Body text shown beneath the title. Markdown supported by OpenClaw. */
  description: string;
}

/**
 * Function signature consumers implement. Pure — should not perform I/O.
 * Called synchronously inside the before_tool_call hook on every matching
 * tool call, so cheap.
 */
export type ResolveFn = (
  params: Record<string, unknown>,
) => GateRequest | null;

/** Registration record passed to `registerResolver`. */
export interface ResolverRegistration {
  /** Tool name as it appears in `event.toolName`. Exact match. */
  toolName: string;
  resolve: ResolveFn;
}

/** Optional diagnostic info attached to a policy decision. */
export interface PolicyDecision {
  bucket: PolicyBucket;
  matchedRule?: {
    toolName: string;
    ruleContent?: string;
    source: RuleSource;
  };
  /** Human-readable reason the engine reached this bucket. Surfaced in prompts. */
  reason?: string;
}

/**
 * Fired after agent-permissions persists an "allow-always" decision to a
 * destination. Lets consumer plugins mirror the rule to an external backend
 * (e.g. a cloud policy store), audit the decision, or invalidate caches.
 */
export interface AllowAlwaysEvent {
  rule: {
    toolName: string;
    ruleContent?: string;
  };
  destination: RuleDestination;
  /** OpenClaw session that the approval originated from, if available. */
  sessionKey?: string;
}

export type AllowAlwaysListener = (
  event: AllowAlwaysEvent,
) => Promise<void> | void;

/**
 * The shape published on `globalThis[AGENT_PERMISSIONS_API_SYMBOL]` once
 * the plugin's `register()` has run. Consumers go through
 * `getAgentPermissionsApi()` rather than reading the symbol directly.
 */
export interface AgentPermissionsApi {
  registerResolver(reg: ResolverRegistration): void;
  onAllowAlwaysPersisted(cb: AllowAlwaysListener): void;
}
