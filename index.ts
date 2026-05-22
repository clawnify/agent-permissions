// OpenClaw plugin default export — what the loader resolves via `main`.
export { default } from "./src/plugin/index.js";

// Public API for in-process consumers (other plugins in the same gateway).
// At dev time these are type-safe via the pnpm workspace symlink. At runtime
// on a customer VPS, each plugin ships its own tarball — consumers resolve
// the API via globalThis[Symbol.for("clawnify.agent-permissions.api.v1")].
export {
  registerResolver,
  onAllowAlwaysPersisted,
  getAgentPermissionsApi,
} from "./src/api/resolver.js";

export type {
  AgentPermissionsApi,
  ResolverRegistration,
  ResolveFn,
  GateRequest,
  AllowAlwaysEvent,
  PolicyBucket,
  PolicyDecision,
  RuleSource,
} from "./src/api/types.js";
