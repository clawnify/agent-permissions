// Compiled entry. tsc produces dist/index.js from this — what
// `package.json#main` and the OpenClaw loader (when no TS support) consume.
//
// The root `index.ts` (sibling to src/) is the TS-direct entry used by
// openclaw.extensions when the host has TS support; it re-exports from this
// file's source so both paths surface the same API.

export { default } from "./plugin/index.js";

export {
  registerResolver,
  onAllowAlwaysPersisted,
  getAgentPermissionsApi,
} from "./api/resolver.js";

export type {
  AgentPermissionsApi,
  ResolverRegistration,
  ResolveFn,
  GateRequest,
  AllowAlwaysEvent,
  PolicyBucket,
  PolicyDecision,
  RuleSource,
} from "./api/types.js";
