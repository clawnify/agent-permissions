// Versioned Symbol used to publish the agent-permissions API on globalThis
// so other plugins in the same gateway process can resolve it at runtime.
//
// The `.v1` suffix lets a future breaking API change coexist with v1
// consumers — bump to `.v2` rather than mutating the v1 shape. Old plugins
// continue resolving v1 (it stays there until removed); new plugins resolve
// v2. Coexistence is the point.

export const AGENT_PERMISSIONS_API_SYMBOL = Symbol.for(
  "clawnify.agent-permissions.api.v1",
);
