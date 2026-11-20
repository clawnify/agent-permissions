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

// Where a permission authority is published (see PermissionAuthority in
// ./types.ts). Unlike the API above, this one is set BY another plugin and
// read here, at each always-ask call, so neither plugin's load order matters.
export const PERMISSION_AUTHORITY_SYMBOL = Symbol.for(
  "clawnify.agent-permissions.authority.v1",
);
