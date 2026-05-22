// Public helpers for consumers of @clawnify/agent-permissions.
//
// Runtime model: agent-permissions' register() publishes its API surface on
// globalThis under AGENT_PERMISSIONS_API_SYMBOL. These helpers look up that
// surface and call through to it. Consumers that try to register before
// agent-permissions has loaded get a loud error rather than a silent no-op.

import { AGENT_PERMISSIONS_API_SYMBOL } from "./symbol.js";
import type {
  AgentPermissionsApi,
  AllowAlwaysListener,
  ResolverRegistration,
} from "./types.js";

const ERR_NOT_LOADED =
  "@clawnify/agent-permissions is not loaded into this gateway. " +
  "Ensure agent-permissions is listed in plugins.allow and plugins.entries " +
  "in openclaw.json, and that it appears BEFORE this plugin in " +
  "plugins.load.paths (so the API is published when register() runs).";

/**
 * Resolve the live API. Throws a descriptive error if agent-permissions
 * hasn't loaded yet (typically a load-order misconfiguration). Cheap —
 * just a Symbol lookup on globalThis.
 */
export function getAgentPermissionsApi(): AgentPermissionsApi {
  const api = (globalThis as Record<symbol, unknown>)[
    AGENT_PERMISSIONS_API_SYMBOL
  ] as AgentPermissionsApi | undefined;
  if (!api) throw new Error(ERR_NOT_LOADED);
  return api;
}

/** Convenience wrapper around `getAgentPermissionsApi().registerResolver(reg)`. */
export function registerResolver(reg: ResolverRegistration): void {
  getAgentPermissionsApi().registerResolver(reg);
}

/** Convenience wrapper around `getAgentPermissionsApi().onAllowAlwaysPersisted(cb)`. */
export function onAllowAlwaysPersisted(cb: AllowAlwaysListener): void {
  getAgentPermissionsApi().onAllowAlwaysPersisted(cb);
}
