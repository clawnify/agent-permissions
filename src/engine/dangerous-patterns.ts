// Dangerous-pattern denylist.
//
// Patterns here may match `ask` rules but cannot be allow-always-persisted —
// granting a broad allow rule like `Bash(python:*)` defeats the gate, since
// the model can run arbitrary code under the umbrella permission. Approval
// prompts for these patterns still get the allow-once / deny options; only
// the persist-forever choice is suppressed.
//
// Conservative defaults ported from Anthropic's Claude Code
// (dangerousPatterns.ts, external-build list — we drop the ant-only
// additions since they reflect their internal sandbox data). Customers can
// extend or replace via `config.dangerousPatterns` in openclaw.json.

/** Cross-platform interpreters + shells + remote-exec wrappers. */
export const DEFAULT_DANGEROUS_PATTERNS: readonly string[] = [
  // Interpreters
  "python",
  "python3",
  "python2",
  "node",
  "deno",
  "tsx",
  "ruby",
  "perl",
  "php",
  "lua",
  // Package runners (each can drop into arbitrary scripts)
  "npx",
  "bunx",
  "npm run",
  "yarn run",
  "pnpm run",
  "bun run",
  // Shells
  "bash",
  "sh",
  "zsh",
  "fish",
  // Built-in eval-style commands
  "eval",
  "exec",
  "env",
  "xargs",
  "sudo",
  // Remote command wrapper
  "ssh",
  // Network-fetch tools (allow rules let model exfil / pivot)
  "curl",
  "wget",
];

/**
 * Check whether a rule's content is "dangerous" — i.e. matches one of the
 * configured prefixes such that allow-always would be unsafe.
 *
 * Matching considers four rule-content shapes (mirroring how Claude Code's
 * permissionSetup.ts:isDangerousBashPermission strips at auto-mode entry):
 *
 *   prefix == "python"
 *   ── exact "python"               → dangerous
 *   ── prefix "python:*"            → dangerous (legacy)
 *   ── wildcard "python *"          → dangerous (trailing args)
 *   ── wildcard "python*"           → dangerous (no separator — paranoid match)
 *   ── wildcard "python -c *"       → dangerous (specific flag form)
 *
 * Tool-wide rules (no content) are NOT considered dangerous here — a
 * tool-wide `Bash` rule is its own problem and should be a separate "you
 * probably don't want this" hint at config-load time.
 */
export function isDangerousRuleContent(
  ruleContent: string | undefined,
  patterns: readonly string[],
): boolean {
  if (!ruleContent) return false;
  const content = ruleContent.trim();
  if (!content) return false;

  for (const prefix of patterns) {
    if (matchesDangerousPrefix(content, prefix)) return true;
  }
  return false;
}

function matchesDangerousPrefix(content: string, prefix: string): boolean {
  // Exact: "python"
  if (content === prefix) return true;
  // Legacy prefix: "python:*"
  if (content === `${prefix}:*`) return true;
  // Wildcard trailing-args form: "python *", "python -c *", etc.
  // Any content that starts with "<prefix> " (followed by anything containing
  // an unescaped `*`) is treated as dangerous.
  if (content.startsWith(`${prefix} `) && content.includes("*")) return true;
  // Wildcard adjacent form: "python*", "python3*" — covers e.g. someone
  // typing `Bash(python*)` thinking it's broad-match (which it is).
  if (content.startsWith(`${prefix}*`)) return true;
  return false;
}
