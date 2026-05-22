// Rule matching + decision tree.
//
// Given (toolName, ruleContent) for an incoming call and a set of rules
// grouped by bucket and source, decide allow / deny / ask:
//
//   1. Walk deny rules across all sources (session → local → user → config).
//      First match wins → bucket = "deny".
//   2. Walk allow rules same way. First match wins → bucket = "allow".
//   3. Walk ask rules same way. First match wins → bucket = "ask".
//   4. No match → defaultMode fallback (see `applyDefaultMode`).
//
// Within each bucket, source priority is session → local → user → config.
// Across buckets, deny > allow > ask > fallback.

import type {
  PolicyBucket,
  PolicyDecision,
  RuleSource,
} from "../api/types.js";
import {
  type ContentMatcher,
  type ParsedRule,
  serializeRule,
} from "./rule-parser.js";

/** A parsed rule tagged with its source for diagnostics. */
export interface SourcedRule {
  rule: ParsedRule;
  source: RuleSource;
}

/** Rule sets indexed by bucket. */
export interface RuleSet {
  allow: SourcedRule[];
  deny: SourcedRule[];
  ask: SourcedRule[];
}

export type DefaultMode =
  | "default"
  | "acceptEdits"
  | "bypassPermissions"
  | "dontAsk";

const SOURCE_PRIORITY: RuleSource[] = ["session", "local", "user", "config"];

/**
 * Evaluate a call against the combined rule set. Returns the bucket + the
 * matched rule (if any) + a human reason string suitable for prompts/logs.
 */
export function evaluatePolicy(args: {
  toolName: string;
  ruleContent: string | undefined;
  rules: RuleSet;
  defaultMode: DefaultMode;
}): PolicyDecision {
  const { toolName, ruleContent, rules, defaultMode } = args;

  const denyMatch = findFirstMatch(toolName, ruleContent, rules.deny);
  if (denyMatch) {
    return decisionFor("deny", denyMatch);
  }

  const allowMatch = findFirstMatch(toolName, ruleContent, rules.allow);
  if (allowMatch) {
    return decisionFor("allow", allowMatch);
  }

  const askMatch = findFirstMatch(toolName, ruleContent, rules.ask);
  if (askMatch) {
    return decisionFor("ask", askMatch);
  }

  return applyDefaultMode(defaultMode);
}

function decisionFor(
  bucket: PolicyBucket,
  matched: SourcedRule,
): PolicyDecision {
  const matchedRule = {
    toolName: matched.rule.toolName,
    ruleContent: contentOfRule(matched.rule),
    source: matched.source,
  };
  return {
    bucket,
    matchedRule,
    reason: `rule '${serializeRule(matched.rule)}' from ${matched.source} settings`,
  };
}

function applyDefaultMode(mode: DefaultMode): PolicyDecision {
  switch (mode) {
    case "bypassPermissions":
    case "dontAsk":
      return { bucket: "allow", reason: `default mode '${mode}'` };
    case "acceptEdits":
      // v1: acceptEdits behaves like default for unclassified tools. Later we
      // can wire tool-category awareness (read-only / edit-CWD / network) so
      // edits in CWD auto-allow while everything else asks.
      return { bucket: "ask", reason: `default mode 'acceptEdits' (no rule match)` };
    case "default":
    default:
      return { bucket: "ask", reason: "no rule match (default mode)" };
  }
}

/**
 * Walk sources in priority order. Return the first rule that matches this
 * tool + content, or null. Within a single source, rules are walked in the
 * order they appear (config file order).
 */
function findFirstMatch(
  toolName: string,
  ruleContent: string | undefined,
  rules: SourcedRule[],
): SourcedRule | null {
  for (const source of SOURCE_PRIORITY) {
    for (const sourced of rules) {
      if (sourced.source !== source) continue;
      if (matchesRule(sourced.rule, toolName, ruleContent)) return sourced;
    }
  }
  return null;
}

/** True if `(toolName, ruleContent)` matches the parsed rule. */
export function matchesRule(
  rule: ParsedRule,
  toolName: string,
  ruleContent: string | undefined,
): boolean {
  if (rule.toolName !== toolName) return false;
  return matchesContent(rule.content, ruleContent);
}

function matchesContent(
  matcher: ContentMatcher,
  ruleContent: string | undefined,
): boolean {
  switch (matcher.type) {
    case "any":
      return true;
    case "exact":
      return ruleContent === matcher.value;
    case "prefix":
      // `foo:*` matches `foo`, `foo …`, `foo:bar`. Same semantics as
      // Claude Code's permissionRuleExtractPrefix path.
      if (ruleContent === undefined) return false;
      return (
        ruleContent === matcher.value ||
        ruleContent.startsWith(`${matcher.value} `) ||
        ruleContent.startsWith(`${matcher.value}:`)
      );
    case "wildcard":
      if (ruleContent === undefined) return false;
      return matchWildcard(matcher.pattern, ruleContent);
  }
}

function contentOfRule(rule: ParsedRule): string | undefined {
  switch (rule.content.type) {
    case "any":
      return undefined;
    case "exact":
      return rule.content.value;
    case "prefix":
      return `${rule.content.value}:*`;
    case "wildcard":
      return rule.content.pattern;
  }
}

// ---------------------------------------------------------------------------
// Wildcard matching
// ---------------------------------------------------------------------------
//
// Port of Claude Code's shellRuleMatching.ts:matchWildcardPattern, with the
// same null-byte sentinel placeholders so escape sequences survive regex
// special-character escaping. Module-level regexes = compiled once.

const ESC_STAR = "\x00ESC_STAR\x00";
const ESC_BACKSLASH = "\x00ESC_BS\x00";
const ESC_STAR_RE = new RegExp(ESC_STAR, "g");
const ESC_BACKSLASH_RE = new RegExp(ESC_BACKSLASH, "g");

/**
 * Match a string against a wildcard pattern. `*` matches any chars; `\*`
 * matches a literal `*`; `\\` matches a literal `\`. Patterns are anchored
 * to the full string (`^pattern$`), with dotall semantics so `*` matches
 * across newlines (heredocs).
 *
 * Special case: a pattern ending in ` *` (space + single trailing wildcard)
 * also matches the prefix with no args — `git *` matches both `git add` and
 * bare `git`. Lifted from Claude Code, where the comment notes this aligns
 * wildcard semantics with prefix-rule semantics (`git:*`).
 */
export function matchWildcard(pattern: string, input: string): boolean {
  const trimmedPattern = pattern.trim();

  // Replace escape sequences with sentinel placeholders so they survive
  // the regex-special-char escape pass that follows.
  let processed = "";
  let i = 0;
  while (i < trimmedPattern.length) {
    const c = trimmedPattern[i]!;
    if (c === "\\" && i + 1 < trimmedPattern.length) {
      const next = trimmedPattern[i + 1]!;
      if (next === "*") {
        processed += ESC_STAR;
        i += 2;
        continue;
      }
      if (next === "\\") {
        processed += ESC_BACKSLASH;
        i += 2;
        continue;
      }
    }
    processed += c;
    i++;
  }

  // Escape regex specials (but leave `*` for the next step).
  const escaped = processed.replace(/[.+?^${}()|[\]\\'"]/g, "\\$&");

  // Unescaped `*` → `.*` for wildcard matching.
  const withWildcards = escaped.replace(/\*/g, ".*");

  // Restore the literal placeholders.
  let regexPattern = withWildcards
    .replace(ESC_STAR_RE, "\\*")
    .replace(ESC_BACKSLASH_RE, "\\\\");

  // Trailing-space-star heuristic: pattern `foo *` (one unescaped wildcard,
  // trailing space-wildcard) becomes `foo( .*)?` so it also matches bare
  // `foo` with no trailing args. Multi-wildcard patterns are excluded.
  const unescapedStarCount = (processed.match(/\*/g) || []).length;
  if (regexPattern.endsWith(" .*") && unescapedStarCount === 1) {
    regexPattern = `${regexPattern.slice(0, -3)}( .*)?`;
  }

  return new RegExp(`^${regexPattern}$`, "s").test(input);
}
