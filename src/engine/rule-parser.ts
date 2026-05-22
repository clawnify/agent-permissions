// Rule string parser.
//
// A rule is one of:
//   "ToolName"               — tool-wide (any content matches)
//   "ToolName(content)"      — content is exact match, prefix (`foo:*`),
//                              or wildcard (`foo *`).
//
// Inside `(content)`, the characters `(`, `)`, `\` are escaped with `\`.
// Inside wildcard patterns, `*` is escaped with `\*` to match a literal star.
//
// Structure cribbed from Anthropic's Claude Code shellRuleMatching.ts +
// permissionRuleParser.ts (studied as prior art). Generalized: in Claude
// Code "content" is always a shell command. Here it's any string returned
// by a resolver, so the same parser supports a fixed-string subject like
// "delete" and a bash command line equally well.

export type ContentMatcher =
  | { type: "any" }
  | { type: "exact"; value: string }
  | { type: "prefix"; value: string }
  | { type: "wildcard"; pattern: string };

export interface ParsedRule {
  toolName: string;
  content: ContentMatcher;
}

/**
 * Parse a rule string into a structured rule.
 *
 * Returns `null` for malformed strings — caller should log and skip rather
 * than fail closed on a config typo. Engine treats a config rule that
 * fails to parse as "this rule does not exist."
 */
export function parseRuleString(ruleString: string): ParsedRule | null {
  const trimmed = ruleString.trim();
  if (!trimmed) return null;

  const openParen = findFirstUnescapedChar(trimmed, "(");
  if (openParen === -1) {
    // No content section: "ToolName" alone is a tool-wide rule.
    return { toolName: trimmed, content: { type: "any" } };
  }

  const closeParen = findLastUnescapedChar(trimmed, ")");
  if (closeParen === -1 || closeParen <= openParen) return null;

  // Stuff after the closing paren = malformed.
  if (closeParen !== trimmed.length - 1) return null;

  const toolName = trimmed.slice(0, openParen);
  if (!toolName) return null;

  const rawContent = trimmed.slice(openParen + 1, closeParen);

  // "ToolName()" and "ToolName(*)" both mean tool-wide.
  if (rawContent === "" || rawContent === "*") {
    return { toolName, content: { type: "any" } };
  }

  const content = unescapeRuleContent(rawContent);
  return { toolName, content: classifyContent(content) };
}

/** Render a rule back to string form. Round-trip-safe with `parseRuleString`. */
export function serializeRule(rule: ParsedRule): string {
  switch (rule.content.type) {
    case "any":
      return rule.toolName;
    case "exact":
      return `${rule.toolName}(${escapeRuleContent(rule.content.value)})`;
    case "prefix":
      // Render in the legacy `foo:*` form rather than wildcard form to keep
      // semantics explicit. `foo:*` matches `foo`, `foo args`, etc.
      return `${rule.toolName}(${escapeRuleContent(rule.content.value)}:*)`;
    case "wildcard":
      return `${rule.toolName}(${rule.content.pattern})`;
  }
}

// ---------------------------------------------------------------------------
// Content classification
// ---------------------------------------------------------------------------

function classifyContent(content: string): ContentMatcher {
  // Legacy `:*` suffix → prefix match.
  const prefixMatch = content.match(/^(.+):\*$/);
  if (prefixMatch) {
    return { type: "prefix", value: prefixMatch[1]! };
  }

  // Any unescaped `*` → wildcard.
  if (hasUnescapedWildcard(content)) {
    return { type: "wildcard", pattern: content };
  }

  // Otherwise exact match.
  return { type: "exact", value: content };
}

/**
 * True if the string contains an unescaped `*`.
 *
 * `\*` → escaped (literal star wanted).
 * `\\*` → unescaped (the `\` is escaping itself, then `*` is free).
 * Even number of preceding backslashes = unescaped.
 */
export function hasUnescapedWildcard(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== "*") continue;
    let backslashes = 0;
    let j = i - 1;
    while (j >= 0 && s[j] === "\\") {
      backslashes++;
      j--;
    }
    if (backslashes % 2 === 0) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Escape / unescape inside (content)
// ---------------------------------------------------------------------------
//
// Order matters in both directions:
//   escape:    `\` → `\\` first, then `(` → `\(`, `)` → `\)`
//   unescape:  `\(` → `(` first, `\)` → `)` first, then `\\` → `\`
// Reversing the order would double-escape or eat backslashes.

export function escapeRuleContent(content: string): string {
  return content
    .replace(/\\/g, "\\\\")
    .replace(/\(/g, "\\(")
    .replace(/\)/g, "\\)");
}

export function unescapeRuleContent(content: string): string {
  return content
    .replace(/\\\(/g, "(")
    .replace(/\\\)/g, ")")
    .replace(/\\\\/g, "\\");
}

// ---------------------------------------------------------------------------
// Unescaped-char search
// ---------------------------------------------------------------------------

function findFirstUnescapedChar(s: string, ch: string): number {
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== ch) continue;
    let backslashes = 0;
    let j = i - 1;
    while (j >= 0 && s[j] === "\\") {
      backslashes++;
      j--;
    }
    if (backslashes % 2 === 0) return i;
  }
  return -1;
}

function findLastUnescapedChar(s: string, ch: string): number {
  for (let i = s.length - 1; i >= 0; i--) {
    if (s[i] !== ch) continue;
    let backslashes = 0;
    let j = i - 1;
    while (j >= 0 && s[j] === "\\") {
      backslashes++;
      j--;
    }
    if (backslashes % 2 === 0) return i;
  }
  return -1;
}
