import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import {
  escapeRuleContent,
  hasUnescapedWildcard,
  parseRuleString,
  serializeRule,
  unescapeRuleContent,
} from "../src/engine/rule-parser.js";

describe("parseRuleString", () => {
  it("parses a bare tool name as tool-wide", () => {
    assert.deepEqual(parseRuleString("Bash"), {
      toolName: "Bash",
      content: { type: "any" },
    });
  });

  it("parses 'Tool(*)' as tool-wide", () => {
    assert.deepEqual(parseRuleString("Bash(*)"), {
      toolName: "Bash",
      content: { type: "any" },
    });
  });

  it("parses 'Tool()' as tool-wide", () => {
    assert.deepEqual(parseRuleString("Bash()"), {
      toolName: "Bash",
      content: { type: "any" },
    });
  });

  it("parses 'Tool(content)' as exact", () => {
    assert.deepEqual(parseRuleString("Bash(npm install)"), {
      toolName: "Bash",
      content: { type: "exact", value: "npm install" },
    });
  });

  it("parses legacy 'foo:*' as prefix", () => {
    assert.deepEqual(parseRuleString("Bash(npm:*)"), {
      toolName: "Bash",
      content: { type: "prefix", value: "npm" },
    });
  });

  it("parses wildcard 'foo *' as wildcard", () => {
    assert.deepEqual(parseRuleString("Bash(git *)"), {
      toolName: "Bash",
      content: { type: "wildcard", pattern: "git *" },
    });
  });

  it("parses wildcard in middle as wildcard", () => {
    assert.deepEqual(parseRuleString("Bash(git * status)"), {
      toolName: "Bash",
      content: { type: "wildcard", pattern: "git * status" },
    });
  });

  it("unescapes parentheses in content", () => {
    assert.deepEqual(parseRuleString('Bash(python -c "print\\(1\\)")'), {
      toolName: "Bash",
      content: { type: "exact", value: 'python -c "print(1)"' },
    });
  });

  it("returns null for malformed: open paren only", () => {
    assert.equal(parseRuleString("Bash("), null);
  });

  it("returns null for malformed: junk after closing paren", () => {
    assert.equal(parseRuleString("Bash(foo)bar"), null);
  });

  it("returns null for empty input", () => {
    assert.equal(parseRuleString(""), null);
    assert.equal(parseRuleString("   "), null);
  });

  it("returns null for tool name missing", () => {
    assert.equal(parseRuleString("(foo)"), null);
  });

  it("treats escaped parens as content, not delimiters", () => {
    // The closing paren is escaped, so the rule has no valid close → null.
    assert.equal(parseRuleString("Bash(foo\\)"), null);
  });
});

describe("serializeRule", () => {
  it("round-trips an exact rule", () => {
    const r = parseRuleString("Bash(npm install)")!;
    assert.equal(serializeRule(r), "Bash(npm install)");
  });

  it("round-trips a prefix rule", () => {
    const r = parseRuleString("Bash(npm:*)")!;
    assert.equal(serializeRule(r), "Bash(npm:*)");
  });

  it("round-trips a wildcard rule", () => {
    const r = parseRuleString("Bash(git *)")!;
    assert.equal(serializeRule(r), "Bash(git *)");
  });

  it("round-trips a tool-wide rule", () => {
    const r = parseRuleString("Bash")!;
    assert.equal(serializeRule(r), "Bash");
  });

  it("re-escapes parentheses in content", () => {
    const r = parseRuleString('Bash(python -c "print\\(1\\)")')!;
    assert.equal(serializeRule(r), 'Bash(python -c "print\\(1\\)")');
  });
});

describe("hasUnescapedWildcard", () => {
  it("detects unescaped *", () => {
    assert.equal(hasUnescapedWildcard("git *"), true);
    assert.equal(hasUnescapedWildcard("git*"), true);
    assert.equal(hasUnescapedWildcard("* run *"), true);
  });

  it("treats \\* as escaped", () => {
    assert.equal(hasUnescapedWildcard("git\\*"), false);
    assert.equal(hasUnescapedWildcard("foo \\* bar"), false);
  });

  it("treats \\\\* as unescaped (the \\ is escaped, * is free)", () => {
    assert.equal(hasUnescapedWildcard("git\\\\*"), true);
  });

  it("returns false when no stars", () => {
    assert.equal(hasUnescapedWildcard("npm install"), false);
    assert.equal(hasUnescapedWildcard(""), false);
  });
});

describe("escapeRuleContent / unescapeRuleContent", () => {
  it("round-trips parentheses", () => {
    const s = "psycopg2.connect()";
    assert.equal(unescapeRuleContent(escapeRuleContent(s)), s);
  });

  it("round-trips backslashes", () => {
    const s = 'echo "test\\nvalue"';
    assert.equal(unescapeRuleContent(escapeRuleContent(s)), s);
  });

  it("round-trips mixed", () => {
    const s = 'python -c "print(1)\\nprint(2)"';
    assert.equal(unescapeRuleContent(escapeRuleContent(s)), s);
  });
});
