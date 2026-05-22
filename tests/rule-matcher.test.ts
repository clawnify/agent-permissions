import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import {
  evaluatePolicy,
  matchesRule,
  matchWildcard,
  type RuleSet,
} from "../src/engine/rule-matcher.js";
import { parseRuleString } from "../src/engine/rule-parser.js";

function rule(s: string) {
  const parsed = parseRuleString(s);
  if (!parsed) throw new Error(`bad rule in test: ${s}`);
  return parsed;
}

describe("matchWildcard", () => {
  it("matches a single trailing star with args", () => {
    assert.equal(matchWildcard("git *", "git add"), true);
    assert.equal(matchWildcard("git *", "git status -s"), true);
  });

  it("matches a single trailing star with NO args (trailing-space-star heuristic)", () => {
    assert.equal(matchWildcard("git *", "git"), true);
  });

  it("does not match a different command", () => {
    assert.equal(matchWildcard("git *", "npm install"), false);
  });

  it("multi-wildcard pattern does NOT get trailing-arg shortcut", () => {
    // `* run *` should NOT match `npm run` (the trailing wildcard must consume something).
    assert.equal(matchWildcard("* run *", "npm run dev"), true);
    assert.equal(matchWildcard("* run *", "npm run"), false);
  });

  it("matches escaped literal star", () => {
    assert.equal(matchWildcard("echo \\*", "echo *"), true);
    assert.equal(matchWildcard("echo \\*", "echo a"), false);
  });

  it("dotall matches across newlines", () => {
    assert.equal(matchWildcard("bash *", "bash -c 'echo a\necho b'"), true);
  });

  it("anchors to full string", () => {
    assert.equal(matchWildcard("git", "git status"), false);
    assert.equal(matchWildcard("git", "git"), true);
  });
});

describe("matchesRule", () => {
  it("matches exact content", () => {
    assert.equal(matchesRule(rule("Bash(npm install)"), "Bash", "npm install"), true);
    assert.equal(matchesRule(rule("Bash(npm install)"), "Bash", "npm uninstall"), false);
  });

  it("matches prefix legacy form", () => {
    const r = rule("Bash(git:*)");
    assert.equal(matchesRule(r, "Bash", "git"), true);
    assert.equal(matchesRule(r, "Bash", "git status"), true);
    assert.equal(matchesRule(r, "Bash", "git:foo"), true);
    assert.equal(matchesRule(r, "Bash", "github"), false);
  });

  it("matches wildcard form", () => {
    const r = rule("Bash(curl *)");
    assert.equal(matchesRule(r, "Bash", "curl"), true);
    assert.equal(matchesRule(r, "Bash", "curl https://example.com"), true);
    assert.equal(matchesRule(r, "Bash", "wget foo"), false);
  });

  it("tool-wide rule matches anything", () => {
    const r = rule("ClawnifyDeleteApp");
    assert.equal(matchesRule(r, "ClawnifyDeleteApp", "anything"), true);
    assert.equal(matchesRule(r, "ClawnifyDeleteApp", undefined), true);
    assert.equal(matchesRule(r, "Bash", "anything"), false);
  });
});

describe("evaluatePolicy", () => {
  function makeRules(opts: {
    allow?: string[];
    deny?: string[];
    ask?: string[];
  }): RuleSet {
    return {
      allow: (opts.allow ?? []).map((s) => ({ rule: rule(s), source: "config" as const })),
      deny: (opts.deny ?? []).map((s) => ({ rule: rule(s), source: "config" as const })),
      ask: (opts.ask ?? []).map((s) => ({ rule: rule(s), source: "config" as const })),
    };
  }

  it("returns deny when a deny rule matches", () => {
    const decision = evaluatePolicy({
      toolName: "Bash",
      ruleContent: "rm -rf /",
      rules: makeRules({ deny: ["Bash(rm -rf /)"] }),
      defaultMode: "default",
    });
    assert.equal(decision.bucket, "deny");
    assert.equal(decision.matchedRule?.source, "config");
  });

  it("returns allow when an allow rule matches and no deny", () => {
    const decision = evaluatePolicy({
      toolName: "Bash",
      ruleContent: "git status",
      rules: makeRules({ allow: ["Bash(git *)"] }),
      defaultMode: "default",
    });
    assert.equal(decision.bucket, "allow");
  });

  it("deny beats allow", () => {
    const decision = evaluatePolicy({
      toolName: "Bash",
      ruleContent: "git push --force",
      rules: makeRules({
        allow: ["Bash(git *)"],
        deny: ["Bash(git push --force)"],
      }),
      defaultMode: "default",
    });
    assert.equal(decision.bucket, "deny");
  });

  it("returns ask when an ask rule matches and no allow/deny", () => {
    const decision = evaluatePolicy({
      toolName: "Bash",
      ruleContent: "curl https://foo",
      rules: makeRules({ ask: ["Bash(curl *)"] }),
      defaultMode: "default",
    });
    assert.equal(decision.bucket, "ask");
  });

  it("falls back to ask under default mode when nothing matches", () => {
    const decision = evaluatePolicy({
      toolName: "Bash",
      ruleContent: "unknown",
      rules: makeRules({}),
      defaultMode: "default",
    });
    assert.equal(decision.bucket, "ask");
    assert.equal(decision.matchedRule, undefined);
  });

  it("falls back to allow under bypassPermissions mode", () => {
    const decision = evaluatePolicy({
      toolName: "Bash",
      ruleContent: "anything",
      rules: makeRules({}),
      defaultMode: "bypassPermissions",
    });
    assert.equal(decision.bucket, "allow");
  });

  it("bypassPermissions does NOT override an explicit deny", () => {
    const decision = evaluatePolicy({
      toolName: "Bash",
      ruleContent: "rm -rf /",
      rules: makeRules({ deny: ["Bash(rm -rf /:*)"] }),
      defaultMode: "bypassPermissions",
    });
    assert.equal(decision.bucket, "deny");
  });

  it("session rules beat config rules for the same call", () => {
    // Config says ask; session says allow → allow wins (session is earlier in priority).
    const rules: RuleSet = {
      allow: [{ rule: rule("Bash(git status)"), source: "session" }],
      deny: [],
      ask: [{ rule: rule("Bash(git status)"), source: "config" }],
    };
    const decision = evaluatePolicy({
      toolName: "Bash",
      ruleContent: "git status",
      rules,
      defaultMode: "default",
    });
    assert.equal(decision.bucket, "allow");
    assert.equal(decision.matchedRule?.source, "session");
  });
});
