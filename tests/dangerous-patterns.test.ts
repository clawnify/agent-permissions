import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import {
  DEFAULT_DANGEROUS_PATTERNS,
  isDangerousRuleContent,
} from "../src/engine/dangerous-patterns.js";

describe("isDangerousRuleContent", () => {
  const patterns = DEFAULT_DANGEROUS_PATTERNS;

  it("flags exact interpreter prefix", () => {
    assert.equal(isDangerousRuleContent("python", patterns), true);
    assert.equal(isDangerousRuleContent("node", patterns), true);
    assert.equal(isDangerousRuleContent("eval", patterns), true);
  });

  it("flags legacy :* form", () => {
    assert.equal(isDangerousRuleContent("python:*", patterns), true);
    assert.equal(isDangerousRuleContent("curl:*", patterns), true);
  });

  it("flags wildcard-with-args form", () => {
    assert.equal(isDangerousRuleContent("python *", patterns), true);
    assert.equal(isDangerousRuleContent("python -c *", patterns), true);
    assert.equal(isDangerousRuleContent("curl https://*", patterns), true);
  });

  it("flags adjacent-wildcard form", () => {
    assert.equal(isDangerousRuleContent("python*", patterns), true);
    assert.equal(isDangerousRuleContent("python3*", patterns), true);
  });

  it("does NOT flag specific safe invocations", () => {
    // Exact commands without wildcards are fine — the user is granting one
    // specific call, not arbitrary code under that interpreter.
    assert.equal(isDangerousRuleContent("python script.py", patterns), false);
    assert.equal(isDangerousRuleContent("curl https://example.com/safe", patterns), false);
  });

  it("does NOT flag empty / undefined content (tool-wide rules)", () => {
    assert.equal(isDangerousRuleContent(undefined, patterns), false);
    assert.equal(isDangerousRuleContent("", patterns), false);
    assert.equal(isDangerousRuleContent("   ", patterns), false);
  });

  it("does NOT flag unrelated commands", () => {
    assert.equal(isDangerousRuleContent("git status", patterns), false);
    assert.equal(isDangerousRuleContent("npm install", patterns), false);
    assert.equal(isDangerousRuleContent("ls -la", patterns), false);
  });

  it("honors a custom pattern list", () => {
    assert.equal(isDangerousRuleContent("safe-thing:*", ["safe-thing"]), true);
    assert.equal(isDangerousRuleContent("python:*", ["safe-thing"]), false);
  });

  it("multi-word patterns work (e.g. 'npm run')", () => {
    assert.equal(isDangerousRuleContent("npm run:*", patterns), true);
    assert.equal(isDangerousRuleContent("npm run *", patterns), true);
    // But the more specific `npm run build` exact is not dangerous.
    assert.equal(isDangerousRuleContent("npm run build", patterns), false);
  });
});
