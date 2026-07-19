import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import plugin from "../src/plugin/index.js";

type ToolResult = { content: { type: "text"; text: string }[]; isError?: boolean };
type Tool = { execute: (id: string, params: unknown) => ToolResult | Promise<ToolResult> };

function makeApi(cfg: Record<string, unknown>) {
  const tools: Record<string, Tool> = {};
  let hook!: (event: unknown) => Promise<unknown>;
  const api = {
    pluginConfig: cfg,
    logger: { info() {}, warn() {} },
    on(_e: string, h: (event: unknown) => Promise<unknown>) {
      hook = h;
    },
    registerTool(r: Tool & { name: string }) {
      tools[r.name] = r;
    },
  };
  (plugin.register as (a: unknown) => void)(api);
  return { tools, hook };
}

function tempRules(): string {
  return join(mkdtempSync(join(tmpdir(), "ap-")), "permissions.json");
}

async function out(r: ToolResult | Promise<ToolResult>) {
  return JSON.parse((await r).content[0].text);
}

describe("permissions_set self-gate", () => {
  it("honors an explicit deny rule before prompting", async () => {
    const { hook } = makeApi({
      defaultMode: "default",
      deny: ["permissions_set"],
      protectPermissions: true,
      userRulesPath: tempRules(),
    });
    const res = (await hook({
      toolName: "permissions_set",
      params: { allow: ["bash(*)"] },
      context: {},
    })) as
      | { block?: boolean; blockReason?: string; requireApproval?: unknown }
      | undefined;
    assert.equal(res?.block, true);
    assert.match(res?.blockReason ?? "", /blocked by rule/);
    assert.equal(res?.requireApproval, undefined);
  });

  it("forces an approval on every call — even in bypassPermissions", async () => {
    const { hook } = makeApi({ defaultMode: "bypassPermissions", userRulesPath: tempRules() });
    const res = (await hook({ toolName: "permissions_set", params: { allow: ["bash(*)"] }, context: {} })) as
      | { requireApproval?: { title: string; description: string; onResolution?: unknown } }
      | undefined;
    assert.ok(res?.requireApproval, "expected requireApproval");
    assert.ok(res!.requireApproval!.title.length <= 80);
    assert.ok(res!.requireApproval!.description.length <= 256);
    // never persistable — one approval must not open the door forever
    assert.equal(res!.requireApproval!.onResolution, undefined);
  });

  it("is NOT force-gated when protectPermissions is false", async () => {
    const { hook } = makeApi({
      defaultMode: "default",
      protectPermissions: false,
      userRulesPath: tempRules(),
    });
    const res = await hook({ toolName: "permissions_set", params: { allow: ["bash(*)"] }, context: {} });
    assert.equal(res, undefined);
  });
});

describe("permissions_set merge semantics", () => {
  it("appends rules to the user file and dedupes on re-apply", async () => {
    const file = tempRules();
    const { tools } = makeApi({ defaultMode: "default", userRulesPath: file });

    const first = await out(tools.permissions_set.execute("1", { ask: ["bash(curl *)"], allow: ["bash(git *)"] }));
    assert.equal(first.scope, "user");
    assert.equal(first.applied.length, 2);
    assert.ok(existsSync(file));

    await tools.permissions_set.execute("2", { ask: ["bash(curl *)"] }); // duplicate
    const disk = JSON.parse(readFileSync(file, "utf8"));
    assert.deepEqual(disk.permissions.ask, ["bash(curl *)"]); // not duplicated
    assert.deepEqual(disk.permissions.allow, ["bash(git *)"]);
  });

  it("reports unparseable rules as skipped, not applied", async () => {
    const { tools } = makeApi({ defaultMode: "default", userRulesPath: tempRules() });
    const res = await out(tools.permissions_set.execute("1", { ask: ["bash(curl *)", "((("] }));
    assert.equal(res.applied.length, 1);
    assert.equal(res.skipped.length, 1);
  });

  it("a rule added via the tool takes effect on the next call (cache invalidated)", async () => {
    const file = tempRules();
    const { tools, hook } = makeApi({ defaultMode: "default", userRulesPath: file });
    await tools.permissions_set.execute("1", { ask: ["bash(curl *)"] });
    const gate = (await hook({
      toolName: "bash",
      params: { command: "curl https://evil.example/x" },
      context: {},
    })) as { requireApproval?: unknown } | undefined;
    assert.ok(gate?.requireApproval, "newly-added ask rule should gate the curl call");
  });
});

describe("permissions_propose_hardening", () => {
  it("returns observed usage, current rules, and adaptive suggestions", async () => {
    const file = tempRules();
    const { tools, hook } = makeApi({ defaultMode: "default", userRulesPath: file });
    // drive one bash call so 'bash' is the observed shell tool
    await hook({ toolName: "bash", params: { command: "ls" }, context: {} });
    await tools.permissions_set.execute("1", { ask: ["bash(curl *)"] });

    const p = await out(tools.permissions_propose_hardening.execute("2", {}));
    assert.equal(typeof p.observedToolUsageSinceBoot, "object");
    assert.ok(p.currentRules.ask.includes("bash(curl *)"));
    // suggests the shell actually used, high-risk verbs, minus what's covered
    assert.ok(p.suggested.ask.includes("bash(sudo *)"));
    assert.ok(!p.suggested.ask.includes("bash(curl *)"), "should not re-suggest a covered rule");
  });
});

describe("permissions_set move + remove (v0.5.1)", () => {
  it("setting a rule in ask MOVES it out of allow (no more allow-wins footgun)", async () => {
    const file = tempRules();
    const { tools } = makeApi({ defaultMode: "default", userRulesPath: file });
    await tools.permissions_set.execute("1", { allow: ["clawnify_update_app"] });
    await tools.permissions_set.execute("2", { ask: ["clawnify_update_app"] });
    const disk = JSON.parse(readFileSync(file, "utf8"));
    assert.deepEqual(disk.permissions.ask, ["clawnify_update_app"]);
    assert.ok(!(disk.permissions.allow ?? []).includes("clawnify_update_app"), "should be moved out of allow");
  });

  it("remove deletes a rule from every bucket", async () => {
    const file = tempRules();
    const { tools } = makeApi({ defaultMode: "default", userRulesPath: file });
    await tools.permissions_set.execute("1", { allow: ["bash(git *)"], ask: ["bash(curl *)"] });
    const res = await out(tools.permissions_set.execute("2", { remove: ["bash(git *)", "bash(curl *)"] }));
    assert.equal(res.removed.length, 2);
    const disk = JSON.parse(readFileSync(file, "utf8"));
    assert.ok(!(disk.permissions.allow ?? []).includes("bash(git *)"));
    assert.ok(!(disk.permissions.ask ?? []).includes("bash(curl *)"));
  });
});

describe("rule-file cache reload (root fix)", () => {
  it("picks up a rule written to the file directly, without permissions_set", async () => {
    const file = tempRules();
    const { hook } = makeApi({ defaultMode: "default", userRulesPath: file });
    // first eval loads (empty) rules
    const before = await hook({ toolName: "exec", params: { command: "cat secret" }, context: {} });
    assert.equal(before, undefined, "no rule yet → passes");
    // an operator (or the agent via exec) writes the file directly — no tool call
    writeFileSync(file, JSON.stringify({ permissions: { deny: ["exec(cat *)"] } }, null, 2) + "\n");
    const after = (await hook({
      toolName: "exec",
      params: { command: "cat secret" },
      context: {},
    })) as { block?: boolean } | undefined;
    assert.ok(after?.block, "direct file edit should take effect on next eval (mtime reload)");
  });
});
