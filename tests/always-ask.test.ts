import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import plugin, { ALWAYS_ASK_TOOLS } from "../src/plugin/index.js";

type Approval = { title: string; description: string; timeoutBehavior?: string; onResolution?: unknown };
type HookResult = { requireApproval?: Approval; block?: boolean } | undefined;

function makeHook(cfg: Record<string, unknown>) {
  let hook!: (event: unknown) => Promise<HookResult>;
  const api = {
    pluginConfig: { userRulesPath: join(mkdtempSync(join(tmpdir(), "ap-")), "permissions.json"), ...cfg },
    logger: { info() {}, warn() {} },
    on(_e: string, h: (event: unknown) => Promise<HookResult>) {
      hook = h;
    },
    registerTool() {},
  };
  (plugin.register as (a: unknown) => void)(api);
  return hook;
}

describe("always-ask tools", () => {
  it("names exactly the flow-authoring tools, flow_run, the schedule tool and rulespec_emit", () => {
    assert.deepEqual([...ALWAYS_ASK_TOOLS].sort(), ["flow_create", "flow_delete", "flow_edit", "flow_publish", "flow_run", "flow_trigger", "rulespec_emit"]);
  });

  it("rulespec_emit asks, even in an unattended session", async () => {
    const hook = makeHook({ defaultMode: "bypassPermissions", skipSessionPatterns: ["email"] });
    const res = await hook({ toolName: "rulespec_emit", params: {}, context: { sessionKey: "agent:main:main:email:1" } });
    assert.equal(res?.requireApproval?.title, "Emit rulespec to SKILL.md?");
    assert.equal(res!.requireApproval!.timeoutBehavior, "deny");
    assert.equal(res!.requireApproval!.onResolution, undefined, "must not be persistable");
  });

  it("flow_run asks unless it runs a published version, even in an unattended session", async () => {
    const ws = mkdtempSync(join(tmpdir(), "ap-ws-"));
    mkdirSync(join(ws, ".clawflow", "versions", "digest"), { recursive: true });
    writeFileSync(join(ws, ".clawflow", "versions", "digest", "2.json"), "{}");
    const prev = process.env.OPENCLAW_WORKSPACE;
    process.env.OPENCLAW_WORKSPACE = ws;
    try {
      const hook = makeHook({ defaultMode: "bypassPermissions", skipSessionPatterns: ["email"] });
      const title = async (params: Record<string, unknown>) =>
        (await hook({ toolName: "flow_run", params, context: { sessionKey: "agent:main:main:email:1" } }))?.requireApproval?.title;
      // Code no one approved asks.
      assert.equal(await title({ flow: { flow: "x", nodes: [{ name: "a", do: "exec", command: "id" }] } }), "Run an inline flow?");
      assert.equal(await title({ file: "digest", draft: true }), 'Run the draft of flow "digest"?');
      assert.equal(await title({ file: "fresh" }), 'Run flow "fresh", which has no published version?');
      assert.equal(await title({ file: "digest", version: 3 }), 'Run flow "digest" v3, which is not published?');
      // A file wins over an inline flow, as in clawflow.
      assert.equal(await title({ file: "fresh", flow: { flow: "x", nodes: [] } }), 'Run flow "fresh", which has no published version?');
      // A published version was approved at flow_publish and runs without asking.
      assert.equal(await title({ file: "digest" }), undefined);
      assert.equal(await title({ file: "flows/digest.json", version: 2 }), undefined);
    } finally {
      if (prev === undefined) delete process.env.OPENCLAW_WORKSPACE;
      else process.env.OPENCLAW_WORKSPACE = prev;
    }
  });

  it("flow_trigger: every action that changes or fires a schedule asks; list is a read", async () => {
    const hook = makeHook({ defaultMode: "bypassPermissions" });
    for (const [action, verb] of [
      ["create", "Schedule"],
      ["update", "Reschedule"],
      ["delete", "Unschedule"],
      ["pause", "Pause the schedule for"],
      ["resume", "Resume the schedule for"],
      ["run_now", "Run now"],
    ] as const) {
      const res = await hook({ toolName: "flow_trigger", params: { action, id: "trg_1" }, context: {} });
      assert.ok(res?.requireApproval, `flow_trigger ${action} must require approval`);
      assert.equal(res!.requireApproval!.title, `${verb} flow "trg_1"?`);
      assert.equal(res!.requireApproval!.onResolution, undefined);
    }
    const create = await hook({ toolName: "flow_trigger", params: { action: "create", flow: "digest" }, context: {} });
    assert.equal(create!.requireApproval!.title, 'Schedule flow "digest"?');
    assert.equal(await hook({ toolName: "flow_trigger", params: { action: "list" }, context: {} }), undefined);
    assert.equal(await hook({ toolName: "flow_trigger", params: {}, context: {} }), undefined);
  });

  it("asks even in bypassPermissions, and the approval is never remembered", async () => {
    const hook = makeHook({ defaultMode: "bypassPermissions" });
    for (const [tool, verb] of [
      ["flow_create", "Create"],
      ["flow_edit", "Edit"],
      ["flow_publish", "Publish"],
      ["flow_delete", "Delete"],
    ] as const) {
      const res = await hook({ toolName: tool, params: { flow: "my-flow" }, context: { sessionKey: "agent:main:main" } });
      assert.ok(res?.requireApproval, `${tool} must require approval`);
      assert.equal(res!.requireApproval!.title, `${verb} flow "my-flow"?`);
      assert.equal(res!.requireApproval!.timeoutBehavior, "deny");
      assert.equal(res!.requireApproval!.onResolution, undefined, "must not be persistable");
      assert.ok(res!.requireApproval!.description.length <= 256);
    }
  });

  it("does not honour skipSessionPatterns: an unattended session cannot publish silently", async () => {
    const hook = makeHook({ defaultMode: "default", skipSessionPatterns: ["email"] });
    const res = await hook({ toolName: "flow_publish", params: { file: "x.flow.json" }, context: { sessionKey: "agent:main:main:email:1" } });
    assert.ok(res?.requireApproval, "must still ask in a skipped session");
    assert.equal(res!.requireApproval!.title, 'Publish flow "x.flow.json"?');
  });

  it("clamps a long flow name to the gateway's title cap", async () => {
    const hook = makeHook({});
    const res = await hook({ toolName: "flow_create", params: { flow: "x".repeat(200) }, context: {} });
    assert.ok(res?.requireApproval);
    assert.ok(res!.requireApproval!.title.length <= 80);
  });

  it("leaves a published flow_run and unrelated tools to the rules", async () => {
    const ws = mkdtempSync(join(tmpdir(), "ap-ws-"));
    mkdirSync(join(ws, ".clawflow", "versions", "f"), { recursive: true });
    writeFileSync(join(ws, ".clawflow", "versions", "f", "1.json"), "{}");
    const prev = process.env.OPENCLAW_WORKSPACE;
    process.env.OPENCLAW_WORKSPACE = ws;
    try {
      const hook = makeHook({ defaultMode: "default" });
      assert.equal(await hook({ toolName: "flow_run", params: { file: "f" }, context: {} }), undefined);
      assert.equal(await hook({ toolName: "flow_list", params: {}, context: {} }), undefined);
    } finally {
      if (prev === undefined) delete process.env.OPENCLAW_WORKSPACE;
      else process.env.OPENCLAW_WORKSPACE = prev;
    }
  });
});
