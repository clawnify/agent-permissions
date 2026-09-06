import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync } from "node:fs";
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
  it("names exactly the flow-authoring tools; flow_run is the operator's opt-in elsewhere", () => {
    assert.deepEqual([...ALWAYS_ASK_TOOLS].sort(), ["flow_create", "flow_delete", "flow_edit", "flow_publish"]);
    assert.ok(!ALWAYS_ASK_TOOLS.includes("flow_run"));
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

  it("leaves flow_run and unrelated tools to the rules", async () => {
    const hook = makeHook({ defaultMode: "default" });
    assert.equal(await hook({ toolName: "flow_run", params: { file: "f" }, context: {} }), undefined);
    assert.equal(await hook({ toolName: "flow_list", params: {}, context: {} }), undefined);
  });
});
