import { afterEach, describe, it, mock } from "node:test";
import { strict as assert } from "node:assert";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import plugin, { ALWAYS_ASK_TOOLS } from "../src/plugin/index.js";
import { PERMISSION_AUTHORITY_SYMBOL } from "../src/api/symbol.js";
import type { AuthorityRequest } from "../src/api/types.js";

type Approval = { title: string; description: string; timeoutBehavior?: string; onResolution?: unknown; allowedDecisions?: string[] };
type HookResult = { requireApproval?: Approval; block?: boolean; blockReason?: string } | undefined;
type Hook = (event: unknown, ctx?: unknown) => Promise<HookResult>;

function makeHook(cfg: Record<string, unknown>) {
  let hook!: Hook;
  const api = {
    pluginConfig: { userRulesPath: join(mkdtempSync(join(tmpdir(), "ap-")), "permissions.json"), ...cfg },
    logger: { info() {}, warn() {} },
    on(_e: string, h: Hook) {
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
      const res = await hook({ toolName: tool, params: { flow: "my-flow", file: "my-flow" }, context: { sessionKey: "agent:main:main" } });
      assert.ok(res?.requireApproval, `${tool} must require approval`);
      assert.equal(res!.requireApproval!.title, `${verb} flow "my-flow"?`);
      assert.equal(res!.requireApproval!.timeoutBehavior, "deny");
      assert.equal(res!.requireApproval!.onResolution, undefined, "must not be persistable");
      assert.ok(res!.requireApproval!.description.length <= 256);
      // With no permission authority nothing can pre-approve it: the prompt says so and offers no "always".
      assert.match(res!.requireApproval!.description, /Approve once \(not remembered\); no rule can pre-approve this\.$/);
      assert.deepEqual(res!.requireApproval!.allowedDecisions, ["allow-once", "deny"]);
    }
  });

  it("flow_edit asks only when it writes a flow file", async () => {
    const hook = makeHook({ defaultMode: "bypassPermissions" });
    const edit = (params: Record<string, unknown>) => hook({ toolName: "flow_edit", params, context: {} });
    const inline = { flow: "x", nodes: [{ name: "a", do: "exec", command: "id" }] };
    // An edit of an inline definition returns the changed definition and writes nothing.
    assert.equal(await edit({ action: "add", flow: inline, nodeDefinition: { name: "b", do: "code", run: "1" } }), undefined);
    assert.equal(await edit({ action: "set", flow: inline, fields: { description: "d" } }), undefined);
    // Listing reads, with a file or without.
    assert.equal(await edit({ action: "list", file: "digest" }), undefined);
    assert.equal(await edit({ action: "list", flow: inline }), undefined);
    // Every action on a file writes it (revert too), and a file wins over an inline flow, as in clawflow.
    for (const action of ["set", "update", "add", "remove", "move", "wrap", "revert"]) {
      const res = await edit({ action, file: "digest" });
      assert.equal(res?.requireApproval?.title, 'Edit flow "digest"?', action);
    }
    assert.equal((await edit({ action: "add", file: "digest", flow: inline }))?.requireApproval?.title, 'Edit flow "digest"?');
    // An action this version does not know is treated as one that writes.
    assert.ok((await edit({ action: "rename", file: "digest" }))?.requireApproval);
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

describe("a permission authority", () => {
  const slot = globalThis as Record<symbol, unknown>;
  const publish = (authority: unknown) => {
    slot[PERMISSION_AUTHORITY_SYMBOL] = authority;
  };
  afterEach(() => {
    delete slot[PERMISSION_AUTHORITY_SYMBOL];
    mock.timers.reset();
  });
  const create = { toolName: "flow_create", params: { flow: "digest", file: "digest", nodes: [] }, toolCallId: "call_1" };
  const NOT_REMEMBERED = /no rule can pre-approve this\.$/;

  it("is asked about the call under the rule it is filed under, with the prompt and the call's ids", async () => {
    const asked: AuthorityRequest[] = [];
    publish((req: AuthorityRequest) => {
      asked.push(req);
      return { bucket: "ask" };
    });
    const hook = makeHook({ defaultMode: "bypassPermissions" });
    await hook(create, { sessionKey: "agent:main:main", runId: "run_1" });
    assert.deepEqual(asked, [
      {
        kind: "flow",
        subject: "write",
        toolName: "flow_create",
        toolCallId: "call_1",
        runId: "run_1",
        sessionKey: "agent:main:main",
        title: 'Create flow "digest"?',
        description: "A flow is code the agent runs later, with HTTP, exec and agent steps.",
      },
    ]);
  });

  it("files each always-ask tool under one rule", async () => {
    const filed: Record<string, string> = {};
    publish((req: AuthorityRequest) => {
      filed[`${req.toolName}${req.title.startsWith("Run now") ? " run_now" : ""}`] = `${req.kind}:${req.subject}`;
      return { bucket: "ask" };
    });
    const hook = makeHook({});
    for (const [toolName, params] of [
      ["flow_create", { flow: "f", file: "f" }],
      ["flow_edit", { action: "add", file: "f" }],
      ["flow_publish", { file: "f" }],
      ["flow_delete", { file: "f" }],
      ["flow_run", { flow: { flow: "f", nodes: [] } }],
      ["flow_trigger", { action: "create", flow: "f" }],
      ["flow_trigger", { action: "run_now", id: "trg_1" }],
      ["rulespec_emit", {}],
    ] as const) {
      await hook({ toolName, params });
    }
    assert.deepEqual(filed, {
      flow_create: "flow:write",
      flow_edit: "flow:write",
      flow_publish: "flow:publish",
      flow_delete: "flow:delete",
      flow_run: "flow:run_unpublished",
      flow_trigger: "flow:schedule",
      "flow_trigger run_now": "flow:schedule",
      rulespec_emit: "rulespec:emit",
    });
  });

  it("runs the call on an explicit allow, in an unattended session too", async () => {
    publish(async () => ({ bucket: "allow" }));
    const hook = makeHook({ defaultMode: "default" });
    assert.equal(await hook(create, { sessionKey: "agent:main:main" }), undefined);
    assert.equal(await hook({ toolName: "flow_publish", params: { file: "digest" } }, { sessionKey: "agent:main:hook:email:1" }), undefined);
  });

  it("blocks the call on a deny, naming the rule or the reason", async () => {
    publish(() => ({ bucket: "deny", rule: "*" }));
    const hook = makeHook({});
    const byRule = await hook(create);
    assert.equal(byRule?.block, true);
    assert.equal(byRule?.blockReason, "flow:write blocked by rule '*'");
    assert.equal(byRule?.requireApproval, undefined);
    publish(() => ({ bucket: "deny", reason: "Flows are off for this workspace." }));
    assert.equal((await hook(create))?.blockReason, "flow:write was stopped. Flows are off for this workspace.");
  });

  it("prompts on ask, and the prompt no longer says nothing can pre-approve it", async () => {
    publish(() => ({ bucket: "ask" }));
    const res = await makeHook({ defaultMode: "bypassPermissions" })(create);
    assert.equal(res?.requireApproval?.title, 'Create flow "digest"?');
    assert.match(res!.requireApproval!.description, /Asks every time until a rule allows it\.$/);
    // Every answer is offered: the authority is the one that can remember an "always".
    assert.equal(res!.requireApproval!.allowedDecisions, undefined);
    assert.equal(res!.requireApproval!.onResolution, undefined, "this plugin still remembers nothing");
    assert.equal(res!.requireApproval!.timeoutBehavior, "deny");
  });

  it("prompts when the authority throws, rejects, answers nothing or nonsense, or is not a function", async () => {
    const hook = makeHook({ defaultMode: "bypassPermissions" });
    for (const authority of [
      () => {
        throw new Error("boom");
      },
      async () => {
        throw new Error("unreachable");
      },
      () => ({ bucket: "maybe" }),
      () => ({ bucket: "ALLOW" }),
      () => ({}),
      () => null,
      async () => undefined,
      () => "allow",
      "allow",
      { bucket: "allow" },
    ]) {
      publish(authority);
      const res = await hook(create);
      assert.ok(res?.requireApproval, `must ask: ${String(authority)}`);
      assert.match(res!.requireApproval!.description, NOT_REMEMBERED);
      assert.deepEqual(res!.requireApproval!.allowedDecisions, ["allow-once", "deny"]);
      assert.notEqual(res?.block, true);
    }
  });

  it("prompts when the authority has not answered in time, instead of leaving the call to the host's hook timeout", async () => {
    mock.timers.enable({ apis: ["setTimeout"] });
    publish(() => new Promise(() => {}));
    const pending = makeHook({ defaultMode: "bypassPermissions" })(create);
    mock.timers.tick(11_999);
    let settled = false;
    void pending.then(() => {
      settled = true;
    });
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(settled, false, "still waiting just before the limit");
    mock.timers.tick(1);
    const res = await pending;
    assert.ok(res?.requireApproval);
    assert.match(res!.requireApproval!.description, NOT_REMEMBERED);
  });

  it("is not asked when a deny rule of this plugin already blocks the call", async () => {
    let asked = 0;
    publish(() => {
      asked++;
      return { bucket: "allow" };
    });
    const res = await makeHook({ deny: ["flow_create"] })(create);
    assert.equal(res?.block, true);
    assert.equal(asked, 0);
  });

  it("is not asked about a call that needs no approval, or about a tool outside the always-ask set", async () => {
    let asked = 0;
    publish(() => {
      asked++;
      return { bucket: "deny" };
    });
    const hook = makeHook({ defaultMode: "default" });
    assert.equal(await hook({ toolName: "flow_trigger", params: { action: "list" } }), undefined);
    assert.equal(await hook({ toolName: "flow_edit", params: { action: "add", flow: { flow: "x", nodes: [] } } }), undefined);
    assert.equal(await hook({ toolName: "flow_list", params: {} }), undefined);
    assert.equal(await hook({ toolName: "bash", params: { command: "ls" } }), undefined);
    assert.equal(asked, 0);
  });

  it("is read at each call, so it can be published after this plugin loads and withdrawn later", async () => {
    const hook = makeHook({ defaultMode: "bypassPermissions" });
    assert.ok((await hook(create))?.requireApproval);
    publish(() => ({ bucket: "allow" }));
    assert.equal(await hook(create), undefined);
    publish(undefined);
    assert.ok((await hook(create))?.requireApproval);
  });

  it("never settles permissions_set: an agent changing its own rules always asks", async () => {
    let asked = 0;
    publish(() => {
      asked++;
      return { bucket: "allow" };
    });
    const res = await makeHook({})({ toolName: "permissions_set", params: { allow: ["bash(rm *)"] } });
    assert.equal(res?.requireApproval?.title, "Modify permission rules?");
    assert.equal(asked, 0);
  });
});
