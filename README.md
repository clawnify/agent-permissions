# @clawnify/agent-permissions

OpenClaw plugin — permission and approval engine for **any OpenClaw agent**.

Gates built-in tool calls (bash, file edit, web fetch, etc.) and any plugin-
registered tool through a three-bucket policy (`allow` / `deny` / `ask`),
with rule sources walked in priority order, in-chat approval surfaced via
OpenClaw's native `requireApproval`, and learning into `allow-always` rules.

**MIT licensed. Maintained by Clawnify, designed for the wider OpenClaw
ecosystem — works in any gateway with any agent setup.**

## Installation

```bash
openclaw plugins install @clawnify/agent-permissions --pin
```

Or via npm:

```bash
npm install @clawnify/agent-permissions
```

Then enable in `openclaw.json`:

```jsonc
{
  "plugins": {
    "allow": ["agent-permissions", "your-consumer-plugin"],
    "entries": {
      "agent-permissions": {
        "enabled": true,
        "config": {
          "defaultMode": "default",
          "ask": ["Bash(*)"],
          "deny": ["Bash(rm -rf /:*)"],
          // Auto-allow `ask` decisions in unattended sessions (no operator to
          // prompt); `deny` is still enforced. Matched as substrings of the
          // session key. Empty by default.
          "skipSessionPatterns": ["hook:email", "webhook", "cron"]
        }
      }
    },
    "load": {
      "paths": [
        "/path/to/agent-permissions",
        "/path/to/your-consumer-plugin"
      ]
    }
  }
}
```

`agent-permissions` must load **before** any consumer plugin (list it first
in `plugins.load.paths`) so the registration API is available when consumer
`register()` runs.

## Why this exists

OpenClaw's built-in permission infrastructure today is:

- **Gateway-level exec-approval** for `bash` — coarse, command-shape rules
- **`registerTrustedToolPolicy`** — bundled-only; external plugins can't use it

Non-bundled plugins that want to gate their own tools (or gate other plugins'
tools) have no host-level seam. They either reinvent approval per-plugin or
ship without it. This engine fills that gap.

Single global `before_tool_call` hook + an extension point so any plugin can
participate without each one rebuilding the policy / approval / learning loop.

## What it does

| Capability | How |
|---|---|
| Gates **any tool call** in the gateway | Single global `before_tool_call` hook at priority 100 (verified upstream sort direction in `src/plugins/hooks.ts:266`) |
| Built-in tools (bash, file edit, web fetch, …) supported out of the box | Generic resolver: shell tools (`bash`/`exec`) match against the actual command; everything else matches by tool name. No registration required. |
| Other plugins' tools supported | Same generic path — operators add rules in `openclaw.json` targeting the tool name. Plugins don't need to know about us. |
| Optional rich prompts | Consumer plugins MAY call `registerResolver({ toolName, resolve })` for tool-specific prompt titles/descriptions. Opt-in. |
| Three-bucket policy | `allow` / `deny` / `ask` evaluated against rule sources in priority order |
| In-chat approval | Uses OpenClaw's native `requireApproval` — same UI as exec approvals |
| Learning | `allow-always` resolutions persist to user/local/session as configured |
| Wildcard rules | `Tool(foo)` exact, `Tool(foo:*)` legacy prefix, `Tool(foo *)` new wildcard |
| Dangerous-pattern denylist | Patterns like `python:*`, `node:*`, `eval` cannot be allow-always-persisted |
| Fail-closed | OpenClaw's hook runner catches exceptions and fails open — this plugin wraps every code path in try/catch and returns `{ block: true }` instead |

## `allow-always` semantic — operator-scoped, transparent

When a user clicks "always" on an approval prompt, the persisted rule is
**the pattern of the rule that triggered the ask**, not the exact call.
That means operators control the breadth at config time by choosing how
specific their `ask` rules are:

```jsonc
"ask": ["clawnify_action(*_SEND*)"]   →  one "always" click allows ALL *_SEND* actions
"ask": ["clawnify_action(GMAIL_*)"]   →  one "always" click allows ALL Gmail actions
"ask": ["clawnify_action(GMAIL_SEND_EMAIL)"]  →  one "always" click allows only that slug
```

Each `ask` pattern → one possible "always" click → the rule is moved from
`ask` to `allow` for future calls. Scales linearly with rule patterns,
not with action count.

The prompt description shows the rule that will be persisted, so there's
no surprise broadening:

```
Run clawnify_action (GMAIL_SEND_EMAIL)?

Params: {...}

Matched: rule 'clawnify_action(*_SEND*)' from config settings

'Always' will allow: `clawnify_action(*_SEND*)`
```

The `dangerousPatterns` denylist is checked against the rule that would
be persisted — so if a matched rule contains a dangerous prefix (e.g.
`Bash(curl *)`), allow-always is refused regardless of which specific
call triggered the prompt.

If no rule matched (only happens under `strict` mode where everything
asks), allow-always persists the exact call.

## Per-tool content extraction (`paramKeys`)

For tools where the policy-relevant content lives in a param (e.g.
Composio's `clawnify_action` takes `{ slug, args }` and you want to gate
on the slug), configure `paramKeys` in `openclaw.json`:

```jsonc
"agent-permissions": {
  "config": {
    "paramKeys": {
      "clawnify_action": "slug",
      "clawnify_call_app_api": "method"
    },
    "ask": [
      "clawnify_action(*_DELETE*)",
      "clawnify_action(*_SEND*)",
      "clawnify_call_app_api(POST)",
      "clawnify_call_app_api(DELETE)"
    ],
    "allow": [
      "clawnify_action(GMAIL_EMAIL_LIST)",
      "clawnify_action(GMAIL_EMAIL_GET)"
    ]
  }
}
```

With the map above:

- `clawnify_action({ slug: "GMAIL_SEND_EMAIL" })` → matches `clawnify_action(*_SEND*)` → asks
- `clawnify_action({ slug: "GMAIL_EMAIL_LIST" })` → matches the explicit allow → passes
- `clawnify_action({ slug: "GMAIL_EMAIL_DELETE" })` → matches `clawnify_action(*_DELETE*)` → asks

No consumer-plugin awareness needed. Wildcard semantics (`*` matches any
chars), prefix legacy (`foo:*`), and exact matching all apply to the
extracted content. Falls back to existing behavior (built-in extractor
for shell tools, tool-wide otherwise) when no `paramKeys` entry exists.

## Default modes

- **`default`** (out of the box) — operator-opt-in: tools pass through unless an `ask` or `deny` rule explicitly matches. No surprises; you add rules for what you want gated.
- **`strict`** — Claude-Code style: ask on anything not explicitly allowed. Opt-in for hard-gate setups.
- **`bypassPermissions`** / **`dontAsk`** — allow everything except matching `deny` rules.
- **`acceptEdits`** — currently behaves like `default`. Reserved for future tool-category-aware behavior (auto-allow edits within CWD).

## What it does NOT do

- **Network calls.** Storage is local files. Consumers that want cloud sync
  can hook `onAllowAlwaysPersisted` and mirror to their own backend.
- **Tool-specific logic.** Each tool's rule-content + prompt text comes from
  a resolver, not from this engine. The engine is tool-agnostic.

## Architecture

```
┌─── OpenClaw gateway process ────────────────────────────────────────┐
│                                                                     │
│  Consumer plugin (e.g. agent-tools, clawflow, third-party)          │
│   └─ on register():                                                 │
│        getAgentPermissionsApi().registerResolver({                  │
│          toolName: "some_tool",                                     │
│          resolve(params) {                                          │
│            return { ruleContent: "delete", title, description };    │
│          },                                                         │
│        })                                                           │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ agent-permissions (this plugin)                              │  │
│  │                                                              │  │
│  │  before_tool_call hook (priority: 100)                       │  │
│  │   ├─ resolver = resolvers.get(event.toolName)                │  │
│  │   ├─ req = resolver(event.params)                            │  │
│  │   ├─ decision = ruleEngine.evaluate(toolName, ruleContent)   │  │
│  │   ├─ bucket "deny"  → { block: true, blockReason }           │  │
│  │   ├─ bucket "ask"   → { requireApproval: {...} }             │  │
│  │   ├─ bucket "allow" → undefined (proceed)                    │  │
│  │   └─ try/catch wrapper → { block: true } on any error        │  │
│  │                                                              │  │
│  │  rule sources walked in priority order:                      │  │
│  │   1. session (in-memory, allow-always with scope:session)    │  │
│  │   2. local   (.openclaw/permissions.json in CWD)             │  │
│  │   3. user    (~/.openclaw/permissions.json)                  │  │
│  │   4. config  (pluginConfig.allow/deny/ask from openclaw.json)│  │
│  │                                                              │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Rule format

Same shape as Anthropic's Claude Code permission system (studied as prior
art).

| Rule | Meaning |
|---|---|
| `ToolName` | Tool-wide rule (any params match). |
| `ToolName(*)` | Equivalent to tool-wide (empty / `*` content). |
| `Bash(npm install)` | Exact match on `(content)`. |
| `Bash(npm:*)` | Legacy prefix syntax — matches `npm`, `npm install`, etc. |
| `Bash(git *)` | Wildcard — `*` matches any chars. Trailing ` *` makes trailing args optional, so `git *` matches both `git add` and bare `git`. |
| `Bash(python -c "print\\(1\\)")` | Escape `(`, `)` in content with `\`. Escape `*` with `\*`. Escape `\` with `\\`. |

## Dangerous patterns

`dangerousPatterns` config (defaults built in) lists prefixes that may match
`ask` rules but can **never** be allow-always-persisted, even if the user
clicks "allow always." Reason: granting `Bash(python:*)` = arbitrary code
execution, which defeats the gate entirely.

Default list (conservative):

```
python python3 python2 node deno tsx ruby perl php lua
npx bunx npm run yarn run pnpm run bun run
bash sh zsh fish
eval exec env xargs sudo ssh
curl wget
```

Override `dangerousPatterns` in `openclaw.json` to extend or replace.

## Inter-plugin API (runtime)

```ts
import { getAgentPermissionsApi } from "@clawnify/agent-permissions";

// In your consumer plugin's register():
const perms = getAgentPermissionsApi(); // throws if agent-permissions not loaded

perms.registerResolver({
  toolName: "my_dangerous_tool",
  resolve(params) {
    const p = params as { target?: string };
    return {
      ruleContent: "delete",
      title: `Delete ${p.target ?? "?"}?`,
      description: "This is irreversible.",
    };
  },
});

perms.onAllowAlwaysPersisted(async (event) => {
  // Optional: mirror to your own backend, audit, etc.
});
```

The plugin publishes its API on `globalThis[Symbol.for("clawnify.agent-permissions.api.v1")]`,
so consumers find it at runtime even when each plugin ships as an independent
tarball with no shared `node_modules`. The `getAgentPermissionsApi()` helper
wraps the Symbol lookup with a descriptive error if the plugin isn't loaded
(typically a `plugins.load.paths` ordering issue).

## Development

```bash
git clone https://github.com/clawnify/agent-permissions.git
cd agent-permissions
npm install
npm run build
npm test
```

Tests use Node's built-in test runner via `tsx`. No vitest/jest setup.

## Permission hardening (agent-proposed, self-gated)

Changing the rule set is itself a **gated tool call**, not a file edit you hope to
intercept. Two tools (v0.5.0):

- **`permissions_propose_hardening`** *(read-only)* — returns observed tool usage
  (since boot), the current rules, and a suggested set of high-risk gates in
  `ToolName(pattern)` syntax. The agent reasons over this with the operator.
- **`permissions_set`** *(mutation)* — a rule lives in exactly **one** bucket, so
  setting it in `allow`/`deny`/`ask` **moves** it there (setting `ask` on a rule
  that was `allow` removes the `allow` — no more "allow silently wins over ask").
  A `remove` param deletes rules outright. Other rules are left untouched (merge,
  not replace). Defaults to **user scope** (`~/.openclaw/permissions.json`).

`permissions_set` is **self-gated**: when `protectPermissions` is on (the
default) every call forces an approval and can never be allow-always-persisted,
so an agent can only *request* a permission change — a human approves the diff.
Set `protectPermissions: false` to opt out (it then follows normal policy).

Rules edited on disk (by the tool, an operator, or a direct write) are picked up
**live** — the rule files are reloaded when their mtime changes, so no gateway
restart is needed for an edit to take effect.

> Tool names match **exactly and case-sensitively**. OpenClaw surfaces the shell
> as `bash` / `exec` (lowercase) — write shell rules as `bash(curl *)` /
> `exec(curl *)`, not `Bash(...)`.

## Releases

Tag a release on GitHub → `.github/workflows/publish.yml` runs `npm publish --provenance`.

## License

MIT.

---

Initiated and maintained by the [Clawnify](https://www.clawnify.com) team — AI agent hosting and orchestration.
