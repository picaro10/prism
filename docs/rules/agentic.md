# Agentic rules (`AGT-*`) — weight 1.5×

Risks specific to code that builds or runs AI agents — PRISM's own territory; mainstream
analyzers don't model these failure modes. Every rule here is deliberately conservative and
carries an anti-self-detection guard (comments and regex/pattern definitions never fire —
a scanner must not flag itself).

| ID | Severity | What it detects |
|---|---|---|
| `AGT-001` | high | A shell command built with interpolation/concatenation (`exec`/`execSync` spawn a shell). |
| `AGT-002` | medium | An environment secret interpolated into an LLM prompt/message. |
| `AGT-003` | medium | A destructive agent tool (delete/drop/kill/…) defined with no confirmation gate. |
| `AGT-004` | high | External content (fetched page, request body, email) interpolated into a prompt. |
| `AGT-005` | high | An MCP/agent server bound to `0.0.0.0`. |
| `AGT-006` | high | A security gate whose `catch` returns a permissive verdict (fails open). |

## AGT-001 — shell injection in tools

`exec`/`execSync` always spawn a shell; interpolating a variable into the command lets
untrusted (LLM- or tool-derived) input inject commands.

```ts
// vulnerable — LLM-derived `dir` can inject
execSync(`ls ${dir}`);

// correct — shell-less, argument array
execFileSync('ls', [dir]);
```

`execFile`/`execFileSync` are intentionally never flagged: they are the fix.

## AGT-002 — secret in prompt

`` `You are a bot. token=${process.env.API_KEY}` `` leaks the credential into model context and
provider logs. Pass credentials via the client/transport, never the message body. Requires both
the env interpolation and a prompt keyword on the same line — ordinary `${process.env.PORT}`
config never fires.

## AGT-003 — destructive tool without confirmation

Fires only on a real tool *definition* (name + description + parameter schema together) whose
name is destructive and whose block carries no confirmation/approval/dangerous marker. A plain
variable containing "delete" never qualifies.

**Known limitation (field-tested):** if your gating lives *outside* the definition (a policy
engine, an RBAC layer), PRISM can't see it. Either add the marker to the definition or accept
the finding with a suppression naming the policy:

```json
{ "rule": "AGT-003", "reason": "Deletes gated by the policy DSL in data/policies/default.yml" }
```

The aggregate score penalty for this rule is capped: ten ungated tools are one missing
convention, not ten independent failures. Every finding is still listed.

## AGT-004 — prompt injection front door

```ts
// vulnerable — instructions inside the page can hijack the agent
const prompt = `Summarize this page: ${await res.text()}`;
```

Treat external content as data: delimit it, pass it in a separate content block, and don't give
tool access to a turn that includes raw external text without a firewall. Detection uses a
closed list of external sources (`fetch`/`.text()`/`req.body`/email/page content) — an internal
variable interpolated into a prompt never fires.

## AGT-005 — public MCP bind

Fires only when the file is MCP/agent-server code (SDK import, `McpServer`) *and* a line binds
`0.0.0.0`. MCP generally assumes a trusted transport — exposing it exposes every tool. Bind
`127.0.0.1`; a plain web app on `0.0.0.0` is `DOC-024`'s business, not this rule's.

## AGT-006 — fail-open security gate

```ts
async function checkPermission(user, action) {
  try { return await policyEngine.evaluate(user, action); }
  catch { return true; }   // ← grants access exactly when the gate is broken
}
```

Fail closed (`return false`/deny) and surface the error. Requires auth/permission/policy/
approval context in the preceding lines — a feature-flag helper defaulting to `true` never
fires.
