# Adapter event fixtures — provenance & redaction

These are **real, redacted** engine event samples (not fabricated), captured locally per the
S1 acceptance-evidence rule (adapter-observability-matrix.md §S1). They feed the adapter
normalization tests and the parity fixture.

## Capture (2026-07-02)

| Engine | Version | Command | Events |
|---|---|---|---|
| Codex | `codex-cli 0.142.3` | `codex exec --json --ephemeral --sandbox read-only --skip-git-repo-check "Reply with exactly the word: ok" </dev/null` | 5 |
| Claude Code | `2.1.198` | `claude -p "Reply with exactly the word: ok" --output-format stream-json --verbose --include-hook-events --no-session-persistence --max-budget-usd 0.10 </dev/null` | 25 |

Both captures used a benign prompt, a read-only/ephemeral sandbox, and (Claude) a `$0.10`
budget cap. The Claude run ended `result.subtype = error_max_budget_usd` — the budget guard
tripped; the full event stream was still captured. `</dev/null` is required or `codex exec`
blocks on stdin.

## Redaction (deterministic script, no hand-handling of raw values)

Values under these keys were replaced with `<REDACTED>`: `session_id, uuid, hook_id,
request_id, thread_id, parent_tool_use_id, cwd, memory_paths, mcp_servers, agents, plugins,
skills, slash_commands, tools, apiKeySource, output_style, model, modelUsage, usage,
total_cost_usd, permission_denials, output, stdout, stderr, ttft_ms, plugin_errors`.
Additionally, any absolute path → `<PATH>`, ISO timestamp → `<TS>`, UUID → `<UUID>`,
`msg_…` → `<MSG_ID>`, `req_…` → `<REQ_ID>`. A leak scan for paths / UUIDs / message ids
returned **0** on both files. Kept (structural, non-sensitive): `type`, `subtype`,
`hook_event`, `hook_name`, `exit_code`, `outcome`, `is_error`, `stop_reason`, `num_turns`,
`permissionMode`, `claude_code_version`, item `type`.

## Capture (2026-07-04) — file-change path shape (F5 known-limitation closure)

| Engine | Version | Command | Fixture |
|---|---|---|---|
| Codex | `codex-cli 0.142.3` | `codex exec --json --ephemeral --sandbox workspace-write` (benign add + delete of two scratch files in a throwaway tmp workspace) | `codex/s1-codex-file-change.redacted.jsonl` |
| Claude Code | `claude 2.1.201` | `claude -p --output-format stream-json --permission-mode acceptEdits` (benign write + delete in a throwaway tmp workspace) | none — see findings below |

**Findings (real, operator-approved paid runs):**

- **Codex `file_change` paths are ABSOLUTE**, prefixed with the run workspace root
  (`{"path":"<workspace>/hello.txt","kind":"add"}`). The item is emitted twice: `item.started`
  (`status: in_progress`) then `item.completed` (`status: completed`) with identical `changes`.
  Verdict path normalization strips the prefix against `workspaceRoot` (P3a) — live-confirmed.
- **Claude Code `Write` tool_use carries an ABSOLUTE `file_path`** in its input. The file
  DELETION in the same run happened via a `Bash` tool_use (`rm <abs path>`) and produced **no
  file-change-shaped event at all** — the shell-rm bypass is live-proven, not just theorized.
  No redacted Claude fixture is committed for this run (the stream is dominated by
  operator-machine hook events); the finding is recorded in
  `claude-code/s1-claude-capture-gap.unsupported-flag.json`.

**Redaction for the file-change fixture:** the real tmp workspace prefix was replaced with the
synthetic root `/workspace/live-capture` (username stripped); `thread_id`/`usage` → `<REDACTED>`
as in the S1 fixtures. The ABSOLUTE path shape is deliberately preserved — the shape itself is
the evidence this capture exists to record.

## Observed event vocabulary (for the adapters)

- **Codex** (JSONL): `thread.started` → `turn.started` → `item.completed`(items: `error`
  [an informational skills-budget notice], `agent_message`) → `turn.completed`(+`usage`).
  File-change runs add `item.started`/`item.completed` pairs with `type: file_change` and
  absolute `changes[].path` (2026-07-04 capture).
- **Claude** (stream-json): `system:init` → `system:hook_event`×N → `assistant` (content
  blocks: `text`, `tool_use`) → `result`. Tool calls (Bash/Edit/Write/MCP) surface as
  `assistant.message.content[].tool_use`.

## Sources

- Codex event schema: openai/codex repo + docs (retrieved 2026-07-02).
- Claude stream-json: code.claude.com/docs/en/cli-reference, /headless, /agent-sdk/streaming-output (retrieved 2026-07-02).

## Still pending (separate captures)

- `codex/s1-codex-output-schema.redacted.json` and `claude-code/s1-claude-json-schema.redacted.json`
  (structured-output runs via `--output-schema` / `--json-schema`) — not yet captured.
- `claude-code/s1-claude-capture-gap.unsupported-flag.json` — authored from the capability matrix;
  its shell-rm / inferred-file-ops claims were live-confirmed 2026-07-04 (see above).
