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

## Observed event vocabulary (for the adapters)

- **Codex** (JSONL): `thread.started` → `turn.started` → `item.completed`(items: `error`
  [an informational skills-budget notice], `agent_message`) → `turn.completed`(+`usage`).
- **Claude** (stream-json): `system:init` → `system:hook_event`×N → `assistant` (content
  blocks: `text`, `tool_use`) → `result`. Tool calls (Bash/Edit/Write/MCP) surface as
  `assistant.message.content[].tool_use`.

## Sources

- Codex event schema: openai/codex repo + docs (retrieved 2026-07-02).
- Claude stream-json: code.claude.com/docs/en/cli-reference, /headless, /agent-sdk/streaming-output (retrieved 2026-07-02).

## Still pending (separate captures)

- `codex/s1-codex-output-schema.redacted.json` and `claude-code/s1-claude-json-schema.redacted.json`
  (structured-output runs via `--output-schema` / `--json-schema`) — not yet captured.
- `claude-code/s1-claude-capture-gap.unsupported-flag.json` — authored from the capability matrix.
