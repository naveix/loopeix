# CLI reference

Information-oriented. Every command Loopeix ships today, its arguments, and its exit codes.
Run `loopeix <command> --help` for the authoritative, version-matched usage.

```
loopeix [COMMAND]
```

Global flags: `--help`, `--version`.

## Topics & commands

### `loopeix doctor`

Check the local install: Node version, CLI version, and that the bundled JSON Schema is present.
Use it first after installing or upgrading.

### `loopeix init`

Create a `.loopeix/` workspace (`workspace.yaml` + `loops/`) in the current directory. Local-only;
writes nothing to your home directory.

### `loopeix spec validate <file>`

Validate a Loopeix YAML file. Runs **structural** validation (shape/enums, from Zod → JSON Schema)
**and** **relational** invariants (cross-field rules a schema can't express, e.g. no T5 tier without
approval, at least one blocking gate). Prints `OK` or `INVALID` with a numbered list of issues.

- Exit `0` — valid.
- Exit non-zero — invalid (issues printed) or file/parse error.

### `loopeix spec inspect <file>`

Print a human-readable summary: version, workflow pattern, roles, tasks, and gates (blocking gates
marked `*`), plus the max risk tier allowed without approval.

### `loopeix run start <loop.yaml | planned-run-dir>`

Execute a loop end to end: drive the engine (or replay a captured stream), seal the ledger,
evaluate gates, verify evidence, build the truthful report, and write the run directory.

- `--engine codex|claude` — which engine CLI to drive (uses that CLI's own login; Loopeix holds
  no API keys). Codex is invoked read-only/ephemeral; Claude respects `--max-budget-usd`
  (default `0.10`, max `100`).
- `--prompt <text>` — the live task for raw YAML runs. Not allowed for planned run directories;
  planned runs derive the prompt from approved planned records.
- `--events-file <jsonl>` — replay a captured event stream instead of a live call (fully offline).
- `--seal <brief.yaml>` — seal a structured brief as ledger event 1 and emit a signed
  `receipt.json` with per-clause verdicts. Without it: ledger + report, no receipt, no verdicts.
- `--workspace <dir>` — where `.loopeix/runs/<id>` lands (default `.`).

When the first argument is a planned run directory containing `resolved-run-plan.json`, the command
runs in planned mode:

- Without `--events-file`, Loopeix builds the same bounded prompt shown by `loopeix run prompt` and
  invokes the planned engine from the planned workspace root.
- With `--events-file <jsonl>`, Loopeix replays captured events into the planned run directory and
  does not render or require the intake prompt.
- `--prompt` is refused so a planned run cannot be silently replaced by fresh operator text.
- The command uses the planned `run_id`, workspace root, and run directory.
- Existing execution artifacts are never overwritten.

Exit `0` on a completed run; non-zero on engine or integrity failure.

### `loopeix verify <receipt.json>`

Verify a signed receipt **offline** — no network, no key exchange (the receipt embeds the public
key). Checks: parse, schema, invariants, doctrine (e.g. no `CONTRADICTED`/`PROMISE_BROKEN`
without a citable evidence id), signature; with `--run-dir <dir>` also `ledger_hash`,
`ledger_head` and `ledger_chain`, binding the receipt to the actual ledger. `--json` for
machine output.

- Exit `0` — `VERIFIED`.
- Exit `1` — `NOT VERIFIED`, failed checks listed. Never a partial pass.

### `loopeix pr <run-dir>`

Render the Claims Check verdict table as PR-ready Markdown (red verdicts first) and, with
`--card <path>`, the shareable Delta Card SVG (static, no scripts, no network). `--out <path>`
writes the Markdown to a file. `pr` verifies the receipt **first** and refuses to render an
unverified receipt (exit `1`), so a CI step fails instead of posting a laundered verdict.

### `loopeix run status <run-dir>`

Read a run's status. For planned run directories that do not have `ledger.jsonl` yet, it reports
`planned`, `integrity: unknown`, the planned `run_id`, and the next `run start` command shape. Once
`ledger.jsonl` exists, it recovers the append-only ledger and reports integrity: `valid` or `hold`,
the run state, the last valid sequence, whether it terminated, and any findings (corruption
quarantined, partial final line dropped, truncation, content-hash mismatch).

- Exit `0` — planned status or ledger integrity `valid`.
- Exit non-zero (e.g. `4`) — integrity `hold` (findings printed). Never a silent pass.

### `loopeix run preflight <planned-run-dir>`

Check whether a planned run directory is startable before `run start` mutates it. This reads
planned-run files only; it does not invoke an engine and does not write artifacts.

- `--engine codex|claude` — required engine to compare against the plan's adapter binding.
- Exit `0` — ready to start.
- Exit `1` — HOLD, with findings such as missing files, wrong engine, invalid generated loop, or
  existing execution artifacts.

### `loopeix run prompt <planned-run-dir>`

Print the exact bounded prompt derived from a planned run directory. This is the human-readable
bridge between an approved compile pack and later live engine execution: it shows the objective,
scope, workspace boundary, allowed/forbidden context, tool grants, gates, evaluations, adapter gaps,
and execution rules before any engine is invoked.

- Reads `intake-brief.json`, `resolved-run-plan.json`, and the planned run files checked by
  `run preflight`.
- Infers the planned engine from `resolved-run-plan.json`; no engine flag is accepted.
- Requires the same startability gate as `run preflight`, including no existing execution artifacts.
- Exit `0` — prints the bounded prompt.
- Exit `1` — HOLD, with findings. No prompt is printed for invalid, wrong-state, or already-started
  planned runs.

### `loopeix run recover <run-dir>`

Like `run status`, but oriented at a run interrupted or corrupted mid-flight: reports the recoverable
valid prefix and what was dropped/quarantined, so you can decide whether to resume. **Read-only in
V1** — it reports and verdicts; it does **not** rewrite history or repair the chain (recovery events
are written by a later sprint). Exit non-zero if the run is held/unrecoverable.

### `loopeix report build <run-dir>`

Rebuild `report.md` + `report.html` for a run from its recorded inputs (`report-input.json`) — a
**truthful Markdown** report (verified claims, unverified claims, capture gaps, waivers, unresolved
findings, redaction/retention state, known limitations — all sections always present) and a
**static, self-contained HTML timeline** (no scripts, no network).

### `loopeix report open <run-dir>`

Show the path to a run's built HTML report so you can open it locally in a browser.

## Privacy commands (documented per the redaction/retention policy)

The redaction & retention policy requires these behaviors; where a subcommand is not yet wired, the
library functions (`redact`, `scanForLeaks`, `buildSupportBundle`, `isExpired`) provide the same
guarantees and the equivalent behavior is documented:

- `loopeix support bundle` — build a **redacted, leak-scanned** support bundle (safe to share only
  if the independent quarantine scan is clean).
- `loopeix privacy purge-run` — purge or tombstone one run per its retention class.
- `loopeix privacy redact-artifact` — write a redacted replacement for one artifact.
- `loopeix privacy list-quarantine` — list quarantined evidence (never auto-deleted).

## Exit code convention

- `0` — success / valid / integrity OK.
- non-zero — validation failed, integrity `hold`, or an operational error. Details are printed to
  stderr; nothing is treated as success unless it is proven so.
