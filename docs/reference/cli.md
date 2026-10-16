# CLI reference

Information-oriented. Every command in the current unreleased source, its arguments, and its exit
codes. Run `node bin/run.js <command> --help` from the same checkout for source-checkpoint-matched
usage; the public `0.1.0` package has an earlier execution contract.

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

Replay an operator-supplied captured event stream, seal the ledger, evaluate gates, verify
evidence, build the truthful report, and write the run directory. Live provider execution is
deliberately fail-closed in the current source: without `--events-file`, the command starts no
Codex or Claude process.

- `--engine codex|claude` — captured-engine identity used to select the event normalizer. This
  flag does not authorize or start that provider.
- `--prompt <text>` — legacy live-run input. Planned run directories refuse it, and all current
  live-execution paths end in `HOLD` before provider process creation.
- `--events-file <jsonl>` — captured JSONL event file required for the executable replay path
  (fully offline).
- `--max-budget-usd <number>` — legacy Claude live-run budget input; it does not enable live
  execution.
- `--seal <brief.yaml>` — seal a structured brief as ledger event 1 and emit a signed
  `receipt.json` with per-clause verdicts. Without it: ledger + report, no receipt, no verdicts.
- `--workspace <dir>` — where `.loopeix/runs/<id>` lands (default `.`).

Usable captured-event replay:

The following fixture paths exist only in a repository clone. Run this from a built clone:

```bash
node bin/run.js run start tests/fixtures/run-seal/seal-loop.yaml --engine codex \
  --events-file tests/fixtures/run-seal/snitch-events.jsonl \
  --seal tests/fixtures/run-seal/snitch-brief.yaml \
  --workspace "$(mktemp -d)"
```

Raw and planned V02 targets are also unavailable: `run start` returns
`UNSUPPORTED_EXECUTION_PROFILE` and creates no provider process.

When the first argument is a planned V01 run directory containing `resolved-run-plan.json`, the
command runs in planned mode. Planned V02 directories are rejected earlier with
`UNSUPPORTED_EXECUTION_PROFILE`:

- Without `--events-file`, Loopeix may validate and render the approved bounded prompt, then returns
  `HOLD` at the S37 pre-spawn boundary; no provider process is started.
- With `--events-file <jsonl>`, Loopeix replays captured events into the planned run directory and
  does not render or require the intake prompt.
- `--prompt` is refused so a planned run cannot be silently replaced by fresh operator text.
- The command uses the planned `run_id`, workspace root, and run directory.
- The command takes `<planned-run-dir>/ledger.lock` before replay or pre-spawn validation and
  releases it through the command finalizer, so concurrent starts fail closed instead of
  interleaving writes.
- Existing execution artifacts are never overwritten.

When the first argument is a raw V01 loop file (raw compatibility mode), an executable replay
allocates a local run id and run directory after spec, option, and sealed-brief validation but
before replay parsing:

- `run_id` is `run_<lowercase-base36-milliseconds>_<16-lowercase-hex>`.
- `run_dir` is exactly `<workspace>/.loopeix/runs/<run_id>`.
- `Date.now()` is evaluated once per run start. The allocator creates `<workspace>/.loopeix/runs`
  recursively, then claims `<run_dir>` with non-recursive `mkdirSync`.
- Collisions retry only `EEXIST`, up to 16 attempts by default; non-collision fs errors fail
  immediately.
- Allocator failure or exhaustion exits the command with `ERROR: cannot reserve raw run directory: ...`
  and exit code `1`.

Exit `0` on a completed replay; non-zero on validation failure, integrity failure, or a deliberate
execution `HOLD`.

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

Read an S35 planned-layout run's status. For planned run directories that do not have `ledger.jsonl` yet, it reports
`planned`, `integrity: unknown`, the planned `run_id`, and the next `run start` command shape. Once
`ledger.jsonl` exists, it recovers the append-only ledger and reports integrity: `valid` or `hold`,
the run state, the last valid sequence, whether it terminated, and any findings (corruption
quarantined, partial final line dropped, truncation, content-hash mismatch).

Raw-compatibility replay directories do not contain `resolved-run-plan.json`; this command rejects
them with `INVALID_RESOLVED_RUN_PLAN_DOCUMENT`. Verify their ledger-bound receipt with
`loopeix verify <receipt> --run-dir <run-dir>` instead.

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
review surface for an approved compile pack: it shows the objective,
scope, workspace boundary, allowed/forbidden context, tool grants, gates, evaluations, adapter gaps,
and execution rules without invoking a provider.

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
are written by a later sprint). It has the same planned-run-layout requirement as `run status` and
rejects raw-compatibility directories. Exit non-zero if the run is held/unrecoverable.

### `loopeix report build <run-dir>`

Rebuild `report.md` + `report.html` for a run from its recorded inputs (`report-input.json`) — a
**truthful Markdown** report (verified claims, unverified claims, capture gaps, waivers, unresolved
findings, redaction/retention state, known limitations — all sections always present) and a
**static, self-contained HTML timeline** (no scripts, no network).
The command takes `<run-dir>/ledger.lock` around the rebuild and writes each report through a
temporary file plus atomic rename, so a concurrent run writer is not interleaved and readers do not
observe half-written report files.

### `loopeix report open <run-dir>`

Show the path to a run's built HTML report so you can open it locally in a browser.

## Privacy library and planned command surface

No privacy/support subcommand is wired today. The library currently provides `redact`,
`scanForLeaks`, `buildSupportBundle`, and the pure expiry predicate `isExpired`.
`buildSupportBundle` redacts and independently scans the bundle it constructs. Purge/tombstone,
artifact replacement, and quarantine listing are not implemented. The names reserved for a later
contract are:

- Planned `loopeix support bundle`
- Planned `loopeix privacy purge-run`
- Planned `loopeix privacy redact-artifact`
- Planned `loopeix privacy list-quarantine`

## Exit code convention

- `0` — success / valid / integrity OK.
- non-zero — validation failed, integrity `hold`, or an operational error. Details are printed to
  stderr; nothing is treated as success unless it is proven so.
