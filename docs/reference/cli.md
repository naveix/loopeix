# CLI reference

Information-oriented. Every command LoopSpec ships today, its arguments, and its exit codes.
Run `loopspec <command> --help` for the authoritative, version-matched usage.

```
loopspec [COMMAND]
```

Global flags: `--help`, `--version`.

## Topics & commands

### `loopspec doctor`

Check the local install: Node version, CLI version, and that the bundled JSON Schema is present.
Use it first after installing or upgrading.

### `loopspec init`

Create a `.loopspec/` workspace (`workspace.yaml` + `loops/`) in the current directory. Local-only;
writes nothing to your home directory.

### `loopspec spec validate <file>`

Validate a LoopSpec YAML file. Runs **structural** validation (shape/enums, from Zod → JSON Schema)
**and** **relational** invariants (cross-field rules a schema can't express, e.g. no T5 tier without
approval, at least one blocking gate). Prints `OK` or `INVALID` with a numbered list of issues.

- Exit `0` — valid.
- Exit non-zero — invalid (issues printed) or file/parse error.

### `loopspec spec inspect <file>`

Print a human-readable summary: version, workflow pattern, roles, tasks, and gates (blocking gates
marked `*`), plus the max risk tier allowed without approval.

### `loopspec run status <run-dir>`

Read a run's append-only ledger, recover it, and report integrity: `valid` or `hold`, the run state,
the last valid sequence, whether it terminated, and any findings (corruption quarantined, partial
final line dropped, truncation, content-hash mismatch).

- Exit `0` — integrity `valid`.
- Exit non-zero (e.g. `4`) — integrity `hold` (findings printed). Never a silent pass.

### `loopspec run recover <run-dir>`

Like `run status`, but oriented at a run interrupted or corrupted mid-flight: reports the recoverable
valid prefix and what was dropped/quarantined, so you can decide whether to resume. **Read-only in
V1** — it reports and verdicts; it does **not** rewrite history or repair the chain (recovery events
are written by a later sprint). Exit non-zero if the run is held/unrecoverable.

### `loopspec report build <run-dir>`  *(not yet wired in V0.3)*

> **Not runnable yet.** This command currently warns and produces no output. Its behavior is
> implemented and tested in the `buildReport` library and arrives at the CLI with the run-execution
> layer.

Intended behavior: build the local report for a run — a **truthful Markdown** report (verified claims,
unverified claims, capture gaps, waivers, unresolved findings, redaction/retention state, known
limitations — all sections always present) and a **static, self-contained HTML timeline** (no scripts,
no network).

### `loopspec report open <run-dir>`  *(not yet wired in V0.3)*

> **Not runnable yet** — warns and does nothing today. Intended: open the built HTML report locally.

## Privacy commands (documented per the redaction/retention policy)

The redaction & retention policy requires these behaviors; where a subcommand is not yet wired, the
library functions (`redact`, `scanForLeaks`, `buildSupportBundle`, `isExpired`) provide the same
guarantees and the equivalent behavior is documented:

- `loopspec support bundle` — build a **redacted, leak-scanned** support bundle (safe to share only
  if the independent quarantine scan is clean).
- `loopspec privacy purge-run` — purge or tombstone one run per its retention class.
- `loopspec privacy redact-artifact` — write a redacted replacement for one artifact.
- `loopspec privacy list-quarantine` — list quarantined evidence (never auto-deleted).

## Exit code convention

- `0` — success / valid / integrity OK.
- non-zero — validation failed, integrity `hold`, or an operational error. Details are printed to
  stderr; nothing is treated as success unless it is proven so.
