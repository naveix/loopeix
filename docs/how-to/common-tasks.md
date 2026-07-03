# How-to: common tasks

Task-oriented recipes. Each assumes Loopeix is installed (`loopeix doctor` passes).

## Validate a spec before you rely on it

```bash
loopeix spec validate path/to/loop.yaml
```

If it prints `INVALID`, fix each numbered issue and re-run. Common ones:

- `risk_tier: Invalid option … T5` — T5 (scheduled/unattended) is forbidden; pick `T0`–`T4`.
- `to_version must be greater than from_version` — a new version file must move forward.
- `at least one blocking gate` — every loop needs a blocking gate (keep `no-t5`).

## See what a spec actually does

```bash
loopeix spec inspect path/to/loop.yaml
```

Reads out roles, tasks, and the blocking gates (`*`). Use it in review to confirm intent without
reading the whole file.

## Check whether a run's evidence is trustworthy

```bash
loopeix run status .loopeix/runs/<run-id>
```

- `valid` → the hash chain is intact and content hashes match.
- `hold` → **do not trust the run as-is**; read the findings (quarantined corrupt lines, a dropped
  partial write, truncation, or a content-hash mismatch). Exit code is non-zero on `hold`.

## Assess whether a run can be recovered

```bash
loopeix run recover .loopeix/runs/<run-id>
```

**Read-only in V1** — it reports the recoverable **valid prefix** (up to the first break) and exactly
what was dropped or quarantined; it does not rewrite or repair the ledger. A corrupt middle line does
not make the whole ledger unreadable — you see the valid prefix and decide whether to continue.

## Build a report from a run

> **Not yet a CLI command in V0.3.** `loopeix report build`/`report open` currently warn and do
> nothing — the report is implemented and tested in the `buildReport` library and reaches the CLI with
> the run-execution layer.

When wired, the Markdown lists verified vs unverified claims and always discloses capture gaps and
redaction state; the HTML timeline is static (no scripts, no network) and safe to open offline.

## Build a redacted support bundle before asking for help

> **Not yet a CLI command in V0.3** — use the `buildSupportBundle` **library function** today; the
> `loopeix support bundle` command arrives with the run-execution layer.

`buildSupportBundle` **redacts, then runs an independent leak-scan**, and marks the bundle
`safe_to_share` only if the scan is clean — so you don't accidentally attach a secret. If the scan
flags something, the bundle is held for your review.

## Propose an improvement to a loop (without breaking the old one)

A run's retro can become a `SpecChangeProposal`:

- The proposal targets a **new** version (`v001 → v002`) and never edits the released version.
- It is validated and forward-only (`to_version > from_version`).
- Applying it is **approval-gated**: a proposal must be `approved` before it can be `applied`, and
  the immutability check refuses to overwrite any existing version.

See [`examples/`](../../examples/) and the retro/proposal fixtures for worked shapes.
