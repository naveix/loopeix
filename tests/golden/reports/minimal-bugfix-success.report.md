# LoopSpec Run Report — minimal-bugfix

- Run: `run_minimal_bugfix_success`
- Loop family: `minimal-bugfix`
- LoopSpec version: `v001` (`sha256:1111…1111`)
- Run state: **completed**
- Integrity: **valid** (ledger sequence 1–9, hash chain intact)

## Outcome

Fixed one small bug with evidence. The blocking gate passed.

## Verified claims

| Claim | Strength | Evidence |
|---|---|---|
| The bug was reproduced and diagnosed. | strong | `ev_0002` (file-hash of `artifacts/diagnosis.md`) |
| The fix was verified by the project check. | strong | `ev_0001` (command, exit 0) via evaluation `eval_0001` PASS |

## Unverified claims

None. Every strong claim in this run has independent supporting evidence.

## Capture gaps

None recorded for this run. No engine adapter was used (local shell only), so no adapter capture gaps apply.

## Waivers

None. No gate was waived.

## Unresolved findings

None. `findings.json` is empty; no blocking, accepted-risk, or deferred findings remain.

## Gate results

| Gate | Blocking | Status | Reason |
|---|---|---|---|
| `claim-support` | yes | **PASS** | All strong claims are supported by command and file evidence. |

## Redaction and retention state

- Redaction policy version: `0.1`.
- Quarantined artifacts: none.
- Raw evidence excluded from this report: none.
- Retention: all artifacts are class `run` (retained until run deletion).
- Known redaction limitations: none for this run; no sensitive material was captured.

## Known limitations

- Evidence hashes, timestamps, and run IDs in this golden report are normalized placeholders for deterministic testing.
- This report format follows the required-section contract in `schema-evidence-gates.md`; the exact rendering is finalized in S12.
