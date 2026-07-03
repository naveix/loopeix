# Loopeix Run Report — adapter limitations disclosed

- Run: `run_adapter_limitations_disclosed`
- Loop family: `expert-sprint`
- Loopeix version: `v001` (`sha256:1111…1111`)
- Engine adapter: `claude_code_cli` (stream-json)
- Run state: **completed**
- Integrity: **valid**

## Outcome

The sprint completed, but this report exists to demonstrate the trust rule: an adapter must
declare what it could not observe, and the report must surface those gaps. Verified claims are
kept strictly separate from what the adapter could not capture.

## Verified claims

| Claim | Strength | Evidence |
|---|---|---|
| The project validation command passed. | strong | `ev_0001` (command, exit 0) |
| The changed files match the change summary. | strong | `ev_0002` (filesystem hash) |

## Unverified claims

| Claim | Strength | Why unverified |
|---|---|---|
| No secret was sent to the engine during the run. | limited | Prompt/transcript payloads are outside Loopeix's capture; see capture gaps. |

## Capture gaps (declared by the adapter — MUST NOT be reported as verified)

| Gap | Adapter | Effect |
|---|---|---|
| Token / context / usage counts | `claude_code_cli` | Not captured as schema-validated events; excluded from evidence. |
| Full raw prompt transcript | `claude_code_cli` | Not captured as primary evidence (privacy policy); claims needing it stay `limited`. |
| Tool-approval + MCP tool-call event shapes | `claude_code_cli` | Event shapes unverified pending approved live samples; recorded as gaps, not proof. |
| File-change events | `claude_code_cli` | Reconstructed from filesystem hashes, not from a native change stream. |

Engine data-transmission boundary: Loopeix adds no telemetry, but the Claude Code CLI may
transmit prompts, files, or tool context under its own settings. This boundary was disclosed
before the run started.

## Waivers

None.

## Unresolved findings

None blocking. One accepted-risk finding:

| Finding | Severity | Classification | Owner | Rationale |
|---|---|---|---|---|
| `find_0001` — usage/token accounting unavailable | low | accepted-risk | operator | Not required for this loop's gates; revisit when adapter samples are approved. |

## Redaction and retention state

- Redaction policy version: `0.1`. Quarantined artifacts: none. Raw evidence excluded: raw
  prompt transcript (by policy). Retention: evidence + report class `run`; raw adapter events class `short`.
- Known redaction limitations: transcript-level redaction not applicable because transcripts are not captured as evidence.

## Known limitations

- This report demonstrates capture-gap disclosure; the underlying adapter event samples are NOT
  included because live Codex/Claude capture is approval-gated (planning blocker G2). No adapter
  event shape is asserted as verified here.
- Identifiers, hashes, and timestamps are normalized placeholders.
