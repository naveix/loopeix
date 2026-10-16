# Security Policy

Loopeix is a local-first tool whose job is honest evidence, so we treat its own security and its
honesty about its limits as the same commitment.

## Reporting a vulnerability

Please report suspected vulnerabilities privately (do **not** open a public issue for an unpatched
flaw). Until a published contact is set up, open a GitHub *security advisory* on the repository, or
contact the maintainer through the repository's listed channel. Include: what you did, what happened,
and the impact. We aim to acknowledge within a few days.

## What Loopeix guarantees — and what it does not

Being explicit about the boundary is part of the security model:

- **No API keys.** Loopeix never asks for, stores, or transmits an API key. The current executable
  path replays operator-supplied captures and does not invoke Codex or Claude.
- **Tamper-EVIDENT, not tamper-PROOF.** The run ledger is a SHA-256 hash chain. It detects accidental
  corruption and naive in-place edits (two independent checks: chain linkage + content-hash
  recomputation), and recovery is fail-closed (a corrupt line is quarantined; state is derived from
  the valid prefix; any problem is `hold`, never a silent `valid`). A write-capable actor who knows
  the public sealing algorithm and controls the workspace signing key **can** re-seal the chain and
  issue a new signed receipt. Receipt signing detects later alteration; it is not an external
  transparency anchor and does not prove the recorded events were true.
- **Provider execution is fail-closed.** `run start` requires `--events-file` for its executable
  replay path. In the V01 compatibility path, legacy `--prompt` and budget inputs do not authorize a
  provider process; the command returns `GENERAL_AGENT_PROHIBITED` before any Codex or Claude process
  is created. Raw and planned V02 targets fail earlier with `UNSUPPORTED_EXECUTION_PROFILE`. The
  Linux CI lane is synthetic and is not production-host qualification evidence.
- **Redaction is conservative, not complete.** The `buildSupportBundle` library function scrubs its
  input by key and pattern, then an **independent** leak-scan (structure walk + provider patterns +
  high-entropy detection) re-checks that bundle before marking it `safe_to_share`. It catches known
  shapes and high-entropy tokens but cannot promise to catch every unknown secret under an innocuous
  key. Loopeix does not currently provide or intercept a general export command.
- **Local-first.** Nothing is sent off your machine by Loopeix itself. The advisory lock that
  serializes ledger appends targets a single machine.

If you find a case where Loopeix claims more than it proves, that is a security bug and we want to
hear about it.

## Supported versions

The public `0.1.0` release and current `main` are supported for security reports. Include the exact
version or source commit because their execution contracts differ.
