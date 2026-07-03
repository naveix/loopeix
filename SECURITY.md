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

- **No API keys.** Loopeix never asks for, stores, or transmits an API key. It invokes the Codex /
  Claude CLIs, which carry their own authentication.
- **Tamper-EVIDENT, not tamper-PROOF.** The run ledger is a SHA-256 hash chain. It detects accidental
  corruption and naive in-place edits (two independent checks: chain linkage + content-hash
  recomputation), and recovery is fail-closed (a corrupt line is quarantined; state is derived from
  the valid prefix; any problem is `hold`, never a silent `valid`). A write-capable actor who knows
  the public sealing algorithm **can** re-seal a forged or truncated chain. Cryptographic
  signing/anchoring is a post-V1 item.
- **Sandboxed engine invocation.** Codex runs under `--sandbox read-only --ephemeral`, invoked with an
  args-array (no shell) and a `--` end-of-options terminator so a prompt cannot be reparsed as a flag
  that overrides the sandbox. Claude runs with a budget cap. A live run is bounded by a timeout, and a
  failed/timed-out run seals `run.failed` (never a fake `completed`).
- **Redaction is conservative, not complete.** Before any support bundle leaves your machine, secrets
  are scrubbed by key and by pattern, and an **independent** leak-scan (structure walk + provider
  patterns + high-entropy detection) re-checks the result. It catches known shapes and high-entropy
  tokens; it cannot promise to catch every unknown secret under an innocuous key, so every export is
  scanned and every report states its redaction limitations.
- **Local-first.** Nothing is sent off your machine by Loopeix itself. The advisory lock that
  serializes ledger appends targets a single machine.

If you find a case where Loopeix claims more than it proves, that is a security bug and we want to
hear about it.

## Supported versions

Pre-release (alpha). Report against `main`.
