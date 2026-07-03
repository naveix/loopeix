# AgentProofProfile examples

The AgentProofProfile (S15) is a strict assurance **overlay** for AI code work — not a separate
product. It composes with the gate engine (S10) and evidence verifier (S11) and adds two rules:

1. **Executable-evidence rule** — every STRONG claim needs at least one `command` (that ran) or
   `test` (that passed). A `file` hash proves the code *exists*, not that it *works*, so file /
   artifact / approval / human_note alone cannot verify a strong claim under this profile.
2. **Mandatory-gate rule** — the unwaivable assurance gates (`no-t5`, `evidence-integrity`,
   `report-truthfulness`) must be present, blocking, and non-waivable.

- [`meets-bar.json`](./meets-bar.json) — a run that satisfies both rules → `assessAgentProof(...).meets_bar === true`.
- [`fails-bar.json`](./fails-bar.json) — a run that violates both (a strong claim with no execution
  evidence; two weakened mandatory gates) → `meets_bar === false` with the specific violations.

See `src/agent-proof.ts` and `tests/unit/agent-proof.test.ts`.
