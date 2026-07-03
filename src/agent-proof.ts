/**
 * AgentProofProfile (S15): a STRICT assurance profile for AI code work — not a separate product, an
 * overlay on the gate engine (S10) and evidence verifier (S11) that raises the bar. FAIL-CLOSED:
 *
 *  1. Executable-evidence rule: a STRONG claim (anything not explicitly `limited`/`informational` —
 *     an unknown/miscased strength is treated as strong) needs a supporting evidence id that is
 *     UNAMBIGUOUSLY a passing execution: every instance of that id is an executable type
 *     (`command`/`test`), at least one instance demonstrably PASSED (outcome `pass` or exit_code 0),
 *     and NONE failed. A file hash proves existence, not that it works; a failed or unproven test
 *     does not count.
 *  2. Mandatory-gate rule: `no-t5`, `evidence-integrity`, `report-truthfulness` must EACH be present
 *     and have EVERY declared instance blocking + non-waivable (a weakened duplicate cannot hide
 *     behind a strong one).
 *
 * `assessAgentProof` reports meets_bar + the specific violations; it never silently passes.
 */

/** Evidence that proves behavior by EXECUTION (not mere existence). */
export const EXECUTABLE_EVIDENCE_TYPES: ReadonlySet<string> = new Set(["command", "test"]);

/** Gates that must be present, blocking, and non-waivable under the profile. */
export const AGENT_PROOF_MANDATORY_GATES: readonly string[] = ["no-t5", "evidence-integrity", "report-truthfulness"];

/** Strengths NOT subject to the executable-evidence rule; anything else (incl. unknown) is strong. */
const NON_STRONG_STRENGTHS: ReadonlySet<string> = new Set(["limited", "informational"]);

export interface AgentProofClaim {
  claim_id: string;
  strength: string;
  supported_by: readonly string[];
}

export interface AgentProofEvidence {
  evidence_id: string;
  type: string;
  /** Optional pass/fail signal for executable evidence. */
  outcome?: string;
  exit_code?: number | null;
}

export interface AgentProofGate {
  id: string;
  blocking: boolean;
  waiver_allowed: boolean;
}

export interface AgentProofInput {
  claims: readonly AgentProofClaim[];
  evidence: readonly AgentProofEvidence[];
  gates: readonly AgentProofGate[];
}

export interface AgentProofResult {
  meets_bar: boolean;
  violations: string[];
  strong_claims_without_execution: string[];
  missing_mandatory_gates: string[];
}

const asArr = <T>(v: readonly T[]): readonly T[] => (Array.isArray(v) ? v : []);

export function assessAgentProof(input: AgentProofInput): AgentProofResult {
  // Group evidence by id — dedup-safe, so a mislabeled duplicate cannot relabel a non-executable id.
  const evById = new Map<string, AgentProofEvidence[]>();
  for (const e of asArr(input.evidence)) {
    if (e == null || typeof e.evidence_id !== "string") continue;
    const list = evById.get(e.evidence_id) ?? [];
    list.push(e);
    evById.set(e.evidence_id, list);
  }

  // An id counts iff EVERY instance is executable-typed, at least one PASSED, and NONE failed.
  const idIsPassingExecution = (id: string): boolean => {
    const items = evById.get(id);
    if (!items || items.length === 0) return false; // phantom id
    const allExecutable = items.every((e) => EXECUTABLE_EVIDENCE_TYPES.has(e.type));
    const anyPassed = items.some((e) => e.outcome === "pass" || e.exit_code === 0);
    const anyFailed = items.some((e) => e.outcome === "fail" || (typeof e.exit_code === "number" && e.exit_code !== 0));
    return allExecutable && anyPassed && !anyFailed;
  };

  const violations: string[] = [];

  // Rule 1 — every STRONG claim needs a passing-execution evidence id.
  const strong_claims_without_execution: string[] = [];
  for (const c of asArr(input.claims)) {
    if (c == null || typeof c.claim_id !== "string") continue;
    const strength = typeof c.strength === "string" ? c.strength.trim().toLowerCase() : "strong";
    if (NON_STRONG_STRENGTHS.has(strength)) continue; // unknown/miscased strength is treated as strong (fail closed)
    const satisfied = asArr(c.supported_by).some((id) => typeof id === "string" && idIsPassingExecution(id));
    if (!satisfied) strong_claims_without_execution.push(c.claim_id);
  }
  if (strong_claims_without_execution.length > 0) {
    violations.push(
      `${strong_claims_without_execution.length} strong claim(s) lack passing executable (command/test) evidence: ${strong_claims_without_execution.join(", ")}`,
    );
  }

  // Rule 2 — mandatory gates present with EVERY instance blocking + non-waivable.
  const gatesById = new Map<string, AgentProofGate[]>();
  for (const g of asArr(input.gates)) {
    if (g == null || typeof g.id !== "string") continue;
    const list = gatesById.get(g.id) ?? [];
    list.push(g);
    gatesById.set(g.id, list);
  }
  const missing_mandatory_gates: string[] = [];
  for (const req of AGENT_PROOF_MANDATORY_GATES) {
    const instances = gatesById.get(req) ?? [];
    if (instances.length === 0 || !instances.every((g) => g.blocking === true && g.waiver_allowed === false)) {
      missing_mandatory_gates.push(req);
    }
  }
  if (missing_mandatory_gates.length > 0) {
    violations.push(`missing, non-blocking, waivable, or weakened-by-duplicate mandatory gate(s): ${missing_mandatory_gates.join(", ")}`);
  }

  return {
    meets_bar: violations.length === 0,
    violations,
    strong_claims_without_execution,
    missing_mandatory_gates,
  };
}
