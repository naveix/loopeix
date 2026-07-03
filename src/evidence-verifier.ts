/**
 * Evidence & evaluation verifier (architecture-plan.md §Evidence Engine, schema-evidence-gates.md).
 *
 * FAIL-CLOSED. A STRONG claim is `verified` only with at least one present, INDEPENDENT evidence
 * item (an allowlist — unknown/misspelled types do NOT count) whose types cover every
 * `required_evidence_types`. Terminal status is RESOLVED from evidence, never trusted from the
 * declared status: a `verified` that does not hold is downgraded; a `waived` is honored only when
 * an approved waiver backs it, otherwise it is resolved from evidence with a finding.
 */

export type ClaimStrengthValue = "strong" | "limited" | "informational";
export type ClaimStatusValue = "verified" | "unverified" | "contradicted" | "waived";

export interface ClaimInput {
  claim_id: string;
  strength: ClaimStrengthValue;
  required_evidence_types: readonly string[];
  supported_by: readonly string[];
  status: ClaimStatusValue;
}

export interface EvidenceInput {
  evidence_id: string;
  type: string;
}

/**
 * Evidence types that independently corroborate a STRONG claim (allowlist — fail closed on
 * anything else). Excludes `human_note` (weak), `approval` (a human sign-off — circular), and
 * `gate` (a result about the same run — not independent corroboration of a technical claim).
 */
export const INDEPENDENT_EVIDENCE_TYPES: ReadonlySet<string> = new Set([
  "command",
  "file",
  "test",
  "artifact",
  "adapter_event",
  "source_citation",
  "browser",
]);

export interface ClaimVerification {
  claim_id: string;
  strength: ClaimStrengthValue;
  declared_status: ClaimStatusValue;
  resolved_status: ClaimStatusValue;
  supporting_evidence: string[];
  missing_evidence_types: string[];
  issues: string[];
}

export interface EvidenceReport {
  claims: ClaimVerification[];
  verified: string[];
  unverified: string[];
  summary: { total: number; verified: number; unverified: number; contradicted: number; waived: number };
}

interface EvidenceResolution {
  resolved: ClaimStatusValue;
  supporting: string[];
  missingTypes: string[];
  issues: string[];
}

function resolveByEvidence(c: ClaimInput, byId: ReadonlyMap<string, EvidenceInput>): EvidenceResolution {
  const issues: string[] = [];
  const supportedBy = Array.isArray(c.supported_by) ? c.supported_by : [];
  const supporting = supportedBy.filter((id) => byId.has(id));
  const phantom = supportedBy.filter((id) => !byId.has(id));
  if (phantom.length > 0) issues.push(`references ${phantom.length} evidence id(s) that do not exist`);

  const supportingTypes = new Set(supporting.map((id) => byId.get(id)!.type));
  const hasIndependent = [...supportingTypes].some((t) => INDEPENDENT_EVIDENCE_TYPES.has(t));
  const reqTypes = Array.isArray(c.required_evidence_types) ? c.required_evidence_types : [];
  const missingTypes = reqTypes.filter((t) => !supportingTypes.has(t));

  let resolved: ClaimStatusValue;
  if (c.strength === "strong") {
    if (supporting.length === 0) {
      resolved = "unverified";
      issues.push("strong claim has no present supporting evidence");
    } else if (!hasIndependent) {
      resolved = "unverified";
      issues.push("strong claim lacks independent evidence (only weak/circular types present)");
    } else if (missingTypes.length > 0) {
      resolved = "unverified";
      issues.push(`missing required evidence types: ${missingTypes.join(", ")}`);
    } else {
      resolved = "verified";
    }
  } else if (supporting.length === 0) {
    resolved = "unverified";
    issues.push("no present supporting evidence");
  } else {
    resolved = "verified";
  }
  return { resolved, supporting, missingTypes, issues };
}

export function verifyEvidence(input: {
  claims: readonly ClaimInput[];
  evidence: readonly EvidenceInput[];
  /** Claim ids covered by an approved, evidence-backed waiver (verified upstream). */
  waived_claim_ids?: readonly string[];
}): EvidenceReport {
  const evidence = Array.isArray(input.evidence) ? input.evidence : [];
  const claimsIn = Array.isArray(input.claims) ? input.claims : [];
  const byId = new Map(evidence.map((e) => [e.evidence_id, e]));
  const waivedOk = new Set(input.waived_claim_ids ?? []);

  const claims: ClaimVerification[] = claimsIn.map((c) => {
    let resolved: ClaimStatusValue;
    let supporting: string[] = [];
    let missingTypes: string[] = [];
    const issues: string[] = [];

    if (c.status === "contradicted") {
      // V1: declaration-driven (no evidence-based contradiction detection yet).
      resolved = "contradicted";
    } else if (c.status === "waived" && waivedOk.has(c.claim_id)) {
      resolved = "waived";
    } else {
      const res = resolveByEvidence(c, byId);
      resolved = res.resolved;
      supporting = res.supporting;
      missingTypes = res.missingTypes;
      issues.push(...res.issues);
      if (c.status === "waived") issues.push("declared 'waived' without an approved waiver; resolved from evidence");
      if (c.status === "verified" && resolved !== "verified") issues.push(`declared 'verified' but downgraded to '${resolved}'`);
    }

    return {
      claim_id: c.claim_id,
      strength: c.strength,
      declared_status: c.status,
      resolved_status: resolved,
      supporting_evidence: supporting,
      missing_evidence_types: missingTypes,
      issues,
    };
  });

  const verified = claims.filter((c) => c.resolved_status === "verified").map((c) => c.claim_id);
  const unverified = claims.filter((c) => c.resolved_status === "unverified").map((c) => c.claim_id);
  return {
    claims,
    verified,
    unverified,
    summary: {
      total: claims.length,
      verified: verified.length,
      unverified: unverified.length,
      contradicted: claims.filter((c) => c.resolved_status === "contradicted").length,
      waived: claims.filter((c) => c.resolved_status === "waived").length,
    },
  };
}

export interface EvaluationInput {
  evaluation_id: string;
  type: string;
  status: "PASS" | "HOLD" | "FAIL" | "SKIPPED";
  required?: boolean;
  exit_code?: number | null;
}

export interface EvalReport {
  results: { evaluation_id: string; status: string; ok: boolean; issue: string | null }[];
  all_required_passed: boolean;
  /** Expected required evaluation ids that were absent from the results. */
  missing_required: string[];
}

/**
 * Verify evaluation results. A command evaluation marked PASS must record `exit_code === 0` — an
 * absent/null/non-zero code cannot confirm success (not ok). With `expected_ids`, a required
 * evaluation that is entirely missing fails `all_required_passed`. Duplicate ids must ALL be ok.
 */
export function verifyEvaluations(
  evaluations: readonly EvaluationInput[],
  opts: { expected_ids?: readonly string[] } = {},
): EvalReport {
  const evals = Array.isArray(evaluations) ? evaluations : [];
  const results = evals.map((e) => {
    let ok = e.status === "PASS";
    let issue: string | null = null;
    if (e.type === "command" && e.status === "PASS" && e.exit_code !== 0) {
      ok = false;
      issue = `command evaluation marked PASS but exit_code is ${e.exit_code ?? "absent"} (cannot confirm exit 0)`;
    } else if (!ok) {
      issue = `evaluation status is ${e.status}`;
    }
    return { evaluation_id: e.evaluation_id, status: e.status, ok, issue };
  });

  // Duplicate ids: an id is ok only if ALL results for it are ok.
  const okById = new Map<string, boolean>();
  for (const r of results) okById.set(r.evaluation_id, (okById.get(r.evaluation_id) ?? true) && r.ok);

  const missing_required = (opts.expected_ids ?? []).filter((id) => !okById.has(id));
  const requiredOk = evals.every((e) => e.required === false || okById.get(e.evaluation_id) === true);
  return { results, all_required_passed: requiredOk && missing_required.length === 0, missing_required };
}
