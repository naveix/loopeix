import { z } from "zod";
import type { Issue } from "./loopeix.js";
import { RedactionState, RetentionClass } from "./runtime.js";
import { Hash, HumanId, IsoTimestamp, MachineId, RiskTier } from "./scalars.js";

/**
 * Evidence / gate / evaluation record schemas (schema-evidence-gates.md).
 * Per the S3 contract these records carry NO `schema_version` field (recorded as a
 * gap for S6 in the fixtures README); they are identified via the run-manifest.
 */

export const ClaimStrength = z.enum(["strong", "limited", "informational"]);
export const ClaimStatus = z.enum(["verified", "unverified", "contradicted", "waived"]);

export const Claim = z.object({
  claim_id: MachineId,
  text: z.string(),
  strength: ClaimStrength,
  required_evidence_types: z.array(z.string()),
  supported_by: z.array(z.string()),
  status: ClaimStatus,
  limitations: z.array(z.string()),
});
export type Claim = z.infer<typeof Claim>;

/** Invariant: a strong claim cannot be `verified` without independent supporting evidence. */
export function checkClaimInvariants(claim: Claim): Issue[] {
  const issues: Issue[] = [];
  if (claim.strength === "strong" && claim.status === "verified" && claim.supported_by.length === 0) {
    issues.push({
      path: `claim(${claim.claim_id}).supported_by`,
      message: `strong claim '${claim.claim_id}' cannot be 'verified' with no supporting evidence`,
    });
  }
  return issues;
}

export const EvidenceType = z.enum([
  "command",
  "file",
  "artifact",
  "approval",
  "test",
  "gate",
  "adapter_event",
  "human_note",
  "source_citation",
  "browser",
]);
export const EvidenceSource = z.enum([
  "codex_cli",
  "claude_code_cli",
  "shell",
  "browser",
  "user",
  "evaluator",
  "loopeix",
]);
export const CaptureMethod = z.enum([
  "jsonl_event",
  "hook",
  "command_output",
  "filesystem_hash",
  "manual_review",
  "screenshot",
  "source_citation",
  "adapter_normalization",
]);

export const EvidenceItem = z.object({
  evidence_id: MachineId,
  type: EvidenceType,
  source: EvidenceSource,
  capture_method: CaptureMethod,
  risk_tier: RiskTier,
  timestamp: IsoTimestamp,
  cwd: z.string().nullable(),
  action: z.string().nullable(),
  artifact_path: z.string().nullable(),
  inputs_hash: Hash.nullable(),
  outputs_hash: Hash.nullable(),
  exit_code: z.number().int().nullable(),
  redaction: RedactionState,
  retention_class: RetentionClass,
  expires_at: IsoTimestamp.nullable(),
  quarantined: z.boolean(),
  supports_claims: z.array(z.string()),
  limitations: z.array(z.string()),
});

export const GateStatus = z.enum(["PASS", "HOLD", "FAIL", "WAIVED"]);

export const GateResult = z.object({
  gate_result_id: MachineId,
  gate_id: HumanId,
  run_id: MachineId,
  status: GateStatus,
  blocking: z.boolean(),
  evaluated_at: IsoTimestamp,
  evaluator: z.string(),
  inputs_checked: z.array(z.string()),
  evidence_used: z.array(z.string()),
  reason: z.string(),
  findings: z.array(z.string()),
  waiver_id: z.string().nullable(),
  output_hash: Hash,
  limitations: z.array(z.string()),
});
export type GateResult = z.infer<typeof GateResult>;

/** Gates that can never be WAIVED in V1 (schema-evidence-gates.md §Unwaivable V1 controls). */
export const UNWAIVABLE_GATES: ReadonlySet<string> = new Set([
  "no-t5",
  "report-truthfulness",
  "secrets-privacy",
  "evidence-integrity",
]);

/** Invariant: an unwaivable gate cannot have status WAIVED. */
export function checkGateResultInvariants(gate: GateResult): Issue[] {
  const issues: Issue[] = [];
  if (gate.status === "WAIVED" && UNWAIVABLE_GATES.has(gate.gate_id)) {
    issues.push({
      path: `gate(${gate.gate_result_id}).status`,
      message: `gate '${gate.gate_id}' is unwaivable in V1 and cannot be WAIVED`,
    });
  }
  return issues;
}

export const EvaluationResultType = z.enum([
  "command",
  "manual-review",
  "source-citation",
  "browser-check",
  "schema-validation",
  "custom",
]);
export const EvaluationResultStatus = z.enum(["PASS", "HOLD", "FAIL", "SKIPPED"]);

export const EvaluationResult = z.object({
  evaluation_result_id: MachineId,
  evaluation_id: HumanId,
  run_id: MachineId,
  type: EvaluationResultType,
  status: EvaluationResultStatus,
  started_at: IsoTimestamp,
  completed_at: IsoTimestamp.nullable(),
  cwd: z.string().nullable(),
  command: z.string().nullable(),
  exit_code: z.number().int().nullable(),
  artifact_path: z.string().nullable(),
  output_hash: Hash.nullable(),
  evidence_ids: z.array(z.string()),
  findings: z.array(z.string()),
  limitations: z.array(z.string()),
});

export const FindingClassification = z.enum(["blocking", "accepted-risk", "deferred", "false-positive"]);
export const FindingSeverity = z.enum(["low", "medium", "high", "critical"]);

export const Finding = z.object({
  finding_id: MachineId,
  title: z.string(),
  classification: FindingClassification,
  severity: FindingSeverity,
  evidence_ids: z.array(z.string()),
  owner: z.string().nullable(),
  rationale: z.string(),
  created_at: IsoTimestamp,
  resolved_at: IsoTimestamp.nullable(),
});
export type Finding = z.infer<typeof Finding>;

/** Invariant: non-blocking classifications require an owner and a rationale. */
export function checkFindingInvariants(finding: Finding): Issue[] {
  const issues: Issue[] = [];
  if (finding.classification !== "blocking") {
    if (finding.owner === null || finding.owner.trim() === "") {
      issues.push({ path: `finding(${finding.finding_id}).owner`, message: `non-blocking finding '${finding.finding_id}' requires an owner` });
    }
    if (finding.rationale.trim() === "") {
      issues.push({ path: `finding(${finding.finding_id}).rationale`, message: `non-blocking finding '${finding.finding_id}' requires a rationale` });
    }
  }
  return issues;
}

export const Waiver = z.object({
  waiver_id: MachineId,
  gate_id: HumanId,
  approver: z.string(),
  approved_at: IsoTimestamp,
  reason: z.string(),
  scope: z.string(),
  // expires_at is a required field that may be null — it must be PRESENT.
  expires_at: IsoTimestamp.nullable(),
  review_condition: z.string(),
  approval_evidence_id: z.string(),
});
