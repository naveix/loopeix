import { z } from "zod";
import { hashCanonical } from "../hash.js";
import { AcceptanceClause, ForbiddenClause } from "./brief.js";
import { EvidenceType } from "./evidence.js";
import type { Issue } from "./loopeix.js";
import { IntegrityStatus, RunState } from "./runtime.js";
import { Hash, HumanId, IsoTimestamp, LoopVersion, MachineId } from "./scalars.js";

/**
 * Signed receipt schema, receipt_version 0.1 (flagship-decision.md, claim-families-v1.md).
 *
 * Two-layer design (ADR 0001), with one deliberate strengthening: the CONSERVATIVE DOCTRINE rule
 * — a `CONTRADICTED` claim or `PROMISE_BROKEN` clause MUST cite at least one evidence id — is
 * encoded STRUCTURALLY as a discriminated union, not as a refinement. That way the rule survives
 * into the generated JSON Schema (`schemas/receipt.schema.json`), so even a stranger validating
 * with plain ajv — no Loopeix code at all — cannot accept an uncited condemnation. Cross-field
 * rules JSON Schema cannot express (evidence-id resolution, summary counts, brief-hash
 * recomputation) live in `checkReceiptInvariants`, same as `checkLoopeixInvariants`.
 *
 * The receipt is an INDEX, not a payload: evidence entries carry hashes and capture metadata,
 * never raw content — the receipt travels, the evidence does not (local-first).
 */

export const ReceiptVerdict = z.enum(["VERIFIED", "CONTRADICTED", "UNSUPPORTED"]);
export const ClauseVerdict = z.enum(["KEPT", "PROMISE_BROKEN", "UNEVALUATED"]);
export const ClaimFamily = z.enum(["tests-ran", "recognized-assertion"]);
export const ClauseType = z.enum(["acceptance", "forbidden", "scope"]);
export const ReceiptEngine = z.enum(["codex_cli", "claude_code_cli"]);
export const ReceiptCaptureLevel = z.enum(["full", "partial"]);
export const ReceiptEvidenceSource = z.enum(["wrapper", "engine_stream"]);

const Base64 = z.string().regex(/^[A-Za-z0-9+/]+={0,2}$/, "must be base64");

/** The signature block emitted by `signCanonical` (src/sign.ts). */
export const ReceiptSignature = z.object({
  algorithm: z.literal("ecdsa-p256-sha256"),
  encoding: z.literal("der-base64"),
  public_key_spki_b64: Base64,
  signature_b64: Base64,
});

/** The sealed promise, embedded in public form. `brief_hash` covers the five content fields.
 *  Acceptance/forbidden entries are the STRUCTURED clause objects of schema/brief.ts (labels
 *  remain the display strings; `kind` names the adjudicating claim family). */
export const ReceiptBrief = z.object({
  brief_version: z.literal("0.1"),
  task: z.string().min(1),
  acceptance: z.array(AcceptanceClause).min(1),
  forbidden: z.array(ForbiddenClause),
  scope: z.array(z.string().min(1)),
  brief_hash: Hash,
});

const claimBase = {
  claim_id: MachineId,
  family: ClaimFamily,
  text: z.string().min(1),
  evidence_ids: z.array(z.string()),
  reason: z.string().optional(),
};

/** Doctrine, structurally: `CONTRADICTED` is unrepresentable without a cited evidence id. */
export const ReceiptClaim = z.discriminatedUnion("verdict", [
  z.object({ ...claimBase, verdict: z.literal("CONTRADICTED"), evidence_ids: z.array(z.string()).min(1) }),
  z.object({ ...claimBase, verdict: z.enum(["VERIFIED", "UNSUPPORTED"]) }),
]);
export type ReceiptClaimRecord = z.infer<typeof ReceiptClaim>;

const clauseBase = {
  clause_id: MachineId,
  clause_type: ClauseType,
  text: z.string().min(1),
  evidence_ids: z.array(z.string()),
  reason: z.string().optional(),
};

/** Doctrine, structurally: `PROMISE_BROKEN` is unrepresentable without a cited evidence id. */
export const ReceiptClause = z.discriminatedUnion("verdict", [
  z.object({ ...clauseBase, verdict: z.literal("PROMISE_BROKEN"), evidence_ids: z.array(z.string()).min(1) }),
  z.object({ ...clauseBase, verdict: z.enum(["KEPT", "UNEVALUATED"]) }),
]);
export type ReceiptClauseRecord = z.infer<typeof ReceiptClause>;

/** Evidence INDEX entry: hash + capture metadata only, never raw content. */
export const ReceiptEvidence = z.object({
  evidence_id: MachineId,
  type: EvidenceType,
  sha256: Hash.optional(),
  capture_level: ReceiptCaptureLevel,
  source: ReceiptEvidenceSource,
});
export type ReceiptEvidenceRecord = z.infer<typeof ReceiptEvidence>;

/** Same field shape as ReportInput's capture_gaps (src/report.ts). */
export const ReceiptCaptureGap = z.object({
  engine: z.string(),
  capability: z.string(),
  level: z.string(),
  note: z.string(),
});

const VerdictCount = z.number().int().min(0);

export const ReceiptSummary = z.object({
  claims: z.object({ verified: VerdictCount, contradicted: VerdictCount, unsupported: VerdictCount }),
  clauses: z.object({ kept: VerdictCount, promise_broken: VerdictCount, unevaluated: VerdictCount }),
});
export type ReceiptSummaryRecord = z.infer<typeof ReceiptSummary>;

/** The structural receipt object. Feeds `z.toJSONSchema` (schemas/receipt.schema.json). */
export const ReceiptShape = z.object({
  receipt_version: z.literal("0.1"),
  run: z.object({
    run_id: MachineId,
    loop_family: HumanId,
    loopeix_version: LoopVersion,
    engine: ReceiptEngine,
    run_state: RunState,
    integrity_status: IntegrityStatus,
    sealed_at: IsoTimestamp,
  }),
  brief: ReceiptBrief,
  /** Binds the receipt to EXACT ledger bytes: count, chain head, and hash of the serialized JSONL. */
  ledger_binding: z.object({
    event_count: z.number().int().min(0),
    head_event_hash: Hash,
    ledger_sha256: Hash,
  }),
  claims: z.array(ReceiptClaim),
  brief_clauses: z.array(ReceiptClause),
  evidence: z.array(ReceiptEvidence),
  capture_gaps: z.array(ReceiptCaptureGap),
  summary: ReceiptSummary,
  signature: ReceiptSignature,
});
export type Receipt = z.infer<typeof ReceiptShape>;

/**
 * Cross-field invariants JSON Schema cannot express (same second-pass style as
 * `checkLoopeixInvariants`). Runs on an already structurally-valid Receipt:
 *  - claim/clause/evidence ids are unique;
 *  - every referenced evidence_id resolves to an entry in evidence[];
 *  - summary counts equal the actual per-verdict counts;
 *  - brief_hash recomputes from the brief's content fields (a re-worded promise cannot
 *    keep the old hash).
 */
export function checkReceiptInvariants(receipt: Receipt): Issue[] {
  const issues: Issue[] = [];

  const dup = (ids: readonly string[], label: string): void => {
    const seen = new Set<string>();
    for (const id of ids) {
      if (seen.has(id)) issues.push({ path: label, message: `duplicate ${label} id: '${id}'` });
      seen.add(id);
    }
  };
  dup(receipt.claims.map((c) => c.claim_id), "claims");
  dup(receipt.brief_clauses.map((c) => c.clause_id), "brief_clauses");
  dup(receipt.evidence.map((e) => e.evidence_id), "evidence");

  const evidenceIds = new Set(receipt.evidence.map((e) => e.evidence_id));
  receipt.claims.forEach((c, i) => {
    c.evidence_ids.forEach((id, j) => {
      if (!evidenceIds.has(id)) {
        issues.push({ path: `claims[${i}].evidence_ids[${j}]`, message: `claim '${c.claim_id}' cites unknown evidence '${id}'` });
      }
    });
  });
  receipt.brief_clauses.forEach((c, i) => {
    c.evidence_ids.forEach((id, j) => {
      if (!evidenceIds.has(id)) {
        issues.push({ path: `brief_clauses[${i}].evidence_ids[${j}]`, message: `clause '${c.clause_id}' cites unknown evidence '${id}'` });
      }
    });
  });

  const count = <T extends string>(verdicts: readonly T[], v: T): number => verdicts.filter((x) => x === v).length;
  const claimVerdicts = receipt.claims.map((c) => c.verdict);
  const clauseVerdicts = receipt.brief_clauses.map((c) => c.verdict);
  const expected: ReceiptSummaryRecord = {
    claims: {
      verified: count(claimVerdicts, "VERIFIED"),
      contradicted: count(claimVerdicts, "CONTRADICTED"),
      unsupported: count(claimVerdicts, "UNSUPPORTED"),
    },
    clauses: {
      kept: count(clauseVerdicts, "KEPT"),
      promise_broken: count(clauseVerdicts, "PROMISE_BROKEN"),
      unevaluated: count(clauseVerdicts, "UNEVALUATED"),
    },
  };
  for (const [group, counts] of Object.entries(expected) as [keyof ReceiptSummaryRecord, Record<string, number>][]) {
    for (const [verdict, n] of Object.entries(counts)) {
      const actual = (receipt.summary[group] as Record<string, number>)[verdict];
      if (actual !== n) {
        issues.push({ path: `summary.${group}.${verdict}`, message: `summary says ${actual} but the receipt contains ${n}` });
      }
    }
  }

  const { brief_hash, ...briefContent } = receipt.brief;
  const recomputed = hashCanonical(briefContent);
  if (recomputed !== brief_hash) {
    issues.push({ path: "brief.brief_hash", message: "brief_hash does not match the brief's content fields (promise text altered)" });
  }

  return issues;
}

/** Compute the `brief_hash` for a brief's content fields (what `buildReceipt` embeds). */
export function computeBriefHash(brief: Omit<z.infer<typeof ReceiptBrief>, "brief_hash">): string {
  return hashCanonical(brief);
}
