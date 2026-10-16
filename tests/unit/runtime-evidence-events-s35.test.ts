import type { ZodType } from "zod";
import { describe, expect, it } from "vitest";
import * as runtime from "../../src/schema/runtime.js";

type EvidenceEventSchemas = {
  EvidenceRecordedEventV02: ZodType;
  ObservationManualRecordedEventV02: ZodType;
  ClaimRecordedEventV02: ZodType;
  FindingRecordedEventV02: ZodType;
  WaiverRecordedEventV02: ZodType;
};

const schemas = runtime as unknown as EvidenceEventSchemas;
const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;

function ref(sequence: number, eventHash = HASH_A): Record<string, unknown> {
  return { ledger_sequence: sequence, event_hash: eventHash };
}

function envelope(
  eventType: string,
  source: string,
  payload: Record<string, unknown>,
  authorityRef: string | null = null,
): Record<string, unknown> {
  return {
    schema_version: "0.2", event_id: "event_evidence_1", run_id: "run_main", sequence: 4,
    recorded_at: "2026-08-10T12:00:00Z", event_type: eventType, source,
    authority_ref: authorityRef, risk_tier: "T2", related_ids: [],
    previous_event_hash: HASH_A, event_hash: HASH_B, payload,
  };
}

describe("S35 evidence-lineage events", () => {
  it("enforces complete evidence content and canonical independence roots", () => {
    const payload = {
      evidence_id: "evidence_1",
      requirement_refs: ["requirement-a"],
      evidence_kind: "command-capture",
      independence_roots: [{
        root_event_ref: ref(1), source_class: "command", authority_root_ref: ref(1),
        authenticated_principal_ref: null, acquisition_scope_hash: HASH_A, independence_key: HASH_A,
      }],
      record_path: "evidence/evidence_1.json", content_path: "evidence/content/output.txt",
      record_hash: HASH_A, content_hash: HASH_A, size_bytes: 2, media_type: "text/plain",
      producer_event_ref: ref(2),
    };
    expect(schemas.EvidenceRecordedEventV02.safeParse(envelope("evidence.recorded", "kernel", payload)).success).toBe(true);
    expect(schemas.EvidenceRecordedEventV02.safeParse(envelope("evidence.recorded", "kernel", { ...payload, content_hash: null })).success).toBe(false);
    expect(schemas.EvidenceRecordedEventV02.safeParse(envelope("evidence.recorded", "kernel", {
      ...payload,
      independence_roots: [{ ...payload.independence_roots[0], authenticated_principal_ref: "principal_1" }],
    })).success).toBe(false);
  });

  it("binds manual observations to the authenticated operator principal", () => {
    const payload = {
      observation_id: "observation_1", record_path: "evidence/observation_1.json", record_hash: HASH_A,
      run_id: "run_main", authenticated_principal_ref: "principal_1", subject_hash: HASH_A,
      observation_scope_hash: HASH_A, observed_at: "2026-08-10T12:00:00Z", limitations: ["limited scope"],
    };
    expect(schemas.ObservationManualRecordedEventV02.safeParse(envelope("observation.manual-recorded", "operator", payload, "principal_1")).success).toBe(true);
    expect(schemas.ObservationManualRecordedEventV02.safeParse(envelope("observation.manual-recorded", "operator", payload, "principal_2")).success).toBe(false);
    expect(schemas.ObservationManualRecordedEventV02.safeParse(envelope("observation.manual-recorded", "operator", { ...payload, run_id: "run_other" }, "principal_1")).success).toBe(false);
  });

  it("accepts only canonical non-empty gate/evaluation verdict sets for claims", () => {
    const payload = {
      claim_id: "claim_1", subject: { kind: "gate", subject_ref: "gate-a" }, evidence_policy_hash: HASH_A,
      verdict_record_refs: [{ record_kind: "gate-result", record_id: "result_1", record_event_ref: ref(1) }],
      status: "verified", record_path: "claims/claim_1.json", record_hash: HASH_A,
      dependency_record_refs: [], observation_root_refs: [ref(1)],
    };
    expect(schemas.ClaimRecordedEventV02.safeParse(envelope("claim.recorded", "kernel", payload)).success).toBe(true);
    expect(schemas.ClaimRecordedEventV02.safeParse(envelope("claim.recorded", "kernel", { ...payload, verdict_record_refs: [] })).success).toBe(false);
    expect(schemas.ClaimRecordedEventV02.safeParse(envelope("claim.recorded", "kernel", { ...payload, status: "waived" })).success).toBe(false);
  });

  it("uses a closed source/authority branch for finding disposition", () => {
    const blocking = {
      finding_id: "finding_1", classification: "blocking",
      disposition_authority_principal_ref: null, disposition_authorization_statement_hash: null,
      reviewed_through_ref: null, record_path: "findings/finding_1.json", record_hash: HASH_A,
      dependency_record_refs: [], observation_root_refs: [],
    };
    expect(schemas.FindingRecordedEventV02.safeParse(envelope("finding.recorded", "evaluator", blocking)).success).toBe(true);
    const accepted = {
      ...blocking, classification: "accepted-risk", disposition_authority_principal_ref: "principal_1",
      disposition_authorization_statement_hash: HASH_A, reviewed_through_ref: ref(2),
    };
    expect(schemas.FindingRecordedEventV02.safeParse(envelope("finding.recorded", "operator", accepted, "principal_1")).success).toBe(true);
    expect(schemas.FindingRecordedEventV02.safeParse(envelope("finding.recorded", "evaluator", accepted)).success).toBe(false);
  });

  it("enforces waiver provenance, epochs, and canonical dependencies", () => {
    const payload = {
      waiver_id: "waiver_1", gate_ref: "gate-a", record_path: "waivers/waiver_1.json", record_hash: HASH_A,
      authority_record_ref: ref(1), action_scope_hash: HASH_A, authority_revocation_epoch: 0,
      authority_envelope_revocation_epoch: 0, required_event_ref: ref(1), prerequisite_set_hash: HASH_A,
      approved_risk_tier: "T2", reviewed_through_ref: ref(1), boundary_clock_ref: ref(2),
      dependency_record_refs: [], observation_root_refs: [],
    };
    expect(schemas.WaiverRecordedEventV02.safeParse(envelope("waiver.recorded", "operator", payload, "principal_1")).success).toBe(true);
    expect(schemas.WaiverRecordedEventV02.safeParse(envelope("waiver.recorded", "operator", payload)).success).toBe(false);
    expect(schemas.WaiverRecordedEventV02.safeParse(envelope("waiver.recorded", "operator", { ...payload, authority_revocation_epoch: -1 }, "principal_1")).success).toBe(false);
  });
});
