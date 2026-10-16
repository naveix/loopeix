import type { ZodType } from "zod";
import { describe, expect, it } from "vitest";
import * as runtime from "../../src/schema/runtime.js";

type CustodyExportSchemas = {
  RecordCustodyStateRecordedEventV02: ZodType;
  RecordExportDecisionRecordedEventV02: ZodType;
};

const schemas = runtime as unknown as CustodyExportSchemas;
const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;
const SUBJECT_HASH = "sha256:4541cd1bdcf59c101feed5390430a570ef633831879ceefaa1883bcd9b282fca";

function ref(sequence: number): Record<string, unknown> {
  return { ledger_sequence: sequence, event_hash: HASH_A };
}

function envelope(eventType: string, source: string, payload: Record<string, unknown>): Record<string, unknown> {
  return {
    schema_version: "0.2", event_id: "event_custody_1", run_id: "run_main", sequence: 4,
    recorded_at: "2026-08-10T12:00:00Z", event_type: eventType, source, authority_ref: null,
    risk_tier: "T2", related_ids: [], previous_event_hash: HASH_A, event_hash: HASH_B, payload,
  };
}

describe("S35 custody and export-decision events", () => {
  it("enforces the closed pre-seal custody branches", () => {
    const payload = {
      subject_kind: "artifact", subject_ref: "artifact-a", subject_hash: SUBJECT_HASH,
      previous_state_event_ref: null, retention_class: "run", expires_at: null,
      quarantine_status: "clear", quarantine_reason: null, integrity_status: "valid",
      integrity_finding_refs: [], export_state: "exportable", export_reason: null,
      export_decision_event_ref: ref(2), policy_version: "policy-v1", evidence_refs: [ref(1)],
    };
    expect(schemas.RecordCustodyStateRecordedEventV02.safeParse(envelope(
      "record.custody-state-recorded", "kernel", payload,
    )).success).toBe(true);
    expect(schemas.RecordCustodyStateRecordedEventV02.safeParse(envelope(
      "record.custody-state-recorded", "kernel", { ...payload, quarantine_status: "quarantined" },
    )).success).toBe(false);
    expect(schemas.RecordCustodyStateRecordedEventV02.safeParse(envelope(
      "record.custody-state-recorded", "kernel", { ...payload, export_decision_event_ref: null },
    )).success).toBe(false);
  });

  it("recomputes artifact export subject hashes and enforces independent checks", () => {
    const selectedBytes = {
      kind: "original-content", ref: "artifact-a", path: "artifacts/content/a.txt",
      hash: HASH_A, size_bytes: 2, media_type: "text/plain", binding_ref: ref(1),
    };
    const check = (kind: "credential" | "privacy") => ({
      result_ref: {
        record_kind: "evaluation-result", record_id: `result_${kind}`, record_event_ref: ref(kind === "credential" ? 2 : 3),
      },
      evaluation_ref: kind === "credential" ? "credential-scan" : "privacy-review",
      evaluator_identity_ref: kind === "credential" ? "evaluator_credential" : "evaluator_privacy",
      policy_digest: HASH_A, subject_hash: SUBJECT_HASH,
    });
    const payload = {
      decision_id: "decision_1", record_path: "custody/export-decision_1.json", record_hash: HASH_A,
      subject_kind: "artifact", subject_ref: "artifact-a", original_record_hash: HASH_A,
      original_content_hash: HASH_A, selected_bytes: selectedBytes, subject_hash: SUBJECT_HASH,
      decision: "exportable", credential_scan_evidence_refs: [check("credential")],
      privacy_review_evidence_refs: [check("privacy")], policy_version: "policy-v1",
    };
    expect(schemas.RecordExportDecisionRecordedEventV02.safeParse(envelope(
      "record.export-decision-recorded", "evaluator", payload,
    )).success).toBe(true);
    expect(schemas.RecordExportDecisionRecordedEventV02.safeParse(envelope(
      "record.export-decision-recorded", "evaluator", { ...payload, subject_hash: HASH_B },
    )).success).toBe(false);
    expect(schemas.RecordExportDecisionRecordedEventV02.safeParse(envelope(
      "record.export-decision-recorded", "evaluator", { ...payload, credential_scan_evidence_refs: [] },
    )).success).toBe(false);
    expect(schemas.RecordExportDecisionRecordedEventV02.safeParse(envelope(
      "record.export-decision-recorded", "evaluator", {
        ...payload,
        privacy_review_evidence_refs: [{ ...check("privacy"), evaluator_identity_ref: "evaluator_credential" }],
      },
    )).success).toBe(false);
    expect(schemas.RecordExportDecisionRecordedEventV02.safeParse(envelope(
      "record.export-decision-recorded", "evaluator", {
        ...payload,
        privacy_review_evidence_refs: [{
          ...check("privacy"),
          result_ref: check("credential").result_ref,
        }],
      },
    )).success).toBe(false);
    expect(schemas.RecordExportDecisionRecordedEventV02.safeParse(envelope(
      "record.export-decision-recorded", "evaluator", {
        ...payload,
        privacy_review_evidence_refs: [{
          ...check("privacy"),
          evaluation_ref: check("credential").evaluation_ref,
        }],
      },
    )).success).toBe(false);
  });
});
