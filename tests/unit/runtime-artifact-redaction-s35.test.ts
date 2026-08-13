import type { ZodType } from "zod";
import { describe, expect, it } from "vitest";
import * as runtime from "../../src/schema/runtime.js";

type RuntimeArtifactRedactionSchemas = {
  ArtifactRecordV02: ZodType;
  ArtifactEvidenceSubjectRefV02: ZodType;
  RedactionDerivativeRecordV02: ZodType;
  ArtifactRecordedEventV02: ZodType;
  RecordRedactionDerivativeRecordedEventV02: ZodType;
};

const schemas = runtime as unknown as RuntimeArtifactRedactionSchemas;
const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;
const HASH_C = `sha256:${"c".repeat(64)}`;
const HASH_D = `sha256:${"d".repeat(64)}`;
const HASH_E = `sha256:${"e".repeat(64)}`;

const ARTIFACT_RECORD_KEYS = [
  "artifact_path",
  "artifact_ref",
  "content_hash",
  "media_type",
  "plan_hash",
  "producer_action_id",
  "producer_task_ref",
  "record_hash",
  "run_id",
  "schema_version",
  "size_bytes",
  "write_admission_ref",
] as const;

const REDACTION_RECORD_KEYS = [
  "created_at",
  "derivative_content_hash",
  "derivative_content_path",
  "derivative_media_type",
  "derivative_ref",
  "derivative_size_bytes",
  "original_content_hash",
  "original_content_path",
  "original_content_size_bytes",
  "original_media_type",
  "original_record_hash",
  "original_record_path",
  "policy_version",
  "record_hash",
  "review_evidence_refs",
  "run_id",
  "schema_version",
  "subject_kind",
  "subject_ref",
] as const;

const ARTIFACT_EVENT_PAYLOAD_KEYS = [
  "artifact_path",
  "artifact_record_hash",
  "artifact_record_path",
  "artifact_ref",
  "content_hash",
  "media_type",
  "producer_action_id",
  "producer_task_ref",
  "size_bytes",
  "write_admission_ref",
] as const;

const REDACTION_EVENT_PAYLOAD_KEYS = [
  "created_at",
  "derivative_content_hash",
  "derivative_content_path",
  "derivative_media_type",
  "derivative_record_hash",
  "derivative_record_path",
  "derivative_ref",
  "derivative_size_bytes",
  "original_content_hash",
  "original_content_path",
  "original_content_size_bytes",
  "original_media_type",
  "original_record_hash",
  "original_record_path",
  "policy_version",
  "review_evidence_refs",
  "subject_kind",
  "subject_ref",
] as const;

function ledgerRef(sequence: number, eventHash = HASH_A): Record<string, unknown> {
  return { ledger_sequence: sequence, event_hash: eventHash };
}

function artifactDependency(sequence = 2): Record<string, unknown> {
  return {
    record_kind: "artifact",
    record_id: "artifact-main",
    record_event_ref: ledgerRef(sequence, HASH_A),
  };
}

function evidenceDependency(sequence = 3): Record<string, unknown> {
  return {
    record_kind: "evidence",
    record_id: "evidence_review_1",
    record_event_ref: ledgerRef(sequence, HASH_B),
  };
}

function validArtifactRecord(): Record<string, unknown> {
  return {
    schema_version: "0.2",
    artifact_ref: "artifact-main",
    run_id: "run_main",
    plan_hash: HASH_A,
    producer_task_ref: "task-main",
    producer_action_id: "action_main",
    write_admission_ref: ledgerRef(1),
    artifact_path: "artifacts/content/result.txt",
    content_hash: HASH_B,
    size_bytes: 0,
    media_type: "text/plain",
    record_hash: HASH_C,
  };
}

function validRedactionRecord(subjectKind: "artifact" | "evidence" = "artifact"): Record<string, unknown> {
  return {
    schema_version: "0.2",
    subject_kind: subjectKind,
    subject_ref: subjectKind === "artifact" ? "artifact-main" : "evidence_subject_1",
    derivative_ref: "derivative_main",
    run_id: "run_main",
    original_record_path: "artifacts/records/artifact-main.json",
    original_record_hash: HASH_A,
    original_content_path: "artifacts/content/result.txt",
    original_content_hash: HASH_B,
    original_content_size_bytes: 0,
    original_media_type: "text/plain",
    derivative_content_path: "custody/derivatives/pre-seal/derivative_main.bin",
    derivative_content_hash: HASH_C,
    derivative_size_bytes: Number.MAX_SAFE_INTEGER,
    derivative_media_type: "text/plain",
    policy_version: "privacy-v1",
    review_evidence_refs: [artifactDependency(), evidenceDependency()],
    created_at: "2026-08-03T12:00:00Z",
    record_hash: HASH_D,
  };
}

function envelope(eventType: string, payload: Record<string, unknown>): Record<string, unknown> {
  return {
    schema_version: "0.2",
    event_id: "event_main",
    run_id: "run_main",
    sequence: 4,
    recorded_at: "2026-08-03T12:00:01Z",
    event_type: eventType,
    source: "kernel",
    authority_ref: null,
    risk_tier: "T2",
    related_ids: ["artifact-main", "run_main"],
    previous_event_hash: HASH_D,
    event_hash: HASH_E,
    payload,
  };
}

function artifactEventPayload(): Record<string, unknown> {
  return {
    artifact_ref: "artifact-main",
    producer_task_ref: "task-main",
    producer_action_id: "action_main",
    write_admission_ref: ledgerRef(1),
    artifact_record_path: "artifacts/records/artifact-main.json",
    artifact_record_hash: HASH_C,
    artifact_path: "artifacts/content/result.txt",
    content_hash: HASH_B,
    size_bytes: 0,
    media_type: "text/plain",
  };
}

function redactionEventPayload(): Record<string, unknown> {
  const record = validRedactionRecord();
  return {
    subject_kind: record.subject_kind,
    subject_ref: record.subject_ref,
    original_record_path: record.original_record_path,
    original_record_hash: record.original_record_hash,
    original_content_path: record.original_content_path,
    original_content_hash: record.original_content_hash,
    original_content_size_bytes: record.original_content_size_bytes,
    original_media_type: record.original_media_type,
    derivative_ref: record.derivative_ref,
    derivative_record_path: "custody/derivatives/pre-seal/derivative_main.json",
    derivative_record_hash: record.record_hash,
    derivative_content_path: record.derivative_content_path,
    derivative_content_hash: record.derivative_content_hash,
    derivative_size_bytes: record.derivative_size_bytes,
    derivative_media_type: record.derivative_media_type,
    policy_version: record.policy_version,
    review_evidence_refs: record.review_evidence_refs,
    created_at: record.created_at,
  };
}

function expectExactKeys(value: unknown, keys: readonly string[]): void {
  expect(Object.keys(value as Record<string, unknown>).sort()).toEqual(keys);
}

describe("Task 3C0a artifact and pre-seal redaction records", () => {
  it("accepts only the exact 12-field ArtifactRecordV02 structure", () => {
    const record = validArtifactRecord();
    const parsed = schemas.ArtifactRecordV02.safeParse(record);
    expect(parsed.success).toBe(true);
    if (parsed.success) expectExactKeys(parsed.data, ARTIFACT_RECORD_KEYS);

    expect(schemas.ArtifactRecordV02.safeParse({ ...record, source_event_ref: ledgerRef(2) }).success).toBe(false);
    expect(schemas.ArtifactRecordV02.safeParse({ ...record, event_hash: HASH_D }).success).toBe(false);
    expect(schemas.ArtifactRecordV02.safeParse({ ...record, manifest_hash: HASH_D }).success).toBe(false);
    expect(schemas.ArtifactRecordV02.safeParse({ ...record, artifact_record_hash: HASH_D }).success).toBe(false);
  });

  it("enforces artifact size, media type, and relative-path boundaries", () => {
    const record = validArtifactRecord();
    expect(schemas.ArtifactRecordV02.safeParse({ ...record, size_bytes: Number.MAX_SAFE_INTEGER }).success).toBe(true);
    expect(schemas.ArtifactRecordV02.safeParse({ ...record, size_bytes: -1 }).success).toBe(false);
    expect(schemas.ArtifactRecordV02.safeParse({ ...record, size_bytes: Number.MAX_SAFE_INTEGER + 1 }).success).toBe(false);
    expect(schemas.ArtifactRecordV02.safeParse({ ...record, media_type: "  " }).success).toBe(false);
    expect(schemas.ArtifactRecordV02.safeParse({ ...record, media_type: "text/\ud83d\ude00" }).success).toBe(true);
    expect(schemas.ArtifactRecordV02.safeParse({ ...record, media_type: "text/plain\ud800" }).success).toBe(false);
    expect(schemas.ArtifactRecordV02.safeParse({ ...record, artifact_path: "../escape.txt" }).success).toBe(false);
  });

  it("discriminates artifact HumanId and evidence MachineId subject namespaces", () => {
    expect(schemas.ArtifactEvidenceSubjectRefV02.safeParse({ subject_kind: "artifact", subject_ref: "artifact-main" }).success).toBe(true);
    expect(schemas.ArtifactEvidenceSubjectRefV02.safeParse({ subject_kind: "evidence", subject_ref: "evidence_subject_1" }).success).toBe(true);
    expect(schemas.ArtifactEvidenceSubjectRefV02.safeParse({ subject_kind: "artifact", subject_ref: "artifact_subject_1" }).success).toBe(false);
    expect(schemas.ArtifactEvidenceSubjectRefV02.safeParse({ subject_kind: "evidence", subject_ref: "evidence-main" }).success).toBe(false);
    expect(schemas.ArtifactEvidenceSubjectRefV02.safeParse({ subject_kind: "artifact", subject_ref: "artifact-main", extra: true }).success).toBe(false);
  });

  it("accepts only the exact complete RedactionDerivativeRecordV02 structure", () => {
    for (const subjectKind of ["artifact", "evidence"] as const) {
      const parsed = schemas.RedactionDerivativeRecordV02.safeParse(validRedactionRecord(subjectKind));
      expect(parsed.success).toBe(true);
      if (parsed.success) expectExactKeys(parsed.data, REDACTION_RECORD_KEYS);
    }

    const record = validRedactionRecord();
    for (const forbiddenKey of ["source_event_ref", "event_hash", "manifest_hash", "custody_event_ref", "export_decision_ref"] as const) {
      expect(schemas.RedactionDerivativeRecordV02.safeParse({ ...record, [forbiddenKey]: HASH_E }).success).toBe(false);
    }
    const { original_content_hash: _omitted, ...incompleteOriginalTuple } = record;
    expect(schemas.RedactionDerivativeRecordV02.safeParse(incompleteOriginalTuple).success).toBe(false);
  });

  it("requires non-empty UTF-8-ordered unique review dependency refs and safe sizes", () => {
    const record = validRedactionRecord();
    expect(schemas.RedactionDerivativeRecordV02.safeParse({ ...record, review_evidence_refs: [] }).success).toBe(false);
    expect(schemas.RedactionDerivativeRecordV02.safeParse({ ...record, review_evidence_refs: [evidenceDependency(), artifactDependency()] }).success).toBe(false);
    expect(schemas.RedactionDerivativeRecordV02.safeParse({ ...record, review_evidence_refs: [artifactDependency(), artifactDependency()] }).success).toBe(false);
    expect(schemas.RedactionDerivativeRecordV02.safeParse({ ...record, original_content_size_bytes: -1 }).success).toBe(false);
    expect(schemas.RedactionDerivativeRecordV02.safeParse({ ...record, derivative_size_bytes: Number.MAX_SAFE_INTEGER + 1 }).success).toBe(false);
    expect(schemas.RedactionDerivativeRecordV02.safeParse({ ...record, policy_version: "" }).success).toBe(false);
    for (const field of ["original_media_type", "derivative_media_type", "policy_version"] as const) {
      expect(schemas.RedactionDerivativeRecordV02.safeParse({ ...record, [field]: `valid-\ud83d\ude00` }).success).toBe(true);
      expect(schemas.RedactionDerivativeRecordV02.safeParse({ ...record, [field]: `invalid\ud800` }).success).toBe(false);
    }
  });
});

describe("Task 3C0a artifact and redaction event constructors", () => {
  it("accepts exact artifact.recorded payload and rejects unknown keys", () => {
    const payload = artifactEventPayload();
    const parsed = schemas.ArtifactRecordedEventV02.safeParse(envelope("artifact.recorded", payload));
    expect(parsed.success).toBe(true);
    if (parsed.success) expectExactKeys((parsed.data as { payload: unknown }).payload, ARTIFACT_EVENT_PAYLOAD_KEYS);

    expect(schemas.ArtifactRecordedEventV02.safeParse(envelope("artifact.recorded", { ...payload, source_event_ref: ledgerRef(2) })).success).toBe(false);
    expect(schemas.ArtifactRecordedEventV02.safeParse(envelope("artifact.recorded", { ...payload, media_type: "text/plain\ud800" })).success).toBe(false);
    expect(schemas.ArtifactRecordedEventV02.safeParse({ ...envelope("artifact.recorded", payload), extra: true }).success).toBe(false);
  });

  it("requires kernel source and null authority for artifact.recorded", () => {
    const event = envelope("artifact.recorded", artifactEventPayload());
    expect(schemas.ArtifactRecordedEventV02.safeParse({ ...event, source: "adapter" }).success).toBe(false);
    expect(schemas.ArtifactRecordedEventV02.safeParse({ ...event, authority_ref: "authority_main" }).success).toBe(false);
    expect(schemas.ArtifactRecordedEventV02.safeParse({ ...event, event_type: "record.redaction-derivative-recorded" }).success).toBe(false);
  });

  it("accepts exact record.redaction-derivative-recorded payload and rejects unknown keys", () => {
    const payload = redactionEventPayload();
    const parsed = schemas.RecordRedactionDerivativeRecordedEventV02.safeParse(
      envelope("record.redaction-derivative-recorded", payload),
    );
    expect(parsed.success).toBe(true);
    if (parsed.success) expectExactKeys((parsed.data as { payload: unknown }).payload, REDACTION_EVENT_PAYLOAD_KEYS);

    expect(schemas.RecordRedactionDerivativeRecordedEventV02.safeParse(
      envelope("record.redaction-derivative-recorded", { ...payload, custody_event_ref: ledgerRef(3) }),
    ).success).toBe(false);
    for (const field of ["original_media_type", "derivative_media_type", "policy_version"] as const) {
      expect(schemas.RecordRedactionDerivativeRecordedEventV02.safeParse(
        envelope("record.redaction-derivative-recorded", { ...payload, [field]: `invalid\ud800` }),
      ).success).toBe(false);
    }
    expect(schemas.RecordRedactionDerivativeRecordedEventV02.safeParse({
      ...envelope("record.redaction-derivative-recorded", payload),
      extra: true,
    }).success).toBe(false);
  });

  it("requires kernel source, null authority, exact subject namespace, ordered reviews, and safe sizes", () => {
    const payload = redactionEventPayload();
    const event = envelope("record.redaction-derivative-recorded", payload);
    expect(schemas.RecordRedactionDerivativeRecordedEventV02.safeParse({ ...event, source: "evaluator" }).success).toBe(false);
    expect(schemas.RecordRedactionDerivativeRecordedEventV02.safeParse({ ...event, authority_ref: "authority_main" }).success).toBe(false);
    expect(schemas.RecordRedactionDerivativeRecordedEventV02.safeParse(envelope(event.event_type as string, {
      ...payload,
      subject_kind: "artifact",
      subject_ref: "artifact_subject_1",
    })).success).toBe(false);
    expect(schemas.RecordRedactionDerivativeRecordedEventV02.safeParse(envelope(event.event_type as string, {
      ...payload,
      review_evidence_refs: [evidenceDependency(), artifactDependency()],
    })).success).toBe(false);
    expect(schemas.RecordRedactionDerivativeRecordedEventV02.safeParse(envelope(event.event_type as string, {
      ...payload,
      derivative_size_bytes: -1,
    })).success).toBe(false);
  });
});
