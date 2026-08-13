import { describe, expect, it } from "vitest";

import { hashCanonical, hashRawBytes } from "../../src/hash.js";
import { hashAuthorityScopeV02 } from "../../src/schema/runtime.js";
import {
  RUNTIME_RECORD_FAMILY_REGISTRY_V02,
  admitRuntimeRecordsV02,
} from "../../src/run/runtime-record-admission-v02.js";
import type { RuntimeEventV02Value } from "../../src/schema/runtime.js";
import {
  createAgencyRecommendationRecordFixtureS36,
  createAuthorityRevocationRecordFixtureS36,
  createBaseAuthorityScopeFixtureS35,
} from "../helpers/runtime-admission-fixture-s35.js";

const RUN_ID = "run_record_admission";
const PLAN_HASH = `sha256:${"a".repeat(64)}`;
const OTHER_HASH = `sha256:${"b".repeat(64)}`;

function jsonBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(`${JSON.stringify(value)}\n`);
}

function artifactFixture() {
  const content = new TextEncoder().encode("artifact bytes");
  const contentHash = hashRawBytes(content);
  const recordPreimage = {
    schema_version: "0.2",
    artifact_ref: "artifact-main",
    run_id: RUN_ID,
    plan_hash: PLAN_HASH,
    producer_task_ref: "task-main",
    producer_action_id: "action_main",
    write_admission_ref: { ledger_sequence: 1, event_hash: OTHER_HASH },
    artifact_path: "artifacts/content/result.txt",
    content_hash: contentHash,
    size_bytes: content.byteLength,
    media_type: "text/plain",
  };
  const record = { ...recordPreimage, record_hash: hashCanonical(recordPreimage) };
  const recordBytes = jsonBytes(record);
  const event = {
    run_id: RUN_ID,
    event_type: "artifact.recorded",
    payload: {
      artifact_ref: record.artifact_ref,
      producer_task_ref: record.producer_task_ref,
      producer_action_id: record.producer_action_id,
      write_admission_ref: record.write_admission_ref,
      artifact_record_path: "artifacts/records/artifact-main.json",
      artifact_record_hash: record.record_hash,
      artifact_path: record.artifact_path,
      content_hash: record.content_hash,
      size_bytes: record.size_bytes,
      media_type: record.media_type,
    },
  } as RuntimeEventV02Value;
  const bytes = new Map<string, Uint8Array>([
    [event.payload.artifact_record_path, recordBytes],
    [event.payload.artifact_path, content],
  ]);
  const hashes = new Map([...bytes].map(([path, value]) => [path, hashRawBytes(value)]));
  return { event, record, recordBytes, content, bytes, hashes };
}

function humanAuthorizationFixture() {
  const proofFields = {
    schema_version: "0.2",
    authorization_id: "authorization_main",
    run_id: RUN_ID,
    plan_hash: PLAN_HASH,
    authorization_subject_hash: OTHER_HASH,
    authenticated_principal_ref: "principal_main",
    authentication_context_hash: OTHER_HASH,
    action_scope_hash: OTHER_HASH,
    approved_risk_tier: "T2",
    operator_key_id: "key_main",
    approval_channel: "local-ed25519",
    approval_nonce: OTHER_HASH,
    proof_algorithm: "ed25519",
    proof_value: "c2lnbmF0dXJl",
    issued_at: "2026-08-10T12:00:00Z",
    expires_at: "2026-08-10T12:05:00Z",
    revocation_epoch: 0,
  } as const;
  const { proof_value: _proofValue, ...statementPreimage } = proofFields;
  const recordPreimage = {
    ...proofFields,
    authorization_statement_hash: hashCanonical(statementPreimage),
  };
  const record = { ...recordPreimage, record_hash: hashCanonical(recordPreimage) };
  const event = {
    run_id: RUN_ID,
    event_type: "authority.human-authorization-recorded",
    payload: {
      authorization_id: record.authorization_id,
      record_path: "authorities/human/authorization_main.json",
      record_hash: record.record_hash,
      run_id: record.run_id,
      plan_hash: record.plan_hash,
      authorization_subject_hash: record.authorization_subject_hash,
      authenticated_principal_ref: record.authenticated_principal_ref,
      authentication_context_hash: record.authentication_context_hash,
      action_scope_hash: record.action_scope_hash,
      approved_risk_tier: record.approved_risk_tier,
      operator_key_id: record.operator_key_id,
      approval_channel: record.approval_channel,
      approval_nonce: record.approval_nonce,
      proof_algorithm: record.proof_algorithm,
      authorization_statement_hash: record.authorization_statement_hash,
      issued_at: record.issued_at,
      expires_at: record.expires_at,
      revocation_epoch: record.revocation_epoch,
    },
  } as RuntimeEventV02Value;
  const recordBytes = jsonBytes(record);
  const bytes = new Map<string, Uint8Array>([
    [event.payload.record_path, recordBytes],
  ]);
  const hashes = new Map([...bytes].map(([path, value]) => [path, hashRawBytes(value)]));
  return { event, record, bytes, hashes };
}

function authorityEnvelopeFixture() {
  const authorityScope = createBaseAuthorityScopeFixtureS35();
  const authoritySubject = authorityScope.authority_subject as { policy_digest: string };
  const issuer = { principal_ref: "operator_1", stable_identity_hash: OTHER_HASH };
  const subject = { principal_ref: "agent_1", stable_identity_hash: PLAN_HASH };
  const lineage = {
    kind: "root" as const,
    root_authority_envelope_ref: null,
    parent_authority_envelope_ref: null,
    delegation: null,
    on_behalf_of_chain: [issuer, subject],
    delegation_depth: 0 as const,
  };
  const actionScopeHash = hashAuthorityScopeV02(authorityScope as never);
  const authorizationSubjectHash = hashCanonical({
    purpose: "authority-envelope-subject-v02", schema_version: "0.2",
    authority_envelope_id: "envelope_main", run_id: RUN_ID, plan_hash: PLAN_HASH,
    policy_digest: authoritySubject.policy_digest, subject, issuer,
    action_scope_hash: actionScopeHash, lineage,
    issued_at: "2026-08-10T12:00:00Z", expires_at: "2026-08-10T12:05:00Z", revocation_epoch: 0,
  });
  const recordPreimage = {
    schema_version: "0.2" as const, authority_envelope_id: "envelope_main", run_id: RUN_ID,
    plan_hash: PLAN_HASH, policy_digest: authoritySubject.policy_digest, subject, issuer,
    authorization_subject_hash: authorizationSubjectHash,
    human_authorization_proof_refs: [{ ledger_sequence: 1, event_hash: OTHER_HASH }],
    authority_scope: authorityScope, action_scope_hash: actionScopeHash, lineage,
    issued_at: "2026-08-10T12:00:00Z", expires_at: "2026-08-10T12:05:00Z", revocation_epoch: 0,
  };
  const record = { ...recordPreimage, record_hash: hashCanonical(recordPreimage) };
  const event = {
    run_id: RUN_ID,
    event_type: "authority.envelope-recorded",
    payload: {
      authority_envelope_id: record.authority_envelope_id,
      record_path: "authorities/envelopes/envelope_main.json", record_hash: record.record_hash,
      run_id: record.run_id, plan_hash: record.plan_hash, policy_digest: record.policy_digest,
      subject_ref: record.subject.principal_ref, issuer_principal_ref: record.issuer.principal_ref,
      authorization_subject_hash: record.authorization_subject_hash,
      human_authorization_proof_refs: record.human_authorization_proof_refs,
      action_class: authorityScope.action_class, action_scope_hash: record.action_scope_hash,
      max_risk_tier: authorityScope.max_risk_tier, issued_at: record.issued_at,
      expires_at: record.expires_at, revocation_epoch: record.revocation_epoch, delegation_depth: 0,
    },
  } as RuntimeEventV02Value;
  const recordBytes = jsonBytes(record);
  const bytes = new Map([[event.payload.record_path, recordBytes]]);
  const hashes = new Map([[event.payload.record_path, hashRawBytes(recordBytes)]]);
  return { event, record, bytes, hashes };
}

function agencyRecommendationFixture(
  conditional = false,
  evidenceRecordKind: "evidence" | "human-authorization" = "evidence",
) {
  const record = createAgencyRecommendationRecordFixtureS36({ conditional, evidence_record_kind: evidenceRecordKind });
  const attestation = record.producer_attestation as Record<string, unknown>;
  const { action_proposal: _actionProposal, action_scope: _actionScope, conditions, producer_attestation: _attestation, schema_version: _schemaVersion, ...copied } = record;
  const event = {
    run_id: record.run_id,
    event_type: "approval.recommendation-recorded",
    payload: {
      ...copied,
      record_path: `authorities/recommendations/${String(record.recommendation_id)}.json`,
      condition_hashes: (conditions as readonly unknown[]).map((condition) => hashCanonical(condition)).sort(),
      signer_key_ref: attestation.signer_key_ref,
      statement_hash: attestation.statement_hash,
    },
  } as RuntimeEventV02Value;
  const recordBytes = jsonBytes(record);
  const path = event.payload.record_path;
  const bytes = new Map([[path, recordBytes]]);
  const hashes = new Map([[path, hashRawBytes(recordBytes)]]);
  return { event, record, bytes, hashes };
}

function authorityRevocationFixture() {
  const record = createAuthorityRevocationRecordFixtureS36();
  const attestation = record.producer_attestation as Record<string, unknown>;
  const { schema_version: _schemaVersion, producer_attestation: _attestation, ...copied } = record;
  const event = {
    run_id: record.run_id,
    event_type: "authority.grant-revoked",
    payload: {
      ...copied,
      record_path: `authorities/revocations/${String(record.revocation_id)}.json`,
      signer_key_ref: attestation.signer_key_ref,
      statement_hash: attestation.statement_hash,
    },
  } as RuntimeEventV02Value;
  const recordBytes = jsonBytes(record);
  const path = event.payload.record_path;
  return {
    event, record,
    bytes: new Map([[path, recordBytes]]),
    hashes: new Map([[path, hashRawBytes(recordBytes)]]),
  };
}

describe("S35 runtime record admission", () => {
  it("admits an exact self-hashed artifact record/content pair in canonical path order", () => {
    const fixture = artifactFixture();
    const result = admitRuntimeRecordsV02({
      events: [fixture.event],
      run_id: RUN_ID,
      plan_hash: PLAN_HASH,
      record_bytes_by_path: fixture.bytes,
      raw_hash_by_path: fixture.hashes,
    });

    expect(result, JSON.stringify(result)).toMatchObject({ ok: true });
    if (!result.ok) return;
    expect(result.value.ordered_paths).toEqual([
      "artifacts/content/result.txt",
      "artifacts/records/artifact-main.json",
    ]);
    expect(result.value.records_by_path.get("artifacts/records/artifact-main.json")).toEqual(fixture.record);
    expect(result.value.content_bytes_by_path.get("artifacts/content/result.txt")).toEqual(fixture.content);
  });

  it("keeps one closed registry row for every canonical record-owning event family", () => {
    expect(Object.fromEntries(RUNTIME_RECORD_FAMILY_REGISTRY_V02.map((row) => [row.event_type, row.path_for_id("id_main")]))).toEqual({
      "artifact.recorded": "artifacts/records/id_main.json",
      "record.redaction-derivative-recorded": "custody/derivatives/pre-seal/id_main.json",
      "task.execution-completed": "task-results/id_main.json",
      "task.execution-failed": "task-results/id_main.json",
      "evidence.recorded": "evidence/records/id_main.json",
      "authority.human-authorization-recorded": "authorities/human/id_main.json",
      "authority.envelope-recorded": "authorities/envelopes/id_main.json",
      "authority.waiver-recorded": "authorities/gate-waivers/id_main.json",
      "approval.recommendation-recorded": "authorities/recommendations/id_main.json",
      "authority.grant-revoked": "authorities/revocations/id_main.json",
      "observation.manual-recorded": "observations/id_main.json",
      "record.export-decision-recorded": "export-decisions/id_main.json",
      "claim.recorded": "claims/id_main.json",
      "finding.recorded": "findings/id_main.json",
      "waiver.recorded": "waivers/id_main.json",
      "gate.result-recorded": "gates/id_main.json",
      "evaluation.result-recorded": "evaluations/id_main.json",
    });
  });

  it("returns distinct closed reasons for missing, extra, hash-invalid, and schema-invalid members", () => {
    const fixture = artifactFixture();
    const input = {
      events: [fixture.event],
      run_id: RUN_ID,
      plan_hash: PLAN_HASH,
      record_bytes_by_path: fixture.bytes,
      raw_hash_by_path: fixture.hashes,
    } as const;

    expect(admitRuntimeRecordsV02({ ...input, record_bytes_by_path: new Map() })).toEqual({
      ok: false,
      reason: "RUNTIME_RECORD_MISSING",
    });
    expect(admitRuntimeRecordsV02({
      ...input,
      record_bytes_by_path: new Map([...fixture.bytes, ["unknown.json", new Uint8Array()]]),
      raw_hash_by_path: new Map([...fixture.hashes, ["unknown.json", hashRawBytes(new Uint8Array())]]),
    })).toEqual({ ok: false, reason: "RUNTIME_SCHEMA_INVENTORY_INVALID" });
    expect(admitRuntimeRecordsV02({
      ...input,
      raw_hash_by_path: new Map(fixture.hashes).set("artifacts/records/artifact-main.json", OTHER_HASH),
    })).toEqual({ ok: false, reason: "RUNTIME_RECORD_HASH_INVALID" });
    expect(admitRuntimeRecordsV02({
      ...input,
      record_bytes_by_path: new Map(fixture.bytes).set("artifacts/records/artifact-main.json", jsonBytes({ nope: true })),
      raw_hash_by_path: new Map(fixture.hashes).set(
        "artifacts/records/artifact-main.json",
        hashRawBytes(jsonBytes({ nope: true })),
      ),
    })).toEqual({ ok: false, reason: "RUNTIME_RECORD_SCHEMA_INVALID" });
  });

  it("rejects an event-selected noncanonical fixed record path before reading bytes", () => {
    const fixture = artifactFixture();
    const event = {
      ...fixture.event,
      payload: { ...fixture.event.payload, artifact_record_path: "artifacts/records/other.json" },
    } as RuntimeEventV02Value;
    expect(admitRuntimeRecordsV02({
      events: [event],
      run_id: RUN_ID,
      plan_hash: PLAN_HASH,
      record_bytes_by_path: fixture.bytes,
      raw_hash_by_path: fixture.hashes,
    })).toEqual({ ok: false, reason: "RUNTIME_SCHEMA_INVENTORY_INVALID" });
  });

  it("admits a strict human authorization record instead of only the event payload shape", () => {
    const fixture = humanAuthorizationFixture();

    expect(admitRuntimeRecordsV02({
      events: [fixture.event],
      run_id: RUN_ID,
      plan_hash: PLAN_HASH,
      record_bytes_by_path: fixture.bytes,
      raw_hash_by_path: fixture.hashes,
    })).toMatchObject({ ok: true });
  });

  it("rejects strict-record, self-hash, and event-binding violations with stable precedence", () => {
    const fixture = humanAuthorizationFixture();
    const path = fixture.event.payload.record_path;

    const unknownFieldPreimage = { ...fixture.record, extension: true };
    delete (unknownFieldPreimage as Partial<typeof fixture.record>).record_hash;
    const unknownFieldRecord = {
      ...unknownFieldPreimage,
      record_hash: hashCanonical(unknownFieldPreimage),
    };
    const unknownFieldBytes = jsonBytes(unknownFieldRecord);
    const unknownFieldEvent = {
      ...fixture.event,
      payload: { ...fixture.event.payload, record_hash: unknownFieldRecord.record_hash },
    } as RuntimeEventV02Value;
    expect(admitRuntimeRecordsV02({
      events: [unknownFieldEvent], run_id: RUN_ID, plan_hash: PLAN_HASH,
      record_bytes_by_path: new Map([[path, unknownFieldBytes]]),
      raw_hash_by_path: new Map([[path, hashRawBytes(unknownFieldBytes)]]),
    })).toEqual({ ok: false, reason: "RUNTIME_RECORD_SCHEMA_INVALID" });

    const badSelfHashBytes = jsonBytes({ ...fixture.record, record_hash: PLAN_HASH });
    const badSelfHashEvent = {
      ...fixture.event,
      payload: { ...fixture.event.payload, record_hash: PLAN_HASH },
    } as RuntimeEventV02Value;
    expect(admitRuntimeRecordsV02({
      events: [badSelfHashEvent], run_id: RUN_ID, plan_hash: PLAN_HASH,
      record_bytes_by_path: new Map([[path, badSelfHashBytes]]),
      raw_hash_by_path: new Map([[path, hashRawBytes(badSelfHashBytes)]]),
    })).toEqual({ ok: false, reason: "RUNTIME_RECORD_HASH_INVALID" });

    const mismatchedPreimage = { ...fixture.record, authenticated_principal_ref: "principal_other" };
    delete (mismatchedPreimage as Partial<typeof fixture.record>).record_hash;
    const mismatchedRecord = { ...mismatchedPreimage, record_hash: hashCanonical(mismatchedPreimage) };
    const mismatchedBytes = jsonBytes(mismatchedRecord);
    const mismatchedEvent = {
      ...fixture.event,
      payload: { ...fixture.event.payload, record_hash: mismatchedRecord.record_hash },
    } as RuntimeEventV02Value;
    expect(admitRuntimeRecordsV02({
      events: [mismatchedEvent], run_id: RUN_ID, plan_hash: PLAN_HASH,
      record_bytes_by_path: new Map([[path, mismatchedBytes]]),
      raw_hash_by_path: new Map([[path, hashRawBytes(mismatchedBytes)]]),
    })).toEqual({ ok: false, reason: "RUNTIME_RECORD_SCHEMA_INVALID" });

    expect(admitRuntimeRecordsV02({
      events: [unknownFieldEvent], run_id: RUN_ID, plan_hash: PLAN_HASH,
      record_bytes_by_path: new Map([[path, unknownFieldBytes]]),
      raw_hash_by_path: new Map([[path, OTHER_HASH]]),
    })).toEqual({ ok: false, reason: "RUNTIME_RECORD_HASH_INVALID" });
  });

  it("admits the strict authority-envelope record behind its selected event bindings", () => {
    const fixture = authorityEnvelopeFixture();
    expect(admitRuntimeRecordsV02({
      events: [fixture.event], run_id: RUN_ID, plan_hash: PLAN_HASH,
      record_bytes_by_path: fixture.bytes, raw_hash_by_path: fixture.hashes,
    })).toMatchObject({ ok: true });
  });

  it("rejects an envelope whose nested subject does not match the event-selected subject", () => {
    const fixture = authorityEnvelopeFixture();
    const changedSubject = { principal_ref: "agent_other", stable_identity_hash: PLAN_HASH };
    const changedLineage = {
      ...fixture.record.lineage,
      on_behalf_of_chain: [fixture.record.issuer, changedSubject],
    };
    const changedSubjectHash = hashCanonical({
      purpose: "authority-envelope-subject-v02", schema_version: fixture.record.schema_version,
      authority_envelope_id: fixture.record.authority_envelope_id, run_id: fixture.record.run_id,
      plan_hash: fixture.record.plan_hash, policy_digest: fixture.record.policy_digest,
      subject: changedSubject, issuer: fixture.record.issuer,
      action_scope_hash: fixture.record.action_scope_hash, lineage: changedLineage,
      issued_at: fixture.record.issued_at, expires_at: fixture.record.expires_at,
      revocation_epoch: fixture.record.revocation_epoch,
    });
    const changedPreimage = {
      ...fixture.record, subject: changedSubject, lineage: changedLineage,
      authorization_subject_hash: changedSubjectHash,
    };
    delete (changedPreimage as Partial<typeof fixture.record>).record_hash;
    const changedRecord = { ...changedPreimage, record_hash: hashCanonical(changedPreimage) };
    const changedBytes = jsonBytes(changedRecord);
    const path = fixture.event.payload.record_path;
    const event = {
      ...fixture.event,
      payload: {
        ...fixture.event.payload,
        record_hash: changedRecord.record_hash,
        authorization_subject_hash: changedSubjectHash,
      },
    } as RuntimeEventV02Value;
    expect(admitRuntimeRecordsV02({
      events: [event], run_id: RUN_ID, plan_hash: PLAN_HASH,
      record_bytes_by_path: new Map([[path, changedBytes]]),
      raw_hash_by_path: new Map([[path, hashRawBytes(changedBytes)]]),
    })).toEqual({ ok: false, reason: "RUNTIME_RECORD_SCHEMA_INVALID" });
  });

  it("admits the strict agency-recommendation record behind copied and derived event bindings", () => {
    const fixture = agencyRecommendationFixture();
    expect(admitRuntimeRecordsV02({
      events: [fixture.event], run_id: String(fixture.record.run_id), plan_hash: String(fixture.record.plan_hash),
      record_bytes_by_path: fixture.bytes, raw_hash_by_path: fixture.hashes,
    })).toMatchObject({ ok: true });
  });

  it("rejects recommendation condition-hash and flattened signer substitution", () => {
    const fixture = agencyRecommendationFixture(true);
    const baseInput = {
      run_id: String(fixture.record.run_id), plan_hash: String(fixture.record.plan_hash),
      record_bytes_by_path: fixture.bytes, raw_hash_by_path: fixture.hashes,
    } as const;
    const conditionMismatch = {
      ...fixture.event,
      payload: { ...fixture.event.payload, condition_hashes: [OTHER_HASH] },
    } as RuntimeEventV02Value;
    expect(admitRuntimeRecordsV02({ ...baseInput, events: [conditionMismatch] }))
      .toEqual({ ok: false, reason: "RUNTIME_RECORD_SCHEMA_INVALID" });

    const signerMismatch = {
      ...fixture.event,
      payload: { ...fixture.event.payload, signer_key_ref: "key_other" },
    } as RuntimeEventV02Value;
    expect(admitRuntimeRecordsV02({ ...baseInput, events: [signerMismatch] }))
      .toEqual({ ok: false, reason: "RUNTIME_RECORD_SCHEMA_INVALID" });
  });

  it("rejects a fully rehashed recommendation whose dependency kind is not evidence", () => {
    const fixture = agencyRecommendationFixture(false, "human-authorization");
    expect(admitRuntimeRecordsV02({
      events: [fixture.event], run_id: String(fixture.record.run_id), plan_hash: String(fixture.record.plan_hash),
      record_bytes_by_path: fixture.bytes, raw_hash_by_path: fixture.hashes,
    })).toEqual({ ok: false, reason: "RUNTIME_RECORD_SCHEMA_INVALID" });
  });

  it("admits the strict authority-revocation record behind flattened attestation bindings", () => {
    const fixture = authorityRevocationFixture();
    expect(admitRuntimeRecordsV02({
      events: [fixture.event], run_id: String(fixture.record.run_id), plan_hash: String(fixture.record.plan_hash),
      record_bytes_by_path: fixture.bytes, raw_hash_by_path: fixture.hashes,
    })).toMatchObject({ ok: true });
  });
});
