import { describe, expect, it } from "vitest";

import { hashCanonical, hashRawBytes } from "../../src/hash.js";
import {
  RUNTIME_RECORD_FAMILY_REGISTRY_V02,
  admitRuntimeRecordsV02,
} from "../../src/run/runtime-record-admission-v02.js";
import type { RuntimeEventV02Value } from "../../src/schema/runtime.js";

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
});
