import { describe, expect, it } from "vitest";

import { hashCanonical, hashRawBytes } from "../../src/hash.js";
import { planRuntimeLedgerMigrationV02ToV03 } from "../../src/run/runtime-ledger-migration-v02-v03.js";

const H = (character: string) => `sha256:${character.repeat(64)}`;
const inventoryV02 = {
  resolved_run_plan: "0.2", ledger_event: "0.2", run_manifest: "0.2", artifact_manifest: "0.2",
  redaction_derivative: "0.2", human_authorization_proof: "0.2", authority_envelope: "0.2",
  agency_recommendation: "0.2", authority_revocation: "0.2", task_result: "0.2",
  manual_observation: "0.2", export_decision: "0.2", evidence_item: "0.2", gate_result: "0.2",
  evaluation_result: "0.2", claim: "0.2", finding: "0.2", waiver: "0.2", gate_waiver_authority: "0.2",
} as const;

function sourceBytes() {
  const initializedPreimage = {
    schema_version: "0.2", event_id: "event_s40_source", run_id: "run_s40_source",
    sequence: 1, recorded_at: "2026-08-24T09:00:00Z", event_type: "run.initialized",
    source: "kernel", authority_ref: null, risk_tier: "T1", related_ids: [], previous_event_hash: null,
    payload: { plan_hash: H("a"), initial_fence_epoch: 0, runtime_schema_versions: inventoryV02 },
  };
  const initialized = { ...initializedPreimage, event_hash: hashCanonical(initializedPreimage) };
  const freezePreimage = {
    schema_version: "0.2", event_id: "event_s40_freeze", run_id: "run_s40_source",
    sequence: 2, recorded_at: "2026-08-24T09:00:01Z", event_type: "run.terminal-freeze-entered",
    source: "evaluator", authority_ref: null, risk_tier: "T1", related_ids: [], previous_event_hash: initialized.event_hash,
    payload: {
      revision: 1, candidate: "completed",
      candidate_evidence_refs: [{ ledger_sequence: 1, event_hash: initialized.event_hash }],
      fence_epoch: 0,
    },
  };
  const freeze = { ...freezePreimage, event_hash: hashCanonical(freezePreimage) };
  const sealPreimage = {
    schema_version: "0.2", event_id: "event_s40_seal", run_id: "run_s40_source",
    sequence: 3, recorded_at: "2026-08-24T09:00:02Z", event_type: "run.terminal-sealed",
    source: "evaluator", authority_ref: null, risk_tier: "T1", related_ids: [], previous_event_hash: freeze.event_hash,
    payload: {
      outcome: "completed", pre_seal_ledger_sequence: 2, pre_seal_ledger_head_hash: freeze.event_hash,
      pre_seal_snapshot_hash: H("c"), previous_fence_epoch: 0, fence_epoch: 1,
    },
  };
  const seal = { ...sealPreimage, event_hash: hashCanonical(sealPreimage) };
  return new TextEncoder().encode(`${[initialized, freeze, seal].map((event) => JSON.stringify(event)).join("\n")}\n`);
}

function activeSourceBytes() {
  const initialized = new TextDecoder().decode(sourceBytes()).split("\n")[0];
  return new TextEncoder().encode(`${initialized}\n`);
}

describe("S40 explicit V02 to new-lineage V03 migration plan", () => {
  it("creates a deterministic distinct V03 run without mutating source bytes or conveying authority", () => {
    const source = sourceBytes();
    const before = new Uint8Array(source);
    const first = planRuntimeLedgerMigrationV02ToV03({
      source_bytes: source, target_run_id: "run_s40_target", recorded_at: "2026-08-24T10:00:00Z",
    });
    const second = planRuntimeLedgerMigrationV02ToV03({
      source_bytes: source, target_run_id: "run_s40_target", recorded_at: "2026-08-24T10:00:00Z",
    });

    expect(first).toEqual(second);
    expect(first).toMatchObject({
      ok: true,
      value: {
        source: { run_id: "run_s40_source", bytes_hash: hashRawBytes(source), event_count: 3 },
        target: { run_id: "run_s40_target", event_count: 1 },
        lineage: {
          source_plan_hash: H("a"), source_sequence: 3, target_plan_hash: H("a"), target_sequence: 1,
          authority_carried_forward: false, historical_leases_carried_forward: false,
        },
      },
    });
    expect(source).toEqual(before);
    if (first.ok) {
      expect(first.value.target.ledger_text).toContain('"ledger_event":"0.3"');
      expect(JSON.stringify(first.value)).not.toContain("simulated_lease");
      expect(Object.isFrozen(first.value.target)).toBe(true);
      expect(typeof first.value.target.ledger_text).toBe("string");
    }
  });

  it("rejects an active but otherwise valid V02 ledger", () => {
    expect(planRuntimeLedgerMigrationV02ToV03({
      source_bytes: activeSourceBytes(), target_run_id: "run_s40_target", recorded_at: "2026-08-24T10:00:00Z",
    })).toEqual({ ok: false, reason: "MIGRATION_SOURCE_NOT_QUIESCENT" });
  });

  it("rejects shared, detached, and over-limit source views before decode", () => {
    const shared = new Uint8Array(new SharedArrayBuffer(sourceBytes().byteLength));
    shared.set(sourceBytes());
    expect(planRuntimeLedgerMigrationV02ToV03({
      source_bytes: shared, target_run_id: "run_s40_target", recorded_at: "2026-08-24T10:00:00Z",
    })).toEqual({ ok: false, reason: "MIGRATION_INPUT_INVALID" });

    const detached = sourceBytes();
    structuredClone(detached.buffer, { transfer: [detached.buffer] });
    expect(planRuntimeLedgerMigrationV02ToV03({
      source_bytes: detached, target_run_id: "run_s40_target", recorded_at: "2026-08-24T10:00:00Z",
    })).toEqual({ ok: false, reason: "MIGRATION_INPUT_INVALID" });

    const oversized = new Uint8Array(67_108_865);
    expect(planRuntimeLedgerMigrationV02ToV03({
      source_bytes: oversized, target_run_id: "run_s40_target", recorded_at: "2026-08-24T10:00:00Z",
    })).toEqual({ ok: false, reason: "MIGRATION_INPUT_INVALID" });
  });

  it("fails closed when migration envelope, descriptor, or byte-view traps throw", () => {
    const valid = {
      source_bytes: sourceBytes(), target_run_id: "run_s40_target", recorded_at: "2026-08-24T10:00:00Z",
    };
    const hostileEnvelope = new Proxy(valid, {
      getPrototypeOf: () => { throw new Error("envelope prototype trap must not escape"); },
    });
    const hostileDescriptors = new Proxy(valid, {
      ownKeys: () => { throw new Error("descriptor trap must not escape"); },
    });
    const hostileBytes = new Proxy(sourceBytes(), {
      getPrototypeOf: () => { throw new Error("byte-view prototype trap must not escape"); },
    });

    expect(planRuntimeLedgerMigrationV02ToV03(hostileEnvelope))
      .toEqual({ ok: false, reason: "MIGRATION_INPUT_INVALID" });
    expect(planRuntimeLedgerMigrationV02ToV03(hostileDescriptors))
      .toEqual({ ok: false, reason: "MIGRATION_INPUT_INVALID" });
    expect(planRuntimeLedgerMigrationV02ToV03({ ...valid, source_bytes: hostileBytes }))
      .toEqual({ ok: false, reason: "MIGRATION_INPUT_INVALID" });
  });

  it("rejects same-run, partial, malformed, V03, and accessor-bearing inputs with no candidate", () => {
    const source = sourceBytes();
    expect(planRuntimeLedgerMigrationV02ToV03({ source_bytes: source, target_run_id: "run_s40_source", recorded_at: "2026-08-24T10:00:00Z" }))
      .toEqual({ ok: false, reason: "MIGRATION_TARGET_INVALID" });
    expect(planRuntimeLedgerMigrationV02ToV03({ source_bytes: source.slice(0, -1), target_run_id: "run_s40_target", recorded_at: "2026-08-24T10:00:00Z" }))
      .toEqual({ ok: false, reason: "MIGRATION_SOURCE_INVALID" });
    expect(planRuntimeLedgerMigrationV02ToV03({ source_bytes: new TextEncoder().encode("not-json\n"), target_run_id: "run_s40_target", recorded_at: "2026-08-24T10:00:00Z" }))
      .toEqual({ ok: false, reason: "MIGRATION_SOURCE_INVALID" });
    const v03Source = new TextEncoder().encode(new TextDecoder().decode(source).replaceAll('"0.2"', '"0.3"'));
    expect(planRuntimeLedgerMigrationV02ToV03({ source_bytes: v03Source, target_run_id: "run_s40_target", recorded_at: "2026-08-24T10:00:00Z" }))
      .toEqual({ ok: false, reason: "MIGRATION_SOURCE_INVALID" });
    const hostile = { source_bytes: source, target_run_id: "run_s40_target", recorded_at: "2026-08-24T10:00:00Z" };
    Object.defineProperty(hostile, "authority", { enumerable: true, get: () => "forged" });
    expect(planRuntimeLedgerMigrationV02ToV03(hostile)).toEqual({ ok: false, reason: "MIGRATION_INPUT_INVALID" });
  });
});
