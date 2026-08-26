import { describe, expect, it } from "vitest";

import { hashCanonical, hashRawBytes } from "../../src/hash.js";
import {
  inspectRuntimeLedgerDocument,
} from "../../src/run/runtime-ledger-dispatch.js";
import {
  inspectRuntimeLedgerV03,
} from "../../src/run/runtime-ledger-v03.js";
import { reduceRuntimeStateV03 } from "../../src/run/runtime-state-reducer-v03.js";

const H = (character: string) => `sha256:${character.repeat(64)}`;
const inventory = {
  resolved_run_plan: "0.2", ledger_event: "0.3", run_manifest: "0.3", artifact_manifest: "0.2",
  redaction_derivative: "0.2", human_authorization_proof: "0.2", authority_envelope: "0.2",
  agency_recommendation: "0.2", authority_revocation: "0.2", task_result: "0.2",
  manual_observation: "0.2", export_decision: "0.2", evidence_item: "0.2", gate_result: "0.2",
  evaluation_result: "0.2", claim: "0.2", finding: "0.2", waiver: "0.2",
  gate_waiver_authority: "0.2",
} as const;

function seal(value: Record<string, unknown>) {
  const { event_hash: _previousHash, ...preimage } = value;
  return { ...preimage, event_hash: hashCanonical(preimage) };
}

function initialized() {
  return seal({
    schema_version: "0.3", event_id: "event_s40_initialized", run_id: "run_s40_ledger",
    sequence: 1, recorded_at: "2026-08-24T10:00:00Z", event_type: "run.initialized",
    source: "kernel", authority_ref: null, risk_tier: "T1", related_ids: [],
    previous_event_hash: null,
    payload: { plan_hash: H("a"), initial_fence_epoch: 0, runtime_schema_versions: inventory },
  });
}

function append(previous: ReturnType<typeof seal>, event: Record<string, unknown>) {
  return seal({
    schema_version: "0.3", event_id: `event_s40_${String(event.event_type).replace(/[^a-z]+/gu, "_")}`,
    run_id: "run_s40_ledger", sequence: Number(previous.sequence) + 1,
    recorded_at: "2026-08-24T10:00:01Z", source: "kernel", authority_ref: null,
    risk_tier: "T1", related_ids: [], previous_event_hash: previous.event_hash,
    ...event,
  });
}

function jsonl(events: readonly unknown[]): string {
  return `${events.map((event) => JSON.stringify(event)).join("\n")}\n`;
}

const bytes = (text: string): Uint8Array => new TextEncoder().encode(text);

describe("S40 V03 ledger validation and version dispatch", () => {
  it("validates an original V03 prefix and derives its state", () => {
    const first = initialized();
    const started = append(first, {
      event_type: "run.started", payload: { executor_profile_hash: H("b") },
    });

    const result = inspectRuntimeLedgerV03(bytes(jsonl([first, started])));
    expect(result).toMatchObject({
      ok: true,
      ledger: { run_id: "run_s40_ledger", sequence: 2, head_hash: started.event_hash },
      state: { state: "running", in_flight_action_ids: [] },
    });
    if (result.ok) {
      expect(Object.isFrozen(result.ledger)).toBe(true);
      expect(Object.isFrozen(result.ledger.events)).toBe(true);
      expect(Object.isFrozen(result.ledger.events[0])).toBe(true);
      expect(Object.isFrozen(result.ledger.events[0]!.payload)).toBe(true);
      expect(reduceRuntimeStateV03(result.ledger)).toMatchObject({ state: "running" });
    }
    expect(inspectRuntimeLedgerDocument(bytes(jsonl([first, started])))).toMatchObject({
      ok: true, version: "0.3", state: { state: "running" },
    });
  });

  it("inspects an owned exact-byte view and rejects text or invalid UTF-8", () => {
    const ledgerBytes = bytes(jsonl([initialized()]));
    expect(inspectRuntimeLedgerV03(ledgerBytes)).toMatchObject({
      ok: true,
      ledger: { sequence: 1, ledger_bytes_hash: hashRawBytes(ledgerBytes) },
    });
    expect(inspectRuntimeLedgerV03(new Uint8Array([0xff]))).toMatchObject({ ok: false, reason: "LEDGER_SYNTAX_INVALID" });
    expect(inspectRuntimeLedgerV03(jsonl([initialized()]) as never)).toMatchObject({ ok: false, reason: "LEDGER_SYNTAX_INVALID" });
  });

  it("fails closed when an exotic byte view throws during prototype inspection", () => {
    const hostile = new Proxy(new Uint8Array([0x7b]), {
      getPrototypeOf: () => { throw new Error("prototype trap must not escape"); },
    });

    expect(inspectRuntimeLedgerV03(hostile)).toMatchObject({ ok: false, reason: "LEDGER_SYNTAX_INVALID" });
    expect(inspectRuntimeLedgerDocument(hostile)).toMatchObject({ ok: false, reason: "LEDGER_SYNTAX_INVALID" });
  });

  it("exposes no alternate array or string brand-minting validator", async () => {
    const ledgerModule = await import("../../src/run/runtime-ledger-v03.js");
    expect(ledgerModule).not.toHaveProperty("validateRuntimeLedgerV03");
    expect(ledgerModule).not.toHaveProperty("parseAndValidateRuntimeLedgerV03");
    expect(ledgerModule).toHaveProperty("inspectRuntimeLedgerV03");
  });

  it("rejects partial final lines, duplicate JSON keys, and malformed lines without dropping evidence", () => {
    const first = initialized();
    expect(inspectRuntimeLedgerV03(bytes(JSON.stringify(first)))).toMatchObject({ ok: false, reason: "LEDGER_SYNTAX_INVALID" });
    expect(inspectRuntimeLedgerV03(bytes('{"schema_version":"0.3","schema_version":"0.3"}\n')))
      .toMatchObject({ ok: false, reason: "LEDGER_SYNTAX_INVALID" });
    expect(inspectRuntimeLedgerV03(bytes("{not-json}\n"))).toMatchObject({ ok: false, reason: "LEDGER_SYNTAX_INVALID" });
  });

  it("rejects mixed, missing, and unknown versions before payload validation", () => {
    const first = initialized();
    expect(inspectRuntimeLedgerDocument(bytes(`${JSON.stringify(first)}\n{"schema_version":"0.2"}\n`)))
      .toEqual({ ok: false, reason: "LEDGER_VERSION_MIXED" });
    expect(inspectRuntimeLedgerDocument(bytes('{"event_type":"run.future"}\n')))
      .toEqual({ ok: false, reason: "LEDGER_VERSION_MISSING" });
    expect(inspectRuntimeLedgerDocument(bytes('{"schema_version":"9.9"}\n')))
      .toEqual({ ok: false, reason: "LEDGER_VERSION_UNSUPPORTED" });
  });

  it("rejects chain, hash, run, duplicate-id, and forward-reference drift", () => {
    const first = initialized();
    const started = append(first, { event_type: "run.started", payload: { executor_profile_hash: H("b") } });
    expect(inspectRuntimeLedgerV03(bytes(jsonl([first, { ...started, sequence: 3 }])))).toMatchObject({ ok: false, reason: "LEDGER_HASH_CHAIN_INVALID" });
    expect(inspectRuntimeLedgerV03(bytes(jsonl([first, { ...started, event_hash: H("c") }])))).toMatchObject({ ok: false, reason: "LEDGER_HASH_CHAIN_INVALID" });
    const foreign = seal({ ...started, event_id: "event_s40_foreign", run_id: "run_s40_foreign" });
    expect(inspectRuntimeLedgerV03(bytes(jsonl([first, foreign])))).toMatchObject({ ok: false, reason: "LEDGER_HISTORY_INVALID" });
    const duplicate = seal({ ...started, event_id: first.event_id });
    expect(inspectRuntimeLedgerV03(bytes(jsonl([first, duplicate])))).toMatchObject({ ok: false, reason: "LEDGER_HISTORY_INVALID" });
    const pause = append(started, {
      event_type: "run.paused", source: "operator", authority_ref: "authority_pause_s40",
      payload: { requested_by: "operator", reason_code: "operator-request", request_event_ref: { ledger_sequence: 99, event_hash: H("d") } },
    });
    expect(inspectRuntimeLedgerV03(bytes(jsonl([first, started, pause])))).toMatchObject({ ok: false, reason: "LEDGER_HISTORY_INVALID" });
  });

  it("requires an exact adjacent same-reason rejection before quarantine", () => {
    const first = initialized();
    const started = append(first, { event_type: "run.started", payload: { executor_profile_hash: H("b") } });
    const rejected = append(started, {
      event_type: "integrity.observation-rejected", source: "integrity",
      payload: {
        reason_code: "capture-gap", observation_hash: H("c"),
        adapter_invocation_id: "adapter_s40_1", claimed_action_id: null,
      },
    });
    expect(inspectRuntimeLedgerV03(bytes(jsonl([first, started, rejected]))))
      .toMatchObject({ ok: true, state: { state: "quarantine-required" } });

    const intervening = append(rejected, { event_type: "run.started", payload: { executor_profile_hash: H("d") } });
    expect(inspectRuntimeLedgerV03(bytes(jsonl([first, started, rejected, intervening]))))
      .toMatchObject({ ok: false, reason: "LEDGER_HISTORY_INVALID" });

    const wrongReason = append(rejected, {
      event_type: "run.quarantined", source: "integrity",
      payload: { reason_code: "authority-breach", evidence_refs: [{ ledger_sequence: rejected.sequence, event_hash: rejected.event_hash }] },
    });
    expect(inspectRuntimeLedgerV03(bytes(jsonl([first, started, rejected, wrongReason]))))
      .toMatchObject({ ok: false, reason: "LEDGER_HISTORY_INVALID" });

    const quarantine = append(rejected, {
      event_type: "run.quarantined", source: "integrity",
      payload: { reason_code: "capture-gap", evidence_refs: [{ ledger_sequence: rejected.sequence, event_hash: rejected.event_hash }] },
    });
    expect(inspectRuntimeLedgerV03(bytes(jsonl([first, started, rejected, quarantine]))))
      .toMatchObject({ ok: true, state: { state: "quarantined" } });

    const forbiddenReuse = append(quarantine, {
      event_type: "run.paused", source: "operator", authority_ref: "authority_s40",
      payload: {
        requested_by: "operator", reason_code: "operator-request",
        request_event_ref: { ledger_sequence: rejected.sequence, event_hash: rejected.event_hash },
      },
    });
    const reused = inspectRuntimeLedgerV03(bytes(jsonl([first, started, rejected, quarantine, forbiddenReuse])));
    expect(reused).toMatchObject({ ok: false, reason: "LEDGER_HISTORY_INVALID" });
    if (!reused.ok) expect(reused.issues[0]?.message).toContain("only the exact adjacent quarantine");
  });

  it("preserves the inherited V02 terminal-history requirement", () => {
    const first = initialized();
    const terminalSeal = append(first, {
      event_type: "run.terminal-sealed",
      source: "evaluator",
      payload: {
        outcome: "completed",
        pre_seal_ledger_sequence: 1,
        pre_seal_ledger_head_hash: first.event_hash,
        pre_seal_snapshot_hash: H("b"),
        previous_fence_epoch: 0,
        fence_epoch: 1,
      },
    });

    expect(inspectRuntimeLedgerV03(bytes(jsonl([first, terminalSeal]))))
      .toMatchObject({ ok: false, reason: "LEDGER_HISTORY_INVALID" });
  });

  it("preserves inherited V02 typed lineage across real event indexes", () => {
    const first = initialized();
    const required = append(first, {
      event_type: "gate.result-required",
      payload: {
        gate_ref: "gate-s40",
        requirement_revision: 1,
        applicability: "always",
        compensation_ref: null,
        prerequisite_set_hash: H("b"),
        prerequisite_refs: [{ ledger_sequence: 1, event_hash: first.event_hash }],
      },
    });
    const wrongLineage = append(required, {
      event_type: "gate.result-recorded",
      source: "evaluator",
      payload: {
        gate_ref: "gate-s40",
        result_id: "result_s40",
        status: "PASS",
        evaluator_identity_ref: "actor_s40",
        policy_digest: H("c"),
        record_path: "gates/result_s40.json",
        record_hash: H("d"),
        required_event_ref: { ledger_sequence: 1, event_hash: first.event_hash },
        waiver_event_ref: null,
      },
    });

    expect(inspectRuntimeLedgerV03(bytes(jsonl([first, required, wrongLineage]))))
      .toMatchObject({ ok: false, reason: "LEDGER_HISTORY_INVALID" });
  });

  it("keeps the frozen V02 reader on the V02 branch", () => {
    const v03 = initialized();
    expect(inspectRuntimeLedgerDocument(bytes(jsonl([v03])))).toMatchObject({ ok: true, version: "0.3" });
    const v02Preimage = {
      ...v03, schema_version: "0.2", payload: {
        ...(v03.payload as Record<string, unknown>),
        runtime_schema_versions: { ...inventory, ledger_event: "0.2", run_manifest: "0.2" },
      },
    };
    const { event_hash: _ignored, ...v02WithoutHash } = v02Preimage;
    const v02 = { ...v02WithoutHash, event_hash: hashCanonical(v02WithoutHash) };
    expect(inspectRuntimeLedgerDocument(bytes(jsonl([v02])))).toMatchObject({ ok: true, version: "0.2" });
  });
});
