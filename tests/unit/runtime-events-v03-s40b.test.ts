import { describe, expect, it } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import {
  IntegrityObservationRejectedEventV03,
  ProcessTerminationAttemptedEventV03,
  RunQuarantinedEventV03,
  RuntimeEventTypesV03,
} from "../../src/schema/runtime-v03.js";
import { RuntimeEventTypesV02 } from "../../src/schema/runtime.js";
import { inspectRuntimeLedgerV03 } from "../../src/run/runtime-ledger-v03.js";

const H = (character: string) => `sha256:${character.repeat(64)}`;
const inventory = {
  resolved_run_plan: "0.2", ledger_event: "0.3", run_manifest: "0.3", artifact_manifest: "0.2",
  redaction_derivative: "0.2", human_authorization_proof: "0.2", authority_envelope: "0.2",
  agency_recommendation: "0.2", authority_revocation: "0.2", task_result: "0.2",
  manual_observation: "0.2", export_decision: "0.2", evidence_item: "0.2", gate_result: "0.2",
  evaluation_result: "0.2", claim: "0.2", finding: "0.2", waiver: "0.2", gate_waiver_authority: "0.2",
} as const;

function append(events: Array<Record<string, unknown>>, event_type: string, source: string, authority_ref: string | null, payload: Record<string, unknown>) {
  const previous = events.at(-1);
  const preimage = {
    schema_version: "0.3", event_id: `event_s40b_${events.length + 1}`, run_id: "run_s40b_integrity",
    sequence: events.length + 1, recorded_at: `2026-08-24T11:00:${String(events.length).padStart(2, "0")}Z`,
    event_type, source, authority_ref, risk_tier: "T1", related_ids: [],
    previous_event_hash: previous?.event_hash ?? null, payload,
  };
  const sealed = { ...preimage, event_hash: hashCanonical(preimage) };
  events.push(sealed);
  return sealed;
}

function activeEvents() {
  const events: Array<Record<string, unknown>> = [];
  append(events, "run.initialized", "kernel", null, {
    plan_hash: H("a"), initial_fence_epoch: 0, runtime_schema_versions: inventory,
  });
  append(events, "run.started", "kernel", null, { executor_profile_hash: H("b") });
  return events;
}

function inspect(events: readonly unknown[]) {
  return inspectRuntimeLedgerV03(new TextEncoder().encode(`${events.map((event) => JSON.stringify(event)).join("\n")}\n`));
}

describe("S40-B1 corrected V03 integrity and termination contract", () => {
  it("is exactly the frozen V02 46 plus the approved five V03 members", () => {
    expect(RuntimeEventTypesV02).toHaveLength(46);
    expect(RuntimeEventTypesV03).toEqual([
      ...RuntimeEventTypesV02,
      "run.started", "run.paused", "run.quarantined", "process.termination-attempted",
      "integrity.observation-rejected",
    ]);
    expect(new Set(RuntimeEventTypesV03)).toHaveLength(51);
  });

  it("accepts only the closed rejection reason/identifier combinations", () => {
    const envelope = {
      schema_version: "0.3", event_id: "event_s40b_rejected", run_id: "run_s40b_integrity", sequence: 3,
      recorded_at: "2026-08-24T11:00:02Z", source: "integrity", authority_ref: null, risk_tier: "T1",
      related_ids: [], previous_event_hash: H("1"), event_hash: H("2"), event_type: "integrity.observation-rejected",
    } as const;
    for (const payload of [
      { reason_code: "capture-gap", observation_hash: H("3"), adapter_invocation_id: "adapter_s40b", claimed_action_id: null },
      { reason_code: "unmatched-observation", observation_hash: H("3"), adapter_invocation_id: null, claimed_action_id: "action_s40b" },
      { reason_code: "authority-breach", observation_hash: H("3"), adapter_invocation_id: "adapter_s40b", claimed_action_id: null },
    ] as const) expect(IntegrityObservationRejectedEventV03.safeParse({ ...envelope, payload }).success).toBe(true);
    expect(IntegrityObservationRejectedEventV03.safeParse({
      ...envelope,
      payload: { reason_code: "capture-gap", observation_hash: H("3"), adapter_invocation_id: null, claimed_action_id: "action_s40b" },
    }).success).toBe(false);
    expect(IntegrityObservationRejectedEventV03.safeParse({
      ...envelope,
      payload: { reason_code: "authority-breach", observation_hash: H("3"), adapter_invocation_id: null, claimed_action_id: null },
    }).success).toBe(false);
  });

  it("requires rejection then exact adjacent singleton same-reason quarantine", () => {
    const events = activeEvents();
    const rejected = append(events, "integrity.observation-rejected", "integrity", null, {
      reason_code: "capture-gap", observation_hash: H("c"), adapter_invocation_id: "adapter_s40b", claimed_action_id: null,
    });
    expect(inspect(events)).toMatchObject({ ok: true, state: { state: "quarantine-required" } });
    const quarantine = append(events, "run.quarantined", "integrity", null, {
      reason_code: "capture-gap", evidence_refs: [{ ledger_sequence: rejected.sequence, event_hash: rejected.event_hash }],
    });
    expect(RunQuarantinedEventV03.safeParse(quarantine).success).toBe(true);
    expect(inspect(events)).toMatchObject({ ok: true, state: { state: "quarantined" } });
    append(events, "run.paused", "operator", "authority_s40b", {
      requested_by: "operator", reason_code: "operator-request",
      request_event_ref: { ledger_sequence: 1, event_hash: events[0]!.event_hash },
    });
    expect(inspect(events)).toMatchObject({ ok: false, reason: "LEDGER_TRANSITION_INVALID" });
  });

  it("requires the exact expanded termination payload without aliases", () => {
    const exact = {
      schema_version: "0.3", event_id: "event_s40b_termination", run_id: "run_s40b_integrity", sequence: 8,
      recorded_at: "2026-08-24T11:00:07Z", source: "adapter", authority_ref: null, risk_tier: "T1",
      related_ids: [], previous_event_hash: H("1"), event_hash: H("2"), event_type: "process.termination-attempted",
      payload: {
        trigger: "quarantine", trigger_event_ref: { ledger_sequence: 7, event_hash: H("7") },
        action_admission_event_ref: { ledger_sequence: 4, event_hash: H("4") }, adapter_invocation_id: "adapter_s40b",
        host_identity_hash: H("a"), boot_id_hash: H("b"), unit_name_hash: H("c"), cgroup_path_hash: H("d"),
        termination_request_hash: H("e"), termination_observation_hash: H("f"), observed_outcome: "unknown",
      },
    } as const;
    expect(ProcessTerminationAttemptedEventV03.safeParse(exact).success).toBe(true);
    const { boot_id_hash: _boot, ...aliasedPayload } = exact.payload;
    expect(ProcessTerminationAttemptedEventV03.safeParse({
      ...exact, payload: { ...aliasedPayload, boot_identity_hash: H("b") },
    }).success).toBe(false);
  });
});
