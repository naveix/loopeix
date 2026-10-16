import { describe, expect, it, vi } from "vitest";

import { admitRuntimeActionV03 } from "../../src/run/runtime-action-admission-v03.js";
import {
  captureRuntimeTerminationCapabilityV03,
  claimRuntimeTerminationCapabilityV03,
  terminateRuntimeActionV03,
  type CapturedRuntimeTerminationCapabilityV03,
} from "../../src/run/runtime-termination-v03.js";
import {
  appendRuntimeEventV03,
  closeRuntimeWriteSessionV03,
  createRuntimeEventDraftV03,
  inspectRuntimeWriteSessionV03ForTermination,
  openRuntimeWriteSessionV03,
  type RuntimeWriteSessionV03,
} from "../../src/run/runtime-write-session-v03.js";
import { createSignedRuntimeActionAdmissionV03Fixture } from "../helpers/runtime-action-admission-v03-fixture.js";

async function ready(terminate: ReturnType<typeof vi.fn>) {
  const at = "2026-08-24T10:00:31Z";
  const fixture = await createSignedRuntimeActionAdmissionV03Fixture({
    additional_event_envelopes: [
      { event_id: "event_execution_started_v03", recorded_at: at },
      { event_id: "event_abort_requested_v03", recorded_at: at },
      { event_id: "event_termination_attempted_v03", recorded_at: at },
    ],
  });
  const opened = await openRuntimeWriteSessionV03(fixture.store, fixture.expectation);
  if (!opened.ok) throw new Error(opened.error);
  const admission = await admitRuntimeActionV03(opened.session, fixture.request);
  if (!admission.ok) throw new Error(admission.error);
  const snapshot = await inspectRuntimeWriteSessionV03ForTermination(opened.session);
  if (!snapshot.ok) throw new Error(snapshot.error);
  const admitted = snapshot.snapshot.events.find((event) => event.sequence === admission.action_admission_event_ref.ledger_sequence)!;
  const payload = admitted.payload as Record<string, unknown>;
  const started = createRuntimeEventDraftV03({
    event_type: "task.execution-started", source: "adapter", authority_ref: null, risk_tier: "T1", related_ids: [],
    payload: {
      action_id: payload.action_id, task_ref: payload.task_ref, admission_ref: admission.action_admission_event_ref,
      adapter_invocation_id: "invocation_termination_v03",
      action_proposal_id: payload.action_proposal_id, action_proposal_hash: payload.action_proposal_hash,
      action_actor_ref: payload.action_actor_ref, action_actor_stable_identity_hash: payload.action_actor_stable_identity_hash,
      on_behalf_of_chain_hash: payload.on_behalf_of_chain_hash, repository_root_ref: payload.repository_root_ref,
      repository_base_ref_identity_hash: payload.repository_base_ref_identity_hash,
      repository_pre_state_hash: payload.repository_pre_state_hash, authorized_change_set_hash: payload.authorized_change_set_hash,
      normalized_dispatch_hash: payload.normalized_dispatch_hash, policy_action_kind: payload.policy_action_kind,
      action_approval_class: payload.action_approval_class,
    },
  });
  if (started === null) throw new Error("started draft invalid");
  const startedResult = await appendRuntimeEventV03(opened.session, started);
  if (!startedResult.ok) throw new Error(startedResult.error);
  const abort = createRuntimeEventDraftV03({
    event_type: "control.abort-requested", source: "operator", authority_ref: "operator_termination_v03",
    risk_tier: "T1", related_ids: [], payload: {
      request_id: "abort_termination_v03", requested_by: "operator", reason_code: "operator-requested",
      policy_decision_ref: null, evidence_refs: [],
    },
  });
  if (abort === null) throw new Error("abort draft invalid");
  const abortResult = await appendRuntimeEventV03(opened.session, abort);
  if (!abortResult.ok) throw new Error(abortResult.error);
  const capability = captureRuntimeTerminationCapabilityV03({
    host_identity: "host-A", boot_id: "boot-A", unit_name: "unit-A", cgroup_path: "/cg/A", terminate,
  });
  if (capability === null) throw new Error("capability rejected");
  return { session: opened.session, capability, request: {
    trigger: "abort", trigger_event_ref: abortResult.event_ref,
    action_admission_event_ref: admission.action_admission_event_ref,
    adapter_invocation_id: "invocation_termination_v03",
  } as const };
}

describe("S40-B6 bounded runtime termination", () => {
  it("binds a genuine unused termination capability exactly once", () => {
    const capability = captureRuntimeTerminationCapabilityV03({
      host_identity: "host-claim",
      boot_id: "boot-claim",
      unit_name: "unit-claim",
      cgroup_path: "/cg/claim",
      terminate: async () => null,
    });
    if (capability === null) throw new Error("capability rejected");

    const claimed = claimRuntimeTerminationCapabilityV03(capability);
    expect(claimed).not.toBeNull();
    expect(claimed).not.toBe(capability);
    expect(Object.isFrozen(claimed)).toBe(true);
    expect(claimRuntimeTerminationCapabilityV03(capability)).toBeNull();
    expect(claimRuntimeTerminationCapabilityV03(
      Object.freeze({}) as CapturedRuntimeTerminationCapabilityV03,
    )).toBeNull();
  });

  it("records terminated only for the exact inactive empty captured target", async () => {
    const terminate = vi.fn(async () => ({
      host_identity: "host-A", boot_id: "boot-A", unit_name: "unit-A", cgroup_path: "/cg/A",
      cgroup_populated: 0, unit_state: "inactive",
    }));
    const state = await ready(terminate);
    await expect(terminateRuntimeActionV03(state.session, state.capability, state.request)).resolves.toMatchObject({
      ok: true, observed_outcome: "terminated", event_ref: { ledger_sequence: 11 },
    });
    expect(terminate).toHaveBeenCalledTimes(1);
    expect(terminate.mock.calls[0]![0]).toEqual({ host_identity: "host-A", boot_id: "boot-A", unit_name: "unit-A", cgroup_path: "/cg/A" });
    await closeRuntimeWriteSessionV03(state.session);
  });

  it.each([
    ["populated cgroup", { host_identity: "host-A", boot_id: "boot-A", unit_name: "unit-A", cgroup_path: "/cg/A", cgroup_populated: 1, unit_state: "inactive" }, "not-terminated"],
    ["identity drift", { host_identity: "host-B", boot_id: "boot-A", unit_name: "unit-A", cgroup_path: "/cg/A", cgroup_populated: 0, unit_state: "inactive" }, "not-terminated"],
    ["missing proof", { host_identity: "host-A" }, "unknown"],
    ["accessor proof", Object.defineProperty({
      boot_id: "boot-A", unit_name: "unit-A", cgroup_path: "/cg/A", cgroup_populated: 0, unit_state: "inactive",
    }, "host_identity", { enumerable: true, get: () => "host-A" }), "unknown"],
  ])("records %s as a closed non-success outcome", async (_name, proof, outcome) => {
    const state = await ready(vi.fn(async () => proof));
    await expect(terminateRuntimeActionV03(state.session, state.capability, state.request))
      .resolves.toMatchObject({ ok: true, observed_outcome: outcome });
    await expect(terminateRuntimeActionV03(state.session, state.capability, state.request))
      .resolves.toEqual({ ok: false, error: "TERMINATION_ALREADY_ATTEMPTED" });
    await closeRuntimeWriteSessionV03(state.session);
  });

  it("rejects a strict request before inspecting or invoking capabilities", async () => {
    const terminate = vi.fn();
    const candidates = [
      { trigger: "abort", extra: true },
      Object.create({ trigger: "abort" }),
      Object.defineProperty({}, "trigger", { enumerable: true, get: () => "abort" }),
      {
        trigger: "abort", adapter_invocation_id: "invocation_termination_v03",
        trigger_event_ref: Object.defineProperty({ event_hash: `sha256:${"a".repeat(64)}` }, "ledger_sequence", {
          enumerable: true, get: () => { throw new Error("nested getter invoked"); },
        }),
        action_admission_event_ref: { ledger_sequence: 1, event_hash: `sha256:${"b".repeat(64)}` },
      },
      {
        trigger: "abort", adapter_invocation_id: "invocation_termination_v03",
        trigger_event_ref: Object.setPrototypeOf({ ledger_sequence: 1, event_hash: `sha256:${"a".repeat(64)}` }, null),
        action_admission_event_ref: { ledger_sequence: 1, event_hash: `sha256:${"b".repeat(64)}` },
      },
    ];
    for (const candidate of candidates) {
      await expect(terminateRuntimeActionV03(Object.freeze({}) as RuntimeWriteSessionV03,
        Object.freeze({}) as never, candidate)).resolves.toEqual({ ok: false, error: "TERMINATION_REQUEST_INVALID" });
    }
    expect(terminate).not.toHaveBeenCalled();
  });

  it("records a thrown termination boundary as unknown exactly once", async () => {
    const state = await ready(vi.fn(async () => { throw new Error("ambiguous host boundary"); }));
    await expect(terminateRuntimeActionV03(state.session, state.capability, state.request))
      .resolves.toMatchObject({ ok: true, observed_outcome: "unknown" });
    await expect(terminateRuntimeActionV03(state.session, state.capability, state.request))
      .resolves.toEqual({ ok: false, error: "TERMINATION_ALREADY_ATTEMPTED" });
    await closeRuntimeWriteSessionV03(state.session);
  });
});
