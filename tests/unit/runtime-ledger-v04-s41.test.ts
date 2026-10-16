import { describe, expect, it } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import {
  inspectRuntimeLedgerV04,
  isValidatedRuntimeLedgerV04,
} from "../../src/run/runtime-ledger-v04.js";

const UTF8 = new TextEncoder();
const H = (character: string) => `sha256:${character.repeat(64)}`;

const inventory = {
  resolved_run_plan: "0.3", ledger_event: "0.4", run_manifest: "0.4",
  artifact_manifest: "0.2", redaction_derivative: "0.2", human_authorization_proof: "0.2",
  authority_envelope: "0.2", agency_recommendation: "0.2", authority_revocation: "0.2",
  task_result: "0.2", manual_observation: "0.2", export_decision: "0.2",
  evidence_item: "0.2", gate_result: "0.2", evaluation_result: "0.2", claim: "0.2",
  finding: "0.2", waiver: "0.2", gate_waiver_authority: "0.2", summary_artifact: "0.1",
} as const;

function event(
  prior: readonly Record<string, unknown>[],
  event_type: string,
  source: string,
  authority_ref: string | null,
  payload: Record<string, unknown>,
): Record<string, unknown> {
  const sequence = prior.length + 1;
  const preimage = {
    schema_version: "0.4",
    event_id: `event_s41_ledger_${sequence}`,
    run_id: "run_s41_ledger",
    sequence,
    recorded_at: `2026-08-26T22:00:${String(sequence).padStart(2, "0")}Z`,
    event_type,
    source,
    authority_ref,
    risk_tier: "T1",
    related_ids: [],
    previous_event_hash: (prior.at(-1)?.event_hash as string | undefined) ?? null,
    payload,
  };
  return { ...preimage, event_hash: hashCanonical(preimage) };
}

function validEvents(): Record<string, unknown>[] {
  const events: Record<string, unknown>[] = [];
  events.push(event(events, "run.initialized", "kernel", null, {
    plan_hash: H("a"), initial_fence_epoch: 0, runtime_schema_versions: inventory,
  }));
  events.push(event(events, "run.started", "kernel", null, { executor_profile_hash: H("b") }));
  const started = events[1]!;
  events.push(event(events, "run.clock-observed", "kernel", null, {
    clock_id: "clock_run_owner_acquire_ledger", observed_at: "2026-08-26T22:00:02Z", elapsed_ms: 0,
    reason: "run-owner-acquisition", task_ref: null, failure_ordinal: null, use_ref: "run_owner_s41_1",
    attempt_ref: null, owner_lease_ref: null, boot_id_hash: H("9"), monotonic_clock_id: "mono_s41_1",
  }));
  const issuedClock = events[2]!;
  events.push(event(events, "execution.attempt-started", "kernel", null, {
    attempt_id: "attempt_s41_1", attempt_ordinal: 1, mode: "ordinary",
    previous_attempt_event_ref: null, resume_request_event_ref: null, resume_nonce_hash: null,
    source_boundary_sequence: 2, source_boundary_head_hash: started.event_hash,
    source_manifest_hash: H("c"), repository_state_hash: H("1"), plan_hash: H("a"), input_hash: H("d"),
    recovery_policy_hash: H("e"), authority_envelope_hash: H("f"),
    run_owner_lease_id: "run_owner_s41_1",
    issued_clock_ref: { ledger_sequence: 3, event_hash: issuedClock.event_hash },
    deadline_elapsed_ms: 30_000, boot_id_hash: H("9"), monotonic_clock_id: "mono_s41_1",
    previous_fence_epoch: 0, fence_epoch: 0,
  }));
  return events;
}

function bytes(events = validEvents()): Uint8Array {
  return UTF8.encode(`${events.map((value) => JSON.stringify(value)).join("\n")}\n`);
}

function ownerHeartbeatEvents(): Record<string, unknown>[] {
  const events = validEvents();
  const attempt = events[3]!;
  const attemptRef = { ledger_sequence: 4, event_hash: attempt.event_hash };
  events.push(event(events, "run.clock-observed", "kernel", null, {
    clock_id: "clock_owner_acquire_ledger", observed_at: "2026-08-26T22:00:04Z", elapsed_ms: 100,
    reason: "owner-acquisition", task_ref: null, failure_ordinal: null, use_ref: "task_owner_ledger_1",
    attempt_ref: attemptRef, owner_lease_ref: attemptRef, boot_id_hash: H("9"), monotonic_clock_id: "mono_s41_1",
  }));
  const acquireClock = events[4]!;
  events.push(event(events, "ownership.lease-acquired", "policy-enforcement-point", "authority_s41", {
    owner_lease_id: "task_owner_ledger_1", scope: "task", scope_ref: "task-s41",
    parent_run_owner_lease_id: "run_owner_s41_1", attempt_event_ref: attemptRef,
    issued_clock_ref: { ledger_sequence: 5, event_hash: acquireClock.event_hash },
    deadline_elapsed_ms: 20_000, boot_id_hash: H("9"), monotonic_clock_id: "mono_s41_1",
    fence_epoch: 0, heartbeat_limit: 3,
  }));
  const owner = events[5]!;
  const ownerRef = { ledger_sequence: 6, event_hash: owner.event_hash };
  events.push(event(events, "run.clock-observed", "kernel", null, {
    clock_id: "clock_owner_heartbeat_ledger", observed_at: "2026-08-26T22:00:06Z", elapsed_ms: 19_999,
    reason: "owner-heartbeat", task_ref: null, failure_ordinal: null, use_ref: "task_owner_ledger_1",
    attempt_ref: attemptRef, owner_lease_ref: ownerRef, boot_id_hash: H("9"), monotonic_clock_id: "mono_s41_1",
  }));
  const heartbeatClock = events[6]!;
  events.push(event(events, "ownership.lease-heartbeat-recorded", "kernel", null, {
    owner_lease_event_ref: ownerRef, heartbeat_ordinal: 1,
    observation_clock_ref: { ledger_sequence: 7, event_hash: heartbeatClock.event_hash },
    previous_deadline_elapsed_ms: 20_000, deadline_elapsed_ms: 25_000,
    boot_id_hash: H("9"), monotonic_clock_id: "mono_s41_1", fence_epoch: 0,
  }));
  return events;
}

const proposalBindings = {
  action_proposal_id: "proposal_s41_non_entry", action_proposal_hash: H("1"),
  action_actor_ref: "actor_s41_non_entry", action_actor_stable_identity_hash: H("2"),
  on_behalf_of_chain_hash: H("3"), repository_root_ref: "repository_s41_non_entry",
  repository_base_ref_identity_hash: H("4"), repository_pre_state_hash: H("5"),
  authorized_change_set_hash: H("6"), normalized_dispatch_hash: H("7"),
} as const;

function nonEntryProofEvents(includeContradictoryStart = false): Record<string, unknown>[] {
  const events = validEvents();
  const attempt = events[3]!;
  const attemptRef = { ledger_sequence: attempt.sequence as number, event_hash: attempt.event_hash as string };
  events.push(event(events, "task.action-admitted", "policy-enforcement-point", "authority_s41", {
    action_id: "action_s41_non_entry", task_ref: "task-s41", lease_id: "lease_s41_non_entry",
    lease_event_ref: attemptRef, admission_clock_ref: attemptRef, ...proposalBindings,
    action_scope_hash: H("8"), action_class: "task", classifier_input_hash: H("9"),
    classifier_registry_hash: H("a"), classifier_rule_hash: H("b"), data_flow_hash: H("c"),
    policy_action_kind: "network-read", action_approval_class: "agency", execution_ordinal: 1,
    retry_of_failure_ordinal: null, fence_epoch: 0, side_effect_refs: ["effect-s41"],
    waiver_gate_use_checks: [], task_executions_after: 1, action_output_bytes_after: 0,
    attempt_event_ref: attemptRef, parent_run_owner_lease_id: "run_owner_s41_1",
    logical_operation_idempotency_key: H("d"), resolved_operation_input_hash: H("e"),
    recovery_policy_hash: H("f"), process_runtime_ceiling_ms: 30_000,
  }));
  const admission = events.at(-1)!;
  const admissionRef = { ledger_sequence: admission.sequence as number, event_hash: admission.event_hash as string };
  if (includeContradictoryStart) {
    events.push(event(events, "task.execution-started", "adapter", null, {
      action_id: "action_s41_non_entry", task_ref: "task-s41", admission_ref: admissionRef,
      adapter_invocation_id: "invocation_s41_non_entry", ...proposalBindings,
      policy_action_kind: "network-read", action_approval_class: "agency",
    }));
  }
  events.push(event(events, "task.execution-non-entry-acknowledged", "adapter", null, {
    action_id: "action_s41_non_entry", task_ref: "task-s41", admission_ref: admissionRef,
    attempt_event_ref: attemptRef, adapter_invocation_id: "invocation_s41_non_entry",
    adapter_ref: "adapter-s41", adapter_version_hash: H("1"), fence_epoch: 0,
    host_identity_hash: H("2"), boot_id_hash: H("3"), unit_name_hash: H("4"),
    cgroup_path_hash: H("5"), acknowledgement_observation_hash: H("6"),
  }));
  const acknowledgement = events.at(-1)!;
  events.push(event(events, "process.termination-attempted", "adapter", null, {
    trigger: "reconciliation", trigger_event_ref: { ledger_sequence: acknowledgement.sequence, event_hash: acknowledgement.event_hash },
    action_admission_event_ref: admissionRef, adapter_invocation_id: "invocation_s41_non_entry",
    host_identity_hash: H("2"), boot_id_hash: H("3"), unit_name_hash: H("4"), cgroup_path_hash: H("5"),
    termination_request_hash: H("7"), termination_observation_hash: H("8"), observed_outcome: "terminated",
  }));
  const termination = events.at(-1)!;
  events.push(event(events, "task.action-outcome-reconciled", "integrity", null, {
    action_id: "action_s41_non_entry", task_ref: "task-s41", admission_ref: admissionRef,
    reconciliation_status: "proven-non-start", attempt_event_ref: attemptRef,
    adapter_invocation_id: "invocation_s41_non_entry", adapter_ref: "adapter-s41",
    adapter_version_hash: H("1"), non_entry_ack_event_ref: {
      ledger_sequence: acknowledgement.sequence, event_hash: acknowledgement.event_hash,
    },
    process_cannot_continue_ref: { ledger_sequence: termination.sequence, event_hash: termination.event_hash },
    fence_epoch: 0,
  }));
  const reconciliation = events.at(-1)!;
  events.push(event(events, "effect.outcome", "integrity", null, {
    task_ref: "task-s41", effect_ref: "effect-s41", action_id: "action_s41_non_entry",
    outcome: "not-committed", evidence_refs: [{ ledger_sequence: reconciliation.sequence, event_hash: reconciliation.event_hash }],
    reconciliation_event_ref: { ledger_sequence: reconciliation.sequence, event_hash: reconciliation.event_hash },
  }));
  return events;
}

function rehashFrom(events: Record<string, unknown>[], startIndex: number): void {
  for (let index = startIndex; index < events.length; index += 1) {
    const current = events[index]!;
    const { event_hash: _oldHash, ...rest } = current;
    const preimage = {
      ...rest,
      previous_event_hash: index === 0 ? null : events[index - 1]!.event_hash,
    };
    events[index] = { ...preimage, event_hash: hashCanonical(preimage) };
  }
}

describe("S41-A V04 runtime ledger inspection", () => {
  it("accepts only an exact later-termination non-entry proof with no contradictory execution facts", () => {
    expect(inspectRuntimeLedgerV04(bytes(nonEntryProofEvents()))).toMatchObject({ ok: true });
    expect(inspectRuntimeLedgerV04(bytes(nonEntryProofEvents(true)))).toMatchObject({
      ok: false, reason: "LEDGER_HISTORY_INVALID",
    });

    const mismatchedHost = nonEntryProofEvents();
    const acknowledgementIndex = mismatchedHost.findIndex((candidate) => candidate.event_type === "task.execution-non-entry-acknowledged");
    mismatchedHost[acknowledgementIndex] = {
      ...mismatchedHost[acknowledgementIndex],
      payload: { ...(mismatchedHost[acknowledgementIndex]!.payload as Record<string, unknown>), host_identity_hash: H("0") },
    };
    rehashFrom(mismatchedHost, acknowledgementIndex);
    const reconciliationIndex = mismatchedHost.findIndex((candidate) => candidate.event_type === "task.action-outcome-reconciled");
    const acknowledgement = mismatchedHost[acknowledgementIndex]!;
    mismatchedHost[reconciliationIndex] = {
      ...mismatchedHost[reconciliationIndex],
      payload: {
        ...(mismatchedHost[reconciliationIndex]!.payload as Record<string, unknown>),
        non_entry_ack_event_ref: { ledger_sequence: acknowledgement.sequence, event_hash: acknowledgement.event_hash },
      },
    };
    rehashFrom(mismatchedHost, reconciliationIndex);
    expect(inspectRuntimeLedgerV04(bytes(mismatchedHost))).toMatchObject({ ok: false, reason: "LEDGER_HISTORY_INVALID" });
  });

  it("admits one exact V04 prefix and owns immutable bytes, events, and reducer state", () => {
    const source = bytes();
    const result = inspectRuntimeLedgerV04(source);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.ledger).toMatchObject({
      run_id: "run_s41_ledger", plan_hash: H("a"), sequence: 4,
      head_hash: validEvents()[3]!.event_hash, sealed: false,
      ledger_byte_length: source.byteLength,
      state: {
        state: "running",
        current_attempt_ordinal: 1,
        current_attempt_mode: "ordinary",
        current_fence_epoch: 0,
      },
    });
    expect(result.ledger.line_byte_lengths.reduce((total, length) => total + length, 0)).toBe(source.byteLength);
    expect(Object.isFrozen(result.ledger)).toBe(true);
    expect(Object.isFrozen(result.ledger.events)).toBe(true);
    expect(Object.isFrozen(result.ledger.line_byte_lengths)).toBe(true);
    expect(isValidatedRuntimeLedgerV04(result.ledger)).toBe(true);
    expect(isValidatedRuntimeLedgerV04({ ...result.ledger })).toBe(false);
    source.fill(0);
    expect(result.ledger.events[0]?.event_type).toBe("run.initialized");
  });

  it.each([
    ["empty", new Uint8Array(), "LEDGER_SYNTAX_INVALID"],
    ["not newline terminated", UTF8.encode("{}"), "LEDGER_SYNTAX_INVALID"],
    ["duplicate JSON key", UTF8.encode('{"schema_version":"0.4","schema_version":"0.4"}\n'), "LEDGER_SYNTAX_INVALID"],
    ["mixed V03 event", UTF8.encode(`${JSON.stringify({ ...validEvents()[0], schema_version: "0.3" })}\n`), "LEDGER_EVENT_SCHEMA_INVALID"],
  ] as const)("fails closed for %s", (_case, input, reason) => {
    expect(inspectRuntimeLedgerV04(input)).toMatchObject({ ok: false, reason });
  });

  it("rejects a broken event hash and a forward ledger reference", () => {
    const hashBroken = validEvents();
    hashBroken[1] = { ...hashBroken[1], event_hash: H("0") };
    expect(inspectRuntimeLedgerV04(bytes(hashBroken))).toMatchObject({ ok: false, reason: "LEDGER_HASH_CHAIN_INVALID" });

    const forward = validEvents();
    const attempt = forward[3]!;
    const payload = { ...(attempt.payload as Record<string, unknown>), issued_clock_ref: { ledger_sequence: 5, event_hash: H("4") } };
    const { event_hash: _oldHash, ...preimage } = { ...attempt, payload };
    forward[3] = { ...preimage, event_hash: hashCanonical(preimage) };
    expect(inspectRuntimeLedgerV04(bytes(forward))).toMatchObject({ ok: false, reason: "LEDGER_HISTORY_INVALID" });
  });

  it("requires attempt start to bind its exact prospective run-owner acquisition clock", () => {
    const wrongLease = validEvents();
    wrongLease[2] = {
      ...wrongLease[2],
      payload: { ...(wrongLease[2]!.payload as Record<string, unknown>), use_ref: "run_owner_wrong" },
    };
    rehashFrom(wrongLease, 2);
    wrongLease[3] = {
      ...wrongLease[3],
      payload: {
        ...(wrongLease[3]!.payload as Record<string, unknown>),
        issued_clock_ref: { ledger_sequence: 3, event_hash: wrongLease[2]!.event_hash },
      },
    };
    rehashFrom(wrongLease, 3);
    expect(inspectRuntimeLedgerV04(bytes(wrongLease))).toMatchObject({ ok: false, reason: "LEDGER_HISTORY_INVALID" });

    const nonLaterDeadline = validEvents();
    nonLaterDeadline[3] = {
      ...nonLaterDeadline[3],
      payload: { ...(nonLaterDeadline[3]!.payload as Record<string, unknown>), deadline_elapsed_ms: 0 },
    };
    rehashFrom(nonLaterDeadline, 3);
    expect(inspectRuntimeLedgerV04(bytes(nonLaterDeadline))).toMatchObject({ ok: false, reason: "LEDGER_EVENT_SCHEMA_INVALID" });
  });

  it("requires a reason-matched same-domain pre-deadline heartbeat observation", () => {
    expect(inspectRuntimeLedgerV04(bytes(ownerHeartbeatEvents()))).toMatchObject({ ok: true });

    const wrongReason = ownerHeartbeatEvents();
    wrongReason[6] = {
      ...wrongReason[6],
      payload: { ...(wrongReason[6]!.payload as Record<string, unknown>), reason: "owner-release" },
    };
    rehashFrom(wrongReason, 6);
    wrongReason[7] = {
      ...wrongReason[7],
      payload: {
        ...(wrongReason[7]!.payload as Record<string, unknown>),
        observation_clock_ref: { ledger_sequence: 7, event_hash: wrongReason[6]!.event_hash },
      },
    };
    rehashFrom(wrongReason, 7);
    expect(inspectRuntimeLedgerV04(bytes(wrongReason))).toMatchObject({ ok: false, reason: "LEDGER_HISTORY_INVALID" });

    const expired = ownerHeartbeatEvents();
    expired[6] = {
      ...expired[6],
      payload: { ...(expired[6]!.payload as Record<string, unknown>), elapsed_ms: 20_000 },
    };
    rehashFrom(expired, 6);
    expired[7] = {
      ...expired[7],
      payload: {
        ...(expired[7]!.payload as Record<string, unknown>),
        observation_clock_ref: { ledger_sequence: 7, event_hash: expired[6]!.event_hash },
      },
    };
    rehashFrom(expired, 7);
    expect(inspectRuntimeLedgerV04(bytes(expired))).toMatchObject({ ok: false, reason: "LEDGER_HISTORY_INVALID" });
  });

  it("rejects non-Uint8Array and shared-memory input without throwing", () => {
    expect(() => inspectRuntimeLedgerV04("ledger" as unknown as Uint8Array)).not.toThrow();
    expect(inspectRuntimeLedgerV04("ledger" as unknown as Uint8Array)).toMatchObject({ ok: false, reason: "LEDGER_SYNTAX_INVALID" });
    if (typeof SharedArrayBuffer !== "undefined") {
      expect(inspectRuntimeLedgerV04(new Uint8Array(new SharedArrayBuffer(8)))).toMatchObject({ ok: false, reason: "LEDGER_SYNTAX_INVALID" });
    }
  });
});
