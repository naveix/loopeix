import { chmodSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import { captureRuntimeFileStoreV04ForTest } from "../../src/run/runtime-file-store-v04.js";
import {
  captureRuntimeClockSourceV04,
  observeRuntimeClockV04,
} from "../../src/run/runtime-clock-observation-v04.js";
import { buildRunManifestV04 } from "../../src/run/runtime-manifest-v04.js";
import { inspectRuntimePlanV03, projectRuntimePlanV03 } from "../../src/run/project-plan-v03.js";
import {
  captureRuntimeNonEntryAcknowledgementV04,
  captureRuntimeTerminationEvidenceV04,
  writeRuntimeNonEntryReconciliationV04,
} from "../../src/run/runtime-non-entry-write-v04.js";
import { inspectRuntimeLedgerV04 } from "../../src/run/runtime-ledger-v04.js";
import { ResolvedRunPlanV02, type ResolvedRunPlanV02Value } from "../../src/schema/runtime.js";
import { captureRuntimeProfileRegistryV03 } from "../../src/schema/runtime-plan-v03.js";
import { RuntimeEventV04, type RuntimeEventV04Value } from "../../src/schema/runtime-v04.js";

const UTF8 = new TextEncoder();
const REGISTRY = captureRuntimeProfileRegistryV03();
const H = (character: string) => `sha256:${character.repeat(64)}`;
const roots: string[] = [];
const inventory = {
  resolved_run_plan: "0.3",
  ledger_event: "0.4",
  run_manifest: "0.4",
  artifact_manifest: "0.2",
  redaction_derivative: "0.2",
  human_authorization_proof: "0.2",
  authority_envelope: "0.2",
  agency_recommendation: "0.2",
  authority_revocation: "0.2",
  task_result: "0.2",
  manual_observation: "0.2",
  export_decision: "0.2",
  evidence_item: "0.2",
  gate_result: "0.2",
  evaluation_result: "0.2",
  claim: "0.2",
  finding: "0.2",
  waiver: "0.2",
  gate_waiver_authority: "0.2",
  summary_artifact: "0.1",
} as const;

function loadPlanV02(): ResolvedRunPlanV02Value {
  return ResolvedRunPlanV02.parse(JSON.parse(readFileSync(
    join(import.meta.dirname, "../fixtures/compat/s35/v02/planned-run/resolved-run-plan.json"),
    "utf8",
  )));
}

function validatedPlan() {
  const projected = projectRuntimePlanV03(loadPlanV02(), REGISTRY);
  if (!projected.ok) throw new Error(projected.reason);
  const bytes = UTF8.encode(JSON.stringify(projected.value));
  const inspected = inspectRuntimePlanV03(bytes);
  if (!inspected.ok) throw new Error(inspected.reason);
  return { bytes, validated_plan: inspected.validated_plan };
}

function writeMode0600(path: string, bytes: Uint8Array): void {
  writeFileSync(path, bytes, { mode: 0o600 });
  chmodSync(path, 0o600);
}

function ref(event: RuntimeEventV04Value) {
  return { ledger_sequence: event.sequence, event_hash: event.event_hash };
}

function observation(label: string, observedAt: string, elapsedMs: number) {
  const source = captureRuntimeClockSourceV04({
    boot_identity: `boot_${label}`,
    monotonic_clock_id: `mono_${label}`,
    observe: () => ({ observed_at: observedAt, elapsed_ms: elapsedMs }),
  });
  if (source === null) throw new Error("clock source capture failed");
  const sampled = observeRuntimeClockV04(source);
  if (!sampled.ok) throw new Error(sampled.error);
  return sampled.value;
}

function append(
  events: RuntimeEventV04Value[],
  runId: string,
  eventType: RuntimeEventV04Value["event_type"],
  source: RuntimeEventV04Value["source"],
  authorityRef: string | null,
  payload: unknown,
) {
  const sequence = events.length + 1;
  const preimage = {
    schema_version: "0.4",
    event_id: `event_non_entry_fixture_s41_${sequence}`,
    run_id: runId,
    sequence,
    recorded_at: `2026-08-30T18:00:${String(sequence).padStart(2, "0")}Z`,
    event_type: eventType,
    source,
    authority_ref: authorityRef,
    risk_tier: "T1",
    related_ids: [],
    previous_event_hash: events.at(-1)?.event_hash ?? null,
    payload,
  };
  const event = RuntimeEventV04.parse({ ...preimage, event_hash: hashCanonical(preimage) });
  events.push(event);
  return event;
}

function fixture(options: Readonly<{ drifted_pre_state_hash?: string }> = {}) {
  const { bytes: planBytes, validated_plan: plan } = validatedPlan();
  const root = realpathSync(mkdtempSync(join(tmpdir(), "loopeix-non-entry-s41-")));
  roots.push(root);
  const events: RuntimeEventV04Value[] = [];

  append(events, plan.run_id, "run.initialized", "kernel", null, {
    plan_hash: plan.plan_hash,
    initial_fence_epoch: 0,
    runtime_schema_versions: inventory,
  });
  const started = append(events, plan.run_id, "run.started", "kernel", null, {
    executor_profile_hash: H("1"),
  });
  const ownerClock = append(events, plan.run_id, "run.clock-observed", "kernel", null, {
    clock_id: "clock_non_entry_owner_s41_1",
    observed_at: "2026-08-30T18:00:02Z",
    elapsed_ms: 1,
    reason: "run-owner-acquisition",
    task_ref: null,
    failure_ordinal: null,
    use_ref: "run_owner_non_entry_s41_1",
    attempt_ref: null,
    owner_lease_ref: null,
    boot_id_hash: H("2"),
    monotonic_clock_id: "mono_non_entry_s41_1",
  });
  const attempt = append(events, plan.run_id, "execution.attempt-started", "kernel", null, {
    attempt_id: "attempt_non_entry_s41_1",
    attempt_ordinal: 1,
    mode: "ordinary",
    previous_attempt_event_ref: null,
    resume_request_event_ref: null,
    resume_nonce_hash: null,
    source_boundary_sequence: started.sequence,
    source_boundary_head_hash: started.event_hash,
    source_manifest_hash: H("3"),
    repository_state_hash: plan.plan.authority_subject.repository.initial_state.repository_state_hash,
    plan_hash: plan.plan_hash,
    input_hash: plan.plan.runtime_input_hash,
    recovery_policy_hash: plan.plan.runtime_recovery_policy_hash,
    authority_envelope_hash: H("4"),
    run_owner_lease_id: "run_owner_non_entry_s41_1",
    issued_clock_ref: ref(ownerClock),
    deadline_elapsed_ms: 1_000,
    boot_id_hash: H("2"),
    monotonic_clock_id: "mono_non_entry_s41_1",
    previous_fence_epoch: 0,
    fence_epoch: 0,
  });
  const admission = append(events, plan.run_id, "task.action-admitted", "policy-enforcement-point", "authority_non_entry_s41", {
    action_id: "action_non_entry_s41_1",
    task_ref: "task-s41",
    lease_id: "lease_non_entry_s41_1",
    lease_event_ref: ref(attempt),
    admission_clock_ref: ref(attempt),
    action_proposal_id: "proposal_non_entry_s41_1",
    action_proposal_hash: H("5"),
    action_actor_ref: "actor_non_entry_s41_1",
    action_actor_stable_identity_hash: H("6"),
    on_behalf_of_chain_hash: H("7"),
    repository_root_ref: plan.plan.authority_subject.repository.initial_state.repository_root_ref,
    repository_base_ref_identity_hash: plan.plan.authority_subject.repository.initial_state.base_ref_identity_hash,
    repository_pre_state_hash: options.drifted_pre_state_hash
      ?? plan.plan.authority_subject.repository.initial_state.repository_state_hash,
    authorized_change_set_hash: H("8"),
    normalized_dispatch_hash: H("9"),
    action_scope_hash: H("a"),
    action_class: "task",
    classifier_input_hash: H("b"),
    classifier_registry_hash: H("c"),
    classifier_rule_hash: H("d"),
    data_flow_hash: H("e"),
    policy_action_kind: "network-read",
    action_approval_class: "agency",
    execution_ordinal: 1,
    retry_of_failure_ordinal: null,
    fence_epoch: 0,
    side_effect_refs: ["effect-non-entry-a-s41", "effect-non-entry-b-s41"],
    waiver_gate_use_checks: [],
    task_executions_after: 1,
    action_output_bytes_after: 0,
    attempt_event_ref: ref(attempt),
    parent_run_owner_lease_id: "run_owner_non_entry_s41_1",
    logical_operation_idempotency_key: H("f"),
    resolved_operation_input_hash: H("0"),
    recovery_policy_hash: plan.plan.runtime_recovery_policy_hash,
    process_runtime_ceiling_ms: 30_000,
  });

  const ledgerBytes = UTF8.encode(`${events.map((event) => JSON.stringify(event)).join("\n")}\n`);
  const manifest = buildRunManifestV04({
    ledger_bytes: ledgerBytes,
    created_at: "2026-08-30T18:01:00Z",
    captured_files: [
      { path: "resolved-run-plan.json", family: "primary" as const, required: true, mode: 384 as const, bytes: planBytes },
      { path: "ledger.jsonl", family: "primary" as const, required: true, mode: 384 as const, bytes: ledgerBytes },
    ],
  });
  if (!manifest.ok) throw new Error(manifest.reason);

  writeMode0600(join(root, "resolved-run-plan.json"), planBytes);
  writeMode0600(join(root, "ledger.jsonl"), ledgerBytes);
  writeMode0600(join(root, "run-manifest.json"), manifest.bytes);

  return {
    root,
    plan,
    attempt,
    admission,
  };
}

afterEach(() => {
  while (roots.length > 0) rmSync(roots.pop()!, { recursive: true, force: true });
});

describe("S41 V04 non-entry reconciliation writer", () => {
  it("commits one exact non-entry acknowledgement, reconciliation termination, proven-non-start closure, and settlement", async () => {
    const value = fixture();
    const store = await captureRuntimeFileStoreV04ForTest({ run_directory: value.root });
    if (!store.ok) throw new Error(store.error);

    const acknowledgement = captureRuntimeNonEntryAcknowledgementV04({
      observation: observation("non_entry_ack_s41", "2026-08-30T18:02:00Z", 20),
      action_admission_event_ref: ref(value.admission),
      action_id: "action_non_entry_s41_1",
      task_ref: "task-s41",
      attempt_event_ref: ref(value.attempt),
      adapter_invocation_id: "invocation_non_entry_s41_1",
      adapter_ref: "adapter-s41",
      adapter_version_hash: H("1"),
      fence_epoch: 0,
      host_identity_hash: H("2"),
      boot_id_hash: H("3"),
      unit_name_hash: H("4"),
      cgroup_path_hash: H("5"),
      acknowledgement_observation_hash: H("6"),
    });
    const termination = captureRuntimeTerminationEvidenceV04({
      observation: observation("non_entry_termination_s41", "2026-08-30T18:02:01Z", 21),
      action_admission_event_ref: ref(value.admission),
      adapter_invocation_id: "invocation_non_entry_s41_1",
      host_identity_hash: H("2"),
      boot_id_hash: H("3"),
      unit_name_hash: H("4"),
      cgroup_path_hash: H("5"),
      termination_request_hash: H("7"),
      termination_observation_hash: H("8"),
      observed_outcome: "terminated",
    });
    expect(acknowledgement).toEqual({ ok: true, value: expect.anything() });
    expect(termination).toEqual({ ok: true, value: expect.anything() });
    if (!acknowledgement.ok || !termination.ok) return;

    const result = await writeRuntimeNonEntryReconciliationV04(store.store, {
      action_admission_event_ref: ref(value.admission),
      acknowledgement: acknowledgement.value,
      termination: termination.value,
      acknowledged_event_id: "event_non_entry_ack_s41",
      termination_event_id: "event_non_entry_termination_s41",
      reconciliation_event_id: "event_non_entry_reconciliation_s41",
      effect_outcome_event_ids: [
        "event_non_entry_effect_a_s41",
        "event_non_entry_effect_b_s41",
      ],
      settled_event_id: "event_non_entry_settled_s41",
    });

    expect(result).toMatchObject({
      ok: true,
      classification: "COMMITTED",
    });
    const ledger = inspectRuntimeLedgerV04(
      new Uint8Array(readFileSync(join(value.root, "ledger.jsonl"))),
    );
    expect(ledger.ok).toBe(true);
    if (!ledger.ok) return;

    const tail = ledger.ledger.events.slice(-6);
    expect(tail.map((event) => event.event_type)).toEqual([
      "task.execution-non-entry-acknowledged",
      "process.termination-attempted",
      "task.action-outcome-reconciled",
      "effect.outcome",
      "effect.outcome",
      "task.action-settled",
    ]);

    const acknowledgementEvent = tail[0]!;
    const terminationEvent = tail[1]!;
    const reconciliationEvent = tail[2]!;
    const firstEffect = tail[3]!;
    const secondEffect = tail[4]!;
    const settlement = tail[5]!;

    expect(acknowledgementEvent.payload).toMatchObject({
      action_id: "action_non_entry_s41_1",
      task_ref: "task-s41",
      admission_ref: ref(value.admission),
      attempt_event_ref: ref(value.attempt),
      adapter_invocation_id: "invocation_non_entry_s41_1",
      adapter_ref: "adapter-s41",
      adapter_version_hash: H("1"),
      fence_epoch: 0,
      host_identity_hash: H("2"),
      boot_id_hash: H("3"),
      unit_name_hash: H("4"),
      cgroup_path_hash: H("5"),
      acknowledgement_observation_hash: H("6"),
    });
    expect(terminationEvent.payload).toMatchObject({
      trigger: "reconciliation",
      trigger_event_ref: ref(acknowledgementEvent),
      action_admission_event_ref: ref(value.admission),
      adapter_invocation_id: "invocation_non_entry_s41_1",
      host_identity_hash: H("2"),
      boot_id_hash: H("3"),
      unit_name_hash: H("4"),
      cgroup_path_hash: H("5"),
      termination_request_hash: H("7"),
      termination_observation_hash: H("8"),
      observed_outcome: "terminated",
    });
    expect(reconciliationEvent.payload).toMatchObject({
      action_id: "action_non_entry_s41_1",
      task_ref: "task-s41",
      admission_ref: ref(value.admission),
      reconciliation_status: "proven-non-start",
      attempt_event_ref: ref(value.attempt),
      adapter_invocation_id: "invocation_non_entry_s41_1",
      adapter_ref: "adapter-s41",
      adapter_version_hash: H("1"),
      non_entry_ack_event_ref: ref(acknowledgementEvent),
      process_cannot_continue_ref: ref(terminationEvent),
      fence_epoch: 0,
    });
    expect([firstEffect, secondEffect].map((event) => event.payload)).toEqual([
      {
        task_ref: "task-s41",
        effect_ref: "effect-non-entry-a-s41",
        action_id: "action_non_entry_s41_1",
        outcome: "not-committed",
        evidence_refs: [ref(reconciliationEvent)],
        reconciliation_event_ref: ref(reconciliationEvent),
      },
      {
        task_ref: "task-s41",
        effect_ref: "effect-non-entry-b-s41",
        action_id: "action_non_entry_s41_1",
        outcome: "not-committed",
        evidence_refs: [ref(reconciliationEvent)],
        reconciliation_event_ref: ref(reconciliationEvent),
      },
    ]);
    expect(settlement.payload).toMatchObject({
      action_id: "action_non_entry_s41_1",
      task_ref: "task-s41",
      terminal_event_ref: ref(reconciliationEvent),
      repository_transition_status: "unchanged",
      effect_outcomes: [
        {
          effect_ref: "effect-non-entry-a-s41",
          outcome: "not-committed",
          outcome_event_ref: ref(firstEffect),
        },
        {
          effect_ref: "effect-non-entry-b-s41",
          outcome: "not-committed",
          outcome_event_ref: ref(secondEffect),
        },
      ],
    });
    expect(ledger.ledger.state.in_flight_action_ids).toEqual([]);
  });

  it("rejects counterfeit top-level descriptors and one-use observation replay", () => {
    const value = fixture();
    const sampled = observation("non_entry_replay_s41", "2026-08-30T18:03:00Z", 30);
    const valid = {
      observation: sampled,
      action_admission_event_ref: ref(value.admission),
      action_id: "action_non_entry_s41_1",
      task_ref: "task-s41",
      attempt_event_ref: ref(value.attempt),
      adapter_invocation_id: "invocation_non_entry_s41_1",
      adapter_ref: "adapter-s41",
      adapter_version_hash: H("1"),
      fence_epoch: 0,
      host_identity_hash: H("2"),
      boot_id_hash: H("3"),
      unit_name_hash: H("4"),
      cgroup_path_hash: H("5"),
      acknowledgement_observation_hash: H("6"),
    };
    expect(captureRuntimeNonEntryAcknowledgementV04(valid)).toEqual({
      ok: true,
      value: expect.anything(),
    });
    expect(captureRuntimeNonEntryAcknowledgementV04(valid)).toEqual({
      ok: false,
      error: "RUNTIME_NON_ENTRY_ACKNOWLEDGEMENT_INVALID",
    });

    const accessor = { ...valid } as Record<string, unknown>;
    Object.defineProperty(accessor, "task_ref", {
      enumerable: true,
      get: () => "task-s41",
    });
    expect(captureRuntimeNonEntryAcknowledgementV04(accessor)).toEqual({
      ok: false,
      error: "RUNTIME_NON_ENTRY_ACKNOWLEDGEMENT_INVALID",
    });

    const trapped = new Proxy({ ...valid, observation: observation("non_entry_proxy_s41", "2026-08-30T18:03:01Z", 31) }, {
      ownKeys: () => {
        throw new Error("trap");
      },
    });
    expect(captureRuntimeNonEntryAcknowledgementV04(trapped)).toEqual({
      ok: false,
      error: "RUNTIME_NON_ENTRY_ACKNOWLEDGEMENT_INVALID",
    });
  });

  it("fails closed on admission repository-state drift", async () => {
    const value = fixture({ drifted_pre_state_hash: H("f") });
    const store = await captureRuntimeFileStoreV04ForTest({ run_directory: value.root });
    if (!store.ok) throw new Error(store.error);
    const acknowledgement = captureRuntimeNonEntryAcknowledgementV04({
      observation: observation("non_entry_drift_ack_s41", "2026-08-30T18:04:00Z", 40),
      action_admission_event_ref: ref(value.admission),
      action_id: "action_non_entry_s41_1",
      task_ref: "task-s41",
      attempt_event_ref: ref(value.attempt),
      adapter_invocation_id: "invocation_non_entry_s41_1",
      adapter_ref: "adapter-s41",
      adapter_version_hash: H("1"),
      fence_epoch: 0,
      host_identity_hash: H("2"),
      boot_id_hash: H("3"),
      unit_name_hash: H("4"),
      cgroup_path_hash: H("5"),
      acknowledgement_observation_hash: H("6"),
    });
    const termination = captureRuntimeTerminationEvidenceV04({
      observation: observation("non_entry_drift_term_s41", "2026-08-30T18:04:01Z", 41),
      action_admission_event_ref: ref(value.admission),
      adapter_invocation_id: "invocation_non_entry_s41_1",
      host_identity_hash: H("2"),
      boot_id_hash: H("3"),
      unit_name_hash: H("4"),
      cgroup_path_hash: H("5"),
      termination_request_hash: H("7"),
      termination_observation_hash: H("8"),
      observed_outcome: "terminated",
    });
    if (!acknowledgement.ok || !termination.ok) throw new Error("capture failed");

    await expect(writeRuntimeNonEntryReconciliationV04(store.store, {
      action_admission_event_ref: ref(value.admission),
      acknowledgement: acknowledgement.value,
      termination: termination.value,
      acknowledged_event_id: "event_non_entry_drift_ack_s41",
      termination_event_id: "event_non_entry_drift_term_s41",
      reconciliation_event_id: "event_non_entry_drift_reconciliation_s41",
      effect_outcome_event_ids: [
        "event_non_entry_drift_effect_a_s41",
        "event_non_entry_drift_effect_b_s41",
      ],
      settled_event_id: "event_non_entry_drift_settled_s41",
    })).resolves.toEqual({
      ok: false,
      classification: "NOT_COMMITTED",
      error: "RUNTIME_NON_ENTRY_REFUSED",
      refusal_reason: "repository-state-drift",
    });
  });

  it("returns OUTCOME_UNKNOWN when the single durable batch becomes ambiguous", async () => {
    const value = fixture();
    let syncCalls = 0;
    const store = await captureRuntimeFileStoreV04ForTest({ run_directory: value.root }, {
      sync: async (handle) => {
        syncCalls += 1;
        if (syncCalls === 3) throw new Error("append sync failed");
        await handle.sync();
      },
    });
    if (!store.ok) throw new Error(store.error);
    const acknowledgement = captureRuntimeNonEntryAcknowledgementV04({
      observation: observation("non_entry_unknown_ack_s41", "2026-08-30T18:05:00Z", 50),
      action_admission_event_ref: ref(value.admission),
      action_id: "action_non_entry_s41_1",
      task_ref: "task-s41",
      attempt_event_ref: ref(value.attempt),
      adapter_invocation_id: "invocation_non_entry_s41_1",
      adapter_ref: "adapter-s41",
      adapter_version_hash: H("1"),
      fence_epoch: 0,
      host_identity_hash: H("2"),
      boot_id_hash: H("3"),
      unit_name_hash: H("4"),
      cgroup_path_hash: H("5"),
      acknowledgement_observation_hash: H("6"),
    });
    const termination = captureRuntimeTerminationEvidenceV04({
      observation: observation("non_entry_unknown_term_s41", "2026-08-30T18:05:01Z", 51),
      action_admission_event_ref: ref(value.admission),
      adapter_invocation_id: "invocation_non_entry_s41_1",
      host_identity_hash: H("2"),
      boot_id_hash: H("3"),
      unit_name_hash: H("4"),
      cgroup_path_hash: H("5"),
      termination_request_hash: H("7"),
      termination_observation_hash: H("8"),
      observed_outcome: "terminated",
    });
    if (!acknowledgement.ok || !termination.ok) throw new Error("capture failed");

    await expect(writeRuntimeNonEntryReconciliationV04(store.store, {
      action_admission_event_ref: ref(value.admission),
      acknowledgement: acknowledgement.value,
      termination: termination.value,
      acknowledged_event_id: "event_non_entry_unknown_ack_s41",
      termination_event_id: "event_non_entry_unknown_term_s41",
      reconciliation_event_id: "event_non_entry_unknown_reconciliation_s41",
      effect_outcome_event_ids: [
        "event_non_entry_unknown_effect_a_s41",
        "event_non_entry_unknown_effect_b_s41",
      ],
      settled_event_id: "event_non_entry_unknown_settled_s41",
    })).resolves.toEqual({
      ok: false,
      classification: "OUTCOME_UNKNOWN",
      error: "RUNTIME_NON_ENTRY_OUTCOME_UNKNOWN",
    });
  });
});
