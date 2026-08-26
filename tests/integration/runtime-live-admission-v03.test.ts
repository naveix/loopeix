import { readFileSync } from "node:fs";

import { afterEach, describe, expect, it, vi } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import {
  captureBrokeredModelExecutorAdapterV01,
  runCapturedBrokeredModelExecutorV01,
} from "../../src/run/brokered-model-executor-v01.js";
import {
  captureRuntimeEffectAdapterV03,
  captureRuntimeExecutionCoordinatorV03,
  closeRuntimeExecutionCoordinatorV03,
  coordinateRuntimeActionV03,
  takeRuntimeInvocationResultV01,
} from "../../src/run/runtime-execution-coordinator-v03.js";
import {
  captureRuntimeTerminationCapabilityV03,
  terminateRuntimeActionV03,
} from "../../src/run/runtime-termination-v03.js";
import {
  appendRuntimeEventV03,
  closeRuntimeWriteSessionV03,
  createRuntimeEventDraftV03,
  inspectSyntheticRuntimeRunStoreV03ForTest,
  openRuntimeWriteSessionV03,
  type RuntimeWriteSessionV03,
} from "../../src/run/runtime-write-session-v03.js";
import {
  createSignedRuntimeActionAdmissionV03Fixture,
  SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS,
} from "../helpers/runtime-action-admission-v03-fixture.js";

const H = (character: string) => `sha256:${character.repeat(64)}`;
const sessions: RuntimeWriteSessionV03[] = [];

afterEach(async () => {
  for (const session of sessions.splice(0)) await closeRuntimeWriteSessionV03(session);
});

const effectClasses = [
  {
    action_kind: "command", program_ref: "git-readonly", arguments_ref: "registered-arguments",
    arguments_hash: H("a"), cwd_ref: "workspace-root",
  },
  {
    action_kind: "file", operation: "write", path_ref: "file-target",
    content_ref: "registered-content", content_hash: H("b"),
  },
  {
    action_kind: "tool", tool_ref: "registered-tool", tool_schema_hash: H("c"),
    arguments_ref: "registered-arguments", arguments_hash: H("d"),
  },
  {
    action_kind: "connector", connector_ref: "registered-connector", account_ref: "registered-account",
    operation_ref: "registered-operation", target_ref: "registered-target",
  },
  {
    action_kind: "network", method: "POST", origin_ref: "api-origin", path_ref: "network-path",
    body_ref: "registered-body", body_hash: H("e"),
  },
] as const;

function modelContext(ordinal: number) {
  return {
    context_version: "0.1",
    executor_profile_hash: H("1"),
    run_id: SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS.run_id,
    plan_hash: H("2"),
    task_ref: "diagnose-root-cause",
    attempt_id: `attempt_live_v03_${ordinal}`,
    turn_id: `turn_live_v03_${ordinal}`,
    actor_identity_hash: H("3"),
    on_behalf_of_chain_hash: H("4"),
    prompt: "Propose the registered bounded action.",
    context_items: [],
    allowed_references: {
      effect_refs: ["effect-diagnose-root-cause"], evidence_refs: [],
      program_refs: ["git-readonly"], path_refs: ["workspace-root", "file-target", "network-path"],
      origin_refs: ["api-origin"], tool_refs: ["registered-tool"], connector_refs: ["registered-connector"],
      account_refs: ["registered-account"], operation_refs: ["registered-operation"],
      target_refs: ["registered-target"], content_refs: ["registered-content"], body_refs: ["registered-body"],
      argument_refs: ["registered-arguments"],
    },
  };
}

function ledgerEvents(store: Parameters<typeof inspectSyntheticRuntimeRunStoreV03ForTest>[0]) {
  const bytes = inspectSyntheticRuntimeRunStoreV03ForTest(store)?.ledger_bytes;
  if (bytes === undefined) throw new Error("runtime ledger unavailable");
  return new TextDecoder().decode(bytes).trim().split("\n")
    .map((row) => JSON.parse(row) as Readonly<{ event_type: string; payload: Record<string, unknown> }>);
}

function coordinatorTerminationCapability(suffix: string) {
  return captureRuntimeTerminationCapabilityV03({
    host_identity: `host_live_${suffix}`,
    boot_id: `boot_live_${suffix}`,
    unit_name: `unit_live_${suffix}`,
    cgroup_path: `/cg/live/${suffix}`,
    terminate: async (request: Readonly<{
      host_identity: string;
      boot_id: string;
      unit_name: string;
      cgroup_path: string;
    }>) => ({ ...request, cgroup_populated: 0 as const, unit_state: "inactive" as const }),
  });
}

describe("S40-B7 live runtime admission integration", { timeout: 60_000 }, () => {
  it("routes the initial captured model executor through one coordinator custody path", async () => {
    const action = effectClasses[0]!;
    const fixture = await createSignedRuntimeActionAdmissionV03Fixture({
      additional_event_envelopes: [{ event_id: `event_started_live_${action.action_kind}`, recorded_at: "2026-08-24T10:00:31Z" }],
    });
    const opened = await openRuntimeWriteSessionV03(fixture.store, fixture.expectation);
    if (!opened.ok) throw new Error(opened.error);
    sessions.push(opened.session);
    const terminationCapability = coordinatorTerminationCapability("model");
    if (terminationCapability === null) throw new Error("termination capability capture failed");
    const coordinator = await captureRuntimeExecutionCoordinatorV03(opened.session, terminationCapability);
    if (coordinator === null) throw new Error("coordinator capture failed");
    const modelAdapterIdentity = Object.freeze({
      executor_profile_hash: H("1"),
      adapter_ref: "model_adapter_live_v01",
      adapter_version_hash: H("7"),
      eligible_adapter_evidence_hash: H("8"),
      bypass_evidence_hash: H("9"),
    });
    const modelAdapter = captureBrokeredModelExecutorAdapterV01({
      ...modelAdapterIdentity,
      invoke: async () => ({
        response_version: "0.1", kind: "action-proposal", proposal_ordinal: 1,
        task_ref: "diagnose-root-cause", effect_refs: ["effect-diagnose-root-cause"],
        data_classes: ["internal"], action,
      }),
    });
    if (modelAdapter === null) throw new Error("captured model adapter rejected");
    const adapterRef = `adapter_live_${action.action_kind}`;
    const adapterVersionHash = H("5");
    const adapterProfileHash = H("6");
    const adapterInvocationId = `invocation_live_${action.action_kind}`;
    const effectAdapter = captureRuntimeEffectAdapterV03({
      normalized_dispatch_hash: fixture.request.normalized_dispatch_hash,
      adapter_ref: adapterRef,
      adapter_version_hash: adapterVersionHash,
      adapter_profile_hash: adapterProfileHash,
      adapter_invocation_id: adapterInvocationId,
      dispatch: async (invocation: Readonly<{
        adapter_invocation_id: string;
        action_admission_event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
        normalized_dispatch_hash: string;
      }>) => ({
        disposition: "DISPATCHED",
        observation: {
          observation_version: "0.1",
          adapter_invocation_id: invocation.adapter_invocation_id,
          claimed_action_id: SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS.action_id,
          action_admission_event_ref: invocation.action_admission_event_ref,
          normalized_dispatch_hash: invocation.normalized_dispatch_hash,
          effect_refs: ["effect-diagnose-root-cause"],
          adapter_identity_hash: hashCanonical({
            purpose: "effect-dispatch-adapter-identity-v01", adapter_ref: adapterRef,
            adapter_version_hash: adapterVersionHash,
          }),
          adapter_profile_hash: adapterProfileHash,
        },
        result: await runCapturedBrokeredModelExecutorV01(
          modelContext(effectClasses.indexOf(action)),
          modelAdapter,
          modelAdapterIdentity,
        ),
      }),
    });
    if (effectAdapter === null) throw new Error("runtime effect adapter rejected");

    const coordinated = await coordinateRuntimeActionV03(coordinator, effectAdapter, fixture.request);
    expect(coordinated).toMatchObject({ ok: true, disposition: "MATCHED", cleanup_status: "OPEN" });
    if (!coordinated.ok || coordinated.disposition !== "MATCHED") throw new Error("matched custody unavailable");
    expect(takeRuntimeInvocationResultV01(coordinated.custody, coordinator, {
      adapter_invocation_id: coordinated.adapter_invocation_id,
      action_admission_event_ref: coordinated.action_admission_event_ref,
    })).toMatchObject({ ok: true, value: { ok: true, value: { kind: "action-proposal", action } } });
    const events = ledgerEvents(fixture.store);
    expect(events.filter((event) => event.event_type === "task.action-admitted")).toHaveLength(1);
    expect(events.filter((event) => event.event_type === "task.execution-started")).toHaveLength(1);
    await closeRuntimeExecutionCoordinatorV03(coordinator);
  });

  it.each(effectClasses)("routes a later synthetic $action_kind effect through the same coordinator API", async (action) => {
    const fixture = await createSignedRuntimeActionAdmissionV03Fixture({
      additional_event_envelopes: [{ event_id: `event_started_effect_${action.action_kind}`, recorded_at: "2026-08-24T10:00:31Z" }],
    });
    const opened = await openRuntimeWriteSessionV03(fixture.store, fixture.expectation);
    if (!opened.ok) throw new Error(opened.error);
    sessions.push(opened.session);
    const terminationCapability = coordinatorTerminationCapability(`effect_${action.action_kind}`);
    if (terminationCapability === null) throw new Error("termination capability capture failed");
    const coordinator = await captureRuntimeExecutionCoordinatorV03(opened.session, terminationCapability);
    if (coordinator === null) throw new Error("coordinator capture failed");
    const adapterRef = `adapter_effect_${action.action_kind}`;
    const adapterVersionHash = H("9");
    const adapterProfileHash = H("a");
    const callback = vi.fn(async (invocation: Readonly<{
      adapter_invocation_id: string;
      action_admission_event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
      normalized_dispatch_hash: string;
    }>) => ({
      disposition: "DISPATCHED",
      observation: {
        observation_version: "0.1", adapter_invocation_id: invocation.adapter_invocation_id,
        claimed_action_id: SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS.action_id,
        action_admission_event_ref: invocation.action_admission_event_ref,
        normalized_dispatch_hash: invocation.normalized_dispatch_hash,
        effect_refs: ["effect-diagnose-root-cause"],
        adapter_identity_hash: hashCanonical({
          purpose: "effect-dispatch-adapter-identity-v01", adapter_ref: adapterRef,
          adapter_version_hash: adapterVersionHash,
        }),
        adapter_profile_hash: adapterProfileHash,
      },
      result: { effect_class: action.action_kind, completed: true },
    }));
    const effectAdapter = captureRuntimeEffectAdapterV03({
      normalized_dispatch_hash: fixture.request.normalized_dispatch_hash,
      adapter_ref: adapterRef, adapter_version_hash: adapterVersionHash,
      adapter_profile_hash: adapterProfileHash,
      adapter_invocation_id: `invocation_effect_${action.action_kind}`,
      dispatch: callback,
    });
    if (effectAdapter === null) throw new Error("runtime effect adapter rejected");

    const coordinated = await coordinateRuntimeActionV03(coordinator, effectAdapter, fixture.request);
    expect(coordinated).toMatchObject({ ok: true, disposition: "MATCHED", cleanup_status: "OPEN" });
    if (!coordinated.ok || coordinated.disposition !== "MATCHED") throw new Error("matched custody unavailable");
    expect(callback).toHaveBeenCalledTimes(1);
    expect(takeRuntimeInvocationResultV01(coordinated.custody, coordinator, {
      adapter_invocation_id: coordinated.adapter_invocation_id,
      action_admission_event_ref: coordinated.action_admission_event_ref,
    })).toEqual({ ok: true, value: { effect_class: action.action_kind, completed: true } });
    const events = ledgerEvents(fixture.store);
    expect(events.filter((event) => event.event_type === "task.action-admitted")).toHaveLength(1);
    expect(events.filter((event) => event.event_type === "task.execution-started")).toHaveLength(1);
    await closeRuntimeExecutionCoordinatorV03(coordinator);
  });

  it("binds B6 termination to the exact coordinator-created execution-start event", async () => {
    const fixture = await createSignedRuntimeActionAdmissionV03Fixture({
      additional_event_envelopes: [
        { event_id: "event_started_live_termination", recorded_at: "2026-08-24T10:00:31Z" },
        { event_id: "event_abort_live_termination", recorded_at: "2026-08-24T10:00:32Z" },
        { event_id: "event_termination_live_termination", recorded_at: "2026-08-24T10:00:33Z" },
      ],
    });
    const opened = await openRuntimeWriteSessionV03(fixture.store, fixture.expectation);
    if (!opened.ok) throw new Error(opened.error);
    sessions.push(opened.session);
    const terminate = vi.fn(async () => ({
      host_identity: "host-live", boot_id: "boot-live", unit_name: "unit-live", cgroup_path: "/cg/live",
      cgroup_populated: 0, unit_state: "inactive",
    }));
    const explicitAbortCapability = captureRuntimeTerminationCapabilityV03({
      host_identity: "host-live", boot_id: "boot-live", unit_name: "unit-live", cgroup_path: "/cg/live", terminate,
    });
    if (explicitAbortCapability === null) throw new Error("termination capability rejected");
    const coordinatorCapability = coordinatorTerminationCapability("abort-owner");
    if (coordinatorCapability === null) throw new Error("coordinator termination capability rejected");
    const coordinator = await captureRuntimeExecutionCoordinatorV03(opened.session, coordinatorCapability);
    if (coordinator === null) throw new Error("coordinator capture failed");
    const adapterRef = "adapter_live_termination";
    const adapterVersionHash = H("7");
    const adapterProfileHash = H("8");
    const effectAdapter = captureRuntimeEffectAdapterV03({
      normalized_dispatch_hash: fixture.request.normalized_dispatch_hash,
      adapter_ref: adapterRef, adapter_version_hash: adapterVersionHash,
      adapter_profile_hash: adapterProfileHash, adapter_invocation_id: "invocation_live_termination",
      dispatch: async (invocation: Readonly<{
        adapter_invocation_id: string;
        action_admission_event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
        normalized_dispatch_hash: string;
      }>) => ({
        disposition: "DISPATCHED",
        observation: {
          observation_version: "0.1", adapter_invocation_id: invocation.adapter_invocation_id,
          claimed_action_id: SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS.action_id,
          action_admission_event_ref: invocation.action_admission_event_ref,
          normalized_dispatch_hash: invocation.normalized_dispatch_hash,
          effect_refs: ["effect-diagnose-root-cause"],
          adapter_identity_hash: hashCanonical({
            purpose: "effect-dispatch-adapter-identity-v01", adapter_ref: adapterRef,
            adapter_version_hash: adapterVersionHash,
          }),
          adapter_profile_hash: adapterProfileHash,
        },
        result: { accepted: true },
      }),
    });
    if (effectAdapter === null) throw new Error("runtime effect adapter rejected");
    const coordinated = await coordinateRuntimeActionV03(coordinator, effectAdapter, fixture.request);
    if (!coordinated.ok || coordinated.disposition !== "MATCHED") throw new Error("matched coordination required");
    const abortDraft = createRuntimeEventDraftV03({
      event_type: "control.abort-requested", source: "operator", authority_ref: "operator_live_termination",
      risk_tier: "T1", related_ids: [], payload: {
        request_id: "abort_live_termination", requested_by: "operator", reason_code: "operator-requested",
        policy_decision_ref: null, evidence_refs: [],
      },
    });
    if (abortDraft === null) throw new Error("abort draft rejected");
    const abort = await appendRuntimeEventV03(opened.session, abortDraft);
    if (!abort.ok) throw new Error(abort.error);
    const terminationRequest = {
      trigger: "abort", trigger_event_ref: abort.event_ref,
      action_admission_event_ref: coordinated.action_admission_event_ref,
      adapter_invocation_id: coordinated.adapter_invocation_id,
    } as const;
    await expect(terminateRuntimeActionV03(opened.session, coordinatorCapability, terminationRequest))
      .resolves.toEqual({ ok: false, error: "TERMINATION_CAPABILITY_INVALID" });
    await expect(terminateRuntimeActionV03(opened.session, explicitAbortCapability, terminationRequest))
      .resolves.toMatchObject({ ok: true, observed_outcome: "terminated" });
    expect(terminate).toHaveBeenCalledTimes(1);
    expect(ledgerEvents(fixture.store).filter((event) => event.event_type === "process.termination-attempted"))
      .toHaveLength(1);
    await closeRuntimeExecutionCoordinatorV03(coordinator);
  });

  it("keeps the coordinator package-private and independent of legacy orchestration", () => {
    const coordinatorSource = readFileSync(new URL("../../src/run/runtime-execution-coordinator-v03.ts", import.meta.url), "utf8");
    const orchestrateSource = readFileSync(new URL("../../src/run/orchestrate.ts", import.meta.url), "utf8");
    const rootSource = readFileSync(new URL("../../src/index.ts", import.meta.url), "utf8");
    expect(coordinatorSource).not.toMatch(/brokered-model-executor|orchestrate|node:fs|node:process|node:net/u);
    expect(orchestrateSource).not.toContain("runtime-execution-coordinator-v03");
    expect(rootSource).not.toMatch(/RuntimeExecutionCoordinatorV03|coordinateRuntimeActionV03|RuntimeInvocationResultCustodyV01/u);
  });
});
