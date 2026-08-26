import { afterEach, describe, expect, it, vi } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import { inspectRuntimeLedgerV03 } from "../../src/run/runtime-ledger-v03.js";
import {
  captureRuntimeEffectAdapterV03,
  captureRuntimeExecutionCoordinatorV03,
  closeRuntimeExecutionCoordinatorV03,
  coordinateRuntimeActionV03,
} from "../../src/run/runtime-execution-coordinator-v03.js";
import { buildRunManifestV03 } from "../../src/run/runtime-manifest-v03.js";
import {
  appendRuntimeEventV03,
  closeRuntimeWriteSessionV03,
  createRuntimeEventDraftV03,
  createSyntheticCapturedRuntimeRunStoreV03ForTest,
  inspectRuntimeWriteSessionV03ForDispatch,
  inspectSyntheticRuntimeRunStoreV03ForTest,
  openRuntimeWriteSessionV03,
  type RuntimeWriteExpectationV03,
  type RuntimeWriteSessionV03,
} from "../../src/run/runtime-write-session-v03.js";
import { captureRuntimeTerminationCapabilityV03 } from "../../src/run/runtime-termination-v03.js";
import {
  createSignedRuntimeActionAdmissionV03Fixture,
  SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS,
} from "../helpers/runtime-action-admission-v03-fixture.js";

const H = (character: string) => `sha256:${character.repeat(64)}`;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const inventory = {
  resolved_run_plan: "0.2", ledger_event: "0.3", run_manifest: "0.3", artifact_manifest: "0.2",
  redaction_derivative: "0.2", human_authorization_proof: "0.2", authority_envelope: "0.2",
  agency_recommendation: "0.2", authority_revocation: "0.2", task_result: "0.2",
  manual_observation: "0.2", export_decision: "0.2", evidence_item: "0.2", gate_result: "0.2",
  evaluation_result: "0.2", claim: "0.2", finding: "0.2", waiver: "0.2", gate_waiver_authority: "0.2",
} as const;

const sessions: RuntimeWriteSessionV03[] = [];

afterEach(async () => {
  for (const session of sessions.splice(0)) await closeRuntimeWriteSessionV03(session);
});

function initialLedger(runId = "run_crash_integration_v03", active = false): Uint8Array {
  const initialized = {
    schema_version: "0.3", event_id: "event_init_v03", run_id: runId, sequence: 1,
    recorded_at: "2026-08-24T10:00:00Z", event_type: "run.initialized", source: "kernel", authority_ref: null,
    risk_tier: "T1", related_ids: [], previous_event_hash: null,
    payload: { plan_hash: H("a"), initial_fence_epoch: 0, runtime_schema_versions: inventory },
  };
  const initializedRow = { ...initialized, event_hash: hashCanonical(initialized) };
  if (!active) {
    return encoder.encode(`${JSON.stringify(initializedRow)}\n`);
  }
  const started = {
    schema_version: "0.3", event_id: "event_started_v03", run_id: runId, sequence: 2,
    recorded_at: "2026-08-24T10:00:01Z", event_type: "run.started", source: "kernel", authority_ref: null,
    risk_tier: "T1", related_ids: [], previous_event_hash: initializedRow.event_hash,
    payload: { executor_profile_hash: H("b") },
  };
  return encoder.encode(`${JSON.stringify(initializedRow)}\n${JSON.stringify({ ...started, event_hash: hashCanonical(started) })}\n`);
}

function captureFiles(ledger: Uint8Array, includePlan = true) {
  const rows = [
    { path: "artifact-manifest.json", family: "projection" as const, required: false, mode: null, bytes: null },
    { path: "ledger.jsonl", family: "primary" as const, required: true, mode: 384, bytes: ledger },
    { path: "records/authority.json", family: "record" as const, required: true, mode: 384, bytes: encoder.encode('{"authority":"captured"}\n') },
  ];
  if (includePlan) {
    rows.push({ path: "resolved-run-plan.json", family: "primary" as const, required: true, mode: 384, bytes: encoder.encode('{"plan":"captured"}\n') });
  }
  return rows;
}

let fixtureOrdinal = 0;

function fixture(options: { faultAt?: string | null; runId?: string; active?: boolean; envelopes?: number } = {}) {
  const runId = options.runId ?? `run_crash_integration_v03_${fixtureOrdinal += 1}`;
  const ledger = initialLedger(runId, options.active ?? false);
  const capturedFiles = captureFiles(ledger, true);
  const manifest = buildRunManifestV03({ ledger_bytes: ledger, created_at: "2026-08-24T10:00:01Z", captured_files: capturedFiles });
  if (!manifest.ok) throw new Error(manifest.reason);
  const store = createSyntheticCapturedRuntimeRunStoreV03ForTest({
    run_id: runId,
    ledger_bytes: ledger,
    manifest_bytes: manifest.bytes,
    captured_files: capturedFiles,
    lock_identity: "lock_crash_integration_v03",
    lock_identity_valid: true,
    fault_at: options.faultAt ?? null,
    event_envelopes: Array.from({ length: options.envelopes ?? 4 }, (_, index) => ({
      event_id: `event_crash_v03_${index + 1}`,
      recorded_at: `2026-08-24T10:00:0${index + 1}Z`,
    })),
    admission_context: {
      authority_trust_context: Object.freeze({}),
      repository_pre_state_hash: H("c"), normalized_dispatch_hash: H("d"), observed_at: "2026-08-24T10:00:10Z",
      elapsed_ms: 15, reviewer_view_hash: H("e"),
      enforcement: { available: true, information_flow_allowed: true, gates_passed: true, immediate_revalidation_passed: true },
      condition_results: [], lease_id: "lease_crash_v03", clock_id: "clock_crash_v03", action_id: "action_crash_v03",
    },
  });
  if (store === null) throw new Error("crash synthetic fixture was rejected");
  const expectation: RuntimeWriteExpectationV03 = {
    run_id: runId,
    ledger_bytes_hash: manifest.manifest.ledger_bytes_hash,
    ledger_sequence: manifest.manifest.ledger_sequence,
    ledger_head_hash: manifest.manifest.ledger_head_hash,
    current_fence_epoch: manifest.manifest.current_fence_epoch,
    manifest_hash: manifest.manifest.manifest_hash,
  };
  const firstLine = decoder.decode(ledger).split("\n")[0];
  if (firstLine === undefined || firstLine.length === 0) throw new Error("initialized event fixture unavailable");
  const initialized = JSON.parse(firstLine) as Readonly<{ sequence: number; event_hash: string }>;
  return {
    runId,
    store,
    expectation,
    initializedRef: {
      ledger_sequence: initialized.sequence,
      event_hash: initialized.event_hash,
    },
  };
}

function startedDraft() {
  const draft = createRuntimeEventDraftV03({
    event_type: "run.started", source: "kernel", authority_ref: null, risk_tier: "T1", related_ids: [],
    payload: { executor_profile_hash: H("b") },
  });
  if (draft === null) throw new Error("run.started draft fixture rejected");
  return draft;
}

function pausedDraft(requestEventRef: Readonly<{ ledger_sequence: number; event_hash: string }>) {
  const draft = createRuntimeEventDraftV03({
    event_type: "run.paused", source: "operator", authority_ref: "principal_operator", risk_tier: "T1", related_ids: [],
    payload: { requested_by: "operator", reason_code: "operator-request", request_event_ref: requestEventRef },
  });
  if (draft === null) throw new Error("run.paused draft fixture rejected");
  return draft;
}

function exactObservation(invocation: { adapter_invocation_id: string; action_admission_event_ref: Readonly<{ ledger_sequence: number; event_hash: string; }>; normalized_dispatch_hash: string; }) {
  return {
    observation_version: "0.1",
    adapter_invocation_id: invocation.adapter_invocation_id,
    claimed_action_id: SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS.action_id,
    action_admission_event_ref: invocation.action_admission_event_ref,
    normalized_dispatch_hash: invocation.normalized_dispatch_hash,
    effect_refs: ["effect-diagnose-root-cause"],
    adapter_identity_hash: hashCanonical({
      purpose: "effect-dispatch-adapter-identity-v01",
      adapter_ref: "adapter_crash_v03",
      adapter_version_hash: H("2"),
    }),
    adapter_profile_hash: H("3"),
  };
}

async function readyCoordinator(dispatch: (invocation: {
  adapter_invocation_id: string;
  action_admission_event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
  normalized_dispatch_hash: string;
}) => Promise<unknown>) {
  const fixtureValue = await createSignedRuntimeActionAdmissionV03Fixture({
    additional_event_envelopes: [
      { event_id: "event_adapter_started_v03", recorded_at: "2026-08-24T10:00:31Z" },
      { event_id: "event_adapter_quarantine_v03", recorded_at: "2026-08-24T10:00:32Z" },
      { event_id: "event_adapter_reject_v03", recorded_at: "2026-08-24T10:00:33Z" },
      { event_id: "event_adapter_termination_v03", recorded_at: "2026-08-24T10:00:34Z" },
    ],
  });
  const opened = await openRuntimeWriteSessionV03(fixtureValue.store, fixtureValue.expectation);
  if (!opened.ok) throw new Error(opened.error);
  sessions.push(opened.session);
  const capability = captureRuntimeTerminationCapabilityV03({
    host_identity: "host_crash_v03",
    boot_id: "boot_crash_v03",
    unit_name: "unit_crash_v03",
    cgroup_path: "/sys/fs/cgroup/crash-v03",
    terminate: async (request: Readonly<{
      host_identity: string;
      boot_id: string;
      unit_name: string;
      cgroup_path: string;
    }>) => ({
      ...request,
      cgroup_populated: 0 as const,
      unit_state: "inactive" as const,
    }),
  });
  if (capability === null) throw new Error("termination capability capture failed");
  const coordinator = await captureRuntimeExecutionCoordinatorV03(opened.session, capability);
  if (coordinator === null) throw new Error("coordinator capture failed");
  const adapter = captureRuntimeEffectAdapterV03({
    normalized_dispatch_hash: fixtureValue.request.normalized_dispatch_hash,
    adapter_ref: "adapter_crash_v03",
    adapter_version_hash: H("2"),
    adapter_profile_hash: H("3"),
    adapter_invocation_id: "invocation_crash_v03",
    dispatch,
  });
  if (adapter === null) throw new Error("adapter capture failed");
  return { ...fixtureValue, session: opened.session, coordinator, adapter };
}

describe("S40-C integration crash and concurrency", { timeout: 60_000 }, () => {
  it.each([
    "append-write", "append-write-partial", "ledger-sync", "ledger-close", "ledger-readback",
    "manifest-temp-write", "manifest-temp-sync", "manifest-temp-close", "manifest-rename", "directory-sync", "final-readback",
  ] as const)("poisons and classifies %s append interruption as OUTCOME_UNKNOWN", async (faultAt) => {
    const fixtureValue = fixture({ faultAt, envelopes: 3 });
    const opened = await openRuntimeWriteSessionV03(fixtureValue.store, fixtureValue.expectation);
    if (!opened.ok) throw new Error(opened.error);
    const result = await appendRuntimeEventV03(opened.session, startedDraft());
    expect(result).toMatchObject({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_IO_OUTCOME_UNKNOWN" });
    expect(inspectSyntheticRuntimeRunStoreV03ForTest(fixtureValue.store)?.poisoned).toBe(true);
    await expect(appendRuntimeEventV03(opened.session, startedDraft())).resolves.toEqual({
      ok: false,
      classification: "OUTCOME_UNKNOWN",
      error: "RUNTIME_WRITE_SESSION_POISONED",
    });
    const snapshot = inspectSyntheticRuntimeRunStoreV03ForTest(fixtureValue.store);
    if (snapshot === null) throw new Error("crash snapshot unavailable");
    const fullInspection = inspectRuntimeLedgerV03(snapshot.ledger_bytes);
    if (fullInspection.ok) {
      expect(fullInspection.ledger.events.map((event) => event.event_type)).toEqual(["run.initialized", "run.started"]);
    } else {
      const lastNewline = snapshot.ledger_bytes.lastIndexOf(10);
      expect(lastNewline).toBeGreaterThanOrEqual(0);
      expect(inspectRuntimeLedgerV03(snapshot.ledger_bytes.slice(0, lastNewline + 1))).toMatchObject({
        ok: true,
        ledger: { events: [{ event_type: "run.initialized" }] },
      });
    }
  });

  it("returns NOT_COMMITTED and closes on before-write without poisoning", async () => {
    const fixtureValue = fixture({ faultAt: "before-write", active: false, envelopes: 2 });
    const opened = await openRuntimeWriteSessionV03(fixtureValue.store, fixtureValue.expectation);
    if (!opened.ok) throw new Error(opened.error);
    await expect(appendRuntimeEventV03(opened.session, startedDraft())).resolves.toEqual({
      ok: false,
      classification: "NOT_COMMITTED",
      error: "RUNTIME_WRITE_NOT_COMMITTED",
    });
    expect(inspectSyntheticRuntimeRunStoreV03ForTest(fixtureValue.store)).toMatchObject({ poisoned: false, lock_held: false });
    await expect(appendRuntimeEventV03(opened.session, startedDraft())).resolves.toEqual({
      ok: false,
      classification: "NOT_COMMITTED",
      error: "RUNTIME_WRITE_SESSION_CLOSED",
    });
  });

  it("serializes concurrent appends and preserves exact tail-write ordering", async () => {
    const fixtureValue = fixture({ active: false, envelopes: 2 });
    const opened = await openRuntimeWriteSessionV03(fixtureValue.store, fixtureValue.expectation);
    if (!opened.ok) throw new Error(opened.error);
    const [first, second] = await Promise.all([
      appendRuntimeEventV03(opened.session, startedDraft()),
      appendRuntimeEventV03(opened.session, pausedDraft(fixtureValue.initializedRef)),
    ]);
    expect(first).toMatchObject({ ok: true, classification: "COMMITTED", event_ref: { ledger_sequence: 2 } });
    expect(second).toMatchObject({ ok: true, classification: "COMMITTED", event_ref: { ledger_sequence: 3 } });
    const operations = inspectSyntheticRuntimeRunStoreV03ForTest(fixtureValue.store)!.operations;
    expect(operations.filter((operation) => operation === "final-readback:exact")).toHaveLength(2);
    expect(operations.indexOf("final-readback:exact")).toBeLessThan(operations.lastIndexOf("prefix-validation:accepted"));
    const dispatch = await inspectRuntimeWriteSessionV03ForDispatch(opened.session);
    expect(dispatch).toMatchObject({
      ok: true,
      snapshot: {
        events: [
          { event_type: "run.initialized" },
          { event_type: "run.started" },
          { event_type: "run.paused" },
        ],
      },
    });
  });

  it("rejects non-canonical ledger text and partial-line corruption as syntax failures", async () => {
    const fixtureValue = fixture({ active: false, envelopes: 2 });
    const snapshot = inspectSyntheticRuntimeRunStoreV03ForTest(fixtureValue.store);
    if (snapshot === null) throw new Error("snapshot unavailable");
    const missingTrailingNewline = snapshot.ledger_bytes.slice(0, snapshot.ledger_bytes.length - 1);
    expect(inspectRuntimeLedgerV03(missingTrailingNewline)).toMatchObject({ ok: false, reason: "LEDGER_SYNTAX_INVALID" });
    const malformedText = `${decoder.decode(snapshot.ledger_bytes).trim()}\n{`;
    const malformedLine = encoder.encode(malformedText);
    expect(inspectRuntimeLedgerV03(malformedLine)).toMatchObject({ ok: false, reason: "LEDGER_SYNTAX_INVALID" });
  });

  it("never dispatches when coordinator admission fails due to ungranted request drift", async () => {
    const dispatch = vi.fn(async (invocation: Parameters<typeof exactObservation>[0]) => ({
      disposition: "DISPATCHED" as const,
      observation: exactObservation(invocation),
      result: { action: "should-not-run" },
    }));
    const state = await readyCoordinator(dispatch);
    await expect(coordinateRuntimeActionV03(state.coordinator, state.adapter, {
      ...state.request,
      normalized_dispatch_hash: H("9"),
    })).resolves.toMatchObject({ ok: false, error: "CANONICAL_AUTHORITY_RECORDS_INVALID", cleanup_status: "CLOSED" });
    expect(dispatch).not.toHaveBeenCalled();
    expect(await inspectRuntimeWriteSessionV03ForDispatch(state.session)).toMatchObject({ ok: false, error: "RUNTIME_WRITE_SESSION_CLOSED" });
    await closeRuntimeExecutionCoordinatorV03(state.coordinator);
  });

  it("closes an admitted disconnect as outcome-unknown without execution-start or retry", async () => {
    const dispatch = vi.fn(async () => { throw new Error("synthetic disconnect"); });
    const state = await readyCoordinator(dispatch);
    await expect(coordinateRuntimeActionV03(state.coordinator, state.adapter, state.request)).resolves.toEqual({
      ok: false,
      error: "DISPATCH_OUTCOME_UNKNOWN_PENDING_RECONCILIATION",
      cleanup_status: "CLOSED",
    });
    expect(dispatch).toHaveBeenCalledTimes(1);
    const snapshot = inspectSyntheticRuntimeRunStoreV03ForTest(state.store);
    if (snapshot === null) throw new Error("disconnect snapshot unavailable");
    const inspected = inspectRuntimeLedgerV03(snapshot.ledger_bytes);
    if (!inspected.ok) throw new Error(inspected.reason);
    expect(inspected.ledger.events.filter((event) => event.event_type === "task.action-admitted")).toHaveLength(1);
    expect(inspected.ledger.events.filter((event) => event.event_type === "task.execution-started")).toHaveLength(0);
  });

  it("quarantines an observation whose claimed invocation and action have no exact grant", async () => {
    const state = await readyCoordinator(async (invocation) => ({
      disposition: "DISPATCHED",
      observation: {
        ...exactObservation(invocation),
        adapter_invocation_id: "invocation_unknown_v03",
        claimed_action_id: "action_unknown_v03",
      },
      result: { must_not_escape: true },
    }));
    await expect(coordinateRuntimeActionV03(state.coordinator, state.adapter, state.request)).resolves.toMatchObject({
      ok: true,
      disposition: "QUARANTINED",
      reason_code: "unmatched-observation",
      termination_result: { ok: true, observed_outcome: "terminated" },
      cleanup_status: "CLOSED",
    });
    const snapshot = inspectSyntheticRuntimeRunStoreV03ForTest(state.store);
    if (snapshot === null) throw new Error("quarantine snapshot unavailable");
    const inspected = inspectRuntimeLedgerV03(snapshot.ledger_bytes);
    if (!inspected.ok) throw new Error(inspected.reason);
    expect(inspected.ledger.events.slice(-3).map((event) => event.event_type)).toEqual([
      "integrity.observation-rejected",
      "run.quarantined",
      "process.termination-attempted",
    ]);
  });

  it("discloses a capture gap, quarantines, and closes without result release", async () => {
    const state = await readyCoordinator(async () => ({
      disposition: "DISPATCHED",
      observation: null,
      result: { must_not_escape: true },
    }));
    await expect(coordinateRuntimeActionV03(state.coordinator, state.adapter, state.request)).resolves.toMatchObject({
      ok: true,
      disposition: "QUARANTINED",
      reason_code: "capture-gap",
      termination_result: { ok: true, observed_outcome: "terminated" },
      cleanup_status: "CLOSED",
    });
  });

  it("keeps the live committed event sequence exactly replay-equivalent", async () => {
    const state = await readyCoordinator(async (invocation) => ({
      disposition: "DISPATCHED",
      observation: exactObservation(invocation),
      result: { bounded: true },
    }));
    await expect(coordinateRuntimeActionV03(state.coordinator, state.adapter, state.request)).resolves.toMatchObject({
      ok: true,
      disposition: "MATCHED",
    });
    const live = await inspectRuntimeWriteSessionV03ForDispatch(state.session);
    if (!live.ok) throw new Error(live.error);
    const snapshot = inspectSyntheticRuntimeRunStoreV03ForTest(state.store);
    if (snapshot === null) throw new Error("live snapshot unavailable");
    const replay = inspectRuntimeLedgerV03(snapshot.ledger_bytes);
    if (!replay.ok) throw new Error(replay.reason);
    expect(replay.ledger.events).toEqual(live.snapshot.events);
    expect({
      run_id: replay.ledger.run_id,
      plan_hash: replay.ledger.plan_hash,
      ledger_sequence: replay.ledger.sequence,
      ledger_head_hash: replay.ledger.head_hash,
    }).toEqual({
      run_id: live.snapshot.run_id,
      plan_hash: live.snapshot.plan_hash,
      ledger_sequence: live.snapshot.ledger_sequence,
      ledger_head_hash: live.snapshot.ledger_head_hash,
    });
    await closeRuntimeExecutionCoordinatorV03(state.coordinator);
  });
});
