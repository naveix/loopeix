import { afterEach, describe, expect, it, vi } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import type { EffectDispatchInvocationV01 } from "../../src/run/runtime-effect-dispatch-broker-v01.js";
import {
  captureRuntimeEffectAdapterV03,
  captureRuntimeExecutionCoordinatorV03,
  closeRuntimeExecutionCoordinatorV03,
  coordinateRuntimeActionV03,
  takeRuntimeInvocationResultV01,
  type CapturedRuntimeEffectAdapterV03,
  type RuntimeExecutionCoordinatorV03,
} from "../../src/run/runtime-execution-coordinator-v03.js";
import {
  closeRuntimeWriteSessionV03,
  inspectRuntimeWriteSessionV03ForDispatch,
  inspectSyntheticRuntimeRunStoreV03ForTest,
  openRuntimeWriteSessionV03,
  type RuntimeWriteSessionV03,
} from "../../src/run/runtime-write-session-v03.js";
import {
  captureRuntimeTerminationCapabilityV03,
  type CapturedRuntimeTerminationCapabilityV03,
} from "../../src/run/runtime-termination-v03.js";
import {
  createSignedRuntimeActionAdmissionV03Fixture,
  SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS,
} from "../helpers/runtime-action-admission-v03-fixture.js";

const H = (character: string) => `sha256:${character.repeat(64)}`;
const sessions: RuntimeWriteSessionV03[] = [];

afterEach(async () => {
  for (const session of sessions.splice(0)) await closeRuntimeWriteSessionV03(session);
});

const metadata = Object.freeze({
  adapter_ref: "adapter_runtime_v03",
  adapter_version_hash: H("2"),
  adapter_profile_hash: H("3"),
  adapter_invocation_id: "invocation_runtime_v03",
});

function termination(terminate = vi.fn(async (request: Readonly<{
  host_identity: string;
  boot_id: string;
  unit_name: string;
  cgroup_path: string;
}>) => ({
  ...request,
  cgroup_populated: 0 as const,
  unit_state: "inactive" as const,
}))) {
  const capability = captureRuntimeTerminationCapabilityV03({
    host_identity: "host_runtime_v03",
    boot_id: "boot_runtime_v03",
    unit_name: "unit_runtime_v03",
    cgroup_path: "/sys/fs/cgroup/runtime-v03",
    terminate,
  });
  if (capability === null) throw new Error("termination capability capture failed");
  return { capability, terminate };
}

function exactObservation(invocation: Readonly<{
  adapter_invocation_id: string;
  action_admission_event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
  normalized_dispatch_hash: string;
}>) {
  return {
    observation_version: "0.1",
    adapter_invocation_id: invocation.adapter_invocation_id,
    claimed_action_id: SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS.action_id,
    action_admission_event_ref: invocation.action_admission_event_ref,
    normalized_dispatch_hash: invocation.normalized_dispatch_hash,
    effect_refs: ["effect-diagnose-root-cause"],
    adapter_identity_hash: hashCanonical({
      purpose: "effect-dispatch-adapter-identity-v01",
      adapter_ref: metadata.adapter_ref,
      adapter_version_hash: metadata.adapter_version_hash,
    }),
    adapter_profile_hash: metadata.adapter_profile_hash,
  };
}

async function ready(
  dispatch: (invocation: EffectDispatchInvocationV01) => Promise<unknown>,
  options: Readonly<{
    terminate?: ReturnType<typeof vi.fn>;
    additional_event_envelopes?: readonly Readonly<{ event_id: string; recorded_at: string }>[];
  }> = {},
) {
  const fixture = await createSignedRuntimeActionAdmissionV03Fixture({
    additional_event_envelopes: options.additional_event_envelopes ?? [
      { event_id: "event_started_coordinator_v03", recorded_at: "2026-08-24T10:00:31Z" },
      { event_id: "event_rejection_coordinator_v03", recorded_at: "2026-08-24T10:00:32Z" },
      { event_id: "event_quarantine_coordinator_v03", recorded_at: "2026-08-24T10:00:33Z" },
      { event_id: "event_termination_coordinator_v03", recorded_at: "2026-08-24T10:00:34Z" },
    ],
  });
  const opened = await openRuntimeWriteSessionV03(fixture.store, fixture.expectation);
  if (!opened.ok) throw new Error(opened.error);
  sessions.push(opened.session);
  const capturedTermination = termination(options.terminate);
  const coordinator = await captureRuntimeExecutionCoordinatorV03(opened.session, capturedTermination.capability);
  if (coordinator === null) throw new Error("coordinator capture failed");
  const effectAdapter = adapter(fixture.request.normalized_dispatch_hash, dispatch);
  if (effectAdapter === null) throw new Error("adapter capture failed");
  return { ...fixture, session: opened.session, coordinator, adapter: effectAdapter, terminate: capturedTermination.terminate };
}

function adapter(normalizedDispatchHash: string, dispatch: (invocation: EffectDispatchInvocationV01) => Promise<unknown>) {
  return captureRuntimeEffectAdapterV03({
    ...metadata,
    normalized_dispatch_hash: normalizedDispatchHash,
    dispatch,
  });
}

describe("S40-B7 runtime execution coordinator", { timeout: 20_000 }, () => {
  it("captures strict opaque coordinator and adapter capabilities", async () => {
    const fixture = await createSignedRuntimeActionAdmissionV03Fixture();
    const opened = await openRuntimeWriteSessionV03(fixture.store, fixture.expectation);
    if (!opened.ok) throw new Error(opened.error);
    sessions.push(opened.session);
    expect(await captureRuntimeExecutionCoordinatorV03(
      opened.session,
      undefined as unknown as CapturedRuntimeTerminationCapabilityV03,
    )).toBeNull();
    expect(await captureRuntimeExecutionCoordinatorV03(
      opened.session,
      Object.freeze({}) as CapturedRuntimeTerminationCapabilityV03,
    )).toBeNull();
    const coordinator = await captureRuntimeExecutionCoordinatorV03(opened.session, termination().capability);
    expect(coordinator).not.toBeNull();
    expect(Object.isFrozen(coordinator)).toBe(true);
    expect(JSON.stringify(coordinator)).toBe("{}");
    const dispatch = vi.fn(async () => ({ disposition: "NOT_STARTED" as const }));
    const effectAdapter = adapter(fixture.request.normalized_dispatch_hash, dispatch);
    expect(effectAdapter).not.toBeNull();
    expect(Object.isFrozen(effectAdapter)).toBe(true);
    expect(JSON.stringify(effectAdapter)).toBe("{}");
    expect(captureRuntimeEffectAdapterV03({
      ...metadata, normalized_dispatch_hash: fixture.request.normalized_dispatch_hash, dispatch, extra: true,
    })).toBeNull();
    expect(captureRuntimeEffectAdapterV03(Object.assign(Object.create(null), {
      ...metadata, normalized_dispatch_hash: fixture.request.normalized_dispatch_hash, dispatch,
    }))).toBeNull();
    await closeRuntimeExecutionCoordinatorV03(coordinator!);
  });

  it("permits exactly one live coordinator for a write session under concurrent capture", async () => {
    const fixture = await createSignedRuntimeActionAdmissionV03Fixture();
    const opened = await openRuntimeWriteSessionV03(fixture.store, fixture.expectation);
    if (!opened.ok) throw new Error(opened.error);
    sessions.push(opened.session);
    const capturedTermination = termination();
    const captures = await Promise.all([
      captureRuntimeExecutionCoordinatorV03(opened.session, capturedTermination.capability),
      captureRuntimeExecutionCoordinatorV03(opened.session, capturedTermination.capability),
    ]);
    const live = captures.filter((candidate): candidate is RuntimeExecutionCoordinatorV03 => candidate !== null);
    expect(live).toHaveLength(1);
    expect(captures.filter((candidate) => candidate === null)).toHaveLength(1);
    await closeRuntimeExecutionCoordinatorV03(live[0]!);
  });

  it("releases one owned frozen result only after exact MATCHED reconciliation", async () => {
    const resultAlias = { kind: "command", nested: { status: "original" } };
    const state = await ready(async (invocation) => ({
      disposition: "DISPATCHED",
      observation: exactObservation(invocation),
      result: resultAlias,
    }));
    const coordinated = await coordinateRuntimeActionV03(state.coordinator, state.adapter, state.request);
    expect(coordinated).toMatchObject({ ok: true, disposition: "MATCHED", cleanup_status: "OPEN" });
    if (!coordinated.ok || coordinated.disposition !== "MATCHED") throw new Error("matched custody unavailable");
    const events = new TextDecoder().decode(inspectSyntheticRuntimeRunStoreV03ForTest(state.store)!.ledger_bytes)
      .trim().split("\n").map((row) => JSON.parse(row) as { event_type: string; payload: Record<string, unknown> });
    const started = events.filter((event) => event.event_type === "task.execution-started");
    expect(started).toHaveLength(1);
    expect(started[0]?.payload).toMatchObject({
      action_id: SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS.action_id,
      admission_ref: coordinated.action_admission_event_ref,
      adapter_invocation_id: coordinated.adapter_invocation_id,
    });
    expect(JSON.stringify(coordinated.custody)).toBe("{}");
    resultAlias.nested.status = "mutated";
    const taken = takeRuntimeInvocationResultV01(coordinated.custody, state.coordinator, {
      adapter_invocation_id: coordinated.adapter_invocation_id,
      action_admission_event_ref: coordinated.action_admission_event_ref,
    });
    expect(taken).toEqual({ ok: true, value: { kind: "command", nested: { status: "original" } } });
    expect(taken.ok && Object.isFrozen(taken.value)).toBe(true);
    expect(taken.ok && Object.isFrozen((taken.value as { nested: object }).nested)).toBe(true);
    expect(takeRuntimeInvocationResultV01(coordinated.custody, state.coordinator, {
      adapter_invocation_id: coordinated.adapter_invocation_id,
      action_admission_event_ref: coordinated.action_admission_event_ref,
    })).toEqual({ ok: false, error: "RESULT_CUSTODY_ALREADY_TAKEN" });
    await closeRuntimeExecutionCoordinatorV03(state.coordinator);
  });

  it("destroys custody on a binding mismatch", async () => {
    const state = await ready(async (invocation) => ({
      disposition: "DISPATCHED", observation: exactObservation(invocation), result: { safe: true },
    }));
    const coordinated = await coordinateRuntimeActionV03(state.coordinator, state.adapter, state.request);
    if (!coordinated.ok || coordinated.disposition !== "MATCHED") throw new Error("matched custody unavailable");
    expect(takeRuntimeInvocationResultV01(coordinated.custody, state.coordinator, {
      adapter_invocation_id: "invocation_wrong_v03",
      action_admission_event_ref: coordinated.action_admission_event_ref,
    })).toEqual({ ok: false, error: "RESULT_CUSTODY_BINDING_MISMATCH" });
    expect(takeRuntimeInvocationResultV01(coordinated.custody, state.coordinator, {
      adapter_invocation_id: coordinated.adapter_invocation_id,
      action_admission_event_ref: coordinated.action_admission_event_ref,
    })).toEqual({ ok: false, error: "RESULT_CUSTODY_ALREADY_TAKEN" });
    await closeRuntimeExecutionCoordinatorV03(state.coordinator);
  });

  it("destroys every outstanding custody when its coordinator closes", async () => {
    const state = await ready(async (invocation) => ({
      disposition: "DISPATCHED", observation: exactObservation(invocation), result: { safe: true },
    }));
    const coordinated = await coordinateRuntimeActionV03(state.coordinator, state.adapter, state.request);
    if (!coordinated.ok || coordinated.disposition !== "MATCHED") throw new Error("matched custody unavailable");
    await expect(closeRuntimeExecutionCoordinatorV03(state.coordinator))
      .resolves.toEqual({ ok: true, cleanup_status: "CLOSED" });
    expect(takeRuntimeInvocationResultV01(coordinated.custody, state.coordinator, {
      adapter_invocation_id: coordinated.adapter_invocation_id,
      action_admission_event_ref: coordinated.action_admission_event_ref,
    })).toEqual({ ok: false, error: "RESULT_CUSTODY_ALREADY_TAKEN" });
  });

  it("consumes custody without invoking a nested binding accessor", async () => {
    const state = await ready(async (invocation) => ({
      disposition: "DISPATCHED", observation: exactObservation(invocation), result: { safe: true },
    }));
    const coordinated = await coordinateRuntimeActionV03(state.coordinator, state.adapter, state.request);
    if (!coordinated.ok || coordinated.disposition !== "MATCHED") throw new Error("matched custody unavailable");
    const getter = vi.fn(() => coordinated.action_admission_event_ref.ledger_sequence);
    const hostileRef = Object.defineProperty({
      event_hash: coordinated.action_admission_event_ref.event_hash,
    }, "ledger_sequence", { enumerable: true, get: getter });
    expect(takeRuntimeInvocationResultV01(coordinated.custody, state.coordinator, {
      adapter_invocation_id: coordinated.adapter_invocation_id,
      action_admission_event_ref: hostileRef,
    })).toEqual({ ok: false, error: "RESULT_CUSTODY_BINDING_MISMATCH" });
    expect(getter).not.toHaveBeenCalled();
    expect(takeRuntimeInvocationResultV01(coordinated.custody, state.coordinator, {
      adapter_invocation_id: coordinated.adapter_invocation_id,
      action_admission_event_ref: coordinated.action_admission_event_ref,
    })).toEqual({ ok: false, error: "RESULT_CUSTODY_ALREADY_TAKEN" });
    await closeRuntimeExecutionCoordinatorV03(state.coordinator);
  });

  it("captures a proxy result without invoking its property getters", async () => {
    const get = vi.fn((target: { safe: boolean }, key: keyof typeof target) => Reflect.get(target, key));
    const result = new Proxy({ safe: true }, { get });
    const state = await ready(async (invocation) => ({
      disposition: "DISPATCHED", observation: exactObservation(invocation), result,
    }));
    const coordinated = await coordinateRuntimeActionV03(state.coordinator, state.adapter, state.request);
    if (!coordinated.ok || coordinated.disposition !== "MATCHED") throw new Error("matched custody unavailable");
    expect(get).not.toHaveBeenCalled();
    expect(takeRuntimeInvocationResultV01(coordinated.custody, state.coordinator, {
      adapter_invocation_id: coordinated.adapter_invocation_id,
      action_admission_event_ref: coordinated.action_admission_event_ref,
    })).toEqual({ ok: true, value: { safe: true } });
    expect(get).not.toHaveBeenCalled();
    await closeRuntimeExecutionCoordinatorV03(state.coordinator);
  });

  it("closes confirmed non-entry as pending reconciliation without B5 or retry", async () => {
    const dispatch = vi.fn(async () => ({ disposition: "NOT_STARTED" as const }));
    const state = await ready(dispatch);
    await expect(coordinateRuntimeActionV03(state.coordinator, state.adapter, state.request)).resolves.toEqual({
      ok: false,
      error: "DISPATCH_NOT_STARTED_PENDING_RECONCILIATION",
      cleanup_status: "CLOSED",
    });
    expect(dispatch).toHaveBeenCalledTimes(1);
    await expect(inspectRuntimeWriteSessionV03ForDispatch(state.session))
      .resolves.toEqual({ ok: false, error: "RUNTIME_WRITE_SESSION_CLOSED" });
    const stored = inspectSyntheticRuntimeRunStoreV03ForTest(state.store);
    expect(stored?.ledger_bytes && new TextDecoder().decode(stored.ledger_bytes)).not.toContain("task.action-outcome");
  });

  it("poisons and closes an ambiguous callback without retry", async () => {
    const dispatch = vi.fn(async () => { throw new Error("ambiguous external boundary"); });
    const state = await ready(dispatch);
    await expect(coordinateRuntimeActionV03(state.coordinator, state.adapter, state.request)).resolves.toEqual({
      ok: false,
      error: "DISPATCH_OUTCOME_UNKNOWN_PENDING_RECONCILIATION",
      cleanup_status: "CLOSED",
    });
    expect(dispatch).toHaveBeenCalledTimes(1);
    expect(inspectSyntheticRuntimeRunStoreV03ForTest(state.store)?.poisoned).toBe(true);
  });

  it("closes pending reconciliation when the durable execution-start append is not committed", async () => {
    const fixture = await createSignedRuntimeActionAdmissionV03Fixture();
    const opened = await openRuntimeWriteSessionV03(fixture.store, fixture.expectation);
    if (!opened.ok) throw new Error(opened.error);
    sessions.push(opened.session);
    const coordinator = await captureRuntimeExecutionCoordinatorV03(opened.session, termination().capability);
    if (coordinator === null) throw new Error("coordinator capture failed");
    const effectAdapter = adapter(fixture.request.normalized_dispatch_hash, async (invocation) => ({
      disposition: "DISPATCHED", observation: exactObservation(invocation), result: { neverReleased: true },
    }));
    if (effectAdapter === null) throw new Error("adapter capture failed");
    await expect(coordinateRuntimeActionV03(coordinator, effectAdapter, fixture.request)).resolves.toEqual({
      ok: false,
      error: "EXECUTION_START_NOT_COMMITTED_PENDING_RECONCILIATION",
      cleanup_status: "CLOSED",
    });
    const events = new TextDecoder().decode(inspectSyntheticRuntimeRunStoreV03ForTest(fixture.store)!.ledger_bytes)
      .trim().split("\n").map((row) => JSON.parse(row) as { event_type: string });
    expect(events.filter((event) => event.event_type === "task.action-admitted")).toHaveLength(1);
    expect(events.filter((event) => event.event_type === "task.execution-started")).toHaveLength(0);
    expect(events.some((event) => event.event_type === "integrity.observation-rejected")).toBe(false);
    expect(inspectSyntheticRuntimeRunStoreV03ForTest(fixture.store)?.poisoned).toBe(true);
  });

  it("quarantines a capture gap, releases no custody, and closes", async () => {
    const rawResult = "never-persist-coordinator-result-9ec747";
    const state = await ready(async () => ({ disposition: "DISPATCHED", observation: null, result: { rawResult } }));
    const result = await coordinateRuntimeActionV03(state.coordinator, state.adapter, state.request);
    expect(result).toMatchObject({
      ok: true,
      disposition: "QUARANTINED",
      reason_code: "capture-gap",
      termination_result: { ok: true, observed_outcome: "terminated" },
      cleanup_status: "CLOSED",
    });
    expect(result).not.toHaveProperty("custody");
    expect(state.terminate).toHaveBeenCalledTimes(1);
    const ledger = new TextDecoder().decode(inspectSyntheticRuntimeRunStoreV03ForTest(state.store)!.ledger_bytes);
    expect(ledger).toContain("integrity.observation-rejected");
    expect(ledger).toContain("run.quarantined");
    expect(ledger).toContain("process.termination-attempted");
    expect(ledger).not.toContain(rawResult);
  });

  it("serializes concurrent duplicate invocation and enters the adapter once", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const dispatch = vi.fn(async (invocation) => {
      await gate;
      return { disposition: "DISPATCHED", observation: exactObservation(invocation), result: { safe: true } };
    });
    const state = await ready(dispatch);
    const first = coordinateRuntimeActionV03(state.coordinator, state.adapter, state.request);
    const second = coordinateRuntimeActionV03(state.coordinator, state.adapter, state.request);
    release();
    const [left, right] = await Promise.all([first, second]);
    expect(left).toMatchObject({ ok: true, disposition: "MATCHED" });
    expect(right).toEqual({ ok: false, error: "RUNTIME_EFFECT_ADAPTER_ALREADY_USED", cleanup_status: "OPEN" });
    expect(dispatch).toHaveBeenCalledTimes(1);
    const events = new TextDecoder().decode(inspectSyntheticRuntimeRunStoreV03ForTest(state.store)!.ledger_bytes)
      .trim().split("\n").map((row) => JSON.parse(row) as { event_type: string });
    expect(events.filter((event) => event.event_type === "lease.issued")).toHaveLength(1);
    expect(events.filter((event) => event.event_type === "run.clock-observed")).toHaveLength(1);
    expect(events.filter((event) => event.event_type === "task.action-admitted")).toHaveLength(1);
    expect(events.filter((event) => event.event_type === "task.execution-started")).toHaveLength(1);
    await closeRuntimeExecutionCoordinatorV03(state.coordinator);
  });

  it("keeps the primary error when close also fails", async () => {
    let state: Awaited<ReturnType<typeof ready>>;
    const dispatch = vi.fn(async () => {
      await closeRuntimeWriteSessionV03(state.session);
      return { disposition: "NOT_STARTED" as const };
    });
    state = await ready(dispatch);
    await expect(coordinateRuntimeActionV03(state.coordinator, state.adapter, state.request)).resolves.toEqual({
      ok: false,
      error: "DISPATCH_NOT_STARTED_PENDING_RECONCILIATION",
      cleanup_status: "CLOSE_FAILED",
    });
    expect(dispatch).toHaveBeenCalledTimes(1);
  });

  it("never invokes the adapter when admission fails", async () => {
    const dispatch = vi.fn(async () => ({ disposition: "NOT_STARTED" as const }));
    const state = await ready(dispatch);
    await expect(coordinateRuntimeActionV03(state.coordinator, state.adapter, {
      ...state.request,
      normalized_dispatch_hash: H("9"),
    })).resolves.toMatchObject({ ok: false, error: "CANONICAL_AUTHORITY_RECORDS_INVALID", cleanup_status: "CLOSED" });
    expect(dispatch).not.toHaveBeenCalled();
  });

  it("closes idempotently and releases its session lock once", async () => {
    const state = await ready(async () => ({ disposition: "NOT_STARTED" as const }));
    await expect(closeRuntimeExecutionCoordinatorV03(state.coordinator))
      .resolves.toEqual({ ok: true, cleanup_status: "CLOSED" });
    await expect(closeRuntimeExecutionCoordinatorV03(state.coordinator))
      .resolves.toEqual({ ok: true, cleanup_status: "CLOSED" });
    const operations = inspectSyntheticRuntimeRunStoreV03ForTest(state.store)!.operations;
    expect(operations.filter((operation) => operation === "lock-released")).toHaveLength(1);
  });

  it.each([
    ["accessor", Object.defineProperty({}, "secret", { enumerable: true, get: vi.fn(() => "leak") })],
    ["prototype", Object.setPrototypeOf({ safe: true }, Object.create(Object.prototype))],
    ["symbol", { [Symbol("hidden")]: true }],
    ["depth", Array.from({ length: 35 }).reduce<Record<string, unknown>>((value) => ({ nested: value }), {})],
    ["nodes", Array.from({ length: 10_001 }, (_, index) => index)],
    ["bytes", "x".repeat(1_048_577)],
  ])("fails closed on an invalid %s result without custody or persistence", async (_label, invalidResult) => {
    const marker = "never-persist-invalid-result-8b934f";
    const state = await ready(async (invocation) => ({
      disposition: "DISPATCHED",
      observation: exactObservation(invocation),
      result: { marker, invalidResult },
    }));
    const outcome = await coordinateRuntimeActionV03(state.coordinator, state.adapter, state.request);
    expect(outcome).toEqual({
      ok: false,
      error: "DISPATCH_OUTCOME_UNKNOWN_PENDING_RECONCILIATION",
      cleanup_status: "CLOSED",
    });
    expect(outcome).not.toHaveProperty("custody");
    const ledger = new TextDecoder().decode(inspectSyntheticRuntimeRunStoreV03ForTest(state.store)!.ledger_bytes);
    expect(ledger).not.toContain(marker);
  });

  it("destroys outstanding custody on cross-coordinator binding", async () => {
    const first = await ready(async (invocation) => ({
      disposition: "DISPATCHED", observation: exactObservation(invocation), result: { safe: true },
    }));
    const matched = await coordinateRuntimeActionV03(first.coordinator, first.adapter, first.request);
    if (!matched.ok || matched.disposition !== "MATCHED") throw new Error("matched custody unavailable");
    await closeRuntimeWriteSessionV03(first.session);
    const second = await ready(async () => ({ disposition: "NOT_STARTED" as const }));
    expect(takeRuntimeInvocationResultV01(matched.custody, second.coordinator, {
      adapter_invocation_id: matched.adapter_invocation_id,
      action_admission_event_ref: matched.action_admission_event_ref,
    })).toEqual({ ok: false, error: "RESULT_CUSTODY_BINDING_MISMATCH" });
    expect(takeRuntimeInvocationResultV01(matched.custody, first.coordinator, {
      adapter_invocation_id: matched.adapter_invocation_id,
      action_admission_event_ref: matched.action_admission_event_ref,
    })).toEqual({ ok: false, error: "RESULT_CUSTODY_ALREADY_TAKEN" });
    await closeRuntimeExecutionCoordinatorV03(first.coordinator);
    await closeRuntimeExecutionCoordinatorV03(second.coordinator);
  });

  it.each([
    ["unmatched-observation", (invocation: Parameters<typeof exactObservation>[0]) => ({
      ...exactObservation(invocation), adapter_invocation_id: "invocation_unknown_v03", claimed_action_id: "action_unknown_v03",
    })],
    ["authority-breach", (invocation: Parameters<typeof exactObservation>[0]) => ({
      ...exactObservation(invocation), normalized_dispatch_hash: H("9"),
    })],
  ] as const)("closes %s quarantine without releasing custody", async (reason, observation) => {
    const state = await ready(async (invocation) => ({
      disposition: "DISPATCHED", observation: observation(invocation), result: { private: true },
    }));
    const outcome = await coordinateRuntimeActionV03(state.coordinator, state.adapter, state.request);
    expect(outcome).toMatchObject({
      ok: true,
      disposition: "QUARANTINED",
      reason_code: reason,
      termination_result: { ok: true, observed_outcome: "terminated" },
      cleanup_status: "CLOSED",
    });
    expect(outcome).not.toHaveProperty("custody");
    expect(state.terminate).toHaveBeenCalledTimes(1);
  });

  it("preserves quarantine when termination observation is unknown", async () => {
    const terminate = vi.fn(async () => { throw new Error("termination transport dropped"); });
    const state = await ready(async () => ({
      disposition: "DISPATCHED", observation: null, result: { private: true },
    }), { terminate });
    await expect(coordinateRuntimeActionV03(state.coordinator, state.adapter, state.request)).resolves.toMatchObject({
      ok: true,
      disposition: "QUARANTINED",
      reason_code: "capture-gap",
      termination_result: { ok: true, observed_outcome: "unknown" },
      cleanup_status: "CLOSED",
    });
    expect(terminate).toHaveBeenCalledTimes(1);
  });

  it("preserves quarantine when termination evidence cannot be committed", async () => {
    const state = await ready(
      async () => ({ disposition: "DISPATCHED", observation: null, result: { private: true } }),
      {
        additional_event_envelopes: [
          { event_id: "event_started_coordinator_v03", recorded_at: "2026-08-24T10:00:31Z" },
          { event_id: "event_rejection_coordinator_v03", recorded_at: "2026-08-24T10:00:32Z" },
          { event_id: "event_quarantine_coordinator_v03", recorded_at: "2026-08-24T10:00:33Z" },
        ],
      },
    );
    await expect(coordinateRuntimeActionV03(state.coordinator, state.adapter, state.request)).resolves.toMatchObject({
      ok: true,
      disposition: "QUARANTINED",
      reason_code: "capture-gap",
      termination_result: { ok: false, error: "TERMINATION_NOT_COMMITTED" },
      cleanup_status: "CLOSED",
    });
    expect(state.terminate).toHaveBeenCalledTimes(1);
  });

  it("rejects forged capabilities without inspecting them", async () => {
    await expect(coordinateRuntimeActionV03(
      Object.freeze({}) as RuntimeExecutionCoordinatorV03,
      Object.freeze({}) as CapturedRuntimeEffectAdapterV03,
      {},
    )).resolves.toEqual({ ok: false, error: "COORDINATOR_INVALID", cleanup_status: "CLOSE_FAILED" });
  });
});
