import { afterEach, describe, expect, it, vi } from "vitest";

import { canonicalize, hashCanonical, hashRawBytes } from "../../src/hash.js";
import {
  captureEffectDispatchBrokerV01,
  dispatchAdmittedActionV01,
  type EffectDispatchInvocationV01,
} from "../../src/run/runtime-effect-dispatch-broker-v01.js";
import { reconcileRuntimeObservationIntegrityV03 } from "../../src/run/runtime-observation-integrity-v03.js";
import { admitRuntimeActionV03 } from "../../src/run/runtime-action-admission-v03.js";
import {
  closeRuntimeWriteSessionV03,
  inspectRuntimeWriteSessionV03ForDispatch,
  openRuntimeWriteSessionV03,
  type RuntimeWriteSessionV03,
  verifyRuntimeWriteSessionTailReadbackV03,
} from "../../src/run/runtime-write-session-v03.js";
import type { CapturedEffectDispatchBrokerV01 } from "../../src/run/runtime-effect-dispatch-broker-v01.js";
import {
  createSignedRuntimeActionAdmissionV03Fixture,
  SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS,
} from "../helpers/runtime-action-admission-v03-fixture.js";

const H = (character: string) => `sha256:${character.repeat(64)}`;
const activeSessions: RuntimeWriteSessionV03[] = [];

afterEach(async () => {
  for (const session of activeSessions.splice(0)) await closeRuntimeWriteSessionV03(session);
});

async function dispatched(observation: unknown | ((invocation: EffectDispatchInvocationV01) => unknown)) {
  const fixture = await createSignedRuntimeActionAdmissionV03Fixture({
    additional_event_envelopes: [
      { event_id: "event_observation_rejected_v03", recorded_at: "2026-08-24T10:00:31Z" },
      { event_id: "event_observation_quarantine_v03", recorded_at: "2026-08-24T10:00:32Z" },
    ],
  });
  const opened = await openRuntimeWriteSessionV03(fixture.store, fixture.expectation);
  if (!opened.ok) throw new Error(opened.error);
  activeSessions.push(opened.session);
  const admission = await admitRuntimeActionV03(opened.session, fixture.request);
  if (!admission.ok) throw new Error(admission.error);
  const adapterRef = "adapter_observation_v01";
  const adapterVersionHash = H("2");
  const adapterProfileHash = H("3");
  const adapterInvocationId = "invocation_observation_v01";
  const dispatch = vi.fn(async (invocation: EffectDispatchInvocationV01) => ({
    disposition: "DISPATCHED" as const,
    observation: typeof observation === "function" ? observation(invocation) : observation,
  }));
  const broker = captureEffectDispatchBrokerV01({
    normalized_dispatch_hash: fixture.request.normalized_dispatch_hash,
    adapter_ref: adapterRef,
    adapter_version_hash: adapterVersionHash,
    adapter_profile_hash: adapterProfileHash,
    adapter_invocation_id: adapterInvocationId,
    dispatch,
  });
  if (broker === null) throw new Error("broker capture failed");
  const dispatchedResult = await dispatchAdmittedActionV01(opened.session, broker, admission.permit);
  if (!dispatchedResult.ok) throw new Error(dispatchedResult.error);
  return {
    ...fixture,
    session: opened.session,
    admission,
    broker,
    adapterRef,
    adapterVersionHash,
    adapterProfileHash,
    adapterInvocationId,
  };
}

describe("S40-B5 runtime observation integrity", { timeout: 20_000 }, () => {
  it("rejects hostile request shapes without invoking getters or inspecting capabilities", async () => {
    const getter = vi.fn(() => "invocation_observation_v01");
    const accessor = Object.defineProperty({}, "adapter_invocation_id", { enumerable: true, get: getter });
    const forgedSession = Object.freeze({}) as RuntimeWriteSessionV03;
    const forgedBroker = Object.freeze({}) as CapturedEffectDispatchBrokerV01;
    for (const request of [
      accessor,
      Object.assign(Object.create(null), { adapter_invocation_id: "invocation_observation_v01" }),
      { adapter_invocation_id: "invocation_observation_v01", alias: true },
      { adapter_invocation_id: "invocation_observation_v01", [Symbol("hidden")]: true },
    ]) {
      await expect(reconcileRuntimeObservationIntegrityV03(forgedSession, forgedBroker, request))
        .resolves.toEqual({ ok: false, error: "OBSERVATION_REQUEST_INVALID" });
    }
    expect(getter).not.toHaveBeenCalled();
  });

  it("accepts an exact captured observation without writing a ledger event", async () => {
    const adapterIdentityHash = hashCanonical({
      purpose: "effect-dispatch-adapter-identity-v01",
      adapter_ref: "adapter_observation_v01",
      adapter_version_hash: H("2"),
    });
    let observation: Record<string, unknown> | null = null;
    const exactState = await dispatched((invocation) => {
      observation = {
        observation_version: "0.1",
        adapter_invocation_id: invocation.adapter_invocation_id,
        claimed_action_id: SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS.action_id,
        action_admission_event_ref: invocation.action_admission_event_ref,
        normalized_dispatch_hash: invocation.normalized_dispatch_hash,
        effect_refs: ["effect-diagnose-root-cause"],
        adapter_identity_hash: adapterIdentityHash,
        adapter_profile_hash: H("3"),
      };
      return observation;
    });
    const before = await inspectRuntimeWriteSessionV03ForDispatch(exactState.session);
    if (!before.ok) throw new Error(before.error);
    const result = await reconcileRuntimeObservationIntegrityV03(
      exactState.session,
      exactState.broker,
      { adapter_invocation_id: exactState.adapterInvocationId },
    );
    expect(result).toEqual({
      ok: true,
      disposition: "MATCHED",
      observation_hash: hashRawBytes(new TextEncoder().encode(canonicalize(observation))),
    });
    const after = await inspectRuntimeWriteSessionV03ForDispatch(exactState.session);
    expect(after.ok && after.snapshot.ledger_sequence).toBe(before.snapshot.ledger_sequence);
    await closeRuntimeWriteSessionV03(exactState.session);
  });

  it("atomically quarantines a missing captured observation as capture-gap", async () => {
    const state = await dispatched(null);
    const result = await reconcileRuntimeObservationIntegrityV03(
      state.session,
      state.broker,
      { adapter_invocation_id: state.adapterInvocationId },
    );
    expect(result).toMatchObject({
      ok: true,
      disposition: "QUARANTINED",
      reason_code: "capture-gap",
    });
    if (!result.ok || result.disposition !== "QUARANTINED") throw new Error("quarantine result unavailable");
    const readback = await verifyRuntimeWriteSessionTailReadbackV03(state.session, {
      events: [
        { event_type: "integrity.observation-rejected", event_ref: result.rejection_event_ref },
        { event_type: "run.quarantined", event_ref: result.quarantine_event_ref },
      ],
      manifest_hash: result.committed_manifest_hash,
    });
    expect(readback.ok).toBe(true);
    if (!readback.ok) throw new Error(readback.error);
    const [rejection, quarantine] = readback.readback.events.slice(-2);
    expect(rejection?.payload).toEqual({
      reason_code: "capture-gap",
      observation_hash: result.observation_hash,
      adapter_invocation_id: state.adapterInvocationId,
      claimed_action_id: null,
    });
    expect(quarantine?.payload).toEqual({
      reason_code: "capture-gap",
      evidence_refs: [result.rejection_event_ref],
    });
    await closeRuntimeWriteSessionV03(state.session);
  });

  it("quarantines a non-canonical effect ref as capture-gap", async () => {
    const adapterIdentityHash = hashCanonical({
      purpose: "effect-dispatch-adapter-identity-v01",
      adapter_ref: "adapter_observation_v01",
      adapter_version_hash: H("2"),
    });
    const state = await dispatched((invocation) => ({
      observation_version: "0.1",
      adapter_invocation_id: invocation.adapter_invocation_id,
      claimed_action_id: SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS.action_id,
      action_admission_event_ref: invocation.action_admission_event_ref,
      normalized_dispatch_hash: invocation.normalized_dispatch_hash,
      effect_refs: ["Effect_Invalid"],
      adapter_identity_hash: adapterIdentityHash,
      adapter_profile_hash: H("3"),
    }));
    await expect(reconcileRuntimeObservationIntegrityV03(
      state.session,
      state.broker,
      { adapter_invocation_id: state.adapterInvocationId },
    )).resolves.toMatchObject({
      ok: true,
      disposition: "QUARANTINED",
      reason_code: "capture-gap",
    });
    await closeRuntimeWriteSessionV03(state.session);
  });

  it("classifies a valid unknown invocation and action as unmatched-observation", async () => {
    const adapterIdentityHash = hashCanonical({
      purpose: "effect-dispatch-adapter-identity-v01",
      adapter_ref: "adapter_observation_v01",
      adapter_version_hash: H("2"),
    });
    const state = await dispatched((invocation) => ({
      observation_version: "0.1",
      adapter_invocation_id: "invocation_unknown_v01",
      claimed_action_id: "action_unknown_v01",
      action_admission_event_ref: invocation.action_admission_event_ref,
      normalized_dispatch_hash: invocation.normalized_dispatch_hash,
      effect_refs: ["effect-diagnose-root-cause"],
      adapter_identity_hash: adapterIdentityHash,
      adapter_profile_hash: H("3"),
    }));
    const result = await reconcileRuntimeObservationIntegrityV03(
      state.session, state.broker, { adapter_invocation_id: state.adapterInvocationId },
    );
    expect(result).toMatchObject({
      ok: true, disposition: "QUARANTINED", reason_code: "unmatched-observation",
    });
    if (!result.ok || result.disposition !== "QUARANTINED") throw new Error("quarantine result unavailable");
    const readback = await verifyRuntimeWriteSessionTailReadbackV03(state.session, {
      events: [
        { event_type: "integrity.observation-rejected", event_ref: result.rejection_event_ref },
        { event_type: "run.quarantined", event_ref: result.quarantine_event_ref },
      ],
      manifest_hash: result.committed_manifest_hash,
    });
    expect(readback.ok && readback.readback.events.at(-2)?.payload).toMatchObject({
      reason_code: "unmatched-observation",
      adapter_invocation_id: "invocation_unknown_v01",
      claimed_action_id: "action_unknown_v01",
    });
    await closeRuntimeWriteSessionV03(state.session);
  });

  it("classifies a known action with a dispatch binding mismatch as authority-breach", async () => {
    const adapterIdentityHash = hashCanonical({
      purpose: "effect-dispatch-adapter-identity-v01",
      adapter_ref: "adapter_observation_v01",
      adapter_version_hash: H("2"),
    });
    const state = await dispatched((invocation) => ({
      observation_version: "0.1",
      adapter_invocation_id: invocation.adapter_invocation_id,
      claimed_action_id: SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS.action_id,
      action_admission_event_ref: invocation.action_admission_event_ref,
      normalized_dispatch_hash: H("9"),
      effect_refs: ["effect-diagnose-root-cause"],
      adapter_identity_hash: adapterIdentityHash,
      adapter_profile_hash: H("3"),
    }));
    const result = await reconcileRuntimeObservationIntegrityV03(
      state.session,
      state.broker,
      { adapter_invocation_id: state.adapterInvocationId },
    );
    expect(result).toMatchObject({ ok: true, disposition: "QUARANTINED", reason_code: "authority-breach" });
    await closeRuntimeWriteSessionV03(state.session);
  });

  it("never persists or echoes malformed raw observation content", async () => {
    const rawSecret = "never-persist-this-observation-value";
    const state = await dispatched({ malformed_private_field: rawSecret });
    const result = await reconcileRuntimeObservationIntegrityV03(
      state.session,
      state.broker,
      { adapter_invocation_id: state.adapterInvocationId },
    );
    expect(result).toMatchObject({ ok: true, disposition: "QUARANTINED", reason_code: "capture-gap" });
    if (!result.ok || result.disposition !== "QUARANTINED") throw new Error("quarantine result unavailable");
    const readback = await verifyRuntimeWriteSessionTailReadbackV03(state.session, {
      events: [
        { event_type: "integrity.observation-rejected", event_ref: result.rejection_event_ref },
        { event_type: "run.quarantined", event_ref: result.quarantine_event_ref },
      ],
      manifest_hash: result.committed_manifest_hash,
    });
    expect(readback.ok).toBe(true);
    expect(JSON.stringify(readback)).not.toContain(rawSecret);
    expect(JSON.stringify(result)).not.toContain(rawSecret);
    await closeRuntimeWriteSessionV03(state.session);
  });

  it("consumes a captured observation once and rejects replay", async () => {
    const adapterIdentityHash = hashCanonical({
      purpose: "effect-dispatch-adapter-identity-v01",
      adapter_ref: "adapter_observation_v01",
      adapter_version_hash: H("2"),
    });
    const state = await dispatched((invocation) => ({
      observation_version: "0.1",
      adapter_invocation_id: invocation.adapter_invocation_id,
      claimed_action_id: SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS.action_id,
      action_admission_event_ref: invocation.action_admission_event_ref,
      normalized_dispatch_hash: invocation.normalized_dispatch_hash,
      effect_refs: ["effect-diagnose-root-cause"],
      adapter_identity_hash: adapterIdentityHash,
      adapter_profile_hash: H("3"),
    }));
    const request = { adapter_invocation_id: state.adapterInvocationId };
    await expect(reconcileRuntimeObservationIntegrityV03(state.session, state.broker, request))
      .resolves.toMatchObject({ ok: true, disposition: "MATCHED" });
    await expect(reconcileRuntimeObservationIntegrityV03(state.session, state.broker, request))
      .resolves.toEqual({ ok: false, error: "EFFECT_OBSERVATION_ALREADY_TAKEN" });
    await closeRuntimeWriteSessionV03(state.session);
  });
});
