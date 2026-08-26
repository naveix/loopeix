import { describe, expect, it, vi } from "vitest";

import {
  captureEffectDispatchBrokerV01,
  dispatchAdmittedActionV01,
  takeCapturedEffectObservationV01,
  type CapturedEffectDispatchBrokerV01,
} from "../../src/run/runtime-effect-dispatch-broker-v01.js";
import {
  admitRuntimeActionV03,
  consumeDispatchPermitV01,
  type DispatchPermitV01,
} from "../../src/run/runtime-action-admission-v03.js";
import {
  closeRuntimeWriteSessionV03,
  inspectRuntimeWriteSessionV03ForDispatch,
  openRuntimeWriteSessionV03,
  type RuntimeWriteSessionV03,
} from "../../src/run/runtime-write-session-v03.js";
import { createSignedRuntimeActionAdmissionV03Fixture } from "../helpers/runtime-action-admission-v03-fixture.js";

const H = (character: string) => `sha256:${character.repeat(64)}`;

function brokerInput(dispatch = vi.fn(async () => ({ disposition: "DISPATCHED" as const, observation: null }))) {
  return {
    normalized_dispatch_hash: H("1"),
    adapter_ref: "adapter_effect_v01",
    adapter_version_hash: H("2"),
    adapter_profile_hash: H("3"),
    adapter_invocation_id: "invocation_effect_v01",
    dispatch,
  };
}

async function admitted(dispatch: ReturnType<typeof vi.fn>, normalizedDispatchHash?: string) {
  const fixture = await createSignedRuntimeActionAdmissionV03Fixture();
  const opened = await openRuntimeWriteSessionV03(fixture.store, fixture.expectation);
  if (!opened.ok) throw new Error(opened.error);
  const admission = await admitRuntimeActionV03(opened.session, fixture.request);
  if (!admission.ok) throw new Error(admission.error);
  const input = brokerInput(dispatch);
  input.normalized_dispatch_hash = normalizedDispatchHash ?? fixture.request.normalized_dispatch_hash;
  const broker = captureEffectDispatchBrokerV01(input);
  if (broker === null) throw new Error("broker capture failed");
  return { ...fixture, session: opened.session, permit: admission.permit, admission, broker };
}

describe("S40-B4 common effect dispatch broker", () => {
  it("captures an immutable opaque broker and rejects aliases/accessors", () => {
    const input = brokerInput();
    const broker = captureEffectDispatchBrokerV01(input);
    expect(broker).not.toBeNull();
    expect(Object.isFrozen(broker)).toBe(true);
    expect(Object.keys(broker ?? {})).toEqual([]);
    expect(JSON.stringify(broker)).toBe("{}");
    expect(captureEffectDispatchBrokerV01({ ...input, alias: true })).toBeNull();
    expect(captureEffectDispatchBrokerV01({ ...input, [Symbol("hidden")]: true })).toBeNull();
    expect(captureEffectDispatchBrokerV01(Object.defineProperty({ ...input }, "adapter_profile_hash", {
      enumerable: false, value: H("3"),
    }))).toBeNull();
    expect(captureEffectDispatchBrokerV01(Object.defineProperty({ ...input }, "adapter_ref", {
      enumerable: true, get: () => "adapter_effect_v01",
    }))).toBeNull();
    expect(captureEffectDispatchBrokerV01(Object.assign(Object.create(null), input))).toBeNull();
    expect(captureEffectDispatchBrokerV01(Object.assign(Object.create({ inherited: true }), input))).toBeNull();
    class BrokerInputClass {}
    expect(captureEffectDispatchBrokerV01(Object.assign(new BrokerInputClass(), input))).toBeNull();
    expect(captureEffectDispatchBrokerV01(new Proxy(input, {
      ownKeys: () => { throw new Error("hostile proxy"); },
    }))).toBeNull();
    let getCount = 0;
    const trapped = new Proxy(input, {
      get: () => { getCount += 1; throw new Error("get trap invoked"); },
    });
    expect(captureEffectDispatchBrokerV01(trapped)).not.toBeNull();
    expect(getCount).toBe(0);
  });

  it("gives forged-session failure precedence and never invokes the adapter", async () => {
    const dispatch = vi.fn(async () => ({ disposition: "DISPATCHED" as const, observation: null }));
    const broker = captureEffectDispatchBrokerV01(brokerInput(dispatch));
    if (broker === null) throw new Error("broker capture failed");
    await expect(dispatchAdmittedActionV01(
      Object.freeze({}) as RuntimeWriteSessionV03,
      Object.freeze({}) as CapturedEffectDispatchBrokerV01,
      Object.freeze({}) as DispatchPermitV01,
    )).resolves.toEqual({ ok: false, error: "RUNTIME_WRITE_SESSION_INVALID" });
    expect(dispatch).not.toHaveBeenCalled();
  });

  it("consumes before adapter entry, dispatches once, and poisons replay", async () => {
    let state: Awaited<ReturnType<typeof admitted>>;
    const dispatch = vi.fn(async () => {
      expect(consumeDispatchPermitV01(state.permit, state.session, state.broker,
        state.request.normalized_dispatch_hash)).toEqual({ ok: false, error: "DISPATCH_PERMIT_ALREADY_USED" });
      return { disposition: "DISPATCHED" as const, observation: { accepted: true } };
    });
    state = await admitted(dispatch);
    await expect(dispatchAdmittedActionV01(state.session, state.broker, state.permit)).resolves.toEqual({
      ok: true, disposition: "DISPATCHED", adapter_invocation_id: "invocation_effect_v01",
    });
    expect(dispatch).toHaveBeenCalledTimes(1);
    expect(dispatch.mock.calls[0]![0]).toMatchObject({
      adapter_invocation_id: "invocation_effect_v01",
      normalized_dispatch_hash: state.request.normalized_dispatch_hash,
      adapter_ref: "adapter_effect_v01",
      adapter_version_hash: H("2"),
      adapter_profile_hash: H("3"),
    });
    expect(takeCapturedEffectObservationV01(Object.freeze({}) as CapturedEffectDispatchBrokerV01,
      state.session, "invocation_effect_v01")).toEqual({ ok: false, error: "EFFECT_OBSERVATION_INVALID" });
    expect(takeCapturedEffectObservationV01(state.broker, state.session, "wrong_invocation"))
      .toEqual({ ok: false, error: "EFFECT_OBSERVATION_BINDING_MISMATCH" });
    const captured = takeCapturedEffectObservationV01(state.broker, state.session, "invocation_effect_v01");
    expect(captured).toMatchObject({
      ok: true,
      binding: {
        normalized_dispatch_hash: state.request.normalized_dispatch_hash,
        adapter_profile_hash: H("3"),
        action_admission_event_ref: state.admission.action_admission_event_ref,
      },
      observation: { accepted: true },
    });
    expect(Object.isFrozen(captured)).toBe(true);
    expect(captured.ok && Object.isFrozen(captured.binding)).toBe(true);
    expect(captured.ok && Object.isFrozen(captured.observation)).toBe(true);
    expect(takeCapturedEffectObservationV01(state.broker, state.session, "invocation_effect_v01"))
      .toEqual({ ok: false, error: "EFFECT_OBSERVATION_ALREADY_TAKEN" });
    await expect(dispatchAdmittedActionV01(state.session, state.broker, state.permit))
      .resolves.toEqual({ ok: false, error: "DISPATCH_PERMIT_ALREADY_USED" });
    await expect(inspectRuntimeWriteSessionV03ForDispatch(state.session))
      .resolves.toEqual({ ok: false, error: "RUNTIME_WRITE_SESSION_POISONED" });
    await closeRuntimeWriteSessionV03(state.session);
  });

  it("captures an own __proto__ observation key without changing the captured prototype", async () => {
    const observation = Object.defineProperty({ accepted: true }, "__proto__", {
      value: { polluted: true }, enumerable: true,
    });
    const state = await admitted(vi.fn(async () => ({ disposition: "DISPATCHED" as const, observation })));
    await expect(dispatchAdmittedActionV01(state.session, state.broker, state.permit)).resolves.toEqual({
      ok: true, disposition: "DISPATCHED", adapter_invocation_id: "invocation_effect_v01",
    });
    const captured = takeCapturedEffectObservationV01(state.broker, state.session, "invocation_effect_v01");
    expect(captured.ok).toBe(true);
    if (!captured.ok || typeof captured.observation !== "object" || captured.observation === null) {
      throw new Error("observation capture failed");
    }
    expect(Object.getPrototypeOf(captured.observation)).toBe(Object.prototype);
    expect(Object.prototype.hasOwnProperty.call(captured.observation, "__proto__")).toBe(true);
    expect(Object.getOwnPropertyDescriptor(captured.observation, "__proto__")?.value).toEqual({ polluted: true });
    await closeRuntimeWriteSessionV03(state.session);
  });

  it("captures array observations without invoking an inherited iterator", async () => {
    let iteratorReads = 0;
    const observation = new Proxy([{ accepted: true }], {
      get: (target, property, receiver) => {
        if (property === Symbol.iterator) {
          iteratorReads += 1;
          throw new Error("inherited iterator invoked");
        }
        return Reflect.get(target, property, receiver);
      },
    });
    const state = await admitted(vi.fn(async () => ({ disposition: "DISPATCHED" as const, observation })));
    try {
      await expect(dispatchAdmittedActionV01(state.session, state.broker, state.permit)).resolves.toEqual({
        ok: true, disposition: "DISPATCHED", adapter_invocation_id: "invocation_effect_v01",
      });
      const captured = takeCapturedEffectObservationV01(state.broker, state.session, "invocation_effect_v01");
      expect(captured).toMatchObject({ ok: true, observation: [{ accepted: true }] });
      expect(iteratorReads).toBe(0);
    } finally {
      await closeRuntimeWriteSessionV03(state.session);
    }
  });

  it("returns proven not-started without poisoning but still consumes the permit", async () => {
    const dispatch = vi.fn(async () => ({ disposition: "NOT_STARTED" as const }));
    const state = await admitted(dispatch);
    await expect(dispatchAdmittedActionV01(state.session, state.broker, state.permit))
      .resolves.toEqual({ ok: false, error: "DISPATCH_NOT_STARTED" });
    expect((await inspectRuntimeWriteSessionV03ForDispatch(state.session)).ok).toBe(true);
    expect(consumeDispatchPermitV01(state.permit, state.session, state.broker, state.request.normalized_dispatch_hash))
      .toEqual({ ok: false, error: "DISPATCH_PERMIT_ALREADY_USED" });
    expect(takeCapturedEffectObservationV01(state.broker, state.session, "invocation_effect_v01"))
      .toEqual({ ok: false, error: "EFFECT_OBSERVATION_BINDING_MISMATCH" });
    await closeRuntimeWriteSessionV03(state.session);
  });

  it("deep-captures observation ownership before caller mutation", async () => {
    const observation = { nested: { status: "original" }, rows: [1, true, null] };
    const dispatch = vi.fn(async () => ({ disposition: "DISPATCHED" as const, observation }));
    const state = await admitted(dispatch);
    await expect(dispatchAdmittedActionV01(state.session, state.broker, state.permit))
      .resolves.toMatchObject({ ok: true, disposition: "DISPATCHED" });
    observation.nested.status = "mutated";
    observation.rows[0] = 999;
    expect(takeCapturedEffectObservationV01(state.broker, Object.freeze({}) as RuntimeWriteSessionV03,
      "invocation_effect_v01")).toEqual({ ok: false, error: "EFFECT_OBSERVATION_BINDING_MISMATCH" });
    expect(takeCapturedEffectObservationV01(state.broker, state.session, "invocation_effect_v01"))
      .toMatchObject({ observation: { nested: { status: "original" }, rows: [1, true, null] } });
    await closeRuntimeWriteSessionV03(state.session);
  });

  it("captures null as an explicit observation gap", async () => {
    const state = await admitted(vi.fn(async () => ({ disposition: "DISPATCHED" as const, observation: null })));
    await expect(dispatchAdmittedActionV01(state.session, state.broker, state.permit))
      .resolves.toMatchObject({ ok: true, disposition: "DISPATCHED" });
    expect(takeCapturedEffectObservationV01(state.broker, state.session, "invocation_effect_v01"))
      .toMatchObject({ ok: true, observation: null });
    await closeRuntimeWriteSessionV03(state.session);
  });

  it.each([
    ["accessor", Object.defineProperty({}, "secret", { enumerable: true, get: () => "value" })],
    ["symbol", { [Symbol("secret")]: true }],
    ["array prototype drift", Object.setPrototypeOf([], Object.create(Array.prototype))],
    ["excess depth", Array.from({ length: 18 }).reduce<Record<string, unknown>>((value) => ({ nested: value }), {})],
    ["excess nodes", Array.from({ length: 2_049 }, (_, index) => index)],
    ["excess UTF-8 bytes", "x".repeat(65_537)],
  ])("collapses %s observation to a closed capture gap without losing dispatch certainty", async (_name, observation) => {
    const dispatch = vi.fn(async () => ({ disposition: "DISPATCHED" as const, observation }));
    const state = await admitted(dispatch);
    await expect(dispatchAdmittedActionV01(state.session, state.broker, state.permit))
      .resolves.toEqual({ ok: true, disposition: "DISPATCHED", adapter_invocation_id: "invocation_effect_v01" });
    expect((await inspectRuntimeWriteSessionV03ForDispatch(state.session)).ok).toBe(true);
    expect(takeCapturedEffectObservationV01(state.broker, state.session, "invocation_effect_v01"))
      .toMatchObject({ ok: true, observation: null });
    await closeRuntimeWriteSessionV03(state.session);
  });

  it.each([
    ["throw", () => { throw new Error("adapter failed"); }],
    ["reject", async () => Promise.reject(new Error("adapter rejected"))],
    ["ambiguous return", async () => ({ disposition: "UNKNOWN" })],
    ["outcome prototype drift", async () => Object.setPrototypeOf({
      disposition: "DISPATCHED", observation: null,
    }, Object.create(Object.prototype))],
    ["outcome observation accessor", async () => Object.defineProperty({ disposition: "DISPATCHED" }, "observation", {
      enumerable: true, get: () => { throw new Error("outcome getter invoked"); },
    })],
    ["non-enumerable outcome observation", async () => Object.defineProperty({ disposition: "DISPATCHED" }, "observation", {
      enumerable: false, value: null,
    })],
    ["callback-supplied invocation metadata", async () => ({
      disposition: "DISPATCHED", observation: null, adapter_invocation_id: "attacker_selected_id", outcome_hash: H("f"),
    })],
  ])("poisons on %s after broker entry and never retries", async (_name, implementation) => {
    const dispatch = vi.fn(implementation);
    const state = await admitted(dispatch);
    await expect(dispatchAdmittedActionV01(state.session, state.broker, state.permit))
      .resolves.toEqual({ ok: false, error: "DISPATCH_OUTCOME_UNKNOWN" });
    expect(dispatch).toHaveBeenCalledTimes(1);
    await expect(inspectRuntimeWriteSessionV03ForDispatch(state.session))
      .resolves.toEqual({ ok: false, error: "RUNTIME_WRITE_SESSION_POISONED" });
    await closeRuntimeWriteSessionV03(state.session);
  });

  it("does not enter the adapter on forged broker or dispatch-hash mismatch", async () => {
    const dispatch = vi.fn(async () => ({ disposition: "DISPATCHED" as const, observation: null }));
    const state = await admitted(dispatch);
    await expect(dispatchAdmittedActionV01(state.session, Object.freeze({}) as CapturedEffectDispatchBrokerV01, state.permit))
      .resolves.toEqual({ ok: false, error: "CAPTURED_BROKER_INVALID" });
    expect(dispatch).not.toHaveBeenCalled();
    const mismatched = captureEffectDispatchBrokerV01(brokerInput(dispatch));
    if (mismatched === null) throw new Error("mismatch broker capture failed");
    await expect(dispatchAdmittedActionV01(state.session, mismatched, state.permit))
      .resolves.toEqual({ ok: false, error: "DISPATCH_BINDING_MISMATCH" });
    expect(dispatch).not.toHaveBeenCalled();
    await expect(inspectRuntimeWriteSessionV03ForDispatch(state.session))
      .resolves.toEqual({ ok: false, error: "RUNTIME_WRITE_SESSION_POISONED" });
    await closeRuntimeWriteSessionV03(state.session);
  });

  it("rejects a genuine permit presented with another live session without poisoning that session", async () => {
    const dispatch = vi.fn(async () => ({ disposition: "DISPATCHED" as const, observation: null }));
    const first = await admitted(dispatch);
    await closeRuntimeWriteSessionV03(first.session);
    const secondFixture = await createSignedRuntimeActionAdmissionV03Fixture();
    const second = await openRuntimeWriteSessionV03(secondFixture.store, secondFixture.expectation);
    if (!second.ok) throw new Error(second.error);
    await expect(dispatchAdmittedActionV01(second.session, first.broker, first.permit))
      .resolves.toEqual({ ok: false, error: "DISPATCH_PERMIT_SESSION_MISMATCH" });
    expect(dispatch).not.toHaveBeenCalled();
    expect((await inspectRuntimeWriteSessionV03ForDispatch(second.session)).ok).toBe(true);
    await closeRuntimeWriteSessionV03(second.session);
  });
});
