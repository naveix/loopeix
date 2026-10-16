import { describe, expect, it, vi } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import {
  captureRuntimeClockSourceV04,
  consumeRuntimeClockObservationV04,
  observeRuntimeClockV04,
} from "../../src/run/runtime-clock-observation-v04.js";

function source(
  rows: readonly Readonly<{ observed_at: string; elapsed_ms: number }>[],
) {
  let index = 0;
  return {
    boot_identity: "boot-identity-s41-test",
    monotonic_clock_id: "monotonic_s41_test",
    observe: () => rows[index++]!,
  };
}

describe("S41 opaque runtime clock observation V04", () => {
  it("captures multiple nondecreasing observations and consumes each exactly once", () => {
    const captured = captureRuntimeClockSourceV04(source([
      { observed_at: "2026-08-30T10:00:00Z", elapsed_ms: 10 },
      { observed_at: "2026-08-30T10:00:00Z", elapsed_ms: 10 },
      { observed_at: "2026-08-30T10:00:01Z", elapsed_ms: 11 },
    ]));
    expect(captured).not.toBeNull();

    const first = observeRuntimeClockV04(captured!);
    const second = observeRuntimeClockV04(captured!);
    const third = observeRuntimeClockV04(captured!);
    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    expect(third.ok).toBe(true);
    if (!first.ok || !second.ok || !third.ok) throw new Error("expected observations");

    const expectedBootHash = hashCanonical({
      purpose: "runtime-clock-boot-identity-v04",
      schema_version: "0.4",
      boot_identity: "boot-identity-s41-test",
    });
    const consumedFirst = consumeRuntimeClockObservationV04(first.value);
    expect(consumedFirst).toEqual({
      boot_id_hash: expectedBootHash,
      monotonic_clock_id: "monotonic_s41_test",
      observed_at: "2026-08-30T10:00:00Z",
      elapsed_ms: 10,
    });
    expect(Object.isFrozen(consumedFirst)).toBe(true);
    expect(consumeRuntimeClockObservationV04(first.value)).toBeNull();
    expect(consumeRuntimeClockObservationV04(second.value)?.elapsed_ms).toBe(10);
    expect(consumeRuntimeClockObservationV04(third.value)?.elapsed_ms).toBe(11);
  });

  it("returns immutable opaque handles and rejects forged or replayed values", () => {
    const captured = captureRuntimeClockSourceV04(source([
      { observed_at: "2026-08-30T10:00:00Z", elapsed_ms: 1 },
    ]));
    expect(captured).not.toBeNull();
    expect(Object.isFrozen(captured)).toBe(true);
    expect(Reflect.ownKeys(captured!)).toEqual([]);
    expect(observeRuntimeClockV04(Object.freeze({}) as typeof captured)).toEqual({
      ok: false,
      error: "RUNTIME_CLOCK_SOURCE_INVALID",
    });
    expect(consumeRuntimeClockObservationV04(Object.freeze({}) as never)).toBeNull();

    const observed = observeRuntimeClockV04(captured!);
    expect(observed.ok).toBe(true);
    if (!observed.ok) throw new Error("expected observation");
    expect(Object.isFrozen(observed.value)).toBe(true);
    expect(Reflect.ownKeys(observed.value)).toEqual([]);
  });

  it("rejects getters, proxies, extras, and mutated captured source identity", () => {
    const getter = vi.fn(() => "boot-identity");
    const getterInput = {
      monotonic_clock_id: "monotonic_s41_test",
      observe: () => ({ observed_at: "2026-08-30T10:00:00Z", elapsed_ms: 1 }),
    } as Record<string, unknown>;
    Object.defineProperty(getterInput, "boot_identity", { enumerable: true, get: getter });
    expect(captureRuntimeClockSourceV04(getterInput)).toBeNull();
    expect(getter).not.toHaveBeenCalled();

    const proxied = new Proxy(source([]), {});
    expect(captureRuntimeClockSourceV04(proxied)).toBeNull();
    expect(captureRuntimeClockSourceV04({ ...source([]), extra: true })).toBeNull();

    const mutable = source([
      { observed_at: "2026-08-30T10:00:00Z", elapsed_ms: 1 },
    ]);
    const captured = captureRuntimeClockSourceV04(mutable);
    expect(captured).not.toBeNull();
    mutable.boot_identity = "changed-boot-identity";
    expect(observeRuntimeClockV04(captured!)).toEqual({
      ok: false,
      error: "RUNTIME_CLOCK_SOURCE_INVALID",
    });

    const mutableClock = source([
      { observed_at: "2026-08-30T10:00:00Z", elapsed_ms: 1 },
    ]);
    const clockCaptured = captureRuntimeClockSourceV04(mutableClock);
    mutableClock.monotonic_clock_id = "monotonic_s41_changed";
    expect(observeRuntimeClockV04(clockCaptured!)).toEqual({
      ok: false,
      error: "RUNTIME_CLOCK_SOURCE_INVALID",
    });
  });

  it.each([
    undefined,
    null,
    {},
    { observed_at: "2026-08-30T10:00:00.000Z", elapsed_ms: 1 },
    { observed_at: "not-a-time", elapsed_ms: 1 },
    { observed_at: "2026-08-30T10:00:00Z", elapsed_ms: -1 },
    { observed_at: "2026-08-30T10:00:00Z", elapsed_ms: 1.5 },
    { observed_at: "2026-08-30T10:00:00Z", elapsed_ms: Number.MAX_SAFE_INTEGER + 1 },
    { observed_at: "2026-08-30T10:00:00Z", elapsed_ms: 1, extra: true },
  ])("rejects invalid callback output %#", (row) => {
    const captured = captureRuntimeClockSourceV04(source([row as never]));
    expect(observeRuntimeClockV04(captured!)).toEqual({
      ok: false,
      error: "RUNTIME_CLOCK_OBSERVATION_INVALID",
    });
  });

  it("fails closed when the callback throws", () => {
    const captured = captureRuntimeClockSourceV04({
      boot_identity: "boot-identity-s41-test",
      monotonic_clock_id: "monotonic_s41_test",
      observe: () => { throw new Error("clock unavailable"); },
    });
    expect(observeRuntimeClockV04(captured!)).toEqual({
      ok: false,
      error: "RUNTIME_CLOCK_OBSERVATION_INVALID",
    });
  });

  it.each([
    [
      { observed_at: "2026-08-30T10:00:01Z", elapsed_ms: 11 },
      { observed_at: "2026-08-30T10:00:02Z", elapsed_ms: 10 },
    ],
    [
      { observed_at: "2026-08-30T10:00:01Z", elapsed_ms: 10 },
      { observed_at: "2026-08-30T10:00:00Z", elapsed_ms: 11 },
    ],
  ])("rejects monotonic or wall-clock regression %#", (first, second) => {
    const captured = captureRuntimeClockSourceV04(source([first, second]));
    expect(observeRuntimeClockV04(captured!).ok).toBe(true);
    expect(observeRuntimeClockV04(captured!)).toEqual({
      ok: false,
      error: "RUNTIME_CLOCK_REGRESSION",
    });
  });
});
