import { isProxy } from "node:util/types";

import { z } from "zod";

import { hashCanonical } from "../hash.js";
import { IsoTimestampV02, MachineIdV02 } from "../schema/scalars-v02.js";

declare const runtimeClockSourceBrandV04: unique symbol;
declare const runtimeClockObservationBrandV04: unique symbol;

/** Package-private opaque authority to sample one stable runtime clock source. */
export type CapturedRuntimeClockSourceV04 = Readonly<{
  [runtimeClockSourceBrandV04]: never;
}>;

/** Package-private one-use observation; facts are available only through consume. */
export type CapturedRuntimeClockObservationV04 = Readonly<{
  [runtimeClockObservationBrandV04]: never;
}>;

export type RuntimeClockObservationFactsV04 = Readonly<{
  boot_id_hash: string;
  monotonic_clock_id: string;
  observed_at: string;
  elapsed_ms: number;
}>;

export type ObserveRuntimeClockV04Result =
  | Readonly<{ ok: true; value: CapturedRuntimeClockObservationV04 }>
  | Readonly<{
      ok: false;
      error:
        | "RUNTIME_CLOCK_SOURCE_INVALID"
        | "RUNTIME_CLOCK_OBSERVATION_INVALID"
        | "RUNTIME_CLOCK_REGRESSION";
    }>;

const RawBootIdentityV04 = z.string().min(1).refine(
  (value) => new TextEncoder().encode(value).byteLength <= 4_096,
  "must be at most 4096 UTF-8 bytes",
);

const ClockObservationV04 = z.object({
  observed_at: IsoTimestampV02,
  elapsed_ms: z.number().int().nonnegative().refine(Number.isSafeInteger),
}).strict();

type ObserveCallback = () => unknown;
type SourceState = {
  source: object;
  observe: ObserveCallback;
  boot_identity: string;
  monotonic_clock_id: string;
  last_observed_at_ms: number | null;
  last_elapsed_ms: number | null;
};

const sources = new WeakMap<object, SourceState>();
const observations = new WeakMap<object, RuntimeClockObservationFactsV04>();

const SOURCE_INVALID = Object.freeze({
  ok: false,
  error: "RUNTIME_CLOCK_SOURCE_INVALID",
} as const);
const OBSERVATION_INVALID = Object.freeze({
  ok: false,
  error: "RUNTIME_CLOCK_OBSERVATION_INVALID",
} as const);
const REGRESSION = Object.freeze({
  ok: false,
  error: "RUNTIME_CLOCK_REGRESSION",
} as const);

function exactDataDescriptors(
  input: unknown,
  expectedKeys: readonly string[],
): Readonly<Record<string, PropertyDescriptor>> | null {
  try {
    if (typeof input !== "object" || input === null || Array.isArray(input)
      || isProxy(input) || Object.getPrototypeOf(input) !== Object.prototype
      || Reflect.ownKeys(input).some((key) => typeof key === "symbol")) return null;
    const descriptors = Object.getOwnPropertyDescriptors(input);
    if (Object.keys(descriptors).sort().join("\u0000") !== [...expectedKeys].sort().join("\u0000")) return null;
    if (expectedKeys.some((key) => {
      const descriptor = descriptors[key];
      return descriptor === undefined || descriptor.enumerable !== true
        || descriptor.get !== undefined || descriptor.set !== undefined
        || !("value" in descriptor);
    })) return null;
    return descriptors;
  } catch {
    return null;
  }
}

function sourceStillStable(state: SourceState): boolean {
  const descriptors = exactDataDescriptors(
    state.source,
    ["boot_identity", "monotonic_clock_id", "observe"],
  );
  return descriptors !== null
    && descriptors.boot_identity?.value === state.boot_identity
    && descriptors.monotonic_clock_id?.value === state.monotonic_clock_id
    && descriptors.observe?.value === state.observe;
}

/**
 * Captures a composition-root-owned clock reader without invoking it. The raw
 * boot identity is retained only inside this module and is never exposed.
 */
export function captureRuntimeClockSourceV04(
  input: unknown,
): CapturedRuntimeClockSourceV04 | null {
  const descriptors = exactDataDescriptors(
    input,
    ["boot_identity", "monotonic_clock_id", "observe"],
  );
  if (descriptors === null) return null;
  const bootIdentity = RawBootIdentityV04.safeParse(descriptors.boot_identity?.value);
  const clockId = MachineIdV02.safeParse(descriptors.monotonic_clock_id?.value);
  const observe = descriptors.observe?.value;
  if (!bootIdentity.success || !clockId.success || typeof observe !== "function" || isProxy(observe)) return null;

  const capability = Object.freeze({}) as CapturedRuntimeClockSourceV04;
  sources.set(capability, {
    source: input as object,
    observe: observe as ObserveCallback,
    boot_identity: bootIdentity.data,
    monotonic_clock_id: clockId.data,
    last_observed_at_ms: null,
    last_elapsed_ms: null,
  });
  return capability;
}

/**
 * Samples the captured source. Equal readings are valid because V04 ledger
 * clocks permit multiple events within one monotonic tick and one UTC second.
 */
export function observeRuntimeClockV04(
  source: CapturedRuntimeClockSourceV04,
): ObserveRuntimeClockV04Result {
  const state = sources.get(source);
  if (state === undefined) return SOURCE_INVALID;
  if (!sourceStillStable(state)) {
    sources.delete(source);
    return SOURCE_INVALID;
  }

  let raw: unknown;
  try {
    raw = Reflect.apply(state.observe, undefined, []);
  } catch {
    sources.delete(source);
    return OBSERVATION_INVALID;
  }
  const descriptors = exactDataDescriptors(raw, ["observed_at", "elapsed_ms"]);
  if (descriptors === null) {
    sources.delete(source);
    return OBSERVATION_INVALID;
  }
  const parsed = ClockObservationV04.safeParse({
    observed_at: descriptors.observed_at?.value,
    elapsed_ms: descriptors.elapsed_ms?.value,
  });
  if (!parsed.success) {
    sources.delete(source);
    return OBSERVATION_INVALID;
  }
  const observedAtMs = Date.parse(parsed.data.observed_at);
  if ((state.last_elapsed_ms !== null && parsed.data.elapsed_ms < state.last_elapsed_ms)
    || (state.last_observed_at_ms !== null && observedAtMs < state.last_observed_at_ms)) {
    sources.delete(source);
    return REGRESSION;
  }

  state.last_elapsed_ms = parsed.data.elapsed_ms;
  state.last_observed_at_ms = observedAtMs;
  const value = Object.freeze({}) as CapturedRuntimeClockObservationV04;
  observations.set(value, Object.freeze({
    boot_id_hash: hashCanonical({
      purpose: "runtime-clock-boot-identity-v04",
      schema_version: "0.4",
      boot_identity: state.boot_identity,
    }),
    monotonic_clock_id: state.monotonic_clock_id,
    observed_at: parsed.data.observed_at,
    elapsed_ms: parsed.data.elapsed_ms,
  }));
  return Object.freeze({ ok: true, value });
}

/** Transfers one observation into its sole writer and destroys the handle. */
export function consumeRuntimeClockObservationV04(
  observation: CapturedRuntimeClockObservationV04,
): RuntimeClockObservationFactsV04 | null {
  const facts = observations.get(observation);
  if (facts === undefined) return null;
  observations.delete(observation);
  return Object.freeze(structuredClone(facts));
}
