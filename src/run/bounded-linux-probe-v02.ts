import { isAbsolute } from "node:path";

import {
  consumeS37LinuxProbeAdmissionV02,
  type S37LinuxBackendIdentityReceiptV02,
  type S37ActionInterpositionProfileV02,
  type S37LinuxHostTupleV02,
  type S37LinuxProbeAdmissionV02,
} from "./pre-spawn-capability-broker-v02.js";

export type S37LinuxProbeRuntimeInputV02 = Readonly<{
  executable: Readonly<{ path: string }>;
  argv: readonly string[];
  cwd: Readonly<{ path: string }>;
  env: Readonly<Record<string, never>>;
  stdin: "closed";
  timeout_ms: 1_000;
  stdout_bytes: 1_024;
  stderr_bytes: 1_024;
  tuple: S37LinuxHostTupleV02;
  receipt: S37LinuxBackendIdentityReceiptV02;
}>;

export type S37LinuxProbeRuntimeOutcomeV02 =
  | Readonly<{
      ok: false;
      confirmed_not_started: true;
      detail: string;
    }>
  | Readonly<{
      ok: true;
      process_started: true;
      exit_code: number | null;
      signal: string | null;
      timed_out: boolean;
      kill_attempted: boolean;
      reaped: boolean;
      forbidden_effect_denied: boolean;
      outcome_ambiguous: boolean;
      stdout: Uint8Array;
      stderr: Uint8Array;
    }>;

export type S37LinuxProbeRuntimeV02 = Readonly<{
  start(input: S37LinuxProbeRuntimeInputV02): Promise<S37LinuxProbeRuntimeOutcomeV02>;
}>;

type HoldResult = Readonly<{
  ok: false;
  reason: "ADMISSION_INVALID" | "SPAWN_FAILED" | "TIMEOUT_REAPED" | "OUTCOME_UNKNOWN";
  terminal: "hold";
  retryable: false;
  process_started: boolean;
  detail: string;
}>;

type SuccessResult = Readonly<{
  ok: true;
  terminal: "completed";
  outcome: "exited" | "forbidden-effect-denied";
  process_started: true;
  exit_code: number | null;
  signal: string | null;
  stdout: Uint8Array;
  stderr: Uint8Array;
}>;

export type S37LinuxProbeExecutionResultV02 = HoldResult | SuccessResult;

const EMPTY_ENV = Object.freeze({}) as Readonly<Record<string, never>>;
const UNKNOWN_OUTCOME_DETAIL = "The S37 Linux probe outcome could not be proven safe and exact.";

type ConsumedAdmissionV02 = Readonly<{
  profile: S37ActionInterpositionProfileV02;
  host_tuple: S37LinuxHostTupleV02;
  backend_receipt: S37LinuxBackendIdentityReceiptV02;
}>;

function freezeDeep<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value) || ArrayBuffer.isView(value)) return value;
  for (const child of Object.values(value)) freezeDeep(child);
  return Object.freeze(value);
}

function hold(
  reason: HoldResult["reason"],
  process_started: boolean,
  detail: string,
): HoldResult {
  return Object.freeze({
    ok: false as const,
    reason,
    terminal: "hold" as const,
    retryable: false as const,
    process_started,
    detail,
  });
}

function completed(
  outcome: SuccessResult["outcome"],
  exit_code: number | null,
  signal: string | null,
  stdout: Uint8Array,
  stderr: Uint8Array,
): SuccessResult {
  return Object.freeze({
    ok: true as const,
    terminal: "completed" as const,
    outcome,
    process_started: true as const,
    exit_code,
    signal,
    stdout,
    stderr,
  });
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null ? value as Record<string, unknown> : null;
}

function isAbsolutePath(value: unknown): value is string {
  return typeof value === "string" && isAbsolute(value) && !value.includes("\0") && !/[\r\n]/u.test(value);
}

function cloneFrozen<T>(value: T): T | null {
  try {
    return freezeDeep(structuredClone(value));
  } catch {
    return null;
  }
}

function fixedViewLength(value: unknown): number | null {
  try {
    if (!ArrayBuffer.isView(value) || Object.prototype.toString.call(value) !== "[object Uint8Array]") return null;
    const view = value as Uint8Array;
    const buffer = view.buffer;
    if (typeof SharedArrayBuffer !== "undefined" && buffer instanceof SharedArrayBuffer) return null;
    if (!(buffer instanceof ArrayBuffer)) return null;
    const resizable = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "resizable")?.get;
    if (resizable !== undefined && resizable.call(buffer) === true) return null;
    const byteLength = Object.getOwnPropertyDescriptor(Uint8Array.prototype, "byteLength")?.get;
    return byteLength === undefined ? view.byteLength : byteLength.call(view);
  } catch {
    return null;
  }
}

function boundedBytes(
  value: unknown,
  limit: 1_024,
  name: "stdout" | "stderr",
): { ok: true; bytes: Uint8Array } | { ok: false; detail: string } {
  try {
    const length = fixedViewLength(value);
    if (length === null) return { ok: false, detail: UNKNOWN_OUTCOME_DETAIL };
    if (length > limit) return { ok: false, detail: `${name} exceeded the 1024-byte S37 cap.` };
    const bytes = new Uint8Array(length);
    bytes.set(Uint8Array.prototype.subarray.call(value as Uint8Array, 0, length));
    return { ok: true, bytes };
  } catch {
    return { ok: false, detail: UNKNOWN_OUTCOME_DETAIL };
  }
}

function validateStartedOutcome(value: unknown): S37LinuxProbeExecutionResultV02 {
  const record = asRecord(value);
  if (record === null || record.ok !== true || record.process_started !== true) {
    return hold("OUTCOME_UNKNOWN", true, UNKNOWN_OUTCOME_DETAIL);
  }

  const exit_code = record.exit_code;
  const signal = record.signal;
  const timed_out = record.timed_out;
  const kill_attempted = record.kill_attempted;
  const reaped = record.reaped;
  const forbidden_effect_denied = record.forbidden_effect_denied;
  const outcome_ambiguous = record.outcome_ambiguous;
  if ((exit_code !== null && !Number.isInteger(exit_code))
    || (signal !== null && typeof signal !== "string")
    || typeof timed_out !== "boolean"
    || typeof kill_attempted !== "boolean"
    || typeof reaped !== "boolean"
    || typeof forbidden_effect_denied !== "boolean"
    || typeof outcome_ambiguous !== "boolean") {
    return hold("OUTCOME_UNKNOWN", true, UNKNOWN_OUTCOME_DETAIL);
  }
  const normalizedExitCode = exit_code as number | null;
  const normalizedSignal = signal as string | null;

  const stdout = boundedBytes(record.stdout, 1_024, "stdout");
  if (!stdout.ok) return hold("OUTCOME_UNKNOWN", true, stdout.detail);
  const stderr = boundedBytes(record.stderr, 1_024, "stderr");
  if (!stderr.ok) return hold("OUTCOME_UNKNOWN", true, stderr.detail);

  if (outcome_ambiguous) return hold("OUTCOME_UNKNOWN", true, UNKNOWN_OUTCOME_DETAIL);

  if (timed_out) {
    return kill_attempted && reaped && !forbidden_effect_denied
      && normalizedExitCode === null && typeof normalizedSignal === "string" && normalizedSignal.length > 0
      ? hold("TIMEOUT_REAPED", true, "The S37 Linux probe timed out, required a kill, and was fully reaped.")
      : hold("OUTCOME_UNKNOWN", true, UNKNOWN_OUTCOME_DETAIL);
  }

  if (!reaped || kill_attempted) return hold("OUTCOME_UNKNOWN", true, UNKNOWN_OUTCOME_DETAIL);

  if (forbidden_effect_denied) {
    if (normalizedExitCode === null && normalizedSignal === null) return hold("OUTCOME_UNKNOWN", true, UNKNOWN_OUTCOME_DETAIL);
    return completed("forbidden-effect-denied", normalizedExitCode, normalizedSignal, stdout.bytes, stderr.bytes);
  }

  if (!Number.isInteger(normalizedExitCode) || normalizedSignal !== null) {
    return hold("OUTCOME_UNKNOWN", true, UNKNOWN_OUTCOME_DETAIL);
  }

  return completed("exited", normalizedExitCode, normalizedSignal, stdout.bytes, stderr.bytes);
}

function consumedAdmissionOrNull(admission: S37LinuxProbeAdmissionV02): ConsumedAdmissionV02 | null {
  const consumed = consumeS37LinuxProbeAdmissionV02(admission);
  return consumed === null ? null : consumed;
}

function buildRuntimeInput(consumed: ConsumedAdmissionV02): S37LinuxProbeRuntimeInputV02 | null {
  const { profile } = consumed;
  if (!isAbsolutePath(profile.executable.path) || !isAbsolutePath(profile.cwd.path)) return null;
  if (!Array.isArray(profile.argv) || profile.argv.some((value) => typeof value !== "string")) return null;
  if (profile.environment.inherit !== false
    || profile.environment.allowed_names.length !== 0
    || Object.keys(profile.environment.values).length !== 0
    || profile.stdin !== "closed"
    || profile.limits.timeout_ms !== 1_000
    || profile.limits.stdout_bytes !== 1_024
    || profile.limits.stderr_bytes !== 1_024) {
    return null;
  }
  const tuple = cloneFrozen(consumed.host_tuple);
  const receipt = cloneFrozen(consumed.backend_receipt);
  if (tuple === null || receipt === null) return null;
  return freezeDeep({
    executable: { path: profile.executable.path },
    argv: Object.freeze([...profile.argv]),
    cwd: { path: profile.cwd.path },
    env: EMPTY_ENV,
    stdin: "closed" as const,
    timeout_ms: 1_000 as const,
    stdout_bytes: 1_024 as const,
    stderr_bytes: 1_024 as const,
    tuple: tuple as S37LinuxHostTupleV02,
    receipt: receipt as S37LinuxBackendIdentityReceiptV02,
  });
}

export async function runBoundedS37LinuxProbeV02(
  admission: S37LinuxProbeAdmissionV02,
  runtime: S37LinuxProbeRuntimeV02,
): Promise<S37LinuxProbeExecutionResultV02> {
  const consumed = consumedAdmissionOrNull(admission);
  if (consumed === null) {
    return hold("ADMISSION_INVALID", false, "S37 Linux probe admission is invalid or already consumed.");
  }

  const input = buildRuntimeInput(consumed);
  if (input === null) {
    return hold("ADMISSION_INVALID", false, "The consumed S37 Linux probe admission is malformed.");
  }

  try {
    const outcome = await runtime.start(input);
    const record = asRecord(outcome);
    if (record !== null && record.ok === false && record.confirmed_not_started === true && typeof record.detail === "string") {
      return hold("SPAWN_FAILED", false, record.detail);
    }
    return validateStartedOutcome(outcome);
  } catch {
    return hold("OUTCOME_UNKNOWN", true, UNKNOWN_OUTCOME_DETAIL);
  }
}
