import {
  ResolvedRunPlanV02,
  type ResolvedRunPlanV02Value,
} from "../schema/runtime.js";
import {
  deriveRuntimeExecutionPolicyForRegisteredAdapterV03,
  isCapturedRuntimeProfileRegistryV03,
  type CapturedRuntimeProfileRegistryV03,
} from "../schema/runtime-plan-v03.js";
import {
  HashRuntimeInputV03,
  HashRuntimeRecoveryPolicyV03,
  ResolvedRunPlanV03,
  type ResolvedRunPlanV03Value,
} from "../schema/runtime-v04.js";

export type ProjectResolvedRunPlanV03Result =
  | Readonly<{ ok: true; value: ResolvedRunPlanV03Value }>
  | Readonly<{ ok: false; reason: "INVALID_V03_RUNTIME_EXECUTION_POLICY" }>;

export type ValidatedRuntimePlanV03 = Readonly<{
  readonly __validated_runtime_plan_v03: unique symbol;
  run_id: string;
  plan_hash: string;
  byte_length: number;
  plan: ResolvedRunPlanV03Value;
}>;

export type RuntimePlanInspectionV03Result =
  | Readonly<{ ok: true; validated_plan: ValidatedRuntimePlanV03 }>
  | Readonly<{
      ok: false;
      reason: "RUNTIME_PLAN_INPUT_INVALID" | "RUNTIME_PLAN_SYNTAX_INVALID" | "RUNTIME_PLAN_SCHEMA_INVALID";
    }>;

const INVALID_POLICY = Object.freeze({
  ok: false,
  reason: "INVALID_V03_RUNTIME_EXECUTION_POLICY",
} as const);
const MAX_RUNTIME_PLAN_BYTES = 4_194_304;
const validatedRuntimePlansV03 = new WeakSet<object>();

function freezeDeep<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) freezeDeep(child);
  return Object.freeze(value);
}

export function projectRuntimePlanV03(
  input: unknown,
  registry: CapturedRuntimeProfileRegistryV03,
): ProjectResolvedRunPlanV03Result {
  if (!isCapturedRuntimeProfileRegistryV03(registry)) return INVALID_POLICY;
  const parsedV02 = ResolvedRunPlanV02.safeParse(input);
  if (!parsedV02.success) return INVALID_POLICY;

  const derived = deriveRuntimeExecutionPolicyForRegisteredAdapterV03(parsedV02.data);
  if (!derived.ok) return derived;

  const base = structuredClone(parsedV02.data) as ResolvedRunPlanV02Value;
  const candidate = {
    ...base,
    schema_version: "0.3",
    execution_profile: "bounded-v04",
    runtime_input_hash: HashRuntimeInputV03(base),
    runtime_recovery_policy_hash: HashRuntimeRecoveryPolicyV03(base),
    required_control_plane_output_bytes: derived.value.required_control_plane_output_bytes,
    runtime_execution_policy: structuredClone(derived.value.runtime_execution_policy),
  };
  const parsedV03 = ResolvedRunPlanV03.safeParse(candidate);
  return parsedV03.success
    ? { ok: true, value: freezeDeep(parsedV03.data) }
    : INVALID_POLICY;
}

export function isValidatedRuntimePlanV03(input: unknown): input is ValidatedRuntimePlanV03 {
  return typeof input === "object" && input !== null && validatedRuntimePlansV03.has(input);
}

export function inspectRuntimePlanV03(input: unknown): RuntimePlanInspectionV03Result {
  try {
    if (!(input instanceof Uint8Array)
      || Object.getPrototypeOf(input) !== Uint8Array.prototype
      || input.buffer instanceof SharedArrayBuffer
      || input.byteLength === 0
      || input.byteLength > MAX_RUNTIME_PLAN_BYTES) {
      return { ok: false, reason: "RUNTIME_PLAN_INPUT_INVALID" };
    }
    const bytes = new Uint8Array(input);
    let value: unknown;
    try {
      const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      const document = parseDocument(text, { uniqueKeys: true });
      if (document.errors.length > 0) return { ok: false, reason: "RUNTIME_PLAN_SYNTAX_INVALID" };
      value = JSON.parse(text) as unknown;
    } catch {
      return { ok: false, reason: "RUNTIME_PLAN_SYNTAX_INVALID" };
    }
    const parsed = ResolvedRunPlanV03.safeParse(value);
    if (!parsed.success) return { ok: false, reason: "RUNTIME_PLAN_SCHEMA_INVALID" };
    const validated = freezeDeep({
      run_id: parsed.data.run_id,
      plan_hash: hashRawBytes(bytes),
      byte_length: bytes.byteLength,
      plan: freezeDeep(parsed.data),
    }) as unknown as ValidatedRuntimePlanV03;
    validatedRuntimePlansV03.add(validated);
    return { ok: true, validated_plan: validated };
  } catch {
    return { ok: false, reason: "RUNTIME_PLAN_INPUT_INVALID" };
  }
}
import { parseDocument } from "yaml";

import { hashRawBytes } from "../hash.js";
