import { z } from "zod";
import { Hash, IsoTimestamp, MachineId } from "../schema/scalars.js";
import { decodeStructuredDocumentV02 } from "../schema/decode-envelope.js";
import {
  detectCredentialV02,
  type CredentialRuleIdV02,
} from "../security/credential-detector-v02.js";
import {
  compareUtf8BytesV02,
  PlanInputV02,
  projectBindingValueSchemaV02,
  type CatalogEntryV02,
  type PlanInputV02 as PlanInputV02Value,
} from "../catalog/item-v02.js";

const MAX_PROMPT_BYTES = 1_048_576;
const MAX_COMBINED_BYTES = 4_194_304;
const MAX_JSON_DEPTH = 64;
const MAX_JSON_NODES = 100_000;
const UTF8 = new TextEncoder();

export type JsonValueV02 = null | boolean | number | string | JsonValueV02[] | { [key: string]: JsonValueV02 };

function isStrictJsonValue(root: unknown): root is JsonValueV02 {
  let nodes = 0;
  const stack: Array<{ value: unknown; depth: number }> = [{ value: root, depth: 1 }];
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === undefined) return false;
    nodes += 1;
    if (nodes > MAX_JSON_NODES || current.depth > MAX_JSON_DEPTH) return false;
    const value = current.value;
    if (value === null || typeof value === "string" || typeof value === "boolean") continue;
    if (typeof value === "number") {
      if (!Number.isFinite(value)) return false;
      continue;
    }
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype || Object.keys(value).length !== value.length) return false;
      for (let index = value.length - 1; index >= 0; index -= 1) {
        if (!Object.hasOwn(value, index)) return false;
        stack.push({ value: value[index], depth: current.depth + 1 });
      }
      continue;
    }
    if (typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) return false;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string") return false;
      const descriptor = descriptors[key];
      if (descriptor === undefined || !("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined) {
        return false;
      }
      stack.push({ value: descriptor.value, depth: current.depth + 1 });
    }
  }
  return true;
}

export const JsonValueV02 = z.custom<JsonValueV02>(isStrictJsonValue, "must be a strict JSON value");
export const BindingKeyV02 = z
  .string()
  .regex(/^[a-z0-9]+(?:[.-][a-z0-9]+)*$/, "must be a canonical lowercase binding key");

const CompileBindingEntryV02 = z
  .object({
    key: BindingKeyV02,
    source: z.enum(["operator", "workspace-observation"]),
    value: JsonValueV02,
    source_ref: z.string().min(1).nullable(),
    source_hash: Hash.nullable(),
  })
  .strict()
  .superRefine((binding, ctx) => {
    const operatorPairIsValid = binding.source === "operator" && binding.source_ref === null && binding.source_hash === null;
    const workspacePairIsValid =
      binding.source === "workspace-observation" && binding.source_ref !== null && binding.source_hash !== null;
    if (!operatorPairIsValid && !workspacePairIsValid) {
      ctx.addIssue({
        code: "custom",
        path: ["source_ref"],
        message: "source_ref and source_hash do not match the declared source",
      });
    }
  });

export const CompileBindingPayloadV02 = z
  .object({ bindings: z.array(CompileBindingEntryV02) })
  .strict()
  .superRefine((payload, ctx) => {
    const seen = new Set<string>();
    for (const [index, binding] of payload.bindings.entries()) {
      if (seen.has(binding.key)) {
        ctx.addIssue({ code: "custom", path: ["bindings", index, "key"], message: "binding keys must be unique" });
      }
      seen.add(binding.key);
    }
  });

export const BindingInputRecordV02 = z
  .object({
    schema_version: z.literal("0.2"),
    binding_input_id: MachineId,
    work_item_id: MachineId,
    submitted_at: IsoTimestamp,
    bindings: z.array(CompileBindingEntryV02.extend({ approved_by: z.literal("operator") }).strict()),
  })
  .strict()
  .superRefine((record, ctx) => {
    for (let index = 1; index < record.bindings.length; index += 1) {
      if (compareUtf8BytesV02(record.bindings[index - 1]!.key, record.bindings[index]!.key) >= 0) {
        ctx.addIssue({ code: "custom", path: ["bindings", index, "key"], message: "bindings must be unique and UTF-8 sorted" });
      }
    }
  });

export type CompileBindingPayloadV02 = z.infer<typeof CompileBindingPayloadV02>;
export type BindingInputRecordV02 = z.infer<typeof BindingInputRecordV02>;

export type { CredentialRuleIdV02 } from "../security/credential-detector-v02.js";

function stringLeavesDepthFirst(root: JsonValueV02): string[] {
  const leaves: string[] = [];
  const stack: JsonValueV02[] = [root];
  while (stack.length > 0) {
    const value = stack.pop();
    if (value === undefined) break;
    if (typeof value === "string") {
      leaves.push(value);
    } else if (Array.isArray(value)) {
      for (let index = value.length - 1; index >= 0; index -= 1) stack.push(value[index]!);
    } else if (typeof value === "object" && value !== null) {
      const keys = Object.keys(value);
      for (let index = keys.length - 1; index >= 0; index -= 1) stack.push(value[keys[index]!]!);
    }
  }
  return leaves;
}

export type DecodeCompileBindingPayloadResultV02 =
  | { ok: true; payload: CompileBindingPayloadV02 }
  | { ok: false; reason: "INPUT_TOO_LARGE" | "INVALID_DOCUMENT_ENVELOPE" | "INVALID_BINDING_INPUT"; message: string };

export function decodeCompileBindingPayloadV02(input: Uint8Array | undefined): DecodeCompileBindingPayloadResultV02 {
  if (input === undefined) return { ok: true, payload: { bindings: [] } };
  const decoded = decodeStructuredDocumentV02(input, "json");
  if (!decoded.ok) return decoded;
  if (typeof decoded.value !== "object" || decoded.value === null || Array.isArray(decoded.value)) {
    return { ok: false, reason: "INVALID_DOCUMENT_ENVELOPE", message: "Binding input must be one object envelope." };
  }
  const parsed = CompileBindingPayloadV02.safeParse(decoded.value);
  if (!parsed.success) {
    return { ok: false, reason: "INVALID_BINDING_INPUT", message: "Binding input is invalid." };
  }
  return { ok: true, payload: parsed.data };
}

export type BindingAdmissionFailureV02 =
  | { ok: false; reason: "INPUT_TOO_LARGE" | "INVALID_BINDING_INPUT"; message: string }
  | {
      ok: false;
      reason: "SENSITIVE_INPUT_REJECTED";
      location: "prompt" | "binding-source-ref" | "binding-value";
      binding_key: string | null;
      rule_id: CredentialRuleIdV02;
      message: string;
    };

export type BindingAdmissionResultV02 = { ok: true; record: BindingInputRecordV02 } | BindingAdmissionFailureV02;

export type PreflightedCompileBindingPayloadV02 = Readonly<{
  readonly __preflighted_compile_binding_payload_v02: unique symbol;
}>;

export type CompileBindingPreflightResultV02 =
  | { ok: true; preflight: PreflightedCompileBindingPayloadV02 }
  | Exclude<DecodeCompileBindingPayloadResultV02, { ok: true }>
  | BindingAdmissionFailureV02;

type BindingPreflightState = {
  payload: CompileBindingPayloadV02;
};

const bindingPreflightRegistry = new WeakMap<object, BindingPreflightState>();

const PLACEHOLDER = /^(?:todo|tbd|placeholder|project-specific|fill-me|unknown|example)$/i;

function isSecretReference(value: JsonValueV02): boolean {
  return typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).length === 2 &&
    value.kind === "secret-ref" &&
    typeof value.ref_id === "string" &&
    /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(value.ref_id);
}

function scanCompileBindingPayloadV02(
  prompt: string,
  payload: CompileBindingPayloadV02,
): BindingAdmissionFailureV02 | null {
  const promptRule = detectCredentialV02(prompt);
  if (promptRule !== null) {
    return {
      ok: false,
      reason: "SENSITIVE_INPUT_REJECTED",
      location: "prompt",
      binding_key: null,
      rule_id: promptRule.rule_id,
      message: "Sensitive input was rejected.",
    };
  }

  for (const binding of payload.bindings) {
    if (binding.source_ref !== null) {
      const sourceRule = detectCredentialV02(binding.source_ref);
      if (sourceRule !== null) {
        return {
          ok: false,
          reason: "SENSITIVE_INPUT_REJECTED",
          location: "binding-source-ref",
          binding_key: binding.key,
          rule_id: sourceRule.rule_id,
          message: "Sensitive input was rejected.",
        };
      }
    }
    for (const leaf of stringLeavesDepthFirst(binding.value)) {
      const valueRule = detectCredentialV02(leaf);
      if (valueRule !== null) {
        return {
          ok: false,
          reason: "SENSITIVE_INPUT_REJECTED",
          location: "binding-value",
          binding_key: binding.key,
          rule_id: valueRule.rule_id,
          message: "Sensitive input was rejected.",
        };
      }
    }
  }
  return null;
}

export function preflightCompileBindingPayloadV02(input: {
  prompt: string;
  binding_payload_bytes?: Uint8Array;
}): CompileBindingPreflightResultV02 {
  const promptBytes = UTF8.encode(input.prompt).byteLength;
  if (promptBytes > MAX_PROMPT_BYTES) {
    return { ok: false, reason: "INPUT_TOO_LARGE", message: `Prompt exceeds ${MAX_PROMPT_BYTES} bytes.` };
  }
  if (input.binding_payload_bytes !== undefined && promptBytes + input.binding_payload_bytes.byteLength > MAX_COMBINED_BYTES) {
    return { ok: false, reason: "INPUT_TOO_LARGE", message: `Prompt and binding input exceed ${MAX_COMBINED_BYTES} bytes.` };
  }

  const promptSensitive = scanCompileBindingPayloadV02(input.prompt, { bindings: [] });
  if (promptSensitive !== null) return promptSensitive;

  const decoded = decodeCompileBindingPayloadV02(input.binding_payload_bytes);
  if (!decoded.ok) return decoded;
  const sensitive = scanCompileBindingPayloadV02(input.prompt, decoded.payload);
  if (sensitive !== null) return sensitive;

  const preflight = Object.freeze({}) as PreflightedCompileBindingPayloadV02;
  bindingPreflightRegistry.set(preflight, { payload: decoded.payload });
  return { ok: true, preflight };
}

export function bindPreflightedCompileBindingPayloadV02(
  preflight: PreflightedCompileBindingPayloadV02,
  lineage: {
    binding_input_id: string;
    work_item_id: string;
    submitted_at: string;
  },
): BindingAdmissionResultV02 {
  const state = bindingPreflightRegistry.get(preflight);
  if (state === undefined) {
    return {
      ok: false,
      reason: "INVALID_BINDING_INPUT",
      message: "Binding preflight is invalid.",
    };
  }
  const record = BindingInputRecordV02.safeParse({
    schema_version: "0.2",
    ...lineage,
    bindings: [...state.payload.bindings]
      .sort((left, right) => compareUtf8BytesV02(left.key, right.key))
      .map((binding) => ({ ...binding, approved_by: "operator" as const })),
  });
  if (!record.success) {
    return { ok: false, reason: "INVALID_BINDING_INPUT", message: "Binding record lineage is invalid." };
  }
  return { ok: true, record: record.data };
}

export type CatalogBindingValidationResultV02 =
  | { ok: true; required_binding_keys: string[] }
  | { ok: false; reason: "INVALID_BINDING_INPUT"; message: string };

export type PlanInputProjectionResultV02 =
  | { ok: true; plan_input: PlanInputV02Value }
  | { ok: false; reason: "INVALID_BINDING_INPUT"; message: string };

export function projectPlanInputV02(input: unknown): PlanInputProjectionResultV02 {
  const record = BindingInputRecordV02.safeParse(input);
  if (!record.success) {
    return { ok: false, reason: "INVALID_BINDING_INPUT", message: "Binding input is invalid." };
  }
  const values = new Map(record.data.bindings.map((binding) => [binding.key, binding.value]));
  const projected = PlanInputV02.safeParse({
    adapter_plan: values.get("project.engine"),
    workspace_boundary: values.get("project.workspace-root"),
  });
  if (!projected.success) {
    return { ok: false, reason: "INVALID_BINDING_INPUT", message: "Binding input is invalid." };
  }
  return { ok: true, plan_input: projected.data };
}

export function validateBindingsForCatalogEntryV02(
  payload: CompileBindingPayloadV02,
  entry: CatalogEntryV02,
): CatalogBindingValidationResultV02 {
  const slots = new Map(entry.binding_slots.map((slot) => [slot.slot_id, slot]));
  const supplied = new Set<string>();
  for (const binding of payload.bindings) {
    const slot = slots.get(binding.key);
    if (slot === undefined || !slot.allowed_sources.includes(binding.source)) {
      return { ok: false, reason: "INVALID_BINDING_INPUT", message: "Binding input is invalid." };
    }
    const secretReference = isSecretReference(binding.value);
    const exactValueSchema = projectBindingValueSchemaV02(slot.slot_id);
    if ((slot.sensitivity === "secret-reference" && (!secretReference || binding.source !== "operator")) ||
      (slot.sensitivity !== "secret-reference" && secretReference) ||
      exactValueSchema === null ||
      !exactValueSchema.safeParse(binding.value).success) {
      return { ok: false, reason: "INVALID_BINDING_INPUT", message: "Binding input is invalid." };
    }
    if (stringLeavesDepthFirst(binding.value).some((leaf) => PLACEHOLDER.test(leaf.trim()) || /[<\[][^>\]]+[>\]]/.test(leaf))) {
      return { ok: false, reason: "INVALID_BINDING_INPUT", message: "Binding input is invalid." };
    }
    supplied.add(binding.key);
  }
  return {
    ok: true,
    required_binding_keys: entry.binding_slots
      .filter((slot) => slot.required && !supplied.has(slot.slot_id))
      .map((slot) => slot.slot_id)
      .sort(compareUtf8BytesV02),
  };
}

export function admitCompileBindingPayloadV02(input: {
  prompt: string;
  payload: unknown;
  binding_input_id: string;
  work_item_id: string;
  submitted_at: string;
}): BindingAdmissionResultV02 {
  const promptBytes = UTF8.encode(input.prompt).byteLength;
  if (promptBytes > MAX_PROMPT_BYTES) {
    return { ok: false, reason: "INPUT_TOO_LARGE", message: `Prompt exceeds ${MAX_PROMPT_BYTES} bytes.` };
  }
  const promptSensitive = scanCompileBindingPayloadV02(input.prompt, { bindings: [] });
  if (promptSensitive !== null) return promptSensitive;
  const parsed = CompileBindingPayloadV02.safeParse(input.payload);
  if (!parsed.success) return { ok: false, reason: "INVALID_BINDING_INPUT", message: "Binding input is invalid." };
  const payloadBytes = UTF8.encode(JSON.stringify(parsed.data)).byteLength;
  if (promptBytes + payloadBytes > MAX_COMBINED_BYTES) {
    return { ok: false, reason: "INPUT_TOO_LARGE", message: `Prompt and binding input exceed ${MAX_COMBINED_BYTES} bytes.` };
  }

  const sensitive = scanCompileBindingPayloadV02(input.prompt, parsed.data);
  if (sensitive !== null) return sensitive;

  const record = BindingInputRecordV02.safeParse({
    schema_version: "0.2",
    binding_input_id: input.binding_input_id,
    work_item_id: input.work_item_id,
    submitted_at: input.submitted_at,
    bindings: [...parsed.data.bindings]
      .sort((left, right) => compareUtf8BytesV02(left.key, right.key))
      .map((binding) => ({ ...binding, approved_by: "operator" as const })),
  });
  if (!record.success) return { ok: false, reason: "INVALID_BINDING_INPUT", message: "Binding record lineage is invalid." };
  return { ok: true, record: record.data };
}
