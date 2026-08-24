import { z } from "zod";

import { hashBytes } from "../hash.js";
import { Hash } from "../schema/scalars.js";
import { HumanIdV02, MachineIdV02 } from "../schema/scalars-v02.js";

const MAX_DEPTH = 32;
const MAX_NODES = 10_000;
const MAX_SNAPSHOT_BYTES = 1_048_576;
const MAX_PROMPT_BYTES = 262_144;
const MAX_CONTEXT_ITEM_BYTES = 131_072;
const MAX_RESPONSE_TEXT_BYTES = 65_536;

const utf8Bounded = (maximum: number) => z.string().refine(
  (value) => Buffer.byteLength(value, "utf8") <= maximum,
  { message: `must not exceed ${maximum} UTF-8 bytes` },
);

const allowedReferenceListV01 = z.array(HumanIdV02).max(128).superRefine((refs, ctx) => {
  const seen = new Set<string>();
  for (const [index, ref] of refs.entries()) {
    if (seen.has(ref)) ctx.addIssue({ code: "custom", path: [index], message: "allowed references must be unique within each kind" });
    seen.add(ref);
  }
});

const AllowedReferenceRegistrySchemaV01 = z.object({
  effect_refs: allowedReferenceListV01,
  evidence_refs: allowedReferenceListV01,
  program_refs: allowedReferenceListV01,
  path_refs: allowedReferenceListV01,
  origin_refs: allowedReferenceListV01,
  tool_refs: allowedReferenceListV01,
  connector_refs: allowedReferenceListV01,
  account_refs: allowedReferenceListV01,
  operation_refs: allowedReferenceListV01,
  target_refs: allowedReferenceListV01,
  content_refs: allowedReferenceListV01,
  body_refs: allowedReferenceListV01,
  argument_refs: allowedReferenceListV01,
}).strict();

const ApprovedModelContextSchemaV01 = z.object({
  context_version: z.literal("0.1"),
  executor_profile_hash: Hash,
  run_id: MachineIdV02,
  plan_hash: Hash,
  task_ref: HumanIdV02,
  attempt_id: MachineIdV02,
  turn_id: MachineIdV02,
  actor_identity_hash: Hash,
  on_behalf_of_chain_hash: Hash,
  prompt: utf8Bounded(MAX_PROMPT_BYTES).refine((value) => value.trim().length > 0),
  context_items: z.array(z.object({
    context_ref: HumanIdV02,
    content_hash: Hash,
    sensitivity: z.enum(["public", "internal", "confidential", "restricted"]),
    content: utf8Bounded(MAX_CONTEXT_ITEM_BYTES),
  }).strict().superRefine((item, ctx) => {
    if (hashBytes(item.content) !== item.content_hash) ctx.addIssue({ code: "custom", path: ["content_hash"], message: "content hash must bind exact UTF-8 bytes" });
  })).max(64).superRefine((items, ctx) => {
    const refs = new Set<string>();
    for (const [index, item] of items.entries()) {
      if (refs.has(item.context_ref)) ctx.addIssue({ code: "custom", path: [index, "context_ref"], message: "context_ref must be unique" });
      refs.add(item.context_ref);
    }
  }),
  allowed_references: AllowedReferenceRegistrySchemaV01,
}).strict();

const CommonProposalFieldsV01 = {
  proposal_ordinal: z.number().int().positive().max(10_000),
  task_ref: HumanIdV02,
  effect_refs: z.array(HumanIdV02).min(1).max(64),
  data_classes: z.array(z.enum(["public", "internal", "confidential", "restricted"])).max(16),
} satisfies z.ZodRawShape;

const RequestedActionV01 = z.discriminatedUnion("action_kind", [
  z.object({
    action_kind: z.literal("command"),
    program_ref: HumanIdV02,
    arguments_ref: HumanIdV02,
    arguments_hash: Hash,
    cwd_ref: HumanIdV02,
  }).strict(),
  z.object({ action_kind: z.literal("file"), operation: z.enum(["read", "write", "delete"]), path_ref: HumanIdV02, content_ref: HumanIdV02.nullable(), content_hash: Hash.nullable() }).strict().superRefine((value, ctx) => {
    const writesContent = value.operation === "write";
    if (writesContent !== (value.content_ref !== null && value.content_hash !== null)) ctx.addIssue({ code: "custom", path: ["content_ref"], message: "only writes require exact content reference and hash" });
  }),
  z.object({ action_kind: z.literal("tool"), tool_ref: HumanIdV02, tool_schema_hash: Hash, arguments_ref: HumanIdV02, arguments_hash: Hash }).strict(),
  z.object({ action_kind: z.literal("connector"), connector_ref: HumanIdV02, account_ref: HumanIdV02, operation_ref: HumanIdV02, target_ref: HumanIdV02 }).strict(),
  z.object({ action_kind: z.literal("network"), method: z.enum(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]), origin_ref: HumanIdV02, path_ref: HumanIdV02, body_ref: HumanIdV02.nullable(), body_hash: Hash.nullable() }).strict().superRefine((value, ctx) => {
    if ((value.body_ref === null) !== (value.body_hash === null)) ctx.addIssue({ code: "custom", path: ["body_ref"], message: "network body reference and hash must appear together" });
  }),
]);

const ModelResponseSchemaV01 = z.discriminatedUnion("kind", [
  z.object({
    response_version: z.literal("0.1"),
    kind: z.literal("action-proposal"),
    ...CommonProposalFieldsV01,
    action: RequestedActionV01,
  }).strict().transform((value) => ({ ...value, trust: "untrusted-proposal" as const })),
  z.object({
    response_version: z.literal("0.1"),
    kind: z.literal("completion-suggestion"),
    summary: utf8Bounded(MAX_RESPONSE_TEXT_BYTES).refine((value) => value.trim().length > 0),
    evidence_refs: z.array(HumanIdV02).max(128),
  }).strict().transform((value) => ({ ...value, trust: "untrusted-suggestion" as const })),
  z.object({
    response_version: z.literal("0.1"),
    kind: z.literal("clarification-suggestion"),
    question: utf8Bounded(MAX_RESPONSE_TEXT_BYTES).refine((value) => value.trim().length > 0),
    required_context_refs: z.array(HumanIdV02).min(1).max(64),
  }).strict().transform((value) => ({ ...value, trust: "untrusted-suggestion" as const })),
]);

type DeepReadonly<T> = T extends (...args: never[]) => unknown
  ? T
  : T extends readonly (infer U)[]
    ? readonly DeepReadonly<U>[]
    : T extends object
      ? { readonly [K in keyof T]: DeepReadonly<T[K]> }
      : T;

export type ApprovedModelContextV01 = DeepReadonly<z.infer<typeof ApprovedModelContextSchemaV01>>;
export type BrokeredModelResponseV01 = DeepReadonly<z.infer<typeof ModelResponseSchemaV01>>;

type SnapshotResult = Readonly<{ ok: true; value: unknown }> | Readonly<{ ok: false }>;

function snapshotPlain(value: unknown, depth = 0, state: { nodes: number } = { nodes: 0 }): SnapshotResult {
  state.nodes += 1;
  if (depth > MAX_DEPTH || state.nodes > MAX_NODES) return { ok: false };
  if (value === null || typeof value === "boolean" || typeof value === "string") return { ok: true, value };
  if (typeof value === "number") return Number.isFinite(value) ? { ok: true, value } : { ok: false };
  if (typeof value !== "object") return { ok: false };
  try {
    const prototype = Object.getPrototypeOf(value);
    if (Array.isArray(value)) {
      if (prototype !== Array.prototype) return { ok: false };
      const descriptors = Object.getOwnPropertyDescriptors(value);
      const keys = Reflect.ownKeys(value);
      if (keys.some((key) => typeof key !== "string") || Object.keys(descriptors).some((key) => key !== "length" && !/^\d+$/u.test(key))) return { ok: false };
      const result: unknown[] = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (descriptor === undefined || !("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined) return { ok: false };
        const child = snapshotPlain(descriptor.value, depth + 1, state);
        if (!child.ok) return child;
        result.push(child.value);
      }
      return { ok: true, value: result };
    }
    if (prototype !== Object.prototype && prototype !== null) return { ok: false };
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(value).some((key) => typeof key !== "string")) return { ok: false };
    const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (!("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined || descriptor.enumerable !== true) return { ok: false };
      const child = snapshotPlain(descriptor.value, depth + 1, state);
      if (!child.ok) return child;
      result[key] = child.value;
    }
    return { ok: true, value: result };
  } catch {
    return { ok: false };
  }
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function captureBounded(value: unknown): SnapshotResult {
  const captured = snapshotPlain(value);
  if (!captured.ok) return captured;
  try {
    if (Buffer.byteLength(JSON.stringify(captured.value), "utf8") > MAX_SNAPSHOT_BYTES) return { ok: false };
    return { ok: true, value: deepFreeze(captured.value) };
  } catch {
    return { ok: false };
  }
}

export type SyntheticBrokeredModelExecutorAdapterV01 = Readonly<{ readonly __synthetic_brokered_model_executor_adapter_v01: unique symbol }>;
type SyntheticAdapter = (context: ApprovedModelContextV01) => unknown | Promise<unknown>;
const syntheticAdapters = new WeakMap<object, SyntheticAdapter>();

export function createSyntheticBrokeredModelExecutorAdapterV01ForTest(adapter: SyntheticAdapter): SyntheticBrokeredModelExecutorAdapterV01 {
  const token = Object.freeze({}) as SyntheticBrokeredModelExecutorAdapterV01;
  syntheticAdapters.set(token, adapter);
  return token;
}

export type BrokeredModelExecutorResultV01 =
  | Readonly<{ ok: true; value: BrokeredModelResponseV01 }>
  | Readonly<{ ok: false; error: "MODEL_CONTEXT_INVALID" | "MODEL_ADAPTER_INVALID" | "MODEL_ADAPTER_FAILURE" | "MODEL_RESPONSE_INVALID" }>;

type ParsedApprovedModelContextV01 = z.infer<typeof ApprovedModelContextSchemaV01>;

function responseReferencesAreRegistered(
  context: ParsedApprovedModelContextV01,
  response: BrokeredModelResponseV01,
): boolean {
  const allowed = Object.fromEntries(
    Object.entries(context.allowed_references).map(([kind, refs]) => [kind, new Set(refs)]),
  ) as { [K in keyof ParsedApprovedModelContextV01["allowed_references"]]: Set<string> };
  const every = (refs: readonly string[], registry: Set<string>): boolean => refs.every((ref) => registry.has(ref));

  if (response.kind === "completion-suggestion") {
    return every(response.evidence_refs, allowed.evidence_refs);
  }
  if (response.kind === "clarification-suggestion") {
    const contextRefs = new Set(context.context_items.map((item) => item.context_ref));
    return every(response.required_context_refs, contextRefs);
  }
  if (!every(response.effect_refs, allowed.effect_refs)) return false;
  switch (response.action.action_kind) {
    case "command":
      return allowed.program_refs.has(response.action.program_ref)
        && allowed.argument_refs.has(response.action.arguments_ref)
        && allowed.path_refs.has(response.action.cwd_ref);
    case "file":
      return allowed.path_refs.has(response.action.path_ref)
        && (response.action.content_ref === null || allowed.content_refs.has(response.action.content_ref));
    case "tool":
      return allowed.tool_refs.has(response.action.tool_ref)
        && allowed.argument_refs.has(response.action.arguments_ref);
    case "connector":
      return allowed.connector_refs.has(response.action.connector_ref)
        && allowed.account_refs.has(response.action.account_ref)
        && allowed.operation_refs.has(response.action.operation_ref)
        && allowed.target_refs.has(response.action.target_ref);
    case "network":
      return allowed.origin_refs.has(response.action.origin_ref)
        && allowed.path_refs.has(response.action.path_ref)
        && (response.action.body_ref === null || allowed.body_refs.has(response.action.body_ref));
  }
}

export async function runBrokeredModelExecutorV01(
  context: unknown,
  adapter: SyntheticBrokeredModelExecutorAdapterV01,
): Promise<BrokeredModelExecutorResultV01> {
  const capturedContext = captureBounded(context);
  if (!capturedContext.ok) return Object.freeze({ ok: false, error: "MODEL_CONTEXT_INVALID" });
  const parsedContext = ApprovedModelContextSchemaV01.safeParse(capturedContext.value);
  if (!parsedContext.success) return Object.freeze({ ok: false, error: "MODEL_CONTEXT_INVALID" });
  const invoke = syntheticAdapters.get(adapter);
  if (invoke === undefined) return Object.freeze({ ok: false, error: "MODEL_ADAPTER_INVALID" });
  let rawResponse: unknown;
  try {
    rawResponse = await invoke(deepFreeze(parsedContext.data));
  } catch {
    return Object.freeze({ ok: false, error: "MODEL_ADAPTER_FAILURE" });
  }
  const capturedResponse = captureBounded(rawResponse);
  if (!capturedResponse.ok) return Object.freeze({ ok: false, error: "MODEL_RESPONSE_INVALID" });
  const parsedResponse = ModelResponseSchemaV01.safeParse(capturedResponse.value);
  if (!parsedResponse.success) return Object.freeze({ ok: false, error: "MODEL_RESPONSE_INVALID" });
  if (parsedResponse.data.kind === "action-proposal" && parsedResponse.data.task_ref !== parsedContext.data.task_ref) {
    return Object.freeze({ ok: false, error: "MODEL_RESPONSE_INVALID" });
  }
  if (!responseReferencesAreRegistered(parsedContext.data, parsedResponse.data)) {
    return Object.freeze({ ok: false, error: "MODEL_RESPONSE_INVALID" });
  }
  return Object.freeze({ ok: true, value: deepFreeze(parsedResponse.data) });
}
