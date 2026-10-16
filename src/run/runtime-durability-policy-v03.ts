import { z } from "zod";

import { canonicalize, hashBytes, hashCanonical } from "../hash.js";
import { Hash } from "../schema/scalars.js";

const MAX_LEDGER_BYTES = 67_108_864;
const MAX_EVENT_BYTES = 1_048_576;
const utf8Bounded = (maximum: number) => z.string().refine(
  (value) => Buffer.byteLength(value, "utf8") <= maximum,
  { message: `must not exceed ${maximum} UTF-8 bytes` },
);

const safeInteger = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const HeadV03 = z.object({
  sequence: safeInteger,
  event_hash: Hash.nullable(),
  ledger_bytes_hash: Hash,
}).strict().superRefine((head, ctx) => {
  if ((head.sequence === 0) !== (head.event_hash === null)) {
    ctx.addIssue({ code: "custom", path: ["event_hash"], message: "only an empty ledger has a null event hash" });
  }
});

const DurabilityStepV03 = z.discriminatedUnion("step", [
  z.object({ step: z.literal("prefix-validation"), outcome: z.enum(["accepted", "rejected-before-write"]) }).strict(),
  z.object({ step: z.literal("append-write"), outcome: z.enum(["zero-bytes-confirmed", "complete", "partial-or-unknown"]) }).strict(),
  z.object({ step: z.literal("prior-state-revalidated"), outcome: z.enum(["exact", "drifted-or-unknown"]) }).strict(),
  z.object({ step: z.literal("ledger-sync"), outcome: z.enum(["confirmed", "failed-or-unknown"]) }).strict(),
  z.object({ step: z.literal("ledger-readback"), outcome: z.enum(["exact", "drifted-or-unknown"]) }).strict(),
  z.object({ step: z.literal("head-publish"), outcome: z.enum(["complete", "failed-or-unknown"]) }).strict(),
  z.object({ step: z.literal("directory-sync"), outcome: z.enum(["confirmed", "failed-or-unknown"]) }).strict(),
  z.object({ step: z.literal("final-readback"), outcome: z.enum(["exact", "drifted-or-unknown"]) }).strict(),
]);

const RuntimeDurabilityObservationV03 = z.object({
  policy_version: z.literal("0.1"),
  prior_head: HeadV03,
  target_head: HeadV03,
  prior_ledger_text: utf8Bounded(MAX_LEDGER_BYTES),
  event_line: z.object({
    bytes: utf8Bounded(MAX_EVENT_BYTES),
    bytes_hash: Hash,
    byte_length: z.number().int().positive().max(MAX_EVENT_BYTES),
  }).strict(),
  steps: z.array(DurabilityStepV03).min(1).max(7),
}).strict().superRefine((value, ctx) => {
  if (value.prior_head.sequence >= Number.MAX_SAFE_INTEGER || value.target_head.sequence !== value.prior_head.sequence + 1) {
    ctx.addIssue({ code: "custom", path: ["target_head", "sequence"], message: "target sequence must increment the prior head exactly once" });
  }
  const names = value.steps.map((step) => step.step);
  if (new Set(names).size !== names.length) ctx.addIssue({ code: "custom", path: ["steps"], message: "durability steps must not repeat" });
});

const EventLineV03 = z.object({
  bytes: utf8Bounded(MAX_EVENT_BYTES),
  bytes_hash: Hash,
  byte_length: z.number().int().positive().max(MAX_EVENT_BYTES),
}).strict();

const RuntimeDurabilityPairObservationV03 = z.object({
  policy_version: z.literal("0.2"),
  prior_head: HeadV03,
  target_head: HeadV03,
  prior_ledger_text: utf8Bounded(MAX_LEDGER_BYTES),
  event_lines: z.tuple([EventLineV03, EventLineV03]),
  steps: z.array(DurabilityStepV03).min(1).max(7),
}).strict().superRefine((value, ctx) => {
  if (value.prior_head.sequence > Number.MAX_SAFE_INTEGER - 2
    || value.target_head.sequence !== value.prior_head.sequence + 2) {
    ctx.addIssue({ code: "custom", path: ["target_head", "sequence"], message: "target sequence must increment the prior head exactly twice" });
  }
  const names = value.steps.map((step) => step.step);
  if (new Set(names).size !== names.length) ctx.addIssue({ code: "custom", path: ["steps"], message: "durability steps must not repeat" });
});

export type RuntimeDurabilityClassificationV03 =
  | Readonly<{ classification: "COMMITTED"; reason: "DURABLE_EXACT_READBACK" }>
  | Readonly<{ classification: "NOT_COMMITTED"; reason: "REJECTED_BEFORE_WRITE" }>
  | Readonly<{ classification: "OUTCOME_UNKNOWN"; reason: "OBSERVATIONS_INVALID" | "DURABILITY_UNCONFIRMED" }>;

const COMMITTED = Object.freeze({ classification: "COMMITTED" as const, reason: "DURABLE_EXACT_READBACK" as const });
const REJECTED = Object.freeze({ classification: "NOT_COMMITTED" as const, reason: "REJECTED_BEFORE_WRITE" as const });
const INVALID = Object.freeze({ classification: "OUTCOME_UNKNOWN" as const, reason: "OBSERVATIONS_INVALID" as const });
const UNKNOWN = Object.freeze({ classification: "OUTCOME_UNKNOWN" as const, reason: "DURABILITY_UNCONFIRMED" as const });

type SnapshotResult = Readonly<{ ok: true; value: unknown }> | Readonly<{ ok: false }>;

function snapshot(value: unknown, depth = 0, state: { nodes: number } = { nodes: 0 }): SnapshotResult {
  state.nodes += 1;
  if (depth > 16 || state.nodes > 1_000) return { ok: false };
  if (value === null || typeof value === "string" || typeof value === "boolean") return { ok: true, value };
  if (typeof value === "number") return Number.isFinite(value) ? { ok: true, value } : { ok: false };
  if (typeof value !== "object") return { ok: false };
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) return { ok: false };
      const descriptors = Object.getOwnPropertyDescriptors(value);
      if (Reflect.ownKeys(value).some((key) => typeof key !== "string")
        || Object.keys(descriptors).some((key) => key !== "length" && !/^\d+$/u.test(key))) return { ok: false };
      const output: unknown[] = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (descriptor === undefined || !("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined) return { ok: false };
        const child = snapshot(descriptor.value, depth + 1, state);
        if (!child.ok) return child;
        output.push(child.value);
      }
      return { ok: true, value: output };
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return { ok: false };
    if (Reflect.ownKeys(value).some((key) => typeof key !== "string")) return { ok: false };
    const output: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
      if (!("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined || descriptor.enumerable !== true) return { ok: false };
      const child = snapshot(descriptor.value, depth + 1, state);
      if (!child.ok) return child;
      output[key] = child.value;
    }
    return { ok: true, value: output };
  } catch {
    return { ok: false };
  }
}

function stepKey(step: z.infer<typeof DurabilityStepV03>): string {
  return `${step.step}:${step.outcome}`;
}

function exactBindingsHold(value: z.infer<typeof RuntimeDurabilityObservationV03>): boolean {
  if (hashBytes(value.prior_ledger_text) !== value.prior_head.ledger_bytes_hash
    || hashBytes(value.event_line.bytes) !== value.event_line.bytes_hash
    || Buffer.byteLength(value.event_line.bytes, "utf8") !== value.event_line.byte_length
    || hashBytes(`${value.prior_ledger_text}${value.event_line.bytes}`) !== value.target_head.ledger_bytes_hash
    || !value.event_line.bytes.endsWith("\n")
    || value.event_line.bytes.slice(0, -1).includes("\n")) return false;

  if (value.prior_head.sequence === 0) {
    if (value.prior_ledger_text !== "") return false;
  } else {
    if (!value.prior_ledger_text.endsWith("\n")) return false;
    const priorLines = value.prior_ledger_text.slice(0, -1).split("\n");
    const priorLine = priorLines.at(-1);
    if (priorLine === undefined || priorLine.length === 0) return false;
    try {
      const priorEvent = JSON.parse(priorLine) as Record<string, unknown>;
      if (priorEvent.sequence !== value.prior_head.sequence
        || priorEvent.event_hash !== value.prior_head.event_hash) return false;
    } catch {
      return false;
    }
  }

  try {
    const event = JSON.parse(value.event_line.bytes.slice(0, -1)) as Record<string, unknown>;
    if (typeof event !== "object" || event === null || Array.isArray(event)
      || event.sequence !== value.target_head.sequence
      || event.event_hash !== value.target_head.event_hash
      || event.previous_event_hash !== value.prior_head.event_hash) return false;
    const { event_hash: eventHash, ...preimage } = event;
    return typeof eventHash === "string" && hashCanonical(preimage) === eventHash;
  } catch {
    return false;
  }
}

function exactPairBindingsHold(value: z.infer<typeof RuntimeDurabilityPairObservationV03>): boolean {
  const [firstLine, secondLine] = value.event_lines;
  if (hashBytes(value.prior_ledger_text) !== value.prior_head.ledger_bytes_hash
    || hashBytes(firstLine.bytes) !== firstLine.bytes_hash
    || hashBytes(secondLine.bytes) !== secondLine.bytes_hash
    || Buffer.byteLength(firstLine.bytes, "utf8") !== firstLine.byte_length
    || Buffer.byteLength(secondLine.bytes, "utf8") !== secondLine.byte_length
    || hashBytes(`${value.prior_ledger_text}${firstLine.bytes}${secondLine.bytes}`) !== value.target_head.ledger_bytes_hash
    || !firstLine.bytes.endsWith("\n") || firstLine.bytes.slice(0, -1).includes("\n")
    || !secondLine.bytes.endsWith("\n") || secondLine.bytes.slice(0, -1).includes("\n")) return false;
  if (value.prior_head.sequence === 0) {
    if (value.prior_ledger_text !== "") return false;
  } else {
    if (!value.prior_ledger_text.endsWith("\n")) return false;
    const priorLine = value.prior_ledger_text.slice(0, -1).split("\n").at(-1);
    if (priorLine === undefined || priorLine.length === 0) return false;
    try {
      const priorEvent = JSON.parse(priorLine) as Record<string, unknown>;
      if (priorEvent.sequence !== value.prior_head.sequence || priorEvent.event_hash !== value.prior_head.event_hash) return false;
    } catch {
      return false;
    }
  }
  try {
    const first = JSON.parse(firstLine.bytes.slice(0, -1)) as Record<string, unknown>;
    const second = JSON.parse(secondLine.bytes.slice(0, -1)) as Record<string, unknown>;
    if (`${canonicalize(first)}\n` !== firstLine.bytes || `${canonicalize(second)}\n` !== secondLine.bytes) return false;
    const { event_hash: firstHash, ...firstPreimage } = first;
    const { event_hash: secondHash, ...secondPreimage } = second;
    return first.sequence === value.prior_head.sequence + 1
      && first.previous_event_hash === value.prior_head.event_hash
      && typeof firstHash === "string" && hashCanonical(firstPreimage) === firstHash
      && second.sequence === value.prior_head.sequence + 2
      && second.previous_event_hash === firstHash
      && typeof secondHash === "string" && hashCanonical(secondPreimage) === secondHash
      && value.target_head.event_hash === secondHash;
  } catch {
    return false;
  }
}

export function classifyRuntimeDurabilityV03(input: unknown): RuntimeDurabilityClassificationV03 {
  const captured = snapshot(input);
  if (!captured.ok) return INVALID;
  const parsed = RuntimeDurabilityObservationV03.safeParse(captured.value);
  if (!parsed.success) return INVALID;
  if (!exactBindingsHold(parsed.data)) return INVALID;
  const steps = parsed.data.steps.map(stepKey);
  if (steps.length === 1 && steps[0] === "prefix-validation:rejected-before-write") return REJECTED;
  if (steps.join("|") === [
    "prefix-validation:accepted",
    "append-write:complete",
    "ledger-sync:confirmed",
    "ledger-readback:exact",
    "head-publish:complete",
    "directory-sync:confirmed",
    "final-readback:exact",
  ].join("|")) return COMMITTED;
  return UNKNOWN;
}

export function classifyRuntimeDurabilityPairV03(input: unknown): RuntimeDurabilityClassificationV03 {
  const captured = snapshot(input);
  if (!captured.ok) return INVALID;
  const parsed = RuntimeDurabilityPairObservationV03.safeParse(captured.value);
  if (!parsed.success || !exactPairBindingsHold(parsed.data)) return INVALID;
  const steps = parsed.data.steps.map(stepKey);
  if (steps.length === 1 && steps[0] === "prefix-validation:rejected-before-write") return REJECTED;
  if (steps.join("|") === [
    "prefix-validation:accepted",
    "append-write:complete",
    "ledger-sync:confirmed",
    "ledger-readback:exact",
    "head-publish:complete",
    "directory-sync:confirmed",
    "final-readback:exact",
  ].join("|")) return COMMITTED;
  return UNKNOWN;
}
