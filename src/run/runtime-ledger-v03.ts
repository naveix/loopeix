import { parseDocument } from "yaml";

import { hashCanonical, hashRawBytes } from "../hash.js";
import { RuntimeEventV03, type RuntimeEventV03Value } from "../schema/runtime-v03.js";
import { validateRuntimeLedgerHistoryV02 } from "./runtime-ledger-v02.js";
import { reduceRuntimeEventPrefixV03, type RuntimeStateV03 } from "./runtime-state-reducer-v03.js";

const MAX_LEDGER_BYTES = 67_108_864;
const MAX_EVENT_BYTES = 4_194_304;
const MAX_EVENTS = 100_000;

export type RuntimeLedgerV03FailureReason =
  | "LEDGER_SYNTAX_INVALID"
  | "LEDGER_EVENT_SCHEMA_INVALID"
  | "LEDGER_HASH_CHAIN_INVALID"
  | "LEDGER_HISTORY_INVALID"
  | "LEDGER_TRANSITION_INVALID";

export type RuntimeLedgerV03Issue = Readonly<{ path: string; message: string }>;

export type ValidatedRuntimeLedgerV03 = Readonly<{
  readonly __validated_runtime_ledger_v03: unique symbol;
  run_id: string;
  plan_hash: string;
  events: readonly RuntimeEventV03Value[];
  sequence: number;
  head_hash: string;
  ledger_bytes_hash: string;
  sealed: boolean;
  state: RuntimeStateV03;
}>;

export type RuntimeLedgerV03ValidationResult =
  | Readonly<{ ok: true; ledger: ValidatedRuntimeLedgerV03; state: RuntimeStateV03 }>
  | Readonly<{ ok: false; reason: RuntimeLedgerV03FailureReason; issues: readonly RuntimeLedgerV03Issue[] }>;

function failure(
  reason: RuntimeLedgerV03FailureReason,
  path: string,
  message: string,
): Extract<RuntimeLedgerV03ValidationResult, { ok: false }> {
  return { ok: false, reason, issues: [{ path, message }] };
}

function refKey(sequence: number, eventHash: string): string {
  return `${sequence}\0${eventHash}`;
}

function collectLedgerRefs(value: unknown, path: string, refs: Array<{ sequence: number; eventHash: string; path: string }>): void {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => collectLedgerRefs(entry, `${path}[${index}]`, refs));
    return;
  }
  if (typeof value !== "object" || value === null) return;
  const record = value as Record<string, unknown>;
  if (Number.isSafeInteger(record.ledger_sequence) && typeof record.event_hash === "string") {
    refs.push({ sequence: record.ledger_sequence as number, eventHash: record.event_hash, path });
    return;
  }
  for (const [key, entry] of Object.entries(record)) collectLedgerRefs(entry, `${path}.${key}`, refs);
}

function freezeDeep<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) freezeDeep(child);
  return Object.freeze(value);
}

type RuntimeLedgerV03HistoryValidationResult =
  | Readonly<{ ok: true; state: RuntimeStateV03; runId: string; planHash: string }>
  | Extract<RuntimeLedgerV03ValidationResult, { ok: false }>;

function validateRuntimeLedgerHistoryV03(events: readonly RuntimeEventV03Value[]): RuntimeLedgerV03HistoryValidationResult {
  const first = events[0];
  if (first?.event_type !== "run.initialized") {
    return failure("LEDGER_HISTORY_INVALID", "event[0]", "A V03 primary ledger must begin with run.initialized.");
  }

  const eventIds = new Set<string>();
  const earlier = new Set<string>();
  for (const [index, event] of events.entries()) {
    if (event.sequence !== index + 1) {
      return failure("LEDGER_HASH_CHAIN_INVALID", `event[${index}].sequence`, `Expected contiguous sequence ${index + 1}.`);
    }
    const expectedPrevious = index === 0 ? null : events[index - 1]!.event_hash;
    if (event.previous_event_hash !== expectedPrevious) {
      return failure("LEDGER_HASH_CHAIN_INVALID", `event[${index}].previous_event_hash`, "previous_event_hash does not match the prior event.");
    }
    const { event_hash: eventHash, ...preimage } = event;
    if (hashCanonical(preimage) !== eventHash) {
      return failure("LEDGER_HASH_CHAIN_INVALID", `event[${index}].event_hash`, "event_hash does not match the RFC 8785 event preimage.");
    }
    if (event.run_id !== first.run_id) {
      return failure("LEDGER_HISTORY_INVALID", `event[${index}].run_id`, "Every event must belong to the initialized run.");
    }
    if (eventIds.has(event.event_id)) {
      return failure("LEDGER_HISTORY_INVALID", `event[${index}].event_id`, "event_id must be unique in the run.");
    }
    eventIds.add(event.event_id);
    const payload = event.payload as unknown as Record<string, unknown>;
    if (typeof payload.run_id === "string" && payload.run_id !== first.run_id) {
      return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.run_id`, "Copied payload run_id must equal the initialized run.");
    }
    if (typeof payload.plan_hash === "string" && payload.plan_hash !== first.payload.plan_hash) {
      return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload.plan_hash`, "Copied payload plan_hash must equal the initialized plan.");
    }
    const refs: Array<{ sequence: number; eventHash: string; path: string }> = [];
    collectLedgerRefs(event.payload, `event[${index}].payload`, refs);
    for (const ref of refs) {
      if (ref.sequence >= event.sequence || !earlier.has(refKey(ref.sequence, ref.eventHash))) {
        return failure("LEDGER_HISTORY_INVALID", ref.path, "Ledger reference must resolve to an exact earlier V03 event.");
      }
    }
    if (event.event_type === "run.terminal-sealed") {
      const previous = events[index - 1];
      if (previous === undefined
        || event.payload.pre_seal_ledger_sequence !== previous.sequence
        || event.payload.pre_seal_ledger_head_hash !== previous.event_hash) {
        return failure("LEDGER_HISTORY_INVALID", `event[${index}].payload`, "Terminal seal must bind and immediately succeed the exact pre-seal V03 prefix.");
      }
    }
    earlier.add(refKey(event.sequence, event.event_hash));
  }

  const inheritedHistoryFailure = validateRuntimeLedgerHistoryV02(events);
  if (inheritedHistoryFailure !== null) {
    return failure("LEDGER_HISTORY_INVALID", inheritedHistoryFailure.issues[0]?.path ?? "(root)", inheritedHistoryFailure.issues[0]?.message ?? "Inherited V02 history is invalid.");
  }
  const reduction = reduceRuntimeEventPrefixV03(events);
  if (!reduction.ok) return failure("LEDGER_TRANSITION_INVALID", reduction.path, reduction.message);
  return { ok: true, state: reduction.state, runId: first.run_id, planHash: first.payload.plan_hash };
}

type RuntimeLedgerV03EventsValidationResult =
  | Readonly<{ ok: true; events: readonly RuntimeEventV03Value[]; state: RuntimeStateV03; runId: string; planHash: string }>
  | Extract<RuntimeLedgerV03ValidationResult, { ok: false }>;

function validateRuntimeLedgerEventsV03(input: readonly unknown[]): RuntimeLedgerV03EventsValidationResult {
  const events: RuntimeEventV03Value[] = [];
  for (const [index, value] of input.entries()) {
    const parsed = RuntimeEventV03.safeParse(value);
    if (!parsed.success) {
      return {
        ok: false,
        reason: "LEDGER_EVENT_SCHEMA_INVALID",
        issues: parsed.error.issues.map((issue) => ({
          path: `event[${index}]${issue.path.length === 0 ? "" : `.${issue.path.map(String).join(".")}`}`,
          message: issue.message,
        })),
      };
    }
    events.push(parsed.data);
  }
  const history = validateRuntimeLedgerHistoryV03(events);
  if (!history.ok) return history;
  return { ok: true, events, state: history.state, runId: history.runId, planHash: history.planHash };
}

function parseAndValidateRuntimeLedgerTextV03(text: string, bytes: Uint8Array): RuntimeLedgerV03ValidationResult {
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_LEDGER_BYTES || !text.endsWith("\n")) {
    return failure("LEDGER_SYNTAX_INVALID", "(root)", "A bounded V03 ledger must be non-empty and newline-terminated.");
  }
  const lines = text.slice(0, -1).split("\n");
  if (lines.length === 0 || lines.length > MAX_EVENTS || lines.some((line) => line.length === 0 || Buffer.byteLength(line, "utf8") > MAX_EVENT_BYTES)) {
    return failure("LEDGER_SYNTAX_INVALID", "(root)", "Every bounded JSONL line must contain exactly one event.");
  }
  const values: unknown[] = [];
  for (const [index, line] of lines.entries()) {
    try {
      const duplicateCheck = parseDocument(line, { uniqueKeys: true });
      if (duplicateCheck.errors.length > 0) {
        return failure("LEDGER_SYNTAX_INVALID", `line[${index + 1}]`, "JSON line contains duplicate keys or invalid framing.");
      }
      values.push(JSON.parse(line) as unknown);
    } catch {
      return failure("LEDGER_SYNTAX_INVALID", `line[${index + 1}]`, "JSON line is invalid.");
    }
  }
  const parsed = validateRuntimeLedgerEventsV03(values);
  if (!parsed.ok) return parsed;
  const frozenEvents = Object.freeze(parsed.events.map((event) => freezeDeep(event)));
  const ledger = Object.freeze({
    run_id: parsed.runId,
    plan_hash: parsed.planHash,
    events: frozenEvents,
    sequence: frozenEvents.length,
    head_hash: frozenEvents.at(-1)!.event_hash,
    ledger_bytes_hash: hashRawBytes(bytes),
    sealed: frozenEvents.at(-1)?.event_type === "run.terminal-sealed",
    state: parsed.state,
  }) as ValidatedRuntimeLedgerV03;
  return { ok: true, ledger, state: parsed.state };
}

function captureRuntimeLedgerBytesV03(input: unknown): Uint8Array | null {
  try {
    if (!(input instanceof Uint8Array) || Object.getPrototypeOf(input) !== Uint8Array.prototype) return null;
    if (input.byteLength === 0 || input.byteLength > MAX_LEDGER_BYTES || input.buffer instanceof SharedArrayBuffer) return null;
    return new Uint8Array(input);
  } catch {
    return null;
  }
}

export function inspectRuntimeLedgerV03(input: Uint8Array): RuntimeLedgerV03ValidationResult {
  const bytes = captureRuntimeLedgerBytesV03(input);
  if (bytes === null) return failure("LEDGER_SYNTAX_INVALID", "(root)", "Runtime ledger input must be an owned Uint8Array byte view.");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return failure("LEDGER_SYNTAX_INVALID", "(root)", "Runtime ledger bytes must be valid UTF-8.");
  }
  return parseAndValidateRuntimeLedgerTextV03(text, bytes);
}
