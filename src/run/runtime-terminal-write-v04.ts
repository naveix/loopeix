import { isProxy } from "node:util/types";

import { z } from "zod";

import { hashCanonical } from "../hash.js";
import { MachineIdV02 } from "../schema/scalars-v02.js";
import { RuntimeEventV04, type RuntimeEventV04Value } from "../schema/runtime-v04.js";
import { inspectRuntimePlanV03, type ValidatedRuntimePlanV03 } from "./project-plan-v03.js";
import {
  closeRuntimeFileStoreSessionV04,
  commitRuntimeFileStoreSessionV04,
  openRuntimeFileStoreSessionV04,
  readRuntimeFileStoreSessionSnapshotV04,
  type CapturedRuntimeFileStoreV04,
  type RuntimeFileStoreSessionSnapshotV04,
  type RuntimeFileStoreSessionV04,
} from "./runtime-file-store-v04.js";
import { inspectRuntimeLedgerV04, type ValidatedRuntimeLedgerV04 } from "./runtime-ledger-v04.js";
import {
  buildRunManifestV04,
  inspectRunManifestV04,
  type ValidatedRunManifestV04,
} from "./runtime-manifest-v04.js";
import {
  consumeRuntimeClockObservationV04,
  type CapturedRuntimeClockObservationV04,
} from "./runtime-clock-observation-v04.js";
import {
  evaluateRuntimeTerminalV04,
  hashRuntimeTerminalProjectionV04,
  isRuntimeTerminalProjectionV04,
  type RuntimeTerminalProjectionV04,
} from "./runtime-terminal-v04.js";

type LedgerRef = Readonly<{ ledger_sequence: number; event_hash: string }>;
type InspectedStore = Readonly<{
  snapshot: RuntimeFileStoreSessionSnapshotV04;
  plan: ValidatedRuntimePlanV03;
  ledger: ValidatedRuntimeLedgerV04;
  manifest: ValidatedRunManifestV04;
}>;

const TerminalWriteInputV04 = z.object({
  projection: z.custom<RuntimeTerminalProjectionV04>(),
  observation: z.custom<CapturedRuntimeClockObservationV04>(),
  event_id: MachineIdV02,
}).strict();

export type RuntimeTerminalWriteV04Result =
  | Readonly<{
      ok: true;
      classification: "COMMITTED";
      action: "FREEZE_ENTERED" | "FREEZE_REVISED" | "SEALED";
      terminal_event_ref: LedgerRef;
      projection_hash: string;
      ledger_bytes_hash: string;
      manifest_hash: string;
    }>
  | Readonly<{
      ok: true;
      classification: "ALREADY_SEALED";
      action: "ALREADY_SEALED";
      projection_hash: string;
      outcome: RuntimeTerminalProjectionV04["terminal_seal"] extends infer T
        ? T extends Readonly<{ outcome: infer O }> ? O : never
        : never;
      seal_event_ref: LedgerRef;
      fence_epoch: number;
      pre_seal_snapshot_hash: string;
    }>
  | Readonly<{
      ok: false;
      classification: "NOT_COMMITTED" | "OUTCOME_UNKNOWN";
      error:
        | "RUNTIME_TERMINAL_INPUT_INVALID"
        | "RUNTIME_TERMINAL_PREFIX_INVALID"
        | "RUNTIME_TERMINAL_REFUSED"
        | "RUNTIME_TERMINAL_NOT_COMMITTED"
        | "RUNTIME_TERMINAL_OUTCOME_UNKNOWN";
      refusal_reason?: string;
      projection_hash?: string;
    }>;

function exactPlainObject(value: unknown, keys: readonly string[]): Record<string, unknown> | null {
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value) || isProxy(value)
      || Object.getPrototypeOf(value) !== Object.prototype
      || Reflect.ownKeys(value).some((key) => typeof key !== "string")) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Object.keys(descriptors).sort().join("\0") !== [...keys].sort().join("\0")) return null;
    for (const descriptor of Object.values(descriptors)) {
      if (!("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined
        || descriptor.enumerable !== true) return null;
    }
    return Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [key, descriptor.value]));
  } catch {
    return null;
  }
}

function hasSafeInputShape(value: unknown): boolean {
  return exactPlainObject(value, ["projection", "observation", "event_id"]) !== null;
}

function refOf(event: Readonly<{ sequence: number; event_hash: string }>): LedgerRef {
  return Object.freeze({ ledger_sequence: event.sequence, event_hash: event.event_hash });
}

function capturedFilesWithLedger(
  snapshot: RuntimeFileStoreSessionSnapshotV04,
  ledgerBytes: Uint8Array,
) {
  return snapshot.captured_files.map((file) => Object.freeze({
    path: file.path,
    family: file.family,
    required: file.required,
    mode: file.path === "ledger.jsonl" ? 384 as const : file.mode,
    bytes: file.path === "ledger.jsonl"
      ? new Uint8Array(ledgerBytes)
      : file.bytes === null ? null : new Uint8Array(file.bytes),
  }));
}

function inspectStoreSnapshot(session: RuntimeFileStoreSessionV04): InspectedStore | null {
  const read = readRuntimeFileStoreSessionSnapshotV04(session);
  if (!read.ok) return null;
  const plan = inspectRuntimePlanV03(read.snapshot.resolved_run_plan_bytes);
  const ledger = inspectRuntimeLedgerV04(read.snapshot.ledger_bytes);
  if (!plan.ok || !ledger.ok) return null;
  const manifest = inspectRunManifestV04({
    manifest_bytes: read.snapshot.manifest_bytes,
    ledger_bytes: read.snapshot.ledger_bytes,
    captured_files: capturedFilesWithLedger(read.snapshot, read.snapshot.ledger_bytes),
  });
  if (!manifest.ok
    || plan.validated_plan.run_id !== ledger.ledger.run_id
    || plan.validated_plan.plan_hash !== ledger.ledger.plan_hash
    || manifest.manifest.run_id !== ledger.ledger.run_id
    || manifest.manifest.plan_hash !== ledger.ledger.plan_hash) return null;
  return Object.freeze({
    snapshot: read.snapshot,
    plan: plan.validated_plan,
    ledger: manifest.ledger,
    manifest: manifest.validated_manifest,
  });
}

function event(
  prior: readonly RuntimeEventV04Value[],
  eventId: string,
  recordedAt: string,
  eventType: RuntimeEventV04Value["event_type"],
  payload: unknown,
): RuntimeEventV04Value | null {
  const sequence = prior.length + 1;
  const preimage = {
    schema_version: "0.4" as const,
    event_id: eventId,
    run_id: prior[0]!.run_id,
    sequence,
    recorded_at: recordedAt,
    event_type: eventType,
    source: "evaluator" as const,
    authority_ref: null,
    risk_tier: "T1" as const,
    related_ids: [],
    previous_event_hash: prior.at(-1)!.event_hash,
    payload,
  };
  const parsed = RuntimeEventV04.safeParse({ ...preimage, event_hash: hashCanonical(preimage) });
  return parsed.success ? parsed.data : null;
}

function appendLedgerBytes(source: Uint8Array, events: readonly RuntimeEventV04Value[]): Uint8Array {
  const tail = new TextEncoder().encode(events.map((row) => `${JSON.stringify(row)}\n`).join(""));
  const joined = new Uint8Array(source.byteLength + tail.byteLength);
  joined.set(source, 0);
  joined.set(tail, source.byteLength);
  return joined;
}

function nextState(
  inspected: InspectedStore,
  events: readonly RuntimeEventV04Value[],
): Readonly<{ ledger_bytes: Uint8Array; manifest_bytes: Uint8Array }> | null {
  const ledgerBytes = appendLedgerBytes(inspected.snapshot.ledger_bytes, events);
  const ledgerInspection = inspectRuntimeLedgerV04(ledgerBytes);
  if (!ledgerInspection.ok) return null;
  const built = buildRunManifestV04({
    ledger_bytes: ledgerBytes,
    created_at: inspected.manifest.created_at,
    captured_files: capturedFilesWithLedger(inspected.snapshot, ledgerBytes),
  });
  return built.ok ? Object.freeze({ ledger_bytes: ledgerBytes, manifest_bytes: built.bytes }) : null;
}

function maximumObservedElapsed(ledger: ValidatedRuntimeLedgerV04): number {
  let maximum = 0;
  for (const row of ledger.events) {
    if (row.event_type === "run.clock-observed") maximum = Math.max(maximum, row.payload.elapsed_ms);
  }
  return maximum;
}

function latestFreeze(ledger: ValidatedRuntimeLedgerV04) {
  for (let index = ledger.events.length - 1; index >= 0; index -= 1) {
    const candidate = ledger.events[index]!;
    if (candidate.event_type === "run.terminal-freeze-entered" || candidate.event_type === "run.terminal-freeze-revised") {
      return candidate;
    }
  }
  return null;
}

function projectionMatchesStore(projection: RuntimeTerminalProjectionV04, inspected: InspectedStore): boolean {
  if (projection.run_id !== inspected.plan.run_id
    || projection.run_id !== inspected.ledger.run_id
    || projection.plan_hash !== inspected.plan.plan_hash
    || projection.plan_hash !== inspected.ledger.plan_hash
    || projection.ledger_sequence !== inspected.ledger.sequence
    || projection.ledger_head_hash !== inspected.ledger.head_hash
    || projection.current_fence_epoch !== inspected.ledger.state.current_fence_epoch) {
    return false;
  }
  const actualFreeze = latestFreeze(inspected.ledger);
  const projectedFreeze = projection.terminal_freeze;
  if ((actualFreeze === null) !== (projectedFreeze === null)) return false;
  if (actualFreeze !== null) {
    if (projectedFreeze === null
      || projectedFreeze.ledger_sequence !== actualFreeze.sequence
      || projectedFreeze.event_hash !== actualFreeze.event_hash
      || projectedFreeze.revision !== actualFreeze.payload.revision
      || projectedFreeze.candidate !== actualFreeze.payload.candidate) return false;
  }
  const lastEvent = inspected.ledger.events.at(-1);
  const actualSeal = lastEvent?.event_type === "run.terminal-sealed" ? lastEvent : null;
  const projectedSeal = projection.terminal_seal;
  if ((actualSeal === null) !== (projectedSeal === null)) return false;
  if (actualSeal !== null) {
    if (projectedSeal === null
      || projectedSeal.ledger_sequence !== actualSeal.sequence
      || projectedSeal.event_hash !== actualSeal.event_hash
      || projectedSeal.outcome !== actualSeal.payload.outcome
      || projectedSeal.fence_epoch !== actualSeal.payload.fence_epoch
      || projectedSeal.pre_seal_ledger_sequence !== actualSeal.payload.pre_seal_ledger_sequence
      || projectedSeal.pre_seal_ledger_head_hash !== actualSeal.payload.pre_seal_ledger_head_hash
      || projectedSeal.pre_seal_snapshot_hash !== actualSeal.payload.pre_seal_snapshot_hash) return false;
  }
  return true;
}

function notCommitted(error: Extract<RuntimeTerminalWriteV04Result, { ok: false }>["error"], projectionHash?: string, refusalReason?: string) {
  return Object.freeze({
    ok: false,
    classification: "NOT_COMMITTED" as const,
    error,
    ...(projectionHash === undefined ? {} : { projection_hash: projectionHash }),
    ...(refusalReason === undefined ? {} : { refusal_reason: refusalReason }),
  });
}

function decisionRefusalReason(decision: ReturnType<typeof evaluateRuntimeTerminalV04>): string {
  if (decision.decision === "continue") return decision.continuation;
  return decision.decision;
}

function freezeEvent(
  inspected: InspectedStore,
  recordedAt: string,
  eventId: string,
  decision: ReturnType<typeof evaluateRuntimeTerminalV04>,
): RuntimeEventV04Value | null {
  if (decision.decision === "freeze-work") {
    return event(inspected.ledger.events, eventId, recordedAt, "run.terminal-freeze-entered", {
      revision: 1,
      candidate: decision.candidate,
      candidate_evidence_refs: decision.candidate_evidence_refs,
      fence_epoch: inspected.ledger.state.current_fence_epoch,
    });
  }
  if (decision.decision === "revise-terminal-freeze") {
    return event(inspected.ledger.events, eventId, recordedAt, "run.terminal-freeze-revised", {
      revision: decision.freeze_revision,
      previous_candidate: decision.previous_candidate,
      candidate: decision.candidate,
      previous_freeze_event_hash: decision.previous_freeze_event_hash,
      candidate_evidence_refs: decision.candidate_evidence_refs,
    });
  }
  if (decision.decision === "seal") {
    return event(inspected.ledger.events, eventId, recordedAt, "run.terminal-sealed", {
      outcome: decision.outcome,
      pre_seal_ledger_sequence: decision.expected_ledger_sequence,
      pre_seal_ledger_head_hash: decision.expected_ledger_head_hash,
      pre_seal_snapshot_hash: decision.pre_seal_snapshot_hash,
      previous_fence_epoch: decision.current_fence_epoch,
      fence_epoch: decision.next_fence_epoch,
    });
  }
  return null;
}

export async function writeRuntimeTerminalV04(
  store: CapturedRuntimeFileStoreV04,
  input: unknown,
): Promise<RuntimeTerminalWriteV04Result> {
  if (!hasSafeInputShape(input)) {
    return notCommitted("RUNTIME_TERMINAL_INPUT_INVALID");
  }
  const parsed = TerminalWriteInputV04.safeParse(input);
  if (!parsed.success
    || !isRuntimeTerminalProjectionV04(parsed.data.projection)) {
    return notCommitted("RUNTIME_TERMINAL_INPUT_INVALID");
  }
  const projectionHash = hashRuntimeTerminalProjectionV04(parsed.data.projection);
  const decision = evaluateRuntimeTerminalV04(parsed.data.projection);

  const opened = await openRuntimeFileStoreSessionV04(store);
  if (!opened.ok) {
    return opened.error === "RUNTIME_FILE_STORE_POISONED"
      ? Object.freeze({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_TERMINAL_OUTCOME_UNKNOWN", projection_hash: projectionHash })
      : notCommitted("RUNTIME_TERMINAL_PREFIX_INVALID", projectionHash);
  }
  try {
    const inspected = inspectStoreSnapshot(opened.session);
    if (inspected === null || !projectionMatchesStore(parsed.data.projection, inspected)) {
      return notCommitted("RUNTIME_TERMINAL_PREFIX_INVALID", projectionHash);
    }
    if (decision.decision === "already-sealed") {
      const seal = inspected.ledger.events.at(-1);
      if (seal?.event_type !== "run.terminal-sealed") {
        return notCommitted("RUNTIME_TERMINAL_PREFIX_INVALID", projectionHash);
      }
      return Object.freeze({
        ok: true,
        classification: "ALREADY_SEALED",
        action: "ALREADY_SEALED",
        projection_hash: projectionHash,
        outcome: decision.outcome,
        seal_event_ref: refOf(seal),
        fence_epoch: decision.fence_epoch,
        pre_seal_snapshot_hash: decision.pre_seal_snapshot_hash,
      });
    }
    const observation = consumeRuntimeClockObservationV04(parsed.data.observation);
    if (observation === null) {
      return notCommitted("RUNTIME_TERMINAL_INPUT_INVALID", projectionHash);
    }
    if (observation.elapsed_ms < maximumObservedElapsed(inspected.ledger)
      || Date.parse(observation.observed_at) < Date.parse(inspected.ledger.events.at(-1)!.recorded_at)) {
      return notCommitted("RUNTIME_TERMINAL_INPUT_INVALID", projectionHash);
    }
    if (decision.decision === "continue"
      || decision.decision === "request-compensation"
      || decision.decision === "revise-compensation-request"
      || decision.decision === "enter-compensation"
      || decision.decision === "escalate-compensation"
      || decision.decision === "settle-compensation") {
      return notCommitted("RUNTIME_TERMINAL_REFUSED", projectionHash, decisionRefusalReason(decision));
    }

    const terminalEvent = freezeEvent(inspected, observation.observed_at, parsed.data.event_id, decision);
    if (terminalEvent === null) {
      return notCommitted("RUNTIME_TERMINAL_PREFIX_INVALID", projectionHash);
    }

    const next = nextState(inspected, [terminalEvent]);
    if (next === null) {
      return notCommitted("RUNTIME_TERMINAL_PREFIX_INVALID", projectionHash);
    }
    const committed = await commitRuntimeFileStoreSessionV04(opened.session, {
      expected_ledger_bytes_hash: inspected.ledger.ledger_bytes_hash,
      expected_manifest_hash: inspected.manifest.manifest_hash,
      next_ledger_bytes: next.ledger_bytes,
      next_manifest_bytes: next.manifest_bytes,
    });
    if (!committed.ok) {
      return committed.classification === "OUTCOME_UNKNOWN"
        ? Object.freeze({
            ok: false,
            classification: "OUTCOME_UNKNOWN",
            error: "RUNTIME_TERMINAL_OUTCOME_UNKNOWN",
            projection_hash: projectionHash,
          })
        : notCommitted("RUNTIME_TERMINAL_NOT_COMMITTED", projectionHash);
    }
    return Object.freeze({
      ok: true,
      classification: "COMMITTED",
      action: decision.decision === "freeze-work"
        ? "FREEZE_ENTERED"
        : decision.decision === "revise-terminal-freeze" ? "FREEZE_REVISED" : "SEALED",
      terminal_event_ref: refOf(terminalEvent),
      projection_hash: projectionHash,
      ledger_bytes_hash: committed.ledger_bytes_hash,
      manifest_hash: committed.manifest_hash,
    });
  } finally {
    await closeRuntimeFileStoreSessionV04(opened.session);
  }
}
