import { isProxy } from "node:util/types";

import { z } from "zod";

import { hashCanonical } from "../hash.js";
import { MachineIdV02 } from "../schema/scalars-v02.js";
import { RuntimeEventV04, type RuntimeEventV04Value } from "../schema/runtime-v04.js";
import { inspectRuntimePlanV03, type ValidatedRuntimePlanV03 } from "./project-plan-v03.js";
import {
  consumeRuntimeClockObservationV04,
  type CapturedRuntimeClockObservationV04,
} from "./runtime-clock-observation-v04.js";
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

const CompensationWriteInputV04 = z.object({
  projection: z.custom<RuntimeTerminalProjectionV04>(),
  observation: z.custom<CapturedRuntimeClockObservationV04>(),
  event_id: MachineIdV02,
}).strict();

export type RuntimeCompensationWriteActionV04 =
  | "COMPENSATION_REQUESTED"
  | "COMPENSATION_REQUEST_REVISED"
  | "COMPENSATION_ENTERED"
  | "COMPENSATION_ESCALATED"
  | "COMPENSATION_SETTLED";

export type RuntimeCompensationWriteV04Result =
  | Readonly<{
      ok: true;
      classification: "COMMITTED";
      action: RuntimeCompensationWriteActionV04;
      compensation_event_ref: LedgerRef;
      projection_hash: string;
      ledger_bytes_hash: string;
      manifest_hash: string;
    }>
  | Readonly<{
      ok: false;
      classification: "NOT_COMMITTED" | "OUTCOME_UNKNOWN";
      error:
        | "RUNTIME_COMPENSATION_INPUT_INVALID"
        | "RUNTIME_COMPENSATION_PREFIX_INVALID"
        | "RUNTIME_COMPENSATION_REFUSED"
        | "RUNTIME_COMPENSATION_NOT_COMMITTED"
        | "RUNTIME_COMPENSATION_OUTCOME_UNKNOWN";
      decision?: string;
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

function capturedFilesWithLedger(snapshot: RuntimeFileStoreSessionSnapshotV04, ledgerBytes: Uint8Array) {
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

function projectionMatchesStore(projection: RuntimeTerminalProjectionV04, inspected: InspectedStore): boolean {
  return projection.run_id === inspected.plan.run_id
    && projection.run_id === inspected.ledger.run_id
    && projection.plan_hash === inspected.plan.plan_hash
    && projection.plan_hash === inspected.ledger.plan_hash
    && projection.ledger_sequence === inspected.ledger.sequence
    && projection.ledger_head_hash === inspected.ledger.head_hash
    && projection.current_fence_epoch === inspected.ledger.state.current_fence_epoch;
}

function maximumObservedElapsed(ledger: ValidatedRuntimeLedgerV04): number {
  let maximum = 0;
  for (const row of ledger.events) {
    if (row.event_type === "run.clock-observed") maximum = Math.max(maximum, row.payload.elapsed_ms);
  }
  return maximum;
}

function makeEvent(
  inspected: InspectedStore,
  eventId: string,
  recordedAt: string,
  decision: ReturnType<typeof evaluateRuntimeTerminalV04>,
): Readonly<{ action: RuntimeCompensationWriteActionV04; event: RuntimeEventV04Value }> | null {
  const selected = (() => {
    switch (decision.decision) {
      case "request-compensation":
        return {
          action: "COMPENSATION_REQUESTED" as const,
          event_type: "run.compensation-requested" as const,
          payload: {
            revision: decision.request_revision,
            pending_terminal: decision.pending_terminal,
            activation_reason: decision.activation_reason,
            compensation_refs: decision.compensation_refs,
            effect_evidence_refs: decision.effect_evidence_refs,
            freeze_event_hash: decision.freeze_event_hash,
          },
        };
      case "revise-compensation-request":
        return {
          action: "COMPENSATION_REQUEST_REVISED" as const,
          event_type: "run.compensation-request-revised" as const,
          payload: {
            revision: decision.request_revision,
            previous_pending_terminal: decision.previous_pending_terminal,
            pending_terminal: decision.pending_terminal,
            activation_reason: decision.activation_reason,
            compensation_refs: decision.compensation_refs,
            added_compensation_refs: decision.added_compensation_refs,
            previous_request_event_hash: decision.previous_request_event_hash,
            freeze_event_hash: decision.freeze_event_hash,
            effect_evidence_refs: decision.effect_evidence_refs,
          },
        };
      case "enter-compensation":
        return {
          action: "COMPENSATION_ENTERED" as const,
          event_type: "run.compensation-phase-entered" as const,
          payload: {
            request_revision: decision.request_revision,
            request_event_hash: decision.request_event_hash,
            pending_terminal: decision.pending_terminal,
            compensation_refs: decision.compensation_refs,
            freeze_event_hash: decision.freeze_event_hash,
          },
        };
      case "escalate-compensation":
        return {
          action: "COMPENSATION_ESCALATED" as const,
          event_type: "run.compensation-candidate-escalated" as const,
          payload: {
            previous_pending_terminal: decision.previous_pending_terminal,
            pending_terminal: decision.pending_terminal,
            activation_reason: decision.activation_reason,
            compensation_refs: decision.compensation_refs,
            previous_candidate_event_hash: decision.previous_candidate_event_hash,
            candidate_evidence_refs: decision.candidate_evidence_refs,
          },
        };
      case "settle-compensation":
        return {
          action: "COMPENSATION_SETTLED" as const,
          event_type: "compensation.settled" as const,
          payload: {
            compensation_ref: decision.settlement.ref,
            status: decision.settlement.status,
            unable_reason: decision.settlement.unable_reason,
            evidence_refs: decision.settlement.evidence_refs,
          },
        };
      default:
        return null;
    }
  })();
  if (selected === null) return null;
  const sequence = inspected.ledger.sequence + 1;
  const preimage = {
    schema_version: "0.4" as const,
    event_id: eventId,
    run_id: inspected.ledger.run_id,
    sequence,
    recorded_at: recordedAt,
    event_type: selected.event_type,
    source: "evaluator" as const,
    authority_ref: null,
    risk_tier: "T1" as const,
    related_ids: [],
    previous_event_hash: inspected.ledger.head_hash,
    payload: selected.payload,
  };
  const parsed = RuntimeEventV04.safeParse({ ...preimage, event_hash: hashCanonical(preimage) });
  return parsed.success ? Object.freeze({ action: selected.action, event: parsed.data }) : null;
}

function nextState(
  inspected: InspectedStore,
  appended: RuntimeEventV04Value,
): Readonly<{ ledger_bytes: Uint8Array; manifest_bytes: Uint8Array }> | null {
  const tail = new TextEncoder().encode(`${JSON.stringify(appended)}\n`);
  const ledgerBytes = new Uint8Array(inspected.snapshot.ledger_bytes.byteLength + tail.byteLength);
  ledgerBytes.set(inspected.snapshot.ledger_bytes, 0);
  ledgerBytes.set(tail, inspected.snapshot.ledger_bytes.byteLength);
  if (!inspectRuntimeLedgerV04(ledgerBytes).ok) return null;
  const built = buildRunManifestV04({
    ledger_bytes: ledgerBytes,
    created_at: inspected.manifest.created_at,
    captured_files: capturedFilesWithLedger(inspected.snapshot, ledgerBytes),
  });
  return built.ok ? Object.freeze({ ledger_bytes: ledgerBytes, manifest_bytes: built.bytes }) : null;
}

function refused(
  error: Extract<RuntimeCompensationWriteV04Result, { ok: false }>["error"],
  projectionHash?: string,
  decision?: string,
): Extract<RuntimeCompensationWriteV04Result, { ok: false }> {
  return Object.freeze({
    ok: false,
    classification: "NOT_COMMITTED",
    error,
    ...(projectionHash === undefined ? {} : { projection_hash: projectionHash }),
    ...(decision === undefined ? {} : { decision }),
  });
}

export async function writeRuntimeCompensationV04(
  store: CapturedRuntimeFileStoreV04,
  input: unknown,
): Promise<RuntimeCompensationWriteV04Result> {
  if (exactPlainObject(input, ["projection", "observation", "event_id"]) === null) {
    return refused("RUNTIME_COMPENSATION_INPUT_INVALID");
  }
  const parsed = CompensationWriteInputV04.safeParse(input);
  if (!parsed.success || !isRuntimeTerminalProjectionV04(parsed.data.projection)) {
    return refused("RUNTIME_COMPENSATION_INPUT_INVALID");
  }
  const projectionHash = hashRuntimeTerminalProjectionV04(parsed.data.projection);
  const decision = evaluateRuntimeTerminalV04(parsed.data.projection);
  const opened = await openRuntimeFileStoreSessionV04(store);
  if (!opened.ok) {
    return opened.error === "RUNTIME_FILE_STORE_POISONED"
      ? Object.freeze({
          ok: false,
          classification: "OUTCOME_UNKNOWN",
          error: "RUNTIME_COMPENSATION_OUTCOME_UNKNOWN",
          projection_hash: projectionHash,
        })
      : refused("RUNTIME_COMPENSATION_PREFIX_INVALID", projectionHash);
  }
  try {
    const inspected = inspectStoreSnapshot(opened.session);
    if (inspected === null || !projectionMatchesStore(parsed.data.projection, inspected)) {
      return refused("RUNTIME_COMPENSATION_PREFIX_INVALID", projectionHash);
    }
    const observation = consumeRuntimeClockObservationV04(parsed.data.observation);
    if (observation === null
      || observation.elapsed_ms < maximumObservedElapsed(inspected.ledger)
      || Date.parse(observation.observed_at) < Date.parse(inspected.ledger.events.at(-1)!.recorded_at)) {
      return refused("RUNTIME_COMPENSATION_INPUT_INVALID", projectionHash);
    }
    const selected = makeEvent(inspected, parsed.data.event_id, observation.observed_at, decision);
    if (selected === null) {
      return refused("RUNTIME_COMPENSATION_REFUSED", projectionHash, decision.decision);
    }
    const next = nextState(inspected, selected.event);
    if (next === null) return refused("RUNTIME_COMPENSATION_PREFIX_INVALID", projectionHash);
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
            error: "RUNTIME_COMPENSATION_OUTCOME_UNKNOWN",
            projection_hash: projectionHash,
          })
        : refused("RUNTIME_COMPENSATION_NOT_COMMITTED", projectionHash);
    }
    return Object.freeze({
      ok: true,
      classification: "COMMITTED",
      action: selected.action,
      compensation_event_ref: Object.freeze({
        ledger_sequence: selected.event.sequence,
        event_hash: selected.event.event_hash,
      }),
      projection_hash: projectionHash,
      ledger_bytes_hash: committed.ledger_bytes_hash,
      manifest_hash: committed.manifest_hash,
    });
  } finally {
    await closeRuntimeFileStoreSessionV04(opened.session);
  }
}
