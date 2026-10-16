import { hashRawBytes } from "../hash.js";
import type {
  CapturedAuthorityTrustContextV02,
  RuntimeEventV02Value,
  TerminalEvaluationResultV02Value,
  TerminalObservationSnapshotV02,
  TerminalSnapshotInvalidReasonV02,
  ValidatedRuntimeProjectionInputV02,
} from "../schema/runtime.js";
import { RuntimeEventV02 as RuntimeEventSchemaV02 } from "../schema/runtime.js";
import type { RuntimeEventV04Value } from "../schema/runtime-v04.js";
import { isValidatedRuntimePlanV03, type ValidatedRuntimePlanV03 } from "./project-plan-v03.js";
import { isValidatedRuntimeLedgerV04, type ValidatedRuntimeLedgerV04 } from "./runtime-ledger-v04.js";
import {
  captureValidatedRunManifestFileV04,
  isValidatedRunManifestPairV04,
  type ValidatedRunManifestV04,
} from "./runtime-manifest-v04.js";
import {
  admitRuntimeRecordsV02,
  isCapturedAuthorityTrustContextV02,
  verifyAdmittedAuthorityTrustRecordsV02,
} from "./runtime-record-admission-v02.js";
import { evaluateTerminalDecisionTableV02 } from "./terminal-evaluator.js";
import {
  buildTerminalObservationSnapshotCoreV02,
  hashTerminalObservationSnapshotCoreV02,
  type AdmittedRuntimeProjectionFactsV02,
} from "./terminal-snapshot.js";

export type RuntimeTerminalProjectionV04 = TerminalObservationSnapshotV02 & Readonly<{
  readonly __runtime_terminal_projection_v04: unique symbol;
}>;

export type RuntimeTerminalProjectionV04Result =
  | Readonly<{ ok: true; value: RuntimeTerminalProjectionV04 }>
  | Readonly<{
      ok: false;
      reason:
        | "RUNTIME_TERMINAL_INPUT_INVALID"
        | "RUNTIME_TERMINAL_LINEAGE_INVALID"
        | "RUNTIME_TERMINAL_RECORD_ADMISSION_INVALID"
        | "RUNTIME_TERMINAL_AUTHORITY_TRUST_INVALID"
        | "RUNTIME_TERMINAL_SNAPSHOT_INVALID";
      snapshot_reason?: TerminalSnapshotInvalidReasonV02;
    }>;

type TerminalSourceV04 = Readonly<{
  validated_plan: ValidatedRuntimePlanV03;
  ledger: ValidatedRuntimeLedgerV04;
  manifest: ValidatedRunManifestV04;
  authority_trust_context: CapturedAuthorityTrustContextV02;
}>;

const projectionSources = new WeakMap<object, ValidatedRuntimeProjectionInputV02>();
const V02_INVENTORY_FROM_V04 = Object.freeze({
  resolved_run_plan: "0.2",
  ledger_event: "0.2",
  run_manifest: "0.2",
  artifact_manifest: "0.2",
  redaction_derivative: "0.2",
  human_authorization_proof: "0.2",
  authority_envelope: "0.2",
  agency_recommendation: "0.2",
  authority_revocation: "0.2",
  task_result: "0.2",
  manual_observation: "0.2",
  export_decision: "0.2",
  evidence_item: "0.2",
  gate_result: "0.2",
  evaluation_result: "0.2",
  claim: "0.2",
  finding: "0.2",
  waiver: "0.2",
  gate_waiver_authority: "0.2",
});

function exactSource(value: unknown): TerminalSourceV04 | null {
  try {
    if (typeof value !== "object" || value === null || Object.getPrototypeOf(value) !== Object.prototype) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Object.keys(descriptors).sort();
    if (keys.join("|") !== ["authority_trust_context", "ledger", "manifest", "validated_plan"].join("|")) return null;
    if (Object.values(descriptors).some((descriptor) => !("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined)) return null;
    return Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [key, descriptor.value])) as TerminalSourceV04;
  } catch {
    return null;
  }
}

function projectTerminalEventToV02(event: RuntimeEventV04Value): RuntimeEventV02Value | null {
  const candidate = (() => {
    switch (event.event_type) {
      case "run.initialized":
        return {
          ...event,
          schema_version: "0.2" as const,
          payload: {
            ...event.payload,
            runtime_schema_versions: V02_INVENTORY_FROM_V04,
          },
        };
      case "run.clock-observed":
        if (
          event.payload.reason !== "action-admission"
          && event.payload.reason !== "retry-check"
          && event.payload.reason !== "waiver-boundary"
          && event.payload.reason !== "terminal-use"
        ) {
          return null;
        }
        return {
          ...event,
          schema_version: "0.2" as const,
          payload: {
            clock_id: event.payload.clock_id,
            observed_at: event.payload.observed_at,
            elapsed_ms: event.payload.elapsed_ms,
            reason: event.payload.reason,
            task_ref: event.payload.task_ref,
            failure_ordinal: event.payload.failure_ordinal,
            use_ref: event.payload.use_ref,
          },
        };
      case "lease.issued": {
        const {
          attempt_event_ref: _attemptEventRef,
          parent_run_owner_lease_id: _parentRunOwnerLeaseId,
          logical_operation_idempotency_key: _logicalOperationIdempotencyKey,
          resolved_operation_input_hash: _resolvedOperationInputHash,
          recovery_policy_hash: _recoveryPolicyHash,
          process_runtime_ceiling_ms: _processRuntimeCeilingMs,
          ...payload
        } = event.payload;
        return { ...event, schema_version: "0.2" as const, payload };
      }
      case "task.action-admitted": {
        const {
          attempt_event_ref: _attemptEventRef,
          parent_run_owner_lease_id: _parentRunOwnerLeaseId,
          logical_operation_idempotency_key: _logicalOperationIdempotencyKey,
          resolved_operation_input_hash: _resolvedOperationInputHash,
          recovery_policy_hash: _recoveryPolicyHash,
          process_runtime_ceiling_ms: _processRuntimeCeilingMs,
          ...payload
        } = event.payload;
        return { ...event, schema_version: "0.2" as const, payload };
      }
      case "task.execution-completed": {
        const {
          attempt_event_ref: _attemptEventRef,
          process_runtime_ms: _processRuntimeMs,
          loop_attempts_after: _loopAttemptsAfter,
          task_executions_after: _taskExecutionsAfter,
          workers_after: _workersAfter,
          ...payload
        } = event.payload;
        return { ...event, schema_version: "0.2" as const, payload };
      }
      case "task.execution-failed": {
        const {
          attempt_event_ref: _attemptEventRef,
          process_runtime_ms: _processRuntimeMs,
          loop_attempts_after: _loopAttemptsAfter,
          task_executions_after: _taskExecutionsAfter,
          workers_after: _workersAfter,
          ...payload
        } = event.payload;
        return { ...event, schema_version: "0.2" as const, payload };
      }
      case "task.action-outcome-reconciled":
        if (event.payload.reconciliation_status === "proven-non-start") return null;
        return { ...event, schema_version: "0.2" as const, payload: event.payload };
      case "effect.outcome": {
        const { reconciliation_event_ref: _reconciliationEventRef, ...payload } = event.payload;
        return { ...event, schema_version: "0.2" as const, payload };
      }
      case "run.fence-advanced": {
        const projectedReason = event.payload.reason === "authority-revoked"
          ? "operator-revoked"
          : event.payload.reason === "lease-revoked"
            ? "lease-revoked"
            : "recovery-boundary";
        return {
          ...event,
          schema_version: "0.2" as const,
          payload: {
            previous_fence_epoch: event.payload.previous_fence_epoch,
            fence_epoch: event.payload.fence_epoch,
            reason: projectedReason,
            evidence_refs: event.payload.evidence_refs,
          },
        };
      }
      default:
        return { ...event, schema_version: "0.2" as const };
    }
  })();
  if (candidate === null) return null;
  const projected = RuntimeEventSchemaV02.safeParse(candidate);
  return projected.success ? projected.data : null;
}

function v02Events(events: readonly RuntimeEventV04Value[]): readonly RuntimeEventV02Value[] {
  const projected: RuntimeEventV02Value[] = [];
  for (const event of events) {
    const admitted = projectTerminalEventToV02(event);
    if (admitted !== null) projected.push(admitted);
  }
  return Object.freeze(projected);
}

export function isRuntimeTerminalProjectionV04(value: unknown): value is RuntimeTerminalProjectionV04 {
  return typeof value === "object" && value !== null && projectionSources.has(value);
}

export function buildRuntimeTerminalProjectionV04(input: unknown): RuntimeTerminalProjectionV04Result {
  try {
    const source = exactSource(input);
    if (source === null
      || !isValidatedRuntimePlanV03(source.validated_plan)
      || !isValidatedRuntimeLedgerV04(source.ledger)
      || !isValidatedRunManifestPairV04(source.manifest, source.ledger)
      || !isCapturedAuthorityTrustContextV02(source.authority_trust_context)) {
      return { ok: false, reason: "RUNTIME_TERMINAL_INPUT_INVALID" };
    }
    const { validated_plan: plan, ledger, manifest } = source;
    const initialized = ledger.events[0];
    if (initialized?.event_type !== "run.initialized"
      || plan.run_id !== ledger.run_id || plan.run_id !== manifest.run_id
      || plan.plan_hash !== ledger.plan_hash || plan.plan_hash !== manifest.plan_hash
      || initialized.payload.plan_hash !== plan.plan_hash
      || manifest.ledger_sequence !== ledger.sequence
      || manifest.ledger_head_hash !== ledger.head_hash
      || manifest.ledger_bytes_hash !== ledger.ledger_bytes_hash
      || manifest.current_fence_epoch !== ledger.state.current_fence_epoch) {
      return { ok: false, reason: "RUNTIME_TERMINAL_LINEAGE_INVALID" };
    }

    const recordBytes = new Map<string, Uint8Array>();
    for (const row of manifest.file_inventory) {
      if (row.family !== "record" || !row.exists) continue;
      const captured = captureValidatedRunManifestFileV04(manifest, row.path);
      if (!captured.ok || captured.bytes === null) {
        return { ok: false, reason: "RUNTIME_TERMINAL_RECORD_ADMISSION_INVALID" };
      }
      recordBytes.set(row.path, captured.bytes);
    }
    const events = v02Events(ledger.events);
    const records = admitRuntimeRecordsV02({
      events,
      run_id: plan.run_id,
      plan_hash: plan.plan_hash,
      record_bytes_by_path: recordBytes,
      raw_hash_by_path: new Map([...recordBytes].map(([path, bytes]) => [path, hashRawBytes(bytes)])),
    });
    if (!records.ok) return { ok: false, reason: "RUNTIME_TERMINAL_RECORD_ADMISSION_INVALID" };
    if (!verifyAdmittedAuthorityTrustRecordsV02(
      source.authority_trust_context,
      records.value.records_by_path,
      events,
    ).ok) return { ok: false, reason: "RUNTIME_TERMINAL_AUTHORITY_TRUST_INVALID" };

    const projection = Object.freeze({
      plan: plan.plan,
      run_id: plan.run_id,
      plan_hash: plan.plan_hash,
      ledger_sequence: ledger.sequence,
      ledger_head_hash: ledger.head_hash,
      completed_loop_attempts: ledger.events.filter((event) => event.event_type === "loop.attempt-completed").length,
      observations: events.filter((event) => event.event_type === "task.progress-observed"),
      events,
    }) as unknown as ValidatedRuntimeProjectionInputV02;
    const facts: AdmittedRuntimeProjectionFactsV02 = Object.freeze({
      controlPlaneConsumedBytes: ledger.ledger_byte_length,
      ledgerLineBytes: ledger.line_byte_lengths,
      decodedRecordsByPath: records.value.records_by_path,
    });
    const built = buildTerminalObservationSnapshotCoreV02(projection, facts, false);
    if (!built.ok) {
      return { ok: false, reason: "RUNTIME_TERMINAL_SNAPSHOT_INVALID", snapshot_reason: built.error };
    }
    const value = built.value as RuntimeTerminalProjectionV04;
    projectionSources.set(value, projection);
    return Object.freeze({ ok: true, value });
  } catch {
    return { ok: false, reason: "RUNTIME_TERMINAL_INPUT_INVALID" };
  }
}

export function hashRuntimeTerminalProjectionV04(projection: RuntimeTerminalProjectionV04): string {
  if (!isRuntimeTerminalProjectionV04(projection)) throw new TypeError("unbranded V04 terminal projection");
  return hashTerminalObservationSnapshotCoreV02(projection);
}

export function evaluateRuntimeTerminalV04(projection: RuntimeTerminalProjectionV04): TerminalEvaluationResultV02Value {
  const source = typeof projection === "object" && projection !== null
    ? projectionSources.get(projection)
    : undefined;
  if (source === undefined) throw new TypeError("unbranded V04 terminal projection");
  return evaluateTerminalDecisionTableV02(projection, source);
}
