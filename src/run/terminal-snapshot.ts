import { hashCanonical, hashRawBytes } from "../hash.js";
import { isCapturedRunFileMetadataV02 } from "../io/runtime-file-capture-v02.js";
import { decodeStructuredDocumentV02 } from "../schema/decode-envelope.js";
import {
  ArtifactManifestV02,
  RunManifestV02,
} from "../schema/runtime-manifests-v02.js";
import {
  ResolvedRunPlanV02,
  type CapturedAuthorityTrustContextV02,
  type LedgerRefV02Value,
  type ProgressObservationEvaluationV02Value,
  type RuntimeProjectionErrorV02,
  type RuntimeProjectionInputV02,
  type RuntimeResult,
  type TerminalObservationSnapshotV02,
  type TerminalSnapshotInvalidReasonV02,
  type ValidatedRuntimeProjectionInputV02,
} from "../schema/runtime.js";
import {
  parseAndValidateRuntimeLedgerStructureV02,
} from "./runtime-ledger-v02.js";
import { deriveProgressV02ForRuntime } from "./progress-evaluator.js";
import {
  admitRuntimeRecordsV02,
  isCapturedAuthorityTrustContextV02,
  verifyAdmittedAuthorityTrustRecordsV02,
} from "./runtime-record-admission-v02.js";
import { deriveCompensationProjectionV02 } from "./compensation-projection-v02.js";
import { projectApplicabilityAndDueV02 } from "./applicability-projection-v02.js";
import { deriveFailurePolicyProjectionV02 } from "./failure-policy-projection-v02.js";

const MAX_STRUCTURED_MEMBER_BYTES = 4_194_304;
const SYNTHETIC_TRUST_FIXTURE = "s35-valid-complete-authority-trust-v01" as const;

const trustedContexts = new WeakSet<object>();
const validatedInputs = new WeakSet<object>();
const terminalSnapshots = new WeakSet<object>();
const terminalSnapshotInputs = new WeakMap<object, ValidatedRuntimeProjectionInputV02>();
type AdmittedCompensationProjectionV02 = Extract<
  ReturnType<typeof deriveCompensationProjectionV02>,
  { ok: true }
>;
const terminalSnapshotCompensationFacts = new WeakMap<object, AdmittedCompensationProjectionV02>();
export type AdmittedRuntimeProjectionFactsV02 = Readonly<{
  controlPlaneConsumedBytes: number;
  ledgerLineBytes: readonly number[];
  /** Exact decoded record facts, populated only after record-family admission. */
  decodedRecordsByPath: ReadonlyMap<string, unknown>;
}>;
const projectionRuntimeFacts = new WeakMap<object, AdmittedRuntimeProjectionFactsV02>();

function failure<T>(error: RuntimeProjectionErrorV02): RuntimeResult<T, RuntimeProjectionErrorV02> {
  return { ok: false, error };
}

function ownDataProperty(object: object, key: PropertyKey): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  if (descriptor === undefined || !("value" in descriptor)) throw new TypeError("not an own data property");
  return descriptor.value;
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
    const length = byteLength === undefined ? view.byteLength : byteLength.call(view);
    return length;
  } catch {
    return null;
  }
}

function fixedCopy(value: unknown): Uint8Array | null {
  try {
    const length = fixedViewLength(value);
    if (length === null) return null;
    const view = value as Uint8Array;
    const copy = new Uint8Array(length);
    copy.set(Uint8Array.prototype.subarray.call(view, 0, length));
    return copy;
  } catch {
    return null;
  }
}

function captureMap(value: unknown): Array<readonly [string, unknown]> | null {
  try {
    if (Object.getPrototypeOf(value) !== Map.prototype) return null;
    const rows = Array.from(Map.prototype.entries.call(value as Map<unknown, unknown>)) as Array<[unknown, unknown]>;
    if (rows.some(([key]) => typeof key !== "string")) return null;
    return rows as Array<readonly [string, unknown]>;
  } catch {
    return null;
  }
}

function compareUtf8(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function decodeUtf8(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

function sameCanonicalValue(left: unknown, right: unknown): boolean {
  try {
    return hashCanonical(left) === hashCanonical(right);
  } catch {
    return false;
  }
}

function eventRef(event: ValidatedRuntimeProjectionInputV02["events"][number]) {
  return { ledger_sequence: event.sequence, event_hash: event.event_hash };
}

function sameLedgerRef(
  left: { ledger_sequence: number; event_hash: string },
  right: { ledger_sequence: number; event_hash: string },
): boolean {
  return left.ledger_sequence === right.ledger_sequence && left.event_hash === right.event_hash;
}

function usesAttemptAwareRecoveryV04(
  input: ValidatedRuntimeProjectionInputV02,
): boolean {
  const plan = input.plan as Record<string, unknown>;
  return typeof plan.runtime_input_hash === "string"
    && typeof plan.runtime_recovery_policy_hash === "string";
}

function uniqueLedgerRefs(
  refs: readonly Readonly<{ ledger_sequence: number; event_hash: string }>[],
) {
  const unique: LedgerRefV02Value[] = [];
  for (const ref of refs) {
    if (unique.some((candidate) => sameLedgerRef(candidate, ref))) continue;
    unique.push({ ledger_sequence: ref.ledger_sequence, event_hash: ref.event_hash });
  }
  return unique;
}

function isFailedFailureClass(failureClass: TerminalObservationSnapshotV02["active_failures"][number]["failure_class"]): boolean {
  return failureClass === "invalid-input"
    || failureClass === "verification-failed"
    || failureClass === "permanent-execution";
}

function progressObservationEvidenceRefs(
  observation: ProgressObservationEvaluationV02Value,
) {
  return uniqueLedgerRefs([
    ...(observation.baseline_ref === null ? [] : [observation.baseline_ref]),
    ...(observation.latest_ref === null ? [] : [observation.latest_ref]),
  ]);
}

function evaluationCountsAsCompleted(
  plan: ValidatedRuntimeProjectionInputV02["plan"],
  evaluation: TerminalObservationSnapshotV02["evaluations"][number],
): boolean {
  const definition = plan.evaluations.find((candidate) => candidate.id === evaluation.ref);
  if (definition === undefined) return false;
  if (!evaluation.applicable) return true;
  return evaluation.due && evaluation.status === "pass";
}

function taskCountsAsCompleted(
  plan: ValidatedRuntimeProjectionInputV02["plan"],
  task: TerminalObservationSnapshotV02["tasks"][number],
  activeCompensationActionTasks: ReadonlySet<string>,
): boolean {
  const definition = plan.tasks.find((candidate) => candidate.id === task.ref);
  if (definition === undefined) return false;
  if (definition.kind === "work") return task.status === "completed";
  return !activeCompensationActionTasks.has(task.ref) || task.status === "completed";
}

export function captureSyntheticAuthorityTrustContextForS35TestV02(
  fixture: typeof SYNTHETIC_TRUST_FIXTURE,
): CapturedAuthorityTrustContextV02 {
  if (fixture !== SYNTHETIC_TRUST_FIXTURE) throw new TypeError("unknown S35 trust fixture");
  const context = Object.freeze({ fixture }) as unknown as CapturedAuthorityTrustContextV02;
  trustedContexts.add(context);
  return context;
}

export function isValidatedRuntimeProjectionInputV02(
  input: unknown,
): input is ValidatedRuntimeProjectionInputV02 {
  return typeof input === "object" && input !== null && validatedInputs.has(input);
}

export function isTerminalObservationSnapshotV02(
  input: unknown,
): input is TerminalObservationSnapshotV02 {
  return typeof input === "object" && input !== null && terminalSnapshots.has(input);
}

/** Package-private evaluator bridge; intentionally absent from the package root. */
export function validatedProjectionForTerminalSnapshotV02(
  snapshot: TerminalObservationSnapshotV02,
): ValidatedRuntimeProjectionInputV02 | undefined {
  return terminalSnapshotInputs.get(snapshot);
}

/** Package-private evaluator bridge; intentionally absent from the package root. */
export function compensationFactsForTerminalSnapshotV02(
  snapshot: TerminalObservationSnapshotV02,
): AdmittedCompensationProjectionV02 | undefined {
  return terminalSnapshotCompensationFacts.get(snapshot);
}

/** Package-private exact hash projection used by terminal sealing and tests. */
export function hashTerminalObservationSnapshotV02(snapshot: TerminalObservationSnapshotV02): string {
  if (!isTerminalObservationSnapshotV02(snapshot)) throw new TypeError("unbranded terminal snapshot");
  return hashTerminalObservationSnapshotCoreV02(snapshot);
}

/** Package-private pure hash core; callers must enforce their own family brand. */
export function hashTerminalObservationSnapshotCoreV02(snapshot: TerminalObservationSnapshotV02): string {
  const { terminal_seal: _terminalSeal, ...projection } = snapshot;
  return hashCanonical({
    purpose: "pre-seal-terminal-observation-snapshot-v02",
    ...projection,
    terminal_seal: null,
  });
}

export function validateRuntimeProjectionInputV02(
  input: unknown,
): RuntimeResult<ValidatedRuntimeProjectionInputV02, RuntimeProjectionErrorV02> {
  try {
    if (Object.getPrototypeOf(input) !== Object.prototype) return failure("RUNTIME_INPUT_BYTE_VIEW_INVALID");
    const source = input as object;
    const planSource = ownDataProperty(source, "resolved_run_plan_bytes");
    const planBytes = fixedCopy(planSource);
    if (planBytes === null) return failure("RUNTIME_INPUT_BYTE_VIEW_INVALID");
    if (planBytes.byteLength > MAX_STRUCTURED_MEMBER_BYTES) return failure("RUNTIME_INPUT_RESOURCE_LIMIT");
    if (planBytes.at(-1) !== 0x0a) return failure("RESOLVED_RUN_PLAN_BYTES_INVALID");

    const decodedPlan = decodeStructuredDocumentV02(planBytes, "json");
    if (!decodedPlan.ok) return failure("RESOLVED_RUN_PLAN_BYTES_INVALID");
    const plan = ResolvedRunPlanV02.safeParse(decodedPlan.value);
    if (!plan.success) return failure("RESOLVED_RUN_PLAN_SCHEMA_INVALID");

    const recordRows = captureMap(ownDataProperty(source, "record_bytes_by_path"));
    const controlRows = captureMap(ownDataProperty(source, "control_projection_bytes_by_path"));
    const metadataRows = captureMap(ownDataProperty(source, "file_metadata_by_path"));
    if (recordRows === null || controlRows === null || metadataRows === null) {
      return failure("RUNTIME_SCHEMA_INVENTORY_INVALID");
    }
    const recordPaths = new Set(recordRows.map(([path]) => path));
    const controlPaths = new Set(controlRows.map(([path]) => path));
    if (recordPaths.size !== recordRows.length || controlPaths.size !== controlRows.length) {
      return failure("RUNTIME_SCHEMA_INVENTORY_INVALID");
    }
    if ([...recordPaths].some((path) => controlPaths.has(path))) return failure("RUNTIME_SCHEMA_INVENTORY_INVALID");

    const fixedOwners = ["resolved-run-plan.json", "ledger.jsonl", "run-manifest.json", "artifact-manifest.json"];
    const expectedMetadata = new Set([...fixedOwners, ...recordPaths, ...controlPaths]);
    if (metadataRows.length !== expectedMetadata.size || metadataRows.some(([path, metadata]) => !expectedMetadata.has(path) || !isCapturedRunFileMetadataV02(metadata))) {
      return failure("RUNTIME_SCHEMA_INVENTORY_INVALID");
    }

    const ledgerSource = ownDataProperty(source, "primary_ledger_bytes");
    const runManifestSource = ownDataProperty(source, "run_manifest_bytes");
    const artifactManifestSource = ownDataProperty(source, "artifact_manifest_bytes");
    const remainingSources = [ledgerSource, runManifestSource, artifactManifestSource, ...recordRows.map(([, bytes]) => bytes), ...controlRows.map(([, bytes]) => bytes)];
    const lengths: number[] = [];
    for (const value of remainingSources) {
      const length = fixedViewLength(value);
      if (length === null) return failure("RUNTIME_INPUT_BYTE_VIEW_INVALID");
      lengths.push(length);
    }
    let total = planBytes.byteLength;
    for (const length of lengths) {
      if (!Number.isSafeInteger(length) || length > MAX_STRUCTURED_MEMBER_BYTES || total > Number.MAX_SAFE_INTEGER - length) {
        return failure("RUNTIME_INPUT_RESOURCE_LIMIT");
      }
      total += length;
    }
    const maximum = MAX_STRUCTURED_MEMBER_BYTES + plan.data.required_control_plane_output_bytes + plan.data.limit_policy.max_output_bytes;
    if (!Number.isSafeInteger(maximum) || total > maximum) return failure("RUNTIME_INPUT_RESOURCE_LIMIT");

    const ledgerBytes = fixedCopy(ledgerSource)!;
    const runManifestBytes = fixedCopy(runManifestSource)!;
    const artifactManifestBytes = fixedCopy(artifactManifestSource)!;
    const copiedRecords = recordRows.sort(([left], [right]) => compareUtf8(left, right)).map(([path, bytes]) => [path, fixedCopy(bytes)!] as const);
    const copiedControls = controlRows.sort(([left], [right]) => compareUtf8(left, right)).map(([path, bytes]) => [path, fixedCopy(bytes)!] as const);
    const capturedBytes = new Map<string, Uint8Array>([
      ["resolved-run-plan.json", planBytes],
      ["ledger.jsonl", ledgerBytes],
      ["run-manifest.json", runManifestBytes],
      ["artifact-manifest.json", artifactManifestBytes],
      ...copiedRecords,
      ...copiedControls,
    ]);
    for (const [path, metadata] of metadataRows) {
      const bytes = capturedBytes.get(path);
      if (bytes === undefined || !isCapturedRunFileMetadataV02(metadata)
        || metadata.mode !== 384 || metadata.size_bytes !== bytes.byteLength
        || metadata.sha256 !== hashRawBytes(bytes)) {
        return failure("RUNTIME_SCHEMA_INVENTORY_INVALID");
      }
    }

    const runManifestDocument = decodeStructuredDocumentV02(runManifestBytes, "json");
    const artifactManifestDocument = decodeStructuredDocumentV02(artifactManifestBytes, "json");
    if (!runManifestDocument.ok || !artifactManifestDocument.ok) return failure("RUNTIME_SCHEMA_INVENTORY_INVALID");
    const runManifest = RunManifestV02.safeParse(runManifestDocument.value);
    const artifactManifest = ArtifactManifestV02.safeParse(artifactManifestDocument.value);
    if (!runManifest.success || !artifactManifest.success) {
      return failure("RUNTIME_SCHEMA_INVENTORY_INVALID");
    }

    const ledgerText = decodeUtf8(ledgerBytes);
    if (ledgerText === null) return failure("LEDGER_SYNTAX_INVALID");
    const structuralLedger = parseAndValidateRuntimeLedgerStructureV02(ledgerText);
    if (!structuralLedger.ok) {
      if (structuralLedger.reason === "LEDGER_SYNTAX_INVALID") return failure("LEDGER_SYNTAX_INVALID");
      if (structuralLedger.reason === "LEDGER_HASH_CHAIN_INVALID") return failure("LEDGER_HASH_CHAIN_INVALID");
      return failure("PLAN_OR_LEDGER_LINEAGE_INVALID");
    }
    const ledger = {
      events: structuralLedger.events,
      sealed: structuralLedger.events.at(-1)?.event_type === "run.terminal-sealed",
    } as const;

    const initialized = ledger.events[0];
    const terminalSealIndex = ledger.events.findIndex((event) => event.event_type === "run.terminal-sealed");
    const postSealEventsPresent = terminalSealIndex >= 0 && terminalSealIndex < ledger.events.length - 1;
    const manifestHead = postSealEventsPresent ? ledger.events[terminalSealIndex] : ledger.events.at(-1);
    const planHash = hashRawBytes(planBytes);
    if (
      initialized?.event_type !== "run.initialized"
      || ledger.events.some((event) => event.run_id !== initialized.run_id)
      || initialized.run_id !== plan.data.run_id
      || initialized.payload.plan_hash !== planHash
      || !sameCanonicalValue(initialized.payload.runtime_schema_versions, runManifest.data.schema_versions)
      || runManifest.data.run_id !== plan.data.run_id
      || runManifest.data.plan_hash !== planHash
      || runManifest.data.ledger_sequence !== manifestHead?.sequence
      || runManifest.data.ledger_head_hash !== manifestHead.event_hash
      || artifactManifest.data.run_id !== plan.data.run_id
      || artifactManifest.data.plan_hash !== planHash
      || artifactManifest.data.ledger_sequence !== manifestHead?.sequence
      || artifactManifest.data.ledger_head_hash !== manifestHead.event_hash
    ) {
      return failure("PLAN_OR_LEDGER_LINEAGE_INVALID");
    }

    // This positive path admits histories whose complete persisted inventory is
    // the fixed primary/projection set. Event families that name external records
    // remain closed until their exact family decoders are present below.
    if (controlRows.length !== 0 || artifactManifest.data.artifacts.length !== 0) {
      return failure("RUNTIME_SCHEMA_INVENTORY_INVALID");
    }
    const hasCompensationPhase = ledger.events.some((event) => event.event_type === "run.compensation-phase-entered");
    const hasFreeze = ledger.events.some((event) => event.event_type === "run.terminal-freeze-entered");
    const expectedRunState = terminalSealIndex >= 0
      ? "sealed"
      : hasCompensationPhase
        ? "compensating"
        : hasFreeze
          ? "frozen"
          : ledger.events.length === 1
            ? "initialized"
            : "running";
    if (runManifest.data.run_state !== expectedRunState) return failure("PLAN_OR_LEDGER_LINEAGE_INVALID");
    const copiedRecordMap = new Map(copiedRecords);
    const admittedRecords = admitRuntimeRecordsV02({
      events: ledger.events,
      run_id: plan.data.run_id,
      plan_hash: planHash,
      record_bytes_by_path: copiedRecordMap,
      raw_hash_by_path: new Map(copiedRecords.map(([path, bytes]) => [path, hashRawBytes(bytes)])),
    });
    if (!admittedRecords.ok) return failure(admittedRecords.reason);

    const expectedInventory: Array<readonly [string, "primary" | "record" | "projection", Uint8Array]> = [
      ["artifact-manifest.json", "projection", artifactManifestBytes],
      ["ledger.jsonl", "primary", ledgerBytes],
      ["resolved-run-plan.json", "primary", planBytes],
      ...admittedRecords.value.ordered_paths.map((path) => [path, "record" as const, copiedRecordMap.get(path)!] as const),
    ];
    expectedInventory.sort(([left], [right]) => compareUtf8(left, right));
    if (runManifest.data.file_inventory.length !== expectedInventory.length) {
      return failure("RUNTIME_SCHEMA_INVENTORY_INVALID");
    }
    for (const [index, [path, family, bytes]] of expectedInventory.entries()) {
      const row = runManifest.data.file_inventory[index];
      if (row === undefined || !row.exists || row.path !== path || row.family !== family
        || !row.required || row.mode !== 384 || row.size_bytes !== bytes.byteLength
        || row.hash !== hashRawBytes(bytes)) {
        return failure("RUNTIME_SCHEMA_INVENTORY_INVALID");
      }
    }
    const authorityTrustContext = ownDataProperty(source, "authority_trust_context");
    if (!(typeof authorityTrustContext === "object" && authorityTrustContext !== null
      && (trustedContexts.has(authorityTrustContext) || isCapturedAuthorityTrustContextV02(authorityTrustContext)))) {
      return failure("AUTHORITY_TRUST_INVALID");
    }
    if (isCapturedAuthorityTrustContextV02(authorityTrustContext)
      && !verifyAdmittedAuthorityTrustRecordsV02(authorityTrustContext, admittedRecords.value.records_by_path, ledger.events).ok) {
      return failure("AUTHORITY_TRUST_INVALID");
    }

    const head = ledger.events.at(-1)!;
    const observations = ledger.events.filter((event) => event.event_type === "task.progress-observed");
    const completedLoopAttempts = ledger.events.filter((event) => event.event_type === "loop.attempt-completed").length;
    const validated = deepFreeze({
      plan: plan.data,
      run_id: plan.data.run_id,
      plan_hash: planHash,
      ledger_sequence: head.sequence,
      ledger_head_hash: head.event_hash,
      completed_loop_attempts: completedLoopAttempts,
      observations,
      events: ledger.events,
    }) as unknown as ValidatedRuntimeProjectionInputV02;
    validatedInputs.add(validated);
    projectionRuntimeFacts.set(validated, {
      controlPlaneConsumedBytes: ledgerBytes.byteLength,
      ledgerLineBytes: ledgerText.slice(0, -1).split("\n").map((line) => Buffer.byteLength(`${line}\n`, "utf8")),
      decodedRecordsByPath: admittedRecords.value.records_by_path,
    });
    return { ok: true, value: validated };
  } catch {
    return failure("RUNTIME_INPUT_BYTE_VIEW_INVALID");
  }
}

export function buildTerminalObservationSnapshotV02(
  input: ValidatedRuntimeProjectionInputV02,
): RuntimeResult<TerminalObservationSnapshotV02, TerminalSnapshotInvalidReasonV02> {
  if (!isValidatedRuntimeProjectionInputV02(input)) return { ok: false, error: "PLAN_OR_LEDGER_LINEAGE_INVALID" };
  const facts = projectionRuntimeFacts.get(input);
  if (facts === undefined || input.events[0]?.event_type !== "run.initialized") {
    return { ok: false, error: "APPLICABILITY_OR_DUE_INVALID" };
  }
  return buildTerminalObservationSnapshotCoreV02(input, facts, true);
}

/** Package-private brand-independent core shared only by already-admitted runtime families. */
export function buildTerminalObservationSnapshotCoreV02(
  input: ValidatedRuntimeProjectionInputV02,
  facts: AdmittedRuntimeProjectionFactsV02,
  brandAsV02 = false,
): RuntimeResult<TerminalObservationSnapshotV02, TerminalSnapshotInvalidReasonV02> {
  const progress = deriveProgressV02ForRuntime(input);
  if (!progress.ok) return progress;
  if (input.events[0]?.event_type !== "run.initialized") {
    return { ok: false, error: "APPLICABILITY_OR_DUE_INVALID" };
  }
  const initializedRef = eventRef(input.events[0]);
  const freezeEvents = input.events.filter((event) => event.event_type === "run.terminal-freeze-entered" || event.event_type === "run.terminal-freeze-revised");
  const freezeEvent = freezeEvents.at(-1);
  const initialFreezeEvent = input.events.find((event) => event.event_type === "run.terminal-freeze-entered");
  const requestEvents = input.events.filter((event) => event.event_type === "run.compensation-requested" || event.event_type === "run.compensation-request-revised");
  const requestEvent = requestEvents.at(-1);
  const phaseEntry = input.events.findLast((event) => event.event_type === "run.compensation-phase-entered");
  const escalation = input.events.findLast((event) => event.event_type === "run.compensation-candidate-escalated");
  const sealEvent = input.events.findLast((event) => event.event_type === "run.terminal-sealed");
  const abortEvent = input.events.findLast((event) => event.event_type === "control.abort-requested");
  const fenceEvent = input.events.findLast((event) => event.event_type === "run.fence-advanced");
  const phase = phaseEntry === undefined ? "work" as const : "compensation" as const;
  const pendingEvent = escalation ?? phaseEntry;
  const pendingTerminal = pendingEvent?.payload.pending_terminal ?? null;
  const terminalFreeze = freezeEvent === undefined ? null : {
    revision: freezeEvent.payload.revision,
    candidate: freezeEvent.payload.candidate,
    ledger_sequence: freezeEvent.sequence,
    event_hash: freezeEvent.event_hash,
  };
  const compensationRequest = requestEvent === undefined ? null : {
    revision: requestEvent.payload.revision,
    pending_terminal: requestEvent.payload.pending_terminal,
    activation_reason: requestEvent.payload.activation_reason,
    compensation_refs: requestEvent.payload.compensation_refs,
    ledger_sequence: requestEvent.sequence,
    event_hash: requestEvent.event_hash,
  };
  const terminalSeal = sealEvent === undefined ? null : {
    ledger_sequence: sealEvent.sequence,
    outcome: sealEvent.payload.outcome,
    fence_epoch: sealEvent.payload.fence_epoch,
    pre_seal_ledger_sequence: sealEvent.payload.pre_seal_ledger_sequence,
    pre_seal_ledger_head_hash: sealEvent.payload.pre_seal_ledger_head_hash,
    pre_seal_snapshot_hash: sealEvent.payload.pre_seal_snapshot_hash,
    event_hash: sealEvent.event_hash,
  };
  const consumed = facts.controlPlaneConsumedBytes;
  const reserved = input.plan.required_control_plane_output_bytes;
  type LimitRef = "max-loop-attempts" | "max-elapsed-ms" | "max-tool-calls" | "max-output-bytes" | "max-tokens" | "max-cost";
  const configuredLimits: LimitRef[] = [
    "max-loop-attempts",
    "max-elapsed-ms",
    "max-tool-calls",
    "max-output-bytes",
  ];
  if (input.plan.limit_policy.max_tokens !== null) configuredLimits.push("max-tokens");
  if (input.plan.limit_policy.max_cost_minor_units !== null) configuredLimits.push("max-cost");
  const attempts = input.events.filter((event) => event.event_type === "loop.attempt-completed");
  const clocks = input.events.filter((event) => event.event_type === "run.clock-observed");
  const terminalExecutions = input.events.filter((event) => event.event_type === "task.execution-completed" || event.event_type === "task.execution-failed");
  const limitBlocks = input.events.filter((event) => event.event_type === "limit.admission-blocked");
  const latestBlockByRef = new Map(limitBlocks.flatMap((event) => event.payload.violations.map((violation) => [violation.limit_ref, { event, violation }] as const)));
  const maxElapsed = clocks.reduce((maximum, event) => Math.max(maximum, event.payload.elapsed_ms), 0);
  const latestExecution = terminalExecutions.at(-1);
  const costConsumed = terminalExecutions.reduce((sum, event) => sum + (event.payload.observed_cost.cost_minor_units ?? 0), 0);
  const recovery = phase === "work" ? input.plan.recovery_policy.reserve : {
    max_elapsed_ms: 0,
    max_tool_calls: 0,
    max_output_bytes: 0,
    max_tokens: null,
    max_cost_minor_units: null,
  };
  const ceilingByRef = {
    "max-loop-attempts": input.plan.limit_policy.max_loop_attempts,
    "max-elapsed-ms": input.plan.limit_policy.max_elapsed_ms - recovery.max_elapsed_ms,
    "max-tool-calls": input.plan.limit_policy.max_tool_calls - recovery.max_tool_calls,
    "max-output-bytes": input.plan.limit_policy.max_output_bytes
      - input.plan.limit_policy.control_plane_output_reserve_bytes - recovery.max_output_bytes,
    "max-tokens": input.plan.limit_policy.max_tokens === null ? null : input.plan.limit_policy.max_tokens - (recovery.max_tokens ?? 0),
    "max-cost": input.plan.limit_policy.max_cost_minor_units === null ? null : input.plan.limit_policy.max_cost_minor_units - (recovery.max_cost_minor_units ?? 0),
  } as const;
  const consumedByRef = {
    "max-loop-attempts": attempts.length,
    "max-elapsed-ms": maxElapsed,
    "max-tool-calls": latestExecution?.payload.tool_calls_after ?? 0,
    "max-output-bytes": latestExecution?.payload.action_output_bytes_after ?? 0,
    "max-tokens": latestExecution?.payload.token_count_after ?? 0,
    "max-cost": costConsumed,
  } as const;
  let limitFactsInvalid = false;
  const limits = configuredLimits.map((ref) => {
    const block = latestBlockByRef.get(ref);
    const consumed = block?.violation.consumed ?? consumedByRef[ref];
    const ceiling = ceilingByRef[ref];
    if (ceiling === null || ceiling < 0) throw new TypeError("invalid derived runtime ceiling");
    if (block !== undefined && block.violation.ceiling !== ceiling) limitFactsInvalid = true;
    const nextRequested = block?.violation.requested ?? null;
    const status = consumed > ceiling
      ? "exceeded" as const
      : nextRequested !== null && consumed + nextRequested > ceiling
        ? "would-exceed" as const
        : consumed === ceiling
          ? "at-ceiling" as const
          : "available" as const;
    const evidence = block?.event
      ?? (ref === "max-loop-attempts" ? attempts.at(-1) : ref === "max-elapsed-ms" ? clocks.at(-1) : latestExecution)
      ?? input.events[0]!;
    return { ref, consumed, next_requested: nextRequested, status, evidence_ref: eventRef(evidence) };
  });
  const taskIds = new Set(input.plan.tasks.map((task) => task.id));
  const applicabilityProjection = projectApplicabilityAndDueV02({
    plan: input.plan,
    events: input.events,
    phase,
    active_compensation_refs: requestEvent?.payload.compensation_refs ?? [],
  });
  if (!applicabilityProjection.ok) return applicabilityProjection;
  const { gates, evaluations } = applicabilityProjection.value;
  if (limitFactsInvalid || limits.some((limit) => limit.status === "exceeded" && limit.ref !== "max-elapsed-ms")) {
    return { ok: false, error: "LIMIT_OBSERVATION_INVALID" };
  }
  const terminalTaskEvents = input.events.filter((event) => event.event_type === "task.execution-completed"
    || event.event_type === "task.execution-failed" || event.event_type === "task.action-outcome-unknown"
    || event.event_type === "task.action-outcome-reconciled");
  if (terminalTaskEvents.some((event) => !taskIds.has(event.payload.task_ref))) {
    return { ok: false, error: "TASK_EFFECT_OR_FAILURE_INVALID" };
  }
  const effectOutcomes = input.events.filter((event) => event.event_type === "effect.outcome");
  const effects = input.plan.side_effects.flatMap((row) => row.effects.map((effect) => {
    const outcome = effectOutcomes.findLast((event) => event.payload.task_ref === row.task_id && event.payload.effect_ref === effect.effect_id);
    return outcome === undefined ? {
      action_id: null,
      task_ref: row.task_id,
      effect_ref: effect.effect_id,
      outcome: "not-started" as const,
      outcome_event_ref: null,
    } : {
      action_id: outcome.payload.action_id,
      task_ref: row.task_id,
      effect_ref: effect.effect_id,
      outcome: outcome.payload.outcome,
      outcome_event_ref: eventRef(outcome),
    };
  }));
  const failurePolicyProjection = deriveFailurePolicyProjectionV02({
    plan: input.plan,
    events: input.events,
  });
  if (!failurePolicyProjection.ok) {
    return { ok: false, error: failurePolicyProjection.reason };
  }
  const { active_failures: activeFailures, policy_blocks: policyBlocks } = failurePolicyProjection.value;
  const actionAdmissions = input.events.filter((event) => event.event_type === "task.action-admitted");
  const actionSettlements = input.events.filter((event) => event.event_type === "task.action-settled");
  const actionStateEvents = input.events.filter((event) => event.event_type === "task.execution-started"
    || event.event_type === "task.execution-completed" || event.event_type === "task.execution-failed"
    || event.event_type === "task.action-outcome-unknown" || event.event_type === "task.action-outcome-reconciled");
  if (actionStateEvents.some((event) => {
    const admission = actionAdmissions.find((candidate) => candidate.payload.action_id === event.payload.action_id);
    return admission === undefined
      || admission.sequence >= event.sequence
      || admission.payload.task_ref !== event.payload.task_ref
      || event.payload.admission_ref.ledger_sequence !== admission.sequence
      || event.payload.admission_ref.event_hash !== admission.event_hash;
  })) {
    return { ok: false, error: "ACTION_ADMISSION_OR_QUIESCENCE_INVALID" };
  }
  const inFlightActions = actionAdmissions.flatMap((admission) => {
    if (actionSettlements.some((settlement) => settlement.payload.action_id === admission.payload.action_id)) return [];
    const latest = actionStateEvents.findLast((event) => event.payload.action_id === admission.payload.action_id);
    const state = latest === undefined ? "admitted" as const
      : latest.event_type === "task.execution-started" ? "started" as const
        : latest.event_type === "task.execution-completed" ? "completed" as const
          : latest.event_type === "task.execution-failed" ? "failed" as const
            : latest.event_type === "task.action-outcome-unknown" ? "outcome-unknown" as const
              : "outcome-reconciled" as const;
    return [{
      action_id: admission.payload.action_id,
      task_ref: admission.payload.task_ref,
      lease_id: admission.payload.lease_id,
      admission_sequence: admission.sequence,
      state,
      latest_state_event_ref: eventRef(latest ?? admission),
    }];
  });
  // Every admitted action remains an active worker until canonical settlement;
  // completion, failure, and outcome recovery change state but not quiescence.
  const activeWorkers = inFlightActions.length;
  const hasUnsettledActionBefore = (sequence: number): boolean => actionAdmissions.some((admission) =>
    admission.sequence < sequence
    && !actionSettlements.some((settlement) =>
      settlement.sequence < sequence
      && settlement.payload.action_id === admission.payload.action_id));
  const activeFailureByTask = new Map(activeFailures.map((failure) => [failure.task_ref, failure] as const));
  const unknownOutcomeByTask = new Map(terminalTaskEvents
    .filter((event) => event.event_type === "task.action-outcome-unknown" || event.event_type === "task.action-outcome-reconciled")
    .map((event) => [event.payload.task_ref, event] as const));
  const completedByTask = new Map(terminalTaskEvents
    .filter((event) => event.event_type === "task.execution-completed")
    .map((event) => [event.payload.task_ref, event] as const));
  const startedTaskIds = new Set(input.events
    .filter((event) => event.event_type === "task.execution-started")
    .map((event) => event.payload.task_ref));
  const inFlightTaskIds = new Set(inFlightActions.map((action) => action.task_ref));
  const taskRows: Array<TerminalObservationSnapshotV02["tasks"][number]> = input.plan.tasks.map((task) => {
    const completed = completedByTask.get(task.id);
    if (completed !== undefined) {
      return {
        ref: task.id,
        status: "completed" as const,
        terminal_event_ref: eventRef(completed),
        condition_evidence_refs: [eventRef(completed)],
      };
    }
    const activeFailure = activeFailureByTask.get(task.id);
    if (activeFailure !== undefined) {
      return {
        ref: task.id,
        status: isFailedFailureClass(activeFailure.failure_class) ? "failed" as const : "blocked" as const,
        terminal_event_ref: activeFailure.failure_event_ref,
        condition_evidence_refs: [activeFailure.failure_event_ref],
      };
    }
    const unknownOutcome = unknownOutcomeByTask.get(task.id);
    if (unknownOutcome !== undefined) {
      return {
        ref: task.id,
        status: "blocked" as const,
        terminal_event_ref: eventRef(unknownOutcome),
        condition_evidence_refs: [eventRef(unknownOutcome)],
      };
    }
    if (startedTaskIds.has(task.id) || inFlightTaskIds.has(task.id)) {
      return {
        ref: task.id,
        status: "running" as const,
        terminal_event_ref: null,
        condition_evidence_refs: [],
      };
    }
    return {
      ref: task.id,
      status: "pending" as const,
      terminal_event_ref: null,
      condition_evidence_refs: [],
    };
  });
  const taskRowsByRef = new Map<string, TerminalObservationSnapshotV02["tasks"][number]>(
    taskRows.map((task) => [task.ref, task]),
  );
  let propagatedDependencyBlock = true;
  while (propagatedDependencyBlock) {
    propagatedDependencyBlock = false;
    for (const task of input.plan.tasks) {
      const current = taskRowsByRef.get(task.id);
      if (current === undefined || current.status !== "pending" || task.kind !== "work") continue;
      const dependencyRows = task.depends_on
        .map((dependencyRef) => taskRowsByRef.get(dependencyRef))
        .filter((dependency): dependency is NonNullable<typeof dependency> => dependency !== undefined)
        .filter((dependency) => dependency.status !== "completed");
      if (!dependencyRows.some((dependency) => dependency.status === "blocked" || dependency.status === "failed")) {
        continue;
      }
      const dependencyEvidence = uniqueLedgerRefs(dependencyRows.flatMap((dependency) => dependency.condition_evidence_refs));
      const dependencyTerminalRef = dependencyRows.find((dependency) => dependency.terminal_event_ref !== null)?.terminal_event_ref ?? null;
      taskRowsByRef.set(task.id, {
        ref: task.id,
        status: "blocked",
        terminal_event_ref: dependencyTerminalRef,
        condition_evidence_refs: dependencyEvidence,
      });
      propagatedDependencyBlock = true;
    }
  }
  const tasks = input.plan.tasks.map((task) => taskRowsByRef.get(task.id)!);
  if (freezeEvents.length > 0) {
    if (freezeEvent === undefined) return { ok: false, error: "TERMINAL_FREEZE_INVALID" };
    const freezeIndex = initialFreezeEvent === undefined ? -1 : input.events.indexOf(initialFreezeEvent);
    const precedingFence = freezeIndex < 0 ? undefined : input.events
      .slice(0, freezeIndex)
      .filter((event) => event.event_type === "run.fence-advanced")
      .at(-1);
    if (initialFreezeEvent === undefined
      || initialFreezeEvent.payload.fence_epoch !== (precedingFence?.payload.fence_epoch ?? 0)) {
      return { ok: false, error: "TERMINAL_FREEZE_INVALID" };
    }
  }
  if (freezeEvent !== undefined) {
    const progressByRef = new Map(progress.value.observations.map((observation) => [observation.ref, observation]));
    const activeCompensationActionTasks = new Set((requestEvent?.payload.compensation_refs ?? [])
      .flatMap((compensationRef) => input.plan.compensations
        .filter((compensation) => compensation.id === compensationRef)
        .map((compensation) => compensation.action_task)));
    const completed = gates.every((gate) => !gate.applicable || !gate.due || gate.status === "pass" || gate.status === "waived-valid")
      && evaluations.every((evaluation) => evaluationCountsAsCompleted(input.plan, evaluation))
      && tasks.every((task) => taskCountsAsCompleted(input.plan, task, activeCompensationActionTasks))
      && input.plan.progress.observations.every((observation) => observation.target === null || progressByRef.get(observation.id)?.target_reached === true);
    const proven = freezeEvent.payload.candidate === "aborted"
      ? abortEvent !== undefined
      : freezeEvent.payload.candidate === "exhausted"
        ? limits.some((limit) => limit.status === "at-ceiling" || limit.status === "would-exceed" || limit.status === "exceeded")
        : freezeEvent.payload.candidate === "stalled"
          ? progress.value.observations.some((observation) => observation.stalled)
          : freezeEvent.payload.candidate === "failed"
            ? activeFailures.some((failure) => isFailedFailureClass(failure.failure_class))
              || tasks.some((task) => task.status === "failed")
              || gates.some((gate) => gate.status === "fail")
              || evaluations.some((evaluation) => evaluation.status === "fail")
            : freezeEvent.payload.candidate === "held"
              ? activeFailures.some((failure) => failure.failure_class === "policy-hold")
                || policyBlocks.some((block) => block.active && block.decision === "hold")
                || gates.some((gate) => gate.status === "hold")
                || evaluations.some((evaluation) => evaluation.status === "hold")
              : freezeEvent.payload.candidate === "blocked"
                ? tasks.some((task) => task.status === "blocked")
                : completed;
    if (!proven) return { ok: false, error: "TERMINAL_FREEZE_INVALID" };
  }

  // Stage 8 precedes request-lineage and ref-set validation. Only known plan
  // compensations are inspected here; unknown refs remain stage 12 ownership.
  for (const event of requestEvents) {
    for (const compensationRef of event.payload.compensation_refs) {
      const compensation = input.plan.compensations.find((candidate) => candidate.id === compensationRef);
      if (compensation === undefined) continue;
      const protectedEffect = effects.find((effect) =>
        effect.task_ref === compensation.for_task && effect.effect_ref === compensation.for_effect);
      if (protectedEffect === undefined
        || protectedEffect.outcome === "not-started"
        || protectedEffect.outcome === "not-committed") {
        return { ok: false, error: "ACTIVATION_INVALID" };
      }
    }
  }

  // Stages 9-11 own compensation-transition lineage. Admission validates only
  // the typed hash chain so malformed durable transitions reach their exact
  // public snapshot reason instead of collapsing into a generic ledger error.
  let transitionFreeze: typeof freezeEvent;
  let transitionRequest: typeof requestEvent;
  let transitionPhase: typeof phaseEntry;
  let transitionCandidate: (typeof input.events)[number] | undefined;
  for (const event of input.events) {
    if (event.event_type === "run.terminal-freeze-entered" || event.event_type === "run.terminal-freeze-revised") {
      transitionFreeze = event;
      continue;
    }
    if (event.event_type === "run.compensation-requested") {
      if (transitionRequest !== undefined || transitionFreeze === undefined
        || !["stalled", "exhausted", "failed", "aborted"].includes(transitionFreeze.payload.candidate)
        || event.payload.pending_terminal !== transitionFreeze.payload.candidate
        || event.payload.freeze_event_hash !== transitionFreeze.event_hash
        || hasUnsettledActionBefore(event.sequence)) {
        return { ok: false, error: "COMPENSATION_REQUEST_INVALID" };
      }
      transitionRequest = event;
      transitionCandidate = event;
      continue;
    }
    if (event.event_type === "run.compensation-request-revised") {
      if (transitionRequest === undefined || transitionFreeze === undefined
        || event.payload.revision !== transitionRequest.payload.revision + 1
        || event.payload.previous_pending_terminal !== transitionRequest.payload.pending_terminal
        || event.payload.previous_request_event_hash !== transitionRequest.event_hash
        || event.payload.freeze_event_hash !== transitionFreeze.event_hash
        || event.payload.pending_terminal !== transitionFreeze.payload.candidate) {
        return { ok: false, error: "COMPENSATION_REQUEST_INVALID" };
      }
      const priorRefs = transitionRequest.payload.compensation_refs;
      const addedRefs = event.payload.compensation_refs.filter((ref) => !priorRefs.includes(ref));
      if (priorRefs.some((ref) => !event.payload.compensation_refs.includes(ref))
        || JSON.stringify(addedRefs) !== JSON.stringify(event.payload.added_compensation_refs)) {
        return { ok: false, error: "COMPENSATION_REQUEST_INVALID" };
      }
      transitionRequest = event;
      transitionCandidate = event;
      continue;
    }
    if (event.event_type === "run.compensation-phase-entered") {
      const eventIndex = input.events.indexOf(event);
      const recoveryBoundary = eventIndex <= 0 ? undefined : input.events[eventIndex - 1];
      const recoveryBoundaryValid = usesAttemptAwareRecoveryV04(input)
        ? recoveryBoundary?.event_type === "run.fence-advanced"
        : recoveryBoundary?.event_type === "run.fence-advanced"
          && recoveryBoundary.payload.reason === "recovery-boundary";
      if (transitionPhase !== undefined || transitionRequest === undefined || transitionFreeze === undefined
        || event.payload.request_revision !== transitionRequest.payload.revision
        || event.payload.request_event_hash !== transitionRequest.event_hash
        || event.payload.pending_terminal !== transitionRequest.payload.pending_terminal
        || JSON.stringify(event.payload.compensation_refs) !== JSON.stringify(transitionRequest.payload.compensation_refs)
        || event.payload.freeze_event_hash !== transitionFreeze.event_hash
        || !recoveryBoundaryValid) {
        return { ok: false, error: "PHASE_OR_PENDING_TERMINAL_INVALID" };
      }
      transitionPhase = event;
      transitionCandidate = event;
      continue;
    }
    if (event.event_type === "run.compensation-candidate-escalated") {
      const priorPending = transitionCandidate?.event_type === "run.compensation-requested"
        || transitionCandidate?.event_type === "run.compensation-request-revised"
        || transitionCandidate?.event_type === "run.compensation-phase-entered"
        || transitionCandidate?.event_type === "run.compensation-candidate-escalated"
        ? transitionCandidate.payload.pending_terminal : undefined;
      if (transitionPhase === undefined || transitionCandidate === undefined
        || event.payload.previous_pending_terminal !== priorPending
        || event.payload.previous_candidate_event_hash !== transitionCandidate.event_hash
        || JSON.stringify(event.payload.compensation_refs) !== JSON.stringify(transitionPhase.payload.compensation_refs)) {
        return { ok: false, error: "CANDIDATE_ESCALATION_INVALID" };
      }
      transitionCandidate = event;
    }
  }
  const compensationProjection = deriveCompensationProjectionV02({
    plan: input.plan,
    events: input.events,
    tasks,
    evaluations,
    effects,
    limits,
    policy_blocks: policyBlocks,
  });
  if (!compensationProjection.ok) return { ok: false, error: compensationProjection.reason };
  if (phaseEntry !== undefined && hasUnsettledActionBefore(phaseEntry.sequence)) {
    return { ok: false, error: "ACTIVE_WORKERS_AT_PHASE_ENTRY" };
  }
  if (consumed > reserved) return { ok: false, error: "CONTROL_PLANE_BUDGET_INVALID" };
  if (sealEvent !== undefined && (freezeEvent === undefined
    || sealEvent.payload.outcome !== (pendingTerminal ?? freezeEvent.payload.candidate))) {
    return { ok: false, error: "TERMINAL_SEAL_OR_FENCE_INVALID" };
  }
  if (sealEvent !== undefined) {
    const sealIndex = input.events.indexOf(sealEvent);
    const prefixEvents = input.events.slice(0, sealIndex);
    const prefixHead = prefixEvents.at(-1);
    if (prefixHead === undefined
      || sealEvent.payload.pre_seal_ledger_sequence !== prefixHead.sequence
      || sealEvent.payload.pre_seal_ledger_head_hash !== prefixHead.event_hash
      || sealEvent.payload.previous_fence_epoch !== (initialFreezeEvent?.payload.fence_epoch ?? fenceEvent?.payload.fence_epoch ?? 0)) {
      return { ok: false, error: "TERMINAL_SEAL_OR_FENCE_INVALID" };
    }
    const prefixInput = deepFreeze({
      ...input,
      ledger_sequence: prefixHead.sequence,
      ledger_head_hash: prefixHead.event_hash,
      completed_loop_attempts: prefixEvents.filter((event) => event.event_type === "loop.attempt-completed").length,
      observations: prefixEvents.filter((event) => event.event_type === "task.progress-observed"),
      events: prefixEvents,
    }) as unknown as ValidatedRuntimeProjectionInputV02;
    const prefixFacts: AdmittedRuntimeProjectionFactsV02 = {
      ...facts,
      controlPlaneConsumedBytes: facts.ledgerLineBytes.slice(0, sealIndex).reduce((sum, bytes) => sum + bytes, 0),
      ledgerLineBytes: facts.ledgerLineBytes.slice(0, sealIndex),
    };
    const prefixSnapshot = buildTerminalObservationSnapshotCoreV02(prefixInput, prefixFacts, false);
    if (!prefixSnapshot.ok) return prefixSnapshot;
    const expectedHash = hashTerminalObservationSnapshotCoreV02(prefixSnapshot.value);
    if (sealEvent.payload.pre_seal_snapshot_hash !== expectedHash) {
      return { ok: false, error: "TERMINAL_SEAL_OR_FENCE_INVALID" };
    }
  }
  if (sealEvent !== undefined && input.events.at(-1) !== sealEvent) {
    return { ok: false, error: "POST_SEAL_ACTION" };
  }
  const snapshot = deepFreeze({
    schema_version: "0.2" as const,
    run_id: input.run_id,
    plan_hash: input.plan_hash,
    ledger_sequence: input.ledger_sequence,
    ledger_head_hash: input.ledger_head_hash,
    current_fence_epoch: sealEvent?.payload.fence_epoch ?? fenceEvent?.payload.fence_epoch ?? input.events[0].payload.initial_fence_epoch,
    phase,
    pending_terminal: pendingTerminal,
    pending_terminal_event_ref: pendingEvent === undefined ? null : eventRef(pendingEvent),
    terminal_freeze: terminalFreeze,
    compensation_request: compensationRequest,
    terminal_seal: terminalSeal,
    control_plane_output: {
      consumed_bytes: consumed,
      reserved_bytes: reserved,
      required_remaining_bytes: reserved - consumed,
    },
    gates,
    evaluations,
    progress: progress.value.observations.map((observation) => ({
      ref: observation.ref,
      target_reached: observation.target_reached,
      stalled: observation.stalled,
      condition_evidence_refs: progressObservationEvidenceRefs(observation),
    })),
    limits,
    tasks,
    effects,
    compensations: compensationProjection.value.compensations,
    active_failures: activeFailures,
    policy_blocks: policyBlocks,
    abort_requested: abortEvent !== undefined,
    abort_event_ref: abortEvent === undefined ? null : eventRef(abortEvent),
    in_flight_actions: inFlightActions,
    active_workers: activeWorkers,
  }) as unknown as TerminalObservationSnapshotV02;
  if (brandAsV02) {
    terminalSnapshots.add(snapshot);
    terminalSnapshotInputs.set(snapshot, input);
    terminalSnapshotCompensationFacts.set(snapshot, compensationProjection);
  }
  return { ok: true, value: snapshot };
}
