import { hashCanonical, hashRawBytes } from "../hash.js";
import { RuntimeSchemaInventoryV03 } from "../schema/runtime-v03.js";
import { RuntimeSchemaInventoryV02 } from "../schema/runtime.js";
import { IsoTimestampV02, MachineIdV02 } from "../schema/scalars-v02.js";
import { parseAndValidateRuntimeLedgerV02 } from "./runtime-ledger-v02.js";
import { inspectRuntimeLedgerV03 } from "./runtime-ledger-v03.js";

const MAX_LEDGER_BYTES = 67_108_864;

export type RuntimeLedgerMigrationFailureV02V03 =
  | "MIGRATION_INPUT_INVALID"
  | "MIGRATION_SOURCE_INVALID"
  | "MIGRATION_SOURCE_NOT_QUIESCENT"
  | "MIGRATION_TARGET_INVALID";

export type RuntimeLedgerMigrationPlanV02V03 = Readonly<{
  source: Readonly<{ run_id: string; plan_hash: string; bytes_hash: string; event_count: number; head_hash: string }>;
  target: Readonly<{ run_id: string; ledger_text: string; bytes_hash: string; event_count: 1; head_hash: string }>;
  lineage: Readonly<{
    schema_version: "0.1";
    migration_profile: "runtime-ledger-v02-to-v03-v01";
    source_run_id: string;
    source_plan_hash: string;
    source_bytes_hash: string;
    source_inventory_hash: string;
    source_sequence: number;
    source_head_hash: string;
    target_run_id: string;
    target_plan_hash: string;
    target_bytes_hash: string;
    target_inventory_hash: string;
    target_sequence: 1;
    target_head_hash: string;
    authority_carried_forward: false;
    historical_leases_carried_forward: false;
    lineage_hash: string;
  }>;
}>;

export type RuntimeLedgerMigrationPlanResultV02V03 =
  | Readonly<{ ok: true; value: RuntimeLedgerMigrationPlanV02V03 }>
  | Readonly<{ ok: false; reason: RuntimeLedgerMigrationFailureV02V03 }>;

function captureInput(input: unknown): Readonly<{ source_bytes: Uint8Array; target_run_id: string; recorded_at: string }> | null {
  try {
    if (typeof input !== "object" || input === null || Object.getPrototypeOf(input) !== Object.prototype) return null;
    const descriptors = Object.getOwnPropertyDescriptors(input);
    if (Reflect.ownKeys(input).some((key) => typeof key !== "string")
      || Object.keys(descriptors).sort().join("|") !== "recorded_at|source_bytes|target_run_id") return null;
    for (const descriptor of Object.values(descriptors)) {
      if (!("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined || descriptor.enumerable !== true) return null;
    }
    const source = descriptors.source_bytes!.value;
    const target = descriptors.target_run_id!.value;
    const recorded = descriptors.recorded_at!.value;
    if (!(source instanceof Uint8Array) || Object.getPrototypeOf(source) !== Uint8Array.prototype
      || typeof target !== "string" || typeof recorded !== "string") return null;
    if (source.byteLength === 0 || source.byteLength > MAX_LEDGER_BYTES || source.buffer instanceof SharedArrayBuffer) return null;
    return { source_bytes: new Uint8Array(source), target_run_id: target, recorded_at: recorded };
  } catch {
    return null;
  }
}

export function planRuntimeLedgerMigrationV02ToV03(input: unknown): RuntimeLedgerMigrationPlanResultV02V03 {
  const captured = captureInput(input);
  if (captured === null) return { ok: false, reason: "MIGRATION_INPUT_INVALID" };
  const targetRun = MachineIdV02.safeParse(captured.target_run_id);
  const recordedAt = IsoTimestampV02.safeParse(captured.recorded_at);
  if (!targetRun.success || !recordedAt.success) return { ok: false, reason: "MIGRATION_TARGET_INVALID" };
  let sourceText: string;
  try {
    sourceText = new TextDecoder("utf-8", { fatal: true }).decode(captured.source_bytes);
  } catch {
    return { ok: false, reason: "MIGRATION_SOURCE_INVALID" };
  }
  const source = parseAndValidateRuntimeLedgerV02(sourceText);
  if (!source.ok || source.events.length === 0) return { ok: false, reason: "MIGRATION_SOURCE_INVALID" };
  const sourceFirst = source.events[0]!;
  if (sourceFirst.event_type !== "run.initialized") return { ok: false, reason: "MIGRATION_SOURCE_INVALID" };
  if (sourceFirst.run_id === targetRun.data) return { ok: false, reason: "MIGRATION_TARGET_INVALID" };
  if (!source.sealed) return { ok: false, reason: "MIGRATION_SOURCE_NOT_QUIESCENT" };
  const inFlight = new Set<string>();
  for (const event of source.events) {
    if (event.event_type === "task.action-admitted") inFlight.add(event.payload.action_id);
    if (event.event_type === "task.action-settled") inFlight.delete(event.payload.action_id);
  }
  if (inFlight.size !== 0) return { ok: false, reason: "MIGRATION_SOURCE_NOT_QUIESCENT" };

  const sourceBytesHash = hashRawBytes(captured.source_bytes);
  const eventId = `event_migration_${sourceBytesHash.slice("sha256:".length, "sha256:".length + 24)}`;
  const inventory = RuntimeSchemaInventoryV03.parse({
    ...sourceFirst.payload.runtime_schema_versions,
    ledger_event: "0.3",
  });
  const targetPreimage = {
    schema_version: "0.3" as const,
    event_id: eventId,
    run_id: targetRun.data,
    sequence: 1,
    recorded_at: recordedAt.data,
    event_type: "run.initialized" as const,
    source: "kernel" as const,
    authority_ref: null,
    risk_tier: sourceFirst.risk_tier,
    related_ids: [sourceFirst.run_id],
    previous_event_hash: null,
    payload: {
      plan_hash: sourceFirst.payload.plan_hash,
      initial_fence_epoch: 0 as const,
      runtime_schema_versions: inventory,
    },
  };
  const targetEvent = { ...targetPreimage, event_hash: hashCanonical(targetPreimage) };
  const targetText = `${JSON.stringify(targetEvent)}\n`;
  const targetBytes = new TextEncoder().encode(targetText);
  const targetValidation = inspectRuntimeLedgerV03(targetBytes);
  if (!targetValidation.ok) return { ok: false, reason: "MIGRATION_TARGET_INVALID" };
  const targetBytesHash = hashRawBytes(targetBytes);
  const sourceInventory = RuntimeSchemaInventoryV02.parse(sourceFirst.payload.runtime_schema_versions);
  const lineagePreimage = {
    schema_version: "0.1" as const,
    migration_profile: "runtime-ledger-v02-to-v03-v01" as const,
    source_run_id: sourceFirst.run_id,
    source_plan_hash: sourceFirst.payload.plan_hash,
    source_bytes_hash: sourceBytesHash,
    source_inventory_hash: hashCanonical(sourceInventory),
    source_sequence: source.events.length,
    source_head_hash: source.events.at(-1)!.event_hash,
    target_run_id: targetRun.data,
    target_plan_hash: sourceFirst.payload.plan_hash,
    target_bytes_hash: targetBytesHash,
    target_inventory_hash: hashCanonical(inventory),
    target_sequence: 1 as const,
    target_head_hash: targetEvent.event_hash,
    authority_carried_forward: false as const,
    historical_leases_carried_forward: false as const,
  };
  const lineage = Object.freeze({ ...lineagePreimage, lineage_hash: hashCanonical(lineagePreimage) });
  return {
    ok: true,
    value: Object.freeze({
      source: Object.freeze({
        run_id: sourceFirst.run_id,
        plan_hash: sourceFirst.payload.plan_hash,
        bytes_hash: sourceBytesHash,
        event_count: source.events.length,
        head_hash: source.events.at(-1)!.event_hash,
      }),
      target: Object.freeze({
        run_id: targetRun.data,
        ledger_text: targetText,
        bytes_hash: targetBytesHash,
        event_count: 1 as const,
        head_hash: targetEvent.event_hash,
      }),
      lineage,
    }),
  };
}
