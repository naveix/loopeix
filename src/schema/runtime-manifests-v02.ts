import { z } from "zod";
import { hashCanonical } from "../hash.js";
import {
  LedgerRefV02,
  RetentionClass,
  RuntimeSchemaInventoryV02,
  compareRuntimeUtf8BytesV02,
} from "./runtime.js";
import {
  HumanIdV02,
  IsoTimestampV02,
  MachineIdV02,
  NonBlankStringV02,
  RelativeRunPathV02,
} from "./scalars-v02.js";
import { Hash } from "./scalars.js";

export { RuntimeSchemaInventoryV02 };

const strictObject = <T extends z.ZodRawShape>(shape: T): z.ZodObject<T> =>
  z.object(shape).strict();
const safeInteger = z.number().int().refine(Number.isSafeInteger, {
  message: "must be a safe integer",
});

const RunManifestPresentFileEntryV02 = strictObject({
  path: RelativeRunPathV02,
  family: z.enum(["primary", "record", "projection"]),
  required: z.boolean(),
  exists: z.literal(true),
  mode: z.literal(384),
  size_bytes: safeInteger.nonnegative(),
  hash: Hash,
});

const RunManifestAbsentFileEntryV02 = strictObject({
  path: RelativeRunPathV02,
  family: z.enum(["primary", "record", "projection"]),
  required: z.literal(false),
  exists: z.literal(false),
  mode: z.null(),
  size_bytes: z.null(),
  hash: z.null(),
});

export const RunManifestFileEntryV02 = z.discriminatedUnion("exists", [
  RunManifestPresentFileEntryV02,
  RunManifestAbsentFileEntryV02,
]);

const SortedRunManifestFileInventoryV02 = z
  .array(RunManifestFileEntryV02)
  .superRefine((rows, context) => {
    for (let index = 1; index < rows.length; index += 1) {
      if (compareRuntimeUtf8BytesV02(rows[index - 1]!.path, rows[index]!.path) >= 0) {
        context.addIssue({
          code: "custom",
          path: [index, "path"],
          message: "file inventory paths must be unique and sorted by UTF-8 bytes",
        });
      }
    }
  });

const TerminalOutcomeV02 = z.enum([
  "completed",
  "held",
  "blocked",
  "failed",
  "stalled",
  "exhausted",
  "aborted",
]);

const RunManifestTerminalV02 = strictObject({
  outcome: TerminalOutcomeV02,
  snapshot_hash: Hash,
  seal_event_ref: LedgerRefV02,
});

const RunManifestV02Base = strictObject({
  schema_version: z.literal("0.2"),
  run_id: MachineIdV02,
  plan_hash: Hash,
  execution_profile: z.literal("bounded-v02"),
  schema_versions: RuntimeSchemaInventoryV02,
  run_state: z.enum(["initialized", "running", "frozen", "compensating", "sealed"]),
  created_at: IsoTimestampV02,
  projection_event_ref: LedgerRefV02,
  ledger_sequence: safeInteger.nonnegative(),
  ledger_head_hash: Hash,
  current_fence_epoch: safeInteger.nonnegative(),
  terminal: RunManifestTerminalV02.nullable(),
  file_inventory: SortedRunManifestFileInventoryV02,
  manifest_hash: Hash,
});

export const RunManifestV02 = RunManifestV02Base.superRefine((manifest, context) => {
  if (
    manifest.projection_event_ref.ledger_sequence !== manifest.ledger_sequence ||
    manifest.projection_event_ref.event_hash !== manifest.ledger_head_hash
  ) {
    context.addIssue({
      code: "custom",
      path: ["projection_event_ref"],
      message: "projection event must equal the projected ledger head",
    });
  }
  if ((manifest.run_state === "sealed") !== (manifest.terminal !== null)) {
    context.addIssue({
      code: "custom",
      path: ["terminal"],
      message: "terminal must be present exactly when the run is sealed",
    });
  }
  if (
    manifest.terminal !== null &&
    (
      manifest.terminal.seal_event_ref.ledger_sequence !== manifest.projection_event_ref.ledger_sequence ||
      manifest.terminal.seal_event_ref.event_hash !== manifest.projection_event_ref.event_hash
    )
  ) {
    context.addIssue({
      code: "custom",
      path: ["terminal", "seal_event_ref"],
      message: "seal event must equal the sealed projection event",
    });
  }

  const { manifest_hash: _manifestHash, ...preimage } = manifest;
  if (manifest.manifest_hash !== hashCanonical(preimage)) {
    context.addIssue({
      code: "custom",
      path: ["manifest_hash"],
      message: "manifest hash must match the exact manifest preimage",
    });
  }
});

export const ArtifactManifestEntryV02 = strictObject({
  artifact_ref: HumanIdV02,
  producer_task_ref: HumanIdV02,
  producer_action_id: MachineIdV02,
  artifact_path: RelativeRunPathV02,
  artifact_record_hash: Hash,
  original_content_hash: Hash,
  current_content_ref: RelativeRunPathV02,
  current_content_hash: Hash,
  size_bytes: safeInteger.nonnegative(),
  media_type: NonBlankStringV02,
  retention_class: RetentionClass,
  expires_at: IsoTimestampV02.nullable(),
  quarantined: z.boolean(),
  exportable: z.boolean(),
  redaction_state: z.enum(["original", "redacted"]),
  source_event_ref: LedgerRefV02,
  state_event_ref: LedgerRefV02,
});

const SortedArtifactManifestEntriesV02 = z
  .array(ArtifactManifestEntryV02)
  .superRefine((rows, context) => {
    for (let index = 1; index < rows.length; index += 1) {
      if (
        compareRuntimeUtf8BytesV02(rows[index - 1]!.artifact_ref, rows[index]!.artifact_ref) >= 0
      ) {
        context.addIssue({
          code: "custom",
          path: [index, "artifact_ref"],
          message: "artifact references must be unique and sorted by UTF-8 bytes",
        });
      }
    }
  });

const ArtifactManifestV02Base = strictObject({
  schema_version: z.literal("0.2"),
  run_id: MachineIdV02,
  plan_hash: Hash,
  projection_event_ref: LedgerRefV02,
  ledger_sequence: safeInteger.nonnegative(),
  ledger_head_hash: Hash,
  artifacts: SortedArtifactManifestEntriesV02,
  manifest_hash: Hash,
});

export const ArtifactManifestV02 = ArtifactManifestV02Base.superRefine((manifest, context) => {
  if (
    manifest.projection_event_ref.ledger_sequence !== manifest.ledger_sequence ||
    manifest.projection_event_ref.event_hash !== manifest.ledger_head_hash
  ) {
    context.addIssue({
      code: "custom",
      path: ["projection_event_ref"],
      message: "projection event must equal the projected ledger head",
    });
  }
  const { manifest_hash: _manifestHash, ...preimage } = manifest;
  if (manifest.manifest_hash !== hashCanonical(preimage)) {
    context.addIssue({
      code: "custom",
      path: ["manifest_hash"],
      message: "manifest hash must match the exact manifest preimage",
    });
  }
});

export type RuntimeSchemaInventoryV02Value = z.infer<typeof RuntimeSchemaInventoryV02>;
export type RunManifestFileEntryV02Value = z.infer<typeof RunManifestFileEntryV02>;
export type RunManifestV02Value = z.infer<typeof RunManifestV02>;
export type ArtifactManifestEntryV02Value = z.infer<typeof ArtifactManifestEntryV02>;
export type ArtifactManifestV02Value = z.infer<typeof ArtifactManifestV02>;
