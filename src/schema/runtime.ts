import { z } from "zod";
import { ArtifactType } from "./loopeix.js";
import { Hash, HumanId, IsoTimestamp, LoopVersion, MachineId, RiskTier, RiskTierV1, SchemaVersion } from "./scalars.js";

/**
 * Runtime record schemas (schema-runtime-contract.md + runtime-file-contracts.md).
 * Well-specified scalar/enum/hash fields are validated precisely (these carry the
 * integrity rules the invalid/runtime fixtures test). Nested objects the contract
 * leaves unspecified are accepted permissively rather than invented.
 */

const anyObject = z.record(z.string(), z.unknown());
const anyArray = z.array(z.unknown());

export const RetentionClass = z.enum(["short", "run", "project", "quarantine"]);

/** Provisional shape (not field-enumerated in S3); matches fixtures. */
export const RedactionState = z.object({
  redacted: z.boolean(),
  policy_version: z.string(),
  targets_removed: z.array(z.string()),
});

export const ResolvedRunPlan = z.object({
  schema_version: SchemaVersion,
  run_id: MachineId,
  loop_family: HumanId,
  loopeix_version: LoopVersion,
  loopeix_version_hash: Hash,
  work_item_id: MachineId,
  intake_brief_id: MachineId,
  created_at: IsoTimestamp,
  assurance_profile: anyObject,
  context_snapshot: anyObject,
  role_assignments: anyArray,
  task_plan: anyArray,
  tool_grants: anyArray,
  workspace_boundary: anyObject,
  adapter_plan: anyObject,
  gate_plan: anyArray,
  evaluation_plan: anyArray,
  risk_controls: z.object({
    max_tier_without_approval: RiskTierV1,
    t5_allowed: z.literal(false),
  }),
});

export const LedgerSource = z.enum([
  "loopeix",
  "codex_cli",
  "claude_code_cli",
  "shell",
  "browser",
  "user",
  "evaluator",
]);

export const LedgerEvent = z.object({
  schema_version: SchemaVersion,
  event_id: MachineId,
  run_id: MachineId,
  sequence: z.number().int().min(1),
  timestamp: IsoTimestamp,
  // event_type is an open enum in the contract (see fixtures README Contract observations).
  event_type: z.string().min(1),
  source: LedgerSource,
  actor_id: z.string().nullable(),
  task_run_id: z.string().nullable(),
  risk_tier: RiskTier,
  payload: anyObject,
  related_ids: z.array(z.string()),
  previous_event_hash: Hash.nullable(),
  event_hash: Hash,
}).strict();
export type LedgerEventRecord = z.infer<typeof LedgerEvent>;

export const RunState = z.enum([
  "planned",
  "ready",
  "running",
  "interrupted",
  "recovering",
  "held",
  "failed",
  "completed",
  "archived",
]);

export const IntegrityStatus = z.enum(["unknown", "valid", "hold", "failed"]);

export const RunManifest = z.object({
  schema_version: SchemaVersion,
  run_id: MachineId,
  loop_family: HumanId,
  loopeix_version: LoopVersion,
  run_state: RunState,
  created_at: IsoTimestamp,
  updated_at: IsoTimestamp,
  workspace_root: z.string().min(1),
  run_dir: z.string().min(1),
  schema_versions: z.record(z.string(), z.string()),
  file_inventory: z.array(
    z.object({
      path: z.string(),
      purpose: z.string(),
      required: z.boolean(),
      exists: z.boolean(),
      hash: Hash,
    }),
  ),
  // The ledger hash is mandatory for run integrity; manifest/report are "where available".
  hashes: z.object({
    ledger: Hash,
    manifest: Hash.optional(),
    report: Hash.optional(),
  }),
  integrity_status: IntegrityStatus,
  last_ledger_sequence: z.number().int(),
  blocking_gate_summary: anyObject,
});
export type RunManifestRecord = z.infer<typeof RunManifest>;

export const ArtifactRecord = z.object({
  artifact_id: z.string().min(1),
  path: z.string().min(1),
  type: ArtifactType,
  producer: z.string().min(1),
  created_at: IsoTimestamp,
  media_type: z.string(),
  size_bytes: z.number().int().min(0),
  hash: Hash,
  retention_class: RetentionClass,
  expires_at: IsoTimestamp.nullable(),
  redaction: RedactionState,
  quarantined: z.boolean(),
  exportable: z.boolean(),
  raw_hash: Hash.nullable(),
  redacted_hash: Hash.nullable(),
  evidence_ids: z.array(z.string()),
});

export const ArtifactManifest = z.object({
  schema_version: SchemaVersion,
  run_id: MachineId,
  updated_at: IsoTimestamp,
  artifacts: z.array(ArtifactRecord),
});
