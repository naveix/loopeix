import { canonicalize, hashRawBytes } from "../hash.js";
import { z, type ZodType } from "zod";
import { MachineId } from "./scalars.js";
import { decodeStructuredDocumentV02 } from "./decode-envelope.js";
import {
  ArtifactSpecV02,
  CompensationSpecV02,
  ControlPrerequisiteV02,
  EvaluatorBindingV02,
  EvaluationSpecV02,
  EvidenceRequirementSpecV02,
  GateApplicabilityV02,
  GoalSpecV02,
  HumanIdV02,
  LimitPolicyV02,
  ProgressSpecV02,
  RecoveryPolicyV02,
  RequiredGateKindV02,
  RetryPolicyV02,
  SideEffectSpecV02,
  StopPolicyV02,
  TriggerSpecV02,
  type LoopeixV02,
} from "./loopeix-v02.js";
import { parseLoopeixDocument } from "./version-dispatch.js";
import {
  detectCredentialV02,
  type CredentialRuleIdV02,
} from "../security/credential-detector-v02.js";

export type { CredentialRuleIdV02 } from "../security/credential-detector-v02.js";

export type MigrationCredentialScanStageV02 =
  | "source-bytes"
  | "source-values"
  | "binding-bytes"
  | "binding-values"
  | "final-output";

export type MigrationCredentialScannerV02 = (
  stage: MigrationCredentialScanStageV02,
  bytes: Uint8Array,
) => { rule_id: CredentialRuleIdV02; provenance: "source" | "bindings" } | null;

export type MigratorVersion = string & { readonly __migrator_version: unique symbol };

export type MigrateV01ToV02Input = {
  source_bytes: Uint8Array;
  source_format: "json" | "yaml";
  migration_id: string;
  migrator_version: MigratorVersion;
  created_at: string;
  bindings_bytes: Uint8Array;
};

type MigrationCommon = {
  migration_contract_version: "0.1";
  migration_id: string | null;
  migrator_version: MigratorVersion | null;
  created_at: string | null;
  source_version: "0.1" | null;
  target_version: "0.2";
  source_format: "json" | "yaml" | null;
  source_hash: string | null;
};

export type LoopeixMigrationResult =
  | (MigrationCommon & {
      status: "rejected";
      reason:
        | "INVALID_MIGRATION_INPUT"
        | "INPUT_TOO_LARGE"
        | "INVALID_BYTE_VIEW"
        | "SENSITIVE_INPUT_REJECTED"
        | "MISSING_SCHEMA_VERSION"
        | "MALFORMED_SCHEMA_VERSION"
        | "UNSUPPORTED_SCHEMA_VERSION"
        | "INVALID_DOCUMENT_ENVELOPE"
        | "INVALID_SOURCE_V01"
        | "UNSUPPORTED_CANONICAL_VALUE"
        | "UNKNOWN_BINDING_PATH"
        | "DUPLICATE_BINDING"
        | "INVALID_BINDING_VALUE"
        | "CANONICALIZATION_FAILED";
      input_part?: "lineage" | "source" | "bindings" | null;
      field?: string | null;
      location?: "source" | "bindings";
      rule_id?: CredentialRuleIdV02;
      location_kind?: "string-value";
      member_ordinal?: null;
      utf16_code_unit_index?: number;
      utf16_code_unit?: number;
      message: string;
    })
  | (MigrationCommon & {
      status: "hold-missing-semantics";
      migration_id: string;
      migrator_version: MigratorVersion;
      created_at: string;
      source_version: "0.1";
      source_format: "json" | "yaml";
      source_hash: string;
      input_part: null;
      required_inputs: Array<{ field: string; reason: string }>;
    })
  | (MigrationCommon & {
      status: "migrated";
      migration_id: string;
      migrator_version: MigratorVersion;
      created_at: string;
      source_version: "0.1";
      source_format: "json" | "yaml";
      source_hash: string;
      input_part: null;
      output_hash: string;
      output: LoopeixV02;
      supplied_bindings: string[];
    });

const MAX_INPUT_BYTES = 4_194_304;
const UTF8 = new TextEncoder();

function frozenCredentialScanner(
  stage: MigrationCredentialScanStageV02,
  bytes: Uint8Array,
): ReturnType<MigrationCredentialScannerV02> {
  const value = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const detected = detectCredentialV02(value);
  return detected === null
    ? null
    : {
        rule_id: detected.rule_id,
        provenance: stage.startsWith("binding") ? "bindings" : "source",
      };
}

type AcceptedLineage = {
  migration_id: string;
  migrator_version: MigratorVersion;
  created_at: string;
  source_format: "json" | "yaml";
};

function invalidLineage(input: unknown): LoopeixMigrationResult | AcceptedLineage {
  if (typeof input !== "object" || input === null || Array.isArray(input)) return lineageFailure(null, null, null, null, null);
  const value = input as Partial<MigrateV01ToV02Input>;
  if (!MachineId.safeParse(value.migration_id).success) return lineageFailure(null, null, null, null, "migration_id");
  const migrationId = value.migration_id as string;
  if (typeof value.migrator_version !== "string" || !isSemver(value.migrator_version)) {
    return lineageFailure(migrationId, null, null, null, "migrator_version");
  }
  const migratorVersion = value.migrator_version as MigratorVersion;
  if (typeof value.created_at !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value.created_at)) {
    return lineageFailure(migrationId, migratorVersion, null, null, "created_at");
  }
  const createdAt = value.created_at;
  if (value.source_format !== "json" && value.source_format !== "yaml") {
    return lineageFailure(migrationId, migratorVersion, createdAt, null, "source_format");
  }
  return { migration_id: migrationId, migrator_version: migratorVersion, created_at: createdAt, source_format: value.source_format };
}

function lineageFailure(
  migrationId: string | null,
  migratorVersion: MigratorVersion | null,
  createdAt: string | null,
  sourceFormat: "json" | "yaml" | null,
  field: string | null,
): LoopeixMigrationResult {
  return {
    migration_contract_version: "0.1",
    migration_id: migrationId,
    migrator_version: migratorVersion,
    created_at: createdAt,
    status: "rejected",
    reason: "INVALID_MIGRATION_INPUT",
    source_version: null,
    target_version: "0.2",
    source_format: sourceFormat,
    source_hash: null,
    input_part: "lineage",
    field,
    message: "Migration lineage input is invalid.",
  };
}

function isSemver(value: string): boolean {
  if (Buffer.byteLength(value, "utf8") > 64 || !/^[\x00-\x7f]+$/.test(value)) return false;
  return /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:0|[1-9]\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.test(value)
    && frozenCredentialScanner("source-values", UTF8.encode(value)) === null;
}

function captureBytes(value: unknown): { ok: true; bytes: Uint8Array } | { ok: false } {
  try {
    if (!(value instanceof Uint8Array) || !(value.buffer instanceof ArrayBuffer)) return { ok: false };
    return { ok: true, bytes: Uint8Array.from(value) };
  } catch {
    return { ok: false };
  }
}

function base(lineage: AcceptedLineage): MigrationCommon {
  return {
    migration_contract_version: "0.1",
    ...lineage,
    source_version: null,
    target_version: "0.2",
    source_hash: null,
  };
}

function reject(
  lineage: AcceptedLineage,
  reason: Extract<LoopeixMigrationResult, { status: "rejected" }>["reason"],
  options: Partial<Extract<LoopeixMigrationResult, { status: "rejected" }>> & { message: string },
): LoopeixMigrationResult {
  return { ...base(lineage), status: "rejected", reason, ...options } as LoopeixMigrationResult;
}

export type CanonicalValueIssue = {
  pointer: string;
  location_kind: "string-value" | "object-key";
  member_ordinal: number | null;
  utf16_code_unit_index: number;
  utf16_code_unit: number;
};

function firstUnpaired(value: string): { index: number; unit: number } | null {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return { index, unit };
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return { index, unit };
    }
  }
  return null;
}

function pointerToken(value: string): string {
  return value.replaceAll("~", "~0").replaceAll("/", "~1");
}

function compareUtf16(left: string, right: string): number {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const difference = left.charCodeAt(index) - right.charCodeAt(index);
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

export function findUnsupportedCanonicalValue(input: unknown): CanonicalValueIssue | null {
  const visit = (value: unknown, pointer: string): CanonicalValueIssue | null => {
    if (typeof value === "string") {
      const issue = firstUnpaired(value);
      return issue === null ? null : { pointer, location_kind: "string-value", member_ordinal: null, utf16_code_unit_index: issue.index, utf16_code_unit: issue.unit };
    }
    if (Array.isArray(value)) {
      for (let index = 0; index < value.length; index += 1) {
        const issue = visit(value[index], `${pointer}/${index}`);
        if (issue !== null) return issue;
      }
      return null;
    }
    if (typeof value === "object" && value !== null) {
      const keys = Object.keys(value).sort(compareUtf16);
      for (let ordinal = 0; ordinal < keys.length; ordinal += 1) {
        const key = keys[ordinal];
        if (key === undefined) continue;
        const keyIssue = firstUnpaired(key);
        if (keyIssue !== null) {
          return { pointer, location_kind: "object-key", member_ordinal: ordinal, utf16_code_unit_index: keyIssue.index, utf16_code_unit: keyIssue.unit };
        }
        const issue = visit((value as Record<string, unknown>)[key], `${pointer}/${pointerToken(key)}`);
        if (issue !== null) return issue;
      }
    }
    return null;
  };
  return visit(input, "");
}

function requiredInputs(
  source: { tasks: readonly { id: string }[]; artifacts: readonly { id: string; path: string }[] },
  supplied: ReadonlySet<string> = new Set(),
): Array<{ field: string; reason: string }> {
  const fields = [
    "trigger",
    "goal",
    "gates",
    "evaluations",
    "evidence_requirements",
    "progress",
    "stop_policy",
    "limit_policy",
    "retry_policy",
    "recovery_policy",
    ...source.tasks.flatMap((task) => [
      `tasks.${task.id}.kind`,
      `tasks.${task.id}.pre_task_gate_refs`,
      `side_effects.${task.id}`,
    ]),
  ];
  for (const artifact of source.artifacts) {
    if (!/^artifacts\/content\/[^/\\]+$/.test(artifact.path)) fields.push(`artifacts.${artifact.id}.path`);
  }
  return fields.filter((field) => !supplied.has(field)).sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right))).map((field) => ({
    field,
    reason: `Explicit V02 semantics are required for ${field}.`,
  }));
}

const MigrationGateControlV02 = z.object({
  gate_id: HumanIdV02,
  applicability: GateApplicabilityV02,
  control_kind: z.union([RequiredGateKindV02, z.literal("project-specific")]),
  risk_tier: z.enum(["T0", "T1", "T2", "T3", "T4"]),
  prerequisites: z.array(ControlPrerequisiteV02).min(1),
  evidence_requirement_refs: z.array(HumanIdV02).min(1),
  evaluator_binding: EvaluatorBindingV02,
}).strict();

type RecognizedBinding = {
  key: string;
  variant: string;
  value: unknown;
  subject: string | null;
  record: Record<string, unknown>;
};

type BindingRecognitionResult =
  | { ok: true; binding: RecognizedBinding }
  | { ok: false; field: string | null };

function recognizeBinding(value: unknown): BindingRecognitionResult {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return { ok: false, field: null };
  }
  const record = value as Record<string, unknown>;
  const variant = record.binding;
  if (typeof variant !== "string") return { ok: false, field: null };
  const simpleKeys: Readonly<Record<string, string>> = {
    trigger: "trigger",
    goal: "goal",
    gates: "gates",
    evaluations: "evaluations",
    "evidence-requirements": "evidence_requirements",
    progress: "progress",
    "stop-policy": "stop_policy",
    "limit-policy": "limit_policy",
    "retry-policy": "retry_policy",
    "recovery-policy": "recovery_policy",
  };
  const simpleKey = simpleKeys[variant];
  if (simpleKey !== undefined) {
    return { ok: true, binding: { key: simpleKey, variant, value: record.value, subject: null, record } };
  }
  const parameterized: Readonly<Record<string, { field: "task_id" | "artifact_id" | "compensation_id"; prefix: string; suffix?: string }>> = {
    "task-kind": { field: "task_id", prefix: "tasks.", suffix: ".kind" },
    "task-pre-task-gate-refs": { field: "task_id", prefix: "tasks.", suffix: ".pre_task_gate_refs" },
    "artifact-path": { field: "artifact_id", prefix: "artifacts.", suffix: ".path" },
    "side-effect": { field: "task_id", prefix: "side_effects." },
    compensation: { field: "compensation_id", prefix: "compensations." },
  };
  const definition = parameterized[variant];
  if (definition === undefined) return { ok: false, field: variant };
  const subject = record[definition.field];
  const safeSubject = typeof subject === "string" ? subject : "(invalid)";
  return {
    ok: true,
    binding: {
      key: `${definition.prefix}${safeSubject}${definition.suffix ?? ""}`,
      variant,
      value: record.value,
      subject: typeof subject === "string" ? subject : null,
      record,
    },
  };
}

function exactKeys(record: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(record).sort();
  const sortedExpected = [...expected].sort();
  return actual.length === sortedExpected.length && actual.every((key, index) => key === sortedExpected[index]);
}

function uniqueStrings(value: unknown): boolean {
  return Array.isArray(value) && value.every((item) => HumanIdV02.safeParse(item).success) && new Set(value).size === value.length;
}

function localBindingIsValid(
  binding: RecognizedBinding,
  source: {
    tasks: readonly { id: string }[];
    artifacts: readonly { id: string; path: string; [key: string]: unknown }[];
  },
): boolean {
  const simpleSchemas: Readonly<Record<string, ZodType>> = {
    trigger: TriggerSpecV02,
    goal: GoalSpecV02,
    gates: z.array(MigrationGateControlV02),
    evaluations: z.array(EvaluationSpecV02),
    "evidence-requirements": z.array(EvidenceRequirementSpecV02).min(1),
    progress: ProgressSpecV02,
    "stop-policy": StopPolicyV02,
    "limit-policy": LimitPolicyV02,
    "retry-policy": RetryPolicyV02,
    "recovery-policy": RecoveryPolicyV02,
  };
  const simple = simpleSchemas[binding.variant];
  if (simple !== undefined) {
    return exactKeys(binding.record, ["binding", "value"]) && simple.safeParse(binding.value).success;
  }

  if (binding.subject === null || !HumanIdV02.safeParse(binding.subject).success) return false;
  const idField = binding.variant === "artifact-path"
    ? "artifact_id"
    : binding.variant === "compensation"
      ? "compensation_id"
      : "task_id";
  if (!exactKeys(binding.record, ["binding", idField, "value"])) return false;

  if (binding.variant === "task-kind") {
    return source.tasks.some((task) => task.id === binding.subject) && (binding.value === "work" || binding.value === "compensation");
  }
  if (binding.variant === "task-pre-task-gate-refs") {
    return source.tasks.some((task) => task.id === binding.subject) && uniqueStrings(binding.value);
  }
  if (binding.variant === "artifact-path") {
    const artifact = source.artifacts.find((item) => item.id === binding.subject);
    return artifact !== undefined && ArtifactSpecV02.safeParse({ ...artifact, path: binding.value }).success;
  }
  if (binding.variant === "side-effect") {
    return source.tasks.some((task) => task.id === binding.subject)
      && SideEffectSpecV02.safeParse(binding.value).success
      && (binding.value as { task_id: string }).task_id === binding.subject;
  }
  const parsedCompensation = CompensationSpecV02.safeParse(binding.value);
  if (!parsedCompensation.success || parsedCompensation.data.id !== binding.subject) return false;
  const taskIds = new Set(source.tasks.map((task) => task.id));
  if (!taskIds.has(parsedCompensation.data.for_task) || !taskIds.has(parsedCompensation.data.action_task)) {
    return false;
  }
  return parsedCompensation.data.preconditions.every((precondition) =>
    precondition.source !== "effect" || taskIds.has(precondition.task_ref),
  );
}

function canonicalBindingOrder(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function migrateCore(input: MigrateV01ToV02Input, scanner: MigrationCredentialScannerV02): LoopeixMigrationResult {
  const lineage = invalidLineage(input);
  if ("status" in lineage) return lineage;

  let sourceLength: number;
  try {
    if (!(input.source_bytes instanceof Uint8Array) || !(input.source_bytes.buffer instanceof ArrayBuffer)) {
      return reject(lineage, "INVALID_BYTE_VIEW", { input_part: "source", field: null, message: "Source byte view is invalid." });
    }
    sourceLength = input.source_bytes.byteLength;
  } catch {
    return reject(lineage, "INVALID_BYTE_VIEW", { input_part: "source", field: null, message: "Source byte view is invalid." });
  }
  if (sourceLength > MAX_INPUT_BYTES) return reject(lineage, "INPUT_TOO_LARGE", { input_part: "source", field: null, message: "Source exceeds 4194304 bytes." });
  const sourceCapture = captureBytes(input.source_bytes);
  if (!sourceCapture.ok) return reject(lineage, "INVALID_BYTE_VIEW", { input_part: "source", field: null, message: "Source byte view is invalid." });

  const rawFinding = scanner("source-bytes", sourceCapture.bytes);
  if (rawFinding !== null) return reject(lineage, "SENSITIVE_INPUT_REJECTED", { location: "source", rule_id: rawFinding.rule_id, message: "Sensitive input rejected." });

  const decoded = decodeStructuredDocumentV02(sourceCapture.bytes, lineage.source_format);
  if (!decoded.ok) return reject(lineage, decoded.reason, { input_part: "source", field: null, message: decoded.message });
  const parsed = parseLoopeixDocument(decoded.value);
  if (!parsed.ok) {
    if (parsed.schema_version === null) return reject(lineage, parsed.reason, { input_part: "source", field: "schema_version", message: parsed.message });
    if (parsed.schema_version === "0.2") return reject(lineage, "UNSUPPORTED_SCHEMA_VERSION", { input_part: "source", field: "schema_version", message: "Only literal V01 sources can migrate." });
    return reject(lineage, "INVALID_SOURCE_V01", { input_part: "source", field: parsed.issues[0]?.path ?? null, message: "Source is not valid frozen V01." });
  }
  if (parsed.schema_version !== "0.1") return reject(lineage, "UNSUPPORTED_SCHEMA_VERSION", { input_part: "source", field: "schema_version", message: "Only literal V01 sources can migrate." });

  const valueBytes = UTF8.encode(JSON.stringify(parsed.value));
  const valueFinding = scanner("source-values", valueBytes);
  if (valueFinding !== null) return reject(lineage, "SENSITIVE_INPUT_REJECTED", { source_version: "0.1", location: "source", rule_id: valueFinding.rule_id, message: "Sensitive input rejected." });
  const sourceHash = hashRawBytes(sourceCapture.bytes);
  const canonicalIssue = findUnsupportedCanonicalValue(parsed.value);
  if (canonicalIssue !== null && canonicalIssue.location_kind === "string-value") {
    return reject(lineage, "UNSUPPORTED_CANONICAL_VALUE", {
      source_version: "0.1",
      source_hash: sourceHash,
      input_part: "source",
      field: canonicalIssue.pointer,
      location_kind: "string-value",
      member_ordinal: null,
      utf16_code_unit_index: canonicalIssue.utf16_code_unit_index,
      utf16_code_unit: canonicalIssue.utf16_code_unit,
      message: "Source contains an unsupported canonical string value.",
    });
  }

  let bindingLength: number;
  try {
    if (!(input.bindings_bytes instanceof Uint8Array) || !(input.bindings_bytes.buffer instanceof ArrayBuffer)) {
      return reject(lineage, "INVALID_BYTE_VIEW", { source_version: "0.1", source_hash: sourceHash, input_part: "bindings", field: null, message: "Bindings byte view is invalid." });
    }
    bindingLength = input.bindings_bytes.byteLength;
  } catch {
    return reject(lineage, "INVALID_BYTE_VIEW", { source_version: "0.1", source_hash: sourceHash, input_part: "bindings", field: null, message: "Bindings byte view is invalid." });
  }
  if (bindingLength > MAX_INPUT_BYTES) return reject(lineage, "INPUT_TOO_LARGE", { source_version: "0.1", source_hash: sourceHash, input_part: "bindings", field: null, message: "Bindings exceed 4194304 bytes." });
  const bindingCapture = captureBytes(input.bindings_bytes);
  if (!bindingCapture.ok) return reject(lineage, "INVALID_BYTE_VIEW", { source_version: "0.1", source_hash: sourceHash, input_part: "bindings", field: null, message: "Bindings byte view is invalid." });
  const bindingFinding = scanner("binding-bytes", bindingCapture.bytes);
  if (bindingFinding !== null) return reject(lineage, "SENSITIVE_INPUT_REJECTED", { source_version: "0.1", location: "bindings", rule_id: bindingFinding.rule_id, message: "Sensitive input rejected." });
  const decodedBindings = decodeStructuredDocumentV02(bindingCapture.bytes, "json");
  if (!decodedBindings.ok || !Array.isArray(decodedBindings.value)) {
    return reject(lineage, decodedBindings.ok ? "INVALID_DOCUMENT_ENVELOPE" : decodedBindings.reason, { source_version: "0.1", source_hash: sourceHash, input_part: "bindings", field: null, message: decodedBindings.ok ? "Bindings must be one JSON array." : decodedBindings.message });
  }
  const bindingValueFinding = scanner("binding-values", UTF8.encode(JSON.stringify(decodedBindings.value)));
  if (bindingValueFinding !== null) return reject(lineage, "SENSITIVE_INPUT_REJECTED", { source_version: "0.1", location: "bindings", rule_id: bindingValueFinding.rule_id, message: "Sensitive input rejected." });

  const recognized: RecognizedBinding[] = [];
  for (const rawBinding of decodedBindings.value) {
    const result = recognizeBinding(rawBinding);
    if (!result.ok) {
      return reject(lineage, "UNKNOWN_BINDING_PATH", {
        source_version: "0.1",
        source_hash: sourceHash,
        input_part: "bindings",
        field: result.field,
        message: "Migration binding is not recognized.",
      });
    }
    recognized.push(result.binding);
  }

  recognized.sort((left, right) => canonicalBindingOrder(left.key, right.key));
  for (let index = 1; index < recognized.length; index += 1) {
    const current = recognized[index];
    const previous = recognized[index - 1];
    if (current !== undefined && previous !== undefined && current.key === previous.key) {
      return reject(lineage, "DUPLICATE_BINDING", {
        source_version: "0.1",
        source_hash: sourceHash,
        input_part: "bindings",
        field: current.key,
        message: "Migration binding is duplicated.",
      });
    }
  }
  for (const binding of recognized) {
    if (!localBindingIsValid(binding, parsed.value)) {
      return reject(lineage, "INVALID_BINDING_VALUE", {
        source_version: "0.1",
        source_hash: sourceHash,
        input_part: "bindings",
        field: binding.key,
        message: "Migration binding value is invalid.",
      });
    }
  }

  const supplied = new Set(recognized.map((binding) => binding.key));
  const missing = requiredInputs(parsed.value, supplied);
  if (missing.length > 0) {
    return {
      ...base(lineage),
      migration_id: lineage.migration_id,
      migrator_version: lineage.migrator_version,
      created_at: lineage.created_at,
      status: "hold-missing-semantics",
      source_version: "0.1",
      source_format: lineage.source_format,
      source_hash: sourceHash,
      input_part: null,
      required_inputs: missing,
    };
  }

  const bindingByKey = new Map(recognized.map((binding) => [binding.key, binding]));
  const value = (key: string): unknown => bindingByKey.get(key)?.value;
  const gateControls = value("gates") as Array<Record<string, unknown>>;
  const candidate: unknown = {
    schema_version: "0.2",
    loop_family: parsed.value.loop_family,
    version: parsed.value.version,
    trigger: value("trigger"),
    goal: value("goal"),
    inputs: parsed.value.inputs,
    context_contract: parsed.value.context_contract,
    workflow_pattern: parsed.value.workflow_pattern,
    roles: parsed.value.roles,
    tasks: parsed.value.tasks.map((task) => ({
      ...task,
      kind: value(`tasks.${task.id}.kind`),
      pre_task_gate_refs: value(`tasks.${task.id}.pre_task_gate_refs`),
    })),
    tool_grants: parsed.value.tool_grants,
    artifacts: parsed.value.artifacts.map((artifact) => ({
      ...artifact,
      path: bindingByKey.has(`artifacts.${artifact.id}.path`)
        ? value(`artifacts.${artifact.id}.path`)
        : artifact.path,
    })),
    gates: parsed.value.gates.map((gate, index) => {
      const control = gateControls[index] ?? {};
      const { gate_id: _gateId, ...members } = control;
      return { ...gate, ...members };
    }),
    evaluations: value("evaluations"),
    evidence_requirements: value("evidence_requirements"),
    risk_controls: parsed.value.risk_controls,
    progress: value("progress"),
    stop_policy: value("stop_policy"),
    limit_policy: value("limit_policy"),
    retry_policy: value("retry_policy"),
    recovery_policy: value("recovery_policy"),
    side_effects: parsed.value.tasks.map((task) => value(`side_effects.${task.id}`)),
    compensations: recognized
      .filter((binding) => binding.variant === "compensation")
      .map((binding) => binding.value),
    retro: parsed.value.retro,
  };
  const validated = parseLoopeixDocument(candidate);
  if (!validated.ok || validated.schema_version !== "0.2") {
    return reject(lineage, "INVALID_BINDING_VALUE", {
      source_version: "0.1",
      source_hash: sourceHash,
      input_part: "bindings",
      field: recognized[0]?.key ?? null,
      message: "The complete migrated V02 candidate is invalid.",
    });
  }

  let canonicalOutput: string;
  try {
    canonicalOutput = canonicalize(validated.value);
  } catch {
    return reject(lineage, "CANONICALIZATION_FAILED", {
      source_version: "0.1",
      source_hash: sourceHash,
      input_part: null,
      field: null,
      message: "The migrated output could not be canonicalized.",
    });
  }
  const outputBytes = UTF8.encode(canonicalOutput);
  const finalFinding = scanner("final-output", outputBytes);
  if (finalFinding !== null) {
    return reject(lineage, "SENSITIVE_INPUT_REJECTED", {
      source_version: "0.1",
      location: finalFinding.provenance,
      rule_id: finalFinding.rule_id,
      message: "Sensitive input rejected.",
    });
  }

  return {
    ...base(lineage),
    migration_id: lineage.migration_id,
    migrator_version: lineage.migrator_version,
    created_at: lineage.created_at,
    status: "migrated",
    source_version: "0.1",
    source_format: lineage.source_format,
    source_hash: sourceHash,
    input_part: null,
    output_hash: hashRawBytes(outputBytes),
    output: validated.value,
    supplied_bindings: [...supplied].sort(canonicalBindingOrder),
  };
}

export function migrateV01ToV02(input: MigrateV01ToV02Input): LoopeixMigrationResult {
  return migrateCore(input, frozenCredentialScanner);
}

export function migrateV01ToV02WithCredentialScannerForTest(
  input: MigrateV01ToV02Input,
  scanner: MigrationCredentialScannerV02,
): LoopeixMigrationResult {
  return migrateCore(input, scanner);
}

export function canonicalizeMigratedOutputForTest(value: LoopeixV02): string | null {
  try {
    return canonicalize(value);
  } catch {
    return null;
  }
}
