import { z } from "zod";
import { canonicalize, hashCanonical } from "../hash.js";
import { ArtifactType } from "./loopeix.js";
import {
  ArtifactSpecV02,
  CompensationSpecV02,
  EvaluationSpecV02,
  EvidenceKindV02,
  EvidenceRequirementSpecV02,
  GateSpecV02,
  GoalSpecV02,
  LimitPolicyV02,
  ProgressSpecV02,
  RecoveryPolicyV02,
  RetryClassV02,
  RetryPolicyV02,
  SideEffectSpecV02,
  SpecialistRoleSpecV02,
  StopPolicyV02,
  TaskSpecV02,
  ToolGrantV02,
  TriggerSpecV02,
} from "./loopeix-v02.js";
import {
  HumanIdV02 as HumanId,
  IsoTimestampV02 as IsoTimestamp,
  MachineIdV02 as MachineId,
  NonBlankStringV02 as NonBlankString,
  RelativeRunPathV02 as RelativeRunPath,
  FreeControlStringV02 as FreeControlString,
  UnicodeScalarStringV02 as UnicodeScalarString,
  boundedArrayV02,
} from "./scalars-v02.js";
import {
  Hash,
  HumanId as HumanIdV01,
  IsoTimestamp as IsoTimestampV01,
  LoopVersion,
  MachineId as MachineIdV01,
  RiskTier,
  RiskTierV1,
  SchemaVersion,
} from "./scalars.js";

/**
 * Runtime record schemas (schema-runtime-contract.md + runtime-file-contracts.md).
 * Well-specified scalar/enum/hash fields are validated precisely (these carry the
 * integrity rules the invalid/runtime fixtures test). Nested objects the contract
 * leaves unspecified are accepted permissively rather than invented.
 */

const anyObject = z.record(z.string(), z.unknown());
const anyArray = z.array(z.unknown());
const strictObject = <T extends z.ZodRawShape>(shape: T): z.ZodObject<T> => z.object(shape).strict();
const safeInteger = z.number().int().refine(Number.isSafeInteger, { message: "must be a safe integer" });
const RUNTIME_UTF8 = new TextEncoder();

export function compareRuntimeUtf8BytesV02(left: string, right: string): number {
  const leftBytes = RUNTIME_UTF8.encode(left);
  const rightBytes = RUNTIME_UTF8.encode(right);
  const length = Math.min(leftBytes.length, rightBytes.length);
  for (let index = 0; index < length; index += 1) {
    const difference = leftBytes[index]! - rightBytes[index]!;
    if (difference !== 0) return difference;
  }
  return leftBytes.length - rightBytes.length;
}

type RuntimeDocumentIssue = { path: string; message: string };

export const RetentionClass = z.enum(["short", "run", "project", "quarantine"]);

/** Provisional shape (not field-enumerated in S3); matches fixtures. */
export const RedactionState = z.object({
  redacted: z.boolean(),
  policy_version: z.string(),
  targets_removed: z.array(z.string()),
});

export const ResolvedRunPlan = z.object({
  schema_version: SchemaVersion,
  run_id: MachineIdV01,
  loop_family: HumanIdV01,
  loopeix_version: LoopVersion,
  loopeix_version_hash: Hash,
  work_item_id: MachineIdV01,
  intake_brief_id: MachineIdV01,
  created_at: IsoTimestampV01,
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

export const ResolvedRunPlanV01 = ResolvedRunPlan;
export type ResolvedRunPlanV01Value = z.infer<typeof ResolvedRunPlanV01>;

const ResolvedRunPlanV01Dispatch = ResolvedRunPlan.extend({
  schema_version: z.literal("0.1"),
});

const RuntimeRecordLimitsV02 = strictObject({
  max_authority_records: safeInteger.positive(),
  max_agency_recommendation_records: safeInteger.positive(),
  max_authority_revocation_records: safeInteger.positive(),
  max_evidence_records: safeInteger.positive(),
  max_task_result_records: safeInteger.positive(),
  max_manual_observation_records: safeInteger.positive(),
  max_export_decision_records: safeInteger.positive(),
  max_claim_records: safeInteger.positive(),
  max_finding_records: safeInteger.positive(),
  max_waiver_records: safeInteger.positive(),
  max_preseal_custody_events: safeInteger.positive(),
});

const RoleAssignmentV02 = strictObject({
  role_ref: HumanId,
  actor_ref: MachineId,
  actor_kind: z.enum(["operator", "agent", "service"]),
  stable_identity_hash: Hash,
});

const Hex40 = z.string().regex(/^[a-f0-9]{40}$/);
const Hex64 = z.string().regex(/^[a-f0-9]{64}$/);
const Utf8SortedUniqueStrings = boundedArrayV02(FreeControlString, { min: 0, max: 256 }).superRefine((values, ctx) => {
  for (let index = 1; index < values.length; index += 1) {
    if (compareRuntimeUtf8BytesV02(values[index - 1]!, values[index]!) >= 0) {
      ctx.addIssue({ code: "custom", path: [index], message: "must be unique and sorted by UTF-8 bytes" });
    }
  }
});

const GitObjectIdV02 = z.discriminatedUnion("algorithm", [
  strictObject({ algorithm: z.literal("sha1"), value: Hex40 }),
  strictObject({ algorithm: z.literal("sha256"), value: Hex64 }),
]);

const RepositoryBaseRefV02 = strictObject({
  kind: z.literal("git-ref"),
  canonical_ref_name: NonBlankString,
  object_id: GitObjectIdV02,
  identity_hash: Hash,
});

const RepositoryStateV02 = strictObject({
  repository_root_ref: MachineId,
  base_ref_identity_hash: Hash,
  head: GitObjectIdV02,
  merge_base: GitObjectIdV02,
  head_state_hash: Hash,
  tracked_diff_hash: Hash,
  staged_diff_hash: Hash,
  untracked_content_hash: Hash,
  submodule_state_hash: Hash,
  repository_state_hash: Hash,
});

const VerifiedRepositoryStateV02 = RepositoryStateV02.superRefine((state, ctx) => {
  const expected = hashCanonical({
    purpose: "repository-state-v02",
    repository_root_ref: state.repository_root_ref,
    base_ref_identity_hash: state.base_ref_identity_hash,
    head: state.head,
    merge_base: state.merge_base,
    head_state_hash: state.head_state_hash,
    tracked_diff_hash: state.tracked_diff_hash,
    staged_diff_hash: state.staged_diff_hash,
    untracked_content_hash: state.untracked_content_hash,
    submodule_state_hash: state.submodule_state_hash,
  });
  if (state.repository_state_hash !== expected) {
    ctx.addIssue({ code: "custom", path: ["repository_state_hash"], message: "repository state hash must match its exact preimage" });
  }
});

const HumanExceptionDestinationV02 = strictObject({
  operator_role_ref: HumanId,
  operator_actor_ref: MachineId,
  operator_stable_identity_hash: Hash,
});

const PolicyActionKindV1 = z.enum([
  "planning",
  "local-read",
  "deterministic-no-side-effect-check",
  "authenticated-read",
  "network-read",
  "reversible-workspace-edit",
  "authenticated-write",
  "commit",
  "deploy",
  "destructive-action",
  "irreversible-action",
  "merge",
  "new-secret-scope",
  "package-change",
  "protected-ref-mutation",
  "publish",
  "push",
  "rebase",
  "release",
  "send",
  "t4-action",
  "approval-contract-edit",
  "connector-admin",
  "connector-delete",
  "force-push",
  "policy-weakening",
  "self-widening",
  "t5-action",
  "uninspectable-side-effect",
]);
const ActionApprovalClassV1 = z.enum(["automatic", "agency", "human_exception", "blocked"]);
const ActionClassifierKeyV1 = strictObject({
  action_class: z.enum(["task", "tool", "artifact-write"]),
  dispatch_kind: z.enum(["process", "tool", "connector", "artifact-write"]),
  adapter_ref: HumanId,
  adapter_version_hash: Hash,
  capability_ref: HumanId,
  capability_definition_hash: Hash,
  operation: z.enum(["read", "write", "delete", "export", "send", "waive"]),
  effective_risk_tier: RiskTierV1,
  effect_classes: z.array(z.enum(["none", "workspace-write", "external-read", "external-write", "destructive"])),
  all_effects_inspectable: z.boolean(),
  all_effects_reversible: z.boolean(),
  data_access_mode: z.enum(["none", "local", "authenticated", "network", "export"]),
  repository_transition_intent: z.enum(["none", "workspace-edit", "commit", "protected-ref-mutation"]),
  cost_mode: z.enum(["none", "metered"]),
});
const ActionClassifierRuleV1 = strictObject({
  rule_version: z.literal("0.1"),
  key: ActionClassifierKeyV1,
  policy_action_kind: PolicyActionKindV1,
  action_approval_class: ActionApprovalClassV1,
  rule_hash: Hash,
});
const ActionClassifierRegistryV1 = strictObject({
  registry_version: z.literal("0.1"),
  rules: z.array(ActionClassifierRuleV1).min(1),
  registry_hash: Hash,
});
const ActionApprovalPolicyEntryV1 = strictObject({
  action_kind: PolicyActionKindV1,
  approval_class: ActionApprovalClassV1,
  classifier_rule_hash: Hash,
});
const ActionApprovalPolicyV1 = strictObject({
  registry_version: z.literal("0.1"),
  policy_digest: Hash,
  classifier_registry: ActionClassifierRegistryV1,
  entries: z.array(ActionApprovalPolicyEntryV1).min(1),
  human_exception_action_kinds: z.tuple([
    z.literal("authenticated-write"),
    z.literal("commit"),
    z.literal("deploy"),
    z.literal("destructive-action"),
    z.literal("irreversible-action"),
    z.literal("merge"),
    z.literal("new-secret-scope"),
    z.literal("package-change"),
    z.literal("protected-ref-mutation"),
    z.literal("publish"),
    z.literal("push"),
    z.literal("rebase"),
    z.literal("release"),
    z.literal("send"),
    z.literal("t4-action"),
  ]),
  blocked_action_kinds: z.tuple([
    z.literal("approval-contract-edit"),
    z.literal("connector-admin"),
    z.literal("connector-delete"),
    z.literal("force-push"),
    z.literal("policy-weakening"),
    z.literal("self-widening"),
    z.literal("t5-action"),
    z.literal("uninspectable-side-effect"),
  ]),
  registry_hash: Hash,
});
const AuthorityMissionSubjectV02 = strictObject({
  objective: NonBlankString,
  success_criteria: GoalSpecV02.shape.success_criteria,
  forbidden_outcomes: Utf8SortedUniqueStrings.min(1),
  terminal_states: StopPolicyV02.shape.terminal_states,
});
const AuthoritySubjectV02 = strictObject({
  mission: AuthorityMissionSubjectV02,
  repository: strictObject({
    spec_subject: strictObject({
      source_authoring_hash: Hash,
      loopeix_version_hash: Hash,
    }),
    compile_subject: strictObject({
      compile_pack_manifest_hash: Hash,
      compiler_bundle_id: MachineId,
      catalog_version_hash: Hash,
      binding_input_hash: Hash,
    }),
    repository_root_ref: MachineId,
    object_format: z.enum(["sha1", "sha256"]),
    base_ref: RepositoryBaseRefV02,
    transition_mode: z.enum(["read-only", "linear-settled-writes"]),
    initial_state: RepositoryStateV02,
  }),
  protection: strictObject({
    delegation_mode: z.enum(["none", "strict-subset-once"]),
    action_approval_policy: ActionApprovalPolicyV1,
    planning_approval_hash: Hash,
    invalidation_rules: z.tuple([
      z.literal("spec-subject-changed"),
      z.literal("compile-subject-changed"),
      z.literal("plan-hash-changed"),
      z.literal("planning-approval-changed"),
      z.literal("policy-digest-changed"),
      z.literal("repository-root-changed"),
      z.literal("repository-base-ref-changed"),
      z.literal("repository-state-chain-broken"),
      z.literal("authorized-change-set-mismatched"),
      z.literal("tool-definition-changed"),
      z.literal("authority-revoked"),
      z.literal("authority-expired"),
    ]),
    human_exception_destination: HumanExceptionDestinationV02,
  }),
  policy_digest: Hash,
});
const AssuranceProfileV02 = strictObject({
  id: HumanId,
  tightens: z.array(HumanId),
});
const ContextSnapshotV02 = strictObject({
  required: z.array(z.string()),
  forbidden: z.array(z.string()),
  untrusted_sources: z.array(z.string()),
});
const WorkspaceBoundaryV02 = strictObject({
  workspace_root: z.string().min(1),
  read: z.array(z.string().min(1)).min(1),
  write: z.array(z.string().min(1)).min(1),
});
const AdapterPlanV02 = strictObject({
  engine: z.enum(["codex_cli", "claude_code_cli"]),
  command: z.string().min(1),
  permission_mode: z.enum(["workspace-write", "read-only", "danger-full-access"]),
  known_gaps: z.array(z.string()),
});

export const ResolvedRunPlanV02 = strictObject({
  schema_version: z.literal("0.2"),
  execution_profile: z.literal("bounded-v02"),
  run_id: MachineId,
  loop_family: HumanId,
  loopeix_version: LoopVersion,
  loopeix_version_hash: Hash,
  source_authoring_hash: Hash,
  compiler_bundle_id: MachineId,
  catalog_version_hash: Hash,
  binding_input_id: MachineId,
  binding_input_hash: Hash,
  compile_pack_manifest_hash: Hash,
  work_item_id: MachineId,
  intake_brief_id: MachineId,
  created_at: IsoTimestamp,
  trigger: TriggerSpecV02,
  goal: GoalSpecV02,
  roles: z.array(SpecialistRoleSpecV02),
  tasks: z.array(TaskSpecV02),
  artifacts: z.array(ArtifactSpecV02),
  gates: z.array(GateSpecV02),
  evaluations: z.array(EvaluationSpecV02),
  evidence_requirements: z.array(EvidenceRequirementSpecV02),
  progress: ProgressSpecV02,
  stop_policy: StopPolicyV02,
  limit_policy: LimitPolicyV02,
  retry_policy: RetryPolicyV02,
  recovery_policy: RecoveryPolicyV02,
  side_effects: z.array(SideEffectSpecV02),
  compensations: z.array(CompensationSpecV02),
  runtime_record_limits: RuntimeRecordLimitsV02,
  required_control_plane_output_bytes: safeInteger.positive(),
  assurance_profile: AssuranceProfileV02,
  context_snapshot: ContextSnapshotV02,
  authority_subject: AuthoritySubjectV02,
  role_assignments: z.array(RoleAssignmentV02),
  tool_grants: z.array(ToolGrantV02),
  workspace_boundary: WorkspaceBoundaryV02,
  adapter_plan: AdapterPlanV02,
  risk_controls: strictObject({
    max_tier_without_approval: RiskTierV1,
    t5_allowed: z.literal(false),
  }),
}).superRefine((plan, ctx) => {
  const idCollections: readonly [string, readonly { id: string }[]][] = [
    ["roles", plan.roles],
    ["tasks", plan.tasks],
    ["artifacts", plan.artifacts],
    ["gates", plan.gates],
    ["evaluations", plan.evaluations],
    ["evidence_requirements", plan.evidence_requirements],
    ["progress.observations", plan.progress.observations],
    ["compensations", plan.compensations],
    ["tool_grants", plan.tool_grants],
  ];
  for (const [path, values] of idCollections) {
    if (new Set(values.map((value) => value.id)).size !== values.length) {
      ctx.addIssue({ code: "custom", path: path.split("."), message: "IDs must be unique" });
    }
  }
  const retryByTask = new Map<string, number>();
  for (const rule of plan.retry_policy.rules) {
    retryByTask.set(rule.task_ref, Math.max(retryByTask.get(rule.task_ref) ?? 0, rule.max_task_executions));
  }
  const taskIds = new Set(plan.tasks.map((task) => task.id));
  const roleIds = new Set(plan.roles.map((role) => role.id));
  const artifactIds = new Set(plan.artifacts.map((artifact) => artifact.id));
  const gateIds = new Set(plan.gates.map((gate) => gate.id));
  const evaluationIds = new Set(plan.evaluations.map((evaluation) => evaluation.id));
  const evidenceIds = new Set(plan.evidence_requirements.map((requirement) => requirement.id));
  for (const [index, task] of plan.tasks.entries()) {
    if (!roleIds.has(task.role)) ctx.addIssue({ code: "custom", path: ["tasks", index, "role"], message: "must reference a declared role" });
    for (const ref of task.artifacts) if (!artifactIds.has(ref)) ctx.addIssue({ code: "custom", path: ["tasks", index, "artifacts"], message: "must reference declared artifacts" });
    for (const ref of task.depends_on) if (!taskIds.has(ref)) ctx.addIssue({ code: "custom", path: ["tasks", index, "depends_on"], message: "must reference declared tasks" });
    for (const ref of task.pre_task_gate_refs) if (!gateIds.has(ref)) ctx.addIssue({ code: "custom", path: ["tasks", index, "pre_task_gate_refs"], message: "must reference declared gates" });
  }
  for (const [index, artifact] of plan.artifacts.entries()) {
    if (!taskIds.has(artifact.producer_task)) ctx.addIssue({ code: "custom", path: ["artifacts", index, "producer_task"], message: "must reference a declared task" });
  }
  for (const criterion of plan.goal.success_criteria) {
    for (const ref of criterion.evaluation_refs) if (!evaluationIds.has(ref)) ctx.addIssue({ code: "custom", path: ["goal", "success_criteria"], message: "must reference declared evaluations" });
  }
  for (const [index, gate] of plan.gates.entries()) {
    for (const ref of gate.evidence_requirement_refs) if (!evidenceIds.has(ref)) ctx.addIssue({ code: "custom", path: ["gates", index, "evidence_requirement_refs"], message: "must reference declared evidence requirements" });
  }
  for (const [index, evaluation] of plan.evaluations.entries()) {
    for (const ref of evaluation.evidence_requirement_refs) if (!evidenceIds.has(ref)) ctx.addIssue({ code: "custom", path: ["evaluations", index, "evidence_requirement_refs"], message: "must reference declared evidence requirements" });
  }
  const retryPairs = plan.retry_policy.rules.map((rule) => `${rule.task_ref}\0${rule.failure_class}`);
  if (new Set(retryPairs).size !== retryPairs.length || retryPairs.length !== taskIds.size * 7) {
    ctx.addIssue({ code: "custom", path: ["retry_policy", "rules"], message: "every task requires each retry class exactly once" });
  }
  const sideEffectTaskIds = plan.side_effects.map((sideEffect) => sideEffect.task_id);
  if (new Set(sideEffectTaskIds).size !== taskIds.size || sideEffectTaskIds.some((taskId) => !taskIds.has(taskId))) {
    ctx.addIssue({ code: "custom", path: ["side_effects"], message: "exactly one side-effect container is required per task" });
  }
  const successCriteria = plan.goal.success_criteria.length;
  const gateCount = plan.gates.length;
  const evaluationCount = plan.evaluations.length;
  const artifactCount = plan.artifacts.length;
  const compensationCount = plan.compensations.length;
  const attemptBudget = plan.tasks.reduce((sum, task) => sum + (retryByTask.get(task.id) ?? 0), 0);
  const expectedLimits = {
    max_authority_records: 9 * attemptBudget + 10 * gateCount,
    max_agency_recommendation_records: 8 * (2 * attemptBudget + compensationCount),
    max_authority_revocation_records: attemptBudget + 2 * gateCount,
    max_evidence_records: 8 * attemptBudget + 12 * gateCount + 4 * evaluationCount + 2 * artifactCount + 32,
    max_task_result_records: attemptBudget,
    max_manual_observation_records: 8 * attemptBudget + 12 * gateCount + 4 * evaluationCount + 2 * artifactCount + 32,
    max_export_decision_records: artifactCount + (8 * attemptBudget + 12 * gateCount + 4 * evaluationCount + 2 * artifactCount + 32),
    max_claim_records: successCriteria + gateCount + evaluationCount,
    max_finding_records: 4 * attemptBudget + 2 * gateCount + 2 * evaluationCount + 2 * artifactCount + 32,
    max_waiver_records: gateCount,
    max_preseal_custody_events: 2 * (artifactCount + (8 * attemptBudget + 12 * gateCount + 4 * evaluationCount + 2 * artifactCount + 32)),
  } as const;
  for (const [key, value] of Object.entries(expectedLimits)) {
    if (plan.runtime_record_limits[key as keyof typeof expectedLimits] !== value) {
      ctx.addIssue({ code: "custom", path: ["runtime_record_limits", key], message: "does not match the contract formula" });
    }
  }
  if (plan.goal.statement !== plan.authority_subject.mission.objective) {
    ctx.addIssue({ code: "custom", path: ["authority_subject", "mission", "objective"], message: "must equal goal.statement" });
  }
  if (JSON.stringify(plan.goal.success_criteria) !== JSON.stringify(plan.authority_subject.mission.success_criteria)) {
    ctx.addIssue({ code: "custom", path: ["authority_subject", "mission", "success_criteria"], message: "must equal goal.success_criteria exactly" });
  }
  if (JSON.stringify(plan.stop_policy.terminal_states) !== JSON.stringify(plan.authority_subject.mission.terminal_states)) {
    ctx.addIssue({ code: "custom", path: ["authority_subject", "mission", "terminal_states"], message: "must equal stop_policy.terminal_states exactly" });
  }
  if (plan.source_authoring_hash !== plan.authority_subject.repository.spec_subject.source_authoring_hash) {
    ctx.addIssue({ code: "custom", path: ["authority_subject", "repository", "spec_subject", "source_authoring_hash"], message: "must equal source_authoring_hash" });
  }
  if (plan.loopeix_version_hash !== plan.authority_subject.repository.spec_subject.loopeix_version_hash) {
    ctx.addIssue({ code: "custom", path: ["authority_subject", "repository", "spec_subject", "loopeix_version_hash"], message: "must equal loopeix_version_hash" });
  }
  if (plan.compile_pack_manifest_hash !== plan.authority_subject.repository.compile_subject.compile_pack_manifest_hash) {
    ctx.addIssue({ code: "custom", path: ["authority_subject", "repository", "compile_subject", "compile_pack_manifest_hash"], message: "must equal compile_pack_manifest_hash" });
  }
  if (plan.compiler_bundle_id !== plan.authority_subject.repository.compile_subject.compiler_bundle_id) {
    ctx.addIssue({ code: "custom", path: ["authority_subject", "repository", "compile_subject", "compiler_bundle_id"], message: "must equal compiler_bundle_id" });
  }
  if (plan.catalog_version_hash !== plan.authority_subject.repository.compile_subject.catalog_version_hash) {
    ctx.addIssue({ code: "custom", path: ["authority_subject", "repository", "compile_subject", "catalog_version_hash"], message: "must equal catalog_version_hash" });
  }
  if (plan.binding_input_hash !== plan.authority_subject.repository.compile_subject.binding_input_hash) {
    ctx.addIssue({ code: "custom", path: ["authority_subject", "repository", "compile_subject", "binding_input_hash"], message: "must equal binding_input_hash" });
  }
  if (plan.authority_subject.policy_digest !== plan.authority_subject.protection.action_approval_policy.policy_digest) {
    ctx.addIssue({ code: "custom", path: ["authority_subject", "policy_digest"], message: "must equal action_approval_policy.policy_digest" });
  }
  const sortedAssignments = [...plan.role_assignments].sort((left, right) =>
    left.role_ref === right.role_ref
      ? compareRuntimeUtf8BytesV02(left.actor_ref, right.actor_ref)
      : compareRuntimeUtf8BytesV02(left.role_ref, right.role_ref),
  );
  if (JSON.stringify(plan.role_assignments) !== JSON.stringify(sortedAssignments)) {
    ctx.addIssue({ code: "custom", path: ["role_assignments"], message: "must be sorted by role then actor" });
  }
  const roleActorPairs = new Set<string>();
  const actorByRef = new Map<string, { actor_kind: string; stable_identity_hash: string }>();
  const actorByStableIdentity = new Map<string, string>();
  for (const [index, assignment] of plan.role_assignments.entries()) {
    const pair = `${assignment.role_ref}\0${assignment.actor_ref}`;
    if (roleActorPairs.has(pair)) {
      ctx.addIssue({ code: "custom", path: ["role_assignments", index], message: "role/actor pairs must be unique" });
    }
    roleActorPairs.add(pair);
    const existingActor = actorByRef.get(assignment.actor_ref);
    if (existingActor !== undefined && (existingActor.actor_kind !== assignment.actor_kind || existingActor.stable_identity_hash !== assignment.stable_identity_hash)) {
      ctx.addIssue({ code: "custom", path: ["role_assignments", index, "actor_ref"], message: "actor_ref must map to one actor kind and one stable identity hash" });
    }
    actorByRef.set(assignment.actor_ref, {
      actor_kind: assignment.actor_kind,
      stable_identity_hash: assignment.stable_identity_hash,
    });
    const alias = actorByStableIdentity.get(assignment.stable_identity_hash);
    if (alias !== undefined && alias !== assignment.actor_ref) {
      ctx.addIssue({ code: "custom", path: ["role_assignments", index, "stable_identity_hash"], message: "stable identity aliases invalidate the plan" });
    }
    actorByStableIdentity.set(assignment.stable_identity_hash, assignment.actor_ref);
  }
  for (const gate of plan.gates) {
    const binding = plan.role_assignments.find((assignment) => assignment.role_ref === gate.evaluator_binding.role_ref && assignment.actor_ref === gate.evaluator_binding.evaluator_identity_ref);
    if (binding === undefined) {
      ctx.addIssue({ code: "custom", path: ["gates", gate.id], message: "gate evaluator binding must resolve to exactly one role assignment" });
    }
  }
  for (const evaluation of plan.evaluations) {
    const binding = plan.role_assignments.find((assignment) => assignment.role_ref === evaluation.evaluator_binding.role_ref && assignment.actor_ref === evaluation.evaluator_binding.evaluator_identity_ref);
    if (binding === undefined) {
      ctx.addIssue({ code: "custom", path: ["evaluations", evaluation.id], message: "evaluation binding must resolve to exactly one role assignment" });
    }
  }
});
export type ResolvedRunPlanV02Value = z.infer<typeof ResolvedRunPlanV02>;

export const ResolvedRunPlanDocument = z.union([ResolvedRunPlanV01, ResolvedRunPlanV02]);

export const RuntimeSchemaInventoryV02 = strictObject({
  resolved_run_plan: z.literal("0.2"),
  ledger_event: z.literal("0.2"),
  run_manifest: z.literal("0.2"),
  artifact_manifest: z.literal("0.2"),
  redaction_derivative: z.literal("0.2"),
  human_authorization_proof: z.literal("0.2"),
  authority_envelope: z.literal("0.2"),
  agency_recommendation: z.literal("0.2"),
  authority_revocation: z.literal("0.2"),
  task_result: z.literal("0.2"),
  manual_observation: z.literal("0.2"),
  export_decision: z.literal("0.2"),
  evidence_item: z.literal("0.2"),
  gate_result: z.literal("0.2"),
  evaluation_result: z.literal("0.2"),
  claim: z.literal("0.2"),
  finding: z.literal("0.2"),
  waiver: z.literal("0.2"),
  gate_waiver_authority: z.literal("0.2"),
});

export type ResolvedRunPlanDocumentParseResult =
  | {
      ok: true;
      schema_version: "0.1";
      execution_profile: "legacy-v01";
      value: ResolvedRunPlanV01Value;
    }
  | {
      ok: true;
      schema_version: "0.2";
      execution_profile: "bounded-v02";
      value: ResolvedRunPlanV02Value;
    }
  | {
      ok: false;
      schema_version: "0.1" | "0.2";
      reason: "INVALID_RESOLVED_RUN_PLAN_DOCUMENT";
      issues: RuntimeDocumentIssue[];
    }
  | {
      ok: false;
      schema_version: null;
      reason:
        | "MISSING_SCHEMA_VERSION"
        | "MALFORMED_SCHEMA_VERSION"
        | "UNSUPPORTED_SCHEMA_VERSION";
      message: string;
    };

type ResolvedRunPlanVersionDispatchResult =
  | { ok: true; schema_version: "0.1" | "0.2" }
  | Extract<ResolvedRunPlanDocumentParseResult, { ok: false; schema_version: null }>;

type SnapshotPlainResult =
  | { ok: true; value: unknown }
  | { ok: false };

function snapshotPlainValue(input: unknown, depth = 0, state: { nodes: number } = { nodes: 0 }): SnapshotPlainResult {
  state.nodes += 1;
  if (state.nodes > 100_000 || depth > 64) return { ok: false };
  if (input === null || typeof input === "string" || typeof input === "boolean") return { ok: true, value: input };
  if (typeof input === "number") return Number.isFinite(input) ? { ok: true, value: input } : { ok: false };
  if (typeof input !== "object") return { ok: false };
  try {
    if (Array.isArray(input)) {
      if (Object.getPrototypeOf(input) !== Array.prototype) return { ok: false };
      const keys = Reflect.ownKeys(input);
      if (keys.some((key) => typeof key !== "string")) return { ok: false };
      const descriptors = Object.getOwnPropertyDescriptors(input);
      const result: unknown[] = [];
      for (let index = 0; index < input.length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (descriptor === undefined || !("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined) return { ok: false };
        const nested = snapshotPlainValue(descriptor.value, depth + 1, state);
        if (!nested.ok) return nested;
        result.push(nested.value);
      }
      if (Object.keys(descriptors).some((key) => key !== "length" && !/^\d+$/.test(key))) return { ok: false };
      return { ok: true, value: result };
    }
    const prototype = Object.getPrototypeOf(input);
    if (prototype !== Object.prototype && prototype !== null) return { ok: false };
    const keys = Reflect.ownKeys(input);
    if (keys.some((key) => typeof key !== "string")) return { ok: false };
    const descriptors = Object.getOwnPropertyDescriptors(input);
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(descriptors)) {
      const descriptor = descriptors[key];
      if (descriptor === undefined || !("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined) return { ok: false };
      const nested = snapshotPlainValue(descriptor.value, depth + 1, state);
      if (!nested.ok) return nested;
      result[key] = nested.value;
    }
    return { ok: true, value: result };
  } catch {
    return { ok: false };
  }
}

function readResolvedRunPlanSchemaVersion(input: unknown): ResolvedRunPlanVersionDispatchResult {
  const snapshotted = snapshotPlainValue(input);
  if (!snapshotted.ok) {
    return {
      ok: false,
      schema_version: null,
      reason: "MALFORMED_SCHEMA_VERSION",
      message: "schema_version must be an unmodified major.minor string.",
    };
  }
  const value = snapshotted.value;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return {
      ok: false,
      schema_version: null,
      reason: "MISSING_SCHEMA_VERSION",
      message: "schema_version is required.",
    };
  }
  const record = value as Record<string, unknown>;
  if (!Object.hasOwn(record, "schema_version")) {
    return {
      ok: false,
      schema_version: null,
      reason: "MISSING_SCHEMA_VERSION",
      message: "schema_version is required.",
    };
  }
  const raw = record.schema_version;
  if (typeof raw !== "string" || !/^\d+\.\d+$/.test(raw)) {
    return {
      ok: false,
      schema_version: null,
      reason: "MALFORMED_SCHEMA_VERSION",
      message: "schema_version must be an unmodified major.minor string.",
    };
  }
  if (raw !== "0.1" && raw !== "0.2") {
    return {
      ok: false,
      schema_version: null,
      reason: "UNSUPPORTED_SCHEMA_VERSION",
      message: "schema_version is not supported; supported versions are '0.1' and '0.2'.",
    };
  }
  return { ok: true, schema_version: raw };
}

function runtimeZodIssues(error: { issues: readonly { path: readonly PropertyKey[]; message: string }[] }): RuntimeDocumentIssue[] {
  return error.issues.map((issue) => ({
    path: issue.path.map((part) => String(part)).join(".") || "(root)",
    message: issue.message,
  }));
}

export function parseResolvedRunPlanDocument(input: unknown): ResolvedRunPlanDocumentParseResult {
  const snapshotted = snapshotPlainValue(input);
  const stableInput = snapshotted.ok ? snapshotted.value : input;
  const dispatched = readResolvedRunPlanSchemaVersion(input);
  if (!dispatched.ok) return dispatched;

  if (dispatched.schema_version === "0.1") {
    const parsed = ResolvedRunPlanV01Dispatch.safeParse(stableInput);
    return parsed.success
      ? { ok: true, schema_version: "0.1", execution_profile: "legacy-v01", value: parsed.data }
      : {
          ok: false,
          schema_version: "0.1",
          reason: "INVALID_RESOLVED_RUN_PLAN_DOCUMENT",
          issues: runtimeZodIssues(parsed.error),
        };
  }

  const parsed = ResolvedRunPlanV02.safeParse(stableInput);
  return parsed.success
    ? { ok: true, schema_version: "0.2", execution_profile: "bounded-v02", value: parsed.data }
    : {
        ok: false,
        schema_version: "0.2",
        reason: "INVALID_RESOLVED_RUN_PLAN_DOCUMENT",
        issues: runtimeZodIssues(parsed.error),
      };
}

export type RuntimeResult<T, E extends string> =
  | { ok: true; value: T }
  | { ok: false; error: E };

export const LedgerRefV02 = strictObject({
  ledger_sequence: safeInteger.positive(),
  event_hash: Hash,
});
export type LedgerRefV02Value = z.infer<typeof LedgerRefV02>;

const CanonicalLedgerRefsV02 = z.array(LedgerRefV02).superRefine((refs, ctx) => {
  for (let index = 1; index < refs.length; index += 1) {
    const previous = refs[index - 1]!;
    const current = refs[index]!;
    const isOutOfOrder = previous.ledger_sequence > current.ledger_sequence
      || (
        previous.ledger_sequence === current.ledger_sequence
        && compareRuntimeUtf8BytesV02(previous.event_hash, current.event_hash) >= 0
      );
    if (isOutOfOrder) {
      ctx.addIssue({
        code: "custom",
        path: [index],
        message: "must be unique and sorted by ledger_sequence then raw UTF-8 event_hash bytes",
      });
    }
  }
});

export const NonEmptyCanonicalLedgerRefsV02 = CanonicalLedgerRefsV02.refine((refs) => refs.length > 0, {
  message: "must contain at least one canonical ledger reference",
});

const CanonicalHumanIdsV02 = z.array(HumanId).superRefine((refs, ctx) => {
  for (let index = 1; index < refs.length; index += 1) {
    if (compareRuntimeUtf8BytesV02(refs[index - 1]!, refs[index]!) >= 0) {
      ctx.addIssue({ code: "custom", path: [index], message: "must be unique and sorted by raw UTF-8 bytes" });
    }
  }
});

const NonEmptyCanonicalHumanIdsV02 = CanonicalHumanIdsV02.refine((refs) => refs.length > 0, {
  message: "must contain at least one canonical human ID",
});

export const RecordDependencyRefV02 = z.union([
  strictObject({
    record_kind: z.literal("artifact"),
    record_id: HumanId,
    record_event_ref: LedgerRefV02,
  }),
  strictObject({
    record_kind: z.enum([
      "agency-recommendation",
      "authority-envelope",
      "authority-revocation",
      "claim",
      "evaluation-result",
      "evidence",
      "export-decision",
      "finding",
      "gate-result",
      "gate-waiver-authority",
      "human-authorization",
      "manual-observation",
      "task-result",
      "waiver",
    ]),
    record_id: MachineId,
    record_event_ref: LedgerRefV02,
  }),
]);

type RecordDependencyRefV02Value = z.infer<typeof RecordDependencyRefV02>;

function compareRecordDependencyRefsV02(left: RecordDependencyRefV02Value, right: RecordDependencyRefV02Value): number {
  const kindComparison = compareRuntimeUtf8BytesV02(left.record_kind, right.record_kind);
  if (kindComparison !== 0) return kindComparison;
  const idComparison = compareRuntimeUtf8BytesV02(left.record_id, right.record_id);
  if (idComparison !== 0) return idComparison;
  if (left.record_event_ref.ledger_sequence !== right.record_event_ref.ledger_sequence) {
    return left.record_event_ref.ledger_sequence < right.record_event_ref.ledger_sequence ? -1 : 1;
  }
  return compareRuntimeUtf8BytesV02(left.record_event_ref.event_hash, right.record_event_ref.event_hash);
}

const CanonicalRecordDependencyRefsV02 = z.array(RecordDependencyRefV02).superRefine((refs, ctx) => {
  for (let index = 1; index < refs.length; index += 1) {
    if (compareRecordDependencyRefsV02(refs[index - 1]!, refs[index]!) >= 0) {
      ctx.addIssue({ code: "custom", path: [index], message: "must be unique and sorted by canonical UTF-8 dependency-ref order" });
    }
  }
});
export const ReviewEvidenceRefsV02 = CanonicalRecordDependencyRefsV02.refine((refs) => refs.length > 0, {
  message: "must contain at least one canonical dependency reference",
});

/** Recommendation evidence is a closed non-empty canonical tuple of evidence records only. */
export const AgencyRecommendationEvidenceRefsV02 = ReviewEvidenceRefsV02.refine(
  (refs) => refs.every((ref) => ref.record_kind === "evidence"),
  { message: "agency recommendation evidence must contain only evidence records" },
);

export const ArtifactRecordV02 = strictObject({
  schema_version: z.literal("0.2"),
  artifact_ref: HumanId,
  run_id: MachineId,
  plan_hash: Hash,
  producer_task_ref: HumanId,
  producer_action_id: MachineId,
  write_admission_ref: LedgerRefV02,
  artifact_path: RelativeRunPath,
  content_hash: Hash,
  size_bytes: safeInteger.nonnegative(),
  media_type: NonBlankString,
  record_hash: Hash,
});
export type ArtifactRecordV02Value = z.infer<typeof ArtifactRecordV02>;

const ArtifactEvidenceSubjectV02 = strictObject({
  subject_kind: z.literal("artifact"),
  subject_ref: HumanId,
});

const EvidenceSubjectV02 = strictObject({
  subject_kind: z.literal("evidence"),
  subject_ref: MachineId,
});

export const ArtifactEvidenceSubjectRefV02 = z.discriminatedUnion("subject_kind", [
  ArtifactEvidenceSubjectV02,
  EvidenceSubjectV02,
]);
export type ArtifactEvidenceSubjectRefV02Value = z.infer<typeof ArtifactEvidenceSubjectRefV02>;

const RedactionDerivativeRecordCommonV02 = {
  schema_version: z.literal("0.2"),
  derivative_ref: MachineId,
  run_id: MachineId,
  original_record_path: RelativeRunPath,
  original_record_hash: Hash,
  original_content_path: RelativeRunPath,
  original_content_hash: Hash,
  original_content_size_bytes: safeInteger.nonnegative(),
  original_media_type: NonBlankString,
  derivative_content_path: RelativeRunPath,
  derivative_content_hash: Hash,
  derivative_size_bytes: safeInteger.nonnegative(),
  derivative_media_type: NonBlankString,
  policy_version: NonBlankString,
  review_evidence_refs: ReviewEvidenceRefsV02,
  created_at: IsoTimestamp,
  record_hash: Hash,
} satisfies z.ZodRawShape;

export const RedactionDerivativeRecordV02 = z.discriminatedUnion("subject_kind", [
  strictObject({ ...ArtifactEvidenceSubjectV02.shape, ...RedactionDerivativeRecordCommonV02 }),
  strictObject({ ...EvidenceSubjectV02.shape, ...RedactionDerivativeRecordCommonV02 }),
]);
export type RedactionDerivativeRecordV02Value = z.infer<typeof RedactionDerivativeRecordV02>;

const Iso4217CurrencyCodeSyntaxV02 = z.string().regex(/^[A-Z]{3}$/);

export const ObservedCostV02 = z.discriminatedUnion("capture", [
  strictObject({
    capture: z.literal("not-applicable"),
    cost_minor_units: z.literal(0),
    cost_currency: z.null(),
    cost_minor_units_after: z.literal(0),
  }),
  strictObject({
    capture: z.literal("captured"),
    cost_minor_units: safeInteger.nonnegative(),
    cost_currency: Iso4217CurrencyCodeSyntaxV02,
    cost_minor_units_after: safeInteger.nonnegative(),
  }),
  strictObject({
    capture: z.literal("unavailable"),
    cost_minor_units: z.null(),
    cost_currency: Iso4217CurrencyCodeSyntaxV02.nullable(),
    cost_minor_units_after: z.null(),
  }),
]);
export type ObservedCostV02Value = z.infer<typeof ObservedCostV02>;

const TaskResultObservationV02 = z.discriminatedUnion("kind", [
  strictObject({
    kind: z.literal("command"),
    command_hash: Hash,
    cwd_identity_hash: Hash,
    input_hash: Hash,
    output_hash: Hash,
    exit_code: safeInteger,
  }),
  strictObject({
    kind: z.literal("browser"),
    target_hash: Hash,
    interaction_hash: Hash,
    browser_session_authority_ref: LedgerRefV02,
    capture_hash: Hash,
  }),
  strictObject({
    kind: z.literal("source-acquisition"),
    requested_uri_hash: Hash,
    final_uri_hash: Hash,
    canonical_source_identity: NonBlankString,
    locator_hash: Hash,
    retrieval_method: z.enum(["http", "browser", "repository", "manual-import"]),
    retrieved_at: IsoTimestamp,
    retriever_identity: NonBlankString,
    retriever_version: NonBlankString,
    auth_class: z.enum(["public", "authenticated"]),
    authentication_scope_hash: Hash.nullable(),
    response_class: z.enum(["success", "not-found", "denied", "error"]),
    content_hash: Hash,
    selector_hash: Hash.nullable(),
    redaction_state: z.enum(["none", "redacted"]),
  }),
  strictObject({
    kind: z.literal("generic"),
    output_hash: Hash,
  }),
]);

const CaptureGapCodesV02 = z.array(NonBlankString).superRefine((codes, ctx) => {
  for (let index = 1; index < codes.length; index += 1) {
    if (compareRuntimeUtf8BytesV02(codes[index - 1]!, codes[index]!) >= 0) {
      ctx.addIssue({ code: "custom", path: [index], message: "must be unique and sorted by UTF-8 bytes" });
    }
  }
});

export const TaskResultV02 = strictObject({
  schema_version: z.literal("0.2"),
  result_id: MachineId,
  run_id: MachineId,
  plan_hash: Hash,
  action_id: MachineId,
  task_ref: HumanId,
  adapter_invocation_id: MachineId,
  status: z.enum(["completed", "failed"]),
  failure_class: RetryClassV02.nullable(),
  observation: TaskResultObservationV02,
  capture_gap_codes: CaptureGapCodesV02,
  record_hash: Hash,
});
export type TaskResultV02Value = z.infer<typeof TaskResultV02>;

const TaskProgressFactStringV02 = UnicodeScalarString.refine(
  (value) => RUNTIME_UTF8.encode(value).byteLength <= 16_384,
  { message: "must be at most 16384 UTF-8 bytes" },
);

const TaskProgressFactsShapeV02 = z.record(
  HumanId,
  z.union([TaskProgressFactStringV02, safeInteger, z.boolean()]),
).superRefine((value, ctx) => {
  const entries = Object.entries(value);
  if (entries.length < 1 || entries.length > 64) {
    ctx.addIssue({
      code: "custom",
      message: "must contain between 1 and 64 progress fact entries",
    });
  }
  if (RUNTIME_UTF8.encode(canonicalize(value)).byteLength > 65_536) {
    ctx.addIssue({
      code: "custom",
      message: "RFC 8785 serialized progress facts must be at most 65536 UTF-8 bytes",
    });
  }
});
export const TaskProgressFactsV02 = z.preprocess((input) => {
  try {
    if (typeof input !== "object" || input === null || Array.isArray(input)) return null;
    if (Object.getPrototypeOf(input) !== Object.prototype) return null;
    const snapshotted = snapshotPlainValue(input);
    return snapshotted.ok ? snapshotted.value : null;
  } catch {
    return null;
  }
}, TaskProgressFactsShapeV02);
export type TaskProgressFactsV02Value = z.infer<typeof TaskProgressFactsV02>;

export const ProgressSampleV02 = z.union([
  strictObject({
    status: z.literal("source-present"),
    sample_ref: z.union([RecordDependencyRefV02, LedgerRefV02]),
    sample_hash: Hash,
    value_status: z.literal("parseable"),
    sample_value: z.union([z.string(), safeInteger, z.boolean(), z.null()]),
  }),
  strictObject({
    status: z.literal("source-present"),
    sample_ref: z.union([RecordDependencyRefV02, LedgerRefV02]),
    sample_hash: Hash,
    value_status: z.literal("value-unparseable"),
    sample_value: z.null(),
  }),
  strictObject({
    status: z.literal("source-missing"),
    sample_ref: z.null(),
    sample_hash: z.null(),
    value_status: z.literal("value-unparseable"),
    sample_value: z.null(),
  }),
]);
export type ProgressSampleV02Value = z.infer<typeof ProgressSampleV02>;

const RuntimeLedgerSourceV02 = z.enum([
  "kernel",
  "policy-enforcement-point",
  "adapter",
  "evaluator",
  "operator",
  "integrity",
]);

const RuntimeEventEnvelopeV02 = strictObject({
  schema_version: z.literal("0.2"),
  event_id: MachineId,
  run_id: MachineId,
  sequence: safeInteger.positive(),
  recorded_at: IsoTimestamp,
  source: RuntimeLedgerSourceV02,
  authority_ref: MachineId.nullable(),
  risk_tier: RiskTier,
  related_ids: Utf8SortedUniqueStrings,
  previous_event_hash: Hash.nullable(),
  event_hash: Hash,
});

export const RunInitializedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("run.initialized"),
  payload: strictObject({
    plan_hash: Hash,
    initial_fence_epoch: z.literal(0),
    runtime_schema_versions: RuntimeSchemaInventoryV02,
  }),
}).strict().superRefine((event, ctx) => {
  if (event.source !== "kernel") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "run.initialized must use source 'kernel'" });
  }
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "run.initialized must not name authority" });
  }
  if (event.sequence !== 1) {
    ctx.addIssue({ code: "custom", path: ["sequence"], message: "run.initialized must be sequence 1" });
  }
  if (event.previous_event_hash !== null) {
    ctx.addIssue({ code: "custom", path: ["previous_event_hash"], message: "run.initialized must not name a previous event" });
  }
});

export const RunClockObservedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("run.clock-observed"),
  payload: strictObject({
    clock_id: MachineId,
    observed_at: IsoTimestamp,
    elapsed_ms: safeInteger.nonnegative(),
    reason: z.enum(["action-admission", "retry-check", "waiver-boundary", "terminal-use"]),
    task_ref: HumanId.nullable(),
    failure_ordinal: safeInteger.positive().nullable(),
    use_ref: MachineId.nullable(),
  }),
}).strict().superRefine((event, ctx) => {
  if (event.source !== "kernel") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "run.clock-observed must use source 'kernel'" });
  }
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "run.clock-observed must not name authority" });
  }
  const payload = event.payload;
  const isActionAdmission = payload.reason === "action-admission"
    && payload.task_ref !== null
    && payload.failure_ordinal === null
    && payload.use_ref !== null;
  const isRetryCheck = payload.reason === "retry-check"
    && payload.task_ref !== null
    && payload.failure_ordinal !== null
    && payload.use_ref === null;
  const isBoundaryUse = (payload.reason === "waiver-boundary" || payload.reason === "terminal-use")
    && payload.task_ref === null
    && payload.failure_ordinal === null
    && payload.use_ref !== null;
  if (!isActionAdmission && !isRetryCheck && !isBoundaryUse) {
    ctx.addIssue({ code: "custom", path: ["payload"], message: "clock reason must match its task, failure ordinal, and use reference branch" });
  }
});

export const RunFenceAdvancedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("run.fence-advanced"),
  payload: strictObject({
    previous_fence_epoch: safeInteger.nonnegative(),
    fence_epoch: safeInteger.positive(),
    reason: z.enum(["lease-revoked", "operator-revoked", "recovery-boundary"]),
    evidence_refs: CanonicalLedgerRefsV02,
  }),
}).strict().superRefine((event, ctx) => {
  if (event.source !== "policy-enforcement-point") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "run.fence-advanced must use source 'policy-enforcement-point'" });
  }
  if (event.authority_ref === null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "run.fence-advanced requires authority" });
  }
  if (event.payload.previous_fence_epoch >= Number.MAX_SAFE_INTEGER
    || event.payload.fence_epoch !== event.payload.previous_fence_epoch + 1) {
    ctx.addIssue({ code: "custom", path: ["payload", "fence_epoch"], message: "fence epoch must increment by exactly one without overflow" });
  }
});

export const ControlAbortRequestedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("control.abort-requested"),
  payload: strictObject({
    request_id: MachineId,
    requested_by: z.enum(["operator", "policy"]),
    reason_code: z.enum([
      "operator-requested",
      "safety-hold",
      "policy-revoked",
      "integrity-failure",
      "agency-recommendation-abort",
    ]),
    policy_decision_ref: LedgerRefV02.nullable(),
    evidence_refs: CanonicalLedgerRefsV02,
  }),
}).strict().superRefine((event, ctx) => {
  const expectedSource = event.payload.requested_by === "operator" ? "operator" : "policy-enforcement-point";
  if (event.source !== expectedSource) {
    ctx.addIssue({ code: "custom", path: ["source"], message: "abort source must match requested_by" });
  }
  if (event.authority_ref === null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "control.abort-requested requires requester authority" });
  }
  const isAgencyAbort = event.payload.reason_code === "agency-recommendation-abort";
  if (isAgencyAbort && (event.payload.requested_by !== "policy" || event.payload.policy_decision_ref === null)) {
    ctx.addIssue({ code: "custom", path: ["payload", "policy_decision_ref"], message: "agency abort requires policy requester and decision reference" });
  }
  if (!isAgencyAbort && event.payload.policy_decision_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["payload", "policy_decision_ref"], message: "only agency abort may name a policy decision" });
  }
});

const ResultRequiredPayloadV02 = {
  requirement_revision: z.literal(1),
  applicability: z.enum(["always", "compensation"]),
  compensation_ref: HumanId.nullable(),
  prerequisite_set_hash: Hash,
  prerequisite_refs: CanonicalLedgerRefsV02,
} satisfies z.ZodRawShape;

function validateResultRequiredApplicabilityV02(
  payload: { applicability: "always" | "compensation"; compensation_ref: string | null },
  ctx: z.RefinementCtx,
): void {
  if (payload.applicability === "always" && payload.compensation_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["payload", "compensation_ref"], message: "always-applicable result must not name compensation" });
  }
  if (payload.applicability === "compensation" && payload.compensation_ref === null) {
    ctx.addIssue({ code: "custom", path: ["payload", "compensation_ref"], message: "compensation-applicable result requires compensation reference" });
  }
}

export const GateResultRequiredEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("gate.result-required"),
  payload: strictObject({ gate_ref: HumanId, ...ResultRequiredPayloadV02 }),
}).strict().superRefine((event, ctx) => {
  if (event.source !== "kernel") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "gate.result-required must use source 'kernel'" });
  }
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "gate.result-required must not name authority" });
  }
  validateResultRequiredApplicabilityV02(event.payload, ctx);
});

export const GateResultRecordedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("gate.result-recorded"),
  payload: strictObject({
    gate_ref: HumanId,
    result_id: MachineId,
    status: z.enum(["PASS", "HOLD", "FAIL", "WAIVED"]),
    evaluator_identity_ref: MachineId,
    policy_digest: Hash,
    record_path: RelativeRunPath,
    record_hash: Hash,
    required_event_ref: LedgerRefV02,
    waiver_event_ref: LedgerRefV02.nullable(),
  }),
}).strict().superRefine((event, ctx) => {
  if (event.source !== "evaluator") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "gate.result-recorded must use source 'evaluator'" });
  }
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "gate.result-recorded must not name authority" });
  }
  const isWaived = event.payload.status === "WAIVED";
  if (isWaived !== (event.payload.waiver_event_ref !== null)) {
    ctx.addIssue({ code: "custom", path: ["payload", "waiver_event_ref"], message: "WAIVED status must exactly pair with a waiver event" });
  }
});

export const EvaluationResultRequiredEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("evaluation.result-required"),
  payload: strictObject({ evaluation_ref: HumanId, ...ResultRequiredPayloadV02 }),
}).strict().superRefine((event, ctx) => {
  if (event.source !== "kernel") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "evaluation.result-required must use source 'kernel'" });
  }
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "evaluation.result-required must not name authority" });
  }
  validateResultRequiredApplicabilityV02(event.payload, ctx);
});

export const EvaluationResultRecordedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("evaluation.result-recorded"),
  payload: strictObject({
    evaluation_ref: HumanId,
    result_id: MachineId,
    status: z.enum(["PASS", "HOLD", "FAIL", "SKIPPED"]),
    evaluator_identity_ref: MachineId,
    policy_digest: Hash,
    export_check_role: z.enum(["credential-scan", "privacy-review"]).nullable(),
    record_path: RelativeRunPath,
    record_hash: Hash,
    required_event_ref: LedgerRefV02,
  }),
}).strict().superRefine((event, ctx) => {
  if (event.source !== "evaluator") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "evaluation.result-recorded must use source 'evaluator'" });
  }
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "evaluation.result-recorded must not name authority" });
  }
});

export const EffectOutcomeEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("effect.outcome"),
  payload: strictObject({
    task_ref: HumanId,
    effect_ref: HumanId,
    action_id: MachineId,
    outcome: z.enum(["not-committed", "committed", "unknown"]),
    evidence_refs: CanonicalLedgerRefsV02,
  }),
}).strict().superRefine((event, ctx) => {
  const expectedSource = event.payload.outcome === "unknown" ? "integrity" : "adapter";
  if (event.source !== expectedSource) {
    ctx.addIssue({ code: "custom", path: ["source"], message: "effect outcome source must match observed or reconciled provenance" });
  }
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "effect.outcome must not name authority" });
  }
});

const AutomaticPolicyActionKindV1 = z.enum([
  "planning",
  "local-read",
  "deterministic-no-side-effect-check",
]);
const AgencyPolicyActionKindV1 = z.enum([
  "authenticated-read",
  "network-read",
  "reversible-workspace-edit",
]);
function validatePepAuthorityV02(
  event: { source: z.infer<typeof RuntimeLedgerSourceV02>; authority_ref: string | null },
  eventType: string,
  ctx: z.RefinementCtx,
): void {
  if (event.source !== "policy-enforcement-point") {
    ctx.addIssue({ code: "custom", path: ["source"], message: `${eventType} must use source 'policy-enforcement-point'` });
  }
  if (event.authority_ref === null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: `${eventType} requires authority` });
  }
}

export const ToolCallAdmittedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("tool.call-admitted"),
  payload: strictObject({
    tool_call_id: MachineId,
    action_id: MachineId,
    task_ref: HumanId,
    tool_grant_ref: HumanId,
    fence_epoch: safeInteger.nonnegative(),
    tool_calls_after: safeInteger.positive(),
  }),
}).strict().superRefine((event, ctx) => {
  validatePepAuthorityV02(event, "tool.call-admitted", ctx);
});

export const ArtifactWriteAdmittedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("artifact.write-admitted"),
  payload: strictObject({
    write_id: MachineId,
    artifact_ref: HumanId,
    action_id: MachineId,
    task_ref: HumanId,
    artifact_path: RelativeRunPath,
    prospective_bytes: safeInteger.nonnegative(),
    fence_epoch: safeInteger.nonnegative(),
    action_output_bytes_after: safeInteger.nonnegative(),
  }),
}).strict().superRefine((event, ctx) => {
  validatePepAuthorityV02(event, "artifact.write-admitted", ctx);
  if (event.payload.action_output_bytes_after < event.payload.prospective_bytes) {
    ctx.addIssue({
      code: "custom",
      path: ["payload", "action_output_bytes_after"],
      message: "post-admission output bytes cannot be less than prospective bytes",
    });
  }
});

const RuntimeLimitRefV02 = z.enum([
  "max-loop-attempts",
  "max-elapsed-ms",
  "max-tool-calls",
  "max-output-bytes",
  "max-tokens",
  "max-cost",
]);
const RuntimeLimitViolationV02 = strictObject({
  limit_ref: RuntimeLimitRefV02,
  consumed: safeInteger.nonnegative(),
  requested: safeInteger.positive(),
  ceiling: safeInteger.nonnegative(),
}).superRefine((violation, ctx) => {
  if (violation.consumed > Number.MAX_SAFE_INTEGER - violation.requested) {
    ctx.addIssue({ code: "custom", path: ["requested"], message: "prospective limit addition must not overflow" });
    return;
  }
  if (violation.consumed + violation.requested <= violation.ceiling) {
    ctx.addIssue({ code: "custom", path: ["requested"], message: "violation must cross its ceiling" });
  }
});
const CanonicalRuntimeLimitViolationsV02 = z.array(RuntimeLimitViolationV02).min(1).superRefine((violations, ctx) => {
  for (let index = 1; index < violations.length; index += 1) {
    if (compareRuntimeUtf8BytesV02(violations[index - 1]!.limit_ref, violations[index]!.limit_ref) >= 0) {
      ctx.addIssue({ code: "custom", path: [index, "limit_ref"], message: "violations must be unique and sorted by UTF-8 limit_ref bytes" });
    }
  }
});

export const LimitAdmissionBlockedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("limit.admission-blocked"),
  payload: strictObject({
    request_id: MachineId,
    task_ref: HumanId,
    phase: z.enum(["work", "compensation"]),
    compensation_ref: HumanId.nullable(),
    request_kind: z.enum(["loop-attempt", "action", "tool-call", "artifact-write", "adapter-budget"]),
    request_hash: Hash,
    violations: CanonicalRuntimeLimitViolationsV02,
  }),
}).strict().superRefine((event, ctx) => {
  validatePepAuthorityV02(event, "limit.admission-blocked", ctx);
  if ((event.payload.phase === "compensation") !== (event.payload.compensation_ref !== null)) {
    ctx.addIssue({
      code: "custom",
      path: ["payload", "compensation_ref"],
      message: "compensation reference must be present exactly in compensation phase",
    });
  }
});

const TaskExecutionStartedPayloadBaseV02 = strictObject({
  action_id: MachineId,
  task_ref: HumanId,
  admission_ref: LedgerRefV02,
  adapter_invocation_id: MachineId,
  action_proposal_id: MachineId,
  action_proposal_hash: Hash,
  action_actor_ref: MachineId,
  action_actor_stable_identity_hash: Hash,
  on_behalf_of_chain_hash: Hash,
  repository_root_ref: MachineId,
  repository_base_ref_identity_hash: Hash,
  repository_pre_state_hash: Hash,
  authorized_change_set_hash: Hash,
  normalized_dispatch_hash: Hash,
});

export const TaskExecutionStartedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("task.execution-started"),
  payload: z.discriminatedUnion("action_approval_class", [
    TaskExecutionStartedPayloadBaseV02.extend({
      policy_action_kind: AutomaticPolicyActionKindV1,
      action_approval_class: z.literal("automatic"),
    }).strict(),
    TaskExecutionStartedPayloadBaseV02.extend({
      policy_action_kind: AgencyPolicyActionKindV1,
      action_approval_class: z.literal("agency"),
    }).strict(),
  ]),
}).strict().superRefine((event, ctx) => {
  if (event.source !== "adapter") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "task.execution-started must use source 'adapter'" });
  }
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "task.execution-started must not name authority" });
  }
});

const AdmittedActionProposalBindingsShapeV02 = {
  action_proposal_id: MachineId,
  action_proposal_hash: Hash,
  action_actor_ref: MachineId,
  action_actor_stable_identity_hash: Hash,
  on_behalf_of_chain_hash: Hash,
  repository_root_ref: MachineId,
  repository_base_ref_identity_hash: Hash,
  repository_pre_state_hash: Hash,
  authorized_change_set_hash: Hash,
  normalized_dispatch_hash: Hash,
  action_scope_hash: Hash,
  action_class: z.enum(["task", "tool", "artifact-write"]),
  classifier_input_hash: Hash,
  classifier_registry_hash: Hash,
  classifier_rule_hash: Hash,
  data_flow_hash: Hash,
} satisfies z.ZodRawShape;

const LeaseIssuedPayloadBaseV02 = {
  lease_id: MachineId,
  task_ref: HumanId,
  phase: z.enum(["work", "compensation"]),
  compensation_ref: HumanId.nullable(),
  ...AdmittedActionProposalBindingsShapeV02,
  authority_envelope_ref: LedgerRefV02,
  policy_decision_ref: LedgerRefV02,
  fence_epoch: safeInteger.nonnegative(),
  issued_at: IsoTimestamp,
  expires_at: IsoTimestamp,
  waiver_gate_refs: CanonicalHumanIdsV02,
} satisfies z.ZodRawShape;

export const LeaseIssuedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("lease.issued"),
  payload: z.discriminatedUnion("action_approval_class", [
    strictObject({
      ...LeaseIssuedPayloadBaseV02,
      policy_action_kind: AutomaticPolicyActionKindV1,
      action_approval_class: z.literal("automatic"),
    }),
    strictObject({
      ...LeaseIssuedPayloadBaseV02,
      policy_action_kind: AgencyPolicyActionKindV1,
      action_approval_class: z.literal("agency"),
    }),
  ]),
}).strict().superRefine((event, ctx) => {
  validatePepAuthorityV02(event, "lease.issued", ctx);
  if ((event.payload.phase === "compensation") !== (event.payload.compensation_ref !== null)) {
    ctx.addIssue({ code: "custom", path: ["payload", "compensation_ref"], message: "compensation reference must be present exactly in compensation phase" });
  }
  if (Date.parse(event.payload.issued_at) >= Date.parse(event.payload.expires_at)) {
    ctx.addIssue({ code: "custom", path: ["payload", "expires_at"], message: "lease interval must be non-empty" });
  }
});

const WaiverGateUseCheckV02 = strictObject({
  gate_ref: HumanId,
  required_event_ref: LedgerRefV02,
  result_event_ref: LedgerRefV02,
  waiver_event_ref: LedgerRefV02,
  authority_record_ref: LedgerRefV02,
  authority_revocation_epoch: safeInteger.nonnegative(),
  authority_envelope_revocation_epoch: safeInteger.nonnegative(),
  use_clock_ref: LedgerRefV02,
});
const CanonicalWaiverGateUseChecksV02 = z.array(WaiverGateUseCheckV02).superRefine((checks, ctx) => {
  for (let index = 1; index < checks.length; index += 1) {
    if (compareRuntimeUtf8BytesV02(checks[index - 1]!.gate_ref, checks[index]!.gate_ref) >= 0) {
      ctx.addIssue({ code: "custom", path: [index, "gate_ref"], message: "waiver checks must be unique and sorted by UTF-8 gate_ref bytes" });
    }
  }
});

function ledgerRefsEqualV02(left: z.infer<typeof LedgerRefV02>, right: z.infer<typeof LedgerRefV02>): boolean {
  return left.ledger_sequence === right.ledger_sequence && left.event_hash === right.event_hash;
}

const TaskActionAdmittedPayloadBaseV02 = {
  action_id: MachineId,
  task_ref: HumanId,
  lease_id: MachineId,
  lease_event_ref: LedgerRefV02,
  admission_clock_ref: LedgerRefV02,
  ...AdmittedActionProposalBindingsShapeV02,
  execution_ordinal: safeInteger.positive(),
  retry_of_failure_ordinal: safeInteger.positive().nullable(),
  fence_epoch: safeInteger.nonnegative(),
  side_effect_refs: NonEmptyCanonicalHumanIdsV02,
  waiver_gate_use_checks: CanonicalWaiverGateUseChecksV02,
  task_executions_after: safeInteger.positive(),
  action_output_bytes_after: safeInteger.nonnegative(),
} satisfies z.ZodRawShape;

export const TaskActionAdmittedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("task.action-admitted"),
  payload: z.discriminatedUnion("action_approval_class", [
    strictObject({
      ...TaskActionAdmittedPayloadBaseV02,
      policy_action_kind: AutomaticPolicyActionKindV1,
      action_approval_class: z.literal("automatic"),
    }),
    strictObject({
      ...TaskActionAdmittedPayloadBaseV02,
      policy_action_kind: AgencyPolicyActionKindV1,
      action_approval_class: z.literal("agency"),
    }),
  ]),
}).strict().superRefine((event, ctx) => {
  validatePepAuthorityV02(event, "task.action-admitted", ctx);
  event.payload.waiver_gate_use_checks.forEach((check, index) => {
    if (!ledgerRefsEqualV02(check.use_clock_ref, event.payload.admission_clock_ref)) {
      ctx.addIssue({ code: "custom", path: ["payload", "waiver_gate_use_checks", index, "use_clock_ref"], message: "waiver use clock must equal the action admission clock" });
    }
  });
});

const EvidenceIndependenceRootV02 = strictObject({
  root_event_ref: LedgerRefV02,
  source_class: z.enum(["command", "filesystem", "browser", "source", "human-authorization", "manual-observation"]),
  authority_root_ref: LedgerRefV02,
  authenticated_principal_ref: MachineId.nullable(),
  acquisition_scope_hash: Hash,
  independence_key: Hash,
}).superRefine((root, ctx) => {
  const requiresPrincipal = root.source_class === "human-authorization" || root.source_class === "manual-observation";
  if (requiresPrincipal !== (root.authenticated_principal_ref !== null)) {
    ctx.addIssue({ code: "custom", path: ["authenticated_principal_ref"], message: "authenticated principal must be present exactly for human roots" });
  }
});
const CanonicalEvidenceIndependenceRootsV02 = z.array(EvidenceIndependenceRootV02).min(1).superRefine((roots, ctx) => {
  const rootRefs = new Set<string>();
  roots.forEach((root, index) => {
    const key = `${root.root_event_ref.ledger_sequence}:${root.root_event_ref.event_hash}`;
    if (rootRefs.has(key)) {
      ctx.addIssue({ code: "custom", path: [index, "root_event_ref"], message: "root event references must be unique" });
    }
    rootRefs.add(key);
    if (index === 0) return;
    const previous = roots[index - 1]!;
    const independenceComparison = compareRuntimeUtf8BytesV02(previous.independence_key, root.independence_key);
    const outOfOrder = independenceComparison > 0
      || (independenceComparison === 0 && previous.root_event_ref.ledger_sequence > root.root_event_ref.ledger_sequence)
      || (independenceComparison === 0
        && previous.root_event_ref.ledger_sequence === root.root_event_ref.ledger_sequence
        && compareRuntimeUtf8BytesV02(previous.root_event_ref.event_hash, root.root_event_ref.event_hash) >= 0);
    if (outOfOrder) {
      ctx.addIssue({ code: "custom", path: [index], message: "independence roots must use canonical key and ledger order" });
    }
  });
});

export const EvidenceRecordedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("evidence.recorded"),
  payload: strictObject({
    evidence_id: MachineId,
    requirement_refs: NonEmptyCanonicalHumanIdsV02,
    evidence_kind: EvidenceKindV02,
    independence_roots: CanonicalEvidenceIndependenceRootsV02,
    record_path: RelativeRunPath,
    record_hash: Hash,
    content_path: RelativeRunPath.nullable(),
    content_hash: Hash.nullable(),
    size_bytes: safeInteger.nonnegative().nullable(),
    media_type: NonBlankString.nullable(),
    producer_event_ref: LedgerRefV02,
  }),
}).strict().superRefine((event, ctx) => {
  if (event.source !== "kernel") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "evidence.recorded must use source 'kernel'" });
  }
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "evidence.recorded must not name authority" });
  }
  const tuple = [event.payload.content_path, event.payload.content_hash, event.payload.size_bytes, event.payload.media_type];
  const nonNullCount = tuple.filter((value) => value !== null).length;
  if (nonNullCount !== 0 && nonNullCount !== tuple.length) {
    ctx.addIssue({ code: "custom", path: ["payload"], message: "evidence content fields must be all null or all non-null" });
  }
});

const CanonicalNonBlankStringsV02 = z.array(NonBlankString).superRefine((values, ctx) => {
  for (let index = 1; index < values.length; index += 1) {
    if (compareRuntimeUtf8BytesV02(values[index - 1]!, values[index]!) >= 0) {
      ctx.addIssue({ code: "custom", path: [index], message: "must be unique and sorted by raw UTF-8 bytes" });
    }
  }
});

export const ObservationManualRecordedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("observation.manual-recorded"),
  payload: strictObject({
    observation_id: MachineId,
    record_path: RelativeRunPath,
    record_hash: Hash,
    run_id: MachineId,
    authenticated_principal_ref: MachineId,
    subject_hash: Hash,
    observation_scope_hash: Hash,
    observed_at: IsoTimestamp,
    limitations: CanonicalNonBlankStringsV02,
  }),
}).strict().superRefine((event, ctx) => {
  if (event.source !== "operator") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "observation.manual-recorded must use source 'operator'" });
  }
  if (event.authority_ref !== event.payload.authenticated_principal_ref) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "observation authority must equal the authenticated principal" });
  }
  if (event.run_id !== event.payload.run_id) {
    ctx.addIssue({ code: "custom", path: ["payload", "run_id"], message: "payload run ID must equal envelope run ID" });
  }
});

const ClaimSubjectV02 = z.discriminatedUnion("kind", [
  strictObject({ kind: z.literal("goal-success-criterion"), subject_ref: HumanId }),
  strictObject({ kind: z.literal("gate"), subject_ref: HumanId }),
  strictObject({ kind: z.literal("evaluation"), subject_ref: HumanId }),
]);
const ClaimVerdictRecordRefV02 = z.discriminatedUnion("record_kind", [
  strictObject({ record_kind: z.literal("gate-result"), record_id: MachineId, record_event_ref: LedgerRefV02 }),
  strictObject({ record_kind: z.literal("evaluation-result"), record_id: MachineId, record_event_ref: LedgerRefV02 }),
]);
const CanonicalClaimVerdictRefsV02 = z.array(ClaimVerdictRecordRefV02).min(1).superRefine((refs, ctx) => {
  for (let index = 1; index < refs.length; index += 1) {
    if (compareRecordDependencyRefsV02(refs[index - 1]!, refs[index]!) >= 0) {
      ctx.addIssue({ code: "custom", path: [index], message: "verdict refs must be unique and canonically sorted" });
    }
  }
});

export const ClaimRecordedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("claim.recorded"),
  payload: strictObject({
    claim_id: MachineId,
    subject: ClaimSubjectV02,
    evidence_policy_hash: Hash,
    verdict_record_refs: CanonicalClaimVerdictRefsV02,
    status: z.enum(["verified", "unverified", "contradicted"]),
    record_path: RelativeRunPath,
    record_hash: Hash,
    dependency_record_refs: CanonicalRecordDependencyRefsV02,
    observation_root_refs: CanonicalLedgerRefsV02,
  }),
}).strict().superRefine((event, ctx) => {
  if (event.source !== "kernel") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "claim.recorded must use source 'kernel'" });
  }
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "claim.recorded must not name authority" });
  }
});

export const FindingRecordedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("finding.recorded"),
  payload: strictObject({
    finding_id: MachineId,
    classification: z.enum(["blocking", "accepted-risk", "deferred", "false-positive"]),
    disposition_authority_principal_ref: MachineId.nullable(),
    disposition_authorization_statement_hash: Hash.nullable(),
    reviewed_through_ref: LedgerRefV02.nullable(),
    record_path: RelativeRunPath,
    record_hash: Hash,
    dependency_record_refs: CanonicalRecordDependencyRefsV02,
    observation_root_refs: CanonicalLedgerRefsV02,
  }),
}).strict().superRefine((event, ctx) => {
  const payload = event.payload;
  const isBlocking = payload.classification === "blocking";
  const dispositionFields = [
    payload.disposition_authority_principal_ref,
    payload.disposition_authorization_statement_hash,
    payload.reviewed_through_ref,
  ];
  const hasCompleteDisposition = dispositionFields.every((field) => field !== null);
  const hasNoDisposition = dispositionFields.every((field) => field === null);
  if ((isBlocking && !hasNoDisposition) || (!isBlocking && !hasCompleteDisposition)) {
    ctx.addIssue({ code: "custom", path: ["payload"], message: "finding disposition fields must match classification" });
  }
  const expectedSource = isBlocking ? "evaluator" : "operator";
  if (event.source !== expectedSource) {
    ctx.addIssue({ code: "custom", path: ["source"], message: "finding source must match classification" });
  }
  const expectedAuthority = isBlocking ? null : payload.disposition_authority_principal_ref;
  if (event.authority_ref !== expectedAuthority) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "finding authority must match disposition principal" });
  }
});

export const WaiverRecordedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("waiver.recorded"),
  payload: strictObject({
    waiver_id: MachineId,
    gate_ref: HumanId,
    record_path: RelativeRunPath,
    record_hash: Hash,
    authority_record_ref: LedgerRefV02,
    action_scope_hash: Hash,
    authority_revocation_epoch: safeInteger.nonnegative(),
    authority_envelope_revocation_epoch: safeInteger.nonnegative(),
    required_event_ref: LedgerRefV02,
    prerequisite_set_hash: Hash,
    approved_risk_tier: RiskTierV1,
    reviewed_through_ref: LedgerRefV02,
    boundary_clock_ref: LedgerRefV02,
    dependency_record_refs: CanonicalRecordDependencyRefsV02,
    observation_root_refs: CanonicalLedgerRefsV02,
  }),
}).strict().superRefine((event, ctx) => {
  if (event.source !== "operator") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "waiver.recorded must use source 'operator'" });
  }
  if (event.authority_ref === null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "waiver.recorded requires operator authority" });
  }
});

export const AuthorityHumanAuthorizationRecordedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("authority.human-authorization-recorded"),
  payload: strictObject({
    authorization_id: MachineId,
    record_path: RelativeRunPath,
    record_hash: Hash,
    run_id: MachineId,
    plan_hash: Hash,
    authorization_subject_hash: Hash,
    authenticated_principal_ref: MachineId,
    authentication_context_hash: Hash,
    action_scope_hash: Hash,
    approved_risk_tier: RiskTierV1,
    operator_key_id: MachineId,
    approval_channel: z.enum(["local-ed25519", "platform-authenticated"]),
    approval_nonce: Hash,
    proof_algorithm: z.enum(["ed25519", "platform-authenticated-v01"]),
    authorization_statement_hash: Hash,
    issued_at: IsoTimestamp,
    expires_at: IsoTimestamp,
    revocation_epoch: safeInteger.nonnegative(),
  }),
}).strict().superRefine((event, ctx) => {
  const payload = event.payload;
  if (event.source !== "operator") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "human authorization must use source 'operator'" });
  }
  if (event.authority_ref !== payload.authenticated_principal_ref) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "authorization authority must equal authenticated principal" });
  }
  if (event.run_id !== payload.run_id) {
    ctx.addIssue({ code: "custom", path: ["payload", "run_id"], message: "payload run ID must equal envelope run ID" });
  }
  const channelPairValid = (payload.approval_channel === "local-ed25519" && payload.proof_algorithm === "ed25519")
    || (payload.approval_channel === "platform-authenticated" && payload.proof_algorithm === "platform-authenticated-v01");
  if (!channelPairValid) {
    ctx.addIssue({ code: "custom", path: ["payload", "proof_algorithm"], message: "proof algorithm must match approval channel" });
  }
  if (Date.parse(payload.issued_at) >= Date.parse(payload.expires_at)) {
    ctx.addIssue({ code: "custom", path: ["payload", "expires_at"], message: "authorization interval must be non-empty" });
  }
});

export const AuthorityEnvelopeRecordedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("authority.envelope-recorded"),
  payload: strictObject({
    authority_envelope_id: MachineId,
    record_path: RelativeRunPath,
    record_hash: Hash,
    run_id: MachineId,
    plan_hash: Hash,
    policy_digest: Hash,
    subject_ref: MachineId,
    issuer_principal_ref: MachineId,
    authorization_subject_hash: Hash,
    human_authorization_proof_refs: NonEmptyCanonicalLedgerRefsV02,
    action_class: z.enum(["gate-waiver", "task", "tool", "artifact-write", "authority-delegation"]),
    action_scope_hash: Hash,
    max_risk_tier: RiskTierV1,
    issued_at: IsoTimestamp,
    expires_at: IsoTimestamp,
    revocation_epoch: safeInteger.nonnegative(),
    delegation_depth: z.union([z.literal(0), z.literal(1)]),
  }),
}).strict().superRefine((event, ctx) => {
  const payload = event.payload;
  validatePepAuthorityV02(event, "authority.envelope-recorded", ctx);
  if (event.authority_ref !== payload.issuer_principal_ref) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "envelope authority must equal issuer principal" });
  }
  if (event.run_id !== payload.run_id) {
    ctx.addIssue({ code: "custom", path: ["payload", "run_id"], message: "payload run ID must equal envelope run ID" });
  }
  if (payload.subject_ref === payload.issuer_principal_ref) {
    ctx.addIssue({ code: "custom", path: ["payload", "subject_ref"], message: "authority envelope cannot be self-issued" });
  }
  if (Date.parse(payload.issued_at) >= Date.parse(payload.expires_at)) {
    ctx.addIssue({ code: "custom", path: ["payload", "expires_at"], message: "authority envelope interval must be non-empty" });
  }
});

const AuthorityRevocationTargetV02 = z.discriminatedUnion("kind", [
  strictObject({
    kind: z.literal("authority-envelope"),
    target_ref: strictObject({
      record_kind: z.literal("authority-envelope"),
      record_id: MachineId,
      record_event_ref: LedgerRefV02,
    }),
    target_scope_hash: Hash,
  }),
  strictObject({
    kind: z.literal("gate-waiver-authority"),
    target_ref: strictObject({
      record_kind: z.literal("gate-waiver-authority"),
      record_id: MachineId,
      record_event_ref: LedgerRefV02,
    }),
    target_scope_hash: Hash,
  }),
]);

export const AuthorityGrantRevokedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("authority.grant-revoked"),
  payload: strictObject({
    revocation_id: MachineId,
    record_path: RelativeRunPath,
    record_hash: Hash,
    run_id: MachineId,
    plan_hash: Hash,
    target: AuthorityRevocationTargetV02,
    previous_revocation_epoch: safeInteger.nonnegative(),
    revocation_epoch: safeInteger.positive(),
    effective_prefix_ref: LedgerRefV02,
    reason_code: z.enum([
      "operator-revoked", "authority-expired", "scope-invalidated", "policy-changed",
      "principal-revoked", "compromise-suspected",
    ]),
    evidence_refs: ReviewEvidenceRefsV02,
    revoker_kind: z.enum(["operator", "policy-enforcement-point"]),
    revoker_identity_ref: MachineId,
    revoker_stable_identity_hash: Hash,
    revoker_authentication_context_hash: Hash,
    policy_digest: Hash,
    revoked_at: IsoTimestamp,
    signer_key_ref: MachineId,
    statement_hash: Hash,
  }),
}).strict().superRefine((event, ctx) => {
  const payload = event.payload;
  if (event.run_id !== payload.run_id) {
    ctx.addIssue({ code: "custom", path: ["payload", "run_id"], message: "payload run ID must equal envelope run ID" });
  }
  if (event.authority_ref !== payload.revoker_identity_ref) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "revocation authority must equal revoker identity" });
  }
  const operatorRevocation = payload.reason_code === "operator-revoked";
  const expectedSource = operatorRevocation ? "operator" : "policy-enforcement-point";
  if (event.source !== expectedSource || payload.revoker_kind !== expectedSource) {
    ctx.addIssue({ code: "custom", path: ["source"], message: "revocation source and revoker kind must match reason" });
  }
  if (payload.previous_revocation_epoch >= Number.MAX_SAFE_INTEGER
    || payload.revocation_epoch !== payload.previous_revocation_epoch + 1) {
    ctx.addIssue({ code: "custom", path: ["payload", "revocation_epoch"], message: "revocation epoch must increment by exactly one without overflow" });
  }
  if (payload.effective_prefix_ref.ledger_sequence >= Number.MAX_SAFE_INTEGER
    || event.sequence !== payload.effective_prefix_ref.ledger_sequence + 1
    || event.previous_event_hash !== payload.effective_prefix_ref.event_hash) {
    ctx.addIssue({ code: "custom", path: ["payload", "effective_prefix_ref"], message: "revocation must immediately follow its effective prefix" });
  }
});

const CustodyStatePayloadCommonV02 = {
  subject_hash: Hash,
  previous_state_event_ref: z.null(),
  retention_class: RetentionClass,
  expires_at: IsoTimestamp.nullable(),
  quarantine_status: z.enum(["clear", "quarantined"]),
  quarantine_reason: z.enum(["privacy-review-required", "redaction-unsafe"]).nullable(),
  integrity_status: z.literal("valid"),
  integrity_finding_refs: z.tuple([]),
  export_state: z.enum(["exportable", "not-exportable"]),
  export_reason: z.enum(["no-current-decision", "policy-denied", "quarantined", "expired"]).nullable(),
  export_decision_event_ref: LedgerRefV02.nullable(),
  policy_version: NonBlankString,
  evidence_refs: CanonicalLedgerRefsV02,
} satisfies z.ZodRawShape;

export const RecordCustodyStateRecordedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("record.custody-state-recorded"),
  payload: z.discriminatedUnion("subject_kind", [
    strictObject({ ...ArtifactEvidenceSubjectV02.shape, ...CustodyStatePayloadCommonV02 }),
    strictObject({ ...EvidenceSubjectV02.shape, ...CustodyStatePayloadCommonV02 }),
  ]),
}).strict().superRefine((event, ctx) => {
  const payload = event.payload;
  if (event.source !== "kernel") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "record.custody-state-recorded must use source 'kernel'" });
  }
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "record.custody-state-recorded must not name authority" });
  }
  const quarantineValid = (payload.quarantine_status === "clear" && payload.quarantine_reason === null)
    || (payload.quarantine_status === "quarantined" && payload.quarantine_reason !== null);
  if (!quarantineValid) {
    ctx.addIssue({ code: "custom", path: ["payload", "quarantine_reason"], message: "quarantine reason must match quarantine status" });
  }
  if (payload.export_state === "exportable") {
    if (payload.quarantine_status !== "clear" || payload.export_reason !== null || payload.export_decision_event_ref === null) {
      ctx.addIssue({ code: "custom", path: ["payload", "export_state"], message: "exportable custody requires clear status and a decision reference" });
    }
  } else if (payload.export_reason === null) {
    ctx.addIssue({ code: "custom", path: ["payload", "export_reason"], message: "not-exportable custody requires a reason" });
  }
});

const ExportSelectedByteTupleShapeV02 = {
  path: RelativeRunPath,
  hash: Hash,
  size_bytes: safeInteger.nonnegative(),
  media_type: NonBlankString,
  binding_ref: LedgerRefV02,
} satisfies z.ZodRawShape;
const ArtifactExportSelectedBytesV02 = z.discriminatedUnion("kind", [
  strictObject({ kind: z.literal("original-content"), ref: HumanId, ...ExportSelectedByteTupleShapeV02 }),
  strictObject({ kind: z.literal("redacted-derivative"), ref: MachineId, ...ExportSelectedByteTupleShapeV02 }),
]);
const EvidenceExportSelectedBytesV02 = z.discriminatedUnion("kind", [
  strictObject({ kind: z.literal("original-content"), ref: MachineId, ...ExportSelectedByteTupleShapeV02 }),
  strictObject({ kind: z.literal("redacted-derivative"), ref: MachineId, ...ExportSelectedByteTupleShapeV02 }),
  strictObject({ kind: z.literal("record-bytes"), ref: MachineId, ...ExportSelectedByteTupleShapeV02 }),
]);
const ExportReviewCheckV02 = strictObject({
  result_ref: RecordDependencyRefV02,
  evaluation_ref: HumanId,
  evaluator_identity_ref: MachineId,
  policy_digest: Hash,
  subject_hash: Hash,
});
const CanonicalExportReviewChecksV02 = z.array(ExportReviewCheckV02).superRefine((checks, ctx) => {
  for (let index = 1; index < checks.length; index += 1) {
    if (compareRecordDependencyRefsV02(checks[index - 1]!.result_ref, checks[index]!.result_ref) >= 0) {
      ctx.addIssue({ code: "custom", path: [index, "result_ref"], message: "export checks must be unique and canonically sorted" });
    }
  }
});
const ExportDecisionPayloadCommonV02 = {
  decision_id: MachineId,
  record_path: RelativeRunPath,
  record_hash: Hash,
  original_record_hash: Hash,
  subject_hash: Hash,
  decision: z.enum(["exportable", "not-exportable"]),
  credential_scan_evidence_refs: CanonicalExportReviewChecksV02,
  privacy_review_evidence_refs: CanonicalExportReviewChecksV02,
  policy_version: NonBlankString,
} satisfies z.ZodRawShape;

export const RecordExportDecisionRecordedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("record.export-decision-recorded"),
  payload: z.discriminatedUnion("subject_kind", [
    strictObject({
      ...ExportDecisionPayloadCommonV02,
      subject_kind: z.literal("artifact"),
      subject_ref: HumanId,
      original_content_hash: Hash,
      selected_bytes: ArtifactExportSelectedBytesV02,
    }),
    strictObject({
      ...ExportDecisionPayloadCommonV02,
      subject_kind: z.literal("evidence"),
      subject_ref: MachineId,
      original_content_hash: Hash.nullable(),
      selected_bytes: EvidenceExportSelectedBytesV02,
    }),
  ]),
}).strict().superRefine((event, ctx) => {
  const payload = event.payload;
  if (event.source !== "evaluator") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "record.export-decision-recorded must use source 'evaluator'" });
  }
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "record.export-decision-recorded must not name authority" });
  }
  const expectedSubjectHash = hashCanonical({
    purpose: "export-subject-v02",
    schema_version: "0.2",
    run_id: event.run_id,
    subject_kind: payload.subject_kind,
    subject_ref: payload.subject_ref,
    original_record_hash: payload.original_record_hash,
    original_content_hash: payload.original_content_hash,
    selected_bytes: payload.selected_bytes,
    policy_version: payload.policy_version,
  });
  if (payload.subject_hash !== expectedSubjectHash) {
    ctx.addIssue({ code: "custom", path: ["payload", "subject_hash"], message: "subject hash must match the exact export subject preimage" });
  }
  if (payload.selected_bytes.kind === "original-content" && payload.selected_bytes.ref !== payload.subject_ref) {
    ctx.addIssue({ code: "custom", path: ["payload", "selected_bytes", "ref"], message: "original-content ref must equal subject ref" });
  }
  if (payload.subject_kind === "evidence" && payload.selected_bytes.kind === "record-bytes") {
    if (payload.original_content_hash !== null
      || payload.selected_bytes.ref !== payload.subject_ref
      || payload.selected_bytes.media_type !== "application/json") {
      ctx.addIssue({ code: "custom", path: ["payload", "selected_bytes"], message: "record-bytes is only valid for content-less evidence JSON" });
    }
  }
  const allChecks = [...payload.credential_scan_evidence_refs, ...payload.privacy_review_evidence_refs];
  allChecks.forEach((check, index) => {
    if (check.subject_hash !== payload.subject_hash) {
      ctx.addIssue({ code: "custom", path: ["payload", "checks", index, "subject_hash"], message: "export check must bind the exact subject hash" });
    }
  });
  const credentialResultRefs = new Set(
    payload.credential_scan_evidence_refs.map((check) => canonicalize(check.result_ref)),
  );
  const credentialEvaluationRefs = new Set(
    payload.credential_scan_evidence_refs.map((check) => check.evaluation_ref),
  );
  payload.privacy_review_evidence_refs.forEach((check, index) => {
    if (credentialResultRefs.has(canonicalize(check.result_ref))) {
      ctx.addIssue({
        code: "custom",
        path: ["payload", "privacy_review_evidence_refs", index, "result_ref"],
        message: "credential and privacy checks must use distinct result refs",
      });
    }
    if (credentialEvaluationRefs.has(check.evaluation_ref)) {
      ctx.addIssue({
        code: "custom",
        path: ["payload", "privacy_review_evidence_refs", index, "evaluation_ref"],
        message: "credential and privacy checks must use distinct evaluation refs",
      });
    }
  });
  if (payload.decision === "exportable") {
    if (payload.credential_scan_evidence_refs.length === 0 || payload.privacy_review_evidence_refs.length === 0) {
      ctx.addIssue({ code: "custom", path: ["payload", "decision"], message: "exportable decision requires credential and privacy checks" });
    }
    const credentialEvaluators = new Set(payload.credential_scan_evidence_refs.map((check) => check.evaluator_identity_ref));
    if (payload.privacy_review_evidence_refs.some((check) => credentialEvaluators.has(check.evaluator_identity_ref))) {
      ctx.addIssue({ code: "custom", path: ["payload", "privacy_review_evidence_refs"], message: "credential and privacy evaluators must be distinct" });
    }
  }
});

const CanonicalHashesV02 = z.array(Hash).superRefine((hashes, ctx) => {
  for (let index = 1; index < hashes.length; index += 1) {
    if (compareRuntimeUtf8BytesV02(hashes[index - 1]!, hashes[index]!) >= 0) {
      ctx.addIssue({ code: "custom", path: [index], message: "hashes must be unique and sorted by raw UTF-8 bytes" });
    }
  }
});
const PolicyReasonCodeRefV02 = strictObject({
  policy_digest: Hash,
  declaration_ref: HumanId,
});
const NonEmptyCanonicalPolicyReasonCodeRefsV02 = z.array(PolicyReasonCodeRefV02).min(1).superRefine((refs, ctx) => {
  for (let index = 1; index < refs.length; index += 1) {
    if (compareRuntimeUtf8BytesV02(canonicalize(refs[index - 1]!), canonicalize(refs[index]!)) >= 0) {
      ctx.addIssue({ code: "custom", path: [index], message: "policy reason refs must be unique and sorted by RFC 8785 bytes" });
    }
  }
});

export const ApprovalRecommendationRecordedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("approval.recommendation-recorded"),
  payload: strictObject({
    recommendation_id: MachineId,
    record_path: RelativeRunPath,
    record_hash: Hash,
    run_id: MachineId,
    plan_hash: Hash,
    task_ref: HumanId,
    phase: z.enum(["work", "compensation"]),
    compensation_ref: HumanId.nullable(),
    action_proposal_id: MachineId,
    action_proposal_hash: Hash,
    action_actor_ref: MachineId,
    action_actor_stable_identity_hash: Hash,
    on_behalf_of_chain_hash: Hash,
    repository_root_ref: MachineId,
    repository_base_ref_identity_hash: Hash,
    repository_pre_state_hash: Hash,
    authorized_change_set_hash: Hash,
    normalized_dispatch_hash: Hash,
    action_scope_hash: Hash,
    action_class: z.enum(["task", "tool", "artifact-write"]),
    classifier_input_hash: Hash,
    classifier_registry_hash: Hash,
    classifier_rule_hash: Hash,
    data_flow_hash: Hash,
    policy_action_kind: AgencyPolicyActionKindV1,
    action_approval_class: z.literal("agency"),
    recommendation_subject_hash: Hash,
    quorum_requirement_hash: Hash,
    policy_digest: Hash,
    reviewed_through_ref: LedgerRefV02,
    evidence_refs: AgencyRecommendationEvidenceRefsV02,
    evidence_independence_keys: CanonicalHashesV02.refine((keys) => keys.length > 0, {
      message: "recommendation requires at least one evidence independence key",
    }),
    evaluator_role_ref: HumanId,
    evaluator_actor_ref: MachineId,
    evaluator_stable_identity_hash: Hash,
    evaluator_authentication_context_hash: Hash,
    decision: z.enum(["allow", "allow_with_conditions", "deny", "escalate", "abort"]),
    condition_hashes: CanonicalHashesV02,
    reason_codes: NonEmptyCanonicalPolicyReasonCodeRefsV02,
    issued_at: IsoTimestamp,
    expires_at: IsoTimestamp,
    signer_key_ref: MachineId,
    statement_hash: Hash,
  }),
}).strict().superRefine((event, ctx) => {
  const payload = event.payload;
  validateEvaluatorNullAuthorityV02(event, "approval.recommendation-recorded", ctx);
  if (event.run_id !== payload.run_id) {
    ctx.addIssue({ code: "custom", path: ["payload", "run_id"], message: "payload run ID must equal envelope run ID" });
  }
  if ((payload.phase === "compensation") !== (payload.compensation_ref !== null)) {
    ctx.addIssue({ code: "custom", path: ["payload", "compensation_ref"], message: "compensation reference must be present exactly in compensation phase" });
  }
  const conditionsValid = payload.decision === "allow_with_conditions"
    ? payload.condition_hashes.length > 0
    : payload.condition_hashes.length === 0;
  if (!conditionsValid) {
    ctx.addIssue({ code: "custom", path: ["payload", "condition_hashes"], message: "condition hashes must match recommendation decision" });
  }
  if (payload.evaluator_actor_ref === payload.action_actor_ref
    || payload.evaluator_stable_identity_hash === payload.action_actor_stable_identity_hash) {
    ctx.addIssue({ code: "custom", path: ["payload", "evaluator_actor_ref"], message: "recommendation evaluator must be independent from action actor" });
  }
  if (payload.reason_codes.some((reason) => reason.policy_digest !== payload.policy_digest)) {
    ctx.addIssue({ code: "custom", path: ["payload", "reason_codes"], message: "reason refs must copy the recommendation policy digest" });
  }
  if (Date.parse(payload.issued_at) >= Date.parse(payload.expires_at)) {
    ctx.addIssue({ code: "custom", path: ["payload", "expires_at"], message: "recommendation interval must be non-empty" });
  }
});

const CanonicalBase64V02 = NonBlankString.refine((value) => {
  try {
    return Buffer.from(value, "base64").toString("base64") === value;
  } catch {
    return false;
  }
}, { message: "must be canonical padded RFC 4648 base64" });
const RepositoryTreeEntryV02 = strictObject({
  entry_kind: z.enum(["regular-file", "symlink", "gitlink"]),
  mode: NonBlankString,
  object_id: GitObjectIdV02,
});
const RepositoryWorktreeEntryV02 = strictObject({
  entry_kind: z.enum(["regular-file", "symlink"]),
  mode: NonBlankString,
  size_bytes: safeInteger.nonnegative(),
  content_hash: Hash,
  tracking: z.enum(["tracked", "untracked"]),
  ignored: z.boolean().nullable(),
}).superRefine((entry, ctx) => {
  if ((entry.tracking === "tracked") !== (entry.ignored === null)) {
    ctx.addIssue({ code: "custom", path: ["ignored"], message: "tracked entries require null ignored; untracked entries require a boolean" });
  }
});
const RepositorySubmoduleCheckoutV02 = z.discriminatedUnion("checkout_state", [
  strictObject({
    checkout_state: z.literal("absent"), nested_object_format: z.null(),
    checked_out_head: z.null(), nested_repository_state_hash: z.null(),
  }),
  strictObject({
    checkout_state: z.literal("present"), nested_object_format: z.enum(["sha1", "sha256"]),
    checked_out_head: GitObjectIdV02, nested_repository_state_hash: Hash,
  }),
]);
const RepositoryPathStateV02 = strictObject({
  path_bytes_base64: CanonicalBase64V02,
  head_entry: RepositoryTreeEntryV02.nullable(),
  index_entry: RepositoryTreeEntryV02.nullable(),
  worktree_entry: RepositoryWorktreeEntryV02.nullable(),
  submodule_checkout: RepositorySubmoduleCheckoutV02.nullable(),
  path_state_hash: Hash,
}).superRefine((state, ctx) => {
  if (state.head_entry === null && state.index_entry === null && state.worktree_entry === null && state.submodule_checkout === null) {
    ctx.addIssue({ code: "custom", message: "repository path state must contain at least one layer" });
  }
  if (state.worktree_entry !== null && state.submodule_checkout !== null) {
    ctx.addIssue({ code: "custom", message: "worktree entry and submodule checkout are mutually exclusive" });
  }
  const expected = hashCanonical({
    purpose: "repository-path-state-v02",
    path_bytes_base64: state.path_bytes_base64,
    head_entry: state.head_entry,
    index_entry: state.index_entry,
    worktree_entry: state.worktree_entry,
    submodule_checkout: state.submodule_checkout,
  });
  if (state.path_state_hash !== expected) {
    ctx.addIssue({ code: "custom", path: ["path_state_hash"], message: "repository path-state hash must match its exact preimage" });
  }
});
const ObservedRepositoryChangeV02 = strictObject({
  path_bytes_base64: CanonicalBase64V02,
  operation: z.enum(["create", "update", "delete", "mode-change"]),
  before_path_state: RepositoryPathStateV02.nullable(),
  after_path_state: RepositoryPathStateV02.nullable(),
}).superRefine((change, ctx) => {
  for (const [field, state] of [["before_path_state", change.before_path_state], ["after_path_state", change.after_path_state]] as const) {
    if (state !== null && state.path_bytes_base64 !== change.path_bytes_base64) {
      ctx.addIssue({ code: "custom", path: [field, "path_bytes_base64"], message: "nested path state must match change path" });
    }
  }
});
const CanonicalObservedRepositoryChangesV02 = z.array(ObservedRepositoryChangeV02).superRefine((changes, ctx) => {
  for (let index = 1; index < changes.length; index += 1) {
    if (Buffer.compare(
      Buffer.from(changes[index - 1]!.path_bytes_base64, "base64"),
      Buffer.from(changes[index]!.path_bytes_base64, "base64"),
    ) >= 0) {
      ctx.addIssue({ code: "custom", path: [index, "path_bytes_base64"], message: "observed changes must be unique and sorted by decoded path bytes" });
    }
  }
});
const ObservedRepositoryChangeSetV02 = strictObject({
  repository_root_ref: MachineId,
  base_ref_identity_hash: Hash,
  repository_pre_state_hash: Hash,
  repository_post_state_hash: Hash,
  head_before: GitObjectIdV02,
  head_after: GitObjectIdV02,
  changes: CanonicalObservedRepositoryChangesV02,
  observed_change_set_hash: Hash,
}).superRefine((observed, ctx) => {
  const expected = hashCanonical({
    purpose: "observed-repository-change-set-v02",
    repository_root_ref: observed.repository_root_ref,
    base_ref_identity_hash: observed.base_ref_identity_hash,
    repository_pre_state_hash: observed.repository_pre_state_hash,
    repository_post_state_hash: observed.repository_post_state_hash,
    head_before: observed.head_before,
    head_after: observed.head_after,
    changes: observed.changes,
  });
  if (observed.observed_change_set_hash !== expected) {
    ctx.addIssue({ code: "custom", path: ["observed_change_set_hash"], message: "observed change-set hash must match its exact preimage" });
  }
});
const EffectSettlementOutcomeV02 = strictObject({
  effect_ref: HumanId,
  outcome: z.enum(["not-committed", "committed", "unknown"]),
  outcome_event_ref: LedgerRefV02,
});
const CanonicalEffectSettlementOutcomesV02 = z.array(EffectSettlementOutcomeV02).min(1).superRefine((outcomes, ctx) => {
  for (let index = 1; index < outcomes.length; index += 1) {
    if (compareRuntimeUtf8BytesV02(outcomes[index - 1]!.effect_ref, outcomes[index]!.effect_ref) >= 0) {
      ctx.addIssue({ code: "custom", path: [index, "effect_ref"], message: "effect outcomes must be unique and sorted by UTF-8 effect_ref bytes" });
    }
  }
});
const TaskActionSettledPayloadBaseV02 = {
  action_id: MachineId,
  task_ref: HumanId,
  terminal_event_ref: LedgerRefV02,
  action_proposal_id: MachineId,
  action_proposal_hash: Hash,
  action_actor_ref: MachineId,
  action_actor_stable_identity_hash: Hash,
  on_behalf_of_chain_hash: Hash,
  repository_root_ref: MachineId,
  repository_base_ref_identity_hash: Hash,
  repository_pre_state_hash: Hash,
  authorized_change_set_hash: Hash,
  normalized_dispatch_hash: Hash,
  repository_post_state: VerifiedRepositoryStateV02,
  repository_post_state_hash: Hash,
  observed_change_set: ObservedRepositoryChangeSetV02,
  observed_change_set_hash: Hash,
  repository_transition_status: z.enum(["unchanged", "authorized-change", "drift-hold"]),
  effect_outcomes: CanonicalEffectSettlementOutcomesV02,
} satisfies z.ZodRawShape;

export const TaskActionSettledEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("task.action-settled"),
  payload: z.discriminatedUnion("action_approval_class", [
    strictObject({
      ...TaskActionSettledPayloadBaseV02,
      policy_action_kind: AutomaticPolicyActionKindV1,
      action_approval_class: z.literal("automatic"),
    }),
    strictObject({
      ...TaskActionSettledPayloadBaseV02,
      policy_action_kind: AgencyPolicyActionKindV1,
      action_approval_class: z.literal("agency"),
    }),
  ]),
}).strict().superRefine((event, ctx) => {
  const payload = event.payload;
  if (event.source !== "kernel") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "task.action-settled must use source 'kernel'" });
  }
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "task.action-settled must not name authority" });
  }
  if (payload.repository_post_state_hash !== payload.repository_post_state.repository_state_hash) {
    ctx.addIssue({ code: "custom", path: ["payload", "repository_post_state_hash"], message: "copied post-state hash must match repository state" });
  }
  if (payload.observed_change_set_hash !== payload.observed_change_set.observed_change_set_hash) {
    ctx.addIssue({ code: "custom", path: ["payload", "observed_change_set_hash"], message: "copied observed hash must match change set" });
  }
  const observed = payload.observed_change_set;
  const post = payload.repository_post_state;
  if (post.repository_root_ref !== payload.repository_root_ref
    || post.base_ref_identity_hash !== payload.repository_base_ref_identity_hash
    || observed.repository_root_ref !== payload.repository_root_ref
    || observed.base_ref_identity_hash !== payload.repository_base_ref_identity_hash
    || observed.repository_pre_state_hash !== payload.repository_pre_state_hash
    || observed.repository_post_state_hash !== payload.repository_post_state_hash
    || canonicalize(observed.head_after) !== canonicalize(post.head)) {
    ctx.addIssue({ code: "custom", path: ["payload"], message: "repository settlement lineage must be exact" });
  }
  if (payload.repository_transition_status === "unchanged"
    && (payload.repository_pre_state_hash !== payload.repository_post_state_hash
      || canonicalize(observed.head_before) !== canonicalize(observed.head_after)
      || observed.changes.length !== 0)) {
    ctx.addIssue({ code: "custom", path: ["payload", "repository_transition_status"], message: "unchanged transition requires identical state, HEAD, and empty delta" });
  }
});

const AuthorityOperationV02 = z.enum([
  "read", "list", "search", "invoke", "create", "append", "update", "rename",
  "delete", "export", "send", "waive",
]);
const AuthorityResourceSelectorV02 = z.discriminatedUnion("kind", [
  strictObject({ kind: z.literal("plan-object"), object_kind: z.enum(["task", "gate", "artifact"]), object_ref: HumanId }),
  strictObject({ kind: z.literal("workspace-path"), workspace_root_ref: MachineId, path_prefix_segments: z.array(NonBlankString) }),
  strictObject({ kind: z.literal("network-origin"), origin_ref: MachineId, path_prefix_segments: z.array(NonBlankString) }),
  strictObject({ kind: z.literal("connector-resource"), connector_ref: HumanId, account_ref: MachineId, resource_prefix_segments: z.array(NonBlankString) }),
  strictObject({ kind: z.literal("tool"), tool_ref: HumanId, tool_definition_hash: Hash }),
]);
const CanonicalAuthorityResourceSelectorsV02 = z.array(AuthorityResourceSelectorV02).superRefine((selectors, ctx) => {
  for (let index = 1; index < selectors.length; index += 1) {
    if (compareRuntimeUtf8BytesV02(canonicalize(selectors[index - 1]!), canonicalize(selectors[index]!)) >= 0) {
      ctx.addIssue({ code: "custom", path: [index], message: "resource selectors must be unique and sorted by RFC 8785 bytes" });
    }
  }
});
const AuthorityCapabilityConstraintV02 = strictObject({
  classifier_key: ActionClassifierKeyV1,
  classifier_rule_hash: Hash,
});
const CanonicalAuthorityCapabilityConstraintsV02 = z.array(AuthorityCapabilityConstraintV02).min(1).superRefine((constraints, ctx) => {
  for (let index = 1; index < constraints.length; index += 1) {
    if (compareRuntimeUtf8BytesV02(canonicalize(constraints[index - 1]!), canonicalize(constraints[index]!)) >= 0) {
      ctx.addIssue({ code: "custom", path: [index], message: "capability constraints must be unique and sorted by RFC 8785 bytes" });
    }
  }
});
const AuthorityCostConstraintV02 = z.discriminatedUnion("capture", [
  strictObject({ capture: z.literal("not-applicable"), max_cost_minor_units: z.literal(0), cost_currency: z.null() }),
  strictObject({ capture: z.literal("required"), max_cost_minor_units: safeInteger.nonnegative(), cost_currency: Iso4217CurrencyCodeSyntaxV02 }),
]);
export const AuthorityScopeV02 = strictObject({
  authority_subject: AuthoritySubjectV02,
  action_class: z.enum(["gate-waiver", "task", "tool", "artifact-write", "authority-delegation"]),
  capability_constraints: CanonicalAuthorityCapabilityConstraintsV02,
  resource_selectors: CanonicalAuthorityResourceSelectorsV02,
  operations: z.array(AuthorityOperationV02),
  max_risk_tier: RiskTierV1,
  side_effect_constraints: strictObject({
    allowed_effect_classes: z.array(z.enum(["none", "workspace-write", "external-read", "external-write", "destructive"])),
    allowed_effect_refs: z.array(strictObject({ task_ref: HumanId, effect_ref: HumanId })),
    require_inspectable: z.boolean(),
    require_reversible: z.boolean(),
    require_idempotency_key: z.boolean(),
    require_compensation: z.boolean(),
  }),
  data_constraints: strictObject({
    readable_classifications: CanonicalNonBlankStringsV02,
    exportable_classifications: CanonicalNonBlankStringsV02,
    sink_refs: z.array(MachineId),
  }),
  bounded_constraints: strictObject({
    max_actions: safeInteger.nonnegative(),
    max_attempts: safeInteger.nonnegative(),
    max_tool_calls: safeInteger.nonnegative(),
    max_output_bytes: safeInteger.nonnegative(),
    max_elapsed_ms: safeInteger.nonnegative(),
    cost: AuthorityCostConstraintV02,
    max_workers: safeInteger.nonnegative(),
    max_decisions: safeInteger.nonnegative(),
    max_delegation_depth: z.union([z.literal(0), z.literal(1)]),
  }),
});

/** Normative V02 authority-scope identity for all new producers. */
export function hashAuthorityScopeV02(scope: z.infer<typeof AuthorityScopeV02>): string {
  return hashCanonical({ purpose: "authority-scope-v02", schema_version: "0.2", ...scope });
}

/** Shipped S35 read-compatibility only; new producers must never emit this hash. */
function hashLegacyRawAuthorityScopeS35V02(scope: z.infer<typeof AuthorityScopeV02>): string {
  return hashCanonical(scope);
}

const AuthorizedRepositoryChangeV02 = strictObject({
  path_bytes_base64: CanonicalBase64V02,
  operation: z.enum(["create", "update", "delete", "mode-change"]),
  expected_pre_path_state: RepositoryPathStateV02.nullable(),
  required_post_path_state: RepositoryPathStateV02.nullable(),
  max_post_worktree_size_bytes: safeInteger.nonnegative(),
}).superRefine((change, ctx) => {
  for (const [field, state] of [["expected_pre_path_state", change.expected_pre_path_state], ["required_post_path_state", change.required_post_path_state]] as const) {
    if (state !== null && state.path_bytes_base64 !== change.path_bytes_base64) {
      ctx.addIssue({ code: "custom", path: [field, "path_bytes_base64"], message: "authorized path state must match change path" });
    }
  }
});
const CanonicalAuthorizedRepositoryChangesV02 = z.array(AuthorizedRepositoryChangeV02).superRefine((changes, ctx) => {
  for (let index = 1; index < changes.length; index += 1) {
    if (Buffer.compare(
      Buffer.from(changes[index - 1]!.path_bytes_base64, "base64"),
      Buffer.from(changes[index]!.path_bytes_base64, "base64"),
    ) >= 0) {
      ctx.addIssue({ code: "custom", path: [index, "path_bytes_base64"], message: "authorized changes must be unique and sorted by decoded path bytes" });
    }
  }
});
const AuthorizedRepositoryChangeSetV02 = strictObject({
  repository_root_ref: MachineId,
  base_ref_identity_hash: Hash,
  repository_pre_state_hash: Hash,
  transition_mode: z.enum(["read-only", "linear-settled-writes"]),
  expected_pre_head: GitObjectIdV02,
  required_post_head: GitObjectIdV02,
  mode: z.enum(["no-change", "path-set", "head-only", "head-and-path-set"]),
  changes: CanonicalAuthorizedRepositoryChangesV02,
}).superRefine((changeSet, ctx) => {
  const headsEqual = canonicalize(changeSet.expected_pre_head) === canonicalize(changeSet.required_post_head);
  const hasChanges = changeSet.changes.length > 0;
  const branchValid = (changeSet.mode === "no-change" && headsEqual && !hasChanges)
    || (changeSet.mode === "path-set" && headsEqual && hasChanges)
    || (changeSet.mode === "head-only" && !headsEqual && !hasChanges)
    || (changeSet.mode === "head-and-path-set" && !headsEqual && hasChanges);
  if (!branchValid || (changeSet.transition_mode === "read-only" && changeSet.mode !== "no-change")) {
    ctx.addIssue({ code: "custom", path: ["mode"], message: "authorized change mode must match HEAD, path changes, and transition mode" });
  }
});

const NormalizedActionDispatchCommonShapeV02 = {
  adapter_ref: HumanId,
  adapter_version_hash: Hash,
  capability_ref: HumanId,
  capability_definition_hash: Hash,
  operation: AuthorityOperationV02,
  target: AuthorityResourceSelectorV02,
  destination: AuthorityResourceSelectorV02.nullable(),
  input_subject_hashes: CanonicalHashesV02,
} satisfies z.ZodRawShape;
const NormalizedActionDispatchV02 = z.discriminatedUnion("kind", [
  strictObject({
    ...NormalizedActionDispatchCommonShapeV02,
    kind: z.literal("process"), executable_ref: MachineId, executable_hash: Hash,
    program: NonBlankString, argv: z.array(UnicodeScalarString), cwd_identity_hash: Hash,
    environment_hash: Hash, stdin_hash: Hash.nullable(), timeout_ms: safeInteger.positive(),
    output_limit_bytes: safeInteger.nonnegative(),
  }),
  strictObject({
    ...NormalizedActionDispatchCommonShapeV02,
    kind: z.literal("tool"), tool_ref: HumanId, tool_definition_hash: Hash,
    arguments: z.json(), arguments_hash: Hash,
  }),
  strictObject({
    ...NormalizedActionDispatchCommonShapeV02,
    kind: z.literal("connector"), connector_ref: HumanId, account_ref: MachineId,
    resource_identity_hash: Hash, arguments: z.json(), arguments_hash: Hash,
  }),
  strictObject({
    ...NormalizedActionDispatchCommonShapeV02,
    kind: z.literal("artifact-write"), artifact_ref: HumanId, artifact_path_hash: Hash,
    prospective_content_hash: Hash, prospective_size_bytes: safeInteger.nonnegative(), media_type: NonBlankString,
  }),
]);
const ActionDataFlowV02 = strictObject({
  readable_classifications: CanonicalNonBlankStringsV02,
  exportable_classifications: CanonicalNonBlankStringsV02,
  sink_refs: z.array(MachineId),
  data_access_mode: z.enum(["none", "local", "authenticated", "network", "export"]),
  data_flow_hash: Hash,
}).superRefine((flow, ctx) => {
  const readable = new Set(flow.readable_classifications);
  if (flow.exportable_classifications.some((classification) => !readable.has(classification))) {
    ctx.addIssue({ code: "custom", path: ["exportable_classifications"], message: "exportable classifications must be a subset of readable classifications" });
  }
  const expected = hashCanonical({
    purpose: "action-data-flow-v02",
    readable_classifications: flow.readable_classifications,
    exportable_classifications: flow.exportable_classifications,
    sink_refs: flow.sink_refs,
    data_access_mode: flow.data_access_mode,
  });
  if (flow.data_flow_hash !== expected) {
    ctx.addIssue({ code: "custom", path: ["data_flow_hash"], message: "data-flow hash must match its exact preimage" });
  }
});
const AuthorityPrincipalV02 = strictObject({ principal_ref: MachineId, stable_identity_hash: Hash });
const ActionCostBudgetV02 = z.discriminatedUnion("capture", [
  strictObject({ capture: z.literal("not-applicable"), cost_minor_units: z.literal(0), cost_currency: z.null() }),
  strictObject({ capture: z.literal("required"), cost_minor_units: safeInteger.nonnegative(), cost_currency: Iso4217CurrencyCodeSyntaxV02 }),
]);
const HumanExceptionPolicyActionKindV1 = z.enum([
  "authenticated-write", "commit", "deploy", "destructive-action", "irreversible-action", "merge",
  "new-secret-scope", "package-change", "protected-ref-mutation", "publish", "push", "rebase",
  "release", "send", "t4-action",
]);
const BlockedPolicyActionKindV1 = z.enum([
  "approval-contract-edit", "connector-admin", "connector-delete", "force-push", "policy-weakening",
  "self-widening", "t5-action", "uninspectable-side-effect",
]);
const CanonicalActionEffectRefsV02 = z.array(strictObject({ task_ref: HumanId, effect_ref: HumanId })).superRefine((refs, ctx) => {
  for (let index = 1; index < refs.length; index += 1) {
    const previous = refs[index - 1]!;
    const current = refs[index]!;
    const taskComparison = compareRuntimeUtf8BytesV02(previous.task_ref, current.task_ref);
    if (taskComparison > 0 || (taskComparison === 0 && compareRuntimeUtf8BytesV02(previous.effect_ref, current.effect_ref) >= 0)) {
      ctx.addIssue({ code: "custom", path: [index], message: "effect refs must be unique and sorted by task then effect" });
    }
  }
});
export const ActionProposalV02 = strictObject({
  proposal_version: z.literal("0.2"),
  action_proposal_id: MachineId,
  run_id: MachineId,
  plan_hash: Hash,
  task_ref: HumanId,
  phase: z.enum(["work", "compensation"]),
  compensation_ref: HumanId.nullable(),
  proposer_actor_ref: MachineId,
  proposer_stable_identity_hash: Hash,
  action_actor_ref: MachineId,
  action_actor_stable_identity_hash: Hash,
  on_behalf_of_chain: z.array(AuthorityPrincipalV02).min(1),
  on_behalf_of_chain_hash: Hash,
  repository_root_ref: MachineId,
  repository_base_ref_identity_hash: Hash,
  repository_pre_state_hash: Hash,
  authorized_change_set: AuthorizedRepositoryChangeSetV02,
  authorized_change_set_hash: Hash,
  normalized_dispatch: NormalizedActionDispatchV02,
  normalized_dispatch_hash: Hash,
  action_scope: AuthorityScopeV02,
  action_scope_hash: Hash,
  action_class: z.enum(["task", "tool", "artifact-write"]),
  classification_binding: strictObject({
    classifier_input_hash: Hash, classifier_registry_hash: Hash, classifier_rule_hash: Hash,
  }),
  policy_action_kind: PolicyActionKindV1,
  action_approval_class: ActionApprovalClassV1,
  side_effect_refs: CanonicalActionEffectRefsV02,
  data_flow: ActionDataFlowV02,
  effective_risk_tier: RiskTierV1,
  budget_delta: strictObject({
    tool_calls: safeInteger.nonnegative(), output_bytes: safeInteger.nonnegative(), tokens: safeInteger.nonnegative(), cost: ActionCostBudgetV02,
  }),
  postcondition_hashes: CanonicalHashesV02,
  verifier_refs: CanonicalHumanIdsV02,
  action_proposal_hash: Hash,
}).superRefine((proposal, ctx) => {
  if ((proposal.phase === "compensation") !== (proposal.compensation_ref !== null)) {
    ctx.addIssue({ code: "custom", path: ["compensation_ref"], message: "compensation reference must be present exactly in compensation phase" });
  }
  const classificationValid = (AutomaticPolicyActionKindV1.safeParse(proposal.policy_action_kind).success && proposal.action_approval_class === "automatic")
    || (AgencyPolicyActionKindV1.safeParse(proposal.policy_action_kind).success && proposal.action_approval_class === "agency")
    || (HumanExceptionPolicyActionKindV1.safeParse(proposal.policy_action_kind).success && proposal.action_approval_class === "human_exception")
    || (BlockedPolicyActionKindV1.safeParse(proposal.policy_action_kind).success && proposal.action_approval_class === "blocked");
  if (!classificationValid) {
    ctx.addIssue({ code: "custom", path: ["policy_action_kind"], message: "policy action kind must match its immutable approval class" });
  }
  const chainHash = hashCanonical({ purpose: "action-on-behalf-of-chain-v02", on_behalf_of_chain: proposal.on_behalf_of_chain });
  const changeSetHash = hashCanonical({ purpose: "authorized-repository-change-set-v02", ...proposal.authorized_change_set });
  const dispatchHash = hashCanonical({ purpose: "normalized-action-dispatch-v02", ...proposal.normalized_dispatch });
  const scopeHashValid = proposal.action_scope_hash === hashAuthorityScopeV02(proposal.action_scope)
    || proposal.action_scope_hash === hashLegacyRawAuthorityScopeS35V02(proposal.action_scope);
  if (proposal.on_behalf_of_chain_hash !== chainHash
    || proposal.authorized_change_set_hash !== changeSetHash
    || proposal.normalized_dispatch_hash !== dispatchHash
    || !scopeHashValid) {
    ctx.addIssue({ code: "custom", message: "proposal nested hashes must match their exact preimages" });
  }
  const { action_proposal_hash: _ignored, ...preimage } = proposal;
  if (proposal.action_proposal_hash !== hashCanonical({ purpose: "action-proposal-v02", ...preimage })) {
    ctx.addIssue({ code: "custom", path: ["action_proposal_hash"], message: "action proposal hash must match its exact preimage" });
  }
});

const PolicyDecisionCopiedBindingsShapeV02 = {
  policy_decision_id: MachineId,
  run_id: MachineId,
  plan_hash: Hash,
  task_ref: HumanId,
  phase: z.enum(["work", "compensation"]),
  compensation_ref: HumanId.nullable(),
  authority_envelope_ref: strictObject({ record_kind: z.literal("authority-envelope"), record_id: MachineId, record_event_ref: LedgerRefV02 }),
  action_proposal: ActionProposalV02,
  action_proposal_id: MachineId,
  action_proposal_hash: Hash,
  action_actor_ref: MachineId,
  action_actor_stable_identity_hash: Hash,
  on_behalf_of_chain_hash: Hash,
  repository_root_ref: MachineId,
  repository_base_ref_identity_hash: Hash,
  repository_pre_state_hash: Hash,
  authorized_change_set_hash: Hash,
  normalized_dispatch_hash: Hash,
  action_scope_hash: Hash,
  action_class: z.enum(["task", "tool", "artifact-write"]),
  classifier_input_hash: Hash,
  classifier_registry_hash: Hash,
  classifier_rule_hash: Hash,
  data_flow_hash: Hash,
  reviewed_through_ref: LedgerRefV02,
  policy_digest: Hash,
  reason_codes: NonEmptyCanonicalPolicyReasonCodeRefsV02,
  issued_at: IsoTimestamp,
  expires_at: IsoTimestamp,
  revocation_epoch: safeInteger.nonnegative(),
} satisfies z.ZodRawShape;
const PolicyDecisionBranchFieldsV02 = {
  quorum_requirement_hash: Hash.nullable(),
  recommendation_event_refs: CanonicalLedgerRefsV02,
  condition_hashes: CanonicalHashesV02,
  failed_condition_hashes: CanonicalHashesV02,
  decision: z.enum(["allow", "deny", "escalate", "abort", "hold"]),
  decision_disposition: z.enum(["lease-eligible", "proposal-final", "human-exception-required", "abort-run", "redecide-after-prefix-change", "non-resumable"]),
  evidence_refs: CanonicalLedgerRefsV02,
} satisfies z.ZodRawShape;

const AutomaticPolicyDecisionPayloadV02 = strictObject({
  ...PolicyDecisionCopiedBindingsShapeV02, ...PolicyDecisionBranchFieldsV02,
  policy_action_kind: AutomaticPolicyActionKindV1, action_approval_class: z.literal("automatic"),
}).superRefine((payload, ctx) => {
  if (payload.quorum_requirement_hash !== null || payload.recommendation_event_refs.length !== 0
    || payload.condition_hashes.length !== 0 || payload.failed_condition_hashes.length !== 0
    || payload.decision !== "allow" || payload.decision_disposition !== "lease-eligible" || payload.evidence_refs.length !== 0) {
    ctx.addIssue({ code: "custom", message: "automatic policy decision must be the exact lease-eligible allow branch" });
  }
});
const AgencyPolicyDecisionPayloadV02 = strictObject({
  ...PolicyDecisionCopiedBindingsShapeV02, ...PolicyDecisionBranchFieldsV02,
  policy_action_kind: AgencyPolicyActionKindV1, action_approval_class: z.literal("agency"),
}).superRefine((payload, ctx) => {
  const nonEmpty = (values: readonly unknown[]): boolean => values.length > 0;
  let valid = false;
  if (payload.quorum_requirement_hash === null) {
    valid = payload.phase === "compensation" && payload.compensation_ref !== null
      && payload.decision === "hold" && payload.decision_disposition === "non-resumable"
      && payload.recommendation_event_refs.length === 0 && payload.condition_hashes.length === 0
      && payload.failed_condition_hashes.length === 0 && nonEmpty(payload.evidence_refs);
  } else if (payload.decision === "hold" && payload.decision_disposition === "non-resumable") {
    valid = payload.condition_hashes.length === 0 && payload.failed_condition_hashes.length === 0;
  } else if (payload.decision === "hold" && payload.decision_disposition === "redecide-after-prefix-change") {
    const conditions = new Set(payload.condition_hashes);
    valid = nonEmpty(payload.recommendation_event_refs) && nonEmpty(payload.condition_hashes)
      && nonEmpty(payload.failed_condition_hashes) && nonEmpty(payload.evidence_refs)
      && payload.failed_condition_hashes.every((hash) => conditions.has(hash));
  } else {
    const dispositionByDecision = {
      allow: "lease-eligible", deny: "proposal-final", escalate: "human-exception-required", abort: "abort-run",
    } as const;
    valid = payload.decision !== "hold" && payload.decision_disposition === dispositionByDecision[payload.decision]
      && nonEmpty(payload.recommendation_event_refs) && payload.failed_condition_hashes.length === 0
      && nonEmpty(payload.evidence_refs);
  }
  if (!valid) ctx.addIssue({ code: "custom", message: "agency policy decision branch is invalid" });
});
function finalHoldPolicyDecisionPayloadV02(
  policyKind: typeof HumanExceptionPolicyActionKindV1 | typeof BlockedPolicyActionKindV1,
  approvalClass: "human_exception" | "blocked",
) {
  return strictObject({
    ...PolicyDecisionCopiedBindingsShapeV02, ...PolicyDecisionBranchFieldsV02,
    policy_action_kind: policyKind, action_approval_class: z.literal(approvalClass),
  }).superRefine((payload, ctx) => {
    if (payload.quorum_requirement_hash !== null || payload.recommendation_event_refs.length !== 0
      || payload.condition_hashes.length !== 0 || payload.failed_condition_hashes.length !== 0
      || payload.decision !== "hold" || payload.decision_disposition !== "non-resumable") {
      ctx.addIssue({ code: "custom", message: `${approvalClass} policy decision must be the exact non-resumable HOLD branch` });
    }
  });
}
const PolicyDecisionPayloadV02 = z.union([
  AutomaticPolicyDecisionPayloadV02,
  AgencyPolicyDecisionPayloadV02,
  finalHoldPolicyDecisionPayloadV02(HumanExceptionPolicyActionKindV1, "human_exception"),
  finalHoldPolicyDecisionPayloadV02(BlockedPolicyActionKindV1, "blocked"),
]);

export const PolicyDecisionRecordedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("policy.decision-recorded"),
  payload: PolicyDecisionPayloadV02,
}).strict().superRefine((event, ctx) => {
  const payload = event.payload;
  validatePepAuthorityV02(event, "policy.decision-recorded", ctx);
  if (event.run_id !== payload.run_id || (payload.phase === "compensation") !== (payload.compensation_ref !== null)) {
    ctx.addIssue({ code: "custom", path: ["payload"], message: "policy decision run and phase lineage must match" });
  }
  const proposal = payload.action_proposal;
  const copiedBindingsEqual = payload.action_proposal_id === proposal.action_proposal_id
    && payload.action_proposal_hash === proposal.action_proposal_hash
    && payload.action_actor_ref === proposal.action_actor_ref
    && payload.action_actor_stable_identity_hash === proposal.action_actor_stable_identity_hash
    && payload.on_behalf_of_chain_hash === proposal.on_behalf_of_chain_hash
    && payload.repository_root_ref === proposal.repository_root_ref
    && payload.repository_base_ref_identity_hash === proposal.repository_base_ref_identity_hash
    && payload.repository_pre_state_hash === proposal.repository_pre_state_hash
    && payload.authorized_change_set_hash === proposal.authorized_change_set_hash
    && payload.normalized_dispatch_hash === proposal.normalized_dispatch_hash
    && payload.action_scope_hash === proposal.action_scope_hash
    && payload.action_class === proposal.action_class
    && payload.classifier_input_hash === proposal.classification_binding.classifier_input_hash
    && payload.classifier_registry_hash === proposal.classification_binding.classifier_registry_hash
    && payload.classifier_rule_hash === proposal.classification_binding.classifier_rule_hash
    && payload.data_flow_hash === proposal.data_flow.data_flow_hash
    && payload.policy_action_kind === proposal.policy_action_kind
    && payload.action_approval_class === proposal.action_approval_class
    && payload.run_id === proposal.run_id && payload.plan_hash === proposal.plan_hash
    && payload.task_ref === proposal.task_ref && payload.phase === proposal.phase
    && payload.compensation_ref === proposal.compensation_ref;
  if (!copiedBindingsEqual) {
    ctx.addIssue({ code: "custom", path: ["payload"], message: "policy decision bindings must exactly copy the action proposal" });
  }
  if (payload.reason_codes.some((reason) => reason.policy_digest !== payload.policy_digest)) {
    ctx.addIssue({ code: "custom", path: ["payload", "reason_codes"], message: "reason refs must copy the decision policy digest" });
  }
  if (Date.parse(payload.issued_at) >= Date.parse(payload.expires_at)) {
    ctx.addIssue({ code: "custom", path: ["payload", "expires_at"], message: "policy decision interval must be non-empty" });
  }
});

export const AuthorityWaiverRecordedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("authority.waiver-recorded"),
  payload: strictObject({
    authority_record_id: MachineId,
    record_path: RelativeRunPath,
    record_hash: Hash,
    run_id: MachineId,
    plan_hash: Hash,
    authority_envelope_ref: strictObject({
      record_kind: z.literal("authority-envelope"), record_id: MachineId, record_event_ref: LedgerRefV02,
    }),
    authority_envelope_scope_hash: Hash,
    authority_envelope_revocation_epoch: z.literal(0),
    authority_scope: AuthorityScopeV02,
    action_scope_hash: Hash,
    human_authorization_proof_ref: LedgerRefV02,
    approval_evidence_refs: ReviewEvidenceRefsV02,
    minimum_independent_approval_roots: safeInteger.min(1).max(8),
    issuer_principal_ref: MachineId,
    issued_at: IsoTimestamp,
    expires_at: IsoTimestamp,
    revocation_epoch: z.literal(0),
    allowed_gate_refs: NonEmptyCanonicalHumanIdsV02,
    max_risk_tier: RiskTierV1,
  }),
}).strict().superRefine((event, ctx) => {
  const payload = event.payload;
  if (event.source !== "operator") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "authority.waiver-recorded must use source 'operator'" });
  }
  if (event.authority_ref !== payload.issuer_principal_ref) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "waiver authority must equal issuer principal" });
  }
  if (event.run_id !== payload.run_id) {
    ctx.addIssue({ code: "custom", path: ["payload", "run_id"], message: "payload run ID must equal envelope run ID" });
  }
  if (payload.approval_evidence_refs.some((ref) => ref.record_kind !== "human-authorization")) {
    ctx.addIssue({ code: "custom", path: ["payload", "approval_evidence_refs"], message: "waiver approval evidence must contain only human authorizations" });
  }
  if (payload.action_scope_hash !== hashAuthorityScopeV02(payload.authority_scope)
    && payload.action_scope_hash !== hashLegacyRawAuthorityScopeS35V02(payload.authority_scope)) {
    ctx.addIssue({ code: "custom", path: ["payload", "action_scope_hash"], message: "action scope hash must match the complete authority scope" });
  }
  const scope = payload.authority_scope;
  const expectedSelectors = payload.allowed_gate_refs.map((object_ref) => ({ kind: "plan-object" as const, object_kind: "gate" as const, object_ref }));
  if (scope.action_class !== "gate-waiver"
    || canonicalize(scope.operations) !== canonicalize(["waive"])
    || canonicalize(scope.resource_selectors) !== canonicalize(expectedSelectors)
    || scope.max_risk_tier !== payload.max_risk_tier
    || canonicalize(scope.side_effect_constraints.allowed_effect_classes) !== canonicalize(["none"])
    || scope.side_effect_constraints.allowed_effect_refs.length !== 0
    || scope.data_constraints.readable_classifications.length !== 0
    || scope.data_constraints.exportable_classifications.length !== 0
    || scope.data_constraints.sink_refs.length !== 0) {
    ctx.addIssue({ code: "custom", path: ["payload", "authority_scope"], message: "authority scope must be the exact no-data, no-effect gate-waiver projection" });
  }
  if (Date.parse(payload.issued_at) >= Date.parse(payload.expires_at)) {
    ctx.addIssue({ code: "custom", path: ["payload", "expires_at"], message: "waiver authority interval must be non-empty" });
  }
});

const TerminalStateNameV02 = z.enum(["completed", "held", "blocked", "failed", "stalled", "exhausted", "aborted"]);
const RecoveryTerminalCandidateV02 = z.enum(["aborted", "failed", "exhausted", "stalled"]);
const CompensationActivationReasonV02 = z.enum([
  "terminal-failure",
  "terminal-exhaustion",
  "terminal-stall",
  "abort-recovery",
]);
export const TERMINAL_PRIORITY_V02: Readonly<Record<z.infer<typeof TerminalStateNameV02>, number>> = {
  completed: 100,
  blocked: 200,
  held: 300,
  stalled: 400,
  exhausted: 500,
  failed: 600,
  aborted: 700,
};
export const RECOVERY_PRIORITY_V02: Readonly<Record<z.infer<typeof RecoveryTerminalCandidateV02>, number>> = {
  stalled: 400,
  exhausted: 500,
  failed: 600,
  aborted: 700,
};

export function expectedCompensationActivationReasonV02(
  candidate: z.infer<typeof RecoveryTerminalCandidateV02>,
): z.infer<typeof CompensationActivationReasonV02> {
  switch (candidate) {
    case "stalled": return "terminal-stall";
    case "exhausted": return "terminal-exhaustion";
    case "failed": return "terminal-failure";
    case "aborted": return "abort-recovery";
  }
}

function validateEvaluatorNullAuthorityV02(
  event: { source: z.infer<typeof RuntimeLedgerSourceV02>; authority_ref: string | null },
  eventType: string,
  ctx: z.RefinementCtx,
): void {
  if (event.source !== "evaluator") {
    ctx.addIssue({ code: "custom", path: ["source"], message: `${eventType} must use source 'evaluator'` });
  }
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: `${eventType} must not name authority` });
  }
}

export const RunTerminalFreezeEnteredEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("run.terminal-freeze-entered"),
  payload: strictObject({
    revision: z.literal(1),
    candidate: TerminalStateNameV02,
    candidate_evidence_refs: NonEmptyCanonicalLedgerRefsV02,
    fence_epoch: safeInteger.nonnegative(),
  }),
}).strict().superRefine((event, ctx) => {
  validateEvaluatorNullAuthorityV02(event, "run.terminal-freeze-entered", ctx);
});

export const RunTerminalFreezeRevisedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("run.terminal-freeze-revised"),
  payload: strictObject({
    revision: safeInteger.min(2),
    previous_candidate: TerminalStateNameV02,
    candidate: TerminalStateNameV02,
    previous_freeze_event_hash: Hash,
    candidate_evidence_refs: NonEmptyCanonicalLedgerRefsV02,
  }),
}).strict().superRefine((event, ctx) => {
  validateEvaluatorNullAuthorityV02(event, "run.terminal-freeze-revised", ctx);
  if (TERMINAL_PRIORITY_V02[event.payload.candidate] <= TERMINAL_PRIORITY_V02[event.payload.previous_candidate]) {
    ctx.addIssue({ code: "custom", path: ["payload", "candidate"], message: "terminal freeze revision must move strictly upward" });
  }
});

export const RunCompensationRequestedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("run.compensation-requested"),
  payload: strictObject({
    revision: z.literal(1),
    pending_terminal: RecoveryTerminalCandidateV02,
    activation_reason: CompensationActivationReasonV02,
    compensation_refs: NonEmptyCanonicalHumanIdsV02,
    effect_evidence_refs: NonEmptyCanonicalLedgerRefsV02,
    freeze_event_hash: Hash,
  }),
}).strict().superRefine((event, ctx) => {
  validateEvaluatorNullAuthorityV02(event, "run.compensation-requested", ctx);
  if (event.payload.activation_reason !== expectedCompensationActivationReasonV02(event.payload.pending_terminal)) {
    ctx.addIssue({ code: "custom", path: ["payload", "activation_reason"], message: "activation reason must match pending terminal" });
  }
});

export const RunCompensationRequestRevisedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("run.compensation-request-revised"),
  payload: strictObject({
    revision: safeInteger.min(2),
    previous_pending_terminal: RecoveryTerminalCandidateV02,
    pending_terminal: RecoveryTerminalCandidateV02,
    activation_reason: CompensationActivationReasonV02,
    compensation_refs: NonEmptyCanonicalHumanIdsV02,
    added_compensation_refs: CanonicalHumanIdsV02,
    previous_request_event_hash: Hash,
    freeze_event_hash: Hash,
    effect_evidence_refs: NonEmptyCanonicalLedgerRefsV02,
  }),
}).strict().superRefine((event, ctx) => {
  validateEvaluatorNullAuthorityV02(event, "run.compensation-request-revised", ctx);
  const payload = event.payload;
  if (payload.activation_reason !== expectedCompensationActivationReasonV02(payload.pending_terminal)) {
    ctx.addIssue({ code: "custom", path: ["payload", "activation_reason"], message: "activation reason must match pending terminal" });
  }
  if (RECOVERY_PRIORITY_V02[payload.pending_terminal] < RECOVERY_PRIORITY_V02[payload.previous_pending_terminal]) {
    ctx.addIssue({ code: "custom", path: ["payload", "pending_terminal"], message: "compensation request cannot downgrade its terminal candidate" });
  }
  if (payload.pending_terminal === payload.previous_pending_terminal && payload.added_compensation_refs.length === 0) {
    ctx.addIssue({ code: "custom", path: ["payload"], message: "compensation request revision must change candidate or add compensation refs" });
  }
  const refs = new Set(payload.compensation_refs);
  if (payload.added_compensation_refs.some((ref) => !refs.has(ref))) {
    ctx.addIssue({ code: "custom", path: ["payload", "added_compensation_refs"], message: "added compensation refs must be included in the complete set" });
  }
});

export const RunCompensationPhaseEnteredEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("run.compensation-phase-entered"),
  payload: strictObject({
    request_revision: safeInteger.positive(),
    request_event_hash: Hash,
    pending_terminal: RecoveryTerminalCandidateV02,
    compensation_refs: NonEmptyCanonicalHumanIdsV02,
    freeze_event_hash: Hash,
  }),
}).strict().superRefine((event, ctx) => {
  validateEvaluatorNullAuthorityV02(event, "run.compensation-phase-entered", ctx);
});

export const RunCompensationCandidateEscalatedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("run.compensation-candidate-escalated"),
  payload: strictObject({
    previous_pending_terminal: RecoveryTerminalCandidateV02,
    pending_terminal: RecoveryTerminalCandidateV02,
    activation_reason: CompensationActivationReasonV02,
    compensation_refs: NonEmptyCanonicalHumanIdsV02,
    previous_candidate_event_hash: Hash,
    candidate_evidence_refs: NonEmptyCanonicalLedgerRefsV02,
  }),
}).strict().superRefine((event, ctx) => {
  validateEvaluatorNullAuthorityV02(event, "run.compensation-candidate-escalated", ctx);
  const payload = event.payload;
  if (RECOVERY_PRIORITY_V02[payload.pending_terminal] <= RECOVERY_PRIORITY_V02[payload.previous_pending_terminal]) {
    ctx.addIssue({ code: "custom", path: ["payload", "pending_terminal"], message: "compensation candidate must move through a strict upward pair" });
  }
  if (payload.activation_reason !== expectedCompensationActivationReasonV02(payload.pending_terminal)) {
    ctx.addIssue({ code: "custom", path: ["payload", "activation_reason"], message: "activation reason must match pending terminal" });
  }
});

const CompensationUnableReasonV02 = z.enum([
  "elapsed-budget-exhausted",
  "tool-call-budget-exhausted",
  "output-budget-exhausted",
  "token-budget-exhausted",
  "cost-budget-exhausted",
  "safety-hold",
  "unknown-action-outcome",
]);

export const CompensationSettledEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("compensation.settled"),
  payload: strictObject({
    compensation_ref: HumanId,
    status: z.enum(["compensated", "compensation-failed", "unable"]),
    unable_reason: CompensationUnableReasonV02.nullable(),
    evidence_refs: NonEmptyCanonicalLedgerRefsV02,
  }),
}).strict().superRefine((event, ctx) => {
  validateEvaluatorNullAuthorityV02(event, "compensation.settled", ctx);
  if ((event.payload.status === "unable") !== (event.payload.unable_reason !== null)) {
    ctx.addIssue({ code: "custom", path: ["payload", "unable_reason"], message: "unable reason must be present exactly for unable settlement" });
  }
});

export const RunTerminalSealedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("run.terminal-sealed"),
  payload: strictObject({
    outcome: TerminalStateNameV02,
    pre_seal_ledger_sequence: safeInteger.positive(),
    pre_seal_ledger_head_hash: Hash,
    pre_seal_snapshot_hash: Hash,
    previous_fence_epoch: safeInteger.nonnegative(),
    fence_epoch: safeInteger.positive(),
  }),
}).strict().superRefine((event, ctx) => {
  validateEvaluatorNullAuthorityV02(event, "run.terminal-sealed", ctx);
  if (event.payload.previous_fence_epoch >= Number.MAX_SAFE_INTEGER
    || event.payload.fence_epoch !== event.payload.previous_fence_epoch + 1) {
    ctx.addIssue({ code: "custom", path: ["payload", "fence_epoch"], message: "terminal seal fence must increment by exactly one without overflow" });
  }
});

const TaskExecutionTerminalPayloadCommonV02 = {
  action_id: MachineId,
  task_ref: HumanId,
  admission_ref: LedgerRefV02,
  result_id: MachineId,
  result_path: RelativeRunPath,
  result_hash: Hash,
  output_bytes: safeInteger.nonnegative(),
  tool_calls: safeInteger.nonnegative(),
  token_count: safeInteger.nonnegative(),
  observed_cost: ObservedCostV02,
  action_output_bytes_after: safeInteger.nonnegative(),
  tool_calls_after: safeInteger.nonnegative(),
  token_count_after: safeInteger.nonnegative(),
} satisfies z.ZodRawShape;

export const TaskExecutionCompletedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("task.execution-completed"),
  payload: strictObject(TaskExecutionTerminalPayloadCommonV02),
}).strict().superRefine((event, ctx) => {
  if (event.source !== "adapter") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "task.execution-completed must use source 'adapter'" });
  }
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "task.execution-completed must have null authority_ref" });
  }
});
export type TaskExecutionCompletedEventV02Value = z.infer<typeof TaskExecutionCompletedEventV02>;

export const TaskExecutionFailedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("task.execution-failed"),
  payload: strictObject({
    ...TaskExecutionTerminalPayloadCommonV02,
    failure_class: RetryClassV02,
    failure_ordinal: safeInteger.positive(),
    failure_clock_ref: LedgerRefV02,
    retry_safety_evidence_refs: CanonicalLedgerRefsV02,
  }),
}).strict().superRefine((event, ctx) => {
  if (event.source !== "adapter") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "task.execution-failed must use source 'adapter'" });
  }
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "task.execution-failed must have null authority_ref" });
  }
});
export type TaskExecutionFailedEventV02Value = z.infer<typeof TaskExecutionFailedEventV02>;

export const TaskActionOutcomeUnknownEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("task.action-outcome-unknown"),
  payload: strictObject({
    action_id: MachineId,
    task_ref: HumanId,
    admission_ref: LedgerRefV02,
    detection_reason: z.enum([
      "process-status-unavailable",
      "dispatch-ack-ambiguous",
      "adapter-stream-lost-after-start",
    ]),
    observation_ref: LedgerRefV02,
    evidence_refs: CanonicalLedgerRefsV02,
  }),
}).strict().superRefine((event, ctx) => {
  if (event.source !== "adapter") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "task.action-outcome-unknown must use source 'adapter'" });
  }
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "task.action-outcome-unknown must have null authority_ref" });
  }
});
export type TaskActionOutcomeUnknownEventV02Value = z.infer<typeof TaskActionOutcomeUnknownEventV02>;

export const TaskActionOutcomeReconciledEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("task.action-outcome-reconciled"),
  payload: strictObject({
    action_id: MachineId,
    task_ref: HumanId,
    admission_ref: LedgerRefV02,
    process_cannot_continue_ref: LedgerRefV02,
    reconciliation_status: z.literal("outcome-remains-unknown"),
    reconciliation_evidence_refs: CanonicalLedgerRefsV02,
  }),
}).strict().superRefine((event, ctx) => {
  if (event.source !== "integrity") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "task.action-outcome-reconciled must use source 'integrity'" });
  }
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "task.action-outcome-reconciled must have null authority_ref" });
  }
});
export type TaskActionOutcomeReconciledEventV02Value = z.infer<typeof TaskActionOutcomeReconciledEventV02>;

export const LoopAttemptCompletedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("loop.attempt-completed"),
  payload: strictObject({
    attempt_ordinal: safeInteger.positive(),
    previous_attempt_event_ref: LedgerRefV02.nullable(),
    prefix_sequence: safeInteger.positive(),
    prefix_head_hash: Hash,
    work_action_refs: CanonicalLedgerRefsV02,
    progress_observation_refs: CanonicalLedgerRefsV02,
  }),
}).strict().superRefine((event, ctx) => {
  if (event.source !== "kernel") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "loop.attempt-completed must use source 'kernel'" });
  }
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "loop.attempt-completed must have null authority_ref" });
  }
});
export type LoopAttemptCompletedEventV02Value = z.infer<typeof LoopAttemptCompletedEventV02>;

export const ArtifactRecordedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("artifact.recorded"),
  payload: strictObject({
    artifact_ref: HumanId,
    producer_task_ref: HumanId,
    producer_action_id: MachineId,
    write_admission_ref: LedgerRefV02,
    artifact_record_path: RelativeRunPath,
    artifact_record_hash: Hash,
    artifact_path: RelativeRunPath,
    content_hash: Hash,
    size_bytes: safeInteger.nonnegative(),
    media_type: NonBlankString,
  }),
}).strict().superRefine((event, ctx) => {
  if (event.source !== "kernel") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "artifact.recorded must use source 'kernel'" });
  }
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "artifact.recorded must have null authority_ref" });
  }
});
export type ArtifactRecordedEventV02Value = z.infer<typeof ArtifactRecordedEventV02>;

const RedactionDerivativeRecordedPayloadCommonV02 = {
  original_record_path: RelativeRunPath,
  original_record_hash: Hash,
  original_content_path: RelativeRunPath,
  original_content_hash: Hash,
  original_content_size_bytes: safeInteger.nonnegative(),
  original_media_type: NonBlankString,
  derivative_ref: MachineId,
  derivative_record_path: RelativeRunPath,
  derivative_record_hash: Hash,
  derivative_content_path: RelativeRunPath,
  derivative_content_hash: Hash,
  derivative_size_bytes: safeInteger.nonnegative(),
  derivative_media_type: NonBlankString,
  policy_version: NonBlankString,
  review_evidence_refs: ReviewEvidenceRefsV02,
  created_at: IsoTimestamp,
} satisfies z.ZodRawShape;

export const RecordRedactionDerivativeRecordedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("record.redaction-derivative-recorded"),
  payload: z.discriminatedUnion("subject_kind", [
    strictObject({ ...ArtifactEvidenceSubjectV02.shape, ...RedactionDerivativeRecordedPayloadCommonV02 }),
    strictObject({ ...EvidenceSubjectV02.shape, ...RedactionDerivativeRecordedPayloadCommonV02 }),
  ]),
}).strict().superRefine((event, ctx) => {
  if (event.source !== "kernel") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "record.redaction-derivative-recorded must use source 'kernel'" });
  }
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "record.redaction-derivative-recorded must have null authority_ref" });
  }
});
export type RecordRedactionDerivativeRecordedEventV02Value = z.infer<typeof RecordRedactionDerivativeRecordedEventV02>;

export const TaskProgressFactRecordedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("task.progress-fact-recorded"),
  payload: strictObject({
    action_id: MachineId,
    task_ref: HumanId,
    adapter_invocation_id: MachineId,
    result_event_ref: LedgerRefV02,
    facts: TaskProgressFactsV02,
  }),
}).strict().superRefine((event, ctx) => {
  if (event.source !== "adapter") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "task.progress-fact-recorded must use source 'adapter'" });
  }
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "task.progress-fact-recorded must have null authority_ref" });
  }
  if (event.payload.result_event_ref.ledger_sequence >= event.sequence) {
    ctx.addIssue({ code: "custom", path: ["payload", "result_event_ref"], message: "result_event_ref must point to an earlier ledger sequence" });
  }
});

export const TaskProgressObservedEventV02 = RuntimeEventEnvelopeV02.extend({
  event_type: z.literal("task.progress-observed"),
  payload: strictObject({
    observation_ref: HumanId,
    task_ref: HumanId.nullable(),
    pending_attempt_ordinal: safeInteger.positive(),
    sample: ProgressSampleV02,
  }),
}).strict().superRefine((event, ctx) => {
  if (event.source !== "evaluator") {
    ctx.addIssue({ code: "custom", path: ["source"], message: "task.progress-observed must use source 'evaluator'" });
  }
  if (event.authority_ref !== null) {
    ctx.addIssue({ code: "custom", path: ["authority_ref"], message: "task.progress-observed must have null authority_ref" });
  }
  const sample = event.payload.sample;
  if (sample.status === "source-present") {
    const sourceSequence = "record_kind" in sample.sample_ref
      ? sample.sample_ref.record_event_ref.ledger_sequence
      : sample.sample_ref.ledger_sequence;
    if (sourceSequence >= event.sequence) {
      ctx.addIssue({ code: "custom", path: ["payload", "sample", "sample_ref"], message: "progress sample refs must point to an earlier ledger sequence" });
    }
  }
  if (sample.status === "source-present" && "ledger_sequence" in sample.sample_ref && sample.sample_hash !== sample.sample_ref.event_hash) {
    ctx.addIssue({ code: "custom", path: ["payload", "sample", "sample_hash"], message: "ledger sample_hash must equal the referenced event hash" });
  }
});
export type TaskProgressObservedEventV02Value = z.infer<typeof TaskProgressObservedEventV02>;

export type ProgressComparisonV02 =
  | "unavailable"
  | "baseline"
  | "unparseable"
  | "improved"
  | "unchanged"
  | "regressed";

export const ProgressObservationEvaluationV02 = strictObject({
  ref: HumanId,
  completed_loop_attempts: safeInteger.nonnegative(),
  parseable_sample_count: safeInteger.nonnegative(),
  baseline_ref: LedgerRefV02.nullable(),
  latest_ref: LedgerRefV02.nullable(),
  comparison: z.enum(["unavailable", "baseline", "unparseable", "improved", "unchanged", "regressed"]),
  target_reached: z.boolean(),
  stalled: z.boolean(),
});
export type ProgressObservationEvaluationV02Value = z.infer<typeof ProgressObservationEvaluationV02>;

export const ProgressEvaluationV02 = strictObject({
  schema_version: z.literal("0.2"),
  run_id: MachineId,
  plan_hash: Hash,
  ledger_sequence: safeInteger.nonnegative(),
  ledger_head_hash: Hash,
  observations: z.array(ProgressObservationEvaluationV02),
});
declare const validatedRuntimeProjectionInputBrand: unique symbol;
declare const progressEvaluationBrand: unique symbol;
export type ProgressEvaluationV02Value = z.infer<typeof ProgressEvaluationV02> & { readonly [progressEvaluationBrand]: true };

export const TerminalSnapshotInvalidReasonsV02 = [
  "PLAN_OR_LEDGER_LINEAGE_INVALID",
  "SNAPSHOT_COVERAGE_OR_ORDER_INVALID",
  "APPLICABILITY_OR_DUE_INVALID",
  "LIMIT_OBSERVATION_INVALID",
  "TASK_EFFECT_OR_FAILURE_INVALID",
  "ACTION_ADMISSION_OR_QUIESCENCE_INVALID",
  "TERMINAL_FREEZE_INVALID",
  "ACTIVATION_INVALID",
  "COMPENSATION_REQUEST_INVALID",
  "CANDIDATE_ESCALATION_INVALID",
  "PHASE_OR_PENDING_TERMINAL_INVALID",
  "COMPENSATION_REF_SET_INVALID",
  "COMPENSATION_SETTLEMENT_INVALID",
  "ACTIVE_WORKERS_AT_PHASE_ENTRY",
  "CONTROL_PLANE_BUDGET_INVALID",
  "TERMINAL_SEAL_OR_FENCE_INVALID",
  "POST_SEAL_ACTION",
] as const;
export type TerminalSnapshotInvalidReasonV02 = (typeof TerminalSnapshotInvalidReasonsV02)[number];

const SettlementEvidenceRefV02 = LedgerRefV02;
const NonEmptySettlementEvidenceRefsV02 = z.tuple([SettlementEvidenceRefV02]).rest(SettlementEvidenceRefV02);

const TerminalSealObservationV02 = strictObject({
  ledger_sequence: safeInteger.positive(),
  outcome: TerminalStateNameV02,
  fence_epoch: safeInteger.positive(),
  pre_seal_ledger_sequence: safeInteger.nonnegative(),
  pre_seal_ledger_head_hash: Hash,
  pre_seal_snapshot_hash: Hash,
  event_hash: Hash,
});

const TerminalFreezeObservationV02 = strictObject({
  revision: safeInteger.positive(),
  candidate: TerminalStateNameV02,
  ledger_sequence: safeInteger.positive(),
  event_hash: Hash,
});

const CompensationRequestObservationV02 = strictObject({
  revision: safeInteger.positive(),
  pending_terminal: RecoveryTerminalCandidateV02,
  activation_reason: CompensationActivationReasonV02,
  compensation_refs: CanonicalHumanIdsV02,
  ledger_sequence: safeInteger.positive(),
  event_hash: Hash,
});

const InFlightActionObservationV02 = strictObject({
  action_id: MachineId,
  task_ref: HumanId,
  lease_id: MachineId,
  admission_sequence: safeInteger.positive(),
  state: z.enum(["admitted", "started", "completed", "failed", "outcome-unknown", "outcome-reconciled"]),
  latest_state_event_ref: SettlementEvidenceRefV02,
});

const CompensationSettlementObservationV02 = z.discriminatedUnion("status", [
  strictObject({
    status: z.literal("pending"),
    unable_reason: z.null(),
    evidence_refs: z.tuple([]),
    transition_sequence: z.null(),
    transition_event_hash: z.null(),
  }),
  strictObject({
    status: z.enum(["compensated", "compensation-failed"]),
    unable_reason: z.null(),
    evidence_refs: NonEmptySettlementEvidenceRefsV02,
    transition_sequence: safeInteger.positive(),
    transition_event_hash: Hash,
  }),
  strictObject({
    status: z.literal("unable"),
    unable_reason: CompensationUnableReasonV02,
    evidence_refs: NonEmptySettlementEvidenceRefsV02,
    transition_sequence: safeInteger.positive(),
    transition_event_hash: Hash,
  }),
]);

const LimitObservationV02 = strictObject({
  ref: RuntimeLimitRefV02,
  consumed: safeInteger.nonnegative(),
  next_requested: safeInteger.nonnegative().nullable(),
  status: z.enum(["available", "at-ceiling", "would-exceed", "exceeded", "capture-gap"]),
  evidence_ref: SettlementEvidenceRefV02,
});

const EffectObservationV02 = z.discriminatedUnion("outcome", [
  strictObject({
    action_id: z.null(),
    task_ref: HumanId,
    effect_ref: HumanId,
    outcome: z.literal("not-started"),
    outcome_event_ref: z.null(),
  }),
  strictObject({
    action_id: MachineId,
    task_ref: HumanId,
    effect_ref: HumanId,
    outcome: z.enum(["not-committed", "committed", "unknown"]),
    outcome_event_ref: SettlementEvidenceRefV02,
  }),
]);

const PolicyBlockObservationV02 = strictObject({
  task_ref: HumanId,
  phase: z.enum(["work", "compensation"]),
  compensation_ref: HumanId.nullable(),
  action_proposal_id: MachineId,
  policy_action_kind: PolicyActionKindV1,
  decision: z.enum(["deny", "escalate", "abort", "hold"]),
  decision_disposition: z.enum([
    "proposal-final",
    "human-exception-required",
    "abort-run",
    "redecide-after-prefix-change",
    "non-resumable",
  ]),
  active: z.boolean(),
  decision_event_ref: SettlementEvidenceRefV02,
  evidence_refs: z.array(SettlementEvidenceRefV02),
});

const TerminalObservationSnapshotStructureV02 = strictObject({
  schema_version: z.literal("0.2"),
  run_id: MachineId,
  plan_hash: Hash,
  ledger_sequence: safeInteger.nonnegative(),
  ledger_head_hash: Hash,
  current_fence_epoch: safeInteger.nonnegative(),
  phase: z.enum(["work", "compensation"]),
  pending_terminal: RecoveryTerminalCandidateV02.nullable(),
  pending_terminal_event_ref: SettlementEvidenceRefV02.nullable(),
  terminal_freeze: TerminalFreezeObservationV02.nullable(),
  compensation_request: CompensationRequestObservationV02.nullable(),
  terminal_seal: TerminalSealObservationV02.nullable(),
  control_plane_output: strictObject({
    consumed_bytes: safeInteger.nonnegative(),
    reserved_bytes: safeInteger.nonnegative(),
    required_remaining_bytes: safeInteger.nonnegative(),
  }),
  gates: z.array(strictObject({
    ref: HumanId,
    applicable: z.boolean(),
    due: z.boolean(),
    status: z.enum(["pass", "hold", "fail", "waived-valid", "waived-invalid", "missing"]),
    required_event_ref: SettlementEvidenceRefV02.nullable(),
    result_event_ref: SettlementEvidenceRefV02.nullable(),
    condition_evidence_refs: z.array(SettlementEvidenceRefV02),
    waiver_active_at_use: z.boolean().nullable(),
    waiver_use_event_refs: z.array(SettlementEvidenceRefV02),
  })),
  evaluations: z.array(strictObject({
    ref: HumanId,
    applicable: z.boolean(),
    due: z.boolean(),
    status: z.enum(["pass", "hold", "fail", "skipped", "missing"]),
    required_event_ref: SettlementEvidenceRefV02.nullable(),
    result_event_ref: SettlementEvidenceRefV02.nullable(),
    condition_evidence_refs: z.array(SettlementEvidenceRefV02),
  })),
  progress: z.array(strictObject({
    ref: HumanId,
    target_reached: z.boolean(),
    stalled: z.boolean(),
    condition_evidence_refs: z.array(SettlementEvidenceRefV02),
  })),
  limits: z.array(LimitObservationV02),
  tasks: z.array(strictObject({
    ref: HumanId,
    status: z.enum(["pending", "running", "completed", "blocked", "failed"]),
    terminal_event_ref: SettlementEvidenceRefV02.nullable(),
    condition_evidence_refs: z.array(SettlementEvidenceRefV02),
  })),
  effects: z.array(EffectObservationV02),
  compensations: z.array(strictObject({
    ref: HumanId,
    activation_requested: z.boolean(),
    applicable: z.boolean(),
    settlement: CompensationSettlementObservationV02,
    decision_evidence_refs: z.array(SettlementEvidenceRefV02),
  })),
  active_failures: z.array(strictObject({
    task_ref: HumanId,
    failure_class: RetryClassV02,
    task_execution_count: safeInteger.nonnegative(),
    failure_ordinal: safeInteger.positive(),
    retry_disposition: z.enum(["waiting", "ready", "ineligible"]),
    failure_event_ref: SettlementEvidenceRefV02,
    failure_clock_ref: SettlementEvidenceRefV02,
    retry_clock_ref: SettlementEvidenceRefV02.nullable(),
  })),
  policy_blocks: z.array(PolicyBlockObservationV02),
  abort_requested: z.boolean(),
  abort_event_ref: SettlementEvidenceRefV02.nullable(),
  in_flight_actions: z.array(InFlightActionObservationV02),
  active_workers: safeInteger.nonnegative(),
});

declare const terminalObservationSnapshotBrand: unique symbol;
export type TerminalObservationSnapshotV02 = z.infer<typeof TerminalObservationSnapshotStructureV02> & {
  readonly [terminalObservationSnapshotBrand]: true;
};
export type TerminalObservationHashProjectionV02 = Readonly<{
  purpose: "pre-seal-terminal-observation-snapshot-v02";
}> & Omit<TerminalObservationSnapshotV02, typeof terminalObservationSnapshotBrand | "terminal_seal"> & {
  terminal_seal: null;
};

const CompensationSettlementDecisionV02 = z.discriminatedUnion("status", [
  strictObject({
    ref: HumanId,
    status: z.enum(["compensated", "compensation-failed"]),
    unable_reason: z.null(),
    evidence_refs: NonEmptySettlementEvidenceRefsV02,
  }),
  strictObject({
    ref: HumanId,
    status: z.literal("unable"),
    unable_reason: CompensationUnableReasonV02,
    evidence_refs: NonEmptySettlementEvidenceRefsV02,
  }),
]);

export const TerminalEvaluationResultV02 = z.discriminatedUnion("decision", [
  strictObject({
    decision: z.literal("continue"),
    continuation: z.enum(["work-open", "terminal-quiescence", "compensation-open"]),
  }),
  strictObject({
    decision: z.literal("freeze-work"),
    candidate: TerminalStateNameV02,
    freeze_revision: z.literal(1),
    candidate_evidence_refs: NonEmptySettlementEvidenceRefsV02,
    fence_epoch: safeInteger.nonnegative(),
  }),
  strictObject({
    decision: z.literal("revise-terminal-freeze"),
    previous_candidate: TerminalStateNameV02,
    candidate: TerminalStateNameV02,
    freeze_revision: safeInteger.min(2),
    previous_freeze_event_hash: Hash,
    candidate_evidence_refs: NonEmptySettlementEvidenceRefsV02,
  }),
  strictObject({
    decision: z.literal("request-compensation"),
    request_revision: z.literal(1),
    pending_terminal: RecoveryTerminalCandidateV02,
    activation_reason: CompensationActivationReasonV02,
    compensation_refs: CanonicalHumanIdsV02,
    effect_evidence_refs: NonEmptySettlementEvidenceRefsV02,
    freeze_event_hash: Hash,
  }),
  strictObject({
    decision: z.literal("revise-compensation-request"),
    request_revision: safeInteger.min(2),
    previous_pending_terminal: RecoveryTerminalCandidateV02,
    pending_terminal: RecoveryTerminalCandidateV02,
    activation_reason: CompensationActivationReasonV02,
    compensation_refs: CanonicalHumanIdsV02,
    added_compensation_refs: CanonicalHumanIdsV02,
    previous_request_event_hash: Hash,
    effect_evidence_refs: NonEmptySettlementEvidenceRefsV02,
    freeze_event_hash: Hash,
  }),
  strictObject({
    decision: z.literal("enter-compensation"),
    request_revision: safeInteger.positive(),
    request_event_hash: Hash,
    pending_terminal: RecoveryTerminalCandidateV02,
    compensation_refs: CanonicalHumanIdsV02,
    freeze_event_hash: Hash,
  }),
  strictObject({
    decision: z.literal("escalate-compensation"),
    previous_pending_terminal: RecoveryTerminalCandidateV02,
    pending_terminal: RecoveryTerminalCandidateV02,
    activation_reason: CompensationActivationReasonV02,
    compensation_refs: CanonicalHumanIdsV02,
    previous_candidate_event_hash: Hash,
    candidate_evidence_refs: NonEmptySettlementEvidenceRefsV02,
  }),
  strictObject({
    decision: z.literal("settle-compensation"),
    settlement: CompensationSettlementDecisionV02,
  }),
  strictObject({
    decision: z.literal("seal"),
    outcome: TerminalStateNameV02,
    expected_ledger_sequence: safeInteger.nonnegative(),
    expected_ledger_head_hash: Hash,
    pre_seal_snapshot_hash: Hash,
    current_fence_epoch: safeInteger.nonnegative(),
    next_fence_epoch: safeInteger.positive(),
  }),
  strictObject({
    decision: z.literal("already-sealed"),
    outcome: TerminalStateNameV02,
    seal_sequence: safeInteger.positive(),
    fence_epoch: safeInteger.positive(),
    pre_seal_snapshot_hash: Hash,
    seal_event_hash: Hash,
  }),
]);
export type TerminalEvaluationResultV02Value = z.infer<typeof TerminalEvaluationResultV02>;

declare const capturedAuthorityTrustContextBrandV02: unique symbol;
export type CapturedAuthorityTrustContextV02 = Readonly<{
  [capturedAuthorityTrustContextBrandV02]: true;
}>;

export type RuntimeProjectionInputV02 = Readonly<{
  resolved_run_plan_bytes: Uint8Array;
  authority_trust_context: CapturedAuthorityTrustContextV02;
  primary_ledger_bytes: Uint8Array;
  run_manifest_bytes: Uint8Array;
  artifact_manifest_bytes: Uint8Array;
  record_bytes_by_path: ReadonlyMap<string, Uint8Array>;
  control_projection_bytes_by_path: ReadonlyMap<string, Uint8Array>;
  file_metadata_by_path: ReadonlyMap<string, unknown>;
}>;

export type RuntimeProjectionInputAdmissionErrorV02 =
  | "RUNTIME_INPUT_BYTE_VIEW_INVALID"
  | "RUNTIME_INPUT_RESOURCE_LIMIT";

export type RuntimeProjectionErrorV02 =
  | TerminalSnapshotInvalidReasonV02
  | RuntimeProjectionInputAdmissionErrorV02
  | "LEDGER_SYNTAX_INVALID"
  | "RESOLVED_RUN_PLAN_BYTES_INVALID"
  | "RESOLVED_RUN_PLAN_SCHEMA_INVALID"
  | "LEDGER_HASH_CHAIN_INVALID"
  | "RUNTIME_RECORD_MISSING"
  | "RUNTIME_RECORD_HASH_INVALID"
  | "RUNTIME_RECORD_SCHEMA_INVALID"
  | "AUTHORITY_TRUST_INVALID"
  | "RUNTIME_SCHEMA_INVENTORY_INVALID";

/** Package-private projection used by the shared pure progress derivation. */
export type ProgressEvaluationInputV02 = Readonly<{
  plan: ResolvedRunPlanV02Value;
  run_id: string;
  plan_hash: string;
  ledger_sequence: number;
  ledger_head_hash: string;
  completed_loop_attempts: number;
  observations: readonly TaskProgressObservedEventV02Value[];
}>;

export type ValidatedRuntimeProjectionInputV02 = ProgressEvaluationInputV02 & Readonly<{
  events: readonly RuntimeEventV02Value[];
  readonly [validatedRuntimeProjectionInputBrand]: true;
}>;

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
  event_id: MachineIdV01,
  run_id: MachineIdV01,
  sequence: z.number().int().min(1),
  timestamp: IsoTimestampV01,
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
  run_id: MachineIdV01,
  loop_family: HumanIdV01,
  loopeix_version: LoopVersion,
  run_state: RunState,
  created_at: IsoTimestampV01,
  updated_at: IsoTimestampV01,
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
  created_at: IsoTimestampV01,
  media_type: z.string(),
  size_bytes: z.number().int().min(0),
  hash: Hash,
  retention_class: RetentionClass,
  expires_at: IsoTimestampV01.nullable(),
  redaction: RedactionState,
  quarantined: z.boolean(),
  exportable: z.boolean(),
  raw_hash: Hash.nullable(),
  redacted_hash: Hash.nullable(),
  evidence_ids: z.array(z.string()),
});

export const ArtifactManifest = z.object({
  schema_version: SchemaVersion,
  run_id: MachineIdV01,
  updated_at: IsoTimestampV01,
  artifacts: z.array(ArtifactRecord),
});

export const RuntimeEventTypesV02 = [
  "run.initialized",
  "run.clock-observed",
  "run.fence-advanced",
  "control.abort-requested",
  "gate.result-required",
  "gate.result-recorded",
  "evaluation.result-required",
  "evaluation.result-recorded",
  "authority.human-authorization-recorded",
  "authority.envelope-recorded",
  "approval.recommendation-recorded",
  "policy.decision-recorded",
  "authority.waiver-recorded",
  "authority.grant-revoked",
  "evidence.recorded",
  "observation.manual-recorded",
  "claim.recorded",
  "finding.recorded",
  "waiver.recorded",
  "lease.issued",
  "task.action-admitted",
  "tool.call-admitted",
  "artifact.write-admitted",
  "limit.admission-blocked",
  "task.execution-started",
  "task.execution-completed",
  "task.progress-fact-recorded",
  "task.execution-failed",
  "task.action-outcome-unknown",
  "task.action-outcome-reconciled",
  "artifact.recorded",
  "record.redaction-derivative-recorded",
  "record.custody-state-recorded",
  "record.export-decision-recorded",
  "effect.outcome",
  "task.action-settled",
  "loop.attempt-completed",
  "task.progress-observed",
  "run.terminal-freeze-entered",
  "run.terminal-freeze-revised",
  "run.compensation-requested",
  "run.compensation-request-revised",
  "run.compensation-phase-entered",
  "run.compensation-candidate-escalated",
  "compensation.settled",
  "run.terminal-sealed",
] as const;

export const RuntimeEventV02 = z.discriminatedUnion("event_type", [
  RunInitializedEventV02,
  RunClockObservedEventV02,
  RunFenceAdvancedEventV02,
  ControlAbortRequestedEventV02,
  GateResultRequiredEventV02,
  GateResultRecordedEventV02,
  EvaluationResultRequiredEventV02,
  EvaluationResultRecordedEventV02,
  AuthorityHumanAuthorizationRecordedEventV02,
  AuthorityEnvelopeRecordedEventV02,
  ApprovalRecommendationRecordedEventV02,
  PolicyDecisionRecordedEventV02,
  AuthorityWaiverRecordedEventV02,
  AuthorityGrantRevokedEventV02,
  EvidenceRecordedEventV02,
  ObservationManualRecordedEventV02,
  ClaimRecordedEventV02,
  FindingRecordedEventV02,
  WaiverRecordedEventV02,
  LeaseIssuedEventV02,
  TaskActionAdmittedEventV02,
  ToolCallAdmittedEventV02,
  ArtifactWriteAdmittedEventV02,
  LimitAdmissionBlockedEventV02,
  TaskExecutionStartedEventV02,
  TaskExecutionCompletedEventV02,
  TaskProgressFactRecordedEventV02,
  TaskExecutionFailedEventV02,
  TaskActionOutcomeUnknownEventV02,
  TaskActionOutcomeReconciledEventV02,
  ArtifactRecordedEventV02,
  RecordRedactionDerivativeRecordedEventV02,
  RecordCustodyStateRecordedEventV02,
  RecordExportDecisionRecordedEventV02,
  EffectOutcomeEventV02,
  TaskActionSettledEventV02,
  LoopAttemptCompletedEventV02,
  TaskProgressObservedEventV02,
  RunTerminalFreezeEnteredEventV02,
  RunTerminalFreezeRevisedEventV02,
  RunCompensationRequestedEventV02,
  RunCompensationRequestRevisedEventV02,
  RunCompensationPhaseEnteredEventV02,
  RunCompensationCandidateEscalatedEventV02,
  CompensationSettledEventV02,
  RunTerminalSealedEventV02,
]);
export type RuntimeEventV02Value = z.infer<typeof RuntimeEventV02>;
