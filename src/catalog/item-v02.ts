import { z } from "zod";
import { Hash, HumanId, IsoTimestamp, LoopVersion, RiskTierV1 } from "../schema/scalars.js";
import { WorkflowPatternType } from "../schema/loopeix.js";
import { hashCanonical } from "../hash.js";
import {
  ArtifactSpecV02,
  CompensationSpecV02,
  ControlPrerequisiteV02,
  EvaluationSpecV02,
  EvidenceRequirementSpecV02,
  GateApplicabilityV02,
  GoalSpecV02,
  LimitPolicyV02,
  NonBlankString,
  ProgressSpecV02,
  RecoveryPolicyV02,
  RequiredGateKindV02,
  RetryPolicyV02,
  SideEffectSpecV02,
  SpecialistRoleSpecV02,
  StopPolicyV02,
  TaskSpecV02,
  ToolGrantV02,
  TriggerSpecV02,
  UnicodeScalarString,
} from "../schema/loopeix-v02.js";

const UTF8 = new TextEncoder();

export function compareUtf8BytesV02(left: string, right: string): number {
  const leftBytes = UTF8.encode(left);
  const rightBytes = UTF8.encode(right);
  const length = Math.min(leftBytes.length, rightBytes.length);
  for (let index = 0; index < length; index += 1) {
    const difference = leftBytes[index]! - rightBytes[index]!;
    if (difference !== 0) return difference;
  }
  return leftBytes.length - rightBytes.length;
}

// The normative 15-slot inventory uses dotted project.* keys, so it takes
// precedence over the stale prose that describes BindingKeyV02 as HumanId.
const BindingKeyV02 = z.string().regex(/^[a-z0-9]+(?:[.-][a-z0-9]+)*$/);
const JsonPointerV02 = z.string().regex(/^\/(?:[^~/]|~[01])+(?:\/(?:[^~/]|~[01])+)*$/);

export const PROJECT_BINDING_SLOT_IDS_V02 = [
  "project.compensations",
  "project.engine",
  "project.evidence-requirements",
  "project.forbidden-context",
  "project.goal",
  "project.hard-limits",
  "project.objective",
  "project.progress",
  "project.recovery-policy",
  "project.required-context",
  "project.retry-policy",
  "project.side-effects",
  "project.stop-policy",
  "project.validation",
  "project.workspace-root",
] as const;

export type ProjectBindingSlotIdV02 = (typeof PROJECT_BINDING_SLOT_IDS_V02)[number];
const ProjectBindingSlotIdV02 = z.enum(PROJECT_BINDING_SLOT_IDS_V02);

export const S35_COMPILER_BUNDLE_ID_V02 = "compiler_s35_v02_1" as const;

export const PROJECT_BINDING_SLOT_CONTRACTS_V02 = {
  "project.compensations": { allowed_sources: ["operator"], destinations: [{ document: "authoring", pointer: "/compensations", merge: "replace" }] },
  "project.engine": { allowed_sources: ["operator"], destinations: [{ document: "plan-input", pointer: "/adapter_plan", merge: "replace" }] },
  "project.evidence-requirements": { allowed_sources: ["operator"], destinations: [{ document: "authoring", pointer: "/evidence_requirements", merge: "replace" }] },
  "project.forbidden-context": { allowed_sources: ["operator"], destinations: [{ document: "authoring", pointer: "/context_contract/forbidden", merge: "union-with-immutable-safety-constant" }] },
  "project.goal": { allowed_sources: ["operator"], destinations: [{ document: "authoring", pointer: "/goal", merge: "replace" }] },
  "project.hard-limits": { allowed_sources: ["operator"], destinations: [{ document: "authoring", pointer: "/limit_policy", merge: "replace" }] },
  "project.objective": { allowed_sources: ["operator"], destinations: [{ document: "approved-intake-brief", pointer: "/objective", merge: "replace" }, { document: "intake-record", pointer: "/objective", merge: "replace" }] },
  "project.progress": { allowed_sources: ["operator"], destinations: [{ document: "authoring", pointer: "/progress", merge: "replace" }] },
  "project.recovery-policy": { allowed_sources: ["operator"], destinations: [{ document: "authoring", pointer: "/recovery_policy", merge: "replace" }] },
  "project.required-context": { allowed_sources: ["operator", "workspace-observation"], destinations: [{ document: "authoring", pointer: "/context_contract/required", merge: "replace" }] },
  "project.retry-policy": { allowed_sources: ["operator"], destinations: [{ document: "authoring", pointer: "/retry_policy", merge: "replace" }] },
  "project.side-effects": { allowed_sources: ["operator"], destinations: [{ document: "authoring", pointer: "/side_effects", merge: "replace" }] },
  "project.stop-policy": { allowed_sources: ["operator"], destinations: [{ document: "authoring", pointer: "/stop_policy", merge: "replace" }] },
  "project.validation": { allowed_sources: ["operator"], destinations: [{ document: "authoring", pointer: "/evaluations", merge: "replace" }] },
  "project.workspace-root": { allowed_sources: ["workspace-observation"], destinations: [{ document: "plan-input", pointer: "/workspace_boundary", merge: "replace" }] },
} as const;

const BoundedProjectStringV02 = NonBlankString.refine((value) => UTF8.encode(value).byteLength <= 8_192, {
  message: "must be at most 8192 UTF-8 bytes",
});
const BoundedContextArrayV02 = z
  .array(BoundedProjectStringV02)
  .max(256)
  .superRefine((values, ctx) => {
    const seen = new Set<string>();
    for (const [index, value] of values.entries()) {
      if (seen.has(value)) ctx.addIssue({ code: "custom", path: [index], message: "context descriptors must be unique" });
      seen.add(value);
    }
  });
export const CanonicalWorkspaceRootV02 = UnicodeScalarString.refine(
  (value) =>
    value === "/" ||
    (/^\/(?:[^/\\\0]+\/)*[^/\\\0]+$/.test(value) &&
      !value.split("/").some((segment) => segment === "." || segment === "..")),
  { message: "must be a canonical absolute local root" },
);
const CanonicalRelativeScopeV02 = NonBlankString.refine(
  (value) =>
    !value.startsWith("/") &&
    !value.includes("\\") &&
    !value.includes("\0") &&
    !/^[A-Za-z]:/.test(value) &&
    !value.split("/").some((segment) => segment === "" || segment === "." || segment === ".."),
  { message: "must be a canonical relative scope" },
);

function requireUtf8SortedUnique(values: readonly string[], ctx: z.RefinementCtx, path: PropertyKey[]): void {
  for (let index = 1; index < values.length; index += 1) {
    if (compareUtf8BytesV02(values[index - 1]!, values[index]!) >= 0) {
      ctx.addIssue({ code: "custom", path: [...path, index], message: "must be UTF-8 sorted and unique" });
    }
  }
}

const CanonicalScopeSetV02 = z.array(CanonicalRelativeScopeV02).min(1).superRefine((values, ctx) => {
  requireUtf8SortedUnique(values, ctx, []);
});

export const AdapterPlanInputV02 = z.object({
  engine: z.enum(["codex", "claude"]),
  command: NonBlankString,
  permission_mode: z.enum(["workspace-write", "read-only", "danger-full-access"]),
  known_gaps: z.array(UnicodeScalarString),
}).strict();

export const WorkspaceBoundaryInputV02 = z.object({
  root: CanonicalWorkspaceRootV02,
  read: CanonicalScopeSetV02,
  write: CanonicalScopeSetV02,
}).strict();

export const PlanInputV02 = z.object({
  adapter_plan: AdapterPlanInputV02,
  workspace_boundary: WorkspaceBoundaryInputV02,
}).strict();
const COMPLETE_RETRY_CLASSES_V02 = [
  "transient-adapter",
  "transient-network",
  "contention",
  "verification-failed",
  "policy-hold",
  "invalid-input",
  "permanent-execution",
] as const;
const CompleteStopPolicyV02 = StopPolicyV02.superRefine((policy, ctx) => {
  const states = policy.terminal_states.map((terminalState) => terminalState.state);
  if (new Set(states).size !== 7) {
    ctx.addIssue({
      code: "custom",
      path: ["terminal_states"],
      message: "each terminal state is required exactly once",
    });
  }
});
const CompleteRetryPolicyV02 = RetryPolicyV02.superRefine((policy, ctx) => {
  const classesByTask = new Map<string, Set<string>>();
  for (const [index, rule] of policy.rules.entries()) {
    const classes = classesByTask.get(rule.task_ref) ?? new Set<string>();
    if (classes.has(rule.failure_class)) {
      ctx.addIssue({ code: "custom", path: ["rules", index, "failure_class"], message: "retry rules must be unique per task and failure class" });
    }
    classes.add(rule.failure_class);
    classesByTask.set(rule.task_ref, classes);
    if (
      !rule.retryable &&
      (rule.max_task_executions !== 1 ||
        rule.backoff !== "none" ||
        rule.base_delay_ms !== 0 ||
        rule.max_delay_ms !== 0)
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["rules", index],
        message: "non-retryable rules require one execution and zero backoff",
      });
    }
  }
  if (classesByTask.size === 0) {
    ctx.addIssue({ code: "custom", path: ["rules"], message: "retry policy must cover at least one task" });
  }
  for (const [taskRef, classes] of classesByTask) {
    if (COMPLETE_RETRY_CLASSES_V02.some((failureClass) => !classes.has(failureClass))) {
      ctx.addIssue({ code: "custom", path: ["rules"], message: `retry policy is incomplete for task '${taskRef}'` });
    }
  }
});

const PROJECT_BINDING_VALUE_SCHEMAS_V02: Record<ProjectBindingSlotIdV02, z.ZodType> = {
  "project.compensations": z.array(CompensationSpecV02),
  "project.engine": AdapterPlanInputV02,
  "project.evidence-requirements": z.array(EvidenceRequirementSpecV02).min(1),
  "project.forbidden-context": BoundedContextArrayV02,
  "project.goal": GoalSpecV02,
  "project.hard-limits": LimitPolicyV02,
  "project.objective": BoundedProjectStringV02,
  "project.progress": ProgressSpecV02,
  "project.recovery-policy": RecoveryPolicyV02,
  "project.required-context": BoundedContextArrayV02,
  "project.retry-policy": CompleteRetryPolicyV02,
  "project.side-effects": z.array(SideEffectSpecV02).min(1),
  "project.stop-policy": CompleteStopPolicyV02,
  "project.validation": z.array(EvaluationSpecV02).min(1),
  "project.workspace-root": WorkspaceBoundaryInputV02,
};

export const StrictJsonValueSchemaDescriptorV02 = z
  .object({
    slot_contract: ProjectBindingSlotIdV02,
    canonical_schema: z.record(z.string(), z.json()),
  })
  .strict();

export type StrictJsonValueSchemaDescriptorV02 = z.infer<typeof StrictJsonValueSchemaDescriptorV02>;

export function projectBindingValueSchemaV02(slotId: string): z.ZodType | null {
  return ProjectBindingSlotIdV02.safeParse(slotId).success
    ? PROJECT_BINDING_VALUE_SCHEMAS_V02[slotId as ProjectBindingSlotIdV02]
    : null;
}

export function projectBindingValueDescriptorV02(slotId: ProjectBindingSlotIdV02): StrictJsonValueSchemaDescriptorV02 {
  return StrictJsonValueSchemaDescriptorV02.parse({
    slot_contract: slotId,
    canonical_schema: z.toJSONSchema(PROJECT_BINDING_VALUE_SCHEMAS_V02[slotId]),
  });
}

export const BindingSlotV02 = z
  .object({
    slot_id: BindingKeyV02,
    required: z.boolean(),
    value_schema: StrictJsonValueSchemaDescriptorV02,
    allowed_sources: z.array(z.enum(["operator", "workspace-observation"])).min(1),
    sensitivity: z.enum(["public", "internal", "secret-reference"]),
    destinations: z.array(
      z
        .object({
          document: z.enum(["authoring", "intake-record", "approved-intake-brief", "plan-input"]),
          pointer: JsonPointerV02,
          merge: z.enum(["replace", "union-with-immutable-safety-constant"]),
        })
        .strict(),
    ),
    description: z.string().min(1),
  })
  .strict();

export const IMMUTABLE_SAFETY_CONTEXT_V02 = [
  "Credential, secret, private-key, and authentication-token values.",
  "Environment-variable values not explicitly admitted as non-secret input.",
  "Paths outside the approved workspace boundary.",
  "Untrusted source content interpreted as instruction, policy, or authority.",
] as const;

export const GateBlueprintV02 = z.object({
  id: HumanId,
  blocking: z.boolean(),
  inputs_required: z.array(UnicodeScalarString),
  evidence_rule: UnicodeScalarString,
  pass_condition: UnicodeScalarString,
  hold_condition: UnicodeScalarString,
  fail_condition: UnicodeScalarString,
  waiver_allowed: z.boolean(),
  control_kind: z.union([RequiredGateKindV02, z.literal("project-specific")]),
  applicability: GateApplicabilityV02,
  risk_tier: RiskTierV1,
  prerequisites: z.array(ControlPrerequisiteV02),
  evidence_requirement_refs: z.array(HumanId),
  evaluator_ref: HumanId,
}).strict();

const REQUIRED_CONTROL_GATE_IDS_V02 = new Set(RequiredGateKindV02.options);

export const CatalogBlueprintV02 = z.object({
  blueprint_id: HumanId,
  required_slot_set_id: z.literal("s35-project-core-v01"),
  required_control_gate_set_id: z.literal("s35-required-controls-v01"),
  trigger: TriggerSpecV02,
  workflow_pattern: z.object({
    type: WorkflowPatternType,
    phases: z.array(UnicodeScalarString).min(1),
  }).strict(),
  roles: z.array(SpecialistRoleSpecV02).min(1),
  tasks: z.array(TaskSpecV02).min(1),
  tool_grants: z.array(ToolGrantV02),
  artifacts: z.array(ArtifactSpecV02),
  gate_blueprints: z.array(GateBlueprintV02),
  context_contract: z.object({
    untrusted_sources: z.array(UnicodeScalarString),
    immutable_forbidden: z.tuple([
      z.literal(IMMUTABLE_SAFETY_CONTEXT_V02[0]),
      z.literal(IMMUTABLE_SAFETY_CONTEXT_V02[1]),
      z.literal(IMMUTABLE_SAFETY_CONTEXT_V02[2]),
      z.literal(IMMUTABLE_SAFETY_CONTEXT_V02[3]),
    ]),
  }).strict(),
  risk_controls: z.object({
    max_tier_without_approval: RiskTierV1,
    t5_allowed: z.literal(false),
  }).strict(),
  retro: z.object({ creates: NonBlankString }).strict(),
  limitation_records: z.array(NonBlankString).min(1),
  evaluation_refs: z.array(HumanId).min(1),
  evidence_requirement_refs: z.array(HumanId).min(1),
}).strict().superRefine((blueprint, ctx) => {
  const roleIds = blueprint.roles.map(({ id }) => id);
  const taskIds = blueprint.tasks.map(({ id }) => id);
  const artifactIds = blueprint.artifacts.map(({ id }) => id);
  const toolGrantIds = blueprint.tool_grants.map(({ id }) => id);
  const gateIds = blueprint.gate_blueprints.map(({ id }) => id);
  const uniqueIds = (ids: readonly string[], path: string): Set<string> => {
    const set = new Set(ids);
    if (set.size !== ids.length) ctx.addIssue({ code: "custom", path: [path], message: `${path} IDs must be unique` });
    return set;
  };
  const roles = uniqueIds(roleIds, "roles");
  const tasks = uniqueIds(taskIds, "tasks");
  const artifacts = uniqueIds(artifactIds, "artifacts");
  const toolGrants = uniqueIds(toolGrantIds, "tool_grants");
  const gates = uniqueIds(gateIds, "gate_blueprints");
  requireUtf8SortedUnique(blueprint.context_contract.untrusted_sources, ctx, ["context_contract", "untrusted_sources"]);
  requireUtf8SortedUnique(blueprint.evaluation_refs, ctx, ["evaluation_refs"]);
  requireUtf8SortedUnique(blueprint.evidence_requirement_refs, ctx, ["evidence_requirement_refs"]);

  for (const [index, role] of blueprint.roles.entries()) {
    for (const toolRef of role.allowed_tools) {
      if (!toolGrants.has(toolRef)) ctx.addIssue({ code: "custom", path: ["roles", index, "allowed_tools"], message: `unknown tool grant '${toolRef}'` });
    }
  }
  for (const [index, task] of blueprint.tasks.entries()) {
    if (!roles.has(task.role)) ctx.addIssue({ code: "custom", path: ["tasks", index, "role"], message: `unknown role '${task.role}'` });
    for (const artifactRef of task.artifacts) if (!artifacts.has(artifactRef)) ctx.addIssue({ code: "custom", path: ["tasks", index, "artifacts"], message: `unknown artifact '${artifactRef}'` });
    for (const taskRef of task.depends_on) if (!tasks.has(taskRef)) ctx.addIssue({ code: "custom", path: ["tasks", index, "depends_on"], message: `unknown task '${taskRef}'` });
    for (const gateRef of task.pre_task_gate_refs) if (!gates.has(gateRef) && !REQUIRED_CONTROL_GATE_IDS_V02.has(gateRef as never)) ctx.addIssue({ code: "custom", path: ["tasks", index, "pre_task_gate_refs"], message: `unknown gate '${gateRef}'` });
  }
  for (const [index, artifact] of blueprint.artifacts.entries()) {
    if (!tasks.has(artifact.producer_task)) ctx.addIssue({ code: "custom", path: ["artifacts", index, "producer_task"], message: `unknown producer task '${artifact.producer_task}'` });
  }
  const expectedEvaluations = [...new Set(["control-review", ...blueprint.gate_blueprints.map(({ evaluator_ref }) => evaluator_ref)])].sort(compareUtf8BytesV02);
  const expectedEvidence = [...new Set(["control-evidence", ...blueprint.gate_blueprints.flatMap(({ evidence_requirement_refs }) => evidence_requirement_refs)])].sort(compareUtf8BytesV02);
  if (hashCanonical(blueprint.evaluation_refs) !== hashCanonical(expectedEvaluations)) ctx.addIssue({ code: "custom", path: ["evaluation_refs"], message: "evaluation refs do not equal gate and required-control closure" });
  if (hashCanonical(blueprint.evidence_requirement_refs) !== hashCanonical(expectedEvidence)) ctx.addIssue({ code: "custom", path: ["evidence_requirement_refs"], message: "evidence refs do not equal gate and required-control closure" });
  for (const [gateIndex, gate] of blueprint.gate_blueprints.entries()) {
    for (const [prerequisiteIndex, prerequisite] of gate.prerequisites.entries()) {
      if (prerequisite.kind === "task-terminal" && !tasks.has(prerequisite.task_ref)) ctx.addIssue({ code: "custom", path: ["gate_blueprints", gateIndex, "prerequisites", prerequisiteIndex], message: `unknown task '${prerequisite.task_ref}'` });
      if (prerequisite.kind === "artifact-recorded" && !artifacts.has(prerequisite.artifact_ref)) ctx.addIssue({ code: "custom", path: ["gate_blueprints", gateIndex, "prerequisites", prerequisiteIndex], message: `unknown artifact '${prerequisite.artifact_ref}'` });
      if (prerequisite.kind === "evidence-recorded" && !expectedEvidence.includes(prerequisite.evidence_requirement_ref)) ctx.addIssue({ code: "custom", path: ["gate_blueprints", gateIndex, "prerequisites", prerequisiteIndex], message: `unknown evidence requirement '${prerequisite.evidence_requirement_ref}'` });
      if (prerequisite.kind === "evaluation-pass" && !expectedEvaluations.includes(prerequisite.evaluation_ref)) ctx.addIssue({ code: "custom", path: ["gate_blueprints", gateIndex, "prerequisites", prerequisiteIndex], message: `unknown evaluation '${prerequisite.evaluation_ref}'` });
      if (prerequisite.kind === "gate-pass" && !gates.has(prerequisite.gate_ref) && !REQUIRED_CONTROL_GATE_IDS_V02.has(prerequisite.gate_ref as never)) ctx.addIssue({ code: "custom", path: ["gate_blueprints", gateIndex, "prerequisites", prerequisiteIndex], message: `unknown gate '${prerequisite.gate_ref}'` });
    }
  }
});

const GeneratedDefaultV02 = z
  .object({
    document: z.enum(["authoring", "intake-record", "approved-intake-brief", "plan-input"]),
    pointer: JsonPointerV02,
    value: z.json(),
  })
  .strict();

export const CatalogEntryV02 = z
  .object({
    item_id: HumanId,
    loop_family: HumanId,
    version: LoopVersion,
    title: z.string().min(1),
    summary: z.string().min(1),
    intent_tags: z.array(HumanId).min(1),
    positive_signals: z.array(z.string().min(1)),
    negative_signals: z.array(z.string().min(1)),
    required_inputs: z.array(HumanId),
    optional_inputs: z.array(HumanId),
    workflow_pattern: WorkflowPatternType,
    max_risk_tier_without_approval: RiskTierV1,
    allowed_tool_grants: z.array(HumanId),
    required_gates: z.array(HumanId).min(1),
    required_evaluations: z.array(HumanId),
    primary_artifacts: z.array(HumanId),
    can_prove: z.array(z.string().min(1)).min(1),
    cannot_prove: z.array(z.string().min(1)).min(1),
    avoid_when: z.array(z.string().min(1)),
    blueprint_hash: Hash,
    binding_slots: z.array(BindingSlotV02),
    generated_defaults: z.array(GeneratedDefaultV02),
    compiler_bundle_id: z.literal(S35_COMPILER_BUNDLE_ID_V02),
    minimum_assurance_profile: HumanId,
    blueprint: CatalogBlueprintV02,
  })
  .strict()
  .superRefine((entry, ctx) => {
    if (entry.blueprint_hash !== hashCanonical(entry.blueprint)) {
      ctx.addIssue({ code: "custom", path: ["blueprint_hash"], message: "blueprint_hash does not match blueprint" });
    }
    if (entry.binding_slots.length !== PROJECT_BINDING_SLOT_IDS_V02.length) {
      ctx.addIssue({ code: "custom", path: ["binding_slots"], message: "binding slots must equal the exact S35 project inventory" });
    }
    for (const [slotIndex, slot] of entry.binding_slots.entries()) {
      const expectedSlotId = PROJECT_BINDING_SLOT_IDS_V02[slotIndex];
      if (slot.slot_id !== expectedSlotId) {
        ctx.addIssue({ code: "custom", path: ["binding_slots", slotIndex, "slot_id"], message: "binding slot is not at its exact canonical inventory position" });
      }
      const projectSchema = projectBindingValueSchemaV02(slot.slot_id);
      if (projectSchema !== null) {
        const expected = projectBindingValueDescriptorV02(slot.slot_id as ProjectBindingSlotIdV02);
        if (hashCanonical(slot.value_schema) !== hashCanonical(expected)) {
          ctx.addIssue({
            code: "custom",
            path: ["binding_slots", slotIndex, "value_schema"],
            message: "value_schema does not match its exact project slot contract",
          });
        }
      }
      if (expectedSlotId !== undefined) {
        const expectedContract = PROJECT_BINDING_SLOT_CONTRACTS_V02[expectedSlotId];
        if (!slot.required) ctx.addIssue({ code: "custom", path: ["binding_slots", slotIndex, "required"], message: "initial project slots must be required" });
        if (slot.sensitivity !== "internal") ctx.addIssue({ code: "custom", path: ["binding_slots", slotIndex, "sensitivity"], message: "initial project slots must be internal" });
        if (hashCanonical(slot.allowed_sources) !== hashCanonical(expectedContract.allowed_sources)) ctx.addIssue({ code: "custom", path: ["binding_slots", slotIndex, "allowed_sources"], message: "allowed sources do not match the exact project slot contract" });
        if (hashCanonical(slot.destinations) !== hashCanonical(expectedContract.destinations)) ctx.addIssue({ code: "custom", path: ["binding_slots", slotIndex, "destinations"], message: "destinations do not match the exact project slot contract" });
      }
    }
    for (let index = 1; index < entry.binding_slots.length; index += 1) {
      if (compareUtf8BytesV02(entry.binding_slots[index - 1]!.slot_id, entry.binding_slots[index]!.slot_id) >= 0) {
        ctx.addIssue({ code: "custom", path: ["binding_slots", index, "slot_id"], message: "binding slots must be sorted and unique" });
      }
    }
    for (const [slotIndex, slot] of entry.binding_slots.entries()) {
      for (let index = 1; index < slot.allowed_sources.length; index += 1) {
        if (compareUtf8BytesV02(slot.allowed_sources[index - 1]!, slot.allowed_sources[index]!) >= 0) {
          ctx.addIssue({ code: "custom", path: ["binding_slots", slotIndex, "allowed_sources", index], message: "allowed sources must be sorted and unique" });
        }
      }
      const destinationKeys = slot.destinations.map(({ document, pointer, merge }) => `${document}\0${pointer}\0${merge}`);
      for (let index = 1; index < destinationKeys.length; index += 1) {
        if (compareUtf8BytesV02(destinationKeys[index - 1]!, destinationKeys[index]!) >= 0) {
          ctx.addIssue({ code: "custom", path: ["binding_slots", slotIndex, "destinations", index], message: "destinations must be sorted and unique" });
        }
      }
    }
    const expectedGeneratedDefaults = [{
      document: "authoring",
      pointer: "/context_contract/forbidden",
      value: [...IMMUTABLE_SAFETY_CONTEXT_V02],
    }];
    if (hashCanonical(entry.generated_defaults) !== hashCanonical(expectedGeneratedDefaults)) {
      ctx.addIssue({ code: "custom", path: ["generated_defaults"], message: "generated defaults do not match the exact immutable safety owner" });
    }
  });

export const CatalogSnapshotV02 = z
  .object({
    schema_version: z.literal("0.2"),
    catalog_id: HumanId,
    catalog_version: LoopVersion,
    entries: z.array(CatalogEntryV02).min(1),
    created_at: IsoTimestamp,
    catalog_hash: Hash,
  })
  .strict()
  .superRefine((snapshot, ctx) => {
    const { catalog_hash: _catalogHash, ...hashable } = snapshot;
    if (snapshot.catalog_hash !== hashCanonical(hashable)) {
      ctx.addIssue({ code: "custom", path: ["catalog_hash"], message: "catalog_hash does not match snapshot" });
    }
    for (let index = 1; index < snapshot.entries.length; index += 1) {
      if (compareUtf8BytesV02(snapshot.entries[index - 1]!.item_id, snapshot.entries[index]!.item_id) >= 0) {
        ctx.addIssue({ code: "custom", path: ["entries", index, "item_id"], message: "entries must be sorted and unique" });
      }
    }
  });

export type BindingSlotV02 = z.infer<typeof BindingSlotV02>;
export type AdapterPlanInputV02 = z.infer<typeof AdapterPlanInputV02>;
export type WorkspaceBoundaryInputV02 = z.infer<typeof WorkspaceBoundaryInputV02>;
export type PlanInputV02 = z.infer<typeof PlanInputV02>;
export type GateBlueprintV02 = z.infer<typeof GateBlueprintV02>;
export type CatalogBlueprintV02 = z.infer<typeof CatalogBlueprintV02>;
export type CatalogEntryV02 = z.infer<typeof CatalogEntryV02>;
export type CatalogSnapshotV02 = z.infer<typeof CatalogSnapshotV02>;
