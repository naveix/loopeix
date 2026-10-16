import { z } from "zod";
import { ArtifactType, EvaluationType, WorkflowPatternType, type Issue } from "./loopeix.js";
import { Hash, LoopVersion, RiskTierV1 } from "./scalars.js";
import {
  HumanIdV02,
  IsoTimestampV02 as IsoTimestamp,
  MachineIdV02 as MachineId,
  NonBlankStringV02 as NonBlankString,
  UnicodeScalarStringV02 as UnicodeScalarString,
} from "./scalars-v02.js";

export {
  HumanIdV02,
  NonBlankStringV02 as NonBlankString,
  UnicodeScalarStringV02 as UnicodeScalarString,
} from "./scalars-v02.js";

const strictObject = <T extends z.ZodRawShape>(shape: T): z.ZodObject<T> => z.object(shape).strict();
const positiveInteger = z.number().int().positive();
const nonNegativeInteger = z.number().int().nonnegative();

export const InputSpecV02 = strictObject({
  id: HumanIdV02,
  description: UnicodeScalarString,
  required: z.boolean(),
});

export const SpecialistRoleSpecV02 = strictObject({
  id: HumanIdV02,
  owns: z.array(UnicodeScalarString).min(1),
  must_not: z.array(UnicodeScalarString),
  allowed_tools: z.array(HumanIdV02),
  handoff: UnicodeScalarString,
});

export const ToolGrantV02 = strictObject({
  id: HumanIdV02,
  tool: UnicodeScalarString,
  scope: UnicodeScalarString,
  risk_tier: RiskTierV1,
  requires_approval: z.boolean(),
});

const ArtifactPathV02 = UnicodeScalarString.refine(
  (value) => {
    if (!value.startsWith("artifacts/content/")) return false;
    const suffix = value.slice("artifacts/content/".length);
    return suffix.length > 0 && !suffix.includes("/") && !suffix.includes("\\") && suffix !== "." && suffix !== "..";
  },
  { message: "must be one direct file under artifacts/content/" },
);

export const ArtifactSpecV02 = strictObject({
  id: HumanIdV02,
  path: ArtifactPathV02,
  type: ArtifactType,
  required: z.boolean(),
  producer_task: HumanIdV02,
  acceptance_checks: z.array(UnicodeScalarString).min(1),
});

export const TriggerSpecV02 = strictObject({
  type: z.literal("operator-invoked"),
  entrypoint: z.enum(["compile", "run-plan", "run-start"]),
});

export const GoalSpecV02 = strictObject({
  statement: NonBlankString,
  success_criteria: z.array(strictObject({
    id: HumanIdV02,
    description: NonBlankString,
    evaluation_refs: z.array(HumanIdV02).min(1),
    required: z.literal(true),
  })).min(1),
});

export const TaskSpecV02 = strictObject({
  id: HumanIdV02,
  role: HumanIdV02,
  artifacts: z.array(HumanIdV02),
  depends_on: z.array(HumanIdV02),
  acceptance_checks: z.array(UnicodeScalarString).min(1),
  kind: z.enum(["work", "compensation"]),
  pre_task_gate_refs: z.array(HumanIdV02),
});

export const RequiredGateKindV02 = z.enum([
  "manifest-completeness",
  "risk-tier-consistency",
  "approval",
  "workspace-boundary",
  "context-and-source-freshness",
  "tool-grant-adherence",
  "evidence-integrity",
  "claim-support",
  "unresolved-findings",
  "secrets-privacy",
  "redaction-retention",
  "adapter-capability",
  "report-truthfulness",
  "ad-hoc-task-provenance",
  "no-t5",
  "intake-boundedness",
  "catalog-selection-evidence",
  "untrusted-instruction-provenance",
  "autonomy-escalation",
]);

export const GateApplicabilityV02 = z.discriminatedUnion("mode", [
  strictObject({ mode: z.literal("always") }),
  strictObject({ mode: z.literal("compensation"), compensation_ref: HumanIdV02 }),
]);

export const ControlPrerequisiteV02 = z.discriminatedUnion("kind", [
  strictObject({ kind: z.literal("run-initialized") }),
  strictObject({ kind: z.literal("task-terminal"), task_ref: HumanIdV02 }),
  strictObject({ kind: z.literal("artifact-recorded"), artifact_ref: HumanIdV02 }),
  strictObject({ kind: z.literal("evidence-recorded"), evidence_requirement_ref: HumanIdV02 }),
  strictObject({ kind: z.literal("gate-pass"), gate_ref: HumanIdV02 }),
  strictObject({ kind: z.literal("evaluation-pass"), evaluation_ref: HumanIdV02 }),
  strictObject({ kind: z.literal("compensation-phase-entered"), compensation_ref: HumanIdV02 }),
  strictObject({ kind: z.literal("compensation-action-terminal"), compensation_ref: HumanIdV02 }),
]);

export const EvaluatorBindingV02 = strictObject({
  role_ref: HumanIdV02,
  evaluator_identity_ref: MachineId,
  policy_digest: Hash,
  export_check_role: z.enum(["credential-scan", "privacy-review"]).nullable(),
});

export const GateSpecV02 = strictObject({
  id: HumanIdV02,
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
  prerequisites: z.array(ControlPrerequisiteV02).min(1),
  evidence_requirement_refs: z.array(HumanIdV02).min(1),
  evaluator_binding: EvaluatorBindingV02,
});

export const EvidenceKindV02 = z.enum([
  "command-capture",
  "filesystem-capture",
  "browser-capture",
  "source-citation",
  "human-authorization",
  "manual-observation",
]);

export const SourceAcquisitionPolicyV02 = strictObject({
  allowed_retrievers: z.array(strictObject({ identity: NonBlankString, version: NonBlankString })).min(1),
  allowed_methods: z.array(z.enum(["http", "browser", "repository", "manual-import"])).min(1),
  allowed_auth_classes: z.array(z.enum(["public", "authenticated"])).min(1),
  allowed_authenticated_scope_hashes: z.array(Hash),
  max_age_ms: positiveInteger,
});

export const EvidenceRequirementSpecV02 = strictObject({
  id: HumanIdV02,
  minimum_independent_roots: z.number().int().min(1).max(8),
  evidence_kinds: z.array(EvidenceKindV02).min(1),
  source_acquisition_policy: SourceAcquisitionPolicyV02.nullable(),
});

export const EvaluationApplicabilityV02 = GateApplicabilityV02;
export const EvaluationSpecV02 = strictObject({
  id: HumanIdV02,
  type: EvaluationType,
  required: z.boolean(),
  command: UnicodeScalarString.optional(),
  success_condition: NonBlankString,
  applicability: EvaluationApplicabilityV02,
  prerequisites: z.array(ControlPrerequisiteV02).min(1),
  evidence_requirement_refs: z.array(HumanIdV02).min(1),
  evaluator_binding: EvaluatorBindingV02,
});

const ProgressObservationV02 = strictObject({
  id: HumanIdV02,
  description: UnicodeScalarString,
  source: z.enum(["evaluation", "artifact", "gate", "ledger"]),
  source_ref: HumanIdV02,
  value_pointer: UnicodeScalarString,
  value_type: z.enum(["number", "string", "boolean"]),
  improves_when: z.union([
    strictObject({ operator: z.enum(["increases", "decreases"]) }),
    strictObject({ operator: z.literal("equals"), target: z.union([z.number().finite(), UnicodeScalarString, z.boolean()]) }),
  ]),
  target: z.union([
    strictObject({ operator: z.enum(["gte", "lte", "equals"]), value: z.union([z.number().finite(), UnicodeScalarString, z.boolean()]) }),
    z.null(),
  ]),
});

export const ProgressSpecV02 = strictObject({
  observations: z.array(ProgressObservationV02).min(1),
  stall_after_loop_attempts: positiveInteger,
});

export const RetryClassV02 = z.enum([
  "transient-adapter",
  "transient-network",
  "contention",
  "verification-failed",
  "policy-hold",
  "invalid-input",
  "permanent-execution",
]);

const StopConditionRefV02 = z.discriminatedUnion("source", [
  strictObject({ source: z.literal("success-criterion"), ref: HumanIdV02, outcome: z.literal("satisfied") }),
  strictObject({ source: z.literal("gate"), ref: HumanIdV02, outcome: z.enum(["satisfied", "satisfied-or-not-applicable", "hold", "fail"]) }),
  strictObject({ source: z.literal("evaluation"), ref: HumanIdV02, outcome: z.enum(["pass", "pass-or-not-applicable", "hold", "fail"]) }),
  strictObject({ source: z.literal("progress"), ref: HumanIdV02, outcome: z.enum(["target-reached", "stalled"]) }),
  strictObject({ source: z.literal("limit"), ref: z.enum(["max-loop-attempts", "max-elapsed-ms", "max-tool-calls", "max-output-bytes", "max-tokens", "max-cost"]), outcome: z.literal("reached") }),
  strictObject({ source: z.literal("task"), ref: HumanIdV02, outcome: z.enum(["completed", "completed-or-not-applicable"]) }),
  strictObject({ source: z.literal("dependency"), ref: HumanIdV02, outcome: z.literal("blocked") }),
  strictObject({ source: z.literal("failure"), task_ref: HumanIdV02, ref: RetryClassV02, outcome: z.literal("observed") }),
  strictObject({ source: z.literal("policy"), task_ref: HumanIdV02, ref: z.literal("policy-block"), outcome: z.literal("hold") }),
  strictObject({ source: z.literal("control"), ref: z.literal("abort-requested"), outcome: z.literal("present") }),
]);

const terminalState = <S extends string, M extends string, P extends number>(state: S, mode: M, priority: P) =>
  strictObject({ state: z.literal(state), condition_mode: z.literal(mode), conditions: z.array(StopConditionRefV02).min(1), priority: z.literal(priority) });

export const TerminalStateSpecV02 = z.discriminatedUnion("state", [
  terminalState("completed", "all", 100),
  terminalState("held", "any", 300),
  terminalState("blocked", "any", 200),
  terminalState("failed", "any", 600),
  terminalState("stalled", "any", 400),
  terminalState("exhausted", "any", 500),
  terminalState("aborted", "any", 700),
]);
export const StopPolicyV02 = strictObject({ terminal_states: z.array(TerminalStateSpecV02).length(7) });

export const LimitPolicyV02 = strictObject({
  max_loop_attempts: positiveInteger,
  max_elapsed_ms: positiveInteger,
  max_tool_calls: positiveInteger,
  max_workers: positiveInteger,
  max_output_bytes: positiveInteger,
  control_plane_output_reserve_bytes: positiveInteger,
  max_tokens: positiveInteger.nullable(),
  max_cost_minor_units: positiveInteger.nullable(),
  cost_currency: UnicodeScalarString.regex(/^[A-Z]{3}$/).nullable(),
});

export const RetryRuleV02 = strictObject({
  task_ref: HumanIdV02,
  failure_class: RetryClassV02,
  retryable: z.boolean(),
  max_task_executions: positiveInteger,
  backoff: z.enum(["none", "fixed", "exponential"]),
  base_delay_ms: nonNegativeInteger,
  max_delay_ms: nonNegativeInteger,
});
export const RetryPolicyV02 = strictObject({ rules: z.array(RetryRuleV02) });

const RecoveryReserveV02 = strictObject({
  max_elapsed_ms: nonNegativeInteger,
  max_tool_calls: nonNegativeInteger,
  max_output_bytes: nonNegativeInteger,
  max_tokens: nonNegativeInteger.nullable(),
  max_cost_minor_units: nonNegativeInteger.nullable(),
});
export const RecoveryPolicyV02 = strictObject({
  resume_from: z.literal("last-durable-boundary"),
  require_input_hash_match: z.literal(true),
  require_policy_hash_match: z.literal(true),
  on_unknown_outcome: z.literal("hold"),
  terminal_compensation: z.literal("before-terminal-seal"),
  activation_reasons: z.tuple([
    z.literal("terminal-failure"),
    z.literal("terminal-exhaustion"),
    z.literal("terminal-stall"),
    z.literal("abort-recovery"),
  ]),
  max_compensation_workers: z.literal(1),
  reserve: RecoveryReserveV02,
});

export const SafeStopBoundaryRefV02 = z.discriminatedUnion("kind", [
  strictObject({ kind: z.literal("before-task"), task_ref: HumanIdV02 }),
  strictObject({ kind: z.literal("after-gate"), gate_ref: HumanIdV02 }),
]);
export const TaskEffectSpecV02 = strictObject({
  effect_id: HumanIdV02,
  effect_class: z.enum(["none", "workspace-write", "external-read", "external-write", "destructive"]),
  description: UnicodeScalarString,
  inspectable: z.boolean(),
  reversible: z.boolean(),
  idempotency: z.enum(["not-required", "required", "unsupported"]),
  last_safe_stop: SafeStopBoundaryRefV02,
  compensation_ref: HumanIdV02.nullable(),
});
export const SideEffectSpecV02 = strictObject({ task_id: HumanIdV02, effects: z.array(TaskEffectSpecV02).min(1) });

export const CompensationPreconditionV02 = z.discriminatedUnion("source", [
  strictObject({ source: z.literal("effect"), task_ref: HumanIdV02, effect_ref: HumanIdV02, outcome: z.literal("committed") }),
  strictObject({ source: z.literal("gate"), ref: HumanIdV02, outcome: z.literal("satisfied") }),
  strictObject({ source: z.literal("evaluation"), ref: HumanIdV02, outcome: z.literal("pass") }),
]);
export const CompensationSpecV02 = strictObject({
  id: HumanIdV02,
  for_task: HumanIdV02,
  for_effect: HumanIdV02,
  action_task: HumanIdV02,
  preconditions: z.array(CompensationPreconditionV02).min(1),
  verification_refs: z.array(HumanIdV02).min(1),
  may_fail: z.literal(true),
});

export const LoopeixV02Shape = strictObject({
  schema_version: z.literal("0.2"),
  loop_family: HumanIdV02,
  version: LoopVersion,
  trigger: TriggerSpecV02,
  goal: GoalSpecV02,
  inputs: z.array(InputSpecV02),
  context_contract: strictObject({
    required: z.array(UnicodeScalarString),
    forbidden: z.array(UnicodeScalarString),
    untrusted_sources: z.array(UnicodeScalarString),
  }),
  workflow_pattern: strictObject({ type: WorkflowPatternType, phases: z.array(UnicodeScalarString).min(1) }),
  roles: z.array(SpecialistRoleSpecV02).min(1),
  tasks: z.array(TaskSpecV02).min(1),
  tool_grants: z.array(ToolGrantV02),
  artifacts: z.array(ArtifactSpecV02),
  gates: z.array(GateSpecV02).min(1),
  evaluations: z.array(EvaluationSpecV02),
  evidence_requirements: z.array(EvidenceRequirementSpecV02).min(1),
  risk_controls: strictObject({ max_tier_without_approval: RiskTierV1, t5_allowed: z.literal(false) }),
  progress: ProgressSpecV02,
  stop_policy: StopPolicyV02,
  limit_policy: LimitPolicyV02,
  retry_policy: RetryPolicyV02,
  recovery_policy: RecoveryPolicyV02,
  side_effects: z.array(SideEffectSpecV02),
  compensations: z.array(CompensationSpecV02),
  retro: strictObject({ creates: NonBlankString }),
});

export type LoopeixV02 = z.infer<typeof LoopeixV02Shape>;

function duplicateIds(values: readonly { id: string }[], path: string, issues: Issue[]): void {
  const seen = new Set<string>();
  for (const value of values) {
    if (seen.has(value.id)) issues.push({ path, message: `duplicate ${path} id: '${value.id}'` });
    seen.add(value.id);
  }
}

export function checkLoopeixV02Invariants(spec: LoopeixV02): Issue[] {
  const issues: Issue[] = [];
  duplicateIds(spec.inputs, "inputs", issues);
  duplicateIds(spec.roles, "roles", issues);
  duplicateIds(spec.tasks, "tasks", issues);
  duplicateIds(spec.tool_grants, "tool_grants", issues);
  duplicateIds(spec.artifacts, "artifacts", issues);
  duplicateIds(spec.gates, "gates", issues);
  duplicateIds(spec.evaluations, "evaluations", issues);
  duplicateIds(spec.evidence_requirements, "evidence_requirements", issues);
  duplicateIds(spec.progress.observations, "progress.observations", issues);
  duplicateIds(spec.compensations, "compensations", issues);

  const roleIds = new Set(spec.roles.map((value) => value.id));
  const taskIds = new Set(spec.tasks.map((value) => value.id));
  const workTaskIds = new Set(spec.tasks.filter((value) => value.kind === "work").map((value) => value.id));
  const artifactIds = new Set(spec.artifacts.map((value) => value.id));
  const gateById = new Map(spec.gates.map((value) => [value.id, value]));
  const evaluationById = new Map(spec.evaluations.map((value) => [value.id, value]));
  const evidenceIds = new Set(spec.evidence_requirements.map((value) => value.id));

  if (workTaskIds.size === 0) issues.push({ path: "tasks", message: "at least one work task is required" });
  spec.tasks.forEach((task, index) => {
    if (!roleIds.has(task.role)) issues.push({ path: `tasks[${index}].role`, message: `unknown role '${task.role}'` });
    if (new Set(task.pre_task_gate_refs).size !== task.pre_task_gate_refs.length) {
      issues.push({ path: `tasks[${index}].pre_task_gate_refs`, message: "gate references must be unique" });
    }
    if (task.kind === "compensation" && task.depends_on.length > 0) {
      issues.push({ path: `tasks[${index}].depends_on`, message: "compensation tasks cannot have dependencies" });
    }
    for (const dependency of task.depends_on) {
      if (!workTaskIds.has(dependency)) issues.push({ path: `tasks[${index}].depends_on`, message: `dependency '${dependency}' is not a work task` });
    }
    for (const artifact of task.artifacts) {
      if (!artifactIds.has(artifact)) issues.push({ path: `tasks[${index}].artifacts`, message: `unknown artifact '${artifact}'` });
    }
    for (const gateRef of task.pre_task_gate_refs) {
      const gate = gateById.get(gateRef);
      if (gate === undefined || !gate.blocking) issues.push({ path: `tasks[${index}].pre_task_gate_refs`, message: `gate '${gateRef}' must be blocking` });
      if (task.kind === "work" && gate?.applicability.mode !== "always") issues.push({ path: `tasks[${index}].pre_task_gate_refs`, message: `work task gate '${gateRef}' must always apply` });
    }
  });

  const workTaskById = new Map(
    spec.tasks.filter((task) => task.kind === "work").map((task) => [task.id, task]),
  );
  const visiting = new Set<string>();
  const visited = new Set<string>();
  const visitWorkTask = (taskId: string): boolean => {
    if (visiting.has(taskId)) return true;
    if (visited.has(taskId)) return false;
    const task = workTaskById.get(taskId);
    if (task === undefined) return false;
    visiting.add(taskId);
    for (const dependency of task.depends_on) {
      if (visitWorkTask(dependency)) return true;
    }
    visiting.delete(taskId);
    visited.add(taskId);
    return false;
  };
  for (const taskId of workTaskById.keys()) {
    if (visitWorkTask(taskId)) {
      issues.push({ path: "tasks", message: "work-task dependency graph contains a cycle" });
      break;
    }
  }

  const requiredGateCounts = new Map<string, number>();
  for (const gate of spec.gates) {
    if (gate.control_kind !== "project-specific") {
      requiredGateCounts.set(gate.control_kind, (requiredGateCounts.get(gate.control_kind) ?? 0) + 1);
      if (gate.applicability.mode !== "always") issues.push({ path: "gates", message: `required gate '${gate.control_kind}' must always apply` });
    }
    if (gate.evaluator_binding.export_check_role !== null) issues.push({ path: "gates", message: "gate export_check_role must be null" });
    for (const ref of gate.evidence_requirement_refs) if (!evidenceIds.has(ref)) issues.push({ path: "gates", message: `unknown evidence requirement '${ref}'` });
  }
  for (const kind of RequiredGateKindV02.options) {
    if (requiredGateCounts.get(kind) !== 1) issues.push({ path: "gates", message: `exactly one '${kind}' gate is required` });
  }
  if (!spec.gates.some((gate) => gate.blocking && gate.applicability.mode === "always")) {
    issues.push({ path: "gates", message: "at least one blocking always-applicable gate is required" });
  }

  for (const criterion of spec.goal.success_criteria) {
    for (const ref of criterion.evaluation_refs) {
      const evaluation = evaluationById.get(ref);
      if (evaluation === undefined || !evaluation.required || evaluation.applicability.mode !== "always") {
        issues.push({ path: "goal.success_criteria", message: `evaluation '${ref}' must be required and always applicable` });
      }
    }
  }
  spec.evaluations.forEach((evaluation, index) => {
    if (evaluation.type === "command" && (evaluation.command === undefined || evaluation.command.trim() === "")) {
      issues.push({ path: `evaluations[${index}].command`, message: "command evaluation requires a non-blank command" });
    }
    if (!roleIds.has(evaluation.evaluator_binding.role_ref)) issues.push({ path: `evaluations[${index}].evaluator_binding.role_ref`, message: "unknown evaluator role" });
    for (const ref of evaluation.evidence_requirement_refs) if (!evidenceIds.has(ref)) issues.push({ path: `evaluations[${index}].evidence_requirement_refs`, message: `unknown evidence requirement '${ref}'` });
  });

  if (spec.progress.stall_after_loop_attempts >= spec.limit_policy.max_loop_attempts) {
    issues.push({ path: "progress.stall_after_loop_attempts", message: "must be below max_loop_attempts" });
  }
  if (spec.limit_policy.control_plane_output_reserve_bytes >= spec.limit_policy.max_output_bytes) {
    issues.push({ path: "limit_policy.control_plane_output_reserve_bytes", message: "must be below max_output_bytes" });
  }
  if ((spec.limit_policy.max_cost_minor_units === null) !== (spec.limit_policy.cost_currency === null)) {
    issues.push({ path: "limit_policy.cost_currency", message: "cost limit and currency must both be null or both be set" });
  }

  const terminalStates = spec.stop_policy.terminal_states.map((value) => value.state);
  if (new Set(terminalStates).size !== 7) issues.push({ path: "stop_policy.terminal_states", message: "each terminal state is required exactly once" });

  const expectedRetryPairs = new Set<string>();
  for (const task of spec.tasks) for (const retryClass of RetryClassV02.options) expectedRetryPairs.add(`${task.id}\u0000${retryClass}`);
  const actualRetryPairs = new Set<string>();
  for (const rule of spec.retry_policy.rules) {
    const key = `${rule.task_ref}\u0000${rule.failure_class}`;
    if (actualRetryPairs.has(key)) issues.push({ path: "retry_policy.rules", message: "retry pair is duplicated" });
    actualRetryPairs.add(key);
    if (!taskIds.has(rule.task_ref)) issues.push({ path: "retry_policy.rules", message: `unknown task '${rule.task_ref}'` });
    if (!rule.retryable && (rule.max_task_executions !== 1 || rule.backoff !== "none" || rule.base_delay_ms !== 0 || rule.max_delay_ms !== 0)) {
      issues.push({ path: "retry_policy.rules", message: "non-retryable rules require one execution and zero backoff" });
    }
  }
  for (const key of expectedRetryPairs) if (!actualRetryPairs.has(key)) issues.push({ path: "retry_policy.rules", message: "every task requires every retry class" });

  const sideEffectTaskIds = spec.side_effects.map((value) => value.task_id);
  if (sideEffectTaskIds.length !== taskIds.size || new Set(sideEffectTaskIds).size !== sideEffectTaskIds.length || sideEffectTaskIds.some((id) => !taskIds.has(id))) {
    issues.push({ path: "side_effects", message: "exactly one side-effect container is required per task" });
  }
  for (const sideEffect of spec.side_effects) {
    const none = sideEffect.effects.find((effect) => effect.effect_class === "none");
    if (none !== undefined && (sideEffect.effects.length !== 1 || !none.inspectable || none.reversible || none.idempotency !== "not-required" || none.compensation_ref !== null)) {
      issues.push({ path: "side_effects", message: "a none effect must be the sole inert effect" });
    }
  }

  const artifactPaths = spec.artifacts.map((value) => value.path);
  if (new Set(artifactPaths).size !== artifactPaths.length) issues.push({ path: "artifacts", message: "artifact paths must be unique" });
  const requiredContext = new Set(spec.context_contract.required);
  if (spec.context_contract.forbidden.some((value) => requiredContext.has(value))) issues.push({ path: "context_contract", message: "required and forbidden context cannot overlap" });
  return issues;
}

export { IsoTimestamp };
