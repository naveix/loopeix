import { z } from "zod";
import { HumanId, LoopVersion, RiskTierV1, SchemaVersion } from "./scalars.js";

/**
 * LoopSpec authoring schema (schema-contract.md).
 *
 * Two-layer design (ADR 0001):
 *  - The Zod object below carries all STRUCTURAL rules and is the source for the
 *    generated JSON Schema (`z.toJSONSchema`).
 *  - Cross-field/relational invariants live in `checkLoopSpecInvariants` because
 *    they cannot be expressed in JSON Schema; they run as a second pass.
 */

export const InputSpec = z.object({
  id: HumanId,
  description: z.string(),
  required: z.boolean(),
});

export const SpecialistRoleSpec = z.object({
  id: HumanId,
  owns: z.array(z.string()).min(1),
  must_not: z.array(z.string()),
  allowed_tools: z.array(HumanId),
  handoff: z.string(),
});

export const TaskSpec = z.object({
  id: HumanId,
  role: HumanId,
  artifacts: z.array(HumanId),
  depends_on: z.array(HumanId),
  acceptance_checks: z.array(z.string()).min(1),
});

export const ToolGrant = z.object({
  id: HumanId,
  tool: z.string(),
  scope: z.string(),
  // RiskTierV1 (no T5): a spec cannot grant a T5 tool in V1.
  risk_tier: RiskTierV1,
  requires_approval: z.boolean(),
});

export const ArtifactType = z.enum([
  "markdown",
  "json",
  "jsonl",
  "yaml",
  "html",
  "text",
  "image",
  "other",
]);

export const ArtifactSpec = z.object({
  id: HumanId,
  path: z.string().min(1),
  type: ArtifactType,
  required: z.boolean(),
  producer_task: HumanId,
  acceptance_checks: z.array(z.string()).min(1),
});

export const GateSpec = z.object({
  id: HumanId,
  blocking: z.boolean(),
  inputs_required: z.array(z.string()),
  evidence_rule: z.string(),
  pass_condition: z.string(),
  hold_condition: z.string(),
  fail_condition: z.string(),
  waiver_allowed: z.boolean(),
});

export const EvaluationType = z.enum([
  "command",
  "manual-review",
  "source-citation",
  "browser-check",
  "schema-validation",
  "custom",
]);

export const EvaluationSpec = z.object({
  id: HumanId,
  type: EvaluationType,
  required: z.boolean(),
  command: z.string().optional(),
  success_condition: z.string(),
});

export const WorkflowPatternType = z.enum([
  "prompt-chaining",
  "routing",
  "parallel-specialists",
  "orchestrator-workers",
  "evaluator-optimizer",
]);

/** The structural LoopSpec object. Feeds `z.toJSONSchema`. */
export const LoopSpecShape = z.object({
  schema_version: SchemaVersion,
  loop_family: HumanId,
  version: LoopVersion,
  outcome: z.object({
    summary: z.string().min(1),
    success_criteria: z.array(z.string()).min(1),
  }),
  inputs: z.array(InputSpec),
  context_contract: z.object({
    required: z.array(z.string()),
    forbidden: z.array(z.string()),
    untrusted_sources: z.array(z.string()),
  }),
  workflow_pattern: z.object({
    type: WorkflowPatternType,
    phases: z.array(z.string()).min(1),
  }),
  roles: z.array(SpecialistRoleSpec).min(1),
  tasks: z.array(TaskSpec).min(1),
  tool_grants: z.array(ToolGrant),
  artifacts: z.array(ArtifactSpec),
  gates: z.array(GateSpec).min(1),
  evaluations: z.array(EvaluationSpec),
  risk_controls: z.object({
    // RiskTierV1 (no T5): T5 can never be the max tier that runs without approval.
    max_tier_without_approval: RiskTierV1,
    // V1 hard rule: T5 is never allowed without an explicit later ADR.
    t5_allowed: z.literal(false),
  }),
  retro: z.object({
    creates: z.string().min(1),
  }),
});

export type LoopSpec = z.infer<typeof LoopSpecShape>;

export interface Issue {
  path: string;
  message: string;
}

/**
 * Cross-field invariants that JSON Schema cannot express (schema-contract.md
 * §Cross-Schema Invariants + RFC §Validation Rules). Runs on an already
 * structurally-valid LoopSpec.
 */
export function checkLoopSpecInvariants(spec: LoopSpec): Issue[] {
  const issues: Issue[] = [];

  const dup = (arr: ReadonlyArray<{ id: string }>, label: string): void => {
    const seen = new Set<string>();
    for (const item of arr) {
      if (seen.has(item.id)) {
        issues.push({ path: label, message: `duplicate ${label} id: '${item.id}'` });
      }
      seen.add(item.id);
    }
  };
  dup(spec.roles, "roles");
  dup(spec.tasks, "tasks");
  dup(spec.artifacts, "artifacts");
  dup(spec.tool_grants, "tool_grants");
  dup(spec.inputs, "inputs");
  dup(spec.gates, "gates");
  dup(spec.evaluations, "evaluations");

  const roleIds = new Set(spec.roles.map((r) => r.id));
  const taskIds = new Set(spec.tasks.map((t) => t.id));
  const artifactIds = new Set(spec.artifacts.map((a) => a.id));

  spec.tasks.forEach((t, i) => {
    if (!roleIds.has(t.role)) {
      issues.push({ path: `tasks[${i}].role`, message: `task '${t.id}' references unknown role '${t.role}'` });
    }
    t.artifacts.forEach((aid, j) => {
      if (!artifactIds.has(aid)) {
        issues.push({ path: `tasks[${i}].artifacts[${j}]`, message: `task '${t.id}' references unknown artifact '${aid}'` });
      }
    });
    t.depends_on.forEach((dep, j) => {
      if (!taskIds.has(dep)) {
        issues.push({ path: `tasks[${i}].depends_on[${j}]`, message: `task '${t.id}' depends on unknown task '${dep}'` });
      }
    });
  });

  spec.artifacts.forEach((a, i) => {
    if (a.required && !taskIds.has(a.producer_task)) {
      issues.push({
        path: `artifacts[${i}].producer_task`,
        message: `required artifact '${a.id}' has no producing task ('${a.producer_task}' not found)`,
      });
    }
  });

  spec.gates.forEach((g, i) => {
    if (g.blocking && g.evidence_rule.trim() === "") {
      issues.push({ path: `gates[${i}].evidence_rule`, message: `blocking gate '${g.id}' must declare a non-empty evidence_rule` });
    }
  });
  // Deliberate conservative V1 default: every spec must have at least one blocking gate.
  // The contract qualifies this "for V1 execution loops", but V1 has no loop-type
  // discriminator, so we require it for all specs (revisit if a discriminator is added).
  if (!spec.gates.some((g) => g.blocking)) {
    issues.push({ path: "gates", message: "at least one blocking gate is required for a V1 execution loop" });
  }

  spec.evaluations.forEach((e, i) => {
    if (e.type === "command" && (e.command === undefined || e.command.trim() === "")) {
      issues.push({ path: `evaluations[${i}].command`, message: `command evaluation '${e.id}' requires a non-empty 'command'` });
    }
  });

  const requiredCtx = new Set(spec.context_contract.required);
  spec.context_contract.forbidden.forEach((f, i) => {
    if (requiredCtx.has(f)) {
      issues.push({ path: `context_contract.forbidden[${i}]`, message: `context '${f}' is listed as both required and forbidden` });
    }
  });

  return issues;
}
