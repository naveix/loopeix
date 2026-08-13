import { canonicalize } from "../hash.js";
import type { PlanReportControlRowV02 } from "../report/plan-renderer.js";
import type { ResolvedRunPlanV02Value } from "../schema/runtime.js";

export type PlannedRunPresentationV02 = Readonly<{
  schema_version: "0.2";
  execution_profile: "bounded-v02";
  run_id: string;
  run_state: "planned";
  execution_supported: false;
  controls_enforced: false;
  reason: "UNSUPPORTED_EXECUTION_PROFILE";
  work_execution: "NOT EXECUTED";
  control_enforcement: "NOT ENFORCED";
  next_action: null;
  controls: readonly PlanReportControlRowV02[];
}>;

type ControlCategory = PlanReportControlRowV02["category"];

function row(
  category: ControlCategory,
  controlRef: string,
  label: string,
  value: unknown,
): PlanReportControlRowV02 {
  return Object.freeze({
    category,
    control_ref: controlRef,
    label,
    value: canonicalize(value),
  });
}

function indexedRows(
  category: ControlCategory,
  prefix: string,
  label: string,
  values: readonly unknown[],
): PlanReportControlRowV02[] {
  return values.map((value, index) => row(category, `${prefix}-${index.toString().padStart(6, "0")}`, label, value));
}

export function presentPlannedRunV02(plan: ResolvedRunPlanV02Value): PlannedRunPresentationV02 {
  const controls: PlanReportControlRowV02[] = [
    row("trigger", "trigger", "Trigger", plan.trigger),
    row("goal", "goal", "Goal", plan.goal),
    row("context", "assurance-profile", "Assurance profile", plan.assurance_profile),
    row("context", "context-snapshot", "Context snapshot", plan.context_snapshot),
    ...indexedRows("context", "role", "Specialist role", plan.roles),
    ...indexedRows("context", "task", "Task", plan.tasks),
    ...indexedRows("context", "tool-grant", "Tool grant", plan.tool_grants),
    row("context", "workspace-boundary", "Workspace boundary", plan.workspace_boundary),
    row("progress", "progress-policy", "Progress policy", plan.progress),
    row("stop", "stop-policy", "Stop policy", plan.stop_policy),
    row("limit", "limit-policy", "Limit policy", plan.limit_policy),
    row("limit", "required-control-plane-output-bytes", "Required control-plane output bytes", plan.required_control_plane_output_bytes),
    row("limit", "runtime-record-limits", "Runtime record limits", plan.runtime_record_limits),
    row("retry", "retry-policy", "Retry policy", plan.retry_policy),
    ...indexedRows("retry", "retry-rule", "Retry rule", plan.retry_policy.rules),
    row("recovery", "recovery-policy", "Recovery policy", plan.recovery_policy),
    ...indexedRows("side-effect", "side-effect", "Side-effect policy", plan.side_effects),
    ...indexedRows("compensation", "compensation", "Compensation", plan.compensations),
    ...indexedRows("gate", "gate", "Gate", plan.gates),
    ...indexedRows("evaluation", "evaluation", "Evaluation", plan.evaluations),
    ...indexedRows("evaluation", "evidence-requirement", "Evidence requirement", plan.evidence_requirements),
    ...indexedRows("terminal", "terminal-state", "Terminal state", plan.stop_policy.terminal_states),
    row("engine", "adapter-plan", "Adapter plan", plan.adapter_plan),
    row("engine", "risk-controls", "Risk controls", plan.risk_controls),
    row("proof-boundary", "authority-subject", "Authority subject", plan.authority_subject),
    row("proof-boundary", "compile-lineage", "Compile lineage", {
      loopeix_version: plan.loopeix_version,
      loopeix_version_hash: plan.loopeix_version_hash,
      source_authoring_hash: plan.source_authoring_hash,
      compiler_bundle_id: plan.compiler_bundle_id,
      catalog_version_hash: plan.catalog_version_hash,
      binding_input_id: plan.binding_input_id,
      binding_input_hash: plan.binding_input_hash,
      compile_pack_manifest_hash: plan.compile_pack_manifest_hash,
      work_item_id: plan.work_item_id,
      intake_brief_id: plan.intake_brief_id,
    }),
    ...indexedRows("proof-boundary", "role-assignment", "Role assignment", plan.role_assignments),
  ];

  return Object.freeze({
    schema_version: "0.2",
    execution_profile: "bounded-v02",
    run_id: plan.run_id,
    run_state: "planned",
    execution_supported: false,
    controls_enforced: false,
    reason: "UNSUPPORTED_EXECUTION_PROFILE",
    work_execution: "NOT EXECUTED",
    control_enforcement: "NOT ENFORCED",
    next_action: null,
    controls: Object.freeze(controls),
  });
}
