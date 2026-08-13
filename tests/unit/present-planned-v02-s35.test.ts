import { describe, expect, it } from "vitest";
import { PlanReportControlCategoriesV02 } from "../../src/report/plan-renderer.js";
import { renderPlanReportV02 } from "../../src/report/plan-renderer.js";
import { presentPlannedRunV02 } from "../../src/run/present-planned-v02.js";
import type { ResolvedRunPlanV02Value } from "../../src/schema/runtime.js";

function plan(): ResolvedRunPlanV02Value {
  return {
    schema_version: "0.2",
    execution_profile: "bounded-v02",
    run_id: "run_example_01",
    trigger: { kind: "manual" },
    goal: { statement: "Ship safely", success_criteria: [] },
    assurance_profile: { id: "assurance", tightens: [] },
    context_snapshot: { required: ["source"], forbidden: ["secrets"], untrusted_sources: [] },
    roles: [{ id: "builder" }],
    tasks: [{ id: "task-a" }],
    tool_grants: [{ id: "workspace-shell" }],
    workspace_boundary: { workspace_root: "/workspace", read: ["."], write: ["src"] },
    progress: { observations: [{ id: "progress-a" }] },
    stop_policy: { terminal_states: [{ terminal_state: "completed" }] },
    limit_policy: { max_actions: 1 },
    required_control_plane_output_bytes: 1,
    runtime_record_limits: { max_task_result_records: 1 },
    retry_policy: { rules: [{ task_ref: "task-a", failure_class: "tool-error" }] },
    recovery_policy: { strategy: "hold" },
    side_effects: [{ task_id: "task-a", effects: [] }],
    compensations: [{ id: "compensation-a" }],
    gates: [{ id: "gate-a" }],
    evaluations: [{ id: "evaluation-a" }],
    evidence_requirements: [{ id: "evidence-a" }],
    adapter_plan: { engine: "codex_cli", command: "codex exec --json", permission_mode: "workspace-write", known_gaps: [] },
    risk_controls: { max_tier_without_approval: "T3", t5_allowed: false },
    authority_subject: { policy_digest: `sha256:${"a".repeat(64)}` },
    loopeix_version: "0.2.0",
    loopeix_version_hash: `sha256:${"b".repeat(64)}`,
    source_authoring_hash: `sha256:${"c".repeat(64)}`,
    compiler_bundle_id: "compiler_bundle_01",
    catalog_version_hash: `sha256:${"d".repeat(64)}`,
    binding_input_id: "binding_input_01",
    binding_input_hash: `sha256:${"e".repeat(64)}`,
    compile_pack_manifest_hash: `sha256:${"f".repeat(64)}`,
    work_item_id: "work_item_01",
    intake_brief_id: "intake_brief_01",
    loop_family: "expert-sprint",
    created_at: "2026-08-12T10:00:00Z",
    role_assignments: [{ role_ref: "builder", actor_ref: "actor_builder_01", actor_kind: "agent", stable_identity_hash: `sha256:${"1".repeat(64)}` }],
  } as unknown as ResolvedRunPlanV02Value;
}

describe("S35 truthful planned V02 presentation", () => {
  it("projects every control category without claiming execution or enforcement", () => {
    const result = presentPlannedRunV02(plan());
    expect(result).toMatchObject({
      schema_version: "0.2",
      execution_profile: "bounded-v02",
      run_state: "planned",
      execution_supported: false,
      controls_enforced: false,
      reason: "UNSUPPORTED_EXECUTION_PROFILE",
      work_execution: "NOT EXECUTED",
      control_enforcement: "NOT ENFORCED",
      next_action: null,
    });
    expect([...new Set(result.controls.map(({ category }) => category))]).toEqual(PlanReportControlCategoriesV02);
    expect(result.controls.find(({ control_ref }) => control_ref === "authority-subject")?.value).toContain("policy_digest");
    expect(result.controls.find(({ control_ref }) => control_ref === "compile-lineage")?.value).toContain("compile_pack_manifest_hash");
    expect(() => renderPlanReportV02({
      generation_id: `prg_${"1".repeat(32)}`,
      resolved_run_plan_hash: `sha256:${"2".repeat(64)}`,
      run_id: result.run_id,
      execution_profile: result.execution_profile,
      controls: result.controls,
    })).not.toThrow();
  });

  it("is deterministic and does not mutate the validated plan", () => {
    const input = plan();
    const before = structuredClone(input);
    expect(presentPlannedRunV02(input)).toEqual(presentPlannedRunV02(input));
    expect(input).toEqual(before);
  });
});
