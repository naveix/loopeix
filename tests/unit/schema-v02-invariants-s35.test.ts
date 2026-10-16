import { describe, expect, it } from "vitest";
import { UnicodeScalarString } from "../../src/schema/loopeix-v02.js";
import { parseLoopeixDocument } from "../../src/schema/version-dispatch.js";

const HASH = `sha256:${"0".repeat(64)}`;
const REQUIRED_GATE_KINDS = [
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
] as const;

const RETRY_CLASSES = [
  "transient-adapter",
  "transient-network",
  "contention",
  "verification-failed",
  "policy-hold",
  "invalid-input",
  "permanent-execution",
] as const;

function validV02(): Record<string, unknown> {
  const gates = REQUIRED_GATE_KINDS.map((controlKind, index) => ({
    id: `gate-${index + 1}`,
    blocking: controlKind === "approval",
    inputs_required: [],
    evidence_rule: "Use captured evidence.",
    pass_condition: "Evidence passes.",
    hold_condition: "Evidence is incomplete.",
    fail_condition: "Evidence fails.",
    waiver_allowed: false,
    control_kind: controlKind,
    applicability: { mode: "always" },
    risk_tier: "T2",
    prerequisites: [{ kind: "run-initialized" }],
    evidence_requirement_refs: ["evidence-main"],
    evaluator_binding: {
      role_ref: "builder",
      evaluator_identity_ref: "actor_builder",
      policy_digest: HASH,
      export_check_role: null,
    },
  }));

  return {
    schema_version: "0.2",
    loop_family: "minimal-loop",
    version: "v001",
    trigger: { type: "operator-invoked", entrypoint: "run-start" },
    goal: {
      statement: "Complete the bounded task.",
      success_criteria: [{
        id: "criterion-main",
        description: "The required evaluation passes.",
        evaluation_refs: ["evaluation-main"],
        required: true,
      }],
    },
    inputs: [],
    context_contract: { required: [], forbidden: [], untrusted_sources: [] },
    workflow_pattern: { type: "prompt-chaining", phases: ["work"] },
    roles: [{
      id: "builder",
      owns: ["implementation"],
      must_not: [],
      allowed_tools: [],
      handoff: "Return evidence.",
    }],
    tasks: [{
      id: "task-main",
      role: "builder",
      artifacts: [],
      depends_on: [],
      acceptance_checks: ["Evaluation passes."],
      kind: "work",
      pre_task_gate_refs: ["gate-3"],
    }],
    tool_grants: [],
    artifacts: [],
    gates,
    evaluations: [{
      id: "evaluation-main",
      type: "command",
      required: true,
      command: "true",
      success_condition: "Exit zero.",
      applicability: { mode: "always" },
      prerequisites: [{ kind: "run-initialized" }],
      evidence_requirement_refs: ["evidence-main"],
      evaluator_binding: {
        role_ref: "builder",
        evaluator_identity_ref: "actor_builder",
        policy_digest: HASH,
        export_check_role: null,
      },
    }],
    evidence_requirements: [{
      id: "evidence-main",
      minimum_independent_roots: 1,
      evidence_kinds: ["command-capture"],
      source_acquisition_policy: null,
    }],
    risk_controls: { max_tier_without_approval: "T2", t5_allowed: false },
    progress: {
      observations: [{
        id: "progress-main",
        description: "Observe evaluation status.",
        source: "evaluation",
        source_ref: "evaluation-main",
        value_pointer: "/status",
        value_type: "string",
        improves_when: { operator: "equals", target: "pass" },
        target: { operator: "equals", value: "pass" },
      }],
      stall_after_loop_attempts: 1,
    },
    stop_policy: {
      terminal_states: [
        { state: "completed", condition_mode: "all", conditions: [{ source: "success-criterion", ref: "criterion-main", outcome: "satisfied" }], priority: 100 },
        { state: "held", condition_mode: "any", conditions: [{ source: "gate", ref: "gate-3", outcome: "hold" }], priority: 300 },
        { state: "blocked", condition_mode: "any", conditions: [{ source: "failure", task_ref: "task-main", ref: "contention", outcome: "observed" }], priority: 200 },
        { state: "failed", condition_mode: "any", conditions: [{ source: "failure", task_ref: "task-main", ref: "invalid-input", outcome: "observed" }], priority: 600 },
        { state: "stalled", condition_mode: "any", conditions: [{ source: "progress", ref: "progress-main", outcome: "stalled" }], priority: 400 },
        { state: "exhausted", condition_mode: "any", conditions: [{ source: "limit", ref: "max-loop-attempts", outcome: "reached" }], priority: 500 },
        { state: "aborted", condition_mode: "any", conditions: [{ source: "control", ref: "abort-requested", outcome: "present" }], priority: 700 },
      ],
    },
    limit_policy: {
      max_loop_attempts: 2,
      max_elapsed_ms: 60_000,
      max_tool_calls: 10,
      max_workers: 1,
      max_output_bytes: 1_000_000,
      control_plane_output_reserve_bytes: 1_000,
      max_tokens: null,
      max_cost_minor_units: null,
      cost_currency: null,
    },
    retry_policy: {
      rules: RETRY_CLASSES.map((failureClass) => ({
        task_ref: "task-main",
        failure_class: failureClass,
        retryable: false,
        max_task_executions: 1,
        backoff: "none",
        base_delay_ms: 0,
        max_delay_ms: 0,
      })),
    },
    recovery_policy: {
      resume_from: "last-durable-boundary",
      require_input_hash_match: true,
      require_policy_hash_match: true,
      on_unknown_outcome: "hold",
      terminal_compensation: "before-terminal-seal",
      activation_reasons: ["terminal-failure", "terminal-exhaustion", "terminal-stall", "abort-recovery"],
      max_compensation_workers: 1,
      reserve: {
        max_elapsed_ms: 0,
        max_tool_calls: 0,
        max_output_bytes: 0,
        max_tokens: null,
        max_cost_minor_units: null,
      },
    },
    side_effects: [{
      task_id: "task-main",
      effects: [{
        effect_id: "effect-none",
        effect_class: "none",
        description: "No task-owned side effect.",
        inspectable: true,
        reversible: false,
        idempotency: "not-required",
        last_safe_stop: { kind: "before-task", task_ref: "task-main" },
        compensation_ref: null,
      }],
    }],
    compensations: [],
    retro: { creates: "A concise retrospective." },
  };
}

describe("S35 strict V02 authoring invariants", () => {
  it("accepts valid surrogate pairs and rejects every unpaired Unicode surrogate", () => {
    expect(UnicodeScalarString.safeParse("valid \ud83d\ude00 pair").success).toBe(true);
    expect(UnicodeScalarString.safeParse("trailing-high\ud800").success).toBe(false);
    expect(UnicodeScalarString.safeParse("lone-low\udc00").success).toBe(false);
    expect(UnicodeScalarString.safeParse("misaligned\ud800x").success).toBe(false);
    expect(UnicodeScalarString.safeParse("two-highs\ud800\ud800").success).toBe(false);

    const validPairDocument = validV02();
    (validPairDocument.goal as Record<string, unknown>).statement = "Complete the \ud83d\ude00 task.";
    expect(parseLoopeixDocument(validPairDocument).ok).toBe(true);

    const trailingHighDocument = validV02();
    (trailingHighDocument.goal as Record<string, unknown>).statement = "Complete the task.\ud800";
    expect(parseLoopeixDocument(trailingHighDocument)).toMatchObject({
      ok: false,
      schema_version: "0.2",
      reason: "INVALID_AUTHORING_DOCUMENT",
    });
  });

  it("accepts a complete bounded contract and rejects every missing loop-control section", () => {
    expect(parseLoopeixDocument(validV02()).ok).toBe(true);

    for (const section of [
      "trigger",
      "goal",
      "evidence_requirements",
      "progress",
      "stop_policy",
      "limit_policy",
      "retry_policy",
      "recovery_policy",
      "side_effects",
      "compensations",
    ]) {
      const candidate = validV02();
      delete candidate[section];
      expect(parseLoopeixDocument(candidate), section).toMatchObject({
        ok: false,
        schema_version: "0.2",
        reason: "INVALID_AUTHORING_DOCUMENT",
      });
    }
  });

  it("rejects a cycle between otherwise valid work-task dependencies", () => {
    const candidate = validV02();
    const tasks = candidate.tasks as Array<Record<string, unknown>>;
    const first = tasks[0]!;
    first.depends_on = ["task-second"];
    tasks.push({
      ...first,
      id: "task-second",
      depends_on: ["task-main"],
    });
    const retryPolicy = candidate.retry_policy as { rules: Array<Record<string, unknown>> };
    retryPolicy.rules.push(
      ...RETRY_CLASSES.map((failureClass) => ({
        task_ref: "task-second",
        failure_class: failureClass,
        retryable: false,
        max_task_executions: 1,
        backoff: "none",
        base_delay_ms: 0,
        max_delay_ms: 0,
      })),
    );
    const sideEffects = candidate.side_effects as Array<Record<string, unknown>>;
    sideEffects.push({
      task_id: "task-second",
      effects: [{
        effect_id: "effect-second-none",
        effect_class: "none",
        description: "No task-owned side effect.",
        inspectable: true,
        reversible: false,
        idempotency: "not-required",
        last_safe_stop: { kind: "before-task", task_ref: "task-second" },
        compensation_ref: null,
      }],
    });

    expect(parseLoopeixDocument(candidate)).toMatchObject({
      ok: false,
      schema_version: "0.2",
      reason: "INVALID_AUTHORING_DOCUMENT",
      issues: expect.arrayContaining([
        expect.objectContaining({ path: "tasks", message: expect.stringContaining("cycle") }),
      ]),
    });
  });
});
