// Independent S35 projection fixture data. This file intentionally imports no
// production module; expected IDs and topologies are transcribed from ADR 0008.

export interface S35ProjectionOracle {
  entry_id: string;
  item_gate_id: string;
  item_evaluation_id: string;
  item_evidence_id: string;
  evaluator_role: string;
  roles: readonly string[];
  tasks: readonly string[];
  objective: string;
  permission_mode: "read-only" | "workspace-write";
  effect_class: "none" | "workspace-write" | "external-read";
  expected_projection_hash: string;
}

export const S35_PROJECTION_ORACLES: readonly S35ProjectionOracle[] = [
  {
    entry_id: "adapter-truth-probe",
    item_gate_id: "no-strength-beyond-observation",
    item_evaluation_id: "adapter-fixture-replay",
    item_evidence_id: "adapter-evidence",
    evaluator_role: "capability-analyst",
    roles: ["capability-analyst", "fixture-tester", "gap-reviewer", "report-author"],
    tasks: ["probe-capabilities", "test-capture-gaps", "review-claim-strength", "report-proof-boundary"],
    objective: "Establish the adapter proof boundary from repeatable observations.",
    permission_mode: "workspace-write",
    effect_class: "workspace-write",
    expected_projection_hash: "sha256:0b8bbc57fff970e8f44a73167d6421c0c004588542372c07d1b9f7309f426967",
  },
  {
    entry_id: "claims-check-pr",
    item_gate_id: "evidence-only-verdicts",
    item_evaluation_id: "receipt-verification",
    item_evidence_id: "claims-evidence",
    evaluator_role: "claim-analyst",
    roles: ["claim-analyst", "evidence-tracer", "contradiction-reviewer", "report-author"],
    tasks: ["extract-claims", "trace-evidence", "test-contradictions", "report-verdicts"],
    objective: "Classify pull-request claims only from admitted evidence.",
    permission_mode: "read-only",
    effect_class: "none",
    expected_projection_hash: "sha256:c390cfd54db5e94cd4e3a71d45e859f1b28105f6b7421e6771ede16c63045b7d",
  },
  {
    entry_id: "expert-sprint",
    item_gate_id: "qa-independence",
    item_evaluation_id: "project-validation",
    item_evidence_id: "sprint-evidence",
    evaluator_role: "phase-zero-analyst",
    roles: ["phase-zero-analyst", "contract-architect", "builder", "independent-qa"],
    tasks: ["produce-findings", "freeze-contracts", "build-disjoint-work", "perform-independent-qa"],
    objective: "Deliver the accepted sprint contract with independent verification.",
    permission_mode: "workspace-write",
    effect_class: "workspace-write",
    expected_projection_hash: "sha256:a21d588e466249fed18d2dd0f52296fa7647c5c76bbefec629632b5190a15cdb",
  },
  {
    entry_id: "loop-engineer-from-vague-brief",
    item_gate_id: "human-intake-approval",
    item_evaluation_id: "schema-validation",
    item_evidence_id: "intake-evidence",
    evaluator_role: "intake-analyst",
    roles: ["intake-analyst", "contract-architect", "independent-reviewer"],
    tasks: ["bound-intake", "resolve-clarifications", "author-loop-contract", "review-loop-contract"],
    objective: "Turn the approved brief into a bounded loop contract.",
    permission_mode: "read-only",
    effect_class: "none",
    expected_projection_hash: "sha256:23c6a3ac313be93dadf9bb083433a99f65fedf32e3c20e909ddf4647c79be6f7",
  },
  {
    entry_id: "research-need-cluster",
    item_gate_id: "source-diversity",
    item_evaluation_id: "source-citation",
    item_evidence_id: "research-evidence",
    evaluator_role: "source-planner",
    roles: ["source-planner", "source-researcher", "corroborator", "synthesizer"],
    tasks: ["plan-sources", "collect-sources", "corroborate-findings", "synthesize-need-clusters"],
    objective: "Produce corroborated need clusters from independent current sources.",
    permission_mode: "read-only",
    effect_class: "external-read",
    expected_projection_hash: "sha256:c6d0a496b901bf46b4d1d1707e0305bad3c43fb8e1aafbb0e2a2d86dc0088a7e",
  },
  {
    entry_id: "safe-bugfix",
    item_gate_id: "change-before-validation",
    item_evaluation_id: "project-validation",
    item_evidence_id: "bugfix-evidence",
    evaluator_role: "diagnostician",
    roles: ["diagnostician", "implementer", "validator", "independent-reviewer"],
    tasks: ["diagnose-root-cause", "implement-change", "validate-change", "review-regression-risk"],
    objective: "Fix the diagnosed defect and preserve regression evidence.",
    permission_mode: "workspace-write",
    effect_class: "workspace-write",
    expected_projection_hash: "sha256:ec18ffca8e411da9d7fbd44069457dbae8812ceeb05f607f71fc0738fa4ec6aa",
  },
] as const;

export const S35_PROJECT_BINDING_KEYS = [
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

const RETRY_CLASSES = [
  "transient-adapter",
  "transient-network",
  "contention",
  "verification-failed",
  "policy-hold",
  "invalid-input",
  "permanent-execution",
] as const;

const policyDigest = `sha256:${"6".repeat(64)}`;

export function bindingInputForProjectionOracle(oracle: S35ProjectionOracle): Record<string, unknown> {
  const firstTask = oracle.tasks[0]!;
  const progressId = "project-progress";
  const criterionId = "project-success";
  const evaluatorBinding = {
    role_ref: oracle.evaluator_role,
    evaluator_identity_ref: `evaluator_${oracle.entry_id.replaceAll("-", "_")}`,
    policy_digest: policyDigest,
    export_check_role: null,
  };
  const values: Record<(typeof S35_PROJECT_BINDING_KEYS)[number], unknown> = {
    "project.compensations": [],
    "project.engine": {
      engine: "codex",
      command: "codex exec --json",
      permission_mode: oracle.permission_mode,
      known_gaps: ["Usage totals require separate admitted evidence."],
    },
    "project.evidence-requirements": [
      {
        id: "control-evidence",
        minimum_independent_roots: 1,
        evidence_kinds: ["manual-observation"],
        source_acquisition_policy: null,
      },
      {
        id: oracle.item_evidence_id,
        minimum_independent_roots: 1,
        evidence_kinds: ["command-capture"],
        source_acquisition_policy: null,
      },
    ].sort((left, right) => left.id < right.id ? -1 : left.id > right.id ? 1 : 0),
    "project.forbidden-context": ["Private customer records."],
    "project.goal": {
      statement: oracle.objective,
      success_criteria: [{
        id: criterionId,
        description: "The item-specific evaluation passes with admitted evidence.",
        evaluation_refs: [oracle.item_evaluation_id],
        required: true,
      }],
    },
    "project.hard-limits": {
      max_loop_attempts: 4,
      max_elapsed_ms: 60_000,
      max_tool_calls: 32,
      max_workers: 1,
      max_output_bytes: 1_000_000,
      control_plane_output_reserve_bytes: 100_000,
      max_tokens: null,
      max_cost_minor_units: null,
      cost_currency: null,
    },
    "project.objective": oracle.objective,
    "project.progress": {
      observations: [{
        id: progressId,
        description: "Track the item-specific evaluation result.",
        source: "evaluation",
        source_ref: oracle.item_evaluation_id,
        value_pointer: "/passed",
        value_type: "boolean",
        improves_when: { operator: "equals", target: true },
        target: { operator: "equals", value: true },
      }],
      stall_after_loop_attempts: 2,
    },
    "project.recovery-policy": {
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
    "project.required-context": ["Approved repository files."],
    "project.retry-policy": {
      rules: oracle.tasks.flatMap((taskRef) => RETRY_CLASSES.map((failureClass) => ({
        task_ref: taskRef,
        failure_class: failureClass,
        retryable: false,
        max_task_executions: 1,
        backoff: "none",
        base_delay_ms: 0,
        max_delay_ms: 0,
      }))),
    },
    "project.side-effects": oracle.tasks.map((taskRef) => ({
      task_id: taskRef,
      effects: [{
        effect_id: `effect-${taskRef}`,
        effect_class: oracle.effect_class,
        description: "Perform only the declared bounded task effect.",
        inspectable: true,
        reversible: false,
        idempotency: oracle.effect_class === "none" ? "not-required" : "required",
        last_safe_stop: { kind: "before-task", task_ref: taskRef },
        compensation_ref: null,
      }],
    })),
    "project.stop-policy": {
      terminal_states: [
        { state: "aborted", condition_mode: "any", conditions: [{ source: "control", ref: "abort-requested", outcome: "present" }], priority: 700 },
        { state: "failed", condition_mode: "any", conditions: [{ source: "failure", task_ref: firstTask, ref: "invalid-input", outcome: "observed" }], priority: 600 },
        { state: "exhausted", condition_mode: "any", conditions: [{ source: "limit", ref: "max-loop-attempts", outcome: "reached" }], priority: 500 },
        { state: "stalled", condition_mode: "any", conditions: [{ source: "progress", ref: progressId, outcome: "stalled" }], priority: 400 },
        { state: "held", condition_mode: "any", conditions: [{ source: "gate", ref: oracle.item_gate_id, outcome: "hold" }], priority: 300 },
        { state: "blocked", condition_mode: "any", conditions: [{ source: "failure", task_ref: firstTask, ref: "contention", outcome: "observed" }], priority: 200 },
        { state: "completed", condition_mode: "all", conditions: [{ source: "success-criterion", ref: criterionId, outcome: "satisfied" }], priority: 100 },
      ],
    },
    "project.validation": [
      {
        id: "control-review",
        type: "manual-review",
        required: true,
        success_condition: "Every required control is supported by admitted evidence.",
        applicability: { mode: "always" },
        prerequisites: [{ kind: "run-initialized" }],
        evidence_requirement_refs: ["control-evidence"],
        evaluator_binding: evaluatorBinding,
      },
      {
        id: oracle.item_evaluation_id,
        type: "manual-review",
        required: true,
        success_condition: "The item-specific acceptance contract is satisfied.",
        applicability: { mode: "always" },
        prerequisites: [{ kind: "run-initialized" }],
        evidence_requirement_refs: [oracle.item_evidence_id],
        evaluator_binding: evaluatorBinding,
      },
    ].sort((left, right) => left.id < right.id ? -1 : left.id > right.id ? 1 : 0),
    "project.workspace-root": {
      root: "/workspace",
      read: ["src"],
      write: ["artifacts"],
    },
  };

  return {
    schema_version: "0.2",
    binding_input_id: `binding_${oracle.entry_id.replaceAll("-", "_")}`,
    work_item_id: `wi_${oracle.entry_id.replaceAll("-", "_")}`,
    submitted_at: "2026-08-10T12:00:00.000Z",
    bindings: S35_PROJECT_BINDING_KEYS.map((key) => ({
      key,
      source: key === "project.workspace-root" ? "workspace-observation" : "operator",
      value: values[key],
      source_ref: key === "project.workspace-root" ? "workspace:root" : null,
      source_hash: key === "project.workspace-root" ? `sha256:${"a".repeat(64)}` : null,
      approved_by: "operator",
    })),
  };
}
