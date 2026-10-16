import { describe, expect, it } from "vitest";
import { deriveProgressV02ForRuntime, evaluateProgressV02 } from "../../src/run/progress-evaluator.js";
import {
  compareRuntimeUtf8BytesV02,
  TaskProgressFactsV02,
  TaskProgressFactRecordedEventV02,
  TaskProgressObservedEventV02,
  ProgressSampleV02,
  type ProgressEvaluationInputV02,
  type ValidatedRuntimeProjectionInputV02,
} from "../../src/schema/runtime.js";

function validResolvedRunPlanV02(): ProgressEvaluationInputV02["plan"] {
  return {
    schema_version: "0.2",
    execution_profile: "bounded-v02",
    run_id: "run_progress_v02",
    loop_family: "minimal-loop",
    loopeix_version: "v001",
    loopeix_version_hash: `sha256:${"1".repeat(64)}`,
    source_authoring_hash: `sha256:${"2".repeat(64)}`,
    compiler_bundle_id: "bundle_progress_v02",
    catalog_version_hash: `sha256:${"3".repeat(64)}`,
    binding_input_id: "binding_progress_v02",
    binding_input_hash: `sha256:${"4".repeat(64)}`,
    compile_pack_manifest_hash: `sha256:${"5".repeat(64)}`,
    work_item_id: "wi_progress_v02",
    intake_brief_id: "brief_progress_v02",
    created_at: "2026-08-03T12:00:00Z",
    trigger: { type: "operator-invoked", entrypoint: "run-start" },
    goal: {
      statement: "Complete the bounded task.",
      success_criteria: [{
        id: "criterion-main",
        description: "Primary evaluation passes.",
        evaluation_refs: ["evaluation-main"],
        required: true,
      }],
    },
    roles: [{
      id: "builder",
      owns: ["implementation"],
      must_not: [],
      allowed_tools: [],
      handoff: "Return evidence only.",
    }],
    tasks: [{
      id: "task-main",
      role: "builder",
      artifacts: [],
      depends_on: [],
      acceptance_checks: ["Evaluation passes."],
      kind: "work",
      pre_task_gate_refs: ["gate-approval"],
    }],
    artifacts: [],
    gates: [{
      id: "gate-approval",
      blocking: true,
      inputs_required: [],
      evidence_rule: "Use captured evidence.",
      pass_condition: "Approval present.",
      hold_condition: "Approval missing.",
      fail_condition: "Approval invalid.",
      waiver_allowed: false,
      control_kind: "approval",
      applicability: { mode: "always" },
      risk_tier: "T2",
      prerequisites: [{ kind: "run-initialized" }],
      evidence_requirement_refs: ["evidence-main"],
      evaluator_binding: {
        role_ref: "builder",
        evaluator_identity_ref: "actor_builder",
        policy_digest: `sha256:${"6".repeat(64)}`,
        export_check_role: null,
      },
    }],
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
        policy_digest: `sha256:${"6".repeat(64)}`,
        export_check_role: null,
      },
    }],
    evidence_requirements: [{
      id: "evidence-main",
      minimum_independent_roots: 1,
      evidence_kinds: ["command-capture"],
      source_acquisition_policy: null,
    }],
    progress: {
      observations: [{
        id: "progress-main",
        description: "Track numeric output.",
        source: "evaluation",
        source_ref: "evaluation-main",
        value_pointer: "/score",
        value_type: "number",
        improves_when: { operator: "increases" },
        target: { operator: "gte", value: 3 },
      }],
      stall_after_loop_attempts: 2,
    },
    stop_policy: {
      terminal_states: [
        { state: "completed", condition_mode: "all", conditions: [{ source: "success-criterion", ref: "criterion-main", outcome: "satisfied" }], priority: 100 },
        { state: "held", condition_mode: "any", conditions: [{ source: "gate", ref: "gate-approval", outcome: "hold" }], priority: 300 },
        { state: "blocked", condition_mode: "any", conditions: [{ source: "failure", task_ref: "task-main", ref: "contention", outcome: "observed" }], priority: 200 },
        { state: "failed", condition_mode: "any", conditions: [{ source: "failure", task_ref: "task-main", ref: "invalid-input", outcome: "observed" }], priority: 600 },
        { state: "stalled", condition_mode: "any", conditions: [{ source: "progress", ref: "progress-main", outcome: "stalled" }], priority: 400 },
        { state: "exhausted", condition_mode: "any", conditions: [{ source: "limit", ref: "max-loop-attempts", outcome: "reached" }], priority: 500 },
        { state: "aborted", condition_mode: "any", conditions: [{ source: "control", ref: "abort-requested", outcome: "present" }], priority: 700 },
      ],
    },
    limit_policy: {
      max_loop_attempts: 4,
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
      rules: [
        "transient-adapter",
        "transient-network",
        "contention",
        "verification-failed",
        "policy-hold",
        "invalid-input",
        "permanent-execution",
      ].map((failureClass) => ({
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
    runtime_record_limits: {
      max_authority_records: 19,
      max_agency_recommendation_records: 16,
      max_authority_revocation_records: 3,
      max_evidence_records: 56,
      max_task_result_records: 1,
      max_manual_observation_records: 56,
      max_export_decision_records: 56,
      max_claim_records: 3,
      max_finding_records: 40,
      max_waiver_records: 1,
      max_preseal_custody_events: 112,
    },
    required_control_plane_output_bytes: 512,
    assurance_profile: { id: "base", tightens: [] },
    context_snapshot: { required: [], forbidden: [], untrusted_sources: [] },
    authority_subject: {
      mission: {
        objective: "Complete the bounded task.",
        success_criteria: [{ id: "criterion-main", description: "Primary evaluation passes.", evaluation_refs: ["evaluation-main"], required: true }],
        forbidden_outcomes: ["data-loss"],
        terminal_states: [
          { state: "completed", condition_mode: "all", conditions: [{ source: "success-criterion", ref: "criterion-main", outcome: "satisfied" }], priority: 100 },
          { state: "held", condition_mode: "any", conditions: [{ source: "gate", ref: "gate-approval", outcome: "hold" }], priority: 300 },
          { state: "blocked", condition_mode: "any", conditions: [{ source: "failure", task_ref: "task-main", ref: "contention", outcome: "observed" }], priority: 200 },
          { state: "failed", condition_mode: "any", conditions: [{ source: "failure", task_ref: "task-main", ref: "invalid-input", outcome: "observed" }], priority: 600 },
          { state: "stalled", condition_mode: "any", conditions: [{ source: "progress", ref: "progress-main", outcome: "stalled" }], priority: 400 },
          { state: "exhausted", condition_mode: "any", conditions: [{ source: "limit", ref: "max-loop-attempts", outcome: "reached" }], priority: 500 },
          { state: "aborted", condition_mode: "any", conditions: [{ source: "control", ref: "abort-requested", outcome: "present" }], priority: 700 },
        ],
      },
      repository: {
        spec_subject: { source_authoring_hash: `sha256:${"2".repeat(64)}`, loopeix_version_hash: `sha256:${"1".repeat(64)}` },
        compile_subject: {
          compile_pack_manifest_hash: `sha256:${"5".repeat(64)}`,
          compiler_bundle_id: "bundle_progress_v02",
          catalog_version_hash: `sha256:${"3".repeat(64)}`,
          binding_input_hash: `sha256:${"4".repeat(64)}`,
        },
        repository_root_ref: "repository_root_progress",
        object_format: "sha1",
        base_ref: { kind: "git-ref", canonical_ref_name: "refs/heads/main", object_id: { algorithm: "sha1", value: "a".repeat(40) }, identity_hash: `sha256:${"8".repeat(64)}` },
        transition_mode: "read-only",
        initial_state: {
          repository_root_ref: "repository_root_progress",
          base_ref_identity_hash: `sha256:${"8".repeat(64)}`,
          head: { algorithm: "sha1", value: "a".repeat(40) },
          merge_base: { algorithm: "sha1", value: "a".repeat(40) },
          head_state_hash: `sha256:${"9".repeat(64)}`,
          tracked_diff_hash: `sha256:${"a".repeat(64)}`,
          staged_diff_hash: `sha256:${"b".repeat(64)}`,
          untracked_content_hash: `sha256:${"c".repeat(64)}`,
          submodule_state_hash: `sha256:${"d".repeat(64)}`,
          repository_state_hash: `sha256:${"e".repeat(64)}`,
        },
      },
      protection: {
        delegation_mode: "none",
        action_approval_policy: {
          registry_version: "0.1",
          policy_digest: `sha256:${"f".repeat(64)}`,
          classifier_registry: {
            registry_version: "0.1",
            rules: [{
              rule_version: "0.1",
              key: {
                action_class: "task", dispatch_kind: "process", adapter_ref: "codex-cli",
                adapter_version_hash: `sha256:${"1".repeat(64)}`, capability_ref: "local-read",
                capability_definition_hash: `sha256:${"2".repeat(64)}`, operation: "read",
                effective_risk_tier: "T2", effect_classes: ["none"], all_effects_inspectable: true,
                all_effects_reversible: true, data_access_mode: "local", repository_transition_intent: "none", cost_mode: "none",
              },
              policy_action_kind: "local-read", action_approval_class: "automatic", rule_hash: `sha256:${"3".repeat(64)}`,
            }],
            registry_hash: `sha256:${"4".repeat(64)}`,
          },
          entries: [{ action_kind: "local-read", approval_class: "automatic", classifier_rule_hash: `sha256:${"3".repeat(64)}` }],
          human_exception_action_kinds: ["authenticated-write", "commit", "deploy", "destructive-action", "irreversible-action", "merge", "new-secret-scope", "package-change", "protected-ref-mutation", "publish", "push", "rebase", "release", "send", "t4-action"],
          blocked_action_kinds: ["approval-contract-edit", "connector-admin", "connector-delete", "force-push", "policy-weakening", "self-widening", "t5-action", "uninspectable-side-effect"],
          registry_hash: `sha256:${"4".repeat(64)}`,
        },
        planning_approval_hash: `sha256:${"5".repeat(64)}`,
        invalidation_rules: ["spec-subject-changed", "compile-subject-changed", "plan-hash-changed", "planning-approval-changed", "policy-digest-changed", "repository-root-changed", "repository-base-ref-changed", "repository-state-chain-broken", "authorized-change-set-mismatched", "tool-definition-changed", "authority-revoked", "authority-expired"],
        human_exception_destination: { operator_role_ref: "builder", operator_actor_ref: "actor_builder", operator_stable_identity_hash: `sha256:${"7".repeat(64)}` },
      },
      policy_digest: `sha256:${"f".repeat(64)}`,
    },
    role_assignments: [{
      role_ref: "builder",
      actor_ref: "actor_builder",
      actor_kind: "agent",
      stable_identity_hash: `sha256:${"7".repeat(64)}`,
    }],
    tool_grants: [],
    workspace_boundary: { workspace_root: "/tmp/workspace", read: ["."], write: ["artifacts"] },
    adapter_plan: { engine: "codex_cli", command: "codex exec --json", permission_mode: "workspace-write", known_gaps: [] },
    risk_controls: { max_tier_without_approval: "T2", t5_allowed: false },
  };
}

function baseInput(): ProgressEvaluationInputV02 {
  return {
    plan: validResolvedRunPlanV02(),
    run_id: "run_progress_v02",
    plan_hash: `sha256:${"8".repeat(64)}`,
    ledger_sequence: 4,
    ledger_head_hash: `sha256:${"9".repeat(64)}`,
    completed_loop_attempts: 3,
    observations: [
      {
        schema_version: "0.2",
        event_id: "event_progress_1",
        run_id: "run_progress_v02",
        sequence: 2,
        recorded_at: "2026-08-03T12:00:01Z",
        event_type: "task.progress-observed",
        source: "evaluator",
        authority_ref: null,
        risk_tier: "T2",
        payload: {
          observation_ref: "progress-main",
          task_ref: null,
          pending_attempt_ordinal: 1,
          sample: {
            status: "source-present",
            sample_ref: { record_kind: "evaluation-result", record_id: "evaluation_result_1", record_event_ref: { ledger_sequence: 1, event_hash: `sha256:${"a".repeat(64)}` } },
            sample_hash: `sha256:${"a".repeat(64)}`,
            value_status: "parseable",
            sample_value: 1,
          },
        },
        related_ids: [],
        previous_event_hash: null,
        event_hash: `sha256:${"b".repeat(64)}`,
      },
      {
        schema_version: "0.2",
        event_id: "event_progress_2",
        run_id: "run_progress_v02",
        sequence: 3,
        recorded_at: "2026-08-03T12:00:02Z",
        event_type: "task.progress-observed",
        source: "evaluator",
        authority_ref: null,
        risk_tier: "T2",
        payload: {
          observation_ref: "progress-main",
          task_ref: null,
          pending_attempt_ordinal: 2,
          sample: {
            status: "source-missing",
            sample_ref: null,
            sample_hash: null,
            value_status: "value-unparseable",
            sample_value: null,
          },
        },
        related_ids: [],
        previous_event_hash: `sha256:${"b".repeat(64)}`,
        event_hash: `sha256:${"c".repeat(64)}`,
      },
      {
        schema_version: "0.2",
        event_id: "event_progress_3",
        run_id: "run_progress_v02",
        sequence: 4,
        recorded_at: "2026-08-03T12:00:03Z",
        event_type: "task.progress-observed",
        source: "evaluator",
        authority_ref: null,
        risk_tier: "T2",
        payload: {
          observation_ref: "progress-main",
          task_ref: null,
          pending_attempt_ordinal: 3,
          sample: {
            status: "source-present",
            sample_ref: { record_kind: "evaluation-result", record_id: "evaluation_result_3", record_event_ref: { ledger_sequence: 3, event_hash: `sha256:${"d".repeat(64)}` } },
            sample_hash: `sha256:${"d".repeat(64)}`,
            value_status: "parseable",
            sample_value: 1,
          },
        },
        related_ids: [],
        previous_event_hash: `sha256:${"c".repeat(64)}`,
        event_hash: `sha256:${"e".repeat(64)}`,
      },
    ],
  };
}

function validatedInput(input: ProgressEvaluationInputV02): ValidatedRuntimeProjectionInputV02 {
  return input as ValidatedRuntimeProjectionInputV02;
}

describe("S35 pure progress evaluation", () => {
  it("uses UTF-8 byte ordering independently of the ASCII-only HumanId grammar", () => {
    expect(compareRuntimeUtf8BytesV02("\u{10000}", "\uE000")).toBeGreaterThan(0);
  });

  it("enforces progress-fact string UTF-8 bounds", () => {
    expect(TaskProgressFactsV02.safeParse({ detail: "x".repeat(16_384) }).success).toBe(true);
    expect(TaskProgressFactsV02.safeParse({ detail: "x".repeat(16_385) }).success).toBe(false);
  });

  it("enforces the complete progress-fact serialized ceiling", () => {
    expect(TaskProgressFactsV02.safeParse({
      alpha: "x".repeat(14_000),
      bravo: "x".repeat(14_000),
      charlie: "x".repeat(14_000),
      delta: "x".repeat(14_000),
      echo: "x".repeat(14_000),
    }).success).toBe(false);
  });

  it("rejects prototyped and accessor progress facts without throwing", () => {
    const prototyped = Object.assign(Object.create({ inherited: 1 }) as object, { score: 1 });
    const accessor = Object.defineProperty({}, "score", {
      enumerable: true,
      get() {
        throw new Error("fact getter must not escape");
      },
    });

    expect(TaskProgressFactsV02.safeParse(prototyped).success).toBe(false);
    expect(() => TaskProgressFactsV02.safeParse(accessor)).not.toThrow();
    expect(TaskProgressFactsV02.safeParse(accessor).success).toBe(false);
  });

  it("rejects unsafe numeric progress samples", () => {
    expect(ProgressSampleV02.safeParse({
      status: "source-present",
      sample_ref: { ledger_sequence: 1, event_hash: `sha256:${"a".repeat(64)}` },
      sample_hash: `sha256:${"a".repeat(64)}`,
      value_status: "parseable",
      sample_value: Number.MAX_SAFE_INTEGER + 1,
    }).success).toBe(false);
  });

  it("enforces the progress-fact event source and authority row", () => {
    const event = {
      schema_version: "0.2",
      event_id: "event_fact_1",
      run_id: "run_progress_v02",
      sequence: 3,
      recorded_at: "2026-08-03T12:00:01Z",
      event_type: "task.progress-fact-recorded",
      source: "kernel",
      authority_ref: "authority_wrong",
      risk_tier: "T2",
      payload: {
        action_id: "action_1",
        task_ref: "task-main",
        adapter_invocation_id: "adapter_invocation_1",
        result_event_ref: { ledger_sequence: 2, event_hash: `sha256:${"a".repeat(64)}` },
        facts: { score: 1 },
      },
      related_ids: [],
      previous_event_hash: `sha256:${"b".repeat(64)}`,
      event_hash: `sha256:${"c".repeat(64)}`,
    };

    expect(TaskProgressFactRecordedEventV02.safeParse(event).success).toBe(false);
    expect(TaskProgressFactRecordedEventV02.safeParse({
      ...event,
      source: "adapter",
      authority_ref: null,
    }).success).toBe(true);
  });

  it("rejects a progress observation whose record source is not earlier", () => {
    const event = baseInput().observations[0]!;
    const sample = event.payload.sample;
    if (sample.status !== "source-present" || !("record_kind" in sample.sample_ref)) {
      throw new Error("test fixture must use a record dependency source");
    }
    const invalid = {
      ...event,
      payload: {
        ...event.payload,
        sample: {
          ...sample,
          sample_ref: {
            ...sample.sample_ref,
            record_event_ref: {
              ...sample.sample_ref.record_event_ref,
              ledger_sequence: event.sequence,
            },
          },
        },
      },
    };

    expect(TaskProgressObservedEventV02.safeParse(invalid).success).toBe(false);
  });

  it("rejects hostile and structural inputs at the branded public boundary", () => {
    const hostile = new Proxy({}, {
      get() {
        throw new Error("caller trap must not escape");
      },
      ownKeys() {
        throw new Error("caller trap must not escape");
      },
    });

    expect(() => evaluateProgressV02(hostile as ValidatedRuntimeProjectionInputV02)).not.toThrow();
    expect(evaluateProgressV02(hostile as ValidatedRuntimeProjectionInputV02)).toEqual({
      ok: false,
      error: "PLAN_OR_LEDGER_LINEAGE_INVALID",
    });
  });

  it("rejects a progress input whose run_id differs from plan.run_id", () => {
    const input = baseInput();
    input.run_id = "run_other_v02";

    expect(deriveProgressV02ForRuntime(validatedInput(input))).toEqual({
      ok: false,
      error: "PLAN_OR_LEDGER_LINEAGE_INVALID",
    });
  });

  it("does not mutate the admitted progress projection", () => {
    const input = baseInput();
    const before = structuredClone(input);
    deriveProgressV02ForRuntime(validatedInput(input));
    expect(input).toEqual(before);
  });

  it("tracks baseline, unparseable suffixes, and stalled unchanged progress", () => {
    const result = deriveProgressV02ForRuntime(validatedInput(baseInput()));

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.observations).toEqual([{
      ref: "progress-main",
      completed_loop_attempts: 3,
      parseable_sample_count: 2,
      baseline_ref: { ledger_sequence: 2, event_hash: `sha256:${"b".repeat(64)}` },
      latest_ref: { ledger_sequence: 4, event_hash: `sha256:${"e".repeat(64)}` },
      comparison: "unchanged",
      target_reached: false,
      stalled: true,
    }]);
  });

  it("resets the stall counter on improvement and marks targets reached", () => {
    const input = baseInput();
    input.ledger_sequence = 6;
    input.completed_loop_attempts = 4;
    input.ledger_head_hash = `sha256:${"f".repeat(64)}`;
    input.observations.push({
      schema_version: "0.2",
      event_id: "event_progress_4",
      run_id: "run_progress_v02",
      sequence: 6,
      recorded_at: "2026-08-03T12:00:04Z",
      event_type: "task.progress-observed",
      source: "evaluator",
      authority_ref: null,
      risk_tier: "T2",
      payload: {
        observation_ref: "progress-main",
        task_ref: null,
        pending_attempt_ordinal: 4,
        sample: {
          status: "source-present",
          sample_ref: { record_kind: "evaluation-result", record_id: "evaluation_result_4", record_event_ref: { ledger_sequence: 5, event_hash: `sha256:${"1".repeat(64)}` } },
          sample_hash: `sha256:${"1".repeat(64)}`,
          value_status: "parseable",
          sample_value: 3,
        },
      },
      related_ids: [],
      previous_event_hash: `sha256:${"e".repeat(64)}`,
      event_hash: `sha256:${"2".repeat(64)}`,
    });

    const result = deriveProgressV02ForRuntime(validatedInput(input));

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.observations[0]).toMatchObject({
      parseable_sample_count: 3,
      comparison: "improved",
      target_reached: true,
      stalled: false,
    });
    expect(result.value.observations[0]?.latest_ref).toEqual({
      ledger_sequence: 6,
      event_hash: `sha256:${"2".repeat(64)}`,
    });
  });

  it("keeps equals progress unchanged across two different non-target values", () => {
    const input = baseInput();
    input.plan.progress.observations[0] = {
      ...input.plan.progress.observations[0]!,
      improves_when: { operator: "equals", target: 3 },
      target: { operator: "equals", value: 3 },
    };
    input.observations = [input.observations[0]!, {
      ...input.observations[2]!,
      payload: {
        ...input.observations[2]!.payload,
        sample: {
          ...input.observations[2]!.payload.sample,
          sample_value: 2,
        },
      },
    }];

    const result = deriveProgressV02ForRuntime(validatedInput(input));

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.observations[0]).toMatchObject({
      comparison: "unchanged",
      target_reached: false,
    });
  });

  it("rejects progress observations whose ref is unknown to the plan", () => {
    const input = baseInput();
    input.observations[0] = {
      ...input.observations[0]!,
      payload: {
        ...input.observations[0]!.payload,
        observation_ref: "progress-missing",
      },
    };

    expect(deriveProgressV02ForRuntime(validatedInput(input))).toEqual({
      ok: false,
      error: "SNAPSHOT_COVERAGE_OR_ORDER_INVALID",
    });
  });
});
