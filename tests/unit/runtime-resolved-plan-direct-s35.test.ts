import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  parseResolvedRunPlanDocument,
  ResolvedRunPlan,
  ResolvedRunPlanV01,
  ResolvedRunPlanV02,
} from "../../src/schema/runtime.js";

const runtimeFixture = JSON.parse(
  readFileSync(join(import.meta.dirname, "../fixtures/valid/runtime/resolved-run-plan-minimal-bugfix.json"), "utf8"),
) as Record<string, unknown>;

function validResolvedRunPlanV02(): Record<string, unknown> {
  return {
    schema_version: "0.2",
    execution_profile: "bounded-v02",
    run_id: "run_minimal_v02",
    loop_family: "minimal-loop",
    loopeix_version: "v001",
    loopeix_version_hash: `sha256:${"1".repeat(64)}`,
    source_authoring_hash: `sha256:${"2".repeat(64)}`,
    compiler_bundle_id: "bundle_minimal_v02",
    catalog_version_hash: `sha256:${"3".repeat(64)}`,
    binding_input_id: "binding_minimal_v02",
    binding_input_hash: `sha256:${"4".repeat(64)}`,
    compile_pack_manifest_hash: `sha256:${"5".repeat(64)}`,
    work_item_id: "wi_minimal_v02",
    intake_brief_id: "brief_minimal_v02",
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
      artifacts: ["artifact-main"],
      depends_on: [],
      acceptance_checks: ["Evaluation passes."],
      kind: "work",
      pre_task_gate_refs: ["gate-approval"],
    }],
    artifacts: [{
      id: "artifact-main",
      path: "artifacts/content/result.txt",
      type: "text",
      required: true,
      producer_task: "task-main",
      acceptance_checks: ["Written once."],
    }],
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
      max_loop_attempts: 3,
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
      max_evidence_records: 58,
      max_task_result_records: 1,
      max_manual_observation_records: 58,
      max_export_decision_records: 59,
      max_claim_records: 3,
      max_finding_records: 42,
      max_waiver_records: 1,
      max_preseal_custody_events: 118,
    },
    required_control_plane_output_bytes: 512,
    assurance_profile: { id: "base", tightens: [] },
    context_snapshot: { required: [], forbidden: [], untrusted_sources: [] },
    authority_subject: {
      mission: {
        objective: "Complete the bounded task.",
        success_criteria: [{
          id: "criterion-main",
          description: "Primary evaluation passes.",
          evaluation_refs: ["evaluation-main"],
          required: true,
        }],
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
        spec_subject: {
          source_authoring_hash: `sha256:${"2".repeat(64)}`,
          loopeix_version_hash: `sha256:${"1".repeat(64)}`,
        },
        compile_subject: {
          compile_pack_manifest_hash: `sha256:${"5".repeat(64)}`,
          compiler_bundle_id: "bundle_minimal_v02",
          catalog_version_hash: `sha256:${"3".repeat(64)}`,
          binding_input_hash: `sha256:${"4".repeat(64)}`,
        },
        repository_root_ref: "repository_root_minimal",
        object_format: "sha1",
        base_ref: {
          kind: "git-ref",
          canonical_ref_name: "refs/heads/main",
          object_id: { algorithm: "sha1", value: "a".repeat(40) },
          identity_hash: `sha256:${"8".repeat(64)}`,
        },
        transition_mode: "read-only",
        initial_state: {
          repository_root_ref: "repository_root_minimal",
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
                action_class: "task",
                dispatch_kind: "process",
                adapter_ref: "codex-cli",
                adapter_version_hash: `sha256:${"1".repeat(64)}`,
                capability_ref: "local-read",
                capability_definition_hash: `sha256:${"2".repeat(64)}`,
                operation: "read",
                effective_risk_tier: "T2",
                effect_classes: ["none"],
                all_effects_inspectable: true,
                all_effects_reversible: true,
                data_access_mode: "local",
                repository_transition_intent: "none",
                cost_mode: "none",
              },
              policy_action_kind: "local-read",
              action_approval_class: "automatic",
              rule_hash: `sha256:${"3".repeat(64)}`,
            }],
            registry_hash: `sha256:${"4".repeat(64)}`,
          },
          entries: [{
            action_kind: "local-read",
            approval_class: "automatic",
            classifier_rule_hash: `sha256:${"3".repeat(64)}`,
          }],
          human_exception_action_kinds: ["authenticated-write", "commit", "deploy", "destructive-action", "irreversible-action", "merge", "new-secret-scope", "package-change", "protected-ref-mutation", "publish", "push", "rebase", "release", "send", "t4-action"],
          blocked_action_kinds: ["approval-contract-edit", "connector-admin", "connector-delete", "force-push", "policy-weakening", "self-widening", "t5-action", "uninspectable-side-effect"],
          registry_hash: `sha256:${"4".repeat(64)}`,
        },
        planning_approval_hash: `sha256:${"5".repeat(64)}`,
        invalidation_rules: ["spec-subject-changed", "compile-subject-changed", "plan-hash-changed", "planning-approval-changed", "policy-digest-changed", "repository-root-changed", "repository-base-ref-changed", "repository-state-chain-broken", "authorized-change-set-mismatched", "tool-definition-changed", "authority-revoked", "authority-expired"],
        human_exception_destination: {
          operator_role_ref: "builder",
          operator_actor_ref: "actor_builder",
          operator_stable_identity_hash: `sha256:${"7".repeat(64)}`,
        },
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

describe("S35 resolved-plan direct module runtime dispatch", () => {
  it("does not reflect an unsupported raw schema version in its error", () => {
    const unsupportedVersion = "12345678901234567890.09876543210987654321";
    const parsed = parseResolvedRunPlanDocument({
      ...runtimeFixture,
      schema_version: unsupportedVersion,
    });

    expect(parsed).toEqual({
      ok: false,
      schema_version: null,
      reason: "UNSUPPORTED_SCHEMA_VERSION",
      message: "schema_version is not supported; supported versions are '0.1' and '0.2'.",
    });
    expect(JSON.stringify(parsed)).not.toContain(unsupportedVersion);
  });

  it("returns a closed parser error when hostile proxy ownKeys throws", () => {
    const hostile = new Proxy({}, {
      ownKeys() {
        throw new Error("ownKeys trap must not escape");
      },
    });

    expect(() => parseResolvedRunPlanDocument(hostile)).not.toThrow();
    expect(parseResolvedRunPlanDocument(hostile)).toEqual({
      ok: false,
      schema_version: null,
      reason: "MALFORMED_SCHEMA_VERSION",
      message: "schema_version must be an unmodified major.minor string.",
    });
  });

  it("keeps legacy ResolvedRunPlan compatibility while exposing a literal V01 schema", () => {
    expect(ResolvedRunPlan.safeParse(runtimeFixture).success).toBe(true);
    expect(ResolvedRunPlanV01.safeParse(runtimeFixture).success).toBe(true);
    expect(ResolvedRunPlanV02.safeParse(runtimeFixture).success).toBe(false);
  });

  it("normalizes V01 success to legacy-v01 without rewriting persisted bytes", () => {
    const parsed = parseResolvedRunPlanDocument(runtimeFixture);

    expect(parsed).toMatchObject({
      ok: true,
      schema_version: "0.1",
      execution_profile: "legacy-v01",
    });
    if (parsed.ok) {
      expect(Object.hasOwn(parsed.value, "execution_profile")).toBe(false);
    }
  });

  it("accepts and strips an extra profile-looking V01 key through the family-aware parser", () => {
    const parsed = parseResolvedRunPlanDocument({
      ...runtimeFixture,
      execution_profile: "bounded-v02",
    });
    expect(parsed).toMatchObject({
      ok: true,
      schema_version: "0.1",
      execution_profile: "legacy-v01",
    });
    if (parsed.ok) expect(Object.hasOwn(parsed.value, "execution_profile")).toBe(false);
  });

  it("accepts a strict bounded-v02 resolved run plan", () => {
    const parsed = parseResolvedRunPlanDocument(validResolvedRunPlanV02());

    expect(parsed).toMatchObject({
      ok: true,
      schema_version: "0.2",
      execution_profile: "bounded-v02",
    });
    expect(ResolvedRunPlanV02.safeParse(validResolvedRunPlanV02()).success).toBe(true);
  });

  it("rejects duplicate IDs in plan-owned projected collections", () => {
    const plan = validResolvedRunPlanV02();
    const roles = plan.roles as Record<string, unknown>[];
    plan.roles = [...roles, { ...roles[0] }];

    expect(ResolvedRunPlanV02.safeParse(plan).success).toBe(false);
  });
});
