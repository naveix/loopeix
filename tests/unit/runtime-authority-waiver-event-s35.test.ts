import type { ZodType } from "zod";
import { describe, expect, it } from "vitest";
import { hashCanonical } from "../../src/hash.js";
import * as runtime from "../../src/schema/runtime.js";

const schemas = runtime as unknown as {
  AuthorityWaiverRecordedEventV02: ZodType;
  PolicyDecisionRecordedEventV02: ZodType;
};
const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;
const ref = (sequence: number) => ({ ledger_sequence: sequence, event_hash: HASH_A });

describe("S35 gate-waiver authority event", () => {
  it("requires an exact no-effect gate-waiver scope and copied scope hash", () => {
    const authorityScope = {
      authority_subject: {
        mission: { objective: "Objective", success_criteria: [{ id: "criterion-main", description: "Done", evaluation_refs: ["evaluation-main"], required: true }], forbidden_outcomes: ["harm"], terminal_states: [
          { state: "completed", condition_mode: "all", conditions: [{ source: "success-criterion", ref: "criterion-main", outcome: "satisfied" }], priority: 100 },
          { state: "held", condition_mode: "any", conditions: [{ source: "gate", ref: "gate-a", outcome: "hold" }], priority: 300 },
          { state: "blocked", condition_mode: "any", conditions: [{ source: "failure", task_ref: "task-main", ref: "contention", outcome: "observed" }], priority: 200 },
          { state: "failed", condition_mode: "any", conditions: [{ source: "failure", task_ref: "task-main", ref: "invalid-input", outcome: "observed" }], priority: 600 },
          { state: "stalled", condition_mode: "any", conditions: [{ source: "progress", ref: "progress-main", outcome: "stalled" }], priority: 400 },
          { state: "exhausted", condition_mode: "any", conditions: [{ source: "limit", ref: "max-loop-attempts", outcome: "reached" }], priority: 500 },
          { state: "aborted", condition_mode: "any", conditions: [{ source: "control", ref: "abort-requested", outcome: "present" }], priority: 700 },
        ] },
        repository: {
          spec_subject: { source_authoring_hash: HASH_A, loopeix_version_hash: HASH_A },
          compile_subject: { compile_pack_manifest_hash: HASH_A, compiler_bundle_id: "bundle_1", catalog_version_hash: HASH_A, binding_input_hash: HASH_A },
          repository_root_ref: "repository_1", object_format: "sha1",
          base_ref: { kind: "git-ref", canonical_ref_name: "refs/heads/main", object_id: { algorithm: "sha1", value: "a".repeat(40) }, identity_hash: HASH_A },
          transition_mode: "read-only",
          initial_state: { repository_root_ref: "repository_1", base_ref_identity_hash: HASH_A, head: { algorithm: "sha1", value: "a".repeat(40) }, merge_base: { algorithm: "sha1", value: "a".repeat(40) }, head_state_hash: HASH_A, tracked_diff_hash: HASH_A, staged_diff_hash: HASH_A, untracked_content_hash: HASH_A, submodule_state_hash: HASH_A, repository_state_hash: HASH_A },
        },
        protection: {
          delegation_mode: "none",
          action_approval_policy: {
            registry_version: "0.1", policy_digest: HASH_A,
            classifier_registry: { registry_version: "0.1", rules: [{ rule_version: "0.1", key: { action_class: "task", dispatch_kind: "process", adapter_ref: "adapter", adapter_version_hash: HASH_A, capability_ref: "capability", capability_definition_hash: HASH_A, operation: "read", effective_risk_tier: "T1", effect_classes: ["none"], all_effects_inspectable: true, all_effects_reversible: true, data_access_mode: "none", repository_transition_intent: "none", cost_mode: "none" }, policy_action_kind: "planning", action_approval_class: "automatic", rule_hash: HASH_A }], registry_hash: HASH_A },
            entries: [{ action_kind: "planning", approval_class: "automatic", classifier_rule_hash: HASH_A }],
            human_exception_action_kinds: ["authenticated-write", "commit", "deploy", "destructive-action", "irreversible-action", "merge", "new-secret-scope", "package-change", "protected-ref-mutation", "publish", "push", "rebase", "release", "send", "t4-action"],
            blocked_action_kinds: ["approval-contract-edit", "connector-admin", "connector-delete", "force-push", "policy-weakening", "self-widening", "t5-action", "uninspectable-side-effect"], registry_hash: HASH_A,
          },
          planning_approval_hash: HASH_A,
          invalidation_rules: ["spec-subject-changed", "compile-subject-changed", "plan-hash-changed", "planning-approval-changed", "policy-digest-changed", "repository-root-changed", "repository-base-ref-changed", "repository-state-chain-broken", "authorized-change-set-mismatched", "tool-definition-changed", "authority-revoked", "authority-expired"],
          human_exception_destination: { operator_role_ref: "operator", operator_actor_ref: "operator_1", operator_stable_identity_hash: HASH_A },
        }, policy_digest: HASH_A,
      },
      action_class: "gate-waiver",
      capability_constraints: [{ classifier_key: { action_class: "task", dispatch_kind: "process", adapter_ref: "adapter", adapter_version_hash: HASH_A, capability_ref: "capability", capability_definition_hash: HASH_A, operation: "read", effective_risk_tier: "T1", effect_classes: ["none"], all_effects_inspectable: true, all_effects_reversible: true, data_access_mode: "none", repository_transition_intent: "none", cost_mode: "none" }, classifier_rule_hash: HASH_A }],
      resource_selectors: [{ kind: "plan-object", object_kind: "gate", object_ref: "gate-a" }],
      operations: ["waive"], max_risk_tier: "T2",
      side_effect_constraints: { allowed_effect_classes: ["none"], allowed_effect_refs: [], require_inspectable: true, require_reversible: true, require_idempotency_key: false, require_compensation: false },
      data_constraints: { readable_classifications: [], exportable_classifications: [], sink_refs: [] },
      bounded_constraints: { max_actions: 1, max_attempts: 1, max_tool_calls: 0, max_output_bytes: 0, max_elapsed_ms: 1000, cost: { capture: "not-applicable", max_cost_minor_units: 0, cost_currency: null }, max_workers: 1, max_decisions: 1, max_delegation_depth: 0 },
    };
    const payload = {
      authority_record_id: "authority_1", record_path: "authority/waiver_1.json", record_hash: HASH_A,
      run_id: "run_main", plan_hash: HASH_A, authority_envelope_ref: { record_kind: "authority-envelope", record_id: "envelope_1", record_event_ref: ref(1) },
      authority_envelope_scope_hash: HASH_A, authority_envelope_revocation_epoch: 0,
      authority_scope: authorityScope, action_scope_hash: hashCanonical(authorityScope), human_authorization_proof_ref: ref(1),
      approval_evidence_refs: [{ record_kind: "human-authorization", record_id: "authorization_1", record_event_ref: ref(1) }],
      minimum_independent_approval_roots: 1, issuer_principal_ref: "principal_1",
      issued_at: "2026-08-10T12:00:00Z", expires_at: "2026-08-10T12:05:00Z",
      revocation_epoch: 0, allowed_gate_refs: ["gate-a"], max_risk_tier: "T2",
    };
    const event = { schema_version: "0.2", event_id: "event_waiver_authority_1", run_id: "run_main", sequence: 2, recorded_at: "2026-08-10T12:00:00Z", event_type: "authority.waiver-recorded", source: "operator", authority_ref: "principal_1", risk_tier: "T4", related_ids: [], previous_event_hash: HASH_A, event_hash: HASH_B, payload };
    const parsed = schemas.AuthorityWaiverRecordedEventV02.safeParse(event);
    expect(parsed.success, parsed.success ? undefined : JSON.stringify(parsed.error.issues, null, 2)).toBe(true);
    expect(schemas.AuthorityWaiverRecordedEventV02.safeParse({ ...event, payload: { ...payload, action_scope_hash: HASH_B } }).success).toBe(false);
    expect(schemas.AuthorityWaiverRecordedEventV02.safeParse({ ...event, payload: { ...payload, allowed_gate_refs: ["gate-b"] } }).success).toBe(false);

    const proposalWithoutHash = {
      proposal_version: "0.2", action_proposal_id: "proposal_1", run_id: "run_main", plan_hash: HASH_A,
      task_ref: "task-main", phase: "work", compensation_ref: null, proposer_actor_ref: "proposer_1",
      proposer_stable_identity_hash: HASH_A, action_actor_ref: "actor_1", action_actor_stable_identity_hash: HASH_A,
      on_behalf_of_chain: [{ principal_ref: "principal_1", stable_identity_hash: HASH_A }],
      on_behalf_of_chain_hash: HASH_A, repository_root_ref: "repository_1",
      repository_base_ref_identity_hash: HASH_A, repository_pre_state_hash: HASH_A,
      authorized_change_set: {
        repository_root_ref: "repository_1", base_ref_identity_hash: HASH_A,
        repository_pre_state_hash: HASH_A, transition_mode: "read-only",
        expected_pre_head: { algorithm: "sha1", value: "a".repeat(40) },
        required_post_head: { algorithm: "sha1", value: "a".repeat(40) }, mode: "no-change", changes: [],
      },
      authorized_change_set_hash: HASH_A,
      normalized_dispatch: {
        kind: "process", adapter_ref: "adapter", adapter_version_hash: HASH_A,
        capability_ref: "capability", capability_definition_hash: HASH_A, operation: "read",
        target: { kind: "plan-object", object_kind: "task", object_ref: "task-main" },
        destination: null, input_subject_hashes: [], executable_ref: "executable_1", executable_hash: HASH_A,
        program: "true", argv: [], cwd_identity_hash: HASH_A, environment_hash: HASH_A,
        stdin_hash: null, timeout_ms: 1000, output_limit_bytes: 1024,
      },
      normalized_dispatch_hash: HASH_A, action_scope: authorityScope,
      action_scope_hash: hashCanonical(authorityScope), action_class: "task",
      classification_binding: { classifier_input_hash: HASH_A, classifier_registry_hash: HASH_A, classifier_rule_hash: HASH_A },
      policy_action_kind: "planning", action_approval_class: "automatic",
      side_effect_refs: [{ task_ref: "task-main", effect_ref: "effect-a" }],
      data_flow: { readable_classifications: [], exportable_classifications: [], sink_refs: [], data_access_mode: "none", data_flow_hash: HASH_A },
      effective_risk_tier: "T1", budget_delta: { tool_calls: 0, output_bytes: 0, tokens: 0, cost: { capture: "not-applicable", cost_minor_units: 0, cost_currency: null } },
      postcondition_hashes: [], verifier_refs: [],
    };
    const proposalWithNestedHashes = {
      ...proposalWithoutHash,
      on_behalf_of_chain_hash: hashCanonical({ purpose: "action-on-behalf-of-chain-v02", on_behalf_of_chain: proposalWithoutHash.on_behalf_of_chain }),
      authorized_change_set_hash: hashCanonical({ purpose: "authorized-repository-change-set-v02", ...proposalWithoutHash.authorized_change_set }),
      normalized_dispatch_hash: hashCanonical({ purpose: "normalized-action-dispatch-v02", ...proposalWithoutHash.normalized_dispatch }),
      data_flow: {
        ...proposalWithoutHash.data_flow,
        data_flow_hash: hashCanonical({
          purpose: "action-data-flow-v02",
          readable_classifications: proposalWithoutHash.data_flow.readable_classifications,
          exportable_classifications: proposalWithoutHash.data_flow.exportable_classifications,
          sink_refs: proposalWithoutHash.data_flow.sink_refs,
          data_access_mode: proposalWithoutHash.data_flow.data_access_mode,
        }),
      },
    };
    const actionProposal = {
      ...proposalWithNestedHashes,
      action_proposal_hash: hashCanonical({ purpose: "action-proposal-v02", ...proposalWithNestedHashes }),
    };
    const decisionPayload = {
      policy_decision_id: "decision_1", run_id: "run_main", plan_hash: HASH_A, task_ref: "task-main",
      phase: "work", compensation_ref: null,
      authority_envelope_ref: { record_kind: "authority-envelope", record_id: "envelope_1", record_event_ref: ref(1) },
      action_proposal: actionProposal, action_proposal_id: "proposal_1",
      action_proposal_hash: actionProposal.action_proposal_hash, action_actor_ref: "actor_1",
      action_actor_stable_identity_hash: HASH_A, on_behalf_of_chain_hash: actionProposal.on_behalf_of_chain_hash,
      repository_root_ref: "repository_1", repository_base_ref_identity_hash: HASH_A,
      repository_pre_state_hash: HASH_A, authorized_change_set_hash: actionProposal.authorized_change_set_hash,
      normalized_dispatch_hash: actionProposal.normalized_dispatch_hash,
      action_scope_hash: hashCanonical(authorityScope), action_class: "task", classifier_input_hash: HASH_A,
      classifier_registry_hash: HASH_A, classifier_rule_hash: HASH_A, data_flow_hash: actionProposal.data_flow.data_flow_hash,
      policy_action_kind: "planning", action_approval_class: "automatic", reviewed_through_ref: ref(1),
      quorum_requirement_hash: null, recommendation_event_refs: [], condition_hashes: [], failed_condition_hashes: [],
      decision: "allow", decision_disposition: "lease-eligible", policy_digest: HASH_A,
      reason_codes: [{ policy_digest: HASH_A, declaration_ref: "automatic-allow" }], evidence_refs: [],
      issued_at: "2026-08-10T12:00:00Z", expires_at: "2026-08-10T12:05:00Z", revocation_epoch: 0,
    };
    const decisionEvent = {
      ...event, event_id: "event_policy_1", event_type: "policy.decision-recorded",
      source: "policy-enforcement-point", authority_ref: "authority_pep", payload: decisionPayload,
    };
    expect(schemas.PolicyDecisionRecordedEventV02.safeParse(decisionEvent).success).toBe(true);
    expect(schemas.PolicyDecisionRecordedEventV02.safeParse({
      ...decisionEvent, payload: { ...decisionPayload, decision_disposition: "proposal-final" },
    }).success).toBe(false);
  });
});
