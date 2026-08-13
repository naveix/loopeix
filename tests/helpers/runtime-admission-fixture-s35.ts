import { hashCanonical } from "../../src/hash.js";
import { hashAuthorityScopeV02 } from "../../src/schema/runtime.js";
import {
  S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
  resolveS35BuiltInActionApprovalPolicyV02,
} from "../../src/run/action-classifier-policy-v02.js";

type LedgerRef = { ledger_sequence: number; event_hash: string };

export type RuntimeLedgerEventV02 = {
  schema_version: "0.2";
  event_id: string;
  run_id: string;
  sequence: number;
  recorded_at: string;
  event_type: string;
  source: string;
  authority_ref: string | null;
  risk_tier: string;
  related_ids: string[];
  previous_event_hash: string | null;
  event_hash: string;
  payload: Record<string, unknown>;
};

const HASH = `sha256:${"a".repeat(64)}`;

const BASE_AUTHORITY_SCOPE = {
  authority_subject: {
    mission: {
      objective: "Objective",
      success_criteria: [{ id: "criterion-main", description: "Done", evaluation_refs: ["evaluation-main"], required: true }],
      forbidden_outcomes: ["harm"],
      terminal_states: [
        { state: "completed", condition_mode: "all", conditions: [{ source: "success-criterion", ref: "criterion-main", outcome: "satisfied" }], priority: 100 },
        { state: "held", condition_mode: "any", conditions: [{ source: "gate", ref: "gate-a", outcome: "hold" }], priority: 300 },
        { state: "blocked", condition_mode: "any", conditions: [{ source: "failure", task_ref: "task-main", ref: "contention", outcome: "observed" }], priority: 200 },
        { state: "failed", condition_mode: "any", conditions: [{ source: "failure", task_ref: "task-main", ref: "invalid-input", outcome: "observed" }], priority: 600 },
        { state: "stalled", condition_mode: "any", conditions: [{ source: "progress", ref: "progress-main", outcome: "stalled" }], priority: 400 },
        { state: "exhausted", condition_mode: "any", conditions: [{ source: "limit", ref: "max-loop-attempts", outcome: "reached" }], priority: 500 },
        { state: "aborted", condition_mode: "any", conditions: [{ source: "control", ref: "abort-requested", outcome: "present" }], priority: 700 },
      ],
    },
    repository: {
      spec_subject: { source_authoring_hash: HASH, loopeix_version_hash: HASH },
      compile_subject: { compile_pack_manifest_hash: HASH, compiler_bundle_id: "bundle_1", catalog_version_hash: HASH, binding_input_hash: HASH },
      repository_root_ref: "repository_1", object_format: "sha1",
      base_ref: { kind: "git-ref", canonical_ref_name: "refs/heads/main", object_id: { algorithm: "sha1", value: "a".repeat(40) }, identity_hash: HASH },
      transition_mode: "read-only",
      initial_state: {
        repository_root_ref: "repository_1", base_ref_identity_hash: HASH,
        head: { algorithm: "sha1", value: "a".repeat(40) }, merge_base: { algorithm: "sha1", value: "a".repeat(40) },
        head_state_hash: HASH, tracked_diff_hash: HASH, staged_diff_hash: HASH, untracked_content_hash: HASH,
        submodule_state_hash: HASH, repository_state_hash: HASH,
      },
    },
    protection: {
      delegation_mode: "none",
      action_approval_policy: {
        registry_version: "0.1", policy_digest: HASH,
        classifier_registry: {
          registry_version: "0.1",
          rules: [{
            rule_version: "0.1", key: {
              action_class: "task", dispatch_kind: "process", adapter_ref: "adapter", adapter_version_hash: HASH,
              capability_ref: "capability", capability_definition_hash: HASH, operation: "read", effective_risk_tier: "T1",
              effect_classes: ["none"], all_effects_inspectable: true, all_effects_reversible: true,
              data_access_mode: "none", repository_transition_intent: "none", cost_mode: "none",
            }, policy_action_kind: "planning", action_approval_class: "automatic", rule_hash: HASH,
          }],
          registry_hash: HASH,
        },
        entries: [{ action_kind: "planning", approval_class: "automatic", classifier_rule_hash: HASH }],
        human_exception_action_kinds: ["authenticated-write", "commit", "deploy", "destructive-action", "irreversible-action", "merge", "new-secret-scope", "package-change", "protected-ref-mutation", "publish", "push", "rebase", "release", "send", "t4-action"],
        blocked_action_kinds: ["approval-contract-edit", "connector-admin", "connector-delete", "force-push", "policy-weakening", "self-widening", "t5-action", "uninspectable-side-effect"], registry_hash: HASH,
      },
      planning_approval_hash: HASH,
      invalidation_rules: ["spec-subject-changed", "compile-subject-changed", "plan-hash-changed", "planning-approval-changed", "policy-digest-changed", "repository-root-changed", "repository-base-ref-changed", "repository-state-chain-broken", "authorized-change-set-mismatched", "tool-definition-changed", "authority-revoked", "authority-expired"],
      human_exception_destination: { operator_role_ref: "operator", operator_actor_ref: "operator_1", operator_stable_identity_hash: HASH },
    },
    policy_digest: HASH,
  },
  action_class: "gate-waiver",
  capability_constraints: [{
    classifier_key: {
      action_class: "task", dispatch_kind: "process", adapter_ref: "adapter", adapter_version_hash: HASH,
      capability_ref: "capability", capability_definition_hash: HASH, operation: "read", effective_risk_tier: "T1",
      effect_classes: ["none"], all_effects_inspectable: true, all_effects_reversible: true,
      data_access_mode: "none", repository_transition_intent: "none", cost_mode: "none",
    },
    classifier_rule_hash: HASH,
  }],
  resource_selectors: [{ kind: "plan-object", object_kind: "gate", object_ref: "gate-a" }],
  operations: ["waive"], max_risk_tier: "T2",
  side_effect_constraints: { allowed_effect_classes: ["none"], allowed_effect_refs: [], require_inspectable: true, require_reversible: true, require_idempotency_key: false, require_compensation: false },
  data_constraints: { readable_classifications: [], exportable_classifications: [], sink_refs: [] },
  bounded_constraints: { max_actions: 1, max_attempts: 1, max_tool_calls: 0, max_output_bytes: 0, max_elapsed_ms: 1000, cost: { capture: "not-applicable", max_cost_minor_units: 0, cost_currency: null }, max_workers: 1, max_decisions: 1, max_delegation_depth: 0 },
};

/** Returns a private clone so one test cannot mutate another test's authority fixture. */
export function createBaseAuthorityScopeFixtureS35(): Record<string, unknown> {
  return structuredClone(BASE_AUTHORITY_SCOPE) as Record<string, unknown>;
}

function ledgerRef(sequence: number, eventHash: string): LedgerRef {
  return { ledger_sequence: sequence, event_hash: eventHash };
}

function timestamp(sequence: number): string {
  return `2026-08-10T12:00:${String(sequence).padStart(2, "0")}Z`;
}

function seal<T extends Omit<RuntimeLedgerEventV02, "event_hash">>(event: T): RuntimeLedgerEventV02 {
  return { ...event, event_hash: hashCanonical(event) };
}

function buildEnvelopePayload(
  subjectRef: string,
  authorityRef: string,
  actionScope: Record<string, unknown>,
  authorityEnvelopeId: string,
  authorizationRef: LedgerRef,
): Record<string, unknown> {
  return {
    authority_envelope_id: authorityEnvelopeId,
    record_path: "authority/envelope_1.json",
    record_hash: HASH,
    run_id: "run_main",
    plan_hash: HASH,
    policy_digest: HASH,
    subject_ref: subjectRef,
    issuer_principal_ref: authorityRef,
    authorization_subject_hash: HASH,
    human_authorization_proof_refs: [authorizationRef],
    action_class: "task",
    action_scope_hash: hashCanonical(actionScope),
    max_risk_tier: "T1",
    issued_at: "2026-08-10T12:00:00Z",
    expires_at: "2026-08-10T12:05:00Z",
    revocation_epoch: 0,
    delegation_depth: 0,
  };
}

function buildProposalPayload(taskRef: string, runId: string, planHash: string, proposalId: string, actionScope: Record<string, unknown>): Record<string, unknown> {
  const proposalWithoutHash = {
    proposal_version: "0.2",
    action_proposal_id: proposalId,
    run_id: runId,
    plan_hash: planHash,
    task_ref: taskRef,
    phase: "work",
    compensation_ref: null,
    proposer_actor_ref: "proposer_1",
    proposer_stable_identity_hash: HASH,
    action_actor_ref: "actor_1",
    action_actor_stable_identity_hash: HASH,
    on_behalf_of_chain: [{ principal_ref: "principal_1", stable_identity_hash: HASH }],
    on_behalf_of_chain_hash: HASH,
    repository_root_ref: "repository_1",
    repository_base_ref_identity_hash: HASH,
    repository_pre_state_hash: HASH,
    authorized_change_set: {
      repository_root_ref: "repository_1",
      base_ref_identity_hash: HASH,
      repository_pre_state_hash: HASH,
      transition_mode: "read-only",
      expected_pre_head: { algorithm: "sha1", value: "a".repeat(40) },
      required_post_head: { algorithm: "sha1", value: "a".repeat(40) },
      mode: "no-change",
      changes: [],
    },
    authorized_change_set_hash: HASH,
    normalized_dispatch: {
      kind: "process",
      adapter_ref: "adapter",
      adapter_version_hash: HASH,
      capability_ref: "capability",
      capability_definition_hash: HASH,
      operation: "read",
      target: { kind: "plan-object", object_kind: "task", object_ref: taskRef },
      destination: null,
      input_subject_hashes: [],
      executable_ref: "executable_1",
      executable_hash: HASH,
      program: "true",
      argv: [],
      cwd_identity_hash: HASH,
      environment_hash: HASH,
      stdin_hash: null,
      timeout_ms: 1000,
      output_limit_bytes: 1024,
    },
    normalized_dispatch_hash: HASH,
    action_scope: actionScope,
    action_scope_hash: hashCanonical(actionScope),
    action_class: "task",
    classification_binding: { classifier_input_hash: HASH, classifier_registry_hash: HASH, classifier_rule_hash: HASH },
    policy_action_kind: "planning",
    action_approval_class: "automatic",
    side_effect_refs: [{ task_ref: taskRef, effect_ref: "effect-a" }],
    data_flow: {
      readable_classifications: [],
      exportable_classifications: [],
      sink_refs: [],
      data_access_mode: "none",
      data_flow_hash: HASH,
    },
    effective_risk_tier: "T1",
    budget_delta: { tool_calls: 0, output_bytes: 0, tokens: 0, cost: { capture: "not-applicable", cost_minor_units: 0, cost_currency: null } },
    postcondition_hashes: [],
    verifier_refs: [],
  } as Record<string, unknown>;

  const proposalWithNestedHashes = {
    ...proposalWithoutHash,
    on_behalf_of_chain_hash: hashCanonical({ purpose: "action-on-behalf-of-chain-v02", on_behalf_of_chain: proposalWithoutHash.on_behalf_of_chain }),
    authorized_change_set_hash: hashCanonical({ purpose: "authorized-repository-change-set-v02", ...proposalWithoutHash.authorized_change_set }),
    normalized_dispatch_hash: hashCanonical({ purpose: "normalized-action-dispatch-v02", ...proposalWithoutHash.normalized_dispatch }),
    data_flow: {
      ...(proposalWithoutHash.data_flow as { readable_classifications: string[]; exportable_classifications: string[]; sink_refs: string[]; data_access_mode: string; data_flow_hash: string }),
      data_flow_hash: hashCanonical({
        purpose: "action-data-flow-v02",
        readable_classifications: proposalWithoutHash.data_flow.readable_classifications,
        exportable_classifications: proposalWithoutHash.data_flow.exportable_classifications,
        sink_refs: proposalWithoutHash.data_flow.sink_refs,
        data_access_mode: proposalWithoutHash.data_flow.data_access_mode,
      }),
    },
  } as Record<string, unknown>;

  const { action_proposal_hash: _ignored, ...proposalHashInput } = proposalWithNestedHashes as { action_proposal_hash?: string } & Record<string, unknown>;
  return {
    ...proposalWithNestedHashes,
    action_proposal_hash: hashCanonical({ purpose: "action-proposal-v02", ...proposalHashInput }),
  };
}

/** Returns one strict agency-classified proposal fixture with fresh nested objects. */
export function createAgencyActionProposalFixtureS35(): Record<string, unknown> {
  const scope = createBaseAuthorityScopeFixtureS35();
  scope.action_class = "task";
  scope.operations = ["read"];
  scope.resource_selectors = [{ kind: "plan-object", object_kind: "task", object_ref: "task-main" }];
  const proposal = buildProposalPayload("task-main", "run_main", HASH, "proposal_1", scope);
  proposal.policy_action_kind = "authenticated-read";
  proposal.action_approval_class = "agency";
  proposal.action_scope_hash = hashAuthorityScopeV02(scope as never);
  const { action_proposal_hash: _ignored, ...preimage } = proposal;
  return {
    ...proposal,
    action_proposal_hash: hashCanonical({ purpose: "action-proposal-v02", ...preimage }),
  };
}

/** Returns a producer-grade S36 authenticated-read proposal with release-pinned policy bytes. */
export function createAgencyActionProposalInputFixtureS36(): Record<string, unknown> {
  const policy = resolveS35BuiltInActionApprovalPolicyV02(S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02);
  if (policy === null) throw new Error("release-pinned S35 policy must resolve");
  const rule = policy.classifier_registry.rules.find((candidate) => candidate.policy_action_kind === "authenticated-read");
  if (rule === undefined) throw new Error("release-pinned authenticated-read rule must resolve");
  const scope = createBaseAuthorityScopeFixtureS35();
  const subject = scope.authority_subject as Record<string, unknown>;
  const protection = subject.protection as Record<string, unknown>;
  protection.action_approval_policy = policy;
  subject.policy_digest = policy.policy_digest;
  scope.action_class = "tool";
  scope.capability_constraints = [{ classifier_key: rule.key, classifier_rule_hash: rule.rule_hash }];
  scope.resource_selectors = [{ kind: "plan-object", object_kind: "task", object_ref: "task-main" }];
  scope.operations = ["read"];
  scope.max_risk_tier = "T2";
  scope.bounded_constraints = {
    ...(scope.bounded_constraints as Record<string, unknown>),
    cost: { capture: "required", max_cost_minor_units: 100, cost_currency: "GBP" },
  };
  const proposal = buildProposalPayload("task-main", "run_main", HASH, "proposal_1", scope);
  proposal.action_class = "tool";
  proposal.normalized_dispatch = {
    kind: "tool",
    adapter_ref: rule.key.adapter_ref,
    adapter_version_hash: rule.key.adapter_version_hash,
    capability_ref: rule.key.capability_ref,
    capability_definition_hash: rule.key.capability_definition_hash,
    operation: rule.key.operation,
    target: { kind: "plan-object", object_kind: "task", object_ref: "task-main" },
    destination: null,
    input_subject_hashes: [],
    tool_ref: "authenticated-read-tool",
    tool_definition_hash: rule.key.capability_definition_hash,
    arguments: {},
    arguments_hash: hashCanonical({}),
  };
  proposal.normalized_dispatch_hash = hashCanonical({ purpose: "normalized-action-dispatch-v02", ...(proposal.normalized_dispatch as Record<string, unknown>) });
  proposal.data_flow = {
    readable_classifications: [], exportable_classifications: [], sink_refs: [], data_access_mode: "authenticated",
    data_flow_hash: hashCanonical({ purpose: "action-data-flow-v02", readable_classifications: [], exportable_classifications: [], sink_refs: [], data_access_mode: "authenticated" }),
  };
  proposal.effective_risk_tier = "T2";
  proposal.budget_delta = { tool_calls: 1, output_bytes: 0, tokens: 0, cost: { capture: "required", cost_minor_units: 0, cost_currency: "GBP" } };
  proposal.classification_binding = {
    classifier_input_hash: hashCanonical({ purpose: "action-classifier-input-v1", key: rule.key }),
    classifier_registry_hash: policy.classifier_registry.registry_hash,
    classifier_rule_hash: rule.rule_hash,
  };
  proposal.policy_action_kind = rule.policy_action_kind;
  proposal.action_approval_class = rule.action_approval_class;
  proposal.action_scope_hash = hashAuthorityScopeV02(scope as never);
  const { action_proposal_hash: _ignored, ...preimage } = proposal;
  return { ...proposal, action_proposal_hash: hashCanonical({ purpose: "action-proposal-v02", ...preimage }) };
}

function finalizeAgencyRecommendationRecordS36(recommendation: Record<string, unknown>): Record<string, unknown> {
  const subjectHash = hashCanonical({
    purpose: "agency-recommendation-subject-v02",
    run_id: recommendation.run_id, plan_hash: recommendation.plan_hash,
    task_ref: recommendation.task_ref, phase: recommendation.phase,
    compensation_ref: recommendation.compensation_ref,
    action_proposal_id: recommendation.action_proposal_id,
    action_proposal_hash: recommendation.action_proposal_hash,
    proposer_actor_ref: recommendation.proposer_actor_ref,
    proposer_stable_identity_hash: recommendation.proposer_stable_identity_hash,
    action_actor_ref: recommendation.action_actor_ref,
    action_actor_stable_identity_hash: recommendation.action_actor_stable_identity_hash,
    on_behalf_of_chain_hash: recommendation.on_behalf_of_chain_hash,
    repository_root_ref: recommendation.repository_root_ref,
    repository_base_ref_identity_hash: recommendation.repository_base_ref_identity_hash,
    repository_pre_state_hash: recommendation.repository_pre_state_hash,
    authorized_change_set_hash: recommendation.authorized_change_set_hash,
    normalized_dispatch_hash: recommendation.normalized_dispatch_hash,
    action_scope_hash: recommendation.action_scope_hash,
    action_class: recommendation.action_class,
    classifier_input_hash: recommendation.classifier_input_hash,
    classifier_registry_hash: recommendation.classifier_registry_hash,
    classifier_rule_hash: recommendation.classifier_rule_hash,
    data_flow_hash: recommendation.data_flow_hash,
    policy_action_kind: recommendation.policy_action_kind,
    action_approval_class: recommendation.action_approval_class,
    quorum_requirement_hash: recommendation.quorum_requirement_hash,
    policy_digest: recommendation.policy_digest,
    reviewed_through_ref: recommendation.reviewed_through_ref,
  });
  const base = { ...recommendation, recommendation_subject_hash: subjectHash };
  const attestation = base.producer_attestation as Record<string, unknown>;
  const { record_hash: _recordHash, producer_attestation: _producerAttestation, ...withoutAttestation } = base;
  const statementHash = hashCanonical({
    ...withoutAttestation,
    producer_attestation: { signer_key_ref: attestation.signer_key_ref, signature_algorithm: attestation.signature_algorithm },
  });
  const withAttestation = { ...base, producer_attestation: { ...attestation, statement_hash: statementHash } };
  delete withAttestation.record_hash;
  return { ...withAttestation, record_hash: hashCanonical(withAttestation) };
}

/** Returns one self-consistent S36 agency-recommendation record fixture. */
export function createAgencyRecommendationRecordFixtureS36(
  options: Readonly<{ conditional?: boolean; evidence_record_kind?: "evidence" | "human-authorization" }> = {},
): Record<string, unknown> {
  const proposal = createAgencyActionProposalFixtureS35();
  const binding = proposal.classification_binding as Record<string, unknown>;
  const flow = proposal.data_flow as Record<string, unknown>;
  const policyDigest = ((proposal.action_scope as Record<string, unknown>).authority_subject as Record<string, unknown>).policy_digest;
  return finalizeAgencyRecommendationRecordS36({
    schema_version: "0.2", recommendation_id: "recommendation_1",
    run_id: proposal.run_id, plan_hash: proposal.plan_hash, task_ref: proposal.task_ref,
    phase: proposal.phase, compensation_ref: proposal.compensation_ref, action_proposal: proposal,
    action_proposal_id: proposal.action_proposal_id, action_proposal_hash: proposal.action_proposal_hash,
    proposer_actor_ref: proposal.proposer_actor_ref, proposer_stable_identity_hash: proposal.proposer_stable_identity_hash,
    action_actor_ref: proposal.action_actor_ref, action_actor_stable_identity_hash: proposal.action_actor_stable_identity_hash,
    on_behalf_of_chain_hash: proposal.on_behalf_of_chain_hash, repository_root_ref: proposal.repository_root_ref,
    repository_base_ref_identity_hash: proposal.repository_base_ref_identity_hash,
    repository_pre_state_hash: proposal.repository_pre_state_hash,
    authorized_change_set_hash: proposal.authorized_change_set_hash,
    normalized_dispatch_hash: proposal.normalized_dispatch_hash, action_scope: proposal.action_scope,
    action_scope_hash: proposal.action_scope_hash, action_class: proposal.action_class,
    classifier_input_hash: binding.classifier_input_hash, classifier_registry_hash: binding.classifier_registry_hash,
    classifier_rule_hash: binding.classifier_rule_hash, data_flow_hash: flow.data_flow_hash,
    policy_action_kind: proposal.policy_action_kind, action_approval_class: proposal.action_approval_class,
    recommendation_subject_hash: HASH, quorum_requirement_hash: HASH, policy_digest: policyDigest,
    reviewed_through_ref: { ledger_sequence: 2, event_hash: HASH },
    evidence_refs: [{
      record_kind: options.evidence_record_kind ?? "evidence",
      record_id: "evidence_1",
      record_event_ref: { ledger_sequence: 1, event_hash: HASH },
    }],
    evidence_independence_keys: [HASH], evaluator_role_ref: "security-reviewer",
    evaluator_actor_ref: "reviewer_1", evaluator_stable_identity_hash: `sha256:${"5".repeat(64)}`,
    evaluator_authentication_context_hash: HASH,
    decision: options.conditional === true ? "allow_with_conditions" : "allow",
    conditions: options.conditional === true ? [{ kind: "require-gate-pass", gate_ref: "gate-main" }] : [],
    reason_codes: [{ policy_digest: policyDigest, declaration_ref: "agency-allow" }],
    issued_at: "2026-08-13T12:01:00Z", expires_at: "2026-08-13T12:04:00Z",
    producer_attestation: { signer_key_ref: "reviewer_key_1", signature_algorithm: "ed25519", statement_hash: HASH, signature_value: "c2ln" },
    record_hash: HASH,
  });
}

/** Returns one self-consistent S36 authority-revocation record fixture. */
export function createAuthorityRevocationRecordFixtureS36(): Record<string, unknown> {
  const base = {
    schema_version: "0.2", revocation_id: "revocation_1", run_id: "run_main", plan_hash: HASH,
    target: {
      kind: "authority-envelope",
      target_ref: { record_kind: "authority-envelope", record_id: "envelope_1", record_event_ref: { ledger_sequence: 1, event_hash: HASH } },
      target_scope_hash: HASH,
    },
    previous_revocation_epoch: 0, revocation_epoch: 1,
    effective_prefix_ref: { ledger_sequence: 2, event_hash: HASH }, reason_code: "operator-revoked",
    evidence_refs: [{ record_kind: "human-authorization", record_id: "authorization_1", record_event_ref: { ledger_sequence: 1, event_hash: HASH } }],
    revoker_kind: "operator", revoker_identity_ref: "operator_1", revoker_stable_identity_hash: HASH,
    revoker_authentication_context_hash: HASH, policy_digest: HASH, revoked_at: "2026-08-13T12:02:00Z",
    producer_attestation: { signer_key_ref: "operator_key_1", signature_algorithm: "ed25519", statement_hash: HASH, signature_value: "c2ln" },
  } as Record<string, unknown>;
  const attestation = base.producer_attestation as Record<string, unknown>;
  const statementHash = hashCanonical({
    ...base,
    producer_attestation: { signer_key_ref: attestation.signer_key_ref, signature_algorithm: attestation.signature_algorithm },
  });
  const withStatement = { ...base, producer_attestation: { ...attestation, statement_hash: statementHash } };
  return { ...withStatement, record_hash: hashCanonical(withStatement) };
}

function buildDecisionPayload(
  taskRef: string,
  runId: string,
  planHash: string,
  decisionId: string,
  decisionAuthorization: LedgerRef,
  envelopeSeq: number,
  envelopeEventHash: string,
  actionProposal: Record<string, unknown>,
): Record<string, unknown> {
  return {
    policy_decision_id: decisionId,
    run_id: runId,
    plan_hash: planHash,
    task_ref: taskRef,
    phase: "work",
    compensation_ref: null,
    authority_envelope_ref: { record_kind: "authority-envelope", record_id: "envelope_1", record_event_ref: ledgerRef(envelopeSeq, envelopeEventHash) },
    action_proposal: actionProposal,
    action_proposal_id: actionProposal.action_proposal_id,
    action_proposal_hash: actionProposal.action_proposal_hash,
    action_actor_ref: actionProposal.action_actor_ref,
    action_actor_stable_identity_hash: actionProposal.action_actor_stable_identity_hash,
    on_behalf_of_chain_hash: actionProposal.on_behalf_of_chain_hash,
    repository_root_ref: actionProposal.repository_root_ref,
    repository_base_ref_identity_hash: actionProposal.repository_base_ref_identity_hash,
    repository_pre_state_hash: actionProposal.repository_pre_state_hash,
    authorized_change_set_hash: actionProposal.authorized_change_set_hash,
    normalized_dispatch_hash: actionProposal.normalized_dispatch_hash,
    action_scope_hash: actionProposal.action_scope_hash,
    action_class: actionProposal.action_class,
    classifier_input_hash: actionProposal.classification_binding.classifier_input_hash,
    classifier_registry_hash: actionProposal.classification_binding.classifier_registry_hash,
    classifier_rule_hash: actionProposal.classification_binding.classifier_rule_hash,
    data_flow_hash: actionProposal.data_flow.data_flow_hash,
    policy_action_kind: "planning",
    action_approval_class: "automatic",
    reviewed_through_ref: decisionAuthorization,
    quorum_requirement_hash: null,
    recommendation_event_refs: [],
    condition_hashes: [],
    failed_condition_hashes: [],
    decision: "allow",
    decision_disposition: "lease-eligible",
    policy_digest: HASH,
    reason_codes: [{ policy_digest: HASH, declaration_ref: "automatic-allow" }],
    evidence_refs: [],
    issued_at: "2026-08-10T12:00:00Z",
    expires_at: "2026-08-10T12:05:00Z",
    revocation_epoch: 0,
  };
}

export interface WorkActionAdmissionResult {
  events: RuntimeLedgerEventV02[];
  lease: RuntimeLedgerEventV02;
  clock: RuntimeLedgerEventV02;
  admission: RuntimeLedgerEventV02;
}

function appendEvent(base: RuntimeLedgerEventV02[], eventType: string, source: string, authorityRef: string | null, payload: Record<string, unknown>, riskTier: string): RuntimeLedgerEventV02 {
  const previous = base.at(-1);
  if (previous === undefined) {
    throw new Error("appendEvent requires a prior ledger event");
  }
  const sequence = base.length + 1;
  const event = {
    schema_version: "0.2" as const,
    event_id: `event_${sequence}`,
    run_id: previous.run_id,
    sequence,
    recorded_at: timestamp(sequence),
    event_type: eventType,
    source,
    authority_ref: authorityRef,
    risk_tier: riskTier,
    related_ids: [],
    previous_event_hash: previous.event_hash,
    payload,
  } as Omit<RuntimeLedgerEventV02, "event_hash">;
  const sealed = seal(event);
  base.push(sealed);
  return sealed;
}

function extractProposalBindings(proposal: Record<string, unknown>) {
  const typed = proposal as {
    action_proposal_id: string;
    action_proposal_hash: string;
    action_actor_ref: string;
    action_actor_stable_identity_hash: string;
    on_behalf_of_chain_hash: string;
    repository_root_ref: string;
    repository_base_ref_identity_hash: string;
    repository_pre_state_hash: string;
    authorized_change_set_hash: string;
    normalized_dispatch_hash: string;
    action_scope_hash: string;
    action_class: "task" | "tool" | "artifact-write";
    classification_binding: { classifier_input_hash: string; classifier_registry_hash: string; classifier_rule_hash: string };
    data_flow: { data_flow_hash: string };
    policy_action_kind: string;
    action_approval_class: string;
  };
  return {
    action_proposal_id: typed.action_proposal_id,
    action_proposal_hash: typed.action_proposal_hash,
    action_actor_ref: typed.action_actor_ref,
    action_actor_stable_identity_hash: typed.action_actor_stable_identity_hash,
    on_behalf_of_chain_hash: typed.on_behalf_of_chain_hash,
    repository_root_ref: typed.repository_root_ref,
    repository_base_ref_identity_hash: typed.repository_base_ref_identity_hash,
    repository_pre_state_hash: typed.repository_pre_state_hash,
    authorized_change_set_hash: typed.authorized_change_set_hash,
    normalized_dispatch_hash: typed.normalized_dispatch_hash,
    action_scope_hash: typed.action_scope_hash,
    action_class: typed.action_class,
    classifier_input_hash: typed.classification_binding.classifier_input_hash,
    classifier_registry_hash: typed.classification_binding.classifier_registry_hash,
    classifier_rule_hash: typed.classification_binding.classifier_rule_hash,
    data_flow_hash: typed.data_flow.data_flow_hash,
    policy_action_kind: typed.policy_action_kind,
    action_approval_class: typed.action_approval_class,
  } as const;
}

export function appendWorkActionAdmissionEvents(
  base: RuntimeLedgerEventV02[],
  options: {
    taskRef?: string;
    actionId?: string;
    leaseId?: string;
    proposalId?: string;
    decisionId?: string;
    authorityScopeRef?: string;
    authorityRef?: string;
    planHash?: string;
  } = {},
): WorkActionAdmissionResult {
  const output = base;
  if (output.length === 0) {
    throw new Error("appendWorkActionAdmissionEvents requires at least the initialized event");
  }

  const taskRef = options.taskRef ?? "task-main";
  const actionId = options.actionId ?? "action_1";
  const leaseId = options.leaseId ?? "lease_1";
  const proposalId = options.proposalId ?? "proposal_1";
  const decisionId = options.decisionId ?? "decision_1";
  const authorityRef = options.authorityRef ?? "principal_1";
  const authorityScopeRef = options.authorityScopeRef ?? "task_main";
  const firstPayload = output[0]?.payload;
  const planHash = options.planHash ?? String((typeof firstPayload === "object" && firstPayload !== null && "plan_hash" in firstPayload) ? (firstPayload as { plan_hash?: unknown }).plan_hash ?? HASH : HASH);

  const actionScope = JSON.parse(JSON.stringify(BASE_AUTHORITY_SCOPE)) as typeof BASE_AUTHORITY_SCOPE;
  const authorization = appendEvent(output, "authority.human-authorization-recorded", "operator", authorityRef, {
    authorization_id: "authorization_1",
    record_path: "authority/authorization_1.json",
    record_hash: HASH,
    run_id: output[0]!.run_id,
    plan_hash: planHash,
    authorization_subject_hash: HASH,
    authenticated_principal_ref: authorityRef,
    authentication_context_hash: HASH,
    action_scope_hash: hashCanonical(actionScope),
    approved_risk_tier: "T2",
    operator_key_id: "key_1",
    approval_channel: "local-ed25519",
    approval_nonce: HASH,
    proof_algorithm: "ed25519",
    authorization_statement_hash: HASH,
    issued_at: "2026-08-10T12:00:00Z",
    expires_at: "2026-08-10T12:05:00Z",
    revocation_epoch: 0,
  }, "T2");

  const envelope = appendEvent(output, "authority.envelope-recorded", "policy-enforcement-point", authorityRef, {
    ...buildEnvelopePayload(authorityScopeRef, authorityRef, actionScope, "envelope_1", ledgerRef(authorization.sequence, authorization.event_hash)),
    run_id: output[0]!.run_id,
    plan_hash: planHash,
  }, "T2");

  const proposal = buildProposalPayload(taskRef, output[0]!.run_id, planHash, proposalId, actionScope);
  const decision = appendEvent(output, "policy.decision-recorded", "policy-enforcement-point", authorityRef, {
    ...buildDecisionPayload(
      taskRef,
      output[0]!.run_id,
      planHash,
      decisionId,
      ledgerRef(authorization.sequence, authorization.event_hash),
      envelope.sequence,
      envelope.event_hash,
      proposal,
    ),
    policy_digest: HASH,
  }, "T2");

  const proposalBindings = extractProposalBindings(proposal);
  const lease = appendEvent(output, "lease.issued", "policy-enforcement-point", authorityRef, {
    lease_id: leaseId,
    task_ref: taskRef,
    phase: "work",
    compensation_ref: null,
    ...proposalBindings,
    authority_envelope_ref: ledgerRef(envelope.sequence, envelope.event_hash),
    policy_decision_ref: ledgerRef(decision.sequence, decision.event_hash),
    fence_epoch: 0,
    issued_at: "2026-08-10T12:00:01Z",
    expires_at: "2026-08-10T12:10:00Z",
    waiver_gate_refs: ["gate-a"],
    policy_action_kind: "planning",
    action_approval_class: "automatic",
  }, "T2");

  const clock = appendEvent(output, "run.clock-observed", "kernel", null, {
    clock_id: "clock_1",
    observed_at: "2026-08-10T12:00:02Z",
    elapsed_ms: 42,
    reason: "action-admission",
    task_ref: taskRef,
    failure_ordinal: null,
    use_ref: actionId,
  }, "T2");

  const admission = appendEvent(output, "task.action-admitted", "policy-enforcement-point", authorityRef, {
    action_id: actionId,
    task_ref: taskRef,
    lease_id: leaseId,
    lease_event_ref: ledgerRef(lease.sequence, lease.event_hash),
    admission_clock_ref: ledgerRef(clock.sequence, clock.event_hash),
    ...proposalBindings,
    execution_ordinal: 1,
    retry_of_failure_ordinal: null,
    fence_epoch: 0,
    side_effect_refs: ["effect-a"],
    waiver_gate_use_checks: [],
    task_executions_after: 1,
    action_output_bytes_after: 0,
    policy_action_kind: "planning",
    action_approval_class: "automatic",
  }, "T2");

  return { events: output, lease, clock, admission };
}
