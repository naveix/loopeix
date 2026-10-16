import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { z } from "zod";

import { hashCanonical, hashRawBytes } from "../../src/hash.js";
import {
  S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
  resolveS35BuiltInActionApprovalPolicyV02,
} from "../../src/run/action-classifier-policy-v02.js";
import { buildRunManifestV03 } from "../../src/run/runtime-manifest-v03.js";
import * as authority from "../../src/run/runtime-record-admission-v02.js";
import {
  createSyntheticCapturedRuntimeRunStoreV03ForTest,
  type RuntimeWriteExpectationV03,
} from "../../src/run/runtime-write-session-v03.js";
import { ActionProposalV02, ResolvedRunPlanV02, hashAuthorityScopeV02 } from "../../src/schema/runtime.js";
import { createBaseAuthorityScopeFixtureS35 } from "./runtime-admission-fixture-s35.js";

const H = (character: string) => `sha256:${character.repeat(64)}`;
const encoder = new TextEncoder();
const sourcePlanBytes = new Uint8Array(readFileSync(join(
  process.cwd(), "tests/fixtures/compat/s35/v02/planned-run/resolved-run-plan.json",
)));
const planCandidate = JSON.parse(new TextDecoder().decode(sourcePlanBytes));
const fixtureEffect = planCandidate.side_effects
  .find((row: { task_id: string }) => row.task_id === "diagnose-root-cause")?.effects
  .find((row: { effect_id: string }) => row.effect_id === "effect-diagnose-root-cause");
if (fixtureEffect === undefined) throw new Error("fixture plan effect unavailable");
fixtureEffect.effect_class = "none";
fixtureEffect.reversible = true;
const plan = ResolvedRunPlanV02.parse(planCandidate);
const planBytes = encoder.encode(JSON.stringify(plan));
const planHash = hashRawBytes(planBytes);
const inventory = {
  resolved_run_plan: "0.2", ledger_event: "0.3", run_manifest: "0.3", artifact_manifest: "0.2",
  redaction_derivative: "0.2", human_authorization_proof: "0.2", authority_envelope: "0.2",
  agency_recommendation: "0.2", authority_revocation: "0.2", task_result: "0.2",
  manual_observation: "0.2", export_decision: "0.2", evidence_item: "0.2", gate_result: "0.2",
  evaluation_result: "0.2", claim: "0.2", finding: "0.2", waiver: "0.2", gate_waiver_authority: "0.2",
} as const;

function event(
  sequence: number,
  eventType: "run.initialized" | "run.started",
  payload: Record<string, unknown>,
  previous: string | null,
) {
  const preimage = {
    schema_version: "0.3", event_id: `event_admission_${sequence}`, run_id: plan.run_id, sequence,
    recorded_at: `2026-08-24T10:00:0${sequence}Z`, event_type: eventType, source: "kernel",
    authority_ref: null, risk_tier: "T1", related_ids: [], previous_event_hash: previous, payload,
  };
  return { ...preimage, event_hash: hashCanonical(preimage) };
}

type LedgerEvent = ReturnType<typeof event> & { event_type: string; source: string; authority_ref: string | null };

function appendEvent(
  events: LedgerEvent[], eventType: string, source: string, authorityRef: string | null,
  recordedAt: string, payload: Record<string, unknown>, riskTier = "T1",
): LedgerEvent {
  const previous = events.at(-1);
  if (previous === undefined) throw new Error("append requires a prior event");
  const preimage = {
    schema_version: "0.3" as const, event_id: `event_admission_${events.length + 1}`,
    run_id: plan.run_id, sequence: events.length + 1, recorded_at: recordedAt,
    event_type: eventType, source, authority_ref: authorityRef, risk_tier: riskTier,
    related_ids: [] as string[], previous_event_hash: previous.event_hash, payload,
  };
  const sealed = { ...preimage, event_hash: hashCanonical(preimage) } as LedgerEvent;
  events.push(sealed);
  return sealed;
}

function ref(eventValue: LedgerEvent) {
  return { ledger_sequence: eventValue.sequence, event_hash: eventValue.event_hash };
}

function automaticProposal(scope: Record<string, unknown>): z.infer<typeof ActionProposalV02> {
  const policy = resolveS35BuiltInActionApprovalPolicyV02(S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02);
  const rule = policy?.classifier_registry.rules.find((row) => row.policy_action_kind === "planning");
  if (policy === null || policy === undefined || rule === undefined) throw new Error("planning policy unavailable");
  const chain = [
    { principal_ref: "operator_admission_v03", stable_identity_hash: H("5") },
    { principal_ref: "agent_admission_v03", stable_identity_hash: H("6") },
  ];
  const dispatch = {
    kind: "process", adapter_ref: rule.key.adapter_ref, adapter_version_hash: rule.key.adapter_version_hash,
    capability_ref: rule.key.capability_ref, capability_definition_hash: rule.key.capability_definition_hash,
    operation: rule.key.operation, target: { kind: "plan-object", object_kind: "task", object_ref: "diagnose-root-cause" },
    destination: null, input_subject_hashes: [], executable_ref: "executor_admission_v03", executable_hash: H("7"),
    program: "true", argv: [], cwd_identity_hash: H("8"), environment_hash: H("9"), stdin_hash: null,
    timeout_ms: 1_000, output_limit_bytes: 1_024,
  };
  const changeSet = {
    repository_root_ref: "repository_1", base_ref_identity_hash: H("a"), repository_pre_state_hash: H("b"),
    transition_mode: "read-only", expected_pre_head: { algorithm: "sha1", value: "a".repeat(40) },
    required_post_head: { algorithm: "sha1", value: "a".repeat(40) }, mode: "no-change", changes: [],
  };
  const dataFlow = { readable_classifications: [], exportable_classifications: [], sink_refs: [], data_access_mode: "none" };
  const preimage = {
    proposal_version: "0.2" as const, action_proposal_id: "proposal_admission_v03", run_id: plan.run_id,
    plan_hash: planHash, task_ref: "diagnose-root-cause", phase: "work" as const, compensation_ref: null,
    proposer_actor_ref: "agent_admission_v03", proposer_stable_identity_hash: H("6"),
    action_actor_ref: "agent_admission_v03", action_actor_stable_identity_hash: H("6"),
    on_behalf_of_chain: chain,
    on_behalf_of_chain_hash: hashCanonical({ purpose: "action-on-behalf-of-chain-v02", on_behalf_of_chain: chain }),
    repository_root_ref: "repository_1", repository_base_ref_identity_hash: H("a"), repository_pre_state_hash: H("b"),
    authorized_change_set: changeSet,
    authorized_change_set_hash: hashCanonical({ purpose: "authorized-repository-change-set-v02", ...changeSet }),
    normalized_dispatch: dispatch,
    normalized_dispatch_hash: hashCanonical({ purpose: "normalized-action-dispatch-v02", ...dispatch }),
    action_scope: scope, action_scope_hash: hashAuthorityScopeV02(scope as never), action_class: "task" as const,
    classification_binding: {
      classifier_input_hash: hashCanonical({ purpose: "action-classifier-input-v1", key: rule.key }),
      classifier_registry_hash: policy.classifier_registry.registry_hash, classifier_rule_hash: rule.rule_hash,
    },
    policy_action_kind: "planning" as const, action_approval_class: "automatic" as const,
    side_effect_refs: [{ task_ref: "diagnose-root-cause", effect_ref: "effect-diagnose-root-cause" }],
    data_flow: { ...dataFlow, data_flow_hash: hashCanonical({ purpose: "action-data-flow-v02", ...dataFlow }) },
    effective_risk_tier: "T1" as const,
    budget_delta: { tool_calls: 0, output_bytes: 0, tokens: 0, cost: { capture: "not-applicable" as const, cost_minor_units: 0 as const, cost_currency: null } },
    postcondition_hashes: [], verifier_refs: [],
  };
  return ActionProposalV02.parse({
    ...preimage, action_proposal_hash: hashCanonical({ purpose: "action-proposal-v02", ...preimage }),
  });
}

export type SignedRuntimeActionAdmissionV03FixtureOptions = Readonly<{
  elapsed_ms?: number;
  envelope_recorded_at?: string;
  context_dispatch_hash?: string;
  enforcement_available?: boolean;
  allowed_effect_class?: "none" | "workspace-write";
  max_decisions?: number;
  additional_event_envelopes?: readonly Readonly<{ event_id: string; recorded_at: string }>[];
}>;

export async function createSignedRuntimeActionAdmissionV03Fixture(options: SignedRuntimeActionAdmissionV03FixtureOptions = {}) {
  const pair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const policy = resolveS35BuiltInActionApprovalPolicyV02(S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02);
  const rule = policy?.classifier_registry.rules.find((row) => row.policy_action_kind === "planning");
  if (policy === null || policy === undefined || rule === undefined) throw new Error("planning policy unavailable");
  const scope = createBaseAuthorityScopeFixtureS35();
  scope.authority_subject = structuredClone(plan.authority_subject);
  scope.action_class = "task";
  scope.capability_constraints = [{ classifier_key: rule.key, classifier_rule_hash: rule.rule_hash }];
  scope.resource_selectors = [{ kind: "plan-object", object_kind: "task", object_ref: "diagnose-root-cause" }];
  scope.operations = ["read"];
  scope.max_risk_tier = "T1";
  scope.bounded_constraints.max_decisions = options.max_decisions ?? scope.bounded_constraints.max_decisions;
  scope.side_effect_constraints = {
    allowed_effect_classes: [options.allowed_effect_class ?? "none"],
    allowed_effect_refs: [{ task_ref: "diagnose-root-cause", effect_ref: "effect-diagnose-root-cause" }],
    require_inspectable: true, require_reversible: true, require_idempotency_key: false, require_compensation: false,
  };
  const proposal = automaticProposal(scope);
  const observedAt = "2026-08-24T10:00:30Z";
  const authContext = {
    context_version: "0.1", trust_domain: "admission-test", approval_channel: "local-ed25519",
    authenticated_principal_ref: "operator_admission_v03", credential_ref: "key_admission_v03",
    channel_subject_hash: H("c"), session_binding_hash: H("d"), assurance_level: "phishing-resistant",
  } as const;
  const trustInput = (durableNonceConsumptions: readonly Record<string, unknown>[]) => ({
    observed_at: observedAt, policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
    authentication_contexts: [authContext],
    operator_keys: [{
      operator_key_id: "key_admission_v03", authenticated_principal_ref: "operator_admission_v03",
      trust_domain: "admission-test", public_key_spki_base64: pair.publicKey.toString("base64"),
      effective_from: "2026-08-24T09:00:00Z", effective_until: "2026-08-24T11:00:00Z", revoked_at: null,
    }],
    platform_channel_verifiers: [], host_producer_keys: [],
    authority_epochs: [{ authenticated_principal_ref: "operator_admission_v03", revocation_epoch: 0, effective_from: "2026-08-24T09:00:00Z" }],
    durable_nonce_consumptions: durableNonceConsumptions,
  });
  const initialTrust = authority.captureAuthorityTrustContextV02(trustInput([]));
  if (!initialTrust.ok) throw new Error("initial trust rejected");
  const envelopeInput = {
    schema_version: "0.2", authority_envelope_id: "envelope_admission_v03", run_id: plan.run_id,
    plan_hash: planHash, policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
    subject: { principal_ref: "agent_admission_v03", stable_identity_hash: H("6") },
    issuer: { principal_ref: "operator_admission_v03", stable_identity_hash: H("5") },
    authority_scope: scope, issued_at: "2026-08-24T10:00:00Z", expires_at: "2026-08-24T10:05:00Z", revocation_epoch: 0,
  };
  const subjectHash = authority.authorityEnvelopeSubjectHashV02(envelopeInput);
  if (subjectHash === null) throw new Error("envelope subject invalid");
  let reserved: Record<string, unknown> | undefined;
  const nonce = authority.captureNonceReservationCapabilityV02(async (row: Record<string, unknown>) => {
    reserved = row;
    return "reserved";
  });
  const signer = authority.captureEd25519AuthoritySignerV02("key_admission_v03", pair.privateKey);
  const proof = await authority.produceLocalHumanAuthorizationProofV02({
    trust_context: initialTrust.value, nonce_reservation: nonce, signer,
    request: {
      authorization_id: "authorization_admission_v03", run_id: plan.run_id, plan_hash: planHash,
      authorization_subject_hash: subjectHash, authenticated_principal_ref: "operator_admission_v03",
      action_scope_hash: hashAuthorityScopeV02(scope as never), approved_risk_tier: "T1",
      operator_key_id: "key_admission_v03", approval_nonce: H("e"),
      issued_at: "2026-08-24T10:00:00Z", expires_at: "2026-08-24T10:05:00Z", revocation_epoch: 0,
    },
  });
  if (!proof.ok || reserved === undefined) throw new Error("proof mint failed");
  const trust = authority.captureAuthorityTrustContextV02(trustInput([reserved]));
  if (!trust.ok) throw new Error("fresh trust rejected");

  const initialized = event(1, "run.initialized", {
    plan_hash: planHash, initial_fence_epoch: 0, runtime_schema_versions: inventory,
  }, null) as LedgerEvent;
  const events: LedgerEvent[] = [initialized];
  appendEvent(events, "run.started", "kernel", null, "2026-08-24T10:00:01Z", { executor_profile_hash: H("1") });
  const proofPayload = {
    authorization_id: proof.value.authorization_id,
    record_path: `authorities/human/${proof.value.authorization_id}.json`, record_hash: proof.value.record_hash,
    run_id: proof.value.run_id, plan_hash: proof.value.plan_hash,
    authorization_subject_hash: proof.value.authorization_subject_hash,
    authenticated_principal_ref: proof.value.authenticated_principal_ref,
    authentication_context_hash: proof.value.authentication_context_hash,
    action_scope_hash: proof.value.action_scope_hash, approved_risk_tier: proof.value.approved_risk_tier,
    operator_key_id: proof.value.operator_key_id, approval_channel: proof.value.approval_channel,
    approval_nonce: proof.value.approval_nonce, proof_algorithm: proof.value.proof_algorithm,
    authorization_statement_hash: proof.value.authorization_statement_hash,
    issued_at: proof.value.issued_at, expires_at: proof.value.expires_at, revocation_epoch: proof.value.revocation_epoch,
  };
  const proofEvent = appendEvent(events, "authority.human-authorization-recorded", "operator",
    "operator_admission_v03", "2026-08-24T10:00:10Z", proofPayload);
  const envelope = authority.constructRootAuthorityEnvelopeV02({
    trust_context: trust.value, envelope: envelopeInput,
    human_authorization_proofs: [{ proof_ref: ref(proofEvent), proof: proof.value }],
  });
  if (!envelope.ok) throw new Error("envelope construction failed");
  const envelopePayload = {
    authority_envelope_id: envelope.value.authority_envelope_id,
    record_path: `authorities/envelopes/${envelope.value.authority_envelope_id}.json`,
    record_hash: envelope.value.record_hash, run_id: envelope.value.run_id, plan_hash: envelope.value.plan_hash,
    policy_digest: envelope.value.policy_digest, subject_ref: envelope.value.subject.principal_ref,
    issuer_principal_ref: envelope.value.issuer.principal_ref,
    authorization_subject_hash: envelope.value.authorization_subject_hash,
    human_authorization_proof_refs: envelope.value.human_authorization_proof_refs,
    action_class: envelope.value.authority_scope.action_class, action_scope_hash: envelope.value.action_scope_hash,
    max_risk_tier: envelope.value.authority_scope.max_risk_tier, issued_at: envelope.value.issued_at,
    expires_at: envelope.value.expires_at, revocation_epoch: envelope.value.revocation_epoch,
    delegation_depth: envelope.value.lineage.delegation_depth,
  };
  const envelopeEvent = appendEvent(events, "authority.envelope-recorded", "policy-enforcement-point",
    "operator_admission_v03", "2026-08-24T10:00:20Z", envelopePayload);
  const producedDecision = authority.producePolicyDecisionV02({
    trust_context: trust.value, authority_envelope: envelope.value, action_proposal: proposal, recommendations: [],
    request: {
      policy_decision_id: "decision_admission_v03",
      authority_envelope_ref: { record_kind: "authority-envelope", record_id: envelope.value.authority_envelope_id, record_event_ref: ref(envelopeEvent) },
      reviewed_through_ref: ref(events[1]!), recommendation_event_refs: [], compensation_evidence_refs: [],
      issued_at: observedAt, expires_at: "2026-08-24T10:05:00Z",
    },
  });
  if (!producedDecision.ok) throw new Error(`producer rejected: ${producedDecision.error}`);
  const decisionValue = producedDecision.value;
  appendEvent(events, "policy.decision-recorded", "policy-enforcement-point",
    "operator_admission_v03", observedAt, decisionValue);

  const ledger = encoder.encode(events.map((row) => JSON.stringify(row)).join("\n") + "\n");
  const proofBytes = encoder.encode(JSON.stringify(proof.value));
  const envelopeBytes = encoder.encode(JSON.stringify(envelope.value));
  const files = [
    { path: "artifact-manifest.json", family: "projection", required: false, mode: null, bytes: null },
    { path: "ledger.jsonl", family: "primary", required: true, mode: 384, bytes: ledger },
    { path: "resolved-run-plan.json", family: "primary", required: true, mode: 384, bytes: planBytes },
    { path: proofPayload.record_path, family: "record", required: true, mode: 384, bytes: proofBytes },
    { path: envelopePayload.record_path, family: "record", required: true, mode: 384, bytes: envelopeBytes },
  ] as const;
  const built = buildRunManifestV03({ ledger_bytes: ledger, created_at: "2026-08-24T10:00:01Z", captured_files: files });
  if (!built.ok) throw new Error(built.reason);
  const store = createSyntheticCapturedRuntimeRunStoreV03ForTest({
    run_id: plan.run_id, ledger_bytes: ledger, manifest_bytes: built.bytes, captured_files: files,
    lock_identity: "lock_signed_admission_v03", lock_identity_valid: true, fault_at: null,
    event_envelopes: [
      { event_id: "event_lease_v03", recorded_at: options.envelope_recorded_at ?? observedAt },
      { event_id: "event_clock_v03", recorded_at: observedAt },
      { event_id: "event_action_v03", recorded_at: observedAt },
      ...(options.additional_event_envelopes ?? []),
    ],
    admission_context: {
      authority_trust_context: trust.value, repository_pre_state_hash: proposal.repository_pre_state_hash,
      normalized_dispatch_hash: options.context_dispatch_hash ?? proposal.normalized_dispatch_hash,
      observed_at: observedAt, elapsed_ms: options.elapsed_ms ?? 30,
      reviewer_view_hash: H("f"), enforcement: {
        available: options.enforcement_available ?? true,
        information_flow_allowed: true, gates_passed: true, immediate_revalidation_passed: true,
      }, condition_results: [], lease_id: "lease_admission_v03", clock_id: "clock_admission_v03", action_id: "action_admission_v03",
    },
  });
  if (store === null) throw new Error("signed store rejected");
  return {
    store,
    expectation: {
      run_id: plan.run_id, ledger_bytes_hash: built.manifest.ledger_bytes_hash,
      ledger_sequence: built.manifest.ledger_sequence, ledger_head_hash: built.manifest.ledger_head_hash,
      current_fence_epoch: 0, manifest_hash: built.manifest.manifest_hash,
    } satisfies RuntimeWriteExpectationV03,
    request: {
      action_proposal_id: proposal.action_proposal_id, policy_decision_id: decisionValue.policy_decision_id,
      normalized_dispatch_hash: proposal.normalized_dispatch_hash, expected_fence_epoch: 0,
    },
  };
}


export const SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS = Object.freeze({
  run_id: plan.run_id,
  lease_id: "lease_admission_v03",
  clock_id: "clock_admission_v03",
  action_id: "action_admission_v03",
  recorded_at: "2026-08-24T10:00:30Z",
  initial_fence_epoch: 0,
});
