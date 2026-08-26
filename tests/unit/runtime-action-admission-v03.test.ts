import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";
import { z } from "zod";

import { hashCanonical, hashRawBytes } from "../../src/hash.js";
import {
  S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
  resolveS35BuiltInActionApprovalPolicyV02,
} from "../../src/run/action-classifier-policy-v02.js";
import {
  admitRuntimeActionV03,
  consumeDispatchPermitV01,
  inspectProspectiveRuntimeActionLimitsV03ForTest,
  type DispatchPermitV01,
} from "../../src/run/runtime-action-admission-v03.js";
import { buildRunManifestV03 } from "../../src/run/runtime-manifest-v03.js";
import {
  closeRuntimeWriteSessionV03,
  createSyntheticCapturedRuntimeRunStoreV03ForTest,
  inspectSyntheticRuntimeRunStoreV03ForTest,
  openRuntimeWriteSessionV03,
  type RuntimeWriteExpectationV03,
  type RuntimeWriteSessionV03,
} from "../../src/run/runtime-write-session-v03.js";
import { ActionProposalV02, ResolvedRunPlanV02, hashAuthorityScopeV02 } from "../../src/schema/runtime.js";
import { createBaseAuthorityScopeFixtureS35 } from "../helpers/runtime-admission-fixture-s35.js";
import {
  createSignedRuntimeActionAdmissionV03Fixture,
  SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS,
} from "../helpers/runtime-action-admission-v03-fixture.js";

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

function fixture() {
  const initialized = event(1, "run.initialized", {
    plan_hash: planHash, initial_fence_epoch: 0, runtime_schema_versions: inventory,
  }, null);
  const started = event(2, "run.started", { executor_profile_hash: H("1") }, initialized.event_hash);
  const ledger = encoder.encode(`${JSON.stringify(initialized)}\n${JSON.stringify(started)}\n`);
  const files = [
    { path: "artifact-manifest.json", family: "projection", required: false, mode: null, bytes: null },
    { path: "ledger.jsonl", family: "primary", required: true, mode: 384, bytes: ledger },
    { path: "resolved-run-plan.json", family: "primary", required: true, mode: 384, bytes: planBytes },
  ] as const;
  const built = buildRunManifestV03({ ledger_bytes: ledger, created_at: "2026-08-24T10:00:01Z", captured_files: files });
  if (!built.ok) throw new Error(built.reason);
  const store = createSyntheticCapturedRuntimeRunStoreV03ForTest({
    run_id: plan.run_id, ledger_bytes: ledger, manifest_bytes: built.bytes, captured_files: files,
    lock_identity: "lock_admission_v03", lock_identity_valid: true, fault_at: null,
    event_envelopes: [
      { event_id: "event_lease_v03", recorded_at: "2026-08-24T10:01:00Z" },
      { event_id: "event_clock_v03", recorded_at: "2026-08-24T10:01:00Z" },
      { event_id: "event_action_v03", recorded_at: "2026-08-24T10:01:00Z" },
    ],
    admission_context: {
      authority_trust_context: Object.freeze({}), repository_pre_state_hash: H("2"),
      normalized_dispatch_hash: H("3"), observed_at: "2026-08-24T10:01:00Z", elapsed_ms: 60_000,
      reviewer_view_hash: H("4"), enforcement: {
        available: true, information_flow_allowed: true, gates_passed: true, immediate_revalidation_passed: true,
      }, condition_results: [], lease_id: "lease_admission_v03", clock_id: "clock_admission_v03", action_id: "action_admission_v03",
    },
  });
  if (store === null) throw new Error("store rejected");
  const expectation: RuntimeWriteExpectationV03 = {
    run_id: plan.run_id, ledger_bytes_hash: built.manifest.ledger_bytes_hash,
    ledger_sequence: built.manifest.ledger_sequence, ledger_head_hash: built.manifest.ledger_head_hash,
    current_fence_epoch: 0, manifest_hash: built.manifest.manifest_hash,
  };
  return { store, expectation };
}

const request = {
  action_proposal_id: "proposal_admission_v03", policy_decision_id: "decision_admission_v03",
  normalized_dispatch_hash: H("3"), expected_fence_epoch: 0,
};

describe("S40-B3 durable runtime action admission", () => {
  it("fails closed on cumulative counter drift, exhausted loops, and unusable cost history", () => {
    const planValue = structuredClone(plan);
    planValue.limit_policy.max_loop_attempts = 4;
    planValue.limit_policy.max_tool_calls = 100;
    planValue.limit_policy.max_output_bytes = 100;
    planValue.limit_policy.max_tokens = 100;
    planValue.limit_policy.max_cost_minor_units = 100;
    planValue.limit_policy.cost_currency = "USD";
    planValue.retry_policy.rules[0]!.max_task_executions = 10;
    const scope = createBaseAuthorityScopeFixtureS35();
    scope.authority_subject = structuredClone(plan.authority_subject);
    scope.bounded_constraints.max_actions = 10;
    scope.bounded_constraints.max_attempts = 10;
    scope.bounded_constraints.max_tool_calls = 100;
    scope.bounded_constraints.max_output_bytes = 100;
    scope.bounded_constraints.cost = { capture: "required", max_cost_minor_units: 100, cost_currency: "USD" };
    const proposal = structuredClone(automaticProposal(scope));
    proposal.budget_delta.cost = { capture: "required", cost_minor_units: 1, cost_currency: "USD" };
    const prior = (event_type: string, payload: Record<string, unknown>) => ({ event_type, payload }) as never;
    const terminal = (overrides: Record<string, unknown>) => prior("task.execution-completed", {
      action_output_bytes_after: 0, tool_calls_after: 0, token_count_after: 0,
      observed_cost: { capture: "captured", cost_minor_units: 0, cost_currency: "USD", cost_minor_units_after: 0 },
      ...overrides,
    });
    const admission = () => prior("task.action-admitted", { task_ref: proposal.task_ref, action_proposal_id: proposal.action_proposal_id });
    expect(inspectProspectiveRuntimeActionLimitsV03ForTest(planValue, proposal, [terminal({
      observed_cost: { capture: "captured", cost_minor_units: 50, cost_currency: "USD", cost_minor_units_after: 50 },
    })], 1)).toBe(true);
    const cases = [
      ["loop ceiling", [admission(), admission(), admission(), admission()]],
      ["tool counter regression", [terminal({ tool_calls_after: 2 }), terminal({ tool_calls_after: 1 })]],
      ["output counter regression", [terminal({ action_output_bytes_after: 2 }), terminal({ action_output_bytes_after: 1 })]],
      ["token counter regression", [terminal({ token_count_after: 2 }), terminal({ token_count_after: 1 })]],
      ["unavailable cost", [terminal({ observed_cost: { capture: "unavailable", cost_minor_units: null, cost_currency: "USD", cost_minor_units_after: null } })]],
      ["wrong cost currency", [terminal({ observed_cost: { capture: "captured", cost_minor_units: 1, cost_currency: "EUR", cost_minor_units_after: 1 } })]],
    ] as const;
    for (const [, history] of cases) {
      expect(inspectProspectiveRuntimeActionLimitsV03ForTest(planValue, proposal, history, 1)).toBe(false);
    }
  });

  it("normalizes the strict four-key request before session authenticity", async () => {
    await expect(admitRuntimeActionV03(Object.freeze({}) as RuntimeWriteSessionV03, { ...request, alias: true }))
      .resolves.toEqual({ ok: false, error: "CANONICAL_AUTHORITY_RECORDS_INVALID" });
    await expect(admitRuntimeActionV03(Object.freeze({}) as RuntimeWriteSessionV03, request))
      .resolves.toEqual({ ok: false, error: "RUNTIME_WRITE_SESSION_INVALID" });
  });

  it("rejects a valid session that has no canonical durable S36 records", async () => {
    const { store, expectation } = fixture();
    const opened = await openRuntimeWriteSessionV03(store, expectation);
    if (!opened.ok) throw new Error(opened.error);
    await expect(admitRuntimeActionV03(opened.session, request))
      .resolves.toEqual({ ok: false, error: "CANONICAL_AUTHORITY_RECORDS_INVALID" });
    await closeRuntimeWriteSessionV03(opened.session);
  });

  it("admits only the exact signed durable decision and mints an opaque permit after three committed appends", async () => {
    const fixtureValue = await createSignedRuntimeActionAdmissionV03Fixture();
    const opened = await openRuntimeWriteSessionV03(fixtureValue.store, fixtureValue.expectation);
    if (!opened.ok) throw new Error(opened.error);
    const admitted = await admitRuntimeActionV03(opened.session, fixtureValue.request);
    expect(admitted, JSON.stringify(admitted)).toMatchObject({
      ok: true,
      lease_event_ref: { ledger_sequence: fixtureValue.expectation.ledger_sequence + 1 },
      admission_clock_ref: { ledger_sequence: fixtureValue.expectation.ledger_sequence + 2 },
      action_admission_event_ref: { ledger_sequence: fixtureValue.expectation.ledger_sequence + 3 },
    });
    if (!admitted.ok) throw new Error(admitted.error);
    expect(Object.keys(admitted.permit)).toEqual([]);
    expect(JSON.stringify(admitted.permit)).toBe("{}");
    const broker = Object.freeze({ kind: "captured-broker" });
    expect(consumeDispatchPermitV01(Object.freeze({}) as DispatchPermitV01, opened.session, broker,
      fixtureValue.request.normalized_dispatch_hash)).toEqual({ ok: false, error: "DISPATCH_PERMIT_INVALID" });
    expect(consumeDispatchPermitV01(admitted.permit, opened.session, broker, H("e")))
      .toEqual({ ok: false, error: "DISPATCH_BINDING_MISMATCH" });
    expect(consumeDispatchPermitV01(admitted.permit, Object.freeze({}) as RuntimeWriteSessionV03, broker,
      fixtureValue.request.normalized_dispatch_hash))
      .toEqual({ ok: false, error: "DISPATCH_PERMIT_SESSION_MISMATCH" });
    expect(consumeDispatchPermitV01(admitted.permit, opened.session, broker,
      fixtureValue.request.normalized_dispatch_hash)).toEqual({
      ok: true, action_admission_event_ref: admitted.action_admission_event_ref,
    });
    expect(consumeDispatchPermitV01(admitted.permit, opened.session, Object.freeze({ kind: "other-broker" }),
      fixtureValue.request.normalized_dispatch_hash)).toEqual({ ok: false, error: "DISPATCH_BINDING_MISMATCH" });
    expect(consumeDispatchPermitV01(admitted.permit, opened.session, broker,
      fixtureValue.request.normalized_dispatch_hash)).toEqual({ ok: false, error: "DISPATCH_PERMIT_ALREADY_USED" });
    const persisted = inspectSyntheticRuntimeRunStoreV03ForTest(fixtureValue.store);
    const events = new TextDecoder().decode(persisted?.ledger_bytes).trim().split("\n").map((line) => JSON.parse(line));
    const [lease, clock, action] = events.slice(-3);
    expect(lease).toMatchObject({
      event_type: "lease.issued", recorded_at: SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS.recorded_at,
      payload: {
        lease_id: SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS.lease_id,
        fence_epoch: SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS.initial_fence_epoch,
      },
    });
    expect(clock).toMatchObject({
      event_type: "run.clock-observed", recorded_at: SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS.recorded_at,
      payload: {
        clock_id: SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS.clock_id,
        reason: "action-admission", use_ref: SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS.action_id,
      },
    });
    expect(action).toMatchObject({
      event_type: "task.action-admitted", recorded_at: SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS.recorded_at,
      payload: {
        action_id: SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS.action_id,
        lease_event_ref: admitted.lease_event_ref,
        admission_clock_ref: admitted.admission_clock_ref, fence_epoch: 0, execution_ordinal: 1,
      },
    });
    await closeRuntimeWriteSessionV03(opened.session);
  });

  it.each([
    ["request dispatch drift", {}, { normalized_dispatch_hash: H("e") }, "CANONICAL_AUTHORITY_RECORDS_INVALID"],
    ["fence epoch drift", {}, { expected_fence_epoch: 1 }, "REPOSITORY_OR_DISPATCH_DRIFT"],
    ["captured dispatch drift", { context_dispatch_hash: H("e") }, {}, "REPOSITORY_OR_DISPATCH_DRIFT"],
    ["event-envelope time drift", { envelope_recorded_at: "2026-08-24T10:00:31Z" }, {}, "REPOSITORY_OR_DISPATCH_DRIFT"],
    ["elapsed limit exhaustion", { elapsed_ms: 60_001 }, {}, "LIMIT_ADMISSION_BLOCKED"],
    ["decision ceiling exhaustion", { max_decisions: 0 }, {}, "LIMIT_ADMISSION_BLOCKED"],
    ["plan side-effect mismatch", { allowed_effect_class: "workspace-write" }, {}, "LIMIT_ADMISSION_BLOCKED"],
    ["unavailable enforcement", { enforcement_available: false }, {}, "SIMULATION_REVALIDATION_FAILED"],
  ] as const)("fails closed before writes on %s", async (_name, options, requestPatch, error) => {
    const fixtureValue = await createSignedRuntimeActionAdmissionV03Fixture(options);
    const opened = await openRuntimeWriteSessionV03(fixtureValue.store, fixtureValue.expectation);
    if (!opened.ok) throw new Error(opened.error);
    const before = inspectSyntheticRuntimeRunStoreV03ForTest(fixtureValue.store)?.operations.length;
    await expect(admitRuntimeActionV03(opened.session, { ...fixtureValue.request, ...requestPatch }))
      .resolves.toEqual({ ok: false, error });
    expect(inspectSyntheticRuntimeRunStoreV03ForTest(fixtureValue.store)?.operations.length).toBe(before);
    await closeRuntimeWriteSessionV03(opened.session);
  });
});
