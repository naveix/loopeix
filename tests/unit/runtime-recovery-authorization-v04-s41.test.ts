import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import * as root from "../../src/index.js";
import { hashCanonical } from "../../src/hash.js";
import { S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02 } from "../../src/run/action-classifier-policy-v02.js";
import {
  inspectRuntimePlanV03,
  projectRuntimePlanV03,
} from "../../src/run/project-plan-v03.js";
import {
  captureAuthorityTrustContextV02,
  captureEd25519AuthoritySignerV02,
  captureNonceReservationCapabilityV02,
  produceLocalHumanAuthorizationProofV02,
} from "../../src/run/runtime-record-admission-v02.js";
import {
  captureRuntimeRecoveryRequestV04,
  consumeCapturedRuntimeRecoveryRequestV04,
  hashRuntimeRecoveryActionScopeV04,
  hashRuntimeRecoveryAuthorizationSubjectV04,
  inspectCapturedRuntimeRecoveryRequestV04,
  RuntimeRecoveryRequestIntentV04,
  type RuntimeRecoveryRequestIntentV04Value,
} from "../../src/run/runtime-recovery-authorization-v04.js";
import { inspectRuntimeLedgerV04 } from "../../src/run/runtime-ledger-v04.js";
import {
  buildRunManifestV04,
  inspectRunManifestV04,
} from "../../src/run/runtime-manifest-v04.js";
import { planRuntimeRecoveryV04 } from "../../src/run/runtime-recovery-v04.js";
import { ResolvedRunPlanV02, type ResolvedRunPlanV02Value } from "../../src/schema/runtime.js";
import { captureRuntimeProfileRegistryV03 } from "../../src/schema/runtime-plan-v03.js";
import { RuntimeEventV04, type RuntimeEventV04Value } from "../../src/schema/runtime-v04.js";
import { createRuntimeRepositoryObservationFixture } from "../helpers/runtime-repository-observation-fixture.js";

const E = new TextEncoder();
const H = (value: string): string => `sha256:${value.repeat(64)}`;
const REGISTRY = captureRuntimeProfileRegistryV03();
const AUTHORITY_HASH = H("f");
const cleanupRepositories: Array<() => void> = [];

afterEach(() => {
  for (const cleanup of cleanupRepositories.splice(0)) cleanup();
});
const inventory = {
  resolved_run_plan: "0.3",
  ledger_event: "0.4",
  run_manifest: "0.4",
  artifact_manifest: "0.2",
  redaction_derivative: "0.2",
  human_authorization_proof: "0.2",
  authority_envelope: "0.2",
  agency_recommendation: "0.2",
  authority_revocation: "0.2",
  task_result: "0.2",
  manual_observation: "0.2",
  export_decision: "0.2",
  evidence_item: "0.2",
  gate_result: "0.2",
  evaluation_result: "0.2",
  claim: "0.2",
  finding: "0.2",
  waiver: "0.2",
  gate_waiver_authority: "0.2",
  summary_artifact: "0.1",
} as const;

function loadPlanV02(): ResolvedRunPlanV02Value {
  return ResolvedRunPlanV02.parse(JSON.parse(readFileSync(
    join(import.meta.dirname, "../fixtures/compat/s35/v02/planned-run/resolved-run-plan.json"),
    "utf8",
  )));
}

function validatedPlan(input: ResolvedRunPlanV02Value = loadPlanV02()) {
  const projected = projectRuntimePlanV03(input, REGISTRY);
  if (!projected.ok) throw new Error(projected.reason);
  const inspected = inspectRuntimePlanV03(E.encode(`${JSON.stringify(projected.value, null, 2)}\n`));
  if (!inspected.ok) throw new Error(inspected.reason);
  return inspected.validated_plan;
}

function ref(event: RuntimeEventV04Value) {
  return { ledger_sequence: event.sequence, event_hash: event.event_hash };
}

function append(
  events: RuntimeEventV04Value[],
  runId: string,
  eventType: RuntimeEventV04Value["event_type"],
  payload: unknown,
  label: string,
) {
  const sequence = events.length + 1;
  const preimage = {
    schema_version: "0.4",
    event_id: `event_recovery_authorization_${label}_${sequence}`,
    run_id: runId,
    sequence,
    recorded_at: `2026-08-30T10:00:${String(sequence).padStart(2, "0")}Z`,
    event_type: eventType,
    source: eventType === "task.action-admitted"
      ? "policy-enforcement-point"
      : eventType === "run.terminal-freeze-entered" || eventType === "run.compensation-phase-entered"
        ? "evaluator"
        : "kernel",
    authority_ref: eventType === "task.action-admitted" ? "authority_s41" : null,
    risk_tier: "T1",
    related_ids: [],
    previous_event_hash: events.at(-1)?.event_hash ?? null,
    payload,
  };
  const event = RuntimeEventV04.parse({ ...preimage, event_hash: hashCanonical(preimage) });
  events.push(event);
  return event;
}

function buildScenario(label = "a") {
  const repository = createRuntimeRepositoryObservationFixture(loadPlanV02(), label);
  cleanupRepositories.push(repository.cleanup);
  const plan = validatedPlan(repository.plan);
  const events: RuntimeEventV04Value[] = [];
  append(events, plan.run_id, "run.initialized", {
    plan_hash: plan.plan_hash,
    initial_fence_epoch: 0,
    runtime_schema_versions: inventory,
  }, label);
  const started = append(events, plan.run_id, "run.started", {
    executor_profile_hash: H("b"),
  }, label);
  const ownerClock = append(events, plan.run_id, "run.clock-observed", {
    clock_id: `clock_${label}`,
    observed_at: "2026-08-30T10:00:02Z",
    elapsed_ms: 1,
    reason: "run-owner-acquisition",
    task_ref: null,
    failure_ordinal: null,
    use_ref: `owner_${label}`,
    attempt_ref: null,
    owner_lease_ref: null,
    boot_id_hash: H("1"),
    monotonic_clock_id: `monotonic_${label}`,
  }, label);
  const attempt = append(events, plan.run_id, "execution.attempt-started", {
    attempt_id: `attempt_${label}`,
    attempt_ordinal: 1,
    mode: "ordinary",
    previous_attempt_event_ref: null,
    resume_request_event_ref: null,
    resume_nonce_hash: null,
    source_boundary_sequence: started.sequence,
    source_boundary_head_hash: started.event_hash,
    source_manifest_hash: H("c"),
    plan_hash: plan.plan_hash,
    input_hash: plan.plan.runtime_input_hash,
    recovery_policy_hash: plan.plan.runtime_recovery_policy_hash,
    authority_envelope_hash: AUTHORITY_HASH,
    repository_state_hash: repository.observation.repository_state_hash,
    run_owner_lease_id: `owner_${label}`,
    issued_clock_ref: ref(ownerClock),
    deadline_elapsed_ms: 1_000,
    boot_id_hash: H("1"),
    monotonic_clock_id: `monotonic_${label}`,
    previous_fence_epoch: 0,
    fence_epoch: 0,
  }, label);
  const action = append(events, plan.run_id, "task.action-admitted", {
    action_id: `action_${label}`,
    task_ref: plan.plan.tasks[0]!.id,
    lease_id: `action_lease_${label}`,
    lease_event_ref: ref(attempt),
    admission_clock_ref: ref(ownerClock),
    action_proposal_id: `proposal_${label}`,
    action_proposal_hash: H("a"),
    action_actor_ref: `actor_${label}`,
    action_actor_stable_identity_hash: H("a"),
    on_behalf_of_chain_hash: H("a"),
    repository_root_ref: `repository_${label}`,
    repository_base_ref_identity_hash: H("a"),
    repository_pre_state_hash: H("a"),
    authorized_change_set_hash: H("a"),
    normalized_dispatch_hash: H("a"),
    action_scope_hash: H("a"),
    action_class: "task",
    classifier_input_hash: H("a"),
    classifier_registry_hash: H("a"),
    classifier_rule_hash: H("a"),
    data_flow_hash: H("a"),
    policy_action_kind: "network-read",
    action_approval_class: "agency",
    execution_ordinal: 1,
    retry_of_failure_ordinal: null,
    fence_epoch: 0,
    side_effect_refs: [`effect-${label}`],
    waiver_gate_use_checks: [],
    task_executions_after: 1,
    action_output_bytes_after: 0,
    attempt_event_ref: ref(attempt),
    parent_run_owner_lease_id: `owner_${label}`,
    logical_operation_idempotency_key: H("2"),
    resolved_operation_input_hash: H("3"),
    recovery_policy_hash: plan.plan.runtime_recovery_policy_hash,
    process_runtime_ceiling_ms: plan.plan.runtime_execution_policy.max_process_runtime_ms,
  }, label);
  const freeze = append(events, plan.run_id, "run.terminal-freeze-entered", {
    revision: 1,
    candidate: "failed",
    candidate_evidence_refs: [ref(attempt)],
    fence_epoch: 0,
  }, label);
  const compensation = append(events, plan.run_id, "run.compensation-phase-entered", {
    request_revision: 1,
    request_event_hash: freeze.event_hash,
    pending_terminal: "failed",
    compensation_refs: [`compensation-${label}`],
    freeze_event_hash: freeze.event_hash,
  }, label);
  const ledgerBytes = E.encode(`${events.map((event) => JSON.stringify(event)).join("\n")}\n`);
  const ledger = inspectRuntimeLedgerV04(ledgerBytes);
  if (!ledger.ok) throw new Error(`${ledger.reason}: ${JSON.stringify(ledger.issues)}`);
  const files = [{
    path: "ledger.jsonl",
    family: "primary",
    required: true,
    mode: 384,
    bytes: ledgerBytes,
  }] as const;
  const built = buildRunManifestV04({
    ledger_bytes: ledgerBytes,
    created_at: "2026-08-30T10:01:00Z",
    captured_files: files,
  });
  if (!built.ok) throw new Error(built.reason);
  const manifest = inspectRunManifestV04({
    manifest_bytes: built.bytes,
    ledger_bytes: ledgerBytes,
    captured_files: files,
  });
  if (!manifest.ok) throw new Error(manifest.reason);
  return {
    plan,
    ledger: manifest.ledger,
    manifest: manifest.validated_manifest,
    attempt,
    action,
    compensation,
    repository_observation: repository.observation,
  };
}

function requestFor(
  scenario: ReturnType<typeof buildScenario>,
  mode: RuntimeRecoveryRequestIntentV04Value["requested_mode"] = "reconciliation-only",
): RuntimeRecoveryRequestIntentV04Value {
  if (mode === "ordinary") return {
    request_id: "request_s41",
    requested_mode: "ordinary",
    resume_nonce_hash: H("6"),
    authority_envelope_hash: AUTHORITY_HASH,
    target_action_admission_ref: null,
    compensation_phase_event_ref: null,
  };
  if (mode === "compensation-continuation") return {
    request_id: "request_s41",
    requested_mode: "compensation-continuation",
    resume_nonce_hash: H("6"),
    authority_envelope_hash: AUTHORITY_HASH,
    target_action_admission_ref: null,
    compensation_phase_event_ref: ref(scenario.compensation),
  };
  return {
    request_id: "request_s41",
    requested_mode: "reconciliation-only",
    resume_nonce_hash: H("6"),
    authority_envelope_hash: AUTHORITY_HASH,
    target_action_admission_ref: ref(scenario.action),
    compensation_phase_event_ref: null,
  };
}

function ownerStatusFor(
  scenario: ReturnType<typeof buildScenario>,
  status: "proven-stale" | "current" | "absent" | "ambiguous" = "proven-stale",
) {
  if (status === "absent") return { status: "absent" as const, evidence_refs: [] as const };
  if (status === "current") {
    return {
      status: "current" as const,
      owner_lease_event_ref: ref(scenario.attempt),
      evidence_refs: [ref(scenario.attempt)],
    };
  }
  if (status === "ambiguous") {
    return {
      status: "ambiguous" as const,
      ambiguous_reason: "heartbeat-at-deadline" as const,
      owner_lease_event_ref: ref(scenario.attempt),
      evidence_refs: [ref(scenario.attempt)],
    };
  }
  return {
    status: "proven-stale" as const,
    stale_reason: "same-domain-deadline-reached" as const,
    owner_lease_event_ref: ref(scenario.attempt),
    evidence_refs: [ref(scenario.attempt)],
  };
}

async function authorizedInput(options: Readonly<{
  scenario?: ReturnType<typeof buildScenario>;
  request?: RuntimeRecoveryRequestIntentV04Value;
  proofRunId?: string;
  proofPlanHash?: string;
  subjectHash?: string;
  scopeHash?: string;
  riskTier?: "T0" | "T1" | "T4";
  repositoryObservation?: ReturnType<typeof buildScenario>["repository_observation"];
}> = {}) {
  const scenario = options.scenario ?? buildScenario();
  const request = options.request ?? requestFor(scenario);
  const repositoryObservation = options.repositoryObservation ?? scenario.repository_observation;
  const pair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const trustInput = {
    observed_at: "2026-08-30T12:00:30Z",
    policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
    authentication_contexts: [{
      context_version: "0.1" as const,
      trust_domain: "local-operator",
      approval_channel: "local-ed25519" as const,
      authenticated_principal_ref: "operator_1",
      credential_ref: "operator_key_1",
      channel_subject_hash: H("1"),
      session_binding_hash: H("2"),
      assurance_level: "phishing-resistant" as const,
    }],
    operator_keys: [{
      operator_key_id: "operator_key_1",
      authenticated_principal_ref: "operator_1",
      trust_domain: "local-operator",
      public_key_spki_base64: pair.publicKey.toString("base64"),
      effective_from: "2026-08-30T12:00:00Z",
      effective_until: "2026-08-30T13:00:00Z",
      revoked_at: null,
    }],
    platform_channel_verifiers: [],
    host_producer_keys: [],
    authority_epochs: [{
      authenticated_principal_ref: "operator_1",
      revocation_epoch: 3,
      effective_from: "2026-08-30T12:00:00Z",
    }],
    durable_nonce_consumptions: [] as Readonly<Record<string, unknown>>[],
  };
  const initialTrust = captureAuthorityTrustContextV02(trustInput);
  if (!initialTrust.ok) throw new Error(initialTrust.error);
  let reserved: Readonly<Record<string, unknown>> | undefined;
  const nonce = captureNonceReservationCapabilityV02(async (row) => {
    reserved = row;
    return "reserved";
  });
  const signer = captureEd25519AuthoritySignerV02("operator_key_1", pair.privateKey);
  const subjectHash = options.subjectHash ?? hashRuntimeRecoveryAuthorizationSubjectV04({
    validated_plan: scenario.plan,
    ledger: scenario.ledger,
    manifest: scenario.manifest,
    request,
    repository_observation: repositoryObservation,
  });
  const scopeHash = options.scopeHash ?? hashRuntimeRecoveryActionScopeV04({
    validated_plan: scenario.plan,
    request,
    repository_observation: repositoryObservation,
  });
  if (subjectHash === null || scopeHash === null) throw new Error("hash fixture failed");
  const proof = await produceLocalHumanAuthorizationProofV02({
    trust_context: initialTrust.value,
    nonce_reservation: nonce,
    signer,
    request: {
      authorization_id: "authorization_1",
      run_id: options.proofRunId ?? scenario.plan.run_id,
      plan_hash: options.proofPlanHash ?? scenario.plan.plan_hash,
      authorization_subject_hash: subjectHash,
      authenticated_principal_ref: "operator_1",
      action_scope_hash: scopeHash,
      approved_risk_tier: options.riskTier ?? "T1",
      operator_key_id: "operator_key_1",
      approval_nonce: H("9"),
      issued_at: "2026-08-30T12:00:00Z",
      expires_at: "2026-08-30T12:05:00Z",
      revocation_epoch: 3,
    },
  });
  if (!proof.ok || reserved === undefined) throw new Error("proof fixture failed");
  const trust = captureAuthorityTrustContextV02({
    ...trustInput,
    durable_nonce_consumptions: [reserved],
  });
  if (!trust.ok) throw new Error(trust.error);
  return {
    scenario,
    request,
    input: {
      trust_context: trust.value,
      authorization_proof: proof.value,
      validated_plan: scenario.plan,
      ledger: scenario.ledger,
      manifest: scenario.manifest,
      request,
      repository_observation: repositoryObservation,
    },
  };
}

const INVALID = {
  ok: false,
  error: "RUNTIME_RECOVERY_REQUEST_AUTHORIZATION_INVALID",
} as const;

describe("S41 authenticated recovery request capture", () => {
  it("defines exactly three strict, mode-specific request shapes", () => {
    const scenario = buildScenario();
    for (const mode of ["ordinary", "reconciliation-only", "compensation-continuation"] as const) {
      expect(RuntimeRecoveryRequestIntentV04.safeParse(requestFor(scenario, mode)).success).toBe(true);
    }
    expect(RuntimeRecoveryRequestIntentV04.safeParse({
      ...requestFor(scenario, "ordinary"),
      extra: true,
    }).success).toBe(false);
    expect(RuntimeRecoveryRequestIntentV04.safeParse({
      ...requestFor(scenario, "reconciliation-only"),
      target_action_admission_ref: null,
    }).success).toBe(false);
  });

  it("captures a genuine T1 reconciliation authorization without consuming it", async () => {
    const fixture = await authorizedInput();
    const captured = captureRuntimeRecoveryRequestV04(fixture.input);
    expect(captured.ok).toBe(true);
    if (!captured.ok) return;
    const first = inspectCapturedRuntimeRecoveryRequestV04(captured.value);
    const second = inspectCapturedRuntimeRecoveryRequestV04(captured.value);
    expect(first).toMatchObject({
      validated_plan: fixture.scenario.plan,
      ledger: fixture.scenario.ledger,
      manifest: fixture.scenario.manifest,
      run_id: fixture.scenario.plan.run_id,
      plan_hash: fixture.scenario.plan.plan_hash,
      source_boundary_sequence: fixture.scenario.ledger.sequence,
      source_boundary_head_hash: fixture.scenario.ledger.head_hash,
      source_manifest_hash: fixture.scenario.manifest.manifest_hash,
      current_attempt_event_ref: ref(fixture.scenario.attempt),
      request: fixture.request,
      authority_ref: "operator_1",
      revocation_epoch: 3,
      approved_risk_tier: "T1",
      current_repository_state_hash: fixture.scenario.repository_observation.repository_state_hash,
    });
    expect(second).toEqual(first);
    expect(second).not.toBe(first);
    expect(second?.request).not.toBe(first?.request);
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first?.request)).toBe(true);
    expect(planRuntimeRecoveryV04({
      ledger: fixture.scenario.ledger,
      manifest: fixture.scenario.manifest,
      plan: fixture.scenario.plan,
      owner_status: ownerStatusFor(fixture.scenario),
      request: captured.value,
      summary: null,
    })).toMatchObject({
      ok: true,
      decision: {
        disposition: "eligible",
        mode: "reconciliation-only",
      },
    });
    const reInspectedLookalike = buildScenario();
    expect(planRuntimeRecoveryV04({
      ledger: reInspectedLookalike.ledger,
      manifest: reInspectedLookalike.manifest,
      plan: reInspectedLookalike.plan,
      owner_status: ownerStatusFor(reInspectedLookalike),
      request: captured.value,
      summary: null,
    })).toEqual({ ok: false, reason: "INVALID_RUNTIME_RECOVERY_INPUT" });
    const elevated = await authorizedInput({ riskTier: "T4" });
    expect(captureRuntimeRecoveryRequestV04(elevated.input).ok).toBe(true);
  });

  it("proof-binds and consumes one genuine current repository observation", async () => {
    const fixture = await authorizedInput();
    const captured = captureRuntimeRecoveryRequestV04(fixture.input);
    expect(captured.ok).toBe(true);
    expect(captureRuntimeRecoveryRequestV04(fixture.input)).toEqual(INVALID);
  });

  it("allows repeatable planning inspection but consumes the executable request exactly once", async () => {
    const fixture = await authorizedInput();
    const captured = captureRuntimeRecoveryRequestV04(fixture.input);
    if (!captured.ok) throw new Error(captured.error);
    expect(inspectCapturedRuntimeRecoveryRequestV04(captured.value)).not.toBeNull();
    expect(inspectCapturedRuntimeRecoveryRequestV04(captured.value)).not.toBeNull();
    expect(consumeCapturedRuntimeRecoveryRequestV04(captured.value)).not.toBeNull();
    expect(consumeCapturedRuntimeRecoveryRequestV04(captured.value)).toBeNull();
    expect(inspectCapturedRuntimeRecoveryRequestV04(captured.value)).toBeNull();
  });

  it("surfaces authenticated repository drift instead of authorizing resume", async () => {
    const source = buildScenario("source");
    const drifted = buildScenario("drifted");
    const fixture = await authorizedInput({
      scenario: source,
      repositoryObservation: drifted.repository_observation,
    });
    const captured = captureRuntimeRecoveryRequestV04(fixture.input);
    expect(captured.ok).toBe(true);
    if (!captured.ok) return;
    expect(planRuntimeRecoveryV04({
      ledger: source.ledger,
      manifest: source.manifest,
      plan: source.plan,
      owner_status: ownerStatusFor(source),
      request: captured.value,
      summary: null,
    })).toEqual({
      ok: true,
      decision: { disposition: "refused", precedence: 5, reason_code: "repository-boundary-drift" },
    });
  });

  it("rejects wrong subject, scope, run, plan, authority, target, and T0 proofs", async () => {
    const scenario = buildScenario();
    const cases = [
      await authorizedInput({ scenario, subjectHash: H("0") }),
      await authorizedInput({ scenario, scopeHash: H("0") }),
      await authorizedInput({ scenario, proofRunId: "wrong_run" }),
      await authorizedInput({ scenario, proofPlanHash: H("0") }),
      await authorizedInput({
        scenario,
        request: { ...requestFor(scenario), authority_envelope_hash: H("0") },
      }),
      await authorizedInput({
        scenario,
        request: {
          ...requestFor(scenario),
          target_action_admission_ref: ref(scenario.attempt),
        },
      }),
      await authorizedInput({ scenario, riskTier: "T0" }),
    ];
    for (const fixture of cases) {
      expect(captureRuntimeRecoveryRequestV04(fixture.input)).toEqual(INVALID);
    }
  });

  it("rejects stale-head bindings, crossed branded pairs, and structural lookalikes", async () => {
    const first = await authorizedInput({
      scenario: buildScenario("a"),
      request: requestFor(buildScenario("a"), "ordinary"),
    });
    const changed = buildScenario("b");
    expect(captureRuntimeRecoveryRequestV04({
      ...first.input,
      validated_plan: changed.plan,
      ledger: changed.ledger,
      manifest: changed.manifest,
    })).toEqual(INVALID);
    expect(captureRuntimeRecoveryRequestV04({
      ...first.input,
      manifest: changed.manifest,
    })).toEqual(INVALID);
    expect(captureRuntimeRecoveryRequestV04({
      ...first.input,
      validated_plan: { ...first.scenario.plan },
    })).toEqual(INVALID);
    expect(captureRuntimeRecoveryRequestV04({
      ...first.input,
      ledger: { ...first.scenario.ledger },
    })).toEqual(INVALID);
    expect(inspectCapturedRuntimeRecoveryRequestV04({})).toBeNull();
  });

  it("copies mutable request input and keeps the capability package-internal", async () => {
    const fixture = await authorizedInput();
    expect(captureRuntimeRecoveryRequestV04({
      ...fixture.input,
      owner_status: ownerStatusFor(fixture.scenario),
    })).toEqual(INVALID);
    const mutableRequest = structuredClone(fixture.request) as {
      request_id: string;
      target_action_admission_ref: { ledger_sequence: number; event_hash: string };
    };
    const captured = captureRuntimeRecoveryRequestV04({
      ...fixture.input,
      request: mutableRequest,
    });
    expect(captured.ok).toBe(true);
    if (!captured.ok) return;
    mutableRequest.request_id = "mutated_request";
    mutableRequest.target_action_admission_ref.ledger_sequence = 999;
    expect(inspectCapturedRuntimeRecoveryRequestV04(captured.value)?.request).toEqual(fixture.request);
    expect("captureRuntimeRecoveryRequestV04" in root).toBe(false);
    expect("inspectCapturedRuntimeRecoveryRequestV04" in root).toBe(false);
  });
});
