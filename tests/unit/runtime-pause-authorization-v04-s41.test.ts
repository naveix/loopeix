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
  captureRuntimePauseRequestV04,
  consumeCapturedRuntimePauseRequestV04,
  hashRuntimePauseActionScopeV04,
  hashRuntimePauseAuthorizationSubjectV04,
  inspectCapturedRuntimePauseRequestV04,
} from "../../src/run/runtime-pause-authorization-v04.js";
import { inspectRuntimeLedgerV04 } from "../../src/run/runtime-ledger-v04.js";
import {
  buildRunManifestV04,
  inspectRunManifestV04,
} from "../../src/run/runtime-manifest-v04.js";
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
  envelope: Readonly<{ source?: RuntimeEventV04Value["source"]; authority_ref?: string | null }> = {},
) {
  const sequence = events.length + 1;
  const preimage = {
    schema_version: "0.4",
    event_id: `event_pause_authorization_${label}_${sequence}`,
    run_id: runId,
    sequence,
    recorded_at: `2026-08-30T16:00:${String(sequence).padStart(2, "0")}Z`,
    event_type: eventType,
    source: envelope.source ?? "kernel",
    authority_ref: envelope.authority_ref ?? null,
    risk_tier: "T1",
    related_ids: [],
    previous_event_hash: events.at(-1)?.event_hash ?? null,
    payload,
  };
  const event = RuntimeEventV04.parse({ ...preimage, event_hash: hashCanonical(preimage) });
  events.push(event);
  return event;
}

function buildScenario(
  label = "a",
  tail: "none" | "inactive-owner" | "pending-pause" | "pending-resume" | "terminal" = "none",
) {
  const repository = createRuntimeRepositoryObservationFixture(
    loadPlanV02(),
    tail === "none"
      ? label
      : ({
          "inactive-owner": "inactive_owner",
          "pending-pause": "pending_pause",
          "pending-resume": "pending_resume",
          terminal: "terminal",
        } as const)[tail],
  );
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
    observed_at: "2026-08-30T16:00:02Z",
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
  if (tail === "inactive-owner") {
    const clock = append(events, plan.run_id, "run.clock-observed", {
      clock_id: `release_clock_${label}`,
      observed_at: "2026-08-30T16:00:03Z",
      elapsed_ms: 2,
      reason: "owner-release",
      task_ref: null,
      failure_ordinal: null,
      use_ref: `owner_${label}`,
      attempt_ref: ref(attempt),
      owner_lease_ref: ref(attempt),
      boot_id_hash: H("1"),
      monotonic_clock_id: `monotonic_${label}`,
    }, label);
    append(events, plan.run_id, "ownership.lease-released", {
      owner_lease_event_ref: ref(attempt),
      release_clock_ref: ref(clock),
      reason: "completed",
      fence_epoch: 0,
    }, label);
  }
  if (tail === "pending-pause") {
    const clock = append(events, plan.run_id, "run.clock-observed", {
      clock_id: `pause_clock_${label}`,
      observed_at: "2026-08-30T16:00:03Z",
      elapsed_ms: 2,
      reason: "pause-request",
      task_ref: null,
      failure_ordinal: null,
      use_ref: `pending_pause_${label}`,
      attempt_ref: ref(attempt),
      owner_lease_ref: ref(attempt),
      boot_id_hash: null,
      monotonic_clock_id: null,
    }, label);
    append(events, plan.run_id, "control.pause-requested", {
      request_id: `pending_pause_${label}`,
      requested_by: "operator",
      reason_code: "operator-request",
      attempt_event_ref: ref(attempt),
      run_owner_lease_ref: ref(attempt),
      request_clock_ref: ref(clock),
      fence_epoch: 0,
    }, label, { source: "operator", authority_ref: "operator_1" });
  }
  if (tail === "pending-resume") {
    const clock = append(events, plan.run_id, "run.clock-observed", {
      clock_id: `recovery_clock_${label}`,
      observed_at: "2026-08-30T16:00:03Z",
      elapsed_ms: 2,
      reason: "recovery-request",
      task_ref: null,
      failure_ordinal: null,
      use_ref: `pending_resume_${label}`,
      attempt_ref: ref(attempt),
      owner_lease_ref: ref(attempt),
      boot_id_hash: null,
      monotonic_clock_id: null,
    }, label);
    append(events, plan.run_id, "recovery.resume-requested", {
      request_id: `pending_resume_${label}`,
      mode: "ordinary",
      resume_nonce_hash: H("7"),
      previous_attempt_event_ref: ref(attempt),
      source_boundary_sequence: clock.sequence,
      source_boundary_head_hash: clock.event_hash,
      source_manifest_hash: H("8"),
      repository_state_hash: repository.observation.repository_state_hash,
      request_clock_ref: ref(clock),
      plan_hash: plan.plan_hash,
      input_hash: plan.plan.runtime_input_hash,
      recovery_policy_hash: plan.plan.runtime_recovery_policy_hash,
      authority_envelope_hash: AUTHORITY_HASH,
      target_action_admission_ref: null,
      compensation_phase_event_ref: null,
    }, label, { source: "operator", authority_ref: "operator_1" });
  }
  if (tail === "terminal") {
    const freeze = append(events, plan.run_id, "run.terminal-freeze-entered", {
      revision: 1,
      candidate: "failed",
      candidate_evidence_refs: [ref(attempt)],
      fence_epoch: 0,
    }, label, { source: "evaluator" });
    append(events, plan.run_id, "run.terminal-sealed", {
      outcome: "failed",
      pre_seal_ledger_sequence: freeze.sequence,
      pre_seal_ledger_head_hash: freeze.event_hash,
      pre_seal_snapshot_hash: H("9"),
      previous_fence_epoch: 0,
      fence_epoch: 1,
    }, label, { source: "evaluator" });
  }
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
    created_at: "2026-08-30T16:01:00Z",
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
  };
}

async function authorizedOperatorInput(options: Readonly<{
  scenario?: ReturnType<typeof buildScenario>;
  subjectHash?: string;
  scopeHash?: string;
  proofRunId?: string;
  proofPlanHash?: string;
  riskTier?: "T0" | "T1" | "T4";
  finalObservedAt?: string;
  finalRevocationEpoch?: number;
}> = {}) {
  const scenario = options.scenario ?? buildScenario();
  const request = {
    request_id: "pause_request_s41",
  };
  const pair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const trustInput = {
    observed_at: "2026-08-30T16:10:30Z",
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
      effective_from: "2026-08-30T16:10:00Z",
      effective_until: "2026-08-30T17:00:00Z",
      revoked_at: null,
    }],
    platform_channel_verifiers: [],
    host_producer_keys: [],
    authority_epochs: [{
      authenticated_principal_ref: "operator_1",
      revocation_epoch: 3,
      effective_from: "2026-08-30T16:10:00Z",
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
  const subjectHash = options.subjectHash ?? hashRuntimePauseAuthorizationSubjectV04({
    validated_plan: scenario.plan,
    ledger: scenario.ledger,
    manifest: scenario.manifest,
    request,
  });
  const scopeHash = options.scopeHash ?? hashRuntimePauseActionScopeV04({
    validated_plan: scenario.plan,
    ledger: scenario.ledger,
    manifest: scenario.manifest,
    request,
  });
  if (subjectHash === null || scopeHash === null) throw new Error("hash fixture failed");
  const proof = await produceLocalHumanAuthorizationProofV02({
    trust_context: initialTrust.value,
    nonce_reservation: nonce,
    signer,
    request: {
      authorization_id: "authorization_pause_1",
      run_id: options.proofRunId ?? scenario.plan.run_id,
      plan_hash: options.proofPlanHash ?? scenario.plan.plan_hash,
      authorization_subject_hash: subjectHash,
      authenticated_principal_ref: "operator_1",
      action_scope_hash: scopeHash,
      approved_risk_tier: options.riskTier ?? "T1",
      operator_key_id: "operator_key_1",
      approval_nonce: H("9"),
      issued_at: "2026-08-30T16:10:00Z",
      expires_at: "2026-08-30T16:15:00Z",
      revocation_epoch: 3,
    },
  });
  if (!proof.ok || reserved === undefined) throw new Error("proof fixture failed");
  const trust = captureAuthorityTrustContextV02({
    ...trustInput,
    observed_at: options.finalObservedAt ?? trustInput.observed_at,
    authority_epochs: [{
      authenticated_principal_ref: "operator_1",
      revocation_epoch: options.finalRevocationEpoch ?? 3,
      effective_from: "2026-08-30T16:10:00Z",
    }],
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
    },
  };
}

describe("S41 bounded pause authorization", () => {
  it("hashes the exact independently specified operator subject and pause scope", () => {
    const scenario = buildScenario("preimage");
    const request = { request_id: "pause_request_s41" };
    const common = {
      run_id: scenario.plan.run_id,
      plan_hash: scenario.plan.plan_hash,
      runtime_input_hash: scenario.plan.plan.runtime_input_hash,
      runtime_recovery_policy_hash: scenario.plan.plan.runtime_recovery_policy_hash,
      request_id: request.request_id,
      requested_by: "operator",
      reason_code: "operator-request",
      current_attempt_event_ref: ref(scenario.attempt),
      run_owner_lease_event_ref: ref(scenario.attempt),
      current_fence_epoch: 0,
      authority_envelope_hash: AUTHORITY_HASH,
    } as const;
    expect(hashRuntimePauseAuthorizationSubjectV04({
      validated_plan: scenario.plan,
      ledger: scenario.ledger,
      manifest: scenario.manifest,
      request,
    })).toBe(hashCanonical({
      purpose: "runtime-pause-request-v04",
      schema_version: "0.4",
      ...common,
      source_boundary_sequence: scenario.ledger.sequence,
      source_boundary_head_hash: scenario.ledger.head_hash,
      source_manifest_hash: scenario.manifest.manifest_hash,
    }));
    expect(hashRuntimePauseActionScopeV04({
      validated_plan: scenario.plan,
      ledger: scenario.ledger,
      manifest: scenario.manifest,
      request,
    })).toBe(hashCanonical({
      purpose: "runtime-pause-scope-v04",
      schema_version: "0.4",
      operation: "pause",
      ...common,
    }));
  });

  it("captures one exact operator pause authorization, allows planning inspection, and consumes it once", async () => {
    const fixture = await authorizedOperatorInput();
    const captured = captureRuntimePauseRequestV04(fixture.input);
    expect(captured.ok).toBe(true);
    if (!captured.ok) return;

    const first = inspectCapturedRuntimePauseRequestV04(captured.value);
    const second = inspectCapturedRuntimePauseRequestV04(captured.value);
    expect(first).toMatchObject({
      run_id: fixture.scenario.plan.run_id,
      plan_hash: fixture.scenario.plan.plan_hash,
      validated_plan: fixture.scenario.plan,
      ledger: fixture.scenario.ledger,
      manifest: fixture.scenario.manifest,
      request: {
        request_id: fixture.request.request_id,
        requested_by: "operator",
        reason_code: "operator-request",
      },
      authority_ref: "operator_1",
      approved_risk_tier: "T1",
      current_attempt_event_ref: ref(fixture.scenario.attempt),
      run_owner_lease_event_ref: ref(fixture.scenario.attempt),
      current_fence_epoch: 0,
      source_boundary_sequence: fixture.scenario.ledger.sequence,
      source_boundary_head_hash: fixture.scenario.ledger.head_hash,
      source_manifest_hash: fixture.scenario.manifest.manifest_hash,
      authority_envelope_hash: AUTHORITY_HASH,
      runtime_input_hash: fixture.scenario.plan.plan.runtime_input_hash,
      runtime_recovery_policy_hash: fixture.scenario.plan.plan.runtime_recovery_policy_hash,
    });
    expect(second).toEqual(first);
    expect(second).not.toBe(first);
    expect(second?.request).not.toBe(first?.request);
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first?.request)).toBe(true);
    expect("captureRuntimePauseRequestV04" in root).toBe(false);
    expect("inspectCapturedRuntimePauseRequestV04" in root).toBe(false);
    expect("consumeCapturedRuntimePauseRequestV04" in root).toBe(false);

    const consumed = consumeCapturedRuntimePauseRequestV04(captured.value);
    expect(consumed).toMatchObject(first!);
    expect(consumeCapturedRuntimePauseRequestV04(captured.value)).toBeNull();
    expect(inspectCapturedRuntimePauseRequestV04(captured.value)).toBeNull();
  });

  it.each([
    ["wrong subject", { subjectHash: H("d") }],
    ["wrong operation scope", { scopeHash: H("e") }],
    ["wrong proof run", { proofRunId: "run_wrong" }],
    ["wrong proof plan", { proofPlanHash: H("d") }],
    ["risk below T1", { riskTier: "T0" as const }],
    ["expired proof", { finalObservedAt: "2026-08-30T16:15:00Z" }],
    ["revoked authority epoch", { finalRevocationEpoch: 4 }],
  ])("rejects %s", async (_label, options) => {
    const fixture = await authorizedOperatorInput(options);
    expect(captureRuntimePauseRequestV04(fixture.input)).toEqual({
      ok: false,
      error: "RUNTIME_PAUSE_REQUEST_AUTHORIZATION_INVALID",
    });
  });

  it("rejects a mismatched ledger/manifest pair and exact boundary drift", async () => {
    const fixture = await authorizedOperatorInput();
    const other = buildScenario("other");
    expect(captureRuntimePauseRequestV04({
      ...fixture.input,
      ledger: other.ledger,
    })).toMatchObject({ ok: false });
    expect(captureRuntimePauseRequestV04({
      ...fixture.input,
      manifest: other.manifest,
    })).toMatchObject({ ok: false });
  });

  it.each([
    ["inactive run owner", "inactive-owner" as const],
    ["pending pause", "pending-pause" as const],
    ["pending resume", "pending-resume" as const],
    ["terminal run", "terminal" as const],
  ])("rejects capture at an %s boundary", async (_label, tail) => {
    const scenario = buildScenario(`boundary_${tail.replaceAll("-", "_")}`, tail);
    const fixture = await authorizedOperatorInput();
    expect(captureRuntimePauseRequestV04({
      ...fixture.input,
      validated_plan: scenario.plan,
      ledger: scenario.ledger,
      manifest: scenario.manifest,
    })).toMatchObject({ ok: false });
  });

  it("rejects extra fields, accessors, proxy traps, and structural capability forgeries", async () => {
    const fixture = await authorizedOperatorInput();
    expect(captureRuntimePauseRequestV04({
      ...fixture.input,
      repository_observation: {},
    })).toMatchObject({ ok: false });
    expect(captureRuntimePauseRequestV04({
      ...fixture.input,
      request: { ...fixture.request, requested_by: "operator" },
    })).toMatchObject({ ok: false });
    const accessorInput = { ...fixture.input } as Record<string, unknown>;
    Object.defineProperty(accessorInput, "request", {
      enumerable: true,
      get: () => fixture.request,
    });
    expect(captureRuntimePauseRequestV04(accessorInput)).toMatchObject({ ok: false });
    const trapped = new Proxy({ ...fixture.input }, {
      ownKeys: () => { throw new Error("trap"); },
    });
    expect(captureRuntimePauseRequestV04(trapped)).toMatchObject({ ok: false });
    expect(inspectCapturedRuntimePauseRequestV04({})).toBeNull();
    expect(consumeCapturedRuntimePauseRequestV04({})).toBeNull();
  });
});
