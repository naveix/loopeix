import { generateKeyPairSync } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
  constants,
} from "node:fs";
import { open as openFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import { S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02 } from "../../src/run/action-classifier-policy-v02.js";
import { inspectRuntimePlanV03, projectRuntimePlanV03 } from "../../src/run/project-plan-v03.js";
import {
  captureAuthorityTrustContextV02,
  captureEd25519AuthoritySignerV02,
  captureNonceReservationCapabilityV02,
  produceLocalHumanAuthorizationProofV02,
} from "../../src/run/runtime-record-admission-v02.js";
import {
  captureRuntimeRecoveryRequestV04,
  hashRuntimeRecoveryActionScopeV04,
  hashRuntimeRecoveryAuthorizationSubjectV04,
} from "../../src/run/runtime-recovery-authorization-v04.js";
import {
  captureRuntimePauseRequestV04,
  hashRuntimePauseActionScopeV04,
  hashRuntimePauseAuthorizationSubjectV04,
} from "../../src/run/runtime-pause-authorization-v04.js";
import {
  captureRuntimeFileStoreV04,
  captureRuntimeFileStoreV04ForTest,
  closeRuntimeFileStoreSessionV04,
  openRuntimeFileStoreSessionV04,
} from "../../src/run/runtime-file-store-v04.js";
import {
  captureRuntimeClockSourceV04,
  observeRuntimeClockV04,
} from "../../src/run/runtime-clock-observation-v04.js";
import { inspectRuntimeLedgerV04 } from "../../src/run/runtime-ledger-v04.js";
import { buildRunManifestV04, inspectRunManifestV04 } from "../../src/run/runtime-manifest-v04.js";
import {
  compactRuntimeWriteSessionV04,
  continuePendingPauseRuntimeWriteSessionV04,
  heartbeatRuntimeOwnerLeaseV04,
  pauseRuntimeWriteSessionV04,
  releaseRuntimeOwnerLeaseV04,
  resumeRuntimeWriteSessionV04,
} from "../../src/run/runtime-write-session-v04.js";
import { ResolvedRunPlanV02, type ResolvedRunPlanV02Value } from "../../src/schema/runtime.js";
import { captureRuntimeProfileRegistryV03 } from "../../src/schema/runtime-plan-v03.js";
import { RuntimeEventV04, type RuntimeEventV04Value } from "../../src/schema/runtime-v04.js";
import * as rootExports from "../../src/index.js";
import { createRuntimeRepositoryObservationFixture } from "../helpers/runtime-repository-observation-fixture.js";

const E = new TextEncoder();
const H = (value: string): string => `sha256:${value.repeat(64)}`;
const bootHash = (label: string): string => hashCanonical({
  purpose: "runtime-clock-boot-identity-v04",
  schema_version: "0.4",
  boot_identity: `boot_${label}`,
});
const roots: string[] = [];
const repositoryCleanups: Array<() => void> = [];
const inventory = {
  resolved_run_plan: "0.3", ledger_event: "0.4", run_manifest: "0.4",
  artifact_manifest: "0.2", redaction_derivative: "0.2", human_authorization_proof: "0.2",
  authority_envelope: "0.2", agency_recommendation: "0.2", authority_revocation: "0.2",
  task_result: "0.2", manual_observation: "0.2", export_decision: "0.2", evidence_item: "0.2",
  gate_result: "0.2", evaluation_result: "0.2", claim: "0.2", finding: "0.2", waiver: "0.2",
  gate_waiver_authority: "0.2", summary_artifact: "0.1",
} as const;

function loadPlanV02(): ResolvedRunPlanV02Value {
  return ResolvedRunPlanV02.parse(JSON.parse(readFileSync(
    join(import.meta.dirname, "../fixtures/compat/s35/v02/planned-run/resolved-run-plan.json"),
    "utf8",
  )));
}

function write0600(path: string, bytes: Uint8Array): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, bytes, { mode: 0o600 });
  chmodSync(path, 0o600);
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
  source: RuntimeEventV04Value["source"] = "kernel",
  authorityRef: string | null = null,
) {
  const sequence = events.length + 1;
  const preimage = {
    schema_version: "0.4",
    event_id: `event_write_fixture_${label}_${sequence}`,
    run_id: runId,
    sequence,
    recorded_at: `2026-08-30T10:00:${String(sequence).padStart(2, "0")}Z`,
    event_type: eventType,
    source,
    authority_ref: authorityRef,
    risk_tier: "T1",
    related_ids: [],
    previous_event_hash: events.at(-1)?.event_hash ?? null,
    payload,
  };
  const value = RuntimeEventV04.parse({ ...preimage, event_hash: hashCanonical(preimage) });
  events.push(value);
  return value;
}

function fixture(
  label = "a",
  subordinate?: Readonly<{ scope: "task" | "integrator"; heartbeat_limit?: number; deadline_elapsed_ms?: number }>,
) {
  const repository = createRuntimeRepositoryObservationFixture(loadPlanV02(), `write_${label}`);
  repositoryCleanups.push(repository.cleanup);
  const projected = projectRuntimePlanV03(repository.plan, captureRuntimeProfileRegistryV03());
  if (!projected.ok) throw new Error(projected.reason);
  const planBytes = E.encode(`${JSON.stringify(projected.value, null, 2)}\n`);
  const plan = inspectRuntimePlanV03(planBytes);
  if (!plan.ok) throw new Error(plan.reason);
  const events: RuntimeEventV04Value[] = [];
  append(events, plan.validated_plan.run_id, "run.initialized", {
    plan_hash: plan.validated_plan.plan_hash,
    initial_fence_epoch: 0,
    runtime_schema_versions: inventory,
  }, label);
  const started = append(events, plan.validated_plan.run_id, "run.started", { executor_profile_hash: H("b") }, label);
  const ownerClock = append(events, plan.validated_plan.run_id, "run.clock-observed", {
    clock_id: `clock_initial_${label}`,
    observed_at: "2026-08-30T10:00:02Z",
    elapsed_ms: 1,
    reason: "run-owner-acquisition",
    task_ref: null,
    failure_ordinal: null,
    use_ref: `owner_initial_${label}`,
    attempt_ref: null,
    owner_lease_ref: null,
    boot_id_hash: bootHash(label),
    monotonic_clock_id: `monotonic_initial_${label}`,
  }, label);
  const attempt = append(events, plan.validated_plan.run_id, "execution.attempt-started", {
    attempt_id: `attempt_initial_${label}`,
    attempt_ordinal: 1,
    mode: "ordinary",
    previous_attempt_event_ref: null,
    resume_request_event_ref: null,
    resume_nonce_hash: null,
    source_boundary_sequence: started.sequence,
    source_boundary_head_hash: started.event_hash,
    source_manifest_hash: H("c"),
    plan_hash: plan.validated_plan.plan_hash,
    input_hash: plan.validated_plan.plan.runtime_input_hash,
    recovery_policy_hash: plan.validated_plan.plan.runtime_recovery_policy_hash,
    authority_envelope_hash: H("f"),
    repository_state_hash: repository.observation.repository_state_hash,
    run_owner_lease_id: `owner_initial_${label}`,
    issued_clock_ref: ref(ownerClock),
    deadline_elapsed_ms: 1_000,
    boot_id_hash: bootHash(label),
    monotonic_clock_id: `monotonic_initial_${label}`,
    previous_fence_epoch: 0,
    fence_epoch: 0,
  }, label);
  const subordinateClock = subordinate === undefined ? null : append(events, plan.validated_plan.run_id, "run.clock-observed", {
    clock_id: `clock_subordinate_${label}`,
    observed_at: "2026-08-30T10:00:05Z",
    elapsed_ms: 10,
    reason: "owner-acquisition",
    task_ref: null,
    failure_ordinal: null,
    use_ref: `owner_subordinate_${label}`,
    attempt_ref: ref(attempt),
    owner_lease_ref: ref(attempt),
    boot_id_hash: bootHash(label),
    monotonic_clock_id: `monotonic_initial_${label}`,
  }, label);
  const subordinateOwner = subordinate === undefined || subordinateClock === null ? null : append(
    events,
    plan.validated_plan.run_id,
    "ownership.lease-acquired",
    {
      owner_lease_id: `owner_subordinate_${label}`,
      scope: subordinate.scope,
      scope_ref: subordinate.scope === "task" ? "task-s41" : `integrator_${label}`,
      parent_run_owner_lease_id: `owner_initial_${label}`,
      attempt_event_ref: ref(attempt),
      issued_clock_ref: ref(subordinateClock),
      deadline_elapsed_ms: subordinate.deadline_elapsed_ms ?? 900,
      boot_id_hash: bootHash(label),
      monotonic_clock_id: `monotonic_initial_${label}`,
      fence_epoch: 0,
      heartbeat_limit: subordinate.heartbeat_limit ?? 2,
    },
    label,
    "policy-enforcement-point",
    `authority_${label}`,
  );
  const ledgerBytes = E.encode(`${events.map((event) => JSON.stringify(event)).join("\n")}\n`);
  const files = [
    { path: "resolved-run-plan.json", family: "primary" as const, required: true, mode: 384 as const, bytes: planBytes },
    { path: "ledger.jsonl", family: "primary" as const, required: true, mode: 384 as const, bytes: ledgerBytes },
  ];
  const manifestBuilt = buildRunManifestV04({
    ledger_bytes: ledgerBytes,
    created_at: "2026-08-30T10:01:00Z",
    captured_files: files,
  });
  if (!manifestBuilt.ok) throw new Error(manifestBuilt.reason);
  const manifest = inspectRunManifestV04({
    manifest_bytes: manifestBuilt.bytes,
    ledger_bytes: ledgerBytes,
    captured_files: files,
  });
  if (!manifest.ok) throw new Error(manifest.reason);
  const root = realpathSync(mkdtempSync(join(tmpdir(), "loopeix-runtime-recovery-write-")));
  roots.push(root);
  write0600(join(root, "resolved-run-plan.json"), planBytes);
  write0600(join(root, "ledger.jsonl"), ledgerBytes);
  write0600(join(root, "run-manifest.json"), manifestBuilt.bytes);
  return {
    root,
    plan: plan.validated_plan,
    ledger: manifest.ledger,
    manifest: manifest.validated_manifest,
    attempt,
    subordinate_owner: subordinateOwner,
    repository_observation: repository.observation,
    fresh_repository_observation: repository.freshObservation,
  };
}

function ownerStatus(value: ReturnType<typeof fixture>) {
  return {
    status: "proven-stale" as const,
    stale_reason: "same-domain-deadline-reached" as const,
    owner_lease_event_ref: ref(value.attempt),
    evidence_refs: [ref(value.attempt)],
  };
}

async function captureRequest(value: ReturnType<typeof fixture>, riskTier: "T1" | "T4" = "T1") {
  const repositoryObservation = value.fresh_repository_observation();
  const request = {
    request_id: `request_recovery_${value.attempt.event_id}`,
    requested_mode: "ordinary" as const,
    resume_nonce_hash: H("6"),
    authority_envelope_hash: H("f"),
    target_action_admission_ref: null,
    compensation_phase_event_ref: null,
  };
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
      authenticated_principal_ref: "operator_write_s41",
      credential_ref: "operator_key_write_s41",
      channel_subject_hash: H("1"),
      session_binding_hash: H("2"),
      assurance_level: "phishing-resistant" as const,
    }],
    operator_keys: [{
      operator_key_id: "operator_key_write_s41",
      authenticated_principal_ref: "operator_write_s41",
      trust_domain: "local-operator",
      public_key_spki_base64: pair.publicKey.toString("base64"),
      effective_from: "2026-08-30T12:00:00Z",
      effective_until: "2026-08-30T13:00:00Z",
      revoked_at: null,
    }],
    platform_channel_verifiers: [],
    host_producer_keys: [],
    authority_epochs: [{
      authenticated_principal_ref: "operator_write_s41",
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
  const subjectHash = hashRuntimeRecoveryAuthorizationSubjectV04({
    validated_plan: value.plan,
    ledger: value.ledger,
    manifest: value.manifest,
    request,
    repository_observation: repositoryObservation,
  });
  const scopeHash = hashRuntimeRecoveryActionScopeV04({
    validated_plan: value.plan,
    request,
    repository_observation: repositoryObservation,
  });
  if (subjectHash === null || scopeHash === null) throw new Error("authorization hashes failed");
  const proof = await produceLocalHumanAuthorizationProofV02({
    trust_context: initialTrust.value,
    nonce_reservation: nonce,
    signer: captureEd25519AuthoritySignerV02("operator_key_write_s41", pair.privateKey),
    request: {
      authorization_id: `authorization_${value.attempt.event_id}`,
      run_id: value.plan.run_id,
      plan_hash: value.plan.plan_hash,
      authorization_subject_hash: subjectHash,
      authenticated_principal_ref: "operator_write_s41",
      action_scope_hash: scopeHash,
      approved_risk_tier: riskTier,
      operator_key_id: "operator_key_write_s41",
      approval_nonce: H("9"),
      issued_at: "2026-08-30T12:00:00Z",
      expires_at: "2026-08-30T12:05:00Z",
      revocation_epoch: 3,
    },
  });
  if (!proof.ok || reserved === undefined) throw new Error("authorization proof failed");
  const trust = captureAuthorityTrustContextV02({ ...trustInput, durable_nonce_consumptions: [reserved] });
  if (!trust.ok) throw new Error(trust.error);
  const captured = captureRuntimeRecoveryRequestV04({
    trust_context: trust.value,
    authorization_proof: proof.value,
    validated_plan: value.plan,
    ledger: value.ledger,
    manifest: value.manifest,
    request,
    repository_observation: repositoryObservation,
  });
  if (!captured.ok) throw new Error(captured.error);
  return captured.value;
}

async function capturePauseRequest(value: ReturnType<typeof fixture>, riskTier: "T1" | "T4" = "T1") {
  const request = { request_id: `pause_${value.attempt.event_id}` };
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
      authenticated_principal_ref: "operator_pause_write_s41",
      credential_ref: "operator_key_pause_write_s41",
      channel_subject_hash: H("1"),
      session_binding_hash: H("2"),
      assurance_level: "phishing-resistant" as const,
    }],
    operator_keys: [{
      operator_key_id: "operator_key_pause_write_s41",
      authenticated_principal_ref: "operator_pause_write_s41",
      trust_domain: "local-operator",
      public_key_spki_base64: pair.publicKey.toString("base64"),
      effective_from: "2026-08-30T12:00:00Z",
      effective_until: "2026-08-30T13:00:00Z",
      revoked_at: null,
    }],
    platform_channel_verifiers: [],
    host_producer_keys: [],
    authority_epochs: [{
      authenticated_principal_ref: "operator_pause_write_s41",
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
  const subjectHash = hashRuntimePauseAuthorizationSubjectV04({
    validated_plan: value.plan,
    ledger: value.ledger,
    manifest: value.manifest,
    request,
  });
  const scopeHash = hashRuntimePauseActionScopeV04({
    validated_plan: value.plan,
    ledger: value.ledger,
    manifest: value.manifest,
    request,
  });
  if (subjectHash === null || scopeHash === null) throw new Error("pause authorization hashes failed");
  const proof = await produceLocalHumanAuthorizationProofV02({
    trust_context: initialTrust.value,
    nonce_reservation: nonce,
    signer: captureEd25519AuthoritySignerV02("operator_key_pause_write_s41", pair.privateKey),
    request: {
      authorization_id: `authorization_pause_${value.attempt.event_id}`,
      run_id: value.plan.run_id,
      plan_hash: value.plan.plan_hash,
      authorization_subject_hash: subjectHash,
      authenticated_principal_ref: "operator_pause_write_s41",
      action_scope_hash: scopeHash,
      approved_risk_tier: riskTier,
      operator_key_id: "operator_key_pause_write_s41",
      approval_nonce: H("8"),
      issued_at: "2026-08-30T12:00:00Z",
      expires_at: "2026-08-30T12:05:00Z",
      revocation_epoch: 3,
    },
  });
  if (!proof.ok || reserved === undefined) throw new Error("pause authorization proof failed");
  const trust = captureAuthorityTrustContextV02({ ...trustInput, durable_nonce_consumptions: [reserved] });
  if (!trust.ok) throw new Error(trust.error);
  const captured = captureRuntimePauseRequestV04({
    trust_context: trust.value,
    authorization_proof: proof.value,
    validated_plan: value.plan,
    ledger: value.ledger,
    manifest: value.manifest,
    request,
  });
  if (!captured.ok) throw new Error(captured.error);
  return captured.value;
}

function freshInput(
  capturedRequest: Awaited<ReturnType<typeof captureRequest>>,
  value: ReturnType<typeof fixture>,
  elapsed = 100,
) {
  return {
    kind: "fresh" as const,
    captured_request: capturedRequest,
    owner_status: ownerStatus(value),
    summary: null,
    request_clock: {
      event_id: "event_recovery_request_clock_s41",
      clock_id: "clock_recovery_request_s41",
      observation: clockObservation("recovery_request_s41", elapsed, "2026-08-30T12:01:01Z"),
    },
    run_owner_clock: {
      event_id: "event_recovery_owner_clock_s41",
      clock_id: "clock_recovery_owner_s41",
      observation: clockObservation("recovery_owner_s41_2", elapsed + 1, "2026-08-30T12:01:02Z", {
        boot_identity: "boot_recovery_s41_2",
        monotonic_clock_id: "monotonic_recovery_s41_2",
      }),
      run_owner_lease_id: "owner_recovery_s41_2",
    },
    request_event: { event_id: "event_recovery_request_s41" },
    attempt_event: {
      event_id: "event_recovery_attempt_s41",
      attempt_id: "attempt_recovery_s41_2",
    },
  };
}

function clockObservation(
  label: string,
  elapsedMs: number,
  observedAt = "2026-08-30T10:00:10Z",
  domain: Readonly<{ boot_identity?: string; monotonic_clock_id?: string }> = {},
) {
  const source = captureRuntimeClockSourceV04({
    boot_identity: domain.boot_identity ?? `boot_${label}`,
    monotonic_clock_id: domain.monotonic_clock_id ?? `monotonic_initial_${label}`,
    observe: () => ({ observed_at: observedAt, elapsed_ms: elapsedMs }),
  });
  if (source === null) throw new Error("clock source capture failed");
  const observed = observeRuntimeClockV04(source);
  if (!observed.ok) throw new Error(observed.error);
  return observed.value;
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
  for (const cleanup of repositoryCleanups.splice(0)) cleanup();
});

describe("S41-C2 durable recovery write session", () => {
  it("derives and commits one immutable summary compaction without caller hashes", async () => {
    const value = fixture("compaction_write", { scope: "integrator" });
    if (value.subordinate_owner === null) throw new Error("integrator fixture missing");
    mkdirSync(join(value.root, "summaries/content"), { recursive: true, mode: 0o700 });
    mkdirSync(join(value.root, "summaries/records"), { recursive: true, mode: 0o700 });
    chmodSync(join(value.root, "summaries"), 0o700);
    chmodSync(join(value.root, "summaries/content"), 0o700);
    chmodSync(join(value.root, "summaries/records"), 0o700);
    const store = await captureRuntimeFileStoreV04({ run_directory: value.root });
    if (!store.ok) throw new Error(store.error);
    const head = value.ledger.events.at(-1)!;
    const result = await compactRuntimeWriteSessionV04(store.store, {
      summary_id: "integrator_compaction_write",
      content_bytes: E.encode("exact bounded summary content"),
      integrator_lease_event_ref: ref(value.subordinate_owner),
      source_first_event_ref: ref(value.ledger.events[0]!),
      source_last_event_ref: ref(head),
      source_prefix_event_ref: ref(head),
      observation: clockObservation("compaction_write", 500, "2026-08-30T12:01:00Z"),
      event_id: "event_compaction_write_s41",
    });
    expect(result).toMatchObject({ ok: true, classification: "COMMITTED" });
    const ledger = inspectRuntimeLedgerV04(new Uint8Array(readFileSync(join(value.root, "ledger.jsonl"))));
    if (!ledger.ok) throw new Error(ledger.reason);
    const compaction = ledger.ledger.events.at(-1)!;
    expect(compaction).toMatchObject({
      event_type: "run.compaction-recorded",
      payload: {
        summary_id: "integrator_compaction_write",
        integrator_lease_event_ref: ref(value.subordinate_owner),
        source_prefix_sequence: head.sequence,
        source_prefix_head_hash: head.event_hash,
      },
    });
    expect(readFileSync(join(value.root, "summaries/content/integrator_compaction_write.bin"))).toEqual(Buffer.from("exact bounded summary content"));
    expect(readFileSync(join(value.root, "summaries/records/integrator_compaction_write.json")).byteLength).toBeGreaterThan(0);
    expect("pre_context_hash" in (result as Record<string, unknown>)).toBe(false);
    expect("post_context_hash" in (result as Record<string, unknown>)).toBe(false);
  });

  it("commits an authorized pause as an intent followed by one exact fence boundary", async () => {
    const value = fixture("pause_success");
    const captured = await capturePauseRequest(value, "T4");
    const store = await captureRuntimeFileStoreV04({ run_directory: value.root });
    if (!store.ok) throw new Error(store.error);
    const result = await pauseRuntimeWriteSessionV04(store.store, {
      captured_request: captured,
      observation: clockObservation("pause_success", 500, "2026-08-30T12:01:00Z"),
      clock_event_id: "clock_pause_success_s41",
      request_event_id: "event_pause_request_success_s41",
      fence_event_id: "event_pause_fence_success_s41",
      paused_event_id: "event_paused_success_s41",
    });
    expect(result).toMatchObject({ ok: true, classification: "COMMITTED" });
    const ledger = inspectRuntimeLedgerV04(new Uint8Array(readFileSync(join(value.root, "ledger.jsonl"))));
    if (!ledger.ok) throw new Error(ledger.reason);
    const [clock, request, fence, paused] = ledger.ledger.events.slice(-4);
    expect(ledger.ledger.state.state).toBe("paused");
    expect([clock, request, fence, paused].map((row) => row?.event_type)).toEqual([
      "run.clock-observed", "control.pause-requested", "run.fence-advanced", "run.paused",
    ]);
    expect(request).toMatchObject({ source: "operator", authority_ref: "operator_pause_write_s41", risk_tier: "T4" });
    expect(fence).toMatchObject({
      source: "policy-enforcement-point",
      authority_ref: "operator_pause_write_s41",
      payload: { previous_fence_epoch: 0, fence_epoch: 1, reason: "pause-request", owner_lease_refs: [ref(value.attempt)] },
    });
    expect(paused).toMatchObject({
      source: "operator",
      authority_ref: "operator_pause_write_s41",
      payload: {
        request_event_ref: ref(request!),
        attempt_event_ref: ref(value.attempt),
        quiescent_boundary_sequence: fence!.sequence,
        quiescent_boundary_head_hash: fence!.event_hash,
        previous_fence_epoch: 0,
        fence_epoch: 1,
        invalidated_owner_lease_refs: [ref(value.attempt)],
      },
    });
  });

  it("reports a durable pause intent when the fence commit is proven not written", async () => {
    const value = fixture("pause_partial");
    const captured = await capturePauseRequest(value);
    let appendOpens = 0;
    const store = await captureRuntimeFileStoreV04ForTest({ run_directory: value.root }, {
      open: async (path, flags, mode) => {
        if ((flags & constants.O_APPEND) === constants.O_APPEND) {
          appendOpens += 1;
          if (appendOpens === 2) throw new Error("proven second-commit pre-write failure");
        }
        return mode === undefined ? openFile(path, flags) : openFile(path, flags, mode);
      },
    });
    if (!store.ok) throw new Error(store.error);
    const result = await pauseRuntimeWriteSessionV04(store.store, {
      captured_request: captured,
      observation: clockObservation("pause_partial", 500, "2026-08-30T12:01:00Z"),
      clock_event_id: "clock_pause_partial_s41",
      request_event_id: "event_pause_request_partial_s41",
      fence_event_id: "event_pause_fence_partial_s41",
      paused_event_id: "event_paused_partial_s41",
    });
    expect(result).toMatchObject({
      ok: false,
      classification: "REQUEST_COMMITTED_PAUSE_NOT_COMMITTED",
      error: "RUNTIME_PAUSE_NOT_COMMITTED",
    });
    const ledger = inspectRuntimeLedgerV04(new Uint8Array(readFileSync(join(value.root, "ledger.jsonl"))));
    if (!ledger.ok) throw new Error(ledger.reason);
    expect(ledger.ledger.events.slice(-2).map((row) => row.event_type)).toEqual([
      "run.clock-observed", "control.pause-requested",
    ]);
    expect(ledger.ledger.state.state).toBe("running");
    if (result.ok || result.request_event_ref === undefined) return;
    const restarted = await captureRuntimeFileStoreV04({ run_directory: value.root });
    if (!restarted.ok) throw new Error(restarted.error);
    const completed = await continuePendingPauseRuntimeWriteSessionV04(restarted.store, {
      pending_request_event_ref: result.request_event_ref,
      observation: clockObservation("pause_partial", 501, "2026-08-30T12:01:01Z"),
      fence_event_id: "event_pause_fence_restarted_s41",
      paused_event_id: "event_paused_restarted_s41",
    });
    expect(completed).toMatchObject({ ok: true, classification: "COMMITTED" });
    const finalLedger = inspectRuntimeLedgerV04(new Uint8Array(readFileSync(join(value.root, "ledger.jsonl"))));
    if (!finalLedger.ok) throw new Error(finalLedger.reason);
    expect(finalLedger.ledger.state.state).toBe("paused");
  });

  it("heartbeats the exact active run owner in one durable clock-and-event commit", async () => {
    const value = fixture("heartbeat_run");
    const store = await captureRuntimeFileStoreV04({ run_directory: value.root });
    if (!store.ok) throw new Error(store.error);

    const result = await heartbeatRuntimeOwnerLeaseV04(store.store, {
      owner_lease_event_ref: ref(value.attempt),
      observation: clockObservation("heartbeat_run", 500),
      clock_event_id: "clock_heartbeat_run_s41",
      heartbeat_event_id: "event_heartbeat_run_s41",
    });

    if (!result.ok) throw new Error(JSON.stringify(result));
    expect(result).toMatchObject({ ok: true, classification: "COMMITTED" });
    const ledger = inspectRuntimeLedgerV04(new Uint8Array(readFileSync(join(value.root, "ledger.jsonl"))));
    if (!ledger.ok) throw new Error(ledger.reason);
    const [clock, heartbeat] = ledger.ledger.events.slice(-2);
    expect(clock).toMatchObject({
      event_type: "run.clock-observed",
      recorded_at: "2026-08-30T10:00:10Z",
      payload: {
        reason: "owner-heartbeat",
        elapsed_ms: 500,
        use_ref: "owner_initial_heartbeat_run",
        attempt_ref: ref(value.attempt),
        owner_lease_ref: ref(value.attempt),
      },
    });
    expect(heartbeat).toMatchObject({
      event_type: "ownership.lease-heartbeat-recorded",
      recorded_at: "2026-08-30T10:00:10Z",
      payload: {
        owner_lease_event_ref: ref(value.attempt),
        heartbeat_ordinal: 1,
        observation_clock_ref: ref(clock!),
        previous_deadline_elapsed_ms: 1_000,
        fence_epoch: 0,
      },
    });
    expect(heartbeat!.payload.deadline_elapsed_ms).toBeGreaterThan(1_000);
  });

  it("caps a subordinate heartbeat at its active parent and enforces the subordinate limit", async () => {
    const value = fixture("heartbeat_task", { scope: "task", heartbeat_limit: 1 });
    if (value.subordinate_owner === null) throw new Error("subordinate fixture missing");
    const store = await captureRuntimeFileStoreV04({ run_directory: value.root });
    if (!store.ok) throw new Error(store.error);
    const first = await heartbeatRuntimeOwnerLeaseV04(store.store, {
      owner_lease_event_ref: ref(value.subordinate_owner),
      observation: clockObservation("heartbeat_task", 500),
      clock_event_id: "clock_heartbeat_task_s41",
      heartbeat_event_id: "event_heartbeat_task_s41",
    });
    expect(first).toMatchObject({ ok: true, classification: "COMMITTED" });
    const ledger = inspectRuntimeLedgerV04(new Uint8Array(readFileSync(join(value.root, "ledger.jsonl"))));
    if (!ledger.ok) throw new Error(ledger.reason);
    expect(ledger.ledger.events.at(-1)).toMatchObject({
      event_type: "ownership.lease-heartbeat-recorded",
      payload: {
        owner_lease_event_ref: ref(value.subordinate_owner),
        heartbeat_ordinal: 1,
        previous_deadline_elapsed_ms: 900,
        deadline_elapsed_ms: 1_000,
        fence_epoch: 0,
      },
    });
    await expect(heartbeatRuntimeOwnerLeaseV04(store.store, {
      owner_lease_event_ref: ref(value.subordinate_owner),
      observation: clockObservation("heartbeat_task", 600, "2026-08-30T10:00:11Z"),
      clock_event_id: "clock_heartbeat_task_limit_s41",
      heartbeat_event_id: "event_heartbeat_task_limit_s41",
    })).resolves.toMatchObject({
      ok: false,
      classification: "NOT_COMMITTED",
      refusal_reason: "heartbeat-limit-reached",
    });
  });

  it("releases the exact active owner and derives its domain, attempt, fence, and refs", async () => {
    const value = fixture("release_task", { scope: "integrator" });
    if (value.subordinate_owner === null) throw new Error("subordinate fixture missing");
    const store = await captureRuntimeFileStoreV04({ run_directory: value.root });
    if (!store.ok) throw new Error(store.error);
    const result = await releaseRuntimeOwnerLeaseV04(store.store, {
      owner_lease_event_ref: ref(value.subordinate_owner),
      observation: clockObservation("release_task", 900),
      clock_event_id: "clock_release_task_s41",
      release_event_id: "event_release_task_s41",
      reason: "completed",
    });
    expect(result).toMatchObject({ ok: true, classification: "COMMITTED" });
    const ledger = inspectRuntimeLedgerV04(new Uint8Array(readFileSync(join(value.root, "ledger.jsonl"))));
    if (!ledger.ok) throw new Error(ledger.reason);
    const [clock, release] = ledger.ledger.events.slice(-2);
    expect(clock).toMatchObject({
      event_type: "run.clock-observed",
      payload: {
        reason: "owner-release",
        use_ref: "owner_subordinate_release_task",
        attempt_ref: ref(value.attempt),
        owner_lease_ref: ref(value.subordinate_owner),
        boot_id_hash: bootHash("release_task"),
        monotonic_clock_id: "monotonic_initial_release_task",
      },
    });
    expect(release).toMatchObject({
      event_type: "ownership.lease-released",
      payload: {
        owner_lease_event_ref: ref(value.subordinate_owner),
        release_clock_ref: ref(clock!),
        reason: "completed",
        fence_epoch: 0,
      },
    });
    await expect(releaseRuntimeOwnerLeaseV04(store.store, {
      owner_lease_event_ref: ref(value.subordinate_owner),
      observation: clockObservation("release_task", 901, "2026-08-30T10:00:11Z"),
      clock_event_id: "clock_release_task_replay_s41",
      release_event_id: "event_release_task_replay_s41",
      reason: "completed",
    })).resolves.toMatchObject({ ok: false, refusal_reason: "owner-not-active" });
  });

  it("fails closed for stale, expired, wrong-domain, wrong-ref, replayed, and unsafe heartbeat inputs", async () => {
    const cases = [
      ["stale", 0, {}, "clock-domain-or-order-invalid"],
      ["deadline", 1_000, {}, "lease-deadline-reached"],
      ["domain", 500, { boot_identity: "wrong_boot" }, "clock-domain-or-order-invalid"],
    ] as const;
    for (const [label, elapsed, domain, refusalReason] of cases) {
      const value = fixture(`reject_${label}`);
      const store = await captureRuntimeFileStoreV04({ run_directory: value.root });
      if (!store.ok) throw new Error(store.error);
      await expect(heartbeatRuntimeOwnerLeaseV04(store.store, {
        owner_lease_event_ref: ref(value.attempt),
        observation: clockObservation(`reject_${label}`, elapsed, "2026-08-30T10:00:10Z", domain),
        clock_event_id: `clock_reject_${label}_s41`,
        heartbeat_event_id: `event_reject_${label}_s41`,
      })).resolves.toMatchObject({ ok: false, classification: "NOT_COMMITTED", refusal_reason: refusalReason });
    }

    const wrongRef = fixture("wrong_ref");
    const wrongRefStore = await captureRuntimeFileStoreV04({ run_directory: wrongRef.root });
    if (!wrongRefStore.ok) throw new Error(wrongRefStore.error);
    await expect(heartbeatRuntimeOwnerLeaseV04(wrongRefStore.store, {
      owner_lease_event_ref: { ledger_sequence: wrongRef.attempt.sequence, event_hash: H("9") },
      observation: clockObservation("wrong_ref", 500),
      clock_event_id: "clock_wrong_ref_s41",
      heartbeat_event_id: "event_wrong_ref_s41",
    })).resolves.toMatchObject({ ok: false, refusal_reason: "owner-not-active" });

    const replay = fixture("replayed_observation");
    const replayStore = await captureRuntimeFileStoreV04({ run_directory: replay.root });
    if (!replayStore.ok) throw new Error(replayStore.error);
    const observation = clockObservation("replayed_observation", 500);
    const firstInput = {
      owner_lease_event_ref: ref(replay.attempt), observation,
      clock_event_id: "clock_replay_first_s41", heartbeat_event_id: "event_replay_first_s41",
    };
    await expect(heartbeatRuntimeOwnerLeaseV04(replayStore.store, firstInput)).resolves.toMatchObject({ ok: true });
    await expect(heartbeatRuntimeOwnerLeaseV04(replayStore.store, {
      ...firstInput,
      clock_event_id: "clock_replay_second_s41",
      heartbeat_event_id: "event_replay_second_s41",
    })).resolves.toMatchObject({ ok: false, error: "RUNTIME_OWNER_LEASE_INPUT_INVALID" });

    const unsafe = fixture("unsafe_input");
    const unsafeStore = await captureRuntimeFileStoreV04({ run_directory: unsafe.root });
    if (!unsafeStore.ok) throw new Error(unsafeStore.error);
    const baseInput = {
      owner_lease_event_ref: ref(unsafe.attempt),
      observation: clockObservation("unsafe_input", 500),
      clock_event_id: "clock_unsafe_s41",
      heartbeat_event_id: "event_unsafe_s41",
    };
    await expect(heartbeatRuntimeOwnerLeaseV04(unsafeStore.store, { ...baseInput, extra: true })).resolves.toMatchObject({ ok: false, error: "RUNTIME_OWNER_LEASE_INPUT_INVALID" });
    let getterCalls = 0;
    const getterInput = Object.defineProperty({}, "owner_lease_event_ref", { enumerable: true, get: () => { getterCalls += 1; return ref(unsafe.attempt); } });
    await expect(heartbeatRuntimeOwnerLeaseV04(unsafeStore.store, getterInput)).resolves.toMatchObject({ ok: false, error: "RUNTIME_OWNER_LEASE_INPUT_INVALID" });
    expect(getterCalls).toBe(0);
    await expect(heartbeatRuntimeOwnerLeaseV04(unsafeStore.store, new Proxy(baseInput, {}))).resolves.toMatchObject({ ok: false, error: "RUNTIME_OWNER_LEASE_INPUT_INVALID" });
    await expect(heartbeatRuntimeOwnerLeaseV04(unsafeStore.store, { ...baseInput, observation: Object.freeze({}) })).resolves.toMatchObject({ ok: false, error: "RUNTIME_OWNER_LEASE_INPUT_INVALID" });
  });

  it("distinguishes proven pre-write failure from an ambiguous append without retry", async () => {
    const notCommitted = fixture("heartbeat_not_committed");
    const notCommittedStore = await captureRuntimeFileStoreV04ForTest({ run_directory: notCommitted.root }, {
      open: async (path, flags, mode) => {
        if ((flags & constants.O_APPEND) === constants.O_APPEND) throw new Error("pre-write failure");
        return mode === undefined ? openFile(path, flags) : openFile(path, flags, mode);
      },
    });
    if (!notCommittedStore.ok) throw new Error(notCommittedStore.error);
    await expect(heartbeatRuntimeOwnerLeaseV04(notCommittedStore.store, {
      owner_lease_event_ref: ref(notCommitted.attempt),
      observation: clockObservation("heartbeat_not_committed", 500),
      clock_event_id: "clock_not_committed_s41",
      heartbeat_event_id: "event_not_committed_s41",
    })).resolves.toEqual({
      ok: false,
      classification: "NOT_COMMITTED",
      error: "RUNTIME_OWNER_LEASE_NOT_COMMITTED",
    });

    const ambiguous = fixture("heartbeat_ambiguous");
    const ambiguousStore = await captureRuntimeFileStoreV04ForTest({ run_directory: ambiguous.root }, {
      write: async (handle, bytes, offset, length, position) => position === null
        ? Math.max(1, Math.floor(length / 2))
        : (await handle.write(bytes, offset, length, position)).bytesWritten,
    });
    if (!ambiguousStore.ok) throw new Error(ambiguousStore.error);
    await expect(heartbeatRuntimeOwnerLeaseV04(ambiguousStore.store, {
      owner_lease_event_ref: ref(ambiguous.attempt),
      observation: clockObservation("heartbeat_ambiguous", 500),
      clock_event_id: "clock_ambiguous_s41",
      heartbeat_event_id: "event_ambiguous_s41",
    })).resolves.toEqual({
      ok: false,
      classification: "OUTCOME_UNKNOWN",
      error: "RUNTIME_OWNER_LEASE_OUTCOME_UNKNOWN",
    });
  });

  it("writes the two ordered batches with exact refs, captured authority, fence, and deadline", async () => {
    const value = fixture();
    const cap = await captureRequest(value, "T4");
    const store = await captureRuntimeFileStoreV04({ run_directory: value.root });
    if (!store.ok) throw new Error(store.error);
    const input = freshInput(cap, value);
    const result = await resumeRuntimeWriteSessionV04(store.store, input);
    expect(result).toMatchObject({ ok: true, classification: "COMMITTED" });
    if (!result.ok) return;
    const ledger = inspectRuntimeLedgerV04(new Uint8Array(readFileSync(join(value.root, "ledger.jsonl"))));
    if (!ledger.ok) throw new Error(ledger.reason);
    expect(ledger.ledger.events.slice(-4).map((event) => event.event_type)).toEqual([
      "run.clock-observed",
      "run.clock-observed",
      "recovery.resume-requested",
      "execution.attempt-started",
    ]);
    const request = ledger.ledger.events.at(-2)!;
    const attempt = ledger.ledger.events.at(-1)!;
    expect(request).toMatchObject({ authority_ref: "operator_write_s41", risk_tier: "T4" });
    expect(attempt).toMatchObject({
      risk_tier: "T4",
      payload: {
        attempt_ordinal: 2,
        resume_request_event_ref: ref(request),
        previous_fence_epoch: 0,
        fence_epoch: 1,
        run_owner_lease_id: "owner_recovery_s41_2",
        repository_state_hash: value.repository_observation.repository_state_hash,
        deadline_elapsed_ms: 101 + value.plan.plan.runtime_execution_policy.owner_lease_duration_ms,
      },
    });
    expect(result.request_event_ref).toEqual(ref(request));
    expect(result.attempt_event_ref).toEqual(ref(attempt));
    expect("resumeRuntimeWriteSessionV04" in rootExports).toBe(false);
    await expect(resumeRuntimeWriteSessionV04(store.store, input)).resolves.toEqual({
      ok: false,
      classification: "NOT_COMMITTED",
      error: "RUNTIME_RECOVERY_AUTHORIZATION_INVALID",
    });
    await expect(resumeRuntimeWriteSessionV04(store.store, freshInput(cap, value))).resolves.toMatchObject({
      ok: false,
      classification: "NOT_COMMITTED",
    });
  });

  it("reports request-only durability and completes once from the exact unchanged head after restart", async () => {
    const value = fixture("restart");
    const cap = await captureRequest(value);
    let appendOpens = 0;
    const store = await captureRuntimeFileStoreV04ForTest({ run_directory: value.root }, {
      open: async (path, flags, mode) => {
        if ((flags & constants.O_APPEND) === constants.O_APPEND) {
          appendOpens += 1;
          if (appendOpens === 2) throw new Error("proven pre-write failure");
        }
        return mode === undefined ? openFile(path, flags) : openFile(path, flags, mode);
      },
    });
    if (!store.ok) throw new Error(store.error);
    const first = await resumeRuntimeWriteSessionV04(store.store, freshInput(cap, value));
    expect(first).toMatchObject({
      ok: false,
      classification: "REQUEST_COMMITTED_ATTEMPT_NOT_COMMITTED",
      error: "RUNTIME_RECOVERY_ATTEMPT_NOT_COMMITTED",
    });
    if (first.ok || first.request_event_ref === undefined) return;

    const restarted = await captureRuntimeFileStoreV04({ run_directory: value.root });
    if (!restarted.ok) throw new Error(restarted.error);
    const completed = await resumeRuntimeWriteSessionV04(restarted.store, {
      kind: "continue-pending",
      pending_request_event_ref: first.request_event_ref,
      owner_status: ownerStatus(value),
      attempt_observation: clockObservation("recovery_owner_s41_2", 102, "2026-08-30T12:02:00Z", {
        boot_identity: "boot_recovery_s41_2",
        monotonic_clock_id: "monotonic_recovery_s41_2",
      }),
      attempt_event: {
        event_id: "event_recovery_attempt_after_restart_s41",
        attempt_id: "attempt_recovery_after_restart_s41",
      },
    });
    expect(completed).toMatchObject({ ok: true, classification: "COMMITTED" });
  });

  it("rejects accessor and counterfeit recovery inputs without invoking caller code", async () => {
    const value = fixture("counterfeit");
    const store = await captureRuntimeFileStoreV04({ run_directory: value.root });
    if (!store.ok) throw new Error(store.error);
    let getterCalls = 0;
    const accessorInput = Object.defineProperty({}, "kind", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return "fresh";
      },
    });
    await expect(resumeRuntimeWriteSessionV04(store.store, accessorInput)).resolves.toEqual({
      ok: false,
      classification: "NOT_COMMITTED",
      error: "RUNTIME_RECOVERY_INPUT_INVALID",
    });
    expect(getterCalls).toBe(0);
    await expect(resumeRuntimeWriteSessionV04(store.store, freshInput(Object.freeze({}) as never, value))).resolves.toEqual({
      ok: false,
      classification: "NOT_COMMITTED",
      error: "RUNTIME_RECOVERY_AUTHORIZATION_INVALID",
    });
  });

  it("refuses concurrent lock ownership and crossed run bindings", async () => {
    const value = fixture("locked");
    const store = await captureRuntimeFileStoreV04({ run_directory: value.root });
    if (!store.ok) throw new Error(store.error);
    const cap = await captureRequest(value);
    const locked = await openRuntimeFileStoreSessionV04(store.store);
    if (!locked.ok) throw new Error(locked.error);
    await expect(resumeRuntimeWriteSessionV04(store.store, freshInput(cap, value))).resolves.toMatchObject({
      ok: false,
      classification: "NOT_COMMITTED",
    });
    await closeRuntimeFileStoreSessionV04(locked.session);

    const drifted = fixture("drifted");
    const driftedStore = await captureRuntimeFileStoreV04({ run_directory: drifted.root });
    if (!driftedStore.ok) throw new Error(driftedStore.error);
    await expect(resumeRuntimeWriteSessionV04(driftedStore.store, freshInput(cap, value))).resolves.toEqual({
      ok: false,
      classification: "NOT_COMMITTED",
      error: "RUNTIME_RECOVERY_AUTHORIZATION_INVALID",
    });
  });

  it("rejects expired authorization and unsafe ordinal overflow", async () => {
    const value = fixture("limits");
    const store = await captureRuntimeFileStoreV04({ run_directory: value.root });
    if (!store.ok) throw new Error(store.error);
    const expiredCap = await captureRequest(value);
    const expiredInput = freshInput(expiredCap, value);
    await expect(resumeRuntimeWriteSessionV04(store.store, {
      ...expiredInput,
      request_clock: {
        ...expiredInput.request_clock,
        observation: clockObservation("recovery_request_expired_s41", 100, "2026-08-30T12:06:00Z"),
      },
    })).resolves.toEqual({
      ok: false,
      classification: "NOT_COMMITTED",
      error: "RUNTIME_RECOVERY_AUTHORIZATION_INVALID",
    });

    const overflowCap = await captureRequest(value);
    await expect(resumeRuntimeWriteSessionV04(store.store, freshInput(overflowCap, value, Number.MAX_SAFE_INTEGER - 1))).resolves.toEqual({
      ok: false,
      classification: "NOT_COMMITTED",
      error: "RUNTIME_RECOVERY_INPUT_INVALID",
    });
  });

  it("poisons an ambiguous append and forbids retry", async () => {
    const ambiguousValue = fixture("ambiguous");
    const ambiguousCap = await captureRequest(ambiguousValue);
    let writes = 0;
    const ambiguousStore = await captureRuntimeFileStoreV04ForTest({ run_directory: ambiguousValue.root }, {
      write: async (handle, bytes, offset, length, position) => {
        writes += 1;
        if (position === null && writes === 2) return Math.max(1, Math.floor(length / 2));
        return (await handle.write(bytes, offset, length, position)).bytesWritten;
      },
    });
    if (!ambiguousStore.ok) throw new Error(ambiguousStore.error);
    await expect(resumeRuntimeWriteSessionV04(ambiguousStore.store, freshInput(ambiguousCap, ambiguousValue))).resolves.toEqual({
      ok: false,
      classification: "OUTCOME_UNKNOWN",
      error: "RUNTIME_RECOVERY_OUTCOME_UNKNOWN",
    });
    await expect(resumeRuntimeWriteSessionV04(ambiguousStore.store, freshInput(ambiguousCap, ambiguousValue))).resolves.toEqual({
      ok: false,
      classification: "OUTCOME_UNKNOWN",
      error: "RUNTIME_RECOVERY_OUTCOME_UNKNOWN",
    });
  });
});
