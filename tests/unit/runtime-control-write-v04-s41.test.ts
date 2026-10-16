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
  abortRuntimeControlV04,
  captureRuntimeAbortRequestV04,
  continuePendingAbortRuntimeControlV04,
  hashRuntimeAbortActionScopeV04,
  hashRuntimeAbortAuthorizationSubjectV04,
} from "../../src/run/runtime-control-write-v04.js";
import {
  captureRuntimeClockSourceV04,
  observeRuntimeClockV04,
} from "../../src/run/runtime-clock-observation-v04.js";
import {
  captureRuntimeFileStoreV04,
  captureRuntimeFileStoreV04ForTest,
} from "../../src/run/runtime-file-store-v04.js";
import { inspectRuntimeLedgerV04 } from "../../src/run/runtime-ledger-v04.js";
import { buildRunManifestV04, inspectRunManifestV04 } from "../../src/run/runtime-manifest-v04.js";
import { ResolvedRunPlanV02, type ResolvedRunPlanV02Value } from "../../src/schema/runtime.js";
import { captureRuntimeProfileRegistryV03 } from "../../src/schema/runtime-plan-v03.js";
import { RuntimeEventV04, type RuntimeEventV04Value } from "../../src/schema/runtime-v04.js";
import { createRuntimeRepositoryObservationFixture } from "../helpers/runtime-repository-observation-fixture.js";

const E = new TextEncoder();
const H = (value: string): string => `sha256:${value.repeat(64)}`;
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
  riskTier: RuntimeEventV04Value["risk_tier"] = "T1",
) {
  const sequence = events.length + 1;
  const preimage = {
    schema_version: "0.4",
    event_id: `event_control_${label}_${sequence}`,
    run_id: runId,
    sequence,
    recorded_at: `2026-08-30T15:00:${String(sequence).padStart(2, "0")}Z`,
    event_type: eventType,
    source,
    authority_ref: authorityRef,
    risk_tier: riskTier,
    related_ids: [],
    previous_event_hash: events.at(-1)?.event_hash ?? null,
    payload,
  };
  const event = RuntimeEventV04.parse({ ...preimage, event_hash: hashCanonical(preimage) });
  events.push(event);
  return event;
}

function fixture(
  label: string,
  subordinateScope: "task" | "integrator" = "task",
) {
  const repository = createRuntimeRepositoryObservationFixture(loadPlanV02(), `abort_control_${label}`);
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
  }, label, "kernel", null, "T1");
  const started = append(events, plan.validated_plan.run_id, "run.started", {
    executor_profile_hash: H("a"),
  }, label, "kernel", null, "T1");
  const ownerClock = append(events, plan.validated_plan.run_id, "run.clock-observed", {
    clock_id: `clock_owner_${label}`,
    observed_at: "2026-08-30T15:00:03Z",
    elapsed_ms: 1,
    reason: "run-owner-acquisition",
    task_ref: null,
    failure_ordinal: null,
    use_ref: `owner_${label}`,
    attempt_ref: null,
    owner_lease_ref: null,
    boot_id_hash: H("b"),
    monotonic_clock_id: `monotonic_${label}`,
  }, label, "kernel", null, "T1");
  const attempt = append(events, plan.validated_plan.run_id, "execution.attempt-started", {
    attempt_id: `attempt_${label}`,
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
    authority_envelope_hash: H("d"),
    repository_state_hash: repository.observation.repository_state_hash,
    run_owner_lease_id: `owner_${label}`,
    issued_clock_ref: ref(ownerClock),
    deadline_elapsed_ms: 1_000,
    boot_id_hash: H("b"),
    monotonic_clock_id: `monotonic_${label}`,
    previous_fence_epoch: 0,
    fence_epoch: 0,
  }, label, "kernel", null, "T1");
  const subordinateClock = append(events, plan.validated_plan.run_id, "run.clock-observed", {
    clock_id: `clock_subordinate_${label}`,
    observed_at: "2026-08-30T15:00:04Z",
    elapsed_ms: 10,
    reason: "owner-acquisition",
    task_ref: null,
    failure_ordinal: null,
    use_ref: `owner_subordinate_${label}`,
    attempt_ref: ref(attempt),
    owner_lease_ref: ref(attempt),
    boot_id_hash: H("b"),
    monotonic_clock_id: `monotonic_${label}`,
  }, label, "kernel", null, "T1");
  const subordinate = append(events, plan.validated_plan.run_id, "ownership.lease-acquired", {
    owner_lease_id: `owner_subordinate_${label}`,
    scope: subordinateScope,
    scope_ref: subordinateScope === "task" ? "task-s41" : "integrator_s41",
    parent_run_owner_lease_id: `owner_${label}`,
    attempt_event_ref: ref(attempt),
    issued_clock_ref: ref(subordinateClock),
    deadline_elapsed_ms: 900,
    boot_id_hash: H("b"),
    monotonic_clock_id: `monotonic_${label}`,
    fence_epoch: 0,
    heartbeat_limit: 2,
  }, label, "policy-enforcement-point", `operator_${label}`, "T4");

  const ledgerBytes = E.encode(`${events.map((event) => JSON.stringify(event)).join("\n")}\n`);
  const files = [
    { path: "resolved-run-plan.json", family: "primary" as const, required: true, mode: 384 as const, bytes: planBytes },
    { path: "ledger.jsonl", family: "primary" as const, required: true, mode: 384 as const, bytes: ledgerBytes },
  ];
  const manifestBuilt = buildRunManifestV04({
    ledger_bytes: ledgerBytes,
    created_at: "2026-08-30T15:01:00Z",
    captured_files: files,
  });
  if (!manifestBuilt.ok) throw new Error(manifestBuilt.reason);
  const manifest = inspectRunManifestV04({
    manifest_bytes: manifestBuilt.bytes,
    ledger_bytes: ledgerBytes,
    captured_files: files,
  });
  if (!manifest.ok) throw new Error(manifest.reason);

  const root = realpathSync(mkdtempSync(join(tmpdir(), "loopeix-runtime-control-write-")));
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
    subordinate,
  };
}

function clockObservation(
  label: string,
  elapsedMs: number,
  observedAt = "2026-08-30T15:02:00Z",
  domain: Readonly<{ boot_identity?: string; monotonic_clock_id?: string }> = {},
) {
  const source = captureRuntimeClockSourceV04({
    boot_identity: domain.boot_identity ?? `boot_${label}`,
    monotonic_clock_id: domain.monotonic_clock_id ?? `monotonic_control_${label}`,
    observe: () => ({ observed_at: observedAt, elapsed_ms: elapsedMs }),
  });
  if (source === null) throw new Error("clock source capture failed");
  const observed = observeRuntimeClockV04(source);
  if (!observed.ok) throw new Error(observed.error);
  return observed.value;
}

async function captureAbortRequest(value: ReturnType<typeof fixture>, riskTier: "T1" | "T4" = "T4") {
  const request = { request_id: `abort_${value.attempt.event_id}` };
  const pair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const trustInput = {
    observed_at: "2026-08-30T15:01:30Z",
    policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
    authentication_contexts: [{
      context_version: "0.1" as const,
      trust_domain: "local-operator",
      approval_channel: "local-ed25519" as const,
      authenticated_principal_ref: "operator_abort_control_s41",
      credential_ref: "operator_key_abort_control_s41",
      channel_subject_hash: H("e"),
      session_binding_hash: H("f"),
      assurance_level: "phishing-resistant" as const,
    }],
    operator_keys: [{
      operator_key_id: "operator_key_abort_control_s41",
      authenticated_principal_ref: "operator_abort_control_s41",
      trust_domain: "local-operator",
      public_key_spki_base64: pair.publicKey.toString("base64"),
      effective_from: "2026-08-30T15:00:00Z",
      effective_until: "2026-08-30T16:00:00Z",
      revoked_at: null,
    }],
    platform_channel_verifiers: [],
    host_producer_keys: [],
    authority_epochs: [{
      authenticated_principal_ref: "operator_abort_control_s41",
      revocation_epoch: 3,
      effective_from: "2026-08-30T15:00:00Z",
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
  const subjectHash = hashRuntimeAbortAuthorizationSubjectV04({
    validated_plan: value.plan,
    ledger: value.ledger,
    manifest: value.manifest,
    request,
  });
  const scopeHash = hashRuntimeAbortActionScopeV04({
    validated_plan: value.plan,
    ledger: value.ledger,
    manifest: value.manifest,
    request,
  });
  if (subjectHash === null || scopeHash === null) throw new Error("abort authorization hashes failed");
  const proof = await produceLocalHumanAuthorizationProofV02({
    trust_context: initialTrust.value,
    nonce_reservation: nonce,
    signer: captureEd25519AuthoritySignerV02("operator_key_abort_control_s41", pair.privateKey),
    request: {
      authorization_id: `authorization_abort_${value.attempt.event_id}`,
      run_id: value.plan.run_id,
      plan_hash: value.plan.plan_hash,
      authorization_subject_hash: subjectHash,
      authenticated_principal_ref: "operator_abort_control_s41",
      action_scope_hash: scopeHash,
      approved_risk_tier: riskTier,
      operator_key_id: "operator_key_abort_control_s41",
      approval_nonce: H("7"),
      issued_at: "2026-08-30T15:01:00Z",
      expires_at: "2026-08-30T15:05:00Z",
      revocation_epoch: 3,
    },
  });
  if (!proof.ok || reserved === undefined) {
    throw new Error(`abort authorization proof failed: ${proof.ok ? "nonce-not-reserved" : proof.error}`);
  }
  const trust = captureAuthorityTrustContextV02({ ...trustInput, durable_nonce_consumptions: [reserved] });
  if (!trust.ok) throw new Error(trust.error);
  const captured = captureRuntimeAbortRequestV04({
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

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
  for (const cleanup of repositoryCleanups.splice(0)) cleanup();
});

describe("S41-C2 durable operator abort control writes", () => {
  it("commits an authorized operator abort, then one exact fence boundary invalidating every active owner", async () => {
    const value = fixture("abort_success", "integrator");
    const captured = await captureAbortRequest(value);
    const store = await captureRuntimeFileStoreV04({ run_directory: value.root });
    if (!store.ok) throw new Error(store.error);

    const result = await abortRuntimeControlV04(store.store, {
      captured_request: captured,
      observation: clockObservation("abort_success", 500, "2026-08-30T15:02:00Z"),
      request_event_id: "event_abort_requested_s41",
      fence_event_id: "event_abort_fence_s41",
    });

    expect(result).toMatchObject({ ok: true, classification: "COMMITTED" });
    const ledger = inspectRuntimeLedgerV04(new Uint8Array(readFileSync(join(value.root, "ledger.jsonl"))));
    if (!ledger.ok) throw new Error(ledger.reason);
    const [request, fence] = ledger.ledger.events.slice(-2);
    expect(request).toMatchObject({
      event_type: "control.abort-requested",
      recorded_at: "2026-08-30T15:02:00Z",
      source: "operator",
      authority_ref: "operator_abort_control_s41",
      risk_tier: "T4",
      payload: {
        request_id: `abort_${value.attempt.event_id}`,
        requested_by: "operator",
        reason_code: "operator-requested",
        policy_decision_ref: null,
        evidence_refs: [ref(value.subordinate)],
      },
    });
    expect(fence).toMatchObject({
      event_type: "run.fence-advanced",
      recorded_at: "2026-08-30T15:02:00Z",
      source: "policy-enforcement-point",
      authority_ref: "operator_abort_control_s41",
      payload: {
        previous_fence_epoch: 0,
        fence_epoch: 1,
        reason: "abort-request",
        evidence_refs: [ref(request!)],
        attempt_ref: ref(value.attempt),
        owner_lease_refs: [ref(value.attempt), ref(value.subordinate)],
      },
    });
    expect(ledger.ledger.state.state).toBe("aborting");
    expect(ledger.ledger.state.active_run_owner?.active).toBe(false);
    expect(ledger.ledger.state.subordinate_owner_leases[0]?.active).toBe(false);
  });

  it("reports a durable abort intent when the fence commit is proven not written, then completes once from the unchanged head", async () => {
    const value = fixture("abort_partial");
    const captured = await captureAbortRequest(value);
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

    const first = await abortRuntimeControlV04(store.store, {
      captured_request: captured,
      observation: clockObservation("abort_partial", 500, "2026-08-30T15:02:00Z"),
      request_event_id: "event_abort_requested_partial_s41",
      fence_event_id: "event_abort_fence_partial_s41",
    });

    expect(first).toMatchObject({
      ok: false,
      classification: "REQUEST_COMMITTED_ABORT_NOT_COMMITTED",
      error: "RUNTIME_ABORT_NOT_COMMITTED",
    });
    const ledger = inspectRuntimeLedgerV04(new Uint8Array(readFileSync(join(value.root, "ledger.jsonl"))));
    if (!ledger.ok) throw new Error(ledger.reason);
    expect(ledger.ledger.events.at(-1)).toMatchObject({
      event_type: "control.abort-requested",
      recorded_at: "2026-08-30T15:02:00Z",
    });
    expect(ledger.ledger.state.state).toBe("aborting");
    if (first.ok || first.request_event_ref === undefined) return;

    const restarted = await captureRuntimeFileStoreV04({ run_directory: value.root });
    if (!restarted.ok) throw new Error(restarted.error);
    const completed = await continuePendingAbortRuntimeControlV04(restarted.store, {
      pending_request_event_ref: first.request_event_ref,
      observation: clockObservation("abort_partial_restart", 501, "2026-08-30T15:02:01Z"),
      fence_event_id: "event_abort_fence_restarted_s41",
    });
    expect(completed).toMatchObject({ ok: true, classification: "COMMITTED" });
    const finalLedger = inspectRuntimeLedgerV04(new Uint8Array(readFileSync(join(value.root, "ledger.jsonl"))));
    if (!finalLedger.ok) throw new Error(finalLedger.reason);
    expect(finalLedger.ledger.events.at(-1)).toMatchObject({
      event_type: "run.fence-advanced",
      recorded_at: "2026-08-30T15:02:01Z",
    });
    expect(finalLedger.ledger.state.current_fence_epoch).toBe(1);
  });

  it("fails closed with OUTCOME_UNKNOWN on an ambiguous fence append and does not retry", async () => {
    const value = fixture("abort_ambiguous");
    const captured = await captureAbortRequest(value);
    let writes = 0;
    const store = await captureRuntimeFileStoreV04ForTest({ run_directory: value.root }, {
      write: async (handle, bytes, offset, length, position) => {
        if (position === null) {
          writes += 1;
          if (writes === 2) return Math.max(1, Math.floor(length / 2));
        }
        return (await handle.write(bytes, offset, length, position)).bytesWritten;
      },
    });
    if (!store.ok) throw new Error(store.error);

    await expect(abortRuntimeControlV04(store.store, {
      captured_request: captured,
      observation: clockObservation("abort_ambiguous", 500, "2026-08-30T15:02:00Z"),
      request_event_id: "event_abort_requested_ambiguous_s41",
      fence_event_id: "event_abort_fence_ambiguous_s41",
    })).resolves.toEqual({
      ok: false,
      classification: "OUTCOME_UNKNOWN",
      error: "RUNTIME_ABORT_OUTCOME_UNKNOWN",
    });
  });
});
