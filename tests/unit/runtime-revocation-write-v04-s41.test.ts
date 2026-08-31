import { generateKeyPairSync } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
  constants,
} from "node:fs";
import { open as openFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { canonicalize, hashCanonical, hashRawBytes } from "../../src/hash.js";
import { S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02 } from "../../src/run/action-classifier-policy-v02.js";
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
import { inspectRuntimePlanV03, projectRuntimePlanV03 } from "../../src/run/project-plan-v03.js";
import {
  captureAuthorityTrustContextV02,
  captureHostProducerEd25519SignerV02,
} from "../../src/run/runtime-record-admission-v02.js";
import {
  captureRuntimeAuthorityRevocationV04,
  continuePendingRuntimeAuthorityRevocationV04,
  revokeRuntimeAuthorityV04,
} from "../../src/run/runtime-revocation-write-v04.js";
import { ResolvedRunPlanV02, type ResolvedRunPlanV02Value } from "../../src/schema/runtime.js";
import { captureRuntimeProfileRegistryV03 } from "../../src/schema/runtime-plan-v03.js";
import { RuntimeEventV04, type RuntimeEventV04Value } from "../../src/schema/runtime-v04.js";

const E = new TextEncoder();
const H = (value: string): string => `sha256:${value.repeat(64)}`;
const roots: string[] = [];
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

function tamperRevocationRecordPlanHash(recordBytes: Uint8Array, planHash: string): Uint8Array {
  const record = JSON.parse(new TextDecoder("utf8", { fatal: true }).decode(recordBytes)) as {
    producer_attestation: Record<string, unknown>;
    record_hash: string;
    plan_hash: string;
  } & Record<string, unknown>;
  const producerAttestation = record.producer_attestation as {
    signer_key_ref: string;
    signature_algorithm: "ed25519";
    statement_hash: string;
    signature_value: string;
  };
  const attestationHeader = {
    signer_key_ref: producerAttestation.signer_key_ref,
    signature_algorithm: producerAttestation.signature_algorithm,
  };
  const { record_hash: _oldRecordHash, producer_attestation: _oldProducerAttestation, ...recordWithoutAttestation } = record;
  const statementHash = hashCanonical({
    ...recordWithoutAttestation,
    plan_hash: planHash,
    producer_attestation: attestationHeader,
  });
  const tampered = {
    ...recordWithoutAttestation,
    plan_hash: planHash,
    producer_attestation: {
      ...producerAttestation,
      statement_hash: statementHash,
    },
  };
  const finalRecord = {
    ...tampered,
    record_hash: hashCanonical(tampered),
  };
  return E.encode(`${canonicalize(finalRecord)}\n`);
}

function rebuildManifestForRestart(
  root: string,
  recordPath: string,
  recordBytes: Uint8Array,
): void {
  const ledgerBytes = new Uint8Array(readFileSync(join(root, "ledger.jsonl")));
  const planBytes = new Uint8Array(readFileSync(join(root, "resolved-run-plan.json")));
  const currentManifest = JSON.parse(readFileSync(join(root, "run-manifest.json"), "utf8")) as { created_at: string };
  const rebuilt = buildRunManifestV04({
    ledger_bytes: ledgerBytes,
    created_at: currentManifest.created_at,
    captured_files: [
      { path: "resolved-run-plan.json", family: "primary" as const, required: true, mode: 384 as const, bytes: planBytes },
      { path: "ledger.jsonl", family: "primary" as const, required: true, mode: 384 as const, bytes: ledgerBytes },
      {
        path: recordPath.slice(root.length + 1),
        family: "record" as const,
        required: true,
        mode: 384 as const,
        bytes: recordBytes,
      },
    ],
  });
  if (!rebuilt.ok) throw new Error(rebuilt.reason);
  writeFileSync(join(root, "run-manifest.json"), rebuilt.bytes, { mode: 0o600 });
}

function ownerClockPayload(label: string, useRef: string) {
  return {
    clock_id: `clock_revocation_owner_${label}_1`,
    observed_at: "2026-08-30T19:00:03Z",
    elapsed_ms: 0,
    reason: "run-owner-acquisition" as const,
    task_ref: null,
    failure_ordinal: null,
    use_ref: useRef,
    attempt_ref: null,
    owner_lease_ref: null,
    boot_id_hash: H("1"),
    monotonic_clock_id: `monotonic_owner_${label}`,
  };
}

function taskOwnerClockPayload(label: string, attempt: RuntimeEventV04Value) {
  return {
    clock_id: `clock_revocation_task_${label}_1`,
    observed_at: "2026-08-30T19:00:04Z",
    elapsed_ms: 1,
    reason: "owner-acquisition" as const,
    task_ref: null,
    failure_ordinal: null,
    use_ref: `task_owner_${label}_1`,
    attempt_ref: ref(attempt),
    owner_lease_ref: ref(attempt),
    boot_id_hash: H("1"),
    monotonic_clock_id: `monotonic_owner_${label}`,
  };
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
    event_id: `event_revocation_${label}_${sequence}`,
    run_id: runId,
    sequence,
    recorded_at: `2026-08-30T19:00:${String(sequence).padStart(2, "0")}Z`,
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
  options: Readonly<{
    create_revocation_directory?: boolean;
    revocation_directory_symlink?: boolean;
  }> = {},
) {
  const projected = projectRuntimePlanV03(loadPlanV02(), captureRuntimeProfileRegistryV03());
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
  const started = append(events, plan.validated_plan.run_id, "run.started", {
    executor_profile_hash: H("a"),
  }, label);
  const envelope = append(events, plan.validated_plan.run_id, "authority.envelope-recorded", {
    authority_envelope_id: `envelope_${label}`,
    record_path: `authorities/envelopes/envelope_${label}.json`,
    record_hash: H("b"),
    run_id: plan.validated_plan.run_id,
    plan_hash: plan.validated_plan.plan_hash,
    policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
    subject_ref: `agent_${label}`,
    issuer_principal_ref: `operator_${label}`,
    authorization_subject_hash: H("c"),
    human_authorization_proof_refs: [ref(started)],
    action_class: "task",
    action_scope_hash: H("d"),
    max_risk_tier: "T4",
    issued_at: "2026-08-30T19:00:00Z",
    expires_at: "2026-08-30T19:05:00Z",
    revocation_epoch: 0,
    delegation_depth: 0,
  }, label, "policy-enforcement-point", `operator_${label}`, "T4");
  const ownerClock = append(events, plan.validated_plan.run_id, "run.clock-observed", ownerClockPayload(label, `run_owner_${label}_1`), label);
  const attempt = append(events, plan.validated_plan.run_id, "execution.attempt-started", {
    attempt_id: `attempt_${label}_1`,
    attempt_ordinal: 1,
    mode: "ordinary",
    previous_attempt_event_ref: null,
    resume_request_event_ref: null,
    resume_nonce_hash: null,
    source_boundary_sequence: started.sequence,
    source_boundary_head_hash: started.event_hash,
    source_manifest_hash: H("1"),
    repository_state_hash: plan.validated_plan.plan.authority_subject.repository.initial_state.repository_state_hash,
    plan_hash: plan.validated_plan.plan_hash,
    input_hash: plan.validated_plan.plan.runtime_input_hash,
    recovery_policy_hash: plan.validated_plan.plan.runtime_recovery_policy_hash,
    authority_envelope_hash: H("2"),
    run_owner_lease_id: `run_owner_${label}_1`,
    issued_clock_ref: ref(ownerClock),
    deadline_elapsed_ms: 1_000,
    boot_id_hash: H("1"),
    monotonic_clock_id: `monotonic_owner_${label}`,
    previous_fence_epoch: 0,
    fence_epoch: 0,
  }, label);
  const taskOwnerClock = append(events, plan.validated_plan.run_id, "run.clock-observed", taskOwnerClockPayload(label, attempt), label);
  const taskLease = append(events, plan.validated_plan.run_id, "ownership.lease-acquired", {
    owner_lease_id: `task_owner_${label}_1`,
    scope: "task",
    scope_ref: `task-${label}`,
    parent_run_owner_lease_id: attempt.payload.run_owner_lease_id,
    attempt_event_ref: ref(attempt),
    issued_clock_ref: ref(taskOwnerClock),
    deadline_elapsed_ms: 999,
    boot_id_hash: attempt.payload.boot_id_hash,
    monotonic_clock_id: attempt.payload.monotonic_clock_id,
    fence_epoch: attempt.payload.fence_epoch,
    heartbeat_limit: 3,
  }, label, "policy-enforcement-point", `operator_${label}`, "T4");

  const ledgerBytes = E.encode(`${events.map((event) => JSON.stringify(event)).join("\n")}\n`);
  const files = [
    { path: "resolved-run-plan.json", family: "primary" as const, required: true, mode: 384 as const, bytes: planBytes },
    { path: "ledger.jsonl", family: "primary" as const, required: true, mode: 384 as const, bytes: ledgerBytes },
  ];
  const manifestBuilt = buildRunManifestV04({
    ledger_bytes: ledgerBytes,
    created_at: "2026-08-30T19:01:00Z",
    captured_files: files,
  });
  if (!manifestBuilt.ok) throw new Error(manifestBuilt.reason);
  const manifest = inspectRunManifestV04({
    manifest_bytes: manifestBuilt.bytes,
    ledger_bytes: ledgerBytes,
    captured_files: files,
  });
  if (!manifest.ok) throw new Error(manifest.reason);

  const root = realpathSync(mkdtempSync(join(tmpdir(), "loopeix-runtime-revocation-write-")));
  roots.push(root);
  write0600(join(root, "resolved-run-plan.json"), planBytes);
  write0600(join(root, "ledger.jsonl"), ledgerBytes);
  write0600(join(root, "run-manifest.json"), manifestBuilt.bytes);
  mkdirSync(join(root, "authorities"), { recursive: true, mode: 0o700 });
  chmodSync(join(root, "authorities"), 0o700);
  if (options.revocation_directory_symlink === true) {
    const target = realpathSync(mkdtempSync(join(tmpdir(), "loopeix-runtime-revocation-parent-")));
    roots.push(target);
    chmodSync(target, 0o700);
    symlinkSync(target, join(root, "authorities/revocations"));
  } else if (options.create_revocation_directory !== false) {
    mkdirSync(join(root, "authorities/revocations"), { recursive: true, mode: 0o700 });
    chmodSync(join(root, "authorities/revocations"), 0o700);
  }

  const pair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const trust = captureAuthorityTrustContextV02({
    observed_at: "2026-08-30T19:02:00Z",
    policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
    authentication_contexts: [{
      context_version: "0.1" as const,
      trust_domain: "reviewer-host",
      approval_channel: "local-ed25519" as const,
      authenticated_principal_ref: `operator_${label}`,
      credential_ref: `revocation_key_${label}`,
      channel_subject_hash: H("e"),
      session_binding_hash: H("f"),
      assurance_level: "phishing-resistant" as const,
    }],
    operator_keys: [{
      operator_key_id: `revocation_key_${label}`,
      authenticated_principal_ref: `operator_${label}`,
      trust_domain: "reviewer-host",
      public_key_spki_base64: pair.publicKey.toString("base64"),
      effective_from: "2026-08-30T19:00:00Z",
      effective_until: "2026-08-30T20:00:00Z",
      revoked_at: null,
    }],
    platform_channel_verifiers: [],
    host_producer_keys: [{
      signer_key_ref: `revocation_key_${label}`,
      authenticated_actor_ref: `operator_${label}`,
      trust_domain: "reviewer-host",
      public_key_spki_base64: pair.publicKey.toString("base64"),
      allowed_record_kinds: ["authority-recommendation", "authority-revocation"].filter((value) => value === "authority-revocation"),
      effective_from: "2026-08-30T19:00:00Z",
      effective_until: "2026-08-30T20:00:00Z",
      revoked_at: null,
    }],
    authority_epochs: [{
      authenticated_principal_ref: `operator_${label}`,
      revocation_epoch: 0,
      effective_from: "2026-08-30T19:00:00Z",
    }],
    durable_nonce_consumptions: [],
  });
  if (!trust.ok) throw new Error(trust.error);
  const signer = captureHostProducerEd25519SignerV02(`revocation_key_${label}`, pair.privateKey);
  return {
    root,
    plan: plan.validated_plan,
    ledger: manifest.ledger,
    manifest: manifest.validated_manifest,
    target: envelope,
    attempt,
    task_lease: taskLease,
    trust: trust.value,
    signer,
  };
}

function clockObservation(label: string, elapsedMs: number, observedAt = "2026-08-30T19:02:00Z") {
  const source = captureRuntimeClockSourceV04({
    boot_identity: `boot_${label}`,
    monotonic_clock_id: `monotonic_${label}`,
    observe: () => ({ observed_at: observedAt, elapsed_ms: elapsedMs }),
  });
  if (source === null) throw new Error("clock source capture failed");
  const observed = observeRuntimeClockV04(source);
  if (!observed.ok) throw new Error(observed.error);
  return observed.value;
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("S41 durable authority revocation writer", () => {
  it("commits one exact operator revocation from the current durable prefix and consumes the capture", async () => {
    const value = fixture("commit");
    const captured = captureRuntimeAuthorityRevocationV04({
      trust_context: value.trust,
      signer: value.signer,
      validated_plan: value.plan,
      ledger: value.ledger,
      manifest: value.manifest,
      observation: clockObservation("commit", 1),
      request: {
        event_id: "event_revocation_committed_s41",
        revocation_id: "revocation_committed_s41",
        target_ref: {
          record_kind: "authority-envelope",
          record_id: value.target.payload.authority_envelope_id,
          record_event_ref: ref(value.target),
        },
        reason_code: "operator-revoked",
        evidence_refs: [{
          record_kind: "human-authorization",
          record_id: "authorization_committed_s41",
          record_event_ref: ref(value.target),
        }],
        revoker_identity_ref: "operator_commit",
        revoker_stable_identity_hash: H("9"),
      },
    });
    expect(captured).toMatchObject({ ok: true });
    if (!captured.ok) return;
    const store = await captureRuntimeFileStoreV04({ run_directory: value.root });
    if (!store.ok) throw new Error(store.error);

    const result = await revokeRuntimeAuthorityV04(store.store, {
      captured_request: captured.value,
    });

    expect(result).toMatchObject({ ok: true, classification: "COMMITTED" });
    const finalLedger = inspectRuntimeLedgerV04(new Uint8Array(readFileSync(join(value.root, "ledger.jsonl"))));
    if (!finalLedger.ok) throw new Error(finalLedger.reason);
    const revocationEvent = finalLedger.ledger.events.at(-2);
    const fenceEvent = finalLedger.ledger.events.at(-1);
    const recordPath = join(value.root, "authorities/revocations/revocation_committed_s41.json");
    expect(revocationEvent).toMatchObject({
      event_type: "authority.grant-revoked",
      source: "operator",
      authority_ref: "operator_commit",
      recorded_at: "2026-08-30T19:02:00Z",
      payload: {
        revocation_id: "revocation_committed_s41",
        record_path: "authorities/revocations/revocation_committed_s41.json",
        run_id: value.plan.run_id,
        plan_hash: value.plan.plan_hash,
        previous_revocation_epoch: 0,
        revocation_epoch: 1,
        effective_prefix_ref: ref(value.task_lease),
        reason_code: "operator-revoked",
        revoker_kind: "operator",
      },
    });
    expect(revocationEvent?.payload.record_hash).toBe(hashRawBytes(new Uint8Array(readFileSync(recordPath))));
    expect(fenceEvent).toMatchObject({
      event_type: "run.fence-advanced",
      source: "policy-enforcement-point",
      authority_ref: "operator_commit",
      recorded_at: "2026-08-30T19:02:00Z",
      payload: {
        previous_fence_epoch: 0,
        fence_epoch: 1,
        reason: "authority-revoked",
        evidence_refs: [ref(revocationEvent!)],
        attempt_ref: ref(value.attempt),
        owner_lease_refs: [ref(value.attempt), ref(value.task_lease)],
      },
    });
    expect(finalLedger.ledger.state.state).toBe("held");
    expect(finalLedger.ledger.state.current_fence_epoch).toBe(1);
    expect(existsSync(recordPath)).toBe(true);
    const record = JSON.parse(readFileSync(recordPath, "utf8")) as Record<string, unknown>;
    expect(record).toMatchObject({
      revocation_id: "revocation_committed_s41",
      run_id: value.plan.run_id,
      plan_hash: value.plan.plan_hash,
      producer_attestation: {
        signer_key_ref: "revocation_key_commit",
        signature_algorithm: "ed25519",
      },
    });
    const manifest = JSON.parse(readFileSync(join(value.root, "run-manifest.json"), "utf8")) as {
      file_inventory: Array<{ path: string }>;
    };
    expect(manifest.file_inventory.map((row) => row.path)).toContain("authorities/revocations/revocation_committed_s41.json");

    await expect(revokeRuntimeAuthorityV04(store.store, {
      captured_request: captured.value,
    })).resolves.toEqual({
      ok: false,
      classification: "NOT_COMMITTED",
      error: "RUNTIME_REVOCATION_AUTHORIZATION_INVALID",
    });
  });

  it("cleans up the persisted record when append never begins and leaves the source prefix unchanged", async () => {
    const value = fixture("prewrite");
    const captured = captureRuntimeAuthorityRevocationV04({
      trust_context: value.trust,
      signer: value.signer,
      validated_plan: value.plan,
      ledger: value.ledger,
      manifest: value.manifest,
      observation: clockObservation("prewrite", 1),
      request: {
        event_id: "event_revocation_prewrite_s41",
        revocation_id: "revocation_prewrite_s41",
        target_ref: {
          record_kind: "authority-envelope",
          record_id: value.target.payload.authority_envelope_id,
          record_event_ref: ref(value.target),
        },
        reason_code: "operator-revoked",
        evidence_refs: [{
          record_kind: "human-authorization",
          record_id: "authorization_prewrite_s41",
          record_event_ref: ref(value.target),
        }],
        revoker_identity_ref: "operator_prewrite",
        revoker_stable_identity_hash: H("7"),
      },
    });
    if (!captured.ok) throw new Error(captured.error);
    let appendOpens = 0;
    const store = await captureRuntimeFileStoreV04ForTest({ run_directory: value.root }, {
      open: async (path, flags, mode) => {
        if ((flags & constants.O_APPEND) === constants.O_APPEND) {
          appendOpens += 1;
          if (appendOpens === 1) throw new Error("proven append pre-write failure");
        }
        return mode === undefined ? openFile(path, flags) : openFile(path, flags, mode);
      },
    });
    if (!store.ok) throw new Error(store.error);

    await expect(revokeRuntimeAuthorityV04(store.store, {
      captured_request: captured.value,
    })).resolves.toEqual({
      ok: false,
      classification: "NOT_COMMITTED",
      error: "RUNTIME_REVOCATION_NOT_COMMITTED",
    });
    expect(existsSync(join(value.root, "authorities/revocations/revocation_prewrite_s41.json"))).toBe(false);
    const ledger = inspectRuntimeLedgerV04(new Uint8Array(readFileSync(join(value.root, "ledger.jsonl"))));
    if (!ledger.ok) throw new Error(ledger.reason);
    expect(ledger.ledger.events.at(-1)?.event_type).toBe("ownership.lease-acquired");
    const manifest = JSON.parse(readFileSync(join(value.root, "run-manifest.json"), "utf8")) as {
      file_inventory: Array<{ path: string }>;
    };
    expect(manifest.file_inventory.map((row) => row.path)).not.toContain("authorities/revocations/revocation_prewrite_s41.json");
  });

  it("returns a truthful partial classification when the revocation commits but the fence does not", async () => {
    const value = fixture("partial");
    const captured = captureRuntimeAuthorityRevocationV04({
      trust_context: value.trust,
      signer: value.signer,
      validated_plan: value.plan,
      ledger: value.ledger,
      manifest: value.manifest,
      observation: clockObservation("partial", 1),
      request: {
        event_id: "event_revocation_partial_s41",
        revocation_id: "revocation_partial_s41",
        target_ref: {
          record_kind: "authority-envelope",
          record_id: value.target.payload.authority_envelope_id,
          record_event_ref: ref(value.target),
        },
        reason_code: "operator-revoked",
        evidence_refs: [{
          record_kind: "human-authorization",
          record_id: "authorization_partial_s41",
          record_event_ref: ref(value.target),
        }],
        revoker_identity_ref: "operator_partial",
        revoker_stable_identity_hash: H("2"),
      },
    });
    if (!captured.ok) throw new Error(captured.error);
    let appendOpens = 0;
    const store = await captureRuntimeFileStoreV04ForTest({ run_directory: value.root }, {
      open: async (path, flags, mode) => {
        if ((flags & constants.O_APPEND) === constants.O_APPEND) {
          appendOpens += 1;
          if (appendOpens === 2) throw new Error("fence append open failed");
        }
        return mode === undefined ? openFile(path, flags) : openFile(path, flags, mode);
      },
    });
    if (!store.ok) throw new Error(store.error);

    await expect(revokeRuntimeAuthorityV04(store.store, {
      captured_request: captured.value,
    })).resolves.toEqual({
      ok: false,
      classification: "REVOCATION_COMMITTED_FENCE_NOT_COMMITTED",
      error: "RUNTIME_REVOCATION_FENCE_NOT_COMMITTED",
      revocation_event_ref: expect.any(Object),
    });
    const finalLedger = inspectRuntimeLedgerV04(new Uint8Array(readFileSync(join(value.root, "ledger.jsonl"))));
    if (!finalLedger.ok) throw new Error(finalLedger.reason);
    expect(finalLedger.ledger.events.at(-1)?.event_type).toBe("authority.grant-revoked");
    expect(existsSync(join(value.root, "authorities/revocations/revocation_partial_s41.json"))).toBe(true);
  });

  it("fails closed with OUTCOME_UNKNOWN on an ambiguous fence append and does not retry", async () => {
    const value = fixture("ambiguous");
    const captured = captureRuntimeAuthorityRevocationV04({
      trust_context: value.trust,
      signer: value.signer,
      validated_plan: value.plan,
      ledger: value.ledger,
      manifest: value.manifest,
      observation: clockObservation("ambiguous", 1),
      request: {
        event_id: "event_revocation_ambiguous_s41",
        revocation_id: "revocation_ambiguous_s41",
        target_ref: {
          record_kind: "authority-envelope",
          record_id: value.target.payload.authority_envelope_id,
          record_event_ref: ref(value.target),
        },
        reason_code: "operator-revoked",
        evidence_refs: [{
          record_kind: "human-authorization",
          record_id: "authorization_ambiguous_s41",
          record_event_ref: ref(value.target),
        }],
        revoker_identity_ref: "operator_ambiguous",
        revoker_stable_identity_hash: H("8"),
      },
    });
    if (!captured.ok) throw new Error(captured.error);
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

    await expect(revokeRuntimeAuthorityV04(store.store, {
      captured_request: captured.value,
    })).resolves.toEqual({
      ok: false,
      classification: "OUTCOME_UNKNOWN",
      error: "RUNTIME_REVOCATION_OUTCOME_UNKNOWN",
      revocation_event_ref: expect.any(Object),
    });
  });

  it("continues one exact pending revocation fence from a restarted store without rewriting the revocation", async () => {
    const value = fixture("restart");
    const captured = captureRuntimeAuthorityRevocationV04({
      trust_context: value.trust,
      signer: value.signer,
      validated_plan: value.plan,
      ledger: value.ledger,
      manifest: value.manifest,
      observation: clockObservation("restart", 1),
      request: {
        event_id: "event_revocation_restart_s41",
        revocation_id: "revocation_restart_s41",
        target_ref: {
          record_kind: "authority-envelope",
          record_id: value.target.payload.authority_envelope_id,
          record_event_ref: ref(value.target),
        },
        reason_code: "operator-revoked",
        evidence_refs: [{
          record_kind: "human-authorization",
          record_id: "authorization_restart_s41",
          record_event_ref: ref(value.target),
        }],
        revoker_identity_ref: "operator_restart",
        revoker_stable_identity_hash: H("7"),
      },
    });
    if (!captured.ok) throw new Error(captured.error);
    let appendOpens = 0;
    const firstStore = await captureRuntimeFileStoreV04ForTest({ run_directory: value.root }, {
      open: async (path, flags, mode) => {
        if ((flags & constants.O_APPEND) === constants.O_APPEND) {
          appendOpens += 1;
          if (appendOpens === 2) throw new Error("fence append open failed");
        }
        return mode === undefined ? openFile(path, flags) : openFile(path, flags, mode);
      },
    });
    if (!firstStore.ok) throw new Error(firstStore.error);

    const partial = await revokeRuntimeAuthorityV04(firstStore.store, {
      captured_request: captured.value,
    });
    expect(partial).toMatchObject({
      ok: false,
      classification: "REVOCATION_COMMITTED_FENCE_NOT_COMMITTED",
      error: "RUNTIME_REVOCATION_FENCE_NOT_COMMITTED",
      revocation_event_ref: expect.any(Object),
    });
    if (partial.ok || partial.revocation_event_ref === undefined) throw new Error("expected pending revocation ref");

    const recordPath = join(value.root, "authorities/revocations/revocation_restart_s41.json");
    const recordBytes = new Uint8Array(readFileSync(recordPath));
    const restarted = await captureRuntimeFileStoreV04({ run_directory: value.root });
    if (!restarted.ok) throw new Error(restarted.error);

    const completed = await continuePendingRuntimeAuthorityRevocationV04(restarted.store, {
      pending_revocation_event_ref: partial.revocation_event_ref,
    });

    expect(completed).toMatchObject({ ok: true, classification: "COMMITTED", revocation_event_ref: partial.revocation_event_ref });
    const finalLedger = inspectRuntimeLedgerV04(new Uint8Array(readFileSync(join(value.root, "ledger.jsonl"))));
    if (!finalLedger.ok) throw new Error(finalLedger.reason);
    const revocationEvent = finalLedger.ledger.events.at(-2);
    const fenceEvent = finalLedger.ledger.events.at(-1);
    expect(revocationEvent).toMatchObject({
      event_type: "authority.grant-revoked",
      event_hash: partial.revocation_event_ref.event_hash,
    });
    expect(fenceEvent).toMatchObject({
      event_type: "run.fence-advanced",
      payload: {
        reason: "authority-revoked",
        evidence_refs: [partial.revocation_event_ref],
      },
    });
    expect(new Uint8Array(readFileSync(recordPath))).toEqual(recordBytes);
  });

  it("refuses pending revocation continuation when the supplied ref is not the exact current durable head", async () => {
    const value = fixture("wrongref");
    const captured = captureRuntimeAuthorityRevocationV04({
      trust_context: value.trust,
      signer: value.signer,
      validated_plan: value.plan,
      ledger: value.ledger,
      manifest: value.manifest,
      observation: clockObservation("wrongref", 1),
      request: {
        event_id: "event_revocation_wrongref_s41",
        revocation_id: "revocation_wrongref_s41",
        target_ref: {
          record_kind: "authority-envelope",
          record_id: value.target.payload.authority_envelope_id,
          record_event_ref: ref(value.target),
        },
        reason_code: "operator-revoked",
        evidence_refs: [{
          record_kind: "human-authorization",
          record_id: "authorization_wrongref_s41",
          record_event_ref: ref(value.target),
        }],
        revoker_identity_ref: "operator_wrongref",
        revoker_stable_identity_hash: H("6"),
      },
    });
    if (!captured.ok) throw new Error(captured.error);
    let appendOpens = 0;
    const firstStore = await captureRuntimeFileStoreV04ForTest({ run_directory: value.root }, {
      open: async (path, flags, mode) => {
        if ((flags & constants.O_APPEND) === constants.O_APPEND) {
          appendOpens += 1;
          if (appendOpens === 2) throw new Error("fence append open failed");
        }
        return mode === undefined ? openFile(path, flags) : openFile(path, flags, mode);
      },
    });
    if (!firstStore.ok) throw new Error(firstStore.error);
    const partial = await revokeRuntimeAuthorityV04(firstStore.store, { captured_request: captured.value });
    if (partial.ok || partial.revocation_event_ref === undefined) throw new Error("expected pending revocation ref");

    const restarted = await captureRuntimeFileStoreV04({ run_directory: value.root });
    if (!restarted.ok) throw new Error(restarted.error);
    await expect(continuePendingRuntimeAuthorityRevocationV04(restarted.store, {
      pending_revocation_event_ref: ref(value.task_lease),
    })).resolves.toEqual({
      ok: false,
      classification: "NOT_COMMITTED",
      error: "RUNTIME_REVOCATION_PREFIX_INVALID",
    });
  });

  it("refuses pending revocation continuation when the durable head drifts after the partial commit", async () => {
    const value = fixture("drifted");
    const captured = captureRuntimeAuthorityRevocationV04({
      trust_context: value.trust,
      signer: value.signer,
      validated_plan: value.plan,
      ledger: value.ledger,
      manifest: value.manifest,
      observation: clockObservation("drifted", 1),
      request: {
        event_id: "event_revocation_drifted_s41",
        revocation_id: "revocation_drifted_s41",
        target_ref: {
          record_kind: "authority-envelope",
          record_id: value.target.payload.authority_envelope_id,
          record_event_ref: ref(value.target),
        },
        reason_code: "operator-revoked",
        evidence_refs: [{
          record_kind: "human-authorization",
          record_id: "authorization_drifted_s41",
          record_event_ref: ref(value.target),
        }],
        revoker_identity_ref: "operator_drifted",
        revoker_stable_identity_hash: H("5"),
      },
    });
    if (!captured.ok) throw new Error(captured.error);
    let appendOpens = 0;
    const firstStore = await captureRuntimeFileStoreV04ForTest({ run_directory: value.root }, {
      open: async (path, flags, mode) => {
        if ((flags & constants.O_APPEND) === constants.O_APPEND) {
          appendOpens += 1;
          if (appendOpens === 2) throw new Error("fence append open failed");
        }
        return mode === undefined ? openFile(path, flags) : openFile(path, flags, mode);
      },
    });
    if (!firstStore.ok) throw new Error(firstStore.error);
    const partial = await revokeRuntimeAuthorityV04(firstStore.store, { captured_request: captured.value });
    if (partial.ok || partial.revocation_event_ref === undefined) throw new Error("expected pending revocation ref");
    const restarted = await captureRuntimeFileStoreV04({ run_directory: value.root });
    if (!restarted.ok) throw new Error(restarted.error);
    chmodSync(value.root, 0o755);

    await expect(continuePendingRuntimeAuthorityRevocationV04(restarted.store, {
      pending_revocation_event_ref: partial.revocation_event_ref,
    })).resolves.toEqual({
      ok: false,
      classification: "NOT_COMMITTED",
      error: "RUNTIME_REVOCATION_PREFIX_INVALID",
    });
  });

  it("refuses pending revocation continuation when the persisted revocation record is tampered and the manifest is rebuilt consistently", async () => {
    const value = fixture("tamperedrecord");
    const captured = captureRuntimeAuthorityRevocationV04({
      trust_context: value.trust,
      signer: value.signer,
      validated_plan: value.plan,
      ledger: value.ledger,
      manifest: value.manifest,
      observation: clockObservation("tamperedrecord", 1),
      request: {
        event_id: "event_revocation_tamperedrecord_s41",
        revocation_id: "revocation_tamperedrecord_s41",
        target_ref: {
          record_kind: "authority-envelope",
          record_id: value.target.payload.authority_envelope_id,
          record_event_ref: ref(value.target),
        },
        reason_code: "operator-revoked",
        evidence_refs: [{
          record_kind: "human-authorization",
          record_id: "authorization_tamperedrecord_s41",
          record_event_ref: ref(value.target),
        }],
        revoker_identity_ref: "operator_tamperedrecord",
        revoker_stable_identity_hash: H("4"),
      },
    });
    if (!captured.ok) throw new Error(captured.error);
    let appendOpens = 0;
    const firstStore = await captureRuntimeFileStoreV04ForTest({ run_directory: value.root }, {
      open: async (path, flags, mode) => {
        if ((flags & constants.O_APPEND) === constants.O_APPEND) {
          appendOpens += 1;
          if (appendOpens === 2) throw new Error("fence append open failed");
        }
        return mode === undefined ? openFile(path, flags) : openFile(path, flags, mode);
      },
    });
    if (!firstStore.ok) throw new Error(firstStore.error);
    const partial = await revokeRuntimeAuthorityV04(firstStore.store, { captured_request: captured.value });
    if (partial.ok || partial.revocation_event_ref === undefined) throw new Error("expected pending revocation ref");

    const recordPath = join(value.root, "authorities/revocations/revocation_tamperedrecord_s41.json");
    const tamperedRecordBytes = tamperRevocationRecordPlanHash(
      new Uint8Array(readFileSync(recordPath)),
      H("0"),
    );
    writeFileSync(recordPath, tamperedRecordBytes, { mode: 0o600 });
    rebuildManifestForRestart(value.root, recordPath, tamperedRecordBytes);

    const restarted = await captureRuntimeFileStoreV04({ run_directory: value.root });
    if (!restarted.ok) throw new Error(restarted.error);

    await expect(continuePendingRuntimeAuthorityRevocationV04(restarted.store, {
      pending_revocation_event_ref: partial.revocation_event_ref,
    })).resolves.toEqual({
      ok: false,
      classification: "NOT_COMMITTED",
      error: "RUNTIME_REVOCATION_PREFIX_INVALID",
    });
    const ledger = inspectRuntimeLedgerV04(new Uint8Array(readFileSync(join(value.root, "ledger.jsonl"))));
    if (!ledger.ok) throw new Error(ledger.reason);
    expect(ledger.ledger.events.at(-1)?.event_type).toBe("authority.grant-revoked");
  });

  it("fails closed with OUTCOME_UNKNOWN on an ambiguous continued fence append and does not retry", async () => {
    const value = fixture("continueambiguous");
    const captured = captureRuntimeAuthorityRevocationV04({
      trust_context: value.trust,
      signer: value.signer,
      validated_plan: value.plan,
      ledger: value.ledger,
      manifest: value.manifest,
      observation: clockObservation("continueambiguous", 1),
      request: {
        event_id: "event_revocation_continueambiguous_s41",
        revocation_id: "revocation_continueambiguous_s41",
        target_ref: {
          record_kind: "authority-envelope",
          record_id: value.target.payload.authority_envelope_id,
          record_event_ref: ref(value.target),
        },
        reason_code: "operator-revoked",
        evidence_refs: [{
          record_kind: "human-authorization",
          record_id: "authorization_continueambiguous_s41",
          record_event_ref: ref(value.target),
        }],
        revoker_identity_ref: "operator_continueambiguous",
        revoker_stable_identity_hash: H("4"),
      },
    });
    if (!captured.ok) throw new Error(captured.error);
    let appendOpens = 0;
    const firstStore = await captureRuntimeFileStoreV04ForTest({ run_directory: value.root }, {
      open: async (path, flags, mode) => {
        if ((flags & constants.O_APPEND) === constants.O_APPEND) {
          appendOpens += 1;
          if (appendOpens === 2) throw new Error("fence append open failed");
        }
        return mode === undefined ? openFile(path, flags) : openFile(path, flags, mode);
      },
    });
    if (!firstStore.ok) throw new Error(firstStore.error);
    const partial = await revokeRuntimeAuthorityV04(firstStore.store, { captured_request: captured.value });
    if (partial.ok || partial.revocation_event_ref === undefined) throw new Error("expected pending revocation ref");

    let writes = 0;
    const restarted = await captureRuntimeFileStoreV04ForTest({ run_directory: value.root }, {
      write: async (handle, bytes, offset, length, position) => {
        if (position === null) {
          writes += 1;
          if (writes === 1) return Math.max(1, Math.floor(length / 2));
        }
        return (await handle.write(bytes, offset, length, position)).bytesWritten;
      },
    });
    if (!restarted.ok) throw new Error(restarted.error);

    await expect(continuePendingRuntimeAuthorityRevocationV04(restarted.store, {
      pending_revocation_event_ref: partial.revocation_event_ref,
    })).resolves.toEqual({
      ok: false,
      classification: "OUTCOME_UNKNOWN",
      error: "RUNTIME_REVOCATION_OUTCOME_UNKNOWN",
      revocation_event_ref: partial.revocation_event_ref,
    });
    expect(writes).toBe(1);
  });

  it("refuses to publish when the captured revocation parent is absent", async () => {
    const value = fixture("absent", { create_revocation_directory: false });
    const captured = captureRuntimeAuthorityRevocationV04({
      trust_context: value.trust,
      signer: value.signer,
      validated_plan: value.plan,
      ledger: value.ledger,
      manifest: value.manifest,
      observation: clockObservation("absent", 1),
      request: {
        event_id: "event_revocation_absent_s41",
        revocation_id: "revocation_absent_s41",
        target_ref: {
          record_kind: "authority-envelope",
          record_id: value.target.payload.authority_envelope_id,
          record_event_ref: ref(value.target),
        },
        reason_code: "operator-revoked",
        evidence_refs: [{
          record_kind: "human-authorization",
          record_id: "authorization_absent_s41",
          record_event_ref: ref(value.target),
        }],
        revoker_identity_ref: "operator_absent",
        revoker_stable_identity_hash: H("6"),
      },
    });
    if (!captured.ok) throw new Error(captured.error);
    const store = await captureRuntimeFileStoreV04({ run_directory: value.root });
    if (!store.ok) throw new Error(store.error);

    await expect(revokeRuntimeAuthorityV04(store.store, {
      captured_request: captured.value,
    })).resolves.toEqual({
      ok: false,
      classification: "NOT_COMMITTED",
      error: "RUNTIME_REVOCATION_NOT_COMMITTED",
    });
    expect(existsSync(join(value.root, "authorities/revocations/revocation_absent_s41.json"))).toBe(false);
  });

  it("refuses to publish when the captured revocation parent is a symlink", async () => {
    const value = fixture("symlink", { revocation_directory_symlink: true });
    const captured = captureRuntimeAuthorityRevocationV04({
      trust_context: value.trust,
      signer: value.signer,
      validated_plan: value.plan,
      ledger: value.ledger,
      manifest: value.manifest,
      observation: clockObservation("symlink", 1),
      request: {
        event_id: "event_revocation_symlink_s41",
        revocation_id: "revocation_symlink_s41",
        target_ref: {
          record_kind: "authority-envelope",
          record_id: value.target.payload.authority_envelope_id,
          record_event_ref: ref(value.target),
        },
        reason_code: "operator-revoked",
        evidence_refs: [{
          record_kind: "human-authorization",
          record_id: "authorization_symlink_s41",
          record_event_ref: ref(value.target),
        }],
        revoker_identity_ref: "operator_symlink",
        revoker_stable_identity_hash: H("5"),
      },
    });
    if (!captured.ok) throw new Error(captured.error);
    const store = await captureRuntimeFileStoreV04({ run_directory: value.root });
    if (!store.ok) throw new Error(store.error);

    await expect(revokeRuntimeAuthorityV04(store.store, {
      captured_request: captured.value,
    })).resolves.toEqual({
      ok: false,
      classification: "NOT_COMMITTED",
      error: "RUNTIME_REVOCATION_NOT_COMMITTED",
    });
  });

  it("fails with PREFIX_INVALID when the captured revocation parent mode drifts", async () => {
    const value = fixture("mode");
    const captured = captureRuntimeAuthorityRevocationV04({
      trust_context: value.trust,
      signer: value.signer,
      validated_plan: value.plan,
      ledger: value.ledger,
      manifest: value.manifest,
      observation: clockObservation("mode", 1),
      request: {
        event_id: "event_revocation_mode_s41",
        revocation_id: "revocation_mode_s41",
        target_ref: {
          record_kind: "authority-envelope",
          record_id: value.target.payload.authority_envelope_id,
          record_event_ref: ref(value.target),
        },
        reason_code: "operator-revoked",
        evidence_refs: [{
          record_kind: "human-authorization",
          record_id: "authorization_mode_s41",
          record_event_ref: ref(value.target),
        }],
        revoker_identity_ref: "operator_mode",
        revoker_stable_identity_hash: H("4"),
      },
    });
    if (!captured.ok) throw new Error(captured.error);
    const store = await captureRuntimeFileStoreV04({ run_directory: value.root });
    if (!store.ok) throw new Error(store.error);
    chmodSync(join(value.root, "authorities/revocations"), 0o755);

    await expect(revokeRuntimeAuthorityV04(store.store, {
      captured_request: captured.value,
    })).resolves.toEqual({
      ok: false,
      classification: "NOT_COMMITTED",
      error: "RUNTIME_REVOCATION_PREFIX_INVALID",
    });
  });

  it("fails with PREFIX_INVALID when the captured revocation parent identity drifts", async () => {
    const value = fixture("drift");
    const captured = captureRuntimeAuthorityRevocationV04({
      trust_context: value.trust,
      signer: value.signer,
      validated_plan: value.plan,
      ledger: value.ledger,
      manifest: value.manifest,
      observation: clockObservation("drift", 1),
      request: {
        event_id: "event_revocation_drift_s41",
        revocation_id: "revocation_drift_s41",
        target_ref: {
          record_kind: "authority-envelope",
          record_id: value.target.payload.authority_envelope_id,
          record_event_ref: ref(value.target),
        },
        reason_code: "operator-revoked",
        evidence_refs: [{
          record_kind: "human-authorization",
          record_id: "authorization_drift_s41",
          record_event_ref: ref(value.target),
        }],
        revoker_identity_ref: "operator_drift",
        revoker_stable_identity_hash: H("3"),
      },
    });
    if (!captured.ok) throw new Error(captured.error);
    const store = await captureRuntimeFileStoreV04({ run_directory: value.root });
    if (!store.ok) throw new Error(store.error);
    rmSync(join(value.root, "authorities/revocations"), { recursive: true, force: true });
    mkdirSync(join(value.root, "authorities/revocations"), { recursive: true, mode: 0o700 });
    chmodSync(join(value.root, "authorities/revocations"), 0o700);

    await expect(revokeRuntimeAuthorityV04(store.store, {
      captured_request: captured.value,
    })).resolves.toEqual({
      ok: false,
      classification: "NOT_COMMITTED",
      error: "RUNTIME_REVOCATION_PREFIX_INVALID",
    });
  });
});
