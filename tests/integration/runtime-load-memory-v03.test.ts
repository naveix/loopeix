import { generateKeyPairSync } from "node:crypto";

import { afterEach, describe, expect, it } from "vitest";

import { canonicalize, hashBytes, hashCanonical } from "../../src/hash.js";
import { S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02 } from "../../src/run/action-classifier-policy-v02.js";
import { admitRuntimeActionV03 } from "../../src/run/runtime-action-admission-v03.js";
import { buildRunManifestV03 } from "../../src/run/runtime-manifest-v03.js";
import {
  captureEffectDispatchBrokerV01,
  dispatchAdmittedActionV01,
  takeCapturedEffectObservationV01,
} from "../../src/run/runtime-effect-dispatch-broker-v01.js";
import {
  captureRuntimeEffectAdapterV03,
  captureRuntimeExecutionCoordinatorV03,
  closeRuntimeExecutionCoordinatorV03,
  coordinateRuntimeActionV03,
  takeRuntimeInvocationResultV01,
} from "../../src/run/runtime-execution-coordinator-v03.js";
import { captureAuthorityTrustContextV02 } from "../../src/run/runtime-record-admission-v02.js";
import { classifyRuntimeDurabilityV03 } from "../../src/run/runtime-durability-policy-v03.js";
import {
  captureRuntimeTerminationCapabilityV03,
} from "../../src/run/runtime-termination-v03.js";
import {
  closeRuntimeWriteSessionV03,
  createSyntheticCapturedRuntimeRunStoreV03ForTest,
  inspectSyntheticRuntimeRunStoreV03ForTest,
  openRuntimeWriteSessionV03,
  type RuntimeWriteSessionV03,
} from "../../src/run/runtime-write-session-v03.js";
import {
  createSignedRuntimeActionAdmissionV03Fixture,
  SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS,
} from "../helpers/runtime-action-admission-v03-fixture.js";

const H = (character: string) => `sha256:${character.repeat(64)}`;
const encoder = new TextEncoder();
const sessions: RuntimeWriteSessionV03[] = [];
const coordinators: Array<NonNullable<Awaited<ReturnType<typeof captureRuntimeExecutionCoordinatorV03>>>> = [];

afterEach(async () => {
  for (const coordinator of coordinators.splice(0)) {
    await closeRuntimeExecutionCoordinatorV03(coordinator);
  }
  for (const session of sessions.splice(0)) {
    await closeRuntimeWriteSessionV03(session);
  }
});

function exactSizedObject(targetBytes: number): Record<string, string> {
  let low = 0;
  let high = targetBytes;
  let match: Record<string, string> | null = null;
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const candidate = { padding: "a".repeat(middle) };
    const bytes = encoder.encode(JSON.stringify(candidate)).byteLength;
    if (bytes === targetBytes) {
      match = candidate;
      break;
    }
    if (bytes < targetBytes) low = middle + 1;
    else high = middle - 1;
  }
  if (match === null) throw new Error(`unable to synthesize exact ${targetBytes}-byte object`);
  return match;
}

function nestedObject(depth: number): unknown {
  let value: unknown = "leaf";
  for (let index = 0; index < depth; index += 1) {
    value = { child: value };
  }
  return value;
}

function countedArray(count: number): readonly string[] {
  return Object.freeze(Array.from({ length: count }, (_, index) => `cell_${index}`));
}

function exactObservation(invocation: Readonly<{
  adapter_invocation_id: string;
  action_admission_event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
  normalized_dispatch_hash: string;
}>) {
  return {
    observation_version: "0.1",
    adapter_invocation_id: invocation.adapter_invocation_id,
    claimed_action_id: SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS.action_id,
    action_admission_event_ref: invocation.action_admission_event_ref,
    normalized_dispatch_hash: invocation.normalized_dispatch_hash,
    effect_refs: ["effect-diagnose-root-cause"],
    adapter_identity_hash: hashCanonical({
      purpose: "effect-dispatch-adapter-identity-v01",
      adapter_ref: "adapter_runtime_load_v03",
      adapter_version_hash: H("7"),
    }),
    adapter_profile_hash: H("8"),
  };
}

async function openSignedSession() {
  const fixture = await createSignedRuntimeActionAdmissionV03Fixture({
    additional_event_envelopes: Array.from({ length: 12 }, (_, index) => ({
      event_id: `event_runtime_load_v03_${index + 1}`,
      recorded_at: `2026-08-24T10:00:${String(index + 10).padStart(2, "0")}Z`,
    })),
  });
  const opened = await openRuntimeWriteSessionV03(fixture.store, fixture.expectation);
  if (!opened.ok) throw new Error(opened.error);
  sessions.push(opened.session);
  return { ...fixture, session: opened.session };
}

async function captureObservationPayload(observation: unknown) {
  const fixture = await openSignedSession();
  const admitted = await admitRuntimeActionV03(fixture.session, fixture.request);
  if (!admitted.ok) throw new Error(admitted.error);
  const adapterInvocationId = "invocation_runtime_load_observation";
  const broker = captureEffectDispatchBrokerV01({
    normalized_dispatch_hash: fixture.request.normalized_dispatch_hash,
    adapter_ref: "adapter_runtime_load_v03",
    adapter_version_hash: H("7"),
    adapter_profile_hash: H("8"),
    adapter_invocation_id: adapterInvocationId,
    dispatch: async () => ({ disposition: "DISPATCHED" as const, observation }),
  });
  if (broker === null) throw new Error("broker capture failed");
  const dispatched = await dispatchAdmittedActionV01(fixture.session, broker, admitted.permit);
  if (!dispatched.ok) throw new Error(dispatched.error);
  const captured = takeCapturedEffectObservationV01(broker, fixture.session, adapterInvocationId);
  await closeRuntimeWriteSessionV03(fixture.session);
  return captured;
}

async function coordinateResultPayload(result: unknown) {
  const fixture = await openSignedSession();
  const terminationCapability = captureRuntimeTerminationCapabilityV03({
    host_identity: "host_runtime_load_result_v03",
    boot_id: "boot_runtime_load_result_v03",
    unit_name: "unit_runtime_load_result_v03",
    cgroup_path: "/cg/load/runtime-result-v03",
    terminate: async (request) => ({
      ...request,
      cgroup_populated: 0 as const,
      unit_state: "inactive" as const,
    }),
  });
  if (terminationCapability === null) throw new Error("termination capability capture failed");
  const coordinator = await captureRuntimeExecutionCoordinatorV03(fixture.session, terminationCapability);
  if (coordinator === null) throw new Error("coordinator capture failed");
  coordinators.push(coordinator);
  const adapter = captureRuntimeEffectAdapterV03({
    normalized_dispatch_hash: fixture.request.normalized_dispatch_hash,
    adapter_ref: "adapter_runtime_load_v03",
    adapter_version_hash: H("7"),
    adapter_profile_hash: H("8"),
    adapter_invocation_id: "invocation_runtime_load_result",
    dispatch: async (invocation: Readonly<{
      adapter_invocation_id: string;
      action_admission_event_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
      normalized_dispatch_hash: string;
    }>) => ({
      disposition: "DISPATCHED" as const,
      observation: exactObservation(invocation),
      result,
    }),
  });
  if (adapter === null) throw new Error("effect adapter capture failed");
  return { coordinator, session: fixture.session, outcome: await coordinateRuntimeActionV03(coordinator, adapter, fixture.request) };
}

function makeAuthorityTrustContext() {
  const pair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const trust = captureAuthorityTrustContextV02({
    observed_at: "2026-08-24T10:00:00Z",
    policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
    authentication_contexts: [{
      authenticated_principal_ref: "operator_runtime_load_v03",
      credential_ref: "key_runtime_load_v03",
      trust_domain: "runtime-load-test",
      approval_channel: "local-ed25519",
      channel_subject_hash: H("1"),
      session_binding_hash: H("2"),
      assurance_level: "phishing-resistant",
      context_version: "0.1",
    }],
    operator_keys: [{
      operator_key_id: "key_runtime_load_v03",
      authenticated_principal_ref: "operator_runtime_load_v03",
      trust_domain: "runtime-load-test",
      public_key_spki_base64: pair.publicKey.toString("base64"),
      effective_from: "2026-08-24T09:00:00Z",
      effective_until: "2026-08-24T11:00:00Z",
      revoked_at: null,
    }],
    platform_channel_verifiers: [],
    host_producer_keys: [],
    authority_epochs: [{
      authenticated_principal_ref: "operator_runtime_load_v03",
      revocation_epoch: 0,
      effective_from: "2026-08-24T09:00:00Z",
    }],
    durable_nonce_consumptions: [],
  });
  if (!trust.ok) throw new Error(trust.error);
  return trust.value;
}

function admissionContextSize(value: Record<string, unknown>): number {
  const { authority_trust_context: _, ...owned } = value;
  return encoder.encode(JSON.stringify(owned)).byteLength;
}

function exactAdmissionContext(targetBytes: number) {
  const authority = makeAuthorityTrustContext();
  const base = {
    authority_trust_context: authority,
    repository_pre_state_hash: H("1"),
    normalized_dispatch_hash: H("2"),
    observed_at: "2026-08-24T10:00:00Z",
    elapsed_ms: 15,
    reviewer_view_hash: H("3"),
    enforcement: {
      available: true,
      information_flow_allowed: true,
      gates_passed: true,
      immediate_revalidation_passed: true,
    },
    condition_results: [] as Array<{ condition_hash: string; satisfied: boolean }>,
    lease_id: "lease_runtime_load_v03",
    clock_id: "clock_runtime_load_v03",
    action_id: "action_runtime_load_v03",
  };
  const padded = {
    ...base,
    observed_at: "2026-08-24T10:00:00.1Z",
  };
  const overhead = admissionContextSize(padded) - admissionContextSize(base);
  const paddingDigits = targetBytes - admissionContextSize(base) - overhead;
  if (paddingDigits < 0) throw new Error(`target ${targetBytes} is below admission-context baseline`);
  const sized = {
    ...base,
    observed_at: `2026-08-24T10:00:00.${"1".repeat(paddingDigits + 1)}Z`,
  };
  if (admissionContextSize(sized) !== targetBytes) {
    throw new Error(`unable to synthesize exact ${targetBytes}-byte admission context`);
  }
  return sized;
}

function priorLedgerText(targetBytes: number) {
  const priorPreimage = {
    schema_version: "0.3",
    event_id: "event_runtime_load_prior",
    run_id: "run_runtime_load_v03",
    sequence: 1,
    recorded_at: "2026-08-24T10:00:00Z",
    event_type: "run.initialized",
    source: "kernel",
    authority_ref: null,
    risk_tier: "T1",
    related_ids: [],
    previous_event_hash: null,
    payload: { plan_hash: H("1"), initial_fence_epoch: 0, runtime_schema_versions: { ledger_event: "0.3", run_manifest: "0.3" } },
  };
  const prior = { ...priorPreimage, event_hash: hashCanonical(priorPreimage) };
  const line = canonicalize(prior);
  const trailer = `${line}\n`;
  const fillerBytes = targetBytes - encoder.encode(trailer).byteLength;
  if (fillerBytes < 0) throw new Error("prior ledger filler must be non-negative");
  const filler = fillerBytes === 0 ? "" : `${"x".repeat(fillerBytes - 1)}\n`;
  return { prior, text: `${filler}${trailer}` };
}

function createStoreWithAdmissionContext(admissionContext: Record<string, unknown>) {
  const initializedPreimage = {
    schema_version: "0.3",
    event_id: "event_runtime_load_initialized",
    run_id: SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS.run_id,
    sequence: 1,
    recorded_at: "2026-08-24T10:00:00Z",
    event_type: "run.initialized",
    source: "kernel",
    authority_ref: null,
    risk_tier: "T1",
    related_ids: [],
    previous_event_hash: null,
    payload: {
      plan_hash: H("a"),
      initial_fence_epoch: 0,
      runtime_schema_versions: {
        resolved_run_plan: "0.2",
        ledger_event: "0.3",
        run_manifest: "0.3",
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
      },
    },
  };
  const initialized = { ...initializedPreimage, event_hash: hashCanonical(initializedPreimage) };
  const ledgerBytes = encoder.encode(`${JSON.stringify(initialized)}\n`);
  const capturedFiles = [
    { path: "artifact-manifest.json", family: "projection" as const, required: false, mode: null, bytes: null },
    { path: "ledger.jsonl", family: "primary" as const, required: true, mode: 384, bytes: ledgerBytes },
    { path: "records/authority.json", family: "record" as const, required: true, mode: 384, bytes: encoder.encode('{"authority":"captured"}\n') },
    { path: "resolved-run-plan.json", family: "primary" as const, required: true, mode: 384, bytes: encoder.encode('{"plan":"captured"}\n') },
  ];
  const manifest = buildRunManifestV03({
    ledger_bytes: ledgerBytes,
    created_at: "2026-08-24T10:00:00Z",
    captured_files: capturedFiles,
  });
  if (!manifest.ok) throw new Error(manifest.reason);
  return createSyntheticCapturedRuntimeRunStoreV03ForTest({
    run_id: SIGNED_RUNTIME_ACTION_ADMISSION_V03_ASSERTIONS.run_id,
    ledger_bytes: ledgerBytes,
    manifest_bytes: manifest.bytes,
    captured_files: capturedFiles,
    lock_identity: "lock_runtime_load_v03",
    lock_identity_valid: true,
    fault_at: null,
    event_envelopes: [{ event_id: "event_runtime_load_context", recorded_at: "2026-08-24T10:00:40Z" }],
    admission_context: admissionContext,
  });
}

function exactEventLine(targetBytes: number, previousEventHash: string) {
  let low = 0;
  let high = targetBytes;
  let match: string | null = null;
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const preimage = {
      schema_version: "0.3",
      event_id: "event_runtime_load_next",
      run_id: "run_runtime_load_v03",
      sequence: 2,
      recorded_at: "2026-08-24T10:00:01Z",
      event_type: "custom.runtime-load-check",
      source: "kernel",
      authority_ref: null,
      risk_tier: "T1",
      related_ids: [],
      previous_event_hash: previousEventHash,
      payload: { padding: "a".repeat(middle) },
    };
    const line = `${canonicalize({ ...preimage, event_hash: hashCanonical(preimage) })}\n`;
    const bytes = encoder.encode(line).byteLength;
    if (bytes === targetBytes) {
      match = line;
      break;
    }
    if (bytes < targetBytes) low = middle + 1;
    else high = middle - 1;
  }
  if (match === null) throw new Error(`unable to synthesize exact ${targetBytes}-byte event line`);
  return match;
}

describe("S40-C load and boundary evidence", { timeout: 120_000 }, () => {
  it("keeps broker observation capture exact at the 65,536-byte edge and nulls overflow", async () => {
    const exact = await captureObservationPayload(exactSizedObject(65_536));
    expect(exact).toMatchObject({ ok: true });
    if (exact.ok) expect(exact.observation).not.toBeNull();

    const overflow = await captureObservationPayload(exactSizedObject(65_537));
    expect(overflow).toMatchObject({ ok: true });
    if (overflow.ok) expect(overflow.observation).toBeNull();
  });

  it("keeps broker observation capture exact at depth 16 and 2,048 nodes, and nulls overflow", async () => {
    const depthAccepted = await captureObservationPayload(nestedObject(16));
    expect(depthAccepted).toMatchObject({ ok: true });
    if (depthAccepted.ok) expect(depthAccepted.observation).not.toBeNull();

    const depthOverflow = await captureObservationPayload(nestedObject(17));
    expect(depthOverflow).toMatchObject({ ok: true });
    if (depthOverflow.ok) expect(depthOverflow.observation).toBeNull();

    const nodesAccepted = await captureObservationPayload(countedArray(2_047));
    expect(nodesAccepted).toMatchObject({ ok: true });
    if (nodesAccepted.ok) expect(nodesAccepted.observation).not.toBeNull();

    const nodesOverflow = await captureObservationPayload(countedArray(2_048));
    expect(nodesOverflow).toMatchObject({ ok: true });
    if (nodesOverflow.ok) expect(nodesOverflow.observation).toBeNull();
  });

  it("releases matched results at the exact result ceiling and fails closed on overflow", async () => {
    const exactBytes = await coordinateResultPayload(exactSizedObject(1_048_576));
    expect(exactBytes.outcome).toMatchObject({ ok: true, disposition: "MATCHED", cleanup_status: "OPEN" });
    if (exactBytes.outcome.ok && exactBytes.outcome.disposition === "MATCHED") {
      expect(takeRuntimeInvocationResultV01(exactBytes.outcome.custody, exactBytes.coordinator, {
        adapter_invocation_id: exactBytes.outcome.adapter_invocation_id,
        action_admission_event_ref: exactBytes.outcome.action_admission_event_ref,
      })).toMatchObject({ ok: true });
    }
    await closeRuntimeExecutionCoordinatorV03(exactBytes.coordinator);
    await closeRuntimeWriteSessionV03(exactBytes.session);

    const overflowBytes = await coordinateResultPayload(exactSizedObject(1_048_577));
    expect(overflowBytes.outcome).toMatchObject({
      ok: false, error: "DISPATCH_OUTCOME_UNKNOWN_PENDING_RECONCILIATION", cleanup_status: "CLOSED",
    });
    await closeRuntimeExecutionCoordinatorV03(overflowBytes.coordinator);
    await closeRuntimeWriteSessionV03(overflowBytes.session);

    const depthAccepted = await coordinateResultPayload(nestedObject(32));
    expect(depthAccepted.outcome).toMatchObject({ ok: true, disposition: "MATCHED" });
    await closeRuntimeExecutionCoordinatorV03(depthAccepted.coordinator);
    await closeRuntimeWriteSessionV03(depthAccepted.session);

    const depthOverflow = await coordinateResultPayload(nestedObject(33));
    expect(depthOverflow.outcome).toMatchObject({
      ok: false, error: "DISPATCH_OUTCOME_UNKNOWN_PENDING_RECONCILIATION", cleanup_status: "CLOSED",
    });
    await closeRuntimeExecutionCoordinatorV03(depthOverflow.coordinator);
    await closeRuntimeWriteSessionV03(depthOverflow.session);

    const nodesAccepted = await coordinateResultPayload(countedArray(9_999));
    expect(nodesAccepted.outcome).toMatchObject({ ok: true, disposition: "MATCHED" });
    await closeRuntimeExecutionCoordinatorV03(nodesAccepted.coordinator);
    await closeRuntimeWriteSessionV03(nodesAccepted.session);

    const nodesOverflow = await coordinateResultPayload(countedArray(10_000));
    expect(nodesOverflow.outcome).toMatchObject({
      ok: false, error: "DISPATCH_OUTCOME_UNKNOWN_PENDING_RECONCILIATION", cleanup_status: "CLOSED",
    });
    await closeRuntimeExecutionCoordinatorV03(nodesOverflow.coordinator);
    await closeRuntimeWriteSessionV03(nodesOverflow.session);
  });

  it("accepts an exact 1,048,576-byte admission context and rejects 1,048,577 bytes", async () => {
    const exactContext = exactAdmissionContext(1_048_576);
    expect(admissionContextSize(exactContext)).toBe(1_048_576);
    const exactStore = createStoreWithAdmissionContext(exactContext);
    expect(exactStore).not.toBeNull();

    const overflowContext = {
      ...exactContext,
      observed_at: `${String(exactContext.observed_at).slice(0, -1)}1Z`,
    };
    expect(admissionContextSize(overflowContext)).toBe(1_048_577);
    expect(createStoreWithAdmissionContext(overflowContext)).toBeNull();
  });

  it("accepts exact 4,096-byte termination identities and rejects 4,097 bytes", () => {
    const exact = "a".repeat(4_096);
    expect(captureRuntimeTerminationCapabilityV03({
      host_identity: exact,
      boot_id: exact,
      unit_name: exact,
      cgroup_path: exact,
      terminate: async () => ({
        host_identity: exact,
        boot_id: exact,
        unit_name: exact,
        cgroup_path: exact,
        cgroup_populated: 0,
        unit_state: "inactive",
      }),
    })).not.toBeNull();

    const overflow = "a".repeat(4_097);
    expect(captureRuntimeTerminationCapabilityV03({
      host_identity: overflow,
      boot_id: exact,
      unit_name: exact,
      cgroup_path: exact,
      terminate: async () => ({
        host_identity: exact,
        boot_id: exact,
        unit_name: exact,
        cgroup_path: exact,
        cgroup_populated: 0,
        unit_state: "inactive",
      }),
    })).toBeNull();
  });

  it("classifies exact 64 MiB prior ledger and exact 1 MiB event line, and rejects overflow", () => {
    const prior = priorLedgerText(67_108_864);
    expect(encoder.encode(prior.text).byteLength).toBe(67_108_864);
    const line = exactEventLine(1_048_576, prior.prior.event_hash);
    expect(encoder.encode(line).byteLength).toBe(1_048_576);
    const observation = {
      policy_version: "0.1",
      prior_head: {
        sequence: 1,
        event_hash: prior.prior.event_hash,
        ledger_bytes_hash: hashBytes(prior.text),
      },
      target_head: {
        sequence: 2,
        event_hash: JSON.parse(line).event_hash,
        ledger_bytes_hash: hashBytes(`${prior.text}${line}`),
      },
      prior_ledger_text: prior.text,
      event_line: {
        bytes: line,
        bytes_hash: hashBytes(line),
        byte_length: encoder.encode(line).byteLength,
      },
      steps: [
        { step: "prefix-validation", outcome: "accepted" },
        { step: "append-write", outcome: "complete" },
        { step: "ledger-sync", outcome: "confirmed" },
        { step: "ledger-readback", outcome: "exact" },
        { step: "head-publish", outcome: "complete" },
        { step: "directory-sync", outcome: "confirmed" },
        { step: "final-readback", outcome: "exact" },
      ],
    } as const;
    expect(classifyRuntimeDurabilityV03(observation)).toEqual({
      classification: "COMMITTED",
      reason: "DURABLE_EXACT_READBACK",
    });
    expect(classifyRuntimeDurabilityV03({ ...observation, prior_ledger_text: `${prior.text}x` }).classification).toBe("OUTCOME_UNKNOWN");
    expect(classifyRuntimeDurabilityV03({
      ...observation,
      event_line: {
        ...observation.event_line,
        bytes: `${line}x`,
        bytes_hash: hashBytes(`${line}x`),
        byte_length: encoder.encode(`${line}x`).byteLength,
      },
    }).classification).toBe("OUTCOME_UNKNOWN");
  });
});
