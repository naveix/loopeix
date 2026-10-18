import { beforeEach, describe, expect, it, vi } from "vitest";

import { hashCanonical } from "../../src/hash.js";

const mocks = vi.hoisted(() => ({
  verify: vi.fn(() => ({ ok: true as const })),
  consumeQualification: vi.fn(),
  inspectSession: vi.fn(),
  commitEvent: vi.fn(),
  captureStore: vi.fn(),
  reconcileStore: vi.fn(),
  disposeStore: vi.fn(),
  beginAuthoritySession: vi.fn(),
  closeSession: vi.fn(),
}));

vi.mock("../../src/run/runtime-record-admission-v02.js", async (load) => {
  const actual = await load<typeof import("../../src/run/runtime-record-admission-v02.js")>();
  return { ...actual, verifyHumanAuthorizationProofV02: mocks.verify };
});

vi.mock("../../src/run/s37-linux-launch-qualification-v03.js", () => ({
  consumeAuthorizedS37LinuxLaunchQualificationV03: mocks.consumeQualification,
}));

vi.mock("../../src/run/s37-product-host-activation-store-v01.js", () => ({
  inspectS37ProductHostActivationStoreSessionV01: mocks.inspectSession,
  commitS37ProductHostActivationEventV01: mocks.commitEvent,
  captureS37ProductHostActivationStoreV01: mocks.captureStore,
  reconcileS37ProductHostActivationStoreV01: mocks.reconcileStore,
  disposeS37ProductHostActivationStoreV01: mocks.disposeStore,
  beginS37ProductHostAuthoritySessionV01: mocks.beginAuthoritySession,
  closeS37ProductHostActivationStoreSessionV01: mocks.closeSession,
}));

import {
  authorizeS37ProductHostLaunchV01,
  commitS37ProductHostLaunchAdmissionV01,
  installS37ProductHostV01,
  transitionS37ProductHostV01,
  activateStableS37ProductHostV01,
  reconcileS37ProductHostActivationV01,
} from "../../src/run/s37-product-host-activation-v01.js";
import type { CapturedAuthorityTrustContextForS36V02 } from "../../src/run/runtime-record-admission-v02.js";
import type { AuthorizedS37LinuxLaunchQualificationV03 } from "../../src/run/s37-linux-launch-qualification-v03.js";
import type { S37ProductHostActivationStoreSessionV01 } from "../../src/run/s37-product-host-activation-store-v01.js";

const H = (character: string): string => `sha256:${character.repeat(64)}`;
const ACTIVATION_ID = `activation_${"a".repeat(64)}`;
const EVENT_FOUR = H("4");
const trust = Object.freeze({}) as CapturedAuthorityTrustContextForS36V02;

function withHash<T extends Record<string, unknown>, K extends string>(
  fields: T,
  purpose: string,
  wrapper: string,
  key: K,
): T & Record<K, string> {
  return { ...fields, [key]: hashCanonical({ purpose, [wrapper]: fields }) } as T & Record<K, string>;
}

function proof() {
  const statement = {
    schema_version: "0.2" as const,
    authorization_id: "authorization_1",
    run_id: "run_1",
    plan_hash: H("1"),
    authorization_subject_hash: H("2"),
    authenticated_principal_ref: "operator_1",
    authentication_context_hash: H("3"),
    action_scope_hash: H("4"),
    approved_risk_tier: "T4" as const,
    operator_key_id: "operator_key_1",
    approval_channel: "local-ed25519" as const,
    approval_nonce: H("5"),
    proof_algorithm: "ed25519" as const,
    issued_at: "2026-10-16T10:00:00Z",
    expires_at: "2026-10-16T10:10:00Z",
    revocation_epoch: 1,
  };
  const authorizationStatementHash = hashCanonical(statement);
  const record = { ...statement, authorization_statement_hash: authorizationStatementHash, proof_value: "cHJvb2Y=" };
  return { ...record, record_hash: hashCanonical(record) };
}

function records(authorizationProof: ReturnType<typeof proof>) {
  const prelaunch = withHash({
    schema_version: "s37-product-host-prelaunch-authorization-revalidation-v01" as const,
    activation_id: ACTIVATION_ID,
    event_four_hash: EVENT_FOUR,
    action_scope_hash: authorizationProof.action_scope_hash,
    proof_record_hash: authorizationProof.record_hash,
    authorization_statement_hash: authorizationProof.authorization_statement_hash,
    authenticated_principal_ref: authorizationProof.authenticated_principal_ref,
    operator_key_id: authorizationProof.operator_key_id,
    approved_risk_tier: "T4" as const,
    revocation_epoch: 1,
    qualification_intent_hash: H("6"),
    qualification_hash: H("7"),
    conformance_receipt_hash: H("8"),
    anchor_generation: 1,
    anchor_hash: H("9"),
    artifact_set_hash: H("a"),
    controller_identity_hash: H("b"),
    broker_profile_hash: H("c"),
    boot_id_hash: H("d"),
    fence_epoch: 1,
    revalidated_at: "2026-10-16T10:01:00Z",
    valid_until: "2026-10-16T10:05:00Z",
  }, "s37-product-host-prelaunch-authorization-revalidation-v01", "revalidation", "prelaunch_authorization_revalidation_hash");
  const finalObservation = withHash({
    schema_version: "s37-product-host-final-observation-v01" as const,
    activation_id: ACTIVATION_ID,
    activation_request_hash: H("e"),
    event_four_hash: EVENT_FOUR,
    anchor_generation: 1,
    anchor_hash: H("9"),
    boot_id_hash: H("d"),
    host_tuple_hash: H("f"),
    systemd_run_hash: H("0"),
    runtime_profile_hash: H("1"),
    artifact_set_hash: H("a"),
    controller_uid: 1001,
    primary_gid: 1002,
    controller_identity_hash: H("b"),
    broker_profile_hash: H("c"),
    conformance_receipt_hash: H("8"),
    qualification_hash: H("7"),
    unit_name_hash: H("2"),
    cgroup_path_hash: H("3"),
    prelaunch_authorization_revalidation_hash: prelaunch.prelaunch_authorization_revalidation_hash,
    prelaunch_authorization_valid_until: prelaunch.valid_until,
    prelaunch_absence_observation_hash: H("4"),
    fence_epoch: 1,
    observed_at: "2026-10-16T10:02:00Z",
  }, "s37-product-host-final-observation-v01", "observation", "final_observation_hash");
  const brokerRequest = withHash({
    schema_version: "s37-product-host-broker-request-v01" as const,
    activation_id: ACTIVATION_ID,
    activation_request_hash: finalObservation.activation_request_hash,
    operation: "launch-stable" as const,
    event_four_hash: EVENT_FOUR,
    anchor_generation: 1,
    anchor_hash: H("9"),
    boot_id_hash: H("d"),
    fence_epoch: 1,
    runtime_profile_hash: H("1"),
    artifact_set_hash: H("a"),
    controller_uid: 1001,
    primary_gid: 1002,
    controller_identity_hash: H("b"),
    qualification_hash: H("7"),
    final_observation_hash: finalObservation.final_observation_hash,
    conformance_receipt_hash: H("8"),
    broker_profile_hash: H("c"),
    systemd_run_hash: H("0"),
    supervisor_hash: H("5"),
    bwrap_hash: H("6"),
    probe_hash: H("7"),
    seccomp_policy_hash: H("8"),
    unit_name: "loopeix-s37-product-activation-v01.service",
    cgroup_path: "/system.slice/loopeix-s37-product-activation-v01.service",
    command: "/usr/bin/systemd-run",
    argv: ["--system"] as const,
    cwd: "/",
    environment: { LANG: "C" },
    stdio: ["ignore", "ignore", "ignore"] as const,
    no_retry: true as const,
    broker_deadline_ms: 5_000 as const,
    prelaunch_authorization_valid_until: prelaunch.valid_until,
  }, "s37-product-host-broker-request-v01", "request", "broker_request_hash");
  const admission = withHash({
    schema_version: "s37-product-host-launch-admission-v01" as const,
    activation_id: ACTIVATION_ID,
    activation_request_hash: brokerRequest.activation_request_hash,
    operation: "launch-stable" as const,
    event_one_hash: H("1"), event_two_hash: H("2"), event_three_hash: H("3"), event_four_hash: EVENT_FOUR,
    authorization_nonce_record_hash: H("4"), launch_nonce_record_hash: H("5"), qualification_nonce_record_hash: H("6"),
    anchor_generation: 1, anchor_hash: H("9"), boot_id_hash: H("d"), controller_uid: 1001, primary_gid: 1002,
    controller_identity_hash: H("b"), fence_epoch: 1, qualification_intent_hash: H("6"),
    activation_decision_facts_hash: H("7"), decision_input_hash: H("8"), decision_simulation_hash: H("9"),
    lease_simulation_hash: H("a"), qualification_request_hash: H("b"), qualification_hash: H("7"),
    prelaunch_authorization_revalidation_hash: prelaunch.prelaunch_authorization_revalidation_hash,
    prelaunch_authorization_valid_until: prelaunch.valid_until,
    final_observation_hash: finalObservation.final_observation_hash,
    conformance_receipt_hash: H("8"), broker_profile_hash: H("c"), broker_request_hash: brokerRequest.broker_request_hash,
  }, "s37-product-host-launch-admission-v01", "admission", "launch_admission_hash");
  return { prelaunch, finalObservation, brokerRequest, admission };
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.inspectSession.mockReturnValue({
    ok: true, activation_id: ACTIVATION_ID, activation_request_hash: H("e"), fence_epoch: 1,
    next_sequence: 5, previous_event_hash: EVENT_FOUR, lock_hash: H("f"),
  });
  mocks.consumeQualification.mockReturnValue({
    qualification: { qualification_hash: H("7"), issued_at: "2026-10-16T10:00:30Z", expires_at: "2026-10-16T10:06:00Z" },
  });
  mocks.closeSession.mockResolvedValue({ released: true, outcome: "NOT_STARTED" });
  mocks.disposeStore.mockResolvedValue(true);
});

function ownedCanonical(value: unknown): Uint8Array {
  return new Uint8Array(new TextEncoder().encode(JSON.stringify(value)));
}

function custodyGateInput() {
  const requestedAt = "2026-10-16T10:00:00Z";
  const expiresAt = "2026-10-16T10:05:00Z";
  const intentFields = {
    schema_version: "s37-product-host-qualification-intent-v01" as const,
    product_profile: "s37-local-product-inert-v03" as const,
    anchor_subject_hash: H("1"), anchor_generation: 1, runtime_profile_hash: H("2"), launch_nonce: H("3"),
    requested_at: requestedAt, expires_at: expiresAt,
  };
  const intent = {
    ...intentFields,
    intent_hash: hashCanonical({ purpose: intentFields.schema_version, intent: intentFields }),
  };
  return {
    proof_request_bytes: ownedCanonical({
      authorization_id: "authorization_1", run_id: "run_1", plan_hash: H("4"), authorization_subject_hash: H("1"),
      authenticated_principal_ref: "operator_1", action_scope_hash: H("5"), approved_risk_tier: "T4",
      operator_key_id: "operator_key_1", approval_nonce: H("6"), issued_at: requestedAt, expires_at: expiresAt,
      revocation_epoch: 0,
    }),
    qualification_intent_bytes: ownedCanonical(intent),
  };
}

describe("S37.1-G3 event-five composition", () => {
  it.each([
    ["install", installS37ProductHostV01],
    ["transition", transitionS37ProductHostV01],
    ["stable", activateStableS37ProductHostV01],
  ] as const)("rejects malformed %s inputs without invoking caller accessors or custody", async (_name, invoke) => {
    const getter = vi.fn(() => { throw new Error("caller accessor executed"); });
    const accessor = Object.defineProperty({}, "proof_request_bytes", { enumerable: true, get: getter });
    const revoked = Proxy.revocable({}, {});
    revoked.revoke();
    const cases: unknown[] = [undefined, null, 1, [], {}, accessor, revoked.proxy];
    for (const input of cases) {
      await expect(Reflect.apply(invoke, undefined, [input])).resolves.toEqual({
        ok: false, outcome: "NOT_STARTED", activation_id: null, evidence_hash: null,
      });
    }
    expect(getter).not.toHaveBeenCalled();
    expect(mocks.beginAuthoritySession).not.toHaveBeenCalled();
  });

  it("rejects non-owned byte views, hidden fields, and caller operation overrides before custody", async () => {
    const valid = custodyGateInput();
    const shared = new Uint8Array(new SharedArrayBuffer(4));
    const resizable = new Uint8Array(new ArrayBuffer(4, { maxByteLength: 8 }));
    const detached = new Uint8Array(4);
    structuredClone(detached.buffer, { transfer: [detached.buffer] });
    const spoofed = Object.defineProperty(new Uint8Array(4), "buffer", {
      get: () => { throw new Error("spoofed typed-array buffer"); },
    });
    for (const bytes of [Buffer.from(valid.proof_request_bytes), shared, resizable, detached,
      new Proxy(valid.proof_request_bytes, {}), valid.proof_request_bytes.subarray(1), spoofed]) {
      await expect(activateStableS37ProductHostV01({ ...valid, proof_request_bytes: bytes })).resolves.toMatchObject({
        ok: false, outcome: "NOT_STARTED",
      });
    }
    for (const input of [
      { ...valid, operation: "install-and-launch" },
      Object.defineProperty({ ...valid }, "hidden", { value: true }),
      { ...valid, [Symbol("extra")]: true },
    ]) {
      await expect(Reflect.apply(activateStableS37ProductHostV01, undefined, [input])).resolves.toMatchObject({
        ok: false, outcome: "NOT_STARTED",
      });
    }
    expect(mocks.beginAuthoritySession).not.toHaveBeenCalled();
  });

  it("keeps custody rejection fail-closed without opening later activation effects", async () => {
    mocks.beginAuthoritySession.mockResolvedValue({ ok: false, outcome: "NOT_STARTED", error: "AUTHORITY_CUSTODY_INVALID" });
    await expect(activateStableS37ProductHostV01(custodyGateInput())).resolves.toEqual({
      ok: false, outcome: "NOT_STARTED", activation_id: null, evidence_hash: null,
    });
    expect(mocks.beginAuthoritySession).toHaveBeenCalledOnce();
    expect(mocks.closeSession).not.toHaveBeenCalled();
    expect(mocks.disposeStore).not.toHaveBeenCalled();
    expect(mocks.commitEvent).not.toHaveBeenCalled();
  });

  it("accepts store-owned custody and releases the clean fence without inventing later host effects", async () => {
    const store = Object.freeze({});
    const session = Object.freeze({});
    mocks.beginAuthoritySession.mockResolvedValue({
      ok: true,
      value: { store, session, custody: Object.freeze({}), trust_context: trust, conformance_receipt_hash: H("8") },
    });
    await expect(activateStableS37ProductHostV01(custodyGateInput())).resolves.toEqual({
      ok: false, outcome: "NOT_STARTED", activation_id: null, evidence_hash: null,
    });
    expect(mocks.beginAuthoritySession).toHaveBeenCalledWith(expect.objectContaining({
      activation_id: expect.stringMatching(/^activation_[a-f0-9]{64}$/u),
      activation_request_hash: expect.stringMatching(/^sha256:[a-f0-9]{64}$/u),
    }));
    expect(mocks.closeSession).toHaveBeenCalledWith(session);
    expect(mocks.disposeStore).toHaveBeenCalledWith(store);
    expect(mocks.commitEvent).not.toHaveBeenCalled();
  });

  it("classifies an unexpected custody-begin failure as unknown rather than falsely not-started", async () => {
    mocks.beginAuthoritySession.mockRejectedValue(new Error("ambiguous begin"));
    await expect(activateStableS37ProductHostV01(custodyGateInput())).resolves.toEqual({
      ok: false, outcome: "OUTCOME_UNKNOWN", activation_id: null, evidence_hash: null,
    });
    expect(mocks.closeSession).not.toHaveBeenCalled();
    expect(mocks.commitEvent).not.toHaveBeenCalled();
  });

  it("maps a proven-absent event-five publication to recovery because event four is already durable", async () => {
    const authorizationProof = proof();
    const authorization = authorizeS37ProductHostLaunchV01({
      trust_context: trust,
      authorization_proof: authorizationProof,
      action_scope_hash: authorizationProof.action_scope_hash,
      anchor_subject_hash: authorizationProof.authorization_subject_hash,
    });
    expect(authorization.ok).toBe(true);
    if (!authorization.ok) return;
    mocks.commitEvent.mockResolvedValue({ ok: false, outcome: "NOT_COMMITTED", error: "ACTIVATION_LEDGER_WRITE_FAILED" });
    const fixture = records(authorizationProof);
    const postCommit = vi.fn();
    const result = await commitS37ProductHostLaunchAdmissionV01({
      session: Object.freeze({}) as S37ProductHostActivationStoreSessionV01,
      launch_authorization: authorization.value,
      qualification_authorization: Object.freeze({}) as AuthorizedS37LinuxLaunchQualificationV03,
      prelaunch_trust_context: trust,
      prelaunch_revalidation: fixture.prelaunch,
      final_observation: fixture.finalObservation,
      broker_request: fixture.brokerRequest,
      launch_admission: fixture.admission,
      post_commit_recapture: postCommit,
      permit_handoff: { mint: vi.fn() },
    });
    expect(result).toEqual({ ok: false, outcome: "RECOVERY_REQUIRED", error: "ACTIVATION_LEDGER_WRITE_FAILED" });
    expect(mocks.commitEvent).toHaveBeenCalledOnce();
    expect(postCommit).not.toHaveBeenCalled();
  });

  it("does not request C3 until exact event-five and manifest hashes return", async () => {
    const authorizationProof = proof();
    const authorization = authorizeS37ProductHostLaunchV01({
      trust_context: trust,
      authorization_proof: authorizationProof,
      action_scope_hash: authorizationProof.action_scope_hash,
      anchor_subject_hash: authorizationProof.authorization_subject_hash,
    });
    if (!authorization.ok) throw new Error(authorization.error);
    const fixture = records(authorizationProof);
    mocks.commitEvent.mockResolvedValue({ ok: true, outcome: "COMMITTED", event_hash: H("a"), manifest_hash: H("b") });
    const postCommit = vi.fn(() => ({ trust_context: trust, revalidation: {} }));
    const result = await commitS37ProductHostLaunchAdmissionV01({
      session: Object.freeze({}) as S37ProductHostActivationStoreSessionV01,
      launch_authorization: authorization.value,
      qualification_authorization: Object.freeze({}) as AuthorizedS37LinuxLaunchQualificationV03,
      prelaunch_trust_context: trust,
      prelaunch_revalidation: fixture.prelaunch,
      final_observation: fixture.finalObservation,
      broker_request: fixture.brokerRequest,
      launch_admission: fixture.admission,
      post_commit_recapture: postCommit,
      permit_handoff: { mint: vi.fn() },
    });
    expect(postCommit).toHaveBeenCalledWith({ event_five_hash: H("a"), manifest_hash: H("b") });
    expect(result).toEqual({ ok: false, outcome: "OUTCOME_UNKNOWN", error: "POST_COMMIT_REVALIDATION_INVALID" });
  });

  it("hands permit material over only after C3 binds the returned event-five readback", async () => {
    const authorizationProof = proof();
    const authorization = authorizeS37ProductHostLaunchV01({
      trust_context: trust,
      authorization_proof: authorizationProof,
      action_scope_hash: authorizationProof.action_scope_hash,
      anchor_subject_hash: authorizationProof.authorization_subject_hash,
    });
    if (!authorization.ok) throw new Error(authorization.error);
    const fixture = records(authorizationProof);
    const order: string[] = [];
    mocks.commitEvent.mockImplementation(async () => {
      order.push("event-five");
      return { ok: true, outcome: "COMMITTED", event_hash: H("a"), manifest_hash: H("b") };
    });
    const postCommitRecapture = vi.fn(() => {
      order.push("c3");
      const fields = {
        schema_version: "s37-product-host-post-commit-authorization-revalidation-v01" as const,
        activation_id: ACTIVATION_ID,
        event_five_hash: H("a"), manifest_hash: H("b"),
        prelaunch_authorization_revalidation_hash: fixture.prelaunch.prelaunch_authorization_revalidation_hash,
        action_scope_hash: authorizationProof.action_scope_hash,
        proof_record_hash: authorizationProof.record_hash,
        authorization_statement_hash: authorizationProof.authorization_statement_hash,
        authenticated_principal_ref: authorizationProof.authenticated_principal_ref,
        operator_key_id: authorizationProof.operator_key_id,
        approved_risk_tier: "T4" as const,
        revocation_epoch: 1,
        anchor_generation: 1,
        anchor_hash: H("9"), artifact_set_hash: H("a"), controller_identity_hash: H("b"), broker_profile_hash: H("c"),
        boot_id_hash: H("d"), fence_epoch: 1, conformance_receipt_hash: H("8"), qualification_hash: H("7"),
        revalidated_at: "2026-10-16T10:03:00Z", valid_until: "2026-10-16T10:04:00Z",
      };
      return {
        trust_context: trust,
        revalidation: {
          ...fields,
          post_commit_authorization_revalidation_hash: hashCanonical({ purpose: fields.schema_version, revalidation: fields }),
        },
      };
    });
    const permit = Object.freeze({});
    const mint = vi.fn(() => { order.push("permit"); return permit; });
    const result = await commitS37ProductHostLaunchAdmissionV01({
      session: Object.freeze({}) as S37ProductHostActivationStoreSessionV01,
      launch_authorization: authorization.value,
      qualification_authorization: Object.freeze({}) as AuthorizedS37LinuxLaunchQualificationV03,
      prelaunch_trust_context: trust,
      prelaunch_revalidation: fixture.prelaunch,
      final_observation: fixture.finalObservation,
      broker_request: fixture.brokerRequest,
      launch_admission: fixture.admission,
      post_commit_recapture: postCommitRecapture,
      permit_handoff: { mint },
    });
    expect(result).toEqual({ ok: true, permit, event_five_hash: H("a"), manifest_hash: H("b") });
    expect(order).toEqual(["event-five", "c3", "permit"]);
    expect(mint.mock.calls[0]?.[0]).toMatchObject({
      event_five_hash: H("a"), manifest_hash: H("b"),
      post_commit_authorization_valid_until: "2026-10-16T10:04:00Z",
    });
  });

  it("classifies an unavailable production store capture as NOT_STARTED", async () => {
    mocks.captureStore.mockResolvedValue({ ok: false, error: "ACTIVATION_PLATFORM_INELIGIBLE" });
    await expect(reconcileS37ProductHostActivationV01()).resolves.toEqual({
      ok: false, outcome: "NOT_STARTED", activation_id: null, evidence_hash: null,
    });
    expect(mocks.reconcileStore).not.toHaveBeenCalled();
    expect(mocks.disposeStore).not.toHaveBeenCalled();
  });

  it.each([
    "ACTIVATION_DESCRIPTOR_CLOSE_AMBIGUOUS", "ACTIVATION_STORE_INVALID",
    "ACTIVATION_ROOT_INVALID", "ACTIVATION_DIRECTORY_INVALID",
  ])("does not claim non-entry when capture cannot prove durable state: %s", async (error) => {
    mocks.captureStore.mockResolvedValue({ ok: false, error });
    await expect(reconcileS37ProductHostActivationV01()).resolves.toEqual({
      ok: false, outcome: "OUTCOME_UNKNOWN", activation_id: null, evidence_hash: null,
    });
    expect(mocks.reconcileStore).not.toHaveBeenCalled();
    expect(mocks.disposeStore).not.toHaveBeenCalled();
  });

  it("contains capture and reconciliation exceptions and disposes a captured store", async () => {
    mocks.captureStore.mockRejectedValueOnce(new Error("capture failed"));
    await expect(reconcileS37ProductHostActivationV01()).resolves.toEqual({
      ok: false, outcome: "OUTCOME_UNKNOWN", activation_id: null, evidence_hash: null,
    });
    const store = Object.freeze({});
    mocks.captureStore.mockResolvedValue({ ok: true, store });
    mocks.reconcileStore.mockRejectedValueOnce(new Error("inspection failed"));
    await expect(reconcileS37ProductHostActivationV01()).resolves.toEqual({
      ok: false, outcome: "OUTCOME_UNKNOWN", activation_id: null, evidence_hash: null,
    });
    expect(mocks.disposeStore).toHaveBeenCalledExactlyOnceWith(store);
  });

  it.each(["false", "rejection"])("does not report completion when store disposal returns %s", async (failure) => {
    mocks.captureStore.mockResolvedValue({ ok: true, store: Object.freeze({}) });
    mocks.reconcileStore.mockResolvedValue({ outcome: "COMPLETED", activation_id: ACTIVATION_ID, evidence_hash: H("7") });
    if (failure === "false") mocks.disposeStore.mockResolvedValue(false);
    else mocks.disposeStore.mockRejectedValue(new Error("close failed"));
    await expect(reconcileS37ProductHostActivationV01()).resolves.toEqual({
      ok: false, outcome: "OUTCOME_UNKNOWN", activation_id: ACTIVATION_ID, evidence_hash: H("7"),
    });
  });
});
