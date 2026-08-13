import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { describe, expect, it } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import { S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02 } from "../../src/run/action-classifier-policy-v02.js";
import * as authority from "../../src/run/runtime-record-admission-v02.js";
import { hashAuthorityScopeV02 } from "../../src/schema/runtime.js";
import { createAgencyRecommendationRecordFixtureS36, createBaseAuthorityScopeFixtureS35 } from "../helpers/runtime-admission-fixture-s35.js";

const H1 = `sha256:${"1".repeat(64)}`;
const H2 = `sha256:${"2".repeat(64)}`;
const NONCE = `sha256:${"3".repeat(64)}`;

function setup() {
  const pair = generateKeyPairSync("ed25519", { publicKeyEncoding: { type: "spki", format: "der" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
  const context = {
    context_version: "0.1", trust_domain: "local-operator", approval_channel: "local-ed25519",
    authenticated_principal_ref: "operator_1", credential_ref: "authority_key_1",
    channel_subject_hash: H1, session_binding_hash: H2, assurance_level: "phishing-resistant",
  };
  const trust = authority.captureAuthorityTrustContextV02({
    observed_at: "2026-08-13T12:00:30Z", policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
    authentication_contexts: [context],
    operator_keys: [{ operator_key_id: "authority_key_1", authenticated_principal_ref: "operator_1", trust_domain: "local-operator", public_key_spki_base64: pair.publicKey.toString("base64"), effective_from: "2026-08-13T12:00:00Z", effective_until: "2026-08-13T13:00:00Z", revoked_at: null }],
    authority_epochs: [{ authenticated_principal_ref: "operator_1", revocation_epoch: 0, effective_from: "2026-08-13T12:00:00Z" }],
    durable_nonce_consumptions: [],
  });
  if (!trust.ok) throw new Error("fixture trust failed");
  return { pair, context, trust: trust.value };
}

const request = {
  authorization_id: "authorization_1", run_id: "run_1", plan_hash: H1,
  authorization_subject_hash: H2, authenticated_principal_ref: "operator_1",
  action_scope_hash: H1, approved_risk_tier: "T2", operator_key_id: "authority_key_1",
  approval_nonce: NONCE, issued_at: "2026-08-13T12:00:00Z", expires_at: "2026-08-13T12:05:00Z", revocation_epoch: 0,
} as const;

describe("S36 authenticated authority producers", () => {
  it("mints a strict signed proof only after an opaque atomic durable reservation", async () => {
    const { pair, trust } = setup();
    const rows: unknown[] = [];
    const nonce = authority.captureNonceReservationCapabilityV02(async (row: unknown) => { rows.push(row); return "reserved"; });
    const signer = authority.captureEd25519AuthoritySignerV02("authority_key_1", pair.privateKey);
    const minted = await authority.produceLocalHumanAuthorizationProofV02({ trust_context: trust, nonce_reservation: nonce, signer, request });
    expect(minted.ok).toBe(true);
    if (!minted.ok) return;
    expect(rows).toHaveLength(1);
    expect(authority.HumanAuthorizationProofV02.safeParse(minted.value).success).toBe(true);
    expect(minted.value.authentication_context_hash).toBe(authority.authenticationContextHashForTrustV02(trust, "operator_1", "authority_key_1"));
    expect(minted.value.proof_value).toMatch(/^[A-Za-z0-9+/]{86}==$/);
  });

  it("returns no proof when reservation is unavailable, consumed, throws, or is structurally forged", async () => {
    const { pair, trust } = setup();
    const signer = authority.captureEd25519AuthoritySignerV02("authority_key_1", pair.privateKey);
    for (const [status, error] of [["unavailable", "NONCE_RESERVATION_UNAVAILABLE"], ["already-consumed", "NONCE_ALREADY_CONSUMED"]] as const) {
      const nonce = authority.captureNonceReservationCapabilityV02(async () => status);
      expect(await authority.produceLocalHumanAuthorizationProofV02({ trust_context: trust, nonce_reservation: nonce, signer, request })).toMatchObject({ ok: false, error });
    }
    const throwing = authority.captureNonceReservationCapabilityV02(async () => { throw new Error("host down"); });
    expect(await authority.produceLocalHumanAuthorizationProofV02({ trust_context: trust, nonce_reservation: throwing, signer, request })).toMatchObject({ ok: false, error: "NONCE_RESERVATION_FAILED" });
    expect(await authority.produceLocalHumanAuthorizationProofV02({ trust_context: trust, nonce_reservation: { reserve: async () => "reserved" } as never, signer, request })).toMatchObject({ ok: false, error: "NONCE_RESERVATION_UNAVAILABLE" });
  });

  it("verifies platform receipts only through the pinned opaque verifier and exact bindings", () => {
    const { pair } = setup();
    const platformContext = { context_version: "0.1", trust_domain: "platform-operator", approval_channel: "platform-authenticated", authenticated_principal_ref: "operator_2", credential_ref: "platform_key_1", channel_subject_hash: H1, session_binding_hash: H2, assurance_level: "platform-session" } as const;
    const base = { schema_version: "0.2", authorization_id: "authorization_platform", run_id: "run_1", plan_hash: H1, authorization_subject_hash: H2, authenticated_principal_ref: "operator_2", authentication_context_hash: hashCanonical({ purpose: "authentication-context-v02", ...platformContext }), action_scope_hash: H1, approved_risk_tier: "T2", operator_key_id: "platform_key_1", approval_channel: "platform-authenticated", approval_nonce: NONCE, proof_algorithm: "platform-authenticated-v01", issued_at: "2026-08-13T12:00:00Z", expires_at: "2026-08-13T12:05:00Z", revocation_epoch: 0 } as const;
    const authorizationStatementHash = hashCanonical(base);
    const withoutRecordHash = { ...base, authorization_statement_hash: authorizationStatementHash, proof_value: "opaque-platform-receipt" };
    const proof = { ...withoutRecordHash, record_hash: hashCanonical(withoutRecordHash) };
    const registry = authority.capturePlatformReceiptVerifierRegistryV02([{ verifier_ref: "platform_verifier_1", verifier_identity_hash: H1, verify: (input) => ({ ok: input.proof_value === "opaque-platform-receipt" && input.session_binding_hash === H2 }) }]);
    const trust = authority.captureAuthorityTrustContextV02({ observed_at: "2026-08-13T12:00:30Z", policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02, authentication_contexts: [platformContext], operator_keys: [], platform_channel_verifiers: [{ operator_key_id: "platform_key_1", authenticated_principal_ref: "operator_2", trust_domain: "platform-operator", verifier_ref: "platform_verifier_1", verifier_identity_hash: H1, proof_algorithm: "platform-authenticated-v01", effective_from: "2026-08-13T12:00:00Z", effective_until: "2026-08-13T13:00:00Z", revoked_at: null }], host_producer_keys: [], authority_epochs: [{ authenticated_principal_ref: "operator_2", revocation_epoch: 0, effective_from: "2026-08-13T12:00:00Z" }], durable_nonce_consumptions: [{ authenticated_principal_ref: "operator_2", approval_nonce: NONCE, domain: "primary-v02", run_id: "run_1", authorization_id: "authorization_platform", authorization_statement_hash: authorizationStatementHash }] }, { platform_receipt_verifier_registry: registry });
    expect(trust.ok).toBe(true);
    if (trust.ok) expect(authority.verifyHumanAuthorizationProofV02(trust.value, proof)).toEqual({ ok: true });
  });

  it("authenticates host-producer attestations by actor, context, kind, key, and signature", () => {
    const producer = generateKeyPairSync("ed25519", { publicKeyEncoding: { type: "spki", format: "der" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
    const producerContext = { context_version: "0.1", trust_domain: "reviewer-host", approval_channel: "local-ed25519", authenticated_principal_ref: "reviewer_1", credential_ref: "reviewer_key_1", channel_subject_hash: H1, session_binding_hash: H2, assurance_level: "phishing-resistant" } as const;
    const trust = authority.captureAuthorityTrustContextV02({ observed_at: "2026-08-13T12:02:00Z", policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02, authentication_contexts: [producerContext], operator_keys: [{ operator_key_id: "reviewer_key_1", authenticated_principal_ref: "reviewer_1", trust_domain: "reviewer-host", public_key_spki_base64: producer.publicKey.toString("base64"), effective_from: "2026-08-13T12:00:00Z", effective_until: "2026-08-13T13:00:00Z", revoked_at: null }], platform_channel_verifiers: [], host_producer_keys: [{ signer_key_ref: "reviewer_key_1", authenticated_actor_ref: "reviewer_1", trust_domain: "reviewer-host", public_key_spki_base64: producer.publicKey.toString("base64"), allowed_record_kinds: ["agency-recommendation"], effective_from: "2026-08-13T12:00:00Z", effective_until: "2026-08-13T13:00:00Z", revoked_at: null }], authority_epochs: [{ authenticated_principal_ref: "reviewer_1", revocation_epoch: 0, effective_from: "2026-08-13T12:00:00Z" }], durable_nonce_consumptions: [] });
    expect(trust.ok).toBe(true);
    if (!trust.ok) return;
    const fixture = createAgencyRecommendationRecordFixtureS36();
    fixture.evaluator_authentication_context_hash = hashCanonical({ purpose: "authentication-context-v02", ...producerContext });
    const { record_hash: _oldRecord, producer_attestation: oldAttestation, ...recordWithoutAttestation } = fixture;
    const old = oldAttestation as Record<string, unknown>;
    const statementHash = hashCanonical({ ...recordWithoutAttestation, producer_attestation: { signer_key_ref: old.signer_key_ref, signature_algorithm: old.signature_algorithm } });
    const attestation = { signer_key_ref: old.signer_key_ref, signature_algorithm: old.signature_algorithm, statement_hash: statementHash, signature_value: cryptoSign(null, Buffer.from(statementHash, "ascii"), producer.privateKey).toString("base64") };
    const withoutRecordHash = { ...recordWithoutAttestation, producer_attestation: attestation };
    const signed = { ...withoutRecordHash, record_hash: hashCanonical(withoutRecordHash) };
    expect(authority.verifyAgencyRecommendationRecordV02(trust.value, signed)).toEqual({ ok: true });
    expect(authority.verifyAgencyRecommendationRecordV02(trust.value, { ...signed, evaluator_actor_ref: "attacker" })).toMatchObject({ ok: false });
    expect(authority.verifyAgencyRecommendationRecordV02(trust.value, { ...signed, issued_at: "2026-08-13T12:03:00Z" })).toMatchObject({ ok: false });
  });

  it("verifies only exact signature, authentication context, epoch, time, and durable first-use tuple", async () => {
    const { pair, context, trust } = setup();
    let reserved: Record<string, unknown> | undefined;
    const nonce = authority.captureNonceReservationCapabilityV02(async (row: Record<string, unknown>) => { reserved = row; return "reserved"; });
    const signer = authority.captureEd25519AuthoritySignerV02("authority_key_1", pair.privateKey);
    const minted = await authority.produceLocalHumanAuthorizationProofV02({ trust_context: trust, nonce_reservation: nonce, signer, request });
    if (!minted.ok || reserved === undefined) throw new Error("fixture mint failed");
    const historical = authority.captureAuthorityTrustContextV02({
      observed_at: "2026-08-13T12:00:30Z", policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
      authentication_contexts: [context], operator_keys: [{ operator_key_id: "authority_key_1", authenticated_principal_ref: "operator_1", trust_domain: "local-operator", public_key_spki_base64: pair.publicKey.toString("base64"), effective_from: "2026-08-13T12:00:00Z", effective_until: "2026-08-13T13:00:00Z", revoked_at: null }],
      authority_epochs: [{ authenticated_principal_ref: "operator_1", revocation_epoch: 0, effective_from: "2026-08-13T12:00:00Z" }], durable_nonce_consumptions: [reserved],
    });
    if (!historical.ok) throw new Error("fixture historical trust failed");
    expect(authority.verifyHumanAuthorizationProofV02(historical.value, minted.value)).toEqual({ ok: true });
    const changed = { ...minted.value, authentication_context_hash: H1 };
    const { record_hash: _old, ...preimage } = changed;
    expect(authority.verifyHumanAuthorizationProofV02(historical.value, { ...changed, record_hash: hashCanonical(preimage) })).toMatchObject({ ok: false, error: "AUTHORITY_PROOF_INVALID" });
    expect(authority.verifyAdmittedAuthorityTrustRecordsV02(historical.value, new Map([
      ["authorities/human/authorization_1.json", minted.value],
    ]))).toEqual({ ok: true });
    expect(authority.verifyAdmittedAuthorityTrustRecordsV02(historical.value, new Map([
      ["authorities/human/authorization_1.json", { ...minted.value, proof_value: "Zm9yZ2Vk" }],
    ]))).toEqual({ ok: false, error: "AUTHORITY_TRUST_INVALID" });
  });

  it("constructs a root envelope only from verified subject-exact proofs", async () => {
    const { pair, context, trust } = setup();
    const scope = createBaseAuthorityScopeFixtureS35();
    scope.authority_subject.policy_digest = S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02;
    scope.authority_subject.protection.action_approval_policy.policy_digest = S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02;
    scope.authority_subject.protection.delegation_mode = "strict-subset-once";
    scope.bounded_constraints.max_delegation_depth = 1;
    const envelopeInput = {
      schema_version: "0.2", authority_envelope_id: "envelope_1", run_id: "run_1", plan_hash: H1,
      policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
      subject: { principal_ref: "agent_1", stable_identity_hash: H2 },
      issuer: { principal_ref: "operator_1", stable_identity_hash: H1 }, authority_scope: scope,
      issued_at: "2026-08-13T12:00:00Z", expires_at: "2026-08-13T12:05:00Z", revocation_epoch: 0,
    };
    const subjectHash = authority.authorityEnvelopeSubjectHashV02(envelopeInput);
    expect(subjectHash).not.toBeNull();
    let reserved: Record<string, unknown> | undefined;
    const nonce = authority.captureNonceReservationCapabilityV02(async (row: Record<string, unknown>) => { reserved = row; return "reserved"; });
    const signer = authority.captureEd25519AuthoritySignerV02("authority_key_1", pair.privateKey);
    const proof = await authority.produceLocalHumanAuthorizationProofV02({
      trust_context: trust, nonce_reservation: nonce, signer,
      request: {
        ...request,
        authorization_subject_hash: subjectHash,
        action_scope_hash: hashAuthorityScopeV02(scope as never),
        approved_risk_tier: scope.max_risk_tier,
      },
    });
    if (!proof.ok || reserved === undefined) throw new Error("proof fixture failed");
    const historical = authority.captureAuthorityTrustContextV02({
      observed_at: "2026-08-13T12:00:30Z", policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
      authentication_contexts: [context], operator_keys: [{ operator_key_id: "authority_key_1", authenticated_principal_ref: "operator_1", trust_domain: "local-operator", public_key_spki_base64: pair.publicKey.toString("base64"), effective_from: "2026-08-13T12:00:00Z", effective_until: "2026-08-13T13:00:00Z", revoked_at: null }],
      authority_epochs: [{ authenticated_principal_ref: "operator_1", revocation_epoch: 0, effective_from: "2026-08-13T12:00:00Z" }], durable_nonce_consumptions: [reserved],
    });
    if (!historical.ok) throw new Error("historical trust fixture failed");
    const proofRef = { ledger_sequence: 1, event_hash: H1 };
    const envelope = authority.constructRootAuthorityEnvelopeV02({ trust_context: historical.value, envelope: envelopeInput, human_authorization_proofs: [{ proof_ref: proofRef, proof: proof.value }] });
    expect(envelope.ok).toBe(true);
    if (!envelope.ok) return;
    expect(envelope.value.authorization_subject_hash).toBe(subjectHash);
    expect(envelope.value.human_authorization_proof_refs).toEqual([proofRef]);
    expect(authority.AuthorityEnvelopeV02.safeParse(envelope.value).success).toBe(true);
    expect(authority.constructRootAuthorityEnvelopeV02({ trust_context: historical.value, envelope: { ...envelopeInput, subject: { principal_ref: "attacker", stable_identity_hash: H2 } }, human_authorization_proofs: [{ proof_ref: proofRef, proof: proof.value }] }))
      .toMatchObject({ ok: false, error: "AUTHORITY_ENVELOPE_INVALID" });

    const childScope = structuredClone(scope);
    childScope.bounded_constraints.max_actions -= 1;
    expect(authority.scopeStrictSubsetV02(childScope, scope)).toBe(true);
    expect(authority.scopeStrictSubsetV02(scope, scope)).toBe(false);
    const widened = structuredClone(childScope);
    widened.operations = [...widened.operations, "delete"];
    expect(authority.scopeStrictSubsetV02(widened, scope)).toBe(false);
    const relaxed = structuredClone(childScope);
    relaxed.side_effect_constraints.require_inspectable = false;
    expect(authority.scopeStrictSubsetV02(relaxed, scope)).toBe(false);
    const changedSubject = structuredClone(childScope);
    changedSubject.authority_subject.mission.objective = "different mission";
    expect(authority.scopeStrictSubsetV02(changedSubject, scope)).toBe(false);
    const higherRisk = structuredClone(childScope);
    higherRisk.max_risk_tier = "T4";
    expect(authority.scopeStrictSubsetV02(higherRisk, scope)).toBe(false);
    const redundantSelector = structuredClone(childScope);
    redundantSelector.resource_selectors = [
      { kind: "workspace-path", workspace_root_ref: "workspace_1", path_prefix_segments: ["src"] },
      { kind: "workspace-path", workspace_root_ref: "workspace_1", path_prefix_segments: ["src", "run"] },
    ];
    expect(authority.scopeStrictSubsetV02(redundantSelector, redundantSelector)).toBe(false);

    const rootRef = { record_kind: "authority-envelope", record_id: envelope.value.authority_envelope_id, record_event_ref: { ledger_sequence: 2, event_hash: H2 } } as const;
    const child = authority.constructDelegatedAuthorityEnvelopeV02({
      trust_context: historical.value,
      root: envelope.value,
      parent: envelope.value,
      child: {
        schema_version: "0.2", authority_envelope_id: "envelope_child", subject: { principal_ref: "agent_2", stable_identity_hash: NONCE },
        authority_scope: childScope, issued_at: "2026-08-13T12:01:00Z", expires_at: "2026-08-13T12:04:00Z", root_ref: rootRef, parent_ref: rootRef,
      },
      inherited_proofs: [{ proof_ref: proofRef, proof: proof.value }],
    });
    expect(child.ok).toBe(true);
    if (child.ok) expect(child.value.human_authorization_proof_refs).toEqual(envelope.value.human_authorization_proof_refs);
    expect(authority.constructDelegatedAuthorityEnvelopeV02({
      trust_context: historical.value, root: envelope.value, parent: envelope.value,
      child: { schema_version: "0.2", authority_envelope_id: "envelope_equal", subject: { principal_ref: "agent_2", stable_identity_hash: NONCE }, authority_scope: scope, issued_at: "2026-08-13T12:01:00Z", expires_at: "2026-08-13T12:04:00Z", root_ref: rootRef, parent_ref: rootRef },
      inherited_proofs: [{ proof_ref: { ledger_sequence: 9, event_hash: H1 }, proof: proof.value }],
    })).toMatchObject({ ok: false, error: "AUTHORITY_ENVELOPE_INVALID" });
  });
});
