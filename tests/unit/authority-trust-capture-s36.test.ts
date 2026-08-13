import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import { S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02 } from "../../src/run/action-classifier-policy-v02.js";
import { resolveS36BuiltInAuthorityDecisionPolicyExtensionV1 } from "../../src/run/action-classifier-policy-v02.js";
import * as authority from "../../src/run/runtime-record-admission-v02.js";

const HASH = `sha256:${"1".repeat(64)}`;

function trustInput(publicKeySpkiBase64: string) {
  const authenticationContext = {
    context_version: "0.1", trust_domain: "local-operator", approval_channel: "local-ed25519",
    authenticated_principal_ref: "operator_1", credential_ref: "authority_key_1",
    channel_subject_hash: HASH, session_binding_hash: `sha256:${"2".repeat(64)}`,
    assurance_level: "phishing-resistant",
  };
  return {
    observed_at: "2026-08-13T12:00:00Z",
    policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
    authentication_contexts: [authenticationContext],
    operator_keys: [{
      operator_key_id: "authority_key_1", authenticated_principal_ref: "operator_1",
      trust_domain: "local-operator", public_key_spki_base64: publicKeySpkiBase64,
      effective_from: "2026-08-13T00:00:00Z", effective_until: "2026-08-14T00:00:00Z", revoked_at: null,
    }],
    authority_epochs: [{ authenticated_principal_ref: "operator_1", revocation_epoch: 0, effective_from: "2026-08-13T00:00:00Z" }],
    durable_nonce_consumptions: [],
  };
}

describe("S36 host authority trust capture", () => {
  it("captures only a complete immutable Ed25519 trust snapshot and rejects structural forgery", () => {
    const pair = generateKeyPairSync("ed25519", { publicKeyEncoding: { type: "spki", format: "der" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
    const input = trustInput(pair.publicKey.toString("base64"));
    const captured = authority.captureAuthorityTrustContextV02(input);
    expect(captured.ok).toBe(true);
    if (!captured.ok) return;
    expect(authority.isCapturedAuthorityTrustContextV02(captured.value)).toBe(true);
    expect(Object.isFrozen(captured.value)).toBe(true);
    expect(authority.capturedAuthorityPolicyExtensionHashV02(captured.value)).toBe(
      resolveS36BuiltInAuthorityDecisionPolicyExtensionV1(input.policy_digest)?.extension_hash,
    );
    const capturedExtension = authority.resolveCapturedAuthorityDecisionPolicyExtensionV02(captured.value);
    expect(capturedExtension).toEqual(resolveS36BuiltInAuthorityDecisionPolicyExtensionV1(input.policy_digest));
    if (capturedExtension !== null) capturedExtension.reason_declarations.reverse();
    expect(authority.resolveCapturedAuthorityDecisionPolicyExtensionV02(captured.value))
      .toEqual(resolveS36BuiltInAuthorityDecisionPolicyExtensionV1(input.policy_digest));
    expect(authority.isCapturedAuthorityTrustContextV02(Object.freeze({ policy_digest: input.policy_digest }) as never)).toBe(false);
    input.operator_keys[0]!.authenticated_principal_ref = "attacker";
    expect(authority.authenticationContextHashForTrustV02(captured.value, "operator_1", "authority_key_1"))
      .toBe(hashCanonical({ purpose: "authentication-context-v02", ...input.authentication_contexts[0], authenticated_principal_ref: "operator_1" }));
  });

  it("rejects receipt-signing P-256 keys, crossed assurance, duplicates, and unknown policy", () => {
    const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1", publicKeyEncoding: { type: "spki", format: "der" } });
    expect(authority.captureAuthorityTrustContextV02(trustInput(pair.publicKey.toString("base64")))).toMatchObject({ ok: false, error: "AUTHORITY_TRUST_INVALID" });
    const ed = generateKeyPairSync("ed25519", { publicKeyEncoding: { type: "spki", format: "der" } });
    const crossed = trustInput(ed.publicKey.toString("base64"));
    crossed.authentication_contexts[0]!.assurance_level = "platform-session";
    expect(authority.captureAuthorityTrustContextV02(crossed)).toMatchObject({ ok: false, error: "AUTHORITY_TRUST_INVALID" });
    const duplicate = trustInput(ed.publicKey.toString("base64"));
    duplicate.operator_keys.push(structuredClone(duplicate.operator_keys[0]!));
    expect(authority.captureAuthorityTrustContextV02(duplicate)).toMatchObject({ ok: false, error: "AUTHORITY_TRUST_INVALID" });
    expect(authority.captureAuthorityTrustContextV02({ ...trustInput(ed.publicKey.toString("base64")), policy_digest: `sha256:${"f".repeat(64)}` }))
      .toMatchObject({ ok: false, error: "AUTHORITY_TRUST_INVALID" });
  });

  it("captures platform verifier and producer trust rows only through opaque host registrations", () => {
    const localPair = generateKeyPairSync("ed25519", { publicKeyEncoding: { type: "spki", format: "der" } });
    const producerPair = generateKeyPairSync("ed25519", { publicKeyEncoding: { type: "spki", format: "der" } });
    const verifierRegistry = authority.capturePlatformReceiptVerifierRegistryV02([
      {
        verifier_ref: "platform_verifier_1",
        verifier_identity_hash: `sha256:${"4".repeat(64)}`,
        verify: () => ({ ok: true }),
      },
    ]);
    const input = trustInput(localPair.publicKey.toString("base64"));
    input.authentication_contexts.push({
      context_version: "0.1",
      trust_domain: "platform-operator",
      approval_channel: "platform-authenticated",
      authenticated_principal_ref: "operator_2",
      credential_ref: "platform_key_1",
      channel_subject_hash: `sha256:${"5".repeat(64)}`,
      session_binding_hash: `sha256:${"6".repeat(64)}`,
      assurance_level: "platform-session",
    });
    expect(
      authority.captureAuthorityTrustContextV02({
        ...input,
        platform_channel_verifiers: [{
          operator_key_id: "platform_key_1",
          authenticated_principal_ref: "operator_2",
          trust_domain: "platform-operator",
          verifier_ref: "platform_verifier_1",
          verifier_identity_hash: `sha256:${"4".repeat(64)}`,
          proof_algorithm: "platform-authenticated-v01",
          effective_from: "2026-08-13T00:00:00Z",
          effective_until: "2026-08-14T00:00:00Z",
          revoked_at: null,
        }],
        host_producer_keys: [{
          signer_key_ref: "reviewer_key_1",
          authenticated_actor_ref: "reviewer_1",
          trust_domain: "local-operator",
          public_key_spki_base64: producerPair.publicKey.toString("base64"),
          allowed_record_kinds: ["agency-recommendation", "authority-revocation"],
          effective_from: "2026-08-13T00:00:00Z",
          effective_until: "2026-08-14T00:00:00Z",
          revoked_at: null,
        }],
      }, { platform_receipt_verifier_registry: verifierRegistry }),
    ).toMatchObject({ ok: true });
    expect(
      authority.captureAuthorityTrustContextV02({
        ...input,
        platform_channel_verifiers: [{
          operator_key_id: "platform_key_1",
          authenticated_principal_ref: "operator_2",
          trust_domain: "platform-operator",
          verifier_ref: "platform_verifier_1",
          verifier_identity_hash: `sha256:${"7".repeat(64)}`,
          proof_algorithm: "platform-authenticated-v01",
          effective_from: "2026-08-13T00:00:00Z",
          effective_until: "2026-08-14T00:00:00Z",
          revoked_at: null,
        }],
        host_producer_keys: [],
      }, { platform_receipt_verifier_registry: verifierRegistry }),
    ).toMatchObject({ ok: false, error: "AUTHORITY_TRUST_INVALID" });
    expect(
      authority.captureAuthorityTrustContextV02({
        ...input,
        platform_channel_verifiers: [{
          operator_key_id: "platform_key_1",
          authenticated_principal_ref: "operator_2",
          trust_domain: "platform-operator",
          verifier_ref: "platform_verifier_1",
          verifier_identity_hash: `sha256:${"4".repeat(64)}`,
          proof_algorithm: "platform-authenticated-v01",
          effective_from: "2026-08-13T00:00:00Z",
          effective_until: "2026-08-14T00:00:00Z",
          revoked_at: null,
        }],
        host_producer_keys: [{
          signer_key_ref: "reviewer_key_1",
          authenticated_actor_ref: "reviewer_1",
          trust_domain: "local-operator",
          public_key_spki_base64: Buffer.from("not-an-ed25519-key").toString("base64"),
          allowed_record_kinds: ["agency-recommendation"],
          effective_from: "2026-08-13T00:00:00Z",
          effective_until: "2026-08-14T00:00:00Z",
          revoked_at: null,
        }],
      }, { platform_receipt_verifier_registry: verifierRegistry }),
    ).toMatchObject({ ok: false, error: "AUTHORITY_TRUST_INVALID" });
  });
});
