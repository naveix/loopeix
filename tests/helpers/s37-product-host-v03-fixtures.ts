import { createHash, generateKeyPairSync } from "node:crypto";

import { canonicalV03 } from "../../src/run/s37-product-host-contract-v03.js";
import { hashCanonicalV03 } from "../../src/run/s37-product-host-contract-v03.js";
import { S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02 } from "../../src/run/action-classifier-policy-v02.js";
import { authorizeS37AnchorMutationV03 } from "../../src/run/s37-anchor-authorization-v03.js";
import {
  captureAuthorityTrustContextV02,
  captureEd25519AuthoritySignerV02,
  captureNonceReservationCapabilityV02,
  produceLocalHumanAuthorizationProofV02,
} from "../../src/run/runtime-record-admission-v02.js";

export const S37_V03_PARENT = "/etc/loopeix/s37.1/product-host-v03";
export const S37_V03_ANCHOR = `${S37_V03_PARENT}/anchor.json`;
export const S37_V03_LIFECYCLE = `${S37_V03_PARENT}/lifecycle-state.json`;
export const S37_V03_LOCK = `${S37_V03_PARENT}/transition.lock`;

export const H = (digit: string): `sha256:${string}` => `sha256:${digit.repeat(64)}`;

export function hashV03(value: unknown): `sha256:${string}` {
  const result = hashCanonicalV03(value);
  if (!result.ok) throw new Error(`invalid V03 fixture: ${result.error}`);
  return result.value as `sha256:${string}`;
}

export function encodeV03(value: unknown): string {
  const result = canonicalV03(value);
  if (!result.ok) throw new Error(`invalid V03 fixture: ${result.error}`);
  return `${result.value}\n`;
}

const keyPair = generateKeyPairSync("ed25519", {
  publicKeyEncoding: { type: "spki", format: "der" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const issuer = Object.freeze({
  key_ref: "qualification_key_1",
  algorithm: "ed25519",
  public_key_spki_base64: keyPair.publicKey.toString("base64"),
  public_key_spki_sha256: `sha256:${createHash("sha256").update(keyPair.publicKey).digest("hex")}`,
});

const managed = (path: string, digit: string) => Object.freeze({
  path, source_sha256: H(digit), sha256: H(digit), mode: "0555",
  uid: 0, gid: 0, nlink: 1, setuid: false,
});

const hostExecutable = (path: string, digit: string) => Object.freeze({
  path, sha256: H(digit), mode: "0755", uid: 0, gid: 0, nlink: 1, setuid: false,
});

const artifacts = Object.freeze({
  supervisor: managed("/opt/loopeix/s37.1/supervisor", "1"),
  probe: managed("/opt/loopeix/s37.1/probe", "2"),
  bwrap: Object.freeze({ ...managed("/opt/loopeix/s37.1/bwrap", "3"), version: "0.11.0" }),
  systemd_run: hostExecutable("/usr/bin/systemd-run", "4"),
  systemctl: hostExecutable("/usr/bin/systemctl", "5"),
  embedded_seccomp_policy_sha256: H("6"),
});

const host = Object.freeze({
  platform: "linux", distribution_id: "debian", distribution_version_id: "13",
  architecture: "x86_64", kernel_release: "6.12.0-amd64", systemd_version: "257",
  cgroup_version: "v2", host_identity_hash: H("7"), controller_uid: 1000,
});

export function makeAnchorV03(generation = 1, predecessorAnchorHash: string | null = null) {
  const operation = generation === 1 ? "install" : "transition";
  const authorizationTransactionId = `transaction_${generation}`;
  const subject = {
    schema_version: "s37-local-product-host-anchor-v03",
    product_profile: "s37-local-product-inert-v03",
    runtime_profile_version: "0.1",
    runtime_profile_hash: H("8"),
    host_role: "local-product",
    transport: "local-only",
    host,
    artifacts,
    cwd: { path: "/", identity_hash: H("9") },
    install_bundle_hash: H("a"),
    qualification_issuer: issuer,
    generation,
    predecessor_anchor_hash: predecessorAnchorHash,
  };
  const anchorSubjectHash = hashV03({ purpose: "s37-local-product-host-anchor-subject-v03", ...subject });
  const mutationPlanHash = hashV03({
    purpose: "s37-anchor-mutation-plan-v03",
    operation,
    authorization_transaction_id: authorizationTransactionId,
    anchor_subject_hash: anchorSubjectHash,
    anchor_path: S37_V03_ANCHOR,
    lifecycle_path: S37_V03_LIFECYCLE,
    generation,
    predecessor_anchor_hash: predecessorAnchorHash,
  });
  const withoutHash = {
    ...subject,
    anchor_subject_hash: anchorSubjectHash,
    operator_authority: {
      authorization_id: `authorization_${generation}`,
      authenticated_principal_ref: "principal_1",
      operator_key_id: "operator_key_1",
      authorization_transaction_id: authorizationTransactionId,
      mutation_plan_hash: mutationPlanHash,
      authorization_subject_hash: anchorSubjectHash,
      action_scope_hash: H("c"),
      approval_nonce: H("d"),
      authorization_statement_hash: H("e"),
      proof_record_hash: H("f"),
      revocation_epoch: 0,
      expires_at: "2026-08-23T12:01:00Z",
    },
    installed_at: "2026-08-23T12:00:00Z",
  };
  return Object.freeze({
    ...withoutHash,
    anchor_hash: hashV03({ purpose: "s37-local-product-host-anchor-v03", ...withoutHash }),
  });
}

export async function makeAuthorizedMutationV03(anchor: ReturnType<typeof makeAnchorV03>) {
  const operation = anchor.generation === 1 ? "install" : "transition";
  const mutationPlan = Object.freeze({
    purpose: "s37-anchor-mutation-plan-v03" as const,
    operation,
    authorization_transaction_id: anchor.operator_authority.authorization_transaction_id,
    anchor_subject_hash: anchor.anchor_subject_hash,
    anchor_path: S37_V03_ANCHOR as "/etc/loopeix/s37.1/product-host-v03/anchor.json",
    lifecycle_path: S37_V03_LIFECYCLE as "/etc/loopeix/s37.1/product-host-v03/lifecycle-state.json",
    generation: anchor.generation,
    predecessor_anchor_hash: anchor.predecessor_anchor_hash,
  });
  const pair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const context = {
    context_version: "0.1" as const,
    trust_domain: "local-operator",
    approval_channel: "local-ed25519" as const,
    authenticated_principal_ref: "principal_1",
    credential_ref: "operator_key_1",
    channel_subject_hash: H("1"),
    session_binding_hash: H("2"),
    assurance_level: "phishing-resistant" as const,
  };
  const trustInput = {
    observed_at: "2026-08-23T12:00:30Z",
    policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
    authentication_contexts: [context],
    operator_keys: [{
      operator_key_id: "operator_key_1",
      authenticated_principal_ref: "principal_1",
      trust_domain: "local-operator",
      public_key_spki_base64: pair.publicKey.toString("base64"),
      effective_from: "2026-08-23T12:00:00Z",
      effective_until: "2026-08-23T13:00:00Z",
      revoked_at: null,
    }],
    platform_channel_verifiers: [],
    host_producer_keys: [],
    authority_epochs: [{
      authenticated_principal_ref: "principal_1",
      revocation_epoch: 3,
      effective_from: "2026-08-23T12:00:00Z",
    }],
    durable_nonce_consumptions: [],
  };
  const initialTrust = captureAuthorityTrustContextV02(trustInput);
  if (!initialTrust.ok) throw new Error("test S36 trust capture failed");
  let reservedRow: Readonly<Record<string, unknown>> | undefined;
  const reservation = captureNonceReservationCapabilityV02(async (row) => {
    reservedRow = row;
    return "reserved";
  });
  const signer = captureEd25519AuthoritySignerV02("operator_key_1", pair.privateKey);
  const proof = await produceLocalHumanAuthorizationProofV02({
    trust_context: initialTrust.value,
    nonce_reservation: reservation,
    signer,
    request: {
      authorization_id: `authorization_${anchor.generation}`,
      run_id: mutationPlan.authorization_transaction_id,
      plan_hash: hashV03(mutationPlan),
      authorization_subject_hash: mutationPlan.anchor_subject_hash,
      authenticated_principal_ref: "principal_1",
      action_scope_hash: H("c"),
      approved_risk_tier: "T4",
      operator_key_id: "operator_key_1",
      approval_nonce: H("d"),
      issued_at: "2026-08-23T12:00:00Z",
      expires_at: "2026-08-23T12:05:00Z",
      revocation_epoch: 3,
    },
  });
  if (!proof.ok || reservedRow === undefined) throw new Error("test S36 proof mint failed");
  const trust = captureAuthorityTrustContextV02({ ...trustInput, durable_nonce_consumptions: [reservedRow] });
  if (!trust.ok) throw new Error("test S36 durable trust capture failed");
  const operatorAuthority = {
    authorization_id: proof.value.authorization_id,
    authenticated_principal_ref: proof.value.authenticated_principal_ref,
    operator_key_id: proof.value.operator_key_id,
    authorization_transaction_id: proof.value.run_id,
    mutation_plan_hash: proof.value.plan_hash,
    authorization_subject_hash: proof.value.authorization_subject_hash,
    action_scope_hash: proof.value.action_scope_hash,
    approval_nonce: proof.value.approval_nonce,
    authorization_statement_hash: proof.value.authorization_statement_hash,
    proof_record_hash: proof.value.record_hash,
    revocation_epoch: proof.value.revocation_epoch,
    expires_at: proof.value.expires_at,
  };
  const { anchor_hash: _discarded, ...anchorWithoutHash } = anchor;
  const proposedWithoutHash = { ...anchorWithoutHash, operator_authority: operatorAuthority };
  const proposedAnchor = Object.freeze({
    ...proposedWithoutHash,
    anchor_hash: hashV03({ purpose: "s37-local-product-host-anchor-v03", ...proposedWithoutHash }),
  });
  const authorized = authorizeS37AnchorMutationV03({
    trust_context: trust.value,
    authorization_proof: proof.value,
    required_risk_tier: "T4",
    mutation_plan: mutationPlan,
    proposed_anchor: proposedAnchor,
  });
  if (!authorized.ok) throw new Error("test S37 authorization failed");
  return Object.freeze({ authorization: authorized.value, anchor: proposedAnchor, mutation_plan: mutationPlan });
}

export function makeTransitionLockV03(anchor: ReturnType<typeof makeAnchorV03>) {
  const body = {
    schema_version: "s37-product-host-transition-lock-v01",
    operation: anchor.generation === 1 ? "install" : "transition",
    authorization_transaction_id: anchor.operator_authority.authorization_transaction_id,
    generation: anchor.generation,
    expected_previous_anchor_hash: anchor.predecessor_anchor_hash,
    proposed_anchor_hash: anchor.anchor_hash,
    authorization_record_hash: anchor.operator_authority.proof_record_hash,
  };
  return Object.freeze({
    ...body,
    lock_hash: hashV03({ purpose: "s37-product-host-transition-lock-v01", ...body }),
  });
}

export function makeLifecycleStateV03(
  status: "PREPARING" | "STABLE",
  anchor: ReturnType<typeof makeAnchorV03>,
  stableAnchorHash: string | null,
) {
  const body = status === "PREPARING" ? {
    schema_version: "s37-product-host-lifecycle-state-v01",
    status,
    generation: anchor.generation,
    stable_anchor_hash: stableAnchorHash,
    expected_previous_anchor_hash: anchor.predecessor_anchor_hash,
    proposed_anchor_hash: anchor.anchor_hash,
    authorization_transaction_id: anchor.operator_authority.authorization_transaction_id,
    authorization_record_hash: anchor.operator_authority.proof_record_hash,
    updated_at: anchor.installed_at,
  } : {
    schema_version: "s37-product-host-lifecycle-state-v01",
    status,
    generation: anchor.generation,
    stable_anchor_hash: anchor.anchor_hash,
    expected_previous_anchor_hash: null,
    proposed_anchor_hash: null,
    authorization_transaction_id: null,
    authorization_record_hash: null,
    updated_at: anchor.installed_at,
  };
  return Object.freeze({
    ...body,
    state_hash: hashV03({ purpose: "s37-product-host-lifecycle-state-v01", ...body }),
  });
}
