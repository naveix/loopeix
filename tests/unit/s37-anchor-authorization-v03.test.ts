import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";

import { S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02 } from "../../src/run/action-classifier-policy-v02.js";
import {
  authorizeS37AnchorMutationV03,
  consumeAuthorizedS37AnchorMutationV03,
} from "../../src/run/s37-anchor-authorization-v03.js";
import {
  captureAuthorityTrustContextV02,
  captureEd25519AuthoritySignerV02,
  captureNonceReservationCapabilityV02,
  produceLocalHumanAuthorizationProofV02,
} from "../../src/run/runtime-record-admission-v02.js";
import {
  H as FIXTURE_HASH,
  S37_V03_ANCHOR,
  S37_V03_LIFECYCLE,
  hashV03,
  makeAnchorV03,
} from "../helpers/s37-product-host-v03-fixtures.js";

const H = (value: string): string => `sha256:${value.repeat(64)}`;

/**
 * Test-only host harness. Production callers receive already captured opaque S36
 * trust/proof values; the bridge never accepts raw keys, clocks, nonce callbacks,
 * or verifier callbacks.
 */
async function capturedAuthorizationFixture() {
  const baseAnchor = makeAnchorV03(2, H("7"));
  const mutationPlan = Object.freeze({
    purpose: "s37-anchor-mutation-plan-v03",
    operation: "transition",
    authorization_transaction_id: baseAnchor.operator_authority.authorization_transaction_id,
    anchor_subject_hash: baseAnchor.anchor_subject_hash,
    anchor_path: S37_V03_ANCHOR,
    lifecycle_path: S37_V03_LIFECYCLE,
    generation: baseAnchor.generation,
    predecessor_anchor_hash: baseAnchor.predecessor_anchor_hash,
  });
  const pair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const context = {
    context_version: "0.1" as const,
    trust_domain: "local-operator",
    approval_channel: "local-ed25519" as const,
    authenticated_principal_ref: "operator_1",
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
      authenticated_principal_ref: "operator_1",
      trust_domain: "local-operator",
      public_key_spki_base64: pair.publicKey.toString("base64"),
      effective_from: "2026-08-23T12:00:00Z",
      effective_until: "2026-08-23T13:00:00Z",
      revoked_at: null,
    }],
    platform_channel_verifiers: [],
    host_producer_keys: [],
    authority_epochs: [{
      authenticated_principal_ref: "operator_1",
      revocation_epoch: 3,
      effective_from: "2026-08-23T12:00:00Z",
    }],
    durable_nonce_consumptions: [],
  };
  const initialTrust = captureAuthorityTrustContextV02(trustInput);
  if (!initialTrust.ok) throw new Error("test-only S36 trust capture failed");
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
      authorization_id: "authorization_1",
      run_id: mutationPlan.authorization_transaction_id,
      plan_hash: hashV03(mutationPlan),
      authorization_subject_hash: mutationPlan.anchor_subject_hash,
      authenticated_principal_ref: "operator_1",
      action_scope_hash: H("5"),
      approved_risk_tier: "T4",
      operator_key_id: "operator_key_1",
      approval_nonce: H("6"),
      issued_at: "2026-08-23T12:00:00Z",
      expires_at: "2026-08-23T12:05:00Z",
      revocation_epoch: 3,
    },
  });
  if (!proof.ok || reservedRow === undefined) throw new Error("test-only S36 proof mint failed");
  const trust = captureAuthorityTrustContextV02({
    ...trustInput,
    durable_nonce_consumptions: [reservedRow],
  });
  if (!trust.ok) throw new Error("test-only historical S36 trust capture failed");
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
  const { anchor_hash: _baseAnchorHash, ...baseAnchorWithoutHash } = baseAnchor;
  const proposedAnchorWithoutHash = {
    ...baseAnchorWithoutHash,
    operator_authority: operatorAuthority,
  };
  const proposedAnchor = Object.freeze({
    ...proposedAnchorWithoutHash,
    anchor_hash: hashV03({
      purpose: "s37-local-product-host-anchor-v03",
      ...proposedAnchorWithoutHash,
    }),
  });
  return {
    trust: trust.value,
    proof: proof.value,
    mutationPlan,
    proposedAnchor,
    operatorAuthority,
  };
}

function validAuthorizationInput(
  fixture: Awaited<ReturnType<typeof capturedAuthorizationFixture>>,
) {
  return {
    trust_context: fixture.trust,
    authorization_proof: fixture.proof,
    required_risk_tier: "T4",
    mutation_plan: fixture.mutationPlan,
    proposed_anchor: fixture.proposedAnchor,
  } as const;
}

function rehashAnchorV03(anchor: Readonly<Record<string, unknown>>) {
  const { anchor_hash: _discardedAnchorHash, ...withoutHash } = anchor;
  return Object.freeze({
    ...withoutHash,
    anchor_hash: hashV03({ purpose: "s37-local-product-host-anchor-v03", ...withoutHash }),
  });
}

describe("S37.1-F2 anchor authorization bridge", () => {
  it("mints one opaque capability and consumes the complete immutable mutation binding once", async () => {
    const fixture = await capturedAuthorizationFixture();
    const authorized = authorizeS37AnchorMutationV03(validAuthorizationInput(fixture));

    expect(authorized.ok).toBe(true);
    if (!authorized.ok) return;
    const consumed = consumeAuthorizedS37AnchorMutationV03(authorized.value);
    expect(consumed).toEqual({
      operation: "transition",
      authorization_transaction_id: fixture.mutationPlan.authorization_transaction_id,
      mutation_plan_hash: hashV03(fixture.mutationPlan),
      anchor_subject_hash: fixture.proposedAnchor.anchor_subject_hash,
      action_scope_hash: H("5"),
      generation: 2,
      predecessor_anchor_hash: H("7"),
      operator_authority: fixture.operatorAuthority,
      mutation_plan: fixture.mutationPlan,
      proposed_anchor: fixture.proposedAnchor,
      proposed_anchor_hash: fixture.proposedAnchor.anchor_hash,
    });
    expect(Object.isFrozen(consumed)).toBe(true);
    expect(Object.isFrozen(consumed?.operator_authority)).toBe(true);
    expect(Object.isFrozen(consumed?.mutation_plan)).toBe(true);
    expect(Object.isFrozen(consumed?.proposed_anchor)).toBe(true);
    expect(consumeAuthorizedS37AnchorMutationV03(authorized.value)).toBeNull();
  });

  it("rejects every hostile authorization input with only ANCHOR_AUTHORIZATION_INVALID", async () => {
    const fixture = await capturedAuthorizationFixture();
    const valid = validAuthorizationInput(fixture);
    const hostileInputs: ReadonlyArray<readonly [string, unknown]> = [
      ["uncaptured trust", { ...valid, trust_context: {} }],
      ["non-T4 request", { ...valid, required_risk_tier: "T3" }],
      ["anchor path drift", {
        ...valid,
        mutation_plan: { ...valid.mutation_plan, anchor_path: "/tmp/anchor.json" },
      }],
      ["lifecycle path drift", {
        ...valid,
        mutation_plan: { ...valid.mutation_plan, lifecycle_path: "/tmp/lifecycle.json" },
      }],
      ["plan operation drift", {
        ...valid,
        mutation_plan: { ...valid.mutation_plan, operation: "install" },
      }],
      ["plan transaction drift", {
        ...valid,
        mutation_plan: { ...valid.mutation_plan, authorization_transaction_id: "transaction_8" },
      }],
      ["plan subject drift", {
        ...valid,
        mutation_plan: { ...valid.mutation_plan, anchor_subject_hash: H("8") },
      }],
      ["plan generation drift", {
        ...valid,
        mutation_plan: { ...valid.mutation_plan, generation: 3 },
      }],
      ["plan predecessor drift", {
        ...valid,
        mutation_plan: { ...valid.mutation_plan, predecessor_anchor_hash: H("8") },
      }],
      ["recomputed plan-hash mismatch", {
        ...valid,
        mutation_plan: { ...valid.mutation_plan, predecessor_anchor_hash: FIXTURE_HASH("8") },
      }],
      ["anchor swap", { ...valid, proposed_anchor: makeAnchorV03(1) }],
      ["anchor generation drift", {
        ...valid,
        proposed_anchor: makeAnchorV03(3, H("7")),
      }],
      ["anchor predecessor drift", {
        ...valid,
        proposed_anchor: makeAnchorV03(2, H("8")),
      }],
      ["anchor operator-authority drift", {
        ...valid,
        proposed_anchor: rehashAnchorV03({
          ...valid.proposed_anchor,
          operator_authority: {
            ...valid.proposed_anchor.operator_authority,
            authorization_transaction_id: "transaction_8",
          },
        }),
      }],
      ["raw clock callback", { ...valid, clock: () => "2026-08-23T12:00:30Z" }],
      ["raw key", { ...valid, operator_private_key: "forbidden" }],
      ["raw nonce callback", { ...valid, reserve_nonce: () => "reserved" }],
      ["raw verifier callback", { ...valid, verify: () => true }],
    ];

    for (const [label, input] of hostileInputs) {
      expect(authorizeS37AnchorMutationV03(input), label).toEqual({
        ok: false,
        error: "ANCHOR_AUTHORIZATION_INVALID",
      });
    }
  });

  it("cannot consume a structured clone of an opaque capability", async () => {
    const fixture = await capturedAuthorizationFixture();
    const authorized = authorizeS37AnchorMutationV03(validAuthorizationInput(fixture));
    expect(authorized.ok).toBe(true);
    if (!authorized.ok) return;

    const clone = structuredClone(authorized.value);
    expect(consumeAuthorizedS37AnchorMutationV03(clone)).toBeNull();
    expect(consumeAuthorizedS37AnchorMutationV03(null)).toBeNull();
    expect(consumeAuthorizedS37AnchorMutationV03(1)).toBeNull();
    expect(consumeAuthorizedS37AnchorMutationV03("capability")).toBeNull();
    expect(consumeAuthorizedS37AnchorMutationV03(authorized.value)).not.toBeNull();
  });
});
