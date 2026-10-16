import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import { S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02 } from "../../src/run/action-classifier-policy-v02.js";
import * as authority from "../../src/run/runtime-record-admission-v02.js";
import { createAgencyActionProposalInputFixtureS36 } from "../helpers/runtime-admission-fixture-s35.js";

const H1 = `sha256:${"1".repeat(64)}`;
const H2 = `sha256:${"2".repeat(64)}`;
const H3 = `sha256:${"3".repeat(64)}`;

function setupReviewer(actorRef = "reviewer_1") {
  const pair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const keyRef = `${actorRef}_key`;
  const context = {
    context_version: "0.1", trust_domain: "reviewer-host", approval_channel: "local-ed25519",
    authenticated_principal_ref: actorRef, credential_ref: keyRef,
    channel_subject_hash: H1, session_binding_hash: H2, assurance_level: "phishing-resistant",
  } as const;
  const trust = authority.captureAuthorityTrustContextV02({
    observed_at: "2026-08-13T12:02:00Z",
    policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
    authentication_contexts: [context],
    operator_keys: [{
      operator_key_id: keyRef, authenticated_principal_ref: actorRef, trust_domain: "reviewer-host",
      public_key_spki_base64: pair.publicKey.toString("base64"), effective_from: "2026-08-13T12:00:00Z",
      effective_until: "2026-08-13T13:00:00Z", revoked_at: null,
    }],
    platform_channel_verifiers: [],
    host_producer_keys: [{
      signer_key_ref: keyRef, authenticated_actor_ref: actorRef, trust_domain: "reviewer-host",
      public_key_spki_base64: pair.publicKey.toString("base64"), allowed_record_kinds: ["agency-recommendation"],
      effective_from: "2026-08-13T12:00:00Z", effective_until: "2026-08-13T13:00:00Z", revoked_at: null,
    }],
    authority_epochs: [{ authenticated_principal_ref: actorRef, revocation_epoch: 0, effective_from: "2026-08-13T12:00:00Z" }],
    durable_nonce_consumptions: [],
  });
  if (!trust.ok) throw new Error("reviewer trust fixture failed");
  return { trust: trust.value, signer: authority.captureHostProducerEd25519SignerV02(keyRef, pair.privateKey) };
}

function proposalAndView() {
  const proposal = createAgencyActionProposalInputFixtureS36();
  const view = authority.constructReviewerViewV02({
    action_proposal: proposal,
    evidence_extractions: [{
      evidence_ref: { record_kind: "evidence", record_id: "evidence_1", record_event_ref: { ledger_sequence: 1, event_hash: H1 } },
      source_selector_hash: H1, source_content_hash: H2, extracted_fact_hashes: [H3], provenance_hash: H1,
      source_trust: "authenticated", sensitivity: "internal", uncertainty: "bounded",
    }],
  });
  if (!view.ok) throw new Error("reviewer view fixture failed");
  return { proposal, view: view.value };
}

function request(overrides: Record<string, unknown> = {}) {
  return {
    recommendation_id: "recommendation_1",
    reviewed_through_ref: { ledger_sequence: 2, event_hash: H2 },
    evidence_refs: [{ record_kind: "evidence", record_id: "evidence_1", record_event_ref: { ledger_sequence: 1, event_hash: H1 } }],
    evidence_independence_keys: [H3],
    evidence_producer_stable_identity_hashes: [H2],
    evaluator_role_ref: "authority-governor",
    evaluator_actor_ref: "reviewer_1",
    evaluator_stable_identity_hash: H1,
    decision: "allow",
    conditions: [],
    reason_declaration_refs: ["recommendation-allow-evidence"],
    issued_at: "2026-08-13T12:01:00Z",
    expires_at: "2026-08-13T12:04:00Z",
    ...overrides,
  };
}

describe("S36 authenticated agency recommendation producer", () => {
  it("resolves quorum and reasons from immutable policy, binds the reviewer view, and signs the exact record", () => {
    const { trust, signer } = setupReviewer();
    const { proposal, view } = proposalAndView();
    const result = authority.produceAgencyRecommendationRecordV02({
      trust_context: trust, signer, action_proposal: proposal, reviewer_view: view, request: request(),
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.quorum_requirement_hash).toMatch(/^sha256:/);
    expect(result.value.reason_codes).toEqual([{ policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02, declaration_ref: "recommendation-allow-evidence" }]);
    expect(result.value.producer_attestation.statement_hash).not.toBe(H1);
    expect(authority.verifyAgencyRecommendationRecordV02(trust, result.value)).toEqual({ ok: true });
  });

  it("rejects caller quorum, stale TTL, incompatible reasons, self approval, and evidence-producer aliasing", () => {
    const { trust, signer } = setupReviewer();
    const { proposal, view } = proposalAndView();
    const produce = (overrides: Record<string, unknown>) => authority.produceAgencyRecommendationRecordV02({
      trust_context: trust, signer, action_proposal: proposal, reviewer_view: view, request: request(overrides),
    });
    expect(produce({ quorum_requirement_hash: H1 })).toMatchObject({ ok: false });
    expect(produce({ expires_at: "2026-08-13T12:07:00Z" })).toMatchObject({ ok: false });
    expect(produce({ reason_declaration_refs: ["recommendation-deny-policy"] })).toMatchObject({ ok: false });
    expect(produce({ evaluator_stable_identity_hash: proposal.proposer_stable_identity_hash })).toMatchObject({ ok: false });
    expect(produce({ evidence_producer_stable_identity_hashes: [H1] })).toMatchObject({ ok: false });
  });

  it("rejects a forged signer, mismatched view, empty evidence, and a role outside the exact quorum row", () => {
    const { trust, signer } = setupReviewer();
    const { proposal, view } = proposalAndView();
    const forged = { key_ref: signer.key_ref } as never;
    expect(authority.produceAgencyRecommendationRecordV02({ trust_context: trust, signer: forged, action_proposal: proposal, reviewer_view: view, request: request() })).toMatchObject({ ok: false });
    expect(authority.produceAgencyRecommendationRecordV02({ trust_context: trust, signer, action_proposal: proposal, reviewer_view: { ...view, reviewer_view_hash: H1 }, request: request() })).toMatchObject({ ok: false });
    expect(authority.produceAgencyRecommendationRecordV02({ trust_context: trust, signer, action_proposal: proposal, reviewer_view: view, request: request({ evidence_refs: [], evidence_independence_keys: [] }) })).toMatchObject({ ok: false });
    expect(authority.produceAgencyRecommendationRecordV02({ trust_context: trust, signer, action_proposal: proposal, reviewer_view: view, request: request({ evaluator_role_ref: "security-reviewer" }) })).toMatchObject({ ok: false });
  });
});
