import { describe, expect, it } from "vitest";

import * as authorityContracts from "../../src/run/runtime-record-admission-v02.js";
import { AgencyRecommendationRecordV02, AuthorityEnvelopeV02, HumanAuthorizationProofV02 } from "../../src/run/runtime-record-admission-v02.js";
import { hashCanonical } from "../../src/hash.js";
import { hashAuthorityScopeV02 } from "../../src/schema/runtime.js";
import { createAgencyRecommendationRecordFixtureS36, createBaseAuthorityScopeFixtureS35 } from "../helpers/runtime-admission-fixture-s35.js";

const HASH = `sha256:${"1".repeat(64)}`;

function finalizeEnvelope(envelope: Record<string, unknown>): Record<string, unknown> {
  const authorizationSubjectHash = hashCanonical({
    purpose: "authority-envelope-subject-v02",
    schema_version: envelope.schema_version,
    authority_envelope_id: envelope.authority_envelope_id,
    run_id: envelope.run_id,
    plan_hash: envelope.plan_hash,
    policy_digest: envelope.policy_digest,
    subject: envelope.subject,
    issuer: envelope.issuer,
    action_scope_hash: envelope.action_scope_hash,
    lineage: envelope.lineage,
    issued_at: envelope.issued_at,
    expires_at: envelope.expires_at,
    revocation_epoch: envelope.revocation_epoch,
  });
  const withoutRecordHash = { ...envelope, authorization_subject_hash: authorizationSubjectHash };
  delete withoutRecordHash.record_hash;
  return { ...withoutRecordHash, record_hash: hashCanonical(withoutRecordHash) };
}

function finalizeProof(proof: Record<string, unknown>): Record<string, unknown> {
  const {
    authorization_statement_hash: _statementHash,
    proof_value,
    record_hash: _recordHash,
    ...statementPreimage
  } = proof;
  const withStatement = {
    ...statementPreimage,
    authorization_statement_hash: hashCanonical(statementPreimage),
    proof_value,
  };
  return { ...withStatement, record_hash: hashCanonical(withStatement) };
}

function validProof(): Record<string, unknown> {
  return finalizeProof({
    schema_version: "0.2",
    authorization_id: "authorization_main",
    run_id: "run_main",
    plan_hash: HASH,
    authorization_subject_hash: HASH,
    authenticated_principal_ref: "principal_main",
    authentication_context_hash: HASH,
    action_scope_hash: HASH,
    approved_risk_tier: "T2",
    operator_key_id: "key_main",
    approval_channel: "local-ed25519",
    approval_nonce: HASH,
    proof_algorithm: "ed25519",
    proof_value: "c2lnbmF0dXJl",
    issued_at: "2026-08-13T12:00:00Z",
    expires_at: "2026-08-13T12:05:00Z",
    revocation_epoch: 0,
  });
}

function validRootEnvelope(): Record<string, unknown> {
  const authorityScope = createBaseAuthorityScopeFixtureS35();
  const authoritySubject = authorityScope.authority_subject as { policy_digest: string };
  const issuer = { principal_ref: "operator_1", stable_identity_hash: HASH };
  const subject = { principal_ref: "agent_1", stable_identity_hash: `sha256:${"2".repeat(64)}` };
  return finalizeEnvelope({
    schema_version: "0.2",
    authority_envelope_id: "envelope_main",
    run_id: "run_main",
    plan_hash: HASH,
    policy_digest: authoritySubject.policy_digest,
    subject,
    issuer,
    authorization_subject_hash: HASH,
    human_authorization_proof_refs: [{ ledger_sequence: 1, event_hash: HASH }],
    authority_scope: authorityScope,
    action_scope_hash: hashAuthorityScopeV02(authorityScope as never),
    lineage: {
      kind: "root",
      root_authority_envelope_ref: null,
      parent_authority_envelope_ref: null,
      delegation: null,
      on_behalf_of_chain: [issuer, subject],
      delegation_depth: 0,
    },
    issued_at: "2026-08-13T12:00:00Z",
    expires_at: "2026-08-13T12:05:00Z",
    revocation_epoch: 0,
    record_hash: HASH,
  });
}

function validDelegableRootEnvelope(): Record<string, unknown> {
  const envelope = validRootEnvelope();
  const scope = structuredClone(envelope.authority_scope) as Record<string, unknown>;
  const subject = scope.authority_subject as {
    protection: { delegation_mode: string };
  };
  const bounds = scope.bounded_constraints as { max_delegation_depth: number };
  subject.protection.delegation_mode = "strict-subset-once";
  bounds.max_delegation_depth = 1;
  return finalizeEnvelope({ ...envelope, authority_scope: scope, action_scope_hash: hashAuthorityScopeV02(scope as never) });
}

function validDelegatedEnvelope(): Record<string, unknown> {
  const root = validDelegableRootEnvelope();
  const rootScope = root.authority_scope as Record<string, unknown>;
  const childScope = structuredClone(rootScope) as Record<string, unknown>;
  (childScope.bounded_constraints as { max_actions: number }).max_actions = 0;
  const rootIssuer = root.issuer as Record<string, unknown>;
  const parentSubject = root.subject as Record<string, unknown>;
  const childSubject = { principal_ref: "child_agent_1", stable_identity_hash: `sha256:${"4".repeat(64)}` };
  const rootRef = {
    record_kind: "authority-envelope",
    record_id: root.authority_envelope_id,
    record_event_ref: { ledger_sequence: 2, event_hash: HASH },
  };
  return finalizeEnvelope({
    ...root,
    authority_envelope_id: "envelope_child",
    subject: childSubject,
    issuer: parentSubject,
    authority_scope: childScope,
    action_scope_hash: hashAuthorityScopeV02(childScope as never),
    lineage: {
      kind: "delegated",
      root_authority_envelope_ref: rootRef,
      parent_authority_envelope_ref: rootRef,
      delegation: {
        delegated_by: parentSubject,
        delegated_to: childSubject,
        parent_scope_hash: root.action_scope_hash,
        child_scope_hash: hashAuthorityScopeV02(childScope as never),
        delegated_at: "2026-08-13T12:01:00Z",
      },
      on_behalf_of_chain: [rootIssuer, parentSubject, childSubject],
      delegation_depth: 1,
    },
  });
}

describe("S36 frozen authority contracts", () => {
  it("admits the exact frozen root authority-envelope shape", () => {
    expect("AuthorityEnvelopeV02" in authorityContracts).toBe(true);
    const envelope = validRootEnvelope();
    expect(AuthorityEnvelopeV02.safeParse(envelope).success).toBe(true);
  });

  it("admits a fully bound frozen agency-recommendation record", () => {
    expect("AgencyRecommendationRecordV02" in authorityContracts).toBe(true);
    const recommendation = createAgencyRecommendationRecordFixtureS36();
    expect(recommendation.action_scope_hash).toBe(hashAuthorityScopeV02(recommendation.action_scope as never));
    expect(AgencyRecommendationRecordV02.safeParse(recommendation).success).toBe(true);
  });

  it("rejects recommendation copy, independence, policy, condition, and hash drift", () => {
    const recommendation = createAgencyRecommendationRecordFixtureS36();
    expect(AgencyRecommendationRecordV02.safeParse({ ...recommendation, action_actor_ref: "actor_other" }).success).toBe(false);
    expect(AgencyRecommendationRecordV02.safeParse({ ...recommendation, evaluator_stable_identity_hash: recommendation.proposer_stable_identity_hash }).success).toBe(false);
    expect(AgencyRecommendationRecordV02.safeParse({ ...recommendation, reason_codes: [{ policy_digest: HASH, declaration_ref: "agency-allow" }] }).success).toBe(false);
    expect(AgencyRecommendationRecordV02.safeParse({ ...recommendation, decision: "allow_with_conditions", conditions: [] }).success).toBe(false);
    expect(AgencyRecommendationRecordV02.safeParse({ ...recommendation, recommendation_subject_hash: HASH }).success).toBe(false);
    expect(AgencyRecommendationRecordV02.safeParse({ ...recommendation, producer_attestation: { ...(recommendation.producer_attestation as Record<string, unknown>), statement_hash: HASH } }).success).toBe(false);
    expect(AgencyRecommendationRecordV02.safeParse({ ...recommendation, record_hash: HASH }).success).toBe(false);
  });

  it("rejects a recommendation that substitutes non-evidence dependency records", () => {
    const recommendation = createAgencyRecommendationRecordFixtureS36({ evidence_record_kind: "human-authorization" });
    expect(AgencyRecommendationRecordV02.safeParse(recommendation).success).toBe(false);
  });

  it("rejects root-envelope policy, scope, lineage, identity, and interval drift", () => {
    const envelope = validRootEnvelope();
    expect(AuthorityEnvelopeV02.safeParse({ ...envelope, policy_digest: `sha256:${"3".repeat(64)}` }).success).toBe(false);
    expect(AuthorityEnvelopeV02.safeParse({ ...envelope, action_scope_hash: `sha256:${"3".repeat(64)}` }).success).toBe(false);
    expect(AuthorityEnvelopeV02.safeParse({
      ...envelope,
      lineage: { ...(envelope.lineage as Record<string, unknown>), on_behalf_of_chain: [envelope.subject, envelope.issuer] },
    }).success).toBe(false);
    expect(AuthorityEnvelopeV02.safeParse({
      ...envelope,
      subject: envelope.issuer,
      lineage: {
        ...(envelope.lineage as Record<string, unknown>),
        on_behalf_of_chain: [envelope.issuer, envelope.issuer],
      },
    }).success).toBe(false);
    expect(AuthorityEnvelopeV02.safeParse({ ...envelope, expires_at: envelope.issued_at }).success).toBe(false);
  });

  it("admits a depth-zero root that retains one bounded delegation opportunity", () => {
    expect(AuthorityEnvelopeV02.safeParse(validDelegableRootEnvelope()).success).toBe(true);
  });

  it("admits one depth-one child with root chain plus child and no second delegation", () => {
    expect(AuthorityEnvelopeV02.safeParse(validDelegatedEnvelope()).success).toBe(true);
  });

  it("rejects substituted envelope subject and record hashes", () => {
    const envelope = validRootEnvelope();
    expect(AuthorityEnvelopeV02.safeParse({ ...envelope, authorization_subject_hash: HASH }).success).toBe(false);
    expect(AuthorityEnvelopeV02.safeParse({ ...envelope, record_hash: HASH }).success).toBe(false);
  });

  it("retains read compatibility for a fully self-consistent legacy S35 raw scope hash", () => {
    const envelope = validRootEnvelope();
    const legacyScopeHash = hashCanonical(envelope.authority_scope);
    expect(AuthorityEnvelopeV02.safeParse(finalizeEnvelope({
      ...envelope,
      action_scope_hash: legacyScopeHash,
    })).success).toBe(true);
  });

  it("rejects duplicate or out-of-order human proof references", () => {
    const envelope = validRootEnvelope();
    const first = { ledger_sequence: 1, event_hash: HASH };
    const second = { ledger_sequence: 2, event_hash: HASH };
    expect(AuthorityEnvelopeV02.safeParse(finalizeEnvelope({
      ...envelope, human_authorization_proof_refs: [first, first],
    })).success).toBe(false);
    expect(AuthorityEnvelopeV02.safeParse(finalizeEnvelope({
      ...envelope, human_authorization_proof_refs: [second, first],
    })).success).toBe(false);
  });

  it("admits the exact local Ed25519 human-authorization shape", () => {
    expect(HumanAuthorizationProofV02.safeParse(validProof()).success).toBe(true);
  });

  it("rejects substituted authorization statement and record hashes", () => {
    const proof = validProof();
    expect(HumanAuthorizationProofV02.safeParse({ ...proof, authorization_statement_hash: HASH }).success).toBe(false);
    expect(HumanAuthorizationProofV02.safeParse({ ...proof, record_hash: HASH }).success).toBe(false);
  });

  it("admits the exact platform-authenticated channel and algorithm pair", () => {
    expect(HumanAuthorizationProofV02.safeParse(finalizeProof({
      ...validProof(),
      approval_channel: "platform-authenticated",
      proof_algorithm: "platform-authenticated-v01",
    })).success).toBe(true);
  });

  it("rejects record fields outside the frozen V02 shape", () => {
    expect(HumanAuthorizationProofV02.safeParse({ ...validProof(), delegated: true }).success).toBe(false);
  });

  it("rejects an authentication channel and proof algorithm mismatch", () => {
    expect(HumanAuthorizationProofV02.safeParse({
      ...validProof(),
      approval_channel: "platform-authenticated",
    }).success).toBe(false);
  });

  it("rejects an empty authorization interval", () => {
    const proof = validProof();
    expect(HumanAuthorizationProofV02.safeParse({ ...proof, expires_at: proof.issued_at }).success).toBe(false);
  });

  it("rejects a revocation epoch outside the non-negative safe-integer domain", () => {
    expect(HumanAuthorizationProofV02.safeParse({
      ...validProof(),
      revocation_epoch: Number.MAX_SAFE_INTEGER + 1,
    }).success).toBe(false);
    expect(HumanAuthorizationProofV02.safeParse({ ...validProof(), revocation_epoch: -1 }).success).toBe(false);
  });

  it.each([
    ["proof value", { proof_value: "" }],
    ["machine ID", { operator_key_id: "not valid" }],
    ["timestamp", { issued_at: "2026-08-13" }],
    ["hash", { approval_nonce: "sha256:bad" }],
  ])("rejects an invalid %s scalar", (_label, replacement) => {
    expect(HumanAuthorizationProofV02.safeParse({ ...validProof(), ...replacement }).success).toBe(false);
  });
});
