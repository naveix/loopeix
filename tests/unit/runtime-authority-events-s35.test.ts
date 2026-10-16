import type { ZodType } from "zod";
import { describe, expect, it } from "vitest";
import * as runtime from "../../src/schema/runtime.js";

type AuthorityEventSchemas = {
  AuthorityHumanAuthorizationRecordedEventV02: ZodType;
  AuthorityEnvelopeRecordedEventV02: ZodType;
  AuthorityGrantRevokedEventV02: ZodType;
};

const schemas = runtime as unknown as AuthorityEventSchemas;
const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;

function ref(sequence: number, eventHash = HASH_A): Record<string, unknown> {
  return { ledger_sequence: sequence, event_hash: eventHash };
}

function envelope(eventType: string, source: string, payload: Record<string, unknown>, authorityRef: string | null): Record<string, unknown> {
  return {
    schema_version: "0.2", event_id: "event_authority_1", run_id: "run_main", sequence: 4,
    recorded_at: "2026-08-10T12:00:00Z", event_type: eventType, source, authority_ref: authorityRef,
    risk_tier: "T4", related_ids: [], previous_event_hash: HASH_A, event_hash: HASH_B, payload,
  };
}

describe("S35 authority root and revocation events", () => {
  it("binds a human authorization to its principal and proof channel", () => {
    const payload = {
      authorization_id: "authorization_1", record_path: "authority/authorization_1.json", record_hash: HASH_A,
      run_id: "run_main", plan_hash: HASH_A, authorization_subject_hash: HASH_A,
      authenticated_principal_ref: "principal_1", authentication_context_hash: HASH_A,
      action_scope_hash: HASH_A, approved_risk_tier: "T4", operator_key_id: "key_1",
      approval_channel: "local-ed25519", approval_nonce: HASH_A, proof_algorithm: "ed25519",
      authorization_statement_hash: HASH_A, issued_at: "2026-08-10T12:00:00Z",
      expires_at: "2026-08-10T12:05:00Z", revocation_epoch: 0,
    };
    expect(schemas.AuthorityHumanAuthorizationRecordedEventV02.safeParse(envelope(
      "authority.human-authorization-recorded", "operator", payload, "principal_1",
    )).success).toBe(true);
    expect(schemas.AuthorityHumanAuthorizationRecordedEventV02.safeParse(envelope(
      "authority.human-authorization-recorded", "operator", { ...payload, proof_algorithm: "platform-authenticated-v01" }, "principal_1",
    )).success).toBe(false);
    expect(schemas.AuthorityHumanAuthorizationRecordedEventV02.safeParse(envelope(
      "authority.human-authorization-recorded", "operator", payload, "principal_2",
    )).success).toBe(false);
  });

  it("requires non-self-issued, phase-independent authority envelope lineage", () => {
    const payload = {
      authority_envelope_id: "envelope_1", record_path: "authority/envelope_1.json", record_hash: HASH_A,
      run_id: "run_main", plan_hash: HASH_A, policy_digest: HASH_A, subject_ref: "agent_1",
      issuer_principal_ref: "principal_1", authorization_subject_hash: HASH_A,
      human_authorization_proof_refs: [ref(1)], action_class: "task", action_scope_hash: HASH_A,
      max_risk_tier: "T3a", issued_at: "2026-08-10T12:00:00Z", expires_at: "2026-08-10T12:05:00Z",
      revocation_epoch: 0, delegation_depth: 0,
    };
    expect(schemas.AuthorityEnvelopeRecordedEventV02.safeParse(envelope(
      "authority.envelope-recorded", "policy-enforcement-point", payload, "principal_1",
    )).success).toBe(true);
    expect(schemas.AuthorityEnvelopeRecordedEventV02.safeParse(envelope(
      "authority.envelope-recorded", "policy-enforcement-point", { ...payload, subject_ref: "principal_1" }, "principal_1",
    )).success).toBe(false);
    expect(schemas.AuthorityEnvelopeRecordedEventV02.safeParse(envelope(
      "authority.envelope-recorded", "policy-enforcement-point", { ...payload, expires_at: payload.issued_at }, "principal_1",
    )).success).toBe(false);
  });

  it("enforces checked immediate-prefix authority revocation", () => {
    const payload = {
      revocation_id: "revocation_1", record_path: "authority/revocation_1.json", record_hash: HASH_A,
      run_id: "run_main", plan_hash: HASH_A,
      target: {
        kind: "authority-envelope", target_ref: {
          record_kind: "authority-envelope", record_id: "envelope_1", record_event_ref: ref(1),
        }, target_scope_hash: HASH_A,
      },
      previous_revocation_epoch: 0, revocation_epoch: 1, effective_prefix_ref: ref(3),
      reason_code: "operator-revoked", evidence_refs: [{
        record_kind: "human-authorization", record_id: "authorization_1", record_event_ref: ref(1),
      }],
      revoker_kind: "operator", revoker_identity_ref: "principal_1", revoker_stable_identity_hash: HASH_A,
      revoker_authentication_context_hash: HASH_A, policy_digest: HASH_A, revoked_at: "2026-08-10T12:00:00Z",
      signer_key_ref: "key_1", statement_hash: HASH_A,
    };
    expect(schemas.AuthorityGrantRevokedEventV02.safeParse(envelope(
      "authority.grant-revoked", "operator", payload, "principal_1",
    )).success).toBe(true);
    expect(schemas.AuthorityGrantRevokedEventV02.safeParse(envelope(
      "authority.grant-revoked", "operator", { ...payload, revocation_epoch: 2 }, "principal_1",
    )).success).toBe(false);
    expect(schemas.AuthorityGrantRevokedEventV02.safeParse(envelope(
      "authority.grant-revoked", "policy-enforcement-point", payload, "principal_1",
    )).success).toBe(false);
    expect(schemas.AuthorityGrantRevokedEventV02.safeParse(envelope(
      "authority.grant-revoked", "operator", {
        ...payload,
        target: { ...payload.target, target_ref: { ...payload.target.target_ref, record_kind: "gate-waiver-authority" } },
      }, "principal_1",
    )).success).toBe(false);
  });
});
