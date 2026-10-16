import { describe, expect, it } from "vitest";

import * as authorityContracts from "../../src/run/runtime-record-admission-v02.js";
import { AuthorityRevocationRecordV02 } from "../../src/run/runtime-record-admission-v02.js";
import { hashCanonical } from "../../src/hash.js";

const HASH = `sha256:${"1".repeat(64)}`;
const OTHER_HASH = `sha256:${"2".repeat(64)}`;
const THIRD_HASH = `sha256:${"3".repeat(64)}`;
const SIGNATURE = "c2lnbmF0dXJl";

function ledgerRef(sequence: number, eventHash = HASH): Record<string, unknown> {
  return { ledger_sequence: sequence, event_hash: eventHash };
}

function finalizeRevocation(record: Record<string, unknown>): Record<string, unknown> {
  const producerAttestation = record.producer_attestation as Record<string, unknown>;
  const recordWithoutHash = { ...record };
  delete recordWithoutHash.record_hash;
  const { statement_hash: _statementHash, signature_value, ...attestationWithoutStatementHash } = producerAttestation;
  void signature_value;
  const statementHash = hashCanonical({
    ...recordWithoutHash,
    producer_attestation: attestationWithoutStatementHash,
  });
  const withStatementHash = {
    ...recordWithoutHash,
    producer_attestation: {
      ...producerAttestation,
      statement_hash: statementHash,
    },
  };
  return {
    ...withStatementHash,
    record_hash: hashCanonical(withStatementHash),
  };
}

function validRevocation(): Record<string, unknown> {
  return finalizeRevocation({
    schema_version: "0.2",
    revocation_id: "revocation_main",
    run_id: "run_main",
    plan_hash: HASH,
    target: {
      kind: "authority-envelope",
      target_ref: {
        record_kind: "authority-envelope",
        record_id: "envelope_main",
        record_event_ref: ledgerRef(2),
      },
      target_scope_hash: OTHER_HASH,
    },
    previous_revocation_epoch: 0,
    revocation_epoch: 1,
    effective_prefix_ref: ledgerRef(4, OTHER_HASH),
    reason_code: "operator-revoked",
    evidence_refs: [
      {
        record_kind: "evidence",
        record_id: "evidence_main",
        record_event_ref: ledgerRef(4, OTHER_HASH),
      },
    ],
    revoker_kind: "operator",
    revoker_identity_ref: "principal_main",
    revoker_stable_identity_hash: HASH,
    revoker_authentication_context_hash: OTHER_HASH,
    policy_digest: THIRD_HASH,
    revoked_at: "2026-08-13T12:00:00Z",
    producer_attestation: {
      signer_key_ref: "key_main",
      signature_algorithm: "ed25519",
      statement_hash: HASH,
      signature_value: SIGNATURE,
    },
    record_hash: HASH,
  });
}

describe("S36 frozen authority revocation contract", () => {
  it("exports and admits the exact revocation record shape", () => {
    expect("AuthorityRevocationRecordV02" in authorityContracts).toBe(true);
    expect(AuthorityRevocationRecordV02.safeParse(validRevocation()).success).toBe(true);
  });

  it("admits the gate-waiver-authority target variant", () => {
    const record = validRevocation();
    expect(AuthorityRevocationRecordV02.safeParse(finalizeRevocation({
      ...record,
      target: {
        kind: "gate-waiver-authority",
        target_ref: {
          record_kind: "gate-waiver-authority",
          record_id: "authority_main",
          record_event_ref: ledgerRef(3),
        },
        target_scope_hash: HASH,
      },
    })).success).toBe(true);
  });

  it("rejects fields outside the frozen V02 shape", () => {
    expect(AuthorityRevocationRecordV02.safeParse({ ...validRevocation(), delegated: true }).success).toBe(false);
  });

  it("rejects target discriminant, revoker-kind, and scalar drift", () => {
    const record = validRevocation();
    expect(AuthorityRevocationRecordV02.safeParse(finalizeRevocation({
      ...record,
      target: {
        kind: "authority-envelope",
        target_ref: {
          record_kind: "gate-waiver-authority",
          record_id: "envelope_main",
          record_event_ref: ledgerRef(2),
        },
        target_scope_hash: OTHER_HASH,
      },
    })).success).toBe(false);
    expect(AuthorityRevocationRecordV02.safeParse(finalizeRevocation({
      ...record,
      reason_code: "policy-changed",
      revoker_kind: "operator",
    })).success).toBe(false);
    expect(AuthorityRevocationRecordV02.safeParse({ ...record, revoked_at: "2026-08-13" }).success).toBe(false);
  });

  it("rejects empty or non-canonical evidence refs", () => {
    const record = validRevocation();
    expect(AuthorityRevocationRecordV02.safeParse(finalizeRevocation({
      ...record,
      evidence_refs: [],
    })).success).toBe(false);
    expect(AuthorityRevocationRecordV02.safeParse(finalizeRevocation({
      ...record,
      evidence_refs: [
        { record_kind: "evidence", record_id: "evidence_b", record_event_ref: ledgerRef(1) },
        { record_kind: "evidence", record_id: "evidence_a", record_event_ref: ledgerRef(1) },
      ],
    })).success).toBe(false);
    expect(AuthorityRevocationRecordV02.safeParse(finalizeRevocation({
      ...record,
      evidence_refs: [
        { record_kind: "evidence", record_id: "evidence_a", record_event_ref: ledgerRef(1) },
        { record_kind: "evidence", record_id: "evidence_a", record_event_ref: ledgerRef(1) },
      ],
    })).success).toBe(false);
  });

  it("rejects evidence after the effective prefix or self-referential evidence", () => {
    const record = validRevocation();
    expect(AuthorityRevocationRecordV02.safeParse(finalizeRevocation({
      ...record,
      evidence_refs: [
        { record_kind: "evidence", record_id: "evidence_main", record_event_ref: ledgerRef(5) },
      ],
    })).success).toBe(false);
    expect(AuthorityRevocationRecordV02.safeParse(finalizeRevocation({
      ...record,
      evidence_refs: [
        { record_kind: "authority-revocation", record_id: "revocation_main", record_event_ref: ledgerRef(1) },
      ],
    })).success).toBe(false);
  });

  it("rejects revocation epochs outside the checked increment-by-one domain", () => {
    const record = validRevocation();
    expect(AuthorityRevocationRecordV02.safeParse(finalizeRevocation({
      ...record,
      previous_revocation_epoch: Number.MAX_SAFE_INTEGER,
      revocation_epoch: Number.MAX_SAFE_INTEGER + 1,
    })).success).toBe(false);
    expect(AuthorityRevocationRecordV02.safeParse(finalizeRevocation({
      ...record,
      revocation_epoch: 2,
    })).success).toBe(false);
    expect(AuthorityRevocationRecordV02.safeParse(finalizeRevocation({
      ...record,
      previous_revocation_epoch: -1,
      revocation_epoch: 0,
    })).success).toBe(false);
  });

  it("rejects substituted attestation statement and record hashes", () => {
    const record = validRevocation();
    expect(AuthorityRevocationRecordV02.safeParse({
      ...record,
      producer_attestation: {
        ...(record.producer_attestation as Record<string, unknown>),
        statement_hash: HASH,
      },
    }).success).toBe(false);
    expect(AuthorityRevocationRecordV02.safeParse({ ...record, record_hash: HASH }).success).toBe(false);
  });
});
