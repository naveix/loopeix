import { describe, expect, it } from "vitest";
import { hashCanonical } from "../../src/hash.js";
import {
  parseAndValidateRuntimeLedgerStructureV02,
  parseAndValidateRuntimeLedgerV02,
  validateRuntimeLedgerV02,
} from "../../src/run/runtime-ledger-v02.js";

const HASH_A = `sha256:${"a".repeat(64)}`;

function seal<T extends Record<string, unknown>>(event: T): T & { event_hash: string } {
  return { ...event, event_hash: hashCanonical(event) };
}

function initialized() {
  return seal({
    schema_version: "0.2",
    event_id: "evt_init",
    run_id: "run_test",
    sequence: 1,
    recorded_at: "2026-08-10T12:00:00Z",
    event_type: "run.initialized",
    source: "kernel",
    authority_ref: null,
    risk_tier: "T1",
    payload: {
      plan_hash: HASH_A,
      initial_fence_epoch: 0,
      runtime_schema_versions: {
        resolved_run_plan: "0.2",
        ledger_event: "0.2",
        run_manifest: "0.2",
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
    related_ids: [],
    previous_event_hash: null,
  });
}

function terminalFreeze(first = initialized()) {
  return seal({
    schema_version: "0.2",
    event_id: "evt_freeze",
    run_id: "run_test",
    sequence: first.sequence + 1,
    recorded_at: "2026-08-10T12:00:01Z",
    event_type: "run.terminal-freeze-entered",
    source: "evaluator",
    authority_ref: null,
    risk_tier: "T1",
    payload: {
      revision: 1,
      candidate: "completed",
      candidate_evidence_refs: [{ ledger_sequence: first.sequence, event_hash: first.event_hash }],
      fence_epoch: 0,
    },
    related_ids: [],
    previous_event_hash: first.event_hash,
  });
}

function terminalSeal(first = initialized()) {
  return seal({
    schema_version: "0.2",
    event_id: "evt_seal",
    run_id: "run_test",
    sequence: first.sequence + 1,
    recorded_at: "2026-08-10T12:00:02Z",
    event_type: "run.terminal-sealed",
    source: "evaluator",
    authority_ref: null,
    risk_tier: "T1",
    payload: {
      outcome: "completed",
      pre_seal_ledger_sequence: first.sequence,
      pre_seal_ledger_head_hash: first.event_hash,
      pre_seal_snapshot_hash: HASH_A,
      previous_fence_epoch: 0,
      fence_epoch: 1,
    },
    related_ids: [],
    previous_event_hash: first.event_hash,
  });
}

function expectReason(result: ReturnType<typeof validateRuntimeLedgerV02>, reason: string): void {
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.reason).toBe(reason);
}

describe("S35 V02 primary-ledger validation", () => {
  it("separates structural ledger validation from later semantic history rules", () => {
    const first = initialized();
    const sealWithoutFreeze = terminalSeal(first);
    const events = [first, sealWithoutFreeze];
    const text = `${events.map((event) => JSON.stringify(event)).join("\n")}\n`;

    expect(parseAndValidateRuntimeLedgerStructureV02(text)).toEqual({
      ok: true,
      events,
    });
    expectReason(validateRuntimeLedgerV02(events), "LEDGER_HISTORY_INVALID");
    expectReason(parseAndValidateRuntimeLedgerV02(text), "LEDGER_HISTORY_INVALID");
  });

  it("keeps structural failures inside syntax, event-schema, and raw hash-chain validation", () => {
    const event = initialized();
    expect(parseAndValidateRuntimeLedgerStructureV02(JSON.stringify(event))).toMatchObject({
      ok: false,
      reason: "LEDGER_SYNTAX_INVALID",
    });
    expect(parseAndValidateRuntimeLedgerStructureV02(`${JSON.stringify({ ...event, extra: true })}\n`)).toMatchObject({
      ok: false,
      reason: "LEDGER_EVENT_SCHEMA_INVALID",
    });
    expect(parseAndValidateRuntimeLedgerStructureV02(`${JSON.stringify({ ...event, event_hash: HASH_A })}\n`)).toMatchObject({
      ok: false,
      reason: "LEDGER_HASH_CHAIN_INVALID",
    });
  });

  it("accepts a valid decoded history and strict newline-terminated JSONL", () => {
    const first = initialized();
    const freeze = terminalFreeze(first);
    const events = [first, freeze, terminalSeal(freeze)];
    const arrayResult = validateRuntimeLedgerV02(events);
    expect(arrayResult).toEqual({ ok: true, events, sealed: true });

    const text = `${events.map((event) => JSON.stringify(event)).join("\n")}\n`;
    expect(parseAndValidateRuntimeLedgerV02(text)).toEqual(arrayResult);
  });

  it("rejects an incomplete final line, blank line, invalid JSON, and duplicate keys", () => {
    const event = initialized();
    expectReason(parseAndValidateRuntimeLedgerV02(JSON.stringify(event)), "LEDGER_SYNTAX_INVALID");
    expectReason(parseAndValidateRuntimeLedgerV02(`${JSON.stringify(event)}\n\n`), "LEDGER_SYNTAX_INVALID");
    expectReason(parseAndValidateRuntimeLedgerV02("{]\n"), "LEDGER_SYNTAX_INVALID");
    const duplicate = JSON.stringify(event).replace('"event_id":"evt_init"', '"event_id":"evt_init","event_id":"evt_other"');
    expectReason(parseAndValidateRuntimeLedgerV02(`${duplicate}\n`), "LEDGER_SYNTAX_INVALID");
  });

  it("rejects schema failures before history interpretation", () => {
    const bad = { ...initialized(), extra: true };
    expectReason(validateRuntimeLedgerV02([bad]), "LEDGER_EVENT_SCHEMA_INVALID");
  });

  it("rejects sequence gaps, link breaks, self-hash mismatches, duplicate IDs, and mixed runs", () => {
    const first = initialized();
    const second = terminalSeal(first);
    expectReason(validateRuntimeLedgerV02([first, { ...second, sequence: 3 }]), "LEDGER_HASH_CHAIN_INVALID");
    expectReason(validateRuntimeLedgerV02([first, { ...second, previous_event_hash: HASH_A }]), "LEDGER_HASH_CHAIN_INVALID");
    expectReason(validateRuntimeLedgerV02([{ ...first, event_hash: HASH_A }]), "LEDGER_HASH_CHAIN_INVALID");
    expectReason(validateRuntimeLedgerV02([first, { ...second, event_id: first.event_id }]), "LEDGER_HISTORY_INVALID");
    expectReason(validateRuntimeLedgerV02([first, { ...second, run_id: "run_other" }]), "LEDGER_HISTORY_INVALID");
  });

  it("requires initialization first and makes the seal final with an exact adjacent prefix binding", () => {
    const first = initialized();
    const second = terminalSeal(first);
    expectReason(validateRuntimeLedgerV02([second]), "LEDGER_HISTORY_INVALID");
    const { event_hash: _sealHash, ...sealPreimage } = second;
    const wrongBinding = seal({ ...sealPreimage, payload: { ...second.payload, pre_seal_ledger_sequence: 99 } });
    expectReason(validateRuntimeLedgerV02([first, wrongBinding]), "LEDGER_HISTORY_INVALID");
    const laterSeal = seal({
      ...sealPreimage,
      event_id: "evt_later_seal",
      sequence: 3,
      previous_event_hash: second.event_hash,
      payload: { ...second.payload, pre_seal_ledger_sequence: 2, pre_seal_ledger_head_hash: second.event_hash },
    });
    expectReason(validateRuntimeLedgerV02([first, second, laterSeal]), "LEDGER_HISTORY_INVALID");
  });

  it("rejects unresolved, future, or hash-mismatched LedgerRefs", () => {
    const first = initialized();
    const required = seal({
      schema_version: "0.2", event_id: "evt_gate", run_id: "run_test", sequence: 2,
      recorded_at: "2026-08-10T12:00:01Z", event_type: "gate.result-required", source: "kernel",
      authority_ref: null, risk_tier: "T1", related_ids: [], previous_event_hash: first.event_hash,
      payload: { gate_ref: "gate-a", requirement_revision: 1, applicability: "always", compensation_ref: null,
        prerequisite_set_hash: HASH_A, prerequisite_refs: [{ ledger_sequence: 1, event_hash: HASH_A }] },
    });
    expectReason(validateRuntimeLedgerV02([first, required]), "LEDGER_HISTORY_INVALID");
  });

  it("rejects an existing event of the wrong canonical evidence producer/root class", () => {
    const first = initialized();
    const required = seal({
      schema_version: "0.2", event_id: "evt_gate", run_id: "run_test", sequence: 2,
      recorded_at: "2026-08-10T12:00:01Z", event_type: "gate.result-required", source: "kernel",
      authority_ref: null, risk_tier: "T1", related_ids: [], previous_event_hash: first.event_hash,
      payload: { gate_ref: "gate-a", requirement_revision: 1, applicability: "always", compensation_ref: null,
        prerequisite_set_hash: HASH_A, prerequisite_refs: [{ ledger_sequence: 1, event_hash: first.event_hash }] },
    });
    const evidence = seal({
      schema_version: "0.2", event_id: "evt_evidence", run_id: "run_test", sequence: 3,
      recorded_at: "2026-08-10T12:00:02Z", event_type: "evidence.recorded", source: "kernel",
      authority_ref: null, risk_tier: "T1", related_ids: [], previous_event_hash: required.event_hash,
      payload: {
        evidence_id: "evidence_1", requirement_refs: ["requirement-a"], evidence_kind: "command-capture",
        independence_roots: [{
          root_event_ref: { ledger_sequence: 2, event_hash: required.event_hash }, source_class: "command",
          authority_root_ref: { ledger_sequence: 1, event_hash: first.event_hash }, authenticated_principal_ref: null,
          acquisition_scope_hash: HASH_A, independence_key: HASH_A,
        }],
        record_path: "evidence/evidence_1.json", record_hash: HASH_A, content_path: null, content_hash: null,
        size_bytes: null, media_type: null, producer_event_ref: { ledger_sequence: 2, event_hash: required.event_hash },
      },
    });
    expectReason(validateRuntimeLedgerV02([first, required, evidence]), "LEDGER_HISTORY_INVALID");
  });

  it("rejects a typed record reference whose record ID does not match its target", () => {
    const first = initialized();
    const required = seal({
      schema_version: "0.2", event_id: "evt_gate", run_id: "run_test", sequence: 2,
      recorded_at: "2026-08-10T12:00:01Z", event_type: "gate.result-required", source: "kernel",
      authority_ref: null, risk_tier: "T1", related_ids: [], previous_event_hash: first.event_hash,
      payload: { gate_ref: "gate-a", requirement_revision: 1, applicability: "always", compensation_ref: null,
        prerequisite_set_hash: HASH_A, prerequisite_refs: [{ ledger_sequence: 1, event_hash: first.event_hash }] },
    });
    const result = seal({
      schema_version: "0.2", event_id: "evt_result", run_id: "run_test", sequence: 3,
      recorded_at: "2026-08-10T12:00:02Z", event_type: "gate.result-recorded", source: "evaluator",
      authority_ref: null, risk_tier: "T1", related_ids: [], previous_event_hash: required.event_hash,
      payload: { gate_ref: "gate-a", result_id: "result_1", status: "PASS", evaluator_identity_ref: "actor_1",
        policy_digest: HASH_A, record_path: "gates/result_1.json", record_hash: HASH_A,
        required_event_ref: { ledger_sequence: 2, event_hash: required.event_hash }, waiver_event_ref: null },
    });
    const badRef = { record_kind: "gate-result", record_id: "result_other", record_event_ref: { ledger_sequence: 3, event_hash: result.event_hash } };
    const claim = seal({
      schema_version: "0.2", event_id: "evt_claim", run_id: "run_test", sequence: 4,
      recorded_at: "2026-08-10T12:00:03Z", event_type: "claim.recorded", source: "kernel",
      authority_ref: null, risk_tier: "T1", related_ids: [], previous_event_hash: result.event_hash,
      payload: { claim_id: "claim_1", subject: { kind: "gate", subject_ref: "gate-a" }, evidence_policy_hash: HASH_A,
        verdict_record_refs: [badRef], status: "verified", record_path: "claims/claim_1.json", record_hash: HASH_A,
        dependency_record_refs: [badRef], observation_root_refs: [] },
    });
    expectReason(validateRuntimeLedgerV02([first, required, result, claim]), "LEDGER_HISTORY_INVALID");
  });
});
