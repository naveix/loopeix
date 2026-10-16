import type { ZodType } from "zod";
import { describe, expect, it } from "vitest";
import * as runtime from "../../src/schema/runtime.js";

type LeaseActionSchemas = {
  LeaseIssuedEventV02: ZodType;
  TaskActionAdmittedEventV02: ZodType;
};

const schemas = runtime as unknown as LeaseActionSchemas;
const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;

function ledgerRef(sequence: number): Record<string, unknown> {
  return { ledger_sequence: sequence, event_hash: HASH_A };
}

function envelope(eventType: string, payload: Record<string, unknown>): Record<string, unknown> {
  return {
    schema_version: "0.2",
    event_id: "event_lease_1",
    run_id: "run_main",
    sequence: 4,
    recorded_at: "2026-08-10T12:00:00Z",
    event_type: eventType,
    source: "policy-enforcement-point",
    authority_ref: "authority_pep",
    risk_tier: "T2",
    related_ids: [],
    previous_event_hash: HASH_A,
    event_hash: HASH_B,
    payload,
  };
}

const proposalBindings = {
  action_proposal_id: "proposal_1",
  action_proposal_hash: HASH_A,
  action_actor_ref: "actor_1",
  action_actor_stable_identity_hash: HASH_A,
  on_behalf_of_chain_hash: HASH_A,
  repository_root_ref: "repository_1",
  repository_base_ref_identity_hash: HASH_A,
  repository_pre_state_hash: HASH_A,
  authorized_change_set_hash: HASH_A,
  normalized_dispatch_hash: HASH_A,
  action_scope_hash: HASH_A,
  action_class: "task",
  classifier_input_hash: HASH_A,
  classifier_registry_hash: HASH_A,
  classifier_rule_hash: HASH_A,
  data_flow_hash: HASH_A,
} as const;

describe("S35 lease issuance and action admission events", () => {
  it("enforces the exact lease.issued policy and phase contract", () => {
    const payload = {
      lease_id: "lease_1",
      task_ref: "task-main",
      phase: "work",
      compensation_ref: null,
      ...proposalBindings,
      policy_action_kind: "planning",
      action_approval_class: "automatic",
      authority_envelope_ref: ledgerRef(1),
      policy_decision_ref: ledgerRef(2),
      fence_epoch: 3,
      issued_at: "2026-08-10T12:00:00Z",
      expires_at: "2026-08-10T12:05:00Z",
      waiver_gate_refs: ["gate-a", "gate-b"],
    };

    expect(schemas.LeaseIssuedEventV02.safeParse(envelope("lease.issued", payload)).success).toBe(true);
    expect(schemas.LeaseIssuedEventV02.safeParse(envelope("lease.issued", {
      ...payload,
      phase: "compensation",
      compensation_ref: null,
    })).success).toBe(false);
    expect(schemas.LeaseIssuedEventV02.safeParse(envelope("lease.issued", {
      ...payload,
      policy_action_kind: "network-read",
      action_approval_class: "automatic",
    })).success).toBe(false);
    expect(schemas.LeaseIssuedEventV02.safeParse(envelope("lease.issued", {
      ...payload,
      waiver_gate_refs: ["gate-b", "gate-a"],
    })).success).toBe(false);
    expect(schemas.LeaseIssuedEventV02.safeParse({
      ...envelope("lease.issued", payload),
      authority_ref: null,
    }).success).toBe(false);
  });

  it("enforces action admission counters, effects, and waiver use clocks", () => {
    const admissionClockRef = ledgerRef(3);
    const payload = {
      action_id: "action_1",
      task_ref: "task-main",
      lease_id: "lease_1",
      lease_event_ref: ledgerRef(2),
      admission_clock_ref: admissionClockRef,
      ...proposalBindings,
      policy_action_kind: "network-read",
      action_approval_class: "agency",
      execution_ordinal: 1,
      retry_of_failure_ordinal: null,
      fence_epoch: 3,
      side_effect_refs: ["effect-a"],
      waiver_gate_use_checks: [{
        gate_ref: "gate-a",
        required_event_ref: ledgerRef(1),
        result_event_ref: ledgerRef(1),
        waiver_event_ref: ledgerRef(2),
        authority_record_ref: ledgerRef(2),
        authority_revocation_epoch: 0,
        authority_envelope_revocation_epoch: 0,
        use_clock_ref: admissionClockRef,
      }],
      task_executions_after: 1,
      action_output_bytes_after: 0,
    };

    expect(schemas.TaskActionAdmittedEventV02.safeParse(envelope("task.action-admitted", payload)).success).toBe(true);
    expect(schemas.TaskActionAdmittedEventV02.safeParse(envelope("task.action-admitted", {
      ...payload,
      side_effect_refs: [],
    })).success).toBe(false);
    expect(schemas.TaskActionAdmittedEventV02.safeParse(envelope("task.action-admitted", {
      ...payload,
      task_executions_after: 0,
    })).success).toBe(false);
    expect(schemas.TaskActionAdmittedEventV02.safeParse(envelope("task.action-admitted", {
      ...payload,
      waiver_gate_use_checks: [{
        ...payload.waiver_gate_use_checks[0],
        use_clock_ref: ledgerRef(4),
      }],
    })).success).toBe(false);
  });
});
