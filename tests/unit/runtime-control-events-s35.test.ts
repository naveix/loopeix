import type { ZodType } from "zod";
import { describe, expect, it } from "vitest";
import * as runtime from "../../src/schema/runtime.js";

type ControlEventSchemas = {
  RunInitializedEventV02: ZodType;
  RunClockObservedEventV02: ZodType;
  RunFenceAdvancedEventV02: ZodType;
  ControlAbortRequestedEventV02: ZodType;
  GateResultRequiredEventV02: ZodType;
  GateResultRecordedEventV02: ZodType;
  EvaluationResultRequiredEventV02: ZodType;
  EvaluationResultRecordedEventV02: ZodType;
  EffectOutcomeEventV02: ZodType;
  RunTerminalFreezeEnteredEventV02: ZodType;
  RunTerminalFreezeRevisedEventV02: ZodType;
  RunCompensationRequestedEventV02: ZodType;
  RunCompensationRequestRevisedEventV02: ZodType;
  RunCompensationPhaseEnteredEventV02: ZodType;
  RunCompensationCandidateEscalatedEventV02: ZodType;
  CompensationSettledEventV02: ZodType;
  RunTerminalSealedEventV02: ZodType;
};

const schemas = runtime as unknown as ControlEventSchemas;
const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;
const HASH_C = `sha256:${"c".repeat(64)}`;

const RUNTIME_SCHEMA_VERSIONS = {
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
} as const;

function ledgerRef(sequence: number, eventHash = HASH_A): Record<string, unknown> {
  return { ledger_sequence: sequence, event_hash: eventHash };
}

function envelope(
  eventType: string,
  source: string,
  payload: Record<string, unknown>,
  authorityRef: string | null = null,
): Record<string, unknown> {
  return {
    schema_version: "0.2",
    event_id: "event_control_1",
    run_id: "run_main",
    sequence: 1,
    recorded_at: "2026-08-10T12:00:00Z",
    event_type: eventType,
    source,
    authority_ref: authorityRef,
    risk_tier: "T2",
    related_ids: [],
    previous_event_hash: null,
    event_hash: HASH_B,
    payload,
  };
}

describe("S35 run control events", () => {
  it("accepts the exact run.initialized contract", () => {
    const payload = {
      plan_hash: HASH_A,
      initial_fence_epoch: 0,
      runtime_schema_versions: RUNTIME_SCHEMA_VERSIONS,
    };

    const parsed = schemas.RunInitializedEventV02.safeParse(envelope("run.initialized", "kernel", payload));

    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(Object.keys((parsed.data as { payload: unknown }).payload as Record<string, unknown>).sort()).toEqual([
        "initial_fence_epoch",
        "plan_hash",
        "runtime_schema_versions",
      ]);
    }
  });

  it("rejects invalid run.initialized envelope and payload variants", () => {
    const payload = {
      plan_hash: HASH_A,
      initial_fence_epoch: 0,
      runtime_schema_versions: RUNTIME_SCHEMA_VERSIONS,
    };
    expect(schemas.RunInitializedEventV02.safeParse(envelope("run.initialized", "adapter", payload)).success).toBe(false);
    expect(schemas.RunInitializedEventV02.safeParse({
      ...envelope("run.initialized", "kernel", payload, "authority_kernel"),
      sequence: 2,
      previous_event_hash: HASH_C,
    }).success).toBe(false);
    expect(schemas.RunInitializedEventV02.safeParse(envelope("run.initialized", "kernel", {
      ...payload,
      extra: true,
    })).success).toBe(false);
  });

  it("accepts all four exact run.clock-observed structural branches", () => {
    const cases = [
      { reason: "action-admission", task_ref: "task-main", failure_ordinal: null, use_ref: "action_main" },
      { reason: "retry-check", task_ref: "task-main", failure_ordinal: 1, use_ref: null },
      { reason: "waiver-boundary", task_ref: null, failure_ordinal: null, use_ref: "waiver_main" },
      { reason: "terminal-use", task_ref: null, failure_ordinal: null, use_ref: "terminal_main" },
    ];
    for (const branch of cases) {
      expect(schemas.RunClockObservedEventV02.safeParse(envelope("run.clock-observed", "kernel", {
        clock_id: "clock_main",
        observed_at: "2026-08-10T12:00:00Z",
        elapsed_ms: 42,
        ...branch,
      })).success).toBe(true);
    }
  });

  it("rejects malformed run.clock-observed branches and envelope authority", () => {
    const payload = {
      clock_id: "clock_main",
      observed_at: "2026-08-10T12:00:00Z",
      elapsed_ms: 42,
      reason: "retry-check",
      task_ref: "task-main",
      failure_ordinal: null,
      use_ref: "action_main",
    };
    expect(schemas.RunClockObservedEventV02.safeParse(envelope("run.clock-observed", "kernel", payload)).success).toBe(false);
    expect(schemas.RunClockObservedEventV02.safeParse(envelope("run.clock-observed", "kernel", {
      ...payload,
      failure_ordinal: 1,
      use_ref: null,
    }, "authority_kernel")).success).toBe(false);
  });

  it("enforces run.fence-advanced source, authority, increment, and canonical evidence", () => {
    const payload = {
      previous_fence_epoch: 2,
      fence_epoch: 3,
      reason: "lease-revoked",
      evidence_refs: [ledgerRef(1, HASH_A), ledgerRef(1, HASH_B)],
    };
    expect(schemas.RunFenceAdvancedEventV02.safeParse(envelope(
      "run.fence-advanced",
      "policy-enforcement-point",
      payload,
      "authority_policy",
    )).success).toBe(true);
    expect(schemas.RunFenceAdvancedEventV02.safeParse(envelope(
      "run.fence-advanced",
      "policy-enforcement-point",
      { ...payload, fence_epoch: 4 },
      "authority_policy",
    )).success).toBe(false);
    expect(schemas.RunFenceAdvancedEventV02.safeParse(envelope(
      "run.fence-advanced",
      "policy-enforcement-point",
      { ...payload, evidence_refs: [ledgerRef(1, HASH_B), ledgerRef(1, HASH_A)] },
    )).success).toBe(false);
  });

  it("enforces control.abort-requested requester, source, authority, and agency lineage", () => {
    const operatorPayload = {
      request_id: "abort_request_1",
      requested_by: "operator",
      reason_code: "operator-requested",
      policy_decision_ref: null,
      evidence_refs: [ledgerRef(1, HASH_A)],
    };
    expect(schemas.ControlAbortRequestedEventV02.safeParse(envelope(
      "control.abort-requested",
      "operator",
      operatorPayload,
      "operator_main",
    )).success).toBe(true);
    const policyPayload = {
      ...operatorPayload,
      requested_by: "policy",
      reason_code: "agency-recommendation-abort",
      policy_decision_ref: ledgerRef(2, HASH_B),
    };
    expect(schemas.ControlAbortRequestedEventV02.safeParse(envelope(
      "control.abort-requested",
      "policy-enforcement-point",
      policyPayload,
      "authority_policy",
    )).success).toBe(true);
    expect(schemas.ControlAbortRequestedEventV02.safeParse(envelope(
      "control.abort-requested",
      "operator",
      policyPayload,
      "operator_main",
    )).success).toBe(false);
    expect(schemas.ControlAbortRequestedEventV02.safeParse(envelope(
      "control.abort-requested",
      "policy-enforcement-point",
      { ...policyPayload, policy_decision_ref: null },
      "authority_policy",
    )).success).toBe(false);
  });

  it("enforces gate.result-required applicability and canonical prerequisites", () => {
    const payload = {
      gate_ref: "gate-main",
      requirement_revision: 1,
      applicability: "always",
      compensation_ref: null,
      prerequisite_set_hash: HASH_A,
      prerequisite_refs: [ledgerRef(1, HASH_A), ledgerRef(2, HASH_B)],
    };
    expect(schemas.GateResultRequiredEventV02.safeParse(envelope("gate.result-required", "kernel", payload)).success).toBe(true);
    expect(schemas.GateResultRequiredEventV02.safeParse(envelope("gate.result-required", "kernel", {
      ...payload,
      applicability: "compensation",
      compensation_ref: "compensation-main",
    })).success).toBe(true);
    expect(schemas.GateResultRequiredEventV02.safeParse(envelope("gate.result-required", "kernel", {
      ...payload,
      compensation_ref: "compensation-main",
    })).success).toBe(false);
    expect(schemas.GateResultRequiredEventV02.safeParse(envelope("gate.result-required", "kernel", {
      ...payload,
      prerequisite_refs: [ledgerRef(2, HASH_B), ledgerRef(1, HASH_A)],
    })).success).toBe(false);
  });

  it("enforces gate.result-recorded evaluator source and waiver pairing", () => {
    const payload = {
      gate_ref: "gate-main",
      result_id: "gate_result_1",
      status: "PASS",
      evaluator_identity_ref: "evaluator_main",
      policy_digest: HASH_A,
      record_path: "records/gates/gate-main.json",
      record_hash: HASH_B,
      required_event_ref: ledgerRef(2, HASH_A),
      waiver_event_ref: null,
    };
    expect(schemas.GateResultRecordedEventV02.safeParse(envelope("gate.result-recorded", "evaluator", payload)).success).toBe(true);
    expect(schemas.GateResultRecordedEventV02.safeParse(envelope("gate.result-recorded", "evaluator", {
      ...payload,
      status: "WAIVED",
      waiver_event_ref: ledgerRef(3, HASH_B),
    })).success).toBe(true);
    expect(schemas.GateResultRecordedEventV02.safeParse(envelope("gate.result-recorded", "evaluator", {
      ...payload,
      status: "WAIVED",
    })).success).toBe(false);
    expect(schemas.GateResultRecordedEventV02.safeParse(envelope("gate.result-recorded", "adapter", payload)).success).toBe(false);
  });

  it("enforces evaluation.result-required applicability and exact revision", () => {
    const payload = {
      evaluation_ref: "evaluation-main",
      requirement_revision: 1,
      applicability: "compensation",
      compensation_ref: "compensation-main",
      prerequisite_set_hash: HASH_A,
      prerequisite_refs: [ledgerRef(1, HASH_A)],
    };
    expect(schemas.EvaluationResultRequiredEventV02.safeParse(envelope("evaluation.result-required", "kernel", payload)).success).toBe(true);
    expect(schemas.EvaluationResultRequiredEventV02.safeParse(envelope("evaluation.result-required", "kernel", {
      ...payload,
      requirement_revision: 2,
    })).success).toBe(false);
    expect(schemas.EvaluationResultRequiredEventV02.safeParse(envelope("evaluation.result-required", "kernel", {
      ...payload,
      applicability: "always",
    })).success).toBe(false);
  });

  it("accepts exact evaluation.result-recorded branches and rejects bad authority/source", () => {
    const payload = {
      evaluation_ref: "evaluation-main",
      result_id: "evaluation_result_1",
      status: "HOLD",
      evaluator_identity_ref: "evaluator_main",
      policy_digest: HASH_A,
      export_check_role: "credential-scan",
      record_path: "records/evaluations/evaluation-main.json",
      record_hash: HASH_B,
      required_event_ref: ledgerRef(2, HASH_A),
    };
    expect(schemas.EvaluationResultRecordedEventV02.safeParse(envelope("evaluation.result-recorded", "evaluator", payload)).success).toBe(true);
    expect(schemas.EvaluationResultRecordedEventV02.safeParse(envelope("evaluation.result-recorded", "evaluator", {
      ...payload,
      status: "SKIPPED",
      export_check_role: null,
    })).success).toBe(true);
    expect(schemas.EvaluationResultRecordedEventV02.safeParse(envelope(
      "evaluation.result-recorded",
      "evaluator",
      payload,
      "evaluator_main",
    )).success).toBe(false);
  });

  it("enforces effect.outcome provenance and canonical evidence", () => {
    const payload = {
      task_ref: "task-main",
      effect_ref: "effect-main",
      action_id: "action_main",
      outcome: "committed",
      evidence_refs: [ledgerRef(1, HASH_A), ledgerRef(1, HASH_B)],
    };
    expect(schemas.EffectOutcomeEventV02.safeParse(envelope("effect.outcome", "adapter", payload)).success).toBe(true);
    expect(schemas.EffectOutcomeEventV02.safeParse(envelope("effect.outcome", "adapter", {
      ...payload,
      outcome: "not-committed",
    })).success).toBe(true);
    expect(schemas.EffectOutcomeEventV02.safeParse(envelope("effect.outcome", "integrity", {
      ...payload,
      outcome: "unknown",
    })).success).toBe(true);
    expect(schemas.EffectOutcomeEventV02.safeParse(envelope("effect.outcome", "adapter", {
      ...payload,
      outcome: "unknown",
    })).success).toBe(false);
    expect(schemas.EffectOutcomeEventV02.safeParse(envelope("effect.outcome", "integrity", {
      ...payload,
      evidence_refs: [ledgerRef(1, HASH_B), ledgerRef(1, HASH_A)],
    })).success).toBe(false);
  });

  it("enforces terminal freeze entry and strict upward revision", () => {
    const entered = {
      revision: 1,
      candidate: "stalled",
      candidate_evidence_refs: [ledgerRef(7, HASH_A)],
      fence_epoch: 2,
    };
    expect(schemas.RunTerminalFreezeEnteredEventV02.safeParse(envelope(
      "run.terminal-freeze-entered",
      "evaluator",
      entered,
    )).success).toBe(true);
    expect(schemas.RunTerminalFreezeEnteredEventV02.safeParse(envelope(
      "run.terminal-freeze-entered",
      "kernel",
      entered,
    )).success).toBe(false);
    expect(schemas.RunTerminalFreezeRevisedEventV02.safeParse(envelope(
      "run.terminal-freeze-revised",
      "evaluator",
      {
        revision: 2,
        previous_candidate: "stalled",
        candidate: "failed",
        previous_freeze_event_hash: HASH_A,
        candidate_evidence_refs: [ledgerRef(8, HASH_B)],
      },
    )).success).toBe(true);
    expect(schemas.RunTerminalFreezeRevisedEventV02.safeParse(envelope(
      "run.terminal-freeze-revised",
      "evaluator",
      {
        revision: 2,
        previous_candidate: "failed",
        candidate: "stalled",
        previous_freeze_event_hash: HASH_A,
        candidate_evidence_refs: [ledgerRef(8, HASH_B)],
      },
    )).success).toBe(false);
  });

  it("enforces compensation request activation mapping and non-empty canonical refs", () => {
    const requested = {
      revision: 1,
      pending_terminal: "failed",
      activation_reason: "terminal-failure",
      compensation_refs: ["compensation-a", "compensation-b"],
      effect_evidence_refs: [ledgerRef(9, HASH_A)],
      freeze_event_hash: HASH_B,
    };
    expect(schemas.RunCompensationRequestedEventV02.safeParse(envelope(
      "run.compensation-requested",
      "evaluator",
      requested,
    )).success).toBe(true);
    expect(schemas.RunCompensationRequestedEventV02.safeParse(envelope(
      "run.compensation-requested",
      "evaluator",
      { ...requested, activation_reason: "terminal-stall" },
    )).success).toBe(false);
    expect(schemas.RunCompensationRequestedEventV02.safeParse(envelope(
      "run.compensation-requested",
      "evaluator",
      { ...requested, compensation_refs: [] },
    )).success).toBe(false);
  });

  it("enforces compensation request revisions without downgrade or no-op", () => {
    const revised = {
      revision: 2,
      previous_pending_terminal: "stalled",
      pending_terminal: "exhausted",
      activation_reason: "terminal-exhaustion",
      compensation_refs: ["compensation-a", "compensation-b"],
      added_compensation_refs: [],
      previous_request_event_hash: HASH_A,
      freeze_event_hash: HASH_B,
      effect_evidence_refs: [ledgerRef(10, HASH_A)],
    };
    expect(schemas.RunCompensationRequestRevisedEventV02.safeParse(envelope(
      "run.compensation-request-revised",
      "evaluator",
      revised,
    )).success).toBe(true);
    expect(schemas.RunCompensationRequestRevisedEventV02.safeParse(envelope(
      "run.compensation-request-revised",
      "evaluator",
      { ...revised, previous_pending_terminal: "failed" },
    )).success).toBe(false);
    expect(schemas.RunCompensationRequestRevisedEventV02.safeParse(envelope(
      "run.compensation-request-revised",
      "evaluator",
      {
        ...revised,
        pending_terminal: "stalled",
        activation_reason: "terminal-stall",
      },
    )).success).toBe(false);
    expect(schemas.RunCompensationRequestRevisedEventV02.safeParse(envelope(
      "run.compensation-request-revised",
      "evaluator",
      { ...revised, added_compensation_refs: ["compensation-c"] },
    )).success).toBe(false);
  });

  it("accepts exact compensation entry and all six strict escalation pairs", () => {
    expect(schemas.RunCompensationPhaseEnteredEventV02.safeParse(envelope(
      "run.compensation-phase-entered",
      "evaluator",
      {
        request_revision: 2,
        request_event_hash: HASH_A,
        pending_terminal: "failed",
        compensation_refs: ["compensation-a"],
        freeze_event_hash: HASH_B,
      },
    )).success).toBe(true);
    const pairs = [
      ["stalled", "exhausted", "terminal-exhaustion"],
      ["stalled", "failed", "terminal-failure"],
      ["stalled", "aborted", "abort-recovery"],
      ["exhausted", "failed", "terminal-failure"],
      ["exhausted", "aborted", "abort-recovery"],
      ["failed", "aborted", "abort-recovery"],
    ] as const;
    for (const [previous, pending, reason] of pairs) {
      expect(schemas.RunCompensationCandidateEscalatedEventV02.safeParse(envelope(
        "run.compensation-candidate-escalated",
        "evaluator",
        {
          previous_pending_terminal: previous,
          pending_terminal: pending,
          activation_reason: reason,
          compensation_refs: ["compensation-a"],
          previous_candidate_event_hash: HASH_A,
          candidate_evidence_refs: [ledgerRef(11, HASH_B)],
        },
      )).success).toBe(true);
    }
    expect(schemas.RunCompensationCandidateEscalatedEventV02.safeParse(envelope(
      "run.compensation-candidate-escalated",
      "evaluator",
      {
        previous_pending_terminal: "failed",
        pending_terminal: "exhausted",
        activation_reason: "terminal-exhaustion",
        compensation_refs: ["compensation-a"],
        previous_candidate_event_hash: HASH_A,
        candidate_evidence_refs: [ledgerRef(11, HASH_B)],
      },
    )).success).toBe(false);
  });

  it("enforces compensation settlement evidence and unable-reason branches", () => {
    const base = {
      compensation_ref: "compensation-a",
      status: "compensated",
      unable_reason: null,
      evidence_refs: [ledgerRef(12, HASH_A)],
    };
    expect(schemas.CompensationSettledEventV02.safeParse(envelope("compensation.settled", "evaluator", base)).success).toBe(true);
    expect(schemas.CompensationSettledEventV02.safeParse(envelope("compensation.settled", "evaluator", {
      ...base,
      status: "unable",
      unable_reason: "safety-hold",
    })).success).toBe(true);
    expect(schemas.CompensationSettledEventV02.safeParse(envelope("compensation.settled", "evaluator", {
      ...base,
      status: "unable",
    })).success).toBe(false);
    expect(schemas.CompensationSettledEventV02.safeParse(envelope("compensation.settled", "evaluator", {
      ...base,
      evidence_refs: [],
    })).success).toBe(false);
  });

  it("enforces terminal seal prefix and checked fence increment", () => {
    const sealed = {
      outcome: "failed",
      pre_seal_ledger_sequence: 15,
      pre_seal_ledger_head_hash: HASH_A,
      pre_seal_snapshot_hash: HASH_B,
      previous_fence_epoch: 3,
      fence_epoch: 4,
    };
    expect(schemas.RunTerminalSealedEventV02.safeParse(envelope("run.terminal-sealed", "evaluator", sealed)).success).toBe(true);
    expect(schemas.RunTerminalSealedEventV02.safeParse(envelope("run.terminal-sealed", "evaluator", {
      ...sealed,
      fence_epoch: 5,
    })).success).toBe(false);
    expect(schemas.RunTerminalSealedEventV02.safeParse(envelope(
      "run.terminal-sealed",
      "evaluator",
      sealed,
      "authority_evaluator",
    )).success).toBe(false);
  });
});
