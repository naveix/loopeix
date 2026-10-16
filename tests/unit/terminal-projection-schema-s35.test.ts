import { describe, expect, expectTypeOf, it } from "vitest";

import {
  TerminalEvaluationResultV02,
  TerminalSnapshotInvalidReasonsV02,
  type TerminalEvaluationResultV02Value,
  type TerminalObservationHashProjectionV02,
  type TerminalObservationSnapshotV02,
  type TerminalSnapshotInvalidReasonV02,
} from "../../src/schema/runtime.js";

const HASH = `sha256:${"a".repeat(64)}`;
const REF = { ledger_sequence: 1, event_hash: HASH };

describe("S35 terminal projection schema foundation", () => {
  it("freezes the exact ordered 17-member invalid-snapshot reason domain", () => {
    expect(TerminalSnapshotInvalidReasonsV02).toEqual([
      "PLAN_OR_LEDGER_LINEAGE_INVALID",
      "SNAPSHOT_COVERAGE_OR_ORDER_INVALID",
      "APPLICABILITY_OR_DUE_INVALID",
      "LIMIT_OBSERVATION_INVALID",
      "TASK_EFFECT_OR_FAILURE_INVALID",
      "ACTION_ADMISSION_OR_QUIESCENCE_INVALID",
      "TERMINAL_FREEZE_INVALID",
      "ACTIVATION_INVALID",
      "COMPENSATION_REQUEST_INVALID",
      "CANDIDATE_ESCALATION_INVALID",
      "PHASE_OR_PENDING_TERMINAL_INVALID",
      "COMPENSATION_REF_SET_INVALID",
      "COMPENSATION_SETTLEMENT_INVALID",
      "ACTIVE_WORKERS_AT_PHASE_ENTRY",
      "CONTROL_PLANE_BUDGET_INVALID",
      "TERMINAL_SEAL_OR_FENCE_INVALID",
      "POST_SEAL_ACTION",
    ]);
    expectTypeOf<TerminalSnapshotInvalidReasonV02>().toEqualTypeOf<
      (typeof TerminalSnapshotInvalidReasonsV02)[number]
    >();
  });

  it("uses the terminal snapshot reason domain for public progress failures", () => {
    expect(TerminalSnapshotInvalidReasonsV02).not.toContain("PROGRESS_SAMPLE_VALUE_INVALID");
    expect(TerminalSnapshotInvalidReasonsV02).not.toContain("PROGRESS_EVENT_RUN_ID_MISMATCH");
  });

  it("accepts every exact evaluator decision branch", () => {
    const branches: TerminalEvaluationResultV02Value[] = [
      { decision: "continue", continuation: "work-open" },
      { decision: "freeze-work", candidate: "failed", freeze_revision: 1, candidate_evidence_refs: [REF], fence_epoch: 0 },
      { decision: "revise-terminal-freeze", previous_candidate: "held", candidate: "failed", freeze_revision: 2, previous_freeze_event_hash: HASH, candidate_evidence_refs: [REF] },
      { decision: "request-compensation", request_revision: 1, pending_terminal: "failed", activation_reason: "terminal-failure", compensation_refs: ["restore"], effect_evidence_refs: [REF], freeze_event_hash: HASH },
      { decision: "revise-compensation-request", request_revision: 2, previous_pending_terminal: "failed", pending_terminal: "aborted", activation_reason: "abort-recovery", compensation_refs: ["restore"], added_compensation_refs: [], previous_request_event_hash: HASH, effect_evidence_refs: [REF], freeze_event_hash: HASH },
      { decision: "enter-compensation", request_revision: 2, request_event_hash: HASH, pending_terminal: "failed", compensation_refs: ["restore"], freeze_event_hash: HASH },
      { decision: "escalate-compensation", previous_pending_terminal: "stalled", pending_terminal: "exhausted", activation_reason: "terminal-exhaustion", compensation_refs: ["restore"], previous_candidate_event_hash: HASH, candidate_evidence_refs: [REF] },
      { decision: "settle-compensation", settlement: { ref: "restore", status: "compensated", unable_reason: null, evidence_refs: [REF] } },
      { decision: "seal", outcome: "completed", expected_ledger_sequence: 4, expected_ledger_head_hash: HASH, pre_seal_snapshot_hash: HASH, current_fence_epoch: 0, next_fence_epoch: 1 },
      { decision: "already-sealed", outcome: "completed", seal_sequence: 5, fence_epoch: 1, pre_seal_snapshot_hash: HASH, seal_event_hash: HASH },
    ];

    expect(branches.map((branch) => TerminalEvaluationResultV02.parse(branch).decision)).toEqual([
      "continue",
      "freeze-work",
      "revise-terminal-freeze",
      "request-compensation",
      "revise-compensation-request",
      "enter-compensation",
      "escalate-compensation",
      "settle-compensation",
      "seal",
      "already-sealed",
    ]);
  });

  it("rejects unknown evaluator fields and empty required evidence", () => {
    expect(TerminalEvaluationResultV02.safeParse({ decision: "continue", continuation: "work-open", extra: true }).success).toBe(false);
    expect(TerminalEvaluationResultV02.safeParse({
      decision: "freeze-work",
      candidate: "failed",
      freeze_revision: 1,
      candidate_evidence_refs: [],
      fence_epoch: 0,
    }).success).toBe(false);
  });

  it("exposes the exact private snapshot field domains without a minting schema", () => {
    expectTypeOf<TerminalObservationSnapshotV02["schema_version"]>().toEqualTypeOf<"0.2">();
    expectTypeOf<TerminalObservationSnapshotV02["phase"]>().toEqualTypeOf<"work" | "compensation">();
    expectTypeOf<TerminalObservationSnapshotV02["pending_terminal"]>().toEqualTypeOf<
      "aborted" | "failed" | "exhausted" | "stalled" | null
    >();
    expectTypeOf<TerminalObservationSnapshotV02["gates"][number]["status"]>().toEqualTypeOf<
      "pass" | "hold" | "fail" | "waived-valid" | "waived-invalid" | "missing"
    >();
    expectTypeOf<TerminalObservationSnapshotV02["active_failures"][number]["retry_disposition"]>().toEqualTypeOf<
      "waiting" | "ready" | "ineligible"
    >();
    expectTypeOf<TerminalObservationSnapshotV02["terminal_seal"]>().not.toBeAny();
    expectTypeOf<TerminalObservationHashProjectionV02["purpose"]>().toEqualTypeOf<
      "pre-seal-terminal-observation-snapshot-v02"
    >();
    expectTypeOf<TerminalObservationHashProjectionV02["terminal_seal"]>().toEqualTypeOf<null>();
  });
});
