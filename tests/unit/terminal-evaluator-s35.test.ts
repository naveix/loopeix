import { describe, expect, it } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import {
  evaluateTerminalDecisionTableV02,
  evaluateTerminalV02,
} from "../../src/run/terminal-evaluator.js";
import type {
  TerminalObservationSnapshotV02,
  ValidatedRuntimeProjectionInputV02,
} from "../../src/schema/runtime.js";
import {
  buildTerminalObservationSnapshotV02,
  validateRuntimeProjectionInputV02,
} from "../../src/run/terminal-snapshot.js";
import { buildInitializedRuntimePositiveFixtureS35 } from "../helpers/runtime-positive-fixture-s35.js";

const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;
const HASH_C = `sha256:${"c".repeat(64)}`;
const HASH_D = `sha256:${"d".repeat(64)}`;

const REF_A = { ledger_sequence: 1, event_hash: HASH_A };
const REF_B = { ledger_sequence: 2, event_hash: HASH_B };
const REF_C = { ledger_sequence: 3, event_hash: HASH_C };
const REF_D = { ledger_sequence: 4, event_hash: HASH_D };

function projectionFixture(
  options: Readonly<{
    progressTargets?: ReadonlyArray<Readonly<{ id: string; target: number | null }>>;
    compensations?: ReadonlyArray<Readonly<{
      id: string;
      for_task: string;
      for_effect: string;
    }>>;
  }> = {},
): ValidatedRuntimeProjectionInputV02 {
  return {
    plan: {
      progress: {
        observations: [...(options.progressTargets ?? [])],
      },
      compensations: [...(options.compensations ?? [])],
    },
  } as unknown as ValidatedRuntimeProjectionInputV02;
}

function snapshotFixture(
  overrides: Partial<TerminalObservationSnapshotV02> = {},
): TerminalObservationSnapshotV02 {
  return {
    schema_version: "0.2",
    run_id: "run_terminal",
    plan_hash: HASH_A,
    ledger_sequence: 4,
    ledger_head_hash: HASH_B,
    current_fence_epoch: 0,
    phase: "work",
    pending_terminal: null,
    pending_terminal_event_ref: null,
    terminal_freeze: null,
    compensation_request: null,
    terminal_seal: null,
    control_plane_output: {
      consumed_bytes: 32,
      reserved_bytes: 128,
      required_remaining_bytes: 96,
    },
    gates: [],
    evaluations: [],
    progress: [],
    limits: [],
    tasks: [],
    effects: [],
    compensations: [],
    active_failures: [],
    policy_blocks: [],
    abort_requested: false,
    abort_event_ref: null,
    in_flight_actions: [],
    active_workers: 0,
    ...overrides,
  } as TerminalObservationSnapshotV02;
}

describe("S35 package-private terminal evaluator boundary", () => {
  it("continues work only for a builder-issued initialized snapshot", async () => {
    const fixture = await buildInitializedRuntimePositiveFixtureS35();
    try {
      const validated = validateRuntimeProjectionInputV02(fixture.input);
      expect(validated).toMatchObject({ ok: true });
      if (!validated.ok) return;
      const snapshot = buildTerminalObservationSnapshotV02(validated.value);
      expect(snapshot).toMatchObject({ ok: true });
      if (!snapshot.ok) return;
      expect(evaluateTerminalV02(snapshot.value)).toEqual({
        decision: "continue",
        continuation: "work-open",
      });
    } finally {
      fixture.dispose();
    }
  });

  it("suppresses only the waiting blocked pair and still honors a higher terminal candidate", () => {
    const blockedWaiting = snapshotFixture({
      tasks: [{
        ref: "task-main",
        status: "blocked",
        terminal_event_ref: null,
        condition_evidence_refs: [REF_A],
      }],
      active_failures: [{
        task_ref: "task-main",
        failure_class: "transient-network",
        task_execution_count: 1,
        failure_ordinal: 1,
        retry_disposition: "waiting",
        failure_event_ref: REF_B,
        failure_clock_ref: REF_C,
        retry_clock_ref: null,
      }],
    });
    const projection = projectionFixture();

    expect(evaluateTerminalDecisionTableV02(blockedWaiting, projection)).toEqual({
      decision: "continue",
      continuation: "work-open",
    });

    expect(evaluateTerminalDecisionTableV02(snapshotFixture({
      ...blockedWaiting,
      abort_requested: true,
      abort_event_ref: REF_D,
    }), projection)).toEqual({
      decision: "freeze-work",
      candidate: "aborted",
      freeze_revision: 1,
      candidate_evidence_refs: [REF_D],
      fence_epoch: 0,
    });
  });

  it("treats policy-hold execution failures as held, not failed", () => {
    const projection = projectionFixture();
    expect(evaluateTerminalDecisionTableV02(snapshotFixture({
      active_failures: [{
        task_ref: "task-main",
        failure_class: "policy-hold",
        task_execution_count: 1,
        failure_ordinal: 1,
        retry_disposition: "ineligible",
        failure_event_ref: REF_A,
        failure_clock_ref: REF_B,
        retry_clock_ref: null,
      }],
      tasks: [{
        ref: "task-main",
        status: "blocked",
        terminal_event_ref: REF_A,
        condition_evidence_refs: [REF_A],
      }],
    }), projection)).toEqual({
      decision: "freeze-work",
      candidate: "held",
      freeze_revision: 1,
      candidate_evidence_refs: [REF_A],
      fence_epoch: 0,
    });
  });

  it("revises terminal freeze only for a strict upward candidate", () => {
    const projection = projectionFixture();
    const snapshot = snapshotFixture({
      terminal_freeze: {
        revision: 1,
        candidate: "held",
        ledger_sequence: 2,
        event_hash: HASH_C,
      },
      tasks: [{
        ref: "task-main",
        status: "failed",
        terminal_event_ref: REF_A,
        condition_evidence_refs: [REF_A],
      }],
    });

    expect(evaluateTerminalDecisionTableV02(snapshot, projection)).toEqual({
      decision: "revise-terminal-freeze",
      previous_candidate: "held",
      candidate: "failed",
      freeze_revision: 2,
      previous_freeze_event_hash: HASH_C,
      candidate_evidence_refs: [REF_A],
    });
  });

  it("revises the compensation request when the quiescent recovery set strictly grows", () => {
    const projection = projectionFixture({
      compensations: [
        { id: "restore-a", for_task: "task-main", for_effect: "protected-main" },
        { id: "restore-b", for_task: "task-main", for_effect: "protected-main" },
      ],
    });
    const snapshot = snapshotFixture({
      terminal_freeze: {
        revision: 1,
        candidate: "failed",
        ledger_sequence: 2,
        event_hash: HASH_C,
      },
      compensation_request: {
        revision: 1,
        pending_terminal: "failed",
        activation_reason: "terminal-failure",
        compensation_refs: ["restore-a"],
        ledger_sequence: 3,
        event_hash: HASH_D,
      },
      tasks: [{
        ref: "task-main",
        status: "failed",
        terminal_event_ref: REF_A,
        condition_evidence_refs: [REF_A],
      }],
      effects: [{
        action_id: "action_main",
        task_ref: "task-main",
        effect_ref: "protected-main",
        outcome: "committed",
        outcome_event_ref: REF_B,
      }],
    });

    expect(evaluateTerminalDecisionTableV02(snapshot, projection)).toEqual({
      decision: "revise-compensation-request",
      request_revision: 2,
      previous_pending_terminal: "failed",
      pending_terminal: "failed",
      activation_reason: "terminal-failure",
      compensation_refs: ["restore-a", "restore-b"],
      added_compensation_refs: ["restore-b"],
      previous_request_event_hash: HASH_D,
      effect_evidence_refs: [REF_B],
      freeze_event_hash: HASH_C,
    });
  });

  it("escalates compensation with the current pending-terminal lineage and unchanged ref set", () => {
    const projection = projectionFixture({
      compensations: [
        { id: "restore-a", for_task: "task-main", for_effect: "protected-main" },
      ],
    });
    const snapshot = snapshotFixture({
      phase: "compensation",
      terminal_freeze: {
        revision: 1,
        candidate: "stalled",
        ledger_sequence: 2,
        event_hash: HASH_C,
      },
      compensation_request: {
        revision: 1,
        pending_terminal: "stalled",
        activation_reason: "terminal-stall",
        compensation_refs: ["restore-a", "restore-b"],
        ledger_sequence: 3,
        event_hash: HASH_D,
      },
      pending_terminal: "stalled",
      pending_terminal_event_ref: REF_B,
      tasks: [{
        ref: "task-main",
        status: "failed",
        terminal_event_ref: REF_A,
        condition_evidence_refs: [REF_A],
      }],
      compensations: [{
        ref: "restore-a",
        activation_requested: true,
        applicable: true,
        settlement: {
          status: "pending",
          unable_reason: null,
          evidence_refs: [],
          transition_sequence: null,
          transition_event_hash: null,
        },
        decision_evidence_refs: [],
      }],
    });

    expect(evaluateTerminalDecisionTableV02(snapshot, projection)).toEqual({
      decision: "escalate-compensation",
      previous_pending_terminal: "stalled",
      pending_terminal: "failed",
      activation_reason: "terminal-failure",
      compensation_refs: ["restore-a", "restore-b"],
      previous_candidate_event_hash: HASH_B,
      candidate_evidence_refs: [REF_A],
    });
  });

  it.each([
    ["stalled", "exhausted"],
    ["stalled", "failed"],
    ["stalled", "aborted"],
    ["exhausted", "failed"],
    ["exhausted", "aborted"],
    ["failed", "aborted"],
  ] as const)("supports the strict compensation escalation %s -> %s", (previous, next) => {
    const projection = projectionFixture();
    const candidateFacts: Partial<TerminalObservationSnapshotV02> = next === "aborted"
      ? { abort_requested: true, abort_event_ref: REF_D }
      : next === "failed"
        ? { tasks: [{ ref: "task-main", status: "failed", terminal_event_ref: REF_A, condition_evidence_refs: [REF_A] }] }
        : { limits: [{ ref: "max-loop-attempts", consumed: 1, next_requested: null, status: "at-ceiling", evidence_ref: REF_A }] };
    const result = evaluateTerminalDecisionTableV02(snapshotFixture({
      phase: "compensation",
      terminal_freeze: { revision: 1, candidate: previous, ledger_sequence: 2, event_hash: HASH_C },
      compensation_request: { revision: 1, pending_terminal: previous, activation_reason: previous === "stalled" ? "terminal-stall" : previous === "exhausted" ? "terminal-exhaustion" : "terminal-failure", compensation_refs: ["restore-a"], ledger_sequence: 3, event_hash: HASH_D },
      pending_terminal: previous,
      pending_terminal_event_ref: REF_B,
      compensations: [{ ref: "restore-a", activation_requested: true, applicable: true, settlement: { status: "pending", unable_reason: null, evidence_refs: [], transition_sequence: null, transition_event_hash: null }, decision_evidence_refs: [] }],
      ...candidateFacts,
    }), projection);
    expect(result).toMatchObject({
      decision: "escalate-compensation",
      previous_pending_terminal: previous,
      pending_terminal: next,
      compensation_refs: ["restore-a"],
      previous_candidate_event_hash: HASH_B,
    });
  });

  it.each([
    ["failed", "failed"],
    ["failed", "exhausted"],
    ["exhausted", "stalled"],
  ] as const)("does not escalate an equal or lower compensation candidate %s -> %s", (previous, observed) => {
    const candidateFacts: Partial<TerminalObservationSnapshotV02> = observed === "failed"
      ? { tasks: [{ ref: "task-main", status: "failed", terminal_event_ref: REF_A, condition_evidence_refs: [REF_A] }] }
      : observed === "exhausted"
        ? { limits: [{ ref: "max-loop-attempts", consumed: 1, next_requested: null, status: "at-ceiling", evidence_ref: REF_A }] }
        : { progress: [{ ref: "progress", target_reached: false, stalled: true, condition_evidence_refs: [REF_A] }] };
    const result = evaluateTerminalDecisionTableV02(snapshotFixture({
      phase: "compensation",
      terminal_freeze: { revision: 1, candidate: previous, ledger_sequence: 2, event_hash: HASH_C },
      compensation_request: { revision: 1, pending_terminal: previous, activation_reason: previous === "failed" ? "terminal-failure" : "terminal-exhaustion", compensation_refs: ["restore-a"], ledger_sequence: 3, event_hash: HASH_D },
      pending_terminal: previous,
      pending_terminal_event_ref: REF_B,
      compensations: [{ ref: "restore-a", activation_requested: true, applicable: true, settlement: { status: "pending", unable_reason: null, evidence_refs: [], transition_sequence: null, transition_event_hash: null }, decision_evidence_refs: [] }],
      ...candidateFacts,
    }), projectionFixture());
    expect(result.decision).not.toBe("escalate-compensation");
  });

  it("returns seal with the exact pre-seal projection hash and checked next fence epoch", () => {
    const projection = projectionFixture();
    const snapshot = snapshotFixture({
      ledger_sequence: 9,
      ledger_head_hash: HASH_D,
      current_fence_epoch: 4,
      terminal_freeze: {
        revision: 1,
        candidate: "completed",
        ledger_sequence: 8,
        event_hash: HASH_C,
      },
    });
    const { terminal_seal: _ignored, ...rest } = snapshot;
    const expectedHash = hashCanonical({
      purpose: "pre-seal-terminal-observation-snapshot-v02",
      ...rest,
      terminal_seal: null,
    });

    expect(evaluateTerminalDecisionTableV02(snapshot, projection)).toEqual({
      decision: "seal",
      outcome: "completed",
      expected_ledger_sequence: 9,
      expected_ledger_head_hash: HASH_D,
      pre_seal_snapshot_hash: expectedHash,
      current_fence_epoch: 4,
      next_fence_epoch: 5,
    });
  });

  it("requests and then enters compensation only after quiescence", () => {
    const projection = projectionFixture({
      compensations: [{ id: "restore-a", for_task: "task-main", for_effect: "protected-main" }],
    });
    const base = snapshotFixture({
      terminal_freeze: { revision: 1, candidate: "failed", ledger_sequence: 2, event_hash: HASH_C },
      tasks: [{ ref: "task-main", status: "failed", terminal_event_ref: REF_A, condition_evidence_refs: [REF_A] }],
      effects: [{ action_id: "action_main", task_ref: "task-main", effect_ref: "protected-main", outcome: "committed", outcome_event_ref: REF_B }],
    });
    expect(evaluateTerminalDecisionTableV02(base, projection)).toEqual({
      decision: "request-compensation",
      request_revision: 1,
      pending_terminal: "failed",
      activation_reason: "terminal-failure",
      compensation_refs: ["restore-a"],
      effect_evidence_refs: [REF_B],
      freeze_event_hash: HASH_C,
    });
    expect(evaluateTerminalDecisionTableV02(snapshotFixture({
      ...base,
      compensation_request: { revision: 1, pending_terminal: "failed", activation_reason: "terminal-failure", compensation_refs: ["restore-a"], ledger_sequence: 3, event_hash: HASH_D },
    }), projection)).toEqual({
      decision: "enter-compensation",
      request_revision: 1,
      request_event_hash: HASH_D,
      pending_terminal: "failed",
      compensation_refs: ["restore-a"],
      freeze_event_hash: HASH_C,
    });
  });

  it("does not treat a skipped always-applicable evaluation as completion", () => {
    const projection = {
      ...projectionFixture(),
      plan: {
        ...(projectionFixture().plan as object),
        tasks: [{ id: "task-main", kind: "work" }],
        evaluations: [{ id: "eval-main", applicability: { mode: "always" } }],
        progress: { observations: [] },
      },
    } as unknown as ValidatedRuntimeProjectionInputV02;
    expect(evaluateTerminalDecisionTableV02(snapshotFixture({
      evaluations: [{
        ref: "eval-main",
        applicable: true,
        due: true,
        status: "skipped",
        required_event_ref: REF_A,
        result_event_ref: REF_B,
        condition_evidence_refs: [REF_B],
      }],
      tasks: [{
        ref: "task-main",
        status: "completed",
        terminal_event_ref: REF_C,
        condition_evidence_refs: [REF_C],
      }],
    }), projection)).toEqual({
      decision: "continue",
      continuation: "work-open",
    });
  });

  it("allows a non-applicable compensation task to remain incomplete while still completing work", () => {
    const projection = {
      ...projectionFixture({
        compensations: [{ id: "restore-a", for_task: "task-main", for_effect: "protected-main" }],
      }),
      plan: {
        ...(projectionFixture({
          compensations: [{ id: "restore-a", for_task: "task-main", for_effect: "protected-main" }],
        }).plan as object),
        tasks: [
          { id: "task-main", kind: "work" },
          { id: "restore-task", kind: "compensation" },
        ],
        compensations: [{
          id: "restore-a",
          for_task: "task-main",
          for_effect: "protected-main",
          action_task: "restore-task",
        }],
        progress: { observations: [] },
      },
    } as unknown as ValidatedRuntimeProjectionInputV02;
    expect(evaluateTerminalDecisionTableV02(snapshotFixture({
      tasks: [
        {
          ref: "task-main",
          status: "completed",
          terminal_event_ref: REF_A,
          condition_evidence_refs: [REF_A],
        },
        {
          ref: "restore-task",
          status: "pending",
          terminal_event_ref: null,
          condition_evidence_refs: [],
        },
      ],
      compensations: [{
        ref: "restore-a",
        activation_requested: false,
        applicable: false,
        settlement: {
          status: "pending",
          unable_reason: null,
          evidence_refs: [],
          transition_sequence: null,
          transition_event_hash: null,
        },
        decision_evidence_refs: [],
      }],
    }), projection)).toEqual({
      decision: "freeze-work",
      candidate: "completed",
      freeze_revision: 1,
      candidate_evidence_refs: [REF_A],
      fence_epoch: 0,
    });
  });

  it("settles the first eligible pending compensation and never re-emits a durable settlement", () => {
    const projection = {
      ...projectionFixture({ compensations: [{ id: "restore-a", for_task: "task-main", for_effect: "protected-main" }] }),
      events: [
        {
          event_type: "run.compensation-requested",
          event_hash: HASH_B,
          payload: { compensation_refs: ["restore-a"] },
        },
        {
          event_type: "run.compensation-phase-entered",
          event_hash: HASH_C,
          payload: { request_event_hash: HASH_B, compensation_refs: ["restore-a"] },
        },
      ],
      plan: {
        ...(projectionFixture().plan as object),
        progress: { observations: [] },
        compensations: [{ id: "restore-a", for_task: "task-main", for_effect: "protected-main", action_task: "restore-task", verification_refs: ["restore-check"] }],
      },
    } as unknown as ValidatedRuntimeProjectionInputV02;
    const compensation = {
      ref: "restore-a",
      activation_requested: true,
      applicable: true,
      settlement: { status: "pending" as const, unable_reason: null, evidence_refs: [] as [], transition_sequence: null, transition_event_hash: null },
      decision_evidence_refs: [],
    };
    const base = snapshotFixture({
      phase: "compensation",
      terminal_freeze: { revision: 1, candidate: "failed", ledger_sequence: 2, event_hash: HASH_C },
      pending_terminal: "failed",
      pending_terminal_event_ref: REF_B,
      compensations: [compensation],
      tasks: [{ ref: "restore-task", status: "completed", terminal_event_ref: REF_A, condition_evidence_refs: [REF_A] }],
      evaluations: [{ ref: "restore-check", applicable: true, due: true, status: "pass", required_event_ref: REF_B, result_event_ref: REF_C, condition_evidence_refs: [REF_C] }],
      effects: [{ action_id: "action_main", task_ref: "task-main", effect_ref: "protected-main", outcome: "committed", outcome_event_ref: REF_B }],
    });
    expect(evaluateTerminalDecisionTableV02(base, projection)).toEqual({
      decision: "settle-compensation",
      settlement: { ref: "restore-a", status: "compensated", unable_reason: null, evidence_refs: [REF_A, REF_C] },
    });
    const settledProjection = {
      ...projection,
      events: [
        ...projection.events,
        {
          event_type: "compensation.settled",
          sequence: 5,
          event_hash: HASH_D,
          payload: { compensation_ref: "restore-a", status: "compensated", unable_reason: null, evidence_refs: [REF_A, REF_C] },
        },
      ],
    } as unknown as ValidatedRuntimeProjectionInputV02;
    expect(evaluateTerminalDecisionTableV02(snapshotFixture({
      ...base,
      compensations: [{ ...compensation, settlement: { status: "compensated", unable_reason: null, evidence_refs: [REF_A, REF_C], transition_sequence: 5, transition_event_hash: HASH_D } }],
    }), settledProjection).decision).toBe("seal");
  });

  it("returns the durable already-sealed branch without reopening work", () => {
    const projection = projectionFixture();
    const snapshot = snapshotFixture({
      terminal_seal: {
        ledger_sequence: 10,
        outcome: "failed",
        fence_epoch: 6,
        pre_seal_ledger_sequence: 9,
        pre_seal_ledger_head_hash: HASH_C,
        pre_seal_snapshot_hash: HASH_B,
        event_hash: HASH_D,
      },
    });

    expect(evaluateTerminalDecisionTableV02(snapshot, projection)).toEqual({
      decision: "already-sealed",
      outcome: "failed",
      seal_sequence: 10,
      fence_epoch: 6,
      pre_seal_snapshot_hash: HASH_B,
      seal_event_hash: HASH_D,
    });
  });

  it("does not throw or manufacture terminal authority for a structural snapshot forgery", () => {
    const forged = Object.freeze({}) as TerminalObservationSnapshotV02;
    expect(() => evaluateTerminalV02(forged)).not.toThrow();
    expect(evaluateTerminalV02(forged)).toEqual({
      decision: "continue",
      continuation: "terminal-quiescence",
    });
  });

  it("cannot emit an action after nested caller mutation of a fabricated snapshot", () => {
    const fabricated = {
      terminal_freeze: null,
      terminal_seal: null,
      gates: [{ status: "pass", nested: { mutable: true } }],
    } as unknown as TerminalObservationSnapshotV02;

    const before = evaluateTerminalV02(fabricated);
    (fabricated as unknown as { terminal_seal: unknown }).terminal_seal = {
      outcome: "completed",
      event_hash: `sha256:${"a".repeat(64)}`,
    };
    (fabricated as unknown as { gates: Array<{ status: string }> }).gates[0]!.status = "fail";
    const after = evaluateTerminalV02(fabricated);

    expect(before).toEqual({ decision: "continue", continuation: "terminal-quiescence" });
    expect(after).toEqual(before);
    expect([before.decision, after.decision]).not.toContain("freeze-work");
    expect([before.decision, after.decision]).not.toContain("already-sealed");
    expect([before.decision, after.decision]).not.toContain("seal");
  });

  it("is absent from the package-root runtime exports", async () => {
    const root = await import("../../src/index.js");
    expect("evaluateTerminalV02" in root).toBe(false);
    expect("evaluateTerminalDecisionTableV02" in root).toBe(false);
    expect("buildTerminalObservationSnapshotV02" in root).toBe(false);
    expect("validateRuntimeProjectionInputV02" in root).toBe(false);
  });
});
