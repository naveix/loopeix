import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  ResolvedRunPlanV02,
  type LedgerRefV02Value,
  type ResolvedRunPlanV02Value,
  type RuntimeEventV02Value,
  type TerminalObservationSnapshotV02,
} from "../../src/schema/runtime.js";
import { deriveCompensationProjectionV02 } from "../../src/run/compensation-projection-v02.js";

const HASHES = Array.from({ length: 20 }, (_, index) =>
  `sha256:${index.toString(16).padStart(64, "0")}`,
);

function ref(sequence: number): LedgerRefV02Value {
  return { ledger_sequence: sequence, event_hash: HASHES[sequence]! };
}

function event(
  eventType: string,
  sequence: number,
  payload: Readonly<Record<string, unknown>>,
): RuntimeEventV02Value {
  return {
    schema_version: "0.2",
    event_id: `event_${sequence}`,
    run_id: "run_compensation_projection",
    sequence,
    recorded_at: "2026-08-12T12:00:00Z",
    event_type: eventType,
    source: "evaluator",
    authority_ref: null,
    risk_tier: "T2",
    related_ids: [],
    previous_event_hash: sequence === 1 ? null : HASHES[sequence - 1],
    event_hash: HASHES[sequence]!,
    payload,
  } as unknown as RuntimeEventV02Value;
}

const basePlan = ResolvedRunPlanV02.parse(JSON.parse(readFileSync(join(
  process.cwd(),
  "tests/fixtures/compat/s35/v02/planned-run/resolved-run-plan.json",
), "utf8")));

const plan: ResolvedRunPlanV02Value = {
  ...basePlan,
  compensations: [{
    id: "restore-workspace",
    for_task: "implement-change",
    for_effect: "effect-implement-change",
    action_task: "restore-task",
    preconditions: [{
      source: "effect",
      task_ref: "implement-change",
      effect_ref: "effect-implement-change",
      outcome: "committed",
    }],
    verification_refs: ["verify-restore"],
    may_fail: true,
  }],
};

type Task = TerminalObservationSnapshotV02["tasks"][number];
type Evaluation = TerminalObservationSnapshotV02["evaluations"][number];
type Effect = TerminalObservationSnapshotV02["effects"][number];
type Limit = TerminalObservationSnapshotV02["limits"][number];
type PolicyBlock = TerminalObservationSnapshotV02["policy_blocks"][number];

const pendingTask: Task = {
  ref: "restore-task",
  status: "pending",
  terminal_event_ref: null,
  condition_evidence_refs: [],
};
const pendingVerifier: Evaluation = {
  ref: "verify-restore",
  applicable: false,
  due: false,
  status: "missing",
  required_event_ref: null,
  result_event_ref: null,
  condition_evidence_refs: [],
};
const committedEffect: Effect = {
  action_id: "action_work",
  task_ref: "implement-change",
  effect_ref: "effect-implement-change",
  outcome: "committed",
  outcome_event_ref: ref(2),
};

function request(sequence = 3): RuntimeEventV02Value {
  return event("run.compensation-requested", sequence, {
    revision: 1,
    pending_terminal: "failed",
    activation_reason: "terminal-failure",
    compensation_refs: ["restore-workspace"],
    effect_evidence_refs: [ref(2)],
    freeze_event_hash: HASHES[1],
  });
}

function phaseEntered(sequence = 4): RuntimeEventV02Value {
  return event("run.compensation-phase-entered", sequence, {
    request_revision: 1,
    request_event_hash: HASHES[3],
    pending_terminal: "failed",
    compensation_refs: ["restore-workspace"],
    freeze_event_hash: HASHES[1],
  });
}

function derive(options: Readonly<{
  events?: readonly RuntimeEventV02Value[];
  plan?: ResolvedRunPlanV02Value;
  tasks?: readonly Task[];
  evaluations?: readonly Evaluation[];
  effects?: readonly Effect[];
  limits?: readonly Limit[];
  policyBlocks?: readonly PolicyBlock[];
}> = {}) {
  return deriveCompensationProjectionV02({
    plan: options.plan ?? plan,
    events: options.events ?? [],
    tasks: options.tasks ?? [pendingTask],
    evaluations: options.evaluations ?? [pendingVerifier],
    effects: options.effects ?? [committedEffect],
    limits: options.limits ?? [],
    policy_blocks: options.policyBlocks ?? [],
  });
}

describe("S35 compensation projection reducer", () => {
  it("keeps a merely committed effect inactive until a canonical request", () => {
    expect(derive()).toEqual({
      ok: true,
      value: {
        compensations: [{
          ref: "restore-workspace",
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
        durable_settlements: [],
        pending_settlement_decisions: [],
      },
    });
  });

  it("makes request membership activation-sticky for a committed effect", () => {
    const result = derive({ events: [request()] });
    expect(result).toMatchObject({
      ok: true,
      value: {
        compensations: [{ activation_requested: true, applicable: true }],
        pending_settlement_decisions: [],
      },
    });
  });

  it("makes compensation action admission applicability-sticky without inventing activation", () => {
    const admitted = event("task.action-admitted", 5, {
      task_ref: "restore-task",
    });
    expect(derive({ events: [admitted] })).toMatchObject({
      ok: true,
      value: {
        compensations: [{ activation_requested: false, applicable: true }],
        pending_settlement_decisions: [],
      },
    });
  });

  it("projects unknown protected-effect evidence as an exact unable decision", () => {
    const unknown: Effect = { ...committedEffect, outcome: "unknown", outcome_event_ref: ref(4) };
    const result = derive({ events: [request(), phaseEntered()], effects: [unknown] });
    expect(result).toMatchObject({
      ok: true,
      value: {
        compensations: [{ activation_requested: true, applicable: true, decision_evidence_refs: [ref(4)] }],
        pending_settlement_decisions: [{
          ref: "restore-workspace",
          status: "unable",
          unable_reason: "unknown-action-outcome",
          evidence_refs: [ref(4)],
        }],
      },
    });
  });

  it("settles as compensated only after the action and every verifier pass", () => {
    const taskEvidence = ref(5);
    const verifierEvidence = ref(6);
    const result = derive({
      events: [request(), phaseEntered()],
      tasks: [{ ...pendingTask, status: "completed", terminal_event_ref: taskEvidence }],
      evaluations: [{
        ...pendingVerifier,
        applicable: true,
        due: true,
        status: "pass",
        result_event_ref: verifierEvidence,
        condition_evidence_refs: [verifierEvidence],
      }],
    });
    expect(result).toMatchObject({
      ok: true,
      value: {
        pending_settlement_decisions: [{
          ref: "restore-workspace",
          status: "compensated",
          unable_reason: null,
          evidence_refs: [taskEvidence, verifierEvidence],
        }],
      },
    });
  });

  it("keeps completed action recovery pending while a verifier is missing or HOLD", () => {
    const taskEvidence = ref(5);
    for (const verifier of [
      pendingVerifier,
      { ...pendingVerifier, applicable: true, due: true, status: "hold" as const, result_event_ref: ref(6) },
    ]) {
      const result = derive({
        events: [request(), phaseEntered()],
        tasks: [{ ...pendingTask, status: "completed", terminal_event_ref: taskEvidence }],
        evaluations: [verifier],
      });
      expect(result).toMatchObject({ ok: true, value: { pending_settlement_decisions: [] } });
    }
  });

  it.each([
    ["failed", pendingVerifier, [ref(5)]],
    ["completed", { ...pendingVerifier, applicable: true, due: true, status: "fail", result_event_ref: ref(6) }, [ref(5), ref(6)]],
  ] as const)("projects permanent action/verifier failure as compensation-failed", (taskStatus, verifier, evidence) => {
    const result = derive({
      events: [request(), phaseEntered()],
      tasks: [{ ...pendingTask, status: taskStatus, terminal_event_ref: ref(5) }],
      evaluations: [verifier],
    });
    expect(result).toMatchObject({
      ok: true,
      value: { pending_settlement_decisions: [{ status: "compensation-failed", evidence_refs: evidence }] },
    });
  });

  it.each([
    ["max-elapsed-ms", "elapsed-budget-exhausted"],
    ["max-tool-calls", "tool-call-budget-exhausted"],
    ["max-output-bytes", "output-budget-exhausted"],
    ["max-tokens", "token-budget-exhausted"],
    ["max-cost", "cost-budget-exhausted"],
  ] as const)("maps closed %s evidence to unable:%s", (limitRef, unableReason) => {
    const evidence = ref(7);
    const configuredPlan: ResolvedRunPlanV02Value = {
      ...plan,
      limit_policy: {
        ...plan.limit_policy,
        max_tokens: limitRef === "max-tokens" ? 10 : plan.limit_policy.max_tokens,
        max_cost_minor_units: limitRef === "max-cost" ? 10 : plan.limit_policy.max_cost_minor_units,
        cost_currency: limitRef === "max-cost" ? "GBP" : plan.limit_policy.cost_currency,
      },
    };
    const result = derive({
      events: [request(), phaseEntered()],
      plan: configuredPlan,
      limits: [{ ref: limitRef, consumed: 10, next_requested: 1, status: "would-exceed", evidence_ref: evidence }],
    });
    expect(result).toMatchObject({
      ok: true,
      value: { pending_settlement_decisions: [{ status: "unable", unable_reason: unableReason, evidence_refs: [evidence] }] },
    });
  });

  it("does not invent token or cost exhaustion when those budgets are unconfigured", () => {
    expect(derive({
      events: [request(), phaseEntered()],
      limits: [
        { ref: "max-tokens", consumed: 10, next_requested: 1, status: "would-exceed", evidence_ref: ref(7) },
        { ref: "max-cost", consumed: 10, next_requested: 1, status: "would-exceed", evidence_ref: ref(8) },
      ],
    })).toMatchObject({ ok: true, value: { pending_settlement_decisions: [] } });
  });

  it("requires an active compensation-only non-resumable policy HOLD for safety-hold", () => {
    const decisionEvent = ref(8);
    const policyEvidence = ref(7);
    const baseBlock: PolicyBlock = {
      task_ref: "restore-task",
      phase: "compensation",
      compensation_ref: "restore-workspace",
      action_proposal_id: "proposal_restore",
      policy_action_kind: "approval-contract-edit",
      decision: "hold",
      decision_disposition: "non-resumable",
      active: true,
      decision_event_ref: decisionEvent,
      evidence_refs: [policyEvidence],
    };
    expect(derive({ events: [request(), phaseEntered()], policyBlocks: [baseBlock] })).toMatchObject({
      ok: true,
      value: { pending_settlement_decisions: [{
        status: "unable",
        unable_reason: "safety-hold",
        evidence_refs: [policyEvidence, decisionEvent],
      }] },
    });
    expect(derive({ events: [request(), phaseEntered()], policyBlocks: [{ ...baseBlock, phase: "work", compensation_ref: null }] }))
      .toMatchObject({ ok: true, value: { pending_settlement_decisions: [] } });
  });

  it("preserves an exact durable settlement separately and rejects contradictory bytes", () => {
    const taskEvidence = ref(5);
    const verifierEvidence = ref(6);
    const settled = event("compensation.settled", 7, {
      compensation_ref: "restore-workspace",
      status: "compensated",
      unable_reason: null,
      evidence_refs: [taskEvidence, verifierEvidence],
    });
    const facts = {
      events: [request(), phaseEntered(), settled],
      tasks: [{ ...pendingTask, status: "completed" as const, terminal_event_ref: taskEvidence }],
      evaluations: [{ ...pendingVerifier, applicable: true, due: true, status: "pass" as const, result_event_ref: verifierEvidence }],
    };
    const result = derive(facts);
    expect(result).toMatchObject({
      ok: true,
      value: {
        compensations: [{ settlement: { status: "compensated", transition_sequence: 7, transition_event_hash: HASHES[7] } }],
        durable_settlements: [{ ref: "restore-workspace", event_ref: ref(7) }],
        pending_settlement_decisions: [],
      },
    });

    const contradiction = event("compensation.settled", 7, {
      compensation_ref: "restore-workspace",
      status: "compensation-failed",
      unable_reason: null,
      evidence_refs: [taskEvidence],
    });
    expect(derive({ ...facts, events: [request(), phaseEntered(), contradiction] })).toEqual({
      ok: false,
      reason: "COMPENSATION_SETTLEMENT_INVALID",
    });
  });

  it("rejects request membership for a known uncommitted protected effect", () => {
    expect(derive({
      events: [request()],
      effects: [{ ...committedEffect, outcome: "not-committed" }],
    })).toEqual({ ok: false, reason: "ACTIVATION_INVALID" });
  });

  it("rejects phase-entry ref drift and duplicate durable settlements", () => {
    const driftedEntry = event("run.compensation-phase-entered", 4, {
      request_revision: 1,
      request_event_hash: HASHES[3],
      pending_terminal: "failed",
      compensation_refs: [],
      freeze_event_hash: HASHES[1],
    });
    expect(derive({ events: [request(), driftedEntry] })).toEqual({
      ok: false,
      reason: "COMPENSATION_REF_SET_INVALID",
    });

    const settlementPayload = {
      compensation_ref: "restore-workspace",
      status: "compensated",
      unable_reason: null,
      evidence_refs: [ref(5), ref(6)],
    };
    expect(derive({
      events: [
        request(),
        phaseEntered(),
        event("compensation.settled", 7, settlementPayload),
        event("compensation.settled", 8, settlementPayload),
      ],
    })).toEqual({ ok: false, reason: "COMPENSATION_SETTLEMENT_INVALID" });
  });
});
