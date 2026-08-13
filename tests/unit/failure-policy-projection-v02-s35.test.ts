import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  ResolvedRunPlanV02,
  type ResolvedRunPlanV02Value,
  type RuntimeEventV02Value,
} from "../../src/schema/runtime.js";
import { deriveFailurePolicyProjectionV02 } from "../../src/run/failure-policy-projection-v02.js";

const HASHES = Array.from({ length: 32 }, (_, index) =>
  `sha256:${index.toString(16).padStart(64, "0")}`,
);
const TASK_REF = "diagnose-root-cause";

const basePlan = ResolvedRunPlanV02.parse(JSON.parse(readFileSync(join(
  process.cwd(),
  "tests/fixtures/compat/s35/v02/planned-run/resolved-run-plan.json",
), "utf8")));

function planWithRetry(options: Readonly<{
  backoff?: "fixed" | "exponential";
  baseDelayMs?: number;
  maxDelayMs?: number;
  maxTaskExecutions?: number;
  idempotency?: "not-required" | "required" | "unsupported";
}> = {}): ResolvedRunPlanV02Value {
  return {
    ...basePlan,
    retry_policy: {
      rules: basePlan.retry_policy.rules.map((rule) =>
        rule.task_ref === TASK_REF && rule.failure_class === "transient-network"
          ? {
              ...rule,
              retryable: true,
              max_task_executions: options.maxTaskExecutions ?? 4,
              backoff: options.backoff ?? "fixed",
              base_delay_ms: options.baseDelayMs ?? 100,
              max_delay_ms: options.maxDelayMs ?? 100,
            }
          : rule,
      ),
    },
    side_effects: basePlan.side_effects.map((spec) =>
      spec.task_id === TASK_REF
        ? { ...spec, effects: spec.effects.map((effect) => ({
            ...effect,
            idempotency: options.idempotency ?? "not-required",
          })) }
        : spec,
    ),
  };
}

function event(
  eventType: string,
  sequence: number,
  payload: Readonly<Record<string, unknown>>,
): RuntimeEventV02Value {
  return {
    schema_version: "0.2",
    event_id: `event_${sequence}`,
    run_id: basePlan.run_id,
    sequence,
    recorded_at: "2026-08-12T12:00:00Z",
    event_type: eventType,
    source: "kernel",
    authority_ref: null,
    risk_tier: "T2",
    related_ids: [],
    previous_event_hash: sequence === 1 ? null : HASHES[sequence - 1],
    event_hash: HASHES[sequence]!,
    payload,
  } as unknown as RuntimeEventV02Value;
}

function admission(sequence: number, executionOrdinal: number, retryOrdinal: number | null = null) {
  return event("task.action-admitted", sequence, {
    action_id: `action_${sequence - 1}`,
    task_ref: TASK_REF,
    admission_clock_ref: { ledger_sequence: sequence - 1, event_hash: HASHES[sequence - 1] },
    execution_ordinal: executionOrdinal,
    retry_of_failure_ordinal: retryOrdinal,
    task_executions_after: executionOrdinal,
  });
}

function actionClock(sequence: number, elapsedMs: number) {
  return event("run.clock-observed", sequence, {
    reason: "action-admission",
    task_ref: TASK_REF,
    failure_ordinal: null,
    use_ref: `action_${sequence}`,
    elapsed_ms: elapsedMs,
  });
}

function failure(sequence: number, ordinal: number, clockSequence: number, safety = true) {
  return event("task.execution-failed", sequence, {
    task_ref: TASK_REF,
    admission_ref: { ledger_sequence: sequence - 1, event_hash: HASHES[sequence - 1] },
    failure_class: "transient-network",
    failure_ordinal: ordinal,
    failure_clock_ref: { ledger_sequence: clockSequence, event_hash: HASHES[clockSequence] },
    retry_safety_evidence_refs: safety
      ? [{ ledger_sequence: sequence - 1, event_hash: HASHES[sequence - 1] }]
      : [],
  });
}

function retryClock(sequence: number, ordinal: number, elapsedMs: number) {
  return event("run.clock-observed", sequence, {
    reason: "retry-check",
    task_ref: TASK_REF,
    failure_ordinal: ordinal,
    use_ref: null,
    elapsed_ms: elapsedMs,
  });
}

function policyDecision(
  sequence: number,
  options: Readonly<{
    proposal?: string;
    phase?: "work" | "compensation";
    compensationRef?: string | null;
    decision?: "deny" | "escalate" | "abort" | "hold" | "allow";
    disposition?: "proposal-final" | "human-exception-required" | "abort-run" | "redecide-after-prefix-change" | "non-resumable" | "lease-eligible";
    reviewedThrough?: number;
  }> = {},
) {
  const phase = options.phase ?? "work";
  const proposal = options.proposal ?? "proposal_main";
  return event("policy.decision-recorded", sequence, {
    task_ref: TASK_REF,
    phase,
    compensation_ref: options.compensationRef ?? null,
    action_proposal_id: proposal,
    policy_action_kind: "local-read",
    decision: options.decision ?? "hold",
    decision_disposition: options.disposition ?? "non-resumable",
    reviewed_through_ref: {
      ledger_sequence: options.reviewedThrough ?? sequence - 1,
      event_hash: HASHES[options.reviewedThrough ?? sequence - 1],
    },
    evidence_refs: [{ ledger_sequence: sequence - 1, event_hash: HASHES[sequence - 1] }],
  });
}

describe("S35 failure and policy projection", () => {
  it("projects waiting without a retry clock and ready at the exact fixed boundary", () => {
    const prefix = [actionClock(1, 1_000), admission(2, 1), failure(3, 1, 1)];
    expect(deriveFailurePolicyProjectionV02({ plan: planWithRetry(), events: prefix })).toMatchObject({
      ok: true,
      value: { active_failures: [{ task_execution_count: 1, failure_ordinal: 1, retry_disposition: "waiting", retry_clock_ref: null }] },
    });
    expect(deriveFailurePolicyProjectionV02({
      plan: planWithRetry(),
      events: [...prefix, retryClock(4, 1, 1_100)],
    })).toMatchObject({
      ok: true,
      value: { active_failures: [{ retry_disposition: "ready", retry_clock_ref: { ledger_sequence: 4, event_hash: HASHES[4] } }] },
    });
  });

  it("uses capped exponential delay and rejects early, duplicate, or decreasing retry clocks", () => {
    const prefix = [
      actionClock(1, 1_000), admission(2, 1), failure(3, 1, 1), retryClock(4, 1, 1_100),
      actionClock(5, 1_200), admission(6, 2, 1), failure(7, 2, 5), retryClock(8, 2, 1_400),
      actionClock(9, 5_000), admission(10, 3, 2), failure(11, 3, 9),
    ];
    const plan = planWithRetry({ backoff: "exponential", baseDelayMs: 100, maxDelayMs: 250 });
    expect(deriveFailurePolicyProjectionV02({ plan, events: [...prefix, retryClock(12, 3, 5_250)] })).toMatchObject({
      ok: true,
      value: { active_failures: [{ retry_disposition: "ready" }] },
    });
    for (const clocks of [
      [retryClock(12, 3, 5_249)],
      [retryClock(12, 3, 4_999)],
      [retryClock(12, 3, 5_250), retryClock(13, 3, 5_251)],
    ]) {
      expect(deriveFailurePolicyProjectionV02({ plan, events: [...prefix, ...clocks] })).toEqual({
        ok: false,
        reason: "TASK_EFFECT_OR_FAILURE_INVALID",
      });
    }
  });

  it("supersedes only the exact ready failure and rejects ordinal or disposition drift", () => {
    const prefix = [
      actionClock(1, 1_000), admission(2, 1), failure(3, 1, 1), retryClock(4, 1, 1_100),
    ];
    expect(deriveFailurePolicyProjectionV02({
      plan: planWithRetry(),
      events: [...prefix, actionClock(5, 1_200), admission(6, 2, 1)],
    })).toMatchObject({ ok: true, value: { active_failures: [] } });
    for (const retryOrdinal of [2, null]) {
      expect(deriveFailurePolicyProjectionV02({
        plan: planWithRetry(),
        events: [...prefix, actionClock(5, 1_200), admission(6, 2, retryOrdinal)],
      })).toEqual({ ok: false, reason: "ACTION_ADMISSION_OR_QUIESCENCE_INVALID" });
    }
    expect(deriveFailurePolicyProjectionV02({
      plan: planWithRetry(),
      events: [actionClock(1, 1_000), admission(2, 1), failure(3, 1, 1), actionClock(4, 1_050), admission(5, 2, 1)],
    })).toEqual({ ok: false, reason: "ACTION_ADMISSION_OR_QUIESCENCE_INVALID" });
  });

  it("rejects copied execution counters and admission-clock lineage that drift", () => {
    const baseAdmission = admission(2, 1);
    const baseFailure = failure(3, 1, 1);
    for (const events of [
      [actionClock(1, 1_000), event("task.action-admitted", 2, {
        ...baseAdmission.payload,
        task_executions_after: 2,
      })],
      [actionClock(1, 1_000), baseAdmission, event("task.execution-failed", 3, {
        ...baseFailure.payload,
        admission_ref: { ledger_sequence: 1, event_hash: HASHES[1] },
      })],
      [actionClock(1, 1_000), baseAdmission, event("task.execution-failed", 3, {
        ...baseFailure.payload,
        failure_clock_ref: { ledger_sequence: 2, event_hash: HASHES[2] },
      })],
    ]) {
      expect(deriveFailurePolicyProjectionV02({ plan: planWithRetry(), events })).toEqual({
        ok: false,
        reason: events.length === 2
          ? "ACTION_ADMISSION_OR_QUIESCENCE_INVALID"
          : "TASK_EFFECT_OR_FAILURE_INVALID",
      });
    }
  });

  it("marks exhausted, non-retryable, and idempotency-unsafe failures ineligible", () => {
    const events = [actionClock(1, 1_000), admission(2, 1), failure(3, 1, 1, false)];
    expect(deriveFailurePolicyProjectionV02({
      plan: planWithRetry({ maxTaskExecutions: 2 }),
      events: [
        actionClock(1, 1_000), admission(2, 1), failure(3, 1, 1), retryClock(4, 1, 1_100),
        actionClock(5, 1_200), admission(6, 2, 1), failure(7, 2, 5),
      ],
    })).toMatchObject({ ok: true, value: { active_failures: [{ retry_disposition: "ineligible" }] } });
    expect(deriveFailurePolicyProjectionV02({
      plan: planWithRetry({ idempotency: "required" }), events,
    })).toMatchObject({ ok: true, value: { active_failures: [{ retry_disposition: "ineligible" }] } });
    expect(deriveFailurePolicyProjectionV02({
      plan: basePlan, events,
    })).toMatchObject({ ok: true, value: { active_failures: [{ retry_disposition: "ineligible" }] } });

    const invalidRulePlan: ResolvedRunPlanV02Value = {
      ...planWithRetry(),
      retry_policy: {
        rules: planWithRetry().retry_policy.rules.map((rule) =>
          rule.task_ref === TASK_REF && rule.failure_class === "transient-network"
            ? { ...rule, backoff: "none", base_delay_ms: 0, max_delay_ms: 0 }
            : rule),
      },
    };
    expect(deriveFailurePolicyProjectionV02({ plan: invalidRulePlan, events })).toEqual({
      ok: false,
      reason: "TASK_EFFECT_OR_FAILURE_INVALID",
    });
  });

  it("retains all non-allow decisions and derives their closed active state", () => {
    const events = [
      policyDecision(2, { proposal: "condition", disposition: "redecide-after-prefix-change", reviewedThrough: 1 }),
      policyDecision(4, { proposal: "condition", decision: "allow", disposition: "lease-eligible", reviewedThrough: 3 }),
      policyDecision(5, { proposal: "deny", decision: "deny", disposition: "proposal-final" }),
      policyDecision(6, { proposal: "escalate", decision: "escalate", disposition: "human-exception-required" }),
      policyDecision(7, { proposal: "abort", decision: "abort", disposition: "abort-run" }),
      policyDecision(8, { proposal: "final-hold", decision: "hold", disposition: "non-resumable" }),
    ];
    const result = deriveFailurePolicyProjectionV02({ plan: basePlan, events });
    expect(result).toMatchObject({
      ok: true,
      value: {
        policy_blocks: [
          { action_proposal_id: "condition", active: false },
          { action_proposal_id: "deny", active: false },
          { action_proposal_id: "escalate", active: true },
          { action_proposal_id: "abort", active: false },
          { action_proposal_id: "final-hold", active: true },
        ],
      },
    });
  });

  it("rejects invalid phase lineage and any activity after a non-resumable hold", () => {
    expect(deriveFailurePolicyProjectionV02({
      plan: basePlan,
      events: [policyDecision(2, { phase: "compensation", compensationRef: "missing" })],
    })).toEqual({ ok: false, reason: "ACTION_ADMISSION_OR_QUIESCENCE_INVALID" });
    expect(deriveFailurePolicyProjectionV02({
      plan: basePlan,
      events: [
        policyDecision(2, { proposal: "final-hold" }),
        policyDecision(3, { proposal: "later", decision: "allow", disposition: "lease-eligible" }),
      ],
    })).toEqual({ ok: false, reason: "ACTION_ADMISSION_OR_QUIESCENCE_INVALID" });
    expect(deriveFailurePolicyProjectionV02({
      plan: basePlan,
      events: [
        policyDecision(2, { proposal: "condition", disposition: "redecide-after-prefix-change", reviewedThrough: 1 }),
        policyDecision(3, { proposal: "condition", decision: "allow", disposition: "lease-eligible", reviewedThrough: 1 }),
      ],
    })).toEqual({ ok: false, reason: "ACTION_ADMISSION_OR_QUIESCENCE_INVALID" });
  });

  it("projects a compensation policy row only for its exact action task and compensation ref", () => {
    const compensationPlan: ResolvedRunPlanV02Value = {
      ...basePlan,
      tasks: basePlan.tasks.map((task) => task.id === TASK_REF
        ? { ...task, kind: "compensation", depends_on: [] }
        : task),
      compensations: [{
        id: "undo-main",
        for_task: "implement-change",
        for_effect: "effect-implement-change",
        action_task: TASK_REF,
        preconditions: [{
          source: "effect",
          task_ref: "implement-change",
          effect_ref: "effect-implement-change",
          outcome: "committed",
        }],
        verification_refs: [basePlan.evaluations[0]!.id],
        may_fail: true,
      }],
    };
    expect(deriveFailurePolicyProjectionV02({
      plan: compensationPlan,
      events: [policyDecision(2, {
        phase: "compensation",
        compensationRef: "undo-main",
        decision: "escalate",
        disposition: "human-exception-required",
      })],
    })).toMatchObject({
      ok: true,
      value: { policy_blocks: [{
        task_ref: TASK_REF,
        phase: "compensation",
        compensation_ref: "undo-main",
        active: true,
      }] },
    });
  });
});
