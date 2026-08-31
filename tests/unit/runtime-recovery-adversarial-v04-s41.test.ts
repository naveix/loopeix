import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it, vi } from "vitest";

import {
  captureEffectDispatchBrokerV01,
  dispatchAdmittedActionV01,
} from "../../src/run/runtime-effect-dispatch-broker-v01.js";
import {
  S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
  simulateAuthorityDecisionV02,
} from "../../src/run/action-classifier-policy-v02.js";
import { projectAuthorityInteractionViewV02 } from "../../src/run/present-planned-v02.js";
import { admitRuntimeActionV03 } from "../../src/run/runtime-action-admission-v03.js";
import {
  appendRuntimeEventV03,
  closeRuntimeWriteSessionV03,
  createRuntimeEventDraftV03,
  inspectRuntimeWriteSessionV03ForDispatch,
  openRuntimeWriteSessionV03,
} from "../../src/run/runtime-write-session-v03.js";
import {
  evaluateRuntimeLimitAccountingV04,
  scheduleRuntimeRetryV04,
} from "../../src/run/runtime-limit-accounting-v04.js";
import { projectRuntimePlanV03 } from "../../src/run/project-plan-v03.js";
import { RuntimeEventV04, type ResolvedRunPlanV03Value } from "../../src/schema/runtime-v04.js";
import { ResolvedRunPlanV02 } from "../../src/schema/runtime.js";
import { captureRuntimeProfileRegistryV03 } from "../../src/schema/runtime-plan-v03.js";
import { createSignedRuntimeActionAdmissionV03Fixture } from "../helpers/runtime-action-admission-v03-fixture.js";

const H = (character: string) => `sha256:${character.repeat(64)}`;
const REGISTRY = captureRuntimeProfileRegistryV03();

function planV03(): ResolvedRunPlanV03Value {
  const source = ResolvedRunPlanV02.parse(JSON.parse(readFileSync(
    join(import.meta.dirname, "../fixtures/compat/s35/v02/planned-run/resolved-run-plan.json"),
    "utf8",
  )));
  source.limit_policy.max_tokens = 100;
  source.limit_policy.max_cost_minor_units = 100;
  source.limit_policy.cost_currency = "GBP";
  source.recovery_policy.reserve.max_elapsed_ms = 500;
  source.recovery_policy.reserve.max_tool_calls = 2;
  source.recovery_policy.reserve.max_output_bytes = 1_000;
  source.recovery_policy.reserve.max_tokens = 10;
  source.recovery_policy.reserve.max_cost_minor_units = 10;
  const projected = projectRuntimePlanV03(source, REGISTRY);
  if (!projected.ok) throw new Error(projected.reason);
  return projected.value;
}

function accountingInput(plan: ResolvedRunPlanV03Value, phase: "work" | "compensation" = "work") {
  return {
    plan,
    phase,
    consumed: {
      loop_attempts: 0,
      execution_attempts: 0,
      task_executions: Object.fromEntries(plan.tasks.map((task) => [task.id, 0])),
      elapsed_ms: 0,
      tool_calls: 0,
      action_output_bytes: 0,
      control_output_bytes: 0,
      token_count: 0,
      cost_minor_units: 0,
      active_workers: 0,
    },
    requested: {
      task_ref: plan.tasks[0]!.id,
      loop_attempts: 0,
      execution_attempts: 0,
      task_executions: 0,
      elapsed_ms: 0,
      tool_calls: 0,
      action_output_bytes: 0,
      control_output_bytes: 0,
      token_count: 0,
      cost_minor_units: 0,
      workers: 0,
      process_runtime_ms: 0,
    },
  };
}

async function admittedBroker(
  dispatch: (input: unknown) => unknown,
  fixtureOptions: Parameters<typeof createSignedRuntimeActionAdmissionV03Fixture>[0] = {},
) {
  const fixture = await createSignedRuntimeActionAdmissionV03Fixture(fixtureOptions);
  const opened = await openRuntimeWriteSessionV03(fixture.store, fixture.expectation);
  if (!opened.ok) throw new Error(opened.error);
  const admission = await admitRuntimeActionV03(opened.session, fixture.request);
  if (!admission.ok) throw new Error(admission.error);
  const broker = captureEffectDispatchBrokerV01({
    normalized_dispatch_hash: fixture.request.normalized_dispatch_hash,
    adapter_ref: "adapter_s41_bounded",
    adapter_version_hash: H("2"),
    adapter_profile_hash: H("3"),
    adapter_invocation_id: "invocation_s41_bounded",
    dispatch,
  });
  if (broker === null) throw new Error("broker capture failed");
  return { ...fixture, session: opened.session, admission, broker };
}

function recoveryRequestEvent() {
  return {
    schema_version: "0.4",
    event_id: "event_s41_adversarial_resume",
    run_id: "run_s41_adversarial",
    sequence: 9,
    recorded_at: "2026-08-30T12:00:09Z",
    event_type: "recovery.resume-requested",
    source: "operator",
    authority_ref: "operator_s41_adversarial",
    risk_tier: "T1",
    related_ids: [],
    previous_event_hash: H("0"),
    payload: {
      request_id: "resume_s41_adversarial",
      mode: "ordinary",
      resume_nonce_hash: H("1"),
      previous_attempt_event_ref: { ledger_sequence: 3, event_hash: H("2") },
      source_boundary_sequence: 8,
      source_boundary_head_hash: H("3"),
      source_manifest_hash: H("4"),
      plan_hash: H("5"),
      input_hash: H("6"),
      recovery_policy_hash: H("7"),
      authority_envelope_hash: H("8"),
      request_clock_ref: { ledger_sequence: 8, event_hash: H("9") },
      target_action_admission_ref: null,
      compensation_phase_event_ref: null,
    },
    event_hash: H("a"),
  };
}

describe("S41-E provider, quota, and mailbox failure boundaries", () => {
  it.each([
    ["quota interruption", () => { throw new Error("quota interrupted"); }],
    ["provider outage", async () => Promise.reject(new Error("provider unavailable"))],
    ["malformed mailbox", async () => ({ disposition: "UNRECOGNIZED" })],
  ])("fails closed on %s after exactly one broker entry and forbids retry", async (_name, dispatchImpl) => {
    const dispatch = vi.fn(dispatchImpl);
    const state = await admittedBroker(dispatch);
    try {
      await expect(dispatchAdmittedActionV01(state.session, state.broker, state.admission.permit))
        .resolves.toEqual({ ok: false, error: "DISPATCH_OUTCOME_UNKNOWN" });
      expect(dispatch).toHaveBeenCalledTimes(1);
      await expect(dispatchAdmittedActionV01(state.session, state.broker, state.admission.permit))
        .resolves.toEqual({ ok: false, error: "RUNTIME_WRITE_SESSION_POISONED" });
      expect(dispatch).toHaveBeenCalledTimes(1);
      await expect(inspectRuntimeWriteSessionV03ForDispatch(state.session))
        .resolves.toEqual({ ok: false, error: "RUNTIME_WRITE_SESSION_POISONED" });
    } finally {
      await closeRuntimeWriteSessionV03(state.session);
    }
  });

  it("holds one protected action exactly once while one envelope-authorized ordinary action produces exactly one external effect", async () => {
    const directory = mkdtempSync(join(tmpdir(), "loopeix-s41-effect-"));
    const counterPath = join(directory, "counter.txt");
    writeFileSync(counterPath, "0\n", { encoding: "utf8", mode: 0o600 });
    const protectedAction = {
      proposal: {
        action_proposal_id: "proposal_s41_protected", action_proposal_hash: H("1"), action_class: "task",
        policy_action_kind: "send", action_approval_class: "human_exception",
        policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
        action_scope_hash: H("2"), normalized_dispatch_hash: H("3"), repository_pre_state_hash: H("4"),
        classifier_rule_hash: H("5"), data_flow_hash: H("6"), effective_risk_tier: "T1",
      },
      reviewer_view_hash: H("7"), reviewed_through_ref: { ledger_sequence: 1, event_hash: H("8") },
      recommendations: [],
      authority: { envelope_verified: true, contained: true, proof_fresh: true, revocation_epoch_current: true },
      enforcement: { available: true, information_flow_allowed: true, gates_passed: true, immediate_revalidation_passed: true },
      condition_results: [], issued_at: "2026-08-30T12:00:00Z", expires_at: "2026-08-30T12:01:00Z",
      fence_epoch: 0,
    } as const;
    const surfaceProtectedAction = vi.fn(() => projectAuthorityInteractionViewV02({
      view: "expert",
      subject: {
        preview_kind: "exception", action_proposal_hash: protectedAction.proposal.action_proposal_hash,
        action_scope_hash: protectedAction.proposal.action_scope_hash,
        scope_delta: { operations_added: [], selectors_added: [], risk_change: null },
        reversible: false, evidence_needed: ["exact-human-authorization"], safe_default: "hold",
        smallest_safe_alternative: { operation: "read", target_ref: "operator-review" },
        requested_decision: "answer", reason_ref: "decision-human-exception-hold",
        resume_boundary: "new-reviewed-prefix", policy_digest: protectedAction.proposal.policy_digest,
      },
    }));
    const dispatch = vi.fn(async () => {
      const prior = Number.parseInt(readFileSync(counterPath, "utf8"), 10);
      writeFileSync(counterPath, `${prior + 1}\n`, { encoding: "utf8", mode: 0o600 });
      return { disposition: "DISPATCHED" as const, observation: { counter_path: counterPath } };
    });
    let state: Awaited<ReturnType<typeof admittedBroker>> | null = null;
    try {
      const protectedDecision = simulateAuthorityDecisionV02(protectedAction);
      expect(protectedDecision).toMatchObject({
        ok: true,
        value: {
          decision: "hold", decision_disposition: "non-resumable", simulated_lease: null,
          reason_codes: [{ declaration_ref: "decision-human-exception-hold" }],
        },
      });
      expect(surfaceProtectedAction()).toMatchObject({
        ok: true, value: { preview_kind: "exception", safe_default: "hold" },
      });
      expect(surfaceProtectedAction).toHaveBeenCalledTimes(1);
      expect(dispatch).not.toHaveBeenCalled();

      state = await admittedBroker(dispatch);
      const snapshot = await inspectRuntimeWriteSessionV03ForDispatch(state.session);
      expect(snapshot.ok).toBe(true);
      if (!snapshot.ok) throw new Error(snapshot.error);
      const envelopes = snapshot.snapshot.events.filter((event) => event.event_type === "authority.envelope-recorded");
      const decisions = snapshot.snapshot.events.filter((event) => event.event_type === "policy.decision-recorded");
      const leases = snapshot.snapshot.events.filter((event) => event.event_type === "lease.issued");
      const admissions = snapshot.snapshot.events.filter((event) => event.event_type === "task.action-admitted");
      expect(envelopes).toHaveLength(1);
      expect(decisions).toHaveLength(1);
      expect(leases).toHaveLength(1);
      expect(admissions).toHaveLength(1);
      expect((envelopes[0]!.payload as { revocation_epoch: number }).revocation_epoch).toBe(0);
      expect((leases[0]!.payload as {
        authority_envelope_ref: Readonly<{ ledger_sequence: number; event_hash: string }>;
      }).authority_envelope_ref).toEqual({
        ledger_sequence: envelopes[0]!.sequence,
        event_hash: envelopes[0]!.event_hash,
      });

      const attempts = await Promise.all([
        dispatchAdmittedActionV01(state.session, state.broker, state.admission.permit),
        dispatchAdmittedActionV01(state.session, state.broker, state.admission.permit),
        dispatchAdmittedActionV01(state.session, state.broker, state.admission.permit),
      ]);
      expect(attempts.filter((row) => row.ok)).toHaveLength(1);
      expect(attempts.filter((row) => !row.ok)).toHaveLength(2);
      expect(dispatch).toHaveBeenCalledTimes(1);
      expect(readFileSync(counterPath, "utf8")).toBe("1\n");
    } finally {
      if (state !== null) await closeRuntimeWriteSessionV03(state.session);
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("refuses dispatch when a later durable clock proves the admitted lease expired", async () => {
    const dispatch = vi.fn(async () => ({ disposition: "DISPATCHED" as const, observation: null }));
    const state = await admittedBroker(dispatch, {
      additional_event_envelopes: [{
        event_id: "event_s41_expired_dispatch_clock",
        recorded_at: "2026-08-24T10:05:00Z",
      }],
    });
    try {
      const clock = createRuntimeEventDraftV03({
        event_type: "run.clock-observed", source: "kernel", authority_ref: null,
        risk_tier: "T1", related_ids: [],
        payload: {
          clock_id: "clock_s41_expired_dispatch", observed_at: "2026-08-24T10:05:00Z",
          elapsed_ms: 300_000, reason: "terminal-use", task_ref: null,
          failure_ordinal: null, use_ref: "dispatch_s41_expired",
        },
      });
      if (clock === null) throw new Error("expiry clock fixture rejected");
      await expect(appendRuntimeEventV03(state.session, clock)).resolves.toMatchObject({
        ok: true, classification: "COMMITTED",
      });
      await expect(dispatchAdmittedActionV01(state.session, state.broker, state.admission.permit))
        .resolves.toEqual({ ok: false, error: "DISPATCH_LEASE_EXPIRED" });
      expect(dispatch).not.toHaveBeenCalled();
    } finally {
      await closeRuntimeWriteSessionV03(state.session);
    }
  });
});

describe("S41-E exact hard-limit and hot-loop boundaries", () => {
  it("rejects every bounded resource after a one-unit overshoot", () => {
    const plan = planV03();
    const cases = [
      ["max-loop-attempts", (input: ReturnType<typeof accountingInput>) => {
        input.consumed.loop_attempts = plan.limit_policy.max_loop_attempts; input.requested.loop_attempts = 1;
      }],
      ["max-elapsed-ms", (input: ReturnType<typeof accountingInput>) => {
        input.consumed.elapsed_ms = plan.limit_policy.max_elapsed_ms - plan.recovery_policy.reserve.max_elapsed_ms;
        input.requested.elapsed_ms = 1;
      }],
      ["max-tool-calls", (input: ReturnType<typeof accountingInput>) => {
        input.consumed.tool_calls = plan.limit_policy.max_tool_calls - plan.recovery_policy.reserve.max_tool_calls;
        input.requested.tool_calls = 1;
      }],
      ["max-output-bytes", (input: ReturnType<typeof accountingInput>) => {
        input.consumed.action_output_bytes = plan.limit_policy.max_output_bytes
          - plan.limit_policy.control_plane_output_reserve_bytes - plan.recovery_policy.reserve.max_output_bytes;
        input.requested.action_output_bytes = 1;
      }],
      ["max-tokens", (input: ReturnType<typeof accountingInput>) => {
        input.consumed.token_count = plan.limit_policy.max_tokens! - plan.recovery_policy.reserve.max_tokens!;
        input.requested.token_count = 1;
      }],
      ["max-cost", (input: ReturnType<typeof accountingInput>) => {
        input.consumed.cost_minor_units = plan.limit_policy.max_cost_minor_units! - plan.recovery_policy.reserve.max_cost_minor_units!;
        input.requested.cost_minor_units = 1;
      }],
      ["max-process-runtime", (input: ReturnType<typeof accountingInput>) => {
        input.requested.process_runtime_ms = plan.runtime_execution_policy.max_process_runtime_ms + 1;
      }],
      ["max-workers", (input: ReturnType<typeof accountingInput>) => {
        input.consumed.active_workers = plan.limit_policy.max_workers; input.requested.workers = 1;
      }],
    ] as const;
    for (const [limit, mutate] of cases) {
      const input = accountingInput(plan);
      mutate(input);
      expect(evaluateRuntimeLimitAccountingV04(input), limit).toMatchObject({
        ok: true,
        value: { admitted: false, violations: [{ limit_ref: limit }] },
      });
    }

    const control = accountingInput(plan);
    control.consumed.control_output_bytes = plan.limit_policy.control_plane_output_reserve_bytes;
    control.requested.control_output_bytes = 1;
    expect(evaluateRuntimeLimitAccountingV04(control)).toMatchObject({
      ok: true,
      value: { admitted: false, violations: [{ limit_ref: "max-output-bytes" }] },
    });
  });

  it("admits the exact action-output ceiling but preserves the control reserve", () => {
    const plan = planV03();
    const workCeiling = plan.limit_policy.max_output_bytes
      - plan.limit_policy.control_plane_output_reserve_bytes
      - plan.recovery_policy.reserve.max_output_bytes;
    const input = accountingInput(plan);
    input.requested.action_output_bytes = workCeiling;
    const exact = evaluateRuntimeLimitAccountingV04(input);
    expect(exact).toMatchObject({ ok: true, value: { admitted: true, remaining: { action_output_bytes: 0 } } });
    input.requested.action_output_bytes += 1;
    expect(evaluateRuntimeLimitAccountingV04(input)).toMatchObject({
      ok: true,
      value: { admitted: false, violations: [{ limit_ref: "max-output-bytes" }] },
    });
  });

  it("reports durable execution-attempt and per-task retry exhaustion without resetting either counter", () => {
    const plan = planV03();
    const input = accountingInput(plan);
    input.consumed.execution_attempts = plan.runtime_execution_policy.max_execution_attempts - 1;
    input.requested.execution_attempts = 1;
    const taskRef = input.requested.task_ref;
    const taskCeiling = Math.max(...plan.retry_policy.rules
      .filter((rule) => rule.task_ref === taskRef)
      .map((rule) => rule.max_task_executions));
    input.consumed.task_executions[taskRef] = taskCeiling - 1;
    input.requested.task_executions = 1;
    expect(evaluateRuntimeLimitAccountingV04(input)).toMatchObject({
      ok: true,
      value: {
        admitted: true,
        execution_attempts_exhausted: true,
        requested_task_executions_exhausted: true,
        remaining: { execution_attempts: 0, requested_task_executions: 0 },
      },
    });
    input.requested.execution_attempts = 2;
    expect(evaluateRuntimeLimitAccountingV04(input)).toMatchObject({ ok: true, value: { admitted: false } });
  });

  it("halts a deterministic retry hot-loop at the global loop ceiling", () => {
    const plan = planV03();
    const identity = {
      run_id: "run_s41_retry_hot_loop",
      task_ref: plan.tasks[0]!.id,
      failure_event_ref: { ledger_sequence: 17, event_hash: H("d") },
      failure_ordinal: 2,
      rule: { retryable: true, backoff: "exponential" as const, base_delay_ms: 50, max_delay_ms: 1_000 },
    };
    expect(scheduleRuntimeRetryV04(identity)).toEqual(scheduleRuntimeRetryV04(structuredClone(identity)));
    const input = accountingInput(plan);
    input.consumed.loop_attempts = plan.limit_policy.max_loop_attempts;
    input.requested.loop_attempts = 1;
    expect(evaluateRuntimeLimitAccountingV04(input)).toMatchObject({
      ok: true,
      value: { admitted: false, violations: [{ limit_ref: "max-loop-attempts" }] },
    });
  });
});

describe("S41-E recovery binding and phase drift schemas", () => {
  it.each([
    ["nonce", (event: ReturnType<typeof recoveryRequestEvent>) => { event.payload.resume_nonce_hash = "bad"; }],
    ["attempt ref", (event: ReturnType<typeof recoveryRequestEvent>) => { event.payload.previous_attempt_event_ref = { ledger_sequence: 0, event_hash: H("2") }; }],
    ["authority", (event: ReturnType<typeof recoveryRequestEvent>) => { event.authority_ref = null; }],
    ["plan", (event: ReturnType<typeof recoveryRequestEvent>) => { event.payload.plan_hash = "bad"; }],
    ["policy", (event: ReturnType<typeof recoveryRequestEvent>) => { event.payload.recovery_policy_hash = "bad"; }],
    ["manifest", (event: ReturnType<typeof recoveryRequestEvent>) => { event.payload.source_manifest_hash = "bad"; }],
  ])("rejects malformed %s binding before it can become durable", (_name, mutate) => {
    const event = recoveryRequestEvent();
    mutate(event);
    expect(RuntimeEventV04.safeParse(event).success).toBe(false);
  });

  it("rejects phase entry with an empty compensation set and a recovery attempt with fence drift", () => {
    const phase = {
      ...recoveryRequestEvent(),
      event_type: "run.compensation-phase-entered",
      source: "evaluator",
      authority_ref: null,
      payload: {
        request_revision: 1,
        request_event_hash: H("1"),
        pending_terminal: "failed",
        compensation_refs: [],
        freeze_event_hash: H("2"),
      },
    };
    expect(RuntimeEventV04.safeParse(phase).success).toBe(false);

    const attempt = {
      ...recoveryRequestEvent(),
      event_type: "execution.attempt-started",
      source: "kernel",
      authority_ref: null,
      payload: {
        attempt_id: "attempt_s41_adversarial_2",
        attempt_ordinal: 2,
        mode: "ordinary",
        previous_attempt_event_ref: { ledger_sequence: 3, event_hash: H("2") },
        resume_request_event_ref: { ledger_sequence: 9, event_hash: H("a") },
        resume_nonce_hash: H("1"),
        source_boundary_sequence: 8,
        source_boundary_head_hash: H("3"),
        source_manifest_hash: H("4"),
        plan_hash: H("5"),
        input_hash: H("6"),
        recovery_policy_hash: H("7"),
        authority_envelope_hash: H("8"),
        run_owner_lease_id: "owner_s41_adversarial_2",
        issued_clock_ref: { ledger_sequence: 8, event_hash: H("9") },
        deadline_elapsed_ms: 10_000,
        boot_id_hash: H("b"),
        monotonic_clock_id: "clock_s41_adversarial_2",
        previous_fence_epoch: 4,
        fence_epoch: 6,
      },
    };
    expect(RuntimeEventV04.safeParse(attempt).success).toBe(false);
  });

  it("keeps compensation failure and every closed unable reason schema-distinct", () => {
    const base = {
      ...recoveryRequestEvent(),
      event_type: "compensation.settled",
      source: "evaluator",
      authority_ref: null,
    };
    const unable = [
      "unknown-action-outcome", "safety-hold", "elapsed-budget-exhausted",
      "tool-call-budget-exhausted", "output-budget-exhausted",
      "token-budget-exhausted", "cost-budget-exhausted",
    ] as const;
    for (const unable_reason of unable) {
      expect(RuntimeEventV04.safeParse({
        ...base,
        payload: { compensation_ref: "compensation-s41", status: "unable", unable_reason, evidence_refs: [{ ledger_sequence: 1, event_hash: H("1") }] },
      }).success, unable_reason).toBe(true);
    }
    expect(RuntimeEventV04.safeParse({
      ...base,
      payload: { compensation_ref: "compensation-s41", status: "compensation-failed", unable_reason: null, evidence_refs: [{ ledger_sequence: 1, event_hash: H("1") }] },
    }).success).toBe(true);
    expect(RuntimeEventV04.safeParse({
      ...base,
      payload: { compensation_ref: "compensation-s41", status: "compensation-failed", unable_reason: "safety-hold", evidence_refs: [{ ledger_sequence: 1, event_hash: H("1") }] },
    }).success).toBe(false);
  });
});
