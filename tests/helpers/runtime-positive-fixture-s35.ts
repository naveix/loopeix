import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { hashCanonical, hashRawBytes } from "../../src/hash.js";
import {
  captureRunFileForRuntimeV02,
  issueAnchoredRunDirectoryReadCapabilityV02,
} from "../../src/io/runtime-file-capture-v02.js";
import { ResolvedRunPlanV02, type RuntimeProjectionInputV02 } from "../../src/schema/runtime.js";
import {
  buildTerminalObservationSnapshotV02,
  captureSyntheticAuthorityTrustContextForS35TestV02,
  hashTerminalObservationSnapshotV02,
  validateRuntimeProjectionInputV02,
} from "../../src/run/terminal-snapshot.js";
import { appendWorkActionAdmissionEvents } from "./runtime-admission-fixture-s35.js";

const PLAN_FIXTURE = join(
  process.cwd(),
  "tests/fixtures/compat/s35/v02/planned-run/resolved-run-plan.json",
);

const RUNTIME_SCHEMA_VERSIONS = {
  resolved_run_plan: "0.2",
  ledger_event: "0.2",
  run_manifest: "0.2",
  artifact_manifest: "0.2",
  redaction_derivative: "0.2",
  evidence_item: "0.2",
  human_authorization_proof: "0.2",
  authority_envelope: "0.2",
  agency_recommendation: "0.2",
  authority_revocation: "0.2",
  task_result: "0.2",
  manual_observation: "0.2",
  export_decision: "0.2",
  gate_result: "0.2",
  evaluation_result: "0.2",
  claim: "0.2",
  finding: "0.2",
  waiver: "0.2",
  gate_waiver_authority: "0.2",
} as const;

function jsonBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(`${JSON.stringify(value)}\n`);
}

function withCanonicalHash<T extends Record<string, unknown>>(
  value: T,
  key: "event_hash" | "manifest_hash",
): T & Record<typeof key, string> {
  return { ...value, [key]: hashCanonical(value) };
}

export type RuntimePositiveFixtureS35 = Readonly<{
  input: RuntimeProjectionInputV02;
  dispose: () => void;
}>;

export async function buildInitializedRuntimePositiveFixtureS35(options: Readonly<{
  malformedLedger?: boolean;
  forgedTrust?: boolean;
  ledgerPlanHashMismatch?: boolean;
  sealedOutcome?: "aborted" | "exhausted";
  frozenOutcome?: "aborted" | "exhausted";
  unprovenAbortFreeze?: boolean;
  invalidFreezeFenceEpoch?: boolean;
  invalidControlPlaneBudget?: boolean;
  completedLoopAttempts?: number;
  preSealSnapshotHash?: string;
  invalidSnapshotStage?: 2 | 3 | 4 | 5 | 6 | 8 | 9 | 10 | 11 | 12 | 13 | 14;
  secondaryInvalidSnapshotStage?: 2 | 3 | 4 | 5 | 6 | 8 | 9 | 10 | 11 | 12 | 13 | 14;
  postSealAction?: boolean;
  compensationPlan?: boolean;
  activeFailureProjection?: boolean;
  policyBlockProjection?: boolean;
  historicalCompensationViolation?: "request-in-flight-settled" | "phase-entry-active-settled";
  phaseBoundaryViolation?: "missing" | "wrong-reason";
}> = {}): Promise<RuntimePositiveFixtureS35> {
  let preSealSnapshotHash = options.preSealSnapshotHash;
  if (options.sealedOutcome !== undefined && preSealSnapshotHash === undefined && !options.unprovenAbortFreeze) {
    const prefix = await buildInitializedRuntimePositiveFixtureS35({
      frozenOutcome: options.sealedOutcome,
      completedLoopAttempts: options.completedLoopAttempts,
    });
    try {
      const validated = validateRuntimeProjectionInputV02(prefix.input);
      if (!validated.ok) throw new Error(`pre-seal validation failed: ${validated.error}`);
      const built = buildTerminalObservationSnapshotV02(validated.value);
      if (!built.ok) throw new Error(`pre-seal snapshot failed: ${built.error}`);
      preSealSnapshotHash = hashTerminalObservationSnapshotV02(built.value);
    } finally {
      prefix.dispose();
    }
  }
  const originalPlan = JSON.parse(readFileSync(PLAN_FIXTURE, "utf8")) as {
    run_id: string;
    required_control_plane_output_bytes: number;
    limit_policy: { max_output_bytes: number; control_plane_output_reserve_bytes: number };
    recovery_policy: { reserve: { max_output_bytes: number } };
    runtime_record_limits: { max_agency_recommendation_records: number };
    compensations: unknown[];
  };
  if (options.invalidControlPlaneBudget) originalPlan.required_control_plane_output_bytes = 1;
  const requestedInvalidStages = [options.invalidSnapshotStage, options.secondaryInvalidSnapshotStage]
    .filter((stage): stage is NonNullable<typeof stage> => stage !== undefined);
  const usesHistoricalCompensation = options.historicalCompensationViolation !== undefined
    || options.phaseBoundaryViolation !== undefined;
  if (options.compensationPlan || usesHistoricalCompensation || requestedInvalidStages.some((stage) => stage >= 8)) {
    originalPlan.compensations = [{
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
    }];
    if (requestedInvalidStages.includes(8)) originalPlan.compensations.push({
      id: "restore-diagnosis",
      for_task: "diagnose-root-cause",
      for_effect: "effect-diagnose-root-cause",
      action_task: "restore-task",
      preconditions: [{
        source: "effect",
        task_ref: "diagnose-root-cause",
        effect_ref: "effect-diagnose-root-cause",
        outcome: "committed",
      }],
      verification_refs: ["verify-restore"],
      may_fail: true,
    });
    originalPlan.runtime_record_limits.max_agency_recommendation_records = requestedInvalidStages.includes(8) ? 80 : 72;
  }
  ResolvedRunPlanV02.parse(originalPlan);
  const usesCompensationPlan = options.compensationPlan
    || usesHistoricalCompensation
    || requestedInvalidStages.some((stage) => stage >= 8);
  const planBytes = options.invalidControlPlaneBudget || usesCompensationPlan
    ? jsonBytes(originalPlan)
    : new Uint8Array(readFileSync(PLAN_FIXTURE));
  const plan = originalPlan;
  const planHash = hashRawBytes(planBytes);
  const runtimeRecordBytes = new Map<string, Uint8Array>();
  const initialized = withCanonicalHash({
    schema_version: "0.2",
    event_id: "event_initialized_s35",
    run_id: plan.run_id,
    sequence: 1,
    recorded_at: "2026-08-12T12:34:56Z",
    event_type: "run.initialized",
    source: "kernel",
    authority_ref: null,
    risk_tier: "T1",
    related_ids: [],
    previous_event_hash: null,
    payload: {
      plan_hash: options.ledgerPlanHashMismatch ? `sha256:${"0".repeat(64)}` : planHash,
      initial_fence_epoch: 0,
      runtime_schema_versions: RUNTIME_SCHEMA_VERSIONS,
    },
  }, "event_hash");
  const events: Array<Record<string, unknown>> = [initialized];
  const appendEvent = (
    eventType: string,
    source: string,
    authorityRef: string | null,
    payload: Record<string, unknown>,
    riskTier = "T2",
  ): Record<string, unknown> & {
    sequence: number;
    event_hash: string;
    payload: Record<string, unknown>;
  } => {
    const previous = events.at(-1)! as typeof initialized;
    const event = withCanonicalHash({
      schema_version: "0.2",
      event_id: `event_snapshot_stage_${options.invalidSnapshotStage}_${events.length + 1}_s35`,
      run_id: plan.run_id,
      sequence: events.length + 1,
      recorded_at: `2026-08-12T12:${String(35 + events.length).padStart(2, "0")}:00Z`,
      event_type: eventType,
      source,
      authority_ref: authorityRef,
      risk_tier: riskTier,
      related_ids: [],
      previous_event_hash: previous.event_hash,
      payload,
    }, "event_hash");
    events.push(event);
    return event;
  };
  const ledgerRef = (event: { sequence: number; event_hash: string }) => ({
    ledger_sequence: event.sequence,
    event_hash: event.event_hash,
  });
  const appendActiveAction = () => {
    const generated = appendWorkActionAdmissionEvents([initialized], {
      taskRef: "diagnose-root-cause",
      actionId: "action_historical_compensation_s35",
      planHash,
    });
    const clock = appendEvent(
      generated.clock.event_type, generated.clock.source, generated.clock.authority_ref,
      generated.clock.payload, generated.clock.risk_tier,
    );
    const admission = appendEvent(
      generated.admission.event_type, generated.admission.source, generated.admission.authority_ref,
      { ...generated.admission.payload, admission_clock_ref: ledgerRef(clock) }, generated.admission.risk_tier,
    );
    const started = appendEvent("task.execution-started", "adapter", null, {
      action_id: admission.payload.action_id,
      task_ref: admission.payload.task_ref,
      admission_ref: ledgerRef(admission),
      adapter_invocation_id: "adapter_invocation_historical_compensation_s35",
      action_proposal_id: admission.payload.action_proposal_id,
      action_proposal_hash: admission.payload.action_proposal_hash,
      action_actor_ref: admission.payload.action_actor_ref,
      action_actor_stable_identity_hash: admission.payload.action_actor_stable_identity_hash,
      on_behalf_of_chain_hash: admission.payload.on_behalf_of_chain_hash,
      repository_root_ref: admission.payload.repository_root_ref,
      repository_base_ref_identity_hash: admission.payload.repository_base_ref_identity_hash,
      repository_pre_state_hash: admission.payload.repository_pre_state_hash,
      authorized_change_set_hash: admission.payload.authorized_change_set_hash,
      normalized_dispatch_hash: admission.payload.normalized_dispatch_hash,
      policy_action_kind: admission.payload.policy_action_kind,
      action_approval_class: admission.payload.action_approval_class,
    });
    return { admission, started };
  };
  const appendActionSettlement = (
    admission: ReturnType<typeof appendEvent>,
    terminal: ReturnType<typeof appendEvent>,
  ) => {
    const hash = `sha256:${"a".repeat(64)}`;
    const head = { algorithm: "sha1", value: "a".repeat(40) };
    const repositoryStateFields = {
      repository_root_ref: "repository_1",
      base_ref_identity_hash: hash,
      head,
      merge_base: head,
      head_state_hash: hash,
      tracked_diff_hash: hash,
      staged_diff_hash: hash,
      untracked_content_hash: hash,
      submodule_state_hash: hash,
    };
    const repositoryStateHash = hashCanonical({ purpose: "repository-state-v02", ...repositoryStateFields });
    const repositoryPostState = { ...repositoryStateFields, repository_state_hash: repositoryStateHash };
    const observedFields = {
      repository_root_ref: "repository_1",
      base_ref_identity_hash: hash,
      repository_pre_state_hash: repositoryStateHash,
      repository_post_state_hash: repositoryStateHash,
      head_before: head,
      head_after: head,
      changes: [],
    };
    const observedChangeSetHash = hashCanonical({ purpose: "observed-repository-change-set-v02", ...observedFields });
    return appendEvent("task.action-settled", "kernel", null, {
      action_id: admission.payload.action_id,
      task_ref: admission.payload.task_ref,
      terminal_event_ref: ledgerRef(terminal),
      action_proposal_id: admission.payload.action_proposal_id,
      action_proposal_hash: admission.payload.action_proposal_hash,
      action_actor_ref: admission.payload.action_actor_ref,
      action_actor_stable_identity_hash: admission.payload.action_actor_stable_identity_hash,
      on_behalf_of_chain_hash: admission.payload.on_behalf_of_chain_hash,
      repository_root_ref: "repository_1",
      repository_base_ref_identity_hash: hash,
      repository_pre_state_hash: repositoryStateHash,
      authorized_change_set_hash: admission.payload.authorized_change_set_hash,
      normalized_dispatch_hash: admission.payload.normalized_dispatch_hash,
      repository_post_state: repositoryPostState,
      repository_post_state_hash: repositoryStateHash,
      observed_change_set: { ...observedFields, observed_change_set_hash: observedChangeSetHash },
      observed_change_set_hash: observedChangeSetHash,
      repository_transition_status: "unchanged",
      effect_outcomes: [{
        effect_ref: "effect-diagnose-root-cause",
        outcome: "not-committed",
        outcome_event_ref: ledgerRef(terminal),
      }],
      policy_action_kind: admission.payload.policy_action_kind,
      action_approval_class: admission.payload.action_approval_class,
    });
  };
  let previousAttempt: { sequence: number; event_hash: string } | null = null;
  for (let ordinal = 1; ordinal <= (options.completedLoopAttempts ?? 0); ordinal += 1) {
    const prefix = events.at(-1)! as typeof initialized;
    const attempt = withCanonicalHash({
      schema_version: "0.2",
      event_id: `event_attempt_${ordinal}_s35`,
      run_id: plan.run_id,
      sequence: events.length + 1,
      recorded_at: `2026-08-12T12:35:0${ordinal}Z`,
      event_type: "loop.attempt-completed",
      source: "kernel",
      authority_ref: null,
      risk_tier: "T1",
      related_ids: [],
      previous_event_hash: prefix.event_hash,
      payload: {
        attempt_ordinal: ordinal,
        previous_attempt_event_ref: previousAttempt === null ? null : {
          ledger_sequence: previousAttempt.sequence,
          event_hash: previousAttempt.event_hash,
        },
        prefix_sequence: prefix.sequence,
        prefix_head_hash: prefix.event_hash,
        work_action_refs: [],
        progress_observation_refs: [],
      },
    }, "event_hash");
    events.push(attempt);
    previousAttempt = attempt;
  }
  for (const invalidSnapshotStage of requestedInvalidStages) {
    if (invalidSnapshotStage >= 8) {
      const ref = (event: { sequence: number; event_hash: string }) => ({
        ledger_sequence: event.sequence,
        event_hash: event.event_hash,
      });
      const appendCommittedEffect = () => appendEvent("effect.outcome", "adapter", null, {
        task_ref: "implement-change",
        effect_ref: "effect-implement-change",
        action_id: "action_implement_change_s35",
        outcome: "committed",
        evidence_refs: [],
      });
      const appendAbortFreeze = () => {
        const abort = appendEvent("control.abort-requested", "operator", "operator_s35", {
          request_id: "abort_request_snapshot_stage_s35",
          requested_by: "operator",
          reason_code: "operator-requested",
          policy_decision_ref: null,
          evidence_refs: [],
        }, "T4");
        return appendEvent("run.terminal-freeze-entered", "evaluator", null, {
          revision: 1,
          candidate: "aborted",
          candidate_evidence_refs: [ref(abort)],
          fence_epoch: options.invalidFreezeFenceEpoch ? 1 : 0,
        }, "T1");
      };
      const appendExhaustionFreeze = () => {
        const ceiling = plan.limit_policy.max_output_bytes
          - plan.limit_policy.control_plane_output_reserve_bytes
          - plan.recovery_policy.reserve.max_output_bytes;
        const limit = appendEvent("limit.admission-blocked", "policy-enforcement-point", "pep_s35", {
          request_id: "limit_request_snapshot_stage_s35",
          task_ref: "diagnose-root-cause",
          phase: "work",
          compensation_ref: null,
          request_kind: "artifact-write",
          request_hash: `sha256:${"e".repeat(64)}`,
          violations: [{ limit_ref: "max-output-bytes", consumed: ceiling, requested: 1, ceiling }],
        });
        return appendEvent("run.terminal-freeze-entered", "evaluator", null, {
          revision: 1,
          candidate: "exhausted",
          candidate_evidence_refs: [ref(limit)],
          fence_epoch: options.invalidFreezeFenceEpoch ? 1 : 0,
        }, "T1");
      };
      const appendRequest = (
        freeze: { sequence: number; event_hash: string },
        pendingTerminal: "aborted" | "exhausted" = "aborted",
        compensationRefs = ["restore-workspace"],
        freezeEventHash = freeze.event_hash,
      ) => appendEvent("run.compensation-requested", "evaluator", null, {
        revision: 1,
        pending_terminal: pendingTerminal,
        activation_reason: pendingTerminal === "aborted" ? "abort-recovery" : "terminal-exhaustion",
        compensation_refs: compensationRefs,
        effect_evidence_refs: [ref(freeze)],
        freeze_event_hash: freezeEventHash,
      }, "T1");
      const appendPhase = (
        freeze: { sequence: number; event_hash: string },
        request: { sequence: number; event_hash: string },
        pendingTerminal: "aborted" | "failed" | "exhausted" = "aborted",
        compensationRefs = ["restore-workspace"],
      ) => {
        appendEvent("run.fence-advanced", "policy-enforcement-point", "pep_s35", {
          previous_fence_epoch: 0,
          fence_epoch: 1,
          reason: "recovery-boundary",
          evidence_refs: [ref(request)],
        });
        return appendEvent("run.compensation-phase-entered", "evaluator", null, {
        request_revision: 1,
        request_event_hash: request.event_hash,
        pending_terminal: pendingTerminal,
        compensation_refs: compensationRefs,
        freeze_event_hash: freeze.event_hash,
        }, "T1");
      };

      if (invalidSnapshotStage === 8) {
        const freeze = appendAbortFreeze();
        appendRequest(freeze, "aborted", ["restore-diagnosis"]);
      } else if (invalidSnapshotStage === 9) {
        appendCommittedEffect();
        const freeze = appendAbortFreeze();
        appendRequest(freeze, "aborted", ["restore-workspace"], `sha256:${"0".repeat(64)}`);
      } else if (invalidSnapshotStage === 10) {
        appendCommittedEffect();
        const freeze = appendExhaustionFreeze();
        const request = appendRequest(freeze, "exhausted");
        const phase = appendPhase(freeze, request, "exhausted");
        appendEvent("run.compensation-candidate-escalated", "evaluator", null, {
          previous_pending_terminal: "exhausted",
          pending_terminal: "failed",
          activation_reason: "terminal-failure",
          compensation_refs: ["restore-workspace"],
          previous_candidate_event_hash: `sha256:${"0".repeat(64)}`,
          candidate_evidence_refs: [ref(phase)],
        }, "T1");
      } else if (invalidSnapshotStage === 11) {
        appendCommittedEffect();
        const freeze = appendAbortFreeze();
        const request = appendRequest(freeze);
        appendPhase(freeze, request, "failed");
      } else if (invalidSnapshotStage === 12) {
        appendCommittedEffect();
        const freeze = appendAbortFreeze();
        appendRequest(freeze, "aborted", ["unknown-compensation"]);
      } else if (invalidSnapshotStage === 13) {
        appendEvent("compensation.settled", "evaluator", null, {
          compensation_ref: "unknown-compensation",
          status: "compensation-failed",
          unable_reason: null,
          evidence_refs: [ref(initialized)],
        }, "T1");
      } else {
        appendCommittedEffect();
        const existingFreeze = events.findLast((event) => event.event_type === "run.terminal-freeze-entered") as
          | { sequence: number; event_hash: string }
          | undefined;
        const freeze = existingFreeze ?? appendAbortFreeze();
        const existingRequest = events.findLast((event) => event.event_type === "run.compensation-requested") as
          | { sequence: number; event_hash: string; payload: Record<string, unknown> }
          | undefined;
        const request = existingRequest ?? appendRequest(freeze);
        const generated = appendWorkActionAdmissionEvents([initialized], {
          taskRef: "diagnose-root-cause",
          actionId: "action_active_worker_s35",
          planHash,
        });
        const clock = appendEvent(
          generated.clock.event_type,
          generated.clock.source,
          generated.clock.authority_ref,
          generated.clock.payload,
          generated.clock.risk_tier,
        );
        const admission = appendEvent(
          generated.admission.event_type,
          generated.admission.source,
          generated.admission.authority_ref,
          { ...generated.admission.payload, admission_clock_ref: ref(clock) },
          generated.admission.risk_tier,
        );
        appendEvent("task.execution-started", "adapter", null, {
          action_id: admission.payload.action_id,
          task_ref: admission.payload.task_ref,
          admission_ref: ref(admission),
          adapter_invocation_id: "adapter_invocation_active_worker_s35",
          action_proposal_id: admission.payload.action_proposal_id,
          action_proposal_hash: admission.payload.action_proposal_hash,
          action_actor_ref: admission.payload.action_actor_ref,
          action_actor_stable_identity_hash: admission.payload.action_actor_stable_identity_hash,
          on_behalf_of_chain_hash: admission.payload.on_behalf_of_chain_hash,
          repository_root_ref: admission.payload.repository_root_ref,
          repository_base_ref_identity_hash: admission.payload.repository_base_ref_identity_hash,
          repository_pre_state_hash: admission.payload.repository_pre_state_hash,
          authorized_change_set_hash: admission.payload.authorized_change_set_hash,
          normalized_dispatch_hash: admission.payload.normalized_dispatch_hash,
          policy_action_kind: admission.payload.policy_action_kind,
          action_approval_class: admission.payload.action_approval_class,
        });
        appendEvent("run.fence-advanced", "policy-enforcement-point", "pep_s35", {
          previous_fence_epoch: 0,
          fence_epoch: 1,
          reason: "recovery-boundary",
          evidence_refs: [ref(request)],
        });
        appendEvent("run.compensation-phase-entered", "evaluator", null, {
          request_revision: request.payload.revision,
          request_event_hash: request.event_hash,
          pending_terminal: request.payload.pending_terminal,
          compensation_refs: request.payload.compensation_refs,
          freeze_event_hash: request.payload.freeze_event_hash,
        }, "T1");
      }
    } else {
    const previous = events.at(-1)! as typeof initialized;
    const stageEvent = invalidSnapshotStage === 2 ? {
      event_type: "task.progress-observed",
      source: "evaluator",
      authority_ref: null,
      payload: {
        observation_ref: "unknown-progress-ref",
        task_ref: null,
        pending_attempt_ordinal: 1,
        sample: {
          status: "source-missing",
          sample_ref: null,
          sample_hash: null,
          value_status: "value-unparseable",
          sample_value: null,
        },
      },
    } : invalidSnapshotStage === 3 ? {
      event_type: "gate.result-required",
      source: "kernel",
      authority_ref: null,
      payload: {
        gate_ref: "unknown-gate-ref",
        requirement_revision: 1,
        applicability: "always",
        compensation_ref: null,
        prerequisite_set_hash: hashCanonical([]),
        prerequisite_refs: [],
      },
    } : invalidSnapshotStage === 4 ? {
      event_type: "limit.admission-blocked",
      source: "policy-enforcement-point",
      authority_ref: "pep_s35",
      payload: {
        request_id: "invalid_limit_request_s35",
        task_ref: "diagnose-root-cause",
        phase: "work",
        compensation_ref: null,
        request_kind: "artifact-write",
        request_hash: `sha256:${"d".repeat(64)}`,
        violations: [{ limit_ref: "max-tool-calls", consumed: 1, requested: 1, ceiling: 1 }],
      },
    } : {
      event_type: "task.action-outcome-unknown",
      source: "adapter",
      authority_ref: null,
      payload: {
        action_id: `action_invalid_stage_${invalidSnapshotStage}_s35`,
        task_ref: invalidSnapshotStage === 5 ? "unknown-task-ref" : "diagnose-root-cause",
        admission_ref: { ledger_sequence: initialized.sequence, event_hash: initialized.event_hash },
        detection_reason: "process-status-unavailable",
        observation_ref: { ledger_sequence: initialized.sequence, event_hash: initialized.event_hash },
        evidence_refs: [],
      },
    };
    const event = withCanonicalHash({
      schema_version: "0.2",
      event_id: `event_invalid_stage_${invalidSnapshotStage}_s35`,
      run_id: plan.run_id,
      sequence: events.length + 1,
      recorded_at: "2026-08-12T12:36:00Z",
      risk_tier: "T2",
      related_ids: [],
      previous_event_hash: previous.event_hash,
      ...stageEvent,
    }, "event_hash");
    events.push(event);
    }
  }
  if (usesHistoricalCompensation) {
    const effect = appendEvent("effect.outcome", "adapter", null, {
      task_ref: "implement-change",
      effect_ref: "effect-implement-change",
      action_id: "action_implement_change_historical_s35",
      outcome: "committed",
      evidence_refs: [],
    });
    const abort = appendEvent("control.abort-requested", "operator", "operator_s35", {
      request_id: "abort_request_historical_s35",
      requested_by: "operator",
      reason_code: "operator-requested",
      policy_decision_ref: null,
      evidence_refs: [],
    }, "T4");
    const freeze = appendEvent("run.terminal-freeze-entered", "evaluator", null, {
      revision: 1,
      candidate: "aborted",
      candidate_evidence_refs: [ledgerRef(abort)],
      fence_epoch: 0,
    }, "T1");
    const appendRequest = () => appendEvent("run.compensation-requested", "evaluator", null, {
      revision: 1,
      pending_terminal: "aborted",
      activation_reason: "abort-recovery",
      compensation_refs: ["restore-workspace"],
      effect_evidence_refs: [ledgerRef(effect)],
      freeze_event_hash: freeze.event_hash,
    }, "T1");
    let active: ReturnType<typeof appendActiveAction> | undefined;
    if (options.historicalCompensationViolation === "request-in-flight-settled") active = appendActiveAction();
    const request = appendRequest();
    if (options.historicalCompensationViolation === "request-in-flight-settled") {
      appendActionSettlement(active!.admission, active!.started);
    } else {
      active = options.historicalCompensationViolation === "phase-entry-active-settled"
        ? appendActiveAction()
        : undefined;
      if (options.historicalCompensationViolation === "phase-entry-active-settled") {
        appendEvent("run.fence-advanced", "policy-enforcement-point", "pep_s35", {
          previous_fence_epoch: 0,
          fence_epoch: 1,
          reason: "recovery-boundary",
          evidence_refs: [ledgerRef(request)],
        });
      } else if (options.phaseBoundaryViolation === "wrong-reason") {
        appendEvent("run.fence-advanced", "policy-enforcement-point", "pep_s35", {
          previous_fence_epoch: 0,
          fence_epoch: 1,
          reason: "lease-revoked",
          evidence_refs: [ledgerRef(request)],
        });
      }
      const phase = appendEvent("run.compensation-phase-entered", "evaluator", null, {
        request_revision: 1,
        request_event_hash: request.event_hash,
        pending_terminal: "aborted",
        compensation_refs: ["restore-workspace"],
        freeze_event_hash: freeze.event_hash,
      }, "T1");
      if (active !== undefined) appendActionSettlement(active.admission, active.started);
      void phase;
    }
  }
  if (options.activeFailureProjection) {
    const generated = appendWorkActionAdmissionEvents([initialized], {
      taskRef: "diagnose-root-cause",
      actionId: "action_failure_s35",
      planHash,
    });
    const clock = appendEvent(
      generated.clock.event_type,
      generated.clock.source,
      generated.clock.authority_ref,
      generated.clock.payload,
      generated.clock.risk_tier,
    );
    const admission = appendEvent(
      generated.admission.event_type,
      generated.admission.source,
      generated.admission.authority_ref,
      { ...generated.admission.payload, admission_clock_ref: {
        ledger_sequence: clock.sequence,
        event_hash: clock.event_hash,
      } },
      generated.admission.risk_tier,
    );
    const resultId = "result_failure_s35";
    const resultPath = `task-results/${resultId}.json`;
    const resultPreimage = {
      schema_version: "0.2",
      result_id: resultId,
      run_id: plan.run_id,
      plan_hash: planHash,
      action_id: admission.payload.action_id,
      task_ref: admission.payload.task_ref,
      adapter_invocation_id: "adapter_invocation_failure_s35",
      status: "failed",
      failure_class: "invalid-input",
      observation: { kind: "generic", output_hash: `sha256:${"b".repeat(64)}` },
      capture_gap_codes: [],
    };
    const resultHash = hashCanonical(resultPreimage);
    runtimeRecordBytes.set(resultPath, jsonBytes({ ...resultPreimage, record_hash: resultHash }));
    appendEvent("task.execution-failed", "adapter", null, {
      action_id: admission.payload.action_id,
      task_ref: admission.payload.task_ref,
      admission_ref: { ledger_sequence: admission.sequence, event_hash: admission.event_hash },
      result_id: resultId,
      result_path: resultPath,
      result_hash: resultHash,
      output_bytes: 0,
      tool_calls: 0,
      token_count: 0,
      observed_cost: {
        capture: "not-applicable",
        cost_minor_units: 0,
        cost_currency: null,
        cost_minor_units_after: 0,
      },
      action_output_bytes_after: 0,
      tool_calls_after: 0,
      token_count_after: 0,
      failure_class: "invalid-input",
      failure_ordinal: 1,
      failure_clock_ref: { ledger_sequence: clock.sequence, event_hash: clock.event_hash },
      retry_safety_evidence_refs: [],
    });
  }
  if (options.policyBlockProjection) {
    const generated = appendWorkActionAdmissionEvents([initialized], {
      taskRef: "diagnose-root-cause",
      actionId: "action_policy_block_s35",
      planHash,
    });
    const generatedDecision = generated.events.find((event) => event.event_type === "policy.decision-recorded");
    if (generatedDecision === undefined) throw new Error("policy-block fixture did not generate a decision");
    const originalPayload = generatedDecision.payload;
    const proposal = {
      ...(originalPayload.action_proposal as Record<string, unknown>),
      policy_action_kind: "approval-contract-edit",
      action_approval_class: "blocked",
    };
    const { action_proposal_hash: _ignored, ...proposalPreimage } = proposal;
    const actionProposalHash = hashCanonical({ purpose: "action-proposal-v02", ...proposalPreimage });
    proposal.action_proposal_hash = actionProposalHash;
    appendEvent("policy.decision-recorded", "policy-enforcement-point", generatedDecision.authority_ref, {
      ...originalPayload,
      authority_envelope_ref: {
        record_kind: "authority-envelope",
        record_id: "envelope_1",
        record_event_ref: { ledger_sequence: initialized.sequence, event_hash: initialized.event_hash },
      },
      action_proposal: proposal,
      action_proposal_hash: actionProposalHash,
      policy_action_kind: "approval-contract-edit",
      action_approval_class: "blocked",
      reviewed_through_ref: { ledger_sequence: initialized.sequence, event_hash: initialized.event_hash },
      decision: "hold",
      decision_disposition: "non-resumable",
    });
  }
  const terminalOutcome = options.sealedOutcome ?? options.frozenOutcome;
  if (terminalOutcome !== undefined) {
    if (!options.unprovenAbortFreeze) {
      if (terminalOutcome === "aborted") {
        appendEvent("control.abort-requested", "operator", "operator_s35", {
        request_id: "abort_request_s35",
        requested_by: "operator",
        reason_code: "operator-requested",
        policy_decision_ref: null,
        evidence_refs: [],
        }, "T4");
      } else {
        const ceiling = plan.limit_policy.max_output_bytes
          - plan.limit_policy.control_plane_output_reserve_bytes
          - plan.recovery_policy.reserve.max_output_bytes;
        appendEvent("limit.admission-blocked", "policy-enforcement-point", "pep_s35", {
            request_id: "limit_request_s35",
            task_ref: "diagnose-root-cause",
            phase: "work",
            compensation_ref: null,
            request_kind: "artifact-write",
            request_hash: `sha256:${"e".repeat(64)}`,
            violations: [{ limit_ref: "max-output-bytes", consumed: ceiling, requested: 1, ceiling }],
        });
      }
    }
    const previous = events.at(-1)! as typeof initialized;
    const freeze = appendEvent("run.terminal-freeze-entered", "evaluator", null, {
        revision: 1,
        candidate: terminalOutcome,
        candidate_evidence_refs: [{ ledger_sequence: previous.sequence, event_hash: previous.event_hash }],
        fence_epoch: options.invalidFreezeFenceEpoch ? 1 : 0,
    }, "T1");
    if (options.sealedOutcome !== undefined) {
      const seal = appendEvent("run.terminal-sealed", "evaluator", null, {
        outcome: options.sealedOutcome,
        pre_seal_ledger_sequence: freeze.sequence,
        pre_seal_ledger_head_hash: freeze.event_hash,
        pre_seal_snapshot_hash: preSealSnapshotHash ?? `sha256:${"f".repeat(64)}`,
        previous_fence_epoch: 0,
        fence_epoch: 1,
      }, "T1");
      if (options.postSealAction) {
        appendEvent("run.clock-observed", "kernel", null, {
            clock_id: "clock_post_seal_s35",
            observed_at: "2026-08-12T12:35:00Z",
            elapsed_ms: 4_000,
            reason: "terminal-use",
            task_ref: null,
            failure_ordinal: null,
            use_ref: "post_seal_use_s35",
        }, "T1");
      }
    }
  }
  const ledgerBytes = options.malformedLedger
    ? new TextEncoder().encode("{]\n")
    : new TextEncoder().encode(`${events.map((event) => JSON.stringify(event)).join("\n")}\n`);
  const head = events.at(-1)! as typeof initialized;
  const manifestHead = options.postSealAction
    ? events.find((event) => event.event_type === "run.terminal-sealed")! as typeof initialized
    : head;

  const artifactManifest = withCanonicalHash({
    schema_version: "0.2",
    run_id: plan.run_id,
    plan_hash: planHash,
    projection_event_ref: { ledger_sequence: manifestHead.sequence, event_hash: manifestHead.event_hash },
    ledger_sequence: manifestHead.sequence,
    ledger_head_hash: manifestHead.event_hash,
    artifacts: [],
  }, "manifest_hash");
  const artifactManifestBytes = jsonBytes(artifactManifest);

  const fileInventory = [
    {
      path: "artifact-manifest.json",
      family: "projection",
      required: true,
      exists: true,
      mode: 384,
      size_bytes: artifactManifestBytes.byteLength,
      hash: hashRawBytes(artifactManifestBytes),
    },
    {
      path: "ledger.jsonl",
      family: "primary",
      required: true,
      exists: true,
      mode: 384,
      size_bytes: ledgerBytes.byteLength,
      hash: hashRawBytes(ledgerBytes),
    },
    {
      path: "resolved-run-plan.json",
      family: "primary",
      required: true,
      exists: true,
      mode: 384,
      size_bytes: planBytes.byteLength,
      hash: planHash,
    },
    ...[...runtimeRecordBytes].map(([path, bytes]) => ({
      path,
      family: "record" as const,
      required: true,
      exists: true,
      mode: 384,
      size_bytes: bytes.byteLength,
      hash: hashRawBytes(bytes),
    })),
  ].sort((left, right) => Buffer.compare(Buffer.from(left.path, "utf8"), Buffer.from(right.path, "utf8")));
  const hasCompensationPhase = events.some((event) => event.event_type === "run.compensation-phase-entered");
  const hasTerminalFreeze = events.some((event) => event.event_type === "run.terminal-freeze-entered");
  const runManifest = withCanonicalHash({
    schema_version: "0.2",
    run_id: plan.run_id,
    plan_hash: planHash,
    execution_profile: "bounded-v02",
    schema_versions: RUNTIME_SCHEMA_VERSIONS,
    run_state: options.sealedOutcome !== undefined
      ? "sealed"
      : hasCompensationPhase
        ? "compensating"
        : options.frozenOutcome !== undefined || hasTerminalFreeze
          ? "frozen"
          : events.length === 1 ? "initialized" : "running",
    created_at: initialized.recorded_at,
    projection_event_ref: { ledger_sequence: manifestHead.sequence, event_hash: manifestHead.event_hash },
    ledger_sequence: manifestHead.sequence,
    ledger_head_hash: manifestHead.event_hash,
    current_fence_epoch: options.sealedOutcome === undefined ? 0 : 1,
    terminal: options.sealedOutcome === undefined ? null : {
      outcome: options.sealedOutcome,
      snapshot_hash: preSealSnapshotHash ?? `sha256:${"f".repeat(64)}`,
      seal_event_ref: { ledger_sequence: manifestHead.sequence, event_hash: manifestHead.event_hash },
    },
    file_inventory: fileInventory,
  }, "manifest_hash");
  const runManifestBytes = jsonBytes(runManifest);

  const root = mkdtempSync("/private/tmp/loopeix-s35-runtime-positive-");
  const files = new Map<string, Uint8Array>([
    ["resolved-run-plan.json", planBytes],
    ["ledger.jsonl", ledgerBytes],
    ["run-manifest.json", runManifestBytes],
    ["artifact-manifest.json", artifactManifestBytes],
    ...runtimeRecordBytes,
  ]);
  for (const [name, bytes] of files) {
    const path = join(root, name);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, bytes, { mode: 0o600 });
  }

  const capability = await issueAnchoredRunDirectoryReadCapabilityV02(root);
  if (!capability.ok) throw new Error(`fixture root capture failed: ${capability.error}`);
  const captures = new Map<string, Awaited<ReturnType<typeof captureRunFileForRuntimeV02>> extends { ok: true; value: infer V } ? V : never>();
  for (const name of files.keys()) {
    const captured = await captureRunFileForRuntimeV02({
      anchored_run_directory: capability.value,
      relative_path: name,
      max_bytes: 4_194_304,
    });
    if (!captured.ok) throw new Error(`fixture file capture failed: ${name}: ${captured.error}`);
    captures.set(name, captured.value);
  }

  const metadata = new Map([...captures].map(([name, capture]) => [name, capture.metadata]));
  const trust = options.forgedTrust
    ? Object.freeze({})
    : captureSyntheticAuthorityTrustContextForS35TestV02("s35-valid-complete-authority-trust-v01");
  return {
    input: {
      resolved_run_plan_bytes: captures.get("resolved-run-plan.json")!.bytes,
      authority_trust_context: trust as RuntimeProjectionInputV02["authority_trust_context"],
      primary_ledger_bytes: captures.get("ledger.jsonl")!.bytes,
      run_manifest_bytes: captures.get("run-manifest.json")!.bytes,
      artifact_manifest_bytes: captures.get("artifact-manifest.json")!.bytes,
      record_bytes_by_path: new Map([...runtimeRecordBytes.keys()].map((path) => [path, captures.get(path)!.bytes])),
      control_projection_bytes_by_path: new Map(),
      file_metadata_by_path: metadata,
    },
    dispose: () => rmSync(root, { recursive: true, force: true }),
  };
}
