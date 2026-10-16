import { generateKeyPairSync } from "node:crypto";
import { chmodSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import { S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02 } from "../../src/run/action-classifier-policy-v02.js";
import { inspectRuntimePlanV03, projectRuntimePlanV03 } from "../../src/run/project-plan-v03.js";
import {
  captureRuntimeClockSourceV04,
  observeRuntimeClockV04,
} from "../../src/run/runtime-clock-observation-v04.js";
import { writeRuntimeCompensationV04 } from "../../src/run/runtime-compensation-write-v04.js";
import { captureRuntimeFileStoreV04 } from "../../src/run/runtime-file-store-v04.js";
import { inspectRuntimeLedgerV04 } from "../../src/run/runtime-ledger-v04.js";
import { buildRunManifestV04, inspectRunManifestV04 } from "../../src/run/runtime-manifest-v04.js";
import { captureAuthorityTrustContextV02 } from "../../src/run/runtime-record-admission-v02.js";
import {
  buildRuntimeTerminalProjectionV04,
  evaluateRuntimeTerminalV04,
  type RuntimeTerminalProjectionV04,
} from "../../src/run/runtime-terminal-v04.js";
import { ResolvedRunPlanV02, RuntimeEventV02, type ResolvedRunPlanV02Value } from "../../src/schema/runtime.js";
import { captureRuntimeProfileRegistryV03 } from "../../src/schema/runtime-plan-v03.js";
import { RuntimeEventV04, type RuntimeEventV04Value } from "../../src/schema/runtime-v04.js";
import { createRuntimeCommandFixtureV04 } from "../helpers/runtime-v04-command-fixture.js";

const UTF8 = new TextEncoder();
const H = (character: string): string => `sha256:${character.repeat(64)}`;
const INVENTORY = {
  resolved_run_plan: "0.3", ledger_event: "0.4", run_manifest: "0.4",
  artifact_manifest: "0.2", redaction_derivative: "0.2", human_authorization_proof: "0.2",
  authority_envelope: "0.2", agency_recommendation: "0.2", authority_revocation: "0.2",
  task_result: "0.2", manual_observation: "0.2", export_decision: "0.2",
  evidence_item: "0.2", gate_result: "0.2", evaluation_result: "0.2", claim: "0.2",
  finding: "0.2", waiver: "0.2", gate_waiver_authority: "0.2", summary_artifact: "0.1",
} as const;

type Decision = "request-compensation" | "revise-compensation-request" | "enter-compensation" | "escalate-compensation" | "settle-compensation";

function ref(event: RuntimeEventV04Value) {
  return { ledger_sequence: event.sequence, event_hash: event.event_hash };
}

function attemptRef(events: readonly RuntimeEventV04Value[]) {
  const attempt = events.find((event) => event.event_type === "execution.attempt-started");
  if (attempt?.event_type !== "execution.attempt-started") throw new Error("attempt ref missing");
  return ref(attempt);
}

function append(
  events: RuntimeEventV04Value[],
  runId: string,
  eventType: RuntimeEventV04Value["event_type"],
  source: RuntimeEventV04Value["source"],
  authorityRef: string | null,
  payload: unknown,
) {
  const sequence = events.length + 1;
  const preimage = {
    schema_version: "0.4" as const,
    event_id: `event_compensation_write_s41_${sequence}`,
    run_id: runId,
    sequence,
    recorded_at: `2026-08-30T19:00:${String(sequence).padStart(2, "0")}Z`,
    event_type: eventType,
    source,
    authority_ref: authorityRef,
    risk_tier: "T1" as const,
    related_ids: [],
    previous_event_hash: events.at(-1)?.event_hash ?? null,
    payload,
  };
  const event = RuntimeEventV04.parse({ ...preimage, event_hash: hashCanonical(preimage) });
  events.push(event);
  return event;
}

function compensationPlan() {
  const source = ResolvedRunPlanV02.parse(JSON.parse(readFileSync(
    join(import.meta.dirname, "../fixtures/compat/s35/v02/planned-run/resolved-run-plan.json"),
    "utf8",
  ))) as ResolvedRunPlanV02Value;
  const plan = structuredClone(source);
  const protectedTask = plan.tasks[0]!;
  const protectedSideEffects = plan.side_effects.find((row) => row.task_id === protectedTask.id)!;
  const protectedEffect = protectedSideEffects.effects[0]!;
  protectedEffect.compensation_ref = "restore-protected-effect";
  plan.tasks.push({
    ...structuredClone(protectedTask),
    id: "restore-protected-task",
    depends_on: [],
    kind: "compensation",
  });
  plan.side_effects.push({
    task_id: "restore-protected-task",
    effects: [{
      effect_id: "effect-restore-protected-task",
      effect_class: "none",
      description: "The compensation verification is observation-only.",
      inspectable: true,
      reversible: false,
      idempotency: "not-required",
      last_safe_stop: { kind: "before-task", task_ref: "restore-protected-task" },
      compensation_ref: null,
    }],
  });
  plan.retry_policy.rules.push(...plan.retry_policy.rules
    .filter((rule) => rule.task_ref === protectedTask.id)
    .map((rule) => ({ ...rule, task_ref: "restore-protected-task" })));
  plan.compensations.push({
    id: "restore-protected-effect",
    for_task: protectedTask.id,
    for_effect: protectedEffect.effect_id,
    action_task: "restore-protected-task",
    preconditions: [{ source: "effect", task_ref: protectedTask.id, effect_ref: protectedEffect.effect_id, outcome: "committed" }],
    verification_refs: [plan.evaluations[0]!.id],
    may_fail: true,
  });
  const retryByTask = new Map<string, number>();
  for (const rule of plan.retry_policy.rules) {
    retryByTask.set(rule.task_ref, Math.max(retryByTask.get(rule.task_ref) ?? 0, rule.max_task_executions));
  }
  const attempts = plan.tasks.reduce((sum, task) => sum + (retryByTask.get(task.id) ?? 0), 0);
  const gates = plan.gates.length;
  const evaluations = plan.evaluations.length;
  const artifacts = plan.artifacts.length;
  const evidence = 8 * attempts + 12 * gates + 4 * evaluations + 2 * artifacts + 32;
  plan.runtime_record_limits = {
    max_authority_records: 9 * attempts + 10 * gates,
    max_agency_recommendation_records: 8 * (2 * attempts + plan.compensations.length),
    max_authority_revocation_records: attempts + 2 * gates,
    max_evidence_records: evidence,
    max_task_result_records: attempts,
    max_manual_observation_records: evidence,
    max_export_decision_records: artifacts + evidence,
    max_claim_records: plan.goal.success_criteria.length + gates + evaluations,
    max_finding_records: 4 * attempts + 2 * gates + 2 * evaluations + 2 * artifacts + 32,
    max_waiver_records: gates,
    max_preseal_custody_events: 2 * (artifacts + evidence),
  };
  const parsed = ResolvedRunPlanV02.parse(plan);
  const projected = projectRuntimePlanV03(parsed, captureRuntimeProfileRegistryV03());
  if (!projected.ok) throw new Error(projected.reason);
  const bytes = UTF8.encode(JSON.stringify(projected.value));
  const inspected = inspectRuntimePlanV03(bytes);
  if (!inspected.ok) throw new Error(inspected.reason);
  return { bytes, plan: inspected.validated_plan, protectedTask, protectedEffect };
}

function baseScenarios() {
  const built = compensationPlan();
  const { plan } = built;
  const events: RuntimeEventV04Value[] = [];
  append(events, plan.run_id, "run.initialized", "kernel", null, {
    plan_hash: plan.plan_hash, initial_fence_epoch: 0, runtime_schema_versions: INVENTORY,
  });
  const started = append(events, plan.run_id, "run.started", "kernel", null, { executor_profile_hash: H("1") });
  const clock = append(events, plan.run_id, "run.clock-observed", "kernel", null, {
    clock_id: "clock_compensation_write_s41", observed_at: "2026-08-30T19:00:03Z", elapsed_ms: 1,
    reason: "run-owner-acquisition", task_ref: null, failure_ordinal: null,
    use_ref: "run_owner_compensation_write_s41", attempt_ref: null, owner_lease_ref: null,
    boot_id_hash: H("1"), monotonic_clock_id: "mono_compensation_write_s41",
  });
  const attempt = append(events, plan.run_id, "execution.attempt-started", "kernel", null, {
    attempt_id: "attempt_compensation_write_s41", attempt_ordinal: 1, mode: "ordinary",
    previous_attempt_event_ref: null, resume_request_event_ref: null, resume_nonce_hash: null,
    source_boundary_sequence: started.sequence, source_boundary_head_hash: started.event_hash,
    source_manifest_hash: H("2"),
    repository_state_hash: plan.plan.authority_subject.repository.initial_state.repository_state_hash,
    plan_hash: plan.plan_hash, input_hash: plan.plan.runtime_input_hash,
    recovery_policy_hash: plan.plan.runtime_recovery_policy_hash, authority_envelope_hash: H("3"),
    run_owner_lease_id: "run_owner_compensation_write_s41", issued_clock_ref: ref(clock),
    deadline_elapsed_ms: 60_000, boot_id_hash: H("1"),
    monotonic_clock_id: "mono_compensation_write_s41", previous_fence_epoch: 0, fence_epoch: 0,
  });
  const proposal = {
    action_proposal_id: "proposal_compensation_write_s41", action_proposal_hash: H("4"),
    action_actor_ref: "actor_compensation_write_s41", action_actor_stable_identity_hash: H("5"),
    on_behalf_of_chain_hash: H("6"), repository_root_ref: "repository_compensation_write_s41",
    repository_base_ref_identity_hash: H("7"), repository_pre_state_hash: H("8"),
    authorized_change_set_hash: H("9"), normalized_dispatch_hash: H("a"),
  } as const;
  const admission = append(events, plan.run_id, "task.action-admitted", "policy-enforcement-point", "authority_compensation_write_s41", {
    action_id: "action_compensation_write_s41", task_ref: built.protectedTask.id,
    lease_id: "lease_compensation_write_s41", lease_event_ref: ref(attempt), admission_clock_ref: ref(clock),
    ...proposal, action_scope_hash: H("b"), action_class: "task", classifier_input_hash: H("c"),
    classifier_registry_hash: H("d"), classifier_rule_hash: H("e"), data_flow_hash: H("f"),
    policy_action_kind: "network-read", action_approval_class: "agency", execution_ordinal: 1,
    retry_of_failure_ordinal: null, fence_epoch: 0, side_effect_refs: [built.protectedEffect.effect_id],
    waiver_gate_use_checks: [], task_executions_after: 1, action_output_bytes_after: 0,
    attempt_event_ref: ref(attempt), parent_run_owner_lease_id: "run_owner_compensation_write_s41",
    logical_operation_idempotency_key: H("1"), resolved_operation_input_hash: H("2"),
    recovery_policy_hash: plan.plan.runtime_recovery_policy_hash, process_runtime_ceiling_ms: 30_000,
  });
  const unknown = append(events, plan.run_id, "task.action-outcome-unknown", "adapter", null, {
    action_id: "action_compensation_write_s41", task_ref: built.protectedTask.id,
    admission_ref: ref(admission), detection_reason: "process-status-unavailable",
    observation_ref: ref(clock), evidence_refs: [ref(clock)],
  });
  const effect = append(events, plan.run_id, "effect.outcome", "integrity", null, {
    task_ref: built.protectedTask.id, effect_ref: built.protectedEffect.effect_id,
    action_id: "action_compensation_write_s41", outcome: "unknown",
    evidence_refs: [ref(unknown)], reconciliation_event_ref: null,
  });
  const head = { algorithm: "sha1" as const, value: "a".repeat(40) };
  const repositoryStateFields = {
    repository_root_ref: proposal.repository_root_ref,
    base_ref_identity_hash: proposal.repository_base_ref_identity_hash,
    head, merge_base: head, head_state_hash: H("1"), tracked_diff_hash: H("2"),
    staged_diff_hash: H("3"), untracked_content_hash: H("4"), submodule_state_hash: H("5"),
  };
  const repositoryStateHash = hashCanonical({ purpose: "repository-state-v02", ...repositoryStateFields });
  const observedFields = {
    repository_root_ref: proposal.repository_root_ref,
    base_ref_identity_hash: proposal.repository_base_ref_identity_hash,
    repository_pre_state_hash: proposal.repository_pre_state_hash,
    repository_post_state_hash: repositoryStateHash, head_before: head, head_after: head, changes: [],
  };
  const observedChangeSetHash = hashCanonical({ purpose: "observed-repository-change-set-v02", ...observedFields });
  append(events, plan.run_id, "task.action-settled", "kernel", null, {
    action_id: "action_compensation_write_s41", task_ref: built.protectedTask.id,
    terminal_event_ref: ref(unknown), ...proposal,
    policy_action_kind: "network-read", action_approval_class: "agency",
    repository_post_state: { ...repositoryStateFields, repository_state_hash: repositoryStateHash },
    repository_post_state_hash: repositoryStateHash,
    observed_change_set: { ...observedFields, observed_change_set_hash: observedChangeSetHash },
    observed_change_set_hash: observedChangeSetHash, repository_transition_status: "authorized-change",
    effect_outcomes: [{ effect_ref: built.protectedEffect.effect_id, outcome: "unknown", outcome_event_ref: ref(effect) }],
  });
  void unknown;
  const quiescent = events.slice(0, 4);
  const directEffect = append(quiescent, plan.run_id, "effect.outcome", "integrity", null, {
    task_ref: built.protectedTask.id, effect_ref: built.protectedEffect.effect_id,
    action_id: "action_compensation_write_s41", outcome: "unknown",
    evidence_refs: [ref(clock)], reconciliation_event_ref: null,
  });
  const simplified = [...quiescent];
  const abort = append(simplified, plan.run_id, "control.abort-requested", "operator", "authority_abort_compensation_s41", {
    request_id: "abort_compensation_write_s41", requested_by: "operator", reason_code: "operator-requested",
    policy_decision_ref: null, evidence_refs: [],
  });
  const directFreeze = append(simplified, plan.run_id, "run.terminal-freeze-entered", "evaluator", null, {
    revision: 1, candidate: "aborted", candidate_evidence_refs: [ref(abort)], fence_epoch: 0,
  });
  const exhausted = [...quiescent];
  const ceiling = plan.plan.limit_policy.max_output_bytes
    - plan.plan.limit_policy.control_plane_output_reserve_bytes
    - plan.plan.recovery_policy.reserve.max_output_bytes;
  const limit = append(exhausted, plan.run_id, "limit.admission-blocked", "policy-enforcement-point", "pep_compensation_write_s41", {
    request_id: "limit_compensation_write_s41",
    task_ref: built.protectedTask.id,
    phase: "work",
    compensation_ref: null,
    request_kind: "artifact-write",
    request_hash: H("b"),
    violations: [{ limit_ref: "max-output-bytes", consumed: ceiling, requested: 1, ceiling }],
  });
  const exhaustedFreeze = append(exhausted, plan.run_id, "run.terminal-freeze-entered", "evaluator", null, {
    revision: 1, candidate: "exhausted", candidate_evidence_refs: [ref(limit)], fence_epoch: 0,
  });
  void directEffect;
  return {
    ...built,
    aborted: Object.freeze({ events: simplified, freeze: directFreeze }),
    exhausted: Object.freeze({ events: exhausted, freeze: exhaustedFreeze }),
  };
}

function decisionEvents(decision: Decision) {
  const base = baseScenarios();
  const aborted = {
    ...base,
    events: [...base.aborted.events],
    freeze: base.aborted.freeze,
  };
  const exhausted = {
    ...base,
    events: [...base.exhausted.events],
    freeze: base.exhausted.freeze,
  };
  if (decision === "request-compensation") return aborted;

  if (decision === "enter-compensation" || decision === "settle-compensation") {
    const requested = append(aborted.events, aborted.plan.run_id, "run.compensation-requested", "evaluator", null, {
      revision: 1, pending_terminal: "aborted", activation_reason: "abort-recovery",
      compensation_refs: ["restore-protected-effect"],
      effect_evidence_refs: [ref(aborted.events.find((event) => event.event_type === "effect.outcome")!)],
      freeze_event_hash: aborted.freeze.event_hash,
    });
    if (decision === "settle-compensation") {
      const currentAttemptRef = attemptRef(aborted.events);
      append(aborted.events, aborted.plan.run_id, "run.fence-advanced", "policy-enforcement-point", "pep_compensation_write_s41", {
        previous_fence_epoch: 0,
        fence_epoch: 1,
        reason: "abort-request",
        evidence_refs: [ref(requested)],
        attempt_ref: currentAttemptRef,
        owner_lease_refs: [currentAttemptRef],
      });
      append(aborted.events, aborted.plan.run_id, "run.compensation-phase-entered", "evaluator", null, {
        request_revision: 1, request_event_hash: requested.event_hash, pending_terminal: "aborted",
        compensation_refs: ["restore-protected-effect"], freeze_event_hash: aborted.freeze.event_hash,
      });
    }
    return aborted;
  }

  const requested = append(exhausted.events, exhausted.plan.run_id, "run.compensation-requested", "evaluator", null, {
    revision: 1, pending_terminal: "exhausted", activation_reason: "terminal-exhaustion",
    compensation_refs: ["restore-protected-effect"],
    effect_evidence_refs: [ref(exhausted.events.find((event) => event.event_type === "effect.outcome")!)],
    freeze_event_hash: exhausted.freeze.event_hash,
  });
  if (decision === "escalate-compensation") {
    const currentAttemptRef = attemptRef(exhausted.events);
    append(exhausted.events, exhausted.plan.run_id, "run.fence-advanced", "policy-enforcement-point", "pep_compensation_write_s41", {
      previous_fence_epoch: 0,
      fence_epoch: 1,
      reason: "lease-revoked",
      evidence_refs: [ref(requested)],
      attempt_ref: currentAttemptRef,
      owner_lease_refs: [currentAttemptRef],
    });
    append(exhausted.events, exhausted.plan.run_id, "run.compensation-phase-entered", "evaluator", null, {
      request_revision: 1, request_event_hash: requested.event_hash, pending_terminal: "exhausted",
      compensation_refs: ["restore-protected-effect"], freeze_event_hash: exhausted.freeze.event_hash,
    });
  }
  const abort = append(exhausted.events, exhausted.plan.run_id, "control.abort-requested", "operator", "authority_abort_compensation_s41", {
    request_id: "abort_compensation_write_s41", requested_by: "operator", reason_code: "operator-requested",
    policy_decision_ref: null, evidence_refs: [],
  });
  append(exhausted.events, exhausted.plan.run_id, "run.terminal-freeze-revised", "evaluator", null, {
    revision: 2, previous_candidate: "exhausted", candidate: "aborted",
    previous_freeze_event_hash: exhausted.freeze.event_hash, candidate_evidence_refs: [ref(abort)],
  });
  return exhausted;
}

function trustContext() {
  const { publicKey } = generateKeyPairSync("ed25519");
  const captured = captureAuthorityTrustContextV02({
    observed_at: "2026-08-30T19:30:00Z", policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
    authentication_contexts: [{
      context_version: "0.1", trust_domain: "local-operator", approval_channel: "local-ed25519",
      authenticated_principal_ref: "operator_compensation_write_s41",
      credential_ref: "operator_key_compensation_write_s41", channel_subject_hash: H("1"),
      session_binding_hash: H("2"), assurance_level: "phishing-resistant",
    }], operator_keys: [{
      operator_key_id: "operator_key_compensation_write_s41",
      authenticated_principal_ref: "operator_compensation_write_s41", trust_domain: "local-operator",
      public_key_spki_base64: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
      effective_from: "2026-08-30T19:00:00Z", effective_until: "2026-08-30T20:00:00Z", revoked_at: null,
    }], platform_channel_verifiers: [], host_producer_keys: [], authority_epochs: [{
      authenticated_principal_ref: "operator_compensation_write_s41", revocation_epoch: 0,
      effective_from: "2026-08-30T19:00:00Z",
    }], durable_nonce_consumptions: [],
  });
  if (!captured.ok) throw new Error(captured.error);
  return captured.value;
}

function write0600(path: string, bytes: Uint8Array): void {
  writeFileSync(path, bytes, { mode: 0o600 });
  chmodSync(path, 0o600);
}

function persist(root: string, scenario: ReturnType<typeof decisionEvents>): void {
  const admission = scenario.events.find((event) => event.event_type === "task.action-admitted");
  if (admission?.event_type === "task.action-admitted") {
    const {
      attempt_event_ref: _attempt, parent_run_owner_lease_id: _owner,
      logical_operation_idempotency_key: _idempotency, resolved_operation_input_hash: _input,
      recovery_policy_hash: _policy, process_runtime_ceiling_ms: _ceiling, ...payload
    } = admission.payload;
    const projected = RuntimeEventV02.safeParse({ ...admission, schema_version: "0.2", payload });
    if (!projected.success) throw new Error(`admission projection: ${JSON.stringify(projected.error.issues)}`);
  }
  for (const row of scenario.events.filter((event) => event.event_type === "task.action-outcome-unknown" || event.event_type === "task.action-settled")) {
    const projected = RuntimeEventV02.safeParse({ ...row, schema_version: "0.2" });
    if (!projected.success) throw new Error(`${row.event_type} projection: ${JSON.stringify(projected.error.issues)}`);
  }
  const ledgerBytes = UTF8.encode(`${scenario.events.map((event) => JSON.stringify(event)).join("\n")}\n`);
  const files = [
    { path: "ledger.jsonl", family: "primary" as const, required: true, mode: 384 as const, bytes: ledgerBytes },
    { path: "resolved-run-plan.json", family: "primary" as const, required: true, mode: 384 as const, bytes: scenario.bytes },
  ];
  const manifest = buildRunManifestV04({ ledger_bytes: ledgerBytes, created_at: "2026-08-30T19:20:00Z", captured_files: files });
  if (!manifest.ok) throw new Error(manifest.reason);
  write0600(join(root, "ledger.jsonl"), ledgerBytes);
  write0600(join(root, "resolved-run-plan.json"), scenario.bytes);
  write0600(join(root, "run-manifest.json"), manifest.bytes);
}

function projection(root: string): RuntimeTerminalProjectionV04 {
  const planBytes = new Uint8Array(readFileSync(join(root, "resolved-run-plan.json")));
  const ledgerBytes = new Uint8Array(readFileSync(join(root, "ledger.jsonl")));
  const manifestBytes = new Uint8Array(readFileSync(join(root, "run-manifest.json")));
  const plan = inspectRuntimePlanV03(planBytes);
  const ledger = inspectRuntimeLedgerV04(ledgerBytes);
  if (!plan.ok || !ledger.ok) throw new Error("prefix inspection failed");
  const manifest = inspectRunManifestV04({
    manifest_bytes: manifestBytes, ledger_bytes: ledgerBytes,
    captured_files: [
      { path: "ledger.jsonl", family: "primary", required: true, mode: 384, bytes: ledgerBytes },
      { path: "resolved-run-plan.json", family: "primary", required: true, mode: 384, bytes: planBytes },
    ],
  });
  if (!manifest.ok) throw new Error(manifest.reason);
  const built = buildRuntimeTerminalProjectionV04({
    validated_plan: plan.validated_plan, ledger: manifest.ledger,
    manifest: manifest.validated_manifest, authority_trust_context: trustContext(),
  });
  if (!built.ok) throw new Error(`${built.reason}:${built.snapshot_reason ?? ""}`);
  return built.value;
}

function observation() {
  const source = captureRuntimeClockSourceV04({
    boot_identity: "boot_compensation_write_s41", monotonic_clock_id: "mono_compensation_write_s41",
    observe: () => ({ observed_at: "2026-08-30T19:01:00Z", elapsed_ms: 2_000 }),
  });
  if (source === null) throw new Error("clock capture failed");
  const sampled = observeRuntimeClockV04(source);
  if (!sampled.ok) throw new Error(sampled.error);
  return sampled.value;
}

const expectedAction = {
  "request-compensation": "COMPENSATION_REQUESTED",
  "revise-compensation-request": "COMPENSATION_REQUEST_REVISED",
  "enter-compensation": "COMPENSATION_ENTERED",
  "escalate-compensation": "COMPENSATION_ESCALATED",
  "settle-compensation": "COMPENSATION_SETTLED",
} as const;

const expectedEventType = {
  "request-compensation": "run.compensation-requested",
  "revise-compensation-request": "run.compensation-request-revised",
  "enter-compensation": "run.compensation-phase-entered",
  "escalate-compensation": "run.compensation-candidate-escalated",
  "settle-compensation": "compensation.settled",
} as const;

describe("S41 V04 compensation durable writer", () => {
  it.each(Object.keys(expectedAction) as Array<keyof typeof expectedAction>)("commits exactly the genuine %s evaluator event", async (decision) => {
    const fixture = createRuntimeCommandFixtureV04();
    try {
      const root = realpathSync(fixture.root);
      const scenario = decisionEvents(decision);
      persist(root, scenario);
      const current = projection(root);
      expect(evaluateRuntimeTerminalV04(current).decision).toBe(decision);
      const store = await captureRuntimeFileStoreV04({ run_directory: root });
      if (!store.ok) throw new Error(store.error);
      const result = await writeRuntimeCompensationV04(store.store, {
        projection: current, observation: observation(), event_id: `event_write_${decision.replaceAll("-", "_")}_s41`,
      });
      expect(result).toMatchObject({ ok: true, classification: "COMMITTED", action: expectedAction[decision] });
      const after = inspectRuntimeLedgerV04(new Uint8Array(readFileSync(join(root, "ledger.jsonl"))));
      if (!after.ok) throw new Error(after.reason);
      expect(after.ledger.sequence).toBe(scenario.events.length + 1);
      expect(after.ledger.events.at(-1)).toMatchObject({
        sequence: scenario.events.length + 1,
        event_type: expectedEventType[decision],
      });
    } finally {
      fixture.cleanup();
    }
  });

  it("rejects forgeries, extra keys, stale projections, and a replayed clock", async () => {
    const fixture = createRuntimeCommandFixtureV04();
    try {
      const root = realpathSync(fixture.root);
      const scenario = decisionEvents("request-compensation");
      persist(root, scenario);
      const current = projection(root);
      const store = await captureRuntimeFileStoreV04({ run_directory: root });
      if (!store.ok) throw new Error(store.error);
      await expect(writeRuntimeCompensationV04(store.store, {
        projection: structuredClone(current), observation: observation(), event_id: "event_forged_compensation_s41",
      })).resolves.toMatchObject({ ok: false, error: "RUNTIME_COMPENSATION_INPUT_INVALID" });
      await expect(writeRuntimeCompensationV04(store.store, {
        projection: current, observation: observation(), event_id: "event_extra_compensation_s41", operation: "request",
      })).resolves.toMatchObject({ ok: false, error: "RUNTIME_COMPENSATION_INPUT_INVALID" });

      const replay = observation();
      const first = await writeRuntimeCompensationV04(store.store, {
        projection: current, observation: replay, event_id: "event_first_compensation_s41",
      });
      expect(first.ok).toBe(true);
      await expect(writeRuntimeCompensationV04(store.store, {
        projection: current, observation: replay, event_id: "event_replay_compensation_s41",
      })).resolves.toMatchObject({ ok: false, error: "RUNTIME_COMPENSATION_PREFIX_INVALID" });
    } finally {
      fixture.cleanup();
    }
  });
});
