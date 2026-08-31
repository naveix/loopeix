import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";
import { canonicalize, hashCanonical, hashRawBytes } from "../../src/hash.js";
import { inspectRuntimeLedgerV04 } from "../../src/run/runtime-ledger-v04.js";
import { evaluateRuntimeLimitAccountingV04 } from "../../src/run/runtime-limit-accounting-v04.js";
import { buildRunManifestV04, inspectRunManifestV04 } from "../../src/run/runtime-manifest-v04.js";
import { inspectRuntimePlanV03, projectRuntimePlanV03 } from "../../src/run/project-plan-v03.js";
import { S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02 } from "../../src/run/action-classifier-policy-v02.js";
import {
  captureAuthorityTrustContextV02,
  captureEd25519AuthoritySignerV02,
  captureNonceReservationCapabilityV02,
  produceLocalHumanAuthorizationProofV02,
} from "../../src/run/runtime-record-admission-v02.js";
import {
  captureRuntimeRecoveryRequestV04,
  hashRuntimeRecoveryActionScopeV04,
  hashRuntimeRecoveryAuthorizationSubjectV04,
} from "../../src/run/runtime-recovery-authorization-v04.js";
import { planRuntimeRecoveryV04 } from "../../src/run/runtime-recovery-v04.js";
import {
  buildRuntimeSummaryArtifactsV04,
  deriveRuntimeCompactionContextHashesV04,
  inspectRuntimeSummaryV04,
  isInspectedSummaryArtifactV01, isValidatedSummaryArtifactV01,
  SUMMARY_INVALIDATION_RULES_V04,
  validateRuntimeSummaryForRecoveryV04,
} from "../../src/run/runtime-summary-v04.js";
import { ResolvedRunPlanV02 } from "../../src/schema/runtime.js";
import { captureRuntimeProfileRegistryV03 } from "../../src/schema/runtime-plan-v03.js";
import { RuntimeEventV04, type RuntimeEventV04Value } from "../../src/schema/runtime-v04.js";
import { createRuntimeRepositoryObservationFixture } from "../helpers/runtime-repository-observation-fixture.js";

const E = new TextEncoder();
const H = (c: string) => `sha256:${c.repeat(64)}`;
const REGISTRY = captureRuntimeProfileRegistryV03();
const RUN_ID = "run_msq2nla8_0102030405060708";
const repositoryCleanups: Array<() => void> = [];

afterEach(() => {
  for (const cleanup of repositoryCleanups.splice(0)) cleanup();
});
const inventory = {
  resolved_run_plan: "0.3", ledger_event: "0.4", run_manifest: "0.4", artifact_manifest: "0.2",
  redaction_derivative: "0.2", human_authorization_proof: "0.2", authority_envelope: "0.2",
  agency_recommendation: "0.2", authority_revocation: "0.2", task_result: "0.2",
  manual_observation: "0.2", export_decision: "0.2", evidence_item: "0.2", gate_result: "0.2",
  evaluation_result: "0.2", claim: "0.2", finding: "0.2", waiver: "0.2",
  gate_waiver_authority: "0.2", summary_artifact: "0.1",
} as const;
const ref = (event: RuntimeEventV04Value) => ({ ledger_sequence: event.sequence, event_hash: event.event_hash });

function append(events: RuntimeEventV04Value[], type: RuntimeEventV04Value["event_type"], source: RuntimeEventV04Value["source"], authority: string | null, payload: unknown) {
  const sequence = events.length + 1;
  const preimage = { schema_version: "0.4", event_id: `event_summary_s41_${sequence}`, run_id: RUN_ID,
    sequence, recorded_at: `2026-08-30T10:00:${String(sequence).padStart(2, "0")}Z`, event_type: type,
    source, authority_ref: authority, risk_tier: "T1", related_ids: [],
    previous_event_hash: events.at(-1)?.event_hash ?? null, payload };
  const event = RuntimeEventV04.parse({ ...preimage, event_hash: hashCanonical(preimage) });
  events.push(event);
  return event;
}

type Options = Readonly<{
  contentSize?: number;
  recordSize?: number;
  recordPatch?: Record<string, unknown>;
  eventPatch?: Record<string, unknown>;
  capturedRecordBytes?: Uint8Array;
  capturedContentBytes?: Uint8Array;
  appendLaterEvent?: boolean;
  withRepositoryObservation?: boolean;
  maxCompactionEvents?: number;
}>;

function loadPlanV02() {
  return ResolvedRunPlanV02.parse(JSON.parse(readFileSync(
    join(import.meta.dirname, "../fixtures/compat/s35/v02/planned-run/resolved-run-plan.json"),
    "utf8",
  )));
}

function validatedPlan(source = loadPlanV02()) {
  const projected = projectRuntimePlanV03(source, REGISTRY);
  if (!projected.ok) throw new Error(projected.reason);
  const inspected = inspectRuntimePlanV03(E.encode(JSON.stringify(projected.value)));
  if (!inspected.ok) throw new Error(inspected.reason);
  return inspected.validated_plan;
}

function fixture(options: Options = {}) {
  const repository = options.withRepositoryObservation
    ? createRuntimeRepositoryObservationFixture(loadPlanV02(), `summary_${repositoryCleanups.length}`)
    : null;
  if (repository !== null) repositoryCleanups.push(repository.cleanup);
  const basePlan = repository?.plan ?? loadPlanV02();
  const plan = validatedPlan(options.maxCompactionEvents === undefined
    ? basePlan
    : ResolvedRunPlanV02.parse({
        ...basePlan,
        limit_policy: { ...basePlan.limit_policy, max_loop_attempts: options.maxCompactionEvents },
      }));
  const runId = plan.run_id;
  if (runId !== RUN_ID) throw new Error("fixture run ID drifted");
  const events: RuntimeEventV04Value[] = [];
  append(events, "run.initialized", "kernel", null, { plan_hash: plan.plan_hash, initial_fence_epoch: 0, runtime_schema_versions: inventory });
  const started = append(events, "run.started", "kernel", null, { executor_profile_hash: H("b") });
  const runOwnerClock = append(events, "run.clock-observed", "kernel", null, {
    clock_id: "clock_run_owner_summary_s41", observed_at: "2026-08-30T10:00:02Z", elapsed_ms: 1,
    reason: "run-owner-acquisition", task_ref: null, failure_ordinal: null, use_ref: "run_owner_summary_s41_1",
    attempt_ref: null, owner_lease_ref: null, boot_id_hash: H("1"), monotonic_clock_id: "clock_summary_s41_1",
  });
  const attempt = append(events, "execution.attempt-started", "kernel", null, {
    attempt_id: "attempt_summary_s41_1", attempt_ordinal: 1, mode: "ordinary",
    previous_attempt_event_ref: null, resume_request_event_ref: null, resume_nonce_hash: null,
    source_boundary_sequence: started.sequence, source_boundary_head_hash: started.event_hash, source_manifest_hash: H("c"),
    plan_hash: plan.plan_hash, input_hash: plan.plan.runtime_input_hash, recovery_policy_hash: plan.plan.runtime_recovery_policy_hash, authority_envelope_hash: H("f"),
    repository_state_hash: plan.plan.authority_subject.repository.initial_state.repository_state_hash,
    run_owner_lease_id: "run_owner_summary_s41_1", issued_clock_ref: ref(runOwnerClock), deadline_elapsed_ms: 1_000,
    boot_id_hash: H("1"), monotonic_clock_id: "clock_summary_s41_1", previous_fence_epoch: 0, fence_epoch: 0,
  });
  const clock = append(events, "run.clock-observed", "kernel", null, {
    clock_id: "clock_integrator_summary_s41", observed_at: "2026-08-30T10:00:04Z", elapsed_ms: 10,
    reason: "owner-acquisition", task_ref: null, failure_ordinal: null, use_ref: "integrator_owner_summary_s41_1",
    attempt_ref: ref(attempt), owner_lease_ref: ref(attempt), boot_id_hash: H("1"), monotonic_clock_id: "clock_summary_s41_1",
  });
  const integrator = append(events, "ownership.lease-acquired", "policy-enforcement-point", "authority_summary_s41", {
    owner_lease_id: "integrator_owner_summary_s41_1", scope: "integrator", scope_ref: "summary_s41_1",
    parent_run_owner_lease_id: "run_owner_summary_s41_1", attempt_event_ref: ref(attempt), issued_clock_ref: ref(clock),
    deadline_elapsed_ms: 999, boot_id_hash: H("1"), monotonic_clock_id: "clock_summary_s41_1", fence_epoch: 0, heartbeat_limit: 2,
  });
  const sourceLedgerBytes = E.encode(`${events.map(JSON.stringify).join("\n")}\n`);
  const sourceCounters = {
    loop_attempts: 0,
    execution_attempts: 1,
    task_executions: Object.fromEntries(plan.plan.tasks.map((task) => [task.id, 0])),
    elapsed_ms: 10,
    tool_calls: 0,
    action_output_bytes: 0,
    control_output_bytes: sourceLedgerBytes.byteLength,
    token_count: 0,
    cost_minor_units: 0,
    active_workers: 0,
  };
  const accounting = evaluateRuntimeLimitAccountingV04({
    plan: plan.plan,
    phase: "work",
    consumed: sourceCounters,
    requested: { task_ref: null, loop_attempts: 0, execution_attempts: 0, task_executions: 0,
      elapsed_ms: 0, tool_calls: 0, action_output_bytes: 0, control_output_bytes: 0,
      token_count: 0, cost_minor_units: 0, workers: 0, process_runtime_ms: 0 },
  });
  if (!accounting.ok) throw new Error(accounting.reason);
  const contentBytes = new Uint8Array(options.contentSize ?? 21).fill(120);
  const preimage = {
    schema_version: "0.1", summary_id: "summary_s41_1", run_id: runId, attempt_id: "attempt_summary_s41_1",
    plan_hash: plan.plan_hash, input_hash: plan.plan.runtime_input_hash, recovery_policy_hash: plan.plan.runtime_recovery_policy_hash, authority_envelope_hash: H("f"),
    producer_ref: ref(integrator), source_first_event_ref: ref(events[0]!), source_last_event_ref: ref(integrator),
    source_prefix_sequence: integrator.sequence, source_prefix_head_hash: integrator.event_hash, lossiness_class: "lossless",
    retained_budget_state: { remaining_elapsed_ms: accounting.value.remaining.elapsed_ms,
      remaining_tool_calls: accounting.value.remaining.tool_calls,
      remaining_action_output_bytes: accounting.value.remaining.action_output_bytes,
      remaining_control_output_bytes: accounting.value.remaining.control_output_bytes,
      remaining_tokens: accounting.value.remaining.token_count,
      remaining_cost_minor_units: accounting.value.remaining.cost_minor_units,
      remaining_workers: accounting.value.remaining.workers },
    retained_counter_state: { loop_attempts_after: sourceCounters.loop_attempts,
      execution_attempts_after: sourceCounters.execution_attempts,
      per_task_executions_after: plan.plan.tasks.map((task) => task.id).sort()
        .map((task_ref) => ({ task_ref, task_executions_after: 0 })),
      action_output_bytes_after: sourceCounters.action_output_bytes,
      control_output_bytes_after: sourceCounters.control_output_bytes,
      tool_calls_after: sourceCounters.tool_calls,
      tokens_after: sourceCounters.token_count,
      cost_minor_units_after: sourceCounters.cost_minor_units,
      active_workers_after: sourceCounters.active_workers },
    fence_epoch: 0, resume_boundary: { source_boundary_sequence: started.sequence, source_boundary_head_hash: started.event_hash,
      source_manifest_hash: H("c"), attempt_event_ref: ref(attempt), fence_epoch: 0 },
    invalidation_rules: SUMMARY_INVALIDATION_RULES_V04, content_path: "summaries/content/summary_s41_1.bin",
    content_hash: hashRawBytes(contentBytes), content_size_bytes: contentBytes.byteLength, ...options.recordPatch,
  };
  const record = { ...preimage, record_hash: hashCanonical(preimage) };
  let text = JSON.stringify(record);
  if (options.recordSize !== undefined) text = text.padEnd(options.recordSize, " ");
  const recordBytes = E.encode(text);
  const sourceLedger = inspectRuntimeLedgerV04(sourceLedgerBytes);
  if (!sourceLedger.ok) throw new Error(sourceLedger.reason);
  const contextHashes = deriveRuntimeCompactionContextHashesV04({
    validated_plan: plan,
    ledger: sourceLedger.ledger,
    summary: record,
    record_bytes: recordBytes,
  });
  if (contextHashes === null) throw new Error("compaction context hash fixture failed");
  const compaction = append(events, "run.compaction-recorded", "kernel", null, {
    summary_id: record.summary_id, summary_record_path: `summaries/records/${record.summary_id}.json`,
    summary_record_hash: hashRawBytes(recordBytes), summary_content_path: record.content_path,
    summary_content_hash: record.content_hash, summary_size_bytes: record.content_size_bytes,
    attempt_event_ref: ref(attempt), integrator_lease_event_ref: ref(integrator),
    source_first_event_ref: record.source_first_event_ref, source_last_event_ref: record.source_last_event_ref,
    source_prefix_sequence: record.source_prefix_sequence, source_prefix_head_hash: record.source_prefix_head_hash,
    pre_context_hash: contextHashes.pre_context_hash, post_context_hash: contextHashes.post_context_hash, ...options.eventPatch,
  });
  if (options.appendLaterEvent) {
    append(events, "run.clock-observed", "kernel", null, {
      clock_id: "clock_summary_s41_later", observed_at: "2026-08-30T10:00:07Z", elapsed_ms: 11,
      reason: "owner-heartbeat", task_ref: null, failure_ordinal: null, use_ref: "integrator_owner_summary_s41_1",
      attempt_ref: ref(attempt), owner_lease_ref: ref(integrator), boot_id_hash: H("1"),
      monotonic_clock_id: "clock_summary_s41_1",
    });
  }
  const ledgerBytes = E.encode(`${events.map(JSON.stringify).join("\n")}\n`);
  const ledgerCheck = inspectRuntimeLedgerV04(ledgerBytes);
  if (!ledgerCheck.ok) throw new Error(`${ledgerCheck.reason}: ${JSON.stringify(ledgerCheck.issues)}`);
  const capturedRecordBytes = options.capturedRecordBytes ?? recordBytes;
  const capturedContentBytes = options.capturedContentBytes ?? contentBytes;
  const files = [
    { path: "ledger.jsonl", family: "primary", required: true, mode: 384, bytes: ledgerBytes },
    { path: `summaries/content/${record.summary_id}.bin`, family: "record", required: true, mode: 384, bytes: capturedContentBytes },
    { path: `summaries/records/${record.summary_id}.json`, family: "record", required: true, mode: 384, bytes: capturedRecordBytes },
  ] as const;
  const built = buildRunManifestV04({ ledger_bytes: ledgerBytes, created_at: "2026-08-30T10:01:00Z", captured_files: files });
  if (!built.ok) throw new Error(built.reason);
  const admitted = inspectRunManifestV04({ manifest_bytes: built.bytes, ledger_bytes: ledgerBytes, captured_files: files });
  if (!admitted.ok) throw new Error(admitted.reason);
  return {
    record,
    recordBytes,
    contentBytes,
    compaction,
    attempt,
    ledgerBytes,
    ledger: admitted.ledger,
    manifest: admitted.validated_manifest,
    plan,
    repository_observation: repository?.observation ?? null,
  };
}

function inspect(value = fixture()) {
  return inspectRuntimeSummaryV04({
    ledger: value.ledger,
    manifest: value.manifest,
    compaction_event_ref: ref(value.compaction),
  });
}
function recordBytes(record: Record<string, unknown>) {
  const { record_hash: _old, ...preimage } = record;
  return E.encode(JSON.stringify({ ...preimage, record_hash: hashCanonical(preimage) }));
}

function validate(value: ReturnType<typeof fixture>) {
  const admitted = inspect(value);
  if (!admitted.ok) throw new Error(admitted.reason);
  return validateRuntimeSummaryForRecoveryV04({
    inspected_summary: admitted.inspected_summary,
    validated_plan: value.plan,
    ledger: value.ledger,
    manifest: value.manifest,
  });
}

function buildSource(
  mutate: ((events: RuntimeEventV04Value[], value: ReturnType<typeof fixture>) => void) | null = null,
) {
  const value = fixture();
  const events = value.ledger.events.slice(0, value.compaction.sequence - 1) as RuntimeEventV04Value[];
  mutate?.(events, value);
  const ledgerBytes = E.encode(`${events.map(JSON.stringify).join("\n")}\n`);
  const files = [{ path: "ledger.jsonl", family: "primary", required: true, mode: 384, bytes: ledgerBytes }] as const;
  const built = buildRunManifestV04({
    ledger_bytes: ledgerBytes,
    created_at: "2026-08-30T10:01:00Z",
    captured_files: files,
  });
  if (!built.ok) throw new Error(built.reason);
  const admitted = inspectRunManifestV04({ manifest_bytes: built.bytes, ledger_bytes: ledgerBytes, captured_files: files });
  if (!admitted.ok) throw new Error(admitted.reason);
  return {
    value,
    events,
    ledger: admitted.ledger,
    manifest: admitted.validated_manifest,
    producer_ref: ref(value.ledger.events[value.compaction.sequence - 2]!),
    first_ref: ref(events[0]!),
    last_ref: ref(events.at(-1)!),
    prefix_ref: ref(events.at(-1)!),
  };
}

function buildInput(source = buildSource(), patch: Record<string, unknown> = {}) {
  return {
    validated_plan: source.value.plan,
    ledger: source.ledger,
    manifest: source.manifest,
    summary_id: "summary_s41_1",
    content_bytes: source.value.contentBytes,
    integrator_lease_event_ref: source.producer_ref,
    source_first_event_ref: source.first_ref,
    source_last_event_ref: source.last_ref,
    source_prefix_event_ref: source.prefix_ref,
    ...patch,
  };
}

async function authorizedRecoveryRequest(
  value: ReturnType<typeof fixture>,
  request: Readonly<{
    request_id: string;
    requested_mode: "ordinary";
    resume_nonce_hash: string;
    authority_envelope_hash: string;
    target_action_admission_ref: null;
    compensation_phase_event_ref: null;
  }>,
) {
  if (value.repository_observation === null) throw new Error("repository observation fixture required");
  const pair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const trustInput = {
    observed_at: "2026-08-30T12:00:30Z",
    policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
    authentication_contexts: [{
      context_version: "0.1" as const,
      trust_domain: "local-operator",
      approval_channel: "local-ed25519" as const,
      authenticated_principal_ref: "operator_summary_s41",
      credential_ref: "operator_key_summary_s41",
      channel_subject_hash: H("1"),
      session_binding_hash: H("2"),
      assurance_level: "phishing-resistant" as const,
    }],
    operator_keys: [{
      operator_key_id: "operator_key_summary_s41",
      authenticated_principal_ref: "operator_summary_s41",
      trust_domain: "local-operator",
      public_key_spki_base64: pair.publicKey.toString("base64"),
      effective_from: "2026-08-30T12:00:00Z",
      effective_until: "2026-08-30T13:00:00Z",
      revoked_at: null,
    }],
    platform_channel_verifiers: [],
    host_producer_keys: [],
    authority_epochs: [{
      authenticated_principal_ref: "operator_summary_s41",
      revocation_epoch: 1,
      effective_from: "2026-08-30T12:00:00Z",
    }],
    durable_nonce_consumptions: [] as const,
  };
  const initialTrust = captureAuthorityTrustContextV02(trustInput);
  if (!initialTrust.ok) throw new Error(initialTrust.error);
  let reserved: Readonly<Record<string, unknown>> | undefined;
  const nonce = captureNonceReservationCapabilityV02(async (row) => {
    reserved = row;
    return "reserved";
  });
  const signer = captureEd25519AuthoritySignerV02("operator_key_summary_s41", pair.privateKey);
  const subjectHash = hashRuntimeRecoveryAuthorizationSubjectV04({
    validated_plan: value.plan,
    ledger: value.ledger,
    manifest: value.manifest,
    request,
    repository_observation: value.repository_observation,
  });
  const scopeHash = hashRuntimeRecoveryActionScopeV04({
    validated_plan: value.plan,
    request,
    repository_observation: value.repository_observation,
  });
  if (subjectHash === null || scopeHash === null) throw new Error("hash fixture failed");
  const proof = await produceLocalHumanAuthorizationProofV02({
    trust_context: initialTrust.value,
    nonce_reservation: nonce,
    signer,
    request: {
      authorization_id: "authorization_summary_s41",
      run_id: value.plan.run_id,
      plan_hash: value.plan.plan_hash,
      authorization_subject_hash: subjectHash,
      authenticated_principal_ref: "operator_summary_s41",
      action_scope_hash: scopeHash,
      approved_risk_tier: "T1",
      operator_key_id: "operator_key_summary_s41",
      approval_nonce: H("9"),
      issued_at: "2026-08-30T12:00:00Z",
      expires_at: "2026-08-30T12:05:00Z",
      revocation_epoch: 1,
    },
  });
  if (!proof.ok || reserved === undefined) throw new Error("proof fixture failed");
  const trust = captureAuthorityTrustContextV02({
    ...trustInput,
    durable_nonce_consumptions: [reserved],
  });
  if (!trust.ok) throw new Error(trust.error);
  const captured = captureRuntimeRecoveryRequestV04({
    trust_context: trust.value,
    authorization_proof: proof.value,
    validated_plan: value.plan,
    ledger: value.ledger,
    manifest: value.manifest,
    request,
    repository_observation: value.repository_observation,
  });
  if (!captured.ok) throw new Error(captured.error);
  return captured.value;
}

describe("S41-B SummaryArtifactV01", () => {
  it("builds deterministic canonical artifacts while deriving every retained binding", () => {
    const source = buildSource();
    const first = buildRuntimeSummaryArtifactsV04(buildInput(source));
    const second = buildRuntimeSummaryArtifactsV04(buildInput(source));
    expect(first).toEqual(second);
    expect(first).toMatchObject({ ok: true });
    if (!first.ok) return;
    expect(first.artifact).toEqual(source.value.record);
    expect(new TextDecoder().decode(first.record_bytes)).toBe(`${canonicalize(first.artifact)}\n`);
    expect(first.artifact).toMatchObject({
      run_id: source.value.plan.run_id,
      attempt_id: source.value.attempt.payload.attempt_id,
      plan_hash: source.value.plan.plan_hash,
      input_hash: source.value.attempt.payload.input_hash,
      recovery_policy_hash: source.value.attempt.payload.recovery_policy_hash,
      authority_envelope_hash: source.value.attempt.payload.authority_envelope_hash,
      producer_ref: source.producer_ref,
      source_first_event_ref: source.first_ref,
      source_last_event_ref: source.last_ref,
      source_prefix_sequence: source.prefix_ref.ledger_sequence,
      source_prefix_head_hash: source.prefix_ref.event_hash,
      lossiness_class: "lossless",
      fence_epoch: source.value.attempt.payload.fence_epoch,
      content_path: "summaries/content/summary_s41_1.bin",
      content_hash: hashRawBytes(source.value.contentBytes),
      content_size_bytes: source.value.contentBytes.byteLength,
    });
    expect(first.record_path).toBe("summaries/records/summary_s41_1.json");
    expect(first.record_raw_hash).toBe(hashRawBytes(first.record_bytes));
    expect(first.pre_context_hash).toBe(hashCanonical({
      purpose: "runtime-context-root-v01",
      schema_version: "0.1",
      run_id: source.value.plan.run_id,
      plan_hash: source.value.plan.plan_hash,
      runtime_input_hash: source.value.plan.plan.runtime_input_hash,
      context_snapshot: source.value.plan.plan.context_snapshot,
    }));
    expect(first.post_context_hash).toBe(hashCanonical({
      purpose: "runtime-context-compaction-v01",
      schema_version: "0.1",
      run_id: source.value.plan.run_id,
      plan_hash: source.value.plan.plan_hash,
      pre_context_hash: first.pre_context_hash,
      summary_id: first.artifact.summary_id,
      summary_record_hash: first.record_raw_hash,
      summary_content_hash: first.artifact.content_hash,
      source_first_event_ref: first.artifact.source_first_event_ref,
      source_last_event_ref: first.artifact.source_last_event_ref,
      source_prefix_sequence: first.artifact.source_prefix_sequence,
      source_prefix_head_hash: first.artifact.source_prefix_head_hash,
    }));
    const { record_hash: _recordHash, ...recordPreimage } = first.artifact;
    expect(first.artifact.record_hash).toBe(hashCanonical(recordPreimage));
    expect(Object.isFrozen(first.artifact)).toBe(true);
  });

  it("chains later compactions from the immediately prior post-context hash", () => {
    const first = fixture({ maxCompactionEvents: 2 });
    const events = [...first.ledger.events] as RuntimeEventV04Value[];
    const secondClock = append(events, "run.clock-observed", "kernel", null, {
      clock_id: "clock_integrator_summary_s41_2", observed_at: "2026-08-30T10:00:07Z", elapsed_ms: 12,
      reason: "owner-acquisition", task_ref: null, failure_ordinal: null, use_ref: "integrator_owner_summary_s41_2",
      attempt_ref: ref(first.attempt), owner_lease_ref: ref(first.attempt), boot_id_hash: H("1"), monotonic_clock_id: "clock_summary_s41_1",
    });
    const secondIntegrator = append(events, "ownership.lease-acquired", "policy-enforcement-point", "authority_summary_s41", {
      owner_lease_id: "integrator_owner_summary_s41_2", scope: "integrator", scope_ref: "summary_s41_2",
      parent_run_owner_lease_id: "run_owner_summary_s41_1", attempt_event_ref: ref(first.attempt), issued_clock_ref: ref(secondClock),
      deadline_elapsed_ms: 998, boot_id_hash: H("1"), monotonic_clock_id: "clock_summary_s41_1", fence_epoch: 0, heartbeat_limit: 2,
    });
    const ledgerBytes = E.encode(`${events.map(JSON.stringify).join("\n")}\n`);
    const ledgerCheck = inspectRuntimeLedgerV04(ledgerBytes);
    if (!ledgerCheck.ok) throw new Error(ledgerCheck.reason);
    const built = buildRunManifestV04({
      ledger_bytes: ledgerBytes,
      created_at: "2026-08-30T10:01:00Z",
      captured_files: [
        { path: "ledger.jsonl", family: "primary", required: true, mode: 384, bytes: ledgerBytes },
        { path: `summaries/content/${first.record.summary_id}.bin`, family: "record", required: true, mode: 384, bytes: first.contentBytes },
        { path: `summaries/records/${first.record.summary_id}.json`, family: "record", required: true, mode: 384, bytes: first.recordBytes },
      ],
    });
    if (!built.ok) throw new Error(built.reason);
    const admitted = inspectRunManifestV04({
      manifest_bytes: built.bytes,
      ledger_bytes: ledgerBytes,
      captured_files: [
        { path: "ledger.jsonl", family: "primary", required: true, mode: 384, bytes: ledgerBytes },
        { path: `summaries/content/${first.record.summary_id}.bin`, family: "record", required: true, mode: 384, bytes: first.contentBytes },
        { path: `summaries/records/${first.record.summary_id}.json`, family: "record", required: true, mode: 384, bytes: first.recordBytes },
      ],
    });
    if (!admitted.ok) throw new Error(admitted.reason);
    const second = buildRuntimeSummaryArtifactsV04({
      validated_plan: first.plan,
      ledger: admitted.ledger,
      manifest: admitted.validated_manifest,
      summary_id: "summary_s41_2",
      content_bytes: new Uint8Array(17).fill(121),
      integrator_lease_event_ref: ref(secondIntegrator),
      source_first_event_ref: ref(first.ledger.events[0]!),
      source_last_event_ref: ref(secondIntegrator),
      source_prefix_event_ref: ref(secondIntegrator),
    });
    expect(second).toMatchObject({ ok: true });
    if (!second.ok) return;
    expect(second.pre_context_hash).toBe(first.compaction.payload.post_context_hash);
    expect(second.post_context_hash).toBe(hashCanonical({
      purpose: "runtime-context-compaction-v01",
      schema_version: "0.1",
      run_id: first.plan.run_id,
      plan_hash: first.plan.plan_hash,
      pre_context_hash: first.compaction.payload.post_context_hash,
      summary_id: second.artifact.summary_id,
      summary_record_hash: second.record_raw_hash,
      summary_content_hash: second.artifact.content_hash,
      source_first_event_ref: second.artifact.source_first_event_ref,
      source_last_event_ref: second.artifact.source_last_event_ref,
      source_prefix_sequence: second.artifact.source_prefix_sequence,
      source_prefix_head_hash: second.artifact.source_prefix_head_hash,
    }));
  });

  it("rejects caller-authored fields, malformed content, and every exact source binding drift", () => {
    const source = buildSource();
    expect(buildRuntimeSummaryArtifactsV04(buildInput(source, { plan_hash: H("9") })))
      .toEqual({ ok: false, reason: "SUMMARY_BUILD_INPUT_INVALID" });
    expect(buildRuntimeSummaryArtifactsV04(buildInput(source, { content_bytes: new Uint8Array() })))
      .toEqual({ ok: false, reason: "SUMMARY_BUILD_CONTENT_INVALID" });
    expect(buildRuntimeSummaryArtifactsV04(buildInput(source, { content_bytes: new Uint8Array(65_537) })))
      .toEqual({ ok: false, reason: "SUMMARY_BUILD_CONTENT_INVALID" });
    for (const field of ["integrator_lease_event_ref", "source_first_event_ref", "source_last_event_ref", "source_prefix_event_ref"] as const) {
      const original = buildInput(source)[field];
      expect(buildRuntimeSummaryArtifactsV04(buildInput(source, {
        [field]: { ...original, event_hash: H("9") },
      }))).toEqual({ ok: false, reason: "SUMMARY_BUILD_INELIGIBLE" });
    }
    expect(buildRuntimeSummaryArtifactsV04(buildInput(source, {
      source_first_event_ref: source.last_ref,
      source_last_event_ref: source.first_ref,
    }))).toEqual({ ok: false, reason: "SUMMARY_BUILD_INELIGIBLE" });
  });

  it("fails closed for a released integrator lease, terminal freeze, and exhausted compaction ceiling", () => {
    const released = buildSource((events, value) => {
      const producer = events.at(-1)!;
      const releaseClock = append(events, "run.clock-observed", "kernel", null, {
        clock_id: "clock_summary_release_s41", observed_at: "2026-08-30T10:00:05Z", elapsed_ms: 11,
        reason: "owner-release", task_ref: null, failure_ordinal: null,
        use_ref: "integrator_owner_summary_s41_1", attempt_ref: ref(value.attempt), owner_lease_ref: ref(producer),
        boot_id_hash: H("1"), monotonic_clock_id: "clock_summary_s41_1",
      });
      append(events, "ownership.lease-released", "kernel", null, {
        owner_lease_event_ref: ref(producer), release_clock_ref: ref(releaseClock), reason: "completed", fence_epoch: 0,
      });
    });
    expect(buildRuntimeSummaryArtifactsV04(buildInput(released, {
      integrator_lease_event_ref: released.producer_ref,
    }))).toEqual({ ok: false, reason: "SUMMARY_BUILD_INELIGIBLE" });

    const frozen = buildSource((events) => {
      append(events, "run.terminal-freeze-entered", "evaluator", null, {
        revision: 1, candidate: "held", candidate_evidence_refs: [ref(events.at(-1)!)], fence_epoch: 0,
      });
    });
    expect(buildRuntimeSummaryArtifactsV04(buildInput(frozen)))
      .toEqual({ ok: false, reason: "SUMMARY_BUILD_INELIGIBLE" });

    const exhausted = fixture({ maxCompactionEvents: 1 });
    expect(buildRuntimeSummaryArtifactsV04({
      ...buildInput(),
      validated_plan: exhausted.plan,
      ledger: exhausted.ledger,
      manifest: exhausted.manifest,
      integrator_lease_event_ref: ref(exhausted.ledger.events[exhausted.compaction.sequence - 2]!),
      source_first_event_ref: ref(exhausted.ledger.events[0]!),
      source_last_event_ref: ref(exhausted.compaction),
      source_prefix_event_ref: ref(exhausted.compaction),
    })).toEqual({ ok: false, reason: "SUMMARY_BUILD_LIMIT_EXCEEDED" });
  });

  it("uses genuine plan/pair custody and mints the sole validated brand from derived prefix truth", () => {
    const value = fixture(); const admitted = inspect(value);
    expect(admitted).toMatchObject({ ok: true }); if (!admitted.ok) return;
    expect(isInspectedSummaryArtifactV01(admitted.inspected_summary)).toBe(true);
    expect(isValidatedSummaryArtifactV01(admitted.inspected_summary)).toBe(false);
    const valid = validateRuntimeSummaryForRecoveryV04({
      inspected_summary: admitted.inspected_summary,
      validated_plan: value.plan,
      ledger: value.ledger,
      manifest: value.manifest,
    });
    expect(valid).toMatchObject({ ok: true }); if (!valid.ok) return;
    expect(isValidatedSummaryArtifactV01(valid.validated_summary)).toBe(true);
    expect(validateRuntimeSummaryForRecoveryV04({
      inspected_summary: { ...admitted.inspected_summary },
      validated_plan: value.plan,
      ledger: value.ledger,
      manifest: value.manifest,
    }))
      .toEqual({ ok: false, reason: "SUMMARY_INPUT_INVALID" });
  });

  it("enforces exact keys, nested vocabulary, row ordering, and the exact 17-literal tuple", () => {
    const value = fixture();
    expect(Object.keys(value.record)).toHaveLength(23);
    expect(value.record.invalidation_rules).toEqual([
      "source-range-mismatch", "source-head-mismatch", "run-mismatch", "attempt-mismatch", "plan-mismatch",
      "input-mismatch", "policy-mismatch", "authority-mismatch", "producer-mismatch", "content-mismatch",
      "record-mismatch", "retained-counter-mismatch", "budget-mismatch", "fence-mismatch",
      "resume-boundary-mismatch", "lossiness-mismatch", "path-mismatch",
    ]);
    for (const patch of [
      { invented: true },
      { retained_budget_state: { ...value.record.retained_budget_state, remaining_token_count: null } },
      { retained_counter_state: { ...value.record.retained_counter_state, loop_attempts: 1 } },
      { retained_counter_state: { ...value.record.retained_counter_state,
        per_task_executions_after: [...value.record.retained_counter_state.per_task_executions_after].reverse() } },
      { resume_boundary: { ...value.record.resume_boundary, sequence: 2 } },
      { invalidation_rules: value.record.invalidation_rules.slice(0, -1) },
    ]) expect(inspect(fixture({ capturedRecordBytes: recordBytes({ ...value.record, ...patch }) })))
      .toMatchObject({ ok: false, reason: "SUMMARY_RECORD_SCHEMA_INVALID" });
  });

  it("bounds exact owned bytes and distinguishes canonical self-hash from raw persisted hash", () => {
    const atRecordCap = fixture({ recordSize: 262_144 });
    expect(inspect(atRecordCap)).toMatchObject({ ok: true });
    expect(hashRawBytes(atRecordCap.recordBytes)).not.toBe(atRecordCap.record.record_hash);
    expect(inspect(fixture({ capturedRecordBytes: new Uint8Array(262_145) })))
      .toEqual({ ok: false, reason: "SUMMARY_INPUT_INVALID" });
    expect(inspect(fixture({ contentSize: 65_536 }))).toMatchObject({ ok: true });
    expect(inspect(fixture({ capturedContentBytes: new Uint8Array(65_537) })))
      .toEqual({ ok: false, reason: "SUMMARY_INPUT_INVALID" });
  });

  it("applies structural precedence and rejects forged pairs, syntax, self-hash, and content drift", () => {
    const v = fixture();
    expect(inspect(fixture({
      capturedRecordBytes: E.encode('{"schema_version":"0.1","summary_id":"a","summary_id":"b"}'),
    }))).toEqual({ ok: false, reason: "SUMMARY_RECORD_SYNTAX_INVALID" });
    expect(inspect(fixture({
      capturedRecordBytes: E.encode(JSON.stringify({ ...v.record, record_hash: H("9") })),
      capturedContentBytes: new Uint8Array(v.contentBytes.length).fill(121),
    })))
      .toEqual({ ok: false, reason: "SUMMARY_RECORD_HASH_INVALID" });
    expect(inspect(fixture({ capturedContentBytes: new Uint8Array(v.contentBytes.length).fill(121) })))
      .toEqual({ ok: false, reason: "SUMMARY_CONTENT_HASH_INVALID" });
    expect(inspectRuntimeSummaryV04({
      ledger: { ...v.ledger }, manifest: v.manifest, compaction_event_ref: ref(v.compaction),
    }))
      .toEqual({ ok: false, reason: "SUMMARY_INPUT_INVALID" });
  });

  it("invalidates recovery when compaction context hashes drift from the exact derived chain", () => {
    expect(validate(fixture({ eventPatch: { pre_context_hash: H("9") } }))).toEqual({
      ok: false,
      reason: "SUMMARY_INVALIDATED",
      invalidation_reason: "source-head-mismatch",
    });
    expect(validate(fixture({ eventPatch: { post_context_hash: H("8") } }))).toEqual({
      ok: false,
      reason: "SUMMARY_INVALIDATED",
      invalidation_reason: "source-head-mismatch",
    });
  });

  it("requires the exact compaction event, direct event bindings, integrator producer, and manifest fence", () => {
    const v = fixture();
    expect(inspectRuntimeSummaryV04({ ledger: v.ledger, manifest: v.manifest,
      compaction_event_ref: v.record.source_last_event_ref }))
      .toEqual({ ok: false, reason: "SUMMARY_LEDGER_BINDING_INVALID" });
    expect(inspect(fixture({ eventPatch: { summary_size_bytes: 22 } })))
      .toEqual({ ok: false, reason: "SUMMARY_LEDGER_BINDING_INVALID" });
    expect(inspect(fixture({ recordPatch: { fence_epoch: 1 } })))
      .toEqual({ ok: false, reason: "SUMMARY_LEDGER_BINDING_INVALID" });

    const ledgerOnlyFiles = [
      { path: "ledger.jsonl", family: "primary", required: true, mode: 384, bytes: v.ledgerBytes },
    ] as const;
    const ledgerOnlyCandidate = buildRunManifestV04({
      ledger_bytes: v.ledgerBytes,
      created_at: "2026-08-30T10:01:00Z",
      captured_files: ledgerOnlyFiles,
    });
    if (!ledgerOnlyCandidate.ok) throw new Error(ledgerOnlyCandidate.reason);
    const ledgerOnly = inspectRunManifestV04({
      manifest_bytes: ledgerOnlyCandidate.bytes,
      ledger_bytes: v.ledgerBytes,
      captured_files: ledgerOnlyFiles,
    });
    if (!ledgerOnly.ok) throw new Error(ledgerOnly.reason);
    expect(inspectRuntimeSummaryV04({
      ledger: ledgerOnly.ledger,
      manifest: ledgerOnly.validated_manifest,
      compaction_event_ref: ref(v.compaction),
    })).toEqual({ ok: false, reason: "SUMMARY_MANIFEST_BINDING_INVALID" });
  });

  it("derives counters and budgets from the exact prefix instead of trusting summary-authored values", () => {
    const baseline = fixture();
    expect(validate(fixture({ recordPatch: {
      retained_counter_state: { ...baseline.record.retained_counter_state, tool_calls_after: 1 },
    } }))).toEqual({ ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "retained-counter-mismatch" });
    expect(validate(fixture({ recordPatch: {
      retained_budget_state: { ...baseline.record.retained_budget_state, remaining_tool_calls: 31 },
    } }))).toEqual({ ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "budget-mismatch" });
  });

  it("keeps opaque prose advisory by requiring lossless recovery input and failing later-head drift closed", () => {
    expect(validate(fixture({ recordPatch: { lossiness_class: "lossy-narrative-only" } })))
      .toEqual({ ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "lossiness-mismatch" });
    expect(validate(fixture({ appendLaterEvent: true })))
      .toEqual({ ok: false, reason: "SUMMARY_INVALIDATED", invalidation_reason: "source-head-mismatch" });
  });

  it("rejects caller-authored expected state and forged plan brands at the trusted boundary", () => {
    const value = fixture(); const admitted = inspect(value); if (!admitted.ok) throw new Error(admitted.reason);
    expect(validateRuntimeSummaryForRecoveryV04({
      inspected_summary: admitted.inspected_summary,
      validated_plan: value.plan,
      ledger: value.ledger,
      manifest: value.manifest,
      expected: value.record,
    })).toEqual({ ok: false, reason: "SUMMARY_INPUT_INVALID" });
    expect(validateRuntimeSummaryForRecoveryV04({
      inspected_summary: admitted.inspected_summary,
      validated_plan: { ...value.plan },
      ledger: value.ledger,
      manifest: value.manifest,
    })).toEqual({ ok: false, reason: "SUMMARY_INPUT_INVALID" });
  });

  it("preserves a genuine validated summary through eligible recovery and refuses later-head drift at precedence five", async () => {
    const request = {
      request_id: "request_summary_s41_1",
      requested_mode: "ordinary",
      resume_nonce_hash: H("8"),
      authority_envelope_hash: H("f"),
      target_action_admission_ref: null,
      compensation_phase_event_ref: null,
    } as const;
    const decide = async (value: ReturnType<typeof fixture>) => {
      const admitted = inspect(value); if (!admitted.ok) throw new Error(admitted.reason);
      const capturedRequest = await authorizedRecoveryRequest(value, request);
      return planRuntimeRecoveryV04({
        ledger: value.ledger,
        manifest: value.manifest,
        plan: value.plan,
        owner_status: {
          status: "proven-stale",
          stale_reason: "same-domain-deadline-reached",
          owner_lease_event_ref: ref(value.attempt),
          evidence_refs: [ref(value.compaction)],
        },
        request: capturedRequest,
        summary: admitted.inspected_summary,
      });
    };
    const eligible = await decide(fixture({ withRepositoryObservation: true }));
    expect(eligible).toMatchObject({ ok: true, decision: { disposition: "eligible" } });
    if (eligible.ok && eligible.decision.disposition === "eligible") {
      expect(isValidatedSummaryArtifactV01(eligible.decision.validated_summary)).toBe(true);
    }
    expect(await decide(fixture({ appendLaterEvent: true, withRepositoryObservation: true }))).toEqual({
      ok: true,
      decision: { disposition: "refused", precedence: 5, reason_code: "summary-lineage-drift" },
    });
  });
});
