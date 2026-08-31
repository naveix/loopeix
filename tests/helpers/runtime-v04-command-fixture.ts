import { readFileSync, chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { hashCanonical } from "../../src/hash.js";
import { inspectRuntimePlanV03, projectRuntimePlanV03 } from "../../src/run/project-plan-v03.js";
import { buildRunManifestV04 } from "../../src/run/runtime-manifest-v04.js";
import { ResolvedRunPlanV02, type ResolvedRunPlanV02Value } from "../../src/schema/runtime.js";
import { captureRuntimeProfileRegistryV03 } from "../../src/schema/runtime-plan-v03.js";
import { RuntimeEventV04, type RuntimeEventV04Value } from "../../src/schema/runtime-v04.js";

const UTF8 = new TextEncoder();
const REGISTRY = captureRuntimeProfileRegistryV03();
const H = (character: string) => `sha256:${character.repeat(64)}`;
const INVENTORY = {
  resolved_run_plan: "0.3",
  ledger_event: "0.4",
  run_manifest: "0.4",
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
  summary_artifact: "0.1",
} as const;

function loadPlanV02(): ResolvedRunPlanV02Value {
  return ResolvedRunPlanV02.parse(JSON.parse(readFileSync(
    join(import.meta.dirname, "../fixtures/compat/s35/v02/planned-run/resolved-run-plan.json"),
    "utf8",
  )));
}

function validatedPlan() {
  const projected = projectRuntimePlanV03(loadPlanV02(), REGISTRY);
  if (!projected.ok) throw new Error(projected.reason);
  const bytes = UTF8.encode(JSON.stringify(projected.value));
  const inspected = inspectRuntimePlanV03(bytes);
  if (!inspected.ok) throw new Error(inspected.reason);
  return { bytes, validated_plan: inspected.validated_plan };
}

function ref(event: RuntimeEventV04Value) {
  return { ledger_sequence: event.sequence, event_hash: event.event_hash };
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
    schema_version: "0.4",
    event_id: `event_command_fixture_s41_${sequence}`,
    run_id: runId,
    sequence,
    recorded_at: `2026-08-30T15:00:${String(sequence).padStart(2, "0")}Z`,
    event_type: eventType,
    source,
    authority_ref: authorityRef,
    risk_tier: "T1",
    related_ids: [],
    previous_event_hash: events.at(-1)?.event_hash ?? null,
    payload,
  };
  const event = RuntimeEventV04.parse({ ...preimage, event_hash: hashCanonical(preimage) });
  events.push(event);
  return event;
}

function write0600(path: string, bytes: Uint8Array): void {
  writeFileSync(path, bytes, { mode: 0o600 });
  chmodSync(path, 0o600);
}

export function createRuntimeCommandFixtureV04(options: Readonly<{
  paused?: boolean;
  tamperManifest?: boolean;
}> = {}) {
  const { bytes: planBytes, validated_plan: plan } = validatedPlan();
  const events: RuntimeEventV04Value[] = [];
  append(events, plan.run_id, "run.initialized", "kernel", null, {
    plan_hash: plan.plan_hash,
    initial_fence_epoch: 0,
    runtime_schema_versions: INVENTORY,
  });
  const started = append(events, plan.run_id, "run.started", "kernel", null, {
    executor_profile_hash: H("1"),
  });
  const ownerClock = append(events, plan.run_id, "run.clock-observed", "kernel", null, {
    clock_id: "clock_command_owner_s41_1",
    observed_at: "2026-08-30T15:00:02Z",
    elapsed_ms: 1,
    reason: "run-owner-acquisition",
    task_ref: null,
    failure_ordinal: null,
    use_ref: "run_owner_command_s41_1",
    attempt_ref: null,
    owner_lease_ref: null,
    boot_id_hash: H("1"),
    monotonic_clock_id: "mono_command_s41_1",
  });
  const attempt = append(events, plan.run_id, "execution.attempt-started", "kernel", null, {
    attempt_id: "attempt_command_s41_1",
    attempt_ordinal: 1,
    mode: "ordinary",
    previous_attempt_event_ref: null,
    resume_request_event_ref: null,
    resume_nonce_hash: null,
    source_boundary_sequence: started.sequence,
    source_boundary_head_hash: started.event_hash,
    source_manifest_hash: H("2"),
    repository_state_hash: plan.plan.authority_subject.repository.initial_state.repository_state_hash,
    plan_hash: plan.plan_hash,
    input_hash: plan.plan.runtime_input_hash,
    recovery_policy_hash: plan.plan.runtime_recovery_policy_hash,
    authority_envelope_hash: H("5"),
    run_owner_lease_id: "run_owner_command_s41_1",
    issued_clock_ref: ref(ownerClock),
    deadline_elapsed_ms: 1_000,
    boot_id_hash: H("1"),
    monotonic_clock_id: "mono_command_s41_1",
    previous_fence_epoch: 0,
    fence_epoch: 0,
  });

  if (options.paused === true) {
    const pauseClock = append(events, plan.run_id, "run.clock-observed", "kernel", null, {
      clock_id: "clock_command_pause_s41_1",
      observed_at: "2026-08-30T15:00:03Z",
      elapsed_ms: 20,
      reason: "pause-request",
      task_ref: null,
      failure_ordinal: null,
      use_ref: "pause_command_s41_1",
      attempt_ref: ref(attempt),
      owner_lease_ref: ref(attempt),
      boot_id_hash: null,
      monotonic_clock_id: null,
    });
    const pauseRequest = append(events, plan.run_id, "control.pause-requested", "operator", "authority_pause_command_s41", {
      request_id: "pause_command_s41_1",
      requested_by: "operator",
      reason_code: "operator-request",
      attempt_event_ref: ref(attempt),
      run_owner_lease_ref: ref(attempt),
      request_clock_ref: ref(pauseClock),
      fence_epoch: 0,
    });
    append(events, plan.run_id, "run.fence-advanced", "policy-enforcement-point", "authority_pause_command_s41", {
      previous_fence_epoch: 0,
      fence_epoch: 1,
      reason: "pause-request",
      evidence_refs: [ref(pauseRequest)],
      attempt_ref: ref(attempt),
      owner_lease_refs: [ref(attempt)],
    });
    append(events, plan.run_id, "run.paused", "operator", "authority_pause_command_s41", {
      requested_by: "operator",
      reason_code: "operator-request",
      request_event_ref: ref(pauseRequest),
      attempt_event_ref: ref(attempt),
      quiescent_boundary_sequence: events.at(-1)!.sequence,
      quiescent_boundary_head_hash: events.at(-1)!.event_hash,
      previous_fence_epoch: 0,
      fence_epoch: 1,
      invalidated_owner_lease_refs: [ref(attempt)],
    });
  }

  const ledgerBytes = UTF8.encode(`${events.map((event) => JSON.stringify(event)).join("\n")}\n`);
  const capturedFiles = [
    { path: "ledger.jsonl", family: "primary" as const, required: true, mode: 384 as const, bytes: ledgerBytes },
    { path: "resolved-run-plan.json", family: "primary" as const, required: true, mode: 384 as const, bytes: planBytes },
  ];
  const manifest = buildRunManifestV04({
    ledger_bytes: ledgerBytes,
    created_at: "2026-08-30T15:01:00Z",
    captured_files: capturedFiles,
  });
  if (!manifest.ok) throw new Error(manifest.reason);

  const root = mkdtempSync(join(tmpdir(), "loopeix-command-v04-"));
  write0600(join(root, "ledger.jsonl"), ledgerBytes);
  write0600(join(root, "resolved-run-plan.json"), planBytes);
  if (options.tamperManifest === true) {
    const tampered = {
      ...manifest.manifest,
      manifest_hash: H("f"),
    };
    write0600(join(root, "run-manifest.json"), UTF8.encode(JSON.stringify(tampered)));
  } else {
    write0600(join(root, "run-manifest.json"), manifest.bytes);
  }

  return {
    root,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}
