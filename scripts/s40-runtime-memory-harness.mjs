import process from "node:process";

import { hashBytes, hashCanonical } from "../dist/hash.js";
import {
  captureBrokeredModelExecutorAdapterV01,
  runCapturedBrokeredModelExecutorV01,
} from "../dist/run/brokered-model-executor-v01.js";
import { buildRunManifestV03 } from "../dist/run/runtime-manifest-v03.js";
import { captureRuntimeTerminationCapabilityV03 } from "../dist/run/runtime-termination-v03.js";
import {
  appendRuntimeEventV03,
  closeRuntimeWriteSessionV03,
  createRuntimeEventDraftV03,
  createSyntheticCapturedRuntimeRunStoreV03ForTest,
  openRuntimeWriteSessionV03,
} from "../dist/run/runtime-write-session-v03.js";

const encoder = new TextEncoder();
const H = (character) => `sha256:${character.repeat(64)}`;
const inventory = Object.freeze({
  resolved_run_plan: "0.2", ledger_event: "0.3", run_manifest: "0.3", artifact_manifest: "0.2",
  redaction_derivative: "0.2", human_authorization_proof: "0.2", authority_envelope: "0.2",
  agency_recommendation: "0.2", authority_revocation: "0.2", task_result: "0.2",
  manual_observation: "0.2", export_decision: "0.2", evidence_item: "0.2", gate_result: "0.2",
  evaluation_result: "0.2", claim: "0.2", finding: "0.2", waiver: "0.2", gate_waiver_authority: "0.2",
});

function forceGc() {
  global.gc();
  global.gc();
}

function heapUsed() {
  return process.memoryUsage().heapUsed;
}

function toMiB(bytes) {
  return Number((bytes / (1024 * 1024)).toFixed(2));
}

function createStore(ordinal) {
  const runId = `run_s40_memory_${ordinal}`;
  const initialized = {
    schema_version: "0.3",
    event_id: `event_s40_memory_init_${ordinal}`,
    run_id: runId,
    sequence: 1,
    recorded_at: "2026-08-24T10:00:00Z",
    event_type: "run.initialized",
    source: "kernel",
    authority_ref: null,
    risk_tier: "T1",
    related_ids: [],
    previous_event_hash: null,
    payload: { plan_hash: H("1"), initial_fence_epoch: 0, runtime_schema_versions: inventory },
  };
  const ledgerBytes = encoder.encode(`${JSON.stringify({ ...initialized, event_hash: hashCanonical(initialized) })}\n`);
  const capturedFiles = [
    { path: "artifact-manifest.json", family: "projection", required: false, mode: null, bytes: null },
    { path: "ledger.jsonl", family: "primary", required: true, mode: 384, bytes: ledgerBytes },
    { path: "records/authority.json", family: "record", required: true, mode: 384, bytes: encoder.encode('{"authority":"captured"}\n') },
    { path: "resolved-run-plan.json", family: "primary", required: true, mode: 384, bytes: encoder.encode('{"plan":"captured"}\n') },
  ];
  const manifest = buildRunManifestV03({
    ledger_bytes: ledgerBytes,
    created_at: "2026-08-24T10:00:00Z",
    captured_files: capturedFiles,
  });
  if (!manifest.ok) throw new Error(`memory harness manifest failed: ${manifest.reason}`);
  const store = createSyntheticCapturedRuntimeRunStoreV03ForTest({
    run_id: runId,
    ledger_bytes: ledgerBytes,
    manifest_bytes: manifest.bytes,
    captured_files: capturedFiles,
    lock_identity: `lock_s40_memory_${ordinal}`,
    lock_identity_valid: true,
    fault_at: null,
    event_envelopes: [{ event_id: `event_s40_memory_started_${ordinal}`, recorded_at: "2026-08-24T10:00:01Z" }],
    admission_context: {
      authority_trust_context: Object.freeze({}),
      repository_pre_state_hash: H("2"),
      normalized_dispatch_hash: H("3"),
      observed_at: "2026-08-24T10:00:00Z",
      elapsed_ms: 1,
      reviewer_view_hash: H("4"),
      enforcement: {
        available: true,
        information_flow_allowed: true,
        gates_passed: true,
        immediate_revalidation_passed: true,
      },
      condition_results: [],
      lease_id: `lease_s40_memory_${ordinal}`,
      clock_id: `clock_s40_memory_${ordinal}`,
      action_id: `action_s40_memory_${ordinal}`,
    },
  });
  if (store === null) throw new Error("memory harness store capture failed");
  return {
    store,
    expectation: {
      run_id: runId,
      ledger_bytes_hash: manifest.manifest.ledger_bytes_hash,
      ledger_sequence: manifest.manifest.ledger_sequence,
      ledger_head_hash: manifest.manifest.ledger_head_hash,
      current_fence_epoch: manifest.manifest.current_fence_epoch,
      manifest_hash: manifest.manifest.manifest_hash,
    },
  };
}

function modelContext(ordinal) {
  const content = `bounded context ${ordinal}`;
  return {
    context_version: "0.1",
    executor_profile_hash: H("5"),
    run_id: `run_s40_memory_${ordinal}`,
    plan_hash: H("1"),
    task_ref: "memory-plateau-check",
    attempt_id: `attempt_s40_memory_${ordinal}`,
    turn_id: `turn_s40_memory_${ordinal}`,
    actor_identity_hash: H("6"),
    on_behalf_of_chain_hash: H("7"),
    prompt: "Return one bounded completion suggestion.",
    context_items: [{
      context_ref: "memory-input",
      content_hash: hashBytes(content),
      sensitivity: "internal",
      content,
    }],
    allowed_references: {
      effect_refs: [], evidence_refs: [], program_refs: [], path_refs: [], origin_refs: [], tool_refs: [],
      connector_refs: [], account_refs: [], operation_refs: [], target_refs: [], content_refs: [], body_refs: [], argument_refs: [],
    },
  };
}

async function runCycle(ordinal) {
  const { store, expectation } = createStore(ordinal);
  const opened = await openRuntimeWriteSessionV03(store, expectation);
  if (!opened.ok) throw new Error(`memory harness session open failed: ${opened.error}`);
  const draft = createRuntimeEventDraftV03({
    event_type: "run.started",
    source: "kernel",
    authority_ref: null,
    risk_tier: "T1",
    related_ids: [],
    payload: { executor_profile_hash: H("5") },
  });
  if (draft === null) throw new Error("memory harness event draft failed");
  const appended = await appendRuntimeEventV03(opened.session, draft);
  if (!appended.ok) throw new Error(`memory harness append failed: ${appended.error}`);
  if (!await closeRuntimeWriteSessionV03(opened.session)) throw new Error("memory harness close failed");

  const adapterIdentity = Object.freeze({
    executor_profile_hash: H("5"),
    adapter_ref: `model_adapter_s40_memory_${ordinal}`,
    adapter_version_hash: H("8"),
    eligible_adapter_evidence_hash: H("9"),
    bypass_evidence_hash: H("a"),
  });
  const adapter = captureBrokeredModelExecutorAdapterV01({
    ...adapterIdentity,
    invoke: async () => ({
      response_version: "0.1",
      kind: "completion-suggestion",
      summary: "Bounded cycle complete.",
      evidence_refs: [],
    }),
  });
  if (adapter === null) throw new Error("memory harness model adapter capture failed");
  const proposed = await runCapturedBrokeredModelExecutorV01(modelContext(ordinal), adapter, adapterIdentity);
  if (!proposed.ok) throw new Error(`memory harness model boundary failed: ${proposed.error}`);

  const identity = `host_s40_memory_${ordinal}`;
  const termination = captureRuntimeTerminationCapabilityV03({
    host_identity: identity,
    boot_id: identity,
    unit_name: identity,
    cgroup_path: `/s40-memory/${ordinal}`,
    terminate: async () => ({
      host_identity: identity,
      boot_id: identity,
      unit_name: identity,
      cgroup_path: `/s40-memory/${ordinal}`,
      cgroup_populated: 0,
      unit_state: "inactive",
    }),
  });
  if (termination === null) throw new Error("memory harness termination capability capture failed");
}

async function main() {
  if (typeof global.gc !== "function") {
    process.stderr.write("s40-memory-harness requires `node --expose-gc`\n");
    process.exit(2);
  }

  const warmupCycles = 20;
  const samplesCount = 8;
  const cyclesPerSample = 25;
  let ordinal = 0;
  for (; ordinal < warmupCycles; ordinal += 1) await runCycle(ordinal);
  forceGc();
  const baseline = heapUsed();
  const samples = [{ iteration: 0, heap_mib: toMiB(baseline) }];

  for (let sample = 1; sample <= samplesCount; sample += 1) {
    for (let cycle = 0; cycle < cyclesPerSample; cycle += 1) {
      await runCycle(ordinal);
      ordinal += 1;
    }
    forceGc();
    samples.push({ iteration: sample * cyclesPerSample, heap_mib: toMiB(heapUsed()) });
  }

  const finalHeap = heapUsed();
  const trailing = samples.slice(-4).map((sample) => sample.heap_mib);
  const trailingRange = Math.max(...trailing) - Math.min(...trailing);
  const finalGrowthMiB = toMiB(finalHeap - baseline);
  const pass = trailingRange <= 12 && finalGrowthMiB <= 24;
  process.stdout.write(`${JSON.stringify({
    pass,
    workload: {
      warmup_cycles: warmupCycles,
      measured_cycles: samplesCount * cyclesPerSample,
      operations_per_cycle: ["manifest-build", "session-open", "durable-append", "session-close", "captured-model", "termination-capture"],
    },
    baseline_heap_mib: toMiB(baseline),
    final_heap_mib: toMiB(finalHeap),
    final_growth_mib: finalGrowthMiB,
    trailing_range_mib: Number(trailingRange.toFixed(2)),
    samples,
    criteria: {
      trailing_range_mib_max: 12,
      final_growth_mib_max: 24,
      note: "Generous GC plateau criteria for noisy local macOS runs; this is a trend probe, not an exact allocation or latency benchmark.",
    },
  }, null, 2)}\n`);
  if (!pass) process.exit(1);
}

await main();
