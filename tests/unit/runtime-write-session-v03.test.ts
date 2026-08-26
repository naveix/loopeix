import { describe, expect, it, vi } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import { buildRunManifestV03, inspectRunManifestV03 } from "../../src/run/runtime-manifest-v03.js";
import { inspectRuntimeLedgerV03 } from "../../src/run/runtime-ledger-v03.js";
import {
  appendRuntimeEventV03,
  appendRuntimeIntegrityQuarantinePairV03,
  closeRuntimeWriteSessionV03,
  createRuntimeEventDraftV03,
  createSyntheticCapturedRuntimeRunStoreV03ForTest,
  inspectSyntheticRuntimeRunStoreV03ForTest,
  invalidateSyntheticRuntimeRunStoreLockV03ForTest,
  inspectRuntimeWriteSessionV03ForAdmission,
  inspectRuntimeWriteSessionV03ForDispatch,
  inspectRuntimeWriteSessionV03ForTermination,
  openRuntimeWriteSessionV03,
  poisonRuntimeWriteSessionV03ForAdmission,
  verifyRuntimeWriteSessionTailReadbackV03,
  verifyRuntimeWriteSessionAdmissionReadbackV03,
  type RuntimeWriteExpectationV03,
} from "../../src/run/runtime-write-session-v03.js";

const H = (character: string) => `sha256:${character.repeat(64)}`;
const encoder = new TextEncoder();
const inventory = {
  resolved_run_plan: "0.2", ledger_event: "0.3", run_manifest: "0.3", artifact_manifest: "0.2",
  redaction_derivative: "0.2", human_authorization_proof: "0.2", authority_envelope: "0.2",
  agency_recommendation: "0.2", authority_revocation: "0.2", task_result: "0.2",
  manual_observation: "0.2", export_decision: "0.2", evidence_item: "0.2", gate_result: "0.2",
  evaluation_result: "0.2", claim: "0.2", finding: "0.2", waiver: "0.2",
  gate_waiver_authority: "0.2",
} as const;
let fixtureOrdinal = 0;

function initialLedger(runId = "run_write_session_v03", active = false): Uint8Array {
  const preimage = {
    schema_version: "0.3", event_id: "event_write_initialized", run_id: runId,
    sequence: 1, recorded_at: "2026-08-24T10:00:00Z", event_type: "run.initialized",
    source: "kernel", authority_ref: null, risk_tier: "T1", related_ids: [], previous_event_hash: null,
    payload: { plan_hash: H("a"), initial_fence_epoch: 0, runtime_schema_versions: inventory },
  };
  const initialized = { ...preimage, event_hash: hashCanonical(preimage) };
  if (!active) return encoder.encode(`${JSON.stringify(initialized)}\n`);
  const startedPreimage = {
    schema_version: "0.3", event_id: "event_write_started_initial", run_id: runId,
    sequence: 2, recorded_at: "2026-08-24T10:00:01Z", event_type: "run.started",
    source: "kernel", authority_ref: null, risk_tier: "T1", related_ids: [],
    previous_event_hash: initialized.event_hash, payload: { executor_profile_hash: H("b") },
  };
  return encoder.encode(`${JSON.stringify(initialized)}\n${JSON.stringify({ ...startedPreimage, event_hash: hashCanonical(startedPreimage) })}\n`);
}

function files(ledger: Uint8Array, includePlan = true) {
  const rows = [
    { path: "artifact-manifest.json", family: "projection", required: false, mode: null, bytes: null },
    { path: "ledger.jsonl", family: "primary", required: true, mode: 384, bytes: ledger },
    { path: "records/authority.json", family: "record", required: true, mode: 384, bytes: encoder.encode('{"authority":"captured"}\n') },
  ] as Array<{ path: string; family: "primary" | "record" | "projection"; required: boolean; mode: 384 | null; bytes: Uint8Array | null }>;
  if (includePlan) rows.push({
    path: "resolved-run-plan.json", family: "primary", required: true, mode: 384,
    bytes: encoder.encode('{"plan":"captured"}\n'),
  });
  return rows;
}

function fixture(options: {
  runId?: string;
  capturedRunId?: string;
  faultAt?: string | null;
  lockIdentityValid?: boolean;
  envelopes?: readonly { event_id: string; recorded_at: string }[];
  includePlan?: boolean;
  active?: boolean;
} = {}) {
  const runId = options.runId ?? `run_write_session_v03_${fixtureOrdinal += 1}`;
  const ledger = initialLedger(runId, options.active ?? false);
  const capturedFiles = files(ledger, options.includePlan ?? true);
  const built = buildRunManifestV03({ ledger_bytes: ledger, created_at: "2026-08-24T10:00:00Z", captured_files: capturedFiles });
  if (!built.ok) throw new Error(built.reason);
  const authorityTrustContext = Object.freeze({});
  const admissionContext = {
    authority_trust_context: authorityTrustContext,
    repository_pre_state_hash: H("c"), normalized_dispatch_hash: H("d"),
    observed_at: "2026-08-24T10:00:00Z", elapsed_ms: 0, reviewer_view_hash: H("e"),
    enforcement: { available: true, information_flow_allowed: true, gates_passed: true, immediate_revalidation_passed: true },
    condition_results: [], lease_id: "lease_write_v03", clock_id: "clock_write_v03", action_id: "action_write_v03",
  };
  const storeInput = {
    run_id: options.capturedRunId ?? runId,
    ledger_bytes: ledger,
    manifest_bytes: built.bytes,
    captured_files: capturedFiles,
    lock_identity: "captured-lock-write-v03",
    lock_identity_valid: options.lockIdentityValid ?? true,
    event_envelopes: options.envelopes ?? [
      { event_id: "event_write_lease", recorded_at: "2026-08-24T10:00:01Z" },
      { event_id: "event_write_clock", recorded_at: "2026-08-24T10:00:02Z" },
      { event_id: "event_write_action", recorded_at: "2026-08-24T10:00:03Z" },
    ],
    fault_at: options.faultAt ?? null,
    admission_context: admissionContext,
  };
  const store = createSyntheticCapturedRuntimeRunStoreV03ForTest(storeInput);
  if (store === null) throw new Error("synthetic store fixture was rejected");
  const expectation: RuntimeWriteExpectationV03 = {
    run_id: runId,
    ledger_bytes_hash: built.manifest.ledger_bytes_hash,
    ledger_sequence: built.manifest.ledger_sequence,
    ledger_head_hash: built.manifest.ledger_head_hash,
    current_fence_epoch: built.manifest.current_fence_epoch,
    manifest_hash: built.manifest.manifest_hash,
  };
  const firstLine = new TextDecoder().decode(ledger).split("\n")[0];
  if (firstLine === undefined || firstLine.length === 0) throw new Error("initialized event fixture unavailable");
  const first = JSON.parse(firstLine) as { sequence: number; event_hash: string };
  return {
    store, expectation, initializedRef: { ledger_sequence: first.sequence, event_hash: first.event_hash },
    authorityTrustContext, admissionContext, storeInput,
    planSourceBytes: capturedFiles.find((row) => row.path === "resolved-run-plan.json")?.bytes ?? null,
  };
}

function startedDraft() {
  const draft = createRuntimeEventDraftV03({
    event_type: "run.started", source: "kernel", authority_ref: null, risk_tier: "T1", related_ids: [],
    payload: { executor_profile_hash: H("b") },
  });
  if (draft === null) throw new Error("draft fixture was rejected");
  return draft;
}

function eventDraft(input: {
  event_type: string;
  source: string;
  authority_ref: string | null;
  payload: Record<string, unknown>;
}) {
  const draft = createRuntimeEventDraftV03({
    ...input, risk_tier: "T1", related_ids: [],
  });
  if (draft === null) throw new Error(`${input.event_type} draft fixture was rejected`);
  return draft;
}

function integrityRejectionDraft(reasonCode = "capture-gap") {
  return eventDraft({
    event_type: "integrity.observation-rejected", source: "integrity", authority_ref: null,
    payload: {
      reason_code: reasonCode, observation_hash: H("d"),
      adapter_invocation_id: "adapter_write_v03", claimed_action_id: null,
    },
  });
}

describe("S40-B2 captured runtime write session V03", () => {
  it("rejects forged stores, sessions, drafts, and caller-supplied envelope fields", async () => {
    const { store, expectation } = fixture();
    await expect(openRuntimeWriteSessionV03(Object.freeze({}) as typeof store, expectation))
      .resolves.toEqual({ ok: false, error: "CAPTURED_STORE_INVALID" });
    const opened = await openRuntimeWriteSessionV03(store, expectation);
    if (!opened.ok) throw new Error(opened.error);
    await expect(appendRuntimeEventV03(Object.freeze({}) as typeof opened.session, startedDraft()))
      .resolves.toEqual({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_WRITE_SESSION_INVALID" });
    await expect(appendRuntimeEventV03(opened.session, Object.freeze({
      schema_version: "0.3", run_id: "forged", sequence: 999, previous_event_hash: H("f"), event_hash: H("f"),
      source: "kernel", authority_ref: null,
    }) as ReturnType<typeof startedDraft>)).resolves.toEqual({
      ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_EVENT_INVALID",
    });
    expect(Object.keys(startedDraft())).toEqual([]);
  });

  it("holds one exact non-stealable lock and binds the captured run identity", async () => {
    const first = fixture();
    const opened = await openRuntimeWriteSessionV03(first.store, first.expectation);
    expect(opened.ok).toBe(true);
    await expect(openRuntimeWriteSessionV03(first.store, first.expectation))
      .resolves.toEqual({ ok: false, error: "RUN_LOCK_UNAVAILABLE" });

    const sharedRun = `run_global_lock_${fixtureOrdinal += 1}`;
    const primary = fixture({ runId: sharedRun });
    const competing = fixture({ runId: sharedRun });
    const primaryOpen = await openRuntimeWriteSessionV03(primary.store, primary.expectation);
    expect(primaryOpen.ok).toBe(true);
    await expect(openRuntimeWriteSessionV03(competing.store, competing.expectation))
      .resolves.toEqual({ ok: false, error: "RUN_LOCK_UNAVAILABLE" });
    if (primaryOpen.ok) await expect(closeRuntimeWriteSessionV03(primaryOpen.session)).resolves.toBe(true);
    await expect(openRuntimeWriteSessionV03(competing.store, competing.expectation))
      .resolves.toMatchObject({ ok: true });

    const mismatched = fixture({ capturedRunId: "run_different_capture" });
    await expect(openRuntimeWriteSessionV03(mismatched.store, mismatched.expectation))
      .resolves.toEqual({ ok: false, error: "RUNTIME_EXPECTATION_MISMATCH" });
    const invalidLock = fixture({ lockIdentityValid: false });
    await expect(openRuntimeWriteSessionV03(invalidLock.store, invalidLock.expectation))
      .resolves.toEqual({ ok: false, error: "RUN_LOCK_IDENTITY_INVALID" });
  });

  it("publishes ledger and manifest in the exact durable order and returns only after exact readback", async () => {
    const { store, expectation } = fixture();
    const opened = await openRuntimeWriteSessionV03(store, expectation);
    if (!opened.ok) throw new Error(opened.error);
    const result = await appendRuntimeEventV03(opened.session, startedDraft());
    expect(result).toMatchObject({ ok: true, classification: "COMMITTED", event_ref: { ledger_sequence: 2 } });
    const snapshot = inspectSyntheticRuntimeRunStoreV03ForTest(store);
    expect(snapshot?.operations).toEqual([
      "lock-acquired", "prefix-validation:accepted", "append-write:began", "append-write:complete",
      "ledger-sync:confirmed", "ledger-close:confirmed", "ledger-readback:exact", "manifest-temp-write:complete",
      "manifest-temp-sync:confirmed", "manifest-temp-close:confirmed", "manifest-rename:complete", "directory-sync:confirmed", "final-readback:exact",
    ]);
    expect(snapshot?.poisoned).toBe(false);
    const capturedFiles = files(snapshot!.ledger_bytes);
    const inspected = inspectRunManifestV03({
      manifest_bytes: snapshot!.manifest_bytes, ledger_bytes: snapshot!.ledger_bytes, captured_files: capturedFiles,
    });
    expect(inspected).toMatchObject({ ok: true, manifest: { run_state: "running", ledger_sequence: 2 } });
  });

  it("verifies one exact committed event as the synchronized ledger tail", async () => {
    const { store, expectation } = fixture();
    const opened = await openRuntimeWriteSessionV03(store, expectation);
    if (!opened.ok) throw new Error(opened.error);
    const committed = await appendRuntimeEventV03(opened.session, startedDraft());
    if (!committed.ok) throw new Error(committed.error);
    const verified = await verifyRuntimeWriteSessionTailReadbackV03(opened.session, {
      events: [{ event_type: "run.started", event_ref: committed.event_ref }],
      manifest_hash: committed.manifest_hash,
    });
    expect(verified).toMatchObject({
      ok: true,
      readback: {
        run_id: expectation.run_id,
        plan_hash: H("a"),
        current_fence_epoch: 0,
        ledger_sequence: committed.event_ref.ledger_sequence,
        ledger_head_hash: committed.event_ref.event_hash,
        manifest_hash: committed.manifest_hash,
        events: [{ event_type: "run.started", sequence: committed.event_ref.ledger_sequence }],
      },
    });
    if (!verified.ok) throw new Error(verified.error);
    expect(Object.isFrozen(verified.readback)).toBe(true);
    expect(Object.isFrozen(verified.readback.events)).toBe(true);
    expect(verified.readback.events.every(Object.isFrozen)).toBe(true);
  });

  it("verifies a terminal-seal tail after its lifecycle transition", async () => {
    const terminalFixture = fixture();
    const terminalOpen = await openRuntimeWriteSessionV03(terminalFixture.store, terminalFixture.expectation);
    if (!terminalOpen.ok) throw new Error(terminalOpen.error);
    const started = await appendRuntimeEventV03(terminalOpen.session, startedDraft());
    if (!started.ok) throw new Error(started.error);
    const freeze = await appendRuntimeEventV03(terminalOpen.session, eventDraft({
      event_type: "run.terminal-freeze-entered", source: "evaluator", authority_ref: null,
      payload: {
        revision: 1, candidate: "completed", candidate_evidence_refs: [started.event_ref], fence_epoch: 0,
      },
    }));
    if (!freeze.ok) throw new Error(freeze.error);
    const sealed = await appendRuntimeEventV03(terminalOpen.session, eventDraft({
      event_type: "run.terminal-sealed", source: "evaluator", authority_ref: null,
      payload: {
        outcome: "completed", pre_seal_ledger_sequence: freeze.event_ref.ledger_sequence,
        pre_seal_ledger_head_hash: freeze.event_ref.event_hash, pre_seal_snapshot_hash: H("c"),
        previous_fence_epoch: 0, fence_epoch: 1,
      },
    }));
    if (!sealed.ok) throw new Error(sealed.error);
    await expect(verifyRuntimeWriteSessionTailReadbackV03(terminalOpen.session, {
      events: [{ event_type: "run.terminal-sealed", event_ref: sealed.event_ref }],
      manifest_hash: sealed.manifest_hash,
    })).resolves.toMatchObject({ ok: true, readback: { current_fence_epoch: 1, events: [{ event_type: "run.terminal-sealed" }] } });
  });

  it("atomically commits an exact rejection-quarantine pair and verifies its quarantined tail", async () => {
    const pairFixture = fixture();
    const opened = await openRuntimeWriteSessionV03(pairFixture.store, pairFixture.expectation);
    if (!opened.ok) throw new Error(opened.error);
    const started = await appendRuntimeEventV03(opened.session, startedDraft());
    if (!started.ok) throw new Error(started.error);
    const rejection = eventDraft({
      event_type: "integrity.observation-rejected", source: "integrity", authority_ref: null,
      payload: {
        reason_code: "capture-gap", observation_hash: H("d"),
        adapter_invocation_id: "adapter_write_v03", claimed_action_id: null,
      },
    });
    const committed = await appendRuntimeIntegrityQuarantinePairV03(opened.session, rejection);
    expect(committed, JSON.stringify(committed)).toMatchObject({
      ok: true,
      classification: "COMMITTED",
      event_refs: [{ ledger_sequence: 3 }, { ledger_sequence: 4 }],
    });
    if (!committed.ok) throw new Error(committed.error);
    const verified = await verifyRuntimeWriteSessionTailReadbackV03(opened.session, {
      events: [
        { event_type: "integrity.observation-rejected", event_ref: committed.event_refs[0] },
        { event_type: "run.quarantined", event_ref: committed.event_refs[1] },
      ],
      manifest_hash: committed.manifest_hash,
    });
    expect(verified).toMatchObject({
      ok: true,
      readback: { events: [{ event_type: "integrity.observation-rejected" }, { event_type: "run.quarantined" }] },
    });
    await expect(inspectRuntimeWriteSessionV03ForTermination(opened.session))
      .resolves.toMatchObject({ ok: true, snapshot: { events: [{}, {}, { event_type: "integrity.observation-rejected" }, { event_type: "run.quarantined" }] } });
  });

  it("rejects every non-rejection draft before any pair write", async () => {
    const pairFixture = fixture({ active: true });
    const opened = await openRuntimeWriteSessionV03(pairFixture.store, pairFixture.expectation);
    if (!opened.ok) throw new Error(opened.error);
    await expect(appendRuntimeIntegrityQuarantinePairV03(opened.session, startedDraft()))
      .resolves.toEqual({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_EVENT_INVALID" });
    expect(inspectSyntheticRuntimeRunStoreV03ForTest(pairFixture.store)?.operations).toEqual(["lock-acquired"]);
  });

  it("returns NOT_COMMITTED for a pair only when no write began", async () => {
    const pairFixture = fixture({ active: true, faultAt: "before-write" });
    const opened = await openRuntimeWriteSessionV03(pairFixture.store, pairFixture.expectation);
    if (!opened.ok) throw new Error(opened.error);
    const rejection = integrityRejectionDraft();
    await expect(appendRuntimeIntegrityQuarantinePairV03(opened.session, rejection))
      .resolves.toEqual({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_WRITE_NOT_COMMITTED" });
    expect(inspectSyntheticRuntimeRunStoreV03ForTest(pairFixture.store)).toMatchObject({
      poisoned: false, lock_held: false,
      operations: ["lock-acquired", "prefix-validation:accepted", "before-write:failed"],
    });
  });

  it.each([
    "append-write", "append-write-partial", "ledger-sync", "ledger-close", "ledger-readback",
    "manifest-temp-write", "manifest-temp-sync", "manifest-temp-close", "manifest-rename",
    "directory-sync", "final-readback",
  ] as const)("keeps pair %s ambiguity OUTCOME_UNKNOWN, poisoned, and non-retryable", async (faultAt) => {
    const pairFixture = fixture({ active: true, faultAt });
    const initialManifest = new Uint8Array(pairFixture.storeInput.manifest_bytes);
    const opened = await openRuntimeWriteSessionV03(pairFixture.store, pairFixture.expectation);
    if (!opened.ok) throw new Error(opened.error);
    const rejection = integrityRejectionDraft();
    await expect(appendRuntimeIntegrityQuarantinePairV03(opened.session, rejection))
      .resolves.toEqual({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_IO_OUTCOME_UNKNOWN" });
    const snapshot = inspectSyntheticRuntimeRunStoreV03ForTest(pairFixture.store)!;
    expect(snapshot.poisoned).toBe(true);
    const beforeRetry = snapshot.operations;
    await expect(appendRuntimeIntegrityQuarantinePairV03(opened.session, rejection))
      .resolves.toEqual({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_WRITE_SESSION_POISONED" });
    expect(inspectSyntheticRuntimeRunStoreV03ForTest(pairFixture.store)?.operations).toEqual(beforeRetry);
    if (faultAt === "append-write") {
      expect(inspectRuntimeLedgerV03(snapshot.ledger_bytes)).toMatchObject({
        ok: true, state: { state: "quarantine-required" }, ledger: { sequence: 3 },
      });
      expect(snapshot.manifest_bytes).toEqual(initialManifest);
    }
    if (faultAt === "append-write-partial") expect(inspectRuntimeLedgerV03(snapshot.ledger_bytes).ok).toBe(false);
  });

  it("allows abort-requested termination inspection but rejects a terminal seal", async () => {
    const abortFixture = fixture();
    const abortOpen = await openRuntimeWriteSessionV03(abortFixture.store, abortFixture.expectation);
    if (!abortOpen.ok) throw new Error(abortOpen.error);
    const started = await appendRuntimeEventV03(abortOpen.session, startedDraft());
    if (!started.ok) throw new Error(started.error);
    const abort = await appendRuntimeEventV03(abortOpen.session, eventDraft({
      event_type: "control.abort-requested", source: "operator", authority_ref: "principal_operator",
      payload: {
        request_id: "abort_write_v03", requested_by: "operator", reason_code: "operator-requested",
        policy_decision_ref: null, evidence_refs: [],
      },
    }));
    if (!abort.ok) throw new Error(abort.error);
    await expect(inspectRuntimeWriteSessionV03ForTermination(abortOpen.session))
      .resolves.toMatchObject({ ok: true, snapshot: { events: [{}, { event_type: "run.started" }, { event_type: "control.abort-requested" }] } });

    const terminalFixture = fixture();
    const terminalOpen = await openRuntimeWriteSessionV03(terminalFixture.store, terminalFixture.expectation);
    if (!terminalOpen.ok) throw new Error(terminalOpen.error);
    const terminalStarted = await appendRuntimeEventV03(terminalOpen.session, startedDraft());
    if (!terminalStarted.ok) throw new Error(terminalStarted.error);
    const freeze = await appendRuntimeEventV03(terminalOpen.session, eventDraft({
      event_type: "run.terminal-freeze-entered", source: "evaluator", authority_ref: null,
      payload: { revision: 1, candidate: "completed", candidate_evidence_refs: [terminalStarted.event_ref], fence_epoch: 0 },
    }));
    if (!freeze.ok) throw new Error(freeze.error);
    const sealed = await appendRuntimeEventV03(terminalOpen.session, eventDraft({
      event_type: "run.terminal-sealed", source: "evaluator", authority_ref: null,
      payload: {
        outcome: "completed", pre_seal_ledger_sequence: freeze.event_ref.ledger_sequence,
        pre_seal_ledger_head_hash: freeze.event_ref.event_hash, pre_seal_snapshot_hash: H("c"),
        previous_fence_epoch: 0, fence_epoch: 1,
      },
    }));
    if (!sealed.ok) throw new Error(sealed.error);
    await expect(inspectRuntimeWriteSessionV03ForTermination(terminalOpen.session))
      .resolves.toEqual({ ok: false, error: "RUN_TERMINAL" });
  });

  it("requires the exact ordered tail, head reference, and synchronized manifest", async () => {
    const { store, expectation, initializedRef } = fixture({ envelopes: [
      { event_id: "event_tail_started", recorded_at: "2026-08-24T10:00:01Z" },
      { event_id: "event_tail_paused", recorded_at: "2026-08-24T10:00:02Z" },
    ] });
    const opened = await openRuntimeWriteSessionV03(store, expectation);
    if (!opened.ok) throw new Error(opened.error);
    const started = await appendRuntimeEventV03(opened.session, startedDraft());
    if (!started.ok) throw new Error(started.error);
    const paused = await appendRuntimeEventV03(opened.session, eventDraft({
      event_type: "run.paused", source: "operator", authority_ref: "principal_operator",
      payload: { requested_by: "operator", reason_code: "operator-request", request_event_ref: initializedRef },
    }));
    if (!paused.ok) throw new Error(paused.error);
    const exact = {
      events: [
        { event_type: "run.started", event_ref: started.event_ref },
        { event_type: "run.paused", event_ref: paused.event_ref },
      ],
      manifest_hash: paused.manifest_hash,
    };
    await expect(verifyRuntimeWriteSessionTailReadbackV03(opened.session, exact))
      .resolves.toMatchObject({ ok: true, readback: { ledger_sequence: paused.event_ref.ledger_sequence } });
    const mismatches = [
      { ...exact, events: [...exact.events].reverse() },
      { ...exact, events: [{ ...exact.events[0]!, event_type: "run.paused" }, exact.events[1]!] },
      { ...exact, events: [exact.events[0]!, { ...exact.events[1]!, event_ref: started.event_ref }] },
      { ...exact, manifest_hash: H("f") },
      { ...exact, events: [exact.events[0]!] },
    ];
    for (const candidate of mismatches) {
      await expect(verifyRuntimeWriteSessionTailReadbackV03(opened.session, candidate))
        .resolves.toEqual({ ok: false, error: "TAIL_READBACK_MISMATCH" });
    }
  });

  it("rejects malformed, accessor-backed, extra-key, empty, oversized, and unsafe expectations", async () => {
    const { store, expectation } = fixture();
    const opened = await openRuntimeWriteSessionV03(store, expectation);
    if (!opened.ok) throw new Error(opened.error);
    const committed = await appendRuntimeEventV03(opened.session, startedDraft());
    if (!committed.ok) throw new Error(committed.error);
    const event = { event_type: "run.started", event_ref: committed.event_ref };
    const accessor = Object.defineProperty({}, "events", { enumerable: true, get: vi.fn() });
    Object.defineProperty(accessor, "manifest_hash", { enumerable: true, value: committed.manifest_hash });
    const malformed = [
      null,
      { events: [], manifest_hash: committed.manifest_hash },
      { events: [event, event, event, event], manifest_hash: committed.manifest_hash },
      { events: [event], manifest_hash: committed.manifest_hash, alias: true },
      { events: [{ ...event, alias: true }], manifest_hash: committed.manifest_hash },
      { events: [{ event_type: "run.started", event_ref: { ...committed.event_ref, alias: true } }], manifest_hash: committed.manifest_hash },
      { events: [{ event_type: "run.started", event_ref: { ledger_sequence: Number.MAX_SAFE_INTEGER + 1, event_hash: committed.event_ref.event_hash } }], manifest_hash: committed.manifest_hash },
      { events: [{ event_type: "run.started", event_ref: { ...committed.event_ref, event_hash: "sha256:ABC" } }], manifest_hash: committed.manifest_hash },
      { events: [event], manifest_hash: "sha256:short" },
      accessor,
    ];
    for (const candidate of malformed) {
      await expect(verifyRuntimeWriteSessionTailReadbackV03(opened.session, candidate))
        .resolves.toEqual({ ok: false, error: "TAIL_READBACK_MISMATCH" });
    }
    expect(Object.getOwnPropertyDescriptor(accessor, "events")?.get).not.toHaveBeenCalled();
  });

  it("fails closed for forged, closed, and poisoned tail-readback sessions", async () => {
    const expected = { events: [{ event_type: "run.started", event_ref: { ledger_sequence: 2, event_hash: H("b") } }], manifest_hash: H("c") };
    await expect(verifyRuntimeWriteSessionTailReadbackV03(Object.freeze({}) as never, expected))
      .resolves.toEqual({ ok: false, error: "RUNTIME_WRITE_SESSION_INVALID" });

    const closedFixture = fixture();
    const closedOpen = await openRuntimeWriteSessionV03(closedFixture.store, closedFixture.expectation);
    if (!closedOpen.ok) throw new Error(closedOpen.error);
    await closeRuntimeWriteSessionV03(closedOpen.session);
    await expect(verifyRuntimeWriteSessionTailReadbackV03(closedOpen.session, expected))
      .resolves.toEqual({ ok: false, error: "RUNTIME_WRITE_SESSION_CLOSED" });

    const poisonedFixture = fixture();
    const poisonedOpen = await openRuntimeWriteSessionV03(poisonedFixture.store, poisonedFixture.expectation);
    if (!poisonedOpen.ok) throw new Error(poisonedOpen.error);
    await poisonRuntimeWriteSessionV03ForAdmission(poisonedOpen.session);
    await expect(verifyRuntimeWriteSessionTailReadbackV03(poisonedOpen.session, expected))
      .resolves.toEqual({ ok: false, error: "RUNTIME_WRITE_SESSION_POISONED" });
  });

  it("fails closed when the authenticated session loses its exact held lock", async () => {
    const lockFixture = fixture();
    const opened = await openRuntimeWriteSessionV03(lockFixture.store, lockFixture.expectation);
    if (!opened.ok) throw new Error(opened.error);
    expect(invalidateSyntheticRuntimeRunStoreLockV03ForTest(lockFixture.store)).toBe(true);
    await expect(verifyRuntimeWriteSessionTailReadbackV03(opened.session, {
      events: [{ event_type: "run.initialized", event_ref: lockFixture.initializedRef }],
      manifest_hash: lockFixture.expectation.manifest_hash,
    })).resolves.toEqual({ ok: false, error: "RUN_LOCK_IDENTITY_INVALID" });
    await expect(inspectRuntimeWriteSessionV03ForTermination(opened.session))
      .resolves.toEqual({ ok: false, error: "RUN_LOCK_IDENTITY_INVALID" });
  });

  it.each([
    "append-write", "ledger-sync", "ledger-close", "ledger-readback", "manifest-temp-write", "manifest-temp-sync",
    "manifest-temp-close", "manifest-rename", "directory-sync", "final-readback",
  ])("classifies %s ambiguity OUTCOME_UNKNOWN, poisons permanently, and never retries", async (faultAt) => {
    const { store, expectation } = fixture({ faultAt });
    const opened = await openRuntimeWriteSessionV03(store, expectation);
    if (!opened.ok) throw new Error(opened.error);
    await expect(appendRuntimeEventV03(opened.session, startedDraft())).resolves.toEqual({
      ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_IO_OUTCOME_UNKNOWN",
    });
    const beforeRetry = inspectSyntheticRuntimeRunStoreV03ForTest(store)!.operations;
    await expect(appendRuntimeEventV03(opened.session, startedDraft())).resolves.toEqual({
      ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_WRITE_SESSION_POISONED",
    });
    expect(inspectSyntheticRuntimeRunStoreV03ForTest(store)!.operations).toEqual(beforeRetry);
    await expect(openRuntimeWriteSessionV03(store, expectation))
      .resolves.toEqual({ ok: false, error: "RUNTIME_IO_OUTCOME_UNKNOWN" });
  });

  it("returns NOT_COMMITTED only with proof that no write began and closes that session", async () => {
    const { store, expectation } = fixture({ faultAt: "before-write" });
    const opened = await openRuntimeWriteSessionV03(store, expectation);
    if (!opened.ok) throw new Error(opened.error);
    await expect(appendRuntimeEventV03(opened.session, startedDraft())).resolves.toEqual({
      ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_WRITE_NOT_COMMITTED",
    });
    expect(inspectSyntheticRuntimeRunStoreV03ForTest(store)).toMatchObject({
      poisoned: false, lock_held: false, operations: ["lock-acquired", "prefix-validation:accepted", "before-write:failed"],
    });
    await expect(appendRuntimeEventV03(opened.session, startedDraft())).resolves.toEqual({
      ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_WRITE_SESSION_CLOSED",
    });
  });

  it("serializes concurrent calls without interleaving their durability steps", async () => {
    const { store, expectation, initializedRef } = fixture({ envelopes: [
      { event_id: "event_write_started", recorded_at: "2026-08-24T10:00:01Z" },
      { event_id: "event_write_paused", recorded_at: "2026-08-24T10:00:02Z" },
    ] });
    const pause = createRuntimeEventDraftV03({
      event_type: "run.paused", source: "operator", authority_ref: "principal_operator",
      risk_tier: "T1", related_ids: [],
      payload: { requested_by: "operator", reason_code: "operator-request", request_event_ref: initializedRef },
    });
    if (pause === null) throw new Error("pause fixture was rejected");
    const opened = await openRuntimeWriteSessionV03(store, expectation);
    if (!opened.ok) throw new Error(opened.error);
    const [started, paused] = await Promise.all([
      appendRuntimeEventV03(opened.session, startedDraft()),
      appendRuntimeEventV03(opened.session, pause),
    ]);
    expect(started).toMatchObject({ ok: true, event_ref: { ledger_sequence: 2 } });
    expect(paused).toMatchObject({ ok: true, event_ref: { ledger_sequence: 3 } });
    const operations = inspectSyntheticRuntimeRunStoreV03ForTest(store)!.operations;
    expect(operations.filter((step) => step === "final-readback:exact")).toHaveLength(2);
    expect(operations.indexOf("final-readback:exact")).toBeLessThan(operations.lastIndexOf("prefix-validation:accepted"));
  });

  it("serializes close behind an in-flight append and rejects every later append", async () => {
    const { store, expectation } = fixture();
    const opened = await openRuntimeWriteSessionV03(store, expectation);
    if (!opened.ok) throw new Error(opened.error);
    const append = appendRuntimeEventV03(opened.session, startedDraft());
    const close = closeRuntimeWriteSessionV03(opened.session);
    await expect(append).resolves.toMatchObject({ ok: true, classification: "COMMITTED" });
    await expect(close).resolves.toBe(true);
    expect(inspectSyntheticRuntimeRunStoreV03ForTest(store)?.operations.at(-1)).toBe("lock-released");
    await expect(appendRuntimeEventV03(opened.session, startedDraft())).resolves.toEqual({
      ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_WRITE_SESSION_CLOSED",
    });
  });

  it("captures an immutable admission view while preserving only the opaque trust capability identity", async () => {
    const { store, expectation, authorityTrustContext, admissionContext } = fixture();
    admissionContext.enforcement.available = false;
    admissionContext.condition_results.push("mutated-after-capture" as never);
    const opened = await openRuntimeWriteSessionV03(store, expectation);
    if (!opened.ok) throw new Error(opened.error);
    const first = await inspectRuntimeWriteSessionV03ForAdmission(opened.session);
    const second = await inspectRuntimeWriteSessionV03ForAdmission(opened.session);
    expect(first).toMatchObject({
      ok: true,
      snapshot: {
        ledger_sequence: 1,
        current_fence_epoch: 0,
        plan_capture: { path: "resolved-run-plan.json" },
        record_captures: [{ path: "records/authority.json" }],
        envelopes: [
          { event_id: "event_write_lease" }, { event_id: "event_write_clock" }, { event_id: "event_write_action" },
        ],
        admission_context: { enforcement: { available: true }, condition_results: [] },
      },
    });
    if (!first.ok || !second.ok) throw new Error("admission snapshot failed");
    const firstContext = first.snapshot.admission_context as { authority_trust_context: object; enforcement: object };
    const secondContext = second.snapshot.admission_context as { authority_trust_context: object; enforcement: object };
    expect(firstContext.authority_trust_context).toBe(authorityTrustContext);
    expect(secondContext.authority_trust_context).toBe(authorityTrustContext);
    expect(firstContext).not.toBe(secondContext);
    expect(firstContext.enforcement).not.toBe(secondContext.enforcement);
    expect(Object.isFrozen(firstContext.enforcement)).toBe(true);
    const record = first.snapshot.record_captures[0]!;
    record.bytes[0] = 0;
    const third = await inspectRuntimeWriteSessionV03ForAdmission(opened.session);
    expect(third).toMatchObject({ ok: true, snapshot: { record_captures: [{ raw_hash: record.raw_hash }] } });
    if (third.ok) expect(third.snapshot.record_captures[0]!.bytes[0]).not.toBe(0);
  });

  it("rejects malformed admission capture without invoking accessors or proxy traps", () => {
    const { storeInput } = fixture();
    const getter = vi.fn(() => Object.freeze({}));
    const accessor = { ...storeInput.admission_context };
    Object.defineProperty(accessor, "authority_trust_context", { enumerable: true, get: getter });
    expect(createSyntheticCapturedRuntimeRunStoreV03ForTest({ ...storeInput, admission_context: accessor })).toBeNull();
    expect(getter).not.toHaveBeenCalled();
    const hostile = { ...storeInput.admission_context, enforcement: new Proxy({}, {
      getPrototypeOf: () => { throw new Error("nested trap"); },
    }) };
    expect(createSyntheticCapturedRuntimeRunStoreV03ForTest({ ...storeInput, admission_context: hostile })).toBeNull();
    const { action_id: _removed, ...missing } = storeInput.admission_context;
    expect(createSyntheticCapturedRuntimeRunStoreV03ForTest({ ...storeInput, admission_context: missing })).toBeNull();
    expect(createSyntheticCapturedRuntimeRunStoreV03ForTest({
      ...storeInput,
      admission_context: { ...storeInput.admission_context, reviewer_view_hash: "x".repeat(1_048_577) },
    })).toBeNull();
  });

  it("requires one exact root resolved-plan capture and owns its bytes", async () => {
    const absent = fixture({ includePlan: false });
    const absentOpen = await openRuntimeWriteSessionV03(absent.store, absent.expectation);
    if (!absentOpen.ok) throw new Error(absentOpen.error);
    await expect(inspectRuntimeWriteSessionV03ForAdmission(absentOpen.session))
      .resolves.toEqual({ ok: false, error: "ADMISSION_CAPTURE_INVALID" });

    const mutable = fixture();
    const source = mutable.planSourceBytes;
    if (source === null) throw new Error("plan source fixture missing");
    const originalFirstByte = source[0]!;
    source[0] = 0;
    const mutableOpen = await openRuntimeWriteSessionV03(mutable.store, mutable.expectation);
    if (!mutableOpen.ok) throw new Error(mutableOpen.error);
    const first = await inspectRuntimeWriteSessionV03ForAdmission(mutableOpen.session);
    if (!first.ok) throw new Error(first.error);
    expect(first.snapshot.plan_capture.bytes[0]).toBe(originalFirstByte);
    const planHash = first.snapshot.plan_capture.raw_hash;
    first.snapshot.plan_capture.bytes[0] = 0;
    const second = await inspectRuntimeWriteSessionV03ForAdmission(mutableOpen.session);
    expect(second).toMatchObject({ ok: true, snapshot: { plan_capture: { raw_hash: planHash } } });
    if (second.ok) expect(second.snapshot.plan_capture.bytes[0]).toBe(originalFirstByte);

    const ambiguous = fixture();
    const aliasRow = {
      path: "captures/resolved-run-plan.json", family: "primary" as const, required: true, mode: 384 as const,
      bytes: encoder.encode('{"plan":"alias"}\n'),
    };
    const ambiguousFiles = [...ambiguous.storeInput.captured_files, aliasRow]
      .sort((left, right) => Buffer.from(left.path).compare(Buffer.from(right.path)));
    const ledger = ambiguous.storeInput.ledger_bytes;
    const manifest = buildRunManifestV03({
      ledger_bytes: ledger, created_at: "2026-08-24T10:00:00Z", captured_files: ambiguousFiles,
    });
    if (!manifest.ok) throw new Error(manifest.reason);
    const ambiguousStore = createSyntheticCapturedRuntimeRunStoreV03ForTest({
      ...ambiguous.storeInput, captured_files: ambiguousFiles, manifest_bytes: manifest.bytes,
    });
    if (ambiguousStore === null) throw new Error("ambiguous store fixture rejected too early");
    const ambiguousOpen = await openRuntimeWriteSessionV03(ambiguousStore, {
      ...ambiguous.expectation, manifest_hash: manifest.manifest.manifest_hash,
    });
    if (!ambiguousOpen.ok) throw new Error(ambiguousOpen.error);
    await expect(inspectRuntimeWriteSessionV03ForAdmission(ambiguousOpen.session))
      .resolves.toEqual({ ok: false, error: "ADMISSION_CAPTURE_INVALID" });
  });

  it("authenticates admission inspection, validates final readback input, and atomically poisons", async () => {
    const { store, expectation } = fixture();
    const opened = await openRuntimeWriteSessionV03(store, expectation);
    if (!opened.ok) throw new Error(opened.error);
    await expect(inspectRuntimeWriteSessionV03ForAdmission(Object.freeze({}) as typeof opened.session))
      .resolves.toEqual({ ok: false, error: "RUNTIME_WRITE_SESSION_INVALID" });
    await expect(verifyRuntimeWriteSessionAdmissionReadbackV03(opened.session, {
      lease_event_ref: { ledger_sequence: 1, event_hash: H("a") },
      admission_clock_ref: { ledger_sequence: 2, event_hash: H("b") },
      action_admission_event_ref: { ledger_sequence: 3, event_hash: H("c") },
      manifest_hash: H("d"),
    })).resolves.toEqual({ ok: false, error: "ADMISSION_READBACK_MISMATCH" });
    await expect(poisonRuntimeWriteSessionV03ForAdmission(opened.session)).resolves.toBe(true);
    await expect(inspectRuntimeWriteSessionV03ForAdmission(opened.session))
      .resolves.toEqual({ ok: false, error: "RUNTIME_WRITE_SESSION_POISONED" });
    await expect(appendRuntimeEventV03(opened.session, startedDraft())).resolves.toEqual({
      ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_WRITE_SESSION_POISONED",
    });
    expect(inspectSyntheticRuntimeRunStoreV03ForTest(store)).toMatchObject({ poisoned: true });
  });

  it("returns a frozen dispatch snapshot after envelopes are consumed without exposing admission captures", async () => {
    const { store, expectation } = fixture({
      envelopes: [{ event_id: "event_dispatch_started", recorded_at: "2026-08-24T10:00:01Z" }],
    });
    const opened = await openRuntimeWriteSessionV03(store, expectation);
    if (!opened.ok) throw new Error(opened.error);
    const committed = await appendRuntimeEventV03(opened.session, startedDraft());
    expect(committed).toMatchObject({ ok: true, event_ref: { ledger_sequence: 2 } });
    const inspected = await inspectRuntimeWriteSessionV03ForDispatch(opened.session);
    expect(inspected).toMatchObject({
      ok: true,
      snapshot: { run_id: expectation.run_id, ledger_sequence: 2, events: [{ event_type: "run.initialized" }, { event_type: "run.started" }] },
    });
    if (!inspected.ok) throw new Error(inspected.error);
    expect(Object.keys(inspected.snapshot).sort()).toEqual([
      "current_fence_epoch", "events", "ledger_head_hash", "ledger_sequence", "manifest_hash", "plan_hash", "run_id",
    ]);
    expect(Object.isFrozen(inspected.snapshot)).toBe(true);
    expect(Object.isFrozen(inspected.snapshot.events)).toBe(true);
    expect(inspected.snapshot.events.every(Object.isFrozen)).toBe(true);
  });

  it("preserves an admitted event risk tier as frozen validated snapshot data", async () => {
    const { store, expectation } = fixture({
      envelopes: [{ event_id: "event_risk_tier_started", recorded_at: "2026-08-24T10:00:01Z" }],
    });
    const opened = await openRuntimeWriteSessionV03(store, expectation);
    if (!opened.ok) throw new Error(opened.error);
    const draft = createRuntimeEventDraftV03({
      event_type: "run.started", source: "kernel", authority_ref: null, risk_tier: "T5", related_ids: [],
      payload: { executor_profile_hash: H("b") },
    });
    if (draft === null) throw new Error("risk-tier draft fixture was rejected");
    const committed = await appendRuntimeEventV03(opened.session, draft);
    if (!committed.ok) throw new Error(committed.error);

    const dispatch = await inspectRuntimeWriteSessionV03ForDispatch(opened.session);
    const termination = await inspectRuntimeWriteSessionV03ForTermination(opened.session);
    const tail = await verifyRuntimeWriteSessionTailReadbackV03(opened.session, {
      events: [{ event_type: "run.started", event_ref: committed.event_ref }],
      manifest_hash: committed.manifest_hash,
    });

    if (!dispatch.ok || !termination.ok || !tail.ok) throw new Error("risk-tier snapshot inspection failed");
    const captured = [
      dispatch.snapshot.events.at(-1),
      termination.snapshot.events.at(-1),
      tail.readback.events.at(-1),
    ];
    expect(captured.map((event) => event?.risk_tier)).toEqual(["T5", "T5", "T5"]);
    expect(captured.every((event) => event !== undefined && Object.isFrozen(event))).toBe(true);
  });

  it("fails closed for forged, closed, and poisoned dispatch sessions", async () => {
    const closed = fixture();
    const closedOpen = await openRuntimeWriteSessionV03(closed.store, closed.expectation);
    if (!closedOpen.ok) throw new Error(closedOpen.error);
    await expect(inspectRuntimeWriteSessionV03ForDispatch(Object.freeze({}) as typeof closedOpen.session))
      .resolves.toEqual({ ok: false, error: "RUNTIME_WRITE_SESSION_INVALID" });
    await closeRuntimeWriteSessionV03(closedOpen.session);
    await expect(inspectRuntimeWriteSessionV03ForDispatch(closedOpen.session))
      .resolves.toEqual({ ok: false, error: "RUNTIME_WRITE_SESSION_CLOSED" });

    const poisoned = fixture();
    const poisonedOpen = await openRuntimeWriteSessionV03(poisoned.store, poisoned.expectation);
    if (!poisonedOpen.ok) throw new Error(poisonedOpen.error);
    await poisonRuntimeWriteSessionV03ForAdmission(poisonedOpen.session);
    await expect(inspectRuntimeWriteSessionV03ForDispatch(poisonedOpen.session))
      .resolves.toEqual({ ok: false, error: "RUNTIME_WRITE_SESSION_POISONED" });
  });
});
