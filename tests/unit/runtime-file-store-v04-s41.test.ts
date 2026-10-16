import {
  constants,
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { open as openFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { hashCanonical, hashRawBytes } from "../../src/hash.js";
import { captureRunFileForRuntimeV02 } from "../../src/io/runtime-file-capture-v02.js";
import { buildRunManifestV04 } from "../../src/run/runtime-manifest-v04.js";
import {
  captureRuntimeFileStoreV04,
  captureRuntimeFileStoreV04ForTest,
  closeRuntimeFileStoreSessionV04,
  commitRuntimeCompactionFileStoreSessionV04,
  commitRuntimeFileStoreSessionV04,
  openRuntimeFileStoreSessionV04,
  readRuntimeFileStoreSessionSnapshotV04,
} from "../../src/run/runtime-file-store-v04.js";

const roots: string[] = [];
const encoder = new TextEncoder();
const H = (character: string) => `sha256:${character.repeat(64)}`;
const inventory = {
  resolved_run_plan: "0.3", ledger_event: "0.4", run_manifest: "0.4",
  artifact_manifest: "0.2", redaction_derivative: "0.2", human_authorization_proof: "0.2",
  authority_envelope: "0.2", agency_recommendation: "0.2", authority_revocation: "0.2",
  task_result: "0.2", manual_observation: "0.2", export_decision: "0.2", evidence_item: "0.2",
  gate_result: "0.2", evaluation_result: "0.2", claim: "0.2", finding: "0.2", waiver: "0.2",
  gate_waiver_authority: "0.2", summary_artifact: "0.1",
} as const;

type LedgerEvent = Record<string, unknown> & Readonly<{ event_hash: string }>;

function makeRoot(): string {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "loopeix-runtime-file-store-")));
  roots.push(root);
  return root;
}

function writeMode0600(path: string, bytes: Uint8Array | string, mode = 0o600): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, bytes, { mode });
  chmodSync(path, mode);
}

function event(
  prior: readonly LedgerEvent[],
  event_type: string,
  source: string,
  authority_ref: string | null,
  payload: Record<string, unknown>,
): LedgerEvent {
  const sequence = prior.length + 1;
  const preimage = {
    schema_version: "0.4",
    event_id: `event_runtime_store_${sequence}`,
    run_id: "run_runtime_store_v04",
    sequence,
    recorded_at: `2026-08-30T12:00:${String(sequence).padStart(2, "0")}Z`,
    event_type,
    source,
    authority_ref,
    risk_tier: "T1",
    related_ids: [],
    previous_event_hash: prior.at(-1)?.event_hash ?? null,
    payload,
  };
  return { ...preimage, event_hash: hashCanonical(preimage) };
}

function baseEvents(): LedgerEvent[] {
  const events: LedgerEvent[] = [];
  events.push(event(events, "run.initialized", "kernel", null, {
    plan_hash: H("a"),
    initial_fence_epoch: 0,
    runtime_schema_versions: inventory,
  }));
  return events;
}

function startedEvents(): LedgerEvent[] {
  const events = baseEvents();
  events.push(event(events, "run.started", "kernel", null, { executor_profile_hash: H("b") }));
  return events;
}

function ref(value: LedgerEvent) {
  return { ledger_sequence: value.sequence as number, event_hash: value.event_hash };
}

function compactionSourceEvents(): LedgerEvent[] {
  const events = baseEvents();
  const started = event(events, "run.started", "kernel", null, { executor_profile_hash: H("b") });
  events.push(started);
  const runClock = event(events, "run.clock-observed", "kernel", null, {
    clock_id: "clock_runtime_store_run", observed_at: "2026-08-30T12:00:03Z", elapsed_ms: 1,
    reason: "run-owner-acquisition", task_ref: null, failure_ordinal: null, use_ref: "run_owner_runtime_store_1",
    attempt_ref: null, owner_lease_ref: null, boot_id_hash: H("1"), monotonic_clock_id: "clock_runtime_store_1",
  });
  events.push(runClock);
  const attempt = event(events, "execution.attempt-started", "kernel", null, {
    attempt_id: "attempt_runtime_store_1", attempt_ordinal: 1, mode: "ordinary",
    previous_attempt_event_ref: null, resume_request_event_ref: null, resume_nonce_hash: null,
    source_boundary_sequence: started.sequence, source_boundary_head_hash: started.event_hash, source_manifest_hash: H("c"),
    plan_hash: H("a"), input_hash: H("d"), recovery_policy_hash: H("e"), authority_envelope_hash: H("f"),
    repository_state_hash: H("9"), run_owner_lease_id: "run_owner_runtime_store_1", issued_clock_ref: ref(runClock),
    deadline_elapsed_ms: 1_000, boot_id_hash: H("1"), monotonic_clock_id: "clock_runtime_store_1",
    previous_fence_epoch: 0, fence_epoch: 0,
  });
  events.push(attempt);
  const integratorClock = event(events, "run.clock-observed", "kernel", null, {
    clock_id: "clock_runtime_store_integrator", observed_at: "2026-08-30T12:00:05Z", elapsed_ms: 2,
    reason: "owner-acquisition", task_ref: null, failure_ordinal: null, use_ref: "integrator_runtime_store_1",
    attempt_ref: ref(attempt), owner_lease_ref: ref(attempt), boot_id_hash: H("1"), monotonic_clock_id: "clock_runtime_store_1",
  });
  events.push(integratorClock);
  events.push(event(events, "ownership.lease-acquired", "policy-enforcement-point", "authority_runtime_store", {
    owner_lease_id: "integrator_runtime_store_1", scope: "integrator", scope_ref: "summary_runtime_store_1",
    parent_run_owner_lease_id: "run_owner_runtime_store_1", attempt_event_ref: ref(attempt),
    issued_clock_ref: ref(integratorClock), deadline_elapsed_ms: 999, boot_id_hash: H("1"),
    monotonic_clock_id: "clock_runtime_store_1", fence_epoch: 0, heartbeat_limit: 2,
  }));
  return events;
}

function ledgerBytes(events: readonly LedgerEvent[]): Uint8Array {
  return encoder.encode(`${events.map((value) => JSON.stringify(value)).join("\n")}\n`);
}

function runFixture() {
  const root = makeRoot();
  const planBytes = encoder.encode('{"schema_version":"0.2","run":"fixture"}\n');
  const recordBytes = encoder.encode("owned-record\n");
  const initialLedgerBytes = ledgerBytes(baseEvents());
  const initialCapturedFiles = [
    { path: "resolved-run-plan.json", family: "primary" as const, required: true, mode: 384 as const, bytes: planBytes },
    { path: "ledger.jsonl", family: "primary" as const, required: true, mode: 384 as const, bytes: initialLedgerBytes },
    { path: "records/evidence.bin", family: "record" as const, required: true, mode: 384 as const, bytes: recordBytes },
    { path: "records/optional.bin", family: "record" as const, required: false, mode: null, bytes: null },
  ];
  const initialManifest = buildRunManifestV04({
    ledger_bytes: initialLedgerBytes,
    created_at: "2026-08-30T12:01:00Z",
    captured_files: initialCapturedFiles,
  });
  if (!initialManifest.ok) throw new Error(initialManifest.reason);
  writeMode0600(join(root, "resolved-run-plan.json"), planBytes);
  writeMode0600(join(root, "ledger.jsonl"), initialLedgerBytes);
  mkdirSync(join(root, "records"), { recursive: true, mode: 0o700 });
  writeMode0600(join(root, "records/evidence.bin"), recordBytes);
  writeMode0600(join(root, "run-manifest.json"), initialManifest.bytes);

  const nextLedgerBytes = ledgerBytes(startedEvents());
  const nextManifest = buildRunManifestV04({
    ledger_bytes: nextLedgerBytes,
    created_at: "2026-08-30T12:01:00Z",
    captured_files: [
      { path: "resolved-run-plan.json", family: "primary" as const, required: true, mode: 384 as const, bytes: planBytes },
      { path: "ledger.jsonl", family: "primary" as const, required: true, mode: 384 as const, bytes: nextLedgerBytes },
      { path: "records/evidence.bin", family: "record" as const, required: true, mode: 384 as const, bytes: recordBytes },
      { path: "records/optional.bin", family: "record" as const, required: false, mode: null, bytes: null },
    ],
  });
  if (!nextManifest.ok) throw new Error(nextManifest.reason);

  return {
    root,
    planBytes,
    recordBytes,
    initialLedgerBytes,
    initialManifestBytes: initialManifest.bytes,
    initialManifestHash: initialManifest.manifest.manifest_hash,
    nextLedgerBytes,
    nextManifestBytes: nextManifest.bytes,
    nextManifestHash: nextManifest.manifest.manifest_hash,
  };
}

function compactionFixture() {
  const root = makeRoot();
  const planBytes = encoder.encode('{"schema_version":"0.3","run":"compaction-fixture"}\n');
  const priorRecordBytes = encoder.encode("owned-record\n");
  const sourceEvents = compactionSourceEvents();
  const initialLedgerBytes = ledgerBytes(sourceEvents);
  const initialFiles = [
    { path: "resolved-run-plan.json", family: "primary" as const, required: true, mode: 384 as const, bytes: planBytes },
    { path: "ledger.jsonl", family: "primary" as const, required: true, mode: 384 as const, bytes: initialLedgerBytes },
    { path: "records/evidence.bin", family: "record" as const, required: true, mode: 384 as const, bytes: priorRecordBytes },
  ];
  const initialManifest = buildRunManifestV04({
    ledger_bytes: initialLedgerBytes,
    created_at: "2026-08-30T12:01:00Z",
    captured_files: initialFiles,
  });
  if (!initialManifest.ok) throw new Error(initialManifest.reason);

  const summaryId = "summary_runtime_store_1";
  const contentPath = `summaries/content/${summaryId}.bin`;
  const recordPath = `summaries/records/${summaryId}.json`;
  const contentBytes = encoder.encode("exact immutable summary content\n");
  const recordBytes = encoder.encode('{"schema_version":"0.1","summary_id":"summary_runtime_store_1"}\n');
  const attempt = sourceEvents[3]!;
  const integrator = sourceEvents[5]!;
  const first = sourceEvents[0]!;
  const prefix = sourceEvents.at(-1)!;
  const nextEvents = [...sourceEvents];
  nextEvents.push(event(nextEvents, "run.compaction-recorded", "kernel", null, {
    summary_id: summaryId,
    summary_record_path: recordPath,
    summary_record_hash: hashRawBytes(recordBytes),
    summary_content_path: contentPath,
    summary_content_hash: hashRawBytes(contentBytes),
    summary_size_bytes: contentBytes.byteLength,
    attempt_event_ref: ref(attempt),
    integrator_lease_event_ref: ref(integrator),
    source_first_event_ref: ref(first),
    source_last_event_ref: ref(prefix),
    source_prefix_sequence: prefix.sequence,
    source_prefix_head_hash: prefix.event_hash,
    pre_context_hash: H("2"),
    post_context_hash: H("3"),
  }));
  const nextLedgerBytes = ledgerBytes(nextEvents);
  const nextManifest = buildRunManifestV04({
    ledger_bytes: nextLedgerBytes,
    created_at: "2026-08-30T12:01:00Z",
    captured_files: [
      { ...initialFiles[0]!, bytes: planBytes },
      { ...initialFiles[1]!, bytes: nextLedgerBytes },
      initialFiles[2]!,
      { path: contentPath, family: "record" as const, required: true, mode: 384 as const, bytes: contentBytes },
      { path: recordPath, family: "record" as const, required: true, mode: 384 as const, bytes: recordBytes },
    ],
  });
  if (!nextManifest.ok) throw new Error(nextManifest.reason);

  writeMode0600(join(root, "resolved-run-plan.json"), planBytes);
  writeMode0600(join(root, "ledger.jsonl"), initialLedgerBytes);
  writeMode0600(join(root, "records/evidence.bin"), priorRecordBytes);
  writeMode0600(join(root, "run-manifest.json"), initialManifest.bytes);
  mkdirSync(join(root, "summaries/content"), { recursive: true, mode: 0o700 });
  mkdirSync(join(root, "summaries/records"), { recursive: true, mode: 0o700 });

  return {
    root, initialLedgerBytes, initialManifestBytes: initialManifest.bytes,
    initialManifestHash: initialManifest.manifest.manifest_hash,
    contentPath, contentBytes, recordPath, recordBytes, nextLedgerBytes,
    nextManifestBytes: nextManifest.bytes, nextManifestHash: nextManifest.manifest.manifest_hash,
  };
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("S41-C2 file-backed runtime store", () => {
  it("commits exact next ledger and manifest bytes to disk and snapshots owned copies only", async () => {
    const fixture = runFixture();
    const captured = await captureRuntimeFileStoreV04({ run_directory: fixture.root });
    expect(captured.ok).toBe(true);
    if (!captured.ok) return;

    const opened = await openRuntimeFileStoreSessionV04(captured.store);
    expect(opened).toMatchObject({ ok: true });
    if (!opened.ok) return;

    const snapshot = readRuntimeFileStoreSessionSnapshotV04(opened.session);
    expect(snapshot).toMatchObject({ ok: true });
    if (!snapshot.ok) return;
    expect(snapshot.snapshot.captured_files.map((file) => file.path)).toEqual([
      "ledger.jsonl",
      "records/evidence.bin",
      "records/optional.bin",
      "resolved-run-plan.json",
    ]);
    snapshot.snapshot.ledger_bytes.fill(0);
    snapshot.snapshot.resolved_run_plan_bytes.fill(1);
    if (snapshot.snapshot.captured_files[0]?.bytes !== null) snapshot.snapshot.captured_files[0].bytes.fill(2);
    expect(readFileSync(join(fixture.root, "ledger.jsonl"))).toEqual(Buffer.from(fixture.initialLedgerBytes));

    const committed = await commitRuntimeFileStoreSessionV04(opened.session, {
      expected_ledger_bytes_hash: hashRawBytes(fixture.initialLedgerBytes),
      expected_manifest_hash: fixture.initialManifestHash,
      next_ledger_bytes: fixture.nextLedgerBytes,
      next_manifest_bytes: fixture.nextManifestBytes,
    });
    expect(committed).toEqual({
      ok: true,
      classification: "COMMITTED",
      ledger_bytes_hash: hashRawBytes(fixture.nextLedgerBytes),
      manifest_hash: fixture.nextManifestHash,
    });
    expect(readFileSync(join(fixture.root, "ledger.jsonl"))).toEqual(Buffer.from(fixture.nextLedgerBytes));
    expect(readFileSync(join(fixture.root, "run-manifest.json"))).toEqual(Buffer.from(fixture.nextManifestBytes));

    const after = readRuntimeFileStoreSessionSnapshotV04(opened.session);
    expect(after).toMatchObject({ ok: true });
    if (after.ok) {
      expect(after.snapshot.ledger_bytes).toEqual(fixture.nextLedgerBytes);
      expect(after.snapshot.manifest_bytes).toEqual(fixture.nextManifestBytes);
    }
    await expect(closeRuntimeFileStoreSessionV04(opened.session)).resolves.toBe(true);
    expect(existsSync(join(fixture.root, ".runtime-v04.lock"))).toBe(false);
  });

  it("refuses concurrent lock acquisition and later allows a new session after release", async () => {
    const fixture = runFixture();
    const captured = await captureRuntimeFileStoreV04({ run_directory: fixture.root });
    if (!captured.ok) throw new Error(captured.error);
    const first = await openRuntimeFileStoreSessionV04(captured.store);
    expect(first).toMatchObject({ ok: true });
    const second = await openRuntimeFileStoreSessionV04(captured.store);
    expect(second).toEqual({ ok: false, error: "RUN_LOCK_UNAVAILABLE" });
    if (first.ok) await closeRuntimeFileStoreSessionV04(first.session);
    const third = await openRuntimeFileStoreSessionV04(captured.store);
    expect(third).toMatchObject({ ok: true });
    if (third.ok) await closeRuntimeFileStoreSessionV04(third.session);
  });

  it("rejects invalid root paths plus symlink, hardlink, and mode drifted runtime files", async () => {
    await expect(captureRuntimeFileStoreV04({ run_directory: "relative/path" })).resolves.toEqual({
      ok: false,
      error: "RUN_DIRECTORY_INVALID",
    });

    const symlinkFixture = runFixture();
    unlinkSync(join(symlinkFixture.root, "records/evidence.bin"));
    writeMode0600(join(symlinkFixture.root, "records/target.bin"), symlinkFixture.recordBytes);
    symlinkSync("target.bin", join(symlinkFixture.root, "records/evidence.bin"));
    await expect(captureRuntimeFileStoreV04({ run_directory: symlinkFixture.root })).resolves.toEqual({
      ok: false,
      error: "RUN_FILE_NOT_REGULAR",
    });

    const hardlinkFixture = runFixture();
    linkSync(join(hardlinkFixture.root, "resolved-run-plan.json"), join(hardlinkFixture.root, "resolved-run-plan.link"));
    await expect(captureRuntimeFileStoreV04({ run_directory: hardlinkFixture.root })).resolves.toEqual({
      ok: false,
      error: "RUN_FILE_IDENTITY_CHANGED",
    });

    const modeFixture = runFixture();
    chmodSync(join(modeFixture.root, "resolved-run-plan.json"), 0o644);
    await expect(captureRuntimeFileStoreV04({ run_directory: modeFixture.root })).resolves.toEqual({
      ok: false,
      error: "RUN_FILE_MODE_INVALID",
    });
  });

  it("fails closed before append when expectations do not match the captured head", async () => {
    const fixture = runFixture();
    const captured = await captureRuntimeFileStoreV04({ run_directory: fixture.root });
    if (!captured.ok) throw new Error(captured.error);
    const opened = await openRuntimeFileStoreSessionV04(captured.store);
    if (!opened.ok) throw new Error(opened.error);
    await expect(commitRuntimeFileStoreSessionV04(opened.session, {
      expected_ledger_bytes_hash: hashRawBytes(fixture.nextLedgerBytes),
      expected_manifest_hash: fixture.initialManifestHash,
      next_ledger_bytes: fixture.nextLedgerBytes,
      next_manifest_bytes: fixture.nextManifestBytes,
    })).resolves.toEqual({
      ok: false,
      classification: "NOT_COMMITTED",
      error: "RUNTIME_EXPECTATION_MISMATCH",
    });
    expect(readFileSync(join(fixture.root, "ledger.jsonl"))).toEqual(Buffer.from(fixture.initialLedgerBytes));
    await closeRuntimeFileStoreSessionV04(opened.session);
  });

  it("poisons the session on injected append, sync, rename, and readback ambiguities", async () => {
    const partial = runFixture();
    let writeCalls = 0;
    const partialStore = await captureRuntimeFileStoreV04ForTest({ run_directory: partial.root }, {
      write: async (handle, bytes, offset, length, position) => {
        writeCalls += 1;
        if (position === null && writeCalls === 2) return Math.max(1, Math.floor(length / 2));
        return (await handle.write(bytes, offset, length, position)).bytesWritten;
      },
    });
    if (!partialStore.ok) throw new Error(partialStore.error);
    const partialSession = await openRuntimeFileStoreSessionV04(partialStore.store);
    if (!partialSession.ok) throw new Error(partialSession.error);
    await expect(commitRuntimeFileStoreSessionV04(partialSession.session, {
      expected_ledger_bytes_hash: hashRawBytes(partial.initialLedgerBytes),
      expected_manifest_hash: partial.initialManifestHash,
      next_ledger_bytes: partial.nextLedgerBytes,
      next_manifest_bytes: partial.nextManifestBytes,
    })).resolves.toEqual({
      ok: false,
      classification: "OUTCOME_UNKNOWN",
      error: "RUNTIME_IO_OUTCOME_UNKNOWN",
    });
    await expect(commitRuntimeFileStoreSessionV04(partialSession.session, {
      expected_ledger_bytes_hash: hashRawBytes(partial.initialLedgerBytes),
      expected_manifest_hash: partial.initialManifestHash,
      next_ledger_bytes: partial.nextLedgerBytes,
      next_manifest_bytes: partial.nextManifestBytes,
    })).resolves.toEqual({
      ok: false,
      classification: "OUTCOME_UNKNOWN",
      error: "RUNTIME_FILE_STORE_SESSION_POISONED",
    });
    await closeRuntimeFileStoreSessionV04(partialSession.session);

    const thrownWriteFixture = runFixture();
    let thrownWriteCalls = 0;
    const thrownWriteStore = await captureRuntimeFileStoreV04ForTest({ run_directory: thrownWriteFixture.root }, {
      write: async (handle, bytes, offset, length, position) => {
        thrownWriteCalls += 1;
        if (position === null && thrownWriteCalls === 2) throw new Error("append write threw");
        return (await handle.write(bytes, offset, length, position)).bytesWritten;
      },
    });
    if (!thrownWriteStore.ok) throw new Error(thrownWriteStore.error);
    const thrownWriteSession = await openRuntimeFileStoreSessionV04(thrownWriteStore.store);
    if (!thrownWriteSession.ok) throw new Error(thrownWriteSession.error);
    await expect(commitRuntimeFileStoreSessionV04(thrownWriteSession.session, {
      expected_ledger_bytes_hash: hashRawBytes(thrownWriteFixture.initialLedgerBytes),
      expected_manifest_hash: thrownWriteFixture.initialManifestHash,
      next_ledger_bytes: thrownWriteFixture.nextLedgerBytes,
      next_manifest_bytes: thrownWriteFixture.nextManifestBytes,
    })).resolves.toEqual({
      ok: false,
      classification: "OUTCOME_UNKNOWN",
      error: "RUNTIME_IO_OUTCOME_UNKNOWN",
    });
    await closeRuntimeFileStoreSessionV04(thrownWriteSession.session);

    const syncFixture = runFixture();
    let syncCalls = 0;
    const syncStore = await captureRuntimeFileStoreV04ForTest({ run_directory: syncFixture.root }, {
      sync: async (handle) => {
        syncCalls += 1;
        if (syncCalls === 3) throw new Error("append sync failed");
        await handle.sync();
      },
    });
    if (!syncStore.ok) throw new Error(syncStore.error);
    const syncSession = await openRuntimeFileStoreSessionV04(syncStore.store);
    if (!syncSession.ok) throw new Error(syncSession.error);
    await expect(commitRuntimeFileStoreSessionV04(syncSession.session, {
      expected_ledger_bytes_hash: hashRawBytes(syncFixture.initialLedgerBytes),
      expected_manifest_hash: syncFixture.initialManifestHash,
      next_ledger_bytes: syncFixture.nextLedgerBytes,
      next_manifest_bytes: syncFixture.nextManifestBytes,
    })).resolves.toMatchObject({
      ok: false,
      classification: "OUTCOME_UNKNOWN",
      error: "RUNTIME_IO_OUTCOME_UNKNOWN",
    });
    await closeRuntimeFileStoreSessionV04(syncSession.session);

    const renameFixture = runFixture();
    const renameStore = await captureRuntimeFileStoreV04ForTest({ run_directory: renameFixture.root }, {
      rename: async () => {
        throw new Error("rename failed");
      },
    });
    if (!renameStore.ok) throw new Error(renameStore.error);
    const renameSession = await openRuntimeFileStoreSessionV04(renameStore.store);
    if (!renameSession.ok) throw new Error(renameSession.error);
    await expect(commitRuntimeFileStoreSessionV04(renameSession.session, {
      expected_ledger_bytes_hash: hashRawBytes(renameFixture.initialLedgerBytes),
      expected_manifest_hash: renameFixture.initialManifestHash,
      next_ledger_bytes: renameFixture.nextLedgerBytes,
      next_manifest_bytes: renameFixture.nextManifestBytes,
    })).resolves.toMatchObject({
      ok: false,
      classification: "OUTCOME_UNKNOWN",
      error: "RUNTIME_IO_OUTCOME_UNKNOWN",
    });
    await closeRuntimeFileStoreSessionV04(renameSession.session);

    const readbackFixture = runFixture();
    let manifestCaptures = 0;
    const readbackStore = await captureRuntimeFileStoreV04ForTest({ run_directory: readbackFixture.root }, {
      capture_file: async (input) => {
        manifestCaptures += input.relative_path === "run-manifest.json" ? 1 : 0;
        if (input.relative_path === "run-manifest.json" && manifestCaptures >= 3) {
          return {
            ok: true,
            value: {
              relative_path: input.relative_path,
              metadata: {
                mode: 384,
                size_bytes: readbackFixture.nextManifestBytes.byteLength,
                sha256: hashRawBytes(readbackFixture.nextManifestBytes),
              } as never,
              bytes: readbackFixture.initialManifestBytes,
            } as never,
          };
        }
        return captureRunFileForRuntimeV02(input);
      },
    });
    if (!readbackStore.ok) throw new Error(readbackStore.error);
    const readbackSession = await openRuntimeFileStoreSessionV04(readbackStore.store);
    if (!readbackSession.ok) throw new Error(readbackSession.error);
    await expect(commitRuntimeFileStoreSessionV04(readbackSession.session, {
      expected_ledger_bytes_hash: hashRawBytes(readbackFixture.initialLedgerBytes),
      expected_manifest_hash: readbackFixture.initialManifestHash,
      next_ledger_bytes: readbackFixture.nextLedgerBytes,
      next_manifest_bytes: readbackFixture.nextManifestBytes,
    })).resolves.toMatchObject({
      ok: false,
      classification: "OUTCOME_UNKNOWN",
      error: "RUNTIME_IO_OUTCOME_UNKNOWN",
    });
    await closeRuntimeFileStoreSessionV04(readbackSession.session);
  });

  it("treats append-handle open failure as definite pre-write not-committed and allows later success", async () => {
    const fixture = runFixture();
    let failAppendOpenOnce = true;
    const captured = await captureRuntimeFileStoreV04ForTest({ run_directory: fixture.root }, {
      open: async (path, flags, mode) => {
        const readWriteMask = constants.O_RDONLY | constants.O_WRONLY | constants.O_RDWR;
        if (
          failAppendOpenOnce
          && path === join(fixture.root, "ledger.jsonl")
          && (flags & readWriteMask) === constants.O_WRONLY
          && (flags & constants.O_APPEND) === constants.O_APPEND
          && (flags & constants.O_CREAT) === 0
        ) {
          failAppendOpenOnce = false;
          throw new Error("append open failed");
        }
        return mode === undefined ? openFile(path, flags) : openFile(path, flags, mode);
      },
    });
    if (!captured.ok) throw new Error(captured.error);
    const opened = await openRuntimeFileStoreSessionV04(captured.store);
    if (!opened.ok) throw new Error(opened.error);

    await expect(commitRuntimeFileStoreSessionV04(opened.session, {
      expected_ledger_bytes_hash: hashRawBytes(fixture.initialLedgerBytes),
      expected_manifest_hash: fixture.initialManifestHash,
      next_ledger_bytes: fixture.nextLedgerBytes,
      next_manifest_bytes: fixture.nextManifestBytes,
    })).resolves.toEqual({
      ok: false,
      classification: "NOT_COMMITTED",
      error: "RUNTIME_IO_NOT_COMMITTED",
    });
    expect(readFileSync(join(fixture.root, "ledger.jsonl"))).toEqual(Buffer.from(fixture.initialLedgerBytes));

    await expect(commitRuntimeFileStoreSessionV04(opened.session, {
      expected_ledger_bytes_hash: hashRawBytes(fixture.initialLedgerBytes),
      expected_manifest_hash: fixture.initialManifestHash,
      next_ledger_bytes: fixture.nextLedgerBytes,
      next_manifest_bytes: fixture.nextManifestBytes,
    })).resolves.toEqual({
      ok: true,
      classification: "COMMITTED",
      ledger_bytes_hash: hashRawBytes(fixture.nextLedgerBytes),
      manifest_hash: fixture.nextManifestHash,
    });
    await closeRuntimeFileStoreSessionV04(opened.session);
  });

  it("only removes the descriptor-proven owned lock path during close", async () => {
    const fixture = runFixture();
    const captured = await captureRuntimeFileStoreV04({ run_directory: fixture.root });
    if (!captured.ok) throw new Error(captured.error);
    const opened = await openRuntimeFileStoreSessionV04(captured.store);
    if (!opened.ok) throw new Error(opened.error);

    const replacementPath = join(fixture.root, ".runtime-v04.lock");
    unlinkSync(replacementPath);
    writeMode0600(replacementPath, "replacement");
    await expect(closeRuntimeFileStoreSessionV04(opened.session)).resolves.toBe(false);
    expect(readFileSync(replacementPath, "utf8")).toBe("replacement");
  });

  it("commits one compaction transaction with immutable summary files and exact final inventory", async () => {
    const fixture = compactionFixture();
    const captured = await captureRuntimeFileStoreV04({ run_directory: fixture.root });
    if (!captured.ok) throw new Error(captured.error);
    const opened = await openRuntimeFileStoreSessionV04(captured.store);
    if (!opened.ok) throw new Error(opened.error);

    const committed = await commitRuntimeCompactionFileStoreSessionV04(opened.session, {
      expected_ledger_bytes_hash: hashRawBytes(fixture.initialLedgerBytes),
      expected_manifest_hash: fixture.initialManifestHash,
      summary_content: { relative_path: fixture.contentPath, bytes: fixture.contentBytes },
      summary_record: { relative_path: fixture.recordPath, bytes: fixture.recordBytes },
      next_ledger_bytes: fixture.nextLedgerBytes,
      next_manifest_bytes: fixture.nextManifestBytes,
    });
    expect(committed).toEqual({
      ok: true,
      classification: "COMMITTED",
      ledger_bytes_hash: hashRawBytes(fixture.nextLedgerBytes),
      manifest_hash: fixture.nextManifestHash,
      summary_content_hash: hashRawBytes(fixture.contentBytes),
      summary_record_hash: hashRawBytes(fixture.recordBytes),
    });
    expect(readFileSync(join(fixture.root, fixture.contentPath))).toEqual(Buffer.from(fixture.contentBytes));
    expect(readFileSync(join(fixture.root, fixture.recordPath))).toEqual(Buffer.from(fixture.recordBytes));
    expect(readFileSync(join(fixture.root, "ledger.jsonl"))).toEqual(Buffer.from(fixture.nextLedgerBytes));
    expect(readFileSync(join(fixture.root, "run-manifest.json"))).toEqual(Buffer.from(fixture.nextManifestBytes));
    const snapshot = readRuntimeFileStoreSessionSnapshotV04(opened.session);
    expect(snapshot.ok && snapshot.snapshot.captured_files.map((file) => file.path)).toEqual([
      "ledger.jsonl",
      "records/evidence.bin",
      "resolved-run-plan.json",
      fixture.contentPath,
      fixture.recordPath,
    ].sort());
    await closeRuntimeFileStoreSessionV04(opened.session);
  });

  it("rejects malformed compaction bindings and existing final paths without altering durable state", async () => {
    const fixture = compactionFixture();
    const captured = await captureRuntimeFileStoreV04({ run_directory: fixture.root });
    if (!captured.ok) throw new Error(captured.error);
    const opened = await openRuntimeFileStoreSessionV04(captured.store);
    if (!opened.ok) throw new Error(opened.error);
    const invalid = await commitRuntimeCompactionFileStoreSessionV04(opened.session, {
      expected_ledger_bytes_hash: hashRawBytes(fixture.initialLedgerBytes),
      expected_manifest_hash: fixture.initialManifestHash,
      summary_content: { relative_path: fixture.contentPath, bytes: encoder.encode("wrong") },
      summary_record: { relative_path: fixture.recordPath, bytes: fixture.recordBytes },
      next_ledger_bytes: fixture.nextLedgerBytes,
      next_manifest_bytes: fixture.nextManifestBytes,
    });
    expect(invalid).toEqual({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_COMPACTION_INVALID" });
    expect(existsSync(join(fixture.root, fixture.contentPath))).toBe(false);
    expect(readFileSync(join(fixture.root, "ledger.jsonl"))).toEqual(Buffer.from(fixture.initialLedgerBytes));

    writeMode0600(join(fixture.root, fixture.contentPath), "unowned-existing");
    const replay = await commitRuntimeCompactionFileStoreSessionV04(opened.session, {
      expected_ledger_bytes_hash: hashRawBytes(fixture.initialLedgerBytes),
      expected_manifest_hash: fixture.initialManifestHash,
      summary_content: { relative_path: fixture.contentPath, bytes: fixture.contentBytes },
      summary_record: { relative_path: fixture.recordPath, bytes: fixture.recordBytes },
      next_ledger_bytes: fixture.nextLedgerBytes,
      next_manifest_bytes: fixture.nextManifestBytes,
    });
    expect(replay).toEqual({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_COMPACTION_PATH_EXISTS" });
    expect(readFileSync(join(fixture.root, fixture.contentPath), "utf8")).toBe("unowned-existing");
    await closeRuntimeFileStoreSessionV04(opened.session);
  });

  it("cleans only descriptor-proven compaction files before append", async () => {
    const fixture = compactionFixture();
    let writes = 0;
    const captured = await captureRuntimeFileStoreV04ForTest({ run_directory: fixture.root }, {
      write: async (handle, bytes, offset, length, position) => {
        writes += 1;
        if (writes === 2) throw new Error("record write failed before append");
        return (await handle.write(bytes, offset, length, position)).bytesWritten;
      },
    });
    if (!captured.ok) throw new Error(captured.error);
    const opened = await openRuntimeFileStoreSessionV04(captured.store);
    if (!opened.ok) throw new Error(opened.error);
    const result = await commitRuntimeCompactionFileStoreSessionV04(opened.session, {
      expected_ledger_bytes_hash: hashRawBytes(fixture.initialLedgerBytes),
      expected_manifest_hash: fixture.initialManifestHash,
      summary_content: { relative_path: fixture.contentPath, bytes: fixture.contentBytes },
      summary_record: { relative_path: fixture.recordPath, bytes: fixture.recordBytes },
      next_ledger_bytes: fixture.nextLedgerBytes,
      next_manifest_bytes: fixture.nextManifestBytes,
    });
    expect(result).toEqual({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_IO_NOT_COMMITTED" });
    expect(existsSync(join(fixture.root, fixture.contentPath))).toBe(false);
    expect(existsSync(join(fixture.root, fixture.recordPath))).toBe(false);
    expect(readFileSync(join(fixture.root, "ledger.jsonl"))).toEqual(Buffer.from(fixture.initialLedgerBytes));
    await closeRuntimeFileStoreSessionV04(opened.session);
  });

  it("poisons rather than deleting a replacement at an invocation-owned path", async () => {
    const fixture = compactionFixture();
    let writes = 0;
    const captured = await captureRuntimeFileStoreV04ForTest({ run_directory: fixture.root }, {
      write: async (handle, bytes, offset, length, position) => {
        writes += 1;
        if (writes === 2) {
          unlinkSync(join(fixture.root, fixture.contentPath));
          writeMode0600(join(fixture.root, fixture.contentPath), "replacement-not-owned-by-invocation");
          throw new Error("write failed after path replacement");
        }
        return (await handle.write(bytes, offset, length, position)).bytesWritten;
      },
    });
    if (!captured.ok) throw new Error(captured.error);
    const opened = await openRuntimeFileStoreSessionV04(captured.store);
    if (!opened.ok) throw new Error(opened.error);
    const result = await commitRuntimeCompactionFileStoreSessionV04(opened.session, {
      expected_ledger_bytes_hash: hashRawBytes(fixture.initialLedgerBytes), expected_manifest_hash: fixture.initialManifestHash,
      summary_content: { relative_path: fixture.contentPath, bytes: fixture.contentBytes },
      summary_record: { relative_path: fixture.recordPath, bytes: fixture.recordBytes },
      next_ledger_bytes: fixture.nextLedgerBytes, next_manifest_bytes: fixture.nextManifestBytes,
    });
    expect(result).toEqual({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_IO_OUTCOME_UNKNOWN" });
    expect(readFileSync(join(fixture.root, fixture.contentPath), "utf8")).toBe("replacement-not-owned-by-invocation");
    await closeRuntimeFileStoreSessionV04(opened.session);
  });

  it("rejects symlink and hardlink occupants at either immutable final path", async () => {
    for (const kind of ["symlink", "hardlink"] as const) {
      const fixture = compactionFixture();
      const target = join(fixture.root, "records/occupant-target.bin");
      writeMode0600(target, "unmanifested-occupant-target");
      const occupied = join(fixture.root, kind === "symlink" ? fixture.contentPath : fixture.recordPath);
      if (kind === "symlink") symlinkSync(target, occupied);
      else linkSync(target, occupied);
      const captured = await captureRuntimeFileStoreV04({ run_directory: fixture.root });
      if (!captured.ok) throw new Error(captured.error);
      const opened = await openRuntimeFileStoreSessionV04(captured.store);
      if (!opened.ok) throw new Error(opened.error);
      expect(await commitRuntimeCompactionFileStoreSessionV04(opened.session, {
        expected_ledger_bytes_hash: hashRawBytes(fixture.initialLedgerBytes), expected_manifest_hash: fixture.initialManifestHash,
        summary_content: { relative_path: fixture.contentPath, bytes: fixture.contentBytes },
        summary_record: { relative_path: fixture.recordPath, bytes: fixture.recordBytes },
        next_ledger_bytes: fixture.nextLedgerBytes, next_manifest_bytes: fixture.nextManifestBytes,
      })).toEqual({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_COMPACTION_PATH_EXISTS" });
      expect(readFileSync(join(fixture.root, "ledger.jsonl"))).toEqual(Buffer.from(fixture.initialLedgerBytes));
      await closeRuntimeFileStoreSessionV04(opened.session);
    }
  });

  it("cleans before append when a captured summary directory drifts", async () => {
    const fixture = compactionFixture();
    let syncs = 0;
    const captured = await captureRuntimeFileStoreV04ForTest({ run_directory: fixture.root }, {
      sync: async (handle) => {
        syncs += 1;
        await handle.sync();
        if (syncs === 4) chmodSync(join(fixture.root, "summaries/content"), 0o755);
      },
    });
    if (!captured.ok) throw new Error(captured.error);
    const opened = await openRuntimeFileStoreSessionV04(captured.store);
    if (!opened.ok) throw new Error(opened.error);
    expect(await commitRuntimeCompactionFileStoreSessionV04(opened.session, {
      expected_ledger_bytes_hash: hashRawBytes(fixture.initialLedgerBytes), expected_manifest_hash: fixture.initialManifestHash,
      summary_content: { relative_path: fixture.contentPath, bytes: fixture.contentBytes },
      summary_record: { relative_path: fixture.recordPath, bytes: fixture.recordBytes },
      next_ledger_bytes: fixture.nextLedgerBytes, next_manifest_bytes: fixture.nextManifestBytes,
    })).toEqual({ ok: false, classification: "NOT_COMMITTED", error: "RUNTIME_IO_NOT_COMMITTED" });
    expect(existsSync(join(fixture.root, fixture.contentPath))).toBe(false);
    expect(readFileSync(join(fixture.root, "ledger.jsonl"))).toEqual(Buffer.from(fixture.initialLedgerBytes));
    await closeRuntimeFileStoreSessionV04(opened.session);
  });

  it("never cleans or retries after the compaction ledger append is attempted", async () => {
    const fixture = compactionFixture();
    let writes = 0;
    const captured = await captureRuntimeFileStoreV04ForTest({ run_directory: fixture.root }, {
      write: async (handle, bytes, offset, length, position) => {
        writes += 1;
        if (position === null) return Math.max(1, Math.floor(length / 2));
        return (await handle.write(bytes, offset, length, position)).bytesWritten;
      },
    });
    if (!captured.ok) throw new Error(captured.error);
    const opened = await openRuntimeFileStoreSessionV04(captured.store);
    if (!opened.ok) throw new Error(opened.error);
    const input = {
      expected_ledger_bytes_hash: hashRawBytes(fixture.initialLedgerBytes),
      expected_manifest_hash: fixture.initialManifestHash,
      summary_content: { relative_path: fixture.contentPath, bytes: fixture.contentBytes },
      summary_record: { relative_path: fixture.recordPath, bytes: fixture.recordBytes },
      next_ledger_bytes: fixture.nextLedgerBytes,
      next_manifest_bytes: fixture.nextManifestBytes,
    };
    expect(await commitRuntimeCompactionFileStoreSessionV04(opened.session, input)).toEqual({
      ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_IO_OUTCOME_UNKNOWN",
    });
    expect(readFileSync(join(fixture.root, fixture.contentPath))).toEqual(Buffer.from(fixture.contentBytes));
    expect(readFileSync(join(fixture.root, fixture.recordPath))).toEqual(Buffer.from(fixture.recordBytes));
    expect(await commitRuntimeCompactionFileStoreSessionV04(opened.session, input)).toEqual({
      ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_FILE_STORE_SESSION_POISONED",
    });
    await closeRuntimeFileStoreSessionV04(opened.session);
  });

  it("poisons without cleanup when manifest publication or final summary readback is ambiguous", async () => {
    const renameFixture = compactionFixture();
    const renameStore = await captureRuntimeFileStoreV04ForTest({ run_directory: renameFixture.root }, {
      rename: async () => { throw new Error("manifest rename failed after append"); },
    });
    if (!renameStore.ok) throw new Error(renameStore.error);
    const renameSession = await openRuntimeFileStoreSessionV04(renameStore.store);
    if (!renameSession.ok) throw new Error(renameSession.error);
    expect(await commitRuntimeCompactionFileStoreSessionV04(renameSession.session, {
      expected_ledger_bytes_hash: hashRawBytes(renameFixture.initialLedgerBytes), expected_manifest_hash: renameFixture.initialManifestHash,
      summary_content: { relative_path: renameFixture.contentPath, bytes: renameFixture.contentBytes },
      summary_record: { relative_path: renameFixture.recordPath, bytes: renameFixture.recordBytes },
      next_ledger_bytes: renameFixture.nextLedgerBytes, next_manifest_bytes: renameFixture.nextManifestBytes,
    })).toEqual({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_IO_OUTCOME_UNKNOWN" });
    expect(existsSync(join(renameFixture.root, renameFixture.contentPath))).toBe(true);
    expect(existsSync(join(renameFixture.root, renameFixture.recordPath))).toBe(true);
    await closeRuntimeFileStoreSessionV04(renameSession.session);

    const readbackFixture = compactionFixture();
    let contentCaptures = 0;
    const readbackStore = await captureRuntimeFileStoreV04ForTest({ run_directory: readbackFixture.root }, {
      capture_file: async (input) => {
        if (input.relative_path === readbackFixture.contentPath) contentCaptures += 1;
        if (input.relative_path === readbackFixture.contentPath && contentCaptures >= 3) {
          const wrong = new Uint8Array(readbackFixture.contentBytes.byteLength).fill(1);
          return { ok: true, value: { relative_path: input.relative_path,
            metadata: { mode: 384, size_bytes: wrong.byteLength, sha256: hashRawBytes(wrong) } as never,
            bytes: wrong } as never };
        }
        return captureRunFileForRuntimeV02(input);
      },
    });
    if (!readbackStore.ok) throw new Error(readbackStore.error);
    const readbackSession = await openRuntimeFileStoreSessionV04(readbackStore.store);
    if (!readbackSession.ok) throw new Error(readbackSession.error);
    expect(await commitRuntimeCompactionFileStoreSessionV04(readbackSession.session, {
      expected_ledger_bytes_hash: hashRawBytes(readbackFixture.initialLedgerBytes), expected_manifest_hash: readbackFixture.initialManifestHash,
      summary_content: { relative_path: readbackFixture.contentPath, bytes: readbackFixture.contentBytes },
      summary_record: { relative_path: readbackFixture.recordPath, bytes: readbackFixture.recordBytes },
      next_ledger_bytes: readbackFixture.nextLedgerBytes, next_manifest_bytes: readbackFixture.nextManifestBytes,
    })).toEqual({ ok: false, classification: "OUTCOME_UNKNOWN", error: "RUNTIME_IO_OUTCOME_UNKNOWN" });
    expect(existsSync(join(readbackFixture.root, readbackFixture.contentPath))).toBe(true);
    expect(existsSync(join(readbackFixture.root, readbackFixture.recordPath))).toBe(true);
    await closeRuntimeFileStoreSessionV04(readbackSession.session);
  });
});
