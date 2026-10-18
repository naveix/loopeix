import { generateKeyPairSync, randomBytes } from "node:crypto";
import { chmodSync, constants, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { lstat, open, realpath, rename, rm, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { canonicalize, hashCanonical, hashRawBytes } from "../../src/hash.js";
import { S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02 } from "../../src/run/action-classifier-policy-v02.js";
import {
  buildS37ProductHostActivationManifestV01,
  hashS37ProductHostActivationEventV01,
} from "../../src/run/s37-product-host-activation-contract-v01.js";
import {
  beginS37ProductHostAuthoritySessionForTestV01,
  captureS37ProductHostAuthorityCustodyV01,
  closeS37ProductHostActivationStoreSessionV01,
  commitS37ProductHostActivationEventV01,
  commitS37ProductHostAuthorizationNonceV01,
  commitS37ProductHostQualificationNonceV01,
  createS37ProductHostActivationStoreForTestV01,
  disposeS37ProductHostActivationStoreV01,
  inspectS37ProductHostActivationStoreSessionV01,
  inspectS37ProductHostAuthorityCustodyV01,
  openS37ProductHostActivationStoreSessionV01,
  reconcileS37ProductHostActivationStoreV01,
  recaptureS37ProductHostAuthorityTrustV01,
  type CapturedS37ProductHostActivationStoreV01,
  type S37ProductHostActivationStoreIoV01,
} from "../../src/run/s37-product-host-activation-store-v01.js";

const roots: string[] = [];
const capturedStores: CapturedS37ProductHostActivationStoreV01[] = [];
const descriptorFaultCleanups: Array<() => Promise<void>> = [];
const H = (character: string): string => `sha256:${character.repeat(64)}`;
const REQUEST = H("1");
const ACTIVATION_ID = `activation_${REQUEST.slice("sha256:".length)}`;

function fixtureRoot(): string {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "loopeix-s37-g2-")));
  roots.push(root);
  chmodSync(root, 0o755);
  const activation = join(root, "activation");
  mkdirSync(activation, { mode: 0o700 });
  for (const name of ["activation-ledger.jsonl", "authorization-nonces.jsonl", "qualification-nonces.jsonl"]) {
    writeFileSync(join(activation, name), new Uint8Array(), { mode: 0o600 });
  }
  return root;
}

function owner(): Readonly<{ uid: bigint; gid: bigint }> {
  const stats = statSync(roots.at(-1)!, { bigint: true });
  return { uid: stats.uid, gid: stats.gid };
}

function ioWithRenameFailure(): S37ProductHostActivationStoreIoV01 {
  return Object.freeze({
    lstat: (path: string) => lstat(path, { bigint: true }),
    realpath,
    open,
    rename: async (source: string, destination: string) => {
      if (destination.endsWith("activation-ledger.jsonl")) throw Object.assign(new Error("ambiguous rename"), { code: "EIO" });
      await rename(source, destination);
    },
    unlink,
    random_bytes: (size: number) => randomBytes(size),
  });
}

function ioWithPostLedgerRenameFailure(): S37ProductHostActivationStoreIoV01 {
  let failed = false;
  return Object.freeze({
    lstat: (path: string) => lstat(path, { bigint: true }),
    realpath,
    open,
    rename: async (source: string, destination: string) => {
      await rename(source, destination);
      if (!failed && destination.endsWith("activation-ledger.jsonl")) {
        failed = true;
        throw Object.assign(new Error("rename committed but acknowledgement failed"), { code: "EIO" });
      }
    },
    unlink,
    random_bytes: (size: number) => randomBytes(size),
  });
}

function ioWithCloseFailure(failPath: (path: string) => boolean): Readonly<{
  io: S37ProductHostActivationStoreIoV01;
  close_attempts: string[];
}> {
  const closeAttempts: string[] = [];
  let failed = false;
  return {
    close_attempts: closeAttempts,
    io: {
      lstat: (path) => lstat(path, { bigint: true }), realpath, rename, unlink,
      random_bytes: (size) => randomBytes(size),
      open: async (path, flags, mode) => {
        const handle = await open(path, flags, mode);
        const close = handle.close.bind(handle);
        handle.close = async () => {
          closeAttempts.push(path);
          if (!failed && failPath(path)) {
            failed = true;
            // This injected failure precedes the real close. Test teardown owns
            // that still-open real descriptor; production must never retry it.
            descriptorFaultCleanups.push(close);
            throw Object.assign(new Error("injected close ambiguity"), { code: "EIO" });
          }
          await close();
        };
        return handle;
      },
    },
  };
}

const SIGNER_READ_FAILURES = [
  "partial-eof", "read-throw", "growth-probe", "probe-throw", "post-handle-stat",
  "post-handle-identity", "post-path-stat", "post-path-identity", "post-directory-identity",
  "post-directory-stat", "post-directory-realpath", "close-ambiguity",
] as const;
type SignerReadFailure = typeof SIGNER_READ_FAILURES[number];

function ioWithRetainedSignerReads(target: string, failure: SignerReadFailure | null) {
  const mainBuffers: Uint8Array[] = [];
  const probeBuffers: Uint8Array[] = [];
  const intactAtClose: boolean[] = [];
  let readFinished = false;
  let closeAttempts = 0;
  const fault = (): Error => Object.assign(new Error("injected signer read failure"), { code: "EIO" });
  const io: S37ProductHostActivationStoreIoV01 = {
    lstat: async (path) => {
      if (readFinished && ((failure === "post-path-stat" && path === target)
        || (failure === "post-directory-stat" && path === join(target, "..")))) throw fault();
      const stats = await lstat(path, { bigint: true });
      if (readFinished && ((failure === "post-path-identity" && path === target)
        || (failure === "post-directory-identity" && path === join(target, "..")))) {
        stats.ino += 1n;
      }
      return stats;
    },
    realpath: async (path) => readFinished && failure === "post-directory-realpath" && path === join(target, "..")
      ? `${path}.changed` : realpath(path),
    rename, unlink, random_bytes: (size) => randomBytes(size),
    open: async (path, flags, mode) => {
      const handle = await open(path, flags, mode);
      if (path !== target) return handle;
      const read = handle.read.bind(handle);
      const stat = handle.stat.bind(handle);
      const close = handle.close.bind(handle);
      let dataReads = 0;
      // Wrap real descriptor I/O: retain exactly the memory the product fills.
      Object.defineProperty(handle, "read", { value: async (
        buffer: Uint8Array, offset: number, length: number, position: number,
      ) => {
        if (buffer.byteLength === 1) {
          probeBuffers.push(buffer);
          const result = await read(buffer, offset, length, position);
          readFinished = true;
          // EOF does not normally populate the probe. A sentinel also proves
          // unconditional probe cleanup on success and a throwing probe read.
          buffer[0] = 0x61;
          if (failure === "probe-throw") throw fault();
          return failure === "growth-probe" ? { buffer, bytesRead: 1 } : result;
        }
        if (!mainBuffers.includes(buffer)) mainBuffers.push(buffer);
        dataReads += 1;
        if (failure === "partial-eof" && dataReads > 1) return { buffer, bytesRead: 0 };
        const result = await read(buffer, offset, failure === "partial-eof" ? Math.min(length, 8) : length, position);
        if (failure === "read-throw") throw fault();
        return result;
      } });
      Object.defineProperty(handle, "stat", { value: async () => {
        if (readFinished && failure === "post-handle-stat") throw fault();
        const stats = await stat({ bigint: true });
        if (readFinished && failure === "post-handle-identity") stats.ino += 1n;
        return stats;
      } });
      handle.close = async () => {
        closeAttempts += 1;
        intactAtClose.push(mainBuffers.at(-1)?.some((byte) => byte !== 0) ?? false);
        if (failure === "close-ambiguity") {
          descriptorFaultCleanups.push(close);
          throw fault();
        }
        await close();
      };
      return handle;
    },
  };
  return { io, main_buffers: mainBuffers, probe_buffers: probeBuffers, intact_at_close: intactAtClose,
    close_attempts: (): number => closeAttempts };
}

async function captured(root: string, io?: S37ProductHostActivationStoreIoV01) {
  const { uid, gid } = owner();
  const result = await createS37ProductHostActivationStoreForTestV01({ root_path: root, owner_uid: uid, owner_gid: gid, io });
  if (!result.ok) throw new Error(result.error);
  capturedStores.push(result.store);
  return result.store;
}

async function opened(root: string, io?: S37ProductHostActivationStoreIoV01) {
  const store = await captured(root, io);
  const result = await openS37ProductHostActivationStoreSessionV01(store, {
    activation_id: ACTIVATION_ID,
    activation_request_hash: REQUEST,
    boot_id_hash: H("b"),
  });
  if (!result.ok) throw new Error(result.error);
  return { store, session: result.session };
}

function requestedEvent() {
  return {
    operation: "install-and-launch",
    event_type: "activation.requested",
    anchor_generation: 1,
    anchor_hash: H("a"),
    controller_uid: 64037,
    payload: {
      request_hash: REQUEST,
      bundle_hash: H("2"),
      proof_request_hash: H("3"),
      qualification_intent_hash: H("4"),
      action_scope_hash: H("5"),
      initial_absence_observation_hash: H("6"),
    },
  } as const;
}

function remainingEvents() {
  const bound = <T extends string, P extends Readonly<Record<string, unknown>>>(eventType: T, payload: P) => ({
    operation: "install-and-launch" as const,
    event_type: eventType,
    anchor_generation: 1,
    anchor_hash: H("a"),
    controller_uid: 64037,
    payload,
  });
  return [
    bound("activation.nonces-reserved", {
      proof_record_hash: H("7"), authorization_nonce_record_hash: H("8"), launch_nonce_record_hash: H("9"),
    }),
    bound("activation.anchor-stable", {
      mutation_plan_hash: H("b"), proposed_anchor_hash: H("a"), anchor_observation_hash: H("c"),
    }),
    bound("activation.qualification-issued", {
      qualification_intent_hash: H("4"), activation_decision_facts_hash: H("d"), decision_input_hash: H("e"),
      decision_simulation_hash: H("f"), lease_simulation_hash: H("0"), qualification_absence_observation_hash: H("1"),
      qualification_request_hash: H("2"), qualification_hash: H("3"), qualification_nonce_record_hash: H("4"),
      boot_observation_hash: H("5"),
    }),
    bound("activation.launch-admitted", {
      launch_admission_hash: H("6"), qualification_hash: H("3"), prelaunch_authorization_revalidation_hash: H("7"),
      final_observation_hash: H("8"), broker_request_hash: H("9"),
    }),
    bound("activation.dispatch-entered", {
      launch_admission_hash: H("6"), broker_request_hash: H("9"), conformance_receipt_hash: H("a"),
      systemd_run_hash: H("b"), runtime_profile_hash: H("c"), artifact_set_hash: H("d"), controller_uid: 64037,
      primary_gid: 64037, controller_identity_hash: H("e"), unit_name_hash: H("f"), cgroup_path_hash: H("0"),
      broker_entry_evidence_hash: H("1"),
    }),
    bound("activation.completed", {
      outcome: "COMPLETED", broker_entry_evidence_hash: H("1"), completion_evidence_hash: H("2"),
    }),
  ] as const;
}

// These semantic fixtures persist genuine nonce records in ADR order. The older
// remainingEvents fixture alone intentionally exercises only ledger transport.
async function receiptPrefix(root: string, stage: number, io: S37ProductHostActivationStoreIoV01,
  ahead: "none" | "authorization" | "launch" | "qualification" = "none") {
  if (stage < 0) return { store: await captured(root, io), session: null, manifests: [] as Uint8Array[] };
  const { store, session } = await opened(root, io);
  const manifests: Uint8Array[] = [];
  const commit = async (event: unknown): Promise<void> => {
    const result = await commitS37ProductHostActivationEventV01(session, event);
    if (!result.ok) throw new Error(result.error);
    manifests.push(readFileSync(join(root, "activation", "activation-manifest.json")));
  };
  if (stage === 0 && ahead === "none") return { store, session, manifests };
  const authorization = await commitS37ProductHostAuthorizationNonceV01(session, {
    authenticated_principal_ref: "operator_1", approval_nonce: H("7"), domain: "primary-v02", run_id: "run_1",
    authorization_id: "authorization_1", authorization_statement_hash: H("8"),
  });
  if (!authorization.ok) throw new Error(authorization.status);
  if (stage === 0) return { store, session, manifests };
  await commit(requestedEvent());
  if (stage === 1 && ahead !== "launch") return { store, session, manifests };
  const launch = await commitS37ProductHostQualificationNonceV01(session, {
    operation: "install-and-launch", reservation_kind: "launch-nonce", reserved_hash: H("5"),
    anchor_generation: 1, anchor_hash: null, qualification_intent_hash: H("4"), qualification_request_hash: null,
  });
  if (!launch.ok) throw new Error(launch.status);
  if (stage === 1) return { store, session, manifests };
  const events = remainingEvents();
  await commit({ ...events[0], payload: { ...events[0].payload,
    authorization_nonce_record_hash: authorization.record_hash, launch_nonce_record_hash: launch.record_hash } });
  if (stage === 2) return { store, session, manifests };
  await commit(events[1]);
  if (stage === 3 && ahead !== "qualification") return { store, session, manifests };
  const qualification = await commitS37ProductHostQualificationNonceV01(session, {
    operation: "install-and-launch", reservation_kind: "qualification-hash", reserved_hash: H("3"),
    anchor_generation: 1, anchor_hash: H("a"), qualification_intent_hash: H("4"), qualification_request_hash: H("2"),
  });
  if (!qualification.ok) throw new Error(qualification.status);
  if (stage === 3) return { store, session, manifests };
  await commit({ ...events[2], payload: { ...events[2].payload, qualification_nonce_record_hash: qualification.record_hash } });
  for (let next = 5; next <= stage; next += 1) await commit(events[next - 2]);
  return { store, session, manifests };
}

function readOnlyPreflightIo(root: string) {
  let armed = false;
  const effects: string[] = [];
  const opens: string[] = [];
  const forbidden = (effect: string): never => {
    effects.push(effect);
    throw new Error(`read-only preflight attempted ${effect}`);
  };
  const io: S37ProductHostActivationStoreIoV01 = {
    lstat: (path) => lstat(path, { bigint: true }), realpath,
    rename: async (source, destination) => armed ? forbidden("rename") : rename(source, destination),
    unlink: async (path) => armed ? forbidden("unlink") : unlink(path),
    random_bytes: (size) => armed ? forbidden("entropy") : randomBytes(size),
    open: async (path, flags, mode) => {
      if (armed) {
        opens.push(path);
        if ((flags & (constants.O_WRONLY | constants.O_RDWR | constants.O_CREAT | constants.O_TRUNC | constants.O_APPEND)) !== 0) {
          forbidden("writable open");
        }
        if (path.startsWith(join(root, "authority") + "/")
          && path !== join(root, "authority", "system-manager-conformance-receipt.json")) forbidden("authority capture");
      }
      const handle = await open(path, flags, mode);
      for (const method of ["write", "writeFile", "writev", "appendFile", "truncate", "chmod", "chown", "utimes", "sync", "datasync"]) {
        const original: unknown = Reflect.get(handle, method);
        if (typeof original !== "function") throw new Error(`missing file handle method ${method}`);
        Object.defineProperty(handle, method, { value: async (...args: unknown[]) => armed
          ? forbidden(method) : Reflect.apply(original, handle, args) });
      }
      return handle;
    },
  };
  return { io, effects, opens, arm: (): void => { armed = true; }, armed: (): boolean => armed };
}

function preflightDurableSnapshot(root: string): unknown {
  const activation = join(root, "activation");
  return readdirSync(activation).sort().map((name) => {
    const path = join(activation, name);
    const stats = statSync(path, { bigint: true });
    return { name, bytes: readFileSync(path).toString("base64"), device: stats.dev.toString(), inode: stats.ino.toString(),
      mode: stats.mode.toString(), links: stats.nlink.toString(), uid: stats.uid.toString(), gid: stats.gid.toString() };
  });
}

function rejectedReceipt(root: string): void {
  installAuthorityFixture(root);
  const path = join(root, "authority", "system-manager-conformance-receipt.json");
  chmodSync(path, 0o600);
  writeFileSync(path, "{}\n");
  chmodSync(path, 0o400);
}

function rewriteNonce(root: string, name: "authorization-nonces.jsonl" | "qualification-nonces.jsonl",
  mutate: (rows: Record<string, unknown>[]) => void): void {
  const path = join(root, "activation", name);
  const rows = readFileSync(path, "utf8").trim().split("\n").filter(Boolean)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
  mutate(rows);
  let previous: string | null = null;
  for (const [index, row] of rows.entries()) {
    row.sequence = index + 1;
    row.previous_record_hash = previous;
    const { record_hash: _hash, ...body } = row;
    row.record_hash = hashCanonical({ purpose: row.schema_version, record: body });
    previous = String(row.record_hash);
  }
  writeFileSync(path, rows.map((row) => `${canonicalize(row)}\n`).join(""));
}

function rewriteLock(root: string, mutate: (body: Record<string, unknown>) => void): void {
  const path = join(root, "activation", "activation.lock");
  const { lock_hash: _hash, ...body } = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  mutate(body);
  chmodSync(path, 0o600);
  writeFileSync(path, `${canonicalize({ ...body,
    lock_hash: hashCanonical({ purpose: "s37-product-host-activation-lock-v01", lock: body }) })}\n`);
  chmodSync(path, 0o400);
}

function rewriteLedger(root: string, mutate: (rows: Record<string, unknown>[]) => void): void {
  const path = join(root, "activation", "activation-ledger.jsonl");
  const rows = readFileSync(path, "utf8").trim().split("\n").map((line) => JSON.parse(line) as Record<string, unknown>);
  mutate(rows);
  let previous: string | null = null;
  for (const row of rows) {
    row.previous_event_hash = previous;
    const { event_hash: _hash, ...body } = row;
    row.event_hash = hashS37ProductHostActivationEventV01(body);
    previous = String(row.event_hash);
  }
  const bytes = new TextEncoder().encode(rows.map((row) => `${canonicalize(row)}\n`).join(""));
  const manifest = buildS37ProductHostActivationManifestV01({ ledger_bytes: bytes });
  if (!manifest.ok) throw new Error(manifest.reason);
  writeFileSync(path, bytes);
  writeFileSync(join(root, "activation", "activation-manifest.json"), manifest.bytes);
}

const iso = (epoch: number): string => new Date(epoch).toISOString().replace(".000Z", "Z");
const hashWith = (purpose: string, wrapper: string, value: Record<string, unknown>): string => hashCanonical({
  purpose, [wrapper]: value,
});
const withHash = <T extends Record<string, unknown>, K extends string>(
  purpose: string, wrapper: string, field: K, value: T,
): T & Record<K, string> => ({
  ...value, [field]: hashWith(purpose, wrapper, value),
}) as T & Record<K, string>;

function conformanceReceipt(now = Math.floor(Date.now() / 1_000) * 1_000) {
  const observed = now - 120_000;
  const capacitySamples = Array.from({ length: 5 }, (_, index) => ({
    timestamp: iso(observed - 60_000 + index * 15_000), cpu_cores: 4, memory_available_bytes: 1_000_000_000,
    swap_used_bytes: index, load1: 0, load5: 0, cpu_psi_some_avg10: 0, memory_psi_some_avg10: 0,
    io_psi_some_avg10: 0, tasks: 1,
  }));
  const capacityHash = hashCanonical({ purpose: "s37-system-manager-readiness-capacity-samples-v01", samples: capacitySamples });
  const envelope = withHash("s37-system-manager-readiness-envelope-v01", "envelope", "envelope_hash", {
    schema_version: "s37-system-manager-readiness-envelope-v01", approved_at: iso(observed - 120_000),
    approved_by: "test-finalizer", valid_from: iso(observed - 90_000), valid_to: iso(observed + 600_000),
    measurement_window_seconds: 60, sample_interval_seconds: 15, min_sample_count: 5, concurrency: 1, task_ceiling: 8,
    host_requirements: {
      platform: "linux", architecture: "x86_64", distro_id: "debian", distro_version_id: "13",
      kernel_release: "6.12.0", systemd_version: "257", cgroup_version: "v2",
      required_cgroup_controllers: ["cpu", "memory"], unprivileged_userns_clone: true, user_manager_status: "available",
    },
    package_requirements: {
      candidate_version: "257", package_file_list_sha256: H("1"), selected_artifact_path: "/usr/bin/systemd-run",
      selected_artifact_sha256: H("3"),
    },
    thresholds: {
      min_cpu_cores: 2, min_memory_available_bytes: 64_000_000, max_swap_used_bytes: 1_000,
      max_swap_growth_bytes: 100, max_load1: 2, max_load5: 2, max_cpu_psi_some_avg10: 5,
      max_memory_psi_some_avg10: 5, max_io_psi_some_avg10: 5,
    },
    threshold_reasons: {
      min_cpu_cores: "bounded trial", min_memory_available_bytes: "bounded trial", max_swap_used_bytes: "bounded trial",
      max_swap_growth_bytes: "bounded trial", max_load1: "bounded trial", max_load5: "bounded trial",
      max_cpu_psi_some_avg10: "bounded trial", max_memory_psi_some_avg10: "bounded trial",
      max_io_psi_some_avg10: "bounded trial",
    },
    resource_limits: {
      cpu_quota_percent: 25, memory_max_bytes: 64_000_000, tasks_max: 8, io_weight: 10, timeout_ms: 1_000,
      stdout_bytes: 1_024, stderr_bytes: 1_024,
    },
    resource_limit_reasons: {
      cpu_quota_percent: "bounded trial", memory_max_bytes: "bounded trial", tasks_max: "bounded trial",
      io_weight: "bounded trial", timeout_ms: "bounded trial", stdout_bytes: "bounded trial", stderr_bytes: "bounded trial",
    },
    observed_at: iso(observed), capacity_samples: capacitySamples, capacity_samples_hash: capacityHash,
  });
  const hostTuple = withHash("s37-system-manager-host-tuple-v01", "host_tuple", "host_tuple_hash", {
    platform: "linux", architecture: "x86_64", distro_id: "debian", distro_version_id: "13",
    kernel_release: "6.12.0", systemd_version: "257", cgroup_version: "v2", cgroup_controllers: ["cpu", "memory"],
    unprivileged_userns_clone: true, user_manager_status: "available", observed_at: iso(observed),
  });
  const packageEvidence = withHash("s37-system-manager-package-evidence-v01", "package_evidence", "package_evidence_hash", {
    candidate_version: "257", package_file_list_sha256: H("1"), selected_artifact_path: "/usr/bin/systemd-run",
    selected_artifact_sha256: H("3"),
  });
  const readiness = withHash("s37-system-manager-readiness-evidence-v01", "evidence", "evidence_hash", {
    schema_version: "s37-system-manager-readiness-evidence-v01", observed_at: iso(observed), host_tuple: hostTuple,
    host_tuple_hash: hostTuple.host_tuple_hash, package_evidence: packageEvidence,
    package_evidence_hash: packageEvidence.package_evidence_hash, boot_id_hash: H("b"),
    envelope_hash: envelope.envelope_hash, capacity_samples: capacitySamples, capacity_samples_hash: capacityHash,
  });
  const child = (kind: "services" | "containers", phase: "before" | "after", at: number) => withHash(
    "s37-system-manager-unchanged-neighbor-snapshot-v01", "snapshot", "snapshot_hash", {
      neighbor_kind: kind, phase, host_tuple_hash: hostTuple.host_tuple_hash, boot_id_hash: H("b"), manager_scope: "system",
      observer_command: kind === "services"
        ? ["/usr/bin/systemctl", "--system", "list-units", "--all", "--no-legend", "--no-pager"]
        : ["/usr/bin/machinectl", "list", "--no-legend", "--no-pager"],
      observer_cwd: "/", observer_env: { LANG: "C" }, parser_version: "s37-neighbor-parser-v01",
      observed_at: iso(at), status: "success", count: 0, raw_snapshot_base64: "",
      raw_snapshot_hash: hashRawBytes(new Uint8Array()),
    },
  );
  const neighborChildren = {
    services_before: child("services", "before", observed - 70_000),
    services_after: child("services", "after", observed + 30_000),
    containers_before: child("containers", "before", observed - 69_000),
    containers_after: child("containers", "after", observed + 31_000),
  };
  const neighbors = {
    schema_version: "s37-system-manager-unchanged-neighbor-snapshot-v01", ...neighborChildren,
    snapshot_set_hash: hashCanonical({
      purpose: "s37-system-manager-unchanged-neighbor-snapshot-set-v01", snapshot_set: neighborChildren,
    }),
  };
  const samples: Record<string, unknown>[] = [];
  const observations: Record<string, unknown>[] = [];
  for (let index = 0; index < 5; index += 1) {
    const started = observed + 1_000 + index * 5_000;
    const finished = started + 4_000;
    const identity = hashCanonical({
      purpose: "s37-system-manager-trial-execution-identity-v01", host_tuple_hash: hostTuple.host_tuple_hash,
      boot_id_hash: H("b"), systemd_run_client_pid: 100 + index, service_main_pid: 200 + index,
      service_start_time_ticks: 300 + index, started_at: iso(started), finished_at: iso(finished),
    });
    const post = withHash("s37-system-manager-trial-post-cgroup-observation-v01", "observation", "observation_hash", {
      schema_version: "s37-system-manager-trial-post-cgroup-observation-v01", cgroup_path_hash: H("5"), state: "absent",
      parent_device: 1, parent_inode: 2, lookup_before_errno: "ENOENT", lookup_after_errno: "ENOENT",
      observed_at: iso(finished),
    });
    const systemctlArgv = ["--system", "show", "--all", "loopeix.service", "--property=LoadState",
      "--property=ActiveState", "--property=SubState", "--property=Job", "--property=ControlGroup", "--property=MainPID"];
    const duringStdout = ["LoadState=loaded", "ActiveState=active", "SubState=running", "Job=",
      "ControlGroup=/system.slice/loopeix.service", `MainPID=${200 + index}`, ""].join("\n");
    const afterStdout = ["LoadState=not-found", "ActiveState=inactive", "SubState=dead", "Job=", "ControlGroup=", "MainPID=0", ""].join("\n");
    const procStatus = `Name:\tprobe\nUid:\t64037\t64037\t64037\t64037\nGid:\t64038\t64038\t64038\t64038\nGroups:\t\n`;
    const procStat = `${200 + index} (probe) ${["S", ...Array(18).fill("0"), String(300 + index)].join(" ")}\n`;
    const observation = withHash("s37-system-manager-trial-execution-observation-v01", "observation", "observation_hash", {
      schema_version: "s37-system-manager-trial-execution-observation-v01", ordinal: index + 1,
      host_tuple_hash: hostTuple.host_tuple_hash, boot_id_hash: H("b"), manager_scope: "system", systemd_version: "257",
      systemd_run_hash: H("3"), systemctl_hash: H("4"), exact_argv_hash: H("6"), controller_uid: 64037,
      primary_gid: 64038, supplementary_gids: [], unit_name_hash: H("7"), cgroup_path_hash: H("5"),
      systemd_run_client_pid: 100 + index, service_main_pid: 200 + index, service_start_time_ticks: 300 + index,
      execution_identity_hash: identity, systemctl_during_command: "/usr/bin/systemctl", systemctl_during_argv: systemctlArgv,
      systemctl_during_cwd: "/", systemctl_during_environment: { LANG: "C" }, systemctl_during_exit_code: 0,
      systemctl_during_signal: null, systemctl_during_timed_out: false, during_observed_at: iso(started + 1_000),
      systemctl_during_stdout_base64: Buffer.from(duringStdout).toString("base64"), systemctl_during_stderr_base64: "", during_load_state: "loaded",
      during_active_state: "active", during_sub_state: "running", during_job: "", during_control_group: "/system.slice/loopeix.service",
      during_main_pid: 200 + index, proc_status_base64: Buffer.from(procStatus).toString("base64"),
      proc_stat_before_base64: Buffer.from(procStat).toString("base64"),
      proc_cgroup_base64: Buffer.from("0::/system.slice/loopeix.service\n").toString("base64"),
      proc_stat_after_base64: Buffer.from(procStat).toString("base64"), observed_service_pid: 200 + index, observed_proc_start_time_ticks: 300 + index,
      observed_uid: 64037, observed_primary_gid: 64038, observed_supplementary_gids: [], observed_cgroup_path_hash: H("5"),
      systemd_run_exit_code: 0, systemd_run_signal: null, systemd_run_timed_out: false,
      systemctl_after_command: "/usr/bin/systemctl", systemctl_after_argv: systemctlArgv, systemctl_after_cwd: "/",
      systemctl_after_environment: { LANG: "C" }, systemctl_after_exit_code: 0, systemctl_after_signal: null,
      systemctl_after_timed_out: false, after_observed_at: iso(started + 3_000),
      systemctl_after_stdout_base64: Buffer.from(afterStdout).toString("base64"),
      systemctl_after_stderr_base64: "", after_load_state: "not-found", after_active_state: "inactive", after_sub_state: "dead",
      after_job: "", after_control_group: "", after_main_pid: 0, post_cgroup_observation: post, observed_at: iso(finished),
    });
    const sample = withHash("s37-system-manager-trial-sample-v01", "sample", "sample_hash", {
      schema_version: "s37-system-manager-trial-sample-v01", ordinal: index + 1, host_tuple_hash: hostTuple.host_tuple_hash,
      boot_id_hash: H("b"), manager_scope: "system", systemd_version: "257", systemd_run_hash: H("3"),
      exact_argv_hash: H("6"), controller_uid: 64037, primary_gid: 64038, supplementary_gids: [], unit_name_hash: H("7"),
      cgroup_path_hash: H("5"), started_at: iso(started), finished_at: iso(finished), systemd_run_client_pid: 100 + index,
      service_main_pid: 200 + index, service_start_time_ticks: 300 + index, execution_identity_hash: identity,
      exit_code: 0, signal: null, timed_out: false, trial_execution_observation_hash: observation.observation_hash,
    });
    observations.push(observation); samples.push(sample);
  }
  const trial = withHash("s37-system-manager-trial-evidence-v01", "trial", "trial_evidence_hash", {
    schema_version: "s37-system-manager-trial-evidence-v01", host_tuple_hash: hostTuple.host_tuple_hash,
    boot_id_hash: H("b"), manager_scope: "system", systemd_version: "257", controller_identity_hash: H("8"),
    unit_name_hash: H("7"), cgroup_path_hash: H("5"), exact_argv_hash: H("6"),
    sample_hashes: samples.map((sample) => sample.sample_hash),
    trial_execution_observation_hashes: observations.map((observation) => observation.observation_hash),
    unchanged_neighbor_snapshot_set_hash: neighbors.snapshot_set_hash, no_retry: true,
  });
  const denyWitnesses = ["ambient-credentials", "child-process", "durable-state", "environment", "filesystem-write",
    "network", "output-limits", "retry", "stdin", "timeout", "tool-server", "unknown-outcome"]
    .map((row, index) => ({ row, witness_sha256: H("abcdef012345"[index]!) }));
  return withHash("s37-system-manager-conformance-receipt-v01", "receipt", "receipt_hash", {
    schema_version: "s37-system-manager-conformance-receipt-v01", host_tuple_hash: hostTuple.host_tuple_hash,
    manager_scope: "system", systemd_version: "257", systemd_run_hash: H("3"), systemctl_hash: H("4"),
    broker_profile_hash: H("9"), exact_argv_hash: H("6"), controller_identity_hash: H("8"), unit_name_hash: H("7"),
    expected_cgroup_path_hash: H("5"), supervisor_hash: H("a"), bwrap_hash: H("c"), probe_hash: H("d"),
    seccomp_policy_hash: H("e"), deny_witness_set_hash: H("f"), deny_witnesses: denyWitnesses,
    readiness_envelope_hash: envelope.envelope_hash, readiness_evidence_hash: readiness.evidence_hash,
    trial_evidence_hash: trial.trial_evidence_hash, readiness_envelope: envelope, readiness_evidence: readiness,
    trial_evidence: trial, samples, trial_execution_observations: observations,
    unchanged_neighbor_snapshot_set_hash: neighbors.snapshot_set_hash, unchanged_neighbor_snapshot_set: neighbors,
    boot_id_hash: H("b"), issued_at: iso(observed + 26_000), expires_at: iso(observed + 326_000),
  });
}

function installAuthorityFixture(root: string): void {
  const authority = join(root, "authority");
  mkdirSync(authority, { mode: 0o700 });
  const authorityPair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "der" }, privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const qualificationPair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "der" }, privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const now = Math.floor(Date.now() / 1_000) * 1_000;
  const trust = {
    observed_at: iso(now), policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
    authentication_contexts: [{
      context_version: "0.1", trust_domain: "local-operator", approval_channel: "local-ed25519",
      authenticated_principal_ref: "operator_1", credential_ref: "authority_key_1", channel_subject_hash: H("1"),
      session_binding_hash: H("2"), assurance_level: "phishing-resistant",
    }],
    operator_keys: [{
      operator_key_id: "authority_key_1", authenticated_principal_ref: "operator_1", trust_domain: "local-operator",
      public_key_spki_base64: authorityPair.publicKey.toString("base64"), effective_from: iso(now - 60_000),
      effective_until: iso(now + 3_600_000), revoked_at: null,
    }], platform_channel_verifiers: [], host_producer_keys: [],
    authority_epochs: [{ authenticated_principal_ref: "operator_1", revocation_epoch: 0, effective_from: iso(now - 60_000) }],
    durable_nonce_consumptions: [],
  };
  writeFileSync(join(authority, "trust-context.json"), JSON.stringify(trust), { mode: 0o400 });
  writeFileSync(join(authority, "authority-ed25519.pem"), authorityPair.privateKey, { mode: 0o400 });
  writeFileSync(join(authority, "qualification-ed25519.pem"), qualificationPair.privateKey, { mode: 0o400 });
  writeFileSync(join(authority, "system-manager-conformance-receipt.json"), JSON.stringify(conformanceReceipt(now)), { mode: 0o400 });
}

type MutableReceiptFixture = ReturnType<typeof conformanceReceipt>;

function mutateReceipt(root: string, mutate: (receipt: MutableReceiptFixture) => void): void {
  const path = join(root, "authority", "system-manager-conformance-receipt.json");
  const receipt = JSON.parse(readFileSync(path, "utf8")) as MutableReceiptFixture;
  mutate(receipt);
  const { receipt_hash: _discarded, ...body } = receipt;
  receipt.receipt_hash = hashWith("s37-system-manager-conformance-receipt-v01", "receipt", body);
  chmodSync(path, 0o600);
  writeFileSync(path, JSON.stringify(receipt));
  chmodSync(path, 0o400);
}

afterEach(async () => {
  while (capturedStores.length > 0) {
    const store = capturedStores.pop();
    if (store !== undefined) await disposeS37ProductHostActivationStoreV01(store);
  }
  while (descriptorFaultCleanups.length > 0) {
    const close = descriptorFaultCleanups.pop();
    if (close !== undefined) await close();
  }
  while (roots.length > 0) {
    const root = roots.pop();
    if (root !== undefined) await rm(root, { recursive: true, force: true });
  }
});

describe("S37.1-G2 durable activation store", () => {
  describe("rejected-receipt durable classification", () => {
    const assertRejected = async (root: string, store: CapturedS37ProductHostActivationStoreV01,
      observed: ReturnType<typeof readOnlyPreflightIo>, outcome: "NOT_STARTED" | "RECOVERY_REQUIRED" | "OUTCOME_UNKNOWN") => {
      const before = preflightDurableSnapshot(root);
      observed.arm();
      await expect(beginS37ProductHostAuthoritySessionForTestV01({
        store, activation_id: ACTIVATION_ID, activation_request_hash: REQUEST,
      })).resolves.toEqual({ ok: false, outcome, error: "AUTHORITY_CUSTODY_INVALID" });
      expect(observed.effects).toEqual([]);
      expect(preflightDurableSnapshot(root)).toEqual(before);
    };

    it.each([
      ["pristine", -1, "none", "NOT_STARTED"],
      ["genesis lock", 0, "none", "RECOVERY_REQUIRED"],
      ["authorization residue", 0, "authorization", "RECOVERY_REQUIRED"],
      ["event one", 1, "none", "RECOVERY_REQUIRED"],
      ["launch reservation ahead of event two", 1, "launch", "RECOVERY_REQUIRED"],
      ["event two", 2, "none", "RECOVERY_REQUIRED"],
      ["event three", 3, "none", "RECOVERY_REQUIRED"],
      ["qualification reservation ahead of event four", 3, "qualification", "RECOVERY_REQUIRED"],
      ["event four", 4, "none", "RECOVERY_REQUIRED"],
      ["event five", 5, "none", "OUTCOME_UNKNOWN"],
      ["event six", 6, "none", "OUTCOME_UNKNOWN"],
      ["event seven with retained completed lock", 7, "none", "OUTCOME_UNKNOWN"],
    ] as const)("classifies %s without mutation or authority capture", async (_name, stage, ahead, outcome) => {
      const root = fixtureRoot();
      rejectedReceipt(root);
      const observed = readOnlyPreflightIo(root);
      const { store } = await receiptPrefix(root, stage, observed.io, ahead);
      await assertRejected(root, store, observed, outcome);
    });

    it.each([1, 2, 3, 4])("retains a valid stage-%i prefix with a missing manifest", async (stage) => {
      const root = fixtureRoot();
      rejectedReceipt(root);
      const observed = readOnlyPreflightIo(root);
      const { store } = await receiptPrefix(root, stage, observed.io);
      await unlink(join(root, "activation", "activation-manifest.json"));
      await assertRejected(root, store, observed, "RECOVERY_REQUIRED");
    });

    it.each([2, 3, 4])("retains a valid stage-%i prefix with an older exact manifest", async (stage) => {
      const root = fixtureRoot();
      rejectedReceipt(root);
      const observed = readOnlyPreflightIo(root);
      const { store, manifests } = await receiptPrefix(root, stage, observed.io);
      writeFileSync(join(root, "activation", "activation-manifest.json"), manifests[0]!);
      await assertRejected(root, store, observed, "RECOVERY_REQUIRED");
    });

    it.each([5, 6, 7])("never weakens stage-%i uncertainty for an older valid manifest", async (stage) => {
      const root = fixtureRoot();
      rejectedReceipt(root);
      const observed = readOnlyPreflightIo(root);
      const { store, manifests } = await receiptPrefix(root, stage, observed.io);
      writeFileSync(join(root, "activation", "activation-manifest.json"), manifests[0]!);
      await assertRejected(root, store, observed, "OUTCOME_UNKNOWN");
    });

    it("does not mistake a different caller request for pristine existing quarantine", async () => {
      const root = fixtureRoot();
      rejectedReceipt(root);
      const observed = readOnlyPreflightIo(root);
      const { store } = await receiptPrefix(root, 1, observed.io);
      const before = preflightDurableSnapshot(root);
      observed.arm();
      await expect(beginS37ProductHostAuthoritySessionForTestV01({
        store, activation_id: `activation_${H("2").slice(7)}`, activation_request_hash: H("2"),
      })).resolves.toEqual({ ok: false, outcome: "RECOVERY_REQUIRED", error: "AUTHORITY_CUSTODY_INVALID" });
      expect(observed.effects).toEqual([]);
      expect(preflightDurableSnapshot(root)).toEqual(before);
    });

    it.each([false, true])("returns unknown for completed history with a new prefix: %s", async (newPrefix) => {
      const root = fixtureRoot();
      rejectedReceipt(root);
      const observed = readOnlyPreflightIo(root);
      const { store, session } = await receiptPrefix(root, 7, observed.io);
      if (session === null) throw new Error("missing fixture session");
      await expect(closeS37ProductHostActivationStoreSessionV01(session)).resolves.toEqual({ released: true, outcome: "COMPLETED" });
      if (newPrefix) {
        const request = H("2");
        const next = await openS37ProductHostActivationStoreSessionV01(store, {
          activation_id: `activation_${request.slice(7)}`, activation_request_hash: request, boot_id_hash: H("b"),
        });
        if (!next.ok) throw new Error(next.error);
        await expect(commitS37ProductHostAuthorizationNonceV01(next.session, {
          authenticated_principal_ref: "operator_1", approval_nonce: H("9"), domain: "primary-v02", run_id: "run_2",
          authorization_id: "authorization_2", authorization_statement_hash: H("8"),
        })).resolves.toMatchObject({ ok: true });
        await expect(commitS37ProductHostActivationEventV01(next.session, {
          ...requestedEvent(), payload: { ...requestedEvent().payload, request_hash: request },
        })).resolves.toMatchObject({ ok: true });
      }
      await assertRejected(root, store, observed, "OUTCOME_UNKNOWN");
    });

    type Contradiction = Readonly<{ name: string; stage: number;
      ahead?: "none" | "authorization" | "launch" | "qualification"; change(root: string): void | Promise<void> }>;
    const contradictions: readonly Contradiction[] = [
      { name: "missing lock", stage: 1, change: (root) => unlink(join(root, "activation", "activation.lock")) },
      { name: "authorization residue without lock", stage: 0, ahead: "authorization",
        change: (root) => unlink(join(root, "activation", "activation.lock")) },
      { name: "malformed lock", stage: 0, change: (root) => {
        const path = join(root, "activation", "activation.lock");
        chmodSync(path, 0o600); writeFileSync(path, "{}\n"); chmodSync(path, 0o400);
      } },
      ...["predecessor_ledger_bytes_hash", "predecessor_ledger_head_hash", "boot_id_hash"].map((field) => ({
        name: `wrong lock ${field}`, stage: 1, change: (root: string) => rewriteLock(root, (body) => { body[field] = H("e"); }),
      })),
      ...["predecessor_ledger_sequence", "fence_epoch"].map((field) => ({
        name: `wrong lock ${field}`, stage: 1, change: (root: string) => rewriteLock(root, (body) => { body[field] = 2; }),
      })),
      { name: "self-consistent unrelated lock request", stage: 1, change: (root) => rewriteLock(root, (body) => {
        body.activation_request_hash = H("e"); body.activation_id = `activation_${H("e").slice(7)}`;
      }) },
      { name: "event one without authorization predecessor", stage: 1,
        change: (root) => rewriteNonce(root, "authorization-nonces.jsonl", (rows) => { rows.length = 0; }) },
      ...["activation_id", "activation_request_hash", "fence_epoch"].map((field) => ({
        name: `wrong authorization ${field}`, stage: 1,
        change: (root: string) => rewriteNonce(root, "authorization-nonces.jsonl", (rows) => {
          rows[0]![field] = field === "fence_epoch" ? 2 : field === "activation_id" ? "activation_other" : H("e");
        }),
      })),
      { name: "second authorization row for one activation", stage: 1,
        change: (root) => rewriteNonce(root, "authorization-nonces.jsonl", (rows) => {
          rows.push({ ...rows[0], approval_nonce: H("e") });
        }) },
      { name: "event two without launch reservation", stage: 2,
        change: (root) => rewriteNonce(root, "qualification-nonces.jsonl", (rows) => { rows.length = 0; }) },
      ...["activation_id", "fence_epoch", "operation", "anchor_generation", "qualification_intent_hash"].map((field) => ({
        name: `wrong launch ${field}`, stage: 1, ahead: "launch" as const,
        change: (root: string) => rewriteNonce(root, "qualification-nonces.jsonl", (rows) => {
          rows[0]![field] = field === "activation_id" ? "activation_other" : field === "operation" ? "transition-and-launch"
            : field === "fence_epoch" || field === "anchor_generation" ? 2 : H("e");
        }),
      })),
      { name: "qualification reservation before event one", stage: 1, ahead: "launch", change: async (root) => {
        writeFileSync(join(root, "activation", "activation-ledger.jsonl"), "");
        await unlink(join(root, "activation", "activation-manifest.json"));
      } },
      { name: "qualification-hash reservation before event three", stage: 3, ahead: "qualification", change: (root) => {
        rewriteLedger(root, (rows) => { rows.splice(1); });
      } },
      { name: "wrong qualification anchor after event three", stage: 3, ahead: "qualification",
        change: (root) => rewriteNonce(root, "qualification-nonces.jsonl", (rows) => { rows[1]!.anchor_hash = H("e"); }) },
      ...["authorization_nonce_record_hash", "launch_nonce_record_hash"].map((field) => ({
        name: `wrong event-two ${field}`, stage: 2,
        change: (root: string) => rewriteLedger(root, (rows) => {
          (rows[1]!.payload as Record<string, unknown>)[field] = H("e");
        }),
      })),
      { name: "event four without qualification reservation", stage: 4,
        change: (root) => rewriteNonce(root, "qualification-nonces.jsonl", (rows) => { rows.splice(1); }) },
      ...["qualification_nonce_record_hash", "qualification_request_hash", "qualification_hash"].map((field) => ({
        name: `wrong event-four ${field}`, stage: 4,
        change: (root: string) => rewriteLedger(root, (rows) => {
          (rows[3]!.payload as Record<string, unknown>)[field] = H("e");
        }),
      })),
      { name: "invalid manifest", stage: 2,
        change: (root) => { writeFileSync(join(root, "activation", "activation-manifest.json"), "{}\n"); } },
      { name: "partial authorization JSONL", stage: 1,
        change: (root) => { writeFileSync(join(root, "activation", "authorization-nonces.jsonl"), "{"); } },
      { name: "partial qualification JSONL", stage: 2,
        change: (root) => { writeFileSync(join(root, "activation", "qualification-nonces.jsonl"), "{"); } },
    ];
    it.each(contradictions)("refuses contradictory $name without changing evidence", async ({ stage, ahead, change }) => {
      const root = fixtureRoot();
      rejectedReceipt(root);
      const observed = readOnlyPreflightIo(root);
      const { store } = await receiptPrefix(root, stage, observed.io, ahead);
      await change(root);
      await assertRejected(root, store, observed, "OUTCOME_UNKNOWN");
    });

    const capturedFiles = ["activation-ledger.jsonl", "authorization-nonces.jsonl", "qualification-nonces.jsonl",
      "activation-manifest.json", "activation.lock"] as const;
    it.each(capturedFiles)("returns unknown when %s cannot be read", async (name) => {
      const root = fixtureRoot();
      rejectedReceipt(root);
      const observed = readOnlyPreflightIo(root);
      const target = join(root, "activation", name);
      const io: S37ProductHostActivationStoreIoV01 = { ...observed.io, open: async (path, flags, mode) => {
        if (observed.armed() && path === target) throw Object.assign(new Error("injected read refusal"), { code: "EACCES" });
        return observed.io.open(path, flags, mode);
      } };
      const { store } = await receiptPrefix(root, 4, io);
      await assertRejected(root, store, observed, "OUTCOME_UNKNOWN");
    });

    it.each(capturedFiles)("does not retry an ambiguous %s descriptor close", async (name) => {
      const root = fixtureRoot();
      rejectedReceipt(root);
      const observed = readOnlyPreflightIo(root);
      const target = join(root, "activation", name);
      let attempts = 0;
      const io: S37ProductHostActivationStoreIoV01 = { ...observed.io, open: async (path, flags, mode) => {
        const handle = await observed.io.open(path, flags, mode);
        if (observed.armed() && path === target) {
          const close = handle.close.bind(handle);
          handle.close = async () => {
            attempts += 1;
            descriptorFaultCleanups.push(close);
            throw Object.assign(new Error("injected ambiguous close"), { code: "EIO" });
          };
        }
        return handle;
      } };
      const { store } = await receiptPrefix(root, 4, io);
      await assertRejected(root, store, observed, "OUTCOME_UNKNOWN");
      expect(attempts).toBe(1);
    });

    it.each(capturedFiles)("rejects raw %s drift during exact revalidation without retry", async (name) => {
      const root = fixtureRoot();
      rejectedReceipt(root);
      const observed = readOnlyPreflightIo(root);
      const target = join(root, "activation", name);
      let reads = 0;
      const io: S37ProductHostActivationStoreIoV01 = { ...observed.io, open: async (path, flags, mode) => {
        const handle = await observed.io.open(path, flags, mode);
        if (observed.armed() && path === target && ++reads === 2) {
          const read = handle.read.bind(handle);
          Object.defineProperty(handle, "read", { value: async (
            buffer: Uint8Array, offset: number, length: number, position: number,
          ) => {
            const result = await read(buffer, offset, length, position);
            if (position === 0 && result.bytesRead > 0) buffer[offset] = buffer[offset]! ^ 1;
            return result;
          } });
        }
        return handle;
      } };
      const { store } = await receiptPrefix(root, 4, io);
      await assertRejected(root, store, observed, "OUTCOME_UNKNOWN");
      expect(reads).toBe(2);
    });

    it.each(["activation.lock", "activation-manifest.json"])("rechecks absent %s before proving no start", async (name) => {
      const root = fixtureRoot();
      rejectedReceipt(root);
      const observed = readOnlyPreflightIo(root);
      let probes = 0;
      const io: S37ProductHostActivationStoreIoV01 = { ...observed.io, lstat: async (path) => {
        if (observed.armed() && path === join(root, "activation", name) && ++probes === 2) {
          throw Object.assign(new Error("absence no longer provable"), { code: "EACCES" });
        }
        return observed.io.lstat(path);
      } };
      const { store } = await receiptPrefix(root, -1, io);
      await assertRejected(root, store, observed, "OUTCOME_UNKNOWN");
      expect(probes).toBe(2);
    });

    it("rejects second-pass replacement identity even when all file bytes are identical", async () => {
      const root = fixtureRoot();
      rejectedReceipt(root);
      const observed = readOnlyPreflightIo(root);
      const target = join(root, "activation", "activation-ledger.jsonl");
      let replaced = false;
      let reads = 0;
      const io: S37ProductHostActivationStoreIoV01 = {
        ...observed.io,
        lstat: async (path) => {
          const stats = await observed.io.lstat(path);
          if (observed.armed() && replaced && path === target) stats.ino += 1n;
          return stats;
        },
        open: async (path, flags, mode) => {
          const handle = await observed.io.open(path, flags, mode);
          if (observed.armed() && path === target) {
            reads += 1;
            if (replaced) {
              const stat = handle.stat.bind(handle);
              Object.defineProperty(handle, "stat", { value: async () => {
                const stats = await stat({ bigint: true }); stats.ino += 1n; return stats;
              } });
            } else {
              const close = handle.close.bind(handle);
              handle.close = async () => { await close(); replaced = true; };
            }
          }
          return handle;
        },
      };
      const { store } = await receiptPrefix(root, 1, io);
      await assertRejected(root, store, observed, "OUTCOME_UNKNOWN");
      expect(reads).toBe(2);
    });

    it.each(["root", "activation"])("rejects final held-%s directory identity drift", async (directory) => {
      const root = fixtureRoot();
      rejectedReceipt(root);
      const observed = readOnlyPreflightIo(root);
      const target = directory === "root" ? root : join(root, "activation");
      let lockReads = 0;
      let revalidated = false;
      let finalProbes = 0;
      const io: S37ProductHostActivationStoreIoV01 = {
        ...observed.io,
        lstat: async (path) => {
          const stats = await observed.io.lstat(path);
          if (observed.armed() && revalidated && path === target) { stats.ino += 1n; finalProbes += 1; }
          return stats;
        },
        open: async (path, flags, mode) => {
          const handle = await observed.io.open(path, flags, mode);
          if (observed.armed() && path === join(root, "activation", "activation.lock") && ++lockReads === 2) {
            const close = handle.close.bind(handle);
            handle.close = async () => { await close(); revalidated = true; };
          }
          return handle;
        },
      };
      const { store } = await receiptPrefix(root, 1, io);
      await assertRejected(root, store, observed, "OUTCOME_UNKNOWN");
      expect(finalProbes).toBe(1);
    });

    it("does not certify a forged store token as pristine", async () => {
      await expect(beginS37ProductHostAuthoritySessionForTestV01({
        store: Object.freeze({}) as CapturedS37ProductHostActivationStoreV01,
        activation_id: ACTIVATION_ID, activation_request_hash: REQUEST,
      })).resolves.toEqual({ ok: false, outcome: "OUTCOME_UNKNOWN", error: "ACTIVATION_STORE_INVALID" });
    });

    it("does not certify a disposed store token as pristine", async () => {
      const root = fixtureRoot();
      const store = await captured(root);
      await expect(disposeS37ProductHostActivationStoreV01(store)).resolves.toBe(true);
      await expect(beginS37ProductHostAuthoritySessionForTestV01({ store,
        activation_id: ACTIVATION_ID, activation_request_hash: REQUEST,
      })).resolves.toEqual({ ok: false, outcome: "OUTCOME_UNKNOWN", error: "ACTIVATION_STORE_INVALID" });
    });

    it("does not certify a poisoned store token as pristine", async () => {
      const root = fixtureRoot();
      const { store, session } = await opened(root, ioWithRenameFailure());
      await expect(commitS37ProductHostActivationEventV01(session, requestedEvent())).resolves.toMatchObject({
        ok: false, outcome: "OUTCOME_UNKNOWN",
      });
      await expect(beginS37ProductHostAuthoritySessionForTestV01({ store,
        activation_id: ACTIVATION_ID, activation_request_hash: REQUEST,
      })).resolves.toEqual({ ok: false, outcome: "OUTCOME_UNKNOWN", error: "ACTIVATION_STORE_INVALID" });
    });
  });

  describe.each(["authority-ed25519.pem", "qualification-ed25519.pem"])("owned %s read buffers", (signer) => {
    it.each(SIGNER_READ_FAILURES)("zeroizes discarded buffers after %s without retrying close", async (failure) => {
      const root = fixtureRoot();
      installAuthorityFixture(root);
      const observed = ioWithRetainedSignerReads(join(root, "authority", signer), failure);
      const { session } = await opened(root, observed.io);
      await expect(captureS37ProductHostAuthorityCustodyV01(session)).resolves.toEqual({
        ok: false, error: "AUTHORITY_CUSTODY_INVALID",
      });
      expect(observed.main_buffers.length).toBeGreaterThan(0);
      expect(observed.main_buffers.every((buffer) => buffer.every((byte) => byte === 0))).toBe(true);
      expect(observed.probe_buffers.every((buffer) => buffer.every((byte) => byte === 0))).toBe(true);
      expect(observed.close_attempts()).toBe(1);
    });

    it("preserves successful bytes through close and zeroizes them after custody consumption and recapture", async () => {
      const root = fixtureRoot();
      installAuthorityFixture(root);
      const observed = ioWithRetainedSignerReads(join(root, "authority", signer), null);
      const { session } = await opened(root, observed.io);
      await expect(captureS37ProductHostAuthorityCustodyV01(session)).resolves.toMatchObject({ ok: true });
      expect(observed.intact_at_close).toEqual([true]);
      expect(observed.main_buffers).toHaveLength(1);
      expect(observed.main_buffers.every((buffer) => buffer.every((byte) => byte === 0))).toBe(true);
      expect(observed.probe_buffers.every((buffer) => buffer.every((byte) => byte === 0))).toBe(true);
      await expect(recaptureS37ProductHostAuthorityTrustV01(session)).resolves.toMatchObject({ ok: true });
      expect(observed.intact_at_close).toEqual([true, true]);
      expect(observed.main_buffers).toHaveLength(2);
      expect(observed.main_buffers.every((buffer) => buffer.every((byte) => byte === 0))).toBe(true);
      expect(observed.probe_buffers.every((buffer) => buffer.every((byte) => byte === 0))).toBe(true);
    });
  });

  it("rejects capture when a temporary ledger descriptor cannot be proven closed", async () => {
    const root = fixtureRoot();
    const target = join(root, "activation", "activation-ledger.jsonl");
    const failure = ioWithCloseFailure((path) => path === target);
    const { uid, gid } = owner();
    const result = await createS37ProductHostActivationStoreForTestV01({
      root_path: root, owner_uid: uid, owner_gid: gid, io: failure.io,
    });
    if (result.ok) capturedStores.push(result.store);
    expect(result).toEqual({ ok: false, error: "ACTIVATION_DESCRIPTOR_CLOSE_AMBIGUOUS" });
    expect(failure.close_attempts.filter((path) => path === target)).toHaveLength(1);
  });

  it.each(["receipt-file", "authority-directory"] as const)(
    "refuses to open a session after ambiguous preflight %s closure", async (kind) => {
      const root = fixtureRoot();
      installAuthorityFixture(root);
      const target = kind === "receipt-file"
        ? join(root, "authority", "system-manager-conformance-receipt.json") : join(root, "authority");
      const failure = ioWithCloseFailure((path) => path === target);
      const store = await captured(root, failure.io);
      await expect(beginS37ProductHostAuthoritySessionForTestV01({
        store, activation_id: ACTIVATION_ID, activation_request_hash: REQUEST,
      })).resolves.toEqual({ ok: false, outcome: "OUTCOME_UNKNOWN", error: "AUTHORITY_CUSTODY_INVALID" });
      expect(() => statSync(join(root, "activation", "activation.lock"))).toThrow();
      expect(failure.close_attempts.filter((path) => path === target)).toHaveLength(1);
      await expect(disposeS37ProductHostActivationStoreV01(store)).resolves.toBe(false);
    },
  );

  it("does not retry or hide an ambiguous copy-on-write temporary descriptor close", async () => {
    const root = fixtureRoot();
    const isTemp = (path: string) => path.endsWith(".tmp");
    const failure = ioWithCloseFailure(isTemp);
    const { store, session } = await opened(root, failure.io);
    await expect(commitS37ProductHostActivationEventV01(session, requestedEvent())).resolves.toEqual({
      ok: false, outcome: "OUTCOME_UNKNOWN", error: "ACTIVATION_LEDGER_WRITE_FAILED",
    });
    expect(failure.close_attempts.filter(isTemp)).toHaveLength(1);
    expect(statSync(join(root, "activation", "activation.lock")).isFile()).toBe(true);
    await expect(disposeS37ProductHostActivationStoreV01(store)).resolves.toBe(false);
  });

  it("quarantines an ambiguously closed new lock instead of returning a usable session", async () => {
    const root = fixtureRoot();
    const target = join(root, "activation", "activation.lock");
    const failure = ioWithCloseFailure((path) => path === target);
    const store = await captured(root, failure.io);
    await expect(openS37ProductHostActivationStoreSessionV01(store, {
      activation_id: ACTIVATION_ID, activation_request_hash: REQUEST, boot_id_hash: H("b"),
    })).resolves.toEqual({ ok: false, outcome: "OUTCOME_UNKNOWN", error: "ACTIVATION_LOCK_CREATE_FAILED" });
    expect(failure.close_attempts.filter((path) => path === target)).toHaveLength(1);
    expect(statSync(target).isFile()).toBe(true);
    await expect(disposeS37ProductHostActivationStoreV01(store)).resolves.toBe(false);
  });

  it("breaks the boot/custody cycle by deriving the session boot only from the fixed receipt", async () => {
    const root = fixtureRoot();
    installAuthorityFixture(root);
    const store = await captured(root);
    const begun = await beginS37ProductHostAuthoritySessionForTestV01({
      store, activation_id: ACTIVATION_ID, activation_request_hash: REQUEST,
    });
    expect(begun.ok).toBe(true);
    if (!begun.ok) throw new Error(begun.error);
    expect(inspectS37ProductHostActivationStoreSessionV01(begun.value.session)).toMatchObject({
      ok: true, activation_id: ACTIVATION_ID, activation_request_hash: REQUEST, fence_epoch: 1,
    });
    await expect(closeS37ProductHostActivationStoreSessionV01(begun.value.session)).resolves.toEqual({
      released: true, outcome: "NOT_STARTED",
    });
    await expect(disposeS37ProductHostActivationStoreV01(store)).resolves.toBe(true);
  });

  it("removes the clean internally-derived lock when full custody rejects after receipt preflight", async () => {
    const root = fixtureRoot();
    installAuthorityFixture(root);
    chmodSync(join(root, "authority", "trust-context.json"), 0o600);
    const store = await captured(root);
    await expect(beginS37ProductHostAuthoritySessionForTestV01({
      store, activation_id: ACTIVATION_ID, activation_request_hash: REQUEST,
    })).resolves.toEqual({ ok: false, outcome: "NOT_STARTED", error: "AUTHORITY_CUSTODY_INVALID" });
    expect(() => statSync(join(root, "activation", "activation.lock"))).toThrow();
    await expect(disposeS37ProductHostActivationStoreV01(store)).resolves.toBe(true);
  });

  it("derives genesis fence/sequence under an exclusive 0400 lock and releases only a clean session", async () => {
    const root = fixtureRoot();
    const { store, session } = await opened(root);
    expect(inspectS37ProductHostActivationStoreSessionV01(session)).toMatchObject({
      ok: true,
      activation_id: ACTIVATION_ID,
      fence_epoch: 1,
      next_sequence: 1,
      previous_event_hash: null,
    });
    expect(statSync(join(root, "activation", "activation.lock")).mode & 0o777).toBe(0o400);
    await expect(closeS37ProductHostActivationStoreSessionV01(session)).resolves.toEqual({ released: true, outcome: "NOT_STARTED" });
    await expect(reconcileS37ProductHostActivationStoreV01(store)).resolves.toEqual({
      outcome: "NOT_STARTED", activation_id: null, evidence_hash: null,
    });
    await expect(disposeS37ProductHostActivationStoreV01(store)).resolves.toBe(true);
  });

  it("returns no activation identity or event evidence for an owned zero-event quarantine lock", async () => {
    const root = fixtureRoot();
    const { store } = await opened(root);
    await expect(reconcileS37ProductHostActivationStoreV01(store)).resolves.toEqual({
      outcome: "RECOVERY_REQUIRED", activation_id: null, evidence_hash: null,
    });
    expect(statSync(join(root, "activation", "activation.lock")).isFile()).toBe(true);
    await expect(disposeS37ProductHostActivationStoreV01(store)).resolves.toBe(true);
  });

  it("retains a semantically invalid zero-event lock as outcome unknown", async () => {
    const root = fixtureRoot();
    const { store } = await opened(root);
    const path = join(root, "activation", "activation.lock");
    const { lock_hash: _hash, ...body } = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
    body.activation_id = "activation_wrong";
    const changed = { ...body, lock_hash: hashCanonical({ purpose: "s37-product-host-activation-lock-v01", lock: body }) };
    chmodSync(path, 0o600);
    writeFileSync(path, `${canonicalize(changed)}\n`);
    chmodSync(path, 0o400);
    await expect(reconcileS37ProductHostActivationStoreV01(store)).resolves.toEqual({
      outcome: "OUTCOME_UNKNOWN", activation_id: null, evidence_hash: null,
    });
    expect(statSync(path).isFile()).toBe(true);
    await expect(disposeS37ProductHostActivationStoreV01(store)).resolves.toBe(true);
  });

  it("classifies a qualification nonce without its event predecessor as outcome unknown", async () => {
    const root = fixtureRoot();
    const { store, session } = await opened(root);
    await expect(commitS37ProductHostQualificationNonceV01(session, {
      operation: "install-and-launch", reservation_kind: "launch-nonce", reserved_hash: H("5"),
      anchor_generation: 1, anchor_hash: null, qualification_intent_hash: H("4"), qualification_request_hash: null,
    })).resolves.toMatchObject({ ok: true });
    await expect(reconcileS37ProductHostActivationStoreV01(store)).resolves.toEqual({
      outcome: "OUTCOME_UNKNOWN", activation_id: null, evidence_hash: null,
    });
    await expect(disposeS37ProductHostActivationStoreV01(store)).resolves.toBe(true);
  });

  it("closes every temporary descriptor after custody refusal and every retained descriptor on disposal", async () => {
    const root = fixtureRoot();
    installAuthorityFixture(root);
    chmodSync(join(root, "authority", "trust-context.json"), 0o600);
    const retained = new Set<Awaited<ReturnType<typeof open>>>();
    const io: S37ProductHostActivationStoreIoV01 = {
      lstat: (path) => lstat(path, { bigint: true }), realpath, rename, unlink,
      random_bytes: (size) => randomBytes(size),
      open: async (path, flags, mode) => {
        const handle = await open(path, flags, mode);
        const close = handle.close.bind(handle);
        retained.add(handle);
        handle.close = async () => {
          await close();
          retained.delete(handle);
        };
        return handle;
      },
    };
    const store = await captured(root, io);
    await expect(beginS37ProductHostAuthoritySessionForTestV01({
      store, activation_id: ACTIVATION_ID, activation_request_hash: REQUEST,
    })).resolves.toEqual({ ok: false, outcome: "NOT_STARTED", error: "AUTHORITY_CUSTODY_INVALID" });
    expect(retained.size).toBe(2);
    await expect(disposeS37ProductHostActivationStoreV01(store)).resolves.toBe(true);
    expect(retained.size).toBe(0);
  });

  it.each(["authorization-nonces.jsonl", "activation-ledger.jsonl"])(
    "retains a clean-session lock if %s changes on disk before close", async (file) => {
      const root = fixtureRoot();
      const { store, session } = await opened(root);
      writeFileSync(join(root, "activation", file), "unexpected durable bytes\n");
      await expect(closeS37ProductHostActivationStoreSessionV01(session)).resolves.toEqual({
        released: false, outcome: "OUTCOME_UNKNOWN",
      });
      expect(statSync(join(root, "activation", "activation.lock")).isFile()).toBe(true);
      await expect(disposeS37ProductHostActivationStoreV01(store)).resolves.toBe(true);
    },
  );

  it.each([5, 6])("quarantines an interrupted event-%i session as outcome unknown", async (stage) => {
    const root = fixtureRoot();
    const { store, session } = await opened(root);
    await expect(commitS37ProductHostActivationEventV01(session, requestedEvent())).resolves.toMatchObject({ ok: true });
    for (const event of remainingEvents().slice(0, stage - 1)) {
      await expect(commitS37ProductHostActivationEventV01(session, event)).resolves.toMatchObject({ ok: true });
    }
    await expect(closeS37ProductHostActivationStoreSessionV01(session)).resolves.toEqual({
      released: false, outcome: "OUTCOME_UNKNOWN",
    });
    expect(statSync(join(root, "activation", "activation.lock")).isFile()).toBe(true);
    await expect(disposeS37ProductHostActivationStoreV01(store)).resolves.toBe(true);
  });

  it("publishes event ledger before its derived manifest and quarantines the nonterminal prefix", async () => {
    const root = fixtureRoot();
    const { store, session } = await opened(root);
    const committed = await commitS37ProductHostActivationEventV01(session, requestedEvent());
    expect(committed).toMatchObject({ ok: true, outcome: "COMMITTED" });
    expect(readFileSync(join(root, "activation", "activation-ledger.jsonl"), "utf8")).toContain("activation.requested");
    expect(JSON.parse(readFileSync(join(root, "activation", "activation-manifest.json"), "utf8"))).toMatchObject({
      status: "REQUESTED", ledger_sequence: 1, fence_epoch: 1,
    });
    await expect(closeS37ProductHostActivationStoreSessionV01(session)).resolves.toEqual({
      released: false, outcome: "RECOVERY_REQUIRED",
    });
    expect(statSync(join(root, "activation", "activation.lock")).isFile()).toBe(true);
    await expect(reconcileS37ProductHostActivationStoreV01(store)).resolves.toMatchObject({
      outcome: "RECOVERY_REQUIRED", activation_id: ACTIVATION_ID,
    });
    await disposeS37ProductHostActivationStoreV01(store);
  });

  it("commits an S36 nonce once, rejects replay, and retains the quarantine lock", async () => {
    const root = fixtureRoot();
    const { store, session } = await opened(root);
    const row = {
      authenticated_principal_ref: "operator_1",
      approval_nonce: H("7"),
      domain: "primary-v02",
      run_id: "run_1",
      authorization_id: "authorization_1",
      authorization_statement_hash: H("8"),
    } as const;
    await expect(commitS37ProductHostAuthorizationNonceV01(session, row)).resolves.toMatchObject({ ok: true, status: "reserved" });
    await expect(commitS37ProductHostAuthorizationNonceV01(session, row)).resolves.toEqual({
      ok: false, status: "already-consumed", outcome: "RECOVERY_REQUIRED",
    });
    const persisted = readFileSync(join(root, "activation", "authorization-nonces.jsonl"), "utf8").trim().split("\n");
    expect(persisted).toHaveLength(1);
    expect(JSON.parse(persisted[0]!)).toMatchObject({ sequence: 1, previous_record_hash: null, fence_epoch: 1 });
    await expect(closeS37ProductHostActivationStoreSessionV01(session)).resolves.toEqual({ released: false, outcome: "RECOVERY_REQUIRED" });
    await disposeS37ProductHostActivationStoreV01(store);
    const recovered = await captured(root);
    await expect(reconcileS37ProductHostActivationStoreV01(recovered)).resolves.toMatchObject({ outcome: "RECOVERY_REQUIRED" });
    await disposeS37ProductHostActivationStoreV01(recovered);
  });

  it("poisons an ambiguous rename without retrying, publishing a manifest, or removing the lock", async () => {
    const root = fixtureRoot();
    const { store, session } = await opened(root, ioWithRenameFailure());
    await expect(commitS37ProductHostActivationEventV01(session, requestedEvent())).resolves.toEqual({
      ok: false, outcome: "OUTCOME_UNKNOWN", error: "ACTIVATION_LEDGER_WRITE_FAILED",
    });
    expect(() => statSync(join(root, "activation", "activation-manifest.json"))).toThrow();
    expect(statSync(join(root, "activation", "activation.lock")).isFile()).toBe(true);
    await expect(closeS37ProductHostActivationStoreSessionV01(session)).resolves.toEqual({ released: false, outcome: "OUTCOME_UNKNOWN" });
    await expect(reconcileS37ProductHostActivationStoreV01(store)).resolves.toEqual({
      outcome: "OUTCOME_UNKNOWN", activation_id: null, evidence_hash: null,
    });
    await disposeS37ProductHostActivationStoreV01(store);
  });

  it("recovers a proven stage-one ledger-ahead-of-manifest crash prefix as recovery-required", async () => {
    const root = fixtureRoot();
    const { store, session } = await opened(root, ioWithPostLedgerRenameFailure());
    await expect(commitS37ProductHostActivationEventV01(session, requestedEvent())).resolves.toEqual({
      ok: false, outcome: "OUTCOME_UNKNOWN", error: "ACTIVATION_LEDGER_WRITE_FAILED",
    });
    expect(readFileSync(join(root, "activation", "activation-ledger.jsonl"), "utf8")).toContain("activation.requested");
    expect(() => statSync(join(root, "activation", "activation-manifest.json"))).toThrow();
    await disposeS37ProductHostActivationStoreV01(store);

    const recovered = await captured(root);
    await expect(reconcileS37ProductHostActivationStoreV01(recovered)).resolves.toMatchObject({
      outcome: "RECOVERY_REQUIRED", activation_id: ACTIVATION_ID,
    });
    await disposeS37ProductHostActivationStoreV01(recovered);
  });

  it("rejects a second process/session while the exact lock is held", async () => {
    const root = fixtureRoot();
    const firstStore = await captured(root);
    const first = await openS37ProductHostActivationStoreSessionV01(firstStore, {
      activation_id: ACTIVATION_ID, activation_request_hash: REQUEST, boot_id_hash: H("b"),
    });
    if (!first.ok) throw new Error(first.error);
    const secondStore = await captured(root);
    await expect(openS37ProductHostActivationStoreSessionV01(secondStore, {
      activation_id: ACTIVATION_ID, activation_request_hash: REQUEST, boot_id_hash: H("b"),
    })).resolves.toMatchObject({ ok: false, outcome: "RECOVERY_REQUIRED", error: "ACTIVATION_LOCK_UNAVAILABLE" });
    await closeS37ProductHostActivationStoreSessionV01(first.session);
    await disposeS37ProductHostActivationStoreV01(firstStore);
    await disposeS37ProductHostActivationStoreV01(secondStore);
  });

  it("removes only an exact completed activation lock during fresh reconciliation", async () => {
    const root = fixtureRoot();
    const { store, session } = await opened(root);
    await expect(commitS37ProductHostActivationEventV01(session, requestedEvent())).resolves.toMatchObject({ ok: true });
    for (const event of remainingEvents()) {
      const committed = await commitS37ProductHostActivationEventV01(session, event);
      if (!committed.ok) throw new Error(`${event.event_type}:${committed.error}`);
    }
    expect(statSync(join(root, "activation", "activation.lock")).isFile()).toBe(true);
    await disposeS37ProductHostActivationStoreV01(store);

    const recovered = await captured(root);
    await expect(reconcileS37ProductHostActivationStoreV01(recovered)).resolves.toMatchObject({
      outcome: "COMPLETED", activation_id: ACTIVATION_ID,
      evidence_hash: JSON.parse(readFileSync(join(root, "activation", "activation-ledger.jsonl"), "utf8")
        .trim().split("\n").at(-1)!).event_hash,
    });
    expect(() => statSync(join(root, "activation", "activation.lock"))).toThrow();
    await disposeS37ProductHostActivationStoreV01(recovered);
  });

  it("does not report a predecessor's completion for a new clean session", async () => {
    const root = fixtureRoot();
    const { store, session } = await opened(root);
    for (const event of [requestedEvent(), ...remainingEvents()]) {
      await expect(commitS37ProductHostActivationEventV01(session, event)).resolves.toMatchObject({ ok: true });
    }
    await expect(closeS37ProductHostActivationStoreSessionV01(session)).resolves.toEqual({ released: true, outcome: "COMPLETED" });
    const request = H("2");
    const next = await openS37ProductHostActivationStoreSessionV01(store, {
      activation_id: `activation_${request.slice(7)}`, activation_request_hash: request, boot_id_hash: H("b"),
    });
    if (!next.ok) throw new Error(next.error);
    await expect(closeS37ProductHostActivationStoreSessionV01(next.session)).resolves.toEqual({
      released: true, outcome: "NOT_STARTED",
    });
    await expect(disposeS37ProductHostActivationStoreV01(store)).resolves.toBe(true);
  });

  it("captures fixed authority custody opaquely and recaptures trust after a durable nonce advance", async () => {
    const root = fixtureRoot();
    installAuthorityFixture(root);
    const { store, session } = await opened(root);
    const custody = await captureS37ProductHostAuthorityCustodyV01(session);
    expect(custody.ok).toBe(true);
    if (!custody.ok) throw new Error(custody.error);
    const inspected = inspectS37ProductHostAuthorityCustodyV01(custody.custody);
    expect(inspected).toMatchObject({ ok: true, authority_key_ref: "authority_key_1" });
    expect(JSON.stringify(inspected)).not.toContain("BEGIN PRIVATE KEY");
    expect(JSON.stringify(inspected)).not.toContain(root);
    await expect(commitS37ProductHostAuthorizationNonceV01(session, {
      authenticated_principal_ref: "operator_1", approval_nonce: H("7"), domain: "primary-v02", run_id: "run_1",
      authorization_id: "authorization_1", authorization_statement_hash: H("8"),
    })).resolves.toMatchObject({ ok: true, status: "reserved" });
    await expect(recaptureS37ProductHostAuthorityTrustV01(session)).resolves.toMatchObject({
      ok: true, custody: custody.custody, conformance_receipt_hash: custody.conformance_receipt_hash,
    });
    await expect(disposeS37ProductHostActivationStoreV01(store)).resolves.toBe(true);
    expect(inspectS37ProductHostAuthorityCustodyV01(custody.custody)).toEqual({
      ok: false, error: "AUTHORITY_CUSTODY_INVALID",
    });
  });

  it("poisons the session when immutable authority custody drifts", async () => {
    const root = fixtureRoot();
    installAuthorityFixture(root);
    const { store, session } = await opened(root);
    const custody = await captureS37ProductHostAuthorityCustodyV01(session);
    if (!custody.ok) throw new Error(custody.error);
    chmodSync(join(root, "authority", "trust-context.json"), 0o600);
    await expect(recaptureS37ProductHostAuthorityTrustV01(session)).resolves.toEqual({
      ok: false, error: "AUTHORITY_CUSTODY_INVALID",
    });
    expect(inspectS37ProductHostActivationStoreSessionV01(session)).toEqual({
      ok: false, error: "ACTIVATION_SESSION_INVALID",
    });
    await expect(disposeS37ProductHostActivationStoreV01(store)).resolves.toBe(true);
  });

  it.each([
    ["readiness sample", (receipt: MutableReceiptFixture) => { receipt.readiness_envelope.capacity_samples[2]!.load1 = 99; }],
    ["neighbor snapshot", (receipt: MutableReceiptFixture) => { receipt.unchanged_neighbor_snapshot_set.services_after.raw_snapshot_base64 = "e30K"; }],
    ["expired validity", (receipt: MutableReceiptFixture) => { receipt.expires_at = receipt.issued_at; }],
    ["raw systemctl observation", (receipt: MutableReceiptFixture) => {
      const observation = receipt.trial_execution_observations[0]!;
      observation.systemctl_during_stdout_base64 = "";
      const { observation_hash: _oldObservationHash, ...observationBody } = observation;
      observation.observation_hash = hashWith(
        "s37-system-manager-trial-execution-observation-v01", "observation", observationBody,
      );
      const sample = receipt.samples[0]!;
      sample.trial_execution_observation_hash = observation.observation_hash;
      const { sample_hash: _oldSampleHash, ...sampleBody } = sample;
      sample.sample_hash = hashWith("s37-system-manager-trial-sample-v01", "sample", sampleBody);
      receipt.trial_evidence.sample_hashes = receipt.samples.map((row) => row.sample_hash);
      receipt.trial_evidence.trial_execution_observation_hashes = receipt.trial_execution_observations
        .map((row) => row.observation_hash);
      const { trial_evidence_hash: _oldTrialHash, ...trialBody } = receipt.trial_evidence;
      receipt.trial_evidence.trial_evidence_hash = hashWith("s37-system-manager-trial-evidence-v01", "trial", trialBody);
      receipt.trial_evidence_hash = receipt.trial_evidence.trial_evidence_hash;
    }],
  ])("rejects a semantically invalid embedded %s even under a recomputed top receipt hash", async (_name, mutation) => {
    const root = fixtureRoot();
    installAuthorityFixture(root);
    mutateReceipt(root, mutation);
    const { store, session } = await opened(root);
    await expect(captureS37ProductHostAuthorityCustodyV01(session)).resolves.toEqual({
      ok: false, error: "AUTHORITY_CUSTODY_INVALID",
    });
    await disposeS37ProductHostActivationStoreV01(store);
  });
});
