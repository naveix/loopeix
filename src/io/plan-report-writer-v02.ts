import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { open, lstat, readFile, readdir, rename, stat, unlink } from "node:fs/promises";
import { promisify } from "node:util";
import { join } from "node:path";
import { canonicalize, hashRawBytes } from "../hash.js";

const execFileAsync = promisify(execFile);
const REPORT_NAMES = ["plan-report.md", "plan-report.html", "plan-report-input.json"] as const;
const SELF_PROCESS_START_IDENTITY = `node-start-${Math.max(0, Date.now() - Math.floor(process.uptime() * 1_000))}`;
type ReportName = (typeof REPORT_NAMES)[number];
type Hash = `sha256:${string}`;

export type PlanReportWriterRequestV02 = Readonly<{
  run_id: string;
  generation_id: string;
  resolved_run_plan_hash: string;
  compile_pack_manifest_hash: string;
  generated_loop_hash: string;
  report_projection_version: "0.1";
  renderer_bundle_id: string;
  renderer_bundle_hash: string;
  ordered: readonly Readonly<{ name: ReportName; sha256: string }>[];
  bytes: ReadonlyMap<ReportName, Uint8Array>;
}>;

export type PlanReportWriterResultV02 =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly reason:
        | "REPORT_BUILD_BUSY"
        | "REPORT_BUILD_STALE_LOCK"
        | "IO_IDENTITY_MISMATCH"
        | "IO_DURABILITY_UNCONFIRMED";
      readonly message: string;
    };

type Descriptor = Readonly<{ name: ReportName; hash: string }>;
type LockV02 = Readonly<{
  version: "0.1";
  invocation_id: string;
  pid: number;
  process_start_identity: string;
  started_at: string;
  source: Readonly<{
    run_id: string;
    resolved_run_plan_hash: string;
    compile_pack_manifest_hash: string;
    generated_loop_hash: string;
    report_projection_version: "0.1";
    renderer_bundle_id: string;
    renderer_bundle_hash: string;
  }>;
  committed_before: readonly Descriptor[] | null;
  target: Readonly<{ generation_id: string; members: readonly Descriptor[] }>;
  temp_names: readonly [string, string, string];
}>;

type CapturedLock = Readonly<{
  lock: LockV02;
  bytes_hash: string;
  device: string;
  inode: string;
}>;

function fail(reason: Exclude<PlanReportWriterResultV02, { ok: true }>["reason"], message: string): PlanReportWriterResultV02 {
  return { ok: false, reason, message };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function isHash(value: unknown): value is Hash {
  return typeof value === "string" && /^sha256:[0-9a-f]{64}$/u.test(value);
}

function parseDescriptors(value: unknown): readonly Descriptor[] | null | undefined {
  if (value === null) return null;
  if (!Array.isArray(value) || value.length !== REPORT_NAMES.length) return undefined;
  const rows: Descriptor[] = [];
  for (let index = 0; index < REPORT_NAMES.length; index += 1) {
    const row = value[index];
    if (!isRecord(row) || !exactKeys(row, ["name", "hash"]) || row.name !== REPORT_NAMES[index] || !isHash(row.hash)) return undefined;
    rows.push(Object.freeze({ name: REPORT_NAMES[index]!, hash: row.hash }));
  }
  return Object.freeze(rows);
}

function parseLock(value: unknown): LockV02 | null {
  if (!isRecord(value) || !exactKeys(value, ["version", "invocation_id", "pid", "process_start_identity", "started_at", "source", "committed_before", "target", "temp_names"])) return null;
  if (value.version !== "0.1" || typeof value.invocation_id !== "string" || !/^prw_[0-9a-f]{32}$/u.test(value.invocation_id)
    || !Number.isSafeInteger(value.pid) || (value.pid as number) <= 0 || typeof value.process_start_identity !== "string"
    || value.process_start_identity.length === 0 || typeof value.started_at !== "string" || Number.isNaN(Date.parse(value.started_at))) return null;
  if (!isRecord(value.source) || !exactKeys(value.source, ["run_id", "resolved_run_plan_hash", "compile_pack_manifest_hash", "generated_loop_hash", "report_projection_version", "renderer_bundle_id", "renderer_bundle_hash"])) return null;
  const source = value.source;
  if (typeof source.run_id !== "string" || !isHash(source.resolved_run_plan_hash) || !isHash(source.compile_pack_manifest_hash)
    || !isHash(source.generated_loop_hash) || source.report_projection_version !== "0.1" || typeof source.renderer_bundle_id !== "string" || !isHash(source.renderer_bundle_hash)) return null;
  const committed = parseDescriptors(value.committed_before);
  if (committed === undefined || !isRecord(value.target) || !exactKeys(value.target, ["generation_id", "members"]) || typeof value.target.generation_id !== "string") return null;
  const target = parseDescriptors(value.target.members);
  if (target === null || target === undefined || !Array.isArray(value.temp_names) || value.temp_names.length !== 3) return null;
  const temps = value.temp_names;
  if (temps.some((name, index) => typeof name !== "string" || !new RegExp(`^${REPORT_NAMES[index]!.replaceAll(".", "\\.")}\\.[0-9a-f]{32}\\.tmp$`, "u").test(name))) return null;
  return Object.freeze({
    version: "0.1",
    invocation_id: value.invocation_id,
    pid: value.pid as number,
    process_start_identity: value.process_start_identity,
    started_at: value.started_at,
    source: Object.freeze({ ...source }) as LockV02["source"],
    committed_before: committed,
    target: Object.freeze({ generation_id: value.target.generation_id, members: target }),
    temp_names: Object.freeze([...temps]) as LockV02["temp_names"],
  });
}

async function processStartIdentity(pid: number): Promise<string | null> {
  if (pid === process.pid) return SELF_PROCESS_START_IDENTITY;
  try {
    const { stdout } = await execFileAsync("/bin/ps", ["-o", "lstart=", "-p", String(pid)], { encoding: "utf8", timeout: 2_000 });
    const value = stdout.trim().replace(/\s+/gu, " ");
    return value.length === 0 ? null : value;
  } catch {
    return null;
  }
}

function processIsDefinitelyDead(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return false;
  } catch (error: unknown) {
    return isRecord(error) && error.code === "ESRCH";
  }
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(path, "r");
  try { await handle.sync(); } finally { await handle.close(); }
}

async function stableFileHash(path: string): Promise<string | null> {
  try {
    const before = await lstat(path, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink()) return null;
    const handle = await open(path, "r");
    try {
      const opened = await handle.stat({ bigint: true });
      if (opened.dev !== before.dev || opened.ino !== before.ino || !opened.isFile()) return null;
      const bytes = await handle.readFile();
      const after = await handle.stat({ bigint: true });
      if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size || after.mtimeNs !== opened.mtimeNs || BigInt(bytes.byteLength) !== opened.size) return null;
      return hashRawBytes(bytes);
    } finally { await handle.close(); }
  } catch { return null; }
}

async function captureLock(path: string): Promise<CapturedLock | null> {
  try {
    const before = await lstat(path, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink() || before.size > 65_536n) return null;
    const bytes = await readFile(path);
    const after = await lstat(path, { bigint: true });
    if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size || after.mtimeNs !== before.mtimeNs || BigInt(bytes.byteLength) !== before.size) return null;
    const decoded = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    const lock = parseLock(decoded);
    return lock === null ? null : { lock, bytes_hash: hashRawBytes(bytes), device: before.dev.toString(), inode: before.ino.toString() };
  } catch { return null; }
}

async function lockUnchanged(path: string, captured: CapturedLock): Promise<boolean> {
  const current = await captureLock(path);
  return current !== null && current.bytes_hash === captured.bytes_hash && current.device === captured.device && current.inode === captured.inode;
}

function requestSource(request: PlanReportWriterRequestV02): LockV02["source"] {
  return Object.freeze({
    run_id: request.run_id,
    resolved_run_plan_hash: request.resolved_run_plan_hash,
    compile_pack_manifest_hash: request.compile_pack_manifest_hash,
    generated_loop_hash: request.generated_loop_hash,
    report_projection_version: request.report_projection_version,
    renderer_bundle_id: request.renderer_bundle_id,
    renderer_bundle_hash: request.renderer_bundle_hash,
  });
}

function sameCanonical(left: unknown, right: unknown): boolean {
  try { return canonicalize(left) === canonicalize(right); } catch { return false; }
}

async function captureCommittedBefore(root: string): Promise<readonly Descriptor[] | null | undefined> {
  const hashes = await Promise.all(REPORT_NAMES.map((name) => stableFileHash(join(root, name))));
  if (hashes.every((hash) => hash === null)) return null;
  if (hashes.some((hash) => hash === null)) return undefined;
  return Object.freeze(REPORT_NAMES.map((name, index) => Object.freeze({ name, hash: hashes[index]! })));
}

async function writeTemp(root: string, name: string, bytes: Uint8Array): Promise<void> {
  const handle = await open(join(root, name), "wx", 0o600);
  try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
}

async function removeInterruptedTemp(root: string, name: string): Promise<void> {
  await unlink(join(root, name));
  await syncDirectory(root);
}

async function classifyAndAdvance(root: string, captured: CapturedLock, request: PlanReportWriterRequestV02): Promise<"advanced" | "complete" | "stale"> {
  if (!(await lockUnchanged(join(root, "plan-report.lock"), captured))) return "stale";
  const lock = captured.lock;
  const entries = await readdir(root, { withFileTypes: true });
  if (entries.some((entry) => entry.isSymbolicLink() || (!entry.isFile() && !entry.isDirectory()))) return "stale";
  const allowed = new Set(["plan-report.lock", ...REPORT_NAMES, ...lock.temp_names]);
  const reportEntries = entries.map((entry) => entry.name).filter((name) => name.startsWith("plan-report"));
  if (reportEntries.some((name) => !allowed.has(name))) return "stale";
  const canonicalHashes = await Promise.all(REPORT_NAMES.map((name) => stableFileHash(join(root, name))));
  const tempHashes = await Promise.all(lock.temp_names.map((name) => stableFileHash(join(root, name))));
  const before = lock.committed_before?.map((row) => row.hash) ?? [null, null, null];
  const target = lock.target.members.map((row) => row.hash);
  const isBeforeOrAbsent = (index: number): boolean => canonicalHashes[index] === before[index];
  const targetAt = (index: number): boolean => canonicalHashes[index] === target[index];

  if (canonicalHashes.every((hash, index) => hash === target[index]) && tempHashes.every((hash) => hash === null)) {
    await syncDirectory(root);
    if (!(await lockUnchanged(join(root, "plan-report.lock"), captured))) return "stale";
    await unlink(join(root, "plan-report.lock"));
    await syncDirectory(root);
    return "complete";
  }
  if (canonicalHashes.every((hash, index) => hash === before[index]) && tempHashes.every((hash) => hash === null)) {
    await writeTemp(root, lock.temp_names[0], request.bytes.get(REPORT_NAMES[0])!);
    return "advanced";
  }
  if (canonicalHashes.every((hash, index) => hash === before[index]) && tempHashes[0] === target[0] && tempHashes[1] === null && tempHashes[2] === null) {
    await writeTemp(root, lock.temp_names[1], request.bytes.get(REPORT_NAMES[1])!);
    return "advanced";
  }
  if (canonicalHashes.every((hash, index) => hash === before[index]) && tempHashes[0] === target[0] && tempHashes[1] === target[1] && tempHashes[2] === null) {
    await writeTemp(root, lock.temp_names[2], request.bytes.get(REPORT_NAMES[2])!);
    return "advanced";
  }
  if (canonicalHashes.every((hash, index) => hash === before[index]) && tempHashes.every((hash, index) => hash === target[index])) {
    await rename(join(root, lock.temp_names[0]), join(root, REPORT_NAMES[0]));
    return "advanced";
  }
  if (targetAt(0) && isBeforeOrAbsent(1) && isBeforeOrAbsent(2) && tempHashes[0] === null && tempHashes[1] === target[1] && tempHashes[2] === target[2]) {
    await rename(join(root, lock.temp_names[1]), join(root, REPORT_NAMES[1]));
    return "advanced";
  }
  if (targetAt(0) && targetAt(1) && isBeforeOrAbsent(2) && tempHashes[0] === null && tempHashes[1] === null && tempHashes[2] === target[2]) {
    await rename(join(root, lock.temp_names[2]), join(root, REPORT_NAMES[2]));
    return "advanced";
  }
  // A dead writer may leave only its current temp incomplete. Remove exactly
  // that lock-owned file, sync the deletion, then let the next classification restage it.
  for (let index = 0; index < tempHashes.length; index += 1) {
    if (tempHashes[index] !== null && tempHashes[index] !== target[index]) {
      const precedingComplete = tempHashes.slice(0, index).every((hash, prior) => hash === target[prior]);
      const followingAbsent = tempHashes.slice(index + 1).every((hash) => hash === null);
      if (precedingComplete && followingAbsent && canonicalHashes.every((hash, position) => hash === before[position])) {
        await removeInterruptedTemp(root, lock.temp_names[index]!);
        return "advanced";
      }
    }
  }
  return "stale";
}

function validateRequest(request: PlanReportWriterRequestV02): boolean {
  return request.ordered.length === REPORT_NAMES.length && request.ordered.every((row, index) => row.name === REPORT_NAMES[index]
    && isHash(row.sha256) && request.bytes.has(row.name) && hashRawBytes(request.bytes.get(row.name)!) === row.sha256);
}

export async function replacePlanReportProjectionSetV02(root: string, request: PlanReportWriterRequestV02): Promise<PlanReportWriterResultV02> {
  if (!validateRequest(request)) return fail("IO_IDENTITY_MISMATCH", "The admitted plan-report output set is invalid.");
  const lockPath = join(root, "plan-report.lock");
  let captured: CapturedLock | null = null;
  try {
    const rootBefore = await stat(root, { bigint: true });
    const processIdentity = await processStartIdentity(process.pid);
    if (processIdentity === null) return fail("IO_DURABILITY_UNCONFIRMED", "The writer process identity could not be authenticated.");
    const committedBefore = await captureCommittedBefore(root);
    if (committedBefore === undefined) return fail("REPORT_BUILD_STALE_LOCK", "The existing plan-report set is partial or invalid.");
    const entropy = randomBytes(16).toString("hex");
    const lock: LockV02 = Object.freeze({
      version: "0.1",
      invocation_id: `prw_${entropy}`,
      pid: process.pid,
      process_start_identity: processIdentity,
      started_at: new Date().toISOString(),
      source: requestSource(request),
      committed_before: committedBefore,
      target: Object.freeze({ generation_id: request.generation_id, members: Object.freeze(request.ordered.map((row) => Object.freeze({ name: row.name, hash: row.sha256 }))) }),
      temp_names: Object.freeze(REPORT_NAMES.map((name) => `${name}.${entropy}.tmp`)) as LockV02["temp_names"],
    });
    const handle = await open(lockPath, "wx", 0o600);
    try { await handle.writeFile(`${canonicalize(lock)}\n`); await handle.sync(); } finally { await handle.close(); }
    captured = await captureLock(lockPath);
    if (captured === null) return fail("IO_DURABILITY_UNCONFIRMED", "The plan-report lock could not be recaptured.");
    const rootAfter = await stat(root, { bigint: true });
    if (rootAfter.dev !== rootBefore.dev || rootAfter.ino !== rootBefore.ino) return fail("IO_IDENTITY_MISMATCH", "The run directory identity changed.");
  } catch (error: unknown) {
    if (!isRecord(error) || error.code !== "EEXIST") return fail("IO_DURABILITY_UNCONFIRMED", "The plan-report lock could not be durably created.");
    captured = await captureLock(lockPath);
    if (captured === null) return fail("REPORT_BUILD_STALE_LOCK", "The existing plan-report lock is malformed or unstable.");
    if (!processIsDefinitelyDead(captured.lock.pid)) {
      const ownerIdentity = await processStartIdentity(captured.lock.pid);
      if (ownerIdentity === captured.lock.process_start_identity) return fail("REPORT_BUILD_BUSY", "Another authenticated plan-report writer is active.");
      return fail("REPORT_BUILD_STALE_LOCK", "The existing plan-report lock owner cannot be safely authenticated.");
    }
    const expectedTarget = request.ordered.map((row) => ({ name: row.name, hash: row.sha256 }));
    if (!sameCanonical(captured.lock.source, requestSource(request)) || captured.lock.target.generation_id !== request.generation_id || !sameCanonical(captured.lock.target.members, expectedTarget)) {
      return fail("REPORT_BUILD_STALE_LOCK", "The dead writer lock does not match the current immutable report lineage.");
    }
  }

  try {
    for (;;) {
      const transition = await classifyAndAdvance(root, captured, request);
      if (transition === "complete") return { ok: true };
      if (transition === "stale") return fail("REPORT_BUILD_STALE_LOCK", "The lock-bound report state is invalid or changed unexpectedly.");
    }
  } catch {
    return fail("IO_DURABILITY_UNCONFIRMED", "The plan-report set could not be durably replaced.");
  }
}
