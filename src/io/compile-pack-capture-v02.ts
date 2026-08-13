import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { lstat, realpath, stat } from "node:fs/promises";
import { createHash } from "node:crypto";
import { extname, join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseDirectChildName, type DirectChildName } from "./captured-file.js";

const MAX_MEMBER_BYTES = 4_194_304;
const MAX_TOTAL_BYTES = 33_554_432;
const REQUEST_TIMEOUT_MS = 30_000;

type FailureReason = "INVALID_COMPILE_PACK" | "INPUT_TOO_LARGE" | "IO_HELPER_UNAVAILABLE" | "IO_IDENTITY_MISMATCH";
type Result<T> = { ok: true; value: T } | { ok: false; reason: FailureReason; message: string };
type Entry = Readonly<{ name: string; kind: "regular-file" | "directory" | "symlink" | "other" }>;
type ChildResponse = { id: number; ok: boolean; operation: string; reason?: string; message?: string; entries?: Entry[]; name?: string; bytes_base64?: string; byte_length?: number };

export type CapturedCompilePackV02 = Readonly<{
  schema_version: "0.2";
  total_byte_length: number;
  source_pack_root_hash: string;
  memberNames(): readonly DirectChildName[];
  memberByteLength(name: DirectChildName): number;
  snapshotMemberBytes(name: DirectChildName): Result<Uint8Array>;
  readonly __captured_compile_pack_v02: unique symbol;
}>;

export type CompilePackCaptureSessionV02 = Readonly<{
  listDirectEntries(): Promise<Result<readonly Entry[]>>;
  captureMember(name: DirectChildName): Promise<Result<{ name: DirectChildName; byte_length: number }>>;
  captureLegacyMember(
    name: DirectChildName,
    limits: Readonly<{ max_member_bytes: number; max_total_bytes: number }>,
  ): Promise<Result<{ name: DirectChildName; byte_length: number }>>;
  snapshotCapturedManifest(): Result<Uint8Array>;
  seal(expected_members: readonly DirectChildName[], capture_order: readonly DirectChildName[]): Promise<Result<CapturedCompilePackV02>>;
  abort(): Promise<Result<null>>;
  readonly __compile_pack_capture_session_v02: unique symbol;
}>;

type State = { child: ChildProcessWithoutNullStreams; nextId: number; buffer: string; pending: Map<number, { resolve(value: ChildResponse): void; timer: NodeJS.Timeout }>; bytes: Map<DirectChildName, Uint8Array>; order: DirectChildName[]; total: number; busy: boolean; status: "open" | "sealed" | "aborted" };
const sessions = new WeakMap<CompilePackCaptureSessionV02, State>();
const packs = new WeakMap<CapturedCompilePackV02, ReadonlyMap<DirectChildName, Uint8Array>>();

function helperPath(): string { const here = fileURLToPath(import.meta.url); return join(dirname(here), `compile-pack-capture-child${extname(here)}`); }
function fail<T>(reason: FailureReason, message: string): Result<T> { return { ok: false, reason, message }; }
function hash(bytes: Uint8Array): string { return `sha256:${createHash("sha256").update(bytes).digest("hex")}`; }
function validBase64(value: string): boolean { return value.length % 4 === 0 && /^[A-Za-z0-9+/]*={0,2}$/.test(value); }
function validPositiveLimit(value: number): boolean { return Number.isSafeInteger(value) && value > 0; }

function request(state: State, operation: string, fields: Record<string, unknown> = {}): Promise<ChildResponse> {
  const id = state.nextId++;
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      state.pending.delete(id); state.child.kill("SIGKILL");
      resolve({ id, ok: false, operation, reason: "IO_HELPER_FAILURE", message: "The compile-pack capture helper timed out." });
    }, REQUEST_TIMEOUT_MS);
    state.pending.set(id, { resolve, timer });
    state.child.stdin.write(`${JSON.stringify({ id, operation, ...fields })}\n`, (error) => {
      if (error === null) return;
      const pending = state.pending.get(id); if (pending === undefined) return;
      clearTimeout(pending.timer); state.pending.delete(id);
      pending.resolve({ id, ok: false, operation, reason: "IO_HELPER_FAILURE", message: "The compile-pack capture helper request failed." });
    });
  });
}

function mapFailure<T>(response: ChildResponse): Result<T> {
  const reason = response.reason === "INPUT_TOO_LARGE" ? "INPUT_TOO_LARGE" : response.reason === "IO_IDENTITY_MISMATCH" ? "IO_IDENTITY_MISMATCH" : response.reason === "IO_HELPER_FAILURE" ? "IO_HELPER_UNAVAILABLE" : "INVALID_COMPILE_PACK";
  return fail(reason, typeof response.message === "string" ? response.message : "The compile pack is invalid.");
}

async function exclusive<T>(state: State, operation: () => Promise<Result<T>>): Promise<Result<T>> {
  if (state.busy) return fail("INVALID_COMPILE_PACK", "Another compile-pack capture operation is already active.");
  state.busy = true;
  try { return await operation(); }
  finally { state.busy = false; }
}

async function stop(state: State, operation: "seal" | "abort"): Promise<Result<null>> {
  const response = await request(state, operation);
  state.child.stdin.end();
  if (!response.ok) { state.child.kill("SIGKILL"); return mapFailure(response); }
  return { ok: true, value: null };
}

export async function openCompilePackCaptureSessionV02(rootPath: string): Promise<Result<CompilePackCaptureSessionV02>> {
  try {
    const metadata = await lstat(rootPath, { bigint: true });
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) return fail("INVALID_COMPILE_PACK", "The compile-pack root must be a direct directory.");
    const root = await realpath(rootPath);
    const identity = await stat(root, { bigint: true });
    const childPath = helperPath();
    const loader = extname(childPath) === ".ts" ? ["--import", import.meta.resolve("tsx")] : [];
    const child = spawn(process.execPath, [...loader, childPath], { cwd: root, env: { LANG: "C", LC_ALL: "C", PATH: process.env.PATH ?? "/usr/bin:/bin" }, shell: false, stdio: ["pipe", "pipe", "pipe"] });
    const state: State = { child, nextId: 1, buffer: "", pending: new Map(), bytes: new Map(), order: [], total: 0, busy: false, status: "open" };
    child.stderr.resume();
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      state.buffer += chunk;
      for (;;) {
        const newline = state.buffer.indexOf("\n"); if (newline < 0) break;
        const line = state.buffer.slice(0, newline); state.buffer = state.buffer.slice(newline + 1);
        let response: ChildResponse;
        try { response = JSON.parse(line) as ChildResponse; } catch { child.kill("SIGKILL"); continue; }
        const pending = state.pending.get(response.id); if (pending === undefined) continue;
        clearTimeout(pending.timer); state.pending.delete(response.id); pending.resolve(response);
      }
    });
    child.once("error", () => { for (const [id, pending] of state.pending) { clearTimeout(pending.timer); pending.resolve({ id, ok: false, operation: "unknown", reason: "IO_HELPER_FAILURE", message: "The compile-pack capture helper failed." }); } state.pending.clear(); });
    child.once("close", () => {
      for (const [id, pending] of state.pending) {
        clearTimeout(pending.timer);
        pending.resolve({ id, ok: false, operation: "unknown", reason: "IO_HELPER_FAILURE", message: "The compile-pack capture helper closed unexpectedly." });
      }
      state.pending.clear();
    });

    let session: CompilePackCaptureSessionV02;
    const captureMember = async (
      name: DirectChildName,
      maxMemberBytes: number,
      maxTotalBytes: number,
    ): Promise<Result<{ name: DirectChildName; byte_length: number }>> => exclusive(state, async () => {
      if (state.status !== "open" || parseDirectChildName(name) === null || state.bytes.has(name)
        || !validPositiveLimit(maxMemberBytes) || !validPositiveLimit(maxTotalBytes)
        || maxTotalBytes < maxMemberBytes) {
        if (state.status === "open") { state.status = "aborted"; await stop(state, "abort"); }
        return fail("INVALID_COMPILE_PACK", "The compile-pack member capture is invalid or duplicated.");
      }
      const remaining = maxTotalBytes - state.total;
      if (remaining <= 0) {
        state.status = "aborted"; await stop(state, "abort");
        return fail("INPUT_TOO_LARGE", "The compile pack exceeds its capture byte budget.");
      }
      const response = await request(state, "capture", {
        name,
        max_member_bytes: maxMemberBytes,
        remaining_total_bytes: remaining,
      });
      if (!response.ok || response.name !== name || typeof response.bytes_base64 !== "string"
        || !validBase64(response.bytes_base64) || !Number.isSafeInteger(response.byte_length)) {
        const result = mapFailure<{ name: DirectChildName; byte_length: number }>(response);
        state.status = "aborted"; await stop(state, "abort");
        return result;
      }
      const bytes = Buffer.from(response.bytes_base64, "base64");
      if (bytes.byteLength !== response.byte_length || bytes.byteLength > Math.min(maxMemberBytes, remaining)) {
        state.child.kill("SIGKILL"); state.status = "aborted";
        return fail("IO_HELPER_UNAVAILABLE", "The compile-pack capture helper returned inconsistent bytes.");
      }
      state.bytes.set(name, new Uint8Array(bytes)); state.order.push(name); state.total += bytes.byteLength;
      return { ok: true, value: { name, byte_length: bytes.byteLength } };
    });
    session = Object.freeze({
      listDirectEntries: async (): Promise<Result<readonly Entry[]>> => {
        return exclusive(state, async () => {
          if (state.status !== "open") return fail("INVALID_COMPILE_PACK", "The compile-pack capture session is closed.");
          const response = await request(state, "list");
          return response.ok && Array.isArray(response.entries) ? { ok: true, value: Object.freeze(response.entries.map((entry) => Object.freeze(entry))) } : mapFailure(response);
        });
      },
      captureMember: async (name: DirectChildName): Promise<Result<{ name: DirectChildName; byte_length: number }>> => {
        return captureMember(name, MAX_MEMBER_BYTES, MAX_TOTAL_BYTES);
      },
      captureLegacyMember: async (
        name: DirectChildName,
        limits: Readonly<{ max_member_bytes: number; max_total_bytes: number }>,
      ) => captureMember(
        name,
        limits.max_member_bytes,
        limits.max_total_bytes,
      ),
      snapshotCapturedManifest: (): Result<Uint8Array> => {
        if (state.status !== "open" || state.busy) return fail("INVALID_COMPILE_PACK", "The compile-pack capture session is closed or busy.");
        const manifestName = parseDirectChildName("pack-manifest.json")!;
        const bytes = state.bytes.get(manifestName);
        return bytes === undefined
          ? fail("INVALID_COMPILE_PACK", "The compile-pack manifest has not been captured.")
          : { ok: true, value: new Uint8Array(bytes) };
      },
      seal: async (expected: readonly DirectChildName[], order: readonly DirectChildName[]): Promise<Result<CapturedCompilePackV02>> => {
        return exclusive(state, async () => {
        if (state.status !== "open" || expected.length !== state.bytes.size || order.length !== state.order.length || expected.some((name) => !state.bytes.has(name)) || order.some((name, index) => name !== state.order[index]) || new Set(expected).size !== expected.length) {
          if (state.status === "open") { state.status = "aborted"; await stop(state, "abort"); }
          return fail("INVALID_COMPILE_PACK", "The captured compile-pack inventory or order is invalid.");
        }
        const stopped = await stop(state, "seal"); if (!stopped.ok) return stopped;
        state.status = "sealed";
        const rows = state.order.map((name) => ({ name, byte_length: state.bytes.get(name)!.byteLength, sha256: hash(state.bytes.get(name)!) }));
        const rootHash = hash(new TextEncoder().encode(JSON.stringify(rows)));
        let pack: CapturedCompilePackV02;
        pack = Object.freeze({ schema_version: "0.2", total_byte_length: state.total, source_pack_root_hash: rootHash, memberNames: () => Object.freeze([...state.order]), memberByteLength: (name: DirectChildName) => state.bytes.get(name)?.byteLength ?? -1, snapshotMemberBytes: (name: DirectChildName): Result<Uint8Array> => { const registered = packs.get(pack)?.get(name); return registered === undefined ? fail("INVALID_COMPILE_PACK", "The captured member is unavailable.") : { ok: true, value: new Uint8Array(registered) }; } }) as CapturedCompilePackV02;
        packs.set(pack, new Map([...state.bytes].map(([name, bytes]) => [name, new Uint8Array(bytes)])));
        return { ok: true, value: pack };
        });
      },
      abort: async (): Promise<Result<null>> => exclusive(state, async () => { if (state.status !== "open") return fail("INVALID_COMPILE_PACK", "The compile-pack capture session is closed."); state.status = "aborted"; return stop(state, "abort"); }),
    }) as unknown as CompilePackCaptureSessionV02;
    sessions.set(session, state);
    const initialized = await request(state, "init", { device: identity.dev.toString(), inode: identity.ino.toString() });
    if (!initialized.ok) { state.child.kill("SIGKILL"); return mapFailure(initialized); }
    return { ok: true, value: session };
  } catch { return fail("IO_HELPER_UNAVAILABLE", "The compile-pack capture helper is unavailable."); }
}
