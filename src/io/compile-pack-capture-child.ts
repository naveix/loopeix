import { constants } from "node:fs";
import { open, readdir, stat } from "node:fs/promises";
import { createInterface } from "node:readline";

type Request =
  | { id: number; operation: "init"; device: string; inode: string }
  | { id: number; operation: "list" }
  | { id: number; operation: "capture"; name: string; max_member_bytes: number; remaining_total_bytes: number }
  | { id: number; operation: "seal" }
  | { id: number; operation: "abort" };

type FailureReason = "INVALID_REQUEST" | "IO_IDENTITY_MISMATCH" | "INVALID_INPUT_FILE" | "INPUT_TOO_LARGE" | "IO_HELPER_FAILURE";
type Response =
  | { id: number; ok: true; operation: Request["operation"]; entries?: Array<{ name: string; kind: "regular-file" | "directory" | "symlink" | "other" }>; name?: string; bytes_base64?: string; byte_length?: number }
  | { id: number; ok: false; operation: Request["operation"] | "unknown"; reason: FailureReason; message: string };

let identity: { device: string; inode: string } | null = null;
let closed = false;
const captured = new Set<string>();

function directName(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value !== "." && value !== ".." &&
    !value.includes("/") && !value.includes("\\") && !value.includes("\0") && value.normalize("NFC") === value;
}

function failure(id: number, operation: Response["operation"], reason: FailureReason, message: string): Response {
  return { id, ok: false, operation, reason, message };
}

async function identityMatches(): Promise<boolean> {
  if (identity === null) return false;
  const current = await stat(".", { bigint: true });
  return current.dev.toString() === identity.device && current.ino.toString() === identity.inode;
}

async function handle(request: Request): Promise<Response> {
  if (closed) return failure(request.id, request.operation, "INVALID_REQUEST", "The capture helper is closed.");
  if (request.operation === "init") {
    if (identity !== null) return failure(request.id, request.operation, "INVALID_REQUEST", "The capture helper is already initialized.");
    const current = await stat(".", { bigint: true });
    if (current.dev.toString() !== request.device || current.ino.toString() !== request.inode) {
      return failure(request.id, request.operation, "IO_IDENTITY_MISMATCH", "The capture helper cwd identity does not match.");
    }
    identity = { device: request.device, inode: request.inode };
    return { id: request.id, ok: true, operation: request.operation };
  }
  if (!(await identityMatches())) return failure(request.id, request.operation, "IO_IDENTITY_MISMATCH", "The capture helper cwd identity changed.");
  if (request.operation === "list") {
    const entries = (await readdir(".", { withFileTypes: true })).map((entry) => ({
      name: entry.name,
      kind: entry.isSymbolicLink() ? "symlink" as const : entry.isFile() ? "regular-file" as const : entry.isDirectory() ? "directory" as const : "other" as const,
    }));
    return { id: request.id, ok: true, operation: request.operation, entries };
  }
  if (request.operation === "capture") {
    if (!directName(request.name) || captured.has(request.name) || !Number.isSafeInteger(request.max_member_bytes) ||
      !Number.isSafeInteger(request.remaining_total_bytes) || request.max_member_bytes <= 0 || request.remaining_total_bytes <= 0) {
      return failure(request.id, request.operation, "INVALID_REQUEST", "The capture request is invalid or duplicated.");
    }
    const ceiling = Math.min(request.max_member_bytes, request.remaining_total_bytes);
    let file: Awaited<ReturnType<typeof open>> | null = null;
    try {
      const noFollow = "O_NOFOLLOW" in constants ? constants.O_NOFOLLOW : 0;
      file = await open(request.name, constants.O_RDONLY | noFollow);
      const metadata = await file.stat({ bigint: true });
      if (!metadata.isFile()) return failure(request.id, request.operation, "INVALID_INPUT_FILE", "The pack member must be a regular file.");
      if (metadata.size > BigInt(ceiling)) return failure(request.id, request.operation, "INPUT_TOO_LARGE", "The compile pack exceeds its capture byte budget.");
      const chunks: Buffer[] = [];
      let length = 0;
      for (;;) {
        const capacity = Math.min(65_536, ceiling + 1 - length);
        if (capacity <= 0) return failure(request.id, request.operation, "INPUT_TOO_LARGE", "The compile pack exceeds its capture byte budget.");
        const chunk = Buffer.allocUnsafe(capacity);
        const read = await file.read(chunk, 0, capacity, null);
        if (read.bytesRead === 0) break;
        length += read.bytesRead;
        if (length > ceiling) return failure(request.id, request.operation, "INPUT_TOO_LARGE", "The compile pack exceeds its capture byte budget.");
        chunks.push(chunk.subarray(0, read.bytesRead));
      }
      captured.add(request.name);
      return { id: request.id, ok: true, operation: request.operation, name: request.name, bytes_base64: Buffer.concat(chunks, length).toString("base64"), byte_length: length };
    } catch (error: unknown) {
      const code = typeof error === "object" && error !== null && "code" in error ? String((error as { code?: unknown }).code) : "";
      return code === "ELOOP" || code === "ENOENT" || code === "ENOTDIR"
        ? failure(request.id, request.operation, "INVALID_INPUT_FILE", "The pack member must be an existing regular file.")
        : failure(request.id, request.operation, "IO_HELPER_FAILURE", "The capture helper could not read the pack member.");
    } finally {
      if (file !== null) await file.close().catch(() => undefined);
    }
  }
  closed = true;
  return { id: request.id, ok: true, operation: request.operation };
}

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
let requestQueue = Promise.resolve();
lines.on("line", (line) => {
  requestQueue = requestQueue.then(async () => {
    let request: Request;
    try { request = JSON.parse(line) as Request; }
    catch { process.stdout.write(`${JSON.stringify(failure(-1, "unknown", "INVALID_REQUEST", "The capture request is malformed."))}\n`); return; }
    try { process.stdout.write(`${JSON.stringify(await handle(request))}\n`); }
    catch { process.stdout.write(`${JSON.stringify(failure(request.id, request.operation, "IO_HELPER_FAILURE", "The capture helper failed."))}\n`); }
    if (closed) process.exitCode = 0;
  }).catch(() => {
    closed = true;
    process.exitCode = 1;
  });
});
