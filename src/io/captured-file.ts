import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { lstat, realpath, stat } from "node:fs/promises";
import { basename, dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type {
  LegacyReplayChildRequest,
  LegacyReplayChildResponse,
  LegacyReplaySessionRequest,
  LegacyReplaySessionResponse,
} from "./legacy-replay-child.js";

export type DirectChildName = string & { readonly __directChildName: unique symbol };

export type LegacyCompatibilityPolicy = {
  mode: "operator-approved-finite";
  max_member_bytes: number;
  max_total_bytes: number;
  max_heap_bytes: number;
  max_elapsed_ms: number;
  approved_by: "operator";
};

export type StructuredFamilySelectionKind = "authoring" | "resolved-run-plan";
export type LegacyV01DocumentKind =
  | "authoring"
  | "resolved-run-plan"
  | "work-item"
  | "intake-record"
  | "catalog-resolution"
  | "compilation-record"
  | "approved-intake-brief"
  | "generated-loop"
  | "ledger-jsonl"
  | "report-input"
  | "receipt";

export type CapturedStructuredFamilyResult =
  | {
      ok: true;
      schema_version: "0.1" | "0.2";
      capture: CapturedStructuredFile;
    }
  | {
      ok: false;
      reason:
        | "INPUT_TOO_LARGE"
        | "INVALID_DOCUMENT_ENVELOPE"
        | "MISSING_SCHEMA_VERSION"
        | "MALFORMED_SCHEMA_VERSION"
        | "UNSUPPORTED_SCHEMA_VERSION"
        | "LEGACY_REPLAY_RESOURCE_LIMIT"
        | "IO_HELPER_UNAVAILABLE";
      message: string;
    };

export type LegacyV01ParseResult =
  | {
      ok: true;
      schema_version: "0.1";
      kind: LegacyV01DocumentKind;
      byte_length: number;
      raw_hash: string;
      value: unknown;
    }
  | {
      ok: false;
      reason:
        | "INVALID_DOCUMENT_ENVELOPE"
        | "INVALID_V01_DOCUMENT"
        | "LEGACY_REPLAY_RESOURCE_LIMIT"
        | "IO_HELPER_UNAVAILABLE";
      message: string;
    };

export type LegacyLedgerV01LineageResult =
  | { ok: true; schema_version: "0.1"; run_id: string }
  | {
      ok: false;
      reason: "INVALID_V01_DOCUMENT" | "LEGACY_REPLAY_RESOURCE_LIMIT" | "IO_HELPER_UNAVAILABLE";
      message: string;
    };

export type CapturedStructuredFile = {
  readonly name: DirectChildName;
  readonly byte_length: number;
  selectFamily(kind: StructuredFamilySelectionKind): Promise<CapturedStructuredFamilyResult>;
  selectLedgerV01Lineage(expectedRunId: string): Promise<LegacyLedgerV01LineageResult>;
  parseV01(kind: LegacyV01DocumentKind): Promise<LegacyV01ParseResult>;
  snapshotBytes(): Promise<
    | { ok: true; bytes: Uint8Array }
    | {
        ok: false;
        reason: "LEGACY_REPLAY_RESOURCE_LIMIT" | "IO_HELPER_UNAVAILABLE";
        message: string;
      }
  >;
};

export type CapturedStructuredFileResult =
  | { ok: true; capture: CapturedStructuredFile }
  | {
      ok: false;
      reason:
        | "INVALID_LEGACY_COMPATIBILITY_POLICY"
        | "INVALID_INPUT_FILE"
        | "INPUT_TOO_LARGE"
        | "LEGACY_REPLAY_RESOURCE_LIMIT"
        | "IO_IDENTITY_MISMATCH"
        | "IO_HELPER_UNAVAILABLE";
      message: string;
    };

export type CapturedStructuredFileReleaseResult =
  | { ok: true }
  | { ok: false; reason: "IO_HELPER_UNAVAILABLE"; message: string };

const AUTOMATIC_POLICY: LegacyCompatibilityPolicy = Object.freeze({
  mode: "operator-approved-finite",
  max_member_bytes: 67_108_864,
  max_total_bytes: 268_435_456,
  max_heap_bytes: 536_870_912,
  max_elapsed_ms: 30_000,
  approved_by: "operator",
});
const MAX_HELPER_OUTPUT_BYTES = 100_663_296;

export function parseDirectChildName(value: string): DirectChildName | null {
  if (
    value.length === 0 ||
    value === "." ||
    value === ".." ||
    value.includes("/") ||
    value.includes("\\") ||
    value.includes("\0") ||
    value.normalize("NFC") !== value ||
    basename(value) !== value
  ) {
    return null;
  }
  return value as DirectChildName;
}

function validLimit(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function resolvePolicy(policy: LegacyCompatibilityPolicy | null): LegacyCompatibilityPolicy | null {
  if (policy === null) return AUTOMATIC_POLICY;
  if (
    !validLimit(policy.max_member_bytes) ||
    !validLimit(policy.max_total_bytes) ||
    !validLimit(policy.max_heap_bytes) ||
    !validLimit(policy.max_elapsed_ms) ||
    policy.mode !== "operator-approved-finite" ||
    policy.approved_by !== "operator" ||
    policy.max_total_bytes < policy.max_member_bytes ||
    policy.max_heap_bytes < policy.max_member_bytes
  ) {
    return null;
  }
  return Object.freeze({ ...policy });
}

function failure(
  reason: Extract<CapturedStructuredFileResult, { ok: false }>["reason"],
  message: string,
): CapturedStructuredFileResult {
  return { ok: false, reason, message };
}

function helperPath(): string {
  const currentPath = fileURLToPath(import.meta.url);
  const extension = extname(currentPath);
  return join(dirname(currentPath), `legacy-replay-child${extension}`);
}

function helperArguments(oneShot: boolean): string[] {
  const path = helperPath();
  const sourceLoader = extname(path) === ".ts" && !oneShot ? ["--import", import.meta.resolve("tsx")] : [];
  return [...sourceLoader, path, ...(oneShot ? ["--one-shot"] : [])];
}

export function requestLegacyReplayChild(
  workingDirectory: string,
  request: LegacyReplayChildRequest,
  policy: LegacyCompatibilityPolicy,
): Promise<LegacyReplayChildResponse> {
  return new Promise((resolve) => {
    const child = spawn(
      process.execPath,
      [`--max-old-space-size=${Math.max(16, Math.floor(policy.max_heap_bytes / 1_048_576))}`, ...helperArguments(true)],
      {
        cwd: workingDirectory,
        env: {
          LANG: "C",
          LC_ALL: "C",
          PATH: process.env.PATH ?? "/usr/bin:/bin",
        },
        shell: false,
        stdio: ["pipe", "pipe", "ignore"],
      },
    );

    let settled = false;
    let output = "";
    const finish = (response: LegacyReplayChildResponse): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(response);
    };
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish({ ok: false, reason: "IO_HELPER_FAILURE", message: "The compatibility helper timed out." });
    }, policy.max_elapsed_ms);

    child.once("error", () => {
      finish({ ok: false, reason: "IO_HELPER_FAILURE", message: "The compatibility helper could not start." });
    });
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      output += chunk;
      if (Buffer.byteLength(output, "utf8") > MAX_HELPER_OUTPUT_BYTES) {
        child.kill("SIGKILL");
        finish({ ok: false, reason: "IO_HELPER_FAILURE", message: "The compatibility helper response was too large." });
      }
    });
    child.once("close", (code) => {
      if (settled) return;
      if (code !== 0) {
        finish({ ok: false, reason: "IO_HELPER_FAILURE", message: "The compatibility helper exited unsuccessfully." });
        return;
      }
      try {
        const parsed = JSON.parse(output) as LegacyReplayChildResponse;
        if (
          typeof parsed !== "object" ||
          parsed === null ||
          typeof parsed.ok !== "boolean" ||
          (parsed.ok &&
            (typeof parsed.bytes_base64 !== "string" || !Number.isSafeInteger(parsed.byte_length))) ||
          (!parsed.ok && (typeof parsed.reason !== "string" || typeof parsed.message !== "string"))
        ) {
          throw new Error("malformed helper response");
        }
        finish(parsed);
      } catch {
        finish({ ok: false, reason: "IO_HELPER_FAILURE", message: "The compatibility helper response was malformed." });
      }
    });
    child.stdin.end(JSON.stringify(request));
  });
}

type SessionFailure = Extract<LegacyReplaySessionResponse, { ok: false }>;

class LegacyReplaySession {
  readonly child: ChildProcessWithoutNullStreams;
  private readonly policy: LegacyCompatibilityPolicy;
  private buffer = "";
  private pending: { resolve: (value: LegacyReplaySessionResponse) => void; timer: NodeJS.Timeout } | null = null;
  private queue: Promise<void> = Promise.resolve();
  private closed = false;
  private responseBytes = 0;

  constructor(workingDirectory: string, policy: LegacyCompatibilityPolicy) {
    this.policy = policy;
    this.child = spawn(
      process.execPath,
      [`--max-old-space-size=${Math.max(16, Math.floor(policy.max_heap_bytes / 1_048_576))}`, ...helperArguments(false)],
      { cwd: workingDirectory, env: { LANG: "C", LC_ALL: "C", PATH: process.env.PATH ?? "/usr/bin:/bin" }, shell: false, stdio: ["pipe", "pipe", "pipe"] },
    );
    this.child.stdout.setEncoding("utf8");
    this.child.stdout.on("data", (chunk: string) => this.receive(chunk));
    this.child.once("error", () => this.failPending("The compatibility helper could not start."));
    this.child.once("close", () => this.failPending("The compatibility helper session closed unexpectedly."));
    this.child.unref();
    (this.child.stdin as NodeJS.WritableStream & { unref?: () => void }).unref?.();
    (this.child.stdout as NodeJS.ReadableStream & { unref?: () => void }).unref?.();
    (this.child.stderr as NodeJS.ReadableStream & { unref?: () => void }).unref?.();
  }

  request(input: LegacyReplaySessionRequest): Promise<LegacyReplaySessionResponse> {
    let resolveResult!: (value: LegacyReplaySessionResponse) => void;
    const result = new Promise<LegacyReplaySessionResponse>((resolve) => { resolveResult = resolve; });
    this.queue = this.queue.then(async () => {
      if (this.closed) {
        resolveResult(this.helperFailure(input.operation, "The compatibility helper session is closed."));
        return;
      }
      const response = await this.send(input);
      resolveResult(response);
    }).catch(() => resolveResult(this.helperFailure(input.operation, "The compatibility helper request failed.")));
    return result;
  }

  terminate(): void {
    if (this.closed) return;
    this.closed = true;
    this.child.kill("SIGKILL");
    this.failPending("The compatibility helper session was terminated.");
  }

  async close(): Promise<CapturedStructuredFileReleaseResult> {
    if (this.closed) {
      return { ok: false, reason: "IO_HELPER_UNAVAILABLE", message: "The compatibility helper session is closed." };
    }
    const response = await this.request({ operation: "close" });
    if (!response.ok) {
      this.terminate();
      return { ok: false, reason: "IO_HELPER_UNAVAILABLE", message: response.message };
    }
    if (response.operation !== "close") {
      this.terminate();
      return { ok: false, reason: "IO_HELPER_UNAVAILABLE", message: "The compatibility helper returned the wrong response kind." };
    }
    return { ok: true };
  }

  private send(input: LegacyReplaySessionRequest): Promise<LegacyReplaySessionResponse> {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.child.kill("SIGKILL");
        this.closed = true;
        if (this.pending !== null) {
          this.pending = null;
          resolve(this.helperFailure(input.operation, "The compatibility helper timed out."));
        }
      }, this.policy.max_elapsed_ms);
      this.pending = { resolve, timer };
      this.child.stdin.write(`${JSON.stringify(input)}\n`, (error) => {
        if (error) this.failPending("The compatibility helper request could not be written.");
      });
    });
  }

  private receive(chunk: string): void {
    this.buffer += chunk;
    if (Buffer.byteLength(this.buffer, "utf8") > MAX_HELPER_OUTPUT_BYTES) {
      this.child.kill("SIGKILL");
      this.closed = true;
      this.failPending("The compatibility helper response was too large.");
      return;
    }
    const newline = this.buffer.indexOf("\n");
    if (newline < 0 || this.pending === null) return;
    const line = this.buffer.slice(0, newline);
    this.buffer = this.buffer.slice(newline + 1);
    this.responseBytes += Buffer.byteLength(line, "utf8");
    if (this.responseBytes > this.policy.max_total_bytes) {
      this.child.kill("SIGKILL");
      this.closed = true;
      this.failPending("The compatibility helper aggregate response limit was exceeded.");
      return;
    }
    const pending = this.pending;
    this.pending = null;
    clearTimeout(pending.timer);
    try {
      const parsed = JSON.parse(line) as LegacyReplaySessionResponse;
      if (typeof parsed !== "object" || parsed === null || typeof parsed.ok !== "boolean" || typeof parsed.operation !== "string") throw new Error("malformed");
      if (parsed.operation === "close") this.closed = true;
      pending.resolve(parsed);
    } catch {
      pending.resolve(this.helperFailure("open", "The compatibility helper response was malformed."));
    }
  }

  private failPending(message: string): void {
    if (this.pending === null) return;
    const pending = this.pending;
    this.pending = null;
    clearTimeout(pending.timer);
    pending.resolve(this.helperFailure("open", message));
  }

  private helperFailure(operation: SessionFailure["operation"], message: string): SessionFailure {
    return { ok: false, operation, reason: "IO_HELPER_FAILURE", message };
  }
}

const captureSessionRegistry = new WeakMap<CapturedStructuredFile, LegacyReplaySession>();

function publicSessionFailure(response: SessionFailure):
  { ok: false; reason: "LEGACY_REPLAY_RESOURCE_LIMIT" | "IO_HELPER_UNAVAILABLE"; message: string } {
  return response.message.includes("timed out") || response.message.includes("limit")
    ? { ok: false, reason: "LEGACY_REPLAY_RESOURCE_LIMIT", message: response.message }
    : { ok: false, reason: "IO_HELPER_UNAVAILABLE", message: response.message };
}

function isCanonicalBase64Shape(value: string): boolean {
  if (value.length % 4 !== 0) return false;
  let contentLength = value.length;
  if (contentLength > 0 && value.charCodeAt(contentLength - 1) === 61) contentLength -= 1;
  if (contentLength > 0 && value.charCodeAt(contentLength - 1) === 61) contentLength -= 1;
  for (let index = 0; index < contentLength; index += 1) {
    const code = value.charCodeAt(index);
    const valid =
      (code >= 65 && code <= 90) ||
      (code >= 97 && code <= 122) ||
      (code >= 48 && code <= 57) ||
      code === 43 ||
      code === 47;
    if (!valid) return false;
  }
  for (let index = contentLength; index < value.length; index += 1) {
    if (value.charCodeAt(index) !== 61) return false;
  }
  const paddingLength = value.length - contentLength;
  return paddingLength <= 2 && (paddingLength === 0 || contentLength % 4 === 4 - paddingLength);
}

function makeCapture(name: DirectChildName, byteLength: number, session: LegacyReplaySession): CapturedStructuredFile {
  let capture: CapturedStructuredFile;
  capture = Object.freeze({
    name,
    byte_length: byteLength,
    selectFamily: async (kind: StructuredFamilySelectionKind): Promise<CapturedStructuredFamilyResult> => {
      const response = await session.request({ operation: "select-family", kind });
      if (!response.ok) {
        if (response.reason === "IO_HELPER_FAILURE") return publicSessionFailure(response);
        return { ok: false, reason: response.reason, message: response.message } as CapturedStructuredFamilyResult;
      }
      if (response.operation !== "select-family") return { ok: false, reason: "IO_HELPER_UNAVAILABLE", message: "The compatibility helper returned the wrong response kind." };
      return { ok: true, schema_version: response.schema_version, capture };
    },
    selectLedgerV01Lineage: async (expectedRunId: string): Promise<LegacyLedgerV01LineageResult> => {
      const response = await session.request({ operation: "select-ledger-v01-lineage", expected_run_id: expectedRunId });
      if (!response.ok) {
        if (response.reason === "IO_HELPER_FAILURE") return publicSessionFailure(response);
        return { ok: false, reason: "INVALID_V01_DOCUMENT", message: response.message };
      }
      if (
        response.operation !== "select-ledger-v01-lineage" ||
        response.schema_version !== "0.1" ||
        response.run_id !== expectedRunId
      ) {
        session.terminate();
        return { ok: false, reason: "IO_HELPER_UNAVAILABLE", message: "The compatibility helper returned inconsistent V01 ledger lineage." };
      }
      return { ok: true, schema_version: "0.1", run_id: response.run_id };
    },
    parseV01: async (kind: LegacyV01DocumentKind): Promise<LegacyV01ParseResult> => {
      const response = await session.request({ operation: "parse-v01", kind });
      if (!response.ok) {
        if (response.reason === "IO_HELPER_FAILURE") return publicSessionFailure(response);
        return { ok: false, reason: response.reason, message: response.message } as LegacyV01ParseResult;
      }
      if (response.operation !== "parse-v01") return { ok: false, reason: "IO_HELPER_UNAVAILABLE", message: "The compatibility helper returned the wrong response kind." };
      if (
        response.schema_version !== "0.1" || response.kind !== kind ||
        response.byte_length !== byteLength || !/^sha256:[0-9a-f]{64}$/.test(response.raw_hash)
      ) {
        session.terminate();
        return { ok: false, reason: "IO_HELPER_UNAVAILABLE", message: "The compatibility helper returned inconsistent V01 parse metadata." };
      }
      const { operation: _operation, ...result } = response;
      return result;
    },
    snapshotBytes: async () => {
      const response = await session.request({ operation: "snapshot" });
      if (!response.ok) return publicSessionFailure(response);
      if (response.operation !== "snapshot") return { ok: false as const, reason: "IO_HELPER_UNAVAILABLE" as const, message: "The compatibility helper returned the wrong response kind." };
      if (!isCanonicalBase64Shape(response.bytes_base64)) {
        session.terminate();
        return { ok: false as const, reason: "IO_HELPER_UNAVAILABLE" as const, message: "The compatibility helper returned a malformed snapshot." };
      }
      const bytes = Buffer.from(response.bytes_base64, "base64");
      if (bytes.byteLength !== response.byte_length || bytes.byteLength !== byteLength) {
        session.terminate();
        return { ok: false as const, reason: "IO_HELPER_UNAVAILABLE" as const, message: "The compatibility helper returned an inconsistent snapshot." };
      }
      return { ok: true as const, bytes: new Uint8Array(bytes) };
    },
  });
  captureSessionRegistry.set(capture, session);
  return capture;
}

export async function releaseCapturedStructuredFile(
  capture: CapturedStructuredFile,
): Promise<CapturedStructuredFileReleaseResult> {
  const session = captureSessionRegistry.get(capture);
  if (session === undefined) {
    return { ok: false, reason: "IO_HELPER_UNAVAILABLE", message: "The captured file helper is unavailable." };
  }
  captureSessionRegistry.delete(capture);
  return session.close();
}

export async function captureStructuredFile(
  inputPath: string,
  policyInput: LegacyCompatibilityPolicy | null,
  expectedDirectoryIdentity?: Readonly<{ device: string; inode: string }>,
): Promise<CapturedStructuredFileResult> {
  const policy = resolvePolicy(policyInput);
  if (policy === null) {
    return failure("INVALID_LEGACY_COMPATIBILITY_POLICY", "The compatibility policy is invalid.");
  }

  try {
    const input = await lstat(inputPath, { bigint: true });
    if (!input.isFile() || input.isSymbolicLink()) {
      return failure("INVALID_INPUT_FILE", "The input must be a direct regular file.");
    }
    if (input.size > BigInt(policy.max_member_bytes)) {
      return failure("INPUT_TOO_LARGE", `The input exceeds ${policy.max_member_bytes} bytes.`);
    }

    const directoryPath = await realpath(dirname(inputPath));
    const directory = await stat(directoryPath, { bigint: true });
    if (expectedDirectoryIdentity !== undefined && (
      directory.dev.toString() !== expectedDirectoryIdentity.device ||
      directory.ino.toString() !== expectedDirectoryIdentity.inode
    )) {
      return failure("IO_IDENTITY_MISMATCH", "The input directory identity changed.");
    }
    const directChildName = parseDirectChildName(basename(inputPath));
    if (directChildName === null) {
      return failure("INVALID_INPUT_FILE", "The input must be a direct child file.");
    }
    const session = new LegacyReplaySession(directoryPath, policy);
    const response = await session.request({
      operation: "open",
      request: {
        direct_child_name: directChildName,
        expected_directory_device: expectedDirectoryIdentity?.device ?? directory.dev.toString(),
        expected_directory_inode: expectedDirectoryIdentity?.inode ?? directory.ino.toString(),
        max_bytes: policy.max_member_bytes,
      },
    });
    if (!response.ok) {
      session.terminate();
      if (response.reason === "IO_IDENTITY_MISMATCH" || response.reason === "INVALID_INPUT_FILE" || response.reason === "INPUT_TOO_LARGE") {
        return failure(response.reason, response.message);
      }
      if (response.message.includes("timed out")) {
        return failure("LEGACY_REPLAY_RESOURCE_LIMIT", response.message);
      }
      return failure("IO_HELPER_UNAVAILABLE", response.message);
    }
    if (response.operation !== "open" || response.byte_length > policy.max_member_bytes) {
      session.terminate();
      return failure("IO_HELPER_UNAVAILABLE", "The compatibility helper returned an inconsistent capture metadata response.");
    }
    return { ok: true, capture: makeCapture(directChildName, response.byte_length, session) };
  } catch {
    return failure("INVALID_INPUT_FILE", "The input must be an existing direct regular file.");
  }
}
