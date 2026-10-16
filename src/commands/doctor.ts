import { spawn } from "node:child_process";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Command } from "@oclif/core";
import { hashRawBytes } from "../hash.js";
import { decodeStructuredDocumentV02 } from "../schema/decode-envelope.js";

export type DoctorCheckId =
  | "node-runtime"
  | "package-version"
  | "platform"
  | "io-helper"
  | "schema-loopeix-v01"
  | "schema-loopeix-v02"
  | "schema-loopeix-dispatcher"
  | "schema-receipt";

export type DoctorFailureReason =
  | "UNSUPPORTED_RUNTIME"
  | "IO_HELPER_UNAVAILABLE"
  | "SCHEMA_PACKAGE_INVALID";

export type DoctorCheck<I extends DoctorCheckId = DoctorCheckId> = {
  id: I;
  ok: boolean;
  detail: string;
};

export type DoctorChecks = readonly [
  DoctorCheck<"node-runtime">,
  DoctorCheck<"package-version">,
  DoctorCheck<"platform">,
  DoctorCheck<"io-helper">,
  DoctorCheck<"schema-loopeix-v01">,
  DoctorCheck<"schema-loopeix-v02">,
  DoctorCheck<"schema-loopeix-dispatcher">,
  DoctorCheck<"schema-receipt">,
];

export type DoctorJsonResult =
  | {
      node: string;
      cli: string;
      schemaBundled: true;
      platform_supported: true;
      filesystem_identity_supported: true;
      ok: true;
      checks: DoctorChecks;
      disposition: "pass";
      reason: null;
      findings: readonly [];
    }
  | {
      node: string;
      cli: string;
      schemaBundled: boolean;
      platform_supported: boolean;
      filesystem_identity_supported: boolean;
      ok: false;
      checks: DoctorChecks;
      disposition: "hold";
      reason: DoctorFailureReason;
      findings: readonly [string, ...string[]];
    };

export type DoctorEvaluationInput = {
  packageRoot: string;
  helperRelativePath: string;
  nodeVersion: string;
  cliVersion: string;
  platform: NodeJS.Platform | string;
  architecture: string;
};

type JsonObject = Record<string, unknown>;

const SCHEMA_FILES = {
  v01: "loopeix-0.1.schema.json",
  v02: "loopeix-0.2.schema.json",
  dispatcher: "loopeix.schema.json",
  receipt: "receipt.schema.json",
} as const;

const SCHEMA_IDS = {
  v01: "https://loopeix.dev/schemas/loopeix-0.1.schema.json",
  v02: "https://loopeix.dev/schemas/loopeix-0.2.schema.json",
  dispatcher: "https://loopeix.dev/schemas/loopeix.schema.json",
  receipt: "https://loopeix.dev/schemas/receipt-0.1.schema.json",
} as const;

const FAILURE_PRESENTATION = {
  UNSUPPORTED_RUNTIME: { exit: 1, message: "This Node.js runtime is not supported." },
  IO_HELPER_UNAVAILABLE: { exit: 4, message: "Required filesystem helper is unavailable." },
  SCHEMA_PACKAGE_INVALID: { exit: 4, message: "Installed schema package is invalid." },
} as const satisfies Record<DoctorFailureReason, { exit: 1 | 4; message: string }>;

const CHECK_REASON = {
  "node-runtime": "UNSUPPORTED_RUNTIME",
  "package-version": "SCHEMA_PACKAGE_INVALID",
  platform: "IO_HELPER_UNAVAILABLE",
  "io-helper": "IO_HELPER_UNAVAILABLE",
  "schema-loopeix-v01": "SCHEMA_PACKAGE_INVALID",
  "schema-loopeix-v02": "SCHEMA_PACKAGE_INVALID",
  "schema-loopeix-dispatcher": "SCHEMA_PACKAGE_INVALID",
  "schema-receipt": "SCHEMA_PACKAGE_INVALID",
} as const satisfies Record<DoctorCheckId, DoctorFailureReason>;

const MAX_PACKAGE_ASSET_BYTES = 4_194_304;
const MAX_HELPER_PROBE_OUTPUT_BYTES = 2_097_152;
const RECEIPT_SCHEMA_SHA256 = "sha256:99337cab3902c862f6777ad36afdabb9dd92a6105d23f2a88133af36d34cd5e5";

function check<I extends DoctorCheckId>(id: I, ok: boolean, pass: string, fail: string): DoctorCheck<I> {
  return { id, ok, detail: ok ? pass : fail };
}

function isSupportedNode(version: string): boolean {
  if (version.length > 32) return false;
  const match = /^v(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})$/u.exec(version);
  if (match === null) return false;
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  return (major === 22 && (minor > 12 || (minor === 12 && patch >= 0))) || major === 24 || major === 26;
}

function isSupportedHost(platform: string, architecture: string): boolean {
  return (platform === "linux" && architecture === "x64") || (platform === "darwin" && architecture === "arm64");
}

function safeHostLabel(platform: string, architecture: string): string {
  return /^[a-z0-9_-]{1,32}$/u.test(platform) && /^[a-z0-9_-]{1,32}$/u.test(architecture)
    ? `${platform}-${architecture}`
    : "unrecognized host";
}

function isRegularFile(path: string): boolean {
  const opened = readStableRegularFile(path);
  return opened !== null;
}

function readStableRegularFile(path: string): Uint8Array | null {
  let descriptor = -1;
  try {
    if (!("O_NOFOLLOW" in constants)) return null;
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.size > MAX_PACKAGE_ASSET_BYTES) return null;
    return new Uint8Array(readFileSync(descriptor));
  } catch {
    return null;
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
  }
}

function asObject(value: unknown): JsonObject | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as JsonObject : null;
}

function readStrictJsonObject(path: string): JsonObject | null {
  const bytes = readStableRegularFile(path);
  if (bytes === null) return null;
  try {
    const decoded = decodeStructuredDocumentV02(bytes, "json");
    return decoded.ok ? asObject(decoded.value) : null;
  } catch {
    return null;
  }
}

function hasNestedId(value: unknown, root = true): boolean {
  if (Array.isArray(value)) return value.some((entry) => hasNestedId(entry, false));
  const object = asObject(value);
  if (object === null) return false;
  if (!root && Object.hasOwn(object, "$id")) return true;
  return Object.values(object).some((entry) => hasNestedId(entry, false));
}

function embeddedVersionSchema(schema: JsonObject, family: "v01" | "v02"): JsonObject {
  const copy = structuredClone(schema);
  delete copy.$schema;
  delete copy.$id;
  const stack: unknown[] = [copy];
  while (stack.length > 0) {
    const value = stack.pop();
    if (Array.isArray(value)) {
      stack.push(...value);
      continue;
    }
    const object = asObject(value);
    if (object === null) continue;
    if (typeof object.$ref === "string" && object.$ref.startsWith("#/$defs/")) {
      object.$ref = `#/$defs/${family}/$defs/${object.$ref.slice("#/$defs/".length)}`;
    }
    stack.push(...Object.values(object));
  }
  return copy;
}

function validVersionSchema(schema: JsonObject | null, family: "v01" | "v02"): schema is JsonObject {
  if (schema === null) return false;
  const expectedVersion = family === "v01" ? "0.1" : "0.2";
  const expectedTitle = family === "v01" ? "Loopeix" : "Loopeix 0.2";
  return schema.$schema === "https://json-schema.org/draft/2020-12/schema" &&
    schema.$id === SCHEMA_IDS[family] &&
    schema.title === expectedTitle &&
    schema["x-loopeix-schema-version"] === expectedVersion &&
    schema["x-compatibility-policy"] === "additive within a minor version; breaking changes bump the version" &&
    !hasNestedId(schema);
}

function validReceiptSchema(schema: JsonObject | null): boolean {
  return schema !== null &&
    schema.$schema === "https://json-schema.org/draft/2020-12/schema" &&
    schema.$id === SCHEMA_IDS.receipt &&
    schema.title === "Loopeix Receipt" &&
    schema["x-loopeix-schema-version"] === "0.1" &&
    schema["x-compatibility-policy"] === "additive within a minor version; breaking changes bump the version" &&
    !hasNestedId(schema);
}

function validDispatcherSchema(dispatcher: JsonObject | null, v01: JsonObject | null, v02: JsonObject | null): boolean {
  if (dispatcher === null || v01 === null || v02 === null || hasNestedId(dispatcher)) return false;
  const definitions = asObject(dispatcher.$defs);
  return dispatcher.$schema === "https://json-schema.org/draft/2020-12/schema" &&
    dispatcher.$id === SCHEMA_IDS.dispatcher &&
    dispatcher.title === "Loopeix Supported Authoring Versions" &&
    JSON.stringify(dispatcher["x-loopeix-supported-schema-versions"]) === JSON.stringify(["0.1", "0.2"]) &&
    dispatcher["x-compatibility-policy"] === "additive within a minor version; breaking changes bump the version" &&
    dispatcher["x-loopeix-schema-version"] === undefined &&
    JSON.stringify(dispatcher.oneOf) === JSON.stringify([{ $ref: "#/$defs/v01" }, { $ref: "#/$defs/v02" }]) &&
    definitions !== null &&
    Object.keys(definitions).length === 2 &&
    JSON.stringify(definitions.v01) === JSON.stringify(embeddedVersionSchema(v01, "v01")) &&
    JSON.stringify(definitions.v02) === JSON.stringify(embeddedVersionSchema(v02, "v02"));
}

function validPackageVersion(packageRoot: string, cliVersion: string): boolean {
  const manifest = readStrictJsonObject(join(packageRoot, "package.json"));
  return cliVersion.length <= 64 && /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(cliVersion) &&
    manifest?.name === "loopeix" && manifest.version === cliVersion;
}

function failureReason(checks: DoctorChecks): DoctorFailureReason | null {
  const reasons = new Set(checks.filter((row) => !row.ok).map((row) => CHECK_REASON[row.id]));
  if (reasons.has("SCHEMA_PACKAGE_INVALID")) return "SCHEMA_PACKAGE_INVALID";
  if (reasons.has("IO_HELPER_UNAVAILABLE")) return "IO_HELPER_UNAVAILABLE";
  if (reasons.has("UNSUPPORTED_RUNTIME")) return "UNSUPPORTED_RUNTIME";
  return null;
}

function probePrivateHelper(input: DoctorEvaluationInput): Promise<boolean> {
  return new Promise((resolveProbe) => {
    const requestedHelperPath = join(input.packageRoot, input.helperRelativePath);
    if (!isRegularFile(requestedHelperPath)) {
      resolveProbe(false);
      return;
    }
    let helperPath: string;
    try {
      helperPath = realpathSync(requestedHelperPath);
    } catch {
      resolveProbe(false);
      return;
    }
    const packageBytes = readStableRegularFile(join(input.packageRoot, "package.json"));
    let directory;
    try {
      directory = lstatSync(input.packageRoot, { bigint: true });
      if (!directory.isDirectory() || directory.isSymbolicLink() || packageBytes === null) {
        resolveProbe(false);
        return;
      }
    } catch {
      resolveProbe(false);
      return;
    }

    const child = spawn(process.execPath, [helperPath, "--one-shot"], {
      cwd: input.packageRoot,
      env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
      shell: false,
      stdio: ["pipe", "pipe", "ignore"],
    });
    let settled = false;
    let output = "";
    const finish = (ok: boolean): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolveProbe(ok);
    };
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(false);
    }, 5_000);
    child.once("error", () => finish(false));
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      output += chunk;
      if (Buffer.byteLength(output, "utf8") > MAX_HELPER_PROBE_OUTPUT_BYTES) {
        child.kill("SIGKILL");
        finish(false);
      }
    });
    child.once("close", (code) => {
      if (settled || code !== 0) {
        finish(false);
        return;
      }
      try {
        const response = JSON.parse(output) as Record<string, unknown>;
        if (response.ok !== true || typeof response.bytes_base64 !== "string" || response.byte_length !== packageBytes.byteLength) {
          finish(false);
          return;
        }
        const captured = Buffer.from(response.bytes_base64, "base64");
        finish(
          captured.byteLength === packageBytes.byteLength &&
          captured.toString("base64") === response.bytes_base64 &&
          Buffer.from(packageBytes).equals(captured),
        );
      } catch {
        finish(false);
      }
    });
    child.stdin.end(JSON.stringify({
      direct_child_name: "package.json",
      expected_directory_device: directory.dev.toString(),
      expected_directory_inode: directory.ino.toString(),
      max_bytes: MAX_PACKAGE_ASSET_BYTES,
    }));
  });
}

export async function evaluateDoctorPackage(input: DoctorEvaluationInput): Promise<DoctorJsonResult> {
  const schemaRoot = join(input.packageRoot, "schemas");
  const dispatcherPath = join(schemaRoot, SCHEMA_FILES.dispatcher);
  const schemaBundled = existsSync(dispatcherPath);
  const v01 = readStrictJsonObject(join(schemaRoot, SCHEMA_FILES.v01));
  const v02 = readStrictJsonObject(join(schemaRoot, SCHEMA_FILES.v02));
  const dispatcher = readStrictJsonObject(dispatcherPath);
  const receipt = readStrictJsonObject(join(schemaRoot, SCHEMA_FILES.receipt));
  const nodeOk = isSupportedNode(input.nodeVersion);
  const packageOk = validPackageVersion(input.packageRoot, input.cliVersion);
  const host = safeHostLabel(input.platform, input.architecture);
  const platformOk = isSupportedHost(input.platform, input.architecture);
  const helperOk = platformOk && await probePrivateHelper(input);
  const v01Ok = validVersionSchema(v01, "v01");
  const v02Ok = validVersionSchema(v02, "v02");
  const dispatcherOk = validDispatcherSchema(dispatcher, v01, v02);
  const receiptBytes = readStableRegularFile(join(schemaRoot, SCHEMA_FILES.receipt));
  const receiptOk = validReceiptSchema(receipt) && receiptBytes !== null && hashRawBytes(receiptBytes) === RECEIPT_SCHEMA_SHA256;
  const checks: DoctorChecks = [
    check("node-runtime", nodeOk, `Node ${input.nodeVersion} is supported.`, "Node runtime is unsupported."),
    check("package-version", packageOk, `Package version ${input.cliVersion} is valid.`, "Installed package metadata is invalid."),
    check("platform", platformOk, `${host} is supported.`, `${host} is not a supported S35 host.`),
    check("io-helper", helperOk, "Private filesystem helper is available.", "Private filesystem helper is unavailable."),
    check("schema-loopeix-v01", v01Ok, "Loopeix 0.1 schema is valid.", "Loopeix 0.1 schema is invalid."),
    check("schema-loopeix-v02", v02Ok, "Loopeix 0.2 schema is valid.", "Loopeix 0.2 schema is invalid."),
    check("schema-loopeix-dispatcher", dispatcherOk, "Loopeix dispatcher schema is valid.", "Loopeix dispatcher schema is invalid."),
    check("schema-receipt", receiptOk, "Receipt schema is valid.", "Receipt schema is invalid."),
  ];
  const reason = failureReason(checks);
  if (reason === null) {
    return {
      node: input.nodeVersion,
      cli: input.cliVersion,
      schemaBundled: true,
      platform_supported: true,
      filesystem_identity_supported: true,
      ok: true,
      checks,
      disposition: "pass",
      reason: null,
      findings: [],
    };
  }
  const findings = checks.filter((row) => !row.ok).map((row) => `${row.id}: ${row.detail}`);
  if (reason === null || findings.length === 0) throw new Error("Doctor check-to-reason mapping is incomplete.");
  return {
    node: input.nodeVersion,
    cli: input.cliVersion,
    schemaBundled,
    platform_supported: platformOk,
    filesystem_identity_supported: helperOk,
    ok: false,
    checks,
    disposition: "hold",
    reason,
    findings: findings as [string, ...string[]],
  };
}

/** `loopeix doctor` — read-only validation of the installed runtime and package. */
export default class Doctor extends Command {
  static summary = "Check the local Loopeix runtime, host, helper, and packaged schemas.";
  static enableJsonFlag = true;

  public async run(): Promise<DoctorJsonResult> {
    await this.parse(Doctor);
    const here = dirname(fileURLToPath(import.meta.url));
    const packageRoot = join(here, "..", "..");
    const extension = extname(fileURLToPath(import.meta.url));
    const result = await evaluateDoctorPackage({
      packageRoot,
      helperRelativePath: extension === ".ts" ? "src/io/legacy-replay-child.ts" : "dist/io/legacy-replay-child.js",
      nodeVersion: process.version,
      cliVersion: this.config.version,
      platform: process.platform,
      architecture: process.arch,
    });
    if (!this.jsonEnabled()) {
      this.log("loopeix doctor");
      for (const row of result.checks) this.log(`  ${row.ok ? "OK" : "HOLD"} ${row.id}: ${row.detail}`);
      if (!result.ok) this.logToStderr(`ERROR [${result.reason}] ${FAILURE_PRESENTATION[result.reason].message}`);
    }
    process.exitCode = result.ok ? 0 : FAILURE_PRESENTATION[result.reason].exit;
    return result;
  }
}
