import { spawn } from "node:child_process";
import { lstatSync, readFileSync } from "node:fs";
import { arch, platform, release } from "node:os";
import process from "node:process";
import { z } from "zod";

import { hashCanonical, hashRawBytes } from "../hash.js";
import { Hash, IsoTimestamp } from "../schema/scalars.js";
import {
  runBoundedS37LinuxProbeV02,
  type S37LinuxProbeExecutionResultV02,
  type S37LinuxProbeRuntimeInputV02,
  type S37LinuxProbeRuntimeOutcomeV02,
  type S37LinuxProbeRuntimeV02,
} from "./bounded-linux-probe-v02.js";
import {
  prepareS37LinuxProbeAdmissionV02,
  type S37ActionInterpositionProfileV02,
  type S37LinuxBackendIdentityReceiptV02,
  type S37LinuxHostTupleV02,
  type S37LinuxProbeAdmissionV02,
  type S37PreSpawnProbeResultV02,
} from "./pre-spawn-capability-broker-v02.js";

const LOCAL_BINDING_PATH = "/etc/loopeix/s37.1/local-product-binding.json";
const MACHINE_ID_PATH = "/etc/machine-id";
const CGROUP_V2_CONTROLLERS_PATH = "/sys/fs/cgroup/cgroup.controllers";
const SUPERVISOR_PATH = "/opt/loopeix/s37.1/supervisor";
const PROBE_PATH = "/opt/loopeix/s37.1/probe";
const BWRAP_PATH = "/opt/loopeix/s37.1/bwrap";
const SYSTEMD_RUN_PATH = "/usr/bin/systemd-run";
const SYSTEMCTL_PATH = "/usr/bin/systemctl";
const PRODUCT_UNIT = "loopeix-s37-product-v02";
const COMPLETE_CONTROLLER_WINDOW_MS = 15_000;
const TRUSTED_DIRECTORIES = [
  "/etc", "/etc/loopeix", "/etc/loopeix/s37.1",
  "/opt", "/opt/loopeix", "/opt/loopeix/s37.1",
  "/usr", "/usr/bin", "/sys", "/sys/fs", "/sys/fs/cgroup",
] as const;

export type S37LocalLinuxProductProbeInputV02 = Readonly<{
  decision_input: unknown;
  decision: unknown;
  simulated_lease: unknown;
  profile: S37ActionInterpositionProfileV02;
  conformance_tuple: S37LinuxHostTupleV02;
  backend_receipt: S37LinuxBackendIdentityReceiptV02;
  phase_b_manifest_sha256: z.infer<typeof Hash>;
}>;

const VerifiedArtifactV02 = z.object({
  path: z.string(),
  sha256: Hash,
  uid: z.literal(0),
  setuid: z.literal(false),
}).strict();

const S37LocalLinuxHostObservationSchemaV02 = z.object({
  observed_at: IsoTimestamp,
  platform: z.literal("linux"),
  architecture: z.string().min(1),
  kernel_release: z.string().min(1),
  systemd_version: z.string().min(1),
  cgroup_version: z.literal("v2"),
  host_identity_hash: Hash,
  controller_uid: z.number().int().positive(),
  binding: z.object({
    binding_version: z.literal("0.1"),
    host_role: z.literal("local-product"),
    transport: z.literal("local-only"),
    host_identity_hash: Hash,
    controller_uid: z.number().int().positive(),
    conformance_tuple_hash: Hash,
    backend_receipt_hash: Hash,
    phase_b_manifest_sha256: Hash,
    expires_at: IsoTimestamp,
    systemd_run_sha256: Hash,
    binding_hash: Hash,
  }).strict(),
  artifacts: z.object({
    supervisor: VerifiedArtifactV02.extend({ path: z.literal("/opt/loopeix/s37.1/supervisor"), mode: z.literal("0555") }),
    probe: VerifiedArtifactV02.extend({ path: z.literal("/opt/loopeix/s37.1/probe"), mode: z.literal("0555") }),
    bwrap: VerifiedArtifactV02.extend({
      path: z.literal("/opt/loopeix/s37.1/bwrap"),
      mode: z.literal("0555"),
      version: z.string().min(1),
    }),
    systemd_run: VerifiedArtifactV02.extend({ path: z.literal("/usr/bin/systemd-run"), mode: z.literal("0755") }),
    systemctl: VerifiedArtifactV02.extend({ path: z.literal("/usr/bin/systemctl"), mode: z.literal("0755") }),
    seccomp_policy_sha256: Hash,
    cwd_identity_hash: Hash,
  }).strict(),
}).strict();

export type S37LocalLinuxHostObservationV02 = z.infer<typeof S37LocalLinuxHostObservationSchemaV02>;

const S37LocalProductBindingFileSchemaV02 = z.object({
  schema_version: z.literal("s37-local-product-binding-v02"),
  host_role: z.literal("local-product"),
  transport: z.literal("local-only"),
  host_identity_hash: Hash,
  controller_uid: z.number().int().positive(),
  conformance_tuple_hash: Hash,
  backend_receipt_hash: Hash,
  phase_b_manifest_sha256: Hash,
  expires_at: IsoTimestamp,
  systemd_version: z.string().min(1),
  artifacts: z.object({
    supervisor_sha256: Hash,
    probe_sha256: Hash,
    bwrap_sha256: Hash,
    bwrap_version: z.string().min(1),
    systemd_run_sha256: Hash,
    systemctl_sha256: Hash,
    seccomp_policy_sha256: Hash,
    cwd_identity_hash: Hash,
  }).strict(),
  binding_hash: Hash,
}).strict();

export type S37LocalLinuxCapabilityV02 = Readonly<{
  observe(): Promise<unknown>;
  start(input: S37LinuxProbeRuntimeInputV02): Promise<S37LinuxProbeRuntimeOutcomeV02>;
}>;

type StableFileMetadataV02 = Readonly<{
  dev: number;
  ino: number;
  mode: number;
  nlink: number;
  uid: number;
  gid: number;
  size: number;
  mtimeMs: number;
  ctimeMs: number;
}>;

export type S37LocalLinuxProductProbeV02 = (
  input: S37LocalLinuxProductProbeInputV02,
) => Promise<S37PreSpawnProbeResultV02 | S37LinuxProbeExecutionResultV02>;

function enforcementUnavailable(detail: string): S37PreSpawnProbeResultV02 {
  return Object.freeze({
    ok: false as const,
    reason: "ENFORCEMENT_UNAVAILABLE" as const,
    terminal: "hold" as const,
    retryable: false as const,
    process_started: false as const,
    detail,
  });
}

function stableMetadata(path: string): StableFileMetadataV02 {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("S37_LOCAL_FILE_INVALID");
  return {
    dev: stat.dev,
    ino: stat.ino,
    mode: stat.mode,
    nlink: stat.nlink,
    uid: stat.uid,
    gid: stat.gid,
    size: stat.size,
    mtimeMs: stat.mtimeMs,
    ctimeMs: stat.ctimeMs,
  };
}

function assertTrustedDirectory(path: string): void {
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== 0 || (stat.mode & 0o022) !== 0) {
    throw new Error("S37_LOCAL_DIRECTORY_UNTRUSTED");
  }
}

function currentUid(): number {
  const uid = typeof process.getuid === "function" ? process.getuid() : Number.NaN;
  if (!Number.isSafeInteger(uid) || uid <= 0) throw new Error("S37_LOCAL_UID_UNAVAILABLE");
  return uid;
}

function assertUserManagerEndpoint(uid: number): void {
  const runtimeDirectory = `/run/user/${uid}`;
  const directory = lstatSync(runtimeDirectory);
  if (!directory.isDirectory() || directory.isSymbolicLink() || directory.uid !== uid
    || (directory.mode & 0o7777) !== 0o700) {
    throw new Error("S37_LOCAL_USER_RUNTIME_UNTRUSTED");
  }
  const bus = lstatSync(`${runtimeDirectory}/bus`);
  if (!bus.isSocket() || bus.isSymbolicLink() || bus.uid !== uid) {
    throw new Error("S37_LOCAL_USER_BUS_UNTRUSTED");
  }
}

function readStableBytes(path: string, mode: number, uid = 0): Uint8Array {
  const before = stableMetadata(path);
  if (before.uid !== uid || before.nlink !== 1 || (before.mode & 0o7777) !== mode) {
    throw new Error("S37_LOCAL_FILE_METADATA_DRIFT");
  }
  const bytes = new Uint8Array(readFileSync(path));
  const after = stableMetadata(path);
  if (JSON.stringify(before) !== JSON.stringify(after) || bytes.byteLength !== before.size) {
    throw new Error("S37_LOCAL_FILE_CAPTURE_DRIFT");
  }
  return bytes;
}

function readStablePseudoBytes(path: string, mode: number, uid = 0): Uint8Array {
  const before = stableMetadata(path);
  if (before.uid !== uid || before.nlink !== 1 || (before.mode & 0o7777) !== mode) {
    throw new Error("S37_LOCAL_PSEUDO_FILE_METADATA_DRIFT");
  }
  const bytes = new Uint8Array(readFileSync(path));
  const after = stableMetadata(path);
  if (JSON.stringify(before) !== JSON.stringify(after) || bytes.byteLength === 0 || bytes.byteLength > 65_536) {
    throw new Error("S37_LOCAL_PSEUDO_FILE_CAPTURE_DRIFT");
  }
  return bytes;
}

function normalizedArchitecture(value: string): string {
  if (value === "x64") return "x86_64";
  if (value === "arm64") return "aarch64";
  return value;
}

function readBindingFile(): z.infer<typeof S37LocalProductBindingFileSchemaV02> {
  const bytes = readStableBytes(LOCAL_BINDING_PATH, 0o444);
  const parsed = S37LocalProductBindingFileSchemaV02.parse(JSON.parse(Buffer.from(bytes).toString("utf8")));
  const { binding_hash: suppliedHash, ...withoutHash } = parsed;
  if (suppliedHash !== hashCanonical({ purpose: "s37-local-product-binding-v02", ...withoutHash })) {
    throw new Error("S37_LOCAL_BINDING_HASH_INVALID");
  }
  return parsed;
}

function readVerifiedArtifact(path: string, mode: number): Readonly<{
  path: string;
  sha256: string;
  mode: string;
  uid: 0;
  setuid: false;
}> {
  const bytes = readStableBytes(path, mode);
  return Object.freeze({
    path,
    sha256: hashRawBytes(bytes),
    mode: mode.toString(8).padStart(4, "0"),
    uid: 0 as const,
    setuid: false as const,
  });
}

function expectedObservationBindingHash(
  observation: S37LocalLinuxHostObservationV02,
): string {
  return hashCanonical({
    purpose: "s37-local-product-binding-v02",
    schema_version: "s37-local-product-binding-v02",
    host_role: observation.binding.host_role,
    transport: observation.binding.transport,
    host_identity_hash: observation.binding.host_identity_hash,
    controller_uid: observation.binding.controller_uid,
    conformance_tuple_hash: observation.binding.conformance_tuple_hash,
    backend_receipt_hash: observation.binding.backend_receipt_hash,
    phase_b_manifest_sha256: observation.binding.phase_b_manifest_sha256,
    expires_at: observation.binding.expires_at,
    systemd_version: observation.systemd_version,
    artifacts: {
      supervisor_sha256: observation.artifacts.supervisor.sha256,
      probe_sha256: observation.artifacts.probe.sha256,
      bwrap_sha256: observation.artifacts.bwrap.sha256,
      bwrap_version: observation.artifacts.bwrap.version,
      systemd_run_sha256: observation.artifacts.systemd_run.sha256,
      systemctl_sha256: observation.artifacts.systemctl.sha256,
      seccomp_policy_sha256: observation.artifacts.seccomp_policy_sha256,
      cwd_identity_hash: observation.artifacts.cwd_identity_hash,
    },
  });
}

export function buildS37SystemdRunInvocationV02(unit: string, uid: number): Readonly<{
  command: typeof SYSTEMD_RUN_PATH;
  args: readonly string[];
  options: Readonly<{
    cwd: "/";
    env: Readonly<{
      XDG_RUNTIME_DIR: string;
      DBUS_SESSION_BUS_ADDRESS: string;
    }>;
    shell: false;
    stdio: "ignore";
    windowsHide: true;
  }>;
}> {
  if (unit !== PRODUCT_UNIT) throw new Error("S37_LOCAL_UNIT_INVALID");
  if (!Number.isSafeInteger(uid) || uid <= 0) throw new Error("S37_LOCAL_UID_INVALID");
  const runtimeDirectory = `/run/user/${uid}`;
  return Object.freeze({
    command: SYSTEMD_RUN_PATH,
    args: Object.freeze([
      "--user", "--quiet", `--unit=${unit}`, "--service-type=exec", "--wait", "--collect",
      "--property=StandardInput=null", "--property=StandardOutput=null", "--property=StandardError=null",
      "--property=NoNewPrivileges=yes", "--property=KillMode=control-group", "--property=PrivateNetwork=yes",
      "--property=CapabilityBoundingSet=", "--property=CPUQuota=25%", "--property=MemoryMax=64000000",
      "--property=TasksMax=8", "--property=IOWeight=10", "--property=RuntimeMaxSec=2s",
      SUPERVISOR_PATH, BWRAP_PATH, PROBE_PATH,
    ]),
    options: Object.freeze({
      cwd: "/" as const,
      env: Object.freeze({
        XDG_RUNTIME_DIR: runtimeDirectory,
        DBUS_SESSION_BUS_ADDRESS: `unix:path=${runtimeDirectory}/bus`,
      }),
      shell: false as const,
      stdio: "ignore" as const,
      windowsHide: true as const,
    }),
  });
}

function localUserManagerEnvironment(uid: number): Readonly<{
  XDG_RUNTIME_DIR: string;
  DBUS_SESSION_BUS_ADDRESS: string;
}> {
  const runtimeDirectory = `/run/user/${uid}`;
  return Object.freeze({
    XDG_RUNTIME_DIR: runtimeDirectory,
    DBUS_SESSION_BUS_ADDRESS: `unix:path=${runtimeDirectory}/bus`,
  });
}

type SystemdManagerVersionObservationV02 =
  | Readonly<{ ok: true; version: string }>
  | Readonly<{ ok: false; detail: string }>;

async function observeSystemdManagerVersion(uid: number): Promise<SystemdManagerVersionObservationV02> {
  try {
    assertUserManagerEndpoint(uid);
  } catch {
    return Object.freeze({
      ok: false as const,
      detail: "S37 local systemd manager endpoint drifted before controller invocation.",
    });
  }
  return await new Promise((resolve) => {
    let child;
    try {
      child = spawn(
        SYSTEMCTL_PATH,
        ["--user", "show", "--property=Version", "--value"],
        {
          cwd: "/",
          env: localUserManagerEnvironment(uid),
          shell: false,
          stdio: ["ignore", "pipe", "ignore"],
          windowsHide: true,
        },
      );
    } catch {
      resolve(Object.freeze({
        ok: false as const,
        detail: "S37 local systemd manager could not be observed before controller invocation.",
      }));
      return;
    }

    const chunks: Buffer[] = [];
    let byteLength = 0;
    let settled = false;
    const finish = (result: SystemdManagerVersionObservationV02) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      clearTimeout(reapTimeout);
      resolve(Object.freeze(result));
    };
    child.stdout.on("data", (chunk: Buffer | Uint8Array | string) => {
      const bytes = Buffer.from(chunk);
      byteLength += bytes.byteLength;
      if (byteLength > 256) {
        child.kill("SIGKILL");
        finish({ ok: false, detail: "S37 local systemd manager could not be observed before controller invocation." });
        return;
      }
      chunks.push(bytes);
    });
    child.once("error", () => finish({
      ok: false,
      detail: "S37 local systemd manager could not be observed before controller invocation.",
    }));
    child.once("close", (code, signal) => {
      const version = Buffer.concat(chunks).toString("utf8").trim();
      if (code !== 0 || signal !== null || version.length === 0 || /[\r\n]/u.test(version)) {
        finish({ ok: false, detail: "S37 local systemd manager could not be observed before controller invocation." });
        return;
      }
      finish({ ok: true, version });
    });
    const timeout = setTimeout(() => {
      child.kill("SIGKILL");
    }, 2_000);
    const reapTimeout = setTimeout(
      () => finish({ ok: false, detail: "S37 local systemd manager could not be observed before controller invocation." }),
      3_000,
    );
  });
}

async function startExactTransientUnit(
  input: S37LinuxProbeRuntimeInputV02,
): Promise<S37LinuxProbeRuntimeOutcomeV02> {
  if (input.executable.path !== PROBE_PATH
    || input.receipt.bwrap.path !== BWRAP_PATH
    || input.timeout_ms !== 1_000
    || input.stdout_bytes !== 1_024
    || input.stderr_bytes !== 1_024) {
    return Object.freeze({
      ok: false as const,
      confirmed_not_started: true as const,
      detail: "S37 local Linux runtime input drifted before transient-unit invocation.",
    });
  }
  const unit = PRODUCT_UNIT;
  let invocation: ReturnType<typeof buildS37SystemdRunInvocationV02>;
  let uid: number;
  try {
    uid = currentUid();
    assertUserManagerEndpoint(uid);
    invocation = buildS37SystemdRunInvocationV02(unit, uid);
  } catch {
    return Object.freeze({
      ok: false as const,
      confirmed_not_started: true as const,
      detail: "S37 local user-manager endpoint drifted before transient-unit invocation.",
    });
  }

  const managerBefore = await observeSystemdManagerVersion(uid);
  if (!managerBefore.ok) {
    return Object.freeze({
      ok: false as const,
      confirmed_not_started: true as const,
      detail: managerBefore.detail,
    });
  }
  if (managerBefore.version !== input.tuple.systemd_version) {
    return Object.freeze({
      ok: false as const,
      confirmed_not_started: true as const,
      detail: "S37 local systemd manager version drifted before controller invocation.",
    });
  }

  return await new Promise((resolve) => {
    let child;
    try {
      child = spawn(invocation.command, [...invocation.args], invocation.options);
    } catch {
      resolve(Object.freeze({
        ok: false as const,
        confirmed_not_started: true as const,
        detail: "S37 local transient-unit controller could not be invoked.",
      }));
      return;
    }

    let settled = false;
    let timedOut = false;
    let killAttempted = false;
    const finish = (outcome: S37LinuxProbeRuntimeOutcomeV02) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      clearTimeout(reapTimeout);
      resolve(Object.freeze(outcome));
    };
    const reapTimeout = setTimeout(() => {
      finish({
        ok: true,
        process_started: true,
        exit_code: null,
        signal: null,
        timed_out: timedOut,
        kill_attempted: killAttempted,
        reaped: false,
        forbidden_effect_denied: false,
        outcome_ambiguous: true,
        stdout: new Uint8Array(),
        stderr: new Uint8Array(),
      });
    }, 5_000);
    const timeout = setTimeout(() => {
      timedOut = true;
      killAttempted = true;
      child.kill("SIGKILL");
    }, 4_000);

    child.once("error", () => {
      finish({
        ok: true,
        process_started: true,
        exit_code: null,
        signal: null,
        timed_out: timedOut,
        kill_attempted: killAttempted,
        reaped: false,
        forbidden_effect_denied: false,
        outcome_ambiguous: true,
        stdout: new Uint8Array(),
        stderr: new Uint8Array(),
      });
    });
    child.once("close", async (code, signal) => {
      const exactPass = !timedOut && code === 0 && signal === null;
      const managerAfter = exactPass
        ? await observeSystemdManagerVersion(uid)
        : Object.freeze({ ok: false as const, detail: "S37 local systemd manager could not be observed after controller invocation." });
      const managerStable = managerAfter.ok && managerAfter.version === managerBefore.version;
      finish({
        ok: true,
        process_started: true,
        exit_code: code,
        signal,
        timed_out: timedOut,
        kill_attempted: killAttempted,
        reaped: true,
        forbidden_effect_denied: false,
        outcome_ambiguous: !exactPass || !managerStable,
        stdout: new Uint8Array(),
        stderr: new Uint8Array(),
      });
    });
  });
}

const localLinuxCapability: S37LocalLinuxCapabilityV02 = Object.freeze({
  observe: async () => {
    if (platform() !== "linux") throw new Error("S37_LOCAL_PLATFORM_UNAVAILABLE");
    for (const path of TRUSTED_DIRECTORIES) assertTrustedDirectory(path);
    const binding = readBindingFile();
    const uid = currentUid();
    if (binding.controller_uid !== uid) throw new Error("S37_LOCAL_CONTROLLER_UID_DRIFT");
    assertUserManagerEndpoint(uid);
    const machineId = Buffer.from(readStableBytes(MACHINE_ID_PATH, 0o444)).toString("utf8").trim();
    if (machineId.length === 0) throw new Error("S37_LOCAL_MACHINE_ID_EMPTY");
    const controllers = Buffer.from(readStablePseudoBytes(CGROUP_V2_CONTROLLERS_PATH, 0o444))
      .toString("utf8").trim().split(/\s+/u);
    if (!["cpu", "io", "memory", "pids"].every((name) => controllers.includes(name))) {
      throw new Error("S37_LOCAL_CGROUP_CONTROLLERS_UNAVAILABLE");
    }
    const supervisor = readVerifiedArtifact(SUPERVISOR_PATH, 0o555);
    const probe = readVerifiedArtifact(PROBE_PATH, 0o555);
    const bwrap = readVerifiedArtifact(BWRAP_PATH, 0o555);
    const systemdRun = readVerifiedArtifact(SYSTEMD_RUN_PATH, 0o755);
    const systemctl = readVerifiedArtifact(SYSTEMCTL_PATH, 0o755);
    if (supervisor.sha256 !== binding.artifacts.supervisor_sha256
      || probe.sha256 !== binding.artifacts.probe_sha256
      || bwrap.sha256 !== binding.artifacts.bwrap_sha256
      || systemdRun.sha256 !== binding.artifacts.systemd_run_sha256
      || systemctl.sha256 !== binding.artifacts.systemctl_sha256) {
      throw new Error("S37_LOCAL_BINDING_ARTIFACT_DRIFT");
    }
    return Object.freeze({
      observed_at: new Date().toISOString(),
      platform: "linux" as const,
      architecture: normalizedArchitecture(arch()),
      kernel_release: release(),
      systemd_version: binding.systemd_version,
      cgroup_version: "v2" as const,
      host_identity_hash: hashRawBytes(Buffer.from(machineId, "utf8")),
      controller_uid: uid,
      binding: {
        binding_version: "0.1" as const,
        host_role: binding.host_role,
        transport: binding.transport,
        host_identity_hash: binding.host_identity_hash,
        controller_uid: binding.controller_uid,
        conformance_tuple_hash: binding.conformance_tuple_hash,
        backend_receipt_hash: binding.backend_receipt_hash,
        phase_b_manifest_sha256: binding.phase_b_manifest_sha256,
        expires_at: binding.expires_at,
        systemd_run_sha256: binding.artifacts.systemd_run_sha256,
        binding_hash: binding.binding_hash,
      },
      artifacts: {
        supervisor,
        probe,
        bwrap: { ...bwrap, version: binding.artifacts.bwrap_version },
        systemd_run: systemdRun,
        systemctl,
        seccomp_policy_sha256: binding.artifacts.seccomp_policy_sha256,
        cwd_identity_hash: binding.artifacts.cwd_identity_hash,
      },
    });
  },
  start: startExactTransientUnit,
});

function observationMismatch(
  input: S37LocalLinuxProductProbeInputV02,
  value: unknown,
): { ok: true; value: S37LocalLinuxHostObservationV02 } | { ok: false; detail: string } {
  const parsed = S37LocalLinuxHostObservationSchemaV02.safeParse(value);
  if (!parsed.success) return { ok: false, detail: "S37 local Linux host observation is invalid." };
  const observation = parsed.data;
  const tuple = input.conformance_tuple;
  const receipt = input.backend_receipt;
  const profile = input.profile;
  if (tuple?.platform !== "linux"
    || observation.architecture !== tuple.architecture
    || observation.kernel_release !== tuple.kernel_release
    || observation.systemd_version !== tuple.systemd_version
    || observation.cgroup_version !== tuple.cgroup_version) {
    return { ok: false, detail: "S37 local Linux host identity drifted from the conformance tuple." };
  }
  if (observation.binding.host_identity_hash !== observation.host_identity_hash
    || observation.binding.controller_uid !== observation.controller_uid
    || observation.binding.conformance_tuple_hash !== receipt?.host_tuple_hash
    || observation.binding.backend_receipt_hash !== receipt?.receipt_hash
    || observation.binding.phase_b_manifest_sha256 !== input.phase_b_manifest_sha256
    || observation.binding.expires_at !== receipt?.expires_at
    || observation.binding.binding_hash !== expectedObservationBindingHash(observation)
    || observation.binding.systemd_run_sha256 !== observation.artifacts.systemd_run.sha256) {
    return { ok: false, detail: "S37 local-product binding drifted from the host or backend receipt." };
  }
  if (observation.artifacts.supervisor.sha256 !== receipt?.launcher_sha256
    || observation.artifacts.probe.path !== profile?.executable?.path
    || observation.artifacts.probe.sha256 !== profile?.executable?.sha256
    || observation.artifacts.bwrap.path !== receipt?.bwrap?.path
    || observation.artifacts.bwrap.version !== receipt?.bwrap?.version
    || observation.artifacts.bwrap.sha256 !== receipt?.bwrap?.sha256
    || observation.artifacts.seccomp_policy_sha256 !== receipt?.seccomp_policy_sha256
    || observation.artifacts.cwd_identity_hash !== profile?.cwd?.identity_hash) {
    return { ok: false, detail: "S37 local Linux artifact identity drifted from the exact profile or receipt." };
  }
  const observedAt = Date.parse(observation.observed_at);
  const receiptExpiresAt = Date.parse(receipt?.expires_at ?? "");
  const decisionExpiresAt = Date.parse(
    typeof input.decision_input === "object" && input.decision_input !== null
      && "expires_at" in input.decision_input
      && typeof input.decision_input.expires_at === "string"
      ? input.decision_input.expires_at
      : "",
  );
  if (!Number.isFinite(observedAt) || !Number.isFinite(receiptExpiresAt) || !Number.isFinite(decisionExpiresAt)
    || observedAt + COMPLETE_CONTROLLER_WINDOW_MS > receiptExpiresAt
    || observedAt + COMPLETE_CONTROLLER_WINDOW_MS > decisionExpiresAt) {
    return { ok: false, detail: "S37 local Linux authority does not cover the complete bounded launch." };
  }
  return { ok: true, value: observation };
}

export async function runS37LinuxHostProbeV02(
  admission: S37LinuxProbeAdmissionV02,
  runtime: S37LinuxProbeRuntimeV02,
): Promise<S37LinuxProbeExecutionResultV02> {
  return runBoundedS37LinuxProbeV02(admission, runtime);
}

export function createS37LocalLinuxProductProbeV02(
  capability: S37LocalLinuxCapabilityV02,
): S37LocalLinuxProductProbeV02 {
  let inFlight = false;
  return async (input) => {
    if (inFlight) return enforcementUnavailable("S37 local product probe concurrency is already consumed.");
    inFlight = true;
    try {
      let firstObservation: unknown;
      try {
        firstObservation = await capability.observe();
      } catch {
        return enforcementUnavailable("S37 local Linux host observation failed.");
      }
      const first = observationMismatch(input, firstObservation);
      if (!first.ok) return enforcementUnavailable(first.detail);

      const prepared = prepareS37LinuxProbeAdmissionV02({
        request: {
          decision_input: input.decision_input,
          decision: input.decision,
          simulated_lease: input.simulated_lease,
          observed_at: first.value.observed_at,
          host: {
            platform: "linux",
            architecture: first.value.architecture,
            available_backends: ["s37-linux-v02"],
          },
          adapter: "s37_inert_probe",
        },
        profile: input.profile,
        host_tuple: input.conformance_tuple,
        backend_receipt: input.backend_receipt,
      });
      if (!prepared.ok) return prepared;

      const runtime: S37LinuxProbeRuntimeV02 = Object.freeze({
        start: async (runtimeInput) => {
          let launchObservation: unknown;
          try {
            launchObservation = await capability.observe();
          } catch {
            return Object.freeze({
              ok: false as const,
              confirmed_not_started: true as const,
              detail: "S37 local Linux launch-time observation failed.",
            });
          }
          const launch = observationMismatch(input, launchObservation);
          if (!launch.ok) {
            return Object.freeze({
              ok: false as const,
              confirmed_not_started: true as const,
              detail: launch.detail,
            });
          }
          return capability.start(runtimeInput);
        },
      });
      return await runS37LinuxHostProbeV02(prepared.value, runtime);
    } finally {
      inFlight = false;
    }
  };
}

const runProvisionedS37LocalLinuxProductProbeV02 = createS37LocalLinuxProductProbeV02(localLinuxCapability);

export async function runS37LocalLinuxProductProbeV02(
  input: S37LocalLinuxProductProbeInputV02,
): Promise<S37PreSpawnProbeResultV02 | S37LinuxProbeExecutionResultV02> {
  if (platform() !== "linux") {
    return enforcementUnavailable("S37 local product probe requires the current process host to be Linux.");
  }
  return runProvisionedS37LocalLinuxProductProbeV02(input);
}
