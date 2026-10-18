import { spawn } from "node:child_process";

import { hashCanonical, hashRawBytes } from "../hash.js";

const BROKER_DEADLINE_MS = 5_000;
const MANAGER_OBSERVATION_DEADLINE_MS = 1_000;
const HASH = /^sha256:[a-f0-9]{64}$/u;
const ACTIVATION_ID = /^activation_[a-f0-9]{64}$/u;
const UTC_SECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u;
const permitBindingKeys = Object.freeze([
  "activation_id", "fence_epoch", "event_five_hash", "manifest_hash", "launch_admission_hash",
  "broker_request_hash", "conformance_receipt_hash", "trial_evidence_hash",
  "post_commit_authorization_revalidation_hash", "post_commit_authorization_valid_until",
  "exact_argv_hash", "manager_version_before_observation_hash", "manager_version_before",
  "controller_uid", "primary_gid", "unit_name_hash", "cgroup_path_hash",
]);

declare const availablePermitBrand: unique symbol;
declare const claimedPermitBrand: unique symbol;

export type S37ProductHostLaunchPermitBindingV01 = Readonly<{
  activation_id: string;
  fence_epoch: number;
  event_five_hash: string;
  manifest_hash: string;
  launch_admission_hash: string;
  broker_request_hash: string;
  conformance_receipt_hash: string;
  trial_evidence_hash: string;
  post_commit_authorization_revalidation_hash: string;
  post_commit_authorization_valid_until: string;
  exact_argv_hash: string;
  manager_version_before_observation_hash: string;
  manager_version_before: string;
  controller_uid: number;
  primary_gid: number;
  unit_name_hash: string;
  cgroup_path_hash: string;
}>;

export type S37ProductHostLaunchPermitV01 = Readonly<{ readonly [availablePermitBrand]: true }>;
export type ClaimedS37ProductHostLaunchPermitV01 = Readonly<{ readonly [claimedPermitBrand]: true }>;
export type S37ProductHostLaunchBrokerOutcomeV01 = Readonly<
  | { ok: true; outcome: "ENTERED_AND_COMPLETED"; broker_entry_evidence: Readonly<Record<string, unknown>> }
  | { ok: false; outcome: "OUTCOME_UNKNOWN" }
>;

const availablePermits = new WeakMap<object, S37ProductHostLaunchPermitBindingV01>();
const claimedPermits = new WeakMap<object, S37ProductHostLaunchPermitBindingV01>();
const consumedPermits = new WeakSet<object>();

function exactPlainRecord(value: unknown, keys: readonly string[]): Record<string, unknown> | null {
  try {
    if (typeof value !== "object" || value === null || Object.getPrototypeOf(value) !== Object.prototype) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(descriptors).some((key) => typeof key !== "string")
      || Object.keys(descriptors).join("\0") !== keys.join("\0")) return null;
    for (const descriptor of Object.values(descriptors)) {
      if (!("value" in descriptor) || !descriptor.enumerable || descriptor.get !== undefined || descriptor.set !== undefined) return null;
    }
    return Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [key, descriptor.value]));
  } catch {
    return null;
  }
}

function capturePermitBinding(value: unknown): S37ProductHostLaunchPermitBindingV01 | null {
  const record = exactPlainRecord(value, permitBindingKeys);
  const validUntil = typeof record?.post_commit_authorization_valid_until === "string"
    ? Date.parse(record.post_commit_authorization_valid_until) : Number.NaN;
  if (record === null || typeof record.activation_id !== "string" || !ACTIVATION_ID.test(record.activation_id)
    || !Number.isSafeInteger(record.fence_epoch) || (record.fence_epoch as number) <= 0
    || !Number.isSafeInteger(record.controller_uid) || (record.controller_uid as number) <= 0
    || !Number.isSafeInteger(record.primary_gid) || (record.primary_gid as number) <= 0
    || typeof record.post_commit_authorization_valid_until !== "string"
    || !UTC_SECONDS.test(record.post_commit_authorization_valid_until)
    || !Number.isFinite(validUntil)
    || new Date(validUntil).toISOString() !== record.post_commit_authorization_valid_until.replace(/Z$/u, ".000Z")
    || typeof record.manager_version_before !== "string" || record.manager_version_before.length === 0
    || Buffer.byteLength(record.manager_version_before, "latin1") > MAX_MANAGER_OUTPUT_BYTES - 1
    || !/^[\x20-\x7e]+$/u.test(record.manager_version_before)) return null;
  for (const key of permitBindingKeys.filter((entry) => entry.endsWith("_hash"))) {
    if (typeof record[key] !== "string" || !HASH.test(record[key] as string)) return null;
  }
  return Object.freeze({ ...record }) as S37ProductHostLaunchPermitBindingV01;
}

export function mintS37ProductHostLaunchPermitV01(input: unknown): S37ProductHostLaunchPermitV01 | null {
  // TODO(S37.1-G3): require the contract module's validated admission,
  // request, and C3 brands once that private integration surface lands.
  const binding = capturePermitBinding(input);
  if (binding === null) return null;
  const permit = Object.freeze({}) as S37ProductHostLaunchPermitV01;
  availablePermits.set(permit, binding);
  return permit;
}

export function claimS37ProductHostLaunchPermitV01(input: unknown): ClaimedS37ProductHostLaunchPermitV01 | null {
  if (typeof input !== "object" || input === null) return null;
  const binding = availablePermits.get(input);
  if (binding === undefined) return null;
  availablePermits.delete(input);
  const claimed = Object.freeze({}) as ClaimedS37ProductHostLaunchPermitV01;
  claimedPermits.set(claimed, binding);
  return claimed;
}

export type S37ProductHostBrokerLifecycleV01 = Readonly<{
  phase: "WAITING_FOR_CLOSE" | "WAITING_FOR_MANAGER_AFTER" | "TERMINAL";
  started_at: number;
  deadline_at: number;
  close_at: number | null;
  after_observation_deadline_at: number | null;
  exit_code: number | null;
  signal: NodeJS.Signals | null;
  result: "PENDING" | "ENTERED_AND_COMPLETED" | "OUTCOME_UNKNOWN";
}>;

export type S37ProductHostBrokerLifecycleEventV01 = Readonly<
  | { type: "error"; at: number }
  | { type: "exit"; at: number; exit_code: number | null; signal: NodeJS.Signals | null }
  | { type: "close"; at: number; exit_code: number | null; signal: NodeJS.Signals | null }
  | { type: "deadline"; at: number }
  | { type: "manager-after-ok"; at: number }
  | { type: "manager-after-failed"; at: number }
>;

function terminal(
  state: S37ProductHostBrokerLifecycleV01,
  result: "ENTERED_AND_COMPLETED" | "OUTCOME_UNKNOWN",
): S37ProductHostBrokerLifecycleV01 {
  return Object.freeze({ ...state, phase: "TERMINAL", result });
}

export function createS37ProductHostBrokerLifecycleV01(startedAt: number): S37ProductHostBrokerLifecycleV01 {
  if (!Number.isSafeInteger(startedAt) || startedAt < 0) throw new TypeError("startedAt must be a nonnegative safe integer");
  return Object.freeze({
    phase: "WAITING_FOR_CLOSE",
    started_at: startedAt,
    deadline_at: startedAt + BROKER_DEADLINE_MS,
    close_at: null,
    after_observation_deadline_at: null,
    exit_code: null,
    signal: null,
    result: "PENDING",
  });
}

export function reduceS37ProductHostBrokerLifecycleV01(
  state: S37ProductHostBrokerLifecycleV01,
  event: S37ProductHostBrokerLifecycleEventV01,
): S37ProductHostBrokerLifecycleV01 {
  if (state.phase === "TERMINAL") return state;
  if (!Number.isSafeInteger(event.at) || event.at < state.started_at) return terminal(state, "OUTCOME_UNKNOWN");
  if (event.type === "deadline") {
    return event.at >= state.deadline_at ? terminal(state, "OUTCOME_UNKNOWN") : state;
  }
  if (event.type === "error" || event.type === "manager-after-failed") return terminal(state, "OUTCOME_UNKNOWN");
  if (event.type === "exit") {
    if (state.phase !== "WAITING_FOR_CLOSE" || event.exit_code !== 0 || event.signal !== null) {
      return terminal(state, "OUTCOME_UNKNOWN");
    }
    return state;
  }
  if (event.type === "close") {
    if (state.phase !== "WAITING_FOR_CLOSE" || event.at >= state.deadline_at
      || event.exit_code !== 0 || event.signal !== null) return terminal(state, "OUTCOME_UNKNOWN");
    return Object.freeze({
      ...state,
      phase: "WAITING_FOR_MANAGER_AFTER",
      close_at: event.at,
      after_observation_deadline_at: Math.min(event.at + MANAGER_OBSERVATION_DEADLINE_MS, state.deadline_at),
      exit_code: event.exit_code,
      signal: event.signal,
    });
  }
  if (state.phase !== "WAITING_FOR_MANAGER_AFTER" || event.type !== "manager-after-ok"
    || state.after_observation_deadline_at === null || event.at >= state.deadline_at
    || event.at >= state.after_observation_deadline_at) return terminal(state, "OUTCOME_UNKNOWN");
  return terminal(state, "ENTERED_AND_COMPLETED");
}

const SYSTEMD_RUN_PATH = "/usr/bin/systemd-run";
const SYSTEMCTL_PATH = "/usr/bin/systemctl";
const UNIT_NAME = "loopeix-s37-product-activation-v01";
const MANAGER_VERSION_ARGV = Object.freeze(["--system", "show", "--property=Version", "--value", "--no-pager"]);
const PROCESS_ENVIRONMENT = Object.freeze({ LANG: "C" });
const MAX_MANAGER_OUTPUT_BYTES = 4_096;

function monotonicNow(): number {
  return Math.floor(performance.now());
}

function exactBrokerArgv(binding: S37ProductHostLaunchPermitBindingV01): readonly string[] {
  return Object.freeze([
    "--system",
    "--quiet",
    `--unit=${UNIT_NAME}`,
    "--service-type=exec",
    "--wait",
    "--collect",
    `--property=User=${binding.controller_uid}`,
    `--property=Group=${binding.primary_gid}`,
    "--property=SupplementaryGroups=",
    "--property=WorkingDirectory=/",
    "--property=StandardInput=null",
    "--property=StandardOutput=null",
    "--property=StandardError=null",
    "--property=NoNewPrivileges=yes",
    "--property=CapabilityBoundingSet=",
    "--property=AmbientCapabilities=",
    "--property=KillMode=control-group",
    "--property=PrivateNetwork=yes",
    "--property=CPUQuota=25%",
    "--property=MemoryMax=64000000",
    "--property=TasksMax=8",
    "--property=IOWeight=10",
    "--property=RuntimeMaxSec=2s",
    "/opt/loopeix/s37.1/supervisor",
    "/opt/loopeix/s37.1/bwrap",
    "/opt/loopeix/s37.1/probe",
  ]);
}

type ManagerVersionObservation = Readonly<{
  parsed_version: string;
  observation_hash: string;
}>;

function runManagerVersionObservation(deadlineAt: number): Promise<ManagerVersionObservation | null> {
  const startedAt = monotonicNow();
  const observationDeadlineAt = Math.min(startedAt + MANAGER_OBSERVATION_DEADLINE_MS, deadlineAt);
  if (startedAt >= observationDeadlineAt) return Promise.resolve(null);
  return new Promise((resolveObservation) => {
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(SYSTEMCTL_PATH, MANAGER_VERSION_ARGV, {
        cwd: "/",
        env: PROCESS_ENVIRONMENT,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch {
      resolveObservation(null);
      return;
    }
    const childStdout = child.stdout;
    const childStderr = child.stderr;
    if (childStdout === null || childStderr === null) {
      const sink = (): void => undefined;
      child.on("error", sink);
      child.once("close", () => child.off("error", sink));
      child.unref();
      resolveObservation(null);
      return;
    }
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let truncated = false;
    let settled = false;
    const timer = setTimeout(() => settle(null), Math.max(0, observationDeadlineAt - monotonicNow()));
    timer.unref?.();

    function retainErrorSinkUntilClose(): void {
      const sink = (): void => undefined;
      child.on("error", sink);
      child.once("close", () => child.off("error", sink));
      (childStdout as unknown as { unref?: () => void }).unref?.();
      (childStderr as unknown as { unref?: () => void }).unref?.();
      child.unref();
    }
    function settle(value: ManagerVersionObservation | null): void {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.removeAllListeners("error");
      child.removeAllListeners("close");
      if (value === null) retainErrorSinkUntilClose();
      resolveObservation(value);
    }
    childStdout.on("data", (chunk: Buffer | Uint8Array) => {
      const bytes = Buffer.from(chunk);
      stdoutBytes += bytes.byteLength;
      if (stdoutBytes <= MAX_MANAGER_OUTPUT_BYTES) stdout.push(bytes);
      else truncated = true;
    });
    childStderr.on("data", (chunk: Buffer | Uint8Array) => {
      const bytes = Buffer.from(chunk);
      stderrBytes += bytes.byteLength;
      if (stderrBytes <= MAX_MANAGER_OUTPUT_BYTES) stderr.push(bytes);
      else truncated = true;
    });
    child.once("error", () => settle(null));
    child.once("close", (exitCode, signal) => {
      const completedAt = monotonicNow();
      const stdoutRaw = Buffer.concat(stdout);
      const stderrRaw = Buffer.concat(stderr);
      const validRaw = !truncated && stdoutBytes <= MAX_MANAGER_OUTPUT_BYTES && stderrBytes <= MAX_MANAGER_OUTPUT_BYTES
        && exitCode === 0 && signal === null && stderrRaw.byteLength === 0
        && completedAt < observationDeadlineAt && /^[\x20-\x7e]+\n$/u.test(stdoutRaw.toString("latin1"));
      if (!validRaw) {
        settle(null);
        return;
      }
      const parsedVersion = stdoutRaw.subarray(0, -1).toString("latin1");
      const preimage = {
        schema_version: "s37-product-host-manager-version-observation-v01",
        command: SYSTEMCTL_PATH,
        argv: MANAGER_VERSION_ARGV,
        cwd: "/",
        environment: PROCESS_ENVIRONMENT,
        stdout_hash: hashRawBytes(stdoutRaw),
        stderr_hash: hashRawBytes(stderrRaw),
        exit_code: exitCode,
        signal,
        timed_out: false,
        truncated: false,
        parsed_version: parsedVersion,
      };
      settle(Object.freeze({
        parsed_version: parsedVersion,
        observation_hash: hashCanonical({
          purpose: "s37-product-host-manager-version-observation-v01",
          observation: preimage,
        }),
      }));
    });
  });
}

function unknownOutcome(): S37ProductHostLaunchBrokerOutcomeV01 {
  return Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN" });
}

export async function enterS37ProductHostLaunchBrokerV01(
  permit: ClaimedS37ProductHostLaunchPermitV01 | null,
): Promise<S37ProductHostLaunchBrokerOutcomeV01> {
  if (permit === null || typeof permit !== "object") return unknownOutcome();
  const binding = claimedPermits.get(permit);
  if (binding === undefined || consumedPermits.has(permit)) return unknownOutcome();
  claimedPermits.delete(permit);
  consumedPermits.add(permit);

  try {
    const validUntil = Date.parse(binding.post_commit_authorization_valid_until);
    if (!Number.isFinite(validUntil) || Date.now() >= validUntil) return unknownOutcome();
    const argv = exactBrokerArgv(binding);
    const exactArgvHash = hashCanonical({ purpose: "s37-product-host-broker-argv-v01", argv });
    if (exactArgvHash !== binding.exact_argv_hash) return unknownOutcome();

    const startedAt = monotonicNow();
    let lifecycle = createS37ProductHostBrokerLifecycleV01(startedAt);
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(SYSTEMD_RUN_PATH, argv, {
        cwd: "/",
        env: PROCESS_ENVIRONMENT,
        shell: false,
        stdio: ["ignore", "ignore", "ignore"],
      });
    } catch {
      return unknownOutcome();
    }
    if (!Number.isSafeInteger(child.pid) || (child.pid ?? 0) <= 0) {
      const sink = (): void => undefined;
      child.on("error", sink);
      child.once("close", () => child.off("error", sink));
      child.unref();
      return unknownOutcome();
    }

    return await new Promise<S37ProductHostLaunchBrokerOutcomeV01>((resolveOutcome) => {
      let settled = false;
      const noopError = (): void => undefined;
      const remaining = Math.max(0, lifecycle.deadline_at - monotonicNow());
      const timer = setTimeout(() => {
        lifecycle = reduceS37ProductHostBrokerLifecycleV01(lifecycle, { type: "deadline", at: lifecycle.deadline_at });
        finish(unknownOutcome());
      }, remaining);
      timer.unref?.();

      function finish(outcome: S37ProductHostLaunchBrokerOutcomeV01): void {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        child.removeAllListeners("error");
        child.removeAllListeners("exit");
        child.removeAllListeners("close");
        if (!outcome.ok) {
          child.on("error", noopError);
          child.once("close", () => child.off("error", noopError));
          child.unref();
        }
        resolveOutcome(outcome);
      }

      child.once("error", () => {
        lifecycle = reduceS37ProductHostBrokerLifecycleV01(lifecycle, { type: "error", at: monotonicNow() });
        finish(unknownOutcome());
      });
      child.once("exit", (exitCode, signal) => {
        lifecycle = reduceS37ProductHostBrokerLifecycleV01(lifecycle, {
          type: "exit", at: monotonicNow(), exit_code: exitCode, signal,
        });
        if (lifecycle.phase === "TERMINAL") finish(unknownOutcome());
      });
      child.once("close", (exitCode, signal) => {
        lifecycle = reduceS37ProductHostBrokerLifecycleV01(lifecycle, {
          type: "close", at: monotonicNow(), exit_code: exitCode, signal,
        });
        if (lifecycle.phase !== "WAITING_FOR_MANAGER_AFTER") {
          finish(unknownOutcome());
          return;
        }
        void runManagerVersionObservation(lifecycle.deadline_at).then((observation) => {
          if (settled) return;
          const observedAt = monotonicNow();
          lifecycle = reduceS37ProductHostBrokerLifecycleV01(lifecycle, observation !== null
            && observation.parsed_version === binding.manager_version_before
            ? { type: "manager-after-ok", at: observedAt }
            : { type: "manager-after-failed", at: observedAt });
          if (lifecycle.result !== "ENTERED_AND_COMPLETED" || observation === null || lifecycle.close_at === null) {
            finish(unknownOutcome());
            return;
          }
          const preimage = {
            schema_version: "s37-product-host-broker-entry-evidence-v01",
            activation_id: binding.activation_id,
            launch_admission_hash: binding.launch_admission_hash,
            broker_request_hash: binding.broker_request_hash,
            conformance_receipt_hash: binding.conformance_receipt_hash,
            trial_evidence_hash: binding.trial_evidence_hash,
            post_commit_authorization_revalidation_hash: binding.post_commit_authorization_revalidation_hash,
            post_commit_authorization_valid_until: binding.post_commit_authorization_valid_until,
            exact_argv_hash: binding.exact_argv_hash,
            manager_version_before_observation_hash: binding.manager_version_before_observation_hash,
            manager_version_after_observation_hash: observation.observation_hash,
            systemd_run_client_pid: child.pid,
            manager_scope: "system",
            service_type: "exec",
            unit_name_hash: binding.unit_name_hash,
            cgroup_path_hash: binding.cgroup_path_hash,
            manager_version_before: binding.manager_version_before,
            manager_version_after: observation.parsed_version,
            exit_code: 0,
            signal: null,
            timed_out: false,
            result: "ENTERED_AND_COMPLETED",
            deadline_ms: BROKER_DEADLINE_MS,
            elapsed_ms: lifecycle.close_at - lifecycle.started_at,
          };
          const evidence = Object.freeze({
            ...preimage,
            broker_entry_evidence_hash: hashCanonical({
              purpose: "s37-product-host-broker-entry-evidence-v01",
              evidence: preimage,
            }),
          });
          const completedAt = monotonicNow();
          if (Date.now() >= validUntil || completedAt >= lifecycle.deadline_at
            || lifecycle.after_observation_deadline_at === null
            || completedAt >= lifecycle.after_observation_deadline_at) {
            finish(unknownOutcome());
            return;
          }
          finish(Object.freeze({ ok: true, outcome: "ENTERED_AND_COMPLETED", broker_entry_evidence: evidence }));
        }, () => finish(unknownOutcome()));
      });
    });
  } catch {
    return unknownOutcome();
  }
}
