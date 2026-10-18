import { createHash, createPrivateKey, createPublicKey, randomBytes, type KeyObject } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import {
  lstat,
  open,
  realpath,
  rename,
  unlink,
  type FileHandle,
} from "node:fs/promises";
import { basename, join } from "node:path";

import { canonicalize, hashCanonical, hashRawBytes } from "../hash.js";
import {
  captureAuthorityTrustContextV02,
  type CapturedAuthorityTrustContextForS36V02,
} from "./runtime-record-admission-v02.js";
import {
  S37ProductHostActivationEventV01,
  buildS37ProductHostActivationManifestV01,
  hashS37ProductHostActivationEventV01,
  hashS37ProductHostActivationLedgerV01,
  inspectS37ProductHostActivationV01,
  reduceS37ProductHostActivationPrefixV01,
  type S37ProductHostActivationEventV01Value,
  type S37ProductHostActivationManifestV01Value,
} from "./s37-product-host-activation-contract-v01.js";

const PRODUCT_HOST_ROOT = "/etc/loopeix/s37.1/product-host-v03";
const ACTIVATION_DIRECTORY = "activation";
const AUTHORITY_DIRECTORY = "authority";
const TRUST_CONTEXT_FILE = "trust-context.json";
const AUTHORITY_SIGNER_FILE = "authority-ed25519.pem";
const QUALIFICATION_SIGNER_FILE = "qualification-ed25519.pem";
const CONFORMANCE_RECEIPT_FILE = "system-manager-conformance-receipt.json";
const LEDGER_FILE = "activation-ledger.jsonl";
const MANIFEST_FILE = "activation-manifest.json";
const AUTHORIZATION_NONCE_FILE = "authorization-nonces.jsonl";
const QUALIFICATION_NONCE_FILE = "qualification-nonces.jsonl";
const LOCK_FILE = "activation.lock";
const MAX_LEDGER_BYTES = 16_777_216;
const MAX_NONCE_LOG_BYTES = 67_108_864;
const MAX_MANIFEST_BYTES = 65_536;
const MAX_LOCK_BYTES = 4_096;
const MAX_TRUST_CONTEXT_BYTES = 1_048_576;
const MAX_SIGNER_BYTES = 65_536;
const MAX_CONFORMANCE_RECEIPT_BYTES = 1_048_576;
const EMPTY = new Uint8Array();
const UTF8 = new TextDecoder("utf-8", { fatal: true });
const ENCODER = new TextEncoder();
const HASH = /^sha256:[0-9a-f]{64}$/u;
const MACHINE_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/u;
const UTC_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u;
const PRINTABLE_ASCII = /^[\x20-\x7e]+$/u;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
// Node's public typings omit Linux O_CLOEXEC. Production is Linux-only and is
// rejected below on every other platform; Node already creates non-inheritable
// descriptors on Darwin, where the Linux numeric flag would be invalid.
const O_CLOEXEC = process.platform === "linux" ? 0x80000 : 0;
const OPERATIONS = ["install-and-launch", "transition-and-launch", "launch-stable"] as const;
const EVENT_TYPES = [
  "activation.requested",
  "activation.nonces-reserved",
  "activation.anchor-stable",
  "activation.qualification-issued",
  "activation.launch-admitted",
  "activation.dispatch-entered",
  "activation.completed",
] as const;
const EVENT_PAYLOAD_KEYS: Readonly<Record<(typeof EVENT_TYPES)[number], readonly string[]>> = Object.freeze({
  "activation.requested": [
    "request_hash", "bundle_hash", "proof_request_hash", "qualification_intent_hash", "action_scope_hash",
    "initial_absence_observation_hash",
  ],
  "activation.nonces-reserved": ["proof_record_hash", "authorization_nonce_record_hash", "launch_nonce_record_hash"],
  "activation.anchor-stable": ["mutation_plan_hash", "proposed_anchor_hash", "anchor_observation_hash"],
  "activation.qualification-issued": [
    "qualification_intent_hash", "activation_decision_facts_hash", "decision_input_hash", "decision_simulation_hash",
    "lease_simulation_hash", "qualification_absence_observation_hash", "qualification_request_hash", "qualification_hash",
    "qualification_nonce_record_hash", "boot_observation_hash",
  ],
  "activation.launch-admitted": [
    "launch_admission_hash", "qualification_hash", "prelaunch_authorization_revalidation_hash", "final_observation_hash",
    "broker_request_hash",
  ],
  "activation.dispatch-entered": [
    "launch_admission_hash", "broker_request_hash", "conformance_receipt_hash", "systemd_run_hash", "runtime_profile_hash",
    "artifact_set_hash", "controller_uid", "primary_gid", "controller_identity_hash", "unit_name_hash", "cgroup_path_hash",
    "broker_entry_evidence_hash",
  ],
  "activation.completed": ["outcome", "broker_entry_evidence_hash", "completion_evidence_hash"],
});

const RECEIPT_KEYS = [
  "schema_version", "host_tuple_hash", "manager_scope", "systemd_version", "systemd_run_hash", "systemctl_hash",
  "broker_profile_hash", "exact_argv_hash", "controller_identity_hash", "unit_name_hash", "expected_cgroup_path_hash",
  "supervisor_hash", "bwrap_hash", "probe_hash", "seccomp_policy_hash", "deny_witness_set_hash", "deny_witnesses",
  "readiness_envelope_hash", "readiness_evidence_hash", "trial_evidence_hash", "readiness_envelope",
  "readiness_evidence", "trial_evidence", "samples", "trial_execution_observations",
  "unchanged_neighbor_snapshot_set_hash", "unchanged_neighbor_snapshot_set", "boot_id_hash", "issued_at", "expires_at",
  "receipt_hash",
] as const;
const ENVELOPE_KEYS = [
  "schema_version", "approved_at", "approved_by", "valid_from", "valid_to", "measurement_window_seconds",
  "sample_interval_seconds", "min_sample_count", "concurrency", "task_ceiling", "host_requirements",
  "package_requirements", "thresholds", "threshold_reasons", "resource_limits", "resource_limit_reasons", "observed_at",
  "capacity_samples", "capacity_samples_hash", "envelope_hash",
] as const;
const CAPACITY_KEYS = [
  "timestamp", "cpu_cores", "memory_available_bytes", "swap_used_bytes", "load1", "load5", "cpu_psi_some_avg10",
  "memory_psi_some_avg10", "io_psi_some_avg10", "tasks",
] as const;
const HOST_REQUIREMENT_KEYS = [
  "platform", "architecture", "distro_id", "distro_version_id", "kernel_release", "systemd_version", "cgroup_version",
  "required_cgroup_controllers", "unprivileged_userns_clone", "user_manager_status",
] as const;
const PACKAGE_REQUIREMENT_KEYS = [
  "candidate_version", "package_file_list_sha256", "selected_artifact_path", "selected_artifact_sha256",
] as const;
const THRESHOLD_KEYS = [
  "min_cpu_cores", "min_memory_available_bytes", "max_swap_used_bytes", "max_swap_growth_bytes", "max_load1", "max_load5",
  "max_cpu_psi_some_avg10", "max_memory_psi_some_avg10", "max_io_psi_some_avg10",
] as const;
const RESOURCE_LIMIT_KEYS = [
  "cpu_quota_percent", "memory_max_bytes", "tasks_max", "io_weight", "timeout_ms", "stdout_bytes", "stderr_bytes",
] as const;
const READINESS_EVIDENCE_KEYS = [
  "schema_version", "observed_at", "host_tuple", "host_tuple_hash", "package_evidence", "package_evidence_hash",
  "boot_id_hash", "envelope_hash", "capacity_samples", "capacity_samples_hash", "evidence_hash",
] as const;
const HOST_TUPLE_KEYS = [
  "platform", "architecture", "distro_id", "distro_version_id", "kernel_release", "systemd_version", "cgroup_version",
  "cgroup_controllers", "unprivileged_userns_clone", "user_manager_status", "observed_at", "host_tuple_hash",
] as const;
const PACKAGE_EVIDENCE_KEYS = [
  "candidate_version", "package_file_list_sha256", "selected_artifact_path", "selected_artifact_sha256",
  "package_evidence_hash",
] as const;
const SNAPSHOT_SET_KEYS = [
  "schema_version", "services_before", "services_after", "containers_before", "containers_after", "snapshot_set_hash",
] as const;
const SNAPSHOT_KEYS = [
  "neighbor_kind", "phase", "host_tuple_hash", "boot_id_hash", "manager_scope", "observer_command", "observer_cwd",
  "observer_env", "parser_version", "observed_at", "status", "count", "raw_snapshot_base64", "raw_snapshot_hash",
  "snapshot_hash",
] as const;
const NEIGHBOR_ROW_KEYS = ["name", "state", "identity_hash"] as const;
const TRIAL_KEYS = [
  "schema_version", "host_tuple_hash", "boot_id_hash", "manager_scope", "systemd_version", "controller_identity_hash",
  "unit_name_hash", "cgroup_path_hash", "exact_argv_hash", "sample_hashes", "trial_execution_observation_hashes",
  "unchanged_neighbor_snapshot_set_hash", "no_retry", "trial_evidence_hash",
] as const;
const SAMPLE_KEYS = [
  "schema_version", "ordinal", "host_tuple_hash", "boot_id_hash", "manager_scope", "systemd_version", "systemd_run_hash",
  "exact_argv_hash", "controller_uid", "primary_gid", "supplementary_gids", "unit_name_hash", "cgroup_path_hash",
  "started_at", "finished_at", "systemd_run_client_pid", "service_main_pid", "service_start_time_ticks",
  "execution_identity_hash", "exit_code", "signal", "timed_out", "trial_execution_observation_hash", "sample_hash",
] as const;
const OBSERVATION_KEYS = [
  "schema_version", "ordinal", "host_tuple_hash", "boot_id_hash", "manager_scope", "systemd_version", "systemd_run_hash",
  "systemctl_hash", "exact_argv_hash", "controller_uid", "primary_gid", "supplementary_gids", "unit_name_hash",
  "cgroup_path_hash", "systemd_run_client_pid", "service_main_pid", "service_start_time_ticks", "execution_identity_hash",
  "systemctl_during_command", "systemctl_during_argv", "systemctl_during_cwd", "systemctl_during_environment",
  "systemctl_during_exit_code", "systemctl_during_signal", "systemctl_during_timed_out", "during_observed_at",
  "systemctl_during_stdout_base64", "systemctl_during_stderr_base64", "during_load_state", "during_active_state",
  "during_sub_state", "during_job", "during_control_group", "during_main_pid", "proc_status_base64",
  "proc_stat_before_base64", "proc_cgroup_base64", "proc_stat_after_base64", "observed_service_pid",
  "observed_proc_start_time_ticks", "observed_uid", "observed_primary_gid", "observed_supplementary_gids",
  "observed_cgroup_path_hash", "systemd_run_exit_code", "systemd_run_signal", "systemd_run_timed_out",
  "systemctl_after_command", "systemctl_after_argv", "systemctl_after_cwd", "systemctl_after_environment",
  "systemctl_after_exit_code", "systemctl_after_signal", "systemctl_after_timed_out", "after_observed_at",
  "systemctl_after_stdout_base64", "systemctl_after_stderr_base64", "after_load_state", "after_active_state",
  "after_sub_state", "after_job", "after_control_group", "after_main_pid", "post_cgroup_observation", "observed_at",
  "observation_hash",
] as const;
const DENY_ROWS = [
  "ambient-credentials", "child-process", "durable-state", "environment", "filesystem-write", "network", "output-limits",
  "retry", "stdin", "timeout", "tool-server", "unknown-outcome",
] as const;

type ActivationOperation = (typeof OPERATIONS)[number];
type ActivationEventType = (typeof EVENT_TYPES)[number];
type UnknownRecord = Record<string, unknown>;
type StoreOutcome = "NOT_STARTED" | "NOT_COMMITTED" | "RECOVERY_REQUIRED" | "OUTCOME_UNKNOWN" | "COMPLETED";

type FileIdentity = Readonly<{
  device: bigint;
  inode: bigint;
  uid: bigint;
  gid: bigint;
  mode: bigint;
  nlink: bigint;
  size: bigint;
}>;

type DirectoryCapture = Readonly<{ path: string; handle: FileHandle; identity: FileIdentity }>;
type FileCapture = Readonly<{ path: string; bytes: Uint8Array; identity: FileIdentity }>;

type ActivationEvent = S37ProductHostActivationEventV01Value;
type ActivationManifest = S37ProductHostActivationManifestV01Value;

type AuthorizationNonceRecord = Readonly<{
  schema_version: "s37-product-host-authorization-nonce-record-v01";
  sequence: number;
  previous_record_hash: string | null;
  activation_id: string;
  fence_epoch: number;
  activation_request_hash: string;
  authenticated_principal_ref: string;
  approval_nonce: string;
  domain: "primary-v02";
  run_id: string;
  authorization_id: string;
  authorization_statement_hash: string;
  record_hash: string;
}>;

type QualificationNonceRecord = Readonly<{
  schema_version: "s37-product-host-qualification-nonce-record-v01";
  sequence: number;
  previous_record_hash: string | null;
  activation_id: string;
  fence_epoch: number;
  operation: ActivationOperation;
  reservation_kind: "launch-nonce" | "qualification-hash";
  reserved_hash: string;
  anchor_generation: number;
  anchor_hash: string | null;
  qualification_intent_hash: string;
  qualification_request_hash: string | null;
  record_hash: string;
}>;

type LockRecord = Readonly<{
  schema_version: "s37-product-host-activation-lock-v01";
  activation_id: string;
  activation_request_hash: string;
  predecessor_ledger_bytes_hash: string;
  predecessor_ledger_sequence: number;
  predecessor_ledger_head_hash: string | null;
  fence_epoch: number;
  boot_id_hash: string;
  owner_nonce: string;
  lock_hash: string;
}>;

type AuthorityCustodyState = {
  store: CapturedS37ProductHostActivationStoreV01;
  directory: DirectoryCapture;
  trust: FileCapture;
  authority_signer_identity: FileIdentity;
  qualification_signer_identity: FileIdentity;
  authority_signer_bytes_hash: string;
  qualification_signer_bytes_hash: string;
  receipt: FileCapture;
  base_trust: UnknownRecord;
  authority_key: KeyObject;
  qualification_key: KeyObject;
  authority_key_ref: string;
  authority_spki_hash: string;
  qualification_spki_hash: string;
  receipt_hash: string;
  disposed: boolean;
};

export type CapturedS37ProductHostActivationStoreV01 = Readonly<{
  readonly __captured_s37_product_host_activation_store_v01: unique symbol;
}>;

export type S37ProductHostActivationStoreSessionV01 = Readonly<{
  readonly __s37_product_host_activation_store_session_v01: unique symbol;
}>;

export type CapturedS37ProductHostAuthorityCustodyV01 = Readonly<{
  readonly __captured_s37_product_host_authority_custody_v01: unique symbol;
}>;

export type S37ProductHostActivationStoreIoV01 = Readonly<{
  lstat(path: string): Promise<BigIntStats>;
  realpath(path: string): Promise<string>;
  open(path: string, flags: number, mode?: number): Promise<FileHandle>;
  rename(source: string, destination: string): Promise<void>;
  unlink(path: string): Promise<void>;
  random_bytes(size: number): Uint8Array;
}>;

type StoreState = {
  root: DirectoryCapture;
  activation: DirectoryCapture;
  owner_uid: bigint;
  owner_gid: bigint;
  io: S37ProductHostActivationStoreIoV01;
  poisoned: boolean;
  authority?: CapturedS37ProductHostAuthorityCustodyV01;
};

type SessionState = {
  store: CapturedS37ProductHostActivationStoreV01;
  lock: FileCapture;
  lock_record: LockRecord;
  ledger_bytes: Uint8Array;
  manifest_bytes: Uint8Array | null;
  authorization_nonce_bytes: Uint8Array;
  qualification_nonce_bytes: Uint8Array;
  events: readonly ActivationEvent[];
  authorization_nonces: readonly AuthorizationNonceRecord[];
  qualification_nonces: readonly QualificationNonceRecord[];
  initial_ledger_hash: string;
  initial_manifest_hash: string | null;
  initial_authorization_hash: string;
  initial_qualification_hash: string;
  wrote_irreversible: boolean;
  poisoned: boolean;
  closed: boolean;
};

const stores = new WeakMap<object, StoreState>();
const sessions = new WeakMap<object, SessionState>();
const authorityCustodies = new WeakMap<object, AuthorityCustodyState>();
const handleCloseAttempts = new WeakMap<FileHandle, boolean>();
const descriptorCloseAmbiguities = new WeakSet<S37ProductHostActivationStoreIoV01>();

async function closeHandleOnce(handle: FileHandle, io: S37ProductHostActivationStoreIoV01): Promise<boolean> {
  const previous = handleCloseAttempts.get(handle);
  if (previous !== undefined) return previous;
  // Reserve the attempt before awaiting: a rejection never authorizes another
  // close, because the descriptor's state may already have changed.
  handleCloseAttempts.set(handle, false);
  try {
    await handle.close();
    handleCloseAttempts.set(handle, true);
    return true;
  } catch {
    descriptorCloseAmbiguities.add(io);
    return false;
  }
}

const defaultIo: S37ProductHostActivationStoreIoV01 = Object.freeze({
  lstat: (path) => lstat(path, { bigint: true }),
  realpath,
  open,
  rename,
  unlink,
  random_bytes: (size) => randomBytes(size),
});

function modeOf(stats: Pick<BigIntStats, "mode">): bigint {
  return stats.mode & 0o7777n;
}

function identityOf(stats: BigIntStats): FileIdentity {
  return Object.freeze({
    device: stats.dev,
    inode: stats.ino,
    uid: stats.uid,
    gid: stats.gid,
    mode: stats.mode,
    nlink: stats.nlink,
    size: stats.size,
  });
}

function sameIdentity(stats: BigIntStats, identity: FileIdentity): boolean {
  return stats.dev === identity.device && stats.ino === identity.inode && stats.uid === identity.uid
    && stats.gid === identity.gid && stats.mode === identity.mode && stats.nlink === identity.nlink
    && stats.size === identity.size;
}

function sameDirectoryIdentity(stats: BigIntStats, identity: FileIdentity): boolean {
  // Directory byte size and link count are filesystem bookkeeping and may
  // legitimately change when this store creates, renames, or removes entries.
  return stats.dev === identity.device && stats.ino === identity.inode && stats.uid === identity.uid
    && stats.gid === identity.gid && stats.mode === identity.mode;
}

function errorCode(error: unknown): string | null {
  return typeof error === "object" && error !== null && "code" in error && typeof error.code === "string"
    ? error.code : null;
}

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Reflect.ownKeys(value).every((key) => typeof key === "string");
}

function exactKeys(value: UnknownRecord, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && Object.keys(value).every((key, index) => key === keys[index]);
}

function exactKeySet(value: UnknownRecord, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function isSafePositive(value: unknown): value is number {
  return Number.isSafeInteger(value) && typeof value === "number" && value > 0;
}

function isSafeNonnegative(value: unknown): value is number {
  return Number.isSafeInteger(value) && typeof value === "number" && value >= 0;
}

function isHash(value: unknown): value is string {
  return typeof value === "string" && HASH.test(value);
}

function isPrintable(value: unknown): value is string {
  return typeof value === "string" && PRINTABLE_ASCII.test(value);
}

function isUtcSecond(value: unknown): value is string {
  if (typeof value !== "string" || !UTC_SECOND.test(value)) return false;
  const epoch = Date.parse(value);
  return Number.isFinite(epoch) && new Date(epoch).toISOString().replace(".000Z", "Z") === value;
}

function isFiniteNonnegative(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function rawHash(bytes: Uint8Array): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function canonicalBase64Bytes(value: unknown, maximum: number): Uint8Array | null {
  if (typeof value !== "string" || !BASE64.test(value)) return null;
  try {
    const bytes = Buffer.from(value, "base64");
    return bytes.byteLength <= maximum && bytes.toString("base64") === value ? new Uint8Array(bytes) : null;
  } catch {
    return null;
  }
}

function without(value: UnknownRecord, key: string): UnknownRecord {
  return Object.fromEntries(Object.entries(value).filter(([name]) => name !== key));
}

function selfHash(value: UnknownRecord, key: string, purpose: string, wrapper: string): boolean {
  return isHash(value[key]) && value[key] === hashCanonical({ purpose, [wrapper]: without(value, key) });
}

function parseExactJson(bytes: Uint8Array): UnknownRecord | null {
  try {
    const text = UTF8.decode(bytes);
    const value: unknown = JSON.parse(text);
    return isRecord(value) && JSON.stringify(value) === text ? value : null;
  } catch {
    return null;
  }
}

function sameCanonical(left: unknown, right: unknown): boolean {
  try { return canonicalize(left) === canonicalize(right); } catch { return false; }
}

function validateCapacitySamples(value: unknown): value is readonly UnknownRecord[] {
  if (!Array.isArray(value) || value.length !== 5) return false;
  let previous = Number.NEGATIVE_INFINITY;
  for (const row of value) {
    if (!isRecord(row) || !exactKeys(row, CAPACITY_KEYS) || !isUtcSecond(row.timestamp)
      || !isSafePositive(row.cpu_cores) || !isSafeNonnegative(row.memory_available_bytes)
      || !isSafeNonnegative(row.swap_used_bytes) || !isFiniteNonnegative(row.load1) || !isFiniteNonnegative(row.load5)
      || !isFiniteNonnegative(row.cpu_psi_some_avg10) || row.cpu_psi_some_avg10 > 100
      || !isFiniteNonnegative(row.memory_psi_some_avg10) || row.memory_psi_some_avg10 > 100
      || !isFiniteNonnegative(row.io_psi_some_avg10) || row.io_psi_some_avg10 > 100
      || !isSafeNonnegative(row.tasks)) return false;
    const epoch = Date.parse(row.timestamp);
    if (previous !== Number.NEGATIVE_INFINITY && epoch - previous !== 15_000) return false;
    previous = epoch;
  }
  return true;
}

function validateReadinessEnvelope(value: unknown): value is UnknownRecord {
  if (!isRecord(value) || !exactKeys(value, ENVELOPE_KEYS)
    || value.schema_version !== "s37-system-manager-readiness-envelope-v01"
    || !isUtcSecond(value.approved_at) || !isUtcSecond(value.valid_from) || !isUtcSecond(value.observed_at)
    || !isUtcSecond(value.valid_to) || !(Date.parse(value.approved_at) < Date.parse(value.valid_from)
      && Date.parse(value.valid_from) < Date.parse(value.observed_at) && Date.parse(value.observed_at) < Date.parse(value.valid_to))
    || value.measurement_window_seconds !== 60 || value.sample_interval_seconds !== 15 || value.min_sample_count !== 5
    || !isPrintable(value.approved_by) || !isSafePositive(value.concurrency) || !isSafePositive(value.task_ceiling)
    || !isRecord(value.host_requirements) || !exactKeys(value.host_requirements, HOST_REQUIREMENT_KEYS)
    || value.host_requirements.platform !== "linux" || value.host_requirements.architecture !== "x86_64"
    || value.host_requirements.distro_id !== "debian" || value.host_requirements.distro_version_id !== "13"
    || !isPrintable(value.host_requirements.kernel_release) || !isPrintable(value.host_requirements.systemd_version)
    || !isPrintable(value.host_requirements.cgroup_version)
    || !Array.isArray(value.host_requirements.required_cgroup_controllers)
    || value.host_requirements.required_cgroup_controllers.length === 0
    || !value.host_requirements.required_cgroup_controllers.every(isPrintable)
    || new Set(value.host_requirements.required_cgroup_controllers).size !== value.host_requirements.required_cgroup_controllers.length
    || typeof value.host_requirements.unprivileged_userns_clone !== "boolean"
    || !isPrintable(value.host_requirements.user_manager_status)
    || !isRecord(value.package_requirements) || !exactKeys(value.package_requirements, PACKAGE_REQUIREMENT_KEYS)
    || !isPrintable(value.package_requirements.candidate_version) || !isHash(value.package_requirements.package_file_list_sha256)
    || !isPrintable(value.package_requirements.selected_artifact_path) || !isHash(value.package_requirements.selected_artifact_sha256)
    || !isRecord(value.thresholds) || !exactKeys(value.thresholds, THRESHOLD_KEYS)
    || !isRecord(value.threshold_reasons) || !exactKeys(value.threshold_reasons, THRESHOLD_KEYS)
    || !THRESHOLD_KEYS.every((key) => isFiniteNonnegative((value.thresholds as UnknownRecord)[key])
      && isPrintable((value.threshold_reasons as UnknownRecord)[key]))
    || !isRecord(value.resource_limits) || !exactKeys(value.resource_limits, RESOURCE_LIMIT_KEYS)
    || !isRecord(value.resource_limit_reasons) || !exactKeys(value.resource_limit_reasons, RESOURCE_LIMIT_KEYS)
    || !RESOURCE_LIMIT_KEYS.every((key) => isSafePositive((value.resource_limits as UnknownRecord)[key])
      && isPrintable((value.resource_limit_reasons as UnknownRecord)[key]))
    || value.resource_limits.cpu_quota_percent !== 25 || value.resource_limits.memory_max_bytes !== 64_000_000
    || value.resource_limits.tasks_max !== 8 || value.resource_limits.io_weight !== 10
    || value.resource_limits.timeout_ms !== 1_000 || value.resource_limits.stdout_bytes !== 1_024
    || value.resource_limits.stderr_bytes !== 1_024 || !validateCapacitySamples(value.capacity_samples)
    || value.capacity_samples.at(-1)?.timestamp !== value.observed_at
    || value.capacity_samples_hash !== hashCanonical({
      purpose: "s37-system-manager-readiness-capacity-samples-v01", samples: value.capacity_samples,
    }) || !selfHash(value, "envelope_hash", "s37-system-manager-readiness-envelope-v01", "envelope")) return false;
  const threshold = value.thresholds;
  const samples = value.capacity_samples;
  return samples.every((row, index) => Date.parse(String(row.timestamp)) >= Date.parse(String(value.valid_from))
      && Date.parse(String(row.timestamp)) <= Date.parse(String(value.valid_to))
      && (index === 0 || (row.swap_used_bytes as number) >= (samples[index - 1]!.swap_used_bytes as number))
      && (row.cpu_cores as number) >= (threshold.min_cpu_cores as number)
      && (row.memory_available_bytes as number) >= (threshold.min_memory_available_bytes as number)
      && (row.swap_used_bytes as number) <= (threshold.max_swap_used_bytes as number)
      && (row.load1 as number) <= (threshold.max_load1 as number) && (row.load5 as number) <= (threshold.max_load5 as number)
      && (row.cpu_psi_some_avg10 as number) <= (threshold.max_cpu_psi_some_avg10 as number)
      && (row.memory_psi_some_avg10 as number) <= (threshold.max_memory_psi_some_avg10 as number)
      && (row.io_psi_some_avg10 as number) <= (threshold.max_io_psi_some_avg10 as number)
      && (row.tasks as number) <= (value.task_ceiling as number))
    && (samples.at(-1)!.swap_used_bytes as number) - (samples[0]!.swap_used_bytes as number)
      <= (threshold.max_swap_growth_bytes as number);
}

function validateReadinessEvidence(value: unknown, envelope: UnknownRecord): value is UnknownRecord {
  if (!isRecord(value) || !exactKeys(value, READINESS_EVIDENCE_KEYS)
    || value.schema_version !== "s37-system-manager-readiness-evidence-v01" || !isUtcSecond(value.observed_at)
    || value.observed_at !== envelope.observed_at || value.envelope_hash !== envelope.envelope_hash
    || !isHash(value.boot_id_hash) || !validateCapacitySamples(value.capacity_samples)
    || !sameCanonical(value.capacity_samples, envelope.capacity_samples)
    || value.capacity_samples_hash !== envelope.capacity_samples_hash
    || !isRecord(value.host_tuple) || !exactKeys(value.host_tuple, HOST_TUPLE_KEYS)
    || value.host_tuple.platform !== "linux" || value.host_tuple.architecture !== "x86_64"
    || value.host_tuple.distro_id !== "debian" || value.host_tuple.distro_version_id !== "13"
    || !isPrintable(value.host_tuple.kernel_release) || !isPrintable(value.host_tuple.systemd_version)
    || !isPrintable(value.host_tuple.cgroup_version) || !Array.isArray(value.host_tuple.cgroup_controllers)
    || value.host_tuple.cgroup_controllers.length === 0 || !value.host_tuple.cgroup_controllers.every(isPrintable)
    || new Set(value.host_tuple.cgroup_controllers).size !== value.host_tuple.cgroup_controllers.length
    || typeof value.host_tuple.unprivileged_userns_clone !== "boolean"
    || !isPrintable(value.host_tuple.user_manager_status) || value.host_tuple.observed_at !== value.observed_at
    || !selfHash(value.host_tuple, "host_tuple_hash", "s37-system-manager-host-tuple-v01", "host_tuple")
    || value.host_tuple_hash !== value.host_tuple.host_tuple_hash
    || !isRecord(value.package_evidence) || !exactKeys(value.package_evidence, PACKAGE_EVIDENCE_KEYS)
    || !isPrintable(value.package_evidence.candidate_version) || !isHash(value.package_evidence.package_file_list_sha256)
    || !isPrintable(value.package_evidence.selected_artifact_path) || !isHash(value.package_evidence.selected_artifact_sha256)
    || !selfHash(value.package_evidence, "package_evidence_hash", "s37-system-manager-package-evidence-v01", "package_evidence")
    || value.package_evidence_hash !== value.package_evidence.package_evidence_hash
    || !selfHash(value, "evidence_hash", "s37-system-manager-readiness-evidence-v01", "evidence")) return false;
  const host = envelope.host_requirements as UnknownRecord;
  const pkg = envelope.package_requirements as UnknownRecord;
  const tuple = value.host_tuple;
  const packageEvidence = value.package_evidence;
  return host.platform === tuple.platform && host.architecture === tuple.architecture && host.distro_id === tuple.distro_id
    && host.distro_version_id === tuple.distro_version_id && host.kernel_release === tuple.kernel_release
    && host.systemd_version === tuple.systemd_version && host.cgroup_version === tuple.cgroup_version
    && sameCanonical(host.required_cgroup_controllers, tuple.cgroup_controllers)
    && host.unprivileged_userns_clone === tuple.unprivileged_userns_clone
    && host.user_manager_status === tuple.user_manager_status
    && pkg.candidate_version === packageEvidence.candidate_version
    && pkg.package_file_list_sha256 === packageEvidence.package_file_list_sha256
    && pkg.selected_artifact_path === packageEvidence.selected_artifact_path
    && pkg.selected_artifact_sha256 === packageEvidence.selected_artifact_sha256;
}

function parseNeighborRows(bytes: Uint8Array, kind: "services" | "containers", hostHash: string, bootHash: string): readonly UnknownRecord[] | null {
  try {
    if (bytes.byteLength === 0) return Object.freeze([]);
    const text = UTF8.decode(bytes);
    if (!text.endsWith("\n") || text.endsWith("\n\n")) return null;
    const rows: UnknownRecord[] = [];
    let previous = "";
    for (const line of text.slice(0, -1).split("\n")) {
      const value: unknown = JSON.parse(line);
      if (!isRecord(value) || JSON.stringify(value) !== line || !exactKeys(value, NEIGHBOR_ROW_KEYS)
        || !isPrintable(value.name) || !isPrintable(value.state) || value.name <= previous || !isHash(value.identity_hash)
        || value.identity_hash !== hashCanonical({
          purpose: "s37-system-manager-neighbor-identity-v01", name: value.name, state: value.state,
          neighbor_kind: kind, manager_scope: "system", host_tuple_hash: hostHash, boot_id_hash: bootHash,
        })) return null;
      previous = value.name;
      rows.push(immutable(value));
    }
    return Object.freeze(rows);
  } catch {
    return null;
  }
}

function validateNeighborChild(
  value: unknown,
  kind: "services" | "containers",
  phase: "before" | "after",
  hostHash: string,
  bootHash: string,
): Readonly<{ record: UnknownRecord; rows: readonly UnknownRecord[]; bytes: Uint8Array }> | null {
  if (!isRecord(value) || !exactKeys(value, SNAPSHOT_KEYS) || value.neighbor_kind !== kind || value.phase !== phase
    || value.host_tuple_hash !== hostHash || value.boot_id_hash !== bootHash || value.manager_scope !== "system"
    || value.observer_cwd !== "/" || !isRecord(value.observer_env) || !exactKeys(value.observer_env, ["LANG"])
    || value.observer_env.LANG !== "C" || value.parser_version !== "s37-neighbor-parser-v01"
    || value.status !== "success" || !isUtcSecond(value.observed_at) || !isSafeNonnegative(value.count)
    || !Array.isArray(value.observer_command)) return null;
  const expected = kind === "services"
    ? ["/usr/bin/systemctl", "--system", "list-units", "--all", "--no-legend", "--no-pager"]
    : ["/usr/bin/machinectl", "list", "--no-legend", "--no-pager"];
  if (!sameCanonical(value.observer_command, expected)) return null;
  const bytes = canonicalBase64Bytes(value.raw_snapshot_base64, 65_536);
  if (bytes === null || value.raw_snapshot_hash !== rawHash(bytes)) return null;
  const rows = parseNeighborRows(bytes, kind, hostHash, bootHash);
  if (rows === null || rows.length !== value.count
    || !selfHash(value, "snapshot_hash", "s37-system-manager-unchanged-neighbor-snapshot-v01", "snapshot")) return null;
  return Object.freeze({ record: value, rows, bytes });
}

function validateNeighborSet(
  value: unknown,
  hostHash: string,
  bootHash: string,
  firstSampleAt: string,
  lastSampleAt: string,
): value is UnknownRecord {
  if (!isRecord(value) || !exactKeys(value, SNAPSHOT_SET_KEYS)
    || value.schema_version !== "s37-system-manager-unchanged-neighbor-snapshot-v01") return false;
  const servicesBefore = validateNeighborChild(value.services_before, "services", "before", hostHash, bootHash);
  const servicesAfter = validateNeighborChild(value.services_after, "services", "after", hostHash, bootHash);
  const containersBefore = validateNeighborChild(value.containers_before, "containers", "before", hostHash, bootHash);
  const containersAfter = validateNeighborChild(value.containers_after, "containers", "after", hostHash, bootHash);
  if (servicesBefore === null || servicesAfter === null || containersBefore === null || containersAfter === null
    || !Buffer.from(servicesBefore.bytes).equals(Buffer.from(servicesAfter.bytes))
    || !Buffer.from(containersBefore.bytes).equals(Buffer.from(containersAfter.bytes))
    || Date.parse(String(servicesBefore.record.observed_at)) >= Date.parse(firstSampleAt)
    || Date.parse(String(containersBefore.record.observed_at)) >= Date.parse(firstSampleAt)
    || Date.parse(String(servicesAfter.record.observed_at)) <= Date.parse(lastSampleAt)
    || Date.parse(String(containersAfter.record.observed_at)) <= Date.parse(lastSampleAt)) return false;
  const preimage = {
    services_before: value.services_before, services_after: value.services_after,
    containers_before: value.containers_before, containers_after: value.containers_after,
  };
  return value.snapshot_set_hash === hashCanonical({
    purpose: "s37-system-manager-unchanged-neighbor-snapshot-set-v01", snapshot_set: preimage,
  });
}

function validateTrialSample(value: unknown, ordinal: number): value is UnknownRecord {
  if (!isRecord(value) || !exactKeys(value, SAMPLE_KEYS) || value.schema_version !== "s37-system-manager-trial-sample-v01"
    || value.ordinal !== ordinal || !isHash(value.host_tuple_hash) || !isHash(value.boot_id_hash) || value.manager_scope !== "system"
    || !isPrintable(value.systemd_version) || !isHash(value.systemd_run_hash) || !isHash(value.exact_argv_hash)
    || !isSafePositive(value.controller_uid) || !isSafePositive(value.primary_gid)
    || !Array.isArray(value.supplementary_gids) || value.supplementary_gids.length !== 0
    || !isHash(value.unit_name_hash) || !isHash(value.cgroup_path_hash) || !isUtcSecond(value.started_at)
    || !isUtcSecond(value.finished_at) || Date.parse(value.started_at) >= Date.parse(value.finished_at)
    || !isSafePositive(value.systemd_run_client_pid) || !isSafePositive(value.service_main_pid)
    || value.systemd_run_client_pid === value.service_main_pid || !isSafePositive(value.service_start_time_ticks)
    || !isHash(value.execution_identity_hash) || value.execution_identity_hash !== hashCanonical({
      purpose: "s37-system-manager-trial-execution-identity-v01", host_tuple_hash: value.host_tuple_hash,
      boot_id_hash: value.boot_id_hash, systemd_run_client_pid: value.systemd_run_client_pid,
      service_main_pid: value.service_main_pid, service_start_time_ticks: value.service_start_time_ticks,
      started_at: value.started_at, finished_at: value.finished_at,
    }) || value.exit_code !== 0 || value.signal !== null || value.timed_out !== false
    || !isHash(value.trial_execution_observation_hash)
    || !selfHash(value, "sample_hash", "s37-system-manager-trial-sample-v01", "sample")) return false;
  return true;
}

function validatePostCgroup(value: unknown, cgroupHash: string): boolean {
  if (!isRecord(value) || value.schema_version !== "s37-system-manager-trial-post-cgroup-observation-v01"
    || value.cgroup_path_hash !== cgroupHash || !isSafeNonnegative(value.parent_device)
    || !isSafeNonnegative(value.parent_inode) || !isUtcSecond(value.observed_at)) return false;
  if (value.state === "absent") {
    return exactKeys(value, [
      "schema_version", "cgroup_path_hash", "state", "parent_device", "parent_inode", "lookup_before_errno",
      "lookup_after_errno", "observed_at", "observation_hash",
    ]) && value.lookup_before_errno === "ENOENT" && value.lookup_after_errno === "ENOENT"
      && selfHash(value, "observation_hash", "s37-system-manager-trial-post-cgroup-observation-v01", "observation");
  }
  if (value.state !== "empty" || !exactKeys(value, [
    "schema_version", "cgroup_path_hash", "state", "parent_device", "parent_inode", "directory_device", "directory_inode",
    "directory_uid", "directory_gid", "directory_mode", "directory_nlink", "cgroup_procs_before_base64",
    "cgroup_procs_after_base64", "cgroup_procs_hash", "descendant_cgroup_procs_observations", "observed_at", "observation_hash",
  ]) || !["directory_device", "directory_inode", "directory_uid", "directory_gid", "directory_mode", "directory_nlink"]
    .every((key) => isSafeNonnegative(value[key]))) return false;
  const before = canonicalBase64Bytes(value.cgroup_procs_before_base64, 65_536);
  const after = canonicalBase64Bytes(value.cgroup_procs_after_base64, 65_536);
  if (before === null || after === null || before.byteLength !== 0 || after.byteLength !== 0
    || value.cgroup_procs_hash !== rawHash(before) || !Array.isArray(value.descendant_cgroup_procs_observations)) return false;
  let previous = "";
  for (const row of value.descendant_cgroup_procs_observations) {
    if (!isRecord(row) || !exactKeys(row, [
      "relative_path", "directory_device", "directory_inode", "directory_uid", "directory_gid", "directory_mode",
      "directory_nlink", "cgroup_procs_before_base64", "cgroup_procs_after_base64", "cgroup_procs_hash",
    ]) || !isPrintable(row.relative_path) || row.relative_path <= previous || row.relative_path.includes("/")
      || row.relative_path === "." || row.relative_path === ".." || row.relative_path.includes("\0")
      || !["directory_device", "directory_inode", "directory_uid", "directory_gid", "directory_mode", "directory_nlink"]
        .every((key) => isSafeNonnegative(row[key]))) return false;
    const childBefore = canonicalBase64Bytes(row.cgroup_procs_before_base64, 65_536);
    const childAfter = canonicalBase64Bytes(row.cgroup_procs_after_base64, 65_536);
    if (childBefore === null || childAfter === null || childBefore.byteLength !== 0 || childAfter.byteLength !== 0
      || row.cgroup_procs_hash !== rawHash(childBefore)) return false;
    previous = row.relative_path;
  }
  return selfHash(value, "observation_hash", "s37-system-manager-trial-post-cgroup-observation-v01", "observation");
}

function decodeBoundedUtf8Base64(value: unknown, maximum: number): string | null {
  const bytes = canonicalBase64Bytes(value, maximum);
  if (bytes === null) return null;
  try { return UTF8.decode(bytes); } catch { return null; }
}

function validateSystemctlEvidence(value: UnknownRecord, phase: "during" | "after"): boolean {
  const stdout = decodeBoundedUtf8Base64(value[`systemctl_${phase}_stdout_base64`], 4_096);
  const stderr = canonicalBase64Bytes(value[`systemctl_${phase}_stderr_base64`], 4_096);
  if (stdout === null || stderr === null || stderr.byteLength !== 0 || !stdout.endsWith("\n") || stdout.endsWith("\n\n")) return false;
  const expected = phase === "during" ? [
    "LoadState=loaded", "ActiveState=active", "SubState=running", "Job=",
    `ControlGroup=${String(value.during_control_group)}`, `MainPID=${String(value.during_main_pid)}`,
  ] : ["LoadState=not-found", "ActiveState=inactive", "SubState=dead", "Job=", "ControlGroup=", "MainPID=0"];
  return sameCanonical(stdout.slice(0, -1).split("\n"), expected);
}

function parseProcStartTime(value: unknown, pid: number): number | null {
  const text = decodeBoundedUtf8Base64(value, 65_536);
  if (text === null || !text.endsWith("\n")) return null;
  const line = text.slice(0, -1);
  const prefix = `${pid} (`;
  const close = line.lastIndexOf(") ");
  if (!line.startsWith(prefix) || close <= prefix.length || line.indexOf("(") !== String(pid).length + 1) return null;
  const fields = line.slice(close + 2).split(" ");
  if (fields.length <= 19 || fields.some((field) => field.length === 0) || !/^\d+$/u.test(fields[19]!)) return null;
  const ticks = Number(fields[19]);
  return isSafePositive(ticks) ? ticks : null;
}

function validateProcEvidence(value: UnknownRecord, sample: UnknownRecord): boolean {
  const status = decodeBoundedUtf8Base64(value.proc_status_base64, 65_536);
  const cgroup = decodeBoundedUtf8Base64(value.proc_cgroup_base64, 65_536);
  const pid = Number(sample.service_main_pid);
  if (status === null || cgroup !== `0::${String(value.during_control_group)}\n`) return false;
  const rows = status.split("\n");
  const uidRows = rows.filter((row) => row.startsWith("Uid:"));
  const gidRows = rows.filter((row) => row.startsWith("Gid:"));
  const groupRows = rows.filter((row) => row.startsWith("Groups:"));
  const numericFields = (row: string): readonly string[] => row.slice(row.indexOf(":") + 1).trim().split(/[\t ]+/u).filter(Boolean);
  const uid = uidRows.length === 1 ? numericFields(uidRows[0]!) : [];
  const gid = gidRows.length === 1 ? numericFields(gidRows[0]!) : [];
  const groups = groupRows.length === 1 ? numericFields(groupRows[0]!) : ["invalid"];
  const startBefore = parseProcStartTime(value.proc_stat_before_base64, pid);
  const startAfter = parseProcStartTime(value.proc_stat_after_base64, pid);
  return uid.length === 4 && uid.every((field) => field === String(sample.controller_uid))
    && gid.length === 4 && gid.every((field) => field === String(sample.primary_gid))
    && groups.length === 0 && startBefore === sample.service_start_time_ticks && startAfter === startBefore;
}

function validateTrialObservation(value: unknown, sample: UnknownRecord, receipt: UnknownRecord): value is UnknownRecord {
  if (!isRecord(value) || !exactKeys(value, OBSERVATION_KEYS)
    || value.schema_version !== "s37-system-manager-trial-execution-observation-v01"
    || !["ordinal", "host_tuple_hash", "boot_id_hash", "manager_scope", "systemd_version", "systemd_run_hash",
      "exact_argv_hash", "controller_uid", "primary_gid", "supplementary_gids", "unit_name_hash", "cgroup_path_hash",
      "systemd_run_client_pid", "service_main_pid", "service_start_time_ticks", "execution_identity_hash"]
      .every((key) => sameCanonical(value[key], sample[key])) || value.systemctl_hash !== receipt.systemctl_hash
    || value.systemctl_during_command !== "/usr/bin/systemctl" || value.systemctl_after_command !== "/usr/bin/systemctl"
    || value.systemctl_during_cwd !== "/" || value.systemctl_after_cwd !== "/"
    || !isRecord(value.systemctl_during_environment) || !exactKeys(value.systemctl_during_environment, ["LANG"])
    || value.systemctl_during_environment.LANG !== "C" || !sameCanonical(value.systemctl_after_environment, value.systemctl_during_environment)
    || !sameCanonical(value.systemctl_after_argv, value.systemctl_during_argv)
    || value.systemctl_during_exit_code !== 0 || value.systemctl_after_exit_code !== 0
    || value.systemctl_during_signal !== null || value.systemctl_after_signal !== null
    || value.systemctl_during_timed_out !== false || value.systemctl_after_timed_out !== false
    || value.systemd_run_exit_code !== 0 || value.systemd_run_signal !== null || value.systemd_run_timed_out !== false
    || !isUtcSecond(value.during_observed_at) || !isUtcSecond(value.after_observed_at) || !isUtcSecond(value.observed_at)
    || Date.parse(value.during_observed_at) < Date.parse(String(sample.started_at))
    || Date.parse(value.after_observed_at) > Date.parse(String(sample.finished_at))
    || Date.parse(value.during_observed_at) >= Date.parse(value.after_observed_at)
    || Date.parse(value.observed_at) < Date.parse(value.after_observed_at)
    || Date.parse(value.observed_at) > Date.parse(String(sample.finished_at))
    || value.during_load_state !== "loaded" || value.during_active_state !== "active" || value.during_sub_state !== "running"
    || value.during_job !== "" || !isPrintable(value.during_control_group) || value.during_main_pid !== sample.service_main_pid
    || value.after_load_state !== "not-found" || value.after_active_state !== "inactive" || value.after_sub_state !== "dead"
    || value.after_job !== "" || value.after_control_group !== "" || value.after_main_pid !== 0
    || value.observed_service_pid !== sample.service_main_pid || value.observed_proc_start_time_ticks !== sample.service_start_time_ticks
    || value.observed_uid !== sample.controller_uid || value.observed_primary_gid !== sample.primary_gid
    || !Array.isArray(value.observed_supplementary_gids) || value.observed_supplementary_gids.length !== 0
    || value.observed_cgroup_path_hash !== sample.cgroup_path_hash
    || !Array.isArray(value.systemctl_during_argv) || value.systemctl_during_argv.length !== 10
    || !sameCanonical(value.systemctl_during_argv.slice(0, 3), ["--system", "show", "--all"])
    || !isPrintable(value.systemctl_during_argv[3])
    || !sameCanonical(value.systemctl_during_argv.slice(4), ["--property=LoadState", "--property=ActiveState",
      "--property=SubState", "--property=Job", "--property=ControlGroup", "--property=MainPID"])
    || !validateSystemctlEvidence(value, "during") || !validateSystemctlEvidence(value, "after")
    || !validateProcEvidence(value, sample)
    || !validatePostCgroup(value.post_cgroup_observation, String(sample.cgroup_path_hash))
    || Date.parse(String((value.post_cgroup_observation as UnknownRecord).observed_at)) < Date.parse(value.after_observed_at)
    || Date.parse(String((value.post_cgroup_observation as UnknownRecord).observed_at)) > Date.parse(String(sample.finished_at))) return false;
  let total = 0;
  for (const key of [
    "systemctl_during_stdout_base64", "systemctl_during_stderr_base64", "proc_status_base64", "proc_stat_before_base64",
    "proc_cgroup_base64", "proc_stat_after_base64", "systemctl_after_stdout_base64", "systemctl_after_stderr_base64",
  ]) {
    const bytes = canonicalBase64Bytes(value[key], 65_536);
    if (bytes === null) return false;
    total += bytes.byteLength;
  }
  return total <= 262_144 && selfHash(value, "observation_hash", "s37-system-manager-trial-execution-observation-v01", "observation")
    && value.observation_hash === sample.trial_execution_observation_hash;
}

function validateReceiptRecord(value: unknown, now = Date.now()): value is UnknownRecord {
  if (!isRecord(value) || !exactKeys(value, RECEIPT_KEYS)
    || value.schema_version !== "s37-system-manager-conformance-receipt-v01" || value.manager_scope !== "system"
    || !isPrintable(value.systemd_version) || !isUtcSecond(value.issued_at) || !isUtcSecond(value.expires_at)
    || Date.parse(value.issued_at) >= Date.parse(value.expires_at) || Date.parse(value.expires_at) - Date.parse(value.issued_at) > 600_000
    || Date.parse(value.issued_at) > now || now >= Date.parse(value.expires_at)
    || !["host_tuple_hash", "systemd_run_hash", "systemctl_hash", "broker_profile_hash", "exact_argv_hash",
      "controller_identity_hash", "unit_name_hash", "expected_cgroup_path_hash", "supervisor_hash", "bwrap_hash",
      "probe_hash", "seccomp_policy_hash", "deny_witness_set_hash", "readiness_envelope_hash", "readiness_evidence_hash",
      "trial_evidence_hash", "unchanged_neighbor_snapshot_set_hash", "boot_id_hash", "receipt_hash"]
      .every((key) => isHash(value[key]))
    || !Array.isArray(value.deny_witnesses) || value.deny_witnesses.length !== DENY_ROWS.length
    || !value.deny_witnesses.every((row, index) => isRecord(row) && exactKeys(row, ["row", "witness_sha256"])
      && row.row === DENY_ROWS[index] && isHash(row.witness_sha256))
    || !validateReadinessEnvelope(value.readiness_envelope)
    || !validateReadinessEvidence(value.readiness_evidence, value.readiness_envelope)
    || value.readiness_envelope_hash !== value.readiness_envelope.envelope_hash
    || value.readiness_evidence_hash !== value.readiness_evidence.evidence_hash
    || value.host_tuple_hash !== value.readiness_evidence.host_tuple_hash
    || value.boot_id_hash !== value.readiness_evidence.boot_id_hash
    || value.systemd_version !== (value.readiness_evidence.host_tuple as UnknownRecord).systemd_version
    || value.systemd_version !== (value.readiness_evidence.package_evidence as UnknownRecord).candidate_version
    || (value.readiness_evidence.package_evidence as UnknownRecord).selected_artifact_path !== "/usr/bin/systemd-run"
    || value.systemd_run_hash !== (value.readiness_evidence.package_evidence as UnknownRecord).selected_artifact_sha256
    || Date.parse(value.expires_at) > Date.parse(String(value.readiness_envelope.valid_to))
    || !Array.isArray(value.samples) || value.samples.length !== 5
    || !(value.samples as unknown[]).every((sample, index) => validateTrialSample(sample, index + 1))
    || !Array.isArray(value.trial_execution_observations) || value.trial_execution_observations.length !== 5
    || !value.trial_execution_observations.every((observation, index) => validateTrialObservation(
      observation, (value.samples as UnknownRecord[])[index] as UnknownRecord, value,
    )) || !isRecord(value.trial_evidence) || !exactKeys(value.trial_evidence, TRIAL_KEYS)
    || value.trial_evidence.schema_version !== "s37-system-manager-trial-evidence-v01"
    || value.trial_evidence.manager_scope !== "system" || value.trial_evidence.no_retry !== true
    || !selfHash(value.trial_evidence, "trial_evidence_hash", "s37-system-manager-trial-evidence-v01", "trial")
    || value.trial_evidence_hash !== value.trial_evidence.trial_evidence_hash
    || !Array.isArray(value.trial_evidence.sample_hashes) || !Array.isArray(value.trial_evidence.trial_execution_observation_hashes)
    || !sameCanonical(value.trial_evidence.sample_hashes, value.samples.map((sample) => (sample as UnknownRecord).sample_hash))
    || !sameCanonical(value.trial_evidence.trial_execution_observation_hashes,
      value.trial_execution_observations.map((observation) => (observation as UnknownRecord).observation_hash))
    || new Set((value.trial_evidence as UnknownRecord).sample_hashes as unknown[]).size !== 5
    || new Set(value.trial_evidence.trial_execution_observation_hashes).size !== 5
    || !["host_tuple_hash", "boot_id_hash", "manager_scope", "systemd_version", "controller_identity_hash", "unit_name_hash",
      "cgroup_path_hash", "exact_argv_hash", "unchanged_neighbor_snapshot_set_hash"]
      .every((key) => (value.trial_evidence as UnknownRecord)[key]
        === (key === "cgroup_path_hash" ? value.expected_cgroup_path_hash : value[key]))) return false;
  const samples = value.samples as UnknownRecord[];
  const envelopeSamples = value.readiness_envelope.capacity_samples as UnknownRecord[];
  for (let index = 1; index < samples.length; index += 1) {
    if (Date.parse(String(samples[index - 1]!.finished_at)) >= Date.parse(String(samples[index]!.started_at))) return false;
  }
  if (new Set(samples.map((sample) => sample.execution_identity_hash)).size !== 5
    || samples.some((sample) => sample.host_tuple_hash !== value.host_tuple_hash || sample.boot_id_hash !== value.boot_id_hash
      || sample.manager_scope !== value.manager_scope || sample.systemd_version !== value.systemd_version
      || sample.systemd_run_hash !== value.systemd_run_hash || sample.exact_argv_hash !== value.exact_argv_hash
      || sample.unit_name_hash !== value.unit_name_hash || sample.cgroup_path_hash !== value.expected_cgroup_path_hash)
    || Date.parse(String(samples[0]!.started_at)) < Date.parse(String(value.readiness_envelope.observed_at))
    || Date.parse(String(samples[0]!.started_at)) - Date.parse(String(value.readiness_envelope.observed_at)) > 15_000
    || Date.parse(String(samples[4]!.finished_at)) > Date.parse(String(value.issued_at))
    || !validateNeighborSet(
      value.unchanged_neighbor_snapshot_set, String(value.host_tuple_hash), String(value.boot_id_hash),
      String(envelopeSamples[0]!.timestamp), String(samples[4]!.finished_at),
    ) || value.unchanged_neighbor_snapshot_set_hash
      !== (value.unchanged_neighbor_snapshot_set as UnknownRecord).snapshot_set_hash
    || value.trial_evidence.unchanged_neighbor_snapshot_set_hash !== value.unchanged_neighbor_snapshot_set_hash
    || !selfHash(value, "receipt_hash", "s37-system-manager-conformance-receipt-v01", "receipt")) return false;
  return true;
}

function importEd25519PrivateKey(bytes: Uint8Array): Readonly<{
  key: KeyObject;
  public_spki_base64: string;
  public_spki_hash: string;
}> | null {
  const owned = Buffer.from(bytes);
  try {
    const key = createPrivateKey({ key: owned, format: "pem" });
    if (key.asymmetricKeyType !== "ed25519") return null;
    const publicDer = createPublicKey(key).export({ format: "der", type: "spki" });
    return Object.freeze({
      key,
      public_spki_base64: publicDer.toString("base64"),
      public_spki_hash: hashRawBytes(publicDer),
    });
  } catch {
    return null;
  } finally {
    owned.fill(0);
  }
}

function mergedAuthorityTrust(
  base: UnknownRecord,
  rows: readonly AuthorizationNonceRecord[],
): CapturedAuthorityTrustContextForS36V02 | null {
  if (!Array.isArray(base.durable_nonce_consumptions)) return null;
  const projected = rows.map((row) => ({
    authenticated_principal_ref: row.authenticated_principal_ref,
    approval_nonce: row.approval_nonce,
    domain: row.domain,
    run_id: row.run_id,
    authorization_id: row.authorization_id,
    authorization_statement_hash: row.authorization_statement_hash,
  }));
  const merged = [...structuredClone(base.durable_nonce_consumptions), ...projected];
  if (merged.some((row) => !isRecord(row))) return null;
  const identities = merged.map((row) => `${String((row as UnknownRecord).authenticated_principal_ref)}:${String((row as UnknownRecord).approval_nonce)}`);
  if (new Set(identities).size !== identities.length) return null;
  merged.sort((left, right) => Buffer.from(canonicalize(left)).compare(Buffer.from(canonicalize(right))));
  const captured = captureAuthorityTrustContextV02({ ...structuredClone(base), durable_nonce_consumptions: merged });
  return captured.ok ? captured.value : null;
}

function captureMatches(left: FileCapture, right: FileCapture): boolean {
  return sameFileIdentity(left.identity, right.identity)
    && Buffer.from(left.bytes).equals(Buffer.from(right.bytes));
}

function isMachineId(value: unknown): value is string {
  return typeof value === "string" && MACHINE_ID.test(value);
}

function isOperation(value: unknown): value is ActivationOperation {
  return typeof value === "string" && (OPERATIONS as readonly string[]).includes(value);
}

function immutable<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) immutable(child);
  return Object.freeze(value);
}

function ownedBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

function canonicalLine(value: unknown): Uint8Array {
  return ENCODER.encode(`${canonicalize(value)}\n`);
}

function hashActivationLedger(bytes: Uint8Array): string {
  return hashS37ProductHostActivationLedgerV01(bytes);
}

function recordHash(domain: string, record: UnknownRecord): string {
  return hashCanonical({ purpose: domain, record });
}

async function captureDirectory(
  path: string,
  mode: bigint,
  ownerUid: bigint,
  ownerGid: bigint,
  io: S37ProductHostActivationStoreIoV01,
): Promise<DirectoryCapture | null> {
  if (descriptorCloseAmbiguities.has(io)) return null;
  let handle: FileHandle | undefined;
  let retained = false;
  try {
    const before = await io.lstat(path);
    if (!before.isDirectory() || before.isSymbolicLink() || before.uid !== ownerUid || before.gid !== ownerGid
      || modeOf(before) !== mode || before.nlink < 1n || await io.realpath(path) !== path) return null;
    handle = await io.open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | O_CLOEXEC);
    const opened = await handle.stat({ bigint: true });
    if (!opened.isDirectory() || !sameIdentity(opened, identityOf(before))) return null;
    retained = true;
    return Object.freeze({ path, handle, identity: identityOf(opened) });
  } catch {
    return null;
  } finally {
    if (handle !== undefined && !retained) await closeHandleOnce(handle, io);
  }
}

async function directoryUnchanged(directory: DirectoryCapture, io: S37ProductHostActivationStoreIoV01): Promise<boolean> {
  if (descriptorCloseAmbiguities.has(io)) return false;
  try {
    const byPath = await io.lstat(directory.path);
    const byHandle = await directory.handle.stat({ bigint: true });
    return byPath.isDirectory() && !byPath.isSymbolicLink() && sameDirectoryIdentity(byPath, directory.identity)
      && sameDirectoryIdentity(byHandle, directory.identity) && await io.realpath(directory.path) === directory.path;
  } catch {
    return false;
  }
}

async function readHandleExact(handle: FileHandle, size: number): Promise<Uint8Array | null> {
  const bytes = new Uint8Array(size);
  const probe = new Uint8Array(1);
  let complete = false;
  try {
    let offset = 0;
    while (offset < bytes.byteLength) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.byteLength - offset, offset);
      if (bytesRead <= 0) return null;
      offset += bytesRead;
    }
    if ((await handle.read(probe, 0, 1, size)).bytesRead !== 0) return null;
    complete = true;
    return bytes;
  } finally {
    probe.fill(0);
    if (!complete) bytes.fill(0);
  }
}

async function readStrictFile(
  directory: DirectoryCapture,
  fileName: string,
  mode: bigint,
  maxBytes: number,
  ownerUid: bigint,
  ownerGid: bigint,
  io: S37ProductHostActivationStoreIoV01,
): Promise<FileCapture | null> {
  if (descriptorCloseAmbiguities.has(io)) return null;
  const path = join(directory.path, fileName);
  let handle: FileHandle | undefined;
  let bytes: Uint8Array | null = null;
  let capture: FileCapture | null = null;
  try {
    const before = await io.lstat(path);
    if (!before.isFile() || before.isSymbolicLink() || before.uid !== ownerUid || before.gid !== ownerGid
      || modeOf(before) !== mode || before.nlink !== 1n || before.size < 0n || before.size > BigInt(maxBytes)) return null;
    handle = await io.open(path, constants.O_RDONLY | constants.O_NOFOLLOW | O_CLOEXEC);
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || !sameIdentity(opened, identityOf(before))) return null;
    bytes = await readHandleExact(handle, Number(opened.size));
    if (bytes === null) return null;
    const afterHandle = await handle.stat({ bigint: true });
    const afterPath = await io.lstat(path);
    if (!sameIdentity(afterHandle, identityOf(opened)) || !sameIdentity(afterPath, identityOf(opened))
      || !await directoryUnchanged(directory, io)) return null;
    capture = Object.freeze({ path, bytes, identity: identityOf(opened) });
  } catch {
    return null;
  } finally {
    if (handle !== undefined && !await closeHandleOnce(handle, io)) capture = null;
    if (capture === null) bytes?.fill(0);
  }
  return capture;
}

async function readOptionalStrictFile(
  directory: DirectoryCapture,
  fileName: string,
  mode: bigint,
  maxBytes: number,
  ownerUid: bigint,
  ownerGid: bigint,
  io: S37ProductHostActivationStoreIoV01,
): Promise<FileCapture | null | "invalid"> {
  try {
    await io.lstat(join(directory.path, fileName));
  } catch (error) {
    return errorCode(error) === "ENOENT" ? null : "invalid";
  }
  return await readStrictFile(directory, fileName, mode, maxBytes, ownerUid, ownerGid, io) ?? "invalid";
}

function parseCanonicalJsonLine(line: string): UnknownRecord | null {
  try {
    const value: unknown = JSON.parse(line);
    return isRecord(value) && canonicalize(value) === line ? value : null;
  } catch {
    return null;
  }
}

function parseJsonl(bytes: Uint8Array): readonly UnknownRecord[] | null {
  try {
    if (bytes.byteLength === 0) return Object.freeze([]);
    const text = UTF8.decode(bytes);
    if (!text.endsWith("\n") || text.endsWith("\n\n")) return null;
    const rows = text.slice(0, -1).split("\n").map(parseCanonicalJsonLine);
    return rows.some((row) => row === null) ? null : Object.freeze(rows as UnknownRecord[]);
  } catch {
    return null;
  }
}

function parseAuthorizationNonces(bytes: Uint8Array): readonly AuthorizationNonceRecord[] | null {
  const rows = parseJsonl(bytes);
  if (rows === null) return null;
  const result: AuthorizationNonceRecord[] = [];
  const unique = new Set<string>();
  for (const [index, row] of rows.entries()) {
    const keys = [
      "schema_version", "sequence", "previous_record_hash", "activation_id", "fence_epoch", "activation_request_hash",
      "authenticated_principal_ref", "approval_nonce", "domain", "run_id", "authorization_id",
      "authorization_statement_hash", "record_hash",
    ];
    const { record_hash: _hash, ...body } = row;
    const identity = `${String(row.authenticated_principal_ref)}:${String(row.approval_nonce)}`;
    if (!exactKeySet(row, keys) || row.schema_version !== "s37-product-host-authorization-nonce-record-v01"
      || row.sequence !== index + 1 || row.previous_record_hash !== (result.at(-1)?.record_hash ?? null)
      || !isMachineId(row.activation_id) || !isSafePositive(row.fence_epoch) || !isHash(row.activation_request_hash)
      || !isMachineId(row.authenticated_principal_ref) || !isHash(row.approval_nonce) || row.domain !== "primary-v02"
      || !isMachineId(row.run_id) || !isMachineId(row.authorization_id) || !isHash(row.authorization_statement_hash)
      || !isHash(row.record_hash) || row.record_hash !== recordHash("s37-product-host-authorization-nonce-record-v01", body)
      || unique.has(identity)) return null;
    unique.add(identity);
    result.push(immutable(row as AuthorizationNonceRecord));
  }
  return Object.freeze(result);
}

function parseQualificationNonces(bytes: Uint8Array): readonly QualificationNonceRecord[] | null {
  const rows = parseJsonl(bytes);
  if (rows === null) return null;
  const result: QualificationNonceRecord[] = [];
  const unique = new Set<string>();
  for (const [index, row] of rows.entries()) {
    const keys = [
      "schema_version", "sequence", "previous_record_hash", "activation_id", "fence_epoch", "operation",
      "reservation_kind", "reserved_hash", "anchor_generation", "anchor_hash", "qualification_intent_hash",
      "qualification_request_hash", "record_hash",
    ];
    const { record_hash: _hash, ...body } = row;
    const kind = row.reservation_kind;
    const identity = `${String(kind)}:${String(row.reserved_hash)}`;
    if (!exactKeySet(row, keys) || row.schema_version !== "s37-product-host-qualification-nonce-record-v01"
      || row.sequence !== index + 1 || row.previous_record_hash !== (result.at(-1)?.record_hash ?? null)
      || !isMachineId(row.activation_id) || !isSafePositive(row.fence_epoch) || !isOperation(row.operation)
      || (kind !== "launch-nonce" && kind !== "qualification-hash") || !isHash(row.reserved_hash)
      || !isSafePositive(row.anchor_generation) || !isHash(row.qualification_intent_hash)
      || !isHash(row.record_hash) || row.record_hash !== recordHash("s37-product-host-qualification-nonce-record-v01", body)
      || unique.has(identity)) return null;
    if (kind === "launch-nonce") {
      if (row.anchor_hash !== null || row.qualification_request_hash !== null) return null;
    } else {
      const launch = result.at(-1);
      if (launch?.reservation_kind !== "launch-nonce" || launch.activation_id !== row.activation_id
        || launch.fence_epoch !== row.fence_epoch || launch.operation !== row.operation
        || launch.anchor_generation !== row.anchor_generation || launch.qualification_intent_hash !== row.qualification_intent_hash
        || !isHash(row.anchor_hash) || !isHash(row.qualification_request_hash)) return null;
    }
    unique.add(identity);
    result.push(immutable(row as QualificationNonceRecord));
  }
  return Object.freeze(result);
}

function parseEvent(row: UnknownRecord): ActivationEvent | null {
  const parsed = S37ProductHostActivationEventV01.safeParse(row);
  return parsed.success ? parsed.data : null;
}

function parseLedger(bytes: Uint8Array): readonly ActivationEvent[] | null {
  const rows = parseJsonl(bytes);
  if (rows === null) return null;
  const result: ActivationEvent[] = [];
  for (const row of rows) {
    const event = parseEvent(row);
    const previous = result.at(-1);
    if (event === null || event.sequence !== result.length + 1
      || event.previous_event_hash !== (previous?.event_hash ?? null)) return null;
    const stage = (event.sequence - 1) % 7;
    if (event.event_type !== EVENT_TYPES[stage]) return null;
    if (stage === 0) {
      const expectedFence = previous === undefined ? 1 : previous.fence_epoch + 1;
      const requestHash = event.event_type === "activation.requested" && isRecord(event.payload)
        && isHash(event.payload.request_hash) ? event.payload.request_hash : null;
      if (previous !== undefined && previous.event_type !== "activation.completed") return null;
      if (requestHash === null || event.fence_epoch !== expectedFence
        || event.activation_id !== `activation_${requestHash.slice(7)}`) return null;
    } else if (previous === undefined || event.activation_id !== previous.activation_id || event.operation !== previous.operation
      || event.anchor_generation !== previous.anchor_generation || event.anchor_hash !== previous.anchor_hash
      || event.boot_id_hash !== previous.boot_id_hash || event.controller_uid !== previous.controller_uid
      || event.fence_epoch !== previous.fence_epoch) return null;
    result.push(event);
  }
  if (!reduceS37ProductHostActivationPrefixV01(result).ok) return null;
  return Object.freeze(result);
}

function manifestFromLedger(bytes: Uint8Array, events: readonly ActivationEvent[]): Readonly<{ manifest: ActivationManifest; bytes: Uint8Array }> | null {
  if (events.length === 0) return null;
  const built = buildS37ProductHostActivationManifestV01({ ledger_bytes: bytes });
  return built.ok ? Object.freeze({ manifest: built.manifest, bytes: ownedBytes(built.bytes) }) : null;
}

function parseManifest(bytes: Uint8Array, ledgerBytes: Uint8Array, events: readonly ActivationEvent[]): ActivationManifest | null {
  if (events.length === 0) return null;
  const inspected = inspectS37ProductHostActivationV01({ ledger_bytes: ledgerBytes, manifest_bytes: bytes });
  return inspected.ok ? inspected.validated_activation.manifest : null;
}

function ledgerPrefixBytes(bytes: Uint8Array, sequence: number): Uint8Array | null {
  try {
    if (!isSafePositive(sequence)) return null;
    const text = UTF8.decode(bytes);
    if (!text.endsWith("\n")) return null;
    const lines = text.slice(0, -1).split("\n");
    if (sequence >= lines.length) return null;
    return ENCODER.encode(`${lines.slice(0, sequence).join("\n")}\n`);
  } catch {
    return null;
  }
}

function classifyManifest(
  capture: FileCapture | null,
  ledgerBytes: Uint8Array,
  events: readonly ActivationEvent[],
): "exact" | "behind" | null {
  if (events.length === 0) return capture === null ? "exact" : null;
  if (capture === null) return "behind";
  if (parseManifest(capture.bytes, ledgerBytes, events) !== null) return "exact";
  try {
    const raw: unknown = JSON.parse(UTF8.decode(capture.bytes));
    if (!isRecord(raw) || !isSafePositive(raw.ledger_sequence)) return null;
    const prefix = ledgerPrefixBytes(ledgerBytes, raw.ledger_sequence);
    return prefix !== null && inspectS37ProductHostActivationV01({ ledger_bytes: prefix, manifest_bytes: capture.bytes }).ok
      ? "behind" : null;
  } catch {
    return null;
  }
}

async function captureStoreAt(
  rootPath: string,
  ownerUid: bigint,
  ownerGid: bigint,
  io: S37ProductHostActivationStoreIoV01,
): Promise<Readonly<{ ok: true; store: CapturedS37ProductHostActivationStoreV01 }> | Readonly<{ ok: false; error: string }>> {
  const root = await captureDirectory(rootPath, 0o755n, ownerUid, ownerGid, io);
  if (root === null) return Object.freeze({ ok: false, error: descriptorCloseAmbiguities.has(io)
    ? "ACTIVATION_DESCRIPTOR_CLOSE_AMBIGUOUS" : "ACTIVATION_ROOT_INVALID" });
  const activation = await captureDirectory(join(rootPath, ACTIVATION_DIRECTORY), 0o700n, ownerUid, ownerGid, io);
  if (activation === null) {
    await closeHandleOnce(root.handle, io);
    return Object.freeze({ ok: false, error: descriptorCloseAmbiguities.has(io)
      ? "ACTIVATION_DESCRIPTOR_CLOSE_AMBIGUOUS" : "ACTIVATION_DIRECTORY_INVALID" });
  }
  const ledger = await readStrictFile(activation, LEDGER_FILE, 0o600n, MAX_LEDGER_BYTES, ownerUid, ownerGid, io);
  const authorization = await readStrictFile(activation, AUTHORIZATION_NONCE_FILE, 0o600n, MAX_NONCE_LOG_BYTES, ownerUid, ownerGid, io);
  const qualification = await readStrictFile(activation, QUALIFICATION_NONCE_FILE, 0o600n, MAX_NONCE_LOG_BYTES, ownerUid, ownerGid, io);
  const events = ledger === null ? null : parseLedger(ledger.bytes);
  const authorizationRows = authorization === null ? null : parseAuthorizationNonces(authorization.bytes);
  const qualificationRows = qualification === null ? null : parseQualificationNonces(qualification.bytes);
  const manifest = await readOptionalStrictFile(activation, MANIFEST_FILE, 0o600n, MAX_MANIFEST_BYTES, ownerUid, ownerGid, io);
  const manifestState = events !== null && manifest !== "invalid"
    ? classifyManifest(manifest, ledger!.bytes, events) : null;
  if (ledger === null || authorization === null || qualification === null || events === null
    || authorizationRows === null || qualificationRows === null || manifestState === null) {
    await closeHandleOnce(activation.handle, io);
    await closeHandleOnce(root.handle, io);
    return Object.freeze({ ok: false, error: descriptorCloseAmbiguities.has(io)
      ? "ACTIVATION_DESCRIPTOR_CLOSE_AMBIGUOUS" : "ACTIVATION_STORE_INVALID" });
  }
  const store = Object.freeze({}) as CapturedS37ProductHostActivationStoreV01;
  stores.set(store, { root, activation, owner_uid: ownerUid, owner_gid: ownerGid, io, poisoned: false });
  return Object.freeze({ ok: true, store });
}

export async function captureS37ProductHostActivationStoreV01(): Promise<
  Readonly<{ ok: true; store: CapturedS37ProductHostActivationStoreV01 }> | Readonly<{ ok: false; error: string }>
> {
  if (process.platform !== "linux") return Object.freeze({ ok: false, error: "ACTIVATION_PLATFORM_INELIGIBLE" });
  return captureStoreAt(PRODUCT_HOST_ROOT, 0n, 0n, defaultIo);
}

export async function createS37ProductHostActivationStoreForTestV01(input: Readonly<{
  root_path: string;
  owner_uid: bigint;
  owner_gid: bigint;
  io?: S37ProductHostActivationStoreIoV01;
}>): Promise<Readonly<{ ok: true; store: CapturedS37ProductHostActivationStoreV01 }> | Readonly<{ ok: false; error: string }>> {
  return captureStoreAt(input.root_path, input.owner_uid, input.owner_gid, input.io ?? defaultIo);
}

function parseOpenInput(input: unknown): Readonly<{
  activation_id: string;
  activation_request_hash: string;
  boot_id_hash: string;
}> | null {
  if (!isRecord(input) || !exactKeys(input, ["activation_id", "activation_request_hash", "boot_id_hash"])
    || !isMachineId(input.activation_id) || !isHash(input.activation_request_hash) || !isHash(input.boot_id_hash)
    || input.activation_id !== `activation_${input.activation_request_hash.slice(7)}`) return null;
  return immutable(input as { activation_id: string; activation_request_hash: string; boot_id_hash: string });
}

async function writeAll(handle: FileHandle, bytes: Uint8Array): Promise<boolean> {
  let offset = 0;
  while (offset < bytes.byteLength) {
    const result = await handle.write(bytes, offset, bytes.byteLength - offset, offset);
    if (result.bytesWritten <= 0) return false;
    offset += result.bytesWritten;
  }
  return true;
}

async function createLock(
  store: StoreState,
  record: LockRecord,
): Promise<FileCapture | null> {
  const path = join(store.activation.path, LOCK_FILE);
  const bytes = canonicalLine(record);
  if (bytes.byteLength > MAX_LOCK_BYTES) return null;
  let handle: FileHandle | undefined;
  try {
    handle = await store.io.open(
      path,
      constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW | O_CLOEXEC,
      0o600,
    );
    if (!await writeAll(handle, bytes)) return null;
    await handle.chown(Number(store.owner_uid), Number(store.owner_gid));
    await handle.chmod(0o400);
    await handle.sync();
    await store.activation.handle.sync();
    const opened = await handle.stat({ bigint: true });
    const byPath = await store.io.lstat(path);
    const readback = await readHandleExact(handle, bytes.byteLength);
    if (!opened.isFile() || opened.uid !== store.owner_uid || opened.gid !== store.owner_gid || modeOf(opened) !== 0o400n
      || opened.nlink !== 1n || !sameIdentity(byPath, identityOf(opened)) || readback === null
      || !Buffer.from(readback).equals(Buffer.from(bytes)) || !await directoryUnchanged(store.activation, store.io)) return null;
    return Object.freeze({ path, bytes, identity: identityOf(opened) });
  } catch {
    return null;
  } finally {
    if (handle !== undefined && !await closeHandleOnce(handle, store.io)) return null;
  }
}

async function currentStoreBytes(store: StoreState): Promise<Readonly<{
  ledger: FileCapture;
  manifest: FileCapture | null;
  authorization: FileCapture;
  qualification: FileCapture;
  events: readonly ActivationEvent[];
  authorization_rows: readonly AuthorizationNonceRecord[];
  qualification_rows: readonly QualificationNonceRecord[];
  manifest_state: "exact" | "behind";
}> | null> {
  if (!await directoryUnchanged(store.root, store.io)
    || !await directoryUnchanged(store.activation, store.io)) return null;
  const ledger = await readStrictFile(store.activation, LEDGER_FILE, 0o600n, MAX_LEDGER_BYTES, store.owner_uid, store.owner_gid, store.io);
  const authorization = await readStrictFile(store.activation, AUTHORIZATION_NONCE_FILE, 0o600n, MAX_NONCE_LOG_BYTES, store.owner_uid, store.owner_gid, store.io);
  const qualification = await readStrictFile(store.activation, QUALIFICATION_NONCE_FILE, 0o600n, MAX_NONCE_LOG_BYTES, store.owner_uid, store.owner_gid, store.io);
  if (ledger === null || authorization === null || qualification === null) return null;
  const events = parseLedger(ledger.bytes);
  const authorizationRows = parseAuthorizationNonces(authorization.bytes);
  const qualificationRows = parseQualificationNonces(qualification.bytes);
  if (events === null || authorizationRows === null || qualificationRows === null) return null;
  const manifestCapture = await readOptionalStrictFile(store.activation, MANIFEST_FILE, 0o600n, MAX_MANIFEST_BYTES, store.owner_uid, store.owner_gid, store.io);
  if (manifestCapture === "invalid") return null;
  const manifestState = classifyManifest(manifestCapture, ledger.bytes, events);
  if (manifestState === null) return null;
  return Object.freeze({
    ledger, manifest: manifestCapture, authorization, qualification, events,
    authorization_rows: authorizationRows, qualification_rows: qualificationRows,
    manifest_state: manifestState,
  });
}

export async function openS37ProductHostActivationStoreSessionV01(
  captured: CapturedS37ProductHostActivationStoreV01,
  input: unknown,
): Promise<Readonly<{ ok: true; session: S37ProductHostActivationStoreSessionV01 }> | Readonly<{ ok: false; outcome: StoreOutcome; error: string }>> {
  const store = stores.get(captured);
  const parsed = parseOpenInput(input);
  if (store === undefined || parsed === null || store.poisoned) {
    return Object.freeze({ ok: false, outcome: "NOT_STARTED", error: "ACTIVATION_SESSION_INPUT_INVALID" });
  }
  const current = await currentStoreBytes(store);
  if (current === null) return Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN", error: "ACTIVATION_STORE_DRIFT" });
  const head = current.events.at(-1);
  if (head !== undefined && head.event_type !== "activation.completed") {
    return Object.freeze({ ok: false, outcome: head.sequence % 7 >= 5 ? "OUTCOME_UNKNOWN" : "RECOVERY_REQUIRED", error: "ACTIVATION_PREFIX_NONTERMINAL" });
  }
  if (head !== undefined && current.manifest_state !== "exact") {
    return Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN", error: "ACTIVATION_MANIFEST_BEHIND" });
  }
  if (current.events.length > Number.MAX_SAFE_INTEGER - 7 || (head?.fence_epoch ?? 0) >= Number.MAX_SAFE_INTEGER) {
    return Object.freeze({ ok: false, outcome: "NOT_STARTED", error: "ACTIVATION_SEQUENCE_EXHAUSTED" });
  }
  const existingLock = await readOptionalStrictFile(store.activation, LOCK_FILE, 0o400n, MAX_LOCK_BYTES, store.owner_uid, store.owner_gid, store.io);
  if (existingLock !== null) {
    return Object.freeze({ ok: false, outcome: existingLock === "invalid" ? "OUTCOME_UNKNOWN" : "RECOVERY_REQUIRED", error: "ACTIVATION_LOCK_UNAVAILABLE" });
  }
  const lockBody = {
    schema_version: "s37-product-host-activation-lock-v01" as const,
    activation_id: parsed.activation_id,
    activation_request_hash: parsed.activation_request_hash,
    predecessor_ledger_bytes_hash: hashActivationLedger(current.ledger.bytes),
    predecessor_ledger_sequence: head?.sequence ?? 0,
    predecessor_ledger_head_hash: head?.event_hash ?? null,
    fence_epoch: (head?.fence_epoch ?? 0) + 1,
    boot_id_hash: parsed.boot_id_hash,
    owner_nonce: `sha256:${Buffer.from(store.io.random_bytes(32)).toString("hex")}`,
  };
  const lockRecord = immutable({
    ...lockBody,
    lock_hash: hashCanonical({ purpose: "s37-product-host-activation-lock-v01", lock: lockBody }),
  });
  const lock = await createLock(store, lockRecord);
  if (lock === null) return Object.freeze({ ok: false, outcome: descriptorCloseAmbiguities.has(store.io)
    ? "OUTCOME_UNKNOWN" : "RECOVERY_REQUIRED", error: "ACTIVATION_LOCK_CREATE_FAILED" });
  const session = Object.freeze({}) as S37ProductHostActivationStoreSessionV01;
  sessions.set(session, {
    store: captured,
    lock,
    lock_record: lockRecord,
    ledger_bytes: ownedBytes(current.ledger.bytes),
    manifest_bytes: current.manifest === null ? null : ownedBytes(current.manifest.bytes),
    authorization_nonce_bytes: ownedBytes(current.authorization.bytes),
    qualification_nonce_bytes: ownedBytes(current.qualification.bytes),
    events: current.events,
    authorization_nonces: current.authorization_rows,
    qualification_nonces: current.qualification_rows,
    initial_ledger_hash: hashRawBytes(current.ledger.bytes),
    initial_manifest_hash: current.manifest === null ? null : hashRawBytes(current.manifest.bytes),
    initial_authorization_hash: hashRawBytes(current.authorization.bytes),
    initial_qualification_hash: hashRawBytes(current.qualification.bytes),
    wrote_irreversible: false,
    poisoned: false,
    closed: false,
  });
  return Object.freeze({ ok: true, session });
}

export function inspectS37ProductHostActivationStoreSessionV01(session: S37ProductHostActivationStoreSessionV01): Readonly<{
  ok: true;
  activation_id: string;
  activation_request_hash: string;
  fence_epoch: number;
  next_sequence: number;
  previous_event_hash: string | null;
  lock_hash: string;
}> | Readonly<{ ok: false; error: string }> {
  const state = sessions.get(session);
  if (state === undefined || state.closed || state.poisoned) return Object.freeze({ ok: false, error: "ACTIVATION_SESSION_INVALID" });
  return Object.freeze({
    ok: true,
    activation_id: state.lock_record.activation_id,
    activation_request_hash: state.lock_record.activation_request_hash,
    fence_epoch: state.lock_record.fence_epoch,
    next_sequence: state.events.length + 1,
    previous_event_hash: state.events.at(-1)?.event_hash ?? null,
    lock_hash: state.lock_record.lock_hash,
  });
}

type CowResult = Readonly<{ ok: true; capture: FileCapture }> | Readonly<{ ok: false; classification: "NOT_COMMITTED" | "OUTCOME_UNKNOWN" }>;

async function replaceCow(
  store: StoreState,
  fileName: string,
  expectedBytes: Uint8Array | null,
  nextBytes: Uint8Array,
  maxBytes: number,
): Promise<CowResult> {
  if (nextBytes.byteLength > maxBytes) return Object.freeze({ ok: false, classification: "NOT_COMMITTED" });
  const current = await readOptionalStrictFile(store.activation, fileName, 0o600n, maxBytes, store.owner_uid, store.owner_gid, store.io);
  if (current === "invalid" || (expectedBytes === null ? current !== null
    : current === null || !Buffer.from(current.bytes).equals(Buffer.from(expectedBytes)))) {
    return Object.freeze({ ok: false, classification: descriptorCloseAmbiguities.has(store.io) ? "OUTCOME_UNKNOWN" : "NOT_COMMITTED" });
  }
  const suffix = Buffer.from(store.io.random_bytes(16)).toString("hex");
  const tempPath = join(store.activation.path, `.${basename(fileName)}.${suffix}.tmp`);
  let handle: FileHandle | undefined;
  let renamed = false;
  try {
    handle = await store.io.open(tempPath, constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW | O_CLOEXEC, 0o600);
    const created = await handle.stat({ bigint: true });
    if (!created.isFile() || created.nlink !== 1n || modeOf(created) !== 0o600n) throw new Error("temp-invalid");
    await handle.chown(Number(store.owner_uid), Number(store.owner_gid));
    await handle.chmod(0o600);
    if (!await writeAll(handle, nextBytes)) throw new Error("partial-write");
    await handle.sync();
    const descriptorReadback = await readHandleExact(handle, nextBytes.byteLength);
    if (descriptorReadback === null || !Buffer.from(descriptorReadback).equals(Buffer.from(nextBytes))) throw new Error("temp-readback");
    if (!await closeHandleOnce(handle, store.io)) throw new Error("temp-close-ambiguous");
    handle = undefined;
    renamed = true;
    await store.io.rename(tempPath, join(store.activation.path, fileName));
    await store.activation.handle.sync();
    const final = await readStrictFile(store.activation, fileName, 0o600n, maxBytes, store.owner_uid, store.owner_gid, store.io);
    if (final === null || !Buffer.from(final.bytes).equals(Buffer.from(nextBytes))) throw new Error("final-readback");
    return Object.freeze({ ok: true, capture: final });
  } catch {
    if (!renamed) {
      if (handle !== undefined) await closeHandleOnce(handle, store.io);
      if (descriptorCloseAmbiguities.has(store.io)) {
        store.poisoned = true;
        return Object.freeze({ ok: false, classification: "OUTCOME_UNKNOWN" });
      }
      try { await store.io.unlink(tempPath); } catch (error) { if (errorCode(error) !== "ENOENT") return Object.freeze({ ok: false, classification: "OUTCOME_UNKNOWN" }); }
      return Object.freeze({ ok: false, classification: "NOT_COMMITTED" });
    }
    store.poisoned = true;
    return Object.freeze({ ok: false, classification: "OUTCOME_UNKNOWN" });
  } finally {
    if (handle !== undefined) await closeHandleOnce(handle, store.io);
  }
}

function activeSession(session: S37ProductHostActivationStoreSessionV01): Readonly<{ session: SessionState; store: StoreState }> | null {
  const state = sessions.get(session);
  if (state === undefined || state.closed || state.poisoned) return null;
  const store = stores.get(state.store);
  return store === undefined || store.poisoned ? null : { session: state, store };
}

function poison(state: SessionState, store: StoreState): void {
  state.poisoned = true;
  store.poisoned = true;
}

type AuthorityCustodyResult = Readonly<{
  ok: true;
  custody: CapturedS37ProductHostAuthorityCustodyV01;
  trust_context: CapturedAuthorityTrustContextForS36V02;
  conformance_receipt_hash: string;
}> | Readonly<{ ok: false; error: "AUTHORITY_CUSTODY_INVALID" }>;

async function readAuthorityFiles(store: StoreState, directory: DirectoryCapture): Promise<Readonly<{
  trust: FileCapture;
  authority_signer: FileCapture;
  qualification_signer: FileCapture;
  receipt: FileCapture;
}> | null> {
  const trust = await readStrictFile(directory, TRUST_CONTEXT_FILE, 0o400n, MAX_TRUST_CONTEXT_BYTES,
    store.owner_uid, store.owner_gid, store.io);
  const authoritySigner = await readStrictFile(directory, AUTHORITY_SIGNER_FILE, 0o400n, MAX_SIGNER_BYTES,
    store.owner_uid, store.owner_gid, store.io);
  const qualificationSigner = await readStrictFile(directory, QUALIFICATION_SIGNER_FILE, 0o400n, MAX_SIGNER_BYTES,
    store.owner_uid, store.owner_gid, store.io);
  const receipt = await readStrictFile(directory, CONFORMANCE_RECEIPT_FILE, 0o400n, MAX_CONFORMANCE_RECEIPT_BYTES,
    store.owner_uid, store.owner_gid, store.io);
  if (trust === null || authoritySigner === null || qualificationSigner === null || receipt === null) {
    authoritySigner?.bytes.fill(0);
    qualificationSigner?.bytes.fill(0);
    return null;
  }
  return Object.freeze({ trust, authority_signer: authoritySigner, qualification_signer: qualificationSigner, receipt });
}

export async function captureS37ProductHostAuthorityCustodyV01(
  session: S37ProductHostActivationStoreSessionV01,
): Promise<AuthorityCustodyResult> {
  const active = activeSession(session);
  if (active === null || active.store.authority !== undefined) {
    return Object.freeze({ ok: false, error: "AUTHORITY_CUSTODY_INVALID" });
  }
  const { session: state, store } = active;
  const directory = await captureDirectory(join(store.root.path, AUTHORITY_DIRECTORY), 0o700n,
    store.owner_uid, store.owner_gid, store.io);
  if (directory === null) return Object.freeze({ ok: false, error: "AUTHORITY_CUSTODY_INVALID" });
  let files: Awaited<ReturnType<typeof readAuthorityFiles>> = null;
  try {
    files = await readAuthorityFiles(store, directory);
    if (files === null) throw new Error("authority-files-invalid");
    const baseTrust = parseExactJson(files.trust.bytes);
    const receipt = parseExactJson(files.receipt.bytes);
    const authoritySignerBytesHash = hashRawBytes(files.authority_signer.bytes);
    const qualificationSignerBytesHash = hashRawBytes(files.qualification_signer.bytes);
    const authorityKey = importEd25519PrivateKey(files.authority_signer.bytes);
    const qualificationKey = importEd25519PrivateKey(files.qualification_signer.bytes);
    files.authority_signer.bytes.fill(0);
    files.qualification_signer.bytes.fill(0);
    if (baseTrust === null || receipt === null || authorityKey === null || qualificationKey === null
      || !validateReceiptRecord(receipt) || receipt.boot_id_hash !== state.lock_record.boot_id_hash
      || !Array.isArray(baseTrust.operator_keys)) {
      throw new Error("authority-content-invalid");
    }
    const baseCapture = captureAuthorityTrustContextV02(baseTrust);
    const mergedTrust = mergedAuthorityTrust(baseTrust, state.authorization_nonces);
    const matchingKeys = baseTrust.operator_keys.filter((row) => isRecord(row)
      && row.public_key_spki_base64 === authorityKey.public_spki_base64 && isMachineId(row.operator_key_id));
    if (!baseCapture.ok || mergedTrust === null || matchingKeys.length !== 1) throw new Error("authority-trust-invalid");
    const custody = Object.freeze({}) as CapturedS37ProductHostAuthorityCustodyV01;
    authorityCustodies.set(custody, {
      store: state.store,
      directory,
      trust: files.trust,
      authority_signer_identity: files.authority_signer.identity,
      qualification_signer_identity: files.qualification_signer.identity,
      authority_signer_bytes_hash: authoritySignerBytesHash,
      qualification_signer_bytes_hash: qualificationSignerBytesHash,
      receipt: files.receipt,
      base_trust: immutable(structuredClone(baseTrust)),
      authority_key: authorityKey.key,
      qualification_key: qualificationKey.key,
      authority_key_ref: String((matchingKeys[0] as UnknownRecord).operator_key_id),
      authority_spki_hash: authorityKey.public_spki_hash,
      qualification_spki_hash: qualificationKey.public_spki_hash,
      receipt_hash: String(receipt.receipt_hash),
      disposed: false,
    });
    store.authority = custody;
    return Object.freeze({
      ok: true,
      custody,
      trust_context: mergedTrust,
      conformance_receipt_hash: String(receipt.receipt_hash),
    });
  } catch {
    if (files !== null) {
      files.authority_signer.bytes.fill(0);
      files.qualification_signer.bytes.fill(0);
    }
    await closeHandleOnce(directory.handle, store.io);
    return Object.freeze({ ok: false, error: "AUTHORITY_CUSTODY_INVALID" });
  }
}

export async function recaptureS37ProductHostAuthorityTrustV01(
  session: S37ProductHostActivationStoreSessionV01,
): Promise<AuthorityCustodyResult> {
  const active = activeSession(session);
  if (active === null || active.store.authority === undefined) {
    return Object.freeze({ ok: false, error: "AUTHORITY_CUSTODY_INVALID" });
  }
  const custody = active.store.authority;
  const captured = authorityCustodies.get(custody);
  if (captured === undefined || captured.disposed || captured.store !== active.session.store
    || !await directoryUnchanged(captured.directory, active.store.io)) {
    poison(active.session, active.store);
    return Object.freeze({ ok: false, error: "AUTHORITY_CUSTODY_INVALID" });
  }
  const files = await readAuthorityFiles(active.store, captured.directory);
  try {
    if (files === null) throw new Error("authority-recapture-invalid");
    const receipt = parseExactJson(files.receipt.bytes);
    const authorityKey = importEd25519PrivateKey(files.authority_signer.bytes);
    const qualificationKey = importEd25519PrivateKey(files.qualification_signer.bytes);
    if (!captureMatches(files.trust, captured.trust) || !captureMatches(files.receipt, captured.receipt)
      || !sameFileIdentity(files.authority_signer.identity, captured.authority_signer_identity)
      || !sameFileIdentity(files.qualification_signer.identity, captured.qualification_signer_identity)
      || hashRawBytes(files.authority_signer.bytes) !== captured.authority_signer_bytes_hash
      || hashRawBytes(files.qualification_signer.bytes) !== captured.qualification_signer_bytes_hash
      || authorityKey === null || qualificationKey === null
      || authorityKey.public_spki_hash !== captured.authority_spki_hash
      || qualificationKey.public_spki_hash !== captured.qualification_spki_hash
      || receipt === null || !validateReceiptRecord(receipt)
      || receipt.boot_id_hash !== active.session.lock_record.boot_id_hash
      || receipt.receipt_hash !== captured.receipt_hash) throw new Error("authority-drift");
    const trust = mergedAuthorityTrust(captured.base_trust, active.session.authorization_nonces);
    if (trust === null) throw new Error("authority-trust-invalid");
    return Object.freeze({
      ok: true,
      custody,
      trust_context: trust,
      conformance_receipt_hash: captured.receipt_hash,
    });
  } catch {
    poison(active.session, active.store);
    return Object.freeze({ ok: false, error: "AUTHORITY_CUSTODY_INVALID" });
  } finally {
    files?.authority_signer.bytes.fill(0);
    files?.qualification_signer.bytes.fill(0);
  }
}

export function inspectS37ProductHostAuthorityCustodyV01(
  custody: CapturedS37ProductHostAuthorityCustodyV01,
): Readonly<{
  ok: true;
  authority_key_ref: string;
  authority_public_key_hash: string;
  qualification_public_key_hash: string;
  conformance_receipt_hash: string;
}> | Readonly<{ ok: false; error: "AUTHORITY_CUSTODY_INVALID" }> {
  const captured = authorityCustodies.get(custody);
  if (captured === undefined || captured.disposed) return Object.freeze({ ok: false, error: "AUTHORITY_CUSTODY_INVALID" });
  return Object.freeze({
    ok: true,
    authority_key_ref: captured.authority_key_ref,
    authority_public_key_hash: captured.authority_spki_hash,
    qualification_public_key_hash: captured.qualification_spki_hash,
    conformance_receipt_hash: captured.receipt_hash,
  });
}

export type BegunS37ProductHostAuthoritySessionV01 = Readonly<{
  store: CapturedS37ProductHostActivationStoreV01;
  session: S37ProductHostActivationStoreSessionV01;
  custody: CapturedS37ProductHostAuthorityCustodyV01;
  trust_context: CapturedAuthorityTrustContextForS36V02;
  conformance_receipt_hash: string;
}>;
type AuthoritySessionBeginOutcome = Exclude<StoreOutcome, "COMPLETED">;

async function receiptBootForStore(store: StoreState): Promise<string | null> {
  const directory = await captureDirectory(join(store.root.path, AUTHORITY_DIRECTORY), 0o700n,
    store.owner_uid, store.owner_gid, store.io);
  if (directory === null) return null;
  try {
    const receipt = await readStrictFile(directory, CONFORMANCE_RECEIPT_FILE, 0o400n, MAX_CONFORMANCE_RECEIPT_BYTES,
      store.owner_uid, store.owner_gid, store.io);
    if (receipt === null) return null;
    const parsed = parseExactJson(receipt.bytes);
    return parsed !== null && validateReceiptRecord(parsed) && isHash(parsed.boot_id_hash) ? parsed.boot_id_hash : null;
  } finally {
    if (!await closeHandleOnce(directory.handle, store.io)) return null;
  }
}

type ReceiptFailureOutcome = "NOT_STARTED" | "RECOVERY_REQUIRED" | "OUTCOME_UNKNOWN";
type ReceiptFailureSnapshot = NonNullable<Awaited<ReturnType<typeof currentStoreBytes>>>;

function receiptFailureDurableOutcome(current: ReceiptFailureSnapshot, lock: FileCapture | null): ReceiptFailureOutcome {
  const stage = current.events.length;
  // Completion and predecessor history cannot certify a new failed begin.
  if (stage > 4) return "OUTCOME_UNKNOWN";
  if (lock === null) return stage === 0 && current.authorization_rows.length === 0
    && current.qualification_rows.length === 0 && current.manifest === null ? "NOT_STARTED" : "OUTCOME_UNKNOWN";
  const parsedLock = parseLock(lock.bytes);
  if (parsedLock === null || parsedLock.predecessor_ledger_sequence !== 0
    || parsedLock.predecessor_ledger_head_hash !== null
    || parsedLock.predecessor_ledger_bytes_hash !== hashActivationLedger(EMPTY)
    || parsedLock.fence_epoch !== 1 || current.authorization_rows.length > 1) return "OUTCOME_UNKNOWN";
  const authorization = current.authorization_rows[0];
  if (authorization !== undefined && (authorization.activation_id !== parsedLock.activation_id
    || authorization.activation_request_hash !== parsedLock.activation_request_hash
    || authorization.fence_epoch !== parsedLock.fence_epoch)) return "OUTCOME_UNKNOWN";
  if (stage === 0) return current.qualification_rows.length === 0 ? "RECOVERY_REQUIRED" : "OUTCOME_UNKNOWN";
  const requested = current.events[0];
  if (requested?.event_type !== "activation.requested" || !isRecord(requested.payload) || authorization === undefined
    || requested.activation_id !== parsedLock.activation_id
    || requested.payload.request_hash !== parsedLock.activation_request_hash
    || requested.fence_epoch !== parsedLock.fence_epoch || requested.boot_id_hash !== parsedLock.boot_id_hash) {
    return "OUTCOME_UNKNOWN";
  }
  const minimumQualificationRows = stage === 4 ? 2 : stage >= 2 ? 1 : 0;
  const maximumQualificationRows = stage >= 3 ? 2 : 1;
  if (current.qualification_rows.length < minimumQualificationRows
    || current.qualification_rows.length > maximumQualificationRows) return "OUTCOME_UNKNOWN";
  const launch = current.qualification_rows[0];
  if (launch !== undefined && (launch.reservation_kind !== "launch-nonce"
    || launch.activation_id !== requested.activation_id || launch.fence_epoch !== requested.fence_epoch
    || launch.operation !== requested.operation || launch.anchor_generation !== requested.anchor_generation
    || launch.qualification_intent_hash !== requested.payload.qualification_intent_hash)) return "OUTCOME_UNKNOWN";
  if (stage >= 2) {
    const reserved = current.events[1];
    if (reserved?.event_type !== "activation.nonces-reserved" || !isRecord(reserved.payload) || launch === undefined
      || reserved.payload.authorization_nonce_record_hash !== authorization.record_hash
      || reserved.payload.launch_nonce_record_hash !== launch.record_hash) return "OUTCOME_UNKNOWN";
  }
  const qualification = current.qualification_rows[1];
  if (qualification !== undefined) {
    const anchor = current.events[2];
    if (anchor?.event_type !== "activation.anchor-stable" || qualification.reservation_kind !== "qualification-hash"
      || qualification.anchor_hash !== anchor.anchor_hash) return "OUTCOME_UNKNOWN";
    // The parser already requires the immediately preceding matching launch
    // row; only event three/four bindings remain to be checked here.
    if (stage === 4) {
      const issued = current.events[3];
      if (issued?.event_type !== "activation.qualification-issued" || !isRecord(issued.payload)
        || issued.payload.qualification_nonce_record_hash !== qualification.record_hash
        || issued.payload.qualification_request_hash !== qualification.qualification_request_hash
        || issued.payload.qualification_hash !== qualification.reserved_hash) return "OUTCOME_UNKNOWN";
    }
  }
  return "RECOVERY_REQUIRED";
}

async function receiptFailureCaptureStillExact(
  store: StoreState, capture: FileCapture | null, fileName: string, mode: bigint, maximum: number,
): Promise<boolean> {
  const current = await readOptionalStrictFile(store.activation, fileName, mode, maximum,
    store.owner_uid, store.owner_gid, store.io);
  return current !== "invalid" && (capture === null ? current === null
    : current !== null && captureMatches(capture, current));
}

async function classifyReceiptFailure(store: StoreState): Promise<ReceiptFailureOutcome> {
  try {
    if (store.poisoned || descriptorCloseAmbiguities.has(store.io)) return "OUTCOME_UNKNOWN";
    const current = await currentStoreBytes(store);
    if (current === null) return "OUTCOME_UNKNOWN";
    const lock = await readOptionalStrictFile(store.activation, LOCK_FILE, 0o400n, MAX_LOCK_BYTES,
      store.owner_uid, store.owner_gid, store.io);
    if (lock === "invalid") return "OUTCOME_UNKNOWN";
    const outcome = receiptFailureDurableOutcome(current, lock);
    if (outcome === "OUTCOME_UNKNOWN") return outcome;
    // Revalidate raw captures sequentially, not a second parsed store snapshot.
    // Absence and identity matter as well as bytes. Drift never authorizes retry.
    for (const [capture, name, mode, maximum] of [
      [current.ledger, LEDGER_FILE, 0o600n, MAX_LEDGER_BYTES],
      [current.authorization, AUTHORIZATION_NONCE_FILE, 0o600n, MAX_NONCE_LOG_BYTES],
      [current.qualification, QUALIFICATION_NONCE_FILE, 0o600n, MAX_NONCE_LOG_BYTES],
      [current.manifest, MANIFEST_FILE, 0o600n, MAX_MANIFEST_BYTES],
      [lock, LOCK_FILE, 0o400n, MAX_LOCK_BYTES],
    ] as const) {
      if (!await receiptFailureCaptureStillExact(store, capture, name, mode, maximum)) return "OUTCOME_UNKNOWN";
    }
    return !store.poisoned && !descriptorCloseAmbiguities.has(store.io)
      && await directoryUnchanged(store.root, store.io) && await directoryUnchanged(store.activation, store.io)
      ? outcome : "OUTCOME_UNKNOWN";
  } catch {
    return "OUTCOME_UNKNOWN";
  }
}

async function beginAuthoritySessionFromCaptured(
  captured: CapturedS37ProductHostActivationStoreV01,
  input: Readonly<{ activation_id: string; activation_request_hash: string }>,
): Promise<Readonly<{ ok: true; value: BegunS37ProductHostAuthoritySessionV01 }>
  | Readonly<{ ok: false; outcome: AuthoritySessionBeginOutcome; error: string }>> {
  const store = stores.get(captured);
  if (store === undefined || store.poisoned) {
    return Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN", error: "ACTIVATION_STORE_INVALID" });
  }
  const bootIdHash = await receiptBootForStore(store);
  if (bootIdHash === null) {
    return Object.freeze({ ok: false, outcome: await classifyReceiptFailure(store), error: "AUTHORITY_CUSTODY_INVALID" });
  }
  const opened = await openS37ProductHostActivationStoreSessionV01(captured, {
    activation_id: input.activation_id,
    activation_request_hash: input.activation_request_hash,
    boot_id_hash: bootIdHash,
  });
  if (!opened.ok) return Object.freeze({
    ok: false,
    outcome: opened.outcome === "COMPLETED" ? "OUTCOME_UNKNOWN" : opened.outcome,
    error: opened.error,
  });
  const authority = await captureS37ProductHostAuthorityCustodyV01(opened.session);
  if (authority.ok) return Object.freeze({
    ok: true,
    value: Object.freeze({
      store: captured,
      session: opened.session,
      custody: authority.custody,
      trust_context: authority.trust_context,
      conformance_receipt_hash: authority.conformance_receipt_hash,
    }),
  });
  const closed = await closeS37ProductHostActivationStoreSessionV01(opened.session);
  return Object.freeze({
    ok: false,
    outcome: closed.released && closed.outcome === "NOT_STARTED" ? "NOT_STARTED" : "OUTCOME_UNKNOWN",
    error: authority.error,
  });
}

export async function beginS37ProductHostAuthoritySessionV01(input: Readonly<{
  activation_id: string;
  activation_request_hash: string;
}>): Promise<Readonly<{ ok: true; value: BegunS37ProductHostAuthoritySessionV01 }>
  | Readonly<{ ok: false; outcome: AuthoritySessionBeginOutcome; error: string }>> {
  let captured: Awaited<ReturnType<typeof captureS37ProductHostActivationStoreV01>>;
  try { captured = await captureS37ProductHostActivationStoreV01(); }
  catch { return Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN", error: "ACTIVATION_STORE_CAPTURE_FAILED" }); }
  if (!captured.ok) return Object.freeze({ ok: false, outcome: captured.error === "ACTIVATION_PLATFORM_INELIGIBLE"
    ? "NOT_STARTED" : "OUTCOME_UNKNOWN", error: captured.error });
  let begun: Awaited<ReturnType<typeof beginAuthoritySessionFromCaptured>>;
  try { begun = await beginAuthoritySessionFromCaptured(captured.store, input); }
  catch {
    await disposeS37ProductHostActivationStoreV01(captured.store).catch(() => false);
    return Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN", error: "AUTHORITY_SESSION_BEGIN_AMBIGUOUS" });
  }
  if (begun.ok) return begun;
  const disposed = await disposeS37ProductHostActivationStoreV01(captured.store);
  return disposed ? begun : Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN", error: "ACTIVATION_STORE_DISPOSE_FAILED" });
}

export async function beginS37ProductHostAuthoritySessionForTestV01(input: Readonly<{
  store: CapturedS37ProductHostActivationStoreV01;
  activation_id: string;
  activation_request_hash: string;
}>): ReturnType<typeof beginAuthoritySessionFromCaptured> {
  return beginAuthoritySessionFromCaptured(input.store, {
    activation_id: input.activation_id,
    activation_request_hash: input.activation_request_hash,
  });
}

export async function commitS37ProductHostAuthorizationNonceV01(
  session: S37ProductHostActivationStoreSessionV01,
  input: unknown,
): Promise<Readonly<{ ok: true; status: "reserved"; record_hash: string }> | Readonly<{ ok: false; status: "already-consumed" | "unavailable"; outcome: StoreOutcome }>> {
  const active = activeSession(session);
  if (active === null || !isRecord(input) || !exactKeys(input, [
    "authenticated_principal_ref", "approval_nonce", "domain", "run_id", "authorization_id", "authorization_statement_hash",
  ]) || !isMachineId(input.authenticated_principal_ref) || !isHash(input.approval_nonce) || input.domain !== "primary-v02"
    || !isMachineId(input.run_id) || !isMachineId(input.authorization_id) || !isHash(input.authorization_statement_hash)) {
    return Object.freeze({ ok: false, status: "unavailable", outcome: "NOT_COMMITTED" });
  }
  if (active.session.authorization_nonces.some((row) => row.authenticated_principal_ref === input.authenticated_principal_ref
    && row.approval_nonce === input.approval_nonce)) {
    return Object.freeze({ ok: false, status: "already-consumed", outcome: "RECOVERY_REQUIRED" });
  }
  const body = {
    schema_version: "s37-product-host-authorization-nonce-record-v01" as const,
    sequence: active.session.authorization_nonces.length + 1,
    previous_record_hash: active.session.authorization_nonces.at(-1)?.record_hash ?? null,
    activation_id: active.session.lock_record.activation_id,
    fence_epoch: active.session.lock_record.fence_epoch,
    activation_request_hash: active.session.lock_record.activation_request_hash,
    authenticated_principal_ref: input.authenticated_principal_ref,
    approval_nonce: input.approval_nonce,
    domain: "primary-v02" as const,
    run_id: input.run_id,
    authorization_id: input.authorization_id,
    authorization_statement_hash: input.authorization_statement_hash,
  };
  const record = immutable({ ...body, record_hash: recordHash("s37-product-host-authorization-nonce-record-v01", body) });
  const nextBytes = concatenate(active.session.authorization_nonce_bytes, canonicalLine(record));
  const written = await replaceCow(active.store, AUTHORIZATION_NONCE_FILE, active.session.authorization_nonce_bytes, nextBytes, MAX_NONCE_LOG_BYTES);
  if (!written.ok) {
    if (written.classification === "OUTCOME_UNKNOWN") poison(active.session, active.store);
    return Object.freeze({ ok: false, status: "unavailable", outcome: written.classification });
  }
  active.session.authorization_nonce_bytes = nextBytes;
  active.session.authorization_nonces = Object.freeze([...active.session.authorization_nonces, record]);
  active.session.wrote_irreversible = true;
  return Object.freeze({ ok: true, status: "reserved", record_hash: record.record_hash });
}

export async function commitS37ProductHostQualificationNonceV01(
  session: S37ProductHostActivationStoreSessionV01,
  input: unknown,
): Promise<Readonly<{ ok: true; status: "reserved"; record_hash: string }> | Readonly<{ ok: false; status: "already-consumed" | "unavailable"; outcome: StoreOutcome }>> {
  const active = activeSession(session);
  const keys = [
    "operation", "reservation_kind", "reserved_hash", "anchor_generation", "anchor_hash", "qualification_intent_hash",
    "qualification_request_hash",
  ];
  if (active === null || !isRecord(input) || !exactKeys(input, keys) || !isOperation(input.operation)
    || (input.reservation_kind !== "launch-nonce" && input.reservation_kind !== "qualification-hash")
    || !isHash(input.reserved_hash) || !isSafePositive(input.anchor_generation) || !isHash(input.qualification_intent_hash)) {
    return Object.freeze({ ok: false, status: "unavailable", outcome: "NOT_COMMITTED" });
  }
  if (active.session.qualification_nonces.some((row) => row.reservation_kind === input.reservation_kind
    && row.reserved_hash === input.reserved_hash)) {
    return Object.freeze({ ok: false, status: "already-consumed", outcome: "RECOVERY_REQUIRED" });
  }
  const previous = active.session.qualification_nonces.at(-1);
  if (input.reservation_kind === "launch-nonce") {
    if (input.anchor_hash !== null || input.qualification_request_hash !== null
      || previous?.reservation_kind === "launch-nonce") return Object.freeze({ ok: false, status: "unavailable", outcome: "NOT_COMMITTED" });
  } else if (!isHash(input.anchor_hash) || !isHash(input.qualification_request_hash)
    || previous?.reservation_kind !== "launch-nonce" || previous.activation_id !== active.session.lock_record.activation_id
    || previous.fence_epoch !== active.session.lock_record.fence_epoch || previous.operation !== input.operation
    || previous.anchor_generation !== input.anchor_generation || previous.qualification_intent_hash !== input.qualification_intent_hash) {
    return Object.freeze({ ok: false, status: "unavailable", outcome: "NOT_COMMITTED" });
  }
  const body = {
    schema_version: "s37-product-host-qualification-nonce-record-v01" as const,
    sequence: active.session.qualification_nonces.length + 1,
    previous_record_hash: previous?.record_hash ?? null,
    activation_id: active.session.lock_record.activation_id,
    fence_epoch: active.session.lock_record.fence_epoch,
    operation: input.operation,
    reservation_kind: input.reservation_kind,
    reserved_hash: input.reserved_hash,
    anchor_generation: input.anchor_generation,
    anchor_hash: input.anchor_hash,
    qualification_intent_hash: input.qualification_intent_hash,
    qualification_request_hash: input.qualification_request_hash,
  };
  const record = immutable({ ...body, record_hash: recordHash("s37-product-host-qualification-nonce-record-v01", body) }) as QualificationNonceRecord;
  const nextBytes = concatenate(active.session.qualification_nonce_bytes, canonicalLine(record));
  const written = await replaceCow(active.store, QUALIFICATION_NONCE_FILE, active.session.qualification_nonce_bytes, nextBytes, MAX_NONCE_LOG_BYTES);
  if (!written.ok) {
    if (written.classification === "OUTCOME_UNKNOWN") poison(active.session, active.store);
    return Object.freeze({ ok: false, status: "unavailable", outcome: written.classification });
  }
  active.session.qualification_nonce_bytes = nextBytes;
  active.session.qualification_nonces = Object.freeze([...active.session.qualification_nonces, record]);
  active.session.wrote_irreversible = true;
  return Object.freeze({ ok: true, status: "reserved", record_hash: record.record_hash });
}

function concatenate(left: Uint8Array, right: Uint8Array): Uint8Array {
  const bytes = new Uint8Array(left.byteLength + right.byteLength);
  bytes.set(left, 0);
  bytes.set(right, left.byteLength);
  return bytes;
}

export async function commitS37ProductHostActivationEventV01(
  session: S37ProductHostActivationStoreSessionV01,
  input: unknown,
): Promise<Readonly<{ ok: true; outcome: "COMMITTED"; event_hash: string; manifest_hash: string }>
  | Readonly<{ ok: false; outcome: "NOT_COMMITTED" | "OUTCOME_UNKNOWN"; error: string }>> {
  const active = activeSession(session);
  const keys = ["operation", "event_type", "anchor_generation", "anchor_hash", "controller_uid", "payload"];
  if (active === null || !isRecord(input) || !exactKeys(input, keys) || !isOperation(input.operation)
    || typeof input.event_type !== "string" || !(EVENT_TYPES as readonly string[]).includes(input.event_type)
    || !isSafePositive(input.anchor_generation) || !isHash(input.anchor_hash) || !isSafePositive(input.controller_uid)
    || !isRecord(input.payload)) return Object.freeze({ ok: false, outcome: "NOT_COMMITTED", error: "ACTIVATION_EVENT_INVALID" });
  const eventType = input.event_type as ActivationEventType;
  const expectedStage = active.session.events.length % 7;
  if (eventType !== EVENT_TYPES[expectedStage] || !exactKeys(input.payload, EVENT_PAYLOAD_KEYS[eventType])) {
    return Object.freeze({ ok: false, outcome: "NOT_COMMITTED", error: "ACTIVATION_EVENT_ORDER_INVALID" });
  }
  if (active.session.events.length > active.session.lock_record.predecessor_ledger_sequence) {
    const first = active.session.events[active.session.lock_record.predecessor_ledger_sequence];
    if (first !== undefined && (input.operation !== first.operation || input.anchor_generation !== first.anchor_generation
      || input.anchor_hash !== first.anchor_hash || input.controller_uid !== first.controller_uid)) {
      return Object.freeze({ ok: false, outcome: "NOT_COMMITTED", error: "ACTIVATION_EVENT_BINDING_INVALID" });
    }
  }
  if (eventType === "activation.requested" && input.payload.request_hash !== active.session.lock_record.activation_request_hash) {
    return Object.freeze({ ok: false, outcome: "NOT_COMMITTED", error: "ACTIVATION_REQUEST_MISMATCH" });
  }
  const body = {
    schema_version: "s37-product-host-activation-event-v01" as const,
    activation_id: active.session.lock_record.activation_id,
    operation: input.operation,
    sequence: active.session.events.length + 1,
    event_type: eventType,
    previous_event_hash: active.session.events.at(-1)?.event_hash ?? null,
    anchor_generation: input.anchor_generation,
    anchor_hash: input.anchor_hash,
    boot_id_hash: active.session.lock_record.boot_id_hash,
    controller_uid: input.controller_uid,
    fence_epoch: active.session.lock_record.fence_epoch,
    payload: immutable(structuredClone(input.payload)),
  };
  const event = immutable({
    ...body,
    event_hash: hashS37ProductHostActivationEventV01(body),
  }) as ActivationEvent;
  const nextEvents = Object.freeze([...active.session.events, event]);
  const nextLedgerBytes = concatenate(active.session.ledger_bytes, canonicalLine(event));
  if (parseLedger(nextLedgerBytes) === null) return Object.freeze({ ok: false, outcome: "NOT_COMMITTED", error: "ACTIVATION_EVENT_INVALID" });
  const builtManifest = manifestFromLedger(nextLedgerBytes, nextEvents);
  if (builtManifest === null) return Object.freeze({ ok: false, outcome: "NOT_COMMITTED", error: "ACTIVATION_MANIFEST_INVALID" });
  const ledgerWrite = await replaceCow(active.store, LEDGER_FILE, active.session.ledger_bytes, nextLedgerBytes, MAX_LEDGER_BYTES);
  if (!ledgerWrite.ok) {
    if (ledgerWrite.classification === "OUTCOME_UNKNOWN") poison(active.session, active.store);
    return Object.freeze({ ok: false, outcome: ledgerWrite.classification, error: "ACTIVATION_LEDGER_WRITE_FAILED" });
  }
  active.session.wrote_irreversible = true;
  const manifestWrite = await replaceCow(active.store, MANIFEST_FILE, active.session.manifest_bytes, builtManifest.bytes, MAX_MANIFEST_BYTES);
  if (!manifestWrite.ok) {
    poison(active.session, active.store);
    return Object.freeze({ ok: false, outcome: "OUTCOME_UNKNOWN", error: "ACTIVATION_MANIFEST_WRITE_FAILED" });
  }
  active.session.ledger_bytes = nextLedgerBytes;
  active.session.manifest_bytes = builtManifest.bytes;
  active.session.events = nextEvents;
  return Object.freeze({ ok: true, outcome: "COMMITTED", event_hash: event.event_hash, manifest_hash: builtManifest.manifest.manifest_hash });
}

async function lockStillExact(state: SessionState, store: StoreState): Promise<boolean> {
  const captured = await readStrictFile(store.activation, LOCK_FILE, 0o400n, MAX_LOCK_BYTES, store.owner_uid, store.owner_gid, store.io);
  return captured !== null && sameFileIdentity(captured.identity, state.lock.identity)
    && Buffer.from(captured.bytes).equals(Buffer.from(state.lock.bytes));
}

function parseLock(bytes: Uint8Array): LockRecord | null {
  try {
    const text = UTF8.decode(bytes);
    if (!text.endsWith("\n") || text.endsWith("\n\n")) return null;
    const row = parseCanonicalJsonLine(text.slice(0, -1));
    if (row === null || !exactKeySet(row, [
      "schema_version", "activation_id", "activation_request_hash", "predecessor_ledger_bytes_hash",
      "predecessor_ledger_sequence", "predecessor_ledger_head_hash", "fence_epoch", "boot_id_hash", "owner_nonce",
      "lock_hash",
    ])) return null;
    const { lock_hash: _lockHash, ...body } = row;
    if (row.schema_version !== "s37-product-host-activation-lock-v01" || !isMachineId(row.activation_id)
      || !isHash(row.activation_request_hash) || !isHash(row.predecessor_ledger_bytes_hash)
      || !isSafeNonnegative(row.predecessor_ledger_sequence)
      || !(row.predecessor_ledger_head_hash === null || isHash(row.predecessor_ledger_head_hash))
      || !isSafePositive(row.fence_epoch) || !isHash(row.boot_id_hash) || !isHash(row.owner_nonce)
      || !isHash(row.lock_hash)
      || row.activation_id !== `activation_${row.activation_request_hash.slice(7)}`
      || (row.predecessor_ledger_sequence === 0
        ? row.predecessor_ledger_head_hash !== null || row.predecessor_ledger_bytes_hash !== hashActivationLedger(EMPTY)
        : !isHash(row.predecessor_ledger_head_hash))
      || row.lock_hash !== hashCanonical({ purpose: "s37-product-host-activation-lock-v01", lock: body })) return null;
    return immutable(row as LockRecord);
  } catch {
    return null;
  }
}

function lockMatchesCompletedActivation(
  lock: LockRecord,
  ledgerBytes: Uint8Array,
  events: readonly ActivationEvent[],
): boolean {
  const head = events.at(-1);
  if (head?.event_type !== "activation.completed") return false;
  const blockStart = events.length - 7;
  const requested = events[blockStart];
  if (requested?.event_type !== "activation.requested" || !isRecord(requested.payload)
    || !isHash(requested.payload.request_hash)) return false;
  const predecessorBytes = blockStart === 0 ? EMPTY : ledgerPrefixBytes(ledgerBytes, blockStart);
  const predecessor = events[blockStart - 1];
  return predecessorBytes !== null && lock.activation_id === head.activation_id
    && lock.activation_request_hash === requested.payload.request_hash
    && lock.predecessor_ledger_bytes_hash === hashActivationLedger(predecessorBytes)
    && lock.predecessor_ledger_sequence === blockStart
    && lock.predecessor_ledger_head_hash === (predecessor?.event_hash ?? null)
    && lock.fence_epoch === head.fence_epoch && lock.boot_id_hash === head.boot_id_hash;
}

function sameFileIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return left.device === right.device && left.inode === right.inode && left.uid === right.uid && left.gid === right.gid
    && left.mode === right.mode && left.nlink === right.nlink && left.size === right.size;
}

async function removeExactLock(state: SessionState, store: StoreState): Promise<boolean> {
  if (!await lockStillExact(state, store)) return false;
  try {
    await store.io.unlink(state.lock.path);
    await store.activation.handle.sync();
    try {
      await store.io.lstat(state.lock.path);
      return false;
    } catch (error) {
      return errorCode(error) === "ENOENT" && await directoryUnchanged(store.activation, store.io);
    }
  } catch {
    return false;
  }
}

async function removeReconciledLock(lock: FileCapture, store: StoreState): Promise<boolean> {
  const reopened = await readStrictFile(store.activation, LOCK_FILE, 0o400n, MAX_LOCK_BYTES, store.owner_uid, store.owner_gid, store.io);
  if (reopened === null || !sameFileIdentity(reopened.identity, lock.identity)
    || !Buffer.from(reopened.bytes).equals(Buffer.from(lock.bytes))) return false;
  try {
    await store.io.unlink(lock.path);
    await store.activation.handle.sync();
    try {
      await store.io.lstat(lock.path);
      return false;
    } catch (error) {
      return errorCode(error) === "ENOENT" && await directoryUnchanged(store.activation, store.io);
    }
  } catch {
    return false;
  }
}

export async function closeS37ProductHostActivationStoreSessionV01(
  session: S37ProductHostActivationStoreSessionV01,
): Promise<Readonly<{ released: boolean; outcome: StoreOutcome }>> {
  const state = sessions.get(session);
  if (state === undefined) return Object.freeze({ released: false, outcome: "OUTCOME_UNKNOWN" });
  if (state.closed) return Object.freeze({ released: false, outcome: state.poisoned ? "OUTCOME_UNKNOWN" : "RECOVERY_REQUIRED" });
  const store = stores.get(state.store);
  state.closed = true;
  if (store === undefined || state.poisoned || store.poisoned) return Object.freeze({ released: false, outcome: "OUTCOME_UNKNOWN" });
  const current = await currentStoreBytes(store);
  if (current === null || !Buffer.from(current.ledger.bytes).equals(Buffer.from(state.ledger_bytes))
    || !Buffer.from(current.authorization.bytes).equals(Buffer.from(state.authorization_nonce_bytes))
    || !Buffer.from(current.qualification.bytes).equals(Buffer.from(state.qualification_nonce_bytes))
    || (current.manifest === null ? state.manifest_bytes !== null : state.manifest_bytes === null
      || !Buffer.from(current.manifest.bytes).equals(Buffer.from(state.manifest_bytes)))) {
    poison(state, store);
    return Object.freeze({ released: false, outcome: "OUTCOME_UNKNOWN" });
  }
  const head = state.events.at(-1);
  const completed = head?.event_type === "activation.completed" && state.manifest_bytes !== null
    && lockMatchesCompletedActivation(state.lock_record, state.ledger_bytes, state.events)
    && parseManifest(state.manifest_bytes, state.ledger_bytes, state.events) !== null;
  const clean = !state.wrote_irreversible
    && hashRawBytes(state.ledger_bytes) === state.initial_ledger_hash
    && (state.manifest_bytes === null ? state.initial_manifest_hash === null : hashRawBytes(state.manifest_bytes) === state.initial_manifest_hash)
    && hashRawBytes(state.authorization_nonce_bytes) === state.initial_authorization_hash
    && hashRawBytes(state.qualification_nonce_bytes) === state.initial_qualification_hash;
  if (!completed && !clean) return Object.freeze({
    released: false,
    outcome: head !== undefined && head.sequence > state.lock_record.predecessor_ledger_sequence
      && ((head.sequence - 1) % 7) + 1 >= 5 ? "OUTCOME_UNKNOWN" : "RECOVERY_REQUIRED",
  });
  const released = await removeExactLock(state, store);
  if (!released) return Object.freeze({ released: false, outcome: "OUTCOME_UNKNOWN" });
  return Object.freeze({ released: true, outcome: completed ? "COMPLETED" : "NOT_STARTED" });
}

export async function reconcileS37ProductHostActivationStoreV01(
  captured: CapturedS37ProductHostActivationStoreV01,
): Promise<Readonly<{ outcome: StoreOutcome; activation_id: string | null; evidence_hash: string | null }>> {
  const store = stores.get(captured);
  if (store === undefined || store.poisoned) return Object.freeze({ outcome: "OUTCOME_UNKNOWN", activation_id: null, evidence_hash: null });
  const current = await currentStoreBytes(store);
  if (current === null) return Object.freeze({ outcome: "OUTCOME_UNKNOWN", activation_id: null, evidence_hash: null });
  const lock = await readOptionalStrictFile(store.activation, LOCK_FILE, 0o400n, MAX_LOCK_BYTES, store.owner_uid, store.owner_gid, store.io);
  if (lock === "invalid") return Object.freeze({ outcome: "OUTCOME_UNKNOWN", activation_id: null, evidence_hash: null });
  const head = current.events.at(-1);
  if (head === undefined) {
    const parsedLock = lock === null ? null : parseLock(lock.bytes);
    const nonceCommitted = current.authorization_rows.length > 0 || current.qualification_rows.length > 0;
    const invalidPrefix = current.qualification_rows.length > 0
      || (lock !== null && (parsedLock === null || parsedLock.predecessor_ledger_sequence !== 0 || parsedLock.fence_epoch !== 1));
    return Object.freeze({
      outcome: invalidPrefix ? "OUTCOME_UNKNOWN" : lock === null && !nonceCommitted ? "NOT_STARTED" : "RECOVERY_REQUIRED",
      activation_id: null,
      evidence_hash: null,
    });
  }
  const stage = ((head.sequence - 1) % 7) + 1;
  if (current.manifest_state === "behind") {
    return Object.freeze({
      outcome: stage >= 5 ? "OUTCOME_UNKNOWN" : "RECOVERY_REQUIRED",
      activation_id: head.activation_id,
      evidence_hash: head.event_hash,
    });
  }
  if (stage === 7) {
    if (lock !== null) {
      const parsedLock = parseLock(lock.bytes);
      if (parsedLock === null || !lockMatchesCompletedActivation(parsedLock, current.ledger.bytes, current.events)
        || !await removeReconciledLock(lock, store)) {
        return Object.freeze({ outcome: "OUTCOME_UNKNOWN", activation_id: head.activation_id, evidence_hash: head.event_hash });
      }
    }
    return Object.freeze({
      outcome: "COMPLETED",
      activation_id: head.activation_id,
      evidence_hash: head.event_hash,
    });
  }
  return Object.freeze({
    outcome: stage >= 5 ? "OUTCOME_UNKNOWN" : "RECOVERY_REQUIRED",
    activation_id: head.activation_id,
    evidence_hash: head.event_hash,
  });
}

export async function disposeS37ProductHostActivationStoreV01(
  captured: CapturedS37ProductHostActivationStoreV01,
): Promise<boolean> {
  const store = stores.get(captured);
  if (store === undefined) return false;
  stores.delete(captured);
  let authorityClosed = true;
  if (store.authority !== undefined) {
    const authority = authorityCustodies.get(store.authority);
    if (authority !== undefined) {
      authority.disposed = true;
      authorityCustodies.delete(store.authority);
      authorityClosed = await closeHandleOnce(authority.directory.handle, store.io);
    }
  }
  const activationClosed = await closeHandleOnce(store.activation.handle, store.io);
  const rootClosed = await closeHandleOnce(store.root.handle, store.io);
  return authorityClosed && activationClosed && rootClosed && !descriptorCloseAmbiguities.has(store.io);
}
