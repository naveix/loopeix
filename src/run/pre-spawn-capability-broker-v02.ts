import { isAbsolute } from "node:path";
import { z } from "zod";

import { canonicalize, hashCanonical } from "../hash.js";
import { Hash, IsoTimestamp } from "../schema/scalars.js";
import {
  revalidateSimulatedAuthorityLeaseV02,
  simulateAuthorityDecisionV02,
  type SimulatedAuthorityLeaseV02,
} from "./action-classifier-policy-v02.js";

type S37Adapter = "s37_inert_probe" | "codex_cli" | "claude_code_cli";

type S37Terminal =
  | "hold-enforcement-unavailable"
  | "hold-general-agent-prohibited";

export type S37AdapterCapabilityRowV02 = Readonly<{
  adapter: S37Adapter;
  declared: Readonly<{
    general_agent: boolean;
    structured_stdout: boolean;
    provider_network_required: boolean;
  }>;
  requested: Readonly<{
    filesystem_write: "deny";
    child_process: "deny";
    network: "deny";
    tool_server: "deny";
    ambient_credentials: "deny";
  }>;
  enforced_by: null;
  terminal: S37Terminal;
}>;

function freezeDeep<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) freezeDeep(child);
  return Object.freeze(value);
}

const requestedZeroEffect = {
  filesystem_write: "deny",
  child_process: "deny",
  network: "deny",
  tool_server: "deny",
  ambient_credentials: "deny",
} as const;

/**
 * S37 capability truth as shipped: no host backend currently proves every deny.
 * `enforced_by` therefore remains null and the enforcement point cannot spawn.
 */
export const S37_ADAPTER_CAPABILITY_MATRIX_V02: readonly S37AdapterCapabilityRowV02[] = freezeDeep([
  {
    adapter: "s37_inert_probe",
    declared: { general_agent: false, structured_stdout: true, provider_network_required: false },
    requested: requestedZeroEffect,
    enforced_by: null,
    terminal: "hold-enforcement-unavailable",
  },
  {
    adapter: "codex_cli",
    declared: { general_agent: true, structured_stdout: true, provider_network_required: true },
    requested: requestedZeroEffect,
    enforced_by: null,
    terminal: "hold-general-agent-prohibited",
  },
  {
    adapter: "claude_code_cli",
    declared: { general_agent: true, structured_stdout: true, provider_network_required: true },
    requested: requestedZeroEffect,
    enforced_by: null,
    terminal: "hold-general-agent-prohibited",
  },
]);

const AbsolutePath = z.string().min(1).refine(
  (value) => isAbsolute(value) && !value.includes("\0") && !/[\r\n]/u.test(value),
  { message: "must be a newline-free absolute path" },
);

const ProfileBindingInputV02 = z.object({
  actor_identity_hash: Hash,
  on_behalf_of_chain_hash: Hash,
  executable: z.object({ path: AbsolutePath, sha256: Hash }).strict(),
  cwd: z.object({ path: AbsolutePath, identity_hash: Hash }).strict(),
}).strict();

export type S37ActionInterpositionProfileV02 = Readonly<{
  profile_version: "0.1";
  probe_kind: "inert-bounded-stdout-stderr";
  actor_identity_hash: string;
  on_behalf_of_chain_hash: string;
  executable: Readonly<{ path: string; sha256: string }>;
  argv: readonly string[];
  cwd: Readonly<{ path: string; identity_hash: string }>;
  filesystem: Readonly<{
    readable_paths: readonly string[];
    writable_paths: readonly string[];
    direct_writes: "deny";
  }>;
  child_process: "deny";
  network: Readonly<{ mode: "deny"; allowed_origins: readonly string[] }>;
  tools: Readonly<{ built_in: "deny"; mcp_servers: "deny" }>;
  environment: Readonly<{
    inherit: false;
    allowed_names: readonly string[];
    values: Readonly<Record<string, never>>;
  }>;
  credentials: "deny";
  stdin: "closed";
  limits: Readonly<{ timeout_ms: 1_000; stdout_bytes: 1_024; stderr_bytes: 1_024 }>;
  durable_state: "forbidden-until-s40";
  retry: "forbidden-non-resumable";
}>;

const EmptyStringArray = z.array(z.string()).length(0);
const EmptyNeverRecord = z.record(z.string(), z.never());
const S37ActionInterpositionProfileSchemaV02 = z.object({
  profile_version: z.literal("0.1"),
  probe_kind: z.literal("inert-bounded-stdout-stderr"),
  actor_identity_hash: Hash,
  on_behalf_of_chain_hash: Hash,
  executable: z.object({ path: AbsolutePath, sha256: Hash }).strict(),
  argv: z.array(z.string()).length(0),
  cwd: z.object({ path: AbsolutePath, identity_hash: Hash }).strict(),
  filesystem: z.object({
    readable_paths: z.tuple([AbsolutePath]),
    writable_paths: z.array(z.string()).length(0),
    direct_writes: z.literal("deny"),
  }).strict(),
  child_process: z.literal("deny"),
  network: z.object({ mode: z.literal("deny"), allowed_origins: EmptyStringArray }).strict(),
  tools: z.object({ built_in: z.literal("deny"), mcp_servers: z.literal("deny") }).strict(),
  environment: z.object({
    inherit: z.literal(false),
    allowed_names: EmptyStringArray,
    values: EmptyNeverRecord,
  }).strict(),
  credentials: z.literal("deny"),
  stdin: z.literal("closed"),
  limits: z.object({
    timeout_ms: z.literal(1_000),
    stdout_bytes: z.literal(1_024),
    stderr_bytes: z.literal(1_024),
  }).strict(),
  durable_state: z.literal("forbidden-until-s40"),
  retry: z.literal("forbidden-non-resumable"),
}).strict();

const S37_LINUX_REQUIRED_BACKEND_V02 = "s37-linux-v02" as const;
const S37_LINUX_MAX_HOST_TUPLE_AGE_MS = 15_000;
const S37_LINUX_MAX_RECEIPT_LIFETIME_MS = 600_000;
const S37_LINUX_REQUIRED_DENY_ROWS_V02 = [
  "ambient-credentials",
  "child-process",
  "durable-state",
  "environment",
  "filesystem-write",
  "network",
  "output-limits",
  "retry",
  "stdin",
  "timeout",
  "tool-server",
  "unknown-outcome",
] as const;
const S37LinuxRequiredDenyRowV02 = z.enum(S37_LINUX_REQUIRED_DENY_ROWS_V02);

export type S37LinuxHostTupleV02 = Readonly<{
  tuple_version: "0.1";
  platform: "linux";
  architecture: string;
  kernel_release: string;
  systemd_version: string;
  cgroup_version: "v2";
  observed_at: string;
}>;

export type S37LinuxBackendIdentityReceiptV02 = Readonly<{
  receipt_version: "0.1";
  host_tuple_hash: string;
  profile_hash: string;
  launcher_sha256: string;
  bwrap: Readonly<{ path: string; version: string; sha256: string; setuid: false }>;
  seccomp_policy_sha256: string;
  deny_rows: readonly (typeof S37_LINUX_REQUIRED_DENY_ROWS_V02)[number][];
  skipped_rows: readonly [];
  issued_at: string;
  expires_at: string;
  receipt_hash: string;
}>;

export type S37LinuxProbeAdmissionV02 = Readonly<{
  readonly __s37_linux_probe_admission_v02: unique symbol;
}>;

export type S37LinuxProbeAdmissionResultV02 =
  | Readonly<{ ok: true; value: S37LinuxProbeAdmissionV02 }>
  | S37PreSpawnProbeResultV02;

const LinuxHostTupleV02 = z.object({
  tuple_version: z.literal("0.1"),
  platform: z.literal("linux"),
  architecture: z.string().trim().min(1),
  kernel_release: z.string().trim().min(1),
  systemd_version: z.string().trim().min(1),
  cgroup_version: z.literal("v2"),
  observed_at: IsoTimestamp,
}).strict();

const LinuxBackendIdentityReceiptV02 = z.object({
  receipt_version: z.literal("0.1"),
  host_tuple_hash: Hash,
  profile_hash: Hash,
  launcher_sha256: Hash,
  bwrap: z.object({
    path: AbsolutePath,
    version: z.string().trim().min(1),
    sha256: Hash,
    setuid: z.literal(false),
  }).strict(),
  seccomp_policy_sha256: Hash,
  deny_rows: z.array(S37LinuxRequiredDenyRowV02).length(S37_LINUX_REQUIRED_DENY_ROWS_V02.length),
  skipped_rows: z.tuple([]),
  issued_at: IsoTimestamp,
  expires_at: IsoTimestamp,
  receipt_hash: Hash,
}).strict();

type S37LinuxProbeAdmissionValueV02 = Readonly<{
  profile: S37ActionInterpositionProfileV02;
  host_tuple: S37LinuxHostTupleV02;
  backend_receipt: S37LinuxBackendIdentityReceiptV02;
}>;

const linuxProbeAdmissionRegistryV02 = new WeakMap<S37LinuxProbeAdmissionV02, S37LinuxProbeAdmissionValueV02>();

/** Derives the one exact S37 zero-effect process profile. It performs no I/O. */
export function buildS37ActionInterpositionProfileV02(input: unknown): S37ActionInterpositionProfileV02 {
  const parsed = ProfileBindingInputV02.safeParse(input);
  if (!parsed.success) throw new Error("S37_PROFILE_INVALID");
  const value = parsed.data;
  return freezeDeep({
    profile_version: "0.1" as const,
    probe_kind: "inert-bounded-stdout-stderr" as const,
    actor_identity_hash: value.actor_identity_hash,
    on_behalf_of_chain_hash: value.on_behalf_of_chain_hash,
    executable: { ...value.executable },
    argv: [] as const,
    cwd: { ...value.cwd },
    filesystem: {
      readable_paths: [value.executable.path],
      writable_paths: [] as const,
      direct_writes: "deny" as const,
    },
    child_process: "deny" as const,
    network: { mode: "deny" as const, allowed_origins: [] as const },
    tools: { built_in: "deny" as const, mcp_servers: "deny" as const },
    environment: {
      inherit: false as const,
      allowed_names: [] as const,
      values: {} as Readonly<Record<string, never>>,
    },
    credentials: "deny" as const,
    stdin: "closed" as const,
    limits: { timeout_ms: 1_000 as const, stdout_bytes: 1_024 as const, stderr_bytes: 1_024 as const },
    durable_state: "forbidden-until-s40" as const,
    retry: "forbidden-non-resumable" as const,
  });
}

const HostV02 = z.object({
  platform: z.enum(["darwin", "linux", "win32"]),
  architecture: z.string().min(1),
  available_backends: z.array(z.string().min(1)),
}).strict();

export type S37PreSpawnHoldReasonV02 =
  | "GENERAL_AGENT_PROHIBITED"
  | "POLICY_DECISION_INVALID"
  | "SIMULATED_LEASE_INVALID"
  | "AUTHORITY_EXPIRED"
  | "ENFORCEMENT_UNAVAILABLE";

export type S37PreSpawnProbeResultV02 = Readonly<{
  ok: false;
  reason: S37PreSpawnHoldReasonV02;
  terminal: "hold";
  retryable: false;
  process_started: false;
  detail: string;
}>;

export type S37PreSpawnProbeRequestV02 = Readonly<{
  decision_input: unknown;
  decision: unknown;
  simulated_lease: unknown;
  observed_at: string;
  host: unknown;
  adapter?: S37Adapter;
}>;

type S37ValidatedAuthorityWindowV02 = Readonly<{ observed_at_ms: number }>;

function hold(reason: S37PreSpawnHoldReasonV02, detail: string): S37PreSpawnProbeResultV02 {
  return freezeDeep({
    ok: false as const,
    reason,
    terminal: "hold" as const,
    retryable: false as const,
    process_started: false as const,
    detail,
  });
}

function freezeCloneDeep<T>(value: T): T {
  return freezeDeep(structuredClone(value));
}

function isS37PreSpawnHoldResultV02(
  value: S37PreSpawnProbeResultV02 | S37ValidatedAuthorityWindowV02,
): value is S37PreSpawnProbeResultV02 {
  return "ok" in value;
}

/** Shared command/API guard: S37 never launches a general Codex or Claude worker. */
export function prohibitS37GeneralAgentSpawnV02(
  adapter: "codex_cli" | "claude_code_cli",
): S37PreSpawnProbeResultV02 {
  return hold("GENERAL_AGENT_PROHIBITED", `${adapter} general-agent execution is prohibited in S37`);
}

function decisionInputWindow(input: unknown): Readonly<{
  issued_at: string;
  expires_at: string;
  policy_action_kind: unknown;
}> | null {
  if (typeof input !== "object" || input === null) return null;
  const candidate = input as {
    issued_at?: unknown;
    expires_at?: unknown;
    proposal?: { policy_action_kind?: unknown };
  };
  if (typeof candidate.issued_at !== "string" || typeof candidate.expires_at !== "string") return null;
  return {
    issued_at: candidate.issued_at,
    expires_at: candidate.expires_at,
    policy_action_kind: candidate.proposal?.policy_action_kind,
  };
}

function validateS37AuthorityRequestV02(input: S37PreSpawnProbeRequestV02): S37PreSpawnProbeResultV02 | S37ValidatedAuthorityWindowV02 {
  const adapter = input.adapter ?? "s37_inert_probe";
  if (adapter !== "s37_inert_probe") {
    return prohibitS37GeneralAgentSpawnV02(adapter);
  }

  const recomputed = simulateAuthorityDecisionV02(input.decision_input);
  if (!recomputed.ok || recomputed.value.decision !== "allow"
    || recomputed.value.decision_disposition !== "lease-eligible"
    || recomputed.value.simulated_lease === null
    || canonicalize(recomputed.value) !== canonicalize(input.decision)) {
    return hold("POLICY_DECISION_INVALID", "the exact fresh S36 decision did not revalidate");
  }

  if (canonicalize(recomputed.value.simulated_lease) !== canonicalize(input.simulated_lease)
    || !revalidateSimulatedAuthorityLeaseV02(
      input.simulated_lease as SimulatedAuthorityLeaseV02,
      input.decision_input,
    ).ok) {
    return hold("SIMULATED_LEASE_INVALID", "the non-durable S36 lease binding changed or is invalid");
  }

  const window = decisionInputWindow(input.decision_input);
  const observedAt = Date.parse(input.observed_at);
  if (window === null || window.policy_action_kind !== "deterministic-no-side-effect-check"
    || !Number.isFinite(observedAt)
    || Date.parse(window.issued_at) > observedAt
    || observedAt >= Date.parse(window.expires_at)) {
    return hold("AUTHORITY_EXPIRED", "the decision window or S37 action kind is not fresh and exact");
  }

  return freezeDeep({ observed_at_ms: observedAt });
}

/**
 * The mandatory S37/S38 pre-spawn interface. The current release has no verified
 * host backend, so a valid request reaches an explicit HOLD and no process starts.
 */
export function enforceS37PreSpawnProbeV02(input: S37PreSpawnProbeRequestV02): S37PreSpawnProbeResultV02 {
  const validated = validateS37AuthorityRequestV02(input);
  if (isS37PreSpawnHoldResultV02(validated)) return validated;

  const host = HostV02.safeParse(input.host);
  if (!host.success) {
    return hold("ENFORCEMENT_UNAVAILABLE", "host capability input is invalid");
  }
  return hold(
    "ENFORCEMENT_UNAVAILABLE",
    `${host.data.platform}/${host.data.architecture} has no verified S37 backend for every required deny`,
  );
}

function invalidLinuxAdmission(detail: string): S37PreSpawnProbeResultV02 {
  return hold("ENFORCEMENT_UNAVAILABLE", detail);
}

function hashS37LinuxHostTupleV02(tuple: S37LinuxHostTupleV02): string {
  return hashCanonical({ purpose: "s37-linux-host-tuple-v02", ...tuple });
}

function hashS37LinuxBackendIdentityReceiptV02(
  receiptWithoutHash: Omit<S37LinuxBackendIdentityReceiptV02, "receipt_hash">,
): string {
  return hashCanonical({ purpose: "s37-linux-backend-identity-receipt-v02", ...receiptWithoutHash });
}

export function prepareS37LinuxProbeAdmissionV02(input: Readonly<{
  request: S37PreSpawnProbeRequestV02;
  profile: S37ActionInterpositionProfileV02;
  host_tuple: unknown;
  backend_receipt: unknown;
}>): S37LinuxProbeAdmissionResultV02 {
  const validated = validateS37AuthorityRequestV02(input.request);
  if (isS37PreSpawnHoldResultV02(validated)) return validated;

  const host = HostV02.safeParse(input.request.host);
  if (!host.success) return invalidLinuxAdmission("host capability input is invalid");
  if (host.data.platform !== "linux") {
    return invalidLinuxAdmission("linux host admission requires a linux host capability record");
  }
  if (host.data.available_backends.length !== 1 || host.data.available_backends[0] !== S37_LINUX_REQUIRED_BACKEND_V02) {
    return invalidLinuxAdmission("linux host admission requires the exact s37-linux-v02 backend advertisement");
  }

  const profile = S37ActionInterpositionProfileSchemaV02.safeParse(input.profile);
  if (!profile.success) return invalidLinuxAdmission("linux host admission requires the exact frozen S37 profile");

  const hostTuple = LinuxHostTupleV02.safeParse(input.host_tuple);
  if (!hostTuple.success) return invalidLinuxAdmission("linux host tuple is invalid");
  if (hostTuple.data.architecture !== host.data.architecture) {
    return invalidLinuxAdmission("linux host tuple architecture drifted from the request host");
  }
  const tupleObservedAt = Date.parse(hostTuple.data.observed_at);
  if (!Number.isFinite(tupleObservedAt)
    || tupleObservedAt > validated.observed_at_ms
    || validated.observed_at_ms - tupleObservedAt > S37_LINUX_MAX_HOST_TUPLE_AGE_MS) {
    return invalidLinuxAdmission("linux host tuple is outside the exact request observation window");
  }

  const receipt = LinuxBackendIdentityReceiptV02.safeParse(input.backend_receipt);
  if (!receipt.success) return invalidLinuxAdmission("linux backend identity receipt is invalid");
  if (canonicalize(receipt.data.deny_rows) !== canonicalize(S37_LINUX_REQUIRED_DENY_ROWS_V02)) {
    return invalidLinuxAdmission("linux backend identity receipt deny rows drifted");
  }
  if (receipt.data.skipped_rows.length !== 0) {
    return invalidLinuxAdmission("linux backend identity receipt may not skip deny rows");
  }

  const expectedHostTupleHash = hashS37LinuxHostTupleV02(hostTuple.data);
  if (receipt.data.host_tuple_hash !== expectedHostTupleHash) {
    return invalidLinuxAdmission("linux backend identity receipt does not bind the observed host tuple");
  }
  const expectedProfileHash = hashCanonical(profile.data);
  if (receipt.data.profile_hash !== expectedProfileHash) {
    return invalidLinuxAdmission("linux backend identity receipt does not bind the exact S37 profile");
  }

  const issuedAt = Date.parse(receipt.data.issued_at);
  const expiresAt = Date.parse(receipt.data.expires_at);
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt)
    || issuedAt < tupleObservedAt
    || issuedAt > validated.observed_at_ms
    || expiresAt - issuedAt > S37_LINUX_MAX_RECEIPT_LIFETIME_MS
    || validated.observed_at_ms >= expiresAt) {
    return invalidLinuxAdmission("linux backend identity receipt is outside the exact request observation window");
  }

  const { receipt_hash: _receiptHash, ...receiptWithoutHash } = receipt.data;
  if (receipt.data.receipt_hash !== hashS37LinuxBackendIdentityReceiptV02(receiptWithoutHash)) {
    return invalidLinuxAdmission("linux backend identity receipt hash is invalid");
  }

  const admission = Object.freeze({}) as S37LinuxProbeAdmissionV02;
  linuxProbeAdmissionRegistryV02.set(admission, freezeCloneDeep({
    profile: profile.data,
    host_tuple: hostTuple.data,
    backend_receipt: receipt.data,
  }));
  return freezeDeep({ ok: true as const, value: admission });
}

export function consumeS37LinuxProbeAdmissionV02(
  admission: S37LinuxProbeAdmissionV02,
): Readonly<{
  profile: S37ActionInterpositionProfileV02;
  host_tuple: S37LinuxHostTupleV02;
  backend_receipt: S37LinuxBackendIdentityReceiptV02;
}> | null {
  const value = linuxProbeAdmissionRegistryV02.get(admission);
  if (value === undefined) return null;
  linuxProbeAdmissionRegistryV02.delete(admission);
  return freezeCloneDeep(value);
}
