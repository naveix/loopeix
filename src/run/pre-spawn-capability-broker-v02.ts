import { isAbsolute } from "node:path";
import { z } from "zod";

import { canonicalize } from "../hash.js";
import { Hash } from "../schema/scalars.js";
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

/**
 * The mandatory S37/S38 pre-spawn interface. The current release has no verified
 * host backend, so a valid request reaches an explicit HOLD and no process starts.
 */
export function enforceS37PreSpawnProbeV02(input: S37PreSpawnProbeRequestV02): S37PreSpawnProbeResultV02 {
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

  const host = HostV02.safeParse(input.host);
  if (!host.success) {
    return hold("ENFORCEMENT_UNAVAILABLE", "host capability input is invalid");
  }
  return hold(
    "ENFORCEMENT_UNAVAILABLE",
    `${host.data.platform}/${host.data.architecture} has no verified S37 backend for every required deny`,
  );
}
