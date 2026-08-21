import { describe, expect, it } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import {
  S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
  simulateAuthorityDecisionV02,
} from "../../src/run/action-classifier-policy-v02.js";
import {
  S37_ADAPTER_CAPABILITY_MATRIX_V02,
  buildS37ActionInterpositionProfileV02,
  consumeS37LinuxProbeAdmissionV02,
  enforceS37PreSpawnProbeV02,
  prepareS37LinuxProbeAdmissionV02,
} from "../../src/run/pre-spawn-capability-broker-v02.js";

const H = `sha256:${"a".repeat(64)}`;
const DENY_ROWS = [
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

function authorityInput() {
  return {
    proposal: {
      action_proposal_id: "proposal_s37_probe",
      action_proposal_hash: H,
      action_class: "task" as const,
      policy_action_kind: "deterministic-no-side-effect-check" as const,
      action_approval_class: "automatic" as const,
      policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
      action_scope_hash: H,
      normalized_dispatch_hash: H,
      repository_pre_state_hash: H,
      classifier_rule_hash: H,
      data_flow_hash: H,
      effective_risk_tier: "T1" as const,
    },
    reviewer_view_hash: H,
    reviewed_through_ref: { ledger_sequence: 1, event_hash: H },
    recommendations: [],
    authority: {
      envelope_verified: true,
      contained: true,
      proof_fresh: true,
      revocation_epoch_current: true,
    },
    enforcement: {
      available: true,
      information_flow_allowed: true,
      gates_passed: true,
      immediate_revalidation_passed: true,
    },
    condition_results: [],
    issued_at: "2026-08-14T10:00:00Z",
    expires_at: "2026-08-14T10:01:00Z",
    fence_epoch: 0,
  } as const;
}

function validRequest() {
  const decisionInput = authorityInput();
  const simulated = simulateAuthorityDecisionV02(decisionInput);
  if (!simulated.ok || simulated.value.simulated_lease === null) {
    throw new Error("S37 authority fixture must produce a simulated lease");
  }
  return {
    decision_input: decisionInput,
    decision: simulated.value,
    simulated_lease: simulated.value.simulated_lease,
    observed_at: "2026-08-14T10:00:30Z",
    host: { platform: "darwin" as const, architecture: "arm64", available_backends: [] },
  };
}

function validProfile() {
  return buildS37ActionInterpositionProfileV02({
    actor_identity_hash: H,
    on_behalf_of_chain_hash: H,
    executable: { path: "/s37/inert-probe", sha256: H },
    cwd: { path: "/s37/empty", identity_hash: H },
  });
}

function validLinuxHostTuple(
  overrides: Partial<{
    tuple_version: "0.1";
    platform: "linux";
    architecture: string;
    kernel_release: string;
    systemd_version: string;
    cgroup_version: "v2";
    observed_at: string;
  }> = {},
) {
  return {
    tuple_version: "0.1" as const,
    platform: "linux" as const,
    architecture: "x64",
    kernel_release: "6.12.0-1-amd64",
    systemd_version: "257.8",
    cgroup_version: "v2" as const,
    observed_at: "2026-08-14T10:00:20Z",
    ...overrides,
  };
}

function validLinuxBackendIdentityReceipt(
  tuple = validLinuxHostTuple(),
  profile = validProfile(),
  overrides: Partial<{
    receipt_version: "0.1";
    host_tuple_hash: string;
    profile_hash: string;
    launcher_sha256: string;
    bwrap: { path: string; version: string; sha256: string; setuid: false | true };
    seccomp_policy_sha256: string;
    deny_rows: readonly string[];
    skipped_rows: readonly string[];
    issued_at: string;
    expires_at: string;
    receipt_hash: string;
  }> = {},
) {
  const withoutHash = {
    receipt_version: "0.1" as const,
    host_tuple_hash: hashCanonical({ purpose: "s37-linux-host-tuple-v02", ...tuple }),
    profile_hash: hashCanonical(profile),
    launcher_sha256: H,
    bwrap: {
      path: "/usr/bin/bwrap",
      version: "0.11.0",
      sha256: H,
      setuid: false as const,
    },
    seccomp_policy_sha256: H,
    deny_rows: [...DENY_ROWS],
    skipped_rows: [] as const,
    issued_at: "2026-08-14T10:00:25Z",
    expires_at: "2026-08-14T10:00:45Z",
    ...overrides,
  };
  return {
    ...withoutHash,
    receipt_hash: overrides.receipt_hash
      ?? hashCanonical({ purpose: "s37-linux-backend-identity-receipt-v02", ...withoutHash }),
  };
}

function validLinuxAdmissionInput() {
  const request = validRequest();
  const profile = validProfile();
  const hostTuple = validLinuxHostTuple();
  return {
    request: {
      ...request,
      observed_at: "2026-08-14T10:00:30Z",
      host: {
        platform: "linux" as const,
        architecture: hostTuple.architecture,
        available_backends: ["s37-linux-v02"],
      },
    },
    profile,
    host_tuple: hostTuple,
    backend_receipt: validLinuxBackendIdentityReceipt(hostTuple, profile),
  };
}

describe("S37 adapter capability truth matrix", () => {
  it("distinguishes declared, requested, and actually enforced controls", () => {
    expect(S37_ADAPTER_CAPABILITY_MATRIX_V02).toEqual([
      expect.objectContaining({
        adapter: "s37_inert_probe",
        declared: expect.objectContaining({ general_agent: false }),
        requested: expect.objectContaining({ network: "deny", child_process: "deny" }),
        enforced_by: null,
        terminal: "hold-enforcement-unavailable",
      }),
      expect.objectContaining({
        adapter: "codex_cli",
        declared: expect.objectContaining({ general_agent: true }),
        terminal: "hold-general-agent-prohibited",
      }),
      expect.objectContaining({
        adapter: "claude_code_cli",
        declared: expect.objectContaining({ general_agent: true }),
        terminal: "hold-general-agent-prohibited",
      }),
    ]);
    expect(Object.isFrozen(S37_ADAPTER_CAPABILITY_MATRIX_V02)).toBe(true);
  });
});

describe("S37 action interposition profile", () => {
  it("is exact, zero-effect, bounded, ambient-authority-free, and immutable", () => {
    const profile = buildS37ActionInterpositionProfileV02({
      actor_identity_hash: H,
      on_behalf_of_chain_hash: H,
      executable: { path: "/s37/inert-probe", sha256: H },
      cwd: { path: "/s37/empty", identity_hash: H },
    });

    expect(profile).toMatchObject({
      profile_version: "0.1",
      probe_kind: "inert-bounded-stdout-stderr",
      executable: { path: "/s37/inert-probe", sha256: H },
      argv: [],
      filesystem: { readable_paths: ["/s37/inert-probe"], writable_paths: [], direct_writes: "deny" },
      child_process: "deny",
      network: { mode: "deny", allowed_origins: [] },
      tools: { built_in: "deny", mcp_servers: "deny" },
      environment: { inherit: false, allowed_names: [], values: {} },
      credentials: "deny",
      stdin: "closed",
      limits: { timeout_ms: 1_000, stdout_bytes: 1_024, stderr_bytes: 1_024 },
      durable_state: "forbidden-until-s40",
      retry: "forbidden-non-resumable",
    });
    expect(Object.isFrozen(profile)).toBe(true);
    expect(Object.isFrozen(profile.environment.values)).toBe(true);
  });

  it("rejects relative paths, malformed hashes, and delimiter-like executable input", () => {
    expect(() => buildS37ActionInterpositionProfileV02({
      actor_identity_hash: H,
      on_behalf_of_chain_hash: H,
      executable: { path: "codex --sandbox danger-full-access", sha256: H },
      cwd: { path: "/s37/empty", identity_hash: H },
    })).toThrow("S37_PROFILE_INVALID");
    expect(() => buildS37ActionInterpositionProfileV02({
      actor_identity_hash: H,
      on_behalf_of_chain_hash: "not-a-hash",
      executable: { path: "/s37/inert-probe", sha256: H },
      cwd: { path: "/s37/empty", identity_hash: H },
    })).toThrow("S37_PROFILE_INVALID");
  });
});

describe("S37 pre-spawn enforcement point", () => {
  it("reaches an honest HOLD on unsupported macOS without invoking a process", () => {
    expect(enforceS37PreSpawnProbeV02(validRequest())).toEqual({
      ok: false,
      reason: "ENFORCEMENT_UNAVAILABLE",
      terminal: "hold",
      retryable: false,
      process_started: false,
      detail: "darwin/arm64 has no verified S37 backend for every required deny",
    });
  });

  it("rejects decision drift before host capability selection", () => {
    const request = validRequest();
    const result = enforceS37PreSpawnProbeV02({
      ...request,
      decision: { ...request.decision, decision_simulation_hash: `sha256:${"b".repeat(64)}` },
    });
    expect(result).toMatchObject({
      ok: false,
      reason: "POLICY_DECISION_INVALID",
      process_started: false,
      retryable: false,
    });
  });

  it("rejects lease drift and expired authority before host capability selection", () => {
    const request = validRequest();
    expect(enforceS37PreSpawnProbeV02({
      ...request,
      simulated_lease: { ...request.simulated_lease, action_proposal_hash: `sha256:${"c".repeat(64)}` },
    })).toMatchObject({ reason: "SIMULATED_LEASE_INVALID", process_started: false });
    expect(enforceS37PreSpawnProbeV02({
      ...request,
      observed_at: "2026-08-14T10:01:00Z",
    })).toMatchObject({ reason: "AUTHORITY_EXPIRED", process_started: false });
  });

  it("prohibits general Codex and Claude adapters even if a host backend is advertised", () => {
    const request = validRequest();
    for (const adapter of ["codex_cli", "claude_code_cli"] as const) {
      expect(enforceS37PreSpawnProbeV02({
        ...request,
        adapter,
        host: { ...request.host, available_backends: ["untrusted-test-backend"] },
      })).toMatchObject({
        reason: "GENERAL_AGENT_PROHIBITED",
        process_started: false,
        retryable: false,
      });
    }
  });
});

describe("S37 Linux probe admission", () => {
  it("mints a single-use opaque admission and returns a deep-frozen consumed payload", () => {
    const prepared = prepareS37LinuxProbeAdmissionV02(validLinuxAdmissionInput());
    expect(prepared.ok).toBe(true);
    if (!prepared.ok) throw new Error("expected S37.1 Linux admission");

    const consumed = consumeS37LinuxProbeAdmissionV02(prepared.value);
    expect(consumed).toMatchObject({
      profile: validLinuxAdmissionInput().profile,
      host_tuple: validLinuxAdmissionInput().host_tuple,
      backend_receipt: validLinuxAdmissionInput().backend_receipt,
    });
    expect(consumed).not.toBeNull();
    expect(Object.isFrozen(consumed)).toBe(true);
    expect(Object.isFrozen(consumed?.profile)).toBe(true);
    expect(Object.isFrozen(consumed?.profile.filesystem.readable_paths)).toBe(true);
    expect(Object.isFrozen(consumed?.host_tuple)).toBe(true);
    expect(Object.isFrozen(consumed?.backend_receipt)).toBe(true);
    expect(Object.isFrozen(consumed?.backend_receipt.deny_rows)).toBe(true);
    expect(consumeS37LinuxProbeAdmissionV02(prepared.value)).toBeNull();
  });

  it("returns null for forged or caller-authored opaque values", () => {
    expect(consumeS37LinuxProbeAdmissionV02(Object.freeze({}) as never)).toBeNull();
  });

  it("preserves the existing general-agent prohibition and Linux-host binding checks", () => {
    const valid = validLinuxAdmissionInput();
    for (const adapter of ["codex_cli", "claude_code_cli"] as const) {
      expect(prepareS37LinuxProbeAdmissionV02({
        ...valid,
        request: { ...valid.request, adapter },
      })).toMatchObject({
        ok: false,
        reason: "GENERAL_AGENT_PROHIBITED",
        process_started: false,
      });
    }

    expect(prepareS37LinuxProbeAdmissionV02({
      ...valid,
      request: {
        ...valid.request,
        host: { ...valid.request.host, available_backends: [] },
      },
    })).toMatchObject({ ok: false, reason: "ENFORCEMENT_UNAVAILABLE", process_started: false });

    expect(prepareS37LinuxProbeAdmissionV02({
      ...valid,
      request: {
        ...valid.request,
        host: { ...valid.request.host, architecture: "arm64" },
      },
    })).toMatchObject({ ok: false, reason: "ENFORCEMENT_UNAVAILABLE", process_started: false });
  });

  it("rejects profile, tuple, and receipt drift before any process could start", () => {
    const valid = validLinuxAdmissionInput();
    expect(prepareS37LinuxProbeAdmissionV02({
      ...valid,
      profile: buildS37ActionInterpositionProfileV02({
        actor_identity_hash: H,
        on_behalf_of_chain_hash: H,
        executable: { path: "/s37/inert-probe-alt", sha256: H },
        cwd: { path: "/s37/empty", identity_hash: H },
      }),
    })).toMatchObject({ ok: false, reason: "ENFORCEMENT_UNAVAILABLE", process_started: false });

    expect(prepareS37LinuxProbeAdmissionV02({
      ...valid,
      host_tuple: validLinuxHostTuple({ observed_at: "2026-08-14T10:00:31Z" }),
    })).toMatchObject({ ok: false, reason: "ENFORCEMENT_UNAVAILABLE", process_started: false });

    expect(prepareS37LinuxProbeAdmissionV02({
      ...valid,
      backend_receipt: validLinuxBackendIdentityReceipt(valid.host_tuple, valid.profile, {
        issued_at: "2026-08-14T10:00:31Z",
      }),
    })).toMatchObject({ ok: false, reason: "ENFORCEMENT_UNAVAILABLE", process_started: false });

    expect(prepareS37LinuxProbeAdmissionV02({
      ...valid,
      backend_receipt: validLinuxBackendIdentityReceipt(valid.host_tuple, valid.profile, {
        expires_at: "2026-08-14T10:00:30Z",
      }),
    })).toMatchObject({ ok: false, reason: "ENFORCEMENT_UNAVAILABLE", process_started: false });
  });

  it("rejects receipt hash and deny-set drift, skipped rows, and setuid bubblewrap", () => {
    const valid = validLinuxAdmissionInput();
    expect(prepareS37LinuxProbeAdmissionV02({
      ...valid,
      backend_receipt: validLinuxBackendIdentityReceipt(valid.host_tuple, valid.profile, {
        host_tuple_hash: H.replace(/a/g, "b"),
      }),
    })).toMatchObject({ ok: false, reason: "ENFORCEMENT_UNAVAILABLE", process_started: false });

    expect(prepareS37LinuxProbeAdmissionV02({
      ...valid,
      backend_receipt: validLinuxBackendIdentityReceipt(valid.host_tuple, valid.profile, {
        profile_hash: H.replace(/a/g, "c"),
      }),
    })).toMatchObject({ ok: false, reason: "ENFORCEMENT_UNAVAILABLE", process_started: false });

    expect(prepareS37LinuxProbeAdmissionV02({
      ...valid,
      backend_receipt: validLinuxBackendIdentityReceipt(valid.host_tuple, valid.profile, {
        deny_rows: DENY_ROWS.slice(0, -1),
      }),
    })).toMatchObject({ ok: false, reason: "ENFORCEMENT_UNAVAILABLE", process_started: false });

    expect(prepareS37LinuxProbeAdmissionV02({
      ...valid,
      backend_receipt: validLinuxBackendIdentityReceipt(valid.host_tuple, valid.profile, {
        skipped_rows: ["network"],
      }),
    })).toMatchObject({ ok: false, reason: "ENFORCEMENT_UNAVAILABLE", process_started: false });

    expect(prepareS37LinuxProbeAdmissionV02({
      ...valid,
      backend_receipt: validLinuxBackendIdentityReceipt(valid.host_tuple, valid.profile, {
        bwrap: {
          path: "/usr/bin/bwrap",
          version: "0.11.0",
          sha256: H,
          setuid: true,
        },
      }),
    })).toMatchObject({ ok: false, reason: "ENFORCEMENT_UNAVAILABLE", process_started: false });

    expect(prepareS37LinuxProbeAdmissionV02({
      ...valid,
      backend_receipt: validLinuxBackendIdentityReceipt(valid.host_tuple, valid.profile, {
        receipt_hash: H.replace(/a/g, "d"),
      }),
    })).toMatchObject({ ok: false, reason: "ENFORCEMENT_UNAVAILABLE", process_started: false });
  });
});
