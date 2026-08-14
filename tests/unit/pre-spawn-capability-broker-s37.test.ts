import { describe, expect, it } from "vitest";

import {
  S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
  simulateAuthorityDecisionV02,
} from "../../src/run/action-classifier-policy-v02.js";
import {
  S37_ADAPTER_CAPABILITY_MATRIX_V02,
  buildS37ActionInterpositionProfileV02,
  enforceS37PreSpawnProbeV02,
} from "../../src/run/pre-spawn-capability-broker-v02.js";

const H = `sha256:${"a".repeat(64)}`;

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
