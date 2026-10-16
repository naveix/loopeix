import { describe, expect, it, vi } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import {
  runBoundedS37LinuxProbeV02,
  type S37LinuxProbeRuntimeV02,
} from "../../src/run/bounded-linux-probe-v02.js";
import {
  S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
  simulateAuthorityDecisionV02,
} from "../../src/run/action-classifier-policy-v02.js";
import {
  buildS37ActionInterpositionProfileV02,
  prepareS37LinuxProbeAdmissionV02,
  type S37LinuxBackendIdentityReceiptV02,
  type S37LinuxHostTupleV02,
} from "../../src/run/pre-spawn-capability-broker-v02.js";

const HASH = `sha256:${"a".repeat(64)}`;
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
      action_proposal_hash: HASH,
      action_class: "task" as const,
      policy_action_kind: "deterministic-no-side-effect-check" as const,
      action_approval_class: "automatic" as const,
      policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
      action_scope_hash: HASH,
      normalized_dispatch_hash: HASH,
      repository_pre_state_hash: HASH,
      classifier_rule_hash: HASH,
      data_flow_hash: HASH,
      effective_risk_tier: "T1" as const,
    },
    reviewer_view_hash: HASH,
    reviewed_through_ref: { ledger_sequence: 1, event_hash: HASH },
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
  const decision_input = authorityInput();
  const simulated = simulateAuthorityDecisionV02(decision_input);
  if (!simulated.ok || simulated.value.simulated_lease === null) {
    throw new Error("S37 authority fixture must produce a simulated lease");
  }
  return {
    decision_input,
    decision: simulated.value,
    simulated_lease: simulated.value.simulated_lease,
    observed_at: "2026-08-14T10:00:30Z",
    host: { platform: "linux" as const, architecture: "x64", available_backends: ["s37-linux-v02"] },
  };
}

function validProfile(overrides: Record<string, unknown> = {}) {
  return Object.freeze({
    ...buildS37ActionInterpositionProfileV02({
      actor_identity_hash: HASH,
      on_behalf_of_chain_hash: HASH,
      executable: { path: "/opt/loopeix/inert-probe", sha256: HASH },
      cwd: { path: "/opt/loopeix/empty", identity_hash: HASH },
    }),
    ...overrides,
  });
}

function validHostTuple(overrides: Partial<S37LinuxHostTupleV02> = {}): S37LinuxHostTupleV02 {
  return Object.freeze({
    tuple_version: "0.1" as const,
    platform: "linux" as const,
    architecture: "x64",
    kernel_release: "6.12.0-1-amd64",
    systemd_version: "257.8",
    cgroup_version: "v2" as const,
    observed_at: "2026-08-14T10:00:20Z",
    ...overrides,
  });
}

function validReceipt(
  tuple: S37LinuxHostTupleV02,
  profile: ReturnType<typeof validProfile>,
  overrides: Partial<S37LinuxBackendIdentityReceiptV02> = {},
): S37LinuxBackendIdentityReceiptV02 {
  const withoutHash = {
    receipt_version: "0.1" as const,
    host_tuple_hash: hashCanonical({ purpose: "s37-linux-host-tuple-v02", ...tuple }),
    profile_hash: hashCanonical(profile),
    launcher_sha256: HASH,
    bwrap: {
      path: "/usr/bin/bwrap",
      version: "0.11.0-2+deb13u1",
      sha256: HASH,
      setuid: false as const,
    },
    seccomp_policy_sha256: HASH,
    deny_rows: [...DENY_ROWS] as const,
    skipped_rows: [] as const,
    issued_at: "2026-08-14T10:00:25Z",
    expires_at: "2026-08-14T10:00:45Z",
    ...overrides,
  };
  return Object.freeze({
    ...withoutHash,
    receipt_hash: overrides.receipt_hash
      ?? hashCanonical({ purpose: "s37-linux-backend-identity-receipt-v02", ...withoutHash }),
  });
}

function mintAdmission(overrides: {
  profile?: Record<string, unknown>;
  tuple?: Partial<S37LinuxHostTupleV02>;
  receipt?: Partial<S37LinuxBackendIdentityReceiptV02>;
} = {}) {
  const request = validRequest();
  const profile = validProfile(overrides.profile);
  const tuple = validHostTuple(overrides.tuple);
  const receipt = validReceipt(tuple, profile, overrides.receipt);
  const prepared = prepareS37LinuxProbeAdmissionV02({
    request,
    profile,
    host_tuple: tuple,
    backend_receipt: receipt,
  });
  if (!prepared.ok) throw new Error(`S37 Linux admission fixture failed: ${prepared.detail}`);
  return { admission: prepared.value, profile, tuple, receipt };
}

function runtime(
  start: S37LinuxProbeRuntimeV02["start"],
): S37LinuxProbeRuntimeV02 {
  return Object.freeze({ start });
}

function startedOutcome(overrides: Record<string, unknown> = {}) {
  return {
    ok: true as const,
    process_started: true as const,
    exit_code: 0,
    signal: null,
    timed_out: false,
    kill_attempted: false,
    reaped: true,
    forbidden_effect_denied: false,
    outcome_ambiguous: false,
    stdout: Uint8Array.from([1, 2, 3]),
    stderr: new Uint8Array(),
    ...overrides,
  };
}

describe("S37.1 bounded Linux probe runtime seam", () => {
  it("rejects a forged admission without touching the runtime", async () => {
    const start = vi.fn();

    await expect(runBoundedS37LinuxProbeV02(Object.freeze({}) as never, runtime(start))).resolves.toEqual({
      ok: false,
      reason: "ADMISSION_INVALID",
      terminal: "hold",
      retryable: false,
      process_started: false,
      detail: "S37 Linux probe admission is invalid or already consumed.",
    });
    expect(start).not.toHaveBeenCalled();
  });

  it("consumes the admission once and rejects reuse without a second runtime call", async () => {
    const { admission } = mintAdmission();
    const start = vi.fn(async () => ({ ok: false as const, confirmed_not_started: true as const, detail: "spawn denied" }));

    await expect(runBoundedS37LinuxProbeV02(admission, runtime(start))).resolves.toEqual({
      ok: false,
      reason: "SPAWN_FAILED",
      terminal: "hold",
      retryable: false,
      process_started: false,
      detail: "spawn denied",
    });
    await expect(runBoundedS37LinuxProbeV02(admission, runtime(start))).resolves.toEqual({
      ok: false,
      reason: "ADMISSION_INVALID",
      terminal: "hold",
      retryable: false,
      process_started: false,
      detail: "S37 Linux probe admission is invalid or already consumed.",
    });
    expect(start).toHaveBeenCalledTimes(1);
  });

  it("derives the exact runtime input from the consumed admission", async () => {
    const { admission, profile, tuple, receipt } = mintAdmission();
    const start = vi.fn(async () => ({ ok: false as const, confirmed_not_started: true as const, detail: "not started" }));

    await runBoundedS37LinuxProbeV02(admission, runtime(start));

    expect(start).toHaveBeenCalledTimes(1);
    const [input] = start.mock.calls[0] ?? [];
    expect(input).toEqual({
      executable: { path: profile.executable.path },
      argv: [],
      cwd: { path: profile.cwd.path },
      env: {},
      stdin: "closed",
      timeout_ms: 1_000,
      stdout_bytes: 1_024,
      stderr_bytes: 1_024,
      tuple,
      receipt,
    });
    expect(Object.isFrozen(input)).toBe(true);
    expect(Object.isFrozen(input.argv)).toBe(true);
    expect(Object.isFrozen(input.env)).toBe(true);
    expect(Object.isFrozen(input.tuple)).toBe(true);
    expect(Object.isFrozen(input.receipt)).toBe(true);
    expect(input.tuple).not.toBe(tuple);
    expect(input.receipt).not.toBe(receipt);
    expect("shell" in input).toBe(false);
  });

  it("accepts exact 1,024-byte stdout and stderr captures", async () => {
    const stdout = new Uint8Array(1_024).fill(0x61);
    const stderr = new Uint8Array(1_024).fill(0x62);

    for (const [stream, bytes] of [["stdout", stdout], ["stderr", stderr]] as const) {
      const { admission } = mintAdmission();
      const result = await runBoundedS37LinuxProbeV02(
        admission,
        runtime(async () => startedOutcome(stream === "stdout" ? { stdout: bytes } : { stderr: bytes })),
      );

      expect(result).toMatchObject({
        ok: true,
        terminal: "completed",
        outcome: "exited",
        process_started: true,
        exit_code: 0,
        signal: null,
      });
      if (result.ok) {
        expect(result[stream]).toHaveLength(1_024);
      }
    }
  });

  it("holds unknown if stdout or stderr exceeds 1,024 bytes", async () => {
    for (const stream of ["stdout", "stderr"] as const) {
      const { admission } = mintAdmission();
      const result = await runBoundedS37LinuxProbeV02(
        admission,
        runtime(async () => startedOutcome({
          [stream]: new Uint8Array(1_025),
        } as Record<string, unknown>)),
      );

      expect(result).toEqual({
        ok: false,
        reason: "OUTCOME_UNKNOWN",
        terminal: "hold",
        retryable: false,
        process_started: true,
        detail: `${stream} exceeded the 1024-byte S37 cap.`,
      });
    }
  });

  it("copies stdout and stderr so later mutation of runtime buffers cannot change the result", async () => {
    const { admission } = mintAdmission();
    const stdout = Uint8Array.from([10, 20, 30]);
    const stderr = Uint8Array.from([40, 50, 60]);

    const result = await runBoundedS37LinuxProbeV02(
      admission,
      runtime(async () => startedOutcome({ stdout, stderr })),
    );

    stdout[0] = 99;
    stderr[0] = 88;

    expect(result).toMatchObject({ ok: true, outcome: "exited" });
    if (!result.ok) return;
    expect(result.stdout).toEqual(Uint8Array.from([10, 20, 30]));
    expect(result.stderr).toEqual(Uint8Array.from([40, 50, 60]));
    expect(result.stdout).not.toBe(stdout);
    expect(result.stderr).not.toBe(stderr);
  });

  it("treats a forbidden-effect deny witness as a completed preventive outcome", async () => {
    const { admission } = mintAdmission();

    await expect(runBoundedS37LinuxProbeV02(
      admission,
      runtime(async () => startedOutcome({
        exit_code: 126,
        forbidden_effect_denied: true,
        stdout: Uint8Array.from([0xde]),
      })),
    )).resolves.toMatchObject({
      ok: true,
      terminal: "completed",
      outcome: "forbidden-effect-denied",
      process_started: true,
      exit_code: 126,
    });
  });

  it("holds a timed-out process that was killed and fully reaped", async () => {
    const { admission } = mintAdmission();

    await expect(runBoundedS37LinuxProbeV02(
      admission,
      runtime(async () => startedOutcome({
        exit_code: null,
        signal: "SIGKILL",
        timed_out: true,
        kill_attempted: true,
        reaped: true,
      })),
    )).resolves.toEqual({
      ok: false,
      reason: "TIMEOUT_REAPED",
      terminal: "hold",
      retryable: false,
      process_started: true,
      detail: "The S37 Linux probe timed out, required a kill, and was fully reaped.",
    });
  });

  it("holds unknown when timeout cleanup is incomplete", async () => {
    for (const overrides of [
      { timed_out: true, kill_attempted: false, reaped: true, exit_code: null, signal: "SIGKILL" },
      { timed_out: true, kill_attempted: true, reaped: false, exit_code: null, signal: "SIGKILL" },
    ]) {
      const { admission } = mintAdmission();
      await expect(runBoundedS37LinuxProbeV02(admission, runtime(async () => startedOutcome(overrides)))).resolves.toEqual({
        ok: false,
        reason: "OUTCOME_UNKNOWN",
        terminal: "hold",
        retryable: false,
        process_started: true,
        detail: "The S37 Linux probe outcome could not be proven safe and exact.",
      });
    }
  });

  it("holds unknown on ambiguous or contradictory started outcomes", async () => {
    for (const outcome of [
      startedOutcome({ outcome_ambiguous: true }),
      { ...startedOutcome(), process_started: false },
      startedOutcome({ signal: "SIGTERM" }),
      startedOutcome({ reaped: false }),
      startedOutcome({ kill_attempted: true }),
    ]) {
      const { admission } = mintAdmission();
      await expect(runBoundedS37LinuxProbeV02(admission, runtime(async () => outcome as never))).resolves.toEqual({
        ok: false,
        reason: "OUTCOME_UNKNOWN",
        terminal: "hold",
        retryable: false,
        process_started: true,
        detail: "The S37 Linux probe outcome could not be proven safe and exact.",
      });
    }
  });

  it("holds unknown if the runtime throws after invocation", async () => {
    const { admission } = mintAdmission();

    await expect(runBoundedS37LinuxProbeV02(
      admission,
      runtime(async () => {
        throw new Error("boom");
      }),
    )).resolves.toEqual({
      ok: false,
      reason: "OUTCOME_UNKNOWN",
      terminal: "hold",
      retryable: false,
      process_started: true,
      detail: "The S37 Linux probe outcome could not be proven safe and exact.",
    });
  });
});
