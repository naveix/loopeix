import { describe, expect, it, vi } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import {
  S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
  simulateAuthorityDecisionV02,
} from "../../src/run/action-classifier-policy-v02.js";
import { buildS37ActionInterpositionProfileV02 } from "../../src/run/pre-spawn-capability-broker-v02.js";

const host = vi.hoisted(() => ({ platform: "darwin" as NodeJS.Platform }));

vi.mock("node:os", () => ({
  arch: () => "arm64",
  platform: () => host.platform,
  release: () => "25.0.0",
}));

import {
  buildS37SystemdRunInvocationV02,
  createS37LocalLinuxProductProbeV02,
  runS37LocalLinuxProductProbeV02,
} from "../../src/run/linux-host-enforcement-v02.js";

const H = `sha256:${"a".repeat(64)}`;
const H2 = `sha256:${"b".repeat(64)}`;
const DENY_ROWS = [
  "ambient-credentials", "child-process", "durable-state", "environment",
  "filesystem-write", "network", "output-limits", "retry", "stdin",
  "timeout", "tool-server", "unknown-outcome",
] as const;

function resealedBindingHash(observation: ReturnType<typeof validProductInput>["observation"]): string {
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

function validProductInput() {
  const decisionInput = {
    proposal: {
      action_proposal_id: "proposal_s37_local_probe",
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
      envelope_verified: true, contained: true, proof_fresh: true, revocation_epoch_current: true,
    },
    enforcement: {
      available: true, information_flow_allowed: true, gates_passed: true, immediate_revalidation_passed: true,
    },
    condition_results: [],
    issued_at: "2026-08-22T12:00:00Z",
    expires_at: "2026-08-22T12:01:00Z",
    fence_epoch: 0,
  } as const;
  const simulated = simulateAuthorityDecisionV02(decisionInput);
  if (!simulated.ok || simulated.value.simulated_lease === null) throw new Error("invalid authority fixture");
  const profile = buildS37ActionInterpositionProfileV02({
    actor_identity_hash: H,
    on_behalf_of_chain_hash: H,
    executable: { path: "/opt/loopeix/s37.1/probe", sha256: H },
    cwd: { path: "/", identity_hash: H2 },
  });
  const conformanceTuple = {
    tuple_version: "0.1" as const,
    platform: "linux" as const,
    architecture: "x86_64",
    kernel_release: "6.12.101+deb13-amd64",
    systemd_version: "257 (257.13-1~deb13u1)",
    cgroup_version: "v2" as const,
    observed_at: "2026-08-22T12:00:20Z",
  };
  const receiptWithoutHash = {
    receipt_version: "0.1" as const,
    host_tuple_hash: hashCanonical({ purpose: "s37-linux-host-tuple-v02", ...conformanceTuple }),
    profile_hash: hashCanonical(profile),
    launcher_sha256: H,
    bwrap: { path: "/opt/loopeix/s37.1/bwrap", version: "0.11.0", sha256: H2, setuid: false as const },
    seccomp_policy_sha256: H,
    deny_rows: [...DENY_ROWS],
    skipped_rows: [] as const,
    issued_at: "2026-08-22T12:00:25Z",
    expires_at: "2026-08-22T12:00:45Z",
  };
  const backendReceipt = {
    ...receiptWithoutHash,
    receipt_hash: hashCanonical({ purpose: "s37-linux-backend-identity-receipt-v02", ...receiptWithoutHash }),
  };
  const bindingWithoutHash = {
    schema_version: "s37-local-product-binding-v02",
    host_role: "local-product",
    transport: "local-only",
    host_identity_hash: H2,
    controller_uid: 1001,
    conformance_tuple_hash: backendReceipt.host_tuple_hash,
    backend_receipt_hash: backendReceipt.receipt_hash,
    phase_b_manifest_sha256: H,
    expires_at: "2026-08-22T12:00:45Z",
    systemd_version: conformanceTuple.systemd_version,
    artifacts: {
      supervisor_sha256: H,
      probe_sha256: H,
      bwrap_sha256: H2,
      bwrap_version: "0.11.0",
      systemd_run_sha256: H2,
      systemctl_sha256: H2,
      seccomp_policy_sha256: H,
      cwd_identity_hash: H2,
    },
  };
  return {
    input: {
      decision_input: decisionInput,
      decision: simulated.value,
      simulated_lease: simulated.value.simulated_lease,
      profile,
      conformance_tuple: conformanceTuple,
      backend_receipt: backendReceipt,
      phase_b_manifest_sha256: H,
    },
    observation: {
      observed_at: "2026-08-22T12:00:30Z",
      platform: "linux" as const,
      architecture: "x86_64",
      kernel_release: conformanceTuple.kernel_release,
      systemd_version: conformanceTuple.systemd_version,
      cgroup_version: "v2" as const,
      host_identity_hash: H2,
      controller_uid: 1001,
      binding: {
        binding_version: "0.1" as const,
        host_role: "local-product" as const,
        transport: "local-only" as const,
        host_identity_hash: H2,
        controller_uid: 1001,
        conformance_tuple_hash: backendReceipt.host_tuple_hash,
        backend_receipt_hash: backendReceipt.receipt_hash,
        phase_b_manifest_sha256: H,
        expires_at: "2026-08-22T12:00:45Z",
        systemd_run_sha256: H2,
        binding_hash: hashCanonical({ purpose: "s37-local-product-binding-v02", ...bindingWithoutHash }),
      },
      artifacts: {
        supervisor: { path: "/opt/loopeix/s37.1/supervisor", sha256: H, mode: "0555", uid: 0, setuid: false as const },
        probe: { path: "/opt/loopeix/s37.1/probe", sha256: H, mode: "0555", uid: 0, setuid: false as const },
        bwrap: { path: "/opt/loopeix/s37.1/bwrap", version: "0.11.0", sha256: H2, mode: "0555", uid: 0, setuid: false as const },
        systemd_run: { path: "/usr/bin/systemd-run", sha256: H2, mode: "0755", uid: 0, setuid: false as const },
        systemctl: { path: "/usr/bin/systemctl", sha256: H2, mode: "0755", uid: 0, setuid: false as const },
        seccomp_policy_sha256: H,
        cwd_identity_hash: H2,
      },
    },
  };
}

describe("S37.1-C local Linux product backend", () => {
  it("rejects a root user-manager controller", () => {
    expect(() => buildS37SystemdRunInvocationV02("loopeix-s37-product-v02", 0))
      .toThrow("S37_LOCAL_UID_INVALID");
  });

  it("derives the platform locally and holds before validating caller data on non-Linux", async () => {
    await expect(runS37LocalLinuxProductProbeV02(Object.freeze({}) as never)).resolves.toEqual({
      ok: false,
      reason: "ENFORCEMENT_UNAVAILABLE",
      terminal: "hold",
      retryable: false,
      process_started: false,
      detail: "S37 local product probe requires the current process host to be Linux.",
    });
  });

  it("runs the exact fresh same-host admission once through the trusted local capability", async () => {
    const fixture = validProductInput();
    const expected = Object.freeze({
      ok: true as const,
      process_started: true as const,
      exit_code: 0,
      signal: null,
      timed_out: false,
      kill_attempted: false,
      reaped: true,
      forbidden_effect_denied: false,
      outcome_ambiguous: false,
      stdout: new Uint8Array(),
      stderr: new Uint8Array(),
    });
    const start = vi.fn(async () => expected);
    const run = createS37LocalLinuxProductProbeV02(Object.freeze({
      observe: vi.fn(async () => fixture.observation),
      start,
    }));

    await expect(run(fixture.input)).resolves.toMatchObject({
      ok: true,
      terminal: "completed",
      process_started: true,
      exit_code: 0,
    });
    expect(start).toHaveBeenCalledTimes(1);
    expect(start.mock.calls[0]?.[0]).toMatchObject({
      executable: { path: "/opt/loopeix/s37.1/probe" },
      tuple: fixture.input.conformance_tuple,
      receipt: fixture.input.backend_receipt,
    });
  });

  it("holds before runtime on every local-host, binding, artifact, or launch-window drift", async () => {
    type Observation = ReturnType<typeof validProductInput>["observation"];
    const cases: ReadonlyArray<readonly [string, (observation: Observation) => unknown]> = [
      ["platform", (value) => ({ ...value, platform: "darwin" })],
      ["architecture", (value) => ({ ...value, architecture: "aarch64" })],
      ["kernel", (value) => ({ ...value, kernel_release: "6.12.102" })],
      ["systemd", (value) => ({ ...value, systemd_version: "258" })],
      ["cgroup", (value) => ({ ...value, cgroup_version: "v1" })],
      ["host identity", (value) => ({ ...value, binding: { ...value.binding, host_identity_hash: H } })],
      ["host role", (value) => ({ ...value, binding: { ...value.binding, host_role: "conformance" } })],
      ["transport", (value) => ({ ...value, binding: { ...value.binding, transport: "remote" } })],
      ["tuple binding", (value) => ({ ...value, binding: { ...value.binding, conformance_tuple_hash: H } })],
      ["receipt binding", (value) => ({ ...value, binding: { ...value.binding, backend_receipt_hash: H } })],
      ["phase b manifest", (value) => ({ ...value, binding: { ...value.binding, phase_b_manifest_sha256: H2 } })],
      ["phase b manifest resealed", (value) => {
        const drifted = { ...value, binding: { ...value.binding, phase_b_manifest_sha256: H2 } };
        return { ...drifted, binding: { ...drifted.binding, binding_hash: resealedBindingHash(drifted) } };
      }],
      ["binding hash", (value) => ({ ...value, binding: { ...value.binding, binding_hash: H } })],
      ["binding expiry", (value) => ({ ...value, binding: { ...value.binding, expires_at: "2026-08-22T12:00:44Z" } })],
      ["supervisor", (value) => ({ ...value, artifacts: { ...value.artifacts, supervisor: { ...value.artifacts.supervisor, sha256: H2 } } })],
      ["probe", (value) => ({ ...value, artifacts: { ...value.artifacts, probe: { ...value.artifacts.probe, sha256: H2 } } })],
      ["bubblewrap", (value) => ({ ...value, artifacts: { ...value.artifacts, bwrap: { ...value.artifacts.bwrap, version: "0.12.0" } } })],
      ["seccomp", (value) => ({ ...value, artifacts: { ...value.artifacts, seccomp_policy_sha256: H2 } })],
      ["cwd", (value) => ({ ...value, artifacts: { ...value.artifacts, cwd_identity_hash: H } })],
      ["launch window", (value) => ({ ...value, observed_at: "2026-08-22T12:00:43Z" })],
    ];

    for (const [name, drift] of cases) {
      const fixture = validProductInput();
      const observation = drift(fixture.observation);
      const start = vi.fn();
      const run = createS37LocalLinuxProductProbeV02(Object.freeze({
        observe: vi.fn(async () => observation),
        start,
      }));
      const result = await run(fixture.input);
      expect(result, name).toMatchObject({
        ok: false,
        reason: "ENFORCEMENT_UNAVAILABLE",
        process_started: false,
        retryable: false,
      });
      expect(start, name).not.toHaveBeenCalled();
    }
  });

  it("consumes the admission but confirms not-started when local truth drifts at launch time", async () => {
    const fixture = validProductInput();
    const drifted = structuredClone(fixture.observation);
    drifted.artifacts.supervisor.sha256 = H2;
    const observe = vi.fn()
      .mockResolvedValueOnce(fixture.observation)
      .mockResolvedValueOnce(drifted);
    const start = vi.fn();
    const run = createS37LocalLinuxProductProbeV02(Object.freeze({ observe, start }));

    await expect(run(fixture.input)).resolves.toMatchObject({
      ok: false,
      reason: "SPAWN_FAILED",
      process_started: false,
      retryable: false,
    });
    expect(observe).toHaveBeenCalledTimes(2);
    expect(start).not.toHaveBeenCalled();
  });

  it("admits only one concurrent local product probe and never queues or retries another", async () => {
    const fixture = validProductInput();
    let finish: ((value: {
      ok: true;
      process_started: true;
      exit_code: number;
      signal: null;
      timed_out: false;
      kill_attempted: false;
      reaped: true;
      forbidden_effect_denied: false;
      outcome_ambiguous: false;
      stdout: Uint8Array;
      stderr: Uint8Array;
    }) => void) | undefined;
    const start = vi.fn(() => new Promise((resolve) => { finish = resolve; }));
    const run = createS37LocalLinuxProductProbeV02(Object.freeze({
      observe: vi.fn(async () => fixture.observation),
      start,
    }));

    const first = run(fixture.input);
    await vi.waitFor(() => expect(start).toHaveBeenCalledTimes(1));
    await expect(run(fixture.input)).resolves.toMatchObject({
      ok: false,
      reason: "ENFORCEMENT_UNAVAILABLE",
      process_started: false,
      retryable: false,
    });
    expect(start).toHaveBeenCalledTimes(1);
    if (finish === undefined) throw new Error("runtime fixture did not start");
    finish({
      ok: true,
      process_started: true,
      exit_code: 0,
      signal: null,
      timed_out: false,
      kill_attempted: false,
      reaped: true,
      forbidden_effect_denied: false,
      outcome_ambiguous: false,
      stdout: new Uint8Array(),
      stderr: new Uint8Array(),
    });
    await expect(first).resolves.toMatchObject({ ok: true, terminal: "completed" });
  });

  it("builds one exact local Type=exec transient-service invocation without a shell or transport", () => {
    const invocation = buildS37SystemdRunInvocationV02("loopeix-s37-product-v02", 1001);
    expect(invocation).toEqual({
      command: "/usr/bin/systemd-run",
      args: [
        "--user", "--quiet", "--unit=loopeix-s37-product-v02",
        "--service-type=exec", "--wait", "--collect",
        "--property=StandardInput=null", "--property=StandardOutput=null", "--property=StandardError=null",
        "--property=NoNewPrivileges=yes", "--property=KillMode=control-group", "--property=PrivateNetwork=yes",
        "--property=CapabilityBoundingSet=", "--property=CPUQuota=25%", "--property=MemoryMax=64000000",
        "--property=TasksMax=8", "--property=IOWeight=10", "--property=RuntimeMaxSec=2s",
        "/opt/loopeix/s37.1/supervisor", "/opt/loopeix/s37.1/bwrap", "/opt/loopeix/s37.1/probe",
      ],
      options: {
        cwd: "/",
        env: {
          XDG_RUNTIME_DIR: "/run/user/1001",
          DBUS_SESSION_BUS_ADDRESS: "unix:path=/run/user/1001/bus",
        },
        shell: false,
        stdio: "ignore",
        windowsHide: true,
      },
    });
    expect(invocation.args).not.toContain("--scope");
    expect(invocation.args).not.toContain("--pipe");
    expect(JSON.stringify(invocation)).not.toMatch(/ssh|scp|sftp|https?:|vps/iu);
  });

  it("requires authority to cover the complete worst-case controller path", async () => {
    const fixture = validProductInput();
    const observation = {
      ...fixture.observation,
      observed_at: "2026-08-22T12:00:30.001Z",
    };
    const start = vi.fn();
    const run = createS37LocalLinuxProductProbeV02(Object.freeze({
      observe: vi.fn(async () => observation),
      start,
    }));

    await expect(run(fixture.input)).resolves.toMatchObject({
      ok: false,
      reason: "ENFORCEMENT_UNAVAILABLE",
      process_started: false,
      retryable: false,
    });
    expect(start).not.toHaveBeenCalled();
  });
});
