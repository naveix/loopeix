import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";

const runtime = vi.hoisted(() => ({
  platform: "linux" as NodeJS.Platform,
  files: new Map<string, Uint8Array>(),
  readHooks: new Map<string, Array<() => void>>(),
  directories: new Set<string>(),
  sockets: new Set<string>(),
  symlinks: new Set<string>(),
  uidOverrides: new Map<string, number>(),
  modeOverrides: new Map<string, number>(),
  spawnCalls: [] as Array<{ command: string; args: string[]; options: Record<string, unknown> }>,
  killCalls: [] as Array<{ command: string; signal: string }>,
  spawnBehavior: "pass" as "pass" | "nonzero" | "error" | "throw" | "timeout" | "timeout-reaped",
  systemctlBehaviors: [] as Array<"pass" | "oversize" | "error" | "throw" | "timeout" | "timeout-reaped" | "multiline">,
  managerVersion: "257 (257.13-1~deb13u1)",
  managerVersions: [] as string[],
  controllerUid: 0,
}));

vi.mock("node:os", () => ({
  arch: () => "x64",
  platform: () => runtime.platform,
  release: () => "6.12.101+deb13-amd64",
}));

vi.mock("node:fs", () => ({
  lstatSync: (path: string) => {
    const bytes = runtime.files.get(path);
    const directory = runtime.directories.has(path);
    const socket = runtime.sockets.has(path);
    if (bytes === undefined && !directory && !socket) throw new Error(`ENOENT: ${path}`);
    const defaultMode = path === "/etc/loopeix/s37.1/local-product-binding.json"
      || path === "/etc/machine-id"
      || path === "/sys/fs/cgroup/cgroup.controllers"
      ? 0o444
      : path === "/usr/bin/systemd-run" || path === "/usr/bin/systemctl" ? 0o755 : 0o555;
    const modeByPath = runtime.modeOverrides.get(path) ?? defaultMode;
    const directoryMode = runtime.modeOverrides.get(path)
      ?? (path === `/run/user/${runtime.controllerUid}` ? 0o700 : 0o755);
    return {
      dev: 1,
      ino: directory ? runtime.directories.size + path.length : runtime.files.size + path.length,
      mode: directory ? 0o40000 | directoryMode : socket ? 0o140600 : 0o100000 | modeByPath,
      nlink: 1,
      uid: runtime.uidOverrides.get(path) ?? (path === `/run/user/${runtime.controllerUid}` || socket ? runtime.controllerUid : 0),
      gid: 0,
      size: path === "/sys/fs/cgroup/cgroup.controllers" ? 0 : bytes?.byteLength ?? 0,
      mtimeMs: 1,
      ctimeMs: 1,
      isFile: () => !directory,
      isDirectory: () => directory,
      isSocket: () => socket,
      isSymbolicLink: () => runtime.symlinks.has(path),
    };
  },
  readFileSync: (path: string) => {
    const bytes = runtime.files.get(path);
    if (bytes === undefined) throw new Error(`ENOENT: ${path}`);
    const hooks = runtime.readHooks.get(path);
    const hook = hooks?.shift();
    if (hooks?.length === 0) runtime.readHooks.delete(path);
    hook?.();
    return Buffer.from(bytes);
  },
}));

vi.mock("node:crypto", async () => {
  const actual = await vi.importActual<typeof import("node:crypto")>("node:crypto");
  return { ...actual, randomBytes: () => Buffer.from("0123456789abcdef", "hex") };
});

vi.mock("node:child_process", () => ({
  spawn: (command: string, args: string[], options: Record<string, unknown>) => {
    const behavior = command === "/usr/bin/systemctl"
      ? runtime.systemctlBehaviors.shift() ?? "pass"
      : runtime.spawnBehavior;
    if (behavior === "throw") throw new Error(`${command} throw`);
    runtime.spawnCalls.push({ command, args, options });
    const child = new EventEmitter() as EventEmitter & {
      pid?: number;
      kill(signal: string): boolean;
      stdout: EventEmitter;
    };
    child.stdout = new EventEmitter();
    if (behavior !== "error" || command === "/usr/bin/systemctl") child.pid = 1234;
    child.kill = (signal) => {
      runtime.killCalls.push({ command, signal });
      if (behavior === "timeout-reaped") queueMicrotask(() => child.emit("close", null, signal));
      return true;
    };
    queueMicrotask(() => {
      if (command === "/usr/bin/systemctl") {
        const managerVersion = runtime.managerVersions.shift() ?? runtime.managerVersion;
        if (behavior === "oversize") child.stdout.emit("data", Buffer.alloc(257, 0x61));
        else if (behavior === "multiline") child.stdout.emit("data", Buffer.from(`${managerVersion}\nunexpected\n`));
        else if (behavior === "error") child.emit("error", new Error("systemctl failed"));
        else if (behavior === "pass") child.stdout.emit("data", Buffer.from(`${managerVersion}\n`));
        if (behavior === "pass" || behavior === "oversize" || behavior === "multiline") child.emit("close", 0, null);
      } else if (behavior === "error") child.emit("error", new Error("spawn failed"));
      else if (behavior === "pass" || behavior === "nonzero") child.emit("close", behavior === "pass" ? 0 : 81, null);
    });
    return child;
  },
}));

import { hashCanonical, hashRawBytes } from "../../src/hash.js";
import {
  S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
  simulateAuthorityDecisionV02,
} from "../../src/run/action-classifier-policy-v02.js";
import { runS37LocalLinuxProductProbeV02 } from "../../src/run/linux-host-enforcement-v02.js";
import { buildS37ActionInterpositionProfileV02 } from "../../src/run/pre-spawn-capability-broker-v02.js";

const H = `sha256:${"a".repeat(64)}`;
const H2 = `sha256:${"b".repeat(64)}`;
const DENY_ROWS = [
  "ambient-credentials", "child-process", "durable-state", "environment",
  "filesystem-write", "network", "output-limits", "retry", "stdin",
  "timeout", "tool-server", "unknown-outcome",
] as const;

function resealInstalledBinding(update: (binding: Record<string, unknown>) => void): void {
  const path = "/etc/loopeix/s37.1/local-product-binding.json";
  const binding = JSON.parse(Buffer.from(runtime.files.get(path) ?? []).toString("utf8")) as Record<string, unknown>;
  update(binding);
  binding.binding_hash = hashCanonical({
    purpose: "s37-local-product-binding-v02",
    ...Object.fromEntries(Object.entries(binding).filter(([key]) => key !== "binding_hash")),
  });
  runtime.files.set(path, Buffer.from(JSON.stringify(binding)));
}

function installFixture() {
  runtime.readHooks.clear();
  runtime.managerVersion = "257 (257.13-1~deb13u1)";
  runtime.managerVersions.length = 0;
  runtime.systemctlBehaviors.length = 0;
  runtime.controllerUid = typeof process.getuid === "function" ? process.getuid() : 501;
  for (const path of [
    "/etc", "/etc/loopeix", "/etc/loopeix/s37.1",
    "/opt", "/opt/loopeix", "/opt/loopeix/s37.1",
    "/usr", "/usr/bin", "/sys", "/sys/fs", "/sys/fs/cgroup",
  ]) runtime.directories.add(path);
  const supervisor = Buffer.from("s37-supervisor");
  const probe = Buffer.from("s37-probe");
  const bwrap = Buffer.from("s37-bwrap");
  const systemdRun = Buffer.from("systemd-run");
  const systemctl = Buffer.from("systemctl");
  runtime.files.set("/etc/machine-id", Buffer.from("local-machine-id\n"));
  runtime.files.set("/sys/fs/cgroup/cgroup.controllers", Buffer.from("cpu io memory pids\n"));
  runtime.files.set("/opt/loopeix/s37.1/supervisor", supervisor);
  runtime.files.set("/opt/loopeix/s37.1/probe", probe);
  runtime.files.set("/opt/loopeix/s37.1/bwrap", bwrap);
  runtime.files.set("/usr/bin/systemd-run", systemdRun);
  runtime.files.set("/usr/bin/systemctl", systemctl);
  runtime.directories.add(`/run/user/${runtime.controllerUid}`);
  runtime.sockets.add(`/run/user/${runtime.controllerUid}/bus`);

  const now = Date.now();
  const tupleObservedAt = new Date(now - 1_000).toISOString();
  const issuedAt = new Date(now - 500).toISOString();
  const expiresAt = new Date(now + 45_000).toISOString();
  const decisionInput = {
    proposal: {
      action_proposal_id: "proposal_s37_product_runtime",
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
    authority: { envelope_verified: true, contained: true, proof_fresh: true, revocation_epoch_current: true },
    enforcement: { available: true, information_flow_allowed: true, gates_passed: true, immediate_revalidation_passed: true },
    condition_results: [],
    issued_at: issuedAt,
    expires_at: new Date(now + 60_000).toISOString(),
    fence_epoch: 0,
  } as const;
  const decision = simulateAuthorityDecisionV02(decisionInput);
  if (!decision.ok || decision.value.simulated_lease === null) throw new Error("invalid decision fixture");
  const profile = buildS37ActionInterpositionProfileV02({
    actor_identity_hash: H,
    on_behalf_of_chain_hash: H,
    executable: { path: "/opt/loopeix/s37.1/probe", sha256: hashRawBytes(probe) },
    cwd: { path: "/", identity_hash: hashCanonical({ purpose: "s37-phase-b-cwd-identity-v1", path: "/" }) },
  });
  const tuple = {
    tuple_version: "0.1" as const,
    platform: "linux" as const,
    architecture: "x86_64",
    kernel_release: "6.12.101+deb13-amd64",
    systemd_version: "257 (257.13-1~deb13u1)",
    cgroup_version: "v2" as const,
    observed_at: tupleObservedAt,
  };
  const receiptWithoutHash = {
    receipt_version: "0.1" as const,
    host_tuple_hash: hashCanonical({ purpose: "s37-linux-host-tuple-v02", ...tuple }),
    profile_hash: hashCanonical(profile),
    launcher_sha256: hashRawBytes(supervisor),
    bwrap: { path: "/opt/loopeix/s37.1/bwrap", version: "0.11.0", sha256: hashRawBytes(bwrap), setuid: false as const },
    seccomp_policy_sha256: H,
    deny_rows: [...DENY_ROWS],
    skipped_rows: [] as const,
    issued_at: issuedAt,
    expires_at: expiresAt,
  };
  const receipt = {
    ...receiptWithoutHash,
    receipt_hash: hashCanonical({ purpose: "s37-linux-backend-identity-receipt-v02", ...receiptWithoutHash }),
  };
  const bindingWithoutHash = {
    schema_version: "s37-local-product-binding-v02" as const,
    host_role: "local-product" as const,
    transport: "local-only" as const,
    host_identity_hash: hashRawBytes(Buffer.from("local-machine-id")),
    controller_uid: runtime.controllerUid,
    conformance_tuple_hash: receipt.host_tuple_hash,
    backend_receipt_hash: receipt.receipt_hash,
    phase_b_manifest_sha256: H,
    expires_at: expiresAt,
    systemd_version: tuple.systemd_version,
    artifacts: {
      supervisor_sha256: hashRawBytes(supervisor),
      probe_sha256: hashRawBytes(probe),
      bwrap_sha256: hashRawBytes(bwrap),
      bwrap_version: "0.11.0",
      systemd_run_sha256: hashRawBytes(systemdRun),
      systemctl_sha256: hashRawBytes(systemctl),
      seccomp_policy_sha256: H,
      cwd_identity_hash: profile.cwd.identity_hash,
    },
  };
  const binding = {
    ...bindingWithoutHash,
    binding_hash: hashCanonical({ purpose: "s37-local-product-binding-v02", ...bindingWithoutHash }),
  };
  runtime.files.set("/etc/loopeix/s37.1/local-product-binding.json", Buffer.from(JSON.stringify(binding)));
  return {
    decision_input: decisionInput,
    decision: decision.value,
    simulated_lease: decision.value.simulated_lease,
    profile,
    conformance_tuple: tuple,
    backend_receipt: receipt,
    phase_b_manifest_sha256: H,
  };
}

function resetRuntime(): void {
  runtime.files.clear();
  runtime.readHooks.clear();
  runtime.directories.clear();
  runtime.sockets.clear();
  runtime.symlinks.clear();
  runtime.uidOverrides.clear();
  runtime.modeOverrides.clear();
  runtime.spawnCalls.length = 0;
  runtime.killCalls.length = 0;
  runtime.spawnBehavior = "pass";
  runtime.systemctlBehaviors.length = 0;
}

describe("S37.1-C concrete local Linux runtime", () => {
  it("rejects root controller execution before observing or starting a process", async () => {
    const getuid = vi.spyOn(process, "getuid").mockReturnValue(0);
    try {
      runtime.files.clear();
      runtime.directories.clear();
      runtime.sockets.clear();
      runtime.symlinks.clear();
      runtime.uidOverrides.clear();
      runtime.modeOverrides.clear();
      runtime.spawnCalls.length = 0;
      runtime.spawnBehavior = "pass";
      const input = installFixture();

      await expect(runS37LocalLinuxProductProbeV02(input)).resolves.toMatchObject({
        ok: false,
        reason: "ENFORCEMENT_UNAVAILABLE",
        process_started: false,
      });
      expect(runtime.spawnCalls).toHaveLength(0);
    } finally {
      getuid.mockRestore();
    }
  });

  it("rejects live systemd manager drift while the binding remains unchanged", async () => {
    runtime.files.clear();
    runtime.directories.clear();
    runtime.sockets.clear();
    runtime.symlinks.clear();
    runtime.uidOverrides.clear();
    runtime.modeOverrides.clear();
    runtime.spawnCalls.length = 0;
    runtime.spawnBehavior = "pass";
    const input = installFixture();
    runtime.managerVersion = "258 (258.1)";

    await expect(runS37LocalLinuxProductProbeV02(input)).resolves.toMatchObject({
      ok: false,
      reason: "SPAWN_FAILED",
      process_started: false,
      retryable: false,
      detail: "S37 local systemd manager version drifted before controller invocation.",
    });
    expect(runtime.spawnCalls.filter(({ command }) => command === "/usr/bin/systemctl")).toHaveLength(1);
    expect(runtime.spawnCalls.filter(({ command }) => command === "/usr/bin/systemd-run")).toHaveLength(0);
  });

  it("rejects systemd manager drift at launch-time revalidation", async () => {
    runtime.files.clear();
    runtime.directories.clear();
    runtime.sockets.clear();
    runtime.symlinks.clear();
    runtime.uidOverrides.clear();
    runtime.modeOverrides.clear();
    runtime.spawnCalls.length = 0;
    runtime.spawnBehavior = "pass";
    const input = installFixture();
    runtime.managerVersions.push("257 (257.13-1~deb13u1)", "258 (258.1)");

    await expect(runS37LocalLinuxProductProbeV02(input)).resolves.toMatchObject({
      ok: false,
      reason: "OUTCOME_UNKNOWN",
      process_started: true,
      retryable: false,
    });
    expect(runtime.spawnCalls.filter(({ command }) => command === "/usr/bin/systemd-run")).toHaveLength(1);
    expect(runtime.spawnCalls.filter(({ command }) => command === "/usr/bin/systemctl")).toHaveLength(2);
  });

  it("revalidates fixed local files and invokes exactly one bounded transient service", async () => {
    runtime.files.clear();
    runtime.directories.clear();
    runtime.sockets.clear();
    runtime.symlinks.clear();
    runtime.uidOverrides.clear();
    runtime.modeOverrides.clear();
    runtime.spawnCalls.length = 0;
    runtime.spawnBehavior = "pass";
    const input = installFixture();

    await expect(runS37LocalLinuxProductProbeV02(input)).resolves.toMatchObject({
      ok: true,
      terminal: "completed",
      process_started: true,
      exit_code: 0,
    });
    const systemdRunCalls = runtime.spawnCalls.filter(({ command }) => command === "/usr/bin/systemd-run");
    expect(systemdRunCalls).toHaveLength(1);
    expect(systemdRunCalls[0]).toMatchObject({
      command: "/usr/bin/systemd-run",
      options: {
        cwd: "/",
        env: {
          XDG_RUNTIME_DIR: `/run/user/${runtime.controllerUid}`,
          DBUS_SESSION_BUS_ADDRESS: `unix:path=/run/user/${runtime.controllerUid}/bus`,
        },
        shell: false,
        stdio: "ignore",
      },
    });
    expect(systemdRunCalls[0]?.args.at(-3)).toBe("/opt/loopeix/s37.1/supervisor");
    expect(systemdRunCalls[0]?.args.at(-2)).toBe("/opt/loopeix/s37.1/bwrap");
    expect(systemdRunCalls[0]?.args.at(-1)).toBe("/opt/loopeix/s37.1/probe");
    expect(runtime.spawnCalls.filter(({ command }) => command === "/usr/bin/systemctl")).toHaveLength(2);
  });

  it("reports controller failure after an admitted version check as started and ambiguous", async () => {
    runtime.files.clear();
    runtime.directories.clear();
    runtime.sockets.clear();
    runtime.symlinks.clear();
    runtime.uidOverrides.clear();
    runtime.modeOverrides.clear();
    runtime.spawnCalls.length = 0;
    runtime.spawnBehavior = "error";
    await expect(runS37LocalLinuxProductProbeV02(installFixture())).resolves.toMatchObject({
      ok: false,
      reason: "OUTCOME_UNKNOWN",
      process_started: true,
      retryable: false,
    });

    runtime.files.clear();
    runtime.directories.clear();
    runtime.sockets.clear();
    runtime.symlinks.clear();
    runtime.uidOverrides.clear();
    runtime.modeOverrides.clear();
    runtime.spawnCalls.length = 0;
    runtime.spawnBehavior = "nonzero";
    await expect(runS37LocalLinuxProductProbeV02(installFixture())).resolves.toMatchObject({
      ok: false,
      reason: "OUTCOME_UNKNOWN",
      process_started: true,
      retryable: false,
    });
    expect(runtime.spawnCalls.filter(({ command }) => command === "/usr/bin/systemd-run")).toHaveLength(1);
  });

  it("fails closed when the transient controller spawn throws before systemd-run starts", async () => {
    resetRuntime();
    const input = installFixture();
    runtime.spawnBehavior = "throw";

    await expect(runS37LocalLinuxProductProbeV02(input)).resolves.toMatchObject({
      ok: false,
      reason: "SPAWN_FAILED",
      process_started: false,
      retryable: false,
      detail: "S37 local transient-unit controller could not be invoked.",
    });
    expect(runtime.spawnCalls.filter(({ command }) => command === "/usr/bin/systemctl")).toHaveLength(1);
    expect(runtime.spawnCalls.filter(({ command }) => command === "/usr/bin/systemd-run")).toHaveLength(0);
  });

  it.each([
    ["oversize output", "oversize"],
    ["spawn error", "error"],
    ["spawn throw", "throw"],
    ["multiline output", "multiline"],
  ] as const)("fails closed on systemctl %s without launching or retrying", async (_name, behavior) => {
    resetRuntime();
    const input = installFixture();
    runtime.systemctlBehaviors.push(behavior);

    await expect(runS37LocalLinuxProductProbeV02(input)).resolves.toMatchObject({
      ok: false,
      reason: "SPAWN_FAILED",
      process_started: false,
      retryable: false,
      detail: "S37 local systemd manager could not be observed before controller invocation.",
    });
    expect(runtime.spawnCalls.filter(({ command }) => command === "/usr/bin/systemctl")).toHaveLength(
      behavior === "throw" ? 0 : 1,
    );
    expect(runtime.spawnCalls.filter(({ command }) => command === "/usr/bin/systemd-run")).toHaveLength(0);
    if (behavior === "oversize") {
      expect(runtime.killCalls).toEqual([{ command: "/usr/bin/systemctl", signal: "SIGKILL" }]);
    }
  });

  it.each([
    ["is reaped after cancellation", "timeout-reaped"],
    ["does not report reaping before the reap deadline", "timeout"],
  ] as const)("fails closed when systemctl times out and %s", async (_name, behavior) => {
    vi.useFakeTimers();
    try {
      resetRuntime();
      const input = installFixture();
      runtime.systemctlBehaviors.push(behavior);

      const pending = runS37LocalLinuxProductProbeV02(input);
      await vi.runAllTimersAsync();
      await expect(pending).resolves.toMatchObject({
        ok: false,
        reason: "SPAWN_FAILED",
        process_started: false,
        retryable: false,
        detail: "S37 local systemd manager could not be observed before controller invocation.",
      });
      expect(runtime.spawnCalls.filter(({ command }) => command === "/usr/bin/systemctl")).toHaveLength(1);
      expect(runtime.spawnCalls.filter(({ command }) => command === "/usr/bin/systemd-run")).toHaveLength(0);
      expect(runtime.killCalls).toEqual([{ command: "/usr/bin/systemctl", signal: "SIGKILL" }]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("fails closed on a systemd-run timeout, reaps once, and never retries", async () => {
    vi.useFakeTimers();
    try {
      resetRuntime();
      runtime.spawnBehavior = "timeout";
      const pending = runS37LocalLinuxProductProbeV02(installFixture());

      await vi.runAllTimersAsync();
      await expect(pending).resolves.toMatchObject({
        ok: false,
        reason: "OUTCOME_UNKNOWN",
        process_started: true,
        retryable: false,
      });
      expect(runtime.spawnCalls.filter(({ command }) => command === "/usr/bin/systemctl")).toHaveLength(1);
      expect(runtime.spawnCalls.filter(({ command }) => command === "/usr/bin/systemd-run")).toHaveLength(1);
      expect(runtime.killCalls).toEqual([{ command: "/usr/bin/systemd-run", signal: "SIGKILL" }]);

      await vi.runAllTimersAsync();
      expect(runtime.spawnCalls.filter(({ command }) => command === "/usr/bin/systemd-run")).toHaveLength(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("fails closed on a nonzero systemd-run exit and never retries", async () => {
    resetRuntime();
    runtime.spawnBehavior = "nonzero";

    await expect(runS37LocalLinuxProductProbeV02(installFixture())).resolves.toMatchObject({
      ok: false,
      reason: "OUTCOME_UNKNOWN",
      process_started: true,
      retryable: false,
    });
    expect(runtime.spawnCalls.filter(({ command }) => command === "/usr/bin/systemctl")).toHaveLength(1);
    expect(runtime.spawnCalls.filter(({ command }) => command === "/usr/bin/systemd-run")).toHaveLength(1);
  });

  it.each([
    ["non-root ownership", () => { runtime.uidOverrides.set("/opt/loopeix", runtime.controllerUid); }],
    ["group-writable mode", () => { runtime.modeOverrides.set("/opt/loopeix", 0o775); }],
    ["symlink substitution", () => { runtime.symlinks.add("/opt/loopeix"); }],
  ] as const)("rejects trusted-directory %s before observing or starting a process", async (_name, drift) => {
    resetRuntime();
    const input = installFixture();
    drift();

    await expect(runS37LocalLinuxProductProbeV02(input)).resolves.toMatchObject({
      ok: false,
      reason: "ENFORCEMENT_UNAVAILABLE",
      process_started: false,
      retryable: false,
    });
    expect(runtime.spawnCalls).toHaveLength(0);
  });

  it("rejects systemctl artifact drift before observing or starting a process", async () => {
    resetRuntime();
    const input = installFixture();
    runtime.files.set("/usr/bin/systemctl", Buffer.from("replaced"));

    await expect(runS37LocalLinuxProductProbeV02(input)).resolves.toMatchObject({
      ok: false,
      reason: "ENFORCEMENT_UNAVAILABLE",
      process_started: false,
      retryable: false,
    });
    expect(runtime.spawnCalls).toHaveLength(0);
  });

  it("rejects launch-time phase B manifest drift even when the binding self-hash is recomputed", async () => {
    resetRuntime();
    const input = installFixture();
    runtime.readHooks.set("/usr/bin/systemctl", [() => {
      resealInstalledBinding((binding) => {
        binding.phase_b_manifest_sha256 = H2;
      });
    }]);

    await expect(runS37LocalLinuxProductProbeV02(input)).resolves.toMatchObject({
      ok: false,
      reason: "SPAWN_FAILED",
      process_started: false,
      retryable: false,
      detail: "S37 local-product binding drifted from the host or backend receipt.",
    });
    expect(runtime.spawnCalls).toHaveLength(0);
  });

  it("holds before invocation on local binding, host, cgroup, artifact, or controller drift", async () => {
    const cases: ReadonlyArray<readonly [string, () => void]> = [
      ["missing binding", () => { runtime.files.delete("/etc/loopeix/s37.1/local-product-binding.json"); }],
      ["binding self hash", () => {
        const path = "/etc/loopeix/s37.1/local-product-binding.json";
        const binding = JSON.parse(Buffer.from(runtime.files.get(path) ?? []).toString("utf8")) as Record<string, unknown>;
        binding.binding_hash = H;
        runtime.files.set(path, Buffer.from(JSON.stringify(binding)));
      }],
      ["phase b manifest resealed", () => {
        resealInstalledBinding((binding) => {
          binding.phase_b_manifest_sha256 = H2;
        });
      }],
      ["machine identity", () => { runtime.files.set("/etc/machine-id", Buffer.from("another-machine\n")); }],
      ["cgroup controller", () => { runtime.files.set("/sys/fs/cgroup/cgroup.controllers", Buffer.from("cpu memory pids\n")); }],
      ["supervisor bytes", () => { runtime.files.set("/opt/loopeix/s37.1/supervisor", Buffer.from("replaced")); }],
      ["systemd-run bytes", () => { runtime.files.set("/usr/bin/systemd-run", Buffer.from("replaced")); }],
      ["binding mode", () => { runtime.modeOverrides.set("/etc/loopeix/s37.1/local-product-binding.json", 0o644); }],
      ["artifact symlink", () => { runtime.symlinks.add("/opt/loopeix/s37.1/bwrap"); }],
      ["runtime ownership", () => { runtime.uidOverrides.set(`/run/user/${runtime.controllerUid}`, 0); }],
      ["missing user bus", () => { runtime.sockets.delete(`/run/user/${runtime.controllerUid}/bus`); }],
    ];

    for (const [name, drift] of cases) {
      runtime.files.clear();
      runtime.directories.clear();
      runtime.sockets.clear();
      runtime.symlinks.clear();
      runtime.uidOverrides.clear();
      runtime.modeOverrides.clear();
      runtime.spawnCalls.length = 0;
      runtime.spawnBehavior = "pass";
      const input = installFixture();
      drift();
      const result = await runS37LocalLinuxProductProbeV02(input);
      expect(result, name).toMatchObject({
        ok: false,
        reason: "ENFORCEMENT_UNAVAILABLE",
        process_started: false,
        retryable: false,
      });
      expect(runtime.spawnCalls.filter(({ command }) => command === "/usr/bin/systemd-run"), name).toHaveLength(0);
    }
  });
});
