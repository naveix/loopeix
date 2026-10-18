import { EventEmitter } from "node:events";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import * as hashFunctions from "../../src/hash.js";

const mocks = vi.hoisted(() => ({ spawn: vi.fn() }));
vi.mock("node:child_process", () => ({ spawn: mocks.spawn }));

import {
  claimS37ProductHostLaunchPermitV01,
  createS37ProductHostBrokerLifecycleV01,
  enterS37ProductHostLaunchBrokerV01,
  mintS37ProductHostLaunchPermitV01,
  reduceS37ProductHostBrokerLifecycleV01,
} from "../../src/run/s37-product-host-launch-broker-v01.js";

const H = (character: string): string => `sha256:${character.repeat(64)}`;

class MockChild extends EventEmitter {
  readonly pid = 1234;
  readonly stdout = new EventEmitter();
  readonly stderr = new EventEmitter();
  readonly kill = vi.fn();
  readonly unref = vi.fn();
}

function exactArgv(): readonly string[] {
  return [
    "--system", "--quiet", "--unit=loopeix-s37-product-activation-v01", "--service-type=exec", "--wait", "--collect",
    "--property=User=1001", "--property=Group=1001", "--property=SupplementaryGroups=", "--property=WorkingDirectory=/",
    "--property=StandardInput=null", "--property=StandardOutput=null", "--property=StandardError=null",
    "--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=", "--property=AmbientCapabilities=",
    "--property=KillMode=control-group", "--property=PrivateNetwork=yes", "--property=CPUQuota=25%",
    "--property=MemoryMax=64000000", "--property=TasksMax=8", "--property=IOWeight=10", "--property=RuntimeMaxSec=2s",
    "/opt/loopeix/s37.1/supervisor", "/opt/loopeix/s37.1/bwrap", "/opt/loopeix/s37.1/probe",
  ];
}

function permitBinding(validUntil = "2099-01-01T00:00:00Z") {
  return {
    activation_id: `activation_${"a".repeat(64)}`,
    fence_epoch: 1,
    event_five_hash: H("1"),
    manifest_hash: H("2"),
    launch_admission_hash: H("3"),
    broker_request_hash: H("4"),
    conformance_receipt_hash: H("5"),
    trial_evidence_hash: H("6"),
    post_commit_authorization_revalidation_hash: H("7"),
    post_commit_authorization_valid_until: validUntil,
    exact_argv_hash: H("8"),
    manager_version_before_observation_hash: H("9"),
    manager_version_before: "systemd 257 (257.5-2)",
    controller_uid: 1001,
    primary_gid: 1001,
    unit_name_hash: H("a"),
    cgroup_path_hash: H("b"),
  };
}

describe("S37.1-G launch broker lifecycle", () => {
  it("fails closed when close ties the absolute broker deadline", () => {
    const initial = createS37ProductHostBrokerLifecycleV01(10_000);
    const result = reduceS37ProductHostBrokerLifecycleV01(initial, {
      type: "close",
      at: 15_000,
      exit_code: 0,
      signal: null,
    });

    expect(result).toEqual({
      phase: "TERMINAL",
      started_at: 10_000,
      deadline_at: 15_000,
      close_at: null,
      after_observation_deadline_at: null,
      exit_code: null,
      signal: null,
      result: "OUTCOME_UNKNOWN",
    });
  });

  it("keeps the absolute deadline live through manager-after validation", () => {
    const initial = createS37ProductHostBrokerLifecycleV01(10_000);
    const closed = reduceS37ProductHostBrokerLifecycleV01(initial, {
      type: "close", at: 14_500, exit_code: 0, signal: null,
    });
    expect(closed.phase).toBe("WAITING_FOR_MANAGER_AFTER");
    expect(closed.after_observation_deadline_at).toBe(15_000);
    expect(reduceS37ProductHostBrokerLifecycleV01(closed, { type: "manager-after-ok", at: 14_999 }).result)
      .toBe("ENTERED_AND_COMPLETED");
    expect(reduceS37ProductHostBrokerLifecycleV01(closed, { type: "manager-after-ok", at: 15_000 }).result)
      .toBe("OUTCOME_UNKNOWN");
  });

  it("is terminal and idempotent after any ambiguous child result", () => {
    const initial = createS37ProductHostBrokerLifecycleV01(10_000);
    const failed = reduceS37ProductHostBrokerLifecycleV01(initial, {
      type: "close", at: 10_100, exit_code: 1, signal: null,
    });
    expect(failed.result).toBe("OUTCOME_UNKNOWN");
    expect(reduceS37ProductHostBrokerLifecycleV01(failed, {
      type: "close", at: 10_200, exit_code: 0, signal: null,
    })).toBe(failed);
  });

  it("never treats exit without close as completion", () => {
    const initial = createS37ProductHostBrokerLifecycleV01(10_000);
    const exited = reduceS37ProductHostBrokerLifecycleV01(initial, {
      type: "exit", at: 10_100, exit_code: 0, signal: null,
    });
    expect(exited).toBe(initial);
    expect(reduceS37ProductHostBrokerLifecycleV01(exited, { type: "deadline", at: 15_000 }).result)
      .toBe("OUTCOME_UNKNOWN");
  });

  it("fails closed when the post-close manager observation fails", () => {
    const initial = createS37ProductHostBrokerLifecycleV01(10_000);
    const closed = reduceS37ProductHostBrokerLifecycleV01(initial, {
      type: "close", at: 10_100, exit_code: 0, signal: null,
    });
    expect(reduceS37ProductHostBrokerLifecycleV01(closed, {
      type: "manager-after-failed", at: 10_200,
    }).result).toBe("OUTCOME_UNKNOWN");
  });
});

describe("S37.1-G opaque launch permit", () => {
  it("cannot be cloned, serialized into authority, or claimed twice", () => {
    const permit = mintS37ProductHostLaunchPermitV01(permitBinding());
    expect(permit).not.toBeNull();
    expect(JSON.stringify(permit)).toBe("{}");
    expect(claimS37ProductHostLaunchPermitV01({ ...permit })).toBeNull();
    const claimed = claimS37ProductHostLaunchPermitV01(permit);
    expect(claimed).not.toBeNull();
    expect(claimS37ProductHostLaunchPermitV01(permit)).toBeNull();
  });

  it("consumes an expired claimed permit without entering a process", async () => {
    const permit = mintS37ProductHostLaunchPermitV01(permitBinding("2000-01-01T00:00:00Z"));
    const claimed = claimS37ProductHostLaunchPermitV01(permit);
    expect((await enterS37ProductHostLaunchBrokerV01(claimed)).outcome).toBe("OUTCOME_UNKNOWN");
    expect((await enterS37ProductHostLaunchBrokerV01(claimed)).outcome).toBe("OUTCOME_UNKNOWN");
  });

  it("rejects reordered, extended, or malformed permit bindings", () => {
    const valid = permitBinding();
    const reordered = { fence_epoch: valid.fence_epoch, activation_id: valid.activation_id,
      ...Object.fromEntries(Object.entries(valid).slice(2)) };
    expect(mintS37ProductHostLaunchPermitV01(reordered)).toBeNull();
    expect(mintS37ProductHostLaunchPermitV01({ ...valid, callback: () => undefined })).toBeNull();
    expect(mintS37ProductHostLaunchPermitV01({ ...valid, exact_argv_hash: "not-a-hash" })).toBeNull();
    expect(mintS37ProductHostLaunchPermitV01({ ...valid, fence_epoch: 0 })).toBeNull();
    expect(mintS37ProductHostLaunchPermitV01({
      ...valid, post_commit_authorization_valid_until: "2099-02-31T00:00:00Z",
    })).toBeNull();
  });

  it("exposes exactly one claimed-permit argument at the process boundary", () => {
    expect(enterS37ProductHostLaunchBrokerV01.length).toBe(1);
  });
});

describe("S37.1-G broker deadline enforcement through final evidence construction", () => {
  const authorizationExpiresAt = Date.parse("2026-10-17T10:00:01Z");
  let wallTime: number;
  let monotonicTime: number;

  beforeEach(() => {
    mocks.spawn.mockReset();
    wallTime = authorizationExpiresAt - 1_000;
    monotonicTime = 10_000;
    vi.spyOn(Date, "now").mockImplementation(() => wallTime);
    vi.spyOn(performance, "now").mockImplementation(() => monotonicTime);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it.each([
    { offset: -1, expected: "ENTERED_AND_COMPLETED" },
    { offset: 0, expected: "OUTCOME_UNKNOWN" },
    { offset: 1, expected: "OUTCOME_UNKNOWN" },
  ] as const)("classifies completion at expiry offset $offset ms as $expected", async ({ offset, expected }) => {
    const serviceClient = new MockChild();
    const managerObserver = new MockChild();
    mocks.spawn.mockReturnValueOnce(serviceClient).mockReturnValueOnce(managerObserver);
    const argv = exactArgv();
    const permit = mintS37ProductHostLaunchPermitV01({
      ...permitBinding("2026-10-17T10:00:01Z"),
      exact_argv_hash: hashCanonical({ purpose: "s37-product-host-broker-argv-v01", argv }),
    });
    const claimed = claimS37ProductHostLaunchPermitV01(permit);
    const resultPromise = enterS37ProductHostLaunchBrokerV01(claimed);

    expect(mocks.spawn).toHaveBeenNthCalledWith(1, "/usr/bin/systemd-run", argv, {
      cwd: "/", env: { LANG: "C" }, shell: false, stdio: ["ignore", "ignore", "ignore"],
    });
    monotonicTime = 10_100;
    serviceClient.emit("close", 0, null);
    expect(mocks.spawn).toHaveBeenNthCalledWith(2, "/usr/bin/systemctl", [
      "--system", "show", "--property=Version", "--value", "--no-pager",
    ], { cwd: "/", env: { LANG: "C" }, shell: false, stdio: ["ignore", "pipe", "pipe"] });
    managerObserver.stdout.emit("data", Buffer.from("systemd 257 (257.5-2)\n"));
    monotonicTime = 10_200;
    managerObserver.emit("close", 0, null);
    wallTime = authorizationExpiresAt + offset;

    const result = await resultPromise;
    expect(result.outcome).toBe(expected);
    expect(result.ok).toBe(expected === "ENTERED_AND_COMPLETED");
    if (!result.ok) expect(result).toEqual({ ok: false, outcome: "OUTCOME_UNKNOWN" });
    expect(mocks.spawn).toHaveBeenCalledTimes(2);
    expect(serviceClient.kill).not.toHaveBeenCalled();
    expect(managerObserver.kill).not.toHaveBeenCalled();
    expect(await enterS37ProductHostLaunchBrokerV01(claimed)).toEqual({ ok: false, outcome: "OUTCOME_UNKNOWN" });
    expect(mocks.spawn).toHaveBeenCalledTimes(2);
  });

  it.each([
    { closeAt: 10_100, observedAt: 10_200, completedAt: 11_099, expected: "ENTERED_AND_COMPLETED" },
    { closeAt: 10_100, observedAt: 10_200, completedAt: 11_100, expected: "OUTCOME_UNKNOWN" },
    { closeAt: 10_100, observedAt: 10_200, completedAt: 11_101, expected: "OUTCOME_UNKNOWN" },
    { closeAt: 14_500, observedAt: 14_999, completedAt: 14_999, expected: "ENTERED_AND_COMPLETED" },
    { closeAt: 14_500, observedAt: 14_999, completedAt: 15_000, expected: "OUTCOME_UNKNOWN" },
    { closeAt: 14_500, observedAt: 14_999, completedAt: 15_001, expected: "OUTCOME_UNKNOWN" },
  ] as const)("classifies evidence completion at $completedAt after close $closeAt as $expected", async ({
    closeAt, observedAt, completedAt, expected,
  }) => {
    const realHashCanonical = hashCanonical;
    let evidenceHashes = 0;
    vi.spyOn(hashFunctions, "hashCanonical").mockImplementation((value: unknown) => {
      const digest = realHashCanonical(value);
      if (typeof value === "object" && value !== null && "purpose" in value
        && value.purpose === "s37-product-host-broker-entry-evidence-v01") {
        evidenceHashes += 1;
        monotonicTime = completedAt;
      }
      return digest;
    });
    const serviceClient = new MockChild();
    const managerObserver = new MockChild();
    mocks.spawn.mockReturnValueOnce(serviceClient).mockReturnValueOnce(managerObserver);
    const permit = mintS37ProductHostLaunchPermitV01({
      ...permitBinding("2026-10-17T10:00:01Z"),
      exact_argv_hash: hashCanonical({ purpose: "s37-product-host-broker-argv-v01", argv: exactArgv() }),
    });
    const claimed = claimS37ProductHostLaunchPermitV01(permit);
    const resultPromise = enterS37ProductHostLaunchBrokerV01(claimed);
    monotonicTime = closeAt;
    serviceClient.emit("close", 0, null);
    managerObserver.stdout.emit("data", Buffer.from("systemd 257 (257.5-2)\n"));
    monotonicTime = observedAt;
    managerObserver.emit("close", 0, null);

    const result = await resultPromise;
    expect(evidenceHashes).toBe(1);
    expect(result.outcome).toBe(expected);
    expect(result.ok).toBe(expected === "ENTERED_AND_COMPLETED");
    if (!result.ok) expect(result).toEqual({ ok: false, outcome: "OUTCOME_UNKNOWN" });
    expect(mocks.spawn).toHaveBeenCalledTimes(2);
    expect(serviceClient.kill).not.toHaveBeenCalled();
    expect(managerObserver.kill).not.toHaveBeenCalled();
    expect(await enterS37ProductHostLaunchBrokerV01(claimed)).toEqual({ ok: false, outcome: "OUTCOME_UNKNOWN" });
    expect(mocks.spawn).toHaveBeenCalledTimes(2);
  });
});
