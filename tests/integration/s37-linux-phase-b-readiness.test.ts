import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import { afterEach, describe, expect, it } from "vitest";

const tempRoots: string[] = [];
const SCRIPT = "scripts/check-s37-linux-phase-b-readiness.mjs";
const SYSCTL_PATH = "/usr/lib/sysctl.d/50-bubblewrap.conf";

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.entries(value)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
    .join(",")}}`;
}

function selfHash(value: Record<string, unknown>, hashKey: string): string {
  const withoutHash = Object.fromEntries(Object.entries(value).filter(([key]) => key !== hashKey));
  return createHash("sha256").update(canonicalJson(withoutHash), "utf8").digest("hex");
}

function seal<T extends Record<string, unknown>>(value: T, hashKey: string): T {
  value[hashKey as keyof T] = selfHash(value, hashKey) as T[keyof T];
  return value;
}

function writeJson(root: string, name: string, value: unknown): string {
  const path = join(root, name);
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  return path;
}

function runReadiness(evidence: unknown, envelope: unknown, extraArgs: readonly string[] = []) {
  const root = mkdtempSync(join(tmpdir(), "loopeix-s37b-"));
  tempRoots.push(root);
  const evidencePath = writeJson(root, "evidence.json", evidence);
  const envelopePath = writeJson(root, "envelope.json", envelope);
  return spawnSync(
    process.execPath,
    [SCRIPT, "--evidence", evidencePath, "--envelope", envelopePath, ...extraArgs],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      shell: false,
      timeout: 15_000,
      maxBuffer: 2 * 1024 * 1024,
    },
  );
}

afterEach(() => {
  while (tempRoots.length > 0) {
    const root = tempRoots.pop();
    if (root !== undefined) rmSync(root, { force: true, recursive: true });
  }
});

function fixtureTimes(now = Date.now()) {
  const observedAt = new Date(now - 2_000);
  return {
    observedAt: observedAt.toISOString(),
    validFrom: new Date(now - 120_000).toISOString(),
    validTo: new Date(now + 120_000).toISOString(),
    samples: [-60, -45, -30, -15, 0].map((offsetSeconds) =>
      new Date(observedAt.getTime() + offsetSeconds * 1_000).toISOString()),
  };
}

function passEnvelope(times = fixtureTimes()) {
  return seal({
    schema_version: "s37-linux-phase-b-readiness-envelope-v1",
    approved_at: new Date(Date.parse(times.validFrom) - 60_000).toISOString(),
    approved_by: "illustrative-test-operator",
    valid_from: times.validFrom,
    valid_to: times.validTo,
    measurement_window_seconds: 60,
    sample_interval_seconds: 15,
    min_sample_count: 5,
    concurrency: 1,
    task_ceiling: 32,
    host_requirements: {
      platform: "linux",
      architecture: "x86_64",
      distro_id: "debian",
      distro_version_id: "13",
      kernel_release: "6.12.95-amd64",
      systemd_version: "257.9-1~deb13u1",
      cgroup_version: 2,
      required_cgroup_controllers: ["cpu", "io", "memory", "pids"],
      unprivileged_userns_clone: true,
      user_manager_status: "running-delegated",
    },
    package_requirements: {
      candidate_version: "0.11.0-2+deb13u1",
      package_file_list_sha256: "1".repeat(64),
      selected_artifact_path: "/opt/loopeix/s37.1/bwrap",
      selected_artifact_sha256: "2".repeat(64),
    },
    thresholds: {
      min_cpu_cores: 4,
      min_memory_available_bytes: 8_000_000_000,
      max_swap_used_bytes: 100_000_000,
      max_swap_growth_bytes: 0,
      max_load1: 0.75,
      max_load5: 0.75,
      max_cpu_psi_some_avg10: 0.5,
      max_memory_psi_some_avg10: 0.5,
      max_io_psi_some_avg10: 0.5,
    },
    threshold_reasons: {
      min_cpu_cores: "Preserves the reviewed host CPU topology.",
      min_memory_available_bytes: "Keeps a large memory reserve for incumbent workloads.",
      max_swap_used_bytes: "Prevents trials during material memory contention.",
      max_swap_growth_bytes: "Stops trials if the host begins swapping.",
      max_load1: "Keeps short-term scheduler demand below the reviewed ceiling.",
      max_load5: "Keeps sustained scheduler demand below the reviewed ceiling.",
      max_cpu_psi_some_avg10: "Prevents trials during CPU pressure.",
      max_memory_psi_some_avg10: "Prevents trials during memory pressure.",
      max_io_psi_some_avg10: "Prevents trials during IO pressure.",
    },
    resource_limits: {
      cpu_quota_percent: 25,
      memory_max_bytes: 64_000_000,
      tasks_max: 8,
      io_weight: 10,
      timeout_ms: 1_000,
      stdout_bytes: 1_024,
      stderr_bytes: 1_024,
    },
    resource_limit_reasons: {
      cpu_quota_percent: "Caps the inert probe to one quarter of one CPU.",
      memory_max_bytes: "Caps the static launcher and probe below the approved reserve.",
      tasks_max: "Allows only the launcher, Bubblewrap, probe, and bounded setup helpers.",
      io_weight: "Gives the conformance unit the lowest practical relative IO priority.",
      timeout_ms: "Matches the frozen hard runtime deadline.",
      stdout_bytes: "Matches the frozen per-stream stdout custody cap.",
      stderr_bytes: "Matches the frozen per-stream stderr custody cap.",
    },
    envelope_sha256: "",
  }, "envelope_sha256");
}

function passEvidence(times = fixtureTimes()) {
  return seal({
    schema_version: "s37-linux-phase-b-readiness-evidence-v1",
    observed_at: times.observedAt,
    host_tuple: {
      platform: "linux",
      architecture: "x86_64",
      distro_id: "debian",
      distro_version_id: "13",
      kernel_release: "6.12.95-amd64",
      systemd_version: "257.9-1~deb13u1",
      cgroup_version: 2,
      cgroup_controllers: ["cpu", "io", "memory", "pids"],
      unprivileged_userns_clone: true,
      user_manager_status: "running-delegated",
    },
    preflight: {
      apt_dpkg_locks_clear: true,
      reboot_required: false,
      shutdown: false,
      maintenance_conflict: false,
      port_evidence: {
        count: 7,
        sha256: "3".repeat(64),
        captured_at: times.observedAt,
      },
    },
    package_review: {
      candidate_version: "0.11.0-2+deb13u1",
      package_file_list_sha256: "1".repeat(64),
      mandatory_sysctl_path: SYSCTL_PATH,
      mandatory_sysctl_path_present: true,
      acquisition_mode: "extract-only-user-staging",
      system_package_install: false,
      sysctl_applied: false,
      service_restart: false,
      selected_artifact: {
        path: "/opt/loopeix/s37.1/bwrap",
        sha256: "2".repeat(64),
        setuid: false,
      },
      clean_install_evidence: null,
    },
    capacity_samples: times.samples.map((timestamp) => ({
      timestamp,
      cpu_cores: 4,
      memory_available_bytes: 11_800_000_000,
      swap_used_bytes: 0,
      load1: 0.11,
      load5: 0.08,
      cpu_psi_some_avg10: 0.02,
      memory_psi_some_avg10: 0.01,
      io_psi_some_avg10: 0.03,
      tasks: 20,
    })),
    evidence_sha256: "",
  }, "evidence_sha256");
}

function resealEvidence(evidence: ReturnType<typeof passEvidence>) {
  return seal(evidence, "evidence_sha256");
}

describe("S37.1-B passive readiness gate", () => {
  it("passes illustrative extract-only evidence without executing live conformance", () => {
    const times = fixtureTimes();
    const result = runReadiness(passEvidence(times), passEnvelope(times));

    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe(
      "S37.1-B passive readiness gate: PASS\nreadiness only; live host conformance not executed\n",
    );
    expect(result.stderr).toBe("");
  });

  it("holds current reboot-required evidence unconditionally", () => {
    const evidence = passEvidence();
    evidence.preflight.reboot_required = true;
    resealEvidence(evidence);
    const result = runReadiness(evidence, passEnvelope());
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: preflight.reboot_required:expected-false");
  });

  it("cannot waive the mandatory Debian sysctl package path", () => {
    const evidence = passEvidence();
    evidence.package_review.mandatory_sysctl_path_present = false;
    resealEvidence(evidence);
    const envelope = passEnvelope() as ReturnType<typeof passEnvelope> & { forbidden_package_paths?: string[] };
    envelope.forbidden_package_paths = [];
    seal(envelope, "envelope_sha256");
    const result = runReadiness(evidence, envelope);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: envelope:unexpected-key:forbidden_package_paths");
    expect(result.stderr).toContain("HOLD: package_review.mandatory_sysctl_path_present:expected-true");
  });

  it("rejects raw listening addresses instead of retaining host-sensitive port data", () => {
    const evidence = passEvidence() as ReturnType<typeof passEvidence>;
    Object.assign(evidence.preflight.port_evidence, { addresses: ["0.0.0.0:22"] });
    resealEvidence(evidence);
    const result = runReadiness(evidence, passEnvelope());
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: preflight.port_evidence:unexpected-key:addresses");
  });

  it("rejects a stale listening-port baseline even when the evidence is resealed", () => {
    const evidence = passEvidence();
    evidence.preflight.port_evidence.captured_at = new Date(
      Date.parse(evidence.observed_at) - 1_000,
    ).toISOString();
    resealEvidence(evidence);
    const result = runReadiness(evidence, passEnvelope());
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "HOLD: preflight.port_evidence.captured_at:not-observed-at",
    );
  });

  it("holds stale and incomplete capacity sampling", () => {
    const times = fixtureTimes();
    const envelope = passEnvelope(times);
    envelope.valid_to = new Date(Date.now() - 30_000).toISOString();
    seal(envelope, "envelope_sha256");
    const evidence = passEvidence(times);
    evidence.capacity_samples.splice(1, 1);
    resealEvidence(evidence);
    const result = runReadiness(evidence, envelope);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: envelope.valid_to:expired");
    expect(result.stderr).toContain("HOLD: capacity_samples:incomplete-interval");
    expect(result.stderr).toContain("HOLD: capacity_samples:below-min-sample-count");
  });

  it("holds evidence that is stale even while its approval window remains valid", () => {
    const times = fixtureTimes();
    const evidence = passEvidence(times);
    const shiftMilliseconds = 30_000;
    evidence.observed_at = new Date(Date.parse(evidence.observed_at) - shiftMilliseconds).toISOString();
    evidence.preflight.port_evidence.captured_at = evidence.observed_at;
    for (const sample of evidence.capacity_samples) {
      sample.timestamp = new Date(Date.parse(sample.timestamp) - shiftMilliseconds).toISOString();
    }
    resealEvidence(evidence);
    const result = runReadiness(evidence, passEnvelope(times));
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: evidence.observed_at:stale");
  });

  it("revalidates sealed historical readiness at an explicit activation time without claiming current readiness", () => {
    const times = fixtureTimes(Date.parse("2025-01-15T12:00:00.000Z"));
    const evidence = passEvidence(times);
    const asOf = new Date(Date.parse(evidence.observed_at) + 5_000).toISOString();
    const result = runReadiness(evidence, passEnvelope(times), ["--as-of", asOf]);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe(
      "S37.1-B passive readiness gate: PASS\nhistorical readiness validation only; not current execution readiness\n",
    );
  });

  it("evaluates historical envelope expiry against --as-of rather than the wall clock", () => {
    const times = fixtureTimes(Date.parse("2025-01-15T12:00:00.000Z"));
    const evidence = passEvidence(times);
    const asOf = new Date(Date.parse(times.validTo) + 1).toISOString();
    const result = runReadiness(evidence, passEnvelope(times), ["--as-of", asOf]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: envelope.valid_to:expired");
  });

  it.each([
    ["invalid", ["--as-of", "not-an-iso-timestamp"], 1, "HOLD: as_of:missing-or-invalid"],
    ["duplicate", ["--as-of", "2025-01-15T12:00:00.000Z", "--as-of", "2025-01-15T12:00:01.000Z"], 64, "duplicate argument: --as-of"],
    ["missing", ["--as-of"], 64, "--as-of requires an ISO timestamp"],
  ] as const)("rejects %s --as-of input", (_label, extraArgs, status, message) => {
    const times = fixtureTimes();
    const result = runReadiness(passEvidence(times), passEnvelope(times), extraArgs);
    expect(result.status).toBe(status);
    expect(result.stderr).toContain(message);
  });

  it("rejects historical validation before the readiness observation", () => {
    const times = fixtureTimes();
    const evidence = passEvidence(times);
    const asOf = new Date(Date.parse(evidence.observed_at) - 1_000).toISOString();
    const result = runReadiness(evidence, passEnvelope(times), ["--as-of", asOf]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: evidence.observed_at:future");
  });

  it("holds when a required cgroup controller is missing", () => {
    const evidence = passEvidence();
    evidence.host_tuple.cgroup_controllers = ["cpu", "memory", "pids"];
    resealEvidence(evidence);
    const result = runReadiness(evidence, passEnvelope());
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: host_tuple.cgroup_controllers:missing:io");
  });

  it("does not let the envelope waive mandatory Linux host controls", () => {
    const evidence = passEvidence();
    evidence.host_tuple.cgroup_version = 1;
    evidence.host_tuple.cgroup_controllers = ["cpu"];
    resealEvidence(evidence);
    const envelope = passEnvelope();
    envelope.host_requirements.cgroup_version = 1;
    envelope.host_requirements.required_cgroup_controllers = ["cpu"];
    seal(envelope, "envelope_sha256");
    const result = runReadiness(evidence, envelope);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: host_requirements.cgroup_version:expected-2");
    expect(result.stderr).toContain(
      "HOLD: host_requirements.required_cgroup_controllers:missing:io",
    );
  });

  it("does not let the envelope approve an older Bubblewrap build", () => {
    const evidence = passEvidence();
    evidence.package_review.candidate_version = "0.11.0-2";
    resealEvidence(evidence);
    const envelope = passEnvelope();
    envelope.package_requirements.candidate_version = "0.11.0-2";
    seal(envelope, "envelope_sha256");
    const result = runReadiness(evidence, envelope);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "HOLD: package_requirements.candidate_version:expected-0.11.0-2+deb13u1",
    );
  });

  it("holds a setuid selected artifact", () => {
    const evidence = passEvidence();
    evidence.package_review.selected_artifact.setuid = true;
    resealEvidence(evidence);
    const result = runReadiness(evidence, passEnvelope());
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: package_review.selected_artifact.setuid:expected-false");
  });

  it.each([
    ["system_package_install", true, "package_review.system_package_install:unauthorized"],
    ["sysctl_applied", true, "package_review.sysctl_applied:expected-false"],
    ["service_restart", true, "package_review.service_restart:expected-false"],
  ] as const)("holds extract-only evidence with %s", (field, value, reason) => {
    const evidence = passEvidence();
    evidence.package_review[field] = value;
    resealEvidence(evidence);
    const result = runReadiness(evidence, passEnvelope());
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(`HOLD: ${reason}`);
  });

  it("holds review-only acquisition because review is not execution readiness", () => {
    const evidence = passEvidence();
    evidence.package_review.acquisition_mode = "review-only";
    resealEvidence(evidence);
    const result = runReadiness(evidence, passEnvelope());
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: package_review.acquisition_mode:review-only");
  });

  it("detects evidence and envelope self-hash tampering", () => {
    const evidence = passEvidence();
    evidence.preflight.port_evidence.count = 8;
    const envelope = passEnvelope();
    envelope.task_ceiling = 33;
    const result = runReadiness(evidence, envelope);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: evidence.evidence_sha256:mismatch");
    expect(result.stderr).toContain("HOLD: envelope.envelope_sha256:mismatch");
  });

  it("requires a rationale for every operator-approved capacity threshold", () => {
    const envelope = passEnvelope();
    envelope.threshold_reasons.max_io_psi_some_avg10 = "";
    seal(envelope, "envelope_sha256");
    const result = runReadiness(passEvidence(), envelope);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "HOLD: threshold_reasons.max_io_psi_some_avg10:missing-or-invalid",
    );
  });

  it("holds runtime ceilings that drift from the frozen timeout and output contract", () => {
    const envelope = passEnvelope();
    envelope.resource_limits.timeout_ms = 1_001;
    envelope.resource_limits.stdout_bytes = 1_025;
    seal(envelope, "envelope_sha256");
    const result = runReadiness(passEvidence(), envelope);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: resource_limits.timeout_ms:expected-1000:actual-1001");
    expect(result.stderr).toContain("HOLD: resource_limits.stdout_bytes:expected-1024:actual-1025");
  });

  it("holds a transient task limit above the approved shared-host ceiling", () => {
    const envelope = passEnvelope();
    envelope.resource_limits.tasks_max = envelope.task_ceiling + 1;
    seal(envelope, "envelope_sha256");
    const result = runReadiness(passEvidence(), envelope);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: resource_limits.tasks_max:exceeds-task-ceiling");
  });

  it("requires a rationale for every operator-approved transient-unit limit", () => {
    const envelope = passEnvelope();
    envelope.resource_limit_reasons.io_weight = "";
    seal(envelope, "envelope_sha256");
    const result = runReadiness(passEvidence(), envelope);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: resource_limit_reasons.io_weight:missing-or-invalid");
  });

  it("evaluates every sample and the task ceiling", () => {
    const evidence = passEvidence();
    evidence.capacity_samples[2]!.memory_available_bytes = 1;
    evidence.capacity_samples[3]!.tasks = 33;
    resealEvidence(evidence);
    const result = runReadiness(evidence, passEnvelope());
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: capacity_samples[2].memory_available_bytes:below-minimum");
    expect(result.stderr).toContain("HOLD: capacity_samples[3].tasks:above-task-ceiling");
  });

  it.each(["--live", "--ssh", "--vps"])("rejects forbidden live flag %s", (flag) => {
    const result = runReadiness(passEvidence(), passEnvelope(), [flag]);
    expect(result.status).toBe(64);
    expect(result.stderr).toContain(`unknown argument: ${flag}`);
    expect(result.stdout).toBe("");
  });
});
