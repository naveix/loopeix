import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import { afterEach, describe, expect, it } from "vitest";
import { buildS37ActionInterpositionProfileV02 } from "../../src/run/pre-spawn-capability-broker-v02.js";

const SCRIPT = "scripts/check-s37-linux-phase-b-conformance-evidence.mjs";
const RAW = "a".repeat(64);
const CONTENT = `sha256:${RAW}`;
const SYSCTL_PATH = "/usr/lib/sysctl.d/50-bubblewrap.conf";
const DENY_ROWS = [
  "ambient-credentials", "child-process", "durable-state", "environment",
  "filesystem-write", "network", "output-limits", "retry", "stdin",
  "timeout", "tool-server", "unknown-outcome",
] as const;
const roots: string[] = [];

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, entry]) => `${JSON.stringify(key)}:${canonical(entry)}`).join(",")}}`;
}

function readinessCanonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(readinessCanonical).join(",")}]`;
  return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, entry]) => `${JSON.stringify(key)}:${readinessCanonical(entry)}`).join(",")}}`;
}

function digest(value: unknown, serializer = canonical): string {
  return createHash("sha256").update(serializer(value), "utf8").digest("hex");
}

function seal<T extends Record<string, unknown>>(value: T, key: string, serializer = canonical): T {
  const body = Object.fromEntries(Object.entries(value).filter(([name]) => name !== key));
  return { ...body, [key]: digest(body, serializer) } as T;
}

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

function fixture(times = fixtureTimes()) {
  const manifest = seal({
    schema_version: "s37-linux-phase-b-build-manifest-v1",
    created_at: "2026-08-21T08:00:00.000Z",
    sources: {
      supervisor: { path: "scripts/s37-linux-phase-b/supervisor.c", sha256: CONTENT },
      probe: { path: "scripts/s37-linux-phase-b/probe.c", sha256: CONTENT },
    },
    compiler: { path: "/usr/bin/gcc", version: "14.2.0", target: "x86_64-linux-gnu", sha256: CONTENT, flags: ["-std=c17", "-D_FORTIFY_SOURCE=3", "-fstack-protector-strong", "-fPIE", "-Wall", "-Wextra", "-Werror", "-Wconversion", "-Wformat=2", "-Wshadow", "-Wstrict-prototypes", "-static-pie"] },
    artifacts: {
      supervisor: { path: "/opt/loopeix/s37.1/supervisor", sha256: CONTENT, mode: "0555", setuid: false },
      probe: { path: "/opt/loopeix/s37.1/probe", sha256: CONTENT, mode: "0555", setuid: false },
    },
    bwrap: { path: "/opt/loopeix/s37.1/bwrap", version: "0.11.0", package_version: "0.11.0-2+deb13u1", sha256: CONTENT, mode: "0555", setuid: false },
    seccomp_policy_sha256: CONTENT,
    manifest_sha256: "",
  }, "manifest_sha256");

  const readiness = seal({
    schema_version: "s37-linux-phase-b-readiness-evidence-v1",
    observed_at: times.observedAt,
    host_tuple: {
      platform: "linux",
      architecture: "x86_64",
      distro_id: "debian",
      distro_version_id: "13",
      kernel_release: "6.12.101+deb13-amd64",
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
        count: 29,
        sha256: RAW,
        captured_at: times.observedAt,
      },
    },
    package_review: {
      candidate_version: "0.11.0-2+deb13u1",
      package_file_list_sha256: RAW,
      mandatory_sysctl_path: SYSCTL_PATH,
      mandatory_sysctl_path_present: true,
      acquisition_mode: "extract-only-user-staging",
      system_package_install: false,
      sysctl_applied: false,
      service_restart: false,
      selected_artifact: { path: manifest.bwrap.path, sha256: RAW, setuid: false },
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
  }, "evidence_sha256", readinessCanonical);

  const envelope = seal({
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
      kernel_release: "6.12.101+deb13-amd64",
      systemd_version: "257.9-1~deb13u1",
      cgroup_version: 2,
      required_cgroup_controllers: ["cpu", "io", "memory", "pids"],
      unprivileged_userns_clone: true,
      user_manager_status: "running-delegated",
    },
    package_requirements: {
      candidate_version: "0.11.0-2+deb13u1",
      package_file_list_sha256: RAW,
      selected_artifact_path: manifest.bwrap.path,
      selected_artifact_sha256: RAW,
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
    resource_limits: { cpu_quota_percent: 25, memory_max_bytes: 64_000_000, tasks_max: 8, io_weight: 10, timeout_ms: 1_000, stdout_bytes: 1_024, stderr_bytes: 1_024 },
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
  }, "envelope_sha256", readinessCanonical);

  const host_tuple = {
    tuple_version: "0.1", platform: "linux", architecture: "x86_64",
    kernel_release: "6.12.101+deb13-amd64", systemd_version: "257.9-1~deb13u1",
    cgroup_version: "v2", observed_at: new Date(Date.parse(times.observedAt) + 1_000).toISOString(),
  } as const;
  const profile = {
    profile_version: "0.1",
    probe_kind: "inert-bounded-stdout-stderr",
    actor_identity_hash: CONTENT,
    on_behalf_of_chain_hash: CONTENT,
    executable: { path: manifest.artifacts.probe.path, sha256: manifest.artifacts.probe.sha256 },
    argv: [],
    cwd: { path: "/", identity_hash: CONTENT },
    filesystem: { readable_paths: [manifest.artifacts.probe.path], writable_paths: [], direct_writes: "deny" },
    child_process: "deny",
    network: { mode: "deny", allowed_origins: [] },
    tools: { built_in: "deny", mcp_servers: "deny" },
    environment: { inherit: false, allowed_names: [], values: {} },
    credentials: "deny",
    stdin: "closed",
    limits: { timeout_ms: 1_000, stdout_bytes: 1_024, stderr_bytes: 1_024 },
    durable_state: "forbidden-until-s40",
    retry: "forbidden-non-resumable",
  };
  const profileHash = `sha256:${digest(profile)}`;
  const execution = {
    unit_name: "loopeix-s37.1-conformance-abcdef123456", service_type: "exec",
    scope: false, pipe: false, standard_input: "null", standard_output: "null",
    standard_error: "null", no_new_privileges: true, kill_mode: "control-group",
    concurrency: 1, cpu_quota_percent: 25, memory_max_bytes: 64_000_000,
    tasks_max: 8, io_weight: 10, timeout_ms: 1_000, stdout_limit_bytes: 1_024,
    stderr_limit_bytes: 1_024, process_started: true, exit_code: 0, probe_duration_ms: 12,
    stdout_bytes: 0, stderr_bytes: 0, profile_hash: profileHash,
    launcher_sha256: manifest.artifacts.supervisor.sha256,
    seccomp_policy_sha256: manifest.seccomp_policy_sha256,
  };
  const receiptBody = {
    receipt_version: "0.1",
    host_tuple_hash: `sha256:${digest({ purpose: "s37-linux-host-tuple-v02", ...host_tuple })}`,
    profile_hash: profileHash,
    launcher_sha256: manifest.artifacts.supervisor.sha256,
    bwrap: { path: manifest.bwrap.path, version: manifest.bwrap.version, sha256: manifest.bwrap.sha256, setuid: false },
    seccomp_policy_sha256: manifest.seccomp_policy_sha256,
    deny_rows: [...DENY_ROWS], skipped_rows: [],
    issued_at: new Date(Date.parse(times.observedAt) + 1_000).toISOString(),
    expires_at: new Date(Date.parse(times.validTo) - 1_000).toISOString(),
  };
  const receipt = {
    ...receiptBody,
    receipt_hash: `sha256:${digest({ purpose: "s37-linux-backend-identity-receipt-v02", ...receiptBody })}`,
  };
  const snapshot = { count: 29, sha256: RAW };
  const evidence = seal({
    schema_version: "s37-linux-phase-b-conformance-evidence-v1",
    observed_at: new Date(Date.parse(times.observedAt) + 2_000).toISOString(),
    host_tuple,
    manifest_sha256: manifest.manifest_sha256,
    readiness_evidence_sha256: readiness.evidence_sha256,
    readiness_envelope_sha256: envelope.envelope_sha256,
    execution,
    deny_rows: DENY_ROWS.map((row) => ({ row, passed: true, skipped: false, witness_sha256: RAW })),
    ports: { before: snapshot, after: { ...snapshot }, delta: 0 },
    neighbors: {
      services_before: { count: 24, sha256: RAW }, services_after: { count: 24, sha256: RAW },
      containers_before: { count: 7, sha256: RAW }, containers_after: { count: 7, sha256: RAW },
    },
    cleanup: { unit_absent: true, process_absent: true, mount_absent: true, temp_absent: true, journal_payload_absent: true, file_absent: true },
    capacity: { envelope_sha256: envelope.envelope_sha256, samples_sha256: digest(readiness.capacity_samples), within_envelope: true, swap_growth_bytes: 0 },
    receipt_hash: receipt.receipt_hash,
    evidence_sha256: "",
  }, "evidence_sha256");
  return { manifest, readiness, envelope, profile, evidence, receipt };
}

function resealReceiptAndEvidence(value: ReturnType<typeof fixture>): void {
  const { receipt_hash: _ignored, ...receiptBody } = value.receipt;
  value.receipt = {
    ...receiptBody,
    receipt_hash: `sha256:${digest({ purpose: "s37-linux-backend-identity-receipt-v02", ...receiptBody })}`,
  };
  value.evidence.receipt_hash = value.receipt.receipt_hash;
  value.evidence = seal(value.evidence, "evidence_sha256");
}

function setActivationOffset(value: ReturnType<typeof fixture>, offsetMilliseconds: number): void {
  value.evidence.host_tuple = {
    ...value.evidence.host_tuple,
    observed_at: new Date(Date.parse(value.readiness.observed_at) + offsetMilliseconds).toISOString(),
  };
  value.evidence.observed_at = new Date(Date.parse(value.evidence.host_tuple.observed_at) + 1_000).toISOString();
  value.receipt.host_tuple_hash = `sha256:${digest({ purpose: "s37-linux-host-tuple-v02", ...value.evidence.host_tuple })}`;
  value.receipt.issued_at = value.evidence.host_tuple.observed_at;
  resealReceiptAndEvidence(value);
}

function run(values = fixture()) {
  const root = mkdtempSync(join(tmpdir(), "loopeix-s37b-evidence-"));
  roots.push(root);
  const mapping = [
    ["--manifest", "manifest.json", values.manifest],
    ["--readiness-evidence", "readiness.json", values.readiness],
    ["--readiness-envelope", "envelope.json", values.envelope],
    ["--profile", "profile.json", values.profile],
    ["--evidence", "evidence.json", values.evidence],
    ["--receipt", "receipt.json", values.receipt],
  ] as const;
  const args: string[] = [];
  for (const [flag, name, value] of mapping) {
    const path = join(root, name);
    writeFileSync(path, `${JSON.stringify(value)}\n`, "utf8");
    args.push(flag, path);
  }
  return spawnSync(process.execPath, [SCRIPT, ...args], { cwd: process.cwd(), encoding: "utf8", shell: false });
}

afterEach(() => {
  while (roots.length > 0) rmSync(roots.pop()!, { recursive: true, force: true });
});

describe("S37.1-B sealed conformance evidence gate", () => {
  it("binds the exact product action-profile shape", () => {
    const value = fixture();
    expect(value.profile).toEqual(buildS37ActionInterpositionProfileV02({
      actor_identity_hash: CONTENT,
      on_behalf_of_chain_hash: CONTENT,
      executable: value.profile.executable,
      cwd: value.profile.cwd,
    }));
  });

  it("emits a Bubblewrap receipt compatible with the product admission schema", () => {
    const brokerSource = readFileSync("src/run/pre-spawn-capability-broker-v02.ts", "utf8");
    const schemaBody = brokerSource.match(
      /const LinuxBackendIdentityReceiptV02 = z\.object\(\{[\s\S]*?bwrap: z\.object\(\{([\s\S]*?)\}\)\.strict\(\),/u,
    )?.[1];
    expect(schemaBody, "product receipt bwrap schema must remain discoverable").toBeDefined();
    const productKeys = [...schemaBody!.matchAll(/^\s{4}([a-z0-9_]+):/gmu)]
      .map((match) => match[1])
      .sort();
    const evidenceKeys = Object.keys(fixture().receipt.bwrap).sort();
    expect(evidenceKeys).toEqual(productKeys);
  });

  it("accepts one complete, tuple-bound, zero-delta receipt", () => {
    const result = run();
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe("S37.1-B conformance evidence gate: PASS\nsealed evidence only; no live host action performed\n");
    expect(result.stderr).toBe("");
  });

  it("accepts genuinely old sealed readiness when activation is within 15 seconds", () => {
    const value = fixture(fixtureTimes(Date.parse("2025-01-15T12:00:00.000Z")));
    setActivationOffset(value, 15_000);
    const result = run(value);
    expect(result.status, result.stderr).toBe(0);
  });

  it("accepts the exact 15.000-second readiness boundary", () => {
    const value = fixture();
    setActivationOffset(value, 15_000);
    const result = run(value);
    expect(result.status, result.stderr).toBe(0);
  });

  it("rejects 15.001 seconds with the direct activation-staleness violation", () => {
    const value = fixture();
    setActivationOffset(value, 15_001);
    const result = run(value);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: evidence.host_tuple.observed_at:readiness-stale-at-activation");
  });

  it.each(["--live", "--ssh", "--vps"])("rejects live surface %s", (flag) => {
    const result = spawnSync(process.execPath, [SCRIPT, flag], { cwd: process.cwd(), encoding: "utf8", shell: false });
    expect(result.status).toBe(64);
    expect(result.stderr).toContain(`unknown argument: ${flag}`);
  });

  it("rejects a missing required input", () => {
    const result = spawnSync(process.execPath, [SCRIPT], { cwd: process.cwd(), encoding: "utf8", shell: false });
    expect(result.status).toBe(64);
    expect(result.stderr).toContain("missing argument: --manifest");
  });

  it.each([
    ["manifest tamper", (value: ReturnType<typeof fixture>) => { value.manifest.bwrap.setuid = true; }],
    ["compiler hash missing", (value: ReturnType<typeof fixture>) => { delete (value.manifest.compiler as Partial<typeof value.manifest.compiler>).sha256; }],
    ["compiler hash invalid", (value: ReturnType<typeof fixture>) => { value.manifest.compiler.sha256 = "not-a-content-hash"; }],
    ["sealed Bubblewrap package version drift", (value: ReturnType<typeof fixture>) => {
      value.manifest.bwrap.package_version = "0.11.0-2+deb13u2-drift";
      value.manifest = seal(value.manifest, "manifest_sha256");
      value.evidence.manifest_sha256 = value.manifest.manifest_sha256;
      resealReceiptAndEvidence(value);
    }],
    ["readiness reboot conflict", (value: ReturnType<typeof fixture>) => { value.readiness.preflight.reboot_required = true; value.readiness = seal(value.readiness, "evidence_sha256", readinessCanonical); }],
    ["minimal readiness forgery", (value: ReturnType<typeof fixture>) => {
      value.readiness = seal({
        schema_version: "s37-linux-phase-b-readiness-evidence-v1",
        observed_at: value.readiness.observed_at,
        preflight: value.readiness.preflight,
        package_review: value.readiness.package_review,
        evidence_sha256: "",
      }, "evidence_sha256", readinessCanonical);
    }],
    ["sealed readiness host tuple drift", (value: ReturnType<typeof fixture>) => {
      value.readiness.host_tuple.kernel_release = "6.12.102-drift-amd64";
      value.envelope.host_requirements.kernel_release = "6.12.102-drift-amd64";
      value.readiness = seal(value.readiness, "evidence_sha256", readinessCanonical);
      value.envelope = seal(value.envelope, "envelope_sha256", readinessCanonical);
      value.evidence.readiness_evidence_sha256 = value.readiness.evidence_sha256;
      value.evidence.readiness_envelope_sha256 = value.envelope.envelope_sha256;
      value.evidence.capacity.envelope_sha256 = value.envelope.envelope_sha256;
      value.evidence = seal(value.evidence, "evidence_sha256");
    }],
    ["product profile policy drift", (value: ReturnType<typeof fixture>) => {
      value.profile.environment.allowed_names = ["SECRET"];
    }],
    ["host tuple observed after conformance", (value: ReturnType<typeof fixture>) => {
      value.evidence.host_tuple = {
        ...value.evidence.host_tuple,
        observed_at: new Date(Date.parse(value.evidence.observed_at) + 1_000).toISOString(),
      };
      value.receipt.host_tuple_hash = `sha256:${digest({ purpose: "s37-linux-host-tuple-v02", ...value.evidence.host_tuple })}`;
      resealReceiptAndEvidence(value);
    }],
    ["readiness stale at activation", (value: ReturnType<typeof fixture>) => {
      value.evidence.host_tuple = {
        ...value.evidence.host_tuple,
        observed_at: new Date(Date.parse(value.readiness.observed_at) + 16_000).toISOString(),
      };
      value.evidence.observed_at = new Date(Date.parse(value.readiness.observed_at) + 17_000).toISOString();
      value.receipt.host_tuple_hash = `sha256:${digest({ purpose: "s37-linux-host-tuple-v02", ...value.evidence.host_tuple })}`;
      value.receipt.issued_at = value.evidence.host_tuple.observed_at;
      resealReceiptAndEvidence(value);
    }],
    ["receipt issued before host observation", (value: ReturnType<typeof fixture>) => {
      value.receipt.issued_at = value.readiness.observed_at;
      resealReceiptAndEvidence(value);
    }],
    ["receipt expires after readiness window", (value: ReturnType<typeof fixture>) => {
      value.receipt.expires_at = new Date(Date.parse(value.envelope.valid_to) + 1_000).toISOString();
      resealReceiptAndEvidence(value);
    }],
    ["scope instead of service", (value: ReturnType<typeof fixture>) => { value.evidence.execution.scope = true; value.evidence = seal(value.evidence, "evidence_sha256"); }],
    ["pipe inherited", (value: ReturnType<typeof fixture>) => { value.evidence.execution.pipe = true; value.evidence = seal(value.evidence, "evidence_sha256"); }],
    ["output escaped", (value: ReturnType<typeof fixture>) => { value.evidence.execution.stdout_bytes = 1; value.evidence = seal(value.evidence, "evidence_sha256"); }],
    ["timeout exceeded", (value: ReturnType<typeof fixture>) => { value.evidence.execution.probe_duration_ms = 1001; value.evidence = seal(value.evidence, "evidence_sha256"); }],
    ["unit limit drift", (value: ReturnType<typeof fixture>) => { value.evidence.execution.tasks_max = 9; value.evidence = seal(value.evidence, "evidence_sha256"); }],
    ["deny row skipped", (value: ReturnType<typeof fixture>) => { value.evidence.deny_rows[0].skipped = true; value.evidence = seal(value.evidence, "evidence_sha256"); }],
    ["port delta", (value: ReturnType<typeof fixture>) => { value.evidence.ports.after.count += 1; value.evidence.ports.delta = 1; value.evidence = seal(value.evidence, "evidence_sha256"); }],
    ["service transition", (value: ReturnType<typeof fixture>) => { value.evidence.neighbors.services_after.count += 1; value.evidence = seal(value.evidence, "evidence_sha256"); }],
    ["cleanup residue", (value: ReturnType<typeof fixture>) => { value.evidence.cleanup.mount_absent = false; value.evidence = seal(value.evidence, "evidence_sha256"); }],
    ["capacity breach", (value: ReturnType<typeof fixture>) => { value.evidence.capacity.within_envelope = false; value.evidence = seal(value.evidence, "evidence_sha256"); }],
    ["capacity sample hash forgery", (value: ReturnType<typeof fixture>) => { value.evidence.capacity.samples_sha256 = "b".repeat(64); value.evidence = seal(value.evidence, "evidence_sha256"); }],
    ["swap growth", (value: ReturnType<typeof fixture>) => { value.evidence.capacity.swap_growth_bytes = 1; value.evidence = seal(value.evidence, "evidence_sha256"); }],
    ["partial receipt", (value: ReturnType<typeof fixture>) => { delete (value.receipt as Partial<typeof value.receipt>).seccomp_policy_sha256; }],
    ["receipt hash tamper", (value: ReturnType<typeof fixture>) => { value.receipt.receipt_hash = `sha256:${"b".repeat(64)}`; }],
  ] as const)("HOLDs on %s", (_label, mutate) => {
    const value = fixture();
    mutate(value);
    const result = run(value);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD:");
  });
});
