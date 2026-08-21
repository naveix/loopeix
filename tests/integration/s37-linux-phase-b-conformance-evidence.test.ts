import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import { afterEach, describe, expect, it } from "vitest";

const SCRIPT = "scripts/check-s37-linux-phase-b-conformance-evidence.mjs";
const RAW = "a".repeat(64);
const CONTENT = `sha256:${RAW}`;
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

function fixture() {
  const manifest = seal({
    schema_version: "s37-linux-phase-b-build-manifest-v1",
    created_at: "2026-08-21T08:00:00.000Z",
    sources: {
      supervisor: { path: "scripts/s37-linux-phase-b/supervisor.c", sha256: CONTENT },
      probe: { path: "scripts/s37-linux-phase-b/probe.c", sha256: CONTENT },
    },
    compiler: { path: "/usr/bin/gcc", version: "14.2.0", target: "x86_64-linux-gnu", flags: ["-std=c17", "-D_FORTIFY_SOURCE=3", "-fstack-protector-strong", "-fPIE", "-Wall", "-Wextra", "-Werror", "-Wconversion", "-Wformat=2", "-Wshadow", "-Wstrict-prototypes", "-static-pie"] },
    artifacts: {
      supervisor: { path: "/opt/loopeix/s37.1/supervisor", sha256: CONTENT, mode: "0555", setuid: false },
      probe: { path: "/opt/loopeix/s37.1/probe", sha256: CONTENT, mode: "0555", setuid: false },
    },
    bwrap: { path: "/opt/loopeix/s37.1/bwrap", version: "0.11.0", sha256: CONTENT, mode: "0555", setuid: false },
    seccomp_policy_sha256: CONTENT,
    manifest_sha256: "",
  }, "manifest_sha256");

  const readiness = seal({
    schema_version: "s37-linux-phase-b-readiness-evidence-v1",
    observed_at: "2026-08-21T08:00:05.000Z",
    preflight: { apt_dpkg_locks_clear: true, reboot_required: false, shutdown: false, maintenance_conflict: false },
    package_review: {
      system_package_install: false, sysctl_applied: false, service_restart: false,
      selected_artifact: { path: manifest.bwrap.path, sha256: RAW, setuid: false },
    },
    evidence_sha256: "",
  }, "evidence_sha256", readinessCanonical);

  const envelope = seal({
    schema_version: "s37-linux-phase-b-readiness-envelope-v1",
    valid_from: "2026-08-21T07:55:00.000Z",
    valid_to: "2026-08-21T08:10:00.000Z",
    concurrency: 1,
    resource_limits: { cpu_quota_percent: 25, memory_max_bytes: 64_000_000, tasks_max: 8, io_weight: 10, timeout_ms: 1_000, stdout_bytes: 1_024, stderr_bytes: 1_024 },
    envelope_sha256: "",
  }, "envelope_sha256", readinessCanonical);

  const host_tuple = {
    tuple_version: "0.1", platform: "linux", architecture: "x86_64",
    kernel_release: "6.12.101+deb13-amd64", systemd_version: "257.8",
    cgroup_version: "v2", observed_at: "2026-08-21T08:00:06.000Z",
  } as const;
  const execution = {
    unit_name: "loopeix-s37.1-conformance-abcdef123456", service_type: "exec",
    scope: false, pipe: false, standard_input: "null", standard_output: "null",
    standard_error: "null", no_new_privileges: true, kill_mode: "control-group",
    concurrency: 1, cpu_quota_percent: 25, memory_max_bytes: 64_000_000,
    tasks_max: 8, io_weight: 10, timeout_ms: 1_000, stdout_limit_bytes: 1_024,
    stderr_limit_bytes: 1_024, process_started: true, exit_code: 0, probe_duration_ms: 12,
    stdout_bytes: 0, stderr_bytes: 0, profile_hash: CONTENT,
    launcher_sha256: manifest.artifacts.supervisor.sha256,
    seccomp_policy_sha256: manifest.seccomp_policy_sha256,
  };
  const receiptBody = {
    receipt_version: "0.1",
    host_tuple_hash: `sha256:${digest({ purpose: "s37-linux-host-tuple-v02", ...host_tuple })}`,
    profile_hash: execution.profile_hash,
    launcher_sha256: manifest.artifacts.supervisor.sha256,
    bwrap: { path: manifest.bwrap.path, version: manifest.bwrap.version, sha256: manifest.bwrap.sha256, setuid: false },
    seccomp_policy_sha256: manifest.seccomp_policy_sha256,
    deny_rows: [...DENY_ROWS], skipped_rows: [],
    issued_at: "2026-08-21T08:00:07.000Z", expires_at: "2026-08-21T08:05:00.000Z",
  };
  const receipt = {
    ...receiptBody,
    receipt_hash: `sha256:${digest({ purpose: "s37-linux-backend-identity-receipt-v02", ...receiptBody })}`,
  };
  const snapshot = { count: 29, sha256: RAW };
  const evidence = seal({
    schema_version: "s37-linux-phase-b-conformance-evidence-v1",
    observed_at: "2026-08-21T08:00:08.000Z",
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
    capacity: { envelope_sha256: envelope.envelope_sha256, samples_sha256: RAW, within_envelope: true, swap_growth_bytes: 0 },
    receipt_hash: receipt.receipt_hash,
    evidence_sha256: "",
  }, "evidence_sha256");
  return { manifest, readiness, envelope, evidence, receipt };
}

function run(values = fixture()) {
  const root = mkdtempSync(join(tmpdir(), "loopeix-s37b-evidence-"));
  roots.push(root);
  const mapping = [
    ["--manifest", "manifest.json", values.manifest],
    ["--readiness-evidence", "readiness.json", values.readiness],
    ["--readiness-envelope", "envelope.json", values.envelope],
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
  it("accepts one complete, tuple-bound, zero-delta receipt", () => {
    const result = run();
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe("S37.1-B conformance evidence gate: PASS\nsealed evidence only; no live host action performed\n");
    expect(result.stderr).toBe("");
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
    ["readiness reboot conflict", (value: ReturnType<typeof fixture>) => { value.readiness.preflight.reboot_required = true; value.readiness = seal(value.readiness, "evidence_sha256", readinessCanonical); }],
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
