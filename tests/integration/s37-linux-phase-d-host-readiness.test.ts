import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  S37_PHASE_D_BINDING_PATH,
  buildS37PhaseDBindingInstallPlan,
  evaluateS37PhaseDHost,
  hashBytes,
  hashCanonical,
} from "../../scripts/s37-linux-phase-d/host-qualification-contract.mjs";

const RAW = "a".repeat(64);
const BYTES = {
  machine_id: Buffer.from("dedicated-product-host\n"),
  cgroup_controllers: Buffer.from("cpu io memory pids\n"),
  supervisor: Buffer.from("supervisor"),
  probe: Buffer.from("probe"),
  bwrap: Buffer.from("bwrap"),
  systemd_run: Buffer.from("systemd-run"),
  systemctl: Buffer.from("systemctl"),
};
const APPROVED_HASHES = {
  supervisor: "sha256:a098a5f32c71fc0f1014b64a2a5e86535690b5d973771bcda35a864d66e60046",
  probe: "sha256:22de7539d222b8092240d17de27e9dbecffbc84684d6576454008030167f361a",
  bwrap: "sha256:0dfa36b98ada69568aaaa741fe210d2150a1441433bd13c428137d6a972a959c",
  seccomp: "sha256:dc318421e96d062286c0a625ceb3db6d7db1ccb6c83a6da17848335de77dbe2c",
};
const APPROVED_SOURCE_HASHES = {
  supervisor: "sha256:515c7fa5e6ba937e25f75b025c4b7d67f8b9354f40955e4a601506881b7c2835",
  probe: "sha256:0cb0abe0b45ad54a46a93ef3adec76bdd3e60824ac97e8e08756e103f5d74405",
};
const DENY_ROWS = [
  "ambient-credentials", "child-process", "durable-state", "environment",
  "filesystem-write", "network", "output-limits", "retry", "stdin",
  "timeout", "tool-server", "unknown-outcome",
] as const;
const DIRECTORIES = [
  "/etc", "/etc/loopeix", "/etc/loopeix/s37.1", "/opt", "/opt/loopeix",
  "/opt/loopeix/s37.1", "/usr", "/usr/bin", "/sys", "/sys/fs", "/sys/fs/cgroup",
];
const ROOTS: string[] = [];

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.entries(value).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0).map(([key, entry]) => `${JSON.stringify(key)}:${canonical(entry)}`).join(",")}}`;
}

function readinessCanonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(readinessCanonical).join(",")}]`;
  return `{${Object.entries(value).sort(([left], [right]) => left.localeCompare(right)).map(([key, entry]) => `${JSON.stringify(key)}:${readinessCanonical(entry)}`).join(",")}}`;
}

function digest(value: unknown, serializer = canonical): string {
  return createHash("sha256").update(serializer(value), "utf8").digest("hex");
}

function seal<T extends Record<string, unknown>>(value: T, key: string, serializer = canonical): T {
  const body = Object.fromEntries(Object.entries(value).filter(([name]) => name !== key));
  return { ...body, [key]: digest(body, serializer) } as T;
}

function capture() {
  const modes = { machine_id: 0o444, cgroup_controllers: 0o444, supervisor: 0o555, probe: 0o555, bwrap: 0o555, systemd_run: 0o755, systemctl: 0o755 };
  return {
    platform: "linux",
    architecture: "x86_64",
    kernel_release: "6.12.101+deb13-amd64",
    controller_uid: 1001,
    directories: Object.fromEntries(DIRECTORIES.map((path) => [path, { kind: "directory", uid: 0, mode: 0o755 }])),
    files: Object.fromEntries(Object.entries(BYTES).map(([name, bytes]) => [name, {
      metadata: { kind: "file", uid: 0, mode: modes[name as keyof typeof modes], nlink: 1 },
      bytes,
      sha256: APPROVED_HASHES[name as keyof typeof APPROVED_HASHES] ?? hashBytes(bytes),
    }])),
    user_runtime: { directory: { kind: "directory", uid: 1001, mode: 0o700 }, bus: { kind: "socket", uid: 1001, mode: 0o600 } },
  };
}

function qualification(now = Date.now()) {
  const host_tuple = {
    tuple_version: "0.1",
    platform: "linux",
    architecture: "x86_64",
    kernel_release: "6.12.101+deb13-amd64",
    systemd_version: "257 (257.13-1~deb13u1)",
    cgroup_version: "v2",
    observed_at: new Date(now - 2_000).toISOString(),
  };
  const profile = {
    profile_version: "0.1",
    probe_kind: "inert-bounded-stdout-stderr",
    actor_identity_hash: `sha256:${"1".repeat(64)}`,
    on_behalf_of_chain_hash: `sha256:${"2".repeat(64)}`,
    executable: { path: "/opt/loopeix/s37.1/probe", sha256: APPROVED_HASHES.probe },
    argv: [],
    cwd: { path: "/", identity_hash: `sha256:${"3".repeat(64)}` },
    filesystem: { readable_paths: ["/opt/loopeix/s37.1/probe"], writable_paths: [], direct_writes: "deny" },
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
  const receiptBody = {
    receipt_version: "0.1",
    host_tuple_hash: hashCanonical({ purpose: "s37-linux-host-tuple-v02", ...host_tuple }),
    profile_hash: hashCanonical(profile),
    launcher_sha256: APPROVED_HASHES.supervisor,
    bwrap: { path: "/opt/loopeix/s37.1/bwrap", version: "0.11.0", sha256: APPROVED_HASHES.bwrap, setuid: false },
    seccomp_policy_sha256: APPROVED_HASHES.seccomp,
    deny_rows: [...DENY_ROWS],
    skipped_rows: [],
    issued_at: new Date(now - 1_000).toISOString(),
    expires_at: new Date(now + 60_000).toISOString(),
  };
  const backend_receipt = {
    ...receiptBody,
    receipt_hash: hashCanonical({ purpose: "s37-linux-backend-identity-receipt-v02", ...receiptBody }),
  };
  return { host_tuple, profile, backend_receipt };
}

function phaseBInputs(qualified = qualification(), now = Date.now()) {
  const observedAt = new Date(now - 3_000).toISOString();
  const validFrom = new Date(now - 120_000).toISOString();
  const validTo = new Date(now + 120_000).toISOString();
  const sampleTimes = [-60, -45, -30, -15, 0].map((offsetSeconds) =>
    new Date(Date.parse(observedAt) + offsetSeconds * 1_000).toISOString());
  const manifest = seal({
    schema_version: "s37-linux-phase-b-build-manifest-v1",
    created_at: new Date(now - 4_000).toISOString(),
    sources: {
      supervisor: { path: "scripts/s37-linux-phase-b/supervisor.c", sha256: APPROVED_SOURCE_HASHES.supervisor },
      probe: { path: "scripts/s37-linux-phase-b/probe.c", sha256: APPROVED_SOURCE_HASHES.probe },
    },
    compiler: {
      path: "/usr/bin/gcc",
      version: "14.2.0",
      target: "x86_64-linux-gnu",
      sha256: `sha256:${RAW}`,
      flags: ["-std=c17", "-D_FORTIFY_SOURCE=3", "-fstack-protector-strong", "-fPIE", "-Wall", "-Wextra", "-Werror", "-Wconversion", "-Wformat=2", "-Wshadow", "-Wstrict-prototypes", "-static-pie"],
    },
    artifacts: {
      supervisor: { path: "/opt/loopeix/s37.1/supervisor", sha256: APPROVED_HASHES.supervisor, mode: "0555", setuid: false },
      probe: { path: "/opt/loopeix/s37.1/probe", sha256: APPROVED_HASHES.probe, mode: "0555", setuid: false },
    },
    bwrap: {
      path: qualified.backend_receipt.bwrap.path,
      version: qualified.backend_receipt.bwrap.version,
      package_version: "0.11.0-2+deb13u1",
      sha256: qualified.backend_receipt.bwrap.sha256,
      mode: "0555",
      setuid: false,
    },
    seccomp_policy_sha256: qualified.backend_receipt.seccomp_policy_sha256,
    manifest_sha256: "",
  }, "manifest_sha256");
  const readiness_evidence = seal({
    schema_version: "s37-linux-phase-b-readiness-evidence-v1",
    observed_at: observedAt,
    host_tuple: {
      platform: "linux",
      architecture: "x86_64",
      distro_id: "debian",
      distro_version_id: "13",
      kernel_release: qualified.host_tuple.kernel_release,
      systemd_version: qualified.host_tuple.systemd_version,
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
      port_evidence: { count: 29, sha256: RAW, captured_at: observedAt },
    },
    package_review: {
      candidate_version: "0.11.0-2+deb13u1",
      package_file_list_sha256: RAW,
      mandatory_sysctl_path: "/usr/lib/sysctl.d/50-bubblewrap.conf",
      mandatory_sysctl_path_present: true,
      acquisition_mode: "extract-only-user-staging",
      system_package_install: false,
      sysctl_applied: false,
      service_restart: false,
      selected_artifact: { path: qualified.backend_receipt.bwrap.path, sha256: qualified.backend_receipt.bwrap.sha256.slice("sha256:".length), setuid: false },
      clean_install_evidence: null,
    },
    capacity_samples: sampleTimes.map((timestamp) => ({
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
  const readiness_envelope = seal({
    schema_version: "s37-linux-phase-b-readiness-envelope-v1",
    approved_at: new Date(Date.parse(validFrom) - 60_000).toISOString(),
    approved_by: "illustrative-test-operator",
    valid_from: validFrom,
    valid_to: validTo,
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
      kernel_release: qualified.host_tuple.kernel_release,
      systemd_version: qualified.host_tuple.systemd_version,
      cgroup_version: 2,
      required_cgroup_controllers: ["cpu", "io", "memory", "pids"],
      unprivileged_userns_clone: true,
      user_manager_status: "running-delegated",
    },
    package_requirements: {
      candidate_version: "0.11.0-2+deb13u1",
      package_file_list_sha256: RAW,
      selected_artifact_path: qualified.backend_receipt.bwrap.path,
      selected_artifact_sha256: qualified.backend_receipt.bwrap.sha256.slice("sha256:".length),
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
  const profileHash = hashCanonical(qualified.profile);
  const snapshot = { count: 29, sha256: RAW };
  const conformance_evidence = seal({
    schema_version: "s37-linux-phase-b-conformance-evidence-v1",
    observed_at: new Date(now - 500).toISOString(),
    host_tuple: qualified.host_tuple,
    manifest_sha256: manifest.manifest_sha256,
    readiness_evidence_sha256: readiness_evidence.evidence_sha256,
    readiness_envelope_sha256: readiness_envelope.envelope_sha256,
    execution: {
      unit_name: "loopeix-s37.1-conformance-abcdef123456",
      service_type: "exec",
      scope: false,
      pipe: false,
      standard_input: "null",
      standard_output: "null",
      standard_error: "null",
      no_new_privileges: true,
      kill_mode: "control-group",
      concurrency: 1,
      cpu_quota_percent: 25,
      memory_max_bytes: 64_000_000,
      tasks_max: 8,
      io_weight: 10,
      timeout_ms: 1_000,
      stdout_limit_bytes: 1_024,
      stderr_limit_bytes: 1_024,
      process_started: true,
      exit_code: 0,
      probe_duration_ms: 12,
      stdout_bytes: 0,
      stderr_bytes: 0,
      profile_hash: profileHash,
      launcher_sha256: qualified.backend_receipt.launcher_sha256,
      seccomp_policy_sha256: qualified.backend_receipt.seccomp_policy_sha256,
    },
    deny_rows: DENY_ROWS.map((row) => ({ row, passed: true, skipped: false, witness_sha256: RAW })),
    ports: { before: snapshot, after: { ...snapshot }, delta: 0 },
    neighbors: {
      services_before: { count: 24, sha256: RAW },
      services_after: { count: 24, sha256: RAW },
      containers_before: { count: 7, sha256: RAW },
      containers_after: { count: 7, sha256: RAW },
    },
    cleanup: {
      unit_absent: true,
      process_absent: true,
      mount_absent: true,
      temp_absent: true,
      journal_payload_absent: true,
      file_absent: true,
    },
    capacity: {
      envelope_sha256: readiness_envelope.envelope_sha256,
      samples_sha256: digest(readiness_evidence.capacity_samples),
      within_envelope: true,
      swap_growth_bytes: 0,
    },
    receipt_hash: qualified.backend_receipt.receipt_hash,
    evidence_sha256: "",
  }, "evidence_sha256");
  return {
    manifest,
    readiness_evidence,
    readiness_envelope,
    conformance_evidence,
    receipt: structuredClone(qualified.backend_receipt),
  };
}

function writeJson(root: string, name: string, value: unknown): string {
  const path = join(root, name);
  writeFileSync(path, `${JSON.stringify(value)}\n`, "utf8");
  return path;
}

function runGenerate(
  qualified = qualification(),
  phaseB = phaseBInputs(qualified),
  extraArgs: readonly string[] = [],
) {
  const root = mkdtempSync(join(tmpdir(), "loopeix-s37d-host-"));
  ROOTS.push(root);
  const qualificationPath = writeJson(root, "qualification.json", qualified);
  const manifestPath = writeJson(root, "manifest.json", phaseB.manifest);
  const readinessEvidencePath = writeJson(root, "readiness-evidence.json", phaseB.readiness_evidence);
  const readinessEnvelopePath = writeJson(root, "readiness-envelope.json", phaseB.readiness_envelope);
  const conformancePath = writeJson(root, "conformance-evidence.json", phaseB.conformance_evidence);
  const receiptPath = writeJson(root, "receipt.json", phaseB.receipt);
  return spawnSync(process.execPath, [
    "scripts/s37-linux-phase-d/check-and-generate-binding.mjs",
    "--qualification", qualificationPath,
    "--manifest", manifestPath,
    "--readiness-evidence", readinessEvidencePath,
    "--readiness-envelope", readinessEnvelopePath,
    "--conformance-evidence", conformancePath,
    "--receipt", receiptPath,
    ...extraArgs,
  ], { cwd: process.cwd(), encoding: "utf8", shell: false });
}

function runGenerateWithPaths(paths: {
  qualification: string;
  manifest: string;
  readinessEvidence: string;
  readinessEnvelope: string;
  conformanceEvidence: string;
  receipt: string;
}, extraArgs: readonly string[] = []) {
  return spawnSync(process.execPath, [
    "scripts/s37-linux-phase-d/check-and-generate-binding.mjs",
    "--qualification", paths.qualification,
    "--manifest", paths.manifest,
    "--readiness-evidence", paths.readinessEvidence,
    "--readiness-envelope", paths.readinessEnvelope,
    "--conformance-evidence", paths.conformanceEvidence,
    "--receipt", paths.receipt,
    ...extraArgs,
  ], { cwd: process.cwd(), encoding: "utf8", shell: false });
}

afterEach(() => {
  while (ROOTS.length > 0) rmSync(ROOTS.pop()!, { recursive: true, force: true });
});

describe("S37.1-D dedicated product-host qualification", () => {
  it("derives a fixed, root-owned binding only from exact sealed Phase B evidence", () => {
    const qualified = qualification();
    const phaseB = phaseBInputs(qualified);
    const result = evaluateS37PhaseDHost(capture(), qualified, phaseB, new Date());
    expect(result).toMatchObject({ ok: true, terminal: "GO" });
    if (!result.ok) return;
    expect(result.binding).toMatchObject({
      host_role: "local-product",
      transport: "local-only",
      controller_uid: 1001,
      phase_b_manifest_sha256: phaseB.manifest.manifest_sha256,
      artifacts: {
        supervisor_sha256: APPROVED_HASHES.supervisor,
        systemd_run_sha256: hashBytes(BYTES.systemd_run),
        systemctl_sha256: hashBytes(BYTES.systemctl),
      },
    });
    const plan = buildS37PhaseDBindingInstallPlan(result.binding);
    expect(plan).toMatchObject({ destination: S37_PHASE_D_BINDING_PATH, uid: 0, gid: 0, mode: 0o444, overwrite: false });
    expect(plan.sha256).toBe(`sha256:${createHash("sha256").update(plan.bytes).digest("hex")}`);
  });

  it("HOLDs qualification-only generation without the exact sealed Phase B inputs", () => {
    const root = mkdtempSync(join(tmpdir(), "loopeix-s37d-host-qualification-only-"));
    ROOTS.push(root);
    const qualificationPath = writeJson(root, "qualification.json", qualification());
    const result = spawnSync(process.execPath, [
      "scripts/s37-linux-phase-d/check-and-generate-binding.mjs",
      "--qualification", qualificationPath,
    ], { cwd: process.cwd(), encoding: "utf8", shell: false });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: phase-b-sealed-inputs-required");
  });

  it.each([
    ["root controller", (host: ReturnType<typeof capture>) => { host.controller_uid = 0; }],
    ["writable trusted directory", (host: ReturnType<typeof capture>) => { host.directories["/opt"].mode = 0o777; }],
    ["symlinked artifact", (host: ReturnType<typeof capture>) => { host.files.bwrap.metadata.kind = "symlink"; }],
    ["wrong artifact mode", (host: ReturnType<typeof capture>) => { host.files.probe.metadata.mode = 0o755; }],
    ["hard-linked artifact", (host: ReturnType<typeof capture>) => { host.files.supervisor.metadata.nlink = 2; }],
    ["missing cgroup controller", (host: ReturnType<typeof capture>) => { host.files.cgroup_controllers.bytes = Buffer.from("cpu memory pids\n"); }],
    ["arm64 guest", (host: ReturnType<typeof capture>) => { host.architecture = "aarch64"; }],
  ])("HOLDs on %s", (_name, mutate) => {
    const host = capture();
    mutate(host);
    const qualified = qualification();
    expect(evaluateS37PhaseDHost(host, qualified, phaseBInputs(qualified), new Date())).toMatchObject({ ok: false, terminal: "HOLD" });
  });

  it("rejects caller/evidence hash drift and insufficient receipt lifetime", () => {
    const now = Date.now();
    const drifted = qualification(now);
    drifted.backend_receipt.launcher_sha256 = `sha256:${"f".repeat(64)}`;
    expect(evaluateS37PhaseDHost(capture(), drifted, phaseBInputs(drifted, now), new Date(now))).toMatchObject({ ok: false });

    const short = qualification(now);
    short.backend_receipt.expires_at = new Date(now + 3_000).toISOString();
    const { receipt_hash: _shortHash, ...shortBody } = short.backend_receipt;
    short.backend_receipt.receipt_hash = hashCanonical({ purpose: "s37-linux-backend-identity-receipt-v02", ...shortBody });
    const shortInputs = phaseBInputs(short, now);
    shortInputs.receipt = structuredClone(short.backend_receipt);
    shortInputs.conformance_evidence.receipt_hash = short.backend_receipt.receipt_hash;
    shortInputs.conformance_evidence = seal(shortInputs.conformance_evidence, "evidence_sha256");
    const result = evaluateS37PhaseDHost(capture(), short, shortInputs, new Date(now));
    expect(result).toMatchObject({ ok: false });
    if (!result.ok) expect(result.violations).toContain("receipt-window-insufficient");

    const stale = qualification(now);
    stale.host_tuple.observed_at = new Date(now - 15_001).toISOString();
    stale.backend_receipt.host_tuple_hash = hashCanonical({ purpose: "s37-linux-host-tuple-v02", ...stale.host_tuple });
    const { receipt_hash: _staleHash, ...staleBody } = stale.backend_receipt;
    stale.backend_receipt.receipt_hash = hashCanonical({ purpose: "s37-linux-backend-identity-receipt-v02", ...staleBody });
    const staleInputs = phaseBInputs(stale, now);
    staleInputs.receipt = structuredClone(stale.backend_receipt);
    staleInputs.conformance_evidence.host_tuple = stale.host_tuple;
    staleInputs.conformance_evidence.receipt_hash = stale.backend_receipt.receipt_hash;
    staleInputs.conformance_evidence = seal(staleInputs.conformance_evidence, "evidence_sha256");
    const staleResult = evaluateS37PhaseDHost(capture(), stale, staleInputs, new Date(now));
    expect(staleResult).toMatchObject({ ok: false });
    if (!staleResult.ok) expect(staleResult.violations).toContain("host-tuple-stale");
  });

  it("rejects a self-consistently rehashed but broadened profile", () => {
    const widened = qualification();
    widened.profile.network.allowed_origins.push("https://example.invalid");
    widened.backend_receipt.profile_hash = hashCanonical(widened.profile);
    const { receipt_hash: _receiptHash, ...body } = widened.backend_receipt;
    widened.backend_receipt.receipt_hash = hashCanonical({ purpose: "s37-linux-backend-identity-receipt-v02", ...body });
    const inputs = phaseBInputs(widened);
    inputs.receipt = structuredClone(widened.backend_receipt);
    inputs.conformance_evidence.execution.profile_hash = hashCanonical(widened.profile);
    inputs.conformance_evidence.receipt_hash = widened.backend_receipt.receipt_hash;
    inputs.conformance_evidence = seal(inputs.conformance_evidence, "evidence_sha256");
    const result = evaluateS37PhaseDHost(capture(), widened, inputs, new Date());
    expect(result).toMatchObject({ ok: false });
    if (!result.ok) expect(result.violations).toContain("profile-contract-invalid");
  });

  it("rejects self-consistently rehashed but unapproved host systemd provenance", () => {
    const host = capture();
    host.files.systemd_run.sha256 = `sha256:${"f".repeat(64)}`;
    const qualified = qualification();
    const result = evaluateS37PhaseDHost(host, qualified, phaseBInputs(qualified), new Date());
    expect(result).toMatchObject({ ok: false });
    if (!result.ok) expect(result.violations).toContain("systemd-run-provenance-unapproved");
  });

  it("rejects sealed Phase B drift in readiness, conformance, and receipt linkage", () => {
    const qualified = qualification();
    const inputs = phaseBInputs(qualified);
    inputs.readiness_envelope.min_sample_count = 4;
    inputs.readiness_envelope = seal(inputs.readiness_envelope, "envelope_sha256", readinessCanonical);
    inputs.conformance_evidence.readiness_envelope_sha256 = inputs.readiness_envelope.envelope_sha256;
    inputs.conformance_evidence.capacity.envelope_sha256 = inputs.readiness_envelope.envelope_sha256;
    inputs.conformance_evidence.neighbors.services_after.count += 1;
    inputs.conformance_evidence = seal(inputs.conformance_evidence, "evidence_sha256");

    const result = evaluateS37PhaseDHost(capture(), qualified, inputs, new Date());
    expect(result).toMatchObject({ ok: false });
    if (!result.ok) {
      expect(result.violations).toContain("phase-b-readiness-min-samples-invalid");
      expect(result.violations).toContain("phase-b-neighbor-drift");
    }
  });

  it.each([
    ["service type", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.execution.service_type = "simple"; }, "phase-b-execution-service-type-invalid"],
    ["scope", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.execution.scope = true; }, "phase-b-execution-scope-invalid"],
    ["pipe", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.execution.pipe = true; }, "phase-b-execution-pipe-invalid"],
    ["standard input", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.execution.standard_input = "inherit"; }, "phase-b-execution-stdio-invalid:standard_input"],
    ["standard output", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.execution.standard_output = "journal"; }, "phase-b-execution-stdio-invalid:standard_output"],
    ["standard error", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.execution.standard_error = "journal"; }, "phase-b-execution-stdio-invalid:standard_error"],
    ["no new privileges", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.execution.no_new_privileges = false; }, "phase-b-execution-no-new-privileges-invalid"],
    ["kill mode", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.execution.kill_mode = "process"; }, "phase-b-execution-kill-mode-invalid"],
    ["concurrency", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.execution.concurrency = 2; }, "phase-b-execution-concurrency-invalid"],
    ["cpu quota", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.execution.cpu_quota_percent = 26; }, "phase-b-execution-limit-invalid:cpu_quota_percent"],
    ["memory max", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.execution.memory_max_bytes = 64_000_001; }, "phase-b-execution-limit-invalid:memory_max_bytes"],
    ["tasks max", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.execution.tasks_max = 9; }, "phase-b-execution-limit-invalid:tasks_max"],
    ["io weight", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.execution.io_weight = 11; }, "phase-b-execution-limit-invalid:io_weight"],
    ["timeout", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.execution.timeout_ms = 1_001; }, "phase-b-execution-limit-invalid:timeout_ms"],
    ["stdout limit", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.execution.stdout_limit_bytes = 1_025; }, "phase-b-execution-stdout-limit-invalid"],
    ["stderr limit", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.execution.stderr_limit_bytes = 1_025; }, "phase-b-execution-stderr-limit-invalid"],
    ["process started", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.execution.process_started = false; }, "phase-b-execution-process-not-started"],
    ["exit code", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.execution.exit_code = 81; }, "phase-b-execution-exit-code-invalid"],
    ["duration", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.execution.probe_duration_ms = 1_001; }, "phase-b-execution-duration-invalid"],
    ["stdout bytes", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.execution.stdout_bytes = 1; }, "phase-b-execution-stdout-nonzero"],
    ["stderr bytes", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.execution.stderr_bytes = 1; }, "phase-b-execution-stderr-nonzero"],
    ["profile link", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.execution.profile_hash = `sha256:${"c".repeat(64)}`; }, "phase-b-conformance-profile-mismatch"],
    ["launcher link", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.execution.launcher_sha256 = `sha256:${"d".repeat(64)}`; }, "phase-b-conformance-launcher-mismatch"],
    ["seccomp link", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.execution.seccomp_policy_sha256 = `sha256:${"e".repeat(64)}`; }, "phase-b-conformance-seccomp-mismatch"],
    ["envelope fixed resource limit", (inputs: ReturnType<typeof phaseBInputs>) => {
      inputs.readiness_envelope.resource_limits.tasks_max = 9;
      inputs.conformance_evidence.execution.tasks_max = 9;
    }, "phase-b-envelope-limit-invalid:tasks_max"],
  ] as const)("rejects exact Phase B execution contract drift in %s", (_label, mutate, expectedViolation) => {
    const qualified = qualification();
    const inputs = phaseBInputs(qualified);
    mutate(inputs);
    inputs.conformance_evidence = seal(inputs.conformance_evidence, "evidence_sha256");
    if ("envelope_sha256" in inputs.readiness_envelope) {
      inputs.readiness_envelope = seal(inputs.readiness_envelope, "envelope_sha256", readinessCanonical);
      inputs.conformance_evidence.readiness_envelope_sha256 = inputs.readiness_envelope.envelope_sha256;
      inputs.conformance_evidence.capacity.envelope_sha256 = inputs.readiness_envelope.envelope_sha256;
      inputs.conformance_evidence = seal(inputs.conformance_evidence, "evidence_sha256");
    }
    const result = evaluateS37PhaseDHost(capture(), qualified, inputs, new Date());
    expect(result).toMatchObject({ ok: false, terminal: "HOLD" });
    if (!result.ok) expect(result.violations).toContain(expectedViolation);
  });

  it.each([
    ["manifest schema", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.manifest.schema_version = "s37-linux-phase-b-build-manifest-v0"; }, "phase-b-manifest-schema-invalid"],
    ["manifest seal", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.manifest.manifest_sha256 = RAW.replace(/a/u, "b"); }, "phase-b-manifest-seal-invalid"],
    ["manifest link", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.manifest_sha256 = RAW; }, "phase-b-conformance-manifest-mismatch"],
    ["manifest supervisor source", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.manifest.sources.supervisor.sha256 = `sha256:${"1".repeat(64)}`; }, "phase-b-manifest-source-unapproved:supervisor"],
    ["manifest probe source", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.manifest.sources.probe.sha256 = `sha256:${"2".repeat(64)}`; }, "phase-b-manifest-source-unapproved:probe"],
    ["manifest supervisor artifact", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.manifest.artifacts.supervisor.sha256 = `sha256:${"3".repeat(64)}`; }, "phase-b-manifest-artifact-unapproved:supervisor"],
    ["manifest probe artifact", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.manifest.artifacts.probe.sha256 = `sha256:${"4".repeat(64)}`; }, "phase-b-manifest-artifact-unapproved:probe"],
    ["manifest bwrap artifact", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.manifest.bwrap.sha256 = `sha256:${"5".repeat(64)}`; }, "phase-b-manifest-bwrap-unapproved"],
    ["manifest seccomp policy", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.manifest.seccomp_policy_sha256 = `sha256:${"6".repeat(64)}`; }, "phase-b-manifest-seccomp-unapproved"],
  ] as const)("rejects Phase B manifest continuity drift in %s", (_label, mutate, expectedViolation) => {
    const qualified = qualification();
    const inputs = phaseBInputs(qualified);
    mutate(inputs);
    if (expectedViolation !== "phase-b-manifest-seal-invalid") inputs.manifest = seal(inputs.manifest, "manifest_sha256");
    if (expectedViolation !== "phase-b-conformance-manifest-mismatch") {
      inputs.conformance_evidence.manifest_sha256 = inputs.manifest.manifest_sha256;
    }
    inputs.conformance_evidence = seal(inputs.conformance_evidence, "evidence_sha256");
    const result = evaluateS37PhaseDHost(capture(), qualified, inputs, new Date());
    expect(result).toMatchObject({ ok: false, terminal: "HOLD" });
    if (!result.ok) expect(result.violations).toContain(expectedViolation);
  });

  it.each([
    ["receipt skipped rows", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.receipt.skipped_rows = ["retry"]; }, "phase-b-receipt-skipped-rows-invalid"],
    ["receipt deny row order", (inputs: ReturnType<typeof phaseBInputs>) => {
      [inputs.receipt.deny_rows[0], inputs.receipt.deny_rows[1]] = [inputs.receipt.deny_rows[1], inputs.receipt.deny_rows[0]];
    }, "phase-b-receipt-deny-rows-invalid"],
    ["conformance deny row order", (inputs: ReturnType<typeof phaseBInputs>) => {
      [inputs.conformance_evidence.deny_rows[0], inputs.conformance_evidence.deny_rows[1]] = [inputs.conformance_evidence.deny_rows[1], inputs.conformance_evidence.deny_rows[0]];
    }, "phase-b-deny-rows-order-invalid"],
    ["conformance deny row skipped", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.deny_rows[0].skipped = true; }, "phase-b-deny-row-invalid:ambient-credentials"],
    ["conformance deny row failed", (inputs: ReturnType<typeof phaseBInputs>) => { inputs.conformance_evidence.deny_rows[0].passed = false; }, "phase-b-deny-row-invalid:ambient-credentials"],
  ] as const)("rejects Phase B deny/receipt drift in %s", (_label, mutate, expectedViolation) => {
    const qualified = qualification();
    const inputs = phaseBInputs(qualified);
    mutate(inputs);
    inputs.conformance_evidence = seal(inputs.conformance_evidence, "evidence_sha256");
    const result = evaluateS37PhaseDHost(capture(), qualified, inputs, new Date());
    expect(result).toMatchObject({ ok: false, terminal: "HOLD" });
    if (!result.ok) expect(result.violations).toContain(expectedViolation);
  });

  it("enforces exact receipt linkage in the pure evaluator and parses the generator inputs before the Linux gate", () => {
    const qualified = qualification();
    const driftedInputs = phaseBInputs(qualified);
    driftedInputs.conformance_evidence.receipt_hash = `sha256:${"b".repeat(64)}`;
    driftedInputs.conformance_evidence = seal(driftedInputs.conformance_evidence, "evidence_sha256");
    const direct = evaluateS37PhaseDHost(capture(), qualified, driftedInputs, new Date());
    expect(direct).toMatchObject({ ok: false, terminal: "HOLD" });
    if (!direct.ok) expect(direct.violations).toContain("phase-b-conformance-receipt-mismatch");

    const parsed = runGenerate(qualified, phaseBInputs(qualified), ["--controller-uid", "1001"]);
    expect(parsed.status).toBe(1);
    expect(parsed.stderr).toContain("HOLD: S37_PHASE_D_PLATFORM_NOT_LINUX");
  });

  it.each([
    ["manifest", "manifest"],
    ["readiness evidence", "readinessEvidence"],
    ["readiness envelope", "readinessEnvelope"],
    ["conformance evidence", "conformanceEvidence"],
    ["receipt", "receipt"],
  ] as const)("requires an absolute Phase B %s path before host capture", (_label, key) => {
    const root = mkdtempSync(join(tmpdir(), "loopeix-s37d-host-relative-"));
    ROOTS.push(root);
    const qualified = qualification();
    const inputs = phaseBInputs(qualified);
    const paths = {
      qualification: writeJson(root, "qualification.json", qualified),
      manifest: writeJson(root, "manifest.json", inputs.manifest),
      readinessEvidence: writeJson(root, "readiness-evidence.json", inputs.readiness_evidence),
      readinessEnvelope: writeJson(root, "readiness-envelope.json", inputs.readiness_envelope),
      conformanceEvidence: writeJson(root, "conformance-evidence.json", inputs.conformance_evidence),
      receipt: writeJson(root, "receipt.json", inputs.receipt),
    };
    paths[key] = paths[key].slice(root.length + 1);
    const result = runGenerateWithPaths(paths, ["--controller-uid", "1001"]);
    expect(result.status).toBe(64);
    expect(result.stderr).toContain("path must be absolute");
  });

  it("keeps the installer behind exact Phase B inputs, root, Linux, explicit-apply, and fixed-destination gates", () => {
    const source = readFileSync("scripts/s37-linux-phase-d/install-binding.mjs", "utf8");
    expect(source).toContain("--readiness-evidence");
    expect(source).toContain("--readiness-envelope");
    expect(source).toContain("--conformance-evidence");
    expect(source).toContain("--receipt");
    expect(source).toContain("--apply-exact-s37-local-product-binding");
    expect(source).toContain('process.platform !== "linux"');
    expect(source).toContain("process.getuid() !== 0");
    expect(source).toContain("plan.overwrite !== false");
    expect(source).not.toContain("--destination");
  });
});
