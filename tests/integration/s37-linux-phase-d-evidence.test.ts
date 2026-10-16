import { createHash } from "node:crypto";
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

import { afterEach, describe, expect, it } from "vitest";

const SCRIPT = "scripts/check-s37-linux-phase-d-evidence.mjs";
const CATALOG_PATH = "scripts/s37-linux-phase-d/case-catalog.json";
const GIT_PATH = "/usr/bin/git";
const RAW = "a".repeat(64);
const CONTENT = `sha256:${RAW}`;
const roots: string[] = [];
const REPO_ROOT = resolve(".");
const BUILD_FLAGS = Object.freeze([
  "-std=c17",
  "-D_FORTIFY_SOURCE=3",
  "-fstack-protector-strong",
  "-fPIE",
  "-Wall",
  "-Wextra",
  "-Werror",
  "-Wconversion",
  "-Wformat=2",
  "-Wshadow",
  "-Wstrict-prototypes",
  "-static-pie",
]);
const CANONICAL_SOURCES = Object.freeze({
  controller_source_sha256: "src/run/linux-host-enforcement-v02.ts",
  broker_source_sha256: "src/run/pre-spawn-capability-broker-v02.ts",
  bounded_probe_source_sha256: "src/run/bounded-linux-probe-v02.ts",
  supervisor_source_sha256: "scripts/s37-linux-phase-b/supervisor.c",
  probe_source_sha256: "scripts/s37-linux-phase-b/probe.c",
});
const PHASE_B_SUPPORT_FILES = Object.freeze({
  manifest: "phase-b-manifest.json",
  readinessEvidence: "phase-b-readiness-evidence.json",
  readinessEnvelope: "phase-b-readiness-envelope.json",
  profile: "phase-b-profile.json",
  conformanceEvidence: "phase-b-conformance-evidence.json",
  receipt: "phase-b-receipt.json",
});
const repositoryFactsCache = new Map<string, Readonly<{
  commit: string;
  tree_sha256: string;
  source_hashes: Readonly<Record<string, string>>;
}>>();

type CatalogCase = Readonly<{
  id: string;
  lane: string;
  requirement: string;
  oracle: string;
}>;

type Catalog = Readonly<{
  schema_version: string;
  supervisor_source_sha256: string;
  probe_source_sha256: string;
  cases: readonly CatalogCase[];
  reviewer_roles: readonly string[];
  catalog_sha256: string;
}>;

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, entry]) => `${JSON.stringify(key)}:${canonical(entry)}`).join(",")}}`;
}

function digest(value: unknown): string {
  return createHash("sha256").update(canonical(value), "utf8").digest("hex");
}

function readinessCanonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(readinessCanonical).join(",")}]`;
  return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, entry]) => `${JSON.stringify(key)}:${readinessCanonical(entry)}`).join(",")}}`;
}

function readinessDigest(value: unknown): string {
  return createHash("sha256").update(readinessCanonical(value), "utf8").digest("hex");
}

function seal<T extends Record<string, unknown>>(value: T): T {
  const body = Object.fromEntries(Object.entries(value).filter(([key]) => key !== "evidence_sha256"));
  return { ...body, evidence_sha256: digest(body) } as T;
}

function sealWithSerializer<T extends Record<string, unknown>>(value: T, key: string, serializer: (value: unknown) => string): T {
  const body = Object.fromEntries(Object.entries(value).filter(([name]) => name !== key));
  return { ...body, [key]: createHash("sha256").update(serializer(body), "utf8").digest("hex") } as T;
}

function catalog(): Catalog {
  return JSON.parse(readFileSync(CATALOG_PATH, "utf8")) as Catalog;
}

function witnessBytes(id: string): Buffer {
  return Buffer.from(`${JSON.stringify({ schema_version: "s37-linux-phase-d-witness-v1", id, passed: true })}\n`, "utf8");
}

function fixture() {
  const cases = catalog().cases.map((entry) => ({
    id: entry.id,
    lane: entry.lane,
    oracle: entry.oracle,
    passed: true,
    skipped: false,
    witness_path: `witnesses/${entry.id}.json`,
    witness_sha256: createHash("sha256").update(witnessBytes(entry.id)).digest("hex"),
  }));
  const snapshot = { count: 7, sha256: RAW };
  const bindings = {
    repository_commit: "b".repeat(40),
    repository_tree_sha256: CONTENT,
    controller_source_sha256: CONTENT,
    broker_source_sha256: CONTENT,
    bounded_probe_source_sha256: CONTENT,
    phase_b_manifest_sha256: RAW,
    phase_b_receipt_sha256: CONTENT,
    supervisor_source_sha256: catalog().supervisor_source_sha256,
    probe_source_sha256: catalog().probe_source_sha256,
    bwrap_sha256: CONTENT,
    seccomp_policy_sha256: CONTENT,
  };
  const value = {
    schema_version: "s37-linux-phase-d-evidence-v1",
    created_at: "2026-08-23T12:00:00.000Z",
    catalog_sha256: catalog().catalog_sha256,
    bindings: { before: bindings, after: { ...bindings } },
    readiness: {
      evidence_sha256: RAW,
      envelope_sha256: RAW,
      sample_count: 5,
      within_envelope: true,
      fresh_at_start: true,
      unchanged_through_end: true,
    },
    cases,
    observations: {
      listening_ports_before: snapshot,
      listening_ports_after: { ...snapshot },
      services_before: { count: 24, sha256: RAW },
      services_after: { count: 24, sha256: RAW },
      containers_before: { count: 3, sha256: RAW },
      containers_after: { count: 3, sha256: RAW },
      swap_used_before_bytes: 0,
      swap_used_after_bytes: 0,
      swap_growth_bytes: 0,
      incumbent_service_transition_count: 0,
    },
    cleanup: {
      unit_absent: true,
      process_absent: true,
      mount_absent: true,
      temp_absent: true,
      journal_payload_absent: true,
      file_absent: true,
    },
    reviewers: [] as Array<{
      role: string;
      reviewer_identity_hash: string;
      reviewed_at: string;
      verdict: string;
      evidence_sha256: string;
      verdict_sha256: string;
    }>,
    evidence_sha256: "",
  };
  const reviewSubjectSha256 = digest(Object.fromEntries(
    Object.entries(value).filter(([key]) => key !== "reviewers" && key !== "evidence_sha256"),
  ));
  value.reviewers = catalog().reviewer_roles.map((role, index) => {
    const reviewer = {
      role,
      reviewer_identity_hash: `sha256:${String(index + 1).repeat(64)}`,
      reviewed_at: `2026-08-23T12:0${index + 1}:00.000Z`,
      verdict: "SHIP_IT",
      evidence_sha256: reviewSubjectSha256,
    };
    return {
      ...reviewer,
      verdict_sha256: digest({ purpose: "s37-linux-phase-d-review-verdict-v1", ...reviewer }),
    };
  });
  return seal(value);
}

function contentHash(path: string): string {
  return `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
}

function repositoryCommit(): string {
  const head = readFileSync(resolve(REPO_ROOT, ".git", "HEAD"), "utf8").trim();
  if (/^[a-f0-9]{40}$/u.test(head)) return head;
  const ref = /^ref:\s+(.+)$/u.exec(head)?.[1];
  if (ref === undefined) throw new Error("missing git HEAD ref");
  return readFileSync(resolve(REPO_ROOT, ".git", ...ref.split("/")), "utf8").trim();
}

function trackedRepositoryFiles(root: string): readonly string[] {
  const result = spawnSync(GIT_PATH, ["-C", root, "ls-files", "-z"], {
    cwd: root,
    encoding: "utf8",
    shell: false,
  });
  if (result.error !== undefined) throw result.error;
  if (result.status !== 0) throw new Error(result.stderr || `git ls-files failed: ${String(result.status)}`);
  return result.stdout
    .split("\0")
    .filter((entry) => entry.length > 0)
    .sort((left, right) => left.localeCompare(right));
}

function repositoryFacts() {
  const cached = repositoryFactsCache.get(REPO_ROOT);
  if (cached !== undefined) return cached;
  const entries: Array<Record<string, string | number>> = [];
  for (const normalizedPath of trackedRepositoryFiles(REPO_ROOT)) {
    const absolutePath = resolve(REPO_ROOT, normalizedPath);
    const stat = lstatSync(absolutePath);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`invalid repo entry: ${normalizedPath}`);
    const bytes = readFileSync(absolutePath);
    entries.push({
      path: normalizedPath,
      type: "file",
      mode: stat.mode,
      size: bytes.byteLength,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    });
  }
  const facts = Object.freeze({
    commit: repositoryCommit(),
    tree_sha256: `sha256:${createHash("sha256").update(JSON.stringify(entries)).digest("hex")}`,
    source_hashes: Object.freeze(Object.fromEntries(
      Object.entries(CANONICAL_SOURCES).map(([key, path]) => [key, contentHash(path)]),
    )),
  });
  repositoryFactsCache.set(REPO_ROOT, facts);
  return facts;
}

function canonicalBindings() {
  const repository = repositoryFacts();
  return {
    repository_commit: repository.commit,
    repository_tree_sha256: repository.tree_sha256,
    controller_source_sha256: repository.source_hashes.controller_source_sha256,
    broker_source_sha256: repository.source_hashes.broker_source_sha256,
    bounded_probe_source_sha256: repository.source_hashes.bounded_probe_source_sha256,
    supervisor_source_sha256: repository.source_hashes.supervisor_source_sha256,
    probe_source_sha256: repository.source_hashes.probe_source_sha256,
  };
}

function phaseBSupport() {
  const bindings = canonicalBindings();
  const hostTuple = {
    tuple_version: "0.1",
    platform: "linux",
    architecture: "x86_64",
    kernel_release: "6.12.101+deb13-amd64",
    systemd_version: "257.13-1~deb13u1",
    cgroup_version: "v2",
    observed_at: "2026-08-23T12:00:02.000Z",
  };
  const profile = {
    profile_version: "0.1",
    probe_kind: "inert-bounded-stdout-stderr",
    actor_identity_hash: CONTENT,
    on_behalf_of_chain_hash: CONTENT,
    executable: { path: "/opt/loopeix/s37.1/probe", sha256: CONTENT },
    argv: [],
    cwd: { path: "/", identity_hash: CONTENT },
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
  const profileHash = `sha256:${digest(profile)}`;
  const manifest = sealWithSerializer({
    schema_version: "s37-linux-phase-b-build-manifest-v1",
    created_at: "2026-08-23T11:59:00.000Z",
    sources: {
      supervisor: { path: "scripts/s37-linux-phase-b/supervisor.c", sha256: bindings.supervisor_source_sha256 },
      probe: { path: "scripts/s37-linux-phase-b/probe.c", sha256: bindings.probe_source_sha256 },
    },
    compiler: {
      path: "/usr/bin/gcc",
      version: "14.2.0",
      target: "x86_64-linux-gnu",
      sha256: CONTENT,
      flags: [...BUILD_FLAGS],
    },
    artifacts: {
      supervisor: { path: "/opt/loopeix/s37.1/supervisor", sha256: CONTENT, mode: "0555", setuid: false },
      probe: { path: "/opt/loopeix/s37.1/probe", sha256: CONTENT, mode: "0555", setuid: false },
    },
    bwrap: { path: "/opt/loopeix/s37.1/bwrap", version: "0.11.0", package_version: "0.11.0-2+deb13u1", sha256: CONTENT, mode: "0555", setuid: false },
    seccomp_policy_sha256: CONTENT,
    manifest_sha256: "",
  }, "manifest_sha256", canonical);

  const readinessEvidence = sealWithSerializer({
    schema_version: "s37-linux-phase-b-readiness-evidence-v1",
    observed_at: "2026-08-23T12:00:00.000Z",
    host_tuple: {
      platform: "linux",
      architecture: "x86_64",
      distro_id: "debian",
      distro_version_id: "13",
      kernel_release: "6.12.101+deb13-amd64",
      systemd_version: "257.13-1~deb13u1",
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
      port_evidence: { count: 7, sha256: RAW, captured_at: "2026-08-23T12:00:00.000Z" },
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
      selected_artifact: { path: "/opt/loopeix/s37.1/bwrap", sha256: RAW, setuid: false },
      clean_install_evidence: null,
    },
    capacity_samples: [
      "2026-08-23T11:59:00.000Z",
      "2026-08-23T11:59:15.000Z",
      "2026-08-23T11:59:30.000Z",
      "2026-08-23T11:59:45.000Z",
      "2026-08-23T12:00:00.000Z",
    ].map((timestamp) => ({
      timestamp,
      cpu_cores: 4,
      memory_available_bytes: 12_000_000_000,
      swap_used_bytes: 0,
      load1: 0.1,
      load5: 0.1,
      cpu_psi_some_avg10: 0.01,
      memory_psi_some_avg10: 0.01,
      io_psi_some_avg10: 0.01,
      tasks: 20,
    })),
    evidence_sha256: "",
  }, "evidence_sha256", readinessCanonical);

  const readinessEnvelope = sealWithSerializer({
    schema_version: "s37-linux-phase-b-readiness-envelope-v1",
    approved_at: "2026-08-23T11:58:00.000Z",
    approved_by: "illustrative-test-operator",
    valid_from: "2026-08-23T11:58:30.000Z",
    valid_to: "2026-08-23T12:10:00.000Z",
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
      systemd_version: "257.13-1~deb13u1",
      cgroup_version: 2,
      required_cgroup_controllers: ["cpu", "io", "memory", "pids"],
      unprivileged_userns_clone: true,
      user_manager_status: "running-delegated",
    },
    package_requirements: {
      candidate_version: "0.11.0-2+deb13u1",
      package_file_list_sha256: RAW,
      selected_artifact_path: "/opt/loopeix/s37.1/bwrap",
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
      min_memory_available_bytes: "Keeps memory reserve for incumbent workloads.",
      max_swap_used_bytes: "Prevents trials during memory contention.",
      max_swap_growth_bytes: "Stops trials if swapping begins.",
      max_load1: "Keeps short-term scheduler demand below the reviewed ceiling.",
      max_load5: "Keeps sustained scheduler demand below the reviewed ceiling.",
      max_cpu_psi_some_avg10: "Prevents trials during CPU pressure.",
      max_memory_psi_some_avg10: "Prevents trials during memory pressure.",
      max_io_psi_some_avg10: "Prevents trials during IO pressure.",
    },
    resource_limits: { cpu_quota_percent: 25, memory_max_bytes: 64_000_000, tasks_max: 8, io_weight: 10, timeout_ms: 1_000, stdout_bytes: 1_024, stderr_bytes: 1_024 },
    resource_limit_reasons: {
      cpu_quota_percent: "Caps the inert probe to one quarter of one CPU.",
      memory_max_bytes: "Caps the launcher and probe below the approved reserve.",
      tasks_max: "Allows only bounded setup helpers.",
      io_weight: "Gives the conformance unit the lowest practical IO priority.",
      timeout_ms: "Matches the frozen hard runtime deadline.",
      stdout_bytes: "Matches the frozen per-stream stdout custody cap.",
      stderr_bytes: "Matches the frozen per-stream stderr custody cap.",
    },
    envelope_sha256: "",
  }, "envelope_sha256", readinessCanonical);

  const receiptBody = {
    receipt_version: "0.1",
    host_tuple_hash: `sha256:${digest({ purpose: "s37-linux-host-tuple-v02", ...hostTuple })}`,
    profile_hash: profileHash,
    launcher_sha256: CONTENT,
    bwrap: { path: "/opt/loopeix/s37.1/bwrap", version: "0.11.0", sha256: CONTENT, setuid: false },
    seccomp_policy_sha256: CONTENT,
    deny_rows: [
      "ambient-credentials", "child-process", "durable-state", "environment",
      "filesystem-write", "network", "output-limits", "retry", "stdin",
      "timeout", "tool-server", "unknown-outcome",
    ],
    skipped_rows: [],
    issued_at: "2026-08-23T12:00:02.000Z",
    expires_at: "2026-08-23T12:09:59.000Z",
  };
  const receipt = {
    ...receiptBody,
    receipt_hash: `sha256:${digest({ purpose: "s37-linux-backend-identity-receipt-v02", ...receiptBody })}`,
  };

  const conformanceEvidence = sealWithSerializer({
    schema_version: "s37-linux-phase-b-conformance-evidence-v1",
    observed_at: "2026-08-23T12:00:03.000Z",
    host_tuple: hostTuple,
    manifest_sha256: manifest.manifest_sha256,
    readiness_evidence_sha256: readinessEvidence.evidence_sha256,
    readiness_envelope_sha256: readinessEnvelope.envelope_sha256,
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
      launcher_sha256: CONTENT,
      seccomp_policy_sha256: CONTENT,
    },
    deny_rows: [
      "ambient-credentials", "child-process", "durable-state", "environment",
      "filesystem-write", "network", "output-limits", "retry", "stdin",
      "timeout", "tool-server", "unknown-outcome",
    ].map((row) => ({ row, passed: true, skipped: false, witness_sha256: RAW })),
    ports: { before: { count: 7, sha256: RAW }, after: { count: 7, sha256: RAW }, delta: 0 },
    neighbors: {
      services_before: { count: 24, sha256: RAW },
      services_after: { count: 24, sha256: RAW },
      containers_before: { count: 3, sha256: RAW },
      containers_after: { count: 3, sha256: RAW },
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
      envelope_sha256: readinessEnvelope.envelope_sha256,
      samples_sha256: digest(readinessEvidence.capacity_samples),
      within_envelope: true,
      swap_growth_bytes: 0,
    },
    receipt_hash: receipt.receipt_hash,
    evidence_sha256: "",
  }, "evidence_sha256", canonical);

  return {
    bindings,
    files: {
      [PHASE_B_SUPPORT_FILES.manifest]: manifest,
      [PHASE_B_SUPPORT_FILES.readinessEvidence]: readinessEvidence,
      [PHASE_B_SUPPORT_FILES.readinessEnvelope]: readinessEnvelope,
      [PHASE_B_SUPPORT_FILES.profile]: profile,
      [PHASE_B_SUPPORT_FILES.conformanceEvidence]: conformanceEvidence,
      [PHASE_B_SUPPORT_FILES.receipt]: receipt,
    },
  };
}

function canonicalPassEvidence() {
  const support = phaseBSupport();
  const bindings = {
    repository_commit: support.bindings.repository_commit,
    repository_tree_sha256: support.bindings.repository_tree_sha256,
    controller_source_sha256: support.bindings.controller_source_sha256,
    broker_source_sha256: support.bindings.broker_source_sha256,
    bounded_probe_source_sha256: support.bindings.bounded_probe_source_sha256,
    phase_b_manifest_sha256: (support.files[PHASE_B_SUPPORT_FILES.manifest] as Record<string, unknown>).manifest_sha256 as string,
    phase_b_receipt_sha256: (support.files[PHASE_B_SUPPORT_FILES.receipt] as Record<string, unknown>).receipt_hash as string,
    supervisor_source_sha256: support.bindings.supervisor_source_sha256,
    probe_source_sha256: support.bindings.probe_source_sha256,
    bwrap_sha256: CONTENT,
    seccomp_policy_sha256: CONTENT,
  };
  const value = fixture();
  value.bindings = { before: { ...bindings }, after: { ...bindings } };
  value.readiness = {
    evidence_sha256: (support.files[PHASE_B_SUPPORT_FILES.readinessEvidence] as Record<string, unknown>).evidence_sha256 as string,
    envelope_sha256: (support.files[PHASE_B_SUPPORT_FILES.readinessEnvelope] as Record<string, unknown>).envelope_sha256 as string,
    sample_count: 5,
    within_envelope: true,
    fresh_at_start: true,
    unchanged_through_end: true,
  };
  const body = Object.fromEntries(Object.entries(value).filter(([key]) => key !== "reviewers" && key !== "evidence_sha256"));
  const reviewSubjectSha256 = digest(body);
  value.reviewers = value.reviewers.map((reviewer) => {
    const next = { ...reviewer, evidence_sha256: reviewSubjectSha256 };
    return {
      ...next,
      verdict_sha256: digest({ purpose: "s37-linux-phase-d-review-verdict-v1", ...Object.fromEntries(Object.entries(next).filter(([key]) => key !== "verdict_sha256")) }),
    };
  });
  return {
    evidence: seal(value),
    supportFiles: support.files,
  };
}

function run(value = fixture(), extraWitnesses: readonly string[] = []) {
  const root = mkdtempSync(join(tmpdir(), "loopeix-s37d-evidence-"));
  roots.push(root);
  const witnesses = join(root, "witnesses");
  mkdirSync(witnesses);
  for (const entry of catalog().cases) writeFileSync(join(witnesses, `${entry.id}.json`), witnessBytes(entry.id));
  for (const name of extraWitnesses) writeFileSync(join(witnesses, name), "unexpected\n", "utf8");
  const path = join(root, "evidence.json");
  writeFileSync(path, `${JSON.stringify(value)}\n`, "utf8");
  return spawnSync(process.execPath, [SCRIPT, "--evidence", path], {
    cwd: process.cwd(), encoding: "utf8", shell: false,
  });
}

function runCanonicalPassBundle(options: Readonly<{
  extraWitnesses?: readonly string[];
  mutateBundle?: (bundle: ReturnType<typeof canonicalPassEvidence>) => void;
  afterWrite?: (root: string, bundle: ReturnType<typeof canonicalPassEvidence>) => void;
}> = {}) {
  const bundle = canonicalPassEvidence();
  options.mutateBundle?.(bundle);
  const root = mkdtempSync(join(tmpdir(), "loopeix-s37d-evidence-"));
  roots.push(root);
  const witnesses = join(root, "witnesses");
  mkdirSync(witnesses);
  for (const entry of catalog().cases) writeFileSync(join(witnesses, `${entry.id}.json`), witnessBytes(entry.id));
  for (const name of options.extraWitnesses ?? []) writeFileSync(join(witnesses, name), "unexpected\n", "utf8");
  for (const [name, value] of Object.entries(bundle.supportFiles)) {
    writeFileSync(join(root, name), `${JSON.stringify(value)}\n`, "utf8");
  }
  const path = join(root, "evidence.json");
  writeFileSync(path, `${JSON.stringify(bundle.evidence)}\n`, "utf8");
  options.afterWrite?.(root, bundle);
  return spawnSync(process.execPath, [SCRIPT, "--evidence", path], {
    cwd: process.cwd(), encoding: "utf8", shell: false,
  });
}

afterEach(() => {
  while (roots.length > 0) rmSync(roots.pop()!, { recursive: true, force: true });
});

describe("S37.1-D sealed adversarial evidence gate", () => {
  it("accepts one complete ordered, zero-delta, independently approved manifest", () => {
    const result = runCanonicalPassBundle();
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe("S37.1-D evidence gate: PASS\nsealed evidence only; no live host action performed\n");
    expect(result.stderr).toBe("");
  });

  it("rejects a fabricated fixture that is not bound to canonical repository and Phase B evidence", () => {
    const result = run(fixture());
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD:");
  });

  it.each([
    ["execution drift", (bundle: ReturnType<typeof canonicalPassEvidence>) => {
      const conformance = bundle.supportFiles[PHASE_B_SUPPORT_FILES.conformanceEvidence] as Record<string, unknown>;
      const execution = conformance.execution as Record<string, unknown>;
      execution.scope = true;
      bundle.supportFiles[PHASE_B_SUPPORT_FILES.conformanceEvidence] = sealWithSerializer(conformance, "evidence_sha256", canonical);
    }, "evidence.execution.scope:expected-false"],
    ["deny-row drift", (bundle: ReturnType<typeof canonicalPassEvidence>) => {
      const conformance = bundle.supportFiles[PHASE_B_SUPPORT_FILES.conformanceEvidence] as Record<string, unknown>;
      const denyRows = conformance.deny_rows as Array<Record<string, unknown>>;
      denyRows[0] = { ...denyRows[0], passed: false };
      bundle.supportFiles[PHASE_B_SUPPORT_FILES.conformanceEvidence] = sealWithSerializer(conformance, "evidence_sha256", canonical);
    }, "evidence.deny_rows[0].passed:expected-true"],
  ] as const)("rejects sibling Phase B %s via the authoritative conformance gate", (_label, mutate, expectedHold) => {
    const result = runCanonicalPassBundle({ mutateBundle: mutate });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: phase_b_support.conformance_gate");
    expect(result.stderr).toContain(expectedHold);
  });

  it.each(["--live", "--ssh", "--vps"])('rejects live surface %s', (flag) => {
    const result = spawnSync(process.execPath, [SCRIPT, flag], {
      cwd: process.cwd(), encoding: "utf8", shell: false,
    });
    expect(result.status).toBe(64);
    expect(result.stderr).toContain(`unknown argument: ${flag}`);
  });

  it("requires exactly one explicit evidence path", () => {
    const missing = spawnSync(process.execPath, [SCRIPT], { cwd: process.cwd(), encoding: "utf8", shell: false });
    expect(missing.status).toBe(64);
    expect(missing.stderr).toContain("missing argument: --evidence");
    const duplicate = spawnSync(process.execPath, [SCRIPT, "--evidence", "a", "--evidence", "b"], { cwd: process.cwd(), encoding: "utf8", shell: false });
    expect(duplicate.status).toBe(64);
    expect(duplicate.stderr).toContain("duplicate argument: --evidence");
  });

  it.each([
    ["missing case", (value: ReturnType<typeof fixture>) => { value.cases.pop(); }],
    ["duplicate case", (value: ReturnType<typeof fixture>) => { value.cases[1] = { ...value.cases[0] }; }],
    ["reordered case", (value: ReturnType<typeof fixture>) => { [value.cases[0], value.cases[1]] = [value.cases[1], value.cases[0]]; }],
    ["skipped case", (value: ReturnType<typeof fixture>) => { value.cases[0].skipped = true; }],
    ["failed case", (value: ReturnType<typeof fixture>) => { value.cases[0].passed = false; }],
    ["oracle drift", (value: ReturnType<typeof fixture>) => { value.cases[0].oracle = "forged"; }],
    ["lane drift", (value: ReturnType<typeof fixture>) => { value.cases[0].lane = "forged"; }],
    ["catalog drift", (value: ReturnType<typeof fixture>) => { value.catalog_sha256 = RAW; }],
    ["supervisor pin drift", (value: ReturnType<typeof fixture>) => { value.bindings.before.supervisor_source_sha256 = CONTENT; value.bindings.after.supervisor_source_sha256 = CONTENT; }],
    ["probe pin drift", (value: ReturnType<typeof fixture>) => { value.bindings.before.probe_source_sha256 = CONTENT; value.bindings.after.probe_source_sha256 = CONTENT; }],
    ["controller hash changed during QA", (value: ReturnType<typeof fixture>) => { value.bindings.after.controller_source_sha256 = `sha256:${"c".repeat(64)}`; }],
    ["bwrap drift", (value: ReturnType<typeof fixture>) => { value.bindings.before.bwrap_sha256 = `sha256:${"b".repeat(64)}`; value.bindings.after.bwrap_sha256 = `sha256:${"b".repeat(64)}`; }],
    ["seccomp drift", (value: ReturnType<typeof fixture>) => { value.bindings.before.seccomp_policy_sha256 = `sha256:${"c".repeat(64)}`; value.bindings.after.seccomp_policy_sha256 = `sha256:${"c".repeat(64)}`; }],
    ["readiness sample underflow", (value: ReturnType<typeof fixture>) => { value.readiness.sample_count = 4; }],
    ["readiness failure", (value: ReturnType<typeof fixture>) => { value.readiness.within_envelope = false; }],
    ["port delta", (value: ReturnType<typeof fixture>) => { value.observations.listening_ports_after.count += 1; }],
    ["service transition", (value: ReturnType<typeof fixture>) => { value.observations.incumbent_service_transition_count = 1; }],
    ["swap growth", (value: ReturnType<typeof fixture>) => { value.observations.swap_growth_bytes = 1; }],
    ["residual process", (value: ReturnType<typeof fixture>) => { value.cleanup.process_absent = false; }],
    ["reviewer HOLD", (value: ReturnType<typeof fixture>) => { value.reviewers[0].verdict = "HOLD"; }],
    ["reviewer subject drift", (value: ReturnType<typeof fixture>) => { value.reviewers[0].evidence_sha256 = RAW; }],
    ["reviewer verdict seal drift", (value: ReturnType<typeof fixture>) => { value.reviewers[0].verdict_sha256 = RAW; }],
    ["reviewer ordering drift", (value: ReturnType<typeof fixture>) => { value.reviewers[0].reviewed_at = "2026-08-23T11:59:59.000Z"; }],
    ["duplicate reviewer identity", (value: ReturnType<typeof fixture>) => {
      value.reviewers[1].reviewer_identity_hash = value.reviewers[0].reviewer_identity_hash;
      const { verdict_sha256: _, ...body } = value.reviewers[1];
      value.reviewers[1].verdict_sha256 = digest({ purpose: "s37-linux-phase-d-review-verdict-v1", ...body });
    }],
    ["witness hash drift", (value: ReturnType<typeof fixture>) => { value.cases[0].witness_sha256 = RAW; }],
    ["unexpected evidence key", (value: ReturnType<typeof fixture>) => { (value as Record<string, unknown>).unexpected = true; }],
  ] as const)("rejects %s even after resealing", (_label, mutate) => {
    const value = fixture();
    mutate(value);
    const result = run(seal(value));
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD:");
  });

  it("rejects a stale evidence self-hash", () => {
    const value = fixture();
    value.cleanup.file_absent = false;
    const result = run(value);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: evidence.evidence_sha256:mismatch");
  });

  it("rejects an unexpected witness file", () => {
    const result = run(fixture(), ["unexpected.json"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: evidence.witnesses:closed-file-set:mismatch");
  });

  it("rejects symlinked sibling Phase B support JSON", () => {
    const result = runCanonicalPassBundle({
      afterWrite(root) {
        const profilePath = join(root, PHASE_B_SUPPORT_FILES.profile);
        unlinkSync(profilePath);
        symlinkSync(join(root, PHASE_B_SUPPORT_FILES.manifest), profilePath);
      },
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: phase_b_support.profile:file-custody-invalid");
  });

  it("ignores unrelated untracked files when deriving repository provenance", () => {
    const scratch = join(REPO_ROOT, ".s37-phase-d-untracked-irrelevant.tmp");
    writeFileSync(scratch, "untracked scratch\n", "utf8");
    try {
      const result = runCanonicalPassBundle();
      expect(result.status, result.stderr).toBe(0);
    } finally {
      rmSync(scratch, { force: true });
    }
  });

  it("uses only exact local proof helpers and has no network, shell, SSH, or VPS surface", () => {
    const source = readFileSync(SCRIPT, "utf8");
    expect(source).toContain("check-s37-linux-phase-b-conformance-evidence.mjs");
    expect(source).toContain("/usr/bin/git");
    expect(source).toMatch(/\bspawnSync\(/u);
    expect(source).not.toMatch(/node:net|node:https|node:http|https?:\/\/|spawn\(|fork\(|\bssh\b|\bvps\b/u);
  });
});
