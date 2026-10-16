import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { evaluateS37LinuxPhaseBReadiness } from "./check-s37-linux-phase-b-readiness.mjs";

const REQUIRED_FLAGS = ["--manifest", "--readiness-evidence", "--readiness-envelope", "--profile", "--evidence", "--receipt"];
const DENY_ROWS = Object.freeze([
  "ambient-credentials", "child-process", "durable-state", "environment",
  "filesystem-write", "network", "output-limits", "retry", "stdin",
  "timeout", "tool-server", "unknown-outcome",
]);
const RAW_HASH = /^[a-f0-9]{64}$/u;
const CONTENT_HASH = /^sha256:[a-f0-9]{64}$/u;
const BUILD_FLAGS = Object.freeze(["-std=c17", "-D_FORTIFY_SOURCE=3", "-fstack-protector-strong", "-fPIE", "-Wall", "-Wextra", "-Werror", "-Wconversion", "-Wformat=2", "-Wshadow", "-Wstrict-prototypes", "-static-pie"]);

const KEYS = Object.freeze({
  manifest: ["schema_version", "created_at", "sources", "compiler", "artifacts", "bwrap", "seccomp_policy_sha256", "manifest_sha256"],
  sources: ["supervisor", "probe"],
  source: ["path", "sha256"],
  compiler: ["path", "version", "target", "sha256", "flags"],
  artifacts: ["supervisor", "probe"],
  artifact: ["path", "sha256", "mode", "setuid"],
  bwrap: ["path", "version", "package_version", "sha256", "mode", "setuid"],
  evidence: ["schema_version", "observed_at", "host_tuple", "manifest_sha256", "readiness_evidence_sha256", "readiness_envelope_sha256", "execution", "deny_rows", "ports", "neighbors", "cleanup", "capacity", "receipt_hash", "evidence_sha256"],
  host: ["tuple_version", "platform", "architecture", "kernel_release", "systemd_version", "cgroup_version", "observed_at"],
  execution: ["unit_name", "service_type", "scope", "pipe", "standard_input", "standard_output", "standard_error", "no_new_privileges", "kill_mode", "concurrency", "cpu_quota_percent", "memory_max_bytes", "tasks_max", "io_weight", "timeout_ms", "stdout_limit_bytes", "stderr_limit_bytes", "process_started", "exit_code", "probe_duration_ms", "stdout_bytes", "stderr_bytes", "profile_hash", "launcher_sha256", "seccomp_policy_sha256"],
  deny: ["row", "passed", "skipped", "witness_sha256"],
  ports: ["before", "after", "delta"],
  snapshot: ["count", "sha256"],
  neighbors: ["services_before", "services_after", "containers_before", "containers_after"],
  cleanup: ["unit_absent", "process_absent", "mount_absent", "temp_absent", "journal_payload_absent", "file_absent"],
  capacity: ["envelope_sha256", "samples_sha256", "within_envelope", "swap_growth_bytes"],
  resourceLimits: ["cpu_quota_percent", "memory_max_bytes", "tasks_max", "io_weight", "timeout_ms", "stdout_bytes", "stderr_bytes"],
  receipt: ["receipt_version", "host_tuple_hash", "profile_hash", "launcher_sha256", "bwrap", "seccomp_policy_sha256", "deny_rows", "skipped_rows", "issued_at", "expires_at", "receipt_hash"],
  receiptBwrap: ["path", "version", "sha256", "setuid"],
  profile: ["profile_version", "probe_kind", "actor_identity_hash", "on_behalf_of_chain_hash", "executable", "argv", "cwd", "filesystem", "child_process", "network", "tools", "environment", "credentials", "stdin", "limits", "durable_state", "retry"],
  profileExecutable: ["path", "sha256"],
  profileCwd: ["path", "identity_hash"],
  profileFilesystem: ["readable_paths", "writable_paths", "direct_writes"],
  profileNetwork: ["mode", "allowed_origins"],
  profileTools: ["built_in", "mcp_servers"],
  profileEnvironment: ["inherit", "allowed_names", "values"],
  profileLimits: ["timeout_ms", "stdout_bytes", "stderr_bytes"],
});

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write(`usage: node scripts/check-s37-linux-phase-b-conformance-evidence.mjs ${REQUIRED_FLAGS.map((flag) => `${flag} <path>`).join(" ")}\n`);
  process.exit(64);
}

function fail(violations) {
  const unique = [...new Set(violations)].sort((left, right) => left.localeCompare(right));
  process.stderr.write(`${unique.map((entry) => `HOLD: ${entry}`).join("\n")}\n`);
  process.exit(1);
}

function cli() {
  const args = process.argv.slice(2);
  const paths = Object.create(null);
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (!REQUIRED_FLAGS.includes(flag)) usage(`unknown argument: ${flag ?? "<missing>"}`);
    if (value === undefined || value.startsWith("--")) usage(`${flag} requires a path`);
    if (paths[flag] !== undefined) usage(`duplicate argument: ${flag}`);
    paths[flag] = value;
  }
  for (const flag of REQUIRED_FLAGS) if (paths[flag] === undefined) usage(`missing argument: ${flag}`);
  return paths;
}

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, entry]) => `${JSON.stringify(key)}:${canonical(entry)}`).join(",")}}`;
}

function readinessCanonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(readinessCanonical).join(",")}]`;
  return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, entry]) => `${JSON.stringify(key)}:${readinessCanonical(entry)}`).join(",")}}`;
}

function sha(value) {
  return createHash("sha256").update(typeof value === "string" ? value : canonical(value), "utf8").digest("hex");
}

function readJson(path, label) {
  try {
    return JSON.parse(readFileSync(resolve(path), "utf8"));
  } catch (error) {
    usage(`${label}:unable-to-read-json:${error instanceof Error ? error.message : String(error)}`);
  }
}

function record(value, keys, label, violations) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    violations.push(`${label}:missing-or-invalid`);
    return null;
  }
  const allowed = new Set(keys);
  for (const key of Object.keys(value)) if (!allowed.has(key)) violations.push(`${label}:unexpected-key:${key}`);
  for (const key of keys) if (!Object.hasOwn(value, key)) violations.push(`${label}:missing-key:${key}`);
  return value;
}

function text(value, label, violations) {
  if (typeof value !== "string" || value.length === 0) {
    violations.push(`${label}:missing-or-invalid`);
    return null;
  }
  return value;
}

function hash(value, label, violations) {
  const result = text(value, label, violations);
  if (result !== null && !RAW_HASH.test(result)) violations.push(`${label}:missing-or-invalid`);
  return result;
}

function contentHash(value, label, violations) {
  const result = text(value, label, violations);
  if (result !== null && !CONTENT_HASH.test(result)) violations.push(`${label}:missing-or-invalid`);
  return result;
}

function bool(value, expected, label, violations) {
  if (typeof value !== "boolean") violations.push(`${label}:missing-or-invalid`);
  else if (value !== expected) violations.push(`${label}:expected-${String(expected)}`);
}

function finite(value, label, violations, { integer = false, min = 0, max = Number.POSITIVE_INFINITY } = {}) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < min || value > max || (integer && !Number.isInteger(value))) {
    violations.push(`${label}:missing-or-invalid`);
    return null;
  }
  return value;
}

function instant(value, label, violations) {
  const result = text(value, label, violations);
  if (result === null) return null;
  const parsed = Date.parse(result);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== result) {
    violations.push(`${label}:missing-or-invalid`);
    return null;
  }
  return parsed;
}

function exact(actual, expected, label, violations) {
  if (actual !== expected) violations.push(`${label}:mismatch`);
}

function selfHash(value, key, label, violations, serializer = canonical) {
  const supplied = hash(value?.[key], `${label}.${key}`, violations);
  if (value && supplied !== null) {
    const body = Object.fromEntries(Object.entries(value).filter(([name]) => name !== key));
    const expected = createHash("sha256").update(serializer(body), "utf8").digest("hex");
    if (supplied !== expected) violations.push(`${label}.${key}:mismatch`);
  }
}

function validateReadiness(readiness, envelope, manifest, evidence, violations) {
  exact(readiness.schema_version, "s37-linux-phase-b-readiness-evidence-v1", "readiness.schema_version", violations);
  exact(envelope.schema_version, "s37-linux-phase-b-readiness-envelope-v1", "readiness_envelope.schema_version", violations);
  selfHash(readiness, "evidence_sha256", "readiness", violations, readinessCanonical);
  selfHash(envelope, "envelope_sha256", "readiness_envelope", violations, readinessCanonical);
  exact(evidence.readiness_evidence_sha256, readiness.evidence_sha256, "evidence.readiness_evidence_sha256", violations);
  exact(evidence.readiness_envelope_sha256, envelope.envelope_sha256, "evidence.readiness_envelope_sha256", violations);
  for (const key of ["platform", "architecture", "kernel_release", "systemd_version"]) {
    exact(
      evidence.host_tuple?.[key],
      readiness.host_tuple?.[key],
      `evidence.host_tuple.${key}:readiness-binding`,
      violations,
    );
  }
  exact(
    evidence.host_tuple?.cgroup_version,
    `v${String(readiness.host_tuple?.cgroup_version ?? "")}`,
    "evidence.host_tuple.cgroup_version:readiness-binding",
    violations,
  );
  bool(readiness.preflight?.apt_dpkg_locks_clear, true, "readiness.preflight.apt_dpkg_locks_clear", violations);
  for (const key of ["reboot_required", "shutdown", "maintenance_conflict"]) bool(readiness.preflight?.[key], false, `readiness.preflight.${key}`, violations);
  exact(envelope.concurrency, 1, "readiness_envelope.concurrency", violations);
  const limits = record(envelope.resource_limits, KEYS.resourceLimits, "readiness_envelope.resource_limits", violations);
  for (const key of ["cpu_quota_percent", "memory_max_bytes", "tasks_max", "io_weight"]) finite(limits?.[key], `readiness_envelope.resource_limits.${key}`, violations, { min: 1 });
  exact(limits?.timeout_ms, 1_000, "readiness_envelope.resource_limits.timeout_ms", violations);
  exact(limits?.stdout_bytes, 1_024, "readiness_envelope.resource_limits.stdout_bytes", violations);
  exact(limits?.stderr_bytes, 1_024, "readiness_envelope.resource_limits.stderr_bytes", violations);
  bool(readiness.package_review?.system_package_install, false, "readiness.package_review.system_package_install", violations);
  bool(readiness.package_review?.sysctl_applied, false, "readiness.package_review.sysctl_applied", violations);
  bool(readiness.package_review?.service_restart, false, "readiness.package_review.service_restart", violations);
  bool(readiness.package_review?.selected_artifact?.setuid, false, "readiness.package_review.selected_artifact.setuid", violations);
  exact(readiness.package_review?.selected_artifact?.path, manifest.bwrap?.path, "readiness.package_review.selected_artifact.path", violations);
  exact(`sha256:${readiness.package_review?.selected_artifact?.sha256 ?? ""}`, manifest.bwrap?.sha256, "readiness.package_review.selected_artifact.sha256", violations);
  exact(readiness.package_review?.candidate_version, manifest.bwrap?.package_version, "readiness.package_review.candidate_version:manifest-binding", violations);
  const observed = instant(evidence.observed_at, "evidence.observed_at", violations);
  const readyObserved = instant(readiness.observed_at, "readiness.observed_at", violations);
  const hostObserved = instant(evidence.host_tuple?.observed_at, "evidence.host_tuple.observed_at", violations);
  const validFrom = instant(envelope.valid_from, "readiness_envelope.valid_from", violations);
  const validTo = instant(envelope.valid_to, "readiness_envelope.valid_to", violations);
  const intervalSeconds = finite(envelope.sample_interval_seconds, "readiness_envelope.sample_interval_seconds", violations, { min: 1 });
  if (readyObserved !== null && observed !== null && readyObserved > observed) violations.push("readiness.observed_at:after-conformance");
  if (readyObserved !== null && hostObserved !== null && readyObserved > hostObserved) violations.push("evidence.host_tuple.observed_at:before-readiness");
  if (readyObserved !== null && hostObserved !== null && intervalSeconds !== null && hostObserved - readyObserved > intervalSeconds * 1000) violations.push("evidence.host_tuple.observed_at:readiness-stale-at-activation");
  if (hostObserved !== null && observed !== null && hostObserved > observed) violations.push("evidence.host_tuple.observed_at:after-conformance");
  if (validFrom !== null && observed !== null && observed < validFrom) violations.push("evidence.observed_at:before-approved-window");
  if (validTo !== null && observed !== null && observed > validTo) violations.push("evidence.observed_at:after-approved-window");
}

function validateManifest(manifest, violations) {
  const root = record(manifest, KEYS.manifest, "manifest", violations);
  if (root === null) return;
  exact(root.schema_version, "s37-linux-phase-b-build-manifest-v1", "manifest.schema_version", violations);
  instant(root.created_at, "manifest.created_at", violations);
  selfHash(root, "manifest_sha256", "manifest", violations);
  const sources = record(root.sources, KEYS.sources, "manifest.sources", violations);
  for (const name of KEYS.sources) {
    const source = record(sources?.[name], KEYS.source, `manifest.sources.${name}`, violations);
    text(source?.path, `manifest.sources.${name}.path`, violations);
    contentHash(source?.sha256, `manifest.sources.${name}.sha256`, violations);
  }
  exact(sources?.supervisor?.path, "scripts/s37-linux-phase-b/supervisor.c", "manifest.sources.supervisor.path", violations);
  exact(sources?.probe?.path, "scripts/s37-linux-phase-b/probe.c", "manifest.sources.probe.path", violations);
  const compiler = record(root.compiler, KEYS.compiler, "manifest.compiler", violations);
  const compilerPath = text(compiler?.path, "manifest.compiler.path", violations);
  if (compilerPath !== null && !isAbsolute(compilerPath)) violations.push("manifest.compiler.path:not-absolute");
  text(compiler?.version, "manifest.compiler.version", violations);
  exact(compiler?.target, "x86_64-linux-gnu", "manifest.compiler.target", violations);
  contentHash(compiler?.sha256, "manifest.compiler.sha256", violations);
  if (!Array.isArray(compiler?.flags) || canonical(compiler.flags) !== canonical(BUILD_FLAGS)) violations.push("manifest.compiler.flags:not-exact");
  const artifacts = record(root.artifacts, KEYS.artifacts, "manifest.artifacts", violations);
  for (const name of KEYS.artifacts) {
    const artifact = record(artifacts?.[name], KEYS.artifact, `manifest.artifacts.${name}`, violations);
    text(artifact?.path, `manifest.artifacts.${name}.path`, violations);
    contentHash(artifact?.sha256, `manifest.artifacts.${name}.sha256`, violations);
    exact(artifact?.mode, "0555", `manifest.artifacts.${name}.mode`, violations);
    bool(artifact?.setuid, false, `manifest.artifacts.${name}.setuid`, violations);
  }
  exact(artifacts?.supervisor?.path, "/opt/loopeix/s37.1/supervisor", "manifest.artifacts.supervisor.path", violations);
  exact(artifacts?.probe?.path, "/opt/loopeix/s37.1/probe", "manifest.artifacts.probe.path", violations);
  const bwrap = record(root.bwrap, KEYS.bwrap, "manifest.bwrap", violations);
  text(bwrap?.path, "manifest.bwrap.path", violations);
  text(bwrap?.version, "manifest.bwrap.version", violations);
  text(bwrap?.package_version, "manifest.bwrap.package_version", violations);
  contentHash(bwrap?.sha256, "manifest.bwrap.sha256", violations);
  exact(bwrap?.mode, "0555", "manifest.bwrap.mode", violations);
  bool(bwrap?.setuid, false, "manifest.bwrap.setuid", violations);
  exact(bwrap?.path, "/opt/loopeix/s37.1/bwrap", "manifest.bwrap.path", violations);
  contentHash(root.seccomp_policy_sha256, "manifest.seccomp_policy_sha256", violations);
}

function validateLiveEvidence(evidence, manifest, receipt, readiness, envelope, violations) {
  const root = record(evidence, KEYS.evidence, "evidence", violations);
  if (root === null) return;
  exact(root.schema_version, "s37-linux-phase-b-conformance-evidence-v1", "evidence.schema_version", violations);
  selfHash(root, "evidence_sha256", "evidence", violations);
  exact(root.manifest_sha256, manifest.manifest_sha256, "evidence.manifest_sha256", violations);
  const host = record(root.host_tuple, KEYS.host, "evidence.host_tuple", violations);
  exact(host?.tuple_version, "0.1", "evidence.host_tuple.tuple_version", violations);
  exact(host?.platform, "linux", "evidence.host_tuple.platform", violations);
  exact(host?.architecture, "x86_64", "evidence.host_tuple.architecture", violations);
  text(host?.kernel_release, "evidence.host_tuple.kernel_release", violations);
  text(host?.systemd_version, "evidence.host_tuple.systemd_version", violations);
  exact(host?.cgroup_version, "v2", "evidence.host_tuple.cgroup_version", violations);
  instant(host?.observed_at, "evidence.host_tuple.observed_at", violations);
  const execution = record(root.execution, KEYS.execution, "evidence.execution", violations);
  if (!/^loopeix-s37\.1-conformance-[a-f0-9]{12}$/u.test(execution?.unit_name ?? "")) violations.push("evidence.execution.unit_name:missing-or-invalid");
  exact(execution?.service_type, "exec", "evidence.execution.service_type", violations);
  bool(execution?.scope, false, "evidence.execution.scope", violations);
  bool(execution?.pipe, false, "evidence.execution.pipe", violations);
  for (const key of ["standard_input", "standard_output", "standard_error"]) exact(execution?.[key], "null", `evidence.execution.${key}`, violations);
  bool(execution?.no_new_privileges, true, "evidence.execution.no_new_privileges", violations);
  exact(execution?.kill_mode, "control-group", "evidence.execution.kill_mode", violations);
  exact(execution?.concurrency, 1, "evidence.execution.concurrency", violations);
  for (const key of ["cpu_quota_percent", "memory_max_bytes", "tasks_max", "io_weight", "timeout_ms"]) {
    exact(execution?.[key], envelope.resource_limits?.[key], `evidence.execution.${key}`, violations);
  }
  exact(execution?.stdout_limit_bytes, envelope.resource_limits?.stdout_bytes, "evidence.execution.stdout_limit_bytes", violations);
  exact(execution?.stderr_limit_bytes, envelope.resource_limits?.stderr_bytes, "evidence.execution.stderr_limit_bytes", violations);
  bool(execution?.process_started, true, "evidence.execution.process_started", violations);
  exact(execution?.exit_code, 0, "evidence.execution.exit_code", violations);
  finite(execution?.probe_duration_ms, "evidence.execution.probe_duration_ms", violations, { max: 1000 });
  exact(execution?.stdout_bytes, 0, "evidence.execution.stdout_bytes", violations);
  exact(execution?.stderr_bytes, 0, "evidence.execution.stderr_bytes", violations);
  contentHash(execution?.profile_hash, "evidence.execution.profile_hash", violations);
  exact(execution?.launcher_sha256, manifest.artifacts?.supervisor?.sha256, "evidence.execution.launcher_sha256", violations);
  exact(execution?.seccomp_policy_sha256, manifest.seccomp_policy_sha256, "evidence.execution.seccomp_policy_sha256", violations);
  if (!Array.isArray(root.deny_rows) || root.deny_rows.length !== DENY_ROWS.length) violations.push("evidence.deny_rows:wrong-length");
  else root.deny_rows.forEach((entry, index) => {
    const row = record(entry, KEYS.deny, `evidence.deny_rows[${index}]`, violations);
    exact(row?.row, DENY_ROWS[index], `evidence.deny_rows[${index}].row`, violations);
    bool(row?.passed, true, `evidence.deny_rows[${index}].passed`, violations);
    bool(row?.skipped, false, `evidence.deny_rows[${index}].skipped`, violations);
    hash(row?.witness_sha256, `evidence.deny_rows[${index}].witness_sha256`, violations);
  });
  const ports = record(root.ports, KEYS.ports, "evidence.ports", violations);
  const before = record(ports?.before, KEYS.snapshot, "evidence.ports.before", violations);
  const after = record(ports?.after, KEYS.snapshot, "evidence.ports.after", violations);
  finite(before?.count, "evidence.ports.before.count", violations, { integer: true });
  hash(before?.sha256, "evidence.ports.before.sha256", violations);
  finite(after?.count, "evidence.ports.after.count", violations, { integer: true });
  hash(after?.sha256, "evidence.ports.after.sha256", violations);
  exact(canonical(after), canonical(before), "evidence.ports.zero-delta", violations);
  exact(ports?.delta, 0, "evidence.ports.delta", violations);
  const neighbors = record(root.neighbors, KEYS.neighbors, "evidence.neighbors", violations);
  for (const name of KEYS.neighbors) {
    const snapshot = record(neighbors?.[name], KEYS.snapshot, `evidence.neighbors.${name}`, violations);
    finite(snapshot?.count, `evidence.neighbors.${name}.count`, violations, { integer: true });
    hash(snapshot?.sha256, `evidence.neighbors.${name}.sha256`, violations);
  }
  exact(canonical(neighbors?.services_after), canonical(neighbors?.services_before), "evidence.neighbors.services-zero-delta", violations);
  exact(canonical(neighbors?.containers_after), canonical(neighbors?.containers_before), "evidence.neighbors.containers-zero-delta", violations);
  const cleanup = record(root.cleanup, KEYS.cleanup, "evidence.cleanup", violations);
  for (const key of KEYS.cleanup) bool(cleanup?.[key], true, `evidence.cleanup.${key}`, violations);
  const capacity = record(root.capacity, KEYS.capacity, "evidence.capacity", violations);
  exact(capacity?.envelope_sha256, root.readiness_envelope_sha256, "evidence.capacity.envelope_sha256", violations);
  hash(capacity?.samples_sha256, "evidence.capacity.samples_sha256", violations);
  if (Array.isArray(readiness.capacity_samples)) {
    exact(capacity?.samples_sha256, sha(readiness.capacity_samples), "evidence.capacity.samples_sha256:readiness-binding", violations);
  } else {
    violations.push("evidence.capacity.samples_sha256:readiness-samples-missing");
  }
  bool(capacity?.within_envelope, true, "evidence.capacity.within_envelope", violations);
  exact(capacity?.swap_growth_bytes, 0, "evidence.capacity.swap_growth_bytes", violations);
  exact(root.receipt_hash, receipt.receipt_hash, "evidence.receipt_hash", violations);
}

function validateReceipt(receipt, evidence, manifest, envelope, violations) {
  const root = record(receipt, KEYS.receipt, "receipt", violations);
  if (root === null) return;
  exact(root.receipt_version, "0.1", "receipt.receipt_version", violations);
  for (const key of ["host_tuple_hash", "profile_hash", "launcher_sha256", "seccomp_policy_sha256", "receipt_hash"]) contentHash(root[key], `receipt.${key}`, violations);
  exact(root.host_tuple_hash, `sha256:${sha({ purpose: "s37-linux-host-tuple-v02", ...evidence.host_tuple })}`, "receipt.host_tuple_hash", violations);
  exact(root.profile_hash, evidence.execution?.profile_hash, "receipt.profile_hash", violations);
  exact(root.launcher_sha256, manifest.artifacts?.supervisor?.sha256, "receipt.launcher_sha256", violations);
  const bwrap = record(root.bwrap, KEYS.receiptBwrap, "receipt.bwrap", violations);
  for (const key of ["path", "version", "sha256"]) exact(bwrap?.[key], manifest.bwrap?.[key], `receipt.bwrap.${key}`, violations);
  bool(bwrap?.setuid, false, "receipt.bwrap.setuid", violations);
  exact(root.seccomp_policy_sha256, manifest.seccomp_policy_sha256, "receipt.seccomp_policy_sha256", violations);
  exact(canonical(root.deny_rows), canonical(DENY_ROWS), "receipt.deny_rows", violations);
  if (!Array.isArray(root.skipped_rows) || root.skipped_rows.length !== 0) violations.push("receipt.skipped_rows:expected-empty");
  const issued = instant(root.issued_at, "receipt.issued_at", violations);
  const expires = instant(root.expires_at, "receipt.expires_at", violations);
  const observed = instant(evidence.observed_at, "evidence.observed_at", violations);
  const hostObserved = instant(evidence.host_tuple?.observed_at, "evidence.host_tuple.observed_at", violations);
  const windowEnd = instant(envelope.valid_to, "readiness_envelope.valid_to", violations);
  if (issued !== null && observed !== null && issued > observed) violations.push("receipt.issued_at:after-observation");
  if (issued !== null && hostObserved !== null && issued < hostObserved) violations.push("receipt.issued_at:before-host-observation");
  if (expires !== null && observed !== null && observed >= expires) violations.push("receipt.expires_at:not-after-observation");
  if (expires !== null && windowEnd !== null && expires > windowEnd) violations.push("receipt.expires_at:after-readiness-window");
  const { receipt_hash: _ignored, ...body } = root;
  exact(root.receipt_hash, `sha256:${sha({ purpose: "s37-linux-backend-identity-receipt-v02", ...body })}`, "receipt.receipt_hash", violations);
}

function validateProductProfile(profile, manifest, evidence, receipt, violations) {
  const root = record(profile, KEYS.profile, "profile", violations);
  if (root === null) return;
  exact(root.profile_version, "0.1", "profile.profile_version", violations);
  exact(root.probe_kind, "inert-bounded-stdout-stderr", "profile.probe_kind", violations);
  contentHash(root.actor_identity_hash, "profile.actor_identity_hash", violations);
  contentHash(root.on_behalf_of_chain_hash, "profile.on_behalf_of_chain_hash", violations);
  const executable = record(root.executable, KEYS.profileExecutable, "profile.executable", violations);
  exact(executable?.path, manifest.artifacts?.probe?.path, "profile.executable.path", violations);
  exact(executable?.sha256, manifest.artifacts?.probe?.sha256, "profile.executable.sha256", violations);
  if (!Array.isArray(root.argv) || root.argv.length !== 0) violations.push("profile.argv:expected-empty");
  const cwd = record(root.cwd, KEYS.profileCwd, "profile.cwd", violations);
  exact(cwd?.path, "/", "profile.cwd.path", violations);
  contentHash(cwd?.identity_hash, "profile.cwd.identity_hash", violations);
  const filesystem = record(root.filesystem, KEYS.profileFilesystem, "profile.filesystem", violations);
  if (!Array.isArray(filesystem?.readable_paths) || canonical(filesystem.readable_paths) !== canonical([manifest.artifacts?.probe?.path])) violations.push("profile.filesystem.readable_paths:not-exact");
  if (!Array.isArray(filesystem?.writable_paths) || filesystem.writable_paths.length !== 0) violations.push("profile.filesystem.writable_paths:expected-empty");
  exact(filesystem?.direct_writes, "deny", "profile.filesystem.direct_writes", violations);
  exact(root.child_process, "deny", "profile.child_process", violations);
  const network = record(root.network, KEYS.profileNetwork, "profile.network", violations);
  exact(network?.mode, "deny", "profile.network.mode", violations);
  if (!Array.isArray(network?.allowed_origins) || network.allowed_origins.length !== 0) violations.push("profile.network.allowed_origins:expected-empty");
  const tools = record(root.tools, KEYS.profileTools, "profile.tools", violations);
  exact(tools?.built_in, "deny", "profile.tools.built_in", violations);
  exact(tools?.mcp_servers, "deny", "profile.tools.mcp_servers", violations);
  const environment = record(root.environment, KEYS.profileEnvironment, "profile.environment", violations);
  exact(environment?.inherit, false, "profile.environment.inherit", violations);
  if (!Array.isArray(environment?.allowed_names) || environment.allowed_names.length !== 0) violations.push("profile.environment.allowed_names:expected-empty");
  const values = record(environment?.values, [], "profile.environment.values", violations);
  if (values !== null && Object.keys(values).length !== 0) violations.push("profile.environment.values:expected-empty");
  exact(root.credentials, "deny", "profile.credentials", violations);
  exact(root.stdin, "closed", "profile.stdin", violations);
  const limits = record(root.limits, KEYS.profileLimits, "profile.limits", violations);
  exact(limits?.timeout_ms, 1_000, "profile.limits.timeout_ms", violations);
  exact(limits?.stdout_bytes, 1_024, "profile.limits.stdout_bytes", violations);
  exact(limits?.stderr_bytes, 1_024, "profile.limits.stderr_bytes", violations);
  exact(root.durable_state, "forbidden-until-s40", "profile.durable_state", violations);
  exact(root.retry, "forbidden-non-resumable", "profile.retry", violations);
  const expectedHash = `sha256:${sha(root)}`;
  exact(evidence.execution?.profile_hash, expectedHash, "evidence.execution.profile_hash:product-binding", violations);
  exact(receipt.profile_hash, expectedHash, "receipt.profile_hash:product-binding", violations);
}

function validateReadinessGate(readiness, envelope, evidence, asOf, violations) {
  const result = evaluateS37LinuxPhaseBReadiness({
    evidence: readiness,
    envelope,
    asOf: typeof evidence.host_tuple?.observed_at === "string" ? evidence.host_tuple.observed_at : asOf,
  });
  for (const violation of result.violations) violations.push(`readiness_gate:${violation}`);
}

function decision(violations) {
  const unique = [...new Set(violations)].sort((left, right) => left.localeCompare(right));
  return { ok: unique.length === 0, violations: unique };
}

export function evaluateS37LinuxPhaseBConformanceEvidence({ manifest, readiness, envelope, profile, evidence, receipt, asOf }) {
  const violations = [];
  validateReadinessGate(readiness, envelope, evidence, asOf, violations);
  validateManifest(manifest, violations);
  validateReceipt(receipt, evidence, manifest, envelope, violations);
  validateProductProfile(profile, manifest, evidence, receipt, violations);
  validateLiveEvidence(evidence, manifest, receipt, readiness, envelope, violations);
  validateReadiness(readiness, envelope, manifest, evidence, violations);
  return decision(violations);
}

function main() {
  const paths = cli();
  const result = evaluateS37LinuxPhaseBConformanceEvidence({
    manifest: readJson(paths["--manifest"], "manifest"),
    readiness: readJson(paths["--readiness-evidence"], "readiness-evidence"),
    envelope: readJson(paths["--readiness-envelope"], "readiness-envelope"),
    profile: readJson(paths["--profile"], "profile"),
    evidence: readJson(paths["--evidence"], "evidence"),
    receipt: readJson(paths["--receipt"], "receipt"),
    asOf: new Date().toISOString(),
  });
  if (!result.ok) fail(result.violations);
  process.stdout.write("S37.1-B conformance evidence gate: PASS\n");
  process.stdout.write("sealed evidence only; no live host action performed\n");
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
