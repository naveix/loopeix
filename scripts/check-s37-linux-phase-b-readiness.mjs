import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const EVIDENCE_SCHEMA = "s37-linux-phase-b-readiness-evidence-v1";
const ENVELOPE_SCHEMA = "s37-linux-phase-b-readiness-envelope-v1";
const MANDATORY_SYSCTL_PATH = "/usr/lib/sysctl.d/50-bubblewrap.conf";
const ACQUISITION_MODE = "extract-only-user-staging";
const REQUIRED_BWRAP_VERSION = "0.11.0-2+deb13u1";
const REQUIRED_CONTROLLERS = Object.freeze(["cpu", "io", "memory", "pids"]);
const SHA256 = /^[a-f0-9]{64}$/u;

const KEYS = Object.freeze({
  evidence: ["schema_version", "observed_at", "host_tuple", "preflight", "package_review", "capacity_samples", "evidence_sha256"],
  envelope: ["schema_version", "approved_at", "approved_by", "valid_from", "valid_to", "measurement_window_seconds", "sample_interval_seconds", "min_sample_count", "concurrency", "task_ceiling", "host_requirements", "package_requirements", "thresholds", "threshold_reasons", "resource_limits", "resource_limit_reasons", "envelope_sha256"],
  host: ["platform", "architecture", "distro_id", "distro_version_id", "kernel_release", "systemd_version", "cgroup_version", "cgroup_controllers", "unprivileged_userns_clone", "user_manager_status"],
  hostRequirements: ["platform", "architecture", "distro_id", "distro_version_id", "kernel_release", "systemd_version", "cgroup_version", "required_cgroup_controllers", "unprivileged_userns_clone", "user_manager_status"],
  preflight: ["apt_dpkg_locks_clear", "reboot_required", "shutdown", "maintenance_conflict", "port_evidence"],
  ports: ["count", "sha256", "captured_at"],
  packageReview: ["candidate_version", "package_file_list_sha256", "mandatory_sysctl_path", "mandatory_sysctl_path_present", "acquisition_mode", "system_package_install", "sysctl_applied", "service_restart", "selected_artifact", "clean_install_evidence"],
  packageRequirements: ["candidate_version", "package_file_list_sha256", "selected_artifact_path", "selected_artifact_sha256"],
  artifact: ["path", "sha256", "setuid"],
  sample: ["timestamp", "cpu_cores", "memory_available_bytes", "swap_used_bytes", "load1", "load5", "cpu_psi_some_avg10", "memory_psi_some_avg10", "io_psi_some_avg10", "tasks"],
  thresholds: ["min_cpu_cores", "min_memory_available_bytes", "max_swap_used_bytes", "max_swap_growth_bytes", "max_load1", "max_load5", "max_cpu_psi_some_avg10", "max_memory_psi_some_avg10", "max_io_psi_some_avg10"],
  resourceLimits: ["cpu_quota_percent", "memory_max_bytes", "tasks_max", "io_weight", "timeout_ms", "stdout_bytes", "stderr_bytes"],
});

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write("usage: node scripts/check-s37-linux-phase-b-readiness.mjs --evidence <path> --envelope <path> [--as-of <ISO timestamp>]\n");
  process.exit(64);
}

function fail(violations) {
  const unique = [...new Set(violations)].sort((left, right) => left.localeCompare(right));
  process.stderr.write(`${unique.map((value) => `HOLD: ${value}`).join("\n")}\n`);
  process.exit(1);
}

function record(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value : null;
}

function strictRecord(value, allowed, label, violations) {
  const result = record(value);
  if (result === null) {
    violations.push(`${label}:missing-or-invalid`);
    return null;
  }
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(result)) {
    if (!allowedSet.has(key)) violations.push(`${label}:unexpected-key:${key}`);
  }
  for (const key of allowed) {
    if (!Object.hasOwn(result, key)) violations.push(`${label}:missing-key:${key}`);
  }
  return result;
}

function string(value, label, violations) {
  if (typeof value !== "string" || value.length === 0) {
    violations.push(`${label}:missing-or-invalid`);
    return null;
  }
  return value;
}

function bool(value, label, violations) {
  if (typeof value !== "boolean") {
    violations.push(`${label}:missing-or-invalid`);
    return null;
  }
  return value;
}

function number(value, label, violations, { integer = false, minimum = 0 } = {}) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < minimum || (integer && !Number.isInteger(value))) {
    violations.push(`${label}:missing-or-invalid`);
    return null;
  }
  return value;
}

function timestamp(value, label, violations) {
  const text = string(value, label, violations);
  if (text === null) return null;
  const milliseconds = Date.parse(text);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== text) {
    violations.push(`${label}:missing-or-invalid`);
    return null;
  }
  return milliseconds;
}

function hash(value, label, violations) {
  const text = string(value, label, violations);
  if (text !== null && !SHA256.test(text)) violations.push(`${label}:missing-or-invalid`);
  return text;
}

function stringArray(value, label, violations) {
  if (!Array.isArray(value) || value.length === 0 || value.some((entry) => typeof entry !== "string" || entry.length === 0)) {
    violations.push(`${label}:missing-or-invalid`);
    return null;
  }
  if (new Set(value).size !== value.length) violations.push(`${label}:duplicates`);
  return value;
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.entries(value)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
    .join(",")}}`;
}

function validateSelfHash(root, key, label, violations) {
  const supplied = hash(root[key], `${label}.${key}`, violations);
  const withoutHash = Object.fromEntries(Object.entries(root).filter(([entry]) => entry !== key));
  const expected = createHash("sha256").update(canonicalJson(withoutHash), "utf8").digest("hex");
  if (supplied !== null && supplied !== expected) violations.push(`${label}.${key}:mismatch`);
}

function readJson(path, label) {
  try {
    return JSON.parse(readFileSync(resolve(path), "utf8"));
  } catch (error) {
    usage(`${label}:unable-to-read-json:${error instanceof Error ? error.message : String(error)}`);
  }
}

function cli() {
  const args = process.argv.slice(2);
  let evidence = null;
  let envelope = null;
  let asOf = null;
  for (let index = 0; index < args.length; index += 1) {
    const flag = args[index];
    const value = args[index + 1];
    if (flag !== "--evidence" && flag !== "--envelope" && flag !== "--as-of") usage(`unknown argument: ${flag}`);
    if (value === undefined || value.startsWith("--")) {
      usage(flag === "--as-of" ? "--as-of requires an ISO timestamp" : `${flag} requires a path`);
    }
    if (flag === "--evidence") {
      if (evidence !== null) usage("duplicate argument: --evidence");
      evidence = value;
    } else if (flag === "--envelope") {
      if (envelope !== null) usage("duplicate argument: --envelope");
      envelope = value;
    } else {
      if (asOf !== null) usage("duplicate argument: --as-of");
      asOf = value;
    }
    index += 1;
  }
  if (evidence === null || envelope === null) usage("both --evidence and --envelope are required");
  return { evidence, envelope, asOf };
}

function exact(actual, expected, label, violations) {
  if (actual !== null && expected !== null && actual !== expected) {
    violations.push(`${label}:expected-${String(expected)}:actual-${String(actual)}`);
  }
}

function validateHost(evidence, envelope, violations) {
  const actual = strictRecord(evidence.host_tuple, KEYS.host, "host_tuple", violations);
  const expected = strictRecord(envelope.host_requirements, KEYS.hostRequirements, "host_requirements", violations);
  if (actual === null || expected === null) return;
  for (const field of ["platform", "architecture", "distro_id", "distro_version_id", "kernel_release", "systemd_version", "user_manager_status"]) {
    exact(string(actual[field], `host_tuple.${field}`, violations), string(expected[field], `host_requirements.${field}`, violations), `host_tuple.${field}`, violations);
  }
  for (const [field, requiredValue] of [
    ["platform", "linux"],
    ["architecture", "x86_64"],
    ["distro_id", "debian"],
    ["distro_version_id", "13"],
    ["user_manager_status", "running-delegated"],
  ]) {
    if (expected[field] !== requiredValue) violations.push(`host_requirements.${field}:expected-${requiredValue}`);
  }
  exact(number(actual.cgroup_version, "host_tuple.cgroup_version", violations, { integer: true }), number(expected.cgroup_version, "host_requirements.cgroup_version", violations, { integer: true }), "host_tuple.cgroup_version", violations);
  if (expected.cgroup_version !== 2) violations.push("host_requirements.cgroup_version:expected-2");
  exact(bool(actual.unprivileged_userns_clone, "host_tuple.unprivileged_userns_clone", violations), bool(expected.unprivileged_userns_clone, "host_requirements.unprivileged_userns_clone", violations), "host_tuple.unprivileged_userns_clone", violations);
  if (expected.unprivileged_userns_clone !== true) violations.push("host_requirements.unprivileged_userns_clone:expected-true");
  const controllers = stringArray(actual.cgroup_controllers, "host_tuple.cgroup_controllers", violations);
  const required = stringArray(expected.required_cgroup_controllers, "host_requirements.required_cgroup_controllers", violations);
  if (controllers !== null && required !== null) {
    for (const controller of required) if (!controllers.includes(controller)) violations.push(`host_tuple.cgroup_controllers:missing:${controller}`);
    for (const controller of REQUIRED_CONTROLLERS) {
      if (!required.includes(controller)) violations.push(`host_requirements.required_cgroup_controllers:missing:${controller}`);
    }
  }
}

function validatePreflight(evidence, observedAt, violations) {
  const preflight = strictRecord(evidence.preflight, KEYS.preflight, "preflight", violations);
  if (preflight === null) return;
  const requiredTrue = bool(preflight.apt_dpkg_locks_clear, "preflight.apt_dpkg_locks_clear", violations);
  if (requiredTrue === false) violations.push("preflight.apt_dpkg_locks_clear:expected-true");
  for (const field of ["reboot_required", "shutdown", "maintenance_conflict"]) {
    const value = bool(preflight[field], `preflight.${field}`, violations);
    if (value === true) violations.push(`preflight.${field}:expected-false`);
  }
  const ports = strictRecord(preflight.port_evidence, KEYS.ports, "preflight.port_evidence", violations);
  if (ports === null) return;
  number(ports.count, "preflight.port_evidence.count", violations, { integer: true });
  hash(ports.sha256, "preflight.port_evidence.sha256", violations);
  const capturedAt = timestamp(ports.captured_at, "preflight.port_evidence.captured_at", violations);
  if (capturedAt !== null && observedAt !== null && capturedAt !== observedAt) {
    violations.push("preflight.port_evidence.captured_at:not-observed-at");
  }
}

function validatePackage(evidence, envelope, violations) {
  const review = strictRecord(evidence.package_review, KEYS.packageReview, "package_review", violations);
  const requirements = strictRecord(envelope.package_requirements, KEYS.packageRequirements, "package_requirements", violations);
  if (review === null || requirements === null) return;
  exact(string(review.candidate_version, "package_review.candidate_version", violations), string(requirements.candidate_version, "package_requirements.candidate_version", violations), "package_review.candidate_version", violations);
  if (requirements.candidate_version !== REQUIRED_BWRAP_VERSION) {
    violations.push(`package_requirements.candidate_version:expected-${REQUIRED_BWRAP_VERSION}`);
  }
  exact(hash(review.package_file_list_sha256, "package_review.package_file_list_sha256", violations), hash(requirements.package_file_list_sha256, "package_requirements.package_file_list_sha256", violations), "package_review.package_file_list_sha256", violations);
  exact(string(review.mandatory_sysctl_path, "package_review.mandatory_sysctl_path", violations), MANDATORY_SYSCTL_PATH, "package_review.mandatory_sysctl_path", violations);
  if (bool(review.mandatory_sysctl_path_present, "package_review.mandatory_sysctl_path_present", violations) === false) violations.push("package_review.mandatory_sysctl_path_present:expected-true");
  const mode = string(review.acquisition_mode, "package_review.acquisition_mode", violations);
  if (mode !== null && mode !== ACQUISITION_MODE) violations.push(`package_review.acquisition_mode:${mode}`);
  if (bool(review.system_package_install, "package_review.system_package_install", violations) === true) violations.push("package_review.system_package_install:unauthorized");
  for (const field of ["sysctl_applied", "service_restart"]) {
    if (bool(review[field], `package_review.${field}`, violations) === true) violations.push(`package_review.${field}:expected-false`);
  }
  if (review.clean_install_evidence !== null) violations.push("package_review.clean_install_evidence:expected-null");
  const artifact = strictRecord(review.selected_artifact, KEYS.artifact, "package_review.selected_artifact", violations);
  if (artifact === null) return;
  exact(string(artifact.path, "package_review.selected_artifact.path", violations), string(requirements.selected_artifact_path, "package_requirements.selected_artifact_path", violations), "package_review.selected_artifact.path", violations);
  exact(hash(artifact.sha256, "package_review.selected_artifact.sha256", violations), hash(requirements.selected_artifact_sha256, "package_requirements.selected_artifact_sha256", violations), "package_review.selected_artifact.sha256", violations);
  if (bool(artifact.setuid, "package_review.selected_artifact.setuid", violations) === true) violations.push("package_review.selected_artifact.setuid:expected-false");
}

function validateEnvelopeTimes(envelope, observedAt, evaluationAt, violations) {
  string(envelope.approved_by, "envelope.approved_by", violations);
  const approvedAt = timestamp(envelope.approved_at, "envelope.approved_at", violations);
  const validFrom = timestamp(envelope.valid_from, "envelope.valid_from", violations);
  const validTo = timestamp(envelope.valid_to, "envelope.valid_to", violations);
  if (approvedAt !== null && validFrom !== null && approvedAt > validFrom) violations.push("envelope.approved_at:after-valid-from");
  if (validFrom !== null && validTo !== null && validFrom >= validTo) violations.push("envelope.valid_window:invalid");
  if (validTo !== null && evaluationAt !== null && validTo < evaluationAt) violations.push("envelope.valid_to:expired");
  if (observedAt !== null && evaluationAt !== null && observedAt > evaluationAt) violations.push("evidence.observed_at:future");
  if (observedAt !== null && validFrom !== null && observedAt < validFrom) violations.push("evidence.observed_at:before-valid-from");
  if (observedAt !== null && validTo !== null && observedAt > validTo) violations.push("evidence.observed_at:after-valid-to");
  return { validFrom, validTo };
}

function validateCapacity(evidence, envelope, observedAt, evaluationAt, validWindow, violations) {
  const thresholds = strictRecord(envelope.thresholds, KEYS.thresholds, "thresholds", violations);
  const thresholdReasons = strictRecord(envelope.threshold_reasons, KEYS.thresholds, "threshold_reasons", violations);
  if (thresholdReasons !== null) {
    for (const key of KEYS.thresholds) string(thresholdReasons[key], `threshold_reasons.${key}`, violations);
  }
  const windowSeconds = number(envelope.measurement_window_seconds, "envelope.measurement_window_seconds", violations, { integer: true, minimum: 1 });
  const intervalSeconds = number(envelope.sample_interval_seconds, "envelope.sample_interval_seconds", violations, { integer: true, minimum: 1 });
  const minSamples = number(envelope.min_sample_count, "envelope.min_sample_count", violations, { integer: true, minimum: 2 });
  const concurrency = number(envelope.concurrency, "envelope.concurrency", violations, { integer: true, minimum: 1 });
  const taskCeiling = number(envelope.task_ceiling, "envelope.task_ceiling", violations, { integer: true, minimum: 1 });
  const resourceLimits = strictRecord(envelope.resource_limits, KEYS.resourceLimits, "resource_limits", violations);
  const resourceLimitReasons = strictRecord(envelope.resource_limit_reasons, KEYS.resourceLimits, "resource_limit_reasons", violations);
  if (resourceLimitReasons !== null) {
    for (const key of KEYS.resourceLimits) string(resourceLimitReasons[key], `resource_limit_reasons.${key}`, violations);
  }
  if (resourceLimits !== null) {
    const cpuQuota = number(resourceLimits.cpu_quota_percent, "resource_limits.cpu_quota_percent", violations, { minimum: 1 });
    const memoryMax = number(resourceLimits.memory_max_bytes, "resource_limits.memory_max_bytes", violations, { integer: true, minimum: 1 });
    const tasksMax = number(resourceLimits.tasks_max, "resource_limits.tasks_max", violations, { integer: true, minimum: 1 });
    number(resourceLimits.io_weight, "resource_limits.io_weight", violations, { integer: true, minimum: 1 });
    exact(number(resourceLimits.timeout_ms, "resource_limits.timeout_ms", violations, { integer: true, minimum: 1 }), 1_000, "resource_limits.timeout_ms", violations);
    exact(number(resourceLimits.stdout_bytes, "resource_limits.stdout_bytes", violations, { integer: true, minimum: 1 }), 1_024, "resource_limits.stdout_bytes", violations);
    exact(number(resourceLimits.stderr_bytes, "resource_limits.stderr_bytes", violations, { integer: true, minimum: 1 }), 1_024, "resource_limits.stderr_bytes", violations);
    const minCpuCores = thresholds === null ? null : number(thresholds.min_cpu_cores, "thresholds.min_cpu_cores", violations, { minimum: 1 });
    const minMemoryAvailable = thresholds === null ? null : number(thresholds.min_memory_available_bytes, "thresholds.min_memory_available_bytes", violations, { minimum: 1 });
    if (cpuQuota !== null && minCpuCores !== null && cpuQuota > minCpuCores * 100) violations.push("resource_limits.cpu_quota_percent:exceeds-host-reserve");
    if (memoryMax !== null && minMemoryAvailable !== null && memoryMax > minMemoryAvailable) violations.push("resource_limits.memory_max_bytes:exceeds-host-reserve");
    if (tasksMax !== null && taskCeiling !== null && tasksMax > taskCeiling) violations.push("resource_limits.tasks_max:exceeds-task-ceiling");
    if (resourceLimits.io_weight > 10_000) violations.push("resource_limits.io_weight:above-systemd-maximum");
  }
  if (concurrency !== null && concurrency !== 1) violations.push("envelope.concurrency:expected-1");
  if (observedAt !== null && evaluationAt !== null && intervalSeconds !== null && evaluationAt - observedAt > intervalSeconds * 1000) {
    violations.push("evidence.observed_at:stale");
  }
  if (!Array.isArray(evidence.capacity_samples)) {
    violations.push("capacity_samples:missing-or-invalid");
    return;
  }
  if (minSamples !== null && evidence.capacity_samples.length < minSamples) violations.push("capacity_samples:below-min-sample-count");
  const parsed = [];
  for (const [index, value] of evidence.capacity_samples.entries()) {
    const label = `capacity_samples[${index}]`;
    const sample = strictRecord(value, KEYS.sample, label, violations);
    if (sample === null) continue;
    const values = {
      timestamp: timestamp(sample.timestamp, `${label}.timestamp`, violations),
      cpu_cores: number(sample.cpu_cores, `${label}.cpu_cores`, violations, { integer: true, minimum: 1 }),
      memory_available_bytes: number(sample.memory_available_bytes, `${label}.memory_available_bytes`, violations),
      swap_used_bytes: number(sample.swap_used_bytes, `${label}.swap_used_bytes`, violations),
      load1: number(sample.load1, `${label}.load1`, violations),
      load5: number(sample.load5, `${label}.load5`, violations),
      cpu_psi_some_avg10: number(sample.cpu_psi_some_avg10, `${label}.cpu_psi_some_avg10`, violations),
      memory_psi_some_avg10: number(sample.memory_psi_some_avg10, `${label}.memory_psi_some_avg10`, violations),
      io_psi_some_avg10: number(sample.io_psi_some_avg10, `${label}.io_psi_some_avg10`, violations),
      tasks: number(sample.tasks, `${label}.tasks`, violations, { integer: true }),
    };
    parsed.push(values);
    if (values.timestamp !== null && validWindow.validFrom !== null && values.timestamp < validWindow.validFrom) {
      violations.push(`${label}.timestamp:before-valid-from`);
    }
    if (values.timestamp !== null && validWindow.validTo !== null && values.timestamp > validWindow.validTo) {
      violations.push(`${label}.timestamp:after-valid-to`);
    }
    if (thresholds !== null) {
      const checks = [
        ["cpu_cores", "min_cpu_cores", "below-minimum"],
        ["memory_available_bytes", "min_memory_available_bytes", "below-minimum"],
        ["swap_used_bytes", "max_swap_used_bytes", "above-maximum"],
        ["load1", "max_load1", "above-maximum"],
        ["load5", "max_load5", "above-maximum"],
        ["cpu_psi_some_avg10", "max_cpu_psi_some_avg10", "above-maximum"],
        ["memory_psi_some_avg10", "max_memory_psi_some_avg10", "above-maximum"],
        ["io_psi_some_avg10", "max_io_psi_some_avg10", "above-maximum"],
      ];
      for (const [metric, thresholdName, reason] of checks) {
        const limit = number(thresholds[thresholdName], `thresholds.${thresholdName}`, violations);
        const actual = values[metric];
        if (actual !== null && limit !== null && (reason === "below-minimum" ? actual < limit : actual > limit)) violations.push(`${label}.${metric}:${reason}`);
      }
    }
    if (values.tasks !== null && taskCeiling !== null && values.tasks > taskCeiling) violations.push(`${label}.tasks:above-task-ceiling`);
  }
  if (parsed.length > 0 && observedAt !== null && parsed.at(-1).timestamp !== observedAt) violations.push("capacity_samples:last-timestamp-not-observed-at");
  if (parsed.length > 1 && intervalSeconds !== null) {
    const intervalMs = intervalSeconds * 1000;
    for (let index = 1; index < parsed.length; index += 1) {
      if (parsed[index - 1].timestamp === null || parsed[index].timestamp === null || parsed[index].timestamp - parsed[index - 1].timestamp !== intervalMs) violations.push("capacity_samples:incomplete-interval");
    }
  }
  if (parsed.length > 1 && windowSeconds !== null && parsed[0].timestamp !== null && parsed.at(-1).timestamp !== null && parsed.at(-1).timestamp - parsed[0].timestamp < windowSeconds * 1000) violations.push("capacity_samples:window-too-short");
  if (parsed.length > 1 && thresholds !== null) {
    const maxGrowth = number(thresholds.max_swap_growth_bytes, "thresholds.max_swap_growth_bytes", violations);
    const first = parsed[0].swap_used_bytes;
    const last = parsed.at(-1).swap_used_bytes;
    if (first !== null && last !== null && maxGrowth !== null && last - first > maxGrowth) violations.push("capacity_samples:swap-growth-above-maximum");
  }
}

function decision(violations) {
  const unique = [...new Set(violations)].sort((left, right) => left.localeCompare(right));
  return { ok: unique.length === 0, violations: unique };
}

export function evaluateS37LinuxPhaseBReadiness({ evidence: evidenceInput, envelope: envelopeInput, asOf }) {
  const violations = [];
  const evidence = strictRecord(evidenceInput, KEYS.evidence, "evidence", violations);
  const envelope = strictRecord(envelopeInput, KEYS.envelope, "envelope", violations);
  if (evidence === null || envelope === null) return decision(violations);
  exact(string(evidence.schema_version, "evidence.schema_version", violations), EVIDENCE_SCHEMA, "evidence.schema_version", violations);
  exact(string(envelope.schema_version, "envelope.schema_version", violations), ENVELOPE_SCHEMA, "envelope.schema_version", violations);
  validateSelfHash(evidence, "evidence_sha256", "evidence", violations);
  validateSelfHash(envelope, "envelope_sha256", "envelope", violations);
  const observedAt = timestamp(evidence.observed_at, "evidence.observed_at", violations);
  const evaluationAt = timestamp(asOf, "as_of", violations);
  const validWindow = validateEnvelopeTimes(envelope, observedAt, evaluationAt, violations);
  validateHost(evidence, envelope, violations);
  validatePreflight(evidence, observedAt, violations);
  validatePackage(evidence, envelope, violations);
  validateCapacity(evidence, envelope, observedAt, evaluationAt, validWindow, violations);
  return decision(violations);
}

function main() {
  const paths = cli();
  const result = evaluateS37LinuxPhaseBReadiness({
    evidence: readJson(paths.evidence, "evidence"),
    envelope: readJson(paths.envelope, "envelope"),
    asOf: paths.asOf ?? new Date().toISOString(),
  });
  if (!result.ok) fail(result.violations);
  process.stdout.write("S37.1-B passive readiness gate: PASS\n");
  process.stdout.write(paths.asOf === null
    ? "readiness only; live host conformance not executed\n"
    : "historical readiness validation only; not current execution readiness\n");
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
