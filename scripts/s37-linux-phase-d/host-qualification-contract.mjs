import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { arch, platform, release } from "node:os";
import process from "node:process";
import jcsCanonicalize from "canonicalize";

export const S37_PHASE_D_BINDING_PATH = "/etc/loopeix/s37.1/local-product-binding.json";
export const S37_PHASE_D_MIN_AUTHORITY_MS = 15_000;
const S37_PHASE_D_MAX_TUPLE_AGE_MS = 15_000;
const S37_PHASE_D_MAX_RECEIPT_LIFETIME_MS = 600_000;

const REQUIRED_CONTROLLERS = Object.freeze(["cpu", "io", "memory", "pids"]);
const REQUIRED_DENY_ROWS = Object.freeze([
  "ambient-credentials", "child-process", "durable-state", "environment",
  "filesystem-write", "network", "output-limits", "retry", "stdin",
  "timeout", "tool-server", "unknown-outcome",
]);
const DIRECTORIES = Object.freeze([
  "/etc", "/etc/loopeix", "/etc/loopeix/s37.1",
  "/opt", "/opt/loopeix", "/opt/loopeix/s37.1",
  "/usr", "/usr/bin", "/sys", "/sys/fs", "/sys/fs/cgroup",
]);
const FILES = Object.freeze({
  machine_id: ["/etc/machine-id", 0o444],
  cgroup_controllers: ["/sys/fs/cgroup/cgroup.controllers", 0o444],
  supervisor: ["/opt/loopeix/s37.1/supervisor", 0o555],
  probe: ["/opt/loopeix/s37.1/probe", 0o555],
  bwrap: ["/opt/loopeix/s37.1/bwrap", 0o555],
  systemd_run: ["/usr/bin/systemd-run", 0o755],
  systemctl: ["/usr/bin/systemctl", 0o755],
});
const HASH = /^sha256:[a-f0-9]{64}$/u;
const RAW_HASH = /^[a-f0-9]{64}$/u;
const APPROVED_ARTIFACTS = Object.freeze({
  supervisor: "sha256:a098a5f32c71fc0f1014b64a2a5e86535690b5d973771bcda35a864d66e60046",
  probe: "sha256:22de7539d222b8092240d17de27e9dbecffbc84684d6576454008030167f361a",
  bwrap: "sha256:0dfa36b98ada69568aaaa741fe210d2150a1441433bd13c428137d6a972a959c",
  systemd_run: "sha256:134039cdeb8db64f3f7eb0a3f917afe7d08ac9866313b02c6caa0af02eaf3945",
  systemctl: "sha256:ff4b294dcb57179cad146355dcfdca5fb7f516963b73f25f09171ec6d2fb0954",
  seccomp: "sha256:dc318421e96d062286c0a625ceb3db6d7db1ccb6c83a6da17848335de77dbe2c",
});
const APPROVED_SOURCES = Object.freeze({
  supervisor: "sha256:515c7fa5e6ba937e25f75b025c4b7d67f8b9354f40955e4a601506881b7c2835",
  probe: "sha256:0cb0abe0b45ad54a46a93ef3adec76bdd3e60824ac97e8e08756e103f5d74405",
});

export function canonical(value) {
  const result = jcsCanonicalize(value);
  if (result === undefined) throw new Error("S37_PHASE_D_CANONICALIZATION_FAILED");
  return result;
}

export function hashCanonical(value) {
  return `sha256:${createHash("sha256").update(canonical(value), "utf8").digest("hex")}`;
}

export function hashBytes(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function metadata(path) {
  const stat = lstatSync(path);
  return Object.freeze({
    kind: stat.isSymbolicLink() ? "symlink" : stat.isDirectory() ? "directory" : stat.isFile() ? "file" : stat.isSocket() ? "socket" : "other",
    uid: stat.uid,
    mode: stat.mode & 0o7777,
    nlink: stat.nlink,
    dev: stat.dev,
    ino: stat.ino,
    size: stat.size,
    mtime_ms: stat.mtimeMs,
    ctime_ms: stat.ctimeMs,
  });
}

function stableFile(path) {
  const before = metadata(path);
  const bytes = new Uint8Array(readFileSync(path));
  const after = metadata(path);
  if (canonical(before) !== canonical(after) || (before.size !== 0 && before.size !== bytes.byteLength)) {
    throw new Error(`S37_PHASE_D_FILE_CAPTURE_DRIFT:${path}`);
  }
  return Object.freeze({ metadata: before, bytes, sha256: hashBytes(bytes) });
}

function normalizedArchitecture(value) {
  if (value === "x64") return "x86_64";
  if (value === "arm64") return "aarch64";
  return value;
}

export function assertS37PhaseDPlatform(observedPlatform) {
  if (observedPlatform !== "linux") throw new Error("S37_PHASE_D_PLATFORM_NOT_LINUX");
}

export function collectLocalHostCapture(controllerUid = typeof process.getuid === "function" ? process.getuid() : Number.NaN) {
  assertS37PhaseDPlatform(platform());
  const directories = Object.fromEntries(DIRECTORIES.map((path) => [path, metadata(path)]));
  const files = Object.fromEntries(Object.entries(FILES).map(([name, [path]]) => [name, stableFile(path)]));
  const runtimeDirectory = `/run/user/${controllerUid}`;
  return Object.freeze({
    platform: "linux",
    architecture: normalizedArchitecture(arch()),
    kernel_release: release(),
    controller_uid: controllerUid,
    directories: Object.freeze(directories),
    files: Object.freeze(files),
    user_runtime: Object.freeze({ directory: metadata(runtimeDirectory), bus: metadata(`${runtimeDirectory}/bus`) }),
  });
}

function add(condition, violations, code) {
  if (!condition) violations.push(code);
}

function exactKeys(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && canonical(Object.keys(value).sort()) === canonical([...keys].sort());
}

function validIso(value) {
  const milliseconds = typeof value === "string" ? Date.parse(value) : Number.NaN;
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function sortedCanonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(sortedCanonical).join(",")}]`;
  return `{${Object.entries(value).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0).map(([key, entry]) => `${JSON.stringify(key)}:${sortedCanonical(entry)}`).join(",")}}`;
}

function readinessCanonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(readinessCanonical).join(",")}]`;
  return `{${Object.entries(value).sort(([left], [right]) => left.localeCompare(right)).map(([key, entry]) => `${JSON.stringify(key)}:${readinessCanonical(entry)}`).join(",")}}`;
}

function rawDigest(value, serializer = sortedCanonical) {
  return createHash("sha256").update(serializer(value), "utf8").digest("hex");
}

function equalCanonical(left, right) {
  return sortedCanonical(left) === sortedCanonical(right);
}

function validateRawSelfHash(value, key, serializer, label, violations) {
  const supplied = value?.[key];
  if (!RAW_HASH.test(supplied ?? "")) {
    violations.push(label);
    return;
  }
  const body = Object.fromEntries(Object.entries(value).filter(([name]) => name !== key));
  if (supplied !== rawDigest(body, serializer)) violations.push(label);
}

function validatePhaseBSealedInputs(phaseB, qualification, violations) {
  if (phaseB === null || typeof phaseB !== "object") {
    violations.push("phase-b-sealed-inputs-required");
    return;
  }
  const manifest = phaseB.manifest;
  const readiness = phaseB.readiness_evidence;
  const envelope = phaseB.readiness_envelope;
  const conformance = phaseB.conformance_evidence;
  const receipt = phaseB.receipt;
  if (manifest === undefined || readiness === undefined || envelope === undefined || conformance === undefined || receipt === undefined) {
    violations.push("phase-b-sealed-inputs-required");
    return;
  }

  add(manifest?.schema_version === "s37-linux-phase-b-build-manifest-v1", violations, "phase-b-manifest-schema-invalid");
  add(readiness?.schema_version === "s37-linux-phase-b-readiness-evidence-v1", violations, "phase-b-readiness-schema-invalid");
  add(envelope?.schema_version === "s37-linux-phase-b-readiness-envelope-v1", violations, "phase-b-readiness-envelope-schema-invalid");
  add(conformance?.schema_version === "s37-linux-phase-b-conformance-evidence-v1", violations, "phase-b-conformance-schema-invalid");
  validateRawSelfHash(manifest, "manifest_sha256", sortedCanonical, "phase-b-manifest-seal-invalid", violations);
  validateRawSelfHash(readiness, "evidence_sha256", readinessCanonical, "phase-b-readiness-seal-invalid", violations);
  validateRawSelfHash(envelope, "envelope_sha256", readinessCanonical, "phase-b-readiness-envelope-seal-invalid", violations);
  validateRawSelfHash(conformance, "evidence_sha256", sortedCanonical, "phase-b-conformance-evidence-seal-invalid", violations);

  add(conformance?.manifest_sha256 === manifest?.manifest_sha256, violations, "phase-b-conformance-manifest-mismatch");
  add(equalCanonical(receipt, qualification?.backend_receipt), violations, "phase-b-conformance-receipt-mismatch");
  if (receipt !== null && typeof receipt === "object" && Object.hasOwn(receipt, "receipt_hash")) {
    const { receipt_hash: supplied, ...body } = receipt;
    add(supplied === hashCanonical({ purpose: "s37-linux-backend-identity-receipt-v02", ...body }), violations, "phase-b-conformance-receipt-mismatch");
  } else violations.push("phase-b-conformance-receipt-mismatch");

  add(conformance?.receipt_hash === receipt?.receipt_hash, violations, "phase-b-conformance-receipt-mismatch");
  add(conformance?.readiness_evidence_sha256 === readiness?.evidence_sha256, violations, "phase-b-conformance-readiness-evidence-mismatch");
  add(conformance?.readiness_envelope_sha256 === envelope?.envelope_sha256, violations, "phase-b-conformance-readiness-envelope-mismatch");
  add(equalCanonical(conformance?.host_tuple, qualification?.host_tuple), violations, "phase-b-conformance-host-tuple-mismatch");
  add(conformance?.execution?.profile_hash === hashCanonical(qualification?.profile), violations, "phase-b-conformance-profile-mismatch");
  add(conformance?.execution?.launcher_sha256 === receipt?.launcher_sha256, violations, "phase-b-conformance-launcher-mismatch");
  add(conformance?.execution?.seccomp_policy_sha256 === receipt?.seccomp_policy_sha256, violations, "phase-b-conformance-seccomp-mismatch");
  add(manifest?.sources?.supervisor?.path === "scripts/s37-linux-phase-b/supervisor.c", violations, "phase-b-manifest-source-path-invalid:supervisor");
  add(manifest?.sources?.probe?.path === "scripts/s37-linux-phase-b/probe.c", violations, "phase-b-manifest-source-path-invalid:probe");
  add(manifest?.sources?.supervisor?.sha256 === APPROVED_SOURCES.supervisor, violations, "phase-b-manifest-source-unapproved:supervisor");
  add(manifest?.sources?.probe?.sha256 === APPROVED_SOURCES.probe, violations, "phase-b-manifest-source-unapproved:probe");
  add(manifest?.artifacts?.supervisor?.path === "/opt/loopeix/s37.1/supervisor", violations, "phase-b-manifest-artifact-path-invalid:supervisor");
  add(manifest?.artifacts?.probe?.path === "/opt/loopeix/s37.1/probe", violations, "phase-b-manifest-artifact-path-invalid:probe");
  add(manifest?.artifacts?.supervisor?.mode === "0555" && manifest?.artifacts?.supervisor?.setuid === false, violations, "phase-b-manifest-artifact-mode-invalid:supervisor");
  add(manifest?.artifacts?.probe?.mode === "0555" && manifest?.artifacts?.probe?.setuid === false, violations, "phase-b-manifest-artifact-mode-invalid:probe");
  add(manifest?.artifacts?.supervisor?.sha256 === APPROVED_ARTIFACTS.supervisor, violations, "phase-b-manifest-artifact-unapproved:supervisor");
  add(manifest?.artifacts?.probe?.sha256 === APPROVED_ARTIFACTS.probe, violations, "phase-b-manifest-artifact-unapproved:probe");
  add(manifest?.bwrap?.path === "/opt/loopeix/s37.1/bwrap", violations, "phase-b-manifest-bwrap-path-invalid");
  add(manifest?.bwrap?.mode === "0555" && manifest?.bwrap?.setuid === false, violations, "phase-b-manifest-bwrap-mode-invalid");
  add(manifest?.bwrap?.sha256 === APPROVED_ARTIFACTS.bwrap, violations, "phase-b-manifest-bwrap-unapproved");
  add(manifest?.seccomp_policy_sha256 === APPROVED_ARTIFACTS.seccomp, violations, "phase-b-manifest-seccomp-unapproved");
  add(qualification?.profile?.executable?.path === manifest?.artifacts?.probe?.path
    && qualification?.profile?.executable?.sha256 === manifest?.artifacts?.probe?.sha256,
  violations, "phase-b-manifest-profile-probe-mismatch");
  add(receipt?.launcher_sha256 === manifest?.artifacts?.supervisor?.sha256, violations, "phase-b-manifest-receipt-launcher-mismatch");
  add(receipt?.bwrap?.path === manifest?.bwrap?.path
    && receipt?.bwrap?.sha256 === manifest?.bwrap?.sha256,
  violations, "phase-b-manifest-receipt-bwrap-mismatch");
  add(receipt?.seccomp_policy_sha256 === manifest?.seccomp_policy_sha256, violations, "phase-b-manifest-receipt-seccomp-mismatch");

  add(Array.isArray(readiness?.capacity_samples) && readiness.capacity_samples.length === 5, violations, "phase-b-readiness-sample-count-invalid");
  add(envelope?.min_sample_count === 5, violations, "phase-b-readiness-min-samples-invalid");
  add(envelope?.concurrency === 1, violations, "phase-b-envelope-concurrency-invalid");
  add(envelope?.resource_limits?.cpu_quota_percent === 25, violations, "phase-b-envelope-limit-invalid:cpu_quota_percent");
  add(envelope?.resource_limits?.memory_max_bytes === 64_000_000, violations, "phase-b-envelope-limit-invalid:memory_max_bytes");
  add(envelope?.resource_limits?.tasks_max === 8, violations, "phase-b-envelope-limit-invalid:tasks_max");
  add(envelope?.resource_limits?.io_weight === 10, violations, "phase-b-envelope-limit-invalid:io_weight");
  add(envelope?.resource_limits?.timeout_ms === 1_000, violations, "phase-b-envelope-limit-invalid:timeout_ms");
  add(envelope?.resource_limits?.stdout_bytes === 1_024, violations, "phase-b-envelope-limit-invalid:stdout_bytes");
  add(envelope?.resource_limits?.stderr_bytes === 1_024, violations, "phase-b-envelope-limit-invalid:stderr_bytes");
  add(conformance?.capacity?.samples_sha256 === rawDigest(readiness?.capacity_samples ?? []), violations, "phase-b-capacity-samples-mismatch");
  add(conformance?.capacity?.envelope_sha256 === envelope?.envelope_sha256, violations, "phase-b-capacity-envelope-mismatch");
  add(conformance?.capacity?.within_envelope === true, violations, "phase-b-capacity-breach");
  add(conformance?.capacity?.swap_growth_bytes === 0, violations, "phase-b-swap-growth");

  add(Array.isArray(receipt?.deny_rows) && canonical(receipt.deny_rows) === canonical(REQUIRED_DENY_ROWS), violations, "phase-b-receipt-deny-rows-invalid");
  add(Array.isArray(receipt?.skipped_rows) && receipt.skipped_rows.length === 0, violations, "phase-b-receipt-skipped-rows-invalid");

  const execution = conformance?.execution;
  add(execution?.service_type === "exec", violations, "phase-b-execution-service-type-invalid");
  add(execution?.scope === false, violations, "phase-b-execution-scope-invalid");
  add(execution?.pipe === false, violations, "phase-b-execution-pipe-invalid");
  for (const key of ["standard_input", "standard_output", "standard_error"]) {
    add(execution?.[key] === "null", violations, `phase-b-execution-stdio-invalid:${key}`);
  }
  add(execution?.no_new_privileges === true, violations, "phase-b-execution-no-new-privileges-invalid");
  add(execution?.kill_mode === "control-group", violations, "phase-b-execution-kill-mode-invalid");
  add(execution?.concurrency === envelope?.concurrency, violations, "phase-b-execution-concurrency-invalid");
  add(execution?.cpu_quota_percent === envelope?.resource_limits?.cpu_quota_percent, violations, "phase-b-execution-limit-invalid:cpu_quota_percent");
  add(execution?.memory_max_bytes === envelope?.resource_limits?.memory_max_bytes, violations, "phase-b-execution-limit-invalid:memory_max_bytes");
  add(execution?.tasks_max === envelope?.resource_limits?.tasks_max, violations, "phase-b-execution-limit-invalid:tasks_max");
  add(execution?.io_weight === envelope?.resource_limits?.io_weight, violations, "phase-b-execution-limit-invalid:io_weight");
  add(execution?.timeout_ms === envelope?.resource_limits?.timeout_ms, violations, "phase-b-execution-limit-invalid:timeout_ms");
  add(execution?.stdout_limit_bytes === envelope?.resource_limits?.stdout_bytes, violations, "phase-b-execution-stdout-limit-invalid");
  add(execution?.stderr_limit_bytes === envelope?.resource_limits?.stderr_bytes, violations, "phase-b-execution-stderr-limit-invalid");
  add(execution?.process_started === true, violations, "phase-b-execution-process-not-started");
  add(execution?.exit_code === 0, violations, "phase-b-execution-exit-code-invalid");
  add(Number.isFinite(execution?.probe_duration_ms) && execution.probe_duration_ms >= 0 && execution.probe_duration_ms <= 1_000, violations, "phase-b-execution-duration-invalid");
  add(execution?.stdout_bytes === 0, violations, "phase-b-execution-stdout-nonzero");
  add(execution?.stderr_bytes === 0, violations, "phase-b-execution-stderr-nonzero");

  const denyRows = Array.isArray(conformance?.deny_rows) ? conformance.deny_rows : [];
  add(denyRows.length === REQUIRED_DENY_ROWS.length, violations, "phase-b-deny-rows-invalid");
  add(canonical(denyRows.map((entry) => entry?.row ?? null)) === canonical(REQUIRED_DENY_ROWS), violations, "phase-b-deny-rows-order-invalid");
  for (const [index, row] of REQUIRED_DENY_ROWS.entries()) {
    const entry = denyRows[index];
    add(entry?.row === row && entry?.passed === true && entry?.skipped === false && RAW_HASH.test(entry?.witness_sha256 ?? ""), violations, `phase-b-deny-row-invalid:${row}`);
  }

  add(conformance?.ports?.delta === 0, violations, "phase-b-port-drift");
  add(equalCanonical(conformance?.ports?.before, conformance?.ports?.after), violations, "phase-b-port-drift");
  add(equalCanonical(conformance?.neighbors?.services_before, conformance?.neighbors?.services_after)
    && equalCanonical(conformance?.neighbors?.containers_before, conformance?.neighbors?.containers_after),
  violations, "phase-b-neighbor-drift");
  for (const key of ["unit_absent", "process_absent", "mount_absent", "temp_absent", "journal_payload_absent", "file_absent"]) {
    add(conformance?.cleanup?.[key] === true, violations, `phase-b-cleanup-invalid:${key}`);
  }
}

export function evaluateS37PhaseDHost(capture, qualification, phaseB, asOf = new Date()) {
  const violations = [];
  const now = asOf instanceof Date ? asOf.getTime() : Number.NaN;
  const tuple = qualification?.host_tuple;
  const receipt = qualification?.backend_receipt;
  const profile = qualification?.profile;

  add(Number.isFinite(now), violations, "clock-invalid");
  add(capture?.platform === "linux", violations, "platform-not-linux");
  add(capture?.architecture === "x86_64", violations, "architecture-not-x86_64");
  add(Number.isSafeInteger(capture?.controller_uid) && capture.controller_uid > 0, violations, "controller-uid-not-nonroot");

  for (const path of DIRECTORIES) {
    const entry = capture?.directories?.[path];
    add(entry?.kind === "directory", violations, `directory-invalid:${path}`);
    add(entry?.uid === 0, violations, `directory-owner-invalid:${path}`);
    add(typeof entry?.mode === "number" && (entry.mode & 0o022) === 0, violations, `directory-writable:${path}`);
  }
  for (const [name, [, mode]] of Object.entries(FILES)) {
    const entry = capture?.files?.[name];
    add(entry?.metadata?.kind === "file", violations, `file-invalid:${name}`);
    add(entry?.metadata?.uid === 0, violations, `file-owner-invalid:${name}`);
    add(entry?.metadata?.mode === mode, violations, `file-mode-invalid:${name}`);
    add(entry?.metadata?.nlink === 1, violations, `file-link-count-invalid:${name}`);
    add(entry?.bytes instanceof Uint8Array && entry.bytes.byteLength > 0, violations, `file-empty:${name}`);
    add(HASH.test(entry?.sha256 ?? ""), violations, `file-hash-invalid:${name}`);
  }
  add(capture?.user_runtime?.directory?.kind === "directory", violations, "user-runtime-invalid");
  add(capture?.user_runtime?.directory?.uid === capture?.controller_uid, violations, "user-runtime-owner-invalid");
  add(capture?.user_runtime?.directory?.mode === 0o700, violations, "user-runtime-mode-invalid");
  add(capture?.user_runtime?.bus?.kind === "socket", violations, "user-bus-invalid");
  add(capture?.user_runtime?.bus?.uid === capture?.controller_uid, violations, "user-bus-owner-invalid");

  const controllers = capture?.files?.cgroup_controllers?.bytes instanceof Uint8Array
    ? Buffer.from(capture.files.cgroup_controllers.bytes).toString("utf8").trim().split(/\s+/u)
    : [];
  add(REQUIRED_CONTROLLERS.every((name) => controllers.includes(name)), violations, "cgroup-controller-missing");

  add(exactKeys(tuple, ["tuple_version", "platform", "architecture", "kernel_release", "systemd_version", "cgroup_version", "observed_at"]), violations, "tuple-shape-invalid");
  add(tuple?.tuple_version === "0.1" && tuple?.platform === "linux" && tuple?.cgroup_version === "v2", violations, "tuple-contract-invalid");
  add(typeof tuple?.systemd_version === "string" && tuple.systemd_version.length > 0, violations, "tuple-systemd-version-invalid");
  add(tuple?.architecture === capture?.architecture && tuple?.kernel_release === capture?.kernel_release, violations, "tuple-host-drift");
  add(validIso(tuple?.observed_at), violations, "tuple-time-invalid");

  const profileContractValid = exactKeys(profile, [
    "profile_version", "probe_kind", "actor_identity_hash", "on_behalf_of_chain_hash", "executable", "argv", "cwd",
    "filesystem", "child_process", "network", "tools", "environment", "credentials", "stdin", "limits",
    "durable_state", "retry",
  ])
    && profile?.profile_version === "0.1"
    && profile?.probe_kind === "inert-bounded-stdout-stderr"
    && HASH.test(profile?.actor_identity_hash ?? "")
    && HASH.test(profile?.on_behalf_of_chain_hash ?? "")
    && exactKeys(profile?.executable, ["path", "sha256"])
    && exactKeys(profile?.cwd, ["path", "identity_hash"])
    && exactKeys(profile?.filesystem, ["readable_paths", "writable_paths", "direct_writes"])
    && exactKeys(profile?.network, ["mode", "allowed_origins"])
    && exactKeys(profile?.tools, ["built_in", "mcp_servers"])
    && exactKeys(profile?.environment, ["inherit", "allowed_names", "values"])
    && exactKeys(profile?.limits, ["timeout_ms", "stdout_bytes", "stderr_bytes"])
    && profile?.cwd?.path === "/" && HASH.test(profile?.cwd?.identity_hash ?? "")
    && Array.isArray(profile?.argv) && profile.argv.length === 0
    && profile?.filesystem?.readable_paths?.length === 1
    && profile.filesystem.readable_paths[0] === "/opt/loopeix/s37.1/probe"
    && Array.isArray(profile?.filesystem?.writable_paths) && profile.filesystem.writable_paths.length === 0
    && profile?.filesystem?.direct_writes === "deny"
    && profile?.child_process === "deny"
    && profile?.network?.mode === "deny" && profile.network.allowed_origins?.length === 0
    && profile?.tools?.built_in === "deny" && profile.tools.mcp_servers === "deny"
    && profile?.environment?.inherit === false && profile.environment.allowed_names?.length === 0
    && exactKeys(profile?.environment?.values, [])
    && profile?.credentials === "deny" && profile?.stdin === "closed"
    && profile?.limits?.timeout_ms === 1_000 && profile.limits.stdout_bytes === 1_024 && profile.limits.stderr_bytes === 1_024
    && profile?.durable_state === "forbidden-until-s40" && profile?.retry === "forbidden-non-resumable";
  add(profileContractValid, violations, "profile-contract-invalid");

  add(exactKeys(receipt, ["receipt_version", "host_tuple_hash", "profile_hash", "launcher_sha256", "bwrap", "seccomp_policy_sha256", "deny_rows", "skipped_rows", "issued_at", "expires_at", "receipt_hash"]), violations, "receipt-shape-invalid");
  add(receipt?.receipt_version === "0.1", violations, "receipt-version-invalid");
  add(Array.isArray(receipt?.deny_rows) && canonical(receipt.deny_rows) === canonical(REQUIRED_DENY_ROWS), violations, "receipt-deny-rows-invalid");
  add(Array.isArray(receipt?.skipped_rows) && receipt.skipped_rows.length === 0, violations, "receipt-skipped-rows");
  for (const field of ["host_tuple_hash", "profile_hash", "launcher_sha256", "seccomp_policy_sha256", "receipt_hash"]) {
    add(HASH.test(receipt?.[field] ?? ""), violations, `receipt-hash-invalid:${field}`);
  }
  add(exactKeys(receipt?.bwrap, ["path", "version", "sha256", "setuid"])
    && receipt?.bwrap?.path === "/opt/loopeix/s37.1/bwrap" && receipt?.bwrap?.setuid === false
    && typeof receipt?.bwrap?.version === "string" && receipt.bwrap.version.length > 0
    && HASH.test(receipt?.bwrap?.sha256 ?? ""), violations, "receipt-bwrap-invalid");
  add(validIso(receipt?.issued_at) && validIso(receipt?.expires_at), violations, "receipt-time-invalid");

  if (tuple !== null && typeof tuple === "object") {
    add(receipt?.host_tuple_hash === hashCanonical({ purpose: "s37-linux-host-tuple-v02", ...tuple }), violations, "receipt-tuple-hash-mismatch");
  }
  if (profile !== null && typeof profile === "object") {
    add(receipt?.profile_hash === hashCanonical(profile), violations, "receipt-profile-hash-mismatch");
  } else violations.push("profile-invalid");
  if (receipt !== null && typeof receipt === "object" && Object.hasOwn(receipt, "receipt_hash")) {
    const { receipt_hash: supplied, ...body } = receipt;
    add(supplied === hashCanonical({ purpose: "s37-linux-backend-identity-receipt-v02", ...body }), violations, "receipt-self-hash-mismatch");
  }

  const artifactHash = (name) => HASH.test(capture?.files?.[name]?.sha256 ?? "") ? capture.files[name].sha256 : null;
  add(receipt?.launcher_sha256 === artifactHash("supervisor"), violations, "supervisor-hash-mismatch");
  add(profile?.executable?.path === "/opt/loopeix/s37.1/probe" && profile?.executable?.sha256 === artifactHash("probe"), violations, "probe-hash-mismatch");
  add(receipt?.bwrap?.sha256 === artifactHash("bwrap"), violations, "bwrap-hash-mismatch");
  add(artifactHash("supervisor") === APPROVED_ARTIFACTS.supervisor, violations, "supervisor-provenance-unapproved");
  add(artifactHash("probe") === APPROVED_ARTIFACTS.probe, violations, "probe-provenance-unapproved");
  add(artifactHash("bwrap") === APPROVED_ARTIFACTS.bwrap, violations, "bwrap-provenance-unapproved");
  add(artifactHash("systemd_run") === APPROVED_ARTIFACTS.systemd_run, violations, "systemd-run-provenance-unapproved");
  add(artifactHash("systemctl") === APPROVED_ARTIFACTS.systemctl, violations, "systemctl-provenance-unapproved");
  add(receipt?.seccomp_policy_sha256 === APPROVED_ARTIFACTS.seccomp, violations, "seccomp-provenance-unapproved");
  validatePhaseBSealedInputs(phaseB, qualification, violations);

  const observedAt = Date.parse(tuple?.observed_at ?? "");
  const issuedAt = Date.parse(receipt?.issued_at ?? "");
  const expiresAt = Date.parse(receipt?.expires_at ?? "");
  add(Number.isFinite(observedAt) && Number.isFinite(issuedAt) && observedAt <= issuedAt, violations, "qualification-time-order-invalid");
  add(Number.isFinite(observedAt) && Number.isFinite(now)
    && now - observedAt >= 0 && now - observedAt <= S37_PHASE_D_MAX_TUPLE_AGE_MS,
  violations, "host-tuple-stale");
  add(Number.isFinite(issuedAt) && issuedAt <= now, violations, "receipt-not-yet-issued");
  add(Number.isFinite(issuedAt) && Number.isFinite(expiresAt)
    && expiresAt - issuedAt > 0 && expiresAt - issuedAt <= S37_PHASE_D_MAX_RECEIPT_LIFETIME_MS,
  violations, "receipt-lifetime-invalid");
  add(Number.isFinite(expiresAt) && now + S37_PHASE_D_MIN_AUTHORITY_MS <= expiresAt, violations, "receipt-window-insufficient");

  const machineId = capture?.files?.machine_id?.bytes instanceof Uint8Array
    ? Buffer.from(capture.files.machine_id.bytes).toString("utf8").trim()
    : "";
  add(machineId.length > 0, violations, "machine-id-empty");
  const unique = [...new Set(violations)].sort();
  if (unique.length > 0) return Object.freeze({ ok: false, terminal: "HOLD", violations: Object.freeze(unique) });

  const bindingWithoutHash = {
    schema_version: "s37-local-product-binding-v02",
    host_role: "local-product",
    transport: "local-only",
    host_identity_hash: hashBytes(Buffer.from(machineId, "utf8")),
    controller_uid: capture.controller_uid,
    conformance_tuple_hash: receipt.host_tuple_hash,
    backend_receipt_hash: receipt.receipt_hash,
    phase_b_manifest_sha256: phaseB.manifest.manifest_sha256,
    expires_at: receipt.expires_at,
    systemd_version: tuple.systemd_version,
    artifacts: {
      supervisor_sha256: artifactHash("supervisor"),
      probe_sha256: artifactHash("probe"),
      bwrap_sha256: artifactHash("bwrap"),
      bwrap_version: receipt.bwrap.version,
      systemd_run_sha256: artifactHash("systemd_run"),
      systemctl_sha256: artifactHash("systemctl"),
      seccomp_policy_sha256: receipt.seccomp_policy_sha256,
      cwd_identity_hash: profile.cwd.identity_hash,
    },
  };
  const binding = Object.freeze({
    ...bindingWithoutHash,
    binding_hash: hashCanonical({ purpose: "s37-local-product-binding-v02", ...bindingWithoutHash }),
  });
  return Object.freeze({ ok: true, terminal: "GO", binding });
}

export function buildS37PhaseDBindingInstallPlan(binding) {
  const bytes = Buffer.from(`${canonical(binding)}\n`, "utf8");
  return Object.freeze({
    destination: S37_PHASE_D_BINDING_PATH,
    bytes,
    sha256: hashBytes(bytes),
    uid: 0,
    gid: 0,
    mode: 0o444,
    overwrite: false,
  });
}
