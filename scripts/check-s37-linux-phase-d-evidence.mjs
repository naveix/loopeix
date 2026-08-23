import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, "..");
const CATALOG_PATH = resolve(SCRIPT_DIR, "s37-linux-phase-d/case-catalog.json");
const PHASE_B_CONFORMANCE_SCRIPT_PATH = resolve(SCRIPT_DIR, "check-s37-linux-phase-b-conformance-evidence.mjs");
const GIT_PATH = "/usr/bin/git";
const RAW_HASH = /^[a-f0-9]{64}$/u;
const CONTENT_HASH = /^sha256:[a-f0-9]{64}$/u;
const COMMIT_HASH = /^[a-f0-9]{40}$/u;
const LANES = Object.freeze(["live-sandbox", "linux-native", "deterministic-controller", "live-coexistence"]);
const REVIEWER_ROLES = Object.freeze([
  "linux-sandbox-security",
  "sre-coexistence",
  "code-boundary-correctness",
  "documentation-visual-truth",
]);
const CATALOG_SHA256 = "bce353ee4c5397cfd1516033a9235774b938d45180fbd9cf15eef752c62a0eaf";
const CASE_COUNT = 65;
const SUPERVISOR_SOURCE_SHA256 = "sha256:515c7fa5e6ba937e25f75b025c4b7d67f8b9354f40955e4a601506881b7c2835";
const PROBE_SOURCE_SHA256 = "sha256:0cb0abe0b45ad54a46a93ef3adec76bdd3e60824ac97e8e08756e103f5d74405";
const PHASE_B_SUPPORT_FILES = Object.freeze({
  manifest: "phase-b-manifest.json",
  readinessEvidence: "phase-b-readiness-evidence.json",
  readinessEnvelope: "phase-b-readiness-envelope.json",
  profile: "phase-b-profile.json",
  conformanceEvidence: "phase-b-conformance-evidence.json",
  receipt: "phase-b-receipt.json",
});
const CANONICAL_SOURCES = Object.freeze({
  controller_source_sha256: "src/run/linux-host-enforcement-v02.ts",
  broker_source_sha256: "src/run/pre-spawn-capability-broker-v02.ts",
  bounded_probe_source_sha256: "src/run/bounded-linux-probe-v02.ts",
  supervisor_source_sha256: "scripts/s37-linux-phase-b/supervisor.c",
  probe_source_sha256: "scripts/s37-linux-phase-b/probe.c",
});
let repositoryFactsCache = null;
const KEYS = Object.freeze({
  catalog: ["schema_version", "supervisor_source_sha256", "probe_source_sha256", "cases", "reviewer_roles", "catalog_sha256"],
  catalogCase: ["id", "lane", "requirement", "oracle"],
  evidence: ["schema_version", "created_at", "catalog_sha256", "bindings", "readiness", "cases", "observations", "cleanup", "reviewers", "evidence_sha256"],
  bindingPair: ["before", "after"],
  binding: ["repository_commit", "repository_tree_sha256", "controller_source_sha256", "broker_source_sha256", "bounded_probe_source_sha256", "phase_b_manifest_sha256", "phase_b_receipt_sha256", "supervisor_source_sha256", "probe_source_sha256", "bwrap_sha256", "seccomp_policy_sha256"],
  readiness: ["evidence_sha256", "envelope_sha256", "sample_count", "within_envelope", "fresh_at_start", "unchanged_through_end"],
  result: ["id", "lane", "oracle", "passed", "skipped", "witness_path", "witness_sha256"],
  observations: ["listening_ports_before", "listening_ports_after", "services_before", "services_after", "containers_before", "containers_after", "swap_used_before_bytes", "swap_used_after_bytes", "swap_growth_bytes", "incumbent_service_transition_count"],
  snapshot: ["count", "sha256"],
  cleanup: ["unit_absent", "process_absent", "mount_absent", "temp_absent", "journal_payload_absent", "file_absent"],
  reviewer: ["role", "reviewer_identity_hash", "reviewed_at", "verdict", "evidence_sha256", "verdict_sha256"],
});

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write("usage: node scripts/check-s37-linux-phase-d-evidence.mjs --evidence <path>\n");
  process.exit(64);
}

function cli() {
  const args = process.argv.slice(2);
  let evidencePath;
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (flag !== "--evidence") usage(`unknown argument: ${flag ?? "<missing>"}`);
    if (value === undefined || value.startsWith("--")) usage("--evidence requires a path");
    if (evidencePath !== undefined) usage("duplicate argument: --evidence");
    evidencePath = value;
  }
  if (evidencePath === undefined) usage("missing argument: --evidence");
  return evidencePath;
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

function digest(value, serializer = canonical) {
  return createHash("sha256").update(serializer(value), "utf8").digest("hex");
}

function contentHashForBytes(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
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

function looseRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value : null;
}

function text(value, label, violations) {
  if (typeof value !== "string" || value.length === 0) {
    violations.push(`${label}:missing-or-invalid`);
    return null;
  }
  return value;
}

function matches(value, pattern, label, violations) {
  const result = text(value, label, violations);
  if (result !== null && !pattern.test(result)) violations.push(`${label}:missing-or-invalid`);
  return result;
}

function bool(value, expected, label, violations) {
  if (typeof value !== "boolean") violations.push(`${label}:missing-or-invalid`);
  else if (value !== expected) violations.push(`${label}:expected-${String(expected)}`);
}

function integer(value, label, violations, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    violations.push(`${label}:missing-or-invalid`);
    return null;
  }
  return value;
}

function instant(value, label, violations) {
  const result = text(value, label, violations);
  if (result === null) return null;
  const parsed = Date.parse(result);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== result) violations.push(`${label}:missing-or-invalid`);
  return Number.isFinite(parsed) ? parsed : null;
}

function same(actual, expected, label, violations) {
  if (actual !== expected) violations.push(`${label}:mismatch`);
}

function sameValue(actual, expected, label, violations) {
  if (canonical(actual) !== canonical(expected)) violations.push(`${label}:mismatch`);
}

function selfHash(value, key, label, violations, serializer = canonical) {
  const supplied = matches(value?.[key], RAW_HASH, `${label}.${key}`, violations);
  if (value !== null && typeof value === "object" && supplied !== null) {
    const body = Object.fromEntries(Object.entries(value).filter(([name]) => name !== key));
    if (supplied !== digest(body, serializer)) violations.push(`${label}.${key}:mismatch`);
  }
}

function readSupportJson(baseDirectory, fileName, label, violations) {
  const path = resolve(baseDirectory, fileName);
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    violations.push(`phase_b_support.${label}:missing-or-unreadable`);
    return null;
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
    violations.push(`phase_b_support.${label}:file-custody-invalid`);
    return null;
  }
  try {
    return Object.freeze({
      path,
      json: JSON.parse(readFileSync(path, "utf8")),
    });
  } catch {
    violations.push(`phase_b_support.${label}:missing-or-unreadable`);
    return null;
  }
}

function readGitHeadCommit(repoRoot, violations) {
  const headPath = resolve(repoRoot, ".git", "HEAD");
  let head;
  try {
    head = readFileSync(headPath, "utf8").trim();
  } catch {
    violations.push("repository.commit:missing-or-unreadable");
    return null;
  }
  if (COMMIT_HASH.test(head)) return head;
  const refMatch = /^ref:\s+(.+)$/u.exec(head);
  if (refMatch === null) {
    violations.push("repository.commit:missing-or-invalid");
    return null;
  }
  const refPath = resolve(repoRoot, ".git", ...refMatch[1].split("/"));
  try {
    const ref = readFileSync(refPath, "utf8").trim();
    if (COMMIT_HASH.test(ref)) return ref;
  } catch {
    // Fall through to packed-refs.
  }
  try {
    const packed = readFileSync(resolve(repoRoot, ".git", "packed-refs"), "utf8").split(/\r?\n/u);
    for (const line of packed) {
      if (line.startsWith("#") || line.startsWith("^") || line.trim().length === 0) continue;
      const [hash, ref] = line.split(" ");
      if (ref === refMatch[1] && COMMIT_HASH.test(hash)) return hash;
    }
  } catch {
    // No packed refs available.
  }
  violations.push("repository.commit:missing-or-invalid");
  return null;
}

function trackedRepositoryFiles(repoRoot, violations) {
  const result = spawnSync(GIT_PATH, ["-C", repoRoot, "ls-files", "-z"], {
    cwd: repoRoot,
    encoding: "utf8",
    shell: false,
  });
  if (result.error !== undefined) {
    violations.push(`repository.tracked-files:spawn-failed:${result.error.message}`);
    return null;
  }
  if (result.status !== 0) {
    violations.push(`repository.tracked-files:nonzero-exit:${String(result.status)}`);
    return null;
  }
  return result.stdout
    .split("\0")
    .filter((entry) => entry.length > 0)
    .sort((left, right) => left.localeCompare(right));
}

function collectRepositoryFacts(repoRoot, violations) {
  if (repositoryFactsCache !== null) return repositoryFactsCache;
  const commit = readGitHeadCommit(repoRoot, violations);
  if (commit === null) return null;
  const sourceHashes = {};
  try {
    const trackedFiles = trackedRepositoryFiles(repoRoot, violations);
    if (trackedFiles === null) return null;
    for (const [key, relativePath] of Object.entries(CANONICAL_SOURCES)) {
      sourceHashes[key] = contentHashForBytes(readFileSync(resolve(repoRoot, relativePath)));
    }
    const entries = [];
    for (const normalizedPath of trackedFiles) {
      const absolutePath = resolve(repoRoot, normalizedPath);
      const stat = lstatSync(absolutePath);
      if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`repository-tree-invalid:${normalizedPath}`);
      const bytes = readFileSync(absolutePath);
      entries.push(Object.freeze({
        path: normalizedPath,
        type: "file",
        mode: stat.mode,
        size: bytes.byteLength,
        sha256: createHash("sha256").update(bytes).digest("hex"),
      }));
    }
    repositoryFactsCache = Object.freeze({
      commit,
      tree_sha256: `sha256:${createHash("sha256").update(JSON.stringify(entries)).digest("hex")}`,
      source_hashes: Object.freeze(sourceHashes),
    });
    return repositoryFactsCache;
  } catch (error) {
    violations.push(error instanceof Error ? error.message : "repository-tree-invalid");
    return null;
  }
}

function validateCatalog(catalog, violations) {
  const root = record(catalog, KEYS.catalog, "catalog", violations);
  if (root === null) return;
  same(root.schema_version, "s37-linux-phase-d-case-catalog-v1", "catalog.schema_version", violations);
  same(root.supervisor_source_sha256, SUPERVISOR_SOURCE_SHA256, "catalog.supervisor_source_sha256", violations);
  same(root.probe_source_sha256, PROBE_SOURCE_SHA256, "catalog.probe_source_sha256", violations);
  selfHash(root, "catalog_sha256", "catalog", violations);
  same(root.catalog_sha256, CATALOG_SHA256, "catalog.catalog_sha256:approved", violations);
  if (!Array.isArray(root.cases) || root.cases.length === 0) {
    violations.push("catalog.cases:missing-or-invalid");
  } else {
    same(root.cases.length, CASE_COUNT, "catalog.cases:closed-count", violations);
    const ids = new Set();
    root.cases.forEach((value, index) => {
      const entry = record(value, KEYS.catalogCase, `catalog.cases[${index}]`, violations);
      const id = text(entry?.id, `catalog.cases[${index}].id`, violations);
      if (id !== null && !/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(id)) violations.push(`catalog.cases[${index}].id:missing-or-invalid`);
      if (id !== null && ids.has(id)) violations.push(`catalog.cases[${index}].id:duplicate`);
      if (id !== null) ids.add(id);
      if (!LANES.includes(entry?.lane)) violations.push(`catalog.cases[${index}].lane:not-closed`);
      text(entry?.requirement, `catalog.cases[${index}].requirement`, violations);
      text(entry?.oracle, `catalog.cases[${index}].oracle`, violations);
    });
  }
  sameValue(root.reviewer_roles, REVIEWER_ROLES, "catalog.reviewer_roles", violations);
}

function validateSnapshot(value, label, violations) {
  const snapshot = record(value, KEYS.snapshot, label, violations);
  integer(snapshot?.count, `${label}.count`, violations);
  matches(snapshot?.sha256, RAW_HASH, `${label}.sha256`, violations);
}

function summarizePhaseBSupport(evidencePath, violations) {
  const baseDirectory = dirname(evidencePath);
  const manifest = readSupportJson(baseDirectory, PHASE_B_SUPPORT_FILES.manifest, "manifest", violations);
  const readinessEvidence = readSupportJson(baseDirectory, PHASE_B_SUPPORT_FILES.readinessEvidence, "readiness_evidence", violations);
  const readinessEnvelope = readSupportJson(baseDirectory, PHASE_B_SUPPORT_FILES.readinessEnvelope, "readiness_envelope", violations);
  const profile = readSupportJson(baseDirectory, PHASE_B_SUPPORT_FILES.profile, "profile", violations);
  const conformanceEvidence = readSupportJson(baseDirectory, PHASE_B_SUPPORT_FILES.conformanceEvidence, "conformance_evidence", violations);
  const receipt = readSupportJson(baseDirectory, PHASE_B_SUPPORT_FILES.receipt, "receipt", violations);
  if ([manifest, readinessEvidence, readinessEnvelope, profile, conformanceEvidence, receipt].some((value) => value === null)) {
    return null;
  }

  const manifestJson = manifest.json;
  const readinessEvidenceJson = readinessEvidence.json;
  const readinessEnvelopeJson = readinessEnvelope.json;
  const profileJson = profile.json;
  const conformanceEvidenceJson = conformanceEvidence.json;
  const receiptJson = receipt.json;

  const conformanceCheck = spawnSync(process.execPath, [
    PHASE_B_CONFORMANCE_SCRIPT_PATH,
    "--manifest", manifest.path,
    "--readiness-evidence", readinessEvidence.path,
    "--readiness-envelope", readinessEnvelope.path,
    "--profile", profile.path,
    "--evidence", conformanceEvidence.path,
    "--receipt", receipt.path,
  ], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    shell: false,
    timeout: 15_000,
    maxBuffer: 2 * 1024 * 1024,
  });
  if (conformanceCheck.error !== undefined) {
    violations.push(`phase_b_support.conformance_gate:spawn-failed:${conformanceCheck.error.message}`);
  } else {
    const stdout = conformanceCheck.stdout ?? "";
    const stderr = conformanceCheck.stderr ?? "";
    if (conformanceCheck.status !== 0 || !stdout.includes("S37.1-B conformance evidence gate: PASS")) {
      const holdLines = stderr
        .split(/\r?\n/u)
        .map((line) => line.trim())
        .filter((line) => line.startsWith("HOLD: "));
      if (holdLines.length > 0) {
        for (const line of holdLines) violations.push(`phase_b_support.conformance_gate:${line.slice("HOLD: ".length)}`);
      } else {
        violations.push(`phase_b_support.conformance_gate:non-pass:${String(conformanceCheck.status)}`);
      }
    }
  }

  same(manifestJson.schema_version, "s37-linux-phase-b-build-manifest-v1", "phase_b_support.manifest.schema_version", violations);
  selfHash(manifestJson, "manifest_sha256", "phase_b_support.manifest", violations);
  same(readinessEvidenceJson.schema_version, "s37-linux-phase-b-readiness-evidence-v1", "phase_b_support.readiness_evidence.schema_version", violations);
  selfHash(readinessEvidenceJson, "evidence_sha256", "phase_b_support.readiness_evidence", violations, readinessCanonical);
  same(readinessEnvelopeJson.schema_version, "s37-linux-phase-b-readiness-envelope-v1", "phase_b_support.readiness_envelope.schema_version", violations);
  selfHash(readinessEnvelopeJson, "envelope_sha256", "phase_b_support.readiness_envelope", violations, readinessCanonical);
  same(conformanceEvidenceJson.schema_version, "s37-linux-phase-b-conformance-evidence-v1", "phase_b_support.conformance_evidence.schema_version", violations);
  selfHash(conformanceEvidenceJson, "evidence_sha256", "phase_b_support.conformance_evidence", violations);
  same(receiptJson.receipt_version, "0.1", "phase_b_support.receipt.receipt_version", violations);
  const receiptHashBody = Object.fromEntries(Object.entries(receiptJson).filter(([key]) => key !== "receipt_hash"));
  same(receiptJson.receipt_hash, `sha256:${digest({ purpose: "s37-linux-backend-identity-receipt-v02", ...receiptHashBody })}`, "phase_b_support.receipt.receipt_hash", violations);

  same(conformanceEvidenceJson.manifest_sha256, manifestJson.manifest_sha256, "phase_b_support.binding.manifest", violations);
  same(conformanceEvidenceJson.readiness_evidence_sha256, readinessEvidenceJson.evidence_sha256, "phase_b_support.binding.readiness_evidence", violations);
  same(conformanceEvidenceJson.readiness_envelope_sha256, readinessEnvelopeJson.envelope_sha256, "phase_b_support.binding.readiness_envelope", violations);
  same(conformanceEvidenceJson.receipt_hash, receiptJson.receipt_hash, "phase_b_support.binding.receipt", violations);
  same(conformanceEvidenceJson.capacity?.envelope_sha256, readinessEnvelopeJson.envelope_sha256, "phase_b_support.binding.capacity_envelope", violations);

  const samples = Array.isArray(readinessEvidenceJson.capacity_samples) ? readinessEvidenceJson.capacity_samples : null;
  if (samples === null) violations.push("phase_b_support.readiness_evidence.capacity_samples:missing-or-invalid");
  const sampleCount = samples?.length ?? null;
  if (sampleCount === null) {
    violations.push("phase_b_support.readiness.sample_count:missing-or-invalid");
  }
  if (samples !== null) {
    same(conformanceEvidenceJson.capacity?.samples_sha256, digest(samples), "phase_b_support.binding.capacity_samples", violations);
  }

  bool(conformanceEvidenceJson.capacity?.within_envelope, true, "phase_b_support.conformance_evidence.capacity.within_envelope", violations);
  same(conformanceEvidenceJson.capacity?.swap_growth_bytes, 0, "phase_b_support.conformance_evidence.capacity.swap_growth_bytes", violations);
  same(conformanceEvidenceJson.ports?.delta, 0, "phase_b_support.conformance_evidence.ports.delta", violations);
  sameValue(conformanceEvidenceJson.ports?.after, conformanceEvidenceJson.ports?.before, "phase_b_support.conformance_evidence.ports.zero_delta", violations);
  sameValue(conformanceEvidenceJson.neighbors?.services_after, conformanceEvidenceJson.neighbors?.services_before, "phase_b_support.conformance_evidence.neighbors.services_zero_delta", violations);
  sameValue(conformanceEvidenceJson.neighbors?.containers_after, conformanceEvidenceJson.neighbors?.containers_before, "phase_b_support.conformance_evidence.neighbors.containers_zero_delta", violations);
  for (const key of KEYS.cleanup) bool(conformanceEvidenceJson.cleanup?.[key], true, `phase_b_support.conformance_evidence.cleanup.${key}`, violations);

  const readyObserved = instant(readinessEvidenceJson.observed_at, "phase_b_support.readiness_evidence.observed_at", violations);
  const hostObserved = instant(conformanceEvidenceJson.host_tuple?.observed_at, "phase_b_support.conformance_evidence.host_tuple.observed_at", violations);
  const sampleIntervalSeconds = integer(readinessEnvelopeJson.sample_interval_seconds, "phase_b_support.readiness_envelope.sample_interval_seconds", violations, 1);
  const freshAtStart = readyObserved !== null
    && hostObserved !== null
    && sampleIntervalSeconds !== null
    && readyObserved <= hostObserved
    && hostObserved - readyObserved <= sampleIntervalSeconds * 1_000;
  if (!freshAtStart) violations.push("phase_b_support.readiness.fresh_at_start:missing-or-invalid");

  const unchangedThroughEnd = conformanceEvidenceJson.ports?.delta === 0
    && canonical(conformanceEvidenceJson.ports?.before) === canonical(conformanceEvidenceJson.ports?.after)
    && canonical(conformanceEvidenceJson.neighbors?.services_before) === canonical(conformanceEvidenceJson.neighbors?.services_after)
    && canonical(conformanceEvidenceJson.neighbors?.containers_before) === canonical(conformanceEvidenceJson.neighbors?.containers_after)
    && KEYS.cleanup.every((key) => conformanceEvidenceJson.cleanup?.[key] === true);
  if (!unchangedThroughEnd) violations.push("phase_b_support.readiness.unchanged_through_end:missing-or-invalid");

  return Object.freeze({
    manifest: manifestJson,
    readiness_evidence: readinessEvidenceJson,
    readiness_envelope: readinessEnvelopeJson,
    profile: profileJson,
    conformance_evidence: conformanceEvidenceJson,
    receipt: receiptJson,
    summary: Object.freeze({
      evidence_sha256: readinessEvidenceJson.evidence_sha256,
      envelope_sha256: readinessEnvelopeJson.envelope_sha256,
      sample_count: sampleCount,
      within_envelope: conformanceEvidenceJson.capacity?.within_envelope === true,
      fresh_at_start: freshAtStart,
      unchanged_through_end: unchangedThroughEnd,
    }),
  });
}

function validateBinding(value, label, catalog, repository, phaseB, violations) {
  const binding = record(value, KEYS.binding, label, violations);
  matches(binding?.repository_commit, COMMIT_HASH, `${label}.repository_commit`, violations);
  for (const key of ["repository_tree_sha256", "controller_source_sha256", "broker_source_sha256", "bounded_probe_source_sha256", "phase_b_receipt_sha256", "supervisor_source_sha256", "probe_source_sha256", "bwrap_sha256", "seccomp_policy_sha256"]) {
    matches(binding?.[key], CONTENT_HASH, `${label}.${key}`, violations);
  }
  matches(binding?.phase_b_manifest_sha256, RAW_HASH, `${label}.phase_b_manifest_sha256`, violations);
  same(binding?.supervisor_source_sha256, catalog?.supervisor_source_sha256, `${label}.supervisor_source_sha256`, violations);
  same(binding?.probe_source_sha256, catalog?.probe_source_sha256, `${label}.probe_source_sha256`, violations);
  if (repository !== null) {
    same(binding?.repository_commit, repository.commit, `${label}.repository_commit:canonical`, violations);
    same(binding?.repository_tree_sha256, repository.tree_sha256, `${label}.repository_tree_sha256:canonical`, violations);
    for (const key of ["controller_source_sha256", "broker_source_sha256", "bounded_probe_source_sha256", "supervisor_source_sha256", "probe_source_sha256"]) {
      same(binding?.[key], repository.source_hashes[key], `${label}.${key}:canonical`, violations);
    }
  }
  if (phaseB !== null) {
    same(binding?.phase_b_manifest_sha256, phaseB.manifest.manifest_sha256, `${label}.phase_b_manifest_sha256:canonical`, violations);
    same(binding?.phase_b_receipt_sha256, phaseB.receipt.receipt_hash, `${label}.phase_b_receipt_sha256:canonical`, violations);
    same(binding?.bwrap_sha256, phaseB.manifest.bwrap?.sha256, `${label}.bwrap_sha256:manifest`, violations);
    same(binding?.bwrap_sha256, phaseB.receipt.bwrap?.sha256, `${label}.bwrap_sha256:receipt`, violations);
    same(binding?.seccomp_policy_sha256, phaseB.manifest.seccomp_policy_sha256, `${label}.seccomp_policy_sha256:manifest`, violations);
    same(binding?.seccomp_policy_sha256, phaseB.receipt.seccomp_policy_sha256, `${label}.seccomp_policy_sha256:receipt`, violations);
  }
}

function validateEvidence(evidence, catalog, evidencePath, repository, phaseB, violations) {
  const root = record(evidence, KEYS.evidence, "evidence", violations);
  if (root === null) return;
  same(root.schema_version, "s37-linux-phase-d-evidence-v1", "evidence.schema_version", violations);
  instant(root.created_at, "evidence.created_at", violations);
  selfHash(root, "evidence_sha256", "evidence", violations);
  const catalogCases = Array.isArray(catalog?.cases) ? catalog.cases : [];
  same(root.catalog_sha256, catalog?.catalog_sha256, "evidence.catalog_sha256", violations);

  const bindings = record(root.bindings, KEYS.bindingPair, "evidence.bindings", violations);
  validateBinding(bindings?.before, "evidence.bindings.before", catalog, repository, phaseB, violations);
  validateBinding(bindings?.after, "evidence.bindings.after", catalog, repository, phaseB, violations);
  sameValue(bindings?.after, bindings?.before, "evidence.bindings.unchanged", violations);

  const readiness = record(root.readiness, KEYS.readiness, "evidence.readiness", violations);
  matches(readiness?.evidence_sha256, RAW_HASH, "evidence.readiness.evidence_sha256", violations);
  matches(readiness?.envelope_sha256, RAW_HASH, "evidence.readiness.envelope_sha256", violations);
  same(readiness?.sample_count, 5, "evidence.readiness.sample_count", violations);
  bool(readiness?.within_envelope, true, "evidence.readiness.within_envelope", violations);
  bool(readiness?.fresh_at_start, true, "evidence.readiness.fresh_at_start", violations);
  bool(readiness?.unchanged_through_end, true, "evidence.readiness.unchanged_through_end", violations);
  if (phaseB !== null) {
    same(readiness?.evidence_sha256, phaseB.summary.evidence_sha256, "evidence.readiness.evidence_sha256:phase-b-support", violations);
    same(readiness?.envelope_sha256, phaseB.summary.envelope_sha256, "evidence.readiness.envelope_sha256:phase-b-support", violations);
    same(readiness?.sample_count, phaseB.summary.sample_count, "evidence.readiness.sample_count:phase-b-support", violations);
    same(readiness?.within_envelope, phaseB.summary.within_envelope, "evidence.readiness.within_envelope:phase-b-support", violations);
    same(readiness?.fresh_at_start, phaseB.summary.fresh_at_start, "evidence.readiness.fresh_at_start:phase-b-support", violations);
    same(readiness?.unchanged_through_end, phaseB.summary.unchanged_through_end, "evidence.readiness.unchanged_through_end:phase-b-support", violations);
  }

  if (!Array.isArray(root.cases)) {
    violations.push("evidence.cases:missing-or-invalid");
  } else {
    if (root.cases.length !== catalogCases.length) violations.push("evidence.cases:wrong-length");
    const ids = new Set();
    root.cases.forEach((value, index) => {
      const result = record(value, KEYS.result, `evidence.cases[${index}]`, violations);
      const catalogCase = catalogCases[index];
      const id = text(result?.id, `evidence.cases[${index}].id`, violations);
      if (id !== null && ids.has(id)) violations.push(`evidence.cases[${index}].id:duplicate`);
      if (id !== null) ids.add(id);
      if (catalogCase === undefined) return;
      same(result?.id, catalogCase.id, `evidence.cases[${index}].id`, violations);
      same(result?.lane, catalogCase.lane, `evidence.cases[${index}].lane`, violations);
      same(result?.oracle, catalogCase.oracle, `evidence.cases[${index}].oracle`, violations);
      bool(result?.passed, true, `evidence.cases[${index}].passed`, violations);
      bool(result?.skipped, false, `evidence.cases[${index}].skipped`, violations);
      const expectedWitnessPath = `witnesses/${catalogCase.id}.json`;
      same(result?.witness_path, expectedWitnessPath, `evidence.cases[${index}].witness_path`, violations);
      const witnessSha256 = matches(result?.witness_sha256, RAW_HASH, `evidence.cases[${index}].witness_sha256`, violations);
      if (result?.witness_path === expectedWitnessPath && witnessSha256 !== null) {
        const absoluteWitnessPath = resolve(dirname(evidencePath), expectedWitnessPath);
        try {
          const stat = lstatSync(absoluteWitnessPath);
          if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
            violations.push(`evidence.cases[${index}].witness:file-custody-invalid`);
          } else {
            const actual = createHash("sha256").update(readFileSync(absoluteWitnessPath)).digest("hex");
            same(actual, witnessSha256, `evidence.cases[${index}].witness_sha256:file`, violations);
          }
        } catch {
          violations.push(`evidence.cases[${index}].witness:missing-or-unreadable`);
        }
      }
    });
    try {
      const witnessDirectory = resolve(dirname(evidencePath), "witnesses");
      const witnessDirectoryStat = lstatSync(witnessDirectory);
      if (!witnessDirectoryStat.isDirectory() || witnessDirectoryStat.isSymbolicLink()) {
        violations.push("evidence.witnesses:directory-custody-invalid");
      }
      const actualWitnessFiles = readdirSync(witnessDirectory).sort();
      const expectedWitnessFiles = catalogCases.map((entry) => `${entry.id}.json`).sort();
      sameValue(actualWitnessFiles, expectedWitnessFiles, "evidence.witnesses:closed-file-set", violations);
    } catch {
      violations.push("evidence.witnesses:directory-missing-or-unreadable");
    }
  }

  const observations = record(root.observations, KEYS.observations, "evidence.observations", violations);
  for (const key of ["listening_ports_before", "listening_ports_after", "services_before", "services_after", "containers_before", "containers_after"]) {
    validateSnapshot(observations?.[key], `evidence.observations.${key}`, violations);
  }
  for (const pair of [["listening_ports_before", "listening_ports_after"], ["services_before", "services_after"], ["containers_before", "containers_after"]]) {
    sameValue(observations?.[pair[0]], observations?.[pair[1]], `evidence.observations.${pair[0]}-zero-delta`, violations);
  }
  const swapBefore = integer(observations?.swap_used_before_bytes, "evidence.observations.swap_used_before_bytes", violations);
  const swapAfter = integer(observations?.swap_used_after_bytes, "evidence.observations.swap_used_after_bytes", violations);
  same(observations?.swap_growth_bytes, 0, "evidence.observations.swap_growth_bytes", violations);
  if (swapBefore !== null && swapAfter !== null) same(swapAfter, swapBefore, "evidence.observations.swap-zero-growth", violations);
  same(observations?.incumbent_service_transition_count, 0, "evidence.observations.incumbent_service_transition_count", violations);

  const cleanup = record(root.cleanup, KEYS.cleanup, "evidence.cleanup", violations);
  for (const key of KEYS.cleanup) bool(cleanup?.[key], true, `evidence.cleanup.${key}`, violations);

  const reviewSubjectSha256 = digest(Object.fromEntries(
    Object.entries(root).filter(([key]) => key !== "reviewers" && key !== "evidence_sha256"),
  ));
  if (!Array.isArray(root.reviewers) || root.reviewers.length !== REVIEWER_ROLES.length) {
    violations.push("evidence.reviewers:wrong-length");
  } else {
    const reviewerIdentities = new Set();
    root.reviewers.forEach((value, index) => {
      const reviewer = record(value, KEYS.reviewer, `evidence.reviewers[${index}]`, violations);
      same(reviewer?.role, REVIEWER_ROLES[index], `evidence.reviewers[${index}].role`, violations);
      matches(reviewer?.reviewer_identity_hash, CONTENT_HASH, `evidence.reviewers[${index}].reviewer_identity_hash`, violations);
      if (reviewerIdentities.has(reviewer?.reviewer_identity_hash)) {
        violations.push(`evidence.reviewers[${index}].reviewer_identity_hash:duplicate`);
      }
      reviewerIdentities.add(reviewer?.reviewer_identity_hash);
      instant(reviewer?.reviewed_at, `evidence.reviewers[${index}].reviewed_at`, violations);
      const createdAt = Date.parse(root.created_at ?? "");
      const reviewedAt = Date.parse(reviewer?.reviewed_at ?? "");
      if (!Number.isFinite(createdAt) || !Number.isFinite(reviewedAt) || reviewedAt < createdAt) {
        violations.push(`evidence.reviewers[${index}].reviewed_at:not-last`);
      }
      same(reviewer?.verdict, "SHIP_IT", `evidence.reviewers[${index}].verdict`, violations);
      matches(reviewer?.evidence_sha256, RAW_HASH, `evidence.reviewers[${index}].evidence_sha256`, violations);
      same(reviewer?.evidence_sha256, reviewSubjectSha256, `evidence.reviewers[${index}].evidence_sha256:review-subject`, violations);
      const expectedVerdictSha256 = digest({
        purpose: "s37-linux-phase-d-review-verdict-v1",
        role: reviewer?.role,
        reviewer_identity_hash: reviewer?.reviewer_identity_hash,
        reviewed_at: reviewer?.reviewed_at,
        verdict: reviewer?.verdict,
        evidence_sha256: reviewer?.evidence_sha256,
      });
      same(reviewer?.verdict_sha256, expectedVerdictSha256, `evidence.reviewers[${index}].verdict_sha256`, violations);
    });
  }
}

const violations = [];
const catalog = readJson(CATALOG_PATH, "catalog");
const evidencePath = resolve(cli());
const evidence = readJson(evidencePath, "evidence");
const repository = collectRepositoryFacts(REPO_ROOT, violations);
const phaseB = summarizePhaseBSupport(evidencePath, violations);
validateCatalog(catalog, violations);
validateEvidence(evidence, catalog, evidencePath, repository, phaseB, violations);

if (violations.length > 0) {
  const unique = [...new Set(violations)].sort((left, right) => left.localeCompare(right));
  process.stderr.write(`${unique.map((entry) => `HOLD: ${entry}`).join("\n")}\n`);
  process.exit(1);
}

process.stdout.write("S37.1-D evidence gate: PASS\nsealed evidence only; no live host action performed\n");
