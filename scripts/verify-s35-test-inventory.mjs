import { lstatSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const REQUIRED_TEST_PATHS = Object.freeze([
  "tests/unit/spec-validation.test.ts",
  "tests/unit/json-schema.test.ts",
  "tests/unit/compiler-compile.test.ts",
  "tests/unit/compiler-pack.test.ts",
  "tests/unit/run-plan.test.ts",
  "tests/unit/run-preflight.test.ts",
  "tests/unit/run-prompt.test.ts",
  "tests/unit/schema-version-dispatch-s35.test.ts",
  "tests/unit/schema-v02-invariants-s35.test.ts",
  "tests/unit/schema-migration-s35.test.ts",
  "tests/unit/migration-canonicalization-s35.test.ts",
  "tests/unit/schema-raw-hash-s35.test.ts",
  "tests/unit/captured-file-s35.test.ts",
  "tests/unit/io-helper-identity-s35.test.ts",
  "tests/unit/output-capabilities-s35.test.ts",
  "tests/unit/legacy-file-compatibility-s35.test.ts",
  "tests/unit/spec-commands-version-s35.test.ts",
  "tests/unit/spec-inspect-v02-s35.test.ts",
  "tests/unit/v02-planned-directory-classifier-s35.test.ts",
  "tests/unit/compiler-replay-v01-s35.test.ts",
  "tests/unit/legacy-pack-compatibility-s35.test.ts",
  "tests/unit/compiler-pack-envelope-s35.test.ts",
  "tests/unit/compiler-v02-projection-s35.test.ts",
  "tests/unit/compile-command-v02-s35.test.ts",
  "tests/unit/spec-new-from-prompt-s35.test.ts",
  "tests/unit/compiler-writer-s35.test.ts",
  "tests/unit/compile-id-allocation-s35.test.ts",
  "tests/unit/plan-id-allocation-s35.test.ts",
  "tests/unit/authority-planning-input-v02-s35.test.ts",
  "tests/unit/repository-observation-v02-s35.test.ts",
  "tests/unit/writer-durability-s35.test.ts",
  "tests/unit/compile-store-s35.test.ts",
  "tests/unit/init-compile-store-s35.test.ts",
  "tests/unit/credential-detector-s35.test.ts",
  "tests/unit/runtime-events-v02-s35.test.ts",
  "tests/unit/runtime-schema-inventory-s35.test.ts",
  "tests/unit/evidence-lineage-s35.test.ts",
  "tests/unit/gate-evidence-waiver-s35.test.ts",
  "tests/unit/administrative-custody-s35.test.ts",
  "tests/unit/progress-evaluator-s35.test.ts",
  "tests/unit/terminal-snapshot-s35.test.ts",
  "tests/unit/terminal-evaluator-s35.test.ts",
  "tests/unit/action-admission-quiescence-s35.test.ts",
  "tests/unit/action-classifier-policy-v02-s35.test.ts",
  "tests/unit/compensation-phase-s35.test.ts",
  "tests/unit/compensation-settlement-s35.test.ts",
  "tests/unit/terminal-seal-fence-s35.test.ts",
  "tests/unit/control-plane-budget-s35.test.ts",
  "tests/unit/run-plan-v02-s35.test.ts",
  "tests/unit/run-preflight-v02-s35.test.ts",
  "tests/unit/run-prompt-v02-s35.test.ts",
  "tests/unit/run-start-v02-hold-s35.test.ts",
  "tests/unit/run-status-v02-s35.test.ts",
  "tests/unit/run-recover-v02-s35.test.ts",
  "tests/unit/report-plan-v02-s35.test.ts",
  "tests/unit/report-open-s35.test.ts",
  "tests/unit/doctor-schemas-s35.test.ts",
  "tests/unit/verify-legacy-policy-s35.test.ts",
  "tests/unit/pr-legacy-policy-s35.test.ts",
  "tests/unit/command-inventory-s35.test.ts",
  "tests/integration/s35-v01-fixture-compat.test.ts",
  "tests/integration/s35-schema-package.test.ts",
  "tests/integration/s35-cross-lane-projection.test.ts",
  "tests/integration/s35-secret-scan.test.ts",
]);

function fail(reason, details) {
  process.stderr.write(`S35 test inventory failed: ${reason}\n`);
  for (const detail of details) process.stderr.write(`- ${detail}\n`);
  process.exit(1);
}

function normalizedResultPath(name) {
  const absolute = resolve(REPOSITORY_ROOT, name);
  return relative(REPOSITORY_ROOT, absolute).split("\\").join("/");
}

export function inventoryEvidenceFailures(report) {
  const failures = [];
  if (report?.success !== true
    || report?.numFailedTestSuites !== 0
    || report?.numFailedTests !== 0
    || report?.numPendingTests !== 0
    || report?.numTodoTests !== 0) {
    failures.push("Vitest did not report a successful complete suite");
  }

  const results = Array.isArray(report?.testResults) ? report.testResults : [];
  const byPath = new Map();
  for (const result of results) {
    if (typeof result?.name !== "string") continue;
    const path = normalizedResultPath(result.name);
    if (byPath.has(path)) failures.push(`${path} (reported more than once)`);
    else byPath.set(path, result);
  }

  for (const path of REQUIRED_TEST_PATHS) {
    const result = byPath.get(path);
    if (result === undefined) {
      failures.push(`${path} (absent from Vitest JSON)`);
      continue;
    }
    const assertions = Array.isArray(result.assertionResults) ? result.assertionResults : [];
    const statuses = assertions.map((assertion) => assertion?.status);
    if (assertions.length === 0) failures.push(`${path} (no executed assertions)`);
    if (statuses.some((status) => status !== "passed")) {
      failures.push(`${path} (non-passing assertion status)`);
    }
    if (result.status !== "passed" || !statuses.includes("passed")) {
      failures.push(`${path} (did not finish with a passing assertion)`);
      for (const assertion of assertions) {
        const messages = Array.isArray(assertion?.failureMessages) ? assertion.failureMessages : [];
        for (const message of messages) {
          if (typeof message === "string" && message.trim().length > 0) {
            failures.push(`${path}: ${message.trim()}`);
          }
        }
      }
    }
  }
  return failures;
}

function main(args) {
  if (args.length !== 1 || !isAbsolute(args[0])) {
    fail("expected exactly one absolute Vitest JSON report path", []);
  }

  const duplicates = REQUIRED_TEST_PATHS.filter((path, index) => REQUIRED_TEST_PATHS.indexOf(path) !== index);
  if (duplicates.length > 0) fail("duplicate required paths", [...new Set(duplicates)].sort());

  const missing = [];
  const disabled = [];
  for (const path of REQUIRED_TEST_PATHS) {
    const absolutePath = resolve(REPOSITORY_ROOT, path);
    try {
      const metadata = lstatSync(absolutePath);
      if (!metadata.isFile() || metadata.isSymbolicLink()) {
        missing.push(`${path} (must be a regular non-symlink file)`);
        continue;
      }
    } catch {
      missing.push(path);
      continue;
    }
    const source = readFileSync(absolutePath, "utf8");
    const forbidden = [
      [/(?:^|[^\w])(?:describe|it|test)\s*\.\s*(?:only|skip|todo)\s*\(/m, "disabled or exclusive test modifier"],
      [/(?:^|[^\w])x(?:describe|it|test)\s*\(/m, "disabled x-prefixed test declaration"],
    ];
    for (const [pattern, label] of forbidden) {
      if (pattern.test(source)) disabled.push(`${path} (${label})`);
    }
  }
  if (missing.length > 0) fail("required test files are missing", missing.sort());
  if (disabled.length > 0) fail("required test files contain disabled or exclusive tests", disabled.sort());

  const reportPath = args[0];
  let reportBytes;
  try {
    const reportMetadata = lstatSync(reportPath);
    if (!reportMetadata.isFile() || reportMetadata.isSymbolicLink()) {
      throw new Error("Vitest report path is not a regular non-symlink file");
    }
    reportBytes = readFileSync(reportPath, "utf8");
  } catch (error) {
    fail("could not read the Vitest JSON report", [error instanceof Error ? error.message : String(error)]);
  }

  let report;
  try {
    report = JSON.parse(reportBytes);
  } catch {
    fail("Vitest did not write valid JSON", []);
  }
  const evidenceFailures = inventoryEvidenceFailures(report);
  if (evidenceFailures.length > 0) fail("Vitest execution evidence is incomplete", evidenceFailures);
  process.stdout.write(`S35 test inventory verified: ${REQUIRED_TEST_PATHS.length} files.\n`);
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2));
}
