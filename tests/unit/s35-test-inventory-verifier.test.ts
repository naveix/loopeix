import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  REQUIRED_TEST_PATHS,
  inventoryEvidenceFailures,
} from "../../scripts/verify-s35-test-inventory.mjs";

const roots: string[] = [];
const verifierPath = fileURLToPath(new URL("../../scripts/verify-s35-test-inventory.mjs", import.meta.url));

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function passingReport() {
  return {
    success: true,
    numFailedTestSuites: 0,
    numFailedTests: 0,
    numPendingTests: 0,
    numTodoTests: 0,
    testResults: REQUIRED_TEST_PATHS.map((path) => ({
      name: join(process.cwd(), path),
      status: "passed",
      assertionResults: [{ status: "passed", failureMessages: [] }],
    })),
  };
}

describe("S35 test inventory report verification", () => {
  it.each([
    "tests/unit/s37-product-host-activation-contract-v01.test.ts",
    "tests/unit/s37-product-host-activation-store-v01.test.ts",
    "tests/unit/s37-product-host-activation-v01.test.ts",
    "tests/unit/s37-product-host-launch-broker-v01.test.ts",
    "tests/integration/s37-product-host-activation-process.test.ts",
    "tests/integration/s37-linux-product-host-v03-tooling.test.ts",
  ])("requires nonempty passing activation evidence for %s", (path) => {
    const report = passingReport();
    report.testResults = report.testResults.filter((result) => result.name !== join(process.cwd(), path));
    expect(inventoryEvidenceFailures(report)).toContain(`${path} (absent from Vitest JSON)`);

    const result: {
      name: string;
      status: string;
      assertionResults: Array<{ status: string; failureMessages: string[] }>;
    } = { name: join(process.cwd(), path), status: "passed", assertionResults: [] };
    report.testResults.push(result);
    expect(inventoryEvidenceFailures(report)).toContain(`${path} (no executed assertions)`);

    result.assertionResults = [{ status: "skipped", failureMessages: [] }];
    expect(inventoryEvidenceFailures(report)).toContain(`${path} (non-passing assertion status)`);

    result.assertionResults = [{ status: "passed", failureMessages: [] }];
    expect(inventoryEvidenceFailures(report)).toEqual([]);
  });

  it("accepts complete passing full-suite evidence", () => {
    expect(inventoryEvidenceFailures(passingReport())).toEqual([]);
  });

  it("rejects duplicate and absent required paths", () => {
    const duplicate = passingReport();
    duplicate.testResults.push(duplicate.testResults[0]!);
    expect(inventoryEvidenceFailures(duplicate)).toContain(
      `${REQUIRED_TEST_PATHS[0]} (reported more than once)`,
    );

    const absent = passingReport();
    absent.testResults.shift();
    expect(inventoryEvidenceFailures(absent)).toContain(
      `${REQUIRED_TEST_PATHS[0]} (absent from Vitest JSON)`,
    );
  });

  it("rejects unsuccessful, empty, failed, and skipped evidence", () => {
    const report = passingReport();
    report.success = false;
    report.numFailedTests = 1;
    report.testResults[0]!.status = "failed";
    report.testResults[0]!.assertionResults = [];
    report.testResults[1]!.assertionResults[0]!.status = "skipped";

    expect(inventoryEvidenceFailures(report)).toEqual(expect.arrayContaining([
      "Vitest did not report a successful complete suite",
      `${REQUIRED_TEST_PATHS[0]} (no executed assertions)`,
      `${REQUIRED_TEST_PATHS[0]} (did not finish with a passing assertion)`,
      `${REQUIRED_TEST_PATHS[1]} (non-passing assertion status)`,
    ]));
  });

  it("fails closed on missing, relative, symlinked, and malformed report paths", () => {
    expect(spawnSync(process.execPath, [verifierPath], { encoding: "utf8" })).toMatchObject({ status: 1 });
    expect(spawnSync(process.execPath, [verifierPath, "relative.json"], { encoding: "utf8" })).toMatchObject({ status: 1 });

    const root = mkdtempSync(join(tmpdir(), "loopeix-s35-inventory-verifier-"));
    roots.push(root);
    const malformedPath = join(root, "malformed.json");
    const symlinkPath = join(root, "report-link.json");
    writeFileSync(malformedPath, "not-json\n");
    symlinkSync(malformedPath, symlinkPath);
    expect(spawnSync(process.execPath, [verifierPath, symlinkPath], { encoding: "utf8" })).toMatchObject({ status: 1 });
    expect(spawnSync(process.execPath, [verifierPath, malformedPath], { encoding: "utf8" })).toMatchObject({ status: 1 });
  });

  it("accepts a complete passing report through the CLI", () => {
    const root = mkdtempSync(join(tmpdir(), "loopeix-s35-inventory-verifier-"));
    roots.push(root);
    const reportPath = join(root, "report.json");
    writeFileSync(reportPath, `${JSON.stringify(passingReport())}\n`);
    const result = spawnSync(process.execPath, [verifierPath, reportPath], { encoding: "utf8" });
    expect(result).toMatchObject({ status: 0 });
    expect(result.stdout).toContain(`S35 test inventory verified: ${REQUIRED_TEST_PATHS.length} files.`);
  });
});
