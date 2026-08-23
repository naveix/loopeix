import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

import { formatViolations, runBoundaryCheck } from "./check-s37-boundaries.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "..");

const rejectedLiveFlags = new Set(["--live", "--vps", "--ssh"]);
const canonicalLinuxModules = [
  {
    file: "src/run/pre-spawn-capability-broker-v02.ts",
    requiredExports: [
      "S37LinuxBackendIdentityReceiptV02",
      "S37LinuxHostTupleV02",
      "S37LinuxProbeAdmissionV02",
      "consumeS37LinuxProbeAdmissionV02",
      "prepareS37LinuxProbeAdmissionV02",
    ],
    required: true,
  },
  {
    file: "src/run/linux-host-enforcement-v02.ts",
    requiredExports: ["runS37LinuxHostProbeV02", "runS37LocalLinuxProductProbeV02"],
    required: true,
  },
  {
    file: "src/run/bounded-linux-probe-v02.ts",
    requiredExports: ["S37LinuxProbeExecutionResultV02", "runBoundedS37LinuxProbeV02"],
    required: true,
  },
];

function createSourceFile(file, source) {
  return ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
}

function collectExports(sourceFile) {
  const exported = new Set();

  function addBindingName(name) {
    if (ts.isIdentifier(name)) {
      exported.add(name.text);
      return;
    }
    if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name)) {
      for (const element of name.elements) {
        if (ts.isBindingElement(element)) addBindingName(element.name);
      }
    }
  }

  function visit(node) {
    if (
      (ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node) || ts.isInterfaceDeclaration(node) ||
        ts.isTypeAliasDeclaration(node) || ts.isEnumDeclaration(node)) &&
      node.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) &&
      node.name !== undefined
    ) {
      exported.add(node.name.text);
    }

    if (ts.isVariableStatement(node) && node.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)) {
      for (const declaration of node.declarationList.declarations) addBindingName(declaration.name);
    }

    if (ts.isExportDeclaration(node) && node.exportClause !== undefined && ts.isNamedExports(node.exportClause)) {
      for (const element of node.exportClause.elements) exported.add(element.name.text);
    }

    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  return exported;
}

function checkCanonicalExports(rootDir) {
  const violations = [];

  for (const module of canonicalLinuxModules) {
    const file = resolve(rootDir, module.file);
    if (!existsSync(file)) {
      if (module.required) violations.push(`missing-canonical-linux-module: ${module.file}`);
      continue;
    }
    const exports = collectExports(createSourceFile(file, readFileSync(file, "utf8")));
    for (const name of module.requiredExports) {
      if (!exports.has(name)) violations.push(`missing-canonical-export:${name}: ${module.file}`);
    }
  }

  return violations;
}

function main() {
  const args = process.argv.slice(2);
  const liveFlag = args.find((arg) => rejectedLiveFlags.has(arg));
  if (liveFlag !== undefined) {
    process.stderr.write(`HOLD: ${liveFlag} is out of scope for the Phase A static gate\n`);
    process.stderr.write("live host conformance not executed\n");
    process.exit(1);
  }

  const boundary = runBoundaryCheck({ rootDir: repoRoot });
  const violations = [...boundary.violations, ...checkCanonicalExports(repoRoot)].sort();
  if (violations.length > 0) {
    process.stderr.write(`${formatViolations(violations)}\n`);
    process.stderr.write("HOLD: live host conformance not executed\n");
    process.exit(1);
  }

  process.stdout.write("S37.1 Phase A static gate: PASS\n");
  process.stdout.write("S37.1 Phase C static gate: PASS\n");
  process.stdout.write("live host conformance not executed\n");
}

main();
