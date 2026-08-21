import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "..");

const defaultFiles = [
  "src/run/pre-spawn-capability-broker-v02.ts",
  "src/run/engine.ts",
];

const brokerFile = "src/run/pre-spawn-capability-broker-v02.ts";
const engineFile = "src/run/engine.ts";
const packageRootFile = "src/index.ts";
const boundedLauncherImporter = "src/run/linux-host-enforcement-v02.ts";
const boundedLauncherModule = "./bounded-linux-probe-v02.js";
const linuxModuleSpecifiers = new Set([
  "./linux-host-enforcement-v02.js",
  "./bounded-linux-probe-v02.js",
]);
const linuxCommandNeedles = [/^ssh$/u, /^scp$/u, /^sftp$/u, /^systemd-run$/u, /^bwrap$/u, /^bubblewrap$/u];
const linuxImportNeedles = [/ssh/u, /systemd-run/u, /\bbwrap\b/u, /bubblewrap/u, /\bremote\b/u];
const forbiddenPackageRootExports = new Set([
  "S37AdapterCapabilityRowV02",
  "S37ActionInterpositionProfileV02",
  "S37PreSpawnHoldReasonV02",
  "S37PreSpawnProbeRequestV02",
  "S37PreSpawnProbeResultV02",
  "S37_ADAPTER_CAPABILITY_MATRIX_V02",
  "buildS37ActionInterpositionProfileV02",
  "consumeS37LinuxProbeAdmissionV02",
  "enforceS37PreSpawnProbeV02",
  "prepareS37LinuxProbeAdmissionV02",
  "prohibitS37GeneralAgentSpawnV02",
  "S37LinuxBackendIdentityReceiptV02",
  "S37LinuxHostTupleV02",
  "S37LinuxProbeAdmissionV02",
]);
const newLinuxModules = [
  "src/run/linux-host-enforcement-v02.ts",
  "src/run/bounded-linux-probe-v02.ts",
];

const forbiddenModules = new Map([
  ["child_process", "child-process-module"],
  ["fs", "filesystem-module"],
  ["fs/promises", "filesystem-module"],
  ["net", "network-module"],
  ["http", "network-module"],
  ["https", "network-module"],
  ["http2", "network-module"],
  ["dgram", "network-module"],
  ["tls", "network-module"],
  ["module", "module-loader"],
  ["os", "os-module"],
  ["process", "ambient-environment"],
]);

const spawnNames = new Set(["spawn", "spawnSync", "exec", "execFile", "execFileSync", "fork"]);
const networkGlobals = new Set(["fetch", "WebSocket", "EventSource"]);
const runtimeEvaluationNames = new Set(["eval", "Function"]);

function toProjectPath(file, rootDir) {
  return relative(rootDir, file).split(sep).join("/");
}

function resolveProjectPath(rootDir, file) {
  return resolve(rootDir, file);
}

function unprefixedModuleName(value) {
  return value.startsWith("node:") ? value.slice(5) : value;
}

function literalModuleSpecifier(node) {
  return ts.isStringLiteralLike(node) ? node.text : undefined;
}

function accessedName(expression) {
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) return expression.name.text;
  if (ts.isElementAccessExpression(expression) && expression.argumentExpression !== undefined) {
    return literalModuleSpecifier(expression.argumentExpression);
  }
  return undefined;
}

function isTrueLiteral(node) {
  return node.kind === ts.SyntaxKind.TrueKeyword;
}

function isCliFile(projectPath) {
  return projectPath.startsWith("src/commands/") && projectPath.endsWith(".ts");
}

function collectTypeScriptFiles(rootDir, start = "src") {
  const startDir = resolveProjectPath(rootDir, start);
  if (!existsSync(startDir)) return [];
  const files = [];

  function walk(currentDir) {
    for (const entry of readdirSync(currentDir, { withFileTypes: true })) {
      const entryPath = join(currentDir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === "node_modules" || entry.name === "dist") continue;
        walk(entryPath);
        continue;
      }
      if (!entry.isFile() || !entry.name.endsWith(".ts") || entry.name.endsWith(".d.ts")) continue;
      files.push(entryPath);
    }
  }

  walk(startDir);
  return files;
}

function createSourceFile(file, source) {
  return ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
}

function addModuleViolation(violations, projectPath, specifier) {
  const moduleName = unprefixedModuleName(specifier);
  const label = forbiddenModules.get(moduleName);
  if (label !== undefined) violations.add(`${label}: ${projectPath}`);
  if (/(?:mcp|connector|tool-runner|workspace-writer)/u.test(specifier)) {
    violations.add(`tool-or-connector-import: ${projectPath}`);
  }
}

function inspectSource(file, source, rootDir = repoRoot) {
  const projectPath = toProjectPath(file, rootDir);
  const sourceFile = createSourceFile(file, source);
  const violations = new Set();

  function visit(node) {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier !== undefined) {
      const specifier = literalModuleSpecifier(node.moduleSpecifier);
      if (specifier !== undefined) addModuleViolation(violations, projectPath, specifier);
    }

    if (
      ts.isImportEqualsDeclaration(node) &&
      ts.isExternalModuleReference(node.moduleReference) &&
      node.moduleReference.expression !== undefined
    ) {
      const specifier = literalModuleSpecifier(node.moduleReference.expression);
      if (specifier !== undefined) addModuleViolation(violations, projectPath, specifier);
    }

    if (ts.isCallExpression(node)) {
      const isDynamicImport = node.expression.kind === ts.SyntaxKind.ImportKeyword;
      const isRequire = ts.isIdentifier(node.expression) && node.expression.text === "require";
      if (isDynamicImport || isRequire) {
        const specifier = node.arguments[0] === undefined ? undefined : literalModuleSpecifier(node.arguments[0]);
        if (specifier === undefined) violations.add(`module-loader: ${projectPath}`);
        else addModuleViolation(violations, projectPath, specifier);
      }

      const name = accessedName(node.expression);
      if (name !== undefined && spawnNames.has(name)) violations.add(`spawn-or-exec: ${projectPath}`);
      if (name !== undefined && networkGlobals.has(name)) violations.add(`global-network-api: ${projectPath}`);
      if (name !== undefined && runtimeEvaluationNames.has(name)) violations.add(`runtime-evaluation: ${projectPath}`);
      if (name === "createRequire") violations.add(`module-loader: ${projectPath}`);
    }

    if (ts.isNewExpression(node)) {
      const name = accessedName(node.expression);
      if (name !== undefined && networkGlobals.has(name)) violations.add(`global-network-api: ${projectPath}`);
      if (name !== undefined && runtimeEvaluationNames.has(name)) violations.add(`runtime-evaluation: ${projectPath}`);
    }

    if (
      (ts.isPropertyAccessExpression(node) &&
        ts.isIdentifier(node.expression) &&
        node.expression.text === "process" &&
        node.name.text === "env") ||
      (ts.isElementAccessExpression(node) &&
        ts.isIdentifier(node.expression) &&
        node.expression.text === "process" &&
        node.argumentExpression !== undefined &&
        literalModuleSpecifier(node.argumentExpression) === "env")
    ) {
      violations.add(`ambient-environment: ${projectPath}`);
    }

    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  return violations;
}

function collectStringLiterals(node, strings = []) {
  if (ts.isStringLiteralLike(node) || ts.isNoSubstitutionTemplateLiteral(node)) strings.push(node.text);
  ts.forEachChild(node, (child) => collectStringLiterals(child, strings));
  return strings;
}

function collectStaticImports(sourceFile) {
  const imports = [];

  function visit(node) {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier !== undefined) {
      const specifier = literalModuleSpecifier(node.moduleSpecifier);
      if (specifier !== undefined) imports.push(specifier);
    }

    if (
      ts.isImportEqualsDeclaration(node) &&
      ts.isExternalModuleReference(node.moduleReference) &&
      node.moduleReference.expression !== undefined
    ) {
      const specifier = literalModuleSpecifier(node.moduleReference.expression);
      if (specifier !== undefined) imports.push(specifier);
    }

    if (ts.isCallExpression(node)) {
      const isDynamicImport = node.expression.kind === ts.SyntaxKind.ImportKeyword;
      const isRequire = ts.isIdentifier(node.expression) && node.expression.text === "require";
      if (isDynamicImport || isRequire) {
        const specifier = node.arguments[0] === undefined ? undefined : literalModuleSpecifier(node.arguments[0]);
        if (specifier !== undefined) imports.push(specifier);
      }
    }

    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  return imports;
}

function checkPackageRootExports(rootDir, violations) {
  const file = resolveProjectPath(rootDir, packageRootFile);
  if (!existsSync(file)) {
    violations.add(`missing-package-root: ${packageRootFile}`);
    return;
  }
  const sourceFile = createSourceFile(file, readFileSync(file, "utf8"));
  const projectPath = toProjectPath(file, rootDir);

  function visit(node) {
    if (ts.isExportDeclaration(node)) {
      const specifier = node.moduleSpecifier === undefined ? undefined : literalModuleSpecifier(node.moduleSpecifier);
      if (
        specifier?.includes("pre-spawn-capability-broker-v02") === true &&
        node.exportClause === undefined
      ) {
        violations.add(`package-root-broker-wildcard-export: ${projectPath}`);
      }
      if (specifier !== undefined && (specifier.includes("linux-host-enforcement-v02") || specifier.includes("bounded-linux-probe-v02"))) {
        violations.add(`package-root-linux-export: ${projectPath}`);
      }
      if (node.exportClause !== undefined && ts.isNamedExports(node.exportClause)) {
        for (const element of node.exportClause.elements) {
          const exportedName = element.name.text;
          const localName = (element.propertyName ?? element.name).text;
          if (forbiddenPackageRootExports.has(exportedName) || forbiddenPackageRootExports.has(localName)) {
            violations.add(`package-root-forbidden-export:${exportedName}: ${projectPath}`);
          }
        }
      }
    } else if (ts.isExportSpecifier(node)) {
      const exportedName = node.name.text;
      const localName = (node.propertyName ?? node.name).text;
      if (forbiddenPackageRootExports.has(exportedName) || forbiddenPackageRootExports.has(localName)) {
        violations.add(`package-root-forbidden-export:${exportedName}: ${projectPath}`);
      }
    }

    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
}

function checkBoundedLauncherImports(rootDir, sourceFiles, violations) {
  for (const file of sourceFiles) {
    const projectPath = toProjectPath(file, rootDir);
    const sourceFile = createSourceFile(file, readFileSync(file, "utf8"));
    for (const specifier of collectStaticImports(sourceFile)) {
      if (specifier !== boundedLauncherModule) continue;
      if (projectPath !== boundedLauncherImporter) {
        violations.add(`bounded-launcher-import-outside-linux-owner: ${projectPath}`);
      }
    }
  }
}

function checkLinuxImportsInCli(rootDir, sourceFiles, violations) {
  for (const file of sourceFiles) {
    const projectPath = toProjectPath(file, rootDir);
    if (projectPath !== engineFile && !isCliFile(projectPath)) continue;
    const sourceFile = createSourceFile(file, readFileSync(file, "utf8"));
    for (const specifier of collectStaticImports(sourceFile)) {
      if (!linuxModuleSpecifiers.has(specifier)) continue;
      violations.add(`linux-module-import-in-engine-or-cli: ${projectPath}`);
    }
  }
}

function checkLinuxModulePolicies(rootDir, violations) {
  for (const projectPath of newLinuxModules) {
    const file = resolveProjectPath(rootDir, projectPath);
    if (!existsSync(file)) continue;
    const source = readFileSync(file, "utf8");
    const sourceFile = createSourceFile(file, source);

    for (const violation of inspectSource(file, source, rootDir)) violations.add(violation);

    function visit(node) {
      if (
        ts.isPropertyAssignment(node) &&
        ((ts.isIdentifier(node.name) && node.name.text === "shell") ||
          (ts.isStringLiteralLike(node.name) && node.name.text === "shell")) &&
        isTrueLiteral(node.initializer)
      ) {
        violations.add(`shell-true-in-linux-module: ${projectPath}`);
      }

      if (ts.isCallExpression(node)) {
        const callName = accessedName(node.expression);
        if (callName !== undefined && spawnNames.has(callName) && node.arguments[0] !== undefined) {
          const command = literalModuleSpecifier(node.arguments[0]);
          if (command !== undefined && linuxCommandNeedles.some((pattern) => pattern.test(command))) {
            violations.add(`forbidden-linux-command-invocation:${command}: ${projectPath}`);
          }
        }
      }

      ts.forEachChild(node, visit);
    }

    for (const specifier of collectStaticImports(sourceFile)) {
      if (linuxImportNeedles.some((pattern) => pattern.test(specifier))) {
        violations.add(`forbidden-linux-import:${specifier}: ${projectPath}`);
      }
    }

    for (const literal of collectStringLiterals(sourceFile)) {
      if (linuxImportNeedles.some((pattern) => pattern.test(literal)) && linuxCommandNeedles.some((pattern) => pattern.test(literal))) {
        violations.add(`forbidden-linux-command-literal:${literal}: ${projectPath}`);
      }
    }

    visit(sourceFile);
  }
}

function checkRequiredDefaults(rootDir, violations) {
  for (const relativeFile of defaultFiles) {
    const file = resolveProjectPath(rootDir, relativeFile);
    if (!existsSync(file)) violations.add(`missing-default-target: ${relativeFile}`);
  }
}

export function runBoundaryCheck(options = {}) {
  const rootDir = options.rootDir === undefined ? repoRoot : resolve(options.rootDir);
  const explicitTargets = options.targets === undefined ? [] : options.targets.map((file) => resolve(file));
  const files = explicitTargets.length === 0
    ? defaultFiles.map((file) => resolveProjectPath(rootDir, file))
    : explicitTargets;
  const violations = new Set();

  for (const file of files) {
    const source = readFileSync(file, "utf8");
    for (const violation of inspectSource(file, source, rootDir)) violations.add(violation);
  }

  if (explicitTargets.length > 0) {
    return {
      rootDir,
      checkedFiles: files.map((file) => toProjectPath(file, rootDir)),
      violations: [...violations].sort(),
    };
  }

  checkRequiredDefaults(rootDir, violations);
  const sourceFiles = collectTypeScriptFiles(rootDir);
  checkPackageRootExports(rootDir, violations);
  checkBoundedLauncherImports(rootDir, sourceFiles, violations);
  checkLinuxImportsInCli(rootDir, sourceFiles, violations);
  checkLinuxModulePolicies(rootDir, violations);

  return {
    rootDir,
    checkedFiles: files.map((file) => toProjectPath(file, rootDir)),
    violations: [...violations].sort(),
  };
}

export function formatViolations(violations) {
  return violations.join("\n");
}

function isDirectExecution() {
  const executed = process.argv[1];
  return executed !== undefined && resolve(executed) === fileURLToPath(import.meta.url);
}

if (isDirectExecution()) {
  const result = runBoundaryCheck({ rootDir: process.cwd(), targets: process.argv.slice(2) });
  if (result.violations.length > 0) {
    process.stderr.write(`${formatViolations(result.violations)}\n`);
    process.exit(1);
  }
}
