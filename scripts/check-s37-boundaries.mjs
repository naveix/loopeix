import { existsSync, readFileSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
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
const phaseCOwnerSha256 = "8d99795eb162e8b16cf780c3b9c8236d3d8d9d4cf6c2b787abae083852ce7045";
const boundedLauncherModule = "./bounded-linux-probe-v02.js";
const linuxModuleSpecifiers = new Set([
  "./linux-host-enforcement-v02.js",
  "./bounded-linux-probe-v02.js",
]);
const linuxModulePaths = new Set([
  "src/run/linux-host-enforcement-v02.ts",
  "src/run/bounded-linux-probe-v02.ts",
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
  "S37LocalLinuxCapabilityV02",
  "S37LocalLinuxHostObservationV02",
  "S37LocalLinuxProductProbeInputV02",
  "S37LocalLinuxProductProbeV02",
  "buildS37SystemdRunInvocationV02",
  "createS37LocalLinuxProductProbeV02",
  "runS37LocalLinuxProductProbeV02",
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

function resolveStaticProjectImport(rootDir, importer, specifier) {
  if (!specifier.startsWith(".")) return null;
  const absolute = resolve(dirname(importer), specifier);
  const withTypeScriptExtension = absolute.endsWith(".js") ? `${absolute.slice(0, -3)}.ts` : absolute;
  const projectPath = toProjectPath(withTypeScriptExtension, rootDir);
  return projectPath === ".." || projectPath.startsWith("../") ? null : projectPath;
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

function enclosingNamedFunction(node) {
  let current = node.parent;
  while (current !== undefined) {
    if (ts.isFunctionDeclaration(current) && current.name !== undefined) return current.name.text;
    current = current.parent;
  }
  return null;
}

function propertyInitializer(object, name) {
  if (!ts.isObjectLiteralExpression(object)) return undefined;
  for (const property of object.properties) {
    if (!ts.isPropertyAssignment(property)) continue;
    const propertyName = ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name)
      ? property.name.text
      : undefined;
    if (propertyName === name) return property.initializer;
  }
  return undefined;
}

function exactStringArray(node, expected) {
  return node !== undefined && ts.isArrayLiteralExpression(node)
    && node.elements.length === expected.length
    && node.elements.every((element, index) => ts.isStringLiteralLike(element) && element.text === expected[index]);
}

function isPropertyPath(node, object, property) {
  return node !== undefined && ts.isPropertyAccessExpression(node)
    && ts.isIdentifier(node.expression) && node.expression.text === object
    && node.name.text === property;
}

function exactNamedImport(declaration, expectedNames) {
  const clause = declaration.importClause;
  const bindings = clause?.namedBindings;
  if (clause === undefined || clause.name !== undefined || bindings === undefined || !ts.isNamedImports(bindings)) return false;
  const names = bindings.elements.map((element) => element.propertyName === undefined ? element.name.text : null);
  return names.length === expectedNames.length
    && names.every((name) => name !== null)
    && [...names].sort().every((name, index) => name === [...expectedNames].sort()[index]);
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

function addModuleViolation(violations, projectPath, specifier, allowedModules = new Set()) {
  const moduleName = unprefixedModuleName(specifier);
  const label = forbiddenModules.get(moduleName);
  if (label !== undefined && !allowedModules.has(moduleName)) violations.add(`${label}: ${projectPath}`);
  if (/(?:mcp|connector|tool-runner|workspace-writer)/u.test(specifier)) {
    violations.add(`tool-or-connector-import: ${projectPath}`);
  }
}

function inspectSource(file, source, rootDir = repoRoot, options = {}) {
  const projectPath = toProjectPath(file, rootDir);
  const sourceFile = createSourceFile(file, source);
  const violations = new Set();
  const allowedModules = options.allowedModules ?? new Set();
  const allowedCalls = options.allowedCalls ?? new Set();

  function visit(node) {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier !== undefined) {
      const specifier = literalModuleSpecifier(node.moduleSpecifier);
      if (specifier !== undefined) addModuleViolation(violations, projectPath, specifier, allowedModules);
    }

    if (
      ts.isImportEqualsDeclaration(node) &&
      ts.isExternalModuleReference(node.moduleReference) &&
      node.moduleReference.expression !== undefined
    ) {
      const specifier = literalModuleSpecifier(node.moduleReference.expression);
      if (specifier !== undefined) addModuleViolation(violations, projectPath, specifier, allowedModules);
    }

    if (ts.isCallExpression(node)) {
      const isDynamicImport = node.expression.kind === ts.SyntaxKind.ImportKeyword;
      const isRequire = ts.isIdentifier(node.expression) && node.expression.text === "require";
      if (isDynamicImport || isRequire) {
        violations.add(`module-loader: ${projectPath}`);
        const specifier = node.arguments[0] === undefined ? undefined : literalModuleSpecifier(node.arguments[0]);
        if (specifier !== undefined) addModuleViolation(violations, projectPath, specifier, allowedModules);
      }

      const name = accessedName(node.expression);
      if (name !== undefined && spawnNames.has(name) && !allowedCalls.has(name)) violations.add(`spawn-or-exec: ${projectPath}`);
      if (name !== undefined && networkGlobals.has(name)) violations.add(`global-network-api: ${projectPath}`);
      if (name !== undefined && runtimeEvaluationNames.has(name)) violations.add(`runtime-evaluation: ${projectPath}`);
      if (name === "createRequire") violations.add(`module-loader: ${projectPath}`);
      if (name === "getBuiltinModule") violations.add(`module-loader: ${projectPath}`);
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
      const importedProjectPath = resolveStaticProjectImport(rootDir, file, specifier);
      if (!linuxModuleSpecifiers.has(specifier) && !linuxModulePaths.has(importedProjectPath)) continue;
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

    const ownerCapability = projectPath === boundedLauncherImporter;
    const inspectOptions = ownerCapability
      ? { allowedModules: new Set(["child_process", "fs", "os", "process"]), allowedCalls: new Set(["spawn"]) }
      : {};
    for (const violation of inspectSource(file, source, rootDir, inspectOptions)) violations.add(violation);
    const ownerSpawnSites = [];
    if (ownerCapability) {
      const sourceSha256 = createHash("sha256").update(source, "utf8").digest("hex");
      if (sourceSha256 !== phaseCOwnerSha256) {
        violations.add(`phase-c-owner-source-digest:mismatch:${sourceSha256}: ${projectPath}`);
      }
      const expectedImports = new Map([
        ["node:child_process", ["spawn"]],
        ["node:fs", ["lstatSync", "readFileSync"]],
        ["node:os", ["arch", "platform", "release"]],
        ["zod", ["z"]],
        ["../hash.js", ["hashCanonical", "hashRawBytes"]],
        ["../schema/scalars.js", ["Hash", "IsoTimestamp"]],
        ["./bounded-linux-probe-v02.js", [
          "runBoundedS37LinuxProbeV02", "S37LinuxProbeExecutionResultV02", "S37LinuxProbeRuntimeInputV02",
          "S37LinuxProbeRuntimeOutcomeV02", "S37LinuxProbeRuntimeV02",
        ]],
        ["./pre-spawn-capability-broker-v02.js", [
          "prepareS37LinuxProbeAdmissionV02", "S37ActionInterpositionProfileV02",
          "S37LinuxBackendIdentityReceiptV02", "S37LinuxHostTupleV02", "S37LinuxProbeAdmissionV02",
          "S37PreSpawnProbeResultV02",
        ]],
      ]);
      const ownerImports = sourceFile.statements.filter(ts.isImportDeclaration);
      const moduleExports = sourceFile.statements.filter((statement) =>
        ts.isExportDeclaration(statement) && statement.moduleSpecifier !== undefined);
      let exactImportSurface = ownerImports.length === expectedImports.size + 1 && moduleExports.length === 0;
      for (const [specifier, names] of expectedImports) {
        const matches = ownerImports.filter((declaration) => literalModuleSpecifier(declaration.moduleSpecifier) === specifier);
        if (matches.length !== 1 || !exactNamedImport(matches[0], names)) exactImportSurface = false;
      }
      const processImports = ownerImports.filter((declaration) =>
        literalModuleSpecifier(declaration.moduleSpecifier) === "node:process");
      const processClause = processImports[0]?.importClause;
      if (processImports.length !== 1 || processClause?.name?.text !== "process" || processClause.namedBindings !== undefined) {
        exactImportSurface = false;
      }
      if (!exactImportSurface) violations.add(`phase-c-owner-import-surface-must-be-exact: ${projectPath}`);

      const childProcessImports = sourceFile.statements.filter((statement) => {
        if (!(ts.isImportDeclaration(statement) || ts.isExportDeclaration(statement))
          || statement.moduleSpecifier === undefined) return false;
        const specifier = literalModuleSpecifier(statement.moduleSpecifier);
        return specifier !== undefined && unprefixedModuleName(specifier) === "child_process";
      });
      const onlyImport = childProcessImports.length === 1 && ts.isImportDeclaration(childProcessImports[0])
        ? childProcessImports[0]
        : undefined;
      const bindings = onlyImport?.importClause?.namedBindings;
      const exactBinding = onlyImport !== undefined
        && literalModuleSpecifier(onlyImport.moduleSpecifier) === "node:child_process"
        && bindings !== undefined && ts.isNamedImports(bindings)
        && bindings.elements.length === 1
        && bindings.elements[0].propertyName === undefined
        && bindings.elements[0].name.text === "spawn";
      if (!exactBinding) {
        violations.add(`phase-c-child-process-import-must-be-sole-unaliased-spawn: ${projectPath}`);
      }
    }

    function visit(node) {
      if (ownerCapability && ts.isIdentifier(node) && node.text === "process") {
        const parent = node.parent;
        const allowedImportBinding = ts.isImportClause(parent) && parent.name === node;
        const allowedGetuid = ts.isPropertyAccessExpression(parent)
          && parent.expression === node && parent.name.text === "getuid"
          && enclosingNamedFunction(node) === "currentUid";
        if (!allowedImportBinding && !allowedGetuid) {
          violations.add(`phase-c-process-reference-must-be-current-uid-only: ${projectPath}`);
        }
      }
      if (ownerCapability && ts.isIdentifier(node) && (node.text === "globalThis" || node.text === "global")) {
        violations.add(`phase-c-ambient-global-reference-forbidden:${node.text}: ${projectPath}`);
      }
      if (ownerCapability && ts.isIdentifier(node) && (node.text === "eval" || node.text === "Function")) {
        violations.add(`phase-c-runtime-evaluation-reference-forbidden:${node.text}: ${projectPath}`);
      }
      if (ownerCapability && ts.isIdentifier(node) && node.text === "spawn") {
        const parent = node.parent;
        const allowedImportBinding = ts.isImportSpecifier(parent)
          && parent.name === node && parent.propertyName === undefined;
        const allowedDirectCall = ts.isCallExpression(parent) && parent.expression === node;
        if (!allowedImportBinding && !allowedDirectCall) {
          violations.add(`phase-c-spawn-reference-must-be-direct-callee: ${projectPath}`);
        }
      }
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
        if (ownerCapability && callName === "spawn") {
          ownerSpawnSites.push(node);
          const owner = enclosingNamedFunction(node);
          if (owner !== "observeSystemdManagerVersion" && owner !== "startExactTransientUnit") {
            violations.add(`phase-c-spawn-outside-admitted-controller:${owner ?? "anonymous"}: ${projectPath}`);
          }
        }
        if (ownerCapability && callName === "observeSystemdManagerVersion"
          && enclosingNamedFunction(node) !== "startExactTransientUnit") {
          violations.add(`phase-c-manager-observation-before-admitted-controller: ${projectPath}`);
        }
        if (callName !== undefined && spawnNames.has(callName) && !ownerCapability && node.arguments[0] !== undefined) {
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

    if (ownerCapability) {
      if (ownerSpawnSites.length !== 2) {
        violations.add(`phase-c-spawn-call-count:expected-2:actual-${ownerSpawnSites.length}: ${projectPath}`);
      }
      for (const spawnCall of ownerSpawnSites) {
        const owner = enclosingNamedFunction(spawnCall);
        const [command, argv, options] = spawnCall.arguments;
        if (owner === "observeSystemdManagerVersion") {
          const env = options === undefined ? undefined : propertyInitializer(options, "env");
          const exactEnv = env !== undefined && ts.isCallExpression(env)
            && ts.isIdentifier(env.expression) && env.expression.text === "localUserManagerEnvironment"
            && env.arguments.length === 1 && ts.isIdentifier(env.arguments[0]) && env.arguments[0].text === "uid";
          const cwd = options === undefined ? undefined : propertyInitializer(options, "cwd");
          const exactOptions = cwd !== undefined
            && ts.isStringLiteralLike(cwd) && cwd.text === "/"
            && exactEnv
            && propertyInitializer(options, "shell")?.kind === ts.SyntaxKind.FalseKeyword
            && exactStringArray(propertyInitializer(options, "stdio"), ["ignore", "pipe", "ignore"])
            && propertyInitializer(options, "windowsHide")?.kind === ts.SyntaxKind.TrueKeyword;
          if (!(command !== undefined && ts.isIdentifier(command) && command.text === "SYSTEMCTL_PATH"
            && exactStringArray(argv, ["--user", "show", "--property=Version", "--value"])
            && exactOptions)) {
            violations.add(`phase-c-systemctl-spawn-shape: ${projectPath}`);
          }
          continue;
        }
        if (owner === "startExactTransientUnit") {
          const exactArgv = argv !== undefined && ts.isArrayLiteralExpression(argv)
            && argv.elements.length === 1 && ts.isSpreadElement(argv.elements[0])
            && isPropertyPath(argv.elements[0].expression, "invocation", "args");
          if (!(isPropertyPath(command, "invocation", "command")
            && exactArgv && isPropertyPath(options, "invocation", "options"))) {
            violations.add(`phase-c-systemd-run-spawn-shape: ${projectPath}`);
          }
          continue;
        }
        violations.add(`phase-c-spawn-unapproved-owner:${owner ?? "anonymous"}: ${projectPath}`);
      }
      const requiredFragments = [
        'import { spawn } from "node:child_process";',
        'import { lstatSync, readFileSync } from "node:fs";',
        'import { arch, platform, release } from "node:os";',
        'import process from "node:process";',
        'shell: false as const',
        'XDG_RUNTIME_DIR: runtimeDirectory',
        'DBUS_SESSION_BUS_ADDRESS: `unix:path=${runtimeDirectory}/bus`',
        'const PRODUCT_UNIT = "loopeix-s37-product-v02";',
        "const COMPLETE_CONTROLLER_WINDOW_MS = 15_000;",
        "const unit = PRODUCT_UNIT;",
        '"--service-type=exec"',
        '"--wait"',
        '"--collect"',
        '"--property=StandardInput=null"',
        '"--property=StandardOutput=null"',
        '"--property=StandardError=null"',
        '"--property=NoNewPrivileges=yes"',
        '"--property=KillMode=control-group"',
        '"--property=PrivateNetwork=yes"',
        '"--property=CapabilityBoundingSet="',
        '"--property=CPUQuota=25%"',
        '"--property=MemoryMax=64000000"',
        '"--property=TasksMax=8"',
        '"--property=IOWeight=10"',
        '"--property=RuntimeMaxSec=2s"',
        '"--user", "show", "--property=Version", "--value"',
        'path: z.literal("/usr/bin/systemctl")',
        'const managerBefore = await observeSystemdManagerVersion(uid);',
        'const managerAfter = exactPass',
      ];
      for (const fragment of requiredFragments) {
        if (!source.includes(fragment)) violations.add(`missing-phase-c-owner-contract:${fragment}: ${projectPath}`);
      }
      for (const forbidden of ['"--scope"', '"--pipe"', "shell: true"]) {
        if (source.includes(forbidden)) violations.add(`forbidden-phase-c-owner-contract:${forbidden}: ${projectPath}`);
      }
    }
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
