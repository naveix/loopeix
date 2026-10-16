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
  "src/schema/runtime-v03.ts",
  "src/run/runtime-ledger-dispatch.ts",
  "src/run/runtime-ledger-v03.ts",
  "src/run/runtime-ledger-migration-v02-v03.ts",
  "src/run/runtime-state-reducer-v03.ts",
  "src/run/runtime-durability-policy-v03.ts",
  "src/run/brokered-model-executor-v01.ts",
];

const brokerFile = "src/run/pre-spawn-capability-broker-v02.ts";
const engineFile = "src/run/engine.ts";
const packageRootFile = "src/index.ts";
const packageRootSha256 = "b0a90a6ab8817c7f3287a82e5ce437329048f800e569a9ddd48af276682e7291";
const boundedLauncherImporter = "src/run/linux-host-enforcement-v02.ts";
const phaseCOwnerSha256 = "8d99795eb162e8b16cf780c3b9c8236d3d8d9d4cf6c2b787abae083852ce7045";
const boundedLauncherModule = "./bounded-linux-probe-v02.js";
const v03ContractModuleNeedle = "s37-product-host-contract-v03";
const v03AuthorityModuleNeedles = new Set([
  v03ContractModuleNeedle,
  "s37-anchor-authorization-v03",
  "s37-product-host-lifecycle-v03",
  "s37-linux-launch-qualification-v03",
  "linux-host-enforcement-v03",
]);
const v03RuntimeApiNames = new Set([
  "parseS37LocalProductHostAnchorV03",
  "parseS37ProductHostLifecycleStateV01",
  "parseS37ProductHostInstallBundleV01",
  "parseS37ProductHostBootstrapInspectionV01",
  "parseS37ProductHostQualificationRequestV01",
  "parseS37ProductHostTransitionLockV01",
  "parseS37LinuxLaunchQualificationV03",
  "qualificationStatementHashV03",
  "qualificationSigningBytesV03",
  "verifyS37LinuxLaunchQualificationSignatureV03",
  "canonicalV03",
  "hashCanonicalV03",
  "AuthorizedS37AnchorMutationV03",
  "authorizeS37AnchorMutationV03",
  "consumeAuthorizedS37AnchorMutationV03",
  "issueAuthorizedS37AnchorMutationV03ForTest",
  "applyS37ProductHostAnchorMutationV03",
  "reconcileS37ProductHostAnchorV03",
  "observeS37ProductHostCustodyV03",
  "S37ProductHostLifecycleIoV03",
  "CapturedS37QualificationIssuerSignerV03",
  "captureS37QualificationIssuerSignerV03",
  "CapturedS37QualificationBootObserverV03",
  "captureS37QualificationBootObserverV03",
  "issueS37LinuxLaunchQualificationV03",
  "AuthorizedS37LinuxLaunchQualificationV03",
  "admitS37LinuxLaunchQualificationV03",
  "consumeAuthorizedS37LinuxLaunchQualificationV03",
  "runS37LocalLinuxProductProbeV03",
  "createS37LocalLinuxProductProbeV03ForTest",
]);
const v03TestCapabilityMintNames = new Map([
  ["issueAuthorizedS37AnchorMutationV03ForTest", "s37-anchor-authorization-v03"],
  ["createS37LocalLinuxProductProbeV03ForTest", "linux-host-enforcement-v03"],
]);
const v03SchemaIds = new Set(
  "s37-local-product-host-anchor-v03|s37-product-host-lifecycle-state-v01|s37-linux-launch-qualification-v03|s37-product-host-bootstrap-inspection-v01|s37-product-host-install-bundle-v01|s37-product-host-qualification-request-v01|s37-product-host-transition-lock-v01".split("|"),
);
const requiredV03CommandSeams = Object.freeze([
  "scripts/s37-linux-product-host-v03/install-anchor.mjs",
  "scripts/s37-linux-product-host-v03/transition-anchor.mjs",
  "scripts/s37-linux-product-host-v03/issue-qualification.mjs",
  "scripts/s37-linux-product-host-v03/reconcile-anchor.mjs",
]);
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
  ...v03RuntimeApiNames,
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

function resolveLocalSourceFile(rootDir, importer, specifier) {
  if (!specifier.startsWith(".")) return null;
  const absolute = resolve(dirname(importer), specifier);
  const candidates = [absolute];
  if (absolute.endsWith(".js")) candidates.push(`${absolute.slice(0, -3)}.ts`);
  if (absolute.endsWith(".mjs")) candidates.push(`${absolute.slice(0, -4)}.mts`);
  if (absolute.endsWith(".cjs")) candidates.push(`${absolute.slice(0, -4)}.cts`);
  if (!/\.[cm]?[jt]s$/u.test(absolute)) {
    candidates.push(`${absolute}.ts`, `${absolute}.js`, join(absolute, "index.ts"), join(absolute, "index.js"));
  }
  for (const candidate of candidates) {
    const projectPath = toProjectPath(candidate, rootDir);
    if (projectPath !== ".." && !projectPath.startsWith("../") && existsSync(candidate)) return candidate;
  }
  return null;
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

function isFalseLiteral(node) {
  let current = node;
  while (ts.isAsExpression(current) || ts.isTypeAssertionExpression(current)
    || ts.isParenthesizedExpression(current) || ts.isSatisfiesExpression(current)) {
    current = current.expression;
  }
  return current.kind === ts.SyntaxKind.FalseKeyword;
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

function collectScriptSourceFiles(rootDir) {
  const startDir = resolveProjectPath(rootDir, "scripts");
  if (!existsSync(startDir)) return [];
  const files = [];
  const sourceExtension = /\.(?:[cm]?[jt]s)$/u;

  function walk(currentDir) {
    for (const entry of readdirSync(currentDir, { withFileTypes: true })) {
      const entryPath = join(currentDir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === "node_modules" || entry.name === "dist") continue;
        walk(entryPath);
        continue;
      }
      if (!entry.isFile() || !sourceExtension.test(entry.name) || entry.name.endsWith(".d.ts")) continue;
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

function propertyNameText(name) {
  return ts.isIdentifier(name) || ts.isStringLiteralLike(name) ? name.text : undefined;
}

function isModuleExportsExpression(node) {
  return ts.isPropertyAccessExpression(node)
    && ts.isIdentifier(node.expression) && node.expression.text === "module"
    && node.name.text === "exports";
}

function commonJsExportName(node) {
  if (ts.isPropertyAccessExpression(node)) {
    if (ts.isIdentifier(node.expression) && node.expression.text === "exports") return node.name.text;
    if (isModuleExportsExpression(node.expression)) return node.name.text;
  }
  if (ts.isElementAccessExpression(node) && node.argumentExpression !== undefined) {
    const name = literalModuleSpecifier(node.argumentExpression);
    if (name === undefined) return undefined;
    if (ts.isIdentifier(node.expression) && node.expression.text === "exports") return name;
    if (isModuleExportsExpression(node.expression)) return name;
  }
  return undefined;
}

function isV03AuthorityModule(specifierOrPath) {
  return [...v03AuthorityModuleNeedles].some((needle) => specifierOrPath.includes(needle));
}

function checkPackageRootV03ExportGraph(rootDir, violations) {
  const rootFile = resolveProjectPath(rootDir, packageRootFile);
  if (!existsSync(rootFile)) return;
  const modules = new Map();
  const pending = [rootFile];

  while (pending.length > 0) {
    const file = pending.pop();
    if (file === undefined || modules.has(file)) continue;
    const sourceFile = createSourceFile(file, readFileSync(file, "utf8"));
    modules.set(file, sourceFile);
    for (const specifier of collectStaticImports(sourceFile)) {
      const importedFile = resolveLocalSourceFile(rootDir, file, specifier);
      if (importedFile !== null && !modules.has(importedFile)) pending.push(importedFile);
    }
  }

  const summaries = new Map();
  for (const [file] of modules) {
    const contractOrigin = isV03AuthorityModule(toProjectPath(file, rootDir));
    summaries.set(file, {
      allForbidden: contractOrigin,
      forbiddenExports: new Set(contractOrigin ? v03RuntimeApiNames : []),
    });
  }

  let changed = true;
  while (changed) {
    changed = false;
    for (const [file, sourceFile] of modules) {
      const summary = summaries.get(file);
      const forbiddenAliases = new Set();
      const namespaceImports = new Map();

      for (const statement of sourceFile.statements) {
        if (!ts.isImportDeclaration(statement)) continue;
        const specifier = literalModuleSpecifier(statement.moduleSpecifier);
        if (specifier === undefined) continue;
        const importedFile = resolveLocalSourceFile(rootDir, file, specifier);
        const imported = importedFile === null ? undefined : summaries.get(importedFile);
        const contractOrigin = isV03AuthorityModule(specifier);
        const clause = statement.importClause;
        if (clause === undefined) continue;
        if (clause.name !== undefined && (contractOrigin || imported?.allForbidden === true)) {
          forbiddenAliases.add(clause.name.text);
        }
        const bindings = clause.namedBindings;
        if (bindings !== undefined && ts.isNamespaceImport(bindings)) {
          if (imported !== undefined) namespaceImports.set(bindings.name.text, imported);
          if (contractOrigin) namespaceImports.set(bindings.name.text, { allForbidden: true, forbiddenExports: v03RuntimeApiNames });
          continue;
        }
        if (bindings === undefined || !ts.isNamedImports(bindings)) continue;
        for (const element of bindings.elements) {
          const importedName = (element.propertyName ?? element.name).text;
          if (v03RuntimeApiNames.has(importedName) || contractOrigin || imported?.allForbidden === true
            || imported?.forbiddenExports.has(importedName) === true) {
            forbiddenAliases.add(element.name.text);
          }
        }
      }

      for (const statement of sourceFile.statements) {
        if (!ts.isVariableStatement(statement)) continue;
        for (const declaration of statement.declarationList.declarations) {
          const initializer = declaration.initializer;
          if (initializer === undefined || !ts.isCallExpression(initializer)
            || !ts.isIdentifier(initializer.expression) || initializer.expression.text !== "require") continue;
          const specifier = initializer.arguments[0] === undefined
            ? undefined
            : literalModuleSpecifier(initializer.arguments[0]);
          if (specifier === undefined) continue;
          const importedFile = resolveLocalSourceFile(rootDir, file, specifier);
          const imported = importedFile === null ? undefined : summaries.get(importedFile);
          if (!isV03AuthorityModule(specifier) && imported?.allForbidden !== true
            && (imported?.forbiddenExports.size ?? 0) === 0) continue;
          if (ts.isIdentifier(declaration.name)) {
            namespaceImports.set(declaration.name.text, imported ?? {
              allForbidden: true,
              forbiddenExports: v03RuntimeApiNames,
            });
          }
          if (ts.isObjectBindingPattern(declaration.name)) {
            for (const element of declaration.name.elements) {
              const importedName = propertyNameText(element.propertyName ?? element.name);
              if (!ts.isIdentifier(element.name) || importedName === undefined) continue;
              if (isV03AuthorityModule(specifier) || imported?.allForbidden === true
                || imported?.forbiddenExports.has(importedName) === true) {
                forbiddenAliases.add(element.name.text);
              }
            }
          }
        }
      }

      let foundAlias = true;
      while (foundAlias) {
        foundAlias = false;
        for (const statement of sourceFile.statements) {
          if (!ts.isVariableStatement(statement)) continue;
          for (const declaration of statement.declarationList.declarations) {
            if (!ts.isIdentifier(declaration.name) || declaration.initializer === undefined) continue;
            const initializer = declaration.initializer;
            let forbidden = ts.isIdentifier(initializer) && forbiddenAliases.has(initializer.text);
            if (ts.isPropertyAccessExpression(initializer) && ts.isIdentifier(initializer.expression)) {
              const namespace = namespaceImports.get(initializer.expression.text);
              forbidden ||= namespace?.allForbidden === true || namespace?.forbiddenExports.has(initializer.name.text) === true;
            }
            if (ts.isElementAccessExpression(initializer) && ts.isIdentifier(initializer.expression)
              && initializer.argumentExpression !== undefined) {
              const namespace = namespaceImports.get(initializer.expression.text);
              const property = literalModuleSpecifier(initializer.argumentExpression);
              forbidden ||= property !== undefined
                && (namespace?.allForbidden === true || namespace?.forbiddenExports.has(property) === true);
            }
            if (forbidden && !forbiddenAliases.has(declaration.name.text)) {
              forbiddenAliases.add(declaration.name.text);
              foundAlias = true;
            }
          }
        }
      }

      const addForbiddenExport = (name) => {
        if (summary.forbiddenExports.has(name)) return;
        summary.forbiddenExports.add(name);
        changed = true;
      };
      const expressionIsForbidden = (expression) => {
        if (ts.isIdentifier(expression)) return forbiddenAliases.has(expression.text)
          || namespaceImports.has(expression.text);
        if (ts.isPropertyAccessExpression(expression) && ts.isIdentifier(expression.expression)) {
          const namespace = namespaceImports.get(expression.expression.text);
          return namespace?.allForbidden === true || namespace?.forbiddenExports.has(expression.name.text) === true;
        }
        if (ts.isElementAccessExpression(expression) && ts.isIdentifier(expression.expression)
          && expression.argumentExpression !== undefined) {
          const namespace = namespaceImports.get(expression.expression.text);
          const property = literalModuleSpecifier(expression.argumentExpression);
          return property !== undefined
            && (namespace?.allForbidden === true || namespace?.forbiddenExports.has(property) === true);
        }
        if (ts.isCallExpression(expression) && ts.isIdentifier(expression.expression)
          && expression.expression.text === "require") {
          const specifier = expression.arguments[0] === undefined
            ? undefined
            : literalModuleSpecifier(expression.arguments[0]);
          if (specifier === undefined) return false;
          const importedFile = resolveLocalSourceFile(rootDir, file, specifier);
          const imported = importedFile === null ? undefined : summaries.get(importedFile);
          return isV03AuthorityModule(specifier) || imported?.allForbidden === true
            || (imported?.forbiddenExports.size ?? 0) > 0;
        }
        return false;
      };

      for (const statement of sourceFile.statements) {
        if (ts.isExportDeclaration(statement)) {
          const specifier = statement.moduleSpecifier === undefined ? undefined : literalModuleSpecifier(statement.moduleSpecifier);
          const importedFile = specifier === undefined ? null : resolveLocalSourceFile(rootDir, file, specifier);
          const imported = importedFile === null ? undefined : summaries.get(importedFile);
          const contractOrigin = specifier !== undefined && isV03AuthorityModule(specifier);
          if (statement.exportClause === undefined) {
            if (contractOrigin) for (const name of v03RuntimeApiNames) addForbiddenExport(name);
            if (imported !== undefined) for (const name of imported.forbiddenExports) addForbiddenExport(name);
            continue;
          }
          if (ts.isNamespaceExport(statement.exportClause)) {
            if (contractOrigin || imported?.allForbidden === true || (imported?.forbiddenExports.size ?? 0) > 0) {
              addForbiddenExport(statement.exportClause.name.text);
            }
            continue;
          }
          for (const element of statement.exportClause.elements) {
            const exportedName = element.name.text;
            const localName = (element.propertyName ?? element.name).text;
            const namespace = namespaceImports.get(localName);
            if (v03RuntimeApiNames.has(exportedName) || v03RuntimeApiNames.has(localName)
              || forbiddenAliases.has(localName) || contractOrigin || imported?.allForbidden === true
              || imported?.forbiddenExports.has(localName) === true || namespace?.allForbidden === true
              || (namespace?.forbiddenExports.size ?? 0) > 0) {
              addForbiddenExport(exportedName);
            }
          }
          continue;
        }

        if (ts.isVariableStatement(statement)
          && statement.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) === true) {
          for (const declaration of statement.declarationList.declarations) {
            if (ts.isIdentifier(declaration.name)
              && (v03RuntimeApiNames.has(declaration.name.text) || forbiddenAliases.has(declaration.name.text))) {
              addForbiddenExport(declaration.name.text);
            }
          }
        }

        if ((ts.isFunctionDeclaration(statement) || ts.isClassDeclaration(statement)) && statement.name !== undefined
          && statement.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) === true
          && v03RuntimeApiNames.has(statement.name.text)) {
          addForbiddenExport(statement.name.text);
        }

        if (ts.isExportAssignment(statement) && ts.isIdentifier(statement.expression)
          && forbiddenAliases.has(statement.expression.text)) {
          addForbiddenExport("default");
        }

        function inspectCommonJs(node) {
          if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
            const namedExport = commonJsExportName(node.left);
            if (namedExport !== undefined && v03RuntimeApiNames.has(namedExport)) addForbiddenExport(namedExport);
            if (namedExport !== undefined && ts.isIdentifier(node.right) && forbiddenAliases.has(node.right.text)) {
              addForbiddenExport(namedExport);
            }
            if (namedExport !== undefined && expressionIsForbidden(node.right)) addForbiddenExport(namedExport);
            if (isModuleExportsExpression(node.left) && expressionIsForbidden(node.right)) addForbiddenExport("default");
            if (isModuleExportsExpression(node.left) && ts.isObjectLiteralExpression(node.right)) {
              for (const property of node.right.properties) {
                if (!ts.isPropertyAssignment(property) && !ts.isShorthandPropertyAssignment(property)) continue;
                const name = propertyNameText(property.name);
                if (name !== undefined && v03RuntimeApiNames.has(name)) addForbiddenExport(name);
                const valueName = ts.isShorthandPropertyAssignment(property)
                  ? property.name.text
                  : ts.isIdentifier(property.initializer) ? property.initializer.text : undefined;
                if (name !== undefined && valueName !== undefined && forbiddenAliases.has(valueName)) {
                  addForbiddenExport(name);
                }
                if (ts.isPropertyAssignment(property) && name !== undefined
                  && expressionIsForbidden(property.initializer)) addForbiddenExport(name);
              }
            }
          }
          ts.forEachChild(node, inspectCommonJs);
        }
        inspectCommonJs(statement);
      }
    }
  }

  const rootSummary = summaries.get(rootFile);
  if (rootSummary === undefined) return;
  for (const name of rootSummary.forbiddenExports) {
    violations.add(`package-root-forbidden-export:${name}: ${packageRootFile}`);
  }
}

function checkPackageRootSourceCustody(rootDir, violations) {
  const file = resolveProjectPath(rootDir, packageRootFile);
  if (!existsSync(file)) return;
  const actualSha256 = createHash("sha256").update(readFileSync(file)).digest("hex");
  if (actualSha256 !== packageRootSha256) {
    violations.add(`package-root-source-digest:mismatch:${actualSha256}: ${packageRootFile}`);
  }
}

function checkPackageRootExports(rootDir, violations) {
  const file = resolveProjectPath(rootDir, packageRootFile);
  if (!existsSync(file)) {
    violations.add(`missing-package-root: ${packageRootFile}`);
    return;
  }
  const sourceFile = createSourceFile(file, readFileSync(file, "utf8"));
  const projectPath = toProjectPath(file, rootDir);
  const forbiddenAliases = new Set();

  for (const statement of sourceFile.statements) {
    if (!ts.isImportDeclaration(statement)) continue;
    const specifier = literalModuleSpecifier(statement.moduleSpecifier);
    const clause = statement.importClause;
    if (clause === undefined) continue;
    if (specifier !== undefined && isV03AuthorityModule(specifier) && clause.name !== undefined) {
      forbiddenAliases.add(clause.name.text);
    }
    const bindings = clause.namedBindings;
    if (bindings !== undefined && ts.isNamespaceImport(bindings)) {
      if (specifier !== undefined && isV03AuthorityModule(specifier)) forbiddenAliases.add(bindings.name.text);
      continue;
    }
    if (bindings === undefined || !ts.isNamedImports(bindings)) continue;
    for (const element of bindings.elements) {
      const importedName = (element.propertyName ?? element.name).text;
      if (v03RuntimeApiNames.has(importedName) || (specifier !== undefined && isV03AuthorityModule(specifier))) {
        forbiddenAliases.add(element.name.text);
      }
    }
  }

  let foundAlias = true;
  while (foundAlias) {
    foundAlias = false;
    for (const statement of sourceFile.statements) {
      if (!ts.isVariableStatement(statement)) continue;
      for (const declaration of statement.declarationList.declarations) {
        if (!ts.isIdentifier(declaration.name) || declaration.initializer === undefined) continue;
        const initializer = declaration.initializer;
        const aliasesForbiddenName = ts.isIdentifier(initializer) && forbiddenAliases.has(initializer.text);
        const aliasesForbiddenProperty = ts.isPropertyAccessExpression(initializer)
          && ts.isIdentifier(initializer.expression) && forbiddenAliases.has(initializer.expression.text)
          && v03RuntimeApiNames.has(initializer.name.text);
        if ((aliasesForbiddenName || aliasesForbiddenProperty) && !forbiddenAliases.has(declaration.name.text)) {
          forbiddenAliases.add(declaration.name.text);
          foundAlias = true;
        }
      }
    }
  }

  function visit(node) {
    if (ts.isExportDeclaration(node)) {
      const specifier = node.moduleSpecifier === undefined ? undefined : literalModuleSpecifier(node.moduleSpecifier);
      if (specifier !== undefined && isV03AuthorityModule(specifier)) {
        violations.add(`package-root-v03-contract-export: ${projectPath}`);
      }
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
          if (forbiddenPackageRootExports.has(exportedName) || forbiddenPackageRootExports.has(localName)
            || forbiddenAliases.has(localName)) {
            violations.add(`package-root-forbidden-export:${exportedName}: ${projectPath}`);
          }
        }
      }
    } else if (
      (ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node) || ts.isInterfaceDeclaration(node)
        || ts.isTypeAliasDeclaration(node) || ts.isEnumDeclaration(node))
      && node.name !== undefined
      && node.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) === true
      && forbiddenPackageRootExports.has(node.name.text)
    ) {
      violations.add(`package-root-forbidden-export:${node.name.text}: ${projectPath}`);
    } else if (
      ts.isVariableStatement(node)
      && node.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) === true
    ) {
      for (const declaration of node.declarationList.declarations) {
        if (ts.isIdentifier(declaration.name)
          && (forbiddenPackageRootExports.has(declaration.name.text) || forbiddenAliases.has(declaration.name.text))) {
          violations.add(`package-root-forbidden-export:${declaration.name.text}: ${projectPath}`);
        }
      }
    } else if (
      ts.isExportAssignment(node)
      && ts.isIdentifier(node.expression)
      && forbiddenPackageRootExports.has(node.expression.text)
    ) {
      violations.add(`package-root-forbidden-export:${node.expression.text}: ${projectPath}`);
    } else if (ts.isExportSpecifier(node)) {
      const exportedName = node.name.text;
      const localName = (node.propertyName ?? node.name).text;
      if (forbiddenPackageRootExports.has(exportedName) || forbiddenPackageRootExports.has(localName)
        || forbiddenAliases.has(localName)) {
        violations.add(`package-root-forbidden-export:${exportedName}: ${projectPath}`);
      }
    }

    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
}

function checkScriptV03ContractAuthority(rootDir, violations) {
  for (const file of collectScriptSourceFiles(rootDir)) {
    const projectPath = toProjectPath(file, rootDir);
    const sourceFile = createSourceFile(file, readFileSync(file, "utf8"));
    const schemaIds = new Set();
    let definesOrExportsApi = false;

    function visit(node) {
      if (
        ((ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node)) && node.name !== undefined
          && v03RuntimeApiNames.has(node.name.text))
        || (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && v03RuntimeApiNames.has(node.name.text))
      ) {
        definesOrExportsApi = true;
      }

      if (ts.isExportSpecifier(node)) {
        const exportedName = node.name.text;
        const localName = (node.propertyName ?? node.name).text;
        if (v03RuntimeApiNames.has(exportedName) || v03RuntimeApiNames.has(localName)) {
          definesOrExportsApi = true;
        }
      }

      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        const exportedName = commonJsExportName(node.left);
        if (exportedName !== undefined && v03RuntimeApiNames.has(exportedName)) {
          definesOrExportsApi = true;
        }
        if (isModuleExportsExpression(node.left) && ts.isObjectLiteralExpression(node.right)) {
          for (const property of node.right.properties) {
            if (!ts.isPropertyAssignment(property) && !ts.isShorthandPropertyAssignment(property)) continue;
            const name = propertyNameText(property.name);
            if (name !== undefined && v03RuntimeApiNames.has(name)) definesOrExportsApi = true;
          }
        }
      }

      if (ts.isStringLiteralLike(node) && v03SchemaIds.has(node.text)) schemaIds.add(node.text);
      ts.forEachChild(node, visit);
    }

    visit(sourceFile);
    if (definesOrExportsApi) violations.add(`script-v03-contract-api-authority: ${projectPath}`);
    if (schemaIds.size === v03SchemaIds.size) violations.add(`script-v03-seven-schema-authority: ${projectPath}`);
  }
}

function checkPackageExportMapV03Authority(rootDir, violations) {
  const packageFile = resolveProjectPath(rootDir, "package.json");
  if (!existsSync(packageFile)) return;
  let packageMetadata;
  try {
    packageMetadata = JSON.parse(readFileSync(packageFile, "utf8"));
  } catch {
    violations.add("package-json-invalid: package.json");
    return;
  }

  function visit(value, path = "$") {
    if (typeof value === "string") {
      if (isV03AuthorityModule(value) || v03RuntimeApiNames.has(value)) {
        violations.add(`package-export-v03-authority:${path}: package.json`);
      }
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((entry, index) => visit(entry, `${path}[${index}]`));
      return;
    }
    if (value === null || typeof value !== "object") return;
    for (const [key, entry] of Object.entries(value)) {
      const nextPath = `${path}.${key}`;
      if (isV03AuthorityModule(key) || v03RuntimeApiNames.has(key)) {
        violations.add(`package-export-v03-authority:${nextPath}: package.json`);
      }
      visit(entry, nextPath);
    }
  }

  visit(packageMetadata.exports, "$.exports");
}

function checkV03TestCapabilityWiring(rootDir, violations) {
  const files = [...collectTypeScriptFiles(rootDir), ...collectScriptSourceFiles(rootDir)];
  for (const file of files) {
    const projectPath = toProjectPath(file, rootDir);
    const sourceFile = createSourceFile(file, readFileSync(file, "utf8"));
    let wired = false;

    function visit(node) {
      if (ts.isIdentifier(node) && v03TestCapabilityMintNames.has(node.text)
        && !projectPath.includes(v03TestCapabilityMintNames.get(node.text))) wired = true;
      if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier !== undefined) {
        const specifier = literalModuleSpecifier(node.moduleSpecifier);
        const exposesTestMint = specifier !== undefined
          && [...v03TestCapabilityMintNames.values()].some((needle) => specifier.includes(needle))
          && !projectPath.includes(specifier.includes("linux-host-enforcement-v03")
            ? "linux-host-enforcement-v03"
            : "s37-anchor-authorization-v03");
        if (exposesTestMint) {
          if (ts.isImportDeclaration(node)) {
            const bindings = node.importClause?.namedBindings;
            if (bindings !== undefined && ts.isNamespaceImport(bindings)) wired = true;
            if (node.importClause === undefined) wired = true;
          } else {
            if (node.exportClause !== undefined && ts.isNamespaceExport(node.exportClause)) wired = true;
            if (node.exportClause === undefined) wired = true;
          }
        }
      }
      ts.forEachChild(node, visit);
    }

    visit(sourceFile);
    if (wired) violations.add(`production-test-capability-wiring: ${projectPath}`);
  }
}

function checkV03ScriptRawAuthorityWiring(rootDir, violations) {
  const forbidden = new Set([
    "captureS37QualificationIssuerSignerV03",
    "captureS37QualificationBootObserverV03",
    "CapturedS37QualificationIssuerSignerV03",
    "CapturedS37QualificationBootObserverV03",
  ]);
  const files = [
    ...collectScriptSourceFiles(rootDir),
    ...collectTypeScriptFiles(rootDir).filter((file) => isCliFile(toProjectPath(file, rootDir))),
  ];
  for (const file of files) {
    const projectPath = toProjectPath(file, rootDir);
    const sourceFile = createSourceFile(file, readFileSync(file, "utf8"));
    let wired = false;
    let f4Context = false;
    function visit(node) {
      if (ts.isImportSpecifier(node) && forbidden.has((node.propertyName ?? node.name).text)) wired = true;
      if (ts.isStringLiteralLike(node) && node.text.includes("s37-linux-launch-qualification-v03")) f4Context = true;
      if (ts.isIdentifier(node) && forbidden.has(node.text)) f4Context = true;
      ts.forEachChild(node, visit);
    }
    visit(sourceFile);
    if (f4Context) {
      function visitRawInput(node) {
        if (ts.isIdentifier(node) && /(?:private.*key|key.*pem|observer.*callback)/iu.test(node.text)) wired = true;
        if (ts.isStringLiteralLike(node) && /(?:private[-_ ]?key|key[-_ ]?pem|observer[-_ ]?callback)/iu.test(node.text)) wired = true;
        ts.forEachChild(node, visitRawInput);
      }
      visitRawInput(sourceFile);
    }
    if (wired) violations.add(`script-v03-raw-authority-wiring: ${projectPath}`);
  }
}

function checkV03ProductionRuntimeHold(rootDir, violations) {
  const projectPath = "src/run/linux-host-enforcement-v03.ts";
  const file = resolveProjectPath(rootDir, projectPath);
  if (!existsSync(file)) return;
  const sourceFile = createSourceFile(file, readFileSync(file, "utf8"));
  const declaration = sourceFile.statements.find((statement) =>
    ts.isFunctionDeclaration(statement) && statement.name?.text === "runS37LocalLinuxProductProbeV03");
  if (declaration === undefined || !ts.isFunctionDeclaration(declaration) || declaration.body === undefined) {
    violations.add(`v03-production-runtime-missing: ${projectPath}`);
    return;
  }
  const exactInput = declaration.parameters.length === 1
    && ts.isIdentifier(declaration.parameters[0].name)
    && (declaration.parameters[0].name.text === "input" || declaration.parameters[0].name.text === "_input")
    && declaration.parameters[0].dotDotDotToken === undefined
    && declaration.parameters[0].initializer === undefined
    && !/(?:authority|observer|runtime|capabilit)/iu.test(declaration.parameters[0].getText(sourceFile));
  if (!exactInput) violations.add(`v03-production-runtime-injected-parameter: ${projectPath}`);

  let holdReason = false;
  let confirmedNotStarted = false;
  let directHoldReturn = false;
  let unsafeProductionPath = false;
  let testMintReference = false;
  function visit(node) {
    if (ts.isStringLiteralLike(node) && node.text === "ENFORCEMENT_UNAVAILABLE") holdReason = true;
    if (ts.isPropertyAssignment(node) && propertyNameText(node.name) === "process_started"
      && isFalseLiteral(node.initializer)) confirmedNotStarted = true;
    if (ts.isIdentifier(node) && node.text === "createS37LocalLinuxProductProbeV03ForTest") testMintReference = true;
    if (ts.isReturnStatement(node)) {
      const exactHold = node.expression !== undefined && ts.isCallExpression(node.expression)
        && ts.isIdentifier(node.expression.expression) && node.expression.expression.text === "hold"
        && node.expression.arguments.length === 0;
      if (exactHold) directHoldReturn = true;
      else unsafeProductionPath = true;
    }
    if (ts.isCallExpression(node)) {
      const exactHold = ts.isIdentifier(node.expression) && node.expression.text === "hold" && node.arguments.length === 0;
      if (!exactHold) unsafeProductionPath = true;
    }
    if (ts.isAwaitExpression(node) || ts.isNewExpression(node)) unsafeProductionPath = true;
    ts.forEachChild(node, visit);
  }
  visit(declaration.body);
  if (directHoldReturn) {
    const holdDeclaration = sourceFile.statements.find((statement) =>
      ts.isFunctionDeclaration(statement) && statement.name?.text === "hold");
    const holdReturnsConstant = holdDeclaration !== undefined && ts.isFunctionDeclaration(holdDeclaration)
      && holdDeclaration.body !== undefined
      && holdDeclaration.body.statements.length === 1
      && ts.isReturnStatement(holdDeclaration.body.statements[0])
      && ts.isIdentifier(holdDeclaration.body.statements[0].expression)
      && holdDeclaration.body.statements[0].expression.text === "ENFORCEMENT_UNAVAILABLE";
    if (!holdReturnsConstant) unsafeProductionPath = true;
    function visitModuleHold(node) {
      if (ts.isStringLiteralLike(node) && node.text === "ENFORCEMENT_UNAVAILABLE") holdReason = true;
      if (ts.isPropertyAssignment(node) && propertyNameText(node.name) === "process_started"
        && isFalseLiteral(node.initializer)) confirmedNotStarted = true;
      ts.forEachChild(node, visitModuleHold);
    }
    visitModuleHold(sourceFile);
  }
  if (!directHoldReturn || !holdReason || !confirmedNotStarted || unsafeProductionPath) {
    violations.add(`v03-production-runtime-s40-hold-missing: ${projectPath}`);
  }
  if (testMintReference) violations.add(`v03-production-runtime-test-mint-wiring: ${projectPath}`);
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

function checkRequiredV03CommandSeams(rootDir, violations) {
  for (const projectPath of requiredV03CommandSeams) {
    if (!existsSync(resolveProjectPath(rootDir, projectPath))) {
      violations.add(`missing-v03-command-seam: ${projectPath}`);
    }
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
  checkRequiredV03CommandSeams(rootDir, violations);
  const sourceFiles = collectTypeScriptFiles(rootDir);
  checkPackageRootSourceCustody(rootDir, violations);
  checkPackageRootExports(rootDir, violations);
  checkPackageRootV03ExportGraph(rootDir, violations);
  checkPackageExportMapV03Authority(rootDir, violations);
  checkScriptV03ContractAuthority(rootDir, violations);
  checkV03TestCapabilityWiring(rootDir, violations);
  checkV03ScriptRawAuthorityWiring(rootDir, violations);
  checkV03ProductionRuntimeHold(rootDir, violations);
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
