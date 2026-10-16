import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDir, "..");

const sourcePins = Object.freeze([
  Object.freeze({
    path: "src/index.ts",
    label: "package-root-source-digest",
    sha256: "b0a90a6ab8817c7f3287a82e5ce437329048f800e569a9ddd48af276682e7291",
  }),
  Object.freeze({
    path: "src/run/orchestrate.ts",
    label: "orchestrate-source-digest",
    sha256: "15b4315e137fe0b9d41c5af011381ccdd7f1ca0323ca9c139d7a34526e7b5073",
  }),
]);

// The eight S40-B kernel modules are package-private. The captured model executor
// seam is checked with the same host rules, but is not counted as a kernel module.
const privateKernelModules = Object.freeze([
  "src/schema/runtime-v03.ts",
  "src/run/runtime-manifest-v03.ts",
  "src/run/runtime-write-session-v03.ts",
  "src/run/runtime-action-admission-v03.ts",
  "src/run/runtime-effect-dispatch-broker-v01.ts",
  "src/run/runtime-observation-integrity-v03.ts",
  "src/run/runtime-termination-v03.ts",
  "src/run/runtime-execution-coordinator-v03.ts",
]);
const capturedExecutorModule = "src/run/brokered-model-executor-v01.ts";
const strictBoundaryModules = Object.freeze([...privateKernelModules, capturedExecutorModule]);
const privateModules = new Set(strictBoundaryModules);

// Production imports are closed to the exact S40 composition graph. Tests may
// import private modules, but production code cannot create another entry path.
const allowedProductionImporters = new Map([
  ["src/schema/runtime-v03.ts", new Set([
    "src/run/runtime-ledger-migration-v02-v03.ts",
    "src/run/runtime-ledger-v03.ts",
    "src/run/runtime-manifest-v03.ts",
    "src/run/runtime-state-reducer-v03.ts",
    "src/run/runtime-write-session-v03.ts",
  ])],
  ["src/run/runtime-manifest-v03.ts", new Set(["src/run/runtime-write-session-v03.ts"])],
  ["src/run/runtime-write-session-v03.ts", new Set([
    "src/run/runtime-action-admission-v03.ts",
    "src/run/runtime-effect-dispatch-broker-v01.ts",
    "src/run/runtime-execution-coordinator-v03.ts",
    "src/run/runtime-observation-integrity-v03.ts",
    "src/run/runtime-termination-v03.ts",
  ])],
  ["src/run/runtime-action-admission-v03.ts", new Set([
    "src/run/runtime-effect-dispatch-broker-v01.ts",
    "src/run/runtime-execution-coordinator-v03.ts",
  ])],
  ["src/run/runtime-effect-dispatch-broker-v01.ts", new Set([
    "src/run/runtime-execution-coordinator-v03.ts",
    "src/run/runtime-observation-integrity-v03.ts",
  ])],
  ["src/run/runtime-observation-integrity-v03.ts", new Set(["src/run/runtime-execution-coordinator-v03.ts"])],
  ["src/run/runtime-termination-v03.ts", new Set(["src/run/runtime-execution-coordinator-v03.ts"])],
  ["src/run/runtime-execution-coordinator-v03.ts", new Set()],
  [capturedExecutorModule, new Set()],
]);

const forbiddenBuiltins = new Map([
  ["child_process", "child-process-module"],
  ["fs", "filesystem-module"],
  ["fs/promises", "filesystem-module"],
  ["process", "ambient-environment"],
  ["net", "network-module"],
  ["http", "network-module"],
  ["https", "network-module"],
  ["http2", "network-module"],
  ["tls", "network-module"],
  ["dgram", "network-module"],
  ["os", "os-module"],
  ["module", "module-loader"],
  ["worker_threads", "worker-thread-module"],
]);
const forbiddenHostModuleWords = /(?:^|[^a-z0-9_])(?:mcp|tool-runner|workspace-writer|systemd|systemctl|cgroup|vps)(?:$|[^a-z0-9_])/iu;
const processEntryCalls = new Set(["exec", "execFile", "execSync", "fork", "spawn", "spawnSync"]);
const dynamicRuntimeCalls = new Set(["eval", "fetch", "Function", "WebSocket", "EventSource"]);
const directBrokerEntryNames = new Set(["captureEffectDispatchBrokerV01", "dispatchAdmittedActionV01"]);
const distSuffixes = Object.freeze([".js", ".js.map", ".d.ts", ".d.ts.map"]);

function projectPath(root, file) {
  return relative(root, file).split(sep).join("/");
}

function sourceFile(file, text = readFileSync(file, "utf8")) {
  return ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
}

function collectTypeScriptFiles(root) {
  const start = resolve(root, "src");
  if (!existsSync(start)) return [];
  const result = [];
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile() && entry.name.endsWith(".ts") && !entry.name.endsWith(".d.ts")) result.push(path);
    }
  };
  visit(start);
  return result.sort();
}

function moduleText(node) {
  return ts.isStringLiteralLike(node) ? node.text : undefined;
}

function normalizedBuiltin(specifier) {
  return specifier.startsWith("node:") ? specifier.slice(5) : specifier;
}

function resolveLocalModule(root, importer, specifier) {
  if (!specifier.startsWith(".")) return null;
  const raw = resolve(dirname(importer), specifier);
  const candidates = [raw];
  if (raw.endsWith(".js")) candidates.push(`${raw.slice(0, -3)}.ts`);
  else if (raw.endsWith(".mjs") || raw.endsWith(".cjs")) candidates.push(`${raw.slice(0, -4)}.ts`);
  else if (!/\.[cm]?[jt]s$/u.test(raw)) candidates.push(`${raw}.ts`, join(raw, "index.ts"));
  const found = candidates.find((candidate) => existsSync(candidate));
  return found === undefined ? null : projectPath(root, found);
}

function callName(expression) {
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) return expression.name.text;
  if (ts.isElementAccessExpression(expression) && expression.argumentExpression !== undefined) {
    return moduleText(expression.argumentExpression);
  }
  return undefined;
}

function isProcessEnvironmentAccess(node) {
  const isEnvMember = (candidate) => (
    (ts.isPropertyAccessExpression(candidate) && candidate.name.text === "env")
    || (ts.isElementAccessExpression(candidate) && moduleText(candidate.argumentExpression) === "env")
  );
  if (!isEnvMember(node)) return false;
  const base = node.expression;
  if (ts.isIdentifier(base) && base.text === "process") return true;
  return ts.isPropertyAccessExpression(base)
    && ts.isIdentifier(base.expression)
    && base.expression.text === "globalThis"
    && base.name.text === "process";
}

function inspectStrictBoundaryFile(root, file, violations) {
  const relativePath = projectPath(root, file);
  const ast = sourceFile(file);
  const visit = (node) => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier !== undefined) {
      const specifier = moduleText(node.moduleSpecifier);
      if (specifier !== undefined) {
        const builtin = normalizedBuiltin(specifier);
        if (forbiddenBuiltins.has(builtin)) violations.add(`${forbiddenBuiltins.get(builtin)}:${relativePath}`);
        if (forbiddenHostModuleWords.test(specifier)) violations.add(`forbidden-host-import:${relativePath}:${specifier}`);
      }
    }
    if (ts.isCallExpression(node)) {
      const name = callName(node.expression);
      if (node.expression.kind === ts.SyntaxKind.ImportKeyword) violations.add(`dynamic-import:${relativePath}`);
      if (name === "require") violations.add(`dynamic-require:${relativePath}`);
      if (name !== undefined && dynamicRuntimeCalls.has(name)) violations.add(`runtime-evaluation:${relativePath}:${name}`);
      if (name !== undefined && processEntryCalls.has(name)) violations.add(`process-host-access:${relativePath}:${name}`);
      if (name !== undefined && /^(?:systemd|systemctl|cgroup|vps)$/iu.test(name)) {
        violations.add(`host-control-call:${relativePath}:${name}`);
      }
      if (name === "dispatch" && relativePath !== "src/run/runtime-effect-dispatch-broker-v01.ts"
        && relativePath !== "src/run/runtime-execution-coordinator-v03.ts") {
        violations.add(`direct-effect-entry-outside-common-broker:${relativePath}`);
      }
    }
    if (isProcessEnvironmentAccess(node)) violations.add(`ambient-environment:${relativePath}`);
    ts.forEachChild(node, visit);
  };
  visit(ast);
}

function importBindings(statement) {
  if (!ts.isImportDeclaration(statement) || statement.importClause === undefined) return [];
  const clause = statement.importClause;
  const names = [];
  if (clause.name !== undefined) names.push(clause.name.text);
  if (clause.namedBindings !== undefined) {
    if (ts.isNamespaceImport(clause.namedBindings)) names.push(clause.namedBindings.name.text);
    else for (const item of clause.namedBindings.elements) names.push((item.propertyName ?? item.name).text, item.name.text);
  }
  return names;
}

function moduleReferences(ast) {
  const references = [];
  const visit = (node) => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier !== undefined) {
      const specifier = moduleText(node.moduleSpecifier);
      if (specifier !== undefined) references.push({ kind: ts.isExportDeclaration(node) ? "export" : "import", node, specifier });
    }
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === "require") {
      const specifier = node.arguments[0] === undefined ? undefined : moduleText(node.arguments[0]);
      if (specifier !== undefined) references.push({ kind: "require", node, specifier });
    }
    ts.forEachChild(node, visit);
  };
  visit(ast);
  return references;
}

function exportedNames(ast) {
  const names = new Set();
  for (const statement of ast.statements) {
    const modifiers = ts.canHaveModifiers(statement) ? ts.getModifiers(statement) : undefined;
    const exported = modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) ?? false;
    if (exported && "name" in statement && statement.name !== undefined && ts.isIdentifier(statement.name)) names.add(statement.name.text);
    if (ts.isExportDeclaration(statement) && statement.exportClause !== undefined && ts.isNamedExports(statement.exportClause)) {
      for (const element of statement.exportClause.elements) names.add(element.name.text, (element.propertyName ?? element.name).text);
    }
  }
  return names;
}

function inspectProductionGraph(root, violations) {
  const files = collectTypeScriptFiles(root);
  const parsed = new Map(files.map((file) => [projectPath(root, file), sourceFile(file)]));
  const exportsByFile = new Map([...parsed].map(([path, ast]) => [path, exportedNames(ast)]));

  for (const [path, ast] of parsed) {
    for (const reference of moduleReferences(ast)) {
      const target = resolveLocalModule(root, resolve(root, path), reference.specifier);
      if (target !== null && privateModules.has(target)) {
        const permitted = allowedProductionImporters.get(target)?.has(path) ?? false;
        if (!permitted) violations.add(`private-module-import-owner:${path}->${target}`);
        if (reference.kind === "export") violations.add(`private-module-export-laundering:${path}->${target}`);
        if (reference.kind === "require") violations.add(`private-module-commonjs-laundering:${path}->${target}`);
      }
      if (reference.kind === "import") {
        const names = importBindings(reference.node);
        if (reference.specifier.includes("/tests/") || reference.specifier.includes("/test-")
          || names.some((name) => /ForTest$/u.test(name))) {
          violations.add(`production-test-helper-import:${path}:${reference.specifier}`);
        }
        if (target === "src/run/runtime-effect-dispatch-broker-v01.ts"
          && path !== "src/run/runtime-execution-coordinator-v03.ts"
          && names.some((name) => directBrokerEntryNames.has(name))) {
          violations.add(`direct-effect-entry-outside-common-broker:${path}`);
        }
      }
    }
  }

  // Walk the root's re-export graph. Any barrel that reaches a private module,
  // including type-only or aliased exports, is public leakage.
  const seen = new Set();
  const walkPublicExports = (path) => {
    if (seen.has(path)) return;
    seen.add(path);
    const ast = parsed.get(path);
    if (ast === undefined) return;
    for (const reference of moduleReferences(ast).filter((entry) => entry.kind === "export")) {
      const target = resolveLocalModule(root, resolve(root, path), reference.specifier);
      if (target === null) continue;
      if (privateModules.has(target)) violations.add(`public-export-reaches-private-module:${path}->${target}`);
      walkPublicExports(target);
    }
    for (const statement of ast.statements) {
      if (!ts.isExportDeclaration(statement) || statement.moduleSpecifier !== undefined || statement.exportClause === undefined
        || !ts.isNamedExports(statement.exportClause)) continue;
      for (const element of statement.exportClause.elements) {
        const local = (element.propertyName ?? element.name).text;
        for (const [candidate, names] of exportsByFile) {
          if (privateModules.has(candidate) && names.has(local)) {
            violations.add(`public-export-private-symbol:${path}:${element.name.text}`);
          }
        }
      }
    }
  };
  walkPublicExports("src/index.ts");

  const rootAst = parsed.get("src/index.ts");
  if (rootAst !== undefined) {
    const privateNames = new Set([...exportsByFile].filter(([path]) => privateModules.has(path)).flatMap(([, names]) => [...names]));
    const visitCommonJs = (node) => {
      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        const left = node.left.getText(rootAst);
        const right = node.right.getText(rootAst);
        if ((left === "module.exports" || left.startsWith("exports."))
          && [...privateNames].some((name) => new RegExp(`\\b${name}\\b`, "u").test(right))) {
          violations.add(`package-root-commonjs-private-export:src/index.ts`);
        }
      }
      ts.forEachChild(node, visitCommonJs);
    };
    visitCommonJs(rootAst);
  }
}

function wildcardMatches(key, subpath) {
  const star = key.indexOf("*");
  if (star < 0) return key === subpath;
  return subpath.startsWith(key.slice(0, star)) && subpath.endsWith(key.slice(star + 1));
}

function exportTargets(value, result = []) {
  if (typeof value === "string") result.push(value);
  else if (Array.isArray(value)) for (const entry of value) exportTargets(entry, result);
  else if (value !== null && typeof value === "object") for (const entry of Object.values(value)) exportTargets(entry, result);
  return result;
}

function inspectPackage(root, violations) {
  const packagePath = resolve(root, "package.json");
  if (!existsSync(packagePath)) {
    violations.add("missing-package-json");
    return;
  }
  let metadata;
  try {
    metadata = JSON.parse(readFileSync(packagePath, "utf8"));
  } catch {
    violations.add("invalid-package-json");
    return;
  }
  const exportsMap = metadata.exports;
  if (exportsMap === null || typeof exportsMap !== "object" || Array.isArray(exportsMap)) {
    violations.add("missing-package-exports");
  } else {
    for (const sourcePath of privateModules) {
      const subpath = `./${sourcePath.replace(/^src\//u, "").replace(/\.ts$/u, "")}`;
      const distStem = `./dist/${sourcePath.replace(/^src\//u, "").replace(/\.ts$/u, "")}`;
      for (const [key, value] of Object.entries(exportsMap)) {
        if (wildcardMatches(key, subpath)) violations.add(`public-private-subpath-export:${key}->${subpath}`);
        for (const target of exportTargets(value)) {
          const expanded = key.includes("*") && target.includes("*")
            ? target.replace("*", subpath.slice(key.indexOf("*"), subpath.length - (key.length - key.indexOf("*") - 1)))
            : target;
          if (expanded === distStem || expanded.startsWith(`${distStem}.`)) {
            violations.add(`package-export-private-artifact:${key}:${target}`);
          }
        }
      }
    }
  }
  if (!Array.isArray(metadata.files) || !metadata.files.includes("dist")) {
    violations.add("private-dist-artifacts-not-packaged");
  }
}

function inspectDist(root, violations) {
  const privateNames = new Set();
  for (const sourcePath of privateModules) {
    const file = resolve(root, sourcePath);
    if (!existsSync(file)) continue;
    for (const name of exportedNames(sourceFile(file))) privateNames.add(name);
    const stem = resolve(root, `dist/${sourcePath.replace(/^src\//u, "").replace(/\.ts$/u, "")}`);
    for (const suffix of distSuffixes) {
      const artifact = `${stem}${suffix}`;
      if (!existsSync(artifact)) violations.add(`missing-private-dist-artifact:${projectPath(root, artifact)}`);
    }
  }
  const indexTypes = resolve(root, "dist/index.d.ts");
  if (!existsSync(indexTypes)) {
    violations.add("missing-dist-index-types:dist/index.d.ts");
    return;
  }
  const declaration = readFileSync(indexTypes, "utf8");
  const privateStems = [...privateModules].map((path) => path.replace(/^src\//u, "").replace(/\.ts$/u, ""));
  if (privateStems.some((stem) => declaration.includes(stem))
    || [...privateNames].some((name) => new RegExp(`\\b${name}\\b`, "u").test(declaration))) {
    violations.add("private-runtime-in-public-types:dist/index.d.ts");
  }
}

function inspectPins(root, violations) {
  for (const pin of sourcePins) {
    const file = resolve(root, pin.path);
    if (!existsSync(file)) {
      violations.add(`missing-source-guard:${pin.path}`);
      continue;
    }
    const actual = createHash("sha256").update(readFileSync(file)).digest("hex");
    if (actual !== pin.sha256) violations.add(`${pin.label}:mismatch:${actual}:${pin.path}`);
  }
}

export function runBoundaryCheck(options = {}) {
  const root = resolve(options.rootDir ?? repositoryRoot);
  const explicitTargets = options.targets?.map((file) => resolve(file)) ?? [];
  const targets = explicitTargets.length > 0 ? explicitTargets : strictBoundaryModules.map((path) => resolve(root, path));
  const violations = new Set();
  for (const file of targets) {
    if (!existsSync(file)) violations.add(`missing-s40-runtime-target:${projectPath(root, file)}`);
    else inspectStrictBoundaryFile(root, file, violations);
  }
  if (explicitTargets.length === 0) {
    inspectPins(root, violations);
    inspectProductionGraph(root, violations);
    inspectPackage(root, violations);
    inspectDist(root, violations);
  }
  return Object.freeze({
    rootDir: root,
    checkedFiles: Object.freeze(targets.map((file) => projectPath(root, file)).sort()),
    violations: Object.freeze([...violations].sort()),
  });
}

export function formatViolations(violations) {
  return violations.join("\n");
}

const executed = process.argv[1];
if (executed !== undefined && resolve(executed) === fileURLToPath(import.meta.url)) {
  const targets = process.argv.slice(2).map((path) => resolve(process.cwd(), path));
  const result = runBoundaryCheck({ rootDir: process.cwd(), targets });
  if (result.violations.length > 0) {
    process.stderr.write(`${formatViolations(result.violations)}\n`);
    process.exitCode = 1;
  }
}
