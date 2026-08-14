import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import ts from "typescript";

const defaultFiles = [
  "src/run/pre-spawn-capability-broker-v02.ts",
  "src/run/engine.ts",
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
  ["process", "ambient-environment"],
]);

const spawnNames = new Set(["spawn", "spawnSync", "exec", "execFile", "execFileSync", "fork"]);
const networkGlobals = new Set(["fetch", "WebSocket", "EventSource"]);
const runtimeEvaluationNames = new Set(["eval", "Function"]);

function unprefixedModuleName(value) {
  return value.startsWith("node:") ? value.slice(5) : value;
}

function recordModule(violations, file, value) {
  const moduleName = unprefixedModuleName(value);
  const label = forbiddenModules.get(moduleName);
  if (label !== undefined) violations.add(`${label}: ${file}`);
  if (/(?:mcp|connector|tool-runner|workspace-writer)/u.test(value)) {
    violations.add(`tool-or-connector-import: ${file}`);
  }
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

function inspectSource(file, source) {
  const sourceFile = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const violations = new Set();

  function visit(node) {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier !== undefined) {
      const specifier = literalModuleSpecifier(node.moduleSpecifier);
      if (specifier !== undefined) recordModule(violations, file, specifier);
    }

    if (
      ts.isImportEqualsDeclaration(node) &&
      ts.isExternalModuleReference(node.moduleReference) &&
      node.moduleReference.expression !== undefined
    ) {
      const specifier = literalModuleSpecifier(node.moduleReference.expression);
      if (specifier !== undefined) recordModule(violations, file, specifier);
    }

    if (ts.isCallExpression(node)) {
      const isDynamicImport = node.expression.kind === ts.SyntaxKind.ImportKeyword;
      const isRequire = ts.isIdentifier(node.expression) && node.expression.text === "require";
      if (isDynamicImport || isRequire) {
        const specifier = node.arguments[0] === undefined ? undefined : literalModuleSpecifier(node.arguments[0]);
        if (specifier === undefined) violations.add(`module-loader: ${file}`);
        else recordModule(violations, file, specifier);
      }

      const name = accessedName(node.expression);
      if (name !== undefined && spawnNames.has(name)) violations.add(`spawn-or-exec: ${file}`);
      if (name !== undefined && networkGlobals.has(name)) violations.add(`global-network-api: ${file}`);
      if (name !== undefined && runtimeEvaluationNames.has(name)) violations.add(`runtime-evaluation: ${file}`);
      if (name === "createRequire") violations.add(`module-loader: ${file}`);
    }

    if (ts.isNewExpression(node)) {
      const name = accessedName(node.expression);
      if (name !== undefined && networkGlobals.has(name)) violations.add(`global-network-api: ${file}`);
      if (name !== undefined && runtimeEvaluationNames.has(name)) violations.add(`runtime-evaluation: ${file}`);
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
      violations.add(`ambient-environment: ${file}`);
    }

    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  return violations;
}

const targets = process.argv.slice(2);
const files = (targets.length === 0 ? defaultFiles : targets).map((file) => resolve(file));
const violations = new Set();

for (const file of files) {
  const source = readFileSync(file, "utf8");
  for (const violation of inspectSource(file, source)) violations.add(violation);
}

if (violations.size > 0) {
  process.stderr.write(`${[...violations].join("\n")}\n`);
  process.exit(1);
}
