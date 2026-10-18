import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const privateModules = Object.freeze([
  "src/run/s37-product-host-activation-contract-v01.ts",
  "src/run/s37-product-host-activation-store-v01.ts",
  "src/run/s37-product-host-activation-v01.ts",
  "src/run/s37-product-host-launch-broker-v01.ts",
]);
const privateModuleSet = new Set(privateModules);
const activationModule = privateModules[2];
const brokerModule = privateModules[3];
const stableActivationAdapter = "scripts/s37-linux-product-host-v03/activate-stable.mjs";
const qualificationHoldAdapter = "scripts/s37-linux-product-host-v03/issue-qualification.mjs";
const activationAdapterModule = "../../dist/run/s37-product-host-activation-v01.js";
const activationAdapterTransportModule = "./activation-adapter-transport-v01.mjs";
const activationAdapterTransport = "scripts/s37-linux-product-host-v03/activation-adapter-transport-v01.mjs";
const activationAdapters = new Map([
  ["scripts/s37-linux-product-host-v03/install-anchor.mjs", Object.freeze({
    api: "installS37ProductHostV01",
    command: "commandS37ProductHostInstallAnchorV03",
    transport: true,
  })],
  ["scripts/s37-linux-product-host-v03/transition-anchor.mjs", Object.freeze({
    api: "transitionS37ProductHostV01",
    command: "commandS37ProductHostTransitionAnchorV03",
    transport: true,
  })],
  [stableActivationAdapter, Object.freeze({
    api: "activateStableS37ProductHostV01",
    command: "commandS37ProductHostActivateStableV01",
    transport: true,
  })],
  ["scripts/s37-linux-product-host-v03/reconcile-anchor.mjs", Object.freeze({
    api: "reconcileS37ProductHostActivationV01",
    command: "commandS37ProductHostReconcileAnchorV03",
    transport: true,
  })],
]);
const allowedAdapterBuiltins = new Set(["fs", "path", "url"]);
const permittedPrivateImporters = new Map([
  [privateModules[0], new Set([privateModules[1], privateModules[2], privateModules[3]])],
  [privateModules[1], new Set([privateModules[2]])],
  [privateModules[2], new Set()],
  [privateModules[3], new Set([privateModules[2]])],
]);
const requiredCompositionFunctions = new Map([
  ["installS37ProductHostV01", ["bundle_bytes", "proof_request_bytes", "qualification_intent_bytes"]],
  ["transitionS37ProductHostV01", ["bundle_bytes", "proof_request_bytes", "qualification_intent_bytes"]],
  ["activateStableS37ProductHostV01", ["proof_request_bytes", "qualification_intent_bytes"]],
  ["reconcileS37ProductHostActivationV01", []],
]);
const forbiddenCompositionFunction = /(?:issue.*Qualification|Qualification.*(?:Issue|ProductHost))/u;
const forbiddenBootstrapModule = /(?:(?:schema\/runtime-v03)|runtime-(?:manifest|write-session|action-admission|effect-dispatch-broker|observation-integrity|termination|execution-coordinator)-v03|brokered-model-executor-v01|runtime-[^/]*-v04|schema\/runtime-v04)(?:\.js)?$/u;
const forbiddenRunPermitName = /(?:DispatchPermitV01|RuntimeActionAdmission|CapturedRuntimeRunStore|RuntimeFileStoreV04)/u;
const networkBuiltins = new Set(["dgram", "dns", "http", "http2", "https", "net", "tls"]);
const processEntryNames = new Set(["exec", "execFile", "execSync", "fork", "spawn", "spawnSync"]);
const forbiddenCallerName = /(?:^|_)(?:callback|clock|cwd|directory|env|expected|file|filesystem|fs|host|key|path|pem|private_key|signer|time|trust)(?:_|$)/iu;
const testSeamName = /(?:ForTest|Synthetic|TestOnly)/u;
const forbiddenTransportText = /(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|private[_ -]?key[_ -]?(?:bytes|pem)|raw[_ -]?pem)/iu;
const rawKeyParameterText = /(?:\bpem\b|private[_A-Za-z0-9]*key|key[_A-Za-z0-9]*bytes|raw[_A-Za-z0-9]*key)/iu;
const forbiddenRemoteText = /(?:^|[^a-z0-9_])(?:container|docker|kubernetes|podman|remote|scp|ssh|tunnel|vps)(?:$|[^a-z0-9_])/iu;

function projectPath(root, file) {
  return relative(root, file).split(sep).join("/");
}

function parseSource(file) {
  const kind = file.endsWith(".mjs") ? ts.ScriptKind.JS : ts.ScriptKind.TS;
  return ts.createSourceFile(file, readFileSync(file, "utf8"), ts.ScriptTarget.Latest, true, kind);
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

function normalizeBuiltin(specifier) {
  return specifier.startsWith("node:") ? specifier.slice(5) : specifier;
}

function resolveLocalModule(root, importer, specifier) {
  if (!specifier.startsWith(".")) return null;
  const raw = resolve(dirname(importer), specifier);
  const candidates = [raw];
  if (raw.endsWith(".js")) candidates.push(raw.slice(0, -3) + ".ts");
  else if (raw.endsWith(".mjs") || raw.endsWith(".cjs")) candidates.push(raw.slice(0, -4) + ".ts");
  else if (!/\.[cm]?[jt]s$/u.test(raw)) candidates.push(raw + ".ts", join(raw, "index.ts"));
  const found = candidates.find((candidate) => existsSync(candidate));
  return found === undefined ? null : projectPath(root, found);
}

function importNames(statement) {
  if (!ts.isImportDeclaration(statement) || statement.importClause === undefined) return [];
  const result = [];
  const clause = statement.importClause;
  if (clause.name !== undefined) result.push(clause.name.text);
  if (clause.namedBindings !== undefined) {
    if (ts.isNamespaceImport(clause.namedBindings)) result.push(clause.namedBindings.name.text);
    else for (const element of clause.namedBindings.elements) {
      result.push((element.propertyName ?? element.name).text, element.name.text);
    }
  }
  return result;
}

function exactNamedImport(statement, expectedName) {
  if (!ts.isImportDeclaration(statement) || statement.importClause === undefined
    || statement.importClause.name !== undefined || statement.importClause.isTypeOnly) return false;
  const bindings = statement.importClause.namedBindings;
  return bindings !== undefined && ts.isNamedImports(bindings)
    && bindings.elements.length === 1 && !bindings.elements[0].isTypeOnly
    && bindings.elements[0].propertyName === undefined
    && bindings.elements[0].name.text === expectedName;
}

function references(ast) {
  const result = [];
  const visit = (node) => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier !== undefined) {
      const specifier = moduleText(node.moduleSpecifier);
      if (specifier !== undefined) {
        result.push({ kind: ts.isExportDeclaration(node) ? "export" : "import", node, specifier });
      }
    }
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === "require") {
      const specifier = node.arguments[0] === undefined ? undefined : moduleText(node.arguments[0]);
      if (specifier !== undefined) result.push({ kind: "require", node, specifier });
    }
    ts.forEachChild(node, visit);
  };
  visit(ast);
  return result;
}

function exportedNames(ast) {
  const result = new Set();
  for (const statement of ast.statements) {
    const modifiers = ts.canHaveModifiers(statement) ? ts.getModifiers(statement) : undefined;
    if (modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)
      && "name" in statement && statement.name !== undefined && ts.isIdentifier(statement.name)) {
      result.add(statement.name.text);
    }
    if (ts.isExportDeclaration(statement) && statement.exportClause !== undefined && ts.isNamedExports(statement.exportClause)) {
      for (const element of statement.exportClause.elements) result.add(element.name.text);
    }
  }
  return result;
}

function typeLiteralKeys(node) {
  if (node === undefined) return null;
  if (ts.isTypeLiteralNode(node)) {
    return node.members.flatMap((member) => {
      if (!ts.isPropertySignature(member) || member.name === undefined) return [];
      return ts.isIdentifier(member.name) || ts.isStringLiteralLike(member.name) ? [member.name.text] : [];
    });
  }
  if (ts.isTypeReferenceNode(node) && node.typeName.getText() === "Readonly" && node.typeArguments?.length === 1) {
    return typeLiteralKeys(node.typeArguments[0]);
  }
  return null;
}

function inspectCompositionSurface(ast, violations) {
  const found = new Map();
  for (const statement of ast.statements) {
    if (ts.isFunctionDeclaration(statement) && statement.name !== undefined) {
      found.set(statement.name.text, statement);
      const modifiers = ts.canHaveModifiers(statement) ? ts.getModifiers(statement) : undefined;
      const exported = modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) ?? false;
      if (exported && forbiddenCompositionFunction.test(statement.name.text)) {
        violations.add("standalone-production-qualification-api:" + activationModule + ":" + statement.name.text);
      }
    }
  }
  for (const [name, expectedKeys] of requiredCompositionFunctions) {
    const declaration = found.get(name);
    if (declaration === undefined) {
      violations.add("missing-composition-function:" + activationModule + ":" + name);
      continue;
    }
    const modifiers = ts.canHaveModifiers(declaration) ? ts.getModifiers(declaration) : undefined;
    if (!(modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) ?? false)) {
      violations.add("composition-function-not-exported:" + activationModule + ":" + name);
    }
    if (expectedKeys.length === 0) {
      if (declaration.parameters.length !== 0) violations.add("composition-input-arity:" + activationModule + ":" + name);
      continue;
    }
    if (declaration.parameters.length !== 1) {
      violations.add("composition-input-arity:" + activationModule + ":" + name);
      continue;
    }
    const keys = typeLiteralKeys(declaration.parameters[0].type);
    if (keys === null || keys.length !== expectedKeys.length || expectedKeys.some((key) => !keys.includes(key))) {
      violations.add("composition-input-keys:" + activationModule + ":" + name);
    }
    if (keys?.some((key) => forbiddenCallerName.test(key))) {
      violations.add("caller-controlled-authority-input:" + activationModule + ":" + name);
    }
  }
}

function inspectPrivateModule(root, path, ast, violations) {
  const file = resolve(root, path);
  const childProcessBindings = new Set();
  for (const reference of references(ast)) {
    const builtin = normalizeBuiltin(reference.specifier);
    if (networkBuiltins.has(builtin) || /(?:ssh|remote|tunnel|container|docker|podman)/iu.test(reference.specifier)) {
      violations.add("remote-or-network-import:" + path + ":" + reference.specifier);
    }
    if (builtin === "process") violations.add("ambient-process-import:" + path);
    if (builtin === "child_process" && path !== brokerModule) violations.add("process-entry-import-outside-broker:" + path);
    if (builtin === "child_process" && reference.kind === "import") {
      for (const name of importNames(reference.node)) childProcessBindings.add(name);
    }
    const target = resolveLocalModule(root, file, reference.specifier);
    if (target !== null && privateModuleSet.has(target)) {
      const base = target.slice(target.lastIndexOf("/") + 1).replace(/\.ts$/u, ".js");
      if (reference.specifier !== "./" + base) {
        violations.add("non-exact-private-import:" + path + "->" + target + ":" + reference.specifier);
      }
    }
    if (/linux-host-enforcement-v02(?:\.js)?$/u.test(reference.specifier)) {
      violations.add("v02-host-fallback:" + path + ":" + reference.specifier);
    }
    if (forbiddenBootstrapModule.test(reference.specifier)) {
      violations.add("s40-s41-bootstrap-dependency:" + path + ":" + reference.specifier);
    }
    if (reference.kind === "import" && importNames(reference.node).some((name) => forbiddenRunPermitName.test(name))) {
      violations.add("non-activation-launch-permit:" + path + ":" + reference.specifier);
    }
    if (reference.kind === "import" && importNames(reference.node).some((name) => testSeamName.test(name))) {
      violations.add("production-test-seam-import:" + path + ":" + reference.specifier);
    }
    if (reference.kind === "require") violations.add("dynamic-require:" + path);
  }
  const visit = (node) => {
    if ((ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node))
      && node.name !== undefined && !testSeamName.test(node.name.getText(ast))) {
      const modifiers = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined;
      const exported = modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) ?? false;
      if (exported && node.parameters.some((parameter) => rawKeyParameterText.test(parameter.getText(ast)))) {
        violations.add("raw-private-key-parameter:" + path + ":" + node.name.getText(ast));
      }
      if (path === privateModules[1] && exported && /capture.*ActivationStore/iu.test(node.name.getText(ast))
        && node.parameters.length !== 0) {
        violations.add("caller-controlled-store-capture:" + path + ":" + node.name.getText(ast));
      }
    }
    if (ts.isCallExpression(node)) {
      if (node.expression.kind === ts.SyntaxKind.ImportKeyword) violations.add("dynamic-import:" + path);
      if (ts.isIdentifier(node.expression) && testSeamName.test(node.expression.text)) {
        violations.add("production-test-seam-call:" + path + ":" + node.expression.text);
      }
      if (ts.isIdentifier(node.expression) && childProcessBindings.has(node.expression.text)
        && processEntryNames.has(node.expression.text) && path !== brokerModule) {
        violations.add("direct-process-entry-outside-broker:" + path + ":" + node.expression.text);
      }
    }
    if (ts.isPropertyAccessExpression(node)
      && ts.isIdentifier(node.expression) && node.expression.text === "process"
      && ["argv", "env", "stdin"].includes(node.name.text)) {
      violations.add("raw-key-transport-surface:" + path + ":process." + node.name.text);
    }
    if (ts.isStringLiteralLike(node) && forbiddenTransportText.test(node.text)) {
      violations.add("raw-private-key-transport:" + path);
    }
    if (ts.isStringLiteralLike(node) && forbiddenRemoteText.test(node.text)) {
      violations.add("remote-or-container-surface:" + path);
    }
    if (ts.isIdentifier(node) && forbiddenRemoteText.test(node.text)) {
      violations.add("remote-or-container-surface:" + path);
    }
    if (ts.isIdentifier(node) && forbiddenRunPermitName.test(node.text)) {
      violations.add("non-activation-launch-permit:" + path + ":" + node.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(ast);
  for (const node of ast.statements) {
    if (/\bshell\s*:\s*true\b/u.test(node.getText(ast))) violations.add("shell-process-entry:" + path);
  }
  if (path === activationModule) inspectCompositionSurface(ast, violations);
}

function inspectBrokerProcessEntry(ast, violations) {
  const childProcessReferences = references(ast).filter((reference) =>
    normalizeBuiltin(reference.specifier) === "child_process");
  if (childProcessReferences.length === 0) return;
  const onlyReference = childProcessReferences.length === 1 ? childProcessReferences[0] : undefined;
  if (onlyReference === undefined || onlyReference.kind !== "import"
    || onlyReference.specifier !== "node:child_process"
    || !exactNamedImport(onlyReference.node, "spawn")) {
    violations.add("broker-process-entry-import-must-be-sole-unaliased-spawn:" + brokerModule);
  }
}

function inspectActivationAdapter(root, path, policy, violations) {
  const file = resolve(root, path);
  if (!existsSync(file)) {
    violations.add("missing-s37-activation-adapter:" + path);
    return;
  }
  const ast = parseSource(file);
  if (ast.parseDiagnostics.length > 0) {
    violations.add("activation-adapter-parse-error:" + path);
    return;
  }

  const imports = ast.statements.filter(ts.isImportDeclaration);
  const activationImports = imports.filter((statement) => moduleText(statement.moduleSpecifier) === activationAdapterModule);
  if (policy.api !== null && (activationImports.length !== 1 || !exactNamedImport(activationImports[0], policy.api))) {
    violations.add("activation-adapter-api-import-must-be-exact:" + path);
  }
  if (policy.api === null && activationImports.length !== 0) {
    violations.add("activation-adapter-api-import-forbidden:" + path);
  }
  const transportImports = imports.filter((statement) => moduleText(statement.moduleSpecifier) === activationAdapterTransportModule);
  if (policy.transport && (transportImports.length !== 1
    || !exactNamedImport(transportImports[0], "runS37ProductHostActivationAdapterTransportV01"))) {
    violations.add("activation-adapter-transport-import-must-be-exact:" + path);
  }
  if (!policy.transport && transportImports.length !== 0) {
    violations.add("activation-adapter-transport-forbidden:" + path);
  }
  for (const statement of imports) {
    const specifier = moduleText(statement.moduleSpecifier);
    if (specifier === undefined) {
      violations.add("activation-adapter-nonliteral-import:" + path);
      continue;
    }
    if (specifier === activationAdapterModule) continue;
    if (specifier === activationAdapterTransportModule
      && exactNamedImport(statement, "runS37ProductHostActivationAdapterTransportV01")) continue;
    const builtin = normalizeBuiltin(specifier);
    if (!specifier.startsWith("node:") || !allowedAdapterBuiltins.has(builtin)) {
      violations.add("activation-adapter-import-not-allowlisted:" + path + ":" + specifier);
    }
  }

  const exports = exportedNames(ast);
  if (exports.size !== 1 || !exports.has(policy.command)) {
    violations.add("activation-adapter-export-surface-must-be-exact:" + path);
  }
  if (ast.statements.some((statement) => {
    const modifiers = ts.canHaveModifiers(statement) ? ts.getModifiers(statement) : undefined;
    return modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.DefaultKeyword) ?? false;
  })) {
    violations.add("activation-adapter-default-export-forbidden:" + path);
  }
  if (ast.statements.some((statement) => ts.isExportDeclaration(statement))) {
    violations.add("activation-adapter-reexport-forbidden:" + path);
  }

  const commandDeclaration = ast.statements.find((statement) =>
    ts.isFunctionDeclaration(statement) && statement.name?.text === policy.command);
  if (commandDeclaration === undefined) {
    violations.add("activation-adapter-command-must-be-function:" + path);
  }
  let apiCalls = 0;
  let commandApiCalls = 0;
  const visit = (node) => {
    if (ts.isCallExpression(node)) {
      if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        violations.add("activation-adapter-dynamic-import:" + path);
      }
      if (ts.isIdentifier(node.expression)) {
        if (node.expression.text === "require") violations.add("activation-adapter-require:" + path);
        if (policy.api !== null && node.expression.text === policy.api) {
          apiCalls += 1;
          let owner = node.parent;
          while (owner !== undefined && !ts.isFunctionLike(owner)) owner = owner.parent;
          if (owner === commandDeclaration) commandApiCalls += 1;
        }
        if (processEntryNames.has(node.expression.text)) {
          violations.add("activation-adapter-process-entry:" + path + ":" + node.expression.text);
        }
        if (node.expression.text === "eval" || node.expression.text === "Function") {
          violations.add("activation-adapter-code-generation:" + path + ":" + node.expression.text);
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(ast);
  if (policy.api !== null && (apiCalls !== 1 || commandApiCalls !== 1)) {
    violations.add("activation-adapter-api-call-must-be-exactly-once-in-command:" + path);
  }
  const source = ast.getFullText();
  const required = ["const HOLD = Object.freeze(", "input === undefined", "return HOLD;"];
  if (required.some((snippet) => !source.includes(snippet))) {
    violations.add("activation-adapter-direct-hold-compatibility-missing:" + path);
  }
}

function inspectActivationAdapterTransport(root, violations) {
  const file = resolve(root, activationAdapterTransport);
  if (!existsSync(file)) {
    violations.add("missing-s37-activation-adapter-transport:" + activationAdapterTransport);
    return;
  }
  const ast = parseSource(file);
  if (ast.parseDiagnostics.length > 0) {
    violations.add("activation-adapter-transport-parse-error:" + activationAdapterTransport);
    return;
  }
  if (references(ast).length !== 0) {
    violations.add("activation-adapter-transport-import-forbidden:" + activationAdapterTransport);
  }
  const exports = exportedNames(ast);
  if (exports.size !== 1 || !exports.has("runS37ProductHostActivationAdapterTransportV01")) {
    violations.add("activation-adapter-transport-export-surface-must-be-exact:" + activationAdapterTransport);
  }
  const source = ast.getFullText();
  if (/\bprocess\s*\./u.test(source)) {
    violations.add("activation-adapter-transport-ambient-process:" + activationAdapterTransport);
  }
  const visit = (node) => {
    if (ts.isCallExpression(node)) {
      if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        violations.add("activation-adapter-transport-dynamic-import:" + activationAdapterTransport);
      }
      if (ts.isIdentifier(node.expression)) {
        if (node.expression.text === "require") violations.add("activation-adapter-transport-require:" + activationAdapterTransport);
        if (processEntryNames.has(node.expression.text)) {
          violations.add("activation-adapter-transport-process-entry:" + activationAdapterTransport + ":" + node.expression.text);
        }
        if (node.expression.text === "eval" || node.expression.text === "Function") {
          violations.add("activation-adapter-transport-code-generation:" + activationAdapterTransport + ":" + node.expression.text);
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(ast);
}

function inspectGraph(root, parsed, violations) {
  const exportsByPrivateFile = new Map(
    [...parsed].filter(([path]) => privateModuleSet.has(path)).map(([path, ast]) => [path, exportedNames(ast)]),
  );
  for (const [path, ast] of parsed) {
    for (const reference of references(ast)) {
      const target = resolveLocalModule(root, resolve(root, path), reference.specifier);
      if (target === null || !privateModuleSet.has(target)) continue;
      if (reference.kind !== "import") violations.add("private-module-export-or-require:" + path + "->" + target);
      if (!(permittedPrivateImporters.get(target)?.has(path) ?? false)) {
        violations.add("private-module-import-owner:" + path + "->" + target);
      }
      if (reference.kind === "import" && importNames(reference.node).some((name) => testSeamName.test(name))) {
        violations.add("production-private-test-seam-import:" + path + "->" + target);
      }
    }
  }
  const seen = new Set();
  const walkExports = (path) => {
    if (seen.has(path)) return;
    seen.add(path);
    const ast = parsed.get(path);
    if (ast === undefined) return;
    for (const reference of references(ast).filter((entry) => entry.kind === "export")) {
      const target = resolveLocalModule(root, resolve(root, path), reference.specifier);
      if (target === null) continue;
      if (privateModuleSet.has(target)) violations.add("public-export-reaches-private-module:" + path + "->" + target);
      walkExports(target);
    }
  };
  walkExports("src/index.ts");
  const rootAst = parsed.get("src/index.ts");
  if (rootAst !== undefined) {
    const rootText = rootAst.getFullText();
    const privateNames = new Set([...exportsByPrivateFile.values()].flatMap((names) => [...names]));
    if ([...privateNames].some((name) => new RegExp("\\b" + name + "\\b", "u").test(rootText))) {
      violations.add("public-index-private-symbol:src/index.ts");
    }
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
  const path = resolve(root, "package.json");
  if (!existsSync(path)) {
    violations.add("missing-package-json");
    return;
  }
  let metadata;
  try {
    metadata = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    violations.add("invalid-package-json");
    return;
  }
  if (metadata.exports === null || typeof metadata.exports !== "object" || Array.isArray(metadata.exports)) {
    violations.add("missing-package-exports");
    return;
  }
  for (const sourcePath of privateModules) {
    const subpath = "./" + sourcePath.replace(/^src\//u, "").replace(/\.ts$/u, "");
    const distStem = "./dist/" + sourcePath.replace(/^src\//u, "").replace(/\.ts$/u, "");
    for (const [key, value] of Object.entries(metadata.exports)) {
      if (wildcardMatches(key, subpath)) violations.add("public-private-subpath-export:" + key + "->" + subpath);
      if (exportTargets(value).some((target) => target === distStem || target.startsWith(distStem + "."))) {
        violations.add("package-export-private-artifact:" + key + ":" + distStem);
      }
    }
  }
}

function inspectQualificationHold(root, violations) {
  const path = resolve(root, qualificationHoldAdapter);
  if (!existsSync(path)) {
    violations.add("missing-qualification-hold-adapter:" + qualificationHoldAdapter);
    return;
  }
  const source = readFileSync(path, "utf8");
  const required = [
    "const HOLD = Object.freeze(",
    "commandS37ProductHostIssueQualificationV03",
    "return HOLD;",
    "HOLD:",
    "process.exitCode = 64",
  ];
  if (required.some((snippet) => !source.includes(snippet))) {
    violations.add("qualification-command-not-unconditional-hold:" + qualificationHoldAdapter);
  }
  if (source.includes("s37-product-host-activation-v01")) {
    violations.add("qualification-command-imports-production-activation:" + qualificationHoldAdapter);
  }
}

export function runS37ProductHostActivationBoundaryCheck(options = {}) {
  const root = resolve(options.rootDir ?? repositoryRoot);
  const violations = new Set();
  for (const path of privateModules) {
    if (!existsSync(resolve(root, path))) violations.add("missing-s37-activation-module:" + path);
  }
  const parsed = new Map(collectTypeScriptFiles(root).map((file) => [projectPath(root, file), parseSource(file)]));
  for (const path of privateModules) {
    const ast = parsed.get(path);
    if (ast !== undefined) inspectPrivateModule(root, path, ast, violations);
  }
  const brokerAst = parsed.get(brokerModule);
  if (brokerAst !== undefined) inspectBrokerProcessEntry(brokerAst, violations);
  inspectActivationAdapterTransport(root, violations);
  for (const [path, policy] of activationAdapters) inspectActivationAdapter(root, path, policy, violations);
  inspectGraph(root, parsed, violations);
  inspectPackage(root, violations);
  inspectQualificationHold(root, violations);
  return Object.freeze({
    rootDir: root,
    checkedFiles: privateModules,
    violations: Object.freeze([...violations].sort()),
  });
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = runS37ProductHostActivationBoundaryCheck({ rootDir: process.cwd() });
  if (result.violations.length > 0) {
    process.stderr.write(result.violations.join("\n") + "\n");
    process.exitCode = 1;
  } else {
    process.stdout.write("S37 product-host activation boundary check passed\n");
  }
}
