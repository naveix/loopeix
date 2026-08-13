import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  cpSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const MAX_TARBALL_BYTES = 67_108_864;
const MAX_MANIFEST_BYTES = 1_048_576;
const HARNESS_ID = "loopeix-s35-runtime-smoke-v01";
const EXPECTED_RECEIPT_SCHEMA_SHA256 = "99337cab3902c862f6777ad36afdabb9dd92a6105d23f2a88133af36d34cd5e5";
const PLANNED_RUN_MEMBERS = Object.freeze([
  "work-item.json", "binding-input.json", "intake-record.json", "catalog-resolution.json",
  "compilation-record.json", "compile-pack-manifest.json", "generated.loop.yaml",
  "intake-brief.json", "resolved-run-plan.json",
]);
function fail(message) { throw new Error(`S35 packed-package smoke failed: ${message}`); }
function assert(value, message) { if (!value) fail(message); }
function sha256(bytes) { return createHash("sha256").update(bytes).digest("hex"); }
function canonical(value) {
  const normalize = (input) => Array.isArray(input) ? input.map(normalize)
    : input !== null && typeof input === "object"
      ? Object.fromEntries(Object.keys(input).sort().map((key) => [key, normalize(input[key])]))
      : input;
  return `${JSON.stringify(normalize(value), null, 2)}\n`;
}
function exactKeys(value, keys) {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    && Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}
function parseArgs(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index]; const value = argv[index + 1];
    assert(["--mode", "--tarball", "--fixtures-root", "--harness-manifest"].includes(flag), `unknown argument ${flag}`);
    assert(value !== undefined && !values.has(flag), `invalid argument ${flag}`);
    values.set(flag, value);
  }
  const mode = values.get("--mode");
  const tarball = values.get("--tarball");
  const fixturesRoot = values.get("--fixtures-root");
  const harnessManifest = values.get("--harness-manifest");
  assert(mode === "full" || mode === "runtime", "--mode must be full or runtime");
  assert(typeof tarball === "string" && isAbsolute(tarball), "--tarball must be absolute");
  assert(typeof fixturesRoot === "string" && isAbsolute(fixturesRoot), "--fixtures-root must be absolute");
  assert(harnessManifest === undefined || (typeof harnessManifest === "string" && isAbsolute(harnessManifest)), "--harness-manifest must be absolute");
  assert(mode !== "runtime" || harnessManifest !== undefined, "runtime mode requires --harness-manifest");
  return {
    mode,
    tarball: resolve(tarball),
    fixturesRoot: resolve(fixturesRoot),
    harnessManifest: harnessManifest === undefined ? null : resolve(harnessManifest),
  };
}

function stableRegularBytes(path, label, maximum) {
  const before = lstatSync(path, { bigint: true });
  assert(before.isFile() && !before.isSymbolicLink(), `${label} is not a direct regular file`);
  assert(before.size <= BigInt(maximum), `${label} exceeds its byte ceiling`);
  const bytes = readFileSync(path);
  const after = statSync(path, { bigint: true });
  assert(before.dev === after.dev && before.ino === after.ino && before.size === after.size
    && before.mtimeNs === after.mtimeNs && BigInt(bytes.byteLength) === before.size, `${label} changed during capture`);
  return bytes;
}

function validateHarnessManifest(path, tarball, tarballBytes, fixturesRoot) {
  if (path === null) return;
  const bytes = stableRegularBytes(path, "harness manifest", MAX_MANIFEST_BYTES);
  let manifest;
  try { manifest = JSON.parse(bytes.toString("utf8")); }
  catch { fail("harness manifest is not valid JSON"); }
  assert(exactKeys(manifest, [
    "schema_version", "harness_id", "source_commit", "product_tarball_name",
    "product_tarball_sha256", "product_tarball_size_bytes", "smoke_script_path",
    "fixture_root", "files", "manifest_hash",
  ]), "harness manifest shape is invalid");
  assert(manifest.schema_version === "0.1" && manifest.harness_id === HARNESS_ID, "harness manifest identity drifted");
  assert(/^[0-9a-f]{40}$/.test(manifest.source_commit), "harness source commit is invalid");
  assert(manifest.product_tarball_name === basename(tarball), "harness product name binding drifted");
  assert(manifest.product_tarball_size_bytes === tarballBytes.byteLength, "harness product size binding drifted");
  assert(manifest.product_tarball_sha256 === sha256(tarballBytes), "harness product hash binding drifted");
  assert(manifest.smoke_script_path === "scripts/smoke-packed-package-s35.mjs", "harness smoke script path drifted");
  assert(typeof manifest.fixture_root === "string" && !manifest.fixture_root.includes("/") && !manifest.fixture_root.includes("\\"), "harness fixture root is unsafe");
  assert(resolve(join(resolve(path, ".."), manifest.fixture_root)) === fixturesRoot, "harness fixture root binding drifted");
  assert(Array.isArray(manifest.files) && manifest.files.length > 0, "harness file inventory is empty");
  const { manifest_hash: recordedHash, ...preimage } = manifest;
  assert(recordedHash === sha256(Buffer.from(canonical(preimage))), "harness manifest self-hash mismatch");
}

function requireCanonicalFixtures(root) {
  const required = [
    "common/s35-package-root-runtime-exports.txt",
    "common/s35-package-root-type-exports.txt",
    "common/s35-packed-paths.txt",
    "common/receipt.schema.json",
    "v02/authoring-valid.loop.yaml",
    "v02/authoring-invalid.loop.yaml",
    "v02/planned-run/work-item.json",
    "v02/planned-run/binding-input.json",
    "v02/planned-run/intake-record.json",
    "v02/planned-run/catalog-resolution.json",
    "v02/planned-run/compilation-record.json",
    "v02/planned-run/compile-pack-manifest.json",
    "v02/planned-run/generated.loop.yaml",
    "v02/planned-run/intake-brief.json",
    "v02/planned-run/resolved-run-plan.json",
  ];
  for (const name of required) {
    try { stableRegularBytes(join(root, name), `required fixture ${name}`, 33_554_432); }
    catch (error) {
      fail(`reviewed canonical fixture is missing or unsafe: ${name}${error instanceof Error ? ` (${error.message})` : ""}`);
    }
  }
}

const { mode, tarball, fixturesRoot, harnessManifest } = parseArgs(process.argv.slice(2));
const tarballBytes = stableRegularBytes(tarball, "product tarball", MAX_TARBALL_BYTES);
const tarballHash = sha256(tarballBytes);
const fixtureIdentity = statSync(fixturesRoot, { bigint: true });
assert(fixtureIdentity.isDirectory(), "fixture root is not a directory");
validateHarnessManifest(harnessManifest, tarball, tarballBytes, fixturesRoot);
requireCanonicalFixtures(fixturesRoot);
const canonicalFixturesRoot = realpathSync(fixturesRoot);
const fixtureVerifier = fileURLToPath(new URL("./verify-v02-fixtures-s35.mjs", import.meta.url));
let independentV02Receipt;
try {
  independentV02Receipt = JSON.parse(execFileSync(process.execPath, [fixtureVerifier, "--fixtures-root", canonicalFixturesRoot], {
    env: { HOME: tmpdir(), LANG: "C", LC_ALL: "C", PATH: process.env.PATH ?? "/usr/bin:/bin" },
    stdio: "pipe",
    timeout: 60_000,
    encoding: "utf8",
  }));
} catch { fail("independent no-product-import V02 fixture verification failed"); }
assert(exactKeys(independentV02Receipt, ["ok", "fixture_count", "planned_member_count", "run_id", "resolved_run_plan_hash"])
  && independentV02Receipt.ok === true && independentV02Receipt.fixture_count === 11
  && independentV02Receipt.planned_member_count === 9, "independent V02 fixture receipt drifted");

const scratch = mkdtempSync(join(tmpdir(), "loopeix-s35-packed-smoke-"));
chmodSync(scratch, 0o700);
let operationError;
try {
  const consumer = join(scratch, "consumer");
  mkdirSync(consumer, { mode: 0o700 });
  const retainedTarball = join(scratch, basename(tarball));
  writeFileSync(retainedTarball, tarballBytes, { mode: 0o600, flag: "wx" });
  writeFileSync(join(consumer, "package.json"), '{"name":"loopeix-s35-smoke","private":true,"type":"module"}\n', { mode: 0o600 });
  execFileSync("npm", [
    "install", "--ignore-scripts", "--no-audit", "--no-fund", "--package-lock=false", retainedTarball,
  ], {
    cwd: consumer,
    env: { HOME: scratch, LANG: "C", LC_ALL: "C", PATH: process.env.PATH ?? "/usr/bin:/bin", TMPDIR: scratch },
    stdio: "pipe",
    timeout: 300_000,
  });

  const probe = join(consumer, "probe.mjs");
  const expectedExports = readFileSync(
    join(fixturesRoot, "common", "s35-package-root-runtime-exports.txt"),
    "utf8",
  ).trim().split("\n");
  writeFileSync(probe, `
    import * as root from "loopeix";
    import { createRequire } from "node:module";
    import { readFileSync } from "node:fs";
    const completed = [];
    const fixture = (...parts) => ${JSON.stringify(fixturesRoot)} + "/" + parts.join("/");
    const expected = ${JSON.stringify(expectedExports)};
    const actual = Object.keys(root).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
    if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error("root runtime export inventory drifted");
    if (root.compilePrompt !== root.compilePromptV02) throw new Error("compilePrompt is not the V02 compiler");
    completed.push("root-export-inventory");

    const planned = JSON.parse(readFileSync(fixture("v02", "planned-run", "resolved-run-plan.json"), "utf8"));
    const parsedV02Plan = root.parseResolvedRunPlanDocument(planned);
    if (!parsedV02Plan.ok || parsedV02Plan.schema_version !== "0.2" || parsedV02Plan.execution_profile !== "bounded-v02") {
      throw new Error("installed V02 planned-run parse failed");
    }
    completed.push("v02-planned-run-parse");

    const replay = await root.replayCompilePack(${JSON.stringify(join(fixturesRoot, "v01", "compiled-safe-bugfix"))});
    if (!replay.ok || replay.schema_version !== "0.1" || replay.compared_member_count !== 7) throw new Error("installed V01 replay failed");
    if ("authority" in replay || "pack" in replay) throw new Error("private replay state leaked");
    completed.push("v01-replay-standard");

    const largeReplay = await root.replayCompilePack(fixture("v01", "large-compiled-pack"));
    if (!largeReplay.ok || largeReplay.schema_version !== "0.1" || largeReplay.compared_member_count !== 7) {
      throw new Error("installed oversized V01 compile-pack replay failed");
    }
    completed.push("v01-replay-oversized-compile-pack");

    const largePlan = JSON.parse(readFileSync(fixture("v01", "large-profileless-plan", "resolved-run-plan.json"), "utf8"));
    const parsedPlan = root.parseResolvedRunPlanDocument(largePlan);
    if (!parsedPlan.ok || parsedPlan.schema_version !== "0.1" || parsedPlan.execution_profile !== "legacy-v01") {
      throw new Error("installed oversized V01 plan parse failed");
    }
    completed.push("v01-plan-oversized-parse");

    const largeLedgerText = readFileSync(fixture("v01", "large-ledger", "ledger.jsonl"), "utf8");
    const parsedLedger = root.parseLedgerText(largeLedgerText);
    const recoveredLedger = root.recoverLedger(parsedLedger.events, {
      partialFinalLineDropped: parsedLedger.partialFinalLineDropped,
      corruptLines: parsedLedger.corruptLines,
    });
    if (recoveredLedger.integrity_status !== "valid" || recoveredLedger.run_state !== "completed"
      || recoveredLedger.last_valid_sequence !== 3 || !recoveredLedger.terminated) {
      throw new Error("installed oversized V01 ledger recovery failed");
    }
    completed.push("v01-ledger-oversized-recover");

    const reportInput = JSON.parse(readFileSync(fixture("v01", "large-report-input", "report-input.json"), "utf8"));
    const report = root.buildReport(reportInput);
    if (report.markdown !== readFileSync(fixture("v01", "large-report-input", "report.md"), "utf8")
      || report.html !== readFileSync(fixture("v01", "large-report-input", "report.html"), "utf8")) {
      throw new Error("installed oversized V01 report rebuild drifted");
    }
    completed.push("v01-report-oversized-build");

    const receiptText = readFileSync(fixture("v01", "large-receipt", "receipt.json"), "utf8");
    const receiptLedgerText = readFileSync(fixture("v01", "large-receipt", "ledger.jsonl"), "utf8");
    const receipt = root.verifyReceipt(receiptText, { ledgerText: receiptLedgerText });
    const expectedReceiptCheckIds = [
      "parse",
      "schema",
      "invariants",
      "doctrine",
      "signature",
      "ledger_hash",
      "ledger_head",
      "ledger_chain",
    ];
    if (!receipt.ok
      || receipt.checks.some((check) => !check.ok)
      || JSON.stringify(receipt.checks.map((check) => check.id)) !== JSON.stringify(expectedReceiptCheckIds)) {
      throw new Error("installed oversized V01 receipt verification failed");
    }
    completed.push("v01-receipt-oversized-verify");

    const require = createRequire(import.meta.url);
    for (const [subpath, id] of [
      ["loopeix/schemas/loopeix", "https://loopeix.dev/schemas/loopeix.schema.json"],
      ["loopeix/schemas/loopeix-0.1", "https://loopeix.dev/schemas/loopeix-0.1.schema.json"],
      ["loopeix/schemas/loopeix-0.2", "https://loopeix.dev/schemas/loopeix-0.2.schema.json"],
      ["loopeix/schemas/receipt", "https://loopeix.dev/schemas/receipt-0.1.schema.json"],
    ]) {
      const schema = JSON.parse(readFileSync(require.resolve(subpath), "utf8"));
      if (schema.$id !== id) throw new Error("schema ID drifted for " + subpath);
    }
    completed.push("schema-export-identities");

    let rejected = false;
    try { await import("loopeix/compiler/read-pack-v02"); }
    catch (error) { rejected = error?.code === "ERR_PACKAGE_PATH_NOT_EXPORTED"; }
    if (!rejected) throw new Error("private compiler subpath was importable");
    completed.push("private-subpath-rejection");
    process.stdout.write(JSON.stringify({ completed }) + "\\n");
  `, { mode: 0o600 });
  const probeOutput = execFileSync(process.execPath, [probe], {
    cwd: consumer,
    env: { HOME: scratch, LANG: "C", LC_ALL: "C", PATH: process.env.PATH ?? "/usr/bin:/bin", TMPDIR: scratch },
    stdio: "pipe",
    timeout: 300_000,
    encoding: "utf8",
  });
  let probeReceipt;
  try { probeReceipt = JSON.parse(probeOutput); }
  catch { fail("installed probe did not emit one JSON operation receipt"); }
  const expectedProbeOperations = [
    "root-export-inventory",
    "v02-planned-run-parse",
    "v01-replay-standard",
    "v01-replay-oversized-compile-pack",
    "v01-plan-oversized-parse",
    "v01-ledger-oversized-recover",
    "v01-report-oversized-build",
    "v01-receipt-oversized-verify",
    "schema-export-identities",
    "private-subpath-rejection",
  ];
  assert(exactKeys(probeReceipt, ["completed"])
    && JSON.stringify(probeReceipt.completed) === JSON.stringify(expectedProbeOperations),
  "installed probe operation receipt drifted");

  const installedRoot = join(consumer, "node_modules", "loopeix");
  assert(realpathSync(installedRoot) !== resolve(process.cwd()), "installed package resolved to the source worktree");
  const expectedReceiptBytes = readFileSync(join(fixturesRoot, "common", "receipt.schema.json"));
  assert(sha256(expectedReceiptBytes) === EXPECTED_RECEIPT_SCHEMA_SHA256, "reviewed receipt fixture drifted from the frozen V01 baseline");
  assert(sha256(readFileSync(join(installedRoot, "schemas", "receipt.schema.json"))) === sha256(expectedReceiptBytes),
    "receipt schema bytes drifted");
  for (const args of [["--help"], ["--version"]]) {
    execFileSync(process.execPath, [join(installedRoot, "bin", "run.js"), ...args], {
      cwd: consumer,
      env: { HOME: scratch, LANG: "C", LC_ALL: "C", PATH: process.env.PATH ?? "/usr/bin:/bin", TMPDIR: scratch },
      stdio: "pipe",
      timeout: 60_000,
    });
  }
  const doctor = JSON.parse(execFileSync(process.execPath, [join(installedRoot, "bin", "run.js"), "doctor", "--json"], {
    cwd: consumer,
    env: { HOME: scratch, LANG: "C", LC_ALL: "C", PATH: process.env.PATH ?? "/usr/bin:/bin", TMPDIR: scratch },
    stdio: "pipe",
    timeout: 60_000,
    encoding: "utf8",
  }));
  assert(exactKeys(doctor, ["node", "cli", "schemaBundled", "platform_supported", "filesystem_identity_supported", "ok", "checks", "disposition", "reason", "findings"])
    && doctor.ok === true && doctor.disposition === "pass" && doctor.reason === null
    && doctor.schemaBundled === true && doctor.platform_supported === true
    && doctor.filesystem_identity_supported === true && Array.isArray(doctor.findings) && doctor.findings.length === 0
    && Array.isArray(doctor.checks) && doctor.checks.map(({ id }) => id).join("|") === "node-runtime|package-version|platform|io-helper|schema-loopeix-v01|schema-loopeix-v02|schema-loopeix-dispatcher|schema-receipt"
    && doctor.checks.every((check) => exactKeys(check, ["id", "ok", "detail"]) && check.ok === true), "installed doctor success branch drifted");
  const installedBin = join(installedRoot, "bin", "run.js");
  const cli = (args) => spawnSync(process.execPath, [installedBin, ...args], {
    cwd: consumer,
    env: { HOME: scratch, LANG: "C", LC_ALL: "C", PATH: process.env.PATH ?? "/usr/bin:/bin", TMPDIR: scratch },
    encoding: "utf8",
    timeout: 120_000,
  });
  for (const json of [false, true]) {
    const validArgs = ["spec", "validate", join(fixturesRoot, "v02", "authoring-valid.loop.yaml"), ...(json ? ["--json"] : [])];
    const valid = cli(validArgs);
    assert(valid.status === 0, `installed valid V02 authoring validation failed${json ? " in JSON mode" : ""}`);
    const invalidArgs = ["spec", "validate", join(fixturesRoot, "v02", "authoring-invalid.loop.yaml"), ...(json ? ["--json"] : [])];
    const invalid = cli(invalidArgs);
    assert(invalid.status === 1, `installed invalid V02 authoring validation did not reject${json ? " in JSON mode" : ""}`);
    if (json) {
      const parsed = JSON.parse(valid.stdout);
      const rejected = JSON.parse(invalid.stdout);
      assert(parsed.ok === true && Array.isArray(parsed.errors) && parsed.errors.length === 0, "valid V02 JSON projection drifted");
      assert(rejected.ok === false && Array.isArray(rejected.errors) && rejected.errors.length > 0
        && rejected.errors.some((error) => error?.path === "limit_policy.max_tool_calls"
          && typeof error?.message === "string"
          && error.message.includes("expected number, received string")), "invalid V02 JSON projection drifted");
    }
  }

  const plannedSource = join(fixturesRoot, "v02", "planned-run");
  const plannedCopy = join(scratch, "planned-run-copy");
  cpSync(plannedSource, plannedCopy, { recursive: true, dereference: false, errorOnExist: true });
  const sourceHashesBefore = PLANNED_RUN_MEMBERS.map((name) => sha256(stableRegularBytes(join(plannedSource, name), `source planned member ${name}`, 33_554_432)));
  const start = cli(["run", "start", plannedCopy, "--engine", "codex"]);
  assert(start.status === 1 && start.stdout.includes("terminal: held") && start.stdout.includes("UNSUPPORTED_EXECUTION_PROFILE"), "installed V02 start did not return the mandatory HOLD");
  assert(readdirSync(plannedCopy).sort().join("\0") === [...PLANNED_RUN_MEMBERS].sort().join("\0"), "V02 start created a run artifact");
  const reportBuild = cli(["report", "build", plannedCopy]);
  assert(reportBuild.status === 0, "installed planned V02 report build failed");
  const reportOpen = cli(["report", "open", plannedCopy]);
  assert(reportOpen.status === 0 && reportOpen.stdout.includes("plan-report.html") && reportOpen.stdout.includes("file://"), "installed planned V02 report open failed");
  assert(readdirSync(plannedCopy).sort().join("\0") === [...PLANNED_RUN_MEMBERS, "plan-report-input.json", "plan-report.md", "plan-report.html"].sort().join("\0"), "planned report output inventory drifted");
  const sourceHashesAfter = PLANNED_RUN_MEMBERS.map((name) => sha256(stableRegularBytes(join(plannedSource, name), `source planned member ${name}`, 33_554_432)));
  assert(JSON.stringify(sourceHashesAfter) === JSON.stringify(sourceHashesBefore), "planned report smoke mutated the reviewed source fixtures");
  if (mode === "full") {
    const declaration = readFileSync(join(installedRoot, "dist", "index.d.ts"), "utf8");
    assert(declaration.includes("CompilePackReadResult") && declaration.includes("ReplayResult"), "public replay declarations are absent");
    execFileSync("npm", [
      "install", "--ignore-scripts", "--no-audit", "--no-fund", "--package-lock=false",
      "typescript@6.0.3", "ajv@8.20.0", "ajv-formats@3.0.1", "yaml@2.9.0",
    ], {
      cwd: consumer,
      env: { HOME: scratch, LANG: "C", LC_ALL: "C", PATH: process.env.PATH ?? "/usr/bin:/bin", TMPDIR: scratch },
      stdio: "pipe",
      timeout: 300_000,
    });
    const typeNames = readFileSync(join(fixturesRoot, "common", "s35-package-root-type-exports.txt"), "utf8").trim().split("\n");
    const typeConsumer = join(consumer, "type-consumer.ts");
    writeFileSync(typeConsumer, [
      `import type { ${typeNames.join(", ")} } from "loopeix";`,
      "export {};",
      "",
    ].join("\n"), { mode: 0o600 });
    writeFileSync(join(consumer, "tsconfig.json"), `${JSON.stringify({
      compilerOptions: {
        module: "NodeNext", moduleResolution: "NodeNext", target: "ES2024", strict: true,
        noEmit: true, skipLibCheck: true, verbatimModuleSyntax: true, types: [],
      },
      files: ["type-consumer.ts"],
    }, null, 2)}\n`, { mode: 0o600 });
    execFileSync(process.execPath, [join(consumer, "node_modules", "typescript", "bin", "tsc"), "--noEmit"], {
      cwd: consumer,
      env: { HOME: scratch, LANG: "C", LC_ALL: "C", PATH: process.env.PATH ?? "/usr/bin:/bin", TMPDIR: scratch },
      stdio: "pipe",
      timeout: 120_000,
    });

    const ajvProbe = join(consumer, "ajv-probe.mjs");
    writeFileSync(ajvProbe, `
      import Ajv2020 from "ajv/dist/2020.js";
      import addFormats from "ajv-formats";
      import { parse as parseYaml } from "yaml";
      import { createRequire } from "node:module";
      import { readFileSync } from "node:fs";
      const require = createRequire(import.meta.url);
      const readSchema = (name) => JSON.parse(readFileSync(require.resolve(name), "utf8"));
      const dispatcher = readSchema("loopeix/schemas/loopeix");
      const v01 = readSchema("loopeix/schemas/loopeix-0.1");
      const v02 = readSchema("loopeix/schemas/loopeix-0.2");
      const ajv = new Ajv2020({ allErrors: true, strict: true, strictTypes: false });
      addFormats(ajv);
      const compatibilityPolicy = "additive within a minor version; breaking changes bump the version";
      const supportedVersions = dispatcher["x-loopeix-supported-schema-versions"];
      if (JSON.stringify(supportedVersions) !== JSON.stringify(["0.1", "0.2"])) throw new Error("dispatcher version annotation drifted");
      if (v01["x-loopeix-schema-version"] !== "0.1" || v02["x-loopeix-schema-version"] !== "0.2") throw new Error("literal schema version annotation drifted");
      if ([dispatcher, v01, v02].some((schema) => schema["x-compatibility-policy"] !== compatibilityPolicy)) throw new Error("compatibility annotation drifted");
      for (const [keyword, schemaType] of [
        ["x-loopeix-supported-schema-versions", "array"],
        ["x-loopeix-schema-version", "string"],
        ["x-compatibility-policy", "string"],
      ]) ajv.addKeyword({ keyword, schemaType, valid: true });
      ajv.addSchema(v01).addSchema(v02);
      const validate = ajv.compile(dispatcher);
      if (ajv.getSchema(v01.$id) === undefined || ajv.getSchema(v02.$id) === undefined) throw new Error("literal schemas are not addressable by ID");
      const valid = parseYaml(readFileSync(${JSON.stringify(join(fixturesRoot, "v02", "authoring-valid.loop.yaml"))}, "utf8"));
      const invalid = parseYaml(readFileSync(${JSON.stringify(join(fixturesRoot, "v02", "authoring-invalid.loop.yaml"))}, "utf8"));
      if (!validate(valid) || validate(invalid)) throw new Error("AJV V02 fixture result drifted");
    `, { mode: 0o600 });
    execFileSync(process.execPath, [ajvProbe], {
      cwd: consumer,
      env: { HOME: scratch, LANG: "C", LC_ALL: "C", PATH: process.env.PATH ?? "/usr/bin:/bin", TMPDIR: scratch },
      stdio: "pipe",
      timeout: 120_000,
    });
  }
  const afterBytes = stableRegularBytes(tarball, "product tarball", MAX_TARBALL_BYTES);
  assert(sha256(afterBytes) === tarballHash && afterBytes.byteLength === tarballBytes.byteLength, "product tarball changed during smoke");
  process.stdout.write(`${JSON.stringify({
    ok: true,
    mode,
    tarball: basename(tarball),
    sha256: tarballHash,
    installed_probe_operations: expectedProbeOperations,
    independent_v02_fixture_hash: independentV02Receipt.resolved_run_plan_hash,
  })}\n`);
} catch (error) {
  operationError = error;
} finally {
  try { rmSync(scratch, { recursive: true, force: false }); }
  catch (cleanupError) {
    if (operationError === undefined) operationError = cleanupError;
    else operationError = new AggregateError([operationError, cleanupError], "smoke operation and cleanup both failed");
  }
}
if (operationError !== undefined) throw operationError;
