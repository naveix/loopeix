import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";

const roots: string[] = [];
const boundaryScript = resolve(process.cwd(), "scripts/check-s37-boundaries.mjs");
const canonicalPackageRoot = readFileSync(resolve(process.cwd(), "src/index.ts"), "utf8");
const v03RuntimeApiNames = [
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
] as const;
const f2AuthorityModules = [
  "s37-anchor-authorization-v03",
  "s37-product-host-lifecycle-v03",
] as const;
const f4AuthorityModules = [
  "s37-linux-launch-qualification-v03",
  "linux-host-enforcement-v03",
] as const;
const v03SchemaIds = [
  "s37-local-product-host-anchor-v03",
  "s37-product-host-lifecycle-state-v01",
  "s37-linux-launch-qualification-v03",
  "s37-product-host-bootstrap-inspection-v01",
  "s37-product-host-install-bundle-v01",
  "s37-product-host-qualification-request-v01",
  "s37-product-host-transition-lock-v01",
] as const;
const requiredV03CommandSeams = [
  "install-anchor.mjs",
  "transition-anchor.mjs",
  "issue-qualification.mjs",
  "reconcile-anchor.mjs",
] as const;

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function runBoundary(options: { cwd?: string; files?: string[] } = {}) {
  return spawnSync(process.execPath, [boundaryScript, ...(options.files ?? [])], {
    cwd: options.cwd ?? process.cwd(),
    encoding: "utf8",
    shell: false,
    timeout: 15_000,
    maxBuffer: 2 * 1024 * 1024,
  });
}

function writeFixture(root: string, entries: Record<string, string>) {
  for (const [relativePath, content] of Object.entries(entries)) {
    const file = join(root, relativePath);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, content);
  }
}

function createBaselineRepo(prefix: string, extraEntries: Record<string, string> = {}) {
  const root = mkdtempSync(join(tmpdir(), prefix));
  roots.push(root);
  const packageRootMutation = extraEntries["src/index.ts"] ?? "";
  const fixtureEntries = { ...extraEntries };
  delete fixtureEntries["src/index.ts"];
  writeFixture(root, {
    "src/index.ts": `${canonicalPackageRoot}${packageRootMutation}`,
    "src/run/pre-spawn-capability-broker-v02.ts": "export function enforceS37PreSpawnProbeV02() { return null; }\n",
    "src/run/engine.ts": "export function runEngine() { return null; }\n",
    "src/commands/run/start.ts": "export function runStart() { return null; }\n",
    ...Object.fromEntries(requiredV03CommandSeams.map((name) => [
      `scripts/s37-linux-product-host-v03/${name}`,
      "process.stderr.write(\"HOLD: S37.1-F command seam is not activated\\n\");\nprocess.exitCode = 64;\n",
    ])),
    ...fixtureEntries,
  });
  return root;
}

describe("S37 static pre-spawn boundary", () => {
  it.each(requiredV03CommandSeams)("requires the V03 command seam: %s", (name) => {
    const root = createBaselineRepo("loopeix-s37-boundary-v03-command-seam-");
    rmSync(join(root, "scripts/s37-linux-product-host-v03", name));

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(`missing-v03-command-seam: scripts/s37-linux-product-host-v03/${name}`);
  });

  it("keeps the broker and compatibility engine free of execution capabilities", () => {
    const result = runBoundary();
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("");
  });

  it("rejects process, filesystem, network, ambient environment, and tool-server traps", () => {
    const root = mkdtempSync(join(tmpdir(), "loopeix-s37-boundary-"));
    roots.push(root);
    const trap = join(root, "trap.ts");
    writeFileSync(trap, [
      'import "node:child_process";',
      'void import("node:fs");',
      'const network = require("node:https");',
      'import "./mcp-connector.js";',
      'import { createRequire } from "node:module";',
      'import { env } from "node:process";',
      "void process.env.SECRET;",
      'spawnSync("sh", []);',
      'void fetch("https://example.com");',
      'new WebSocket("wss://example.com");',
      'void import(moduleName);',
      'eval("ignored");',
    ].join("\n"));

    const result = runBoundary({ files: [trap] });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("child-process-module");
    expect(result.stderr).toContain("filesystem-module");
    expect(result.stderr).toContain("network-module");
    expect(result.stderr).toContain("module-loader");
    expect(result.stderr).toContain("spawn-or-exec");
    expect(result.stderr).toContain("ambient-environment");
    expect(result.stderr).toContain("global-network-api");
    expect(result.stderr).toContain("runtime-evaluation");
    expect(result.stderr).toContain("tool-or-connector-import");
  });

  it("ignores capability words that occur only in comments and strings", () => {
    const root = mkdtempSync(join(tmpdir(), "loopeix-s37-boundary-clean-"));
    roots.push(root);
    const clean = join(root, "clean.ts");
    writeFileSync(clean, [
      "// Never read process.env or call fetch here.",
      'const policyNote = "spawnSync( and WebSocket are prohibited";',
      "void policyNote;",
    ].join("\n"));

    const result = runBoundary({ files: [clean] });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toBe("");
  });

  it("rejects package-root exports of pre-spawn broker and Linux boundary names", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-export-", {
      "src/index.ts": 'export { prepareS37LinuxProbeAdmissionV02 } from "./run/pre-spawn-capability-broker-v02.js";\n',
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("package-root-forbidden-export:prepareS37LinuxProbeAdmissionV02");
  });

  it("rejects package-root exports of the Phase C local product entry", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-product-export-", {
      "src/index.ts": 'export { runS37LocalLinuxProductProbeV02 } from "./run/linux-host-enforcement-v02.js";\n',
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("package-root-linux-export: src/index.ts");
    expect(result.stderr).toContain("package-root-forbidden-export:runS37LocalLinuxProductProbeV02");
  });

  it("rejects package-root wildcard exports of the package-private broker", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-export-all-", {
      "src/index.ts": 'export * from "./run/pre-spawn-capability-broker-v02.js";\n',
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("package-root-broker-wildcard-export: src/index.ts");
  });

  it.each(v03RuntimeApiNames)("rejects every package-root V03 runtime API export: %s", (apiName) => {
    const root = createBaselineRepo("loopeix-s37-boundary-v03-api-export-", {
      "src/index.ts": `export { ${apiName} as publicApi } from "./run/other.js";\n`,
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(`package-root-forbidden-export:publicApi: src/index.ts`);
  });

  it.each([
    'export * from "./run/s37-product-host-contract-v03.js";',
    'export * as productHostContract from "./run/s37-product-host-contract-v03.js";',
    'export { harmlessName } from "./run/s37-product-host-contract-v03.js";',
  ])("rejects any package-root export path to the V03 contract: %s", (statement) => {
    const root = createBaselineRepo("loopeix-s37-boundary-v03-path-export-", {
      "src/index.ts": `${statement}\n`,
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("package-root-v03-contract-export: src/index.ts");
  });

  it("rejects package-root declarations and local alias exports of V03 runtime APIs", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-v03-local-export-", {
      "src/index.ts": [
        "export function canonicalV03() { return null; }",
        "const localParser = () => null;",
        "export { localParser as parseS37LocalProductHostAnchorV03 };",
      ].join("\n"),
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("package-root-forbidden-export:canonicalV03: src/index.ts");
    expect(result.stderr).toContain("package-root-forbidden-export:parseS37LocalProductHostAnchorV03: src/index.ts");
  });

  it("rejects laundering a V03 runtime API through imported and local aliases", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-v03-alias-laundering-", {
      "src/index.ts": [
        'import { canonicalV03 as importedContract } from "./run/other.js";',
        "const localAlias = importedContract;",
        "export { localAlias as harmlessPublicName };",
      ].join("\n"),
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("package-root-forbidden-export:harmlessPublicName: src/index.ts");
  });

  it("rejects exporting a forbidden namespace object under a harmless package-root name", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-v03-namespace-object-", {
      "src/index.ts": [
        'import * as barrel from "./run/barrel.js";',
        "export { barrel as harmless };",
      ].join("\n"),
      "src/run/barrel.ts": 'export { canonicalV03 } from "./s37-product-host-contract-v03.js";\n',
      "src/run/s37-product-host-contract-v03.ts": "export const canonicalV03 = (value: unknown) => value;\n",
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("package-root-source-digest:mismatch:");
    expect(result.stderr).toContain("package-root-forbidden-export:harmless: src/index.ts");
  });

  it("rejects a forbidden imported alias exported as the package default", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-v03-default-alias-", {
      "src/index.ts": [
        'import { canonicalV03 as localContract } from "./run/s37-product-host-contract-v03.js";',
        "export default localContract;",
      ].join("\n"),
      "src/run/s37-product-host-contract-v03.ts": "export const canonicalV03 = (value: unknown) => value;\n",
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("package-root-source-digest:mismatch:");
    expect(result.stderr).toContain("package-root-forbidden-export:default: src/index.ts");
  });

  it.each([
    "exports.harmless = localContract;",
    "module.exports = { harmless: localContract };",
  ])("rejects a forbidden imported alias laundered through CommonJS: %s", (commonJsExport) => {
    const root = createBaselineRepo("loopeix-s37-boundary-v03-cjs-alias-value-", {
      "src/index.ts": [
        'import { canonicalV03 as localContract } from "./run/s37-product-host-contract-v03.js";',
        commonJsExport,
      ].join("\n"),
      "src/run/s37-product-host-contract-v03.ts": "export const canonicalV03 = (value: unknown) => value;\n",
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("package-root-source-digest:mismatch:");
    expect(result.stderr).toContain("package-root-forbidden-export:harmless: src/index.ts");
  });

  it("fails closed when an otherwise harmless package-root comment changes canonical custody", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-package-root-custody-", {
      "src/index.ts": "// harmless unreviewed package-root mutation\n",
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("package-root-source-digest:mismatch:");
    expect(result.stderr).toContain(": src/index.ts");
  });

  it.each([
    [
      "intermediate named re-export alias",
      'export { harmlessAlias } from "./run/barrel.js";\n',
      'export { canonicalV03 as harmlessAlias } from "./s37-product-host-contract-v03.js";\n',
    ],
    [
      "intermediate wildcard re-export",
      'export * from "./run/barrel.js";\n',
      'export { canonicalV03 as harmlessAlias } from "./s37-product-host-contract-v03.js";\n',
    ],
    [
      "namespace property laundering",
      'import * as barrel from "./run/barrel.js";\nexport const harmlessAlias = barrel.canonicalV03;\n',
      'export { canonicalV03 } from "./s37-product-host-contract-v03.js";\n',
    ],
    [
      "cycle-safe wildcard traversal",
      'export * from "./run/barrel.js";\n',
      'export * from "./cycle.js";\nexport { canonicalV03 } from "./s37-product-host-contract-v03.js";\n',
    ],
  ])("rejects package-root V03 authority through %s", (_name, indexSource, barrelSource) => {
    const root = createBaselineRepo("loopeix-s37-boundary-v03-transitive-", {
      "src/index.ts": indexSource,
      "src/run/barrel.ts": barrelSource,
      "src/run/cycle.ts": 'export * from "./barrel.js";\n',
      "src/run/s37-product-host-contract-v03.ts": "export const canonicalV03 = (value: unknown) => value;\n",
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("package-root-forbidden-export:");
  });

  it.each([
    "exports.canonicalV03 = (value) => value;",
    "module.exports.canonicalV03 = (value) => value;",
    "module.exports = { canonicalV03: (value) => value };",
  ])("rejects package-root CommonJS V03 exports: %s", (source) => {
    const root = createBaselineRepo("loopeix-s37-boundary-v03-root-cjs-", {
      "src/index.ts": `${source}\n`,
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("package-root-forbidden-export:canonicalV03: src/index.ts");
  });

  it.each([
    "function parseS37LinuxLaunchQualificationV03(candidate) { return candidate; }",
    "const canonicalV03 = (value) => JSON.stringify(value);",
    "export function hashCanonicalV03(value) { return String(value); }",
    "const localVerify = () => true; export { localVerify as verifyS37LinuxLaunchQualificationSignatureV03 };",
    "exports.qualificationSigningBytesV03 = (value) => Buffer.from(String(value));",
  ])("rejects duplicate V03 contract API authority under scripts: %s", (source) => {
    const root = createBaselineRepo("loopeix-s37-boundary-v03-script-api-", {
      "scripts/nested/contract-copy.mjs": `${source}\n`,
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("script-v03-contract-api-authority: scripts/nested/contract-copy.mjs");
  });

  it.each([
    "module.exports = { canonicalV03: (value) => value };",
    "exports['canonicalV03'] = (value) => value;",
    "module.exports['canonicalV03'] = (value) => value;",
  ])("rejects duplicate CommonJS V03 contract authority under scripts: %s", (source) => {
    const root = createBaselineRepo("loopeix-s37-boundary-v03-script-cjs-", {
      "scripts/nested/contract-copy.cjs": `${source}\n`,
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("script-v03-contract-api-authority: scripts/nested/contract-copy.cjs");
  });

  it("rejects a script that embeds all seven V03 schema IDs as contract authority", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-v03-script-schemas-", {
      "scripts/schema-authority.ts": `const schemas = new Set(${JSON.stringify(v03SchemaIds)});\nvoid schemas;\n`,
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("script-v03-seven-schema-authority: scripts/schema-authority.ts");
  });

  it("allows a future script wrapper to import the built V03 contract without redefining it", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-v03-dist-wrapper-", {
      "scripts/product-wrapper.mjs": [
        'import { parseS37LinuxLaunchQualificationV03 } from "../dist/run/s37-product-host-contract-v03.js";',
        "const result = parseS37LinuxLaunchQualificationV03(JSON.parse(process.argv[2] ?? 'null'));",
        "process.stdout.write(JSON.stringify(result));",
      ].join("\n"),
    });

    const result = runBoundary({ cwd: root });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toBe("");
  });

  it.each(f2AuthorityModules)("rejects direct, wildcard, namespace, and default package-root exposure of %s", (moduleNeedle) => {
    for (const statement of [
      `export { harmless } from "./run/${moduleNeedle}.js";`,
      `export * from "./run/${moduleNeedle}.js";`,
      `export * as harmless from "./run/${moduleNeedle}.js";`,
      `import authority from "./run/${moduleNeedle}.js"; export default authority;`,
    ]) {
      const root = createBaselineRepo("loopeix-s37-boundary-f2-direct-", {
        "src/index.ts": `${statement}\n`,
        [`src/run/${moduleNeedle}.ts`]: "export const harmless = true; export default harmless;\n",
      });
      const result = runBoundary({ cwd: root });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("package-root-forbidden-export:");
    }
  });

  it.each(f2AuthorityModules)("rejects transitive and CommonJS laundering of %s", (moduleNeedle) => {
    const root = createBaselineRepo("loopeix-s37-boundary-f2-transitive-", {
      "src/index.ts": 'export * from "./run/barrel.js";\n',
      "src/run/barrel.ts": 'import * as authority from "./authority.js"; export { authority as harmless };\n',
      "src/run/authority.ts": `export * from "./${moduleNeedle}.js";\n`,
      [`src/run/${moduleNeedle}.ts`]: "export const harmlessInternal = true;\n",
    });
    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("package-root-forbidden-export:harmless");

    const cjsRoot = createBaselineRepo("loopeix-s37-boundary-f2-cjs-", {
      "src/index.ts": "module.exports = { observeS37ProductHostCustodyV03 };\n",
    });
    const cjsResult = runBoundary({ cwd: cjsRoot });
    expect(cjsResult.status).toBe(1);
    expect(cjsResult.stderr).toContain("package-root-forbidden-export:observeS37ProductHostCustodyV03");
  });

  it.each(f2AuthorityModules)("rejects transitive CommonJS require laundering of %s", (moduleNeedle) => {
    const root = createBaselineRepo("loopeix-s37-boundary-f2-cjs-transitive-", {
      "src/index.ts": 'const barrel = require("./run/barrel.js"); module.exports = { harmless: barrel.harmless };\n',
      "src/run/barrel.ts": `const authority = require("./${moduleNeedle}.js"); exports.harmless = authority.internal;\n`,
      [`src/run/${moduleNeedle}.ts`]: "export const internal = true;\n",
    });
    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("package-root-forbidden-export:harmless");
  });

  it.each(f2AuthorityModules)("rejects package.json subpath exposure of %s", (moduleNeedle) => {
    const root = createBaselineRepo("loopeix-s37-boundary-f2-package-map-", {
      "package.json": JSON.stringify({ exports: { [`./${moduleNeedle}`]: `./dist/run/${moduleNeedle}.js` } }),
    });
    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("package-export-v03-authority:");
  });

  it.each([
    "function authorizeS37AnchorMutationV03() { return null; }",
    "const applyS37ProductHostAnchorMutationV03 = () => null;",
    "exports.observeS37ProductHostCustodyV03 = () => null;",
  ])("rejects duplicate F2 authority under scripts: %s", (source) => {
    const root = createBaselineRepo("loopeix-s37-boundary-f2-script-authority-", {
      "scripts/f2-authority-copy.mjs": `${source}\n`,
    });
    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("script-v03-contract-api-authority:");
  });

  it.each([
    'import { issueAuthorizedS37AnchorMutationV03ForTest } from "./s37-anchor-authorization-v03.js";',
    'import * as authorization from "./s37-anchor-authorization-v03.js"; void authorization;',
    'export * from "./s37-anchor-authorization-v03.js";',
  ])("rejects production wiring of the test-only authorization mint: %s", (source) => {
    const root = createBaselineRepo("loopeix-s37-boundary-f2-test-mint-", {
      "src/run/production-consumer.ts": `${source}\n`,
    });
    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("production-test-capability-wiring: src/run/production-consumer.ts");
  });

  it("allows internal source modules to import the contract and non-test authorization APIs", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-f2-internal-import-", {
      "src/run/internal-lifecycle.ts": [
        'import { canonicalV03 } from "./s37-product-host-contract-v03.js";',
        'import { consumeAuthorizedS37AnchorMutationV03 } from "./s37-anchor-authorization-v03.js";',
        "void canonicalV03; void consumeAuthorizedS37AnchorMutationV03;",
      ].join("\n"),
    });
    const result = runBoundary({ cwd: root });
    expect(result.status, result.stderr).toBe(0);
  });

  it.each(f4AuthorityModules)("rejects all direct package-root exposure forms for F4 module %s", (moduleNeedle) => {
    for (const statement of [
      `export { harmless } from "./run/${moduleNeedle}.js";`,
      `export * from "./run/${moduleNeedle}.js";`,
      `export * as harmless from "./run/${moduleNeedle}.js";`,
      `import authority from "./run/${moduleNeedle}.js"; export default authority;`,
    ]) {
      const root = createBaselineRepo("loopeix-s37-boundary-f4-direct-", {
        "src/index.ts": `${statement}\n`,
        [`src/run/${moduleNeedle}.ts`]: "export const harmless = true; export default harmless;\n",
      });
      const result = runBoundary({ cwd: root });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("package-root-forbidden-export:");
    }
  });

  it.each(f4AuthorityModules)("rejects transitive ESM and CommonJS laundering of F4 module %s", (moduleNeedle) => {
    const esmRoot = createBaselineRepo("loopeix-s37-boundary-f4-esm-transitive-", {
      "src/index.ts": 'export * from "./run/barrel.js";\n',
      "src/run/barrel.ts": 'import * as authority from "./authority.js"; export { authority as harmless };\n',
      "src/run/authority.ts": `export * from "./${moduleNeedle}.js";\n`,
      [`src/run/${moduleNeedle}.ts`]: "export const internal = true;\n",
    });
    const esmResult = runBoundary({ cwd: esmRoot });
    expect(esmResult.status).toBe(1);
    expect(esmResult.stderr).toContain("package-root-forbidden-export:harmless");

    const cjsRoot = createBaselineRepo("loopeix-s37-boundary-f4-cjs-transitive-", {
      "src/index.ts": 'const barrel = require("./run/barrel.js"); module.exports = { harmless: barrel.harmless };\n',
      "src/run/barrel.ts": `const authority = require("./${moduleNeedle}.js"); exports.harmless = authority.internal;\n`,
      [`src/run/${moduleNeedle}.ts`]: "export const internal = true;\n",
    });
    const cjsResult = runBoundary({ cwd: cjsRoot });
    expect(cjsResult.status).toBe(1);
    expect(cjsResult.stderr).toContain("package-root-forbidden-export:harmless");
  });

  it.each(f4AuthorityModules)("rejects package.json subpath exposure of F4 module %s", (moduleNeedle) => {
    const root = createBaselineRepo("loopeix-s37-boundary-f4-package-map-", {
      "package.json": JSON.stringify({ exports: { [`./${moduleNeedle}`]: `./dist/run/${moduleNeedle}.js` } }),
    });
    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("package-export-v03-authority:");
  });

  it.each([
    "function issueS37LinuxLaunchQualificationV03() { return null; }",
    "const admitS37LinuxLaunchQualificationV03 = () => null;",
    "exports.runS37LocalLinuxProductProbeV03 = () => null;",
  ])("rejects duplicate F4 authority under scripts: %s", (source) => {
    const root = createBaselineRepo("loopeix-s37-boundary-f4-script-copy-", {
      "scripts/f4-authority-copy.mjs": `${source}\n`,
    });
    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("script-v03-contract-api-authority:");
  });

  it.each([
    'import { createS37LocalLinuxProductProbeV03ForTest } from "./linux-host-enforcement-v03.js";',
    'import * as runtime from "./linux-host-enforcement-v03.js"; void runtime;',
    'export * from "./linux-host-enforcement-v03.js";',
  ])("rejects production wiring of the F4 test-only runtime factory: %s", (source) => {
    const root = createBaselineRepo("loopeix-s37-boundary-f4-test-mint-", {
      "src/run/production-consumer.ts": `${source}\n`,
    });
    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("production-test-capability-wiring: src/run/production-consumer.ts");
  });

  it.each([
    'import { captureS37QualificationIssuerSignerV03 } from "../dist/run/s37-linux-launch-qualification-v03.js";',
    'import { captureS37QualificationBootObserverV03 } from "../dist/run/s37-linux-launch-qualification-v03.js";',
    'import { issueS37LinuxLaunchQualificationV03 } from "../dist/run/s37-linux-launch-qualification-v03.js"; const privateKeyPem = process.argv[2]; void issueS37LinuxLaunchQualificationV03; void privateKeyPem;',
    'import { issueS37LinuxLaunchQualificationV03 } from "../dist/run/s37-linux-launch-qualification-v03.js"; const observerCallback = () => null; void issueS37LinuxLaunchQualificationV03; void observerCallback;',
  ])("rejects raw F4 private-key or observer wiring under scripts: %s", (source) => {
    const root = createBaselineRepo("loopeix-s37-boundary-f4-raw-script-", {
      "scripts/f4-raw-authority.mjs": `${source}\n`,
    });
    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("script-v03-raw-authority-wiring:");
  });

  it("rejects raw F4 signer wiring in a compatibility CLI", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-f4-raw-cli-", {
      "src/commands/run/f4.ts": [
        'import { captureS37QualificationIssuerSignerV03 } from "../../run/s37-linux-launch-qualification-v03.js";',
        "export function runF4() { return captureS37QualificationIssuerSignerV03; }",
      ].join("\n"),
    });
    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("script-v03-raw-authority-wiring: src/commands/run/f4.ts");
  });

  it("rejects injected authority, observer, or runtime parameters on the production V03 entry", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-f4-injected-runtime-", {
      "src/run/linux-host-enforcement-v03.ts": [
        "export function runS37LocalLinuxProductProbeV03(input, authority, observer, runtime) {",
        '  return { reason: "ENFORCEMENT_UNAVAILABLE", process_started: false };',
        "}",
      ].join("\n"),
    });
    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("v03-production-runtime-injected-parameter:");
  });

  it("rejects production V03 activation or wiring through the test-only factory", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-f4-activation-", {
      "src/run/linux-host-enforcement-v03.ts": [
        "export function createS37LocalLinuxProductProbeV03ForTest() { return null; }",
        "export function runS37LocalLinuxProductProbeV03(input) {",
        "  void input; return createS37LocalLinuxProductProbeV03ForTest();",
        "}",
      ].join("\n"),
    });
    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("v03-production-runtime-s40-hold-missing:");
    expect(result.stderr).toContain("v03-production-runtime-test-mint-wiring:");
  });

  it("rejects side effects before an eventual production V03 HOLD", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-f4-work-before-hold-", {
      "src/run/linux-host-enforcement-v03.ts": [
        'const ENFORCEMENT_UNAVAILABLE = { reason: "ENFORCEMENT_UNAVAILABLE", process_started: false };',
        "function hold() { return ENFORCEMENT_UNAVAILABLE; }",
        "function doWork() { return null; }",
        "export function runS37LocalLinuxProductProbeV03(input) {",
        "  void input; doWork(); return hold();",
        "}",
      ].join("\n"),
    });
    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("v03-production-runtime-s40-hold-missing:");
  });

  it("permits the V03 runtime's exact internal imports while production remains S40 HOLD", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-f4-internal-imports-", {
      "src/run/linux-host-enforcement-v03.ts": [
        'import { admitS37LinuxLaunchQualificationV03 } from "./s37-linux-launch-qualification-v03.js";',
        'import { observeS37ProductHostCustodyV03 } from "./s37-product-host-lifecycle-v03.js";',
        'import { canonicalV03 } from "./s37-product-host-contract-v03.js";',
        'import { runS37LocalLinuxProductProbeV02 } from "./linux-host-enforcement-v02.js";',
        'const ENFORCEMENT_UNAVAILABLE = { reason: "ENFORCEMENT_UNAVAILABLE", process_started: false };',
        "function hold() { return ENFORCEMENT_UNAVAILABLE; }",
        "export function runS37LocalLinuxProductProbeV03(input) {",
        "  void input; void admitS37LinuxLaunchQualificationV03; void observeS37ProductHostCustodyV03;",
        "  void canonicalV03; void runS37LocalLinuxProductProbeV02;",
        "  return hold();",
        "}",
        "export function createS37LocalLinuxProductProbeV03ForTest() { return null; }",
      ].join("\n"),
    });
    const result = runBoundary({ cwd: root });
    expect(result.status, result.stderr).toBe(0);
  });

  it("rejects a direct bounded V02 launcher import from the V03 runtime", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-f4-bounded-import-", {
      "src/run/linux-host-enforcement-v03.ts": [
        'import { runBoundedS37LinuxProbeV02 } from "./bounded-linux-probe-v02.js";',
        "export function runS37LocalLinuxProductProbeV03(input) {",
        "  void input; void runBoundedS37LinuxProbeV02;",
        '  return { reason: "ENFORCEMENT_UNAVAILABLE", process_started: false };',
        "}",
      ].join("\n"),
    });
    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("bounded-launcher-import-outside-linux-owner: src/run/linux-host-enforcement-v03.ts");
  });

  it("rejects bounded launcher imports outside the Linux owner module", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-import-", {
      "src/run/not-allowed.ts": 'import "./bounded-linux-probe-v02.js";\n',
      "src/run/bounded-linux-probe-v02.ts": "export function runBoundedS37LinuxProbeV02() { return null; }\n",
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("bounded-launcher-import-outside-linux-owner: src/run/not-allowed.ts");
  });

  it.each([
    'import "../../run/linux-host-enforcement-v02.js";',
    'import { runS37LocalLinuxProductProbeV02 } from "../../run/linux-host-enforcement-v02.js";',
    'import localBackend from "../../run/linux-host-enforcement-v02.js";',
  ])("rejects real-path Linux module imports inside the compatibility CLI: %s", (statement) => {
    const root = createBaselineRepo("loopeix-s37-boundary-cli-", {
      "src/commands/run/start.ts": `${statement}\nexport function runStart() { return null; }\n`,
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("linux-module-import-in-engine-or-cli: src/commands/run/start.ts");
  });

  it("rejects shell:true and forbidden launcher commands inside Linux modules", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-shell-", {
      "src/run/linux-host-enforcement-v02.ts": 'export const launch = { shell: true };\n',
      "src/run/bounded-linux-probe-v02.ts": 'export function runBoundedS37LinuxProbeV02() { return null; }\n',
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("shell-true-in-linux-module: src/run/linux-host-enforcement-v02.ts");
  });

  it("rejects direct OS and spawn capabilities outside the sole Phase C Linux owner", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-linux-os-", {
      "src/run/bounded-linux-probe-v02.ts": 'import { spawn } from "node:child_process";\nexport const launch = () => spawn("/bin/true");\n',
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("child-process-module: src/run/bounded-linux-probe-v02.ts");
    expect(result.stderr).toContain("spawn-or-exec: src/run/bounded-linux-probe-v02.ts");
  });

  it("rejects dynamic loading, scope, pipe, or shell widening in the Phase C owner", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-owner-widening-", {
      "src/run/linux-host-enforcement-v02.ts": [
        'const child = require("node:child_process");',
        'export const widened = ["--scope", "--pipe", { shell: true }, child];',
      ].join("\n"),
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("module-loader: src/run/linux-host-enforcement-v02.ts");
    expect(result.stderr).toContain('forbidden-phase-c-owner-contract:"--scope"');
    expect(result.stderr).toContain('forbidden-phase-c-owner-contract:"--pipe"');
    expect(result.stderr).toContain("shell-true-in-linux-module: src/run/linux-host-enforcement-v02.ts");
  });

  it("rejects manager observation or process creation outside the admitted controller", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-preadmission-spawn-", {
      "src/run/linux-host-enforcement-v02.ts": [
        "export async function observeBeforeAdmission() {",
        "  await observeSystemdManagerVersion(1001);",
        "  return spawn('/usr/bin/systemctl', []);",
        "}",
      ].join("\n"),
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("phase-c-manager-observation-before-admitted-controller");
    expect(result.stderr).toContain("phase-c-spawn-outside-admitted-controller:observeBeforeAdmission");
  });

  it.each([
    ["manager observer", "      child = spawn(\n        SYSTEMCTL_PATH,", "      void spawn('/bin/sh', ['-c', 'true']);\n      child = spawn(\n        SYSTEMCTL_PATH,"],
    ["transient controller", "      child = spawn(invocation.command, [...invocation.args], invocation.options);", "      void spawn('/bin/sh', ['-c', 'true']);\n      child = spawn(invocation.command, [...invocation.args], invocation.options);"],
  ])("rejects an extra spawn inside the allowlisted %s", (_name, needle, replacement) => {
    const canonical = readFileSync(resolve(process.cwd(), "src/run/linux-host-enforcement-v02.ts"), "utf8");
    expect(canonical).toContain(needle);
    const root = createBaselineRepo("loopeix-s37-boundary-extra-owner-spawn-", {
      "src/run/linux-host-enforcement-v02.ts": canonical.replace(needle, replacement),
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("phase-c-spawn-call-count:expected-2:actual-3");
  });

  it("rejects local indirection of the spawn capability", () => {
    const canonical = readFileSync(resolve(process.cwd(), "src/run/linux-host-enforcement-v02.ts"), "utf8");
    const needle = "      child = spawn(\n        SYSTEMCTL_PATH,";
    const replacement = "      const launch = spawn;\n      void launch('/bin/sh', []);\n      child = spawn(\n        SYSTEMCTL_PATH,";
    expect(canonical).toContain(needle);
    const root = createBaselineRepo("loopeix-s37-boundary-spawn-alias-", {
      "src/run/linux-host-enforcement-v02.ts": canonical.replace(needle, replacement),
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("phase-c-spawn-reference-must-be-direct-callee");
  });

  it("rejects an additional aliased child-process import", () => {
    const canonical = readFileSync(resolve(process.cwd(), "src/run/linux-host-enforcement-v02.ts"), "utf8");
    const needle = 'import { spawn } from "node:child_process";';
    const replacement = `${needle}\nimport { spawn as launch } from "node:child_process";`;
    expect(canonical).toContain(needle);
    const root = createBaselineRepo("loopeix-s37-boundary-spawn-import-alias-", {
      "src/run/linux-host-enforcement-v02.ts": canonical.replace(needle, replacement),
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("phase-c-child-process-import-must-be-sole-unaliased-spawn");
  });

  it("rejects any extra OS-capability import in the Phase C owner", () => {
    const canonical = readFileSync(resolve(process.cwd(), "src/run/linux-host-enforcement-v02.ts"), "utf8");
    const needle = 'import { lstatSync, readFileSync } from "node:fs";';
    const replacement = 'import { lstatSync, readFileSync, writeFileSync } from "node:fs";';
    expect(canonical).toContain(needle);
    const root = createBaselineRepo("loopeix-s37-boundary-extra-os-import-", {
      "src/run/linux-host-enforcement-v02.ts": canonical.replace(needle, replacement),
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("phase-c-owner-import-surface-must-be-exact");
  });

  it.each([
    ["getBuiltinModule", '      const load = (process as any)["getBuiltinModule"];\n      const cp = load("node:child_process");\n      void cp["spawn"]("/bin/sh", []);'],
    ["binding", '      const load = (process as any)["binding"];\n      void load("spawn_sync");'],
  ])("rejects indirect ambient process capability acquisition through %s", (_name, extraCode) => {
    const canonical = readFileSync(resolve(process.cwd(), "src/run/linux-host-enforcement-v02.ts"), "utf8");
    const needle = "      child = spawn(\n        SYSTEMCTL_PATH,";
    expect(canonical).toContain(needle);
    const root = createBaselineRepo("loopeix-s37-boundary-process-loader-", {
      "src/run/linux-host-enforcement-v02.ts": canonical.replace(needle, `${extraCode}\n${needle}`),
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("phase-c-process-reference-must-be-current-uid-only");
  });

  it.each([
    ["Function", '      const Build = Function;\n      void Build("return process")();'],
    ["eval", '      const run = eval;\n      void run("process.getBuiltinModule(\\"node:child_process\\")");'],
  ])("rejects indirect runtime evaluation through %s", (name, extraCode) => {
    const canonical = readFileSync(resolve(process.cwd(), "src/run/linux-host-enforcement-v02.ts"), "utf8");
    const needle = "      child = spawn(\n        SYSTEMCTL_PATH,";
    expect(canonical).toContain(needle);
    const root = createBaselineRepo("loopeix-s37-boundary-runtime-eval-", {
      "src/run/linux-host-enforcement-v02.ts": canonical.replace(needle, `${extraCode}\n${needle}`),
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(`phase-c-runtime-evaluation-reference-forbidden:${name}`);
    expect(result.stderr).toContain("phase-c-owner-source-digest:mismatch");
  });

  it.each([
    [
      'import * as cp from "child_process";',
      '      void cp["spawn"]("/bin/sh", []);',
    ],
    [
      'import { execFile as launch } from "child_process";',
      '      void launch("/bin/sh", []);',
    ],
  ])("rejects a bare-specifier process-capability bypass: %s", (extraImport, extraCall) => {
    const canonical = readFileSync(resolve(process.cwd(), "src/run/linux-host-enforcement-v02.ts"), "utf8");
    const importNeedle = 'import { spawn } from "node:child_process";';
    const callNeedle = "      child = spawn(\n        SYSTEMCTL_PATH,";
    expect(canonical).toContain(importNeedle);
    expect(canonical).toContain(callNeedle);
    const mutated = canonical
      .replace(importNeedle, `${importNeedle}\n${extraImport}`)
      .replace(callNeedle, `${extraCall}\n${callNeedle}`);
    const root = createBaselineRepo("loopeix-s37-boundary-bare-process-import-", {
      "src/run/linux-host-enforcement-v02.ts": mutated,
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("phase-c-child-process-import-must-be-sole-unaliased-spawn");
  });

  it("rejects broker access to direct OS capability modules", () => {
    const root = createBaselineRepo("loopeix-s37-boundary-os-", {
      "src/run/pre-spawn-capability-broker-v02.ts": 'import "node:os";\nexport function enforceS37PreSpawnProbeV02() { return null; }\n',
    });

    const result = runBoundary({ cwd: root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("os-module: src/run/pre-spawn-capability-broker-v02.ts");
  });
});
