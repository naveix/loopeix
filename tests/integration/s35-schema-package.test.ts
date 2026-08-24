import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const repositoryRoot = join(import.meta.dirname, "../..");
const fixtureRoot = join(repositoryRoot, "tests/fixtures/compat/s35/v01");
const commonFixtureRoot = join(repositoryRoot, "tests/fixtures/compat/s35/common");
const expectedReceiptSchemaSha256 = "99337cab3902c862f6777ad36afdabb9dd92a6105d23f2a88133af36d34cd5e5";
const s40PrivateGeneratedModules = [
  "run/brokered-model-executor-v01",
  "run/runtime-durability-policy-v03",
  "run/runtime-ledger-dispatch",
  "run/runtime-ledger-migration-v02-v03",
  "run/runtime-ledger-v03",
  "run/runtime-state-reducer-v03",
  "schema/runtime-v03",
] as const;

function oracle(name: string): string[] {
  return readFileSync(join(fixtureRoot, name), "utf8").trim().split("\n");
}

function commonOracle(name: string): string[] {
  return readFileSync(join(commonFixtureRoot, name), "utf8").trim().split("\n");
}

const addedRuntimeValues = [
  "LoopeixDocument",
  "LoopeixV01",
  "LoopeixV02",
  "ResolvedRunPlanDocument",
  "ResolvedRunPlanV01",
  "ResolvedRunPlanV02",
  "compilePromptV02",
  "migrateV01ToV02",
  "parseLoopeixDocument",
  "parseResolvedRunPlanDocument",
  "projectPlannedRunV02",
  "replayCompilePack",
] as const;

const addedTypeNames = [
  "CompilePackReadResult",
  "CompileRequestResultV02",
  "LoopeixDocumentParseResult",
  "LoopeixMigrationResult",
  "LoopeixV01Value",
  "LoopeixV02Value",
  "MigrateV01ToV02Input",
  "MigratorVersion",
  "PlanProjectionResult",
  "ReplayResult",
  "ResolvedRunPlanDocumentParseResult",
  "ResolvedRunPlanV01Value",
  "ResolvedRunPlanV02Value",
] as const;

function sorted(values: readonly string[]): string[] {
  return [...values].sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
}

function sha256(bytes: string | Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function declarationTypeExports(): string[] {
  const declarationPath = join(repositoryRoot, "dist/index.d.ts");
  const program = ts.createProgram([declarationPath], {
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
    target: ts.ScriptTarget.ES2024,
    skipLibCheck: false,
  });
  const diagnostics = ts.getPreEmitDiagnostics(program);
  expect(diagnostics.map((diagnostic) => ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n"))).toEqual([]);
  const source = program.getSourceFile(declarationPath);
  expect(source).toBeDefined();
  const moduleSymbol = source === undefined ? undefined : program.getTypeChecker().getSymbolAtLocation(source);
  expect(moduleSymbol).toBeDefined();
  const checker = program.getTypeChecker();
  return sorted(checker.getExportsOfModule(moduleSymbol!)
    .filter((symbol) => {
      const target = (symbol.flags & ts.SymbolFlags.Alias) !== 0 ? checker.getAliasedSymbol(symbol) : symbol;
      return (target.flags & ts.SymbolFlags.Type) !== 0;
    })
    .map((symbol) => symbol.name));
}

function packagePaths(): string[] {
  const paths: string[] = [];
  const walk = (directory: string, prefix: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const nextPath = join(directory, entry.name);
      const name = `${prefix}/${entry.name}`;
      if (entry.isDirectory()) walk(nextPath, name);
      else if (entry.isFile()) paths.push(name);
    }
  };

  for (const root of ["bin", "dist", "schemas"] as const) walk(join(repositoryRoot, root), root);
  paths.push("CHANGELOG.md", "LICENSE", "NOTICE", "README.md", "oclif.manifest.json", "package.json", "npm-shrinkwrap.json");
  return sorted(paths);
}

describe("S35 schema and package contract", () => {
  it("exposes only the frozen baseline plus the exact sanctioned S35 root values", async () => {
    const root = await import("../../src/index.js");
    const expected = sorted([...oracle("package-root-runtime-exports.txt"), ...addedRuntimeValues]);

    expect(sorted(Object.keys(root))).toEqual(expected);
    expect(root.compilePrompt).toBe(root.compilePromptV02);
    const parent = mkdtempSync(join(tmpdir(), "loopeix-public-pack-s35-"));
    const destination = join(parent, "forged-pack");
    try {
      expect(() => root.writeCompilePack({ ok: true }, destination)).toThrow(/package-private compiler authority/u);
      expect(existsSync(destination)).toBe(false);
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });

  it("replays a captured V01 pack through the flat public facade without leaking authorities", async () => {
    const root = await import("../../src/index.js");
    const result = await root.replayCompilePack(join(fixtureRoot, "compiled-safe-bugfix"));

    expect(result).toEqual({
      ok: true,
      disposition: "replayed",
      schema_version: "0.1",
      source_pack_root_hash: expect.stringMatching(/^sha256:[0-9a-f]{64}$/u),
      compared_member_count: 7,
      reason: null,
      findings: [],
    });
    expect(Object.keys(result)).not.toContain("authority");
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.findings)).toBe(true);
  });

  it("holds malformed manifests before selecting a family", async () => {
    const root = await import("../../src/index.js");
    const parent = mkdtempSync(join(tmpdir(), "loopeix-public-replay-s35-"));
    try {
      writeFileSync(join(parent, "pack-manifest.json"), '{"schema_version":" 0.2"}\n');
      await expect(root.replayCompilePack(parent)).resolves.toEqual({
        ok: false,
        disposition: "hold",
        schema_version: null,
        source_pack_root_hash: null,
        compared_member_count: 0,
        reason: "MALFORMED_SCHEMA_VERSION",
        findings: [],
      });
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });

  it("exposes only the frozen baseline plus the exact sanctioned S35 root types", () => {
    const expected = sorted([...oracle("package-root-type-exports.txt"), ...addedTypeNames]);
    expect(declarationTypeExports()).toEqual(expected);
  }, 15_000);

  it("freezes the reviewed common package oracles for runtime smoke", () => {
    expect(commonOracle("s35-package-root-runtime-exports.txt"))
      .toEqual(sorted([...oracle("package-root-runtime-exports.txt"), ...addedRuntimeValues]));
    expect(commonOracle("s35-package-root-type-exports.txt"))
      .toEqual(sorted([...oracle("package-root-type-exports.txt"), ...addedTypeNames]));
    expect(commonOracle("s35-packed-paths.txt")).toEqual(packagePaths());

    const commonReceiptBytes = readFileSync(join(commonFixtureRoot, "receipt.schema.json"));
    const schemaReceiptBytes = readFileSync(join(repositoryRoot, "schemas/receipt.schema.json"));
    expect(sha256(commonReceiptBytes)).toBe(expectedReceiptSchemaSha256);
    expect(sha256(schemaReceiptBytes)).toBe(expectedReceiptSchemaSha256);
    expect(commonReceiptBytes).toEqual(schemaReceiptBytes);
  });

  it("ships the self-contained dispatcher and both literal family schemas with stable IDs", () => {
    const packageJson = JSON.parse(readFileSync(join(repositoryRoot, "package.json"), "utf8")) as {
      exports: Record<string, unknown>;
      files: string[];
    };
    const dispatcher = JSON.parse(readFileSync(join(repositoryRoot, "schemas/loopeix.schema.json"), "utf8")) as {
      $id: string;
      $defs: Record<string, unknown>;
    };
    const v01 = JSON.parse(readFileSync(join(repositoryRoot, "schemas/loopeix-0.1.schema.json"), "utf8")) as { $id: string };
    const v02 = JSON.parse(readFileSync(join(repositoryRoot, "schemas/loopeix-0.2.schema.json"), "utf8")) as { $id: string };

    expect(dispatcher.$id).toBe("https://loopeix.dev/schemas/loopeix.schema.json");
    expect(Object.keys(dispatcher.$defs)).toEqual(["v01", "v02"]);
    expect(v01.$id).toBe("https://loopeix.dev/schemas/loopeix-0.1.schema.json");
    expect(v02.$id).toBe("https://loopeix.dev/schemas/loopeix-0.2.schema.json");
    expect(packageJson.exports).toMatchObject({
      "./schemas/loopeix": "./schemas/loopeix.schema.json",
      "./schemas/loopeix-0.1": "./schemas/loopeix-0.1.schema.json",
      "./schemas/loopeix-0.2": "./schemas/loopeix-0.2.schema.json",
    });
    expect(packageJson.files).toEqual([
      "bin", "dist", "schemas", "oclif.manifest.json", "npm-shrinkwrap.json",
      "NOTICE", "README.md", "LICENSE", "CHANGELOG.md",
    ]);
  });

  it("packages the reviewed S40 artifacts without publishing any private module subpath", () => {
    const packageJson = JSON.parse(readFileSync(join(repositoryRoot, "package.json"), "utf8")) as {
      exports: Record<string, unknown>;
    };
    const jsonPaths: string[] = [];
    const walk = (directory: string): void => {
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        const path = join(directory, entry.name);
        if (entry.isDirectory()) walk(path);
        else if (entry.name.endsWith(".json")) jsonPaths.push(path.slice(join(repositoryRoot, "dist").length + 1));
      }
    };
    walk(join(repositoryRoot, "dist"));

    expect(sorted(jsonPaths)).toEqual(["report/plan-renderer-bundle.json"]);
    const packedPaths = packagePaths();
    for (const modulePath of s40PrivateGeneratedModules) {
      for (const suffix of [".d.ts", ".d.ts.map", ".js", ".js.map"] as const) {
        expect(packedPaths).toContain(`dist/${modulePath}${suffix}`);
      }
      expect(Object.hasOwn(packageJson.exports, `./${modulePath}`)).toBe(false);
    }
    for (const privatePath of [
      "./compiler/read-pack-v02",
      "./io/output-capabilities",
      "./run/planned-directory-classifier",
      "./schema/version-dispatch",
    ]) {
      expect(Object.hasOwn(packageJson.exports, privatePath)).toBe(false);
    }
  });

  it("blocks installed smoke before npm when reviewed common/V02 fixtures are absent", () => {
    const root = mkdtempSync(join(tmpdir(), "loopeix-s35-smoke-preflight-"));
    try {
      const tarball = join(root, "loopeix-0.1.0.tgz");
      const fixtures = join(root, "fixtures");
      writeFileSync(tarball, "not executed\n");
      mkdirSync(fixtures);
      const result = spawnSync(process.execPath, [
        join(repositoryRoot, "scripts/smoke-packed-package-s35.mjs"),
        "--mode", "full",
        "--tarball", tarball,
        "--fixtures-root", fixtures,
      ], { encoding: "utf8" });

      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain("reviewed canonical fixture is missing or unsafe");
      expect(existsSync(join(root, "consumer"))).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("requires a verified harness manifest in runtime smoke mode", () => {
    const result = spawnSync(process.execPath, [
      join(repositoryRoot, "scripts/smoke-packed-package-s35.mjs"),
      "--mode", "runtime",
      "--tarball", "/tmp/loopeix-s35-never-read.tgz",
      "--fixtures-root", "/tmp",
    ], { encoding: "utf8" });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("runtime mode requires --harness-manifest");
  });

  it("builds a byte-deterministic harness that passes strict artifact verification", () => {
    const root = mkdtempSync(join(tmpdir(), "loopeix-s35-artifact-protocol-"));
    try {
      const fixtures = join(root, "fixtures");
      const first = join(root, "first");
      const second = join(root, "second");
      const tarball = join(root, "loopeix-0.1.0.tgz");
      const smoke = join(root, "smoke.mjs");
      mkdirSync(fixtures);
      mkdirSync(first);
      mkdirSync(second);
      writeFileSync(join(fixtures, "fixture.txt"), "fixture\n");
      writeFileSync(tarball, "product\n");
      writeFileSync(smoke, "process.exit(0);\n", { mode: 0o600 });
      const builder = join(repositoryRoot, "scripts/build-s35-runtime-smoke-harness.mjs");
      for (const output of [first, second]) {
        execFileSync(process.execPath, [
          builder,
          "--tarball", tarball,
          "--fixtures-root", fixtures,
          "--output-dir", output,
          "--smoke-script", smoke,
        ], { cwd: repositoryRoot, stdio: "pipe" });
      }
      const expectedArtifactNames = [
        "loopeix-0.1.0.tgz",
        "loopeix-s35-runtime-smoke-v01.tar",
        "s35-build-artifact-manifest-v01.json",
        "verify-s35-build-artifacts.mjs",
      ];
      expect(readdirSync(first).sort(sorted)).toEqual(expectedArtifactNames.sort(sorted));
      expect(readdirSync(second).sort(sorted)).toEqual(expectedArtifactNames.sort(sorted));
      for (const name of expectedArtifactNames) {
        expect(readFileSync(join(first, name))).toEqual(readFileSync(join(second, name)));
      }
      const outerManifest = JSON.parse(readFileSync(join(first, "s35-build-artifact-manifest-v01.json"), "utf8")) as Record<string, unknown>;
      expect(outerManifest).not.toHaveProperty("verifier");
      expect(readFileSync(join(first, "verify-s35-build-artifacts.mjs"))).toEqual(
        readFileSync(join(repositoryRoot, "scripts/verify-s35-build-artifacts.mjs")),
      );
      for (const name of expectedArtifactNames) chmodSync(join(first, name), 0o644);
      const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repositoryRoot, encoding: "utf8" }).trim();
      execFileSync(process.execPath, [
        join(first, "verify-s35-build-artifacts.mjs"),
        "--artifact-dir", first,
        "--expected-source-commit", commit,
      ], { cwd: repositoryRoot, stdio: "pipe" });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
