import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import Doctor, { evaluateDoctorPackage } from "../../src/commands/doctor.js";

const repositoryRoot = join(import.meta.dirname, "..", "..");
const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function packageCopy(): string {
  const root = mkdtempSync(join(tmpdir(), "loopeix-doctor-s35-"));
  roots.push(root);
  mkdirSync(join(root, "schemas"));
  mkdirSync(join(root, "dist", "io"), { recursive: true });
  for (const name of [
    "loopeix-0.1.schema.json",
    "loopeix-0.2.schema.json",
    "loopeix.schema.json",
    "receipt.schema.json",
  ]) {
    cpSync(join(repositoryRoot, "schemas", name), join(root, "schemas", name));
  }
  writeFileSync(join(root, "package.json"), JSON.stringify({ name: "loopeix", version: "0.1.0", type: "module" }));
  cpSync(
    join(repositoryRoot, "dist", "io", "legacy-replay-child.js"),
    join(root, "dist", "io", "legacy-replay-child.js"),
  );
  return root;
}

function evaluate(root: string, overrides: Partial<Parameters<typeof evaluateDoctorPackage>[0]> = {}) {
  return evaluateDoctorPackage({
    packageRoot: root,
    helperRelativePath: "dist/io/legacy-replay-child.js",
    nodeVersion: "v26.0.0",
    cliVersion: "0.1.0",
    platform: "darwin",
    architecture: "arm64",
    ...overrides,
  });
}

describe("S35 doctor package and schema contract", () => {
  it("returns the exact successful union and canonical eight-check order", async () => {
    const result = await evaluate(packageCopy());
    expect(result).toEqual({
      node: "v26.0.0",
      cli: "0.1.0",
      schemaBundled: true,
      platform_supported: true,
      filesystem_identity_supported: true,
      ok: true,
      checks: [
        { id: "node-runtime", ok: true, detail: "Node v26.0.0 is supported." },
        { id: "package-version", ok: true, detail: "Package version 0.1.0 is valid." },
        { id: "platform", ok: true, detail: "darwin-arm64 is supported." },
        { id: "io-helper", ok: true, detail: "Private filesystem helper is available." },
        { id: "schema-loopeix-v01", ok: true, detail: "Loopeix 0.1 schema is valid." },
        { id: "schema-loopeix-v02", ok: true, detail: "Loopeix 0.2 schema is valid." },
        { id: "schema-loopeix-dispatcher", ok: true, detail: "Loopeix dispatcher schema is valid." },
        { id: "schema-receipt", ok: true, detail: "Receipt schema is valid." },
      ],
      disposition: "pass",
      reason: null,
      findings: [],
    });
  });

  it("fails closed on a missing, broken, or symlinked helper and an unsupported declared host", async () => {
    const root = packageCopy();
    unlinkSync(join(root, "dist", "io", "legacy-replay-child.js"));
    const result = await evaluate(root, { platform: "linux", architecture: "arm64" });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected doctor to hold");
    expect(result.reason).toBe("IO_HELPER_UNAVAILABLE");
    expect(result.platform_supported).toBe(false);
    expect(result.filesystem_identity_supported).toBe(false);
    expect(result.findings).toEqual([
      "platform: linux-arm64 is not a supported S35 host.",
      "io-helper: Private filesystem helper is unavailable.",
    ]);

    writeFileSync(join(root, "helper-target.js"), "export {};\n");
    symlinkSync(join(root, "helper-target.js"), join(root, "dist", "io", "legacy-replay-child.js"));
    const symlinked = await evaluate(root);
    expect(symlinked.filesystem_identity_supported).toBe(false);

    unlinkSync(join(root, "dist", "io", "legacy-replay-child.js"));
    writeFileSync(join(root, "dist", "io", "legacy-replay-child.js"), "export {};\n");
    const broken = await evaluate(root);
    expect(broken.filesystem_identity_supported).toBe(false);
  });

  it("validates strict schema metadata, dispatcher refs, and reason precedence", async () => {
    const root = packageCopy();
    const dispatcherPath = join(root, "schemas", "loopeix.schema.json");
    const dispatcher = readFileSync(dispatcherPath, "utf8");
    writeFileSync(dispatcherPath, dispatcher.replace('"$ref": "#/$defs/v02"', '"$ref": "./remote-v02.json"'));
    const result = await evaluate(root, { nodeVersion: "v25.9.0", platform: "win32", architecture: "x64" });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected doctor to hold");
    expect(result.reason).toBe("SCHEMA_PACKAGE_INVALID");
    expect(result.findings.map((finding) => finding.split(":", 1)[0])).toEqual([
      "node-runtime",
      "platform",
      "io-helper",
      "schema-loopeix-dispatcher",
    ]);
  });

  it("rejects malformed, duplicate-key, non-regular, and package-version-incoherent assets", async () => {
    const malformedRoot = packageCopy();
    writeFileSync(join(malformedRoot, "schemas", "loopeix-0.1.schema.json"), "{not json}\n");
    expect((await evaluate(malformedRoot)).ok).toBe(false);

    const duplicateRoot = packageCopy();
    const v02Path = join(duplicateRoot, "schemas", "loopeix-0.2.schema.json");
    writeFileSync(v02Path, readFileSync(v02Path, "utf8").replace(
      '"$id": "https://loopeix.dev/schemas/loopeix-0.2.schema.json",',
      '"$id": "https://loopeix.dev/schemas/loopeix-0.2.schema.json",\n  "$id": "https://loopeix.dev/schemas/loopeix-0.2.schema.json",',
    ));
    expect((await evaluate(duplicateRoot)).ok).toBe(false);

    const receiptRoot = packageCopy();
    const receiptPath = join(receiptRoot, "schemas", "receipt.schema.json");
    writeFileSync(receiptPath, readFileSync(receiptPath, "utf8").replace('"minLength": 1', '"minLength": 2'));
    expect((await evaluate(receiptRoot)).checks[7].ok).toBe(false);

    const dispatcherPolicyRoot = packageCopy();
    const policyPath = join(dispatcherPolicyRoot, "schemas", "loopeix.schema.json");
    writeFileSync(policyPath, readFileSync(policyPath, "utf8").replace(
      "additive within a minor version; breaking changes bump the version",
      "tampered policy",
    ));
    expect((await evaluate(dispatcherPolicyRoot)).checks[6].ok).toBe(false);

    const symlinkRoot = packageCopy();
    const v01Path = join(symlinkRoot, "schemas", "loopeix-0.1.schema.json");
    const v01Target = join(symlinkRoot, "v01-target.json");
    cpSync(v01Path, v01Target);
    unlinkSync(v01Path);
    symlinkSync(v01Target, v01Path);
    expect((await evaluate(symlinkRoot)).ok).toBe(false);

    const packageRoot = packageCopy();
    writeFileSync(join(packageRoot, "package.json"), JSON.stringify({ name: "loopeix", version: "9.9.9", type: "module" }));
    const result = await evaluate(packageRoot);
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected doctor to hold");
    expect(result.reason).toBe("SCHEMA_PACKAGE_INVALID");
    expect(result.checks[1]).toEqual({
      id: "package-version",
      ok: false,
      detail: "Installed package metadata is invalid.",
    });
  });

  it.each([
    ["v22.11.99", false],
    ["v22.12.0", true],
    ["v22.99.1", true],
    ["v23.0.0", false],
    ["v24.0.0", true],
    ["v25.0.0", false],
    ["v26.0.0", true],
    ["v27.0.0", false],
    ["v22.12.0-rc.1", false],
    ["v022.012.000", false],
    ["22.12.0", false],
  ] as const)("applies the exact stable Node range to %s", async (nodeVersion, supported) => {
    const result = await evaluate(packageCopy(), { nodeVersion });
    expect(result.checks[0].ok).toBe(supported);
    if (!supported) {
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("expected unsupported runtime");
      expect(result.reason).toBe("UNSUPPORTED_RUNTIME");
    }
  });

  it("renders the actual command boundary in fixed order with one JSON object and no stderr", async () => {
    const previousExitCode = process.exitCode;
    process.exitCode = 4;
    const stdout: string[] = [];
    const stderr: string[] = [];
    const log = vi.spyOn(Doctor.prototype, "log").mockImplementation((message?: unknown) => stdout.push(String(message ?? "")));
    const logJson = vi.spyOn(Doctor.prototype as never, "logJson" as never).mockImplementation(((value: unknown) => {
      stdout.push(JSON.stringify(value));
    }) as never);
    const logToStderr = vi.spyOn(Doctor.prototype, "logToStderr").mockImplementation((message?: unknown) => stderr.push(String(message ?? "")));
    try {
      const result = await Doctor.run(["--json"], repositoryRoot);
      expect(result).toMatchObject({ ok: true, disposition: "pass", reason: null });
      expect(stdout).toEqual([JSON.stringify(result)]);
      expect(stderr).toEqual([]);
      expect(process.exitCode).toBe(0);

      stdout.length = 0;
      const human = await Doctor.run([], repositoryRoot);
      expect(human.ok).toBe(true);
      expect(stdout).toHaveLength(9);
      expect(stdout[0]).toBe("loopeix doctor");
      expect(stdout.slice(1).every((line) => line.startsWith("  OK "))).toBe(true);
      expect(stderr).toEqual([]);
    } finally {
      log.mockRestore();
      logJson.mockRestore();
      logToStderr.mockRestore();
      process.exitCode = previousExitCode;
    }
  });

  it("never echoes unbounded injected host or version metadata", async () => {
    const secret = `token-${"x".repeat(200)}`;
    const result = await evaluate(packageCopy(), {
      platform: secret,
      architecture: secret,
      nodeVersion: `v26.0.0-${secret}`,
      cliVersion: secret,
    });
    const diagnostics = JSON.stringify({
      checks: result.checks.map((row) => row.detail),
      findings: result.findings,
    });
    expect(diagnostics).not.toContain(secret);
    expect(result.node).toBe(`v26.0.0-${secret}`);
    expect(result.cli).toBe(secret);
    expect(result.checks[2]?.detail).toBe("unrecognized host is not a supported S35 host.");
  });
});
