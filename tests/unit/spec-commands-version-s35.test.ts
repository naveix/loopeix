import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import SpecValidate from "../../src/commands/spec/validate.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

async function runValidate(argv: string[]): Promise<{ exitCode: number; stdout: string; result: Awaited<ReturnType<typeof SpecValidate.run>> }> {
  const priorExitCode = process.exitCode;
  process.exitCode = 0;
  const stdout: string[] = [];
  const log = vi.spyOn(SpecValidate.prototype, "log").mockImplementation((message?: unknown) => {
    stdout.push(String(message ?? ""));
  });
  const logJson = vi.spyOn(SpecValidate.prototype as never, "logJson" as never).mockImplementation(((value: unknown) => {
    stdout.push(JSON.stringify(value));
  }) as never);
  try {
    const result = await SpecValidate.run(argv, import.meta.dirname);
    return { exitCode: Number(process.exitCode ?? 0), stdout: stdout.join("\n"), result };
  } finally {
    log.mockRestore();
    logJson.mockRestore();
    process.exitCode = priorExitCode;
  }
}

describe("S35 spec command version dispatch", () => {
  it("accepts literal V01 and rejects an unsupported family before structural fallback", async () => {
    const root = mkdtempSync(join(tmpdir(), "loopeix-s35-spec-version-"));
    roots.push(root);
    const fixture = readFileSync(
      join(import.meta.dirname, "../fixtures/valid/specs/minimal-bugfix.loop.yaml"),
      "utf8",
    );
    const v01Path = join(root, "v01.loop.yaml");
    const unsupportedPath = join(root, "unsupported.loop.yaml");
    writeFileSync(v01Path, fixture);
    writeFileSync(unsupportedPath, fixture.replace('schema_version: "0.1"', 'schema_version: "0.3"'));

    expect(await runValidate([v01Path])).toMatchObject({ exitCode: 0 });
    const unsupported = await runValidate([unsupportedPath]);
    expect(unsupported.exitCode).toBe(1);
    expect(unsupported.stdout).toContain("UNSUPPORTED_SCHEMA_VERSION");
  });

  it("preserves the invalid V02 JSON validation projection used by package smoke", async () => {
    const invalidPath = join(import.meta.dirname, "../fixtures/compat/s35/v02/authoring-invalid.loop.yaml");

    const invalid = await runValidate([invalidPath, "--json"]);
    expect(invalid.exitCode).toBe(1);
    expect(invalid.stdout).not.toContain("INVALID_AUTHORING_DOCUMENT");
    expect(invalid.result).toEqual({
      ok: false,
      errors: [
        {
          path: "limit_policy.max_tool_calls",
          message: "Invalid input: expected number, received string",
        },
      ],
    });
  });
});
