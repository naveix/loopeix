import { mkdirSync, mkdtempSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/schema/version-dispatch.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/schema/version-dispatch.js")>();
  return {
    ...actual,
    parseLoopeixDocument: vi.fn((input: unknown) => {
      if (
        typeof input === "object" && input !== null &&
        (input as Record<string, unknown>).schema_version === "0.2" &&
        (input as Record<string, unknown>).__s35_start_fixture === true
      ) {
        return { ok: true, schema_version: "0.2", value: input };
      }
      return actual.parseLoopeixDocument(input);
    }),
  };
});

vi.mock("../../src/run/capture-planned-v02.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/run/capture-planned-v02.js")>();
  return {
    ...actual,
    capturePlannedRunV02: vi.fn(async (rootPath: string) => {
      const names = readdirSync(rootPath);
      return names.includes("ledger.jsonl")
        ? { ok: false, reason: "V02_RUN_LAYOUT_CONTAMINATED", message: "contaminated" }
        : { ok: true, captured: Object.freeze({ run_id: "run_fixture_01" }) };
    }),
    consumeCapturedPlannedRunV02: vi.fn(() => ({ plan: {}, member_bytes: new Map() })),
  };
});

vi.mock("../../src/run/engine.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/run/engine.js")>();
  return { ...actual, runEngine: vi.fn(), parseJsonlEvents: vi.fn(actual.parseJsonlEvents) };
});

vi.mock("../../src/run/id.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/run/id.js")>();
  return { ...actual, reserveRawRunDirectory: vi.fn(actual.reserveRawRunDirectory) };
});

vi.mock("../../src/lock.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/lock.js")>();
  return { ...actual, acquireLock: vi.fn(actual.acquireLock) };
});

vi.mock("../../src/keys.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/keys.js")>();
  return { ...actual, ensureSigningKey: vi.fn(actual.ensureSigningKey) };
});

vi.mock("../../src/run/run-dir.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/run/run-dir.js")>();
  return { ...actual, writeRunDir: vi.fn(actual.writeRunDir) };
});

import { ensureSigningKey } from "../../src/keys.js";
import { acquireLock } from "../../src/lock.js";
import RunStart from "../../src/commands/run/start.js";
import { parseJsonlEvents, runEngine } from "../../src/run/engine.js";
import { reserveRawRunDirectory } from "../../src/run/id.js";
import { writeRunDir } from "../../src/run/run-dir.js";

const repoRoot = join(import.meta.dirname, "..", "..");
const CORE_NAMES = Object.freeze([
  "work-item.json",
  "binding-input.json",
  "intake-record.json",
  "catalog-resolution.json",
  "compilation-record.json",
  "compile-pack-manifest.json",
  "generated.loop.yaml",
  "intake-brief.json",
  "resolved-run-plan.json",
]);

async function runStart(argv: string[]): Promise<{ exitCode: number; out: string }> {
  const previousExitCode = process.exitCode;
  process.exitCode = 0;
  const lines: string[] = [];
  const log = vi.spyOn(RunStart.prototype, "log").mockImplementation(function (message?: unknown): void {
    lines.push(String(message ?? ""));
  });
  try {
    await RunStart.run(argv, repoRoot);
    return { exitCode: Number(process.exitCode ?? 0), out: lines.join("\n") };
  } finally {
    log.mockRestore();
    process.exitCode = previousExitCode;
  }
}

function expectNoExecutionSideEffects(): void {
  expect(reserveRawRunDirectory).not.toHaveBeenCalled();
  expect(acquireLock).not.toHaveBeenCalled();
  expect(parseJsonlEvents).not.toHaveBeenCalled();
  expect(runEngine).not.toHaveBeenCalled();
  expect(ensureSigningKey).not.toHaveBeenCalled();
  expect(writeRunDir).not.toHaveBeenCalled();
}

let directory: string;
beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "loopeix-run-start-v02-hold-"));
  vi.clearAllMocks();
});
afterEach(() => {
  rmSync(directory, { recursive: true, force: true });
});

function createRawV02(): string {
  const path = join(directory, "raw-v02.yaml");
  writeFileSync(path, "schema_version: '0.2'\n__s35_start_fixture: true\n");
  return path;
}

function createPlannedV02(extraName?: string): string {
  const runDirectory = join(directory, "planned-v02");
  // The directory itself is created by the first direct-member write.
  for (const name of CORE_NAMES) {
    const path = join(runDirectory, name);
    if (name === CORE_NAMES[0]) mkdirSync(runDirectory);
    writeFileSync(
      path,
      name === "resolved-run-plan.json"
        ? '{"schema_version":"0.2","execution_profile":"bounded-v02","__s35_start_fixture":true}\n'
        : "",
    );
  }
  if (extraName !== undefined) writeFileSync(join(runDirectory, extraName), "contamination\n");
  return runDirectory;
}

describe("S35 V02 run start fail-closed boundary", () => {
  it("holds a raw V02 live start before run identity, engine, signing, or writes", async () => {
    const source = createRawV02();

    const result = await runStart([
      source,
      "--engine", "codex",
      "--prompt", "must never reach the engine",
      "--seal", join(directory, "missing-brief.yaml"),
      "--workspace", join(directory, "workspace"),
    ]);

    expect(result).toEqual({
      exitCode: 1,
      out: [
        "terminal: held",
        "reason: UNSUPPORTED_EXECUTION_PROFILE",
        "message: This execution profile is not available in S35.",
      ].join("\n"),
    });
    expectNoExecutionSideEffects();
    expect(readdirSync(directory).sort()).toEqual(["raw-v02.yaml"]);
  });

  it("does not load captured events for a raw V02 start", async () => {
    const source = createRawV02();

    const result = await runStart([
      source,
      "--engine", "claude",
      "--events-file", join(directory, "missing-events.jsonl"),
    ]);

    expect(result.exitCode).toBe(1);
    expect(result.out).toContain("reason: UNSUPPORTED_EXECUTION_PROFILE");
    expectNoExecutionSideEffects();
  });

  it("holds a symlinked raw input after safe capture rejects it", async () => {
    const source = createRawV02();
    const link = join(directory, "raw-v02-link.yaml");
    symlinkSync(source, link);

    const result = await runStart([
      link,
      "--engine", "codex",
      "--prompt", "must never reach the legacy direct reader",
      "--workspace", join(directory, "workspace"),
    ]);

    expect(result).toEqual({
      exitCode: 4,
      out: [
        "terminal: held",
        "reason: INVALID_AUTHORING_DOCUMENT",
        "message: The authoring document could not be captured and validated safely.",
      ].join("\n"),
    });
    expectNoExecutionSideEffects();
    expect(readdirSync(directory).sort()).toEqual(["raw-v02-link.yaml", "raw-v02.yaml"]);
  });

  it("holds an exact planned V02 layout before prompt override, locks, or event reads", async () => {
    const runDirectory = createPlannedV02();
    const before = readdirSync(runDirectory).sort();

    const result = await runStart([
      runDirectory,
      "--engine", "codex",
      "--prompt", "must not select the V01 prompt override error",
      "--events-file", join(directory, "missing-events.jsonl"),
    ]);

    expect(result.exitCode).toBe(1);
    expect(result.out).toContain("reason: UNSUPPORTED_EXECUTION_PROFILE");
    expect(result.out).not.toContain("planned run directories use");
    expect(readdirSync(runDirectory).sort()).toEqual(before);
    expectNoExecutionSideEffects();
  });

  it("gives planned V02 layout contamination precedence over the profile HOLD", async () => {
    const runDirectory = createPlannedV02("ledger.jsonl");
    const before = readdirSync(runDirectory).sort();

    const result = await runStart([
      runDirectory,
      "--engine", "codex",
      "--events-file", join(directory, "missing-events.jsonl"),
    ]);

    expect(result).toEqual({
      exitCode: 4,
      out: [
        "terminal: held",
        "reason: V02_RUN_LAYOUT_CONTAMINATED",
        "message: Planned V02 run directory layout is contaminated.",
      ].join("\n"),
    });
    expect(readdirSync(runDirectory).sort()).toEqual(before);
    expectNoExecutionSideEffects();
  });
});
