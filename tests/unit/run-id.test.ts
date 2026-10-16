import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const fsMockState = vi.hoisted(() => ({
  failPath: null as string | null,
  sentinel: Object.assign(new Error("sentinel mkdir failure"), { code: "EACCES" }) as NodeJS.ErrnoException,
}));

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    mkdirSync: vi.fn((path: Parameters<typeof actual.mkdirSync>[0], options?: Parameters<typeof actual.mkdirSync>[1]) => {
      if (fsMockState.failPath !== null && String(path) === fsMockState.failPath) {
        throw fsMockState.sentinel;
      }
      return actual.mkdirSync(path, options);
    }),
  };
});

vi.mock("../../src/run/engine.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/run/engine.js")>();
  return {
    ...actual,
    runEngine: vi.fn(),
  };
});

import RunStart from "../../src/commands/run/start.js";
import { parseJsonlEvents, runEngine } from "../../src/run/engine.js";

const repoRoot = join(import.meta.dirname, "..", "..");
const specPath = join(repoRoot, "tests", "fixtures", "valid", "specs", "minimal-bugfix.loop.yaml");
const eventsPath = join(repoRoot, "tests", "fixtures", "adapter-events", "codex", "s1-codex-exec-json.redacted.jsonl");
const fixedNow = new Date("2026-07-10T12:34:56.789Z");

async function runStart(argv: string[]): Promise<{ exitCode: number; out: string }> {
  const before = process.exitCode;
  process.exitCode = 0;
  const lines: string[] = [];
  const spy = vi.spyOn(RunStart.prototype, "log").mockImplementation(function (message?: unknown): void {
    lines.push(String(message ?? ""));
  });
  try {
    await RunStart.run(argv, repoRoot);
    return { exitCode: Number(process.exitCode ?? 0), out: lines.join("\n") };
  } finally {
    spy.mockRestore();
    process.exitCode = before;
  }
}

describe("loopeix run start raw replay run ids", () => {
  let workspace: string;

  beforeEach(() => {
    workspace = mkdtempSync(join(tmpdir(), "loopeix-run-id-"));
    vi.mocked(runEngine).mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
    fsMockState.failPath = null;
    rmSync(workspace, { recursive: true, force: true });
  });

  it("creates two distinct entropy-shaped run ids for raw replays started in the same millisecond", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(fixedNow);

    const first = await runStart([specPath, "--engine", "codex", "--events-file", eventsPath, "--workspace", workspace]);
    const second = await runStart([specPath, "--engine", "codex", "--events-file", eventsPath, "--workspace", workspace]);

    expect(first.exitCode).toBe(4);
    expect(second.exitCode).toBe(4);

    const runsDir = join(workspace, ".loopeix", "runs");
    const runDirs = readdirSync(runsDir).sort();

    expect(runDirs).toHaveLength(2);

    for (const runDirName of runDirs) {
      expect(runDirName).toMatch(/^run_[a-z0-9]+_[0-9a-f]{16}$/);

      const runJson = JSON.parse(readFileSync(join(runsDir, runDirName, "run.json"), "utf8")) as { run_id?: string };
      expect(runJson.run_id).toBe(runDirName);
    }
  });

  it("S37 holds a raw live run before directory reservation or engine invocation", async () => {
    const blockedWorkspace = join(workspace, "workspace-file");
    writeFileSync(blockedWorkspace, "not a directory\n");

    const result = await runStart([
      specPath,
      "--engine",
      "codex",
      "--prompt",
      "perform external work",
      "--workspace",
      blockedWorkspace,
    ]);

    expect(result.exitCode).toBe(1);
    expect(result.out).toContain("reason: GENERAL_AGENT_PROHIBITED");
    expect(result.out).not.toContain("cannot reserve raw run directory");
    expect(runEngine).not.toHaveBeenCalled();
  });

  it("fails directory reservation before reading raw replay events", async () => {
    const blockedWorkspace = join(workspace, "workspace-file");
    const missingEvents = join(workspace, "missing-events.jsonl");
    writeFileSync(blockedWorkspace, "not a directory\n");

    const result = await runStart([
      specPath,
      "--engine",
      "codex",
      "--events-file",
      missingEvents,
      "--workspace",
      blockedWorkspace,
    ]);

    expect(result.exitCode).toBe(1);
    expect(result.out).toContain("ERROR: cannot reserve raw run directory:");
    expect(runEngine).not.toHaveBeenCalled();
  });

  it("rejects an empty raw live prompt before target capture, allocation, or engine invocation", async () => {
    vi.mocked(runEngine).mockReturnValue({
      engine: "codex_cli",
      rawEvents: parseJsonlEvents(readFileSync(eventsPath, "utf8")),
      exit_code: 0,
      timed_out: false,
      stderr: "",
    });

    const result = await runStart([
      join(workspace, "missing.loop.yaml"),
      "--engine",
      "codex",
      "--prompt",
      "",
      "--workspace",
      workspace,
    ]);

    expect(result.exitCode).toBe(1);
    expect(result.out).toContain("ERROR: --prompt is required for a live run");
    expect(existsSync(join(workspace, ".loopeix", "runs"))).toBe(false);
    expect(runEngine).not.toHaveBeenCalled();
  });
});

describe("reserveRawRunDirectory", () => {
  let allocatorWorkspace: string;

  beforeEach(() => {
    allocatorWorkspace = mkdtempSync(join(tmpdir(), "loopeix-run-id-allocator-"));
  });

  afterEach(() => {
    fsMockState.failPath = null;
    rmSync(allocatorWorkspace, { recursive: true, force: true });
  });

  it("creates an entropy-shaped run id and claims the matching directory", async () => {
    const { reserveRawRunDirectory } = await import("../../src/run/id.js");
    const fixedNow = 36 ** 6 + 36 ** 3 + 35;
    const randomBytes = vi.fn(() => Uint8Array.from([0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70]));
    const allocation = reserveRawRunDirectory(allocatorWorkspace, {
      now: () => fixedNow,
      randomBytes,
    });

    expect(allocation).toEqual({
      run_id: "run_100100z_0010203040506070",
      run_dir: join(allocatorWorkspace, ".loopeix", "runs", "run_100100z_0010203040506070"),
    });
    expect(randomBytes.mock.calls).toEqual([[8]]);
    expect(readdirSync(join(allocatorWorkspace, ".loopeix", "runs"))).toEqual(["run_100100z_0010203040506070"]);
  });

  it("returns the normalized joined run directory path", async () => {
    const { reserveRawRunDirectory } = await import("../../src/run/id.js");
    const workspaceWithTrailingSlash = `${allocatorWorkspace}/`;
    const randomBytes = vi.fn(() => Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 5]));

    const allocation = reserveRawRunDirectory(workspaceWithTrailingSlash, {
      now: () => 5,
      randomBytes,
    });

    expect(allocation.run_dir).toBe(join(allocatorWorkspace, ".loopeix", "runs", "run_5_0000000000000005"));
    expect(randomBytes.mock.calls).toEqual([[8]]);
  });

  it("retries when the candidate directory already exists and later claims a fresh id", async () => {
    const { reserveRawRunDirectory } = await import("../../src/run/id.js");
    const parent = join(allocatorWorkspace, ".loopeix", "runs");
    mkdirSync(join(parent, "run_42_deadbeefcafebabe"), { recursive: true });
    const entropy = [
      Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]),
      Uint8Array.from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
    ];
    let calls = 0;
    const now = vi.fn().mockReturnValueOnce(146).mockReturnValue(147);
    const randomBytes = vi.fn(() => entropy[calls++]!);

    const allocation = reserveRawRunDirectory(allocatorWorkspace, {
      now,
      randomBytes,
    });

    expect(allocation).toEqual({
      run_id: "run_42_1122334455667788",
      run_dir: join(parent, "run_42_1122334455667788"),
    });
    expect(calls).toBe(2);
    expect(now).toHaveBeenCalledTimes(1);
    expect(randomBytes.mock.calls).toEqual([[8], [8]]);
    expect(readdirSync(parent).sort()).toEqual(["run_42_1122334455667788", "run_42_deadbeefcafebabe"]);
  });

  it("throws a specific allocation error after exhausting repeated collisions", async () => {
    const { reserveRawRunDirectory } = await import("../../src/run/id.js");
    const parent = join(allocatorWorkspace, ".loopeix", "runs");
    mkdirSync(join(parent, "run_2_aaaaaaaaaaaaaaaa"), { recursive: true });
    const now = vi.fn().mockReturnValueOnce(2).mockReturnValue(3);
    const randomBytes = vi.fn(() => Uint8Array.from([0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa]));

    expect(() =>
      reserveRawRunDirectory(allocatorWorkspace, {
        now,
        randomBytes,
        maxAttempts: 2,
      }),
    ).toThrowError("cannot reserve raw run directory after 2 attempts");
    expect(now).toHaveBeenCalledTimes(1);
    expect(randomBytes.mock.calls).toEqual([[8], [8]]);
  });

  it("uses a default collision budget of 16 attempts", async () => {
    const { reserveRawRunDirectory } = await import("../../src/run/id.js");
    const parent = join(allocatorWorkspace, ".loopeix", "runs");
    mkdirSync(join(parent, "run_3_bbbbbbbbbbbbbbbb"), { recursive: true });
    const randomBytes = vi.fn(() => Uint8Array.from([0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb]));

    expect(() =>
      reserveRawRunDirectory(allocatorWorkspace, {
        now: () => 3,
        randomBytes,
      }),
    ).toThrowError("cannot reserve raw run directory after 16 attempts");
    expect(randomBytes.mock.calls).toEqual(Array.from({ length: 16 }, () => [8]));
  });

  it("propagates non-collision filesystem errors unchanged", async () => {
    const { reserveRawRunDirectory } = await import("../../src/run/id.js");
    const candidatePath = join(allocatorWorkspace, ".loopeix", "runs", "run_7_0000000000000001");
    fsMockState.failPath = candidatePath;
    const randomBytes = vi.fn(() => Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 1]));

    let thrown: unknown;
    try {
      reserveRawRunDirectory(allocatorWorkspace, {
        now: () => 7,
        randomBytes,
      });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBe(fsMockState.sentinel);
    expect((thrown as NodeJS.ErrnoException).code).toBe("EACCES");
    expect((thrown as Error).message).toBe("sentinel mkdir failure");
    expect(randomBytes.mock.calls).toEqual([[8]]);
  });

  it("validates maxAttempts before reading the timestamp", async () => {
    const { reserveRawRunDirectory } = await import("../../src/run/id.js");
    const now = vi.fn(() => {
      throw new Error("timestamp should not be read");
    });

    expect(() =>
      reserveRawRunDirectory(allocatorWorkspace, {
        maxAttempts: 0,
        now,
      }),
    ).toThrowError(new RangeError("maxAttempts must be a positive safe integer"));
    expect(now).not.toHaveBeenCalled();
  });

  it.each([
    { maxAttempts: 0, label: "zero" },
    { maxAttempts: -1, label: "negative" },
    { maxAttempts: 1.5, label: "non-integer" },
  ])("throws RangeError for $label maxAttempts", async ({ maxAttempts }) => {
    const { reserveRawRunDirectory } = await import("../../src/run/id.js");

    expect(() =>
      reserveRawRunDirectory(allocatorWorkspace, {
        maxAttempts,
      }),
    ).toThrowError(new RangeError("maxAttempts must be a positive safe integer"));
  });

  it.each([
    { now: () => -1, label: "negative" },
    { now: () => 1.5, label: "fractional" },
    { now: () => Number.POSITIVE_INFINITY, label: "non-finite" },
  ])("throws RangeError for $label timestamp", async ({ now }) => {
    const { reserveRawRunDirectory } = await import("../../src/run/id.js");

    expect(() =>
      reserveRawRunDirectory(allocatorWorkspace, {
        now,
      }),
    ).toThrowError(new RangeError("now() must return a non-negative safe integer"));
  });
});
