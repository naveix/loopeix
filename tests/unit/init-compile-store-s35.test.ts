import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Init, { type InitCommandResult } from "../../src/commands/init.js";

const repoRoot = join(import.meta.dirname, "..", "..");
const sentinelBytes = "*\n!.gitignore\n";
const freshPaths = [
  ".loopeix/",
  ".loopeix/loops/",
  ".loopeix/workspace.yaml",
  ".loopeix/keys/",
  ".loopeix/keys/.gitignore",
  ".loopeix/compiles/",
  ".loopeix/compiles/.gitignore",
];

type RunResult = Readonly<{
  result: InitCommandResult;
  exitCode: number;
  stdout: string;
  stderr: string;
}>;

let workspace: string;
let cwdSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  workspace = mkdtempSync(join(tmpdir(), "loopeix-init-s35-"));
  cwdSpy = vi.spyOn(process, "cwd").mockReturnValue(workspace);
});

afterEach(() => {
  cwdSpy.mockRestore();
  rmSync(workspace, { recursive: true, force: true });
});

async function runInit(argv: string[]): Promise<RunResult> {
  const previousExitCode = process.exitCode;
  process.exitCode = 0;
  const stdout: string[] = [];
  const stderr: string[] = [];
  const log = vi.spyOn(Init.prototype, "log").mockImplementation((message?: unknown) => stdout.push(String(message ?? "")));
  const logJson = vi.spyOn(Init.prototype as never, "logJson" as never).mockImplementation(((value: unknown) => {
    stdout.push(JSON.stringify(value));
  }) as never);
  const logToStderr = vi.spyOn(Init.prototype, "logToStderr").mockImplementation((message?: unknown) => stderr.push(String(message ?? "")));
  const warn = vi.spyOn(Init.prototype, "warn").mockImplementation((message: unknown) => {
    stderr.push(String(message));
    return message as string;
  });
  try {
    const result = (await Init.run(argv, repoRoot)) as InitCommandResult;
    return {
      result,
      exitCode: Number(process.exitCode ?? 0),
      stdout: stdout.join("\n"),
      stderr: stderr.join("\n"),
    };
  } finally {
    log.mockRestore();
    logJson.mockRestore();
    logToStderr.mockRestore();
    warn.mockRestore();
    process.exitCode = previousExitCode;
  }
}

function createV01Workspace(): string {
  const root = join(workspace, ".loopeix");
  mkdirSync(join(root, "loops"), { recursive: true });
  mkdirSync(join(root, "keys"), { recursive: true });
  writeFileSync(join(root, "workspace.yaml"), "preserve-workspace\n");
  writeFileSync(join(root, "keys", ".gitignore"), "preserve-keys\n");
  return root;
}

describe("S35 loopeix init compile-store contract", () => {
  it("creates the fresh seven-path scaffold in canonical order and preserves JSON key meaning", async () => {
    const human = await runInit([]);
    expect(human.exitCode).toBe(0);
    expect(human.result).toEqual({ created: freshPaths });
    expect(human.stdout).toBe(`created:\n${freshPaths.map((path) => `  ${path}`).join("\n")}`);
    expect(human.stderr).toBe("");
    expect(readFileSync(join(workspace, ".loopeix", "compiles", ".gitignore"), "utf8")).toBe(sentinelBytes);

    rmSync(join(workspace, ".loopeix"), { recursive: true, force: true });
    const json = await runInit(["--json"]);
    expect(json.exitCode).toBe(0);
    expect(JSON.stringify(json.result)).toBe(JSON.stringify({ created: freshPaths }));
    expect(json.stdout).toBe(JSON.stringify({ created: freshPaths }));
    expect(json.stderr).toBe("");
  });

  it("dry-runs the fresh seven paths without creating a workspace", async () => {
    const result = await runInit(["--dry-run"]);
    expect(result.result).toEqual({ created: [], dryRun: true });
    expect(result.stdout).toBe(`would create:\n${freshPaths.map((path) => `  ${path}`).join("\n")}`);
    expect(result.stderr).toBe("");
    expect(existsSync(join(workspace, ".loopeix"))).toBe(false);
  });

  it("adds only missing compile-store paths and never overwrites V01 members", async () => {
    const root = createV01Workspace();
    const beforeWorkspace = readFileSync(join(root, "workspace.yaml"), "utf8");
    const beforeKeys = readFileSync(join(root, "keys", ".gitignore"), "utf8");

    const dry = await runInit(["--dry-run"]);
    expect(dry.result).toEqual({ created: [], dryRun: true });
    expect(dry.stdout).toBe("would create:\n  .loopeix/compiles/\n  .loopeix/compiles/.gitignore");
    expect(existsSync(join(root, "compiles"))).toBe(false);

    const created = await runInit([]);
    expect(created.result).toEqual({ created: [".loopeix/compiles/", ".loopeix/compiles/.gitignore"] });
    expect(created.stdout).toBe("created:\n  .loopeix/compiles/\n  .loopeix/compiles/.gitignore");
    expect(readFileSync(join(root, "workspace.yaml"), "utf8")).toBe(beforeWorkspace);
    expect(readFileSync(join(root, "keys", ".gitignore"), "utf8")).toBe(beforeKeys);
    expect(readFileSync(join(root, "compiles", ".gitignore"), "utf8")).toBe(sentinelBytes);

    rmSync(join(root, "compiles", ".gitignore"));
    const sentinelOnly = await runInit([]);
    expect(sentinelOnly.result).toEqual({ created: [".loopeix/compiles/.gitignore"] });
  });

  it("keeps the exact sentinel as the frozen existing-workspace no-op", async () => {
    const root = createV01Workspace();
    mkdirSync(join(root, "compiles"));
    writeFileSync(join(root, "compiles", ".gitignore"), sentinelBytes);

    const human = await runInit([]);
    expect(human.result).toEqual({ created: [] });
    expect(human.stdout).toBe("");
    expect(human.stderr).toBe(".loopeix already exists; nothing created.");

    const json = await runInit(["--json"]);
    expect(json.result).toEqual({ created: [] });
    expect(json.stdout).toBe(JSON.stringify({ created: [] }));
    expect(json.stderr).toBe("");
  });

  it("dry-runs and atomically repairs a stale direct regular sentinel", async () => {
    const root = createV01Workspace();
    const compiles = join(root, "compiles");
    const sentinel = join(compiles, ".gitignore");
    mkdirSync(compiles);
    writeFileSync(sentinel, "stale\n", { mode: 0o644 });

    const humanDry = await runInit(["--dry-run"]);
    expect(humanDry.result).toEqual({
      created: [], dryRun: true, repaired: [], wouldRepair: [".loopeix/compiles/.gitignore"],
    });
    expect(humanDry.stdout).toBe("would repair:\n  .loopeix/compiles/.gitignore");
    expect(humanDry.stderr).toBe("");
    expect(readFileSync(sentinel, "utf8")).toBe("stale\n");
    expect(readdirSync(compiles)).toEqual([".gitignore"]);

    const dry = await runInit(["--dry-run", "--json"]);
    const expectedDry = {
      created: [], dryRun: true, repaired: [], wouldRepair: [".loopeix/compiles/.gitignore"],
    };
    expect(JSON.stringify(dry.result)).toBe(JSON.stringify(expectedDry));
    expect(dry.stdout).toBe(JSON.stringify(expectedDry));
    expect(dry.stderr).toBe("");

    const repaired = await runInit([]);
    expect(JSON.stringify(repaired.result)).toBe(JSON.stringify({
      created: [], repaired: [".loopeix/compiles/.gitignore"],
    }));
    expect(repaired.stdout).toBe("repaired:\n  .loopeix/compiles/.gitignore");
    expect(repaired.stderr).toBe("");
    expect(readFileSync(sentinel, "utf8")).toBe(sentinelBytes);
    expect(lstatSync(sentinel).mode & 0o777).toBe(0o600);
    expect(readdirSync(compiles)).toEqual([".gitignore"]);
  });

  it("rejects symlink, dangling-symlink, and non-regular sentinels with the exact identity envelope", async () => {
    for (const kind of ["symlink", "dangling", "directory"] as const) {
      rmSync(join(workspace, ".loopeix"), { recursive: true, force: true });
      const root = createV01Workspace();
      const compiles = join(root, "compiles");
      const sentinel = join(compiles, ".gitignore");
      mkdirSync(compiles);
      if (kind === "directory") mkdirSync(sentinel);
      else symlinkSync(kind === "symlink" ? join(root, "workspace.yaml") : join(root, "missing"), sentinel);

      const result = await runInit(["--json"]);
      expect(result.exitCode).toBe(4);
      expect(JSON.stringify(result.result)).toBe(JSON.stringify({
        ok: false,
        disposition: "hold",
        reason: "IO_IDENTITY_MISMATCH",
        findings: ["Filesystem identity validation failed."],
      }));
      expect(result.stdout).toBe(JSON.stringify(result.result));
      expect(result.stderr).toBe("");
      expect(readdirSync(compiles)).toEqual([".gitignore"]);
    }
  });

  it("maps an unusable compile directory to COMPILE_STORE_INVALID without touching V01 files", async () => {
    const root = createV01Workspace();
    writeFileSync(join(root, "compiles"), "not-a-directory\n");

    const result = await runInit([]);
    expect(result.exitCode).toBe(1);
    expect(result.result).toEqual({
      ok: false,
      disposition: "hold",
      reason: "COMPILE_STORE_INVALID",
      findings: ["Compile store is unavailable or invalid."],
    });
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("ERROR [COMPILE_STORE_INVALID] Compile store is unavailable or invalid.");
    expect(readFileSync(join(root, "workspace.yaml"), "utf8")).toBe("preserve-workspace\n");
    expect(readFileSync(join(root, "keys", ".gitignore"), "utf8")).toBe("preserve-keys\n");
  });
});
