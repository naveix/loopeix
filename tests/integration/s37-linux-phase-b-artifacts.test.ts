import { cpSync, mkdtempSync, rmSync, readFileSync, writeFileSync, renameSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import { afterEach, describe, expect, it } from "vitest";

const SCRIPT = "scripts/check-s37-linux-phase-b-artifacts.mjs";
const SUPERVISOR_REL = "scripts/s37-linux-phase-b/supervisor.c";
const PROBE_REL = "scripts/s37-linux-phase-b/probe.c";
const TEMP_ROOTS: string[] = [];

function runArtifacts(extraArgs: string[] = [], options: { root?: string } = {}) {
  const args = options.root === undefined ? extraArgs : ["--root", options.root, ...extraArgs];
  return spawnSync(process.execPath, [SCRIPT, ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    shell: false,
    timeout: 15_000,
    maxBuffer: 2 * 1024 * 1024,
  });
}

function writeFixture(override?: (content: string) => string, target = SUPERVISOR_REL) {
  const root = mkdtempSync(join(tmpdir(), "loopeix-s37b-artifacts-"));
  const targetSupervisor = join(root, SUPERVISOR_REL);

  cpSync(join(process.cwd(), "scripts"), join(root, "scripts"), { recursive: true });
  TEMP_ROOTS.push(root);

  if (target !== SUPERVISOR_REL) {
    throw new Error(`unexpected fixture target: ${target}`);
  }
  const source = readFileSync(join(process.cwd(), SUPERVISOR_REL), "utf8");
  writeFileSync(targetSupervisor, override?.(source) ?? source, "utf8");

  return { root };
}

function writeProbeFixture(override?: (content: string) => string) {
  const root = mkdtempSync(join(tmpdir(), "loopeix-s37b-artifacts-"));
  cpSync(join(process.cwd(), "scripts"), join(root, "scripts"), { recursive: true });
  const targetProbe = join(root, PROBE_REL);
  const sourceProbe = readFileSync(join(process.cwd(), PROBE_REL), "utf8");
  writeFileSync(targetProbe, override?.(sourceProbe) ?? sourceProbe, "utf8");
  TEMP_ROOTS.push(root);
  return { root, targetProbe };
}

function mutateSupervisorToken(token: string, replacement: string) {
  const fixture = writeFixture((content) => content.replace(token, replacement));
  return fixture.root;
}

function mutateProbeToken(token: string, replacement: string) {
  const fixture = writeProbeFixture((content) => content.replace(token, replacement));
  return fixture.root;
}

afterEach(() => {
  while (TEMP_ROOTS.length > 0) {
    const root = TEMP_ROOTS.pop();
    if (root !== undefined) rmSync(root, { force: true, recursive: true });
  }
});

describe("S37.1-B artifacts static gate", () => {
  it("passes pristine supervisor + probe sources from repo root", () => {
    const result = runArtifacts();
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    expect(result.stdout).toBe(
      "S37.1-B artifacts static gate: PASS\nartifact code review only; live conformance not executed\n",
    );
    expect(result.stderr).toBe("");
  });

  it("passes with an explicit --root path", () => {
    const root = mkdtempSync(join(tmpdir(), "loopeix-s37b-artifacts-root-"));
    cpSync("scripts", join(root, "scripts"), { recursive: true });
    TEMP_ROOTS.push(root);

    const result = runArtifacts([], { root });
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("S37.1-B artifacts static gate: PASS");
  });

  it("rejects forbidden live flags", () => {
    for (const flag of ["--live", "--ssh", "--vps"]) {
      const result = runArtifacts([flag]);
      expect(result.status).toBe(64);
      expect(result.stderr).toContain(`unknown argument: ${flag}`);
    }
  });

  it("rejects --root with missing value", () => {
    const result = runArtifacts(["--root"]);
    expect(result.status).toBe(64);
    expect(result.stderr).toContain("--root requires an absolute repository path");
  });

  it("rejects --root with a relative path", () => {
    const result = runArtifacts([], { root: "scripts" });
    expect(result.status).toBe(64);
    expect(result.stderr).toContain("--root requires an absolute repository path");
  });

  it("rejects unknown arguments", () => {
    const result = runArtifacts(["--not-a-flag"]);
    expect(result.status).toBe(64);
    expect(result.stderr).toContain("unknown argument: --not-a-flag");
  });

  it("rejects missing supervisor source", () => {
    const root = mkdtempSync(join(tmpdir(), "loopeix-s37b-artifacts-missing-"));
    cpSync(join(process.cwd(), "scripts"), join(root, "scripts"), { recursive: true });
    TEMP_ROOTS.push(root);

    renameSync(join(root, SUPERVISOR_REL), join(root, SUPERVISOR_REL.replace(".c", ".bak")));
    const result = runArtifacts([], { root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: supervisor.c:missing");
  });

  it.each([
    ["supervisor must keep 1000 ms deadline", "DEADLINE_MS = 1000", "DEADLINE_MS = 999"],
    ["supervisor must keep 1024 byte stream cap", "STREAM_CAP = 1024", "STREAM_CAP = 2048"],
    [
      "supervisor must validate no shell/system/popen",
      "execve(argv[1], bwrap_argv, empty_env);",
      "system(\"echo breach\")",
    ],
    ["supervisor must include memfd seals", "F_SEAL_WRITE", "F_SEAL_GROW"],
    ["supervisor must pass a seccomp FD", '(char *)"--seccomp", policy_text,', '(char *)"--noseccomp", policy_text,'],
  ] as const)("%s", (label, match, replacement) => {
    expect(label).toBeTruthy();
    const root = mutateSupervisorToken(match, replacement);
    const result = runArtifacts([], { root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD:");
  });

  it.each([
    ["probe must keep fixed 64-byte report", "_Static_assert(sizeof(struct probe_report) == 64, \"probe report must remain fixed at 64 bytes\");", "_Static_assert(sizeof(struct probe_report) == 32, \"probe report drift\");"],
    ["probe must deny syscall families", "DENY_ERRNO(__NR_execve)", "DENY_ERRNO(__NR_fstat)"],
    ["probe must enforce no_new_privs", "prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)", "prctl(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0)"],
    ["probe must keep mmap check", "PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0", "PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0"],
  ] as const)("%s", (label, match, replacement) => {
    expect(label).toBeTruthy();
    const root = mutateProbeToken(match, replacement);
    const result = runArtifacts([], { root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD:");
  });

  it("rejects duplicate --root", () => {
    const result = spawnSync(process.execPath, [
      SCRIPT,
      "--root", process.cwd(),
      "--root", process.cwd(),
    ], {
      cwd: process.cwd(),
      encoding: "utf8",
      shell: false,
    });
    expect(result.status).toBe(64);
    expect(result.stderr).toContain("duplicate argument: --root");
  });
});
