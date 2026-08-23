import { cpSync, mkdtempSync, rmSync, readFileSync, writeFileSync, renameSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import { afterEach, describe, expect, it } from "vitest";

const SCRIPT = "scripts/check-s37-linux-phase-b-artifacts.mjs";
const SUPERVISOR_REL = "scripts/s37-linux-phase-b/supervisor.c";
const PROBE_REL = "scripts/s37-linux-phase-b/probe.c";
const ENVIRONMENT_RUNTIME_TEST = "scripts/s37-linux-phase-b/test-probe-canonical-environment.sh";
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
  it("keeps the sealed Bubblewrap seccomp policy and probe filter fail-closed", () => {
    const source = readFileSync(join(process.cwd(), SUPERVISOR_REL), "utf8");
    const probe = readFileSync(join(process.cwd(), PROBE_REL), "utf8");
    const bwrapFilter = source.match(
      /static const struct sock_filter bwrap_seccomp_filter\[\] = \{([\s\S]*?)\n\};/u,
    )?.[1];

    expect(bwrapFilter).toBeDefined();
    for (const syscall of [
      "clone", "clone3", "fork", "vfork", "socket", "socketpair", "connect", "bind",
      "listen", "accept", "accept4",
    ]) {
      expect(bwrapFilter).toContain(`DENY_ERRNO(__NR_${syscall})`);
    }
    for (const syscall of ["socket", "socketpair", "connect", "bind", "listen", "accept", "accept4"]) {
      expect(probe).toContain(`DENY_ERRNO(__NR_${syscall})`);
    }
  });

  it("preserves authenticated partial bootstrap failure classification", () => {
    const supervisor = readFileSync(join(process.cwd(), SUPERVISOR_REL), "utf8");
    const probe = readFileSync(join(process.cwd(), PROBE_REL), "utf8");

    expect(probe).not.toContain("filter_ok && prctl(PR_GET_NO_NEW_PRIVS");
    expect(probe).toContain("prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1");
    expect(supervisor).toContain("(UINT32_C(1) << 2) - UINT32_C(1)");
    expect(supervisor).toContain("observed == bootstrap_checks");
    expect(supervisor).toContain("(report.failed & (UINT32_C(1) << 1)) != 0");
  });

  it("pins Bubblewrap's unavoidable environment to exactly PWD=/", () => {
    const supervisor = readFileSync(join(process.cwd(), SUPERVISOR_REL), "utf8");
    const probe = readFileSync(join(process.cwd(), PROBE_REL), "utf8");

    expect(supervisor).toContain('(char *)"--chdir", (char *)"/"');
    expect(probe).toContain("static int has_canonical_environment(void)");
    expect(probe).toContain('strcmp(environ[0], "PWD=/") == 0');
    expect(probe).toContain("environ[1] == NULL");
    expect(probe).toContain('getcwd(cwd, sizeof(cwd)) != NULL && strcmp(cwd, "/") == 0');
  });

  it("executes the real canonical-environment predicate across positive and negative cases", () => {
    const result = spawnSync("/bin/sh", [ENVIRONMENT_RUNTIME_TEST, process.cwd()], {
      cwd: process.cwd(),
      encoding: "utf8",
      shell: false,
      timeout: 15_000,
    });

    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    expect(result.stdout).toBe("S37.1-B canonical environment runtime tests passed\n");
    expect(result.stderr).toBe("");
  });

  it("uses explicitly unsigned report masks under the frozen warning policy", () => {
    const supervisor = readFileSync(join(process.cwd(), SUPERVISOR_REL), "utf8");

    expect(supervisor).toMatch(
      /const uint32_t bootstrap_checks =\s*\(UINT32_C\(1\) << 2\) - UINT32_C\(1\);/u,
    );
    expect(supervisor).toContain("const uint32_t all_checks = (UINT32_C(1) << 10) - UINT32_C(1);");
    expect(supervisor).toContain("observed & ~all_checks");
  });

  it("classifies only the exact quarantined Bubblewrap seccomp setup failure", () => {
    const supervisor = readFileSync(join(process.cwd(), SUPERVISOR_REL), "utf8");

    expect(supervisor).toContain("SUPERVISOR_BWRAP_SECCOMP_SETUP = 78");
    expect(supervisor).toContain("is_exact_bwrap_seccomp_setup_failure");
    expect(supervisor).toContain("prctl(PR_SET_SECCOMP) reported EINVAL");
    expect(supervisor).toMatch(
      /WEXITSTATUS\(child_status\) == 1 &&[\s\S]*is_exact_bwrap_seccomp_setup_failure\(&out, &err\)/u,
    );
  });

  it.each([
    [
      "diagnostic pipe must remain close-on-exec",
      "pipe2(exec_errno_pipe, O_CLOEXEC)",
      "pipe2(exec_errno_pipe, 0)",
      "exec-errno-pipe-not-cloexec",
    ],
    [
      "inherited descriptor cleanup must preserve only diagnostic fd 4",
      "FIRST_CLOSE_FD = 5",
      "FIRST_CLOSE_FD = 4",
      "exec-errno-fd-not-preserved",
    ],
    [
      "diagnostic fd setup failure must remain explicit",
      "SUPERVISOR_CHILD_EXEC_ERRNO_FD = 72",
      "SUPERVISOR_CHILD_EXEC_ERRNO_FD = 76",
      "exec-errno-child-exit-missing",
    ],
    [
      "execve diagnostic must require empty stdout and stderr",
      "is_exact_bwrap_execve_failure(&out, &err, &exec_errno)",
      "is_exact_bwrap_execve_failure(&out, &out, &exec_errno)",
      "bwrap-execve-classification-missing",
    ],
  ] as const)("rejects when %s", (_label, match, replacement, violation) => {
    const root = mutateSupervisorToken(match, replacement);
    const result = runArtifacts([], { root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(`HOLD: supervisor:${violation}`);
  });

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

  it("rejects a missing durable canonical-environment runtime test", () => {
    const root = mkdtempSync(join(tmpdir(), "loopeix-s37b-artifacts-missing-runtime-"));
    cpSync(join(process.cwd(), "scripts"), join(root, "scripts"), { recursive: true });
    TEMP_ROOTS.push(root);

    renameSync(
      join(root, ENVIRONMENT_RUNTIME_TEST),
      join(root, ENVIRONMENT_RUNTIME_TEST.replace(".sh", ".bak")),
    );
    const result = runArtifacts([], { root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: canonical-environment-runtime-test:missing");
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
    ["supervisor must pin the canonical cwd", '(char *)"--chdir", (char *)"/"', '(char *)"--chdir", (char *)"/tmp"'],
  ] as const)("%s", (label, match, replacement) => {
    expect(label).toBeTruthy();
    const root = mutateSupervisorToken(match, replacement);
    const result = runArtifacts([], { root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD:");
  });

  it("rejects comment-only token camouflage in supervisor exec", () => {
    const root = mutateSupervisorToken(
      "execve(argv[1], bwrap_argv, empty_env);",
      'execve("/bin/sh", bwrap_argv, empty_env); /* execve(argv[1], bwrap_argv, empty_env); */',
    );
    const result = runArtifacts([], { root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: supervisor:supervisor-can-use-shell-wrapper");
  });

  it.each([
    [
      "a later environment override",
      '(char *)"--", (char *)"/loopeix-s37-probe", NULL,',
      '(char *)"--setenv", (char *)"EXTRA", (char *)"1",\n      (char *)"--", (char *)"/loopeix-s37-probe", NULL,',
    ],
    [
      "a duplicate late chdir",
      '(char *)"--", (char *)"/loopeix-s37-probe", NULL,',
      '(char *)"--chdir", (char *)"/tmp",\n      (char *)"--", (char *)"/loopeix-s37-probe", NULL,',
    ],
    [
      "reordered clear/unset operations",
      '(char *)"--clearenv", (char *)"--unsetenv", (char *)"PWD",',
      '(char *)"--unsetenv", (char *)"PWD", (char *)"--clearenv",',
    ],
    [
      "an unrecognized Bubblewrap flag",
      '(char *)"--new-session",',
      '(char *)"--share-net", (char *)"--new-session",',
    ],
  ] as const)("rejects %s in the exact Bubblewrap argv", (_label, match, replacement) => {
    const root = mutateSupervisorToken(match, replacement);
    const result = runArtifacts([], { root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("HOLD: supervisor:bwrap-argv-not-exact");
  });

  it.each([
    ["process creation", "    DENY_ERRNO(__NR_clone),", "    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),", "clone"],
    ["extended process creation", "    DENY_ERRNO(__NR_clone3),", "    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),", "clone3"],
    ["fork", "    DENY_ERRNO(__NR_fork),", "    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),", "fork"],
    ["vfork", "    DENY_ERRNO(__NR_vfork),", "    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),", "vfork"],
    ["network creation", "    DENY_ERRNO(__NR_socket),", "    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),", "socket"],
    ["network pair creation", "    DENY_ERRNO(__NR_socketpair),", "    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),", "socketpair"],
    ["network connection", "    DENY_ERRNO(__NR_connect),", "    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),", "connect"],
    ["network binding", "    DENY_ERRNO(__NR_bind),", "    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),", "bind"],
    ["network listening", "    DENY_ERRNO(__NR_listen),", "    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),", "listen"],
    ["network acceptance", "    DENY_ERRNO(__NR_accept),", "    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),", "accept"],
    ["network acceptance", "    DENY_ERRNO(__NR_accept4),", "    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),", "accept4"],
  ] as const)("rejects missing %s denial in the sealed policy", (_label, match, replacement, syscall) => {
    const root = mutateSupervisorToken(match, replacement);
    const result = runArtifacts([], { root });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(`HOLD: supervisor:bwrap-filter-deny-missing:${syscall}`);
  });

  it.each([
    ["probe must keep fixed 64-byte report", "_Static_assert(sizeof(struct probe_report) == 64, \"probe report must remain fixed at 64 bytes\");", "_Static_assert(sizeof(struct probe_report) == 32, \"probe report drift\");"],
    ["probe must deny syscall families", "DENY_ERRNO(__NR_execve)", "DENY_ERRNO(__NR_fstat)"],
    ["probe must enforce no_new_privs", "prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)", "prctl(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0)"],
    ["probe must keep mmap check", "PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0", "PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0"],
    ["probe must require exact canonical PWD", 'strcmp(environ[0], "PWD=/") == 0', 'strcmp(environ[0], "PWD=/tmp") == 0'],
    ["probe must reject every extra environment entry", "environ[1] == NULL", "environ[1] != NULL"],
    ["probe must verify the actual canonical cwd", 'strcmp(cwd, "/") == 0', 'strcmp(cwd, "/tmp") == 0'],
    ["probe must reject permissive predicate suffixes", 'strcmp(cwd, "/") == 0;', 'strcmp(cwd, "/") == 0 || 1;'],
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
