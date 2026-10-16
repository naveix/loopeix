import { readFileSync, existsSync, lstatSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const DEFAULT_ROOT = resolve(SCRIPT_DIR, "..");
const SUPERVISOR_PATH = "scripts/s37-linux-phase-b/supervisor.c";
const PROBE_PATH = "scripts/s37-linux-phase-b/probe.c";
const CANONICAL_ENVIRONMENT_TEST_PATH = "scripts/s37-linux-phase-b/test-probe-canonical-environment.sh";
const REJECTED_FLAGS = new Set(["--live", "--ssh", "--vps"]);

function usage(message) {
  if (message) process.stderr.write(`${message}\n`);
  process.stderr.write("usage: node scripts/check-s37-linux-phase-b-artifacts.mjs [--root <absolute-path>]\n");
  process.exit(64);
}

function fail(violations) {
  const unique = [...new Set(violations)].sort((left, right) => left.localeCompare(right));
  process.stderr.write(`${unique.map((entry) => `HOLD: ${entry}`).join("\n")}\n`);
  process.exit(1);
}

function cli() {
  const args = process.argv.slice(2);
  let root = null;
  for (let index = 0; index < args.length; index += 1) {
    const flag = args[index];
    const value = args[index + 1];
    if (REJECTED_FLAGS.has(flag)) usage(`unknown argument: ${flag}`);
    if (flag !== "--root") usage(`unknown argument: ${flag}`);
    if (value === undefined || value.startsWith("--")) usage("--root requires an absolute repository path");
    if (!value.startsWith("/")) usage("--root requires an absolute repository path");
    if (root !== null) usage("duplicate argument: --root");
    root = value;
    index += 1;
  }
  return resolve(root ?? DEFAULT_ROOT);
}

function assert(condition, label, violations, message) {
  if (!condition) violations.push(`${label}:${message}`);
}

function assertMatch(source, label, pattern, violations, message) {
  assert(pattern.test(source), label, violations, message);
}

function assertAbsent(source, label, pattern, violations, message) {
  assert(!pattern.test(source), label, violations, message);
}

function collectMatches(source, pattern) {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
  return [...source.matchAll(new RegExp(pattern.source, flags))].map((match) => match[1]);
}

function stripCComments(source) {
  let result = "";
  let index = 0;
  while (index < source.length) {
    const current = source[index];
    const next = source[index + 1];
    if (current === "\"" || current === "'") {
      const quote = current;
      result += current;
      index += 1;
      while (index < source.length) {
        const value = source[index];
        result += value;
        index += 1;
        if (value === "\\") {
          if (index < source.length) {
            result += source[index];
            index += 1;
          }
          continue;
        }
        if (value === quote) break;
      }
      continue;
    }
    if (current === "/" && next === "/") {
      result += "  ";
      index += 2;
      while (index < source.length && source[index] !== "\n") {
        result += " ";
        index += 1;
      }
      continue;
    }
    if (current === "/" && next === "*") {
      result += "  ";
      index += 2;
      while (index < source.length) {
        const value = source[index];
        const following = source[index + 1];
        if (value === "\n") result += "\n";
        else result += " ";
        index += 1;
        if (value === "*" && following === "/") {
          result += " ";
          index += 1;
          break;
        }
      }
      continue;
    }
    result += current;
    index += 1;
  }
  return result;
}

function extractCArrayTokens(source, symbol, violations) {
  const block = collectMatches(source, new RegExp(
    String.raw`char \*const ${symbol}\[\] = \{([\s\S]*?)\};`,
    "u",
  ));
  if (block.length !== 1) {
    violations.push(`${symbol}:missing-or-ambiguous`);
    return [];
  }
  return stripCComments(block[0])
    .split(",")
    .map((token) => token.replace(/\s+/gu, " ").trim().replace(/^\(char \*\)\s*/u, ""))
    .filter((token) => token.length > 0);
}

function validateSupervisor(source, violations) {
  const supervisorFileLabel = "supervisor";
  assertMatch(source, supervisorFileLabel, /enum \{ DEADLINE_MS = 1000,\s*STREAM_CAP = 1024 \}/u, violations, "missing-or-not-exact-constants");
  assertMatch(source, supervisorFileLabel, /enum \{ POLICY_FD = 3,\s*EXEC_ERRNO_FD = 4,\s*FIRST_CLOSE_FD = 5 \}/u, violations, "exec-errno-fd-not-preserved");
  assertMatch(source, supervisorFileLabel, /struct capture[\s\S]*uint8_t bytes\[STREAM_CAP\];/u, violations, "capture-buffer-width-not-streamcap");
  assertMatch(source, supervisorFileLabel, /int is_absolute_regular_executable\(const char \*path\)/u, violations, "missing-absolute-exec-validation");
  assertMatch(source, supervisorFileLabel, /lstat\(path, &link_status\).*?!S_ISLNK/su, violations, "symlink-executable-not-rejected");
  assertMatch(source, supervisorFileLabel, /realpath\(path, resolved\).*?strcmp\(path, resolved\) == 0/su, violations, "executable-path-not-canonical");
  assertMatch(source, supervisorFileLabel, /S_IWGRP \| S_IWOTH/u, violations, "writable-executable-not-rejected");
  assertMatch(source, supervisorFileLabel, /main\(int argc, char \*\*argv\)/u, violations, "entrypoint-signature-changed");
  assertMatch(source, supervisorFileLabel, /argc != 3/su, violations, "argc-contract-changed");
  assertMatch(
    source,
    supervisorFileLabel,
    /is_absolute_regular_executable\(argv\[1\]\).*is_absolute_regular_executable\(argv\[2\]\)/us,
    violations,
    "binary-and-probe-must-be-absolute",
  );
  assertMatch(source, supervisorFileLabel, /int make_policy_memfd\(void\)/u, violations, "missing-memfd-policy-builder");
  assertMatch(source, supervisorFileLabel, /F_ADD_SEALS,\s*F_SEAL_SEAL \| F_SEAL_SHRINK \| F_SEAL_GROW \| F_SEAL_WRITE/u, violations, "memfd-not-sealed");
  assertMatch(source, supervisorFileLabel, /MFD_ALLOW_SEALING/u, violations, "memfd-not-allow-sealing");
  assertMatch(source, supervisorFileLabel, /F_SETFD,\s*flags & ~FD_CLOEXEC/u, violations, "memfd-fd-flag-not-held-open");
  assertMatch(source, supervisorFileLabel, /prctl\(PR_SET_CHILD_SUBREAPER,\s*1\)/u, violations, "missing-child-subreaper");

  const bwrapFilterBlocks = collectMatches(
    source,
    /static const struct sock_filter bwrap_seccomp_filter\[\] = \{([\s\S]*?)\n\};/u,
  );
  if (bwrapFilterBlocks.length !== 1) {
    violations.push("supervisor:bwrap-filter-missing-or-ambiguous");
  } else {
    const bwrapFilter = stripCComments(bwrapFilterBlocks[0]);
    for (const syscall of [
      "clone", "clone3", "fork", "vfork", "socket", "socketpair", "connect", "bind",
      "listen", "accept", "accept4",
    ]) {
      assertMatch(
        bwrapFilter,
        supervisorFileLabel,
        new RegExp(`DENY_ERRNO\\(__NR_${syscall}\\)`, "u"),
        violations,
        `bwrap-filter-deny-missing:${syscall}`,
      );
    }
  }

  const argv = extractCArrayTokens(source, "bwrap_argv", violations);
  if (argv.length > 0) {
    const expected = [
      "argv[1]",
      '"--unshare-user"', '"--unshare-ipc"', '"--unshare-pid"',
      '"--unshare-net"', '"--unshare-uts"', '"--disable-userns"',
      '"--clearenv"', '"--unsetenv"', '"PWD"',
      '"--chdir"', '"/"',
      '"--new-session"', '"--die-with-parent"',
      '"--cap-drop"', '"ALL"',
      '"--ro-bind"', "argv[2]", '"/loopeix-s37-probe"',
      '"--remount-ro"', '"/"',
      '"--seccomp"', "policy_text",
      '"--"', '"/loopeix-s37-probe"', "NULL",
    ];
    assert(JSON.stringify(argv) === JSON.stringify(expected), supervisorFileLabel, violations, "bwrap-argv-not-exact");
    assertMatch(source, supervisorFileLabel, /"--remount-ro",\s*\(char \*\)"\/"/u, violations, "bwrap-ro-root-bind-missing");
    assertMatch(source, supervisorFileLabel, /"--chdir",\s*\(char \*\)"\/"/u, violations, "bwrap-canonical-chdir-missing");
  assertMatch(source, supervisorFileLabel, /"--seccomp",\s*policy_text,/u, violations, "bwrap-seccomp-missing");
    assertMatch(source, supervisorFileLabel, /"--",/u, violations, "bwrap-exec-separator-missing");
  }
  assertMatch(source, supervisorFileLabel, /char \*const empty_env\[\] = \{NULL\};/u, violations, "empty-env-missing");
  assertMatch(source, supervisorFileLabel, /static char policy_text\[\] = "3";/u, violations, "seccomp-fd-not-fixed");
  assertMatch(source, supervisorFileLabel, /policy_fd != POLICY_FD && dup2\(policy_fd, POLICY_FD\)/u, violations, "seccomp-fd-not-duplicated");
  assertMatch(source, supervisorFileLabel, /exec_errno_pipe\[1\] != EXEC_ERRNO_FD &&[\s\S]*dup2\(exec_errno_pipe\[1\], EXEC_ERRNO_FD\)[\s\S]*fcntl\(EXEC_ERRNO_FD, F_SETFD, FD_CLOEXEC\)/u, violations, "exec-errno-fd-not-preserved");
  assertMatch(source, supervisorFileLabel, /syscall\(SYS_close_range,\s*\(unsigned int\)FIRST_CLOSE_FD,\s*~0u,\s*0u\)/u, violations, "inherited-fds-not-closed");
  assertMatch(source, supervisorFileLabel, /getrlimit\(RLIMIT_NOFILE, &limit\)/u, violations, "fd-close-fallback-limit-missing");
  assertMatch(source, supervisorFileLabel, /for \(int fd = FIRST_CLOSE_FD; fd < \(int\)limit\.rlim_cur; \+\+fd\)/u, violations, "fd-close-fallback-loop-missing");
  assertMatch(source, supervisorFileLabel, /pipe2\(stdout_pipe,\s*O_CLOEXEC\)/u, violations, "separate-stdout-pipe-missing");
  assertMatch(source, supervisorFileLabel, /pipe2\(stderr_pipe,\s*O_CLOEXEC\)/u, violations, "separate-stderr-pipe-missing");
  assertMatch(source, supervisorFileLabel, /pipe2\(exec_errno_pipe,\s*O_CLOEXEC\)/u, violations, "exec-errno-pipe-not-cloexec");
  assertMatch(source, supervisorFileLabel, /setpgid\(0,\s*0\) != 0/u, violations, "child-no-setpgid");
  assertMatch(source, supervisorFileLabel, /setpgid\(child,\s*child\)/u, violations, "parent-no-child-pgrp");
  assertMatch(source, supervisorFileLabel, /PR_SET_CHILD_SUBREAPER/u, violations, "subreaper-custody-missing");
  assertMatch(source, supervisorFileLabel, /waitpid\(-1,\s*&status,\s*WNOHANG\)/u, violations, "whole-child-tree-reap-missing");
  assertMatch(source, supervisorFileLabel, /reap_all_children\(child,/u, violations, "bounded-descendant-reap-missing");
  assertMatch(source, supervisorFileLabel, /kill\(-child,\s*SIGKILL\)/u, violations, "no-pgid-kill");
  assertMatch(source, supervisorFileLabel, /capture_available\(&out\);/u, violations, "stdout-collection-regressed");
  assertMatch(source, supervisorFileLabel, /capture_available\(&err\);/u, violations, "stderr-collection-regressed");
  assertMatch(source, supervisorFileLabel, /err->length != 0 \|\| out->length !=/u, violations, "no-stdout-stderr-quarantine");
  assertMatch(source, supervisorFileLabel, /int report_result\(const struct capture \*out, const struct capture \*err\)/u, violations, "no-output-validation");
  assertMatch(source, supervisorFileLabel, /const uint32_t bootstrap_checks =[\s\S]*\(UINT32_C\(1\) << 2\) - UINT32_C\(1\);[\s\S]*const uint32_t all_checks = \(UINT32_C\(1\) << 10\) - UINT32_C\(1\);/u, violations, "bootstrap-report-mask-missing");
  assertMatch(source, supervisorFileLabel, /observed == bootstrap_checks &&[\s\S]*\(report\.failed & \(UINT32_C\(1\) << 1\)\) != 0/u, violations, "partial-bootstrap-report-not-authenticated");
  assertMatch(source, supervisorFileLabel, /SUPERVISOR_PROBE_NO_NEW_PRIVS = 80[\s\S]*SUPERVISOR_PROBE_PRIVATE_MMAP = 89/u, violations, "probe-failure-exit-map-missing");
  assertMatch(source, supervisorFileLabel, /SUPERVISOR_CHILD_EXEC_ERRNO_FD = 72[\s\S]*SUPERVISOR_CHILD_CLOSE_RANGE = 77/u, violations, "exec-errno-child-exit-missing");
  assertMatch(source, supervisorFileLabel, /SUPERVISOR_BWRAP_SECCOMP_SETUP = 78/u, violations, "bwrap-seccomp-setup-exit-missing");
  assertMatch(source, supervisorFileLabel, /SUPERVISOR_BWRAP_EXECVE_ERRNO = 79/u, violations, "bwrap-execve-exit-missing");
  assertMatch(source, supervisorFileLabel, /const uint32_t value = \(uint32_t\)error_number;[\s\S]*write\(EXEC_ERRNO_FD, &value, sizeof\(value\)\)[\s\S]*_exit\(127\)/u, violations, "exec-errno-child-witness-missing");
  assertMatch(source, supervisorFileLabel, /int is_exact_bwrap_execve_failure\(const struct capture \*out,[\s\S]*out->length != 0 \|\| err->length != 0 \|\| exec_errno->overflow[\s\S]*exec_errno->length != sizeof\(uint32_t\)[\s\S]*error_number > 0 && error_number <= 4095/u, violations, "bwrap-execve-classifier-not-exact");
  assertMatch(source, supervisorFileLabel, /WEXITSTATUS\(child_status\) == 127 &&[\s\S]*is_exact_bwrap_execve_failure\(&out, &err, &exec_errno\)[\s\S]*return SUPERVISOR_BWRAP_EXECVE_ERRNO/u, violations, "bwrap-execve-classification-missing");
  assertMatch(source, supervisorFileLabel, /int is_exact_bwrap_seccomp_setup_failure\(const struct capture \*out,[\s\S]*out->length != 0[\s\S]*err->length == diagnostic_length[\s\S]*err->length == diagnostic_length \* 2u/u, violations, "bwrap-seccomp-diagnostic-must-be-exact-and-quarantined");
  assertMatch(source, supervisorFileLabel, /WEXITSTATUS\(child_status\) == 1 &&[\s\S]*is_exact_bwrap_seccomp_setup_failure\(&out, &err\)[\s\S]*return SUPERVISOR_BWRAP_SECCOMP_SETUP/u, violations, "bwrap-seccomp-setup-classification-missing");
  assertMatch(source, supervisorFileLabel, /WEXITSTATUS\(child_status\) == 122 && report_status >= 80 && report_status <= 89/u, violations, "probe-failure-report-not-preserved");
  assertMatch(source, supervisorFileLabel, /\bexecve\(argv\[1\],\s*bwrap_argv,\s*empty_env\);/u, violations, "supervisor-can-use-shell-wrapper");
  assertMatch(source, supervisorFileLabel, /const int execve_errno = errno;[\s\S]*exit_with_execve_errno\(execve_errno\)/u, violations, "exec-failure-path-missing");
  assertMatch(source, supervisorFileLabel, /SUPERVISOR_SETUP|SUPERVISOR_TIMEOUT_REAPED|SUPERVISOR_OUTPUT_OVERFLOW|SUPERVISOR_CHILD_FAILURE|SUPERVISOR_REPORT_INVALID/u, violations, "supervisor-exit-enum-drift");

  assertAbsent(source, supervisorFileLabel, /\bsystem\s*\(/u, violations, "forbidden-system-call");
  assertAbsent(source, supervisorFileLabel, /\bpopen\s*\(/u, violations, "forbidden-popen-call");
  assertAbsent(source, supervisorFileLabel, /\b(?:printf|fprintf|dprintf|puts|fputs)\s*\(/u, violations, "supervisor-must-not-emit-output");
}

function validateProbe(source, violations) {
  const probeFileLabel = "probe";
  assertMatch(source, probeFileLabel, /_Static_assert\(sizeof\(struct probe_report\) == 64, /u, violations, "probe-report-size-drift");
  assertMatch(source, probeFileLabel, /_Static_assert\(sizeof\(struct probe_report\) == 64/u, violations, "probe-report-size-drift");
  assertMatch(source, probeFileLabel, /enum probe_check/u, violations, "probe-check-enum-missing");
  assertMatch(source, probeFileLabel, /#define DENY_ERRNO/u, violations, "probe-deny-macro-missing");
  assertMatch(source, probeFileLabel, /AUDIT_ARCH_X86_64/u, violations, "probe-no-arch-gate");
  assertMatch(source, probeFileLabel, /BPF_STMT\(BPF_RET \| BPF_K, SECCOMP_RET_KILL_PROCESS\)/u, violations, "probe-arch-mismatch-not-kill");
  assertMatch(source, probeFileLabel, /prctl\(PR_SET_NO_NEW_PRIVS,\s*1/u, violations, "probe-must-set-no-new-privs");
  assertAbsent(source, probeFileLabel, /filter_ok && prctl\(PR_GET_NO_NEW_PRIVS/u, violations, "no-new-privs-observation-coupled-to-filter");
  assertMatch(source, probeFileLabel, /record_check\(&report, CHECK_NO_NEW_PRIVS,\s*prctl\(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0\) == 1\)/u, violations, "no-new-privs-independent-observation-missing");
  assertMatch(source, probeFileLabel, /SECCOMP_MODE_FILTER/u, violations, "probe-must-install-filter");
  assertMatch(source, probeFileLabel, /CHECK_NO_NEW_PRIVS/u, violations, "probe-check-no-new-privs-missing");
  assertMatch(source, probeFileLabel, /CHECK_SECOND_FILTER/u, violations, "probe-check-second-filter-missing");
  assertMatch(source, probeFileLabel, /CHECK_CANONICAL_ENVIRONMENT/u, violations, "probe-check-canonical-environment-missing");
  assertMatch(source, probeFileLabel, /CHECK_EXACT_FDS/u, violations, "probe-check-fd-set-missing");
  assertMatch(source, probeFileLabel, /CHECK_FILESYSTEM/u, violations, "probe-check-filesystem-missing");
  assertMatch(source, probeFileLabel, /CHECK_FORK_CLONE/u, violations, "probe-check-process-missing");
  assertMatch(source, probeFileLabel, /CHECK_EXEC_REENTRY/u, violations, "probe-check-exec-missing");
  assertMatch(source, probeFileLabel, /CHECK_NETWORK/u, violations, "probe-check-network-missing");
  assertMatch(source, probeFileLabel, /CHECK_ABSENT_PATHS/u, violations, "probe-check-paths-missing");
  assertMatch(source, probeFileLabel, /\bCHECK_PRIVATE_MMAP\b/u, violations, "probe-check-mmap-missing");
  assertMatch(source, probeFileLabel, /enum \{ ALL_CHECKS = \(1u << 10\) - 1u \}/u, violations, "probe-not-closed-all-rows");
  const canonicalEnvironmentBlocks = collectMatches(
    source,
    /static int has_canonical_environment\(void\) \{([\s\S]*?)\n\}/u,
  );
  assert(canonicalEnvironmentBlocks.length === 1, probeFileLabel, violations, "probe-canonical-environment-fn-missing-or-ambiguous");
  if (canonicalEnvironmentBlocks.length === 1) {
    const canonicalEnvironmentBody = stripCComments(canonicalEnvironmentBlocks[0]).replace(/\s+/gu, " ").trim();
    const expectedCanonicalEnvironmentBody = [
      "char cwd[2];",
      "return environ != NULL && environ[0] != NULL &&",
      'strcmp(environ[0], "PWD=/") == 0 && environ[1] == NULL &&',
      'getcwd(cwd, sizeof(cwd)) != NULL && strcmp(cwd, "/") == 0;',
    ].join(" ");
    assert(canonicalEnvironmentBody === expectedCanonicalEnvironmentBody, probeFileLabel, violations, "probe-canonical-environment-body-not-exact");
  }
  assertMatch(source, probeFileLabel, /environ != NULL && environ\[0\] != NULL/u, violations, "probe-canonical-environment-null-guard-missing");
  assertMatch(source, probeFileLabel, /strcmp\(environ\[0\], "PWD=\/"\) == 0 && environ\[1\] == NULL/u, violations, "probe-canonical-environment-not-exact");
  assertMatch(source, probeFileLabel, /getcwd\(cwd, sizeof\(cwd\)\) != NULL && strcmp\(cwd, "\/"\) == 0/u, violations, "probe-canonical-cwd-not-exact");
  assertAbsent(source, probeFileLabel, /\bgetenv\s*\(/u, violations, "probe-canonical-environment-must-not-use-getenv");
  assertAbsent(source, probeFileLabel, /\bunsetenv\s*\(/u, violations, "probe-canonical-environment-must-not-self-clean");
  assertMatch(source, probeFileLabel, /record_check\(&report, CHECK_CANONICAL_ENVIRONMENT,\s*has_canonical_environment\(\)\);/u, violations, "probe-canonical-environment-wiring-not-exact");
  assertMatch(source, probeFileLabel, /static int has_exact_file_descriptors\(void\)/u, violations, "probe-fd-check-missing");
  assertMatch(source, probeFileLabel, /for \(int fd = 3; fd < 4096; \+\+fd\)/u, violations, "probe-fd-loop-drift");
  assertMatch(source, probeFileLabel, /static int filesystem_writes_are_denied\(void\)/u, violations, "probe-filesystem-check-missing");
  assertMatch(source, probeFileLabel, /write_is_denied\("\/loopeix-s37-write"\)/u, violations, "probe-filesystem-path-set-changed");
  assertMatch(source, probeFileLabel, /static int process_creation_is_denied\(void\)/u, violations, "probe-process-check-missing");
  assertMatch(source, probeFileLabel, /#ifdef __NR_clone3/u, violations, "probe-process-deny-row-missing");
  assertMatch(source, probeFileLabel, /static int exec_reentry_is_denied\(void\)/u, violations, "probe-exec-reentry-check-missing");
  assertMatch(source, probeFileLabel, /#ifdef __NR_execveat/u, violations, "probe-exec-syscall-row-missing");
  assertMatch(source, probeFileLabel, /static int network_is_denied\(void\)/u, violations, "probe-network-check-missing");
  assertMatch(source, probeFileLabel, /static int tools_and_credentials_are_absent\(void\)/u, violations, "probe-tool-cred-check-missing");
  assertMatch(source, probeFileLabel, /"\/bin\/sh"/u, violations, "probe-tool-paths-regressed");
  assertMatch(source, probeFileLabel, /static int private_memory_is_bounded_and_writable\(void\)/u, violations, "probe-mmap-check-missing");
  assertMatch(source, probeFileLabel, /\bargc != 1\b/u, violations, "probe-argc-contract-missing");
  assertMatch(source, probeFileLabel, /write_full\(STDOUT_FILENO, &report, sizeof\(report\)\)/u, violations, "probe-report-not-written-to-stdout");
  assertMatch(source, probeFileLabel, /report\.passed == ALL_CHECKS/u, violations, "probe-closed-pass-maybe-violated");
  assertMatch(source, probeFileLabel, /report\.failed == 0/u, violations, "probe-failed-mask-not-enforced");
  assertMatch(source, probeFileLabel, /execve\(argv\[0\], argv, envp\);/u, violations, "probe-no-self-reentry");
  assertMatch(source, probeFileLabel, /report\.passed == ALL_CHECKS && report\.failed == 0 \? 0 : 122/u, violations, "probe-return-code-not-hardened");

  for (const syscall of [
    "clone", "clone3", "fork", "vfork", "execve", "execveat", "socket",
    "socketpair", "connect", "bind", "listen", "accept", "accept4",
  ]) {
    assertMatch(source, probeFileLabel, new RegExp(`DENY_ERRNO\\(__NR_${syscall}\\)`, "u"), violations, `probe-deny-syscall-missing:${syscall}`);
  }
  for (const family of ["AF_INET", "AF_INET6", "AF_UNIX", "AF_NETLINK"]) {
    assertMatch(source, probeFileLabel, new RegExp(`socket_creation_is_denied\\(${family},`, "u"), violations, `probe-network-family-missing:${family}`);
  }
  assertMatch(source, probeFileLabel, /SOCK_STREAM/u, violations, "probe-network-stream-missing");
  assertMatch(source, probeFileLabel, /SOCK_DGRAM/u, violations, "probe-network-datagram-missing");
  assertMatch(source, probeFileLabel, /posix_spawn\(/u, violations, "probe-posix-spawn-witness-missing");
  assertMatch(source, probeFileLabel, /shared_file_mmap_write_is_denied/u, violations, "probe-shared-mmap-write-witness-missing");
  assertMatch(source, probeFileLabel, /PROT_READ \| PROT_WRITE, MAP_SHARED, fd, 0/u, violations, "probe-shared-mmap-mode-missing");
}

function main() {
  const rootDir = cli();
  const supervisorPath = resolve(rootDir, SUPERVISOR_PATH);
  const probePath = resolve(rootDir, PROBE_PATH);
  const canonicalEnvironmentTestPath = resolve(rootDir, CANONICAL_ENVIRONMENT_TEST_PATH);
  const violations = [];
  try {
    const stats = statSync(rootDir);
    if (!stats.isDirectory()) usage(`${rootDir} is not a directory`);
  } catch {
    usage(`${rootDir} does not exist`);
  }
  if (!existsSync(supervisorPath) || !existsSync(probePath) || !existsSync(canonicalEnvironmentTestPath)) {
    if (!existsSync(supervisorPath)) violations.push("supervisor.c:missing");
    if (!existsSync(probePath)) violations.push("probe.c:missing");
    if (!existsSync(canonicalEnvironmentTestPath)) violations.push("canonical-environment-runtime-test:missing");
    fail(violations);
  }

  const canonicalEnvironmentTestStats = lstatSync(canonicalEnvironmentTestPath);
  assert(canonicalEnvironmentTestStats.isFile(), "canonical-environment-runtime-test", violations, "not-regular-file");
  assert(!canonicalEnvironmentTestStats.isSymbolicLink(), "canonical-environment-runtime-test", violations, "symlink-forbidden");
  assert((canonicalEnvironmentTestStats.mode & 0o111) !== 0, "canonical-environment-runtime-test", violations, "not-executable");
  assert((canonicalEnvironmentTestStats.mode & 0o022) === 0, "canonical-environment-runtime-test", violations, "group-or-other-writable");

  const supervisorSource = readFileSync(supervisorPath, "utf8");
  const probeSource = readFileSync(probePath, "utf8");
  const canonicalEnvironmentTestSource = readFileSync(canonicalEnvironmentTestPath, "utf8");
  const normalizedSupervisor = stripCComments(supervisorSource);
  const normalizedProbe = stripCComments(probeSource);

  validateSupervisor(normalizedSupervisor, violations);
  validateProbe(normalizedProbe, violations);
  for (const required of [
    "-DLOOPEIX_S37_CANONICAL_ENVIRONMENT_TEST",
    "run_case 0 / PWD=/",
    "run_case 1 /",
    "run_case 1 / PWD=/ EXTRA=x",
    "run_case 1 / PWD=/tmp",
    'run_case 1 "$test_root" PWD=/',
  ]) {
    assert(canonicalEnvironmentTestSource.includes(required), "canonical-environment-runtime-test", violations, `contract-missing:${required}`);
  }

  if (violations.length > 0) fail(violations);

  process.stdout.write("S37.1-B artifacts static gate: PASS\n");
  process.stdout.write("artifact code review only; live conformance not executed\n");
}

main();
