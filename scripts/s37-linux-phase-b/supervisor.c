#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/memfd.h>
#include <linux/seccomp.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum supervisor_exit {
  SUPERVISOR_OK = 0,
  SUPERVISOR_USAGE = 64,
  SUPERVISOR_SETUP = 65,
  SUPERVISOR_SPAWN = 66,
  SUPERVISOR_TIMEOUT_REAPED = 67,
  SUPERVISOR_OUTPUT_OVERFLOW = 68,
  SUPERVISOR_CHILD_FAILURE = 69,
  SUPERVISOR_REPORT_INVALID = 70,
  SUPERVISOR_REAP_FAILURE = 71,
  SUPERVISOR_CHILD_SETPGID = 73,
  SUPERVISOR_CHILD_STDOUT = 74,
  SUPERVISOR_CHILD_STDERR = 75,
  SUPERVISOR_CHILD_POLICY_FD = 76,
  SUPERVISOR_CHILD_CLOSE_RANGE = 77,
  SUPERVISOR_PROBE_NO_NEW_PRIVS = 80,
  SUPERVISOR_PROBE_SECOND_FILTER = 81,
  SUPERVISOR_PROBE_EMPTY_ENV = 82,
  SUPERVISOR_PROBE_EXACT_FDS = 83,
  SUPERVISOR_PROBE_FILESYSTEM = 84,
  SUPERVISOR_PROBE_FORK_CLONE = 85,
  SUPERVISOR_PROBE_EXEC_REENTRY = 86,
  SUPERVISOR_PROBE_NETWORK = 87,
  SUPERVISOR_PROBE_ABSENT_PATHS = 88,
  SUPERVISOR_PROBE_PRIVATE_MMAP = 89,
};

enum { DEADLINE_MS = 1000, STREAM_CAP = 1024 };

struct probe_report {
  uint8_t magic[8];
  uint32_t version;
  uint32_t size;
  uint32_t passed;
  uint32_t failed;
  uint8_t reserved[40];
};

_Static_assert(sizeof(struct probe_report) == 64, "probe report ABI drifted");

#define DENY_ERRNO(syscall_number)                                              \
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (syscall_number), 0, 1),                 \
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))

static const struct sock_filter outer_filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#ifdef __NR_clone
    DENY_ERRNO(__NR_clone),
#endif
#ifdef __NR_clone3
    DENY_ERRNO(__NR_clone3),
#endif
#ifdef __NR_fork
    DENY_ERRNO(__NR_fork),
#endif
#ifdef __NR_vfork
    DENY_ERRNO(__NR_vfork),
#endif
#ifdef __NR_socket
    DENY_ERRNO(__NR_socket),
#endif
#ifdef __NR_socketpair
    DENY_ERRNO(__NR_socketpair),
#endif
#ifdef __NR_connect
    DENY_ERRNO(__NR_connect),
#endif
#ifdef __NR_bind
    DENY_ERRNO(__NR_bind),
#endif
#ifdef __NR_listen
    DENY_ERRNO(__NR_listen),
#endif
#ifdef __NR_accept
    DENY_ERRNO(__NR_accept),
#endif
#ifdef __NR_accept4
    DENY_ERRNO(__NR_accept4),
#endif
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};

struct capture {
  uint8_t bytes[STREAM_CAP];
  size_t length;
  int fd;
  int open;
  int overflow;
};

static int is_absolute_regular_executable(const char *path) {
  char resolved[PATH_MAX];
  struct stat status;
  struct stat link_status;
  return path != NULL && path[0] == '/' && lstat(path, &link_status) == 0 &&
         !S_ISLNK(link_status.st_mode) && realpath(path, resolved) != NULL &&
         strcmp(path, resolved) == 0 && stat(path, &status) == 0 &&
         S_ISREG(status.st_mode) &&
         (status.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0 &&
         (status.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static int make_policy_memfd(void) {
  int fd = (int)syscall(SYS_memfd_create, "loopeix-s37-seccomp",
                        MFD_CLOEXEC | MFD_ALLOW_SEALING);
  if (fd < 0) return -1;
  const uint8_t *cursor = (const uint8_t *)outer_filter;
  size_t remaining = sizeof(outer_filter);
  while (remaining > 0) {
    ssize_t written = write(fd, cursor, remaining);
    if (written < 0) {
      if (errno == EINTR) continue;
      close(fd);
      return -1;
    }
    if (written == 0) {
      close(fd);
      return -1;
    }
    cursor += (size_t)written;
    remaining -= (size_t)written;
  }
  if (lseek(fd, 0, SEEK_SET) != 0 ||
      fcntl(fd, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) != 0) {
    close(fd);
    return -1;
  }
  int flags = fcntl(fd, F_GETFD);
  if (flags < 0 || fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL);
  return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 ? 0 : -1;
}

static int close_inherited_fds(void) {
  if (syscall(SYS_close_range, 4u, ~0u, 0u) == 0) return 0;
  if (errno != ENOSYS && errno != EPERM && errno != EINVAL) return -1;
  struct rlimit limit;
  if (getrlimit(RLIMIT_NOFILE, &limit) != 0 || limit.rlim_cur == RLIM_INFINITY ||
      limit.rlim_cur > (rlim_t)INT_MAX) return -1;
  for (int fd = 4; fd < (int)limit.rlim_cur; ++fd) {
    if (close(fd) != 0 && errno != EBADF) return -1;
  }
  return 0;
}

static int64_t monotonic_milliseconds(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
  return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static void capture_available(struct capture *stream) {
  while (stream->open) {
    uint8_t buffer[256];
    ssize_t count = read(stream->fd, buffer, sizeof(buffer));
    if (count > 0) {
      size_t available = STREAM_CAP - stream->length;
      size_t copied = (size_t)count < available ? (size_t)count : available;
      if (copied > 0) {
        memcpy(stream->bytes + stream->length, buffer, copied);
        stream->length += copied;
      }
      if ((size_t)count > copied) stream->overflow = 1;
      continue;
    }
    if (count == 0) {
      close(stream->fd);
      stream->open = 0;
      return;
    }
    if (errno == EINTR) continue;
    if (errno == EAGAIN || errno == EWOULDBLOCK) return;
    close(stream->fd);
    stream->open = 0;
    stream->overflow = 1;
  }
}

static int reap_all_children(pid_t child, int child_already_reaped,
                             int *child_status, int64_t reap_deadline) {
  int saw_child = child_already_reaped;
  for (;;) {
    int status = 0;
    pid_t reaped = waitpid(-1, &status, WNOHANG);
    if (reaped > 0) {
      if (reaped == child) {
        *child_status = status;
        saw_child = 1;
      }
      continue;
    }
    if (reaped == 0) {
      int64_t now = monotonic_milliseconds();
      if (now < 0 || now >= reap_deadline) return -1;
      struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
      while (nanosleep(&pause, &pause) != 0 && errno == EINTR) {}
      continue;
    }
    if (reaped < 0 && errno == EINTR) continue;
    if (reaped < 0 && errno == ECHILD) return saw_child ? 0 : -1;
    return -1;
  }
}

static void close_pipe(int pipe_fds[2]) {
  if (pipe_fds[0] >= 0) close(pipe_fds[0]);
  if (pipe_fds[1] >= 0) close(pipe_fds[1]);
  pipe_fds[0] = -1;
  pipe_fds[1] = -1;
}

static int report_result(const struct capture *out, const struct capture *err) {
  static const uint8_t magic[8] = {'L', 'X', 'S', '3', '7', 'P', 'B', '1'};
  if (err->length != 0 || out->length != sizeof(struct probe_report)) {
    return SUPERVISOR_REPORT_INVALID;
  }
  struct probe_report report;
  memcpy(&report, out->bytes, sizeof(report));
  if (memcmp(report.magic, magic, sizeof(magic)) != 0 || report.version != 1 ||
      report.size != sizeof(report) || (report.passed & report.failed) != 0 ||
      (report.passed | report.failed) != ((1u << 10) - 1u)) {
    return SUPERVISOR_REPORT_INVALID;
  }
  for (size_t index = 0; index < sizeof(report.reserved); ++index) {
    if (report.reserved[index] != 0) return SUPERVISOR_REPORT_INVALID;
  }
  if (report.failed == 0 && report.passed == ((1u << 10) - 1u)) {
    return SUPERVISOR_OK;
  }
  for (uint32_t index = 0; index < 10; ++index) {
    if ((report.failed & (1u << index)) != 0) return 80 + (int)index;
  }
  return SUPERVISOR_REPORT_INVALID;
}

int main(int argc, char **argv) {
  if (argc != 3 || !is_absolute_regular_executable(argv[1]) ||
      !is_absolute_regular_executable(argv[2])) return SUPERVISOR_USAGE;

  int policy_fd = make_policy_memfd();
  int stdout_pipe[2] = {-1, -1};
  int stderr_pipe[2] = {-1, -1};
  if (policy_fd < 0 || pipe2(stdout_pipe, O_CLOEXEC) != 0 ||
      pipe2(stderr_pipe, O_CLOEXEC) != 0 || prctl(PR_SET_CHILD_SUBREAPER, 1) != 0) {
    if (policy_fd >= 0) close(policy_fd);
    close_pipe(stdout_pipe);
    close_pipe(stderr_pipe);
    return SUPERVISOR_SETUP;
  }

  static char policy_text[] = "3";

  char *const bwrap_argv[] = {
      argv[1],
      (char *)"--unshare-user", (char *)"--unshare-ipc", (char *)"--unshare-pid",
      (char *)"--unshare-net", (char *)"--unshare-uts", (char *)"--disable-userns",
      (char *)"--clearenv", (char *)"--unsetenv", (char *)"PWD",
      (char *)"--new-session", (char *)"--die-with-parent",
      (char *)"--cap-drop", (char *)"ALL",
      (char *)"--ro-bind", argv[2], (char *)"/loopeix-s37-probe",
      (char *)"--remount-ro", (char *)"/",
      (char *)"--seccomp", policy_text,
      (char *)"--", (char *)"/loopeix-s37-probe", NULL,
  };
  char *const empty_env[] = {NULL};

  int64_t started_at = monotonic_milliseconds();
  if (started_at < 0) {
    close(policy_fd);
    close_pipe(stdout_pipe);
    close_pipe(stderr_pipe);
    return SUPERVISOR_SETUP;
  }
  pid_t child = fork();
  if (child < 0) {
    close(policy_fd);
    close_pipe(stdout_pipe);
    close_pipe(stderr_pipe);
    return SUPERVISOR_SPAWN;
  }
  if (child == 0) {
    if (setpgid(0, 0) != 0) _exit(SUPERVISOR_CHILD_SETPGID);
    if (dup2(stdout_pipe[1], STDOUT_FILENO) < 0) _exit(SUPERVISOR_CHILD_STDOUT);
    if (dup2(stderr_pipe[1], STDERR_FILENO) < 0) _exit(SUPERVISOR_CHILD_STDERR);
    if ((policy_fd != 3 && dup2(policy_fd, 3) < 0) ||
        fcntl(3, F_SETFD, 0) != 0) _exit(SUPERVISOR_CHILD_POLICY_FD);
    if (close_inherited_fds() != 0) {
      _exit(SUPERVISOR_CHILD_CLOSE_RANGE);
    }
    close(STDIN_FILENO);
    execve(argv[1], bwrap_argv, empty_env);
    _exit(127);
  }

  (void)setpgid(child, child);
  close(policy_fd);
  close(stdout_pipe[1]);
  close(stderr_pipe[1]);
  if (set_nonblocking(stdout_pipe[0]) != 0 || set_nonblocking(stderr_pipe[0]) != 0) {
    (void)kill(-child, SIGKILL);
    int ignored;
    int64_t reap_started = monotonic_milliseconds();
    int reaped = reap_started < 0
                     ? -1
                     : reap_all_children(child, 0, &ignored, reap_started + 250);
    close(stdout_pipe[0]);
    close(stderr_pipe[0]);
    return reaped == 0 ? SUPERVISOR_SETUP : SUPERVISOR_REAP_FAILURE;
  }

  struct capture out = {.bytes = {0}, .length = 0, .fd = stdout_pipe[0], .open = 1, .overflow = 0};
  struct capture err = {.bytes = {0}, .length = 0, .fd = stderr_pipe[0], .open = 1, .overflow = 0};
  int timed_out = 0;
  int observed_exit = 0;
  int child_status = 0;
  const int64_t deadline = started_at + DEADLINE_MS;

  while (!observed_exit && !timed_out && !out.overflow && !err.overflow) {
    int status = 0;
    pid_t waited = waitpid(child, &status, WNOHANG);
    if (waited == child) {
      observed_exit = 1;
      child_status = status;
      break;
    }
    if (waited < 0 && errno != EINTR) break;
    int64_t now = monotonic_milliseconds();
    if (now < 0 || now >= deadline) {
      timed_out = 1;
      break;
    }
    struct pollfd fds[2] = {
        {.fd = out.fd, .events = out.open ? POLLIN | POLLHUP : 0},
        {.fd = err.fd, .events = err.open ? POLLIN | POLLHUP : 0},
    };
    int remaining = (int)(deadline - now);
    int polled = poll(fds, 2, remaining);
    if (polled < 0 && errno != EINTR) break;
    capture_available(&out);
    capture_available(&err);
  }

  int must_kill = timed_out || out.overflow || err.overflow || !observed_exit;
  if (must_kill && kill(-child, SIGKILL) != 0 && errno != ESRCH) {
    if (out.open) close(out.fd);
    if (err.open) close(err.fd);
    return SUPERVISOR_REAP_FAILURE;
  }
  int64_t reap_started = must_kill ? monotonic_milliseconds() : started_at;
  int64_t reap_deadline = must_kill && reap_started >= 0 ? reap_started + 250 : deadline;
  if (reap_started < 0 ||
      reap_all_children(child, observed_exit, &child_status, reap_deadline) != 0) {
    if (out.open) close(out.fd);
    if (err.open) close(err.fd);
    return SUPERVISOR_REAP_FAILURE;
  }

  capture_available(&out);
  capture_available(&err);
  if (out.open) close(out.fd);
  if (err.open) close(err.fd);

  if (timed_out) return SUPERVISOR_TIMEOUT_REAPED;
  if (out.overflow || err.overflow) return SUPERVISOR_OUTPUT_OVERFLOW;
  if (!WIFEXITED(child_status)) return SUPERVISOR_CHILD_FAILURE;
  int report_status = report_result(&out, &err);
  if (WEXITSTATUS(child_status) == 0) return report_status;
  if (WEXITSTATUS(child_status) == 122 && report_status >= 80 && report_status <= 89) {
    return report_status;
  }
  if (WEXITSTATUS(child_status) >= 73 && WEXITSTATUS(child_status) <= 77) {
    return WEXITSTATUS(child_status);
  }
  return SUPERVISOR_CHILD_FAILURE;
}
