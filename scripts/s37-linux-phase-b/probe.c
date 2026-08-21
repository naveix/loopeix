#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/netlink.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

enum probe_check {
  CHECK_NO_NEW_PRIVS = 1u << 0,
  CHECK_SECOND_FILTER = 1u << 1,
  CHECK_EMPTY_ENV = 1u << 2,
  CHECK_EXACT_FDS = 1u << 3,
  CHECK_FILESYSTEM = 1u << 4,
  CHECK_FORK_CLONE = 1u << 5,
  CHECK_EXEC_REENTRY = 1u << 6,
  CHECK_NETWORK = 1u << 7,
  CHECK_ABSENT_PATHS = 1u << 8,
  CHECK_PRIVATE_MMAP = 1u << 9,
};

enum { ALL_CHECKS = (1u << 10) - 1u };

struct probe_report {
  uint8_t magic[8];
  uint32_t version;
  uint32_t size;
  uint32_t passed;
  uint32_t failed;
  uint8_t reserved[40];
};

_Static_assert(sizeof(struct probe_report) == 64, "probe report must remain fixed at 64 bytes");

#define DENY_ERRNO(syscall_number)                                              \
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (syscall_number), 0, 1),                 \
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))

static int install_second_filter(void) {
  static const struct sock_filter filter[] = {
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
#ifdef __NR_execve
      DENY_ERRNO(__NR_execve),
#endif
#ifdef __NR_execveat
      DENY_ERRNO(__NR_execveat),
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
  const struct sock_fprog program = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = (struct sock_filter *)filter,
  };

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) return -1;
  return 0;
}

static int has_empty_environment(void) {
  return environ != NULL && environ[0] == NULL;
}

static int has_exact_file_descriptors(void) {
  if (fcntl(STDIN_FILENO, F_GETFD) != -1 || errno != EBADF) return 0;
  if (fcntl(STDOUT_FILENO, F_GETFD) == -1) return 0;
  if (fcntl(STDERR_FILENO, F_GETFD) == -1) return 0;
  for (int fd = 3; fd < 4096; ++fd) {
    errno = 0;
    if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) return 0;
  }
  return 1;
}

static int write_is_denied(const char *path) {
  errno = 0;
  int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd >= 0) {
    close(fd);
    unlink(path);
    return 0;
  }
  return errno == EROFS || errno == EACCES || errno == ENOENT;
}

static int existing_file_write_is_denied(const char *path) {
  errno = 0;
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd >= 0) {
    close(fd);
    return 0;
  }
  return errno == EROFS || errno == EACCES;
}

static int shared_file_mmap_write_is_denied(const char *path) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return 0;
  errno = 0;
  void *mapping = mmap(NULL, 1, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  int saved_errno = errno;
  close(fd);
  if (mapping != MAP_FAILED) {
    munmap(mapping, 1);
    return 0;
  }
  return saved_errno == EACCES || saved_errno == EPERM || saved_errno == EROFS;
}

static int filesystem_writes_are_denied(void) {
  return write_is_denied("/loopeix-s37-write") &&
         write_is_denied("/tmp/loopeix-s37-write") &&
         existing_file_write_is_denied("/loopeix-s37-probe") &&
         shared_file_mmap_write_is_denied("/loopeix-s37-probe");
}

static int denied_process_syscall(long syscall_number, unsigned long argument) {
  errno = 0;
  long result = syscall(syscall_number, argument, NULL, NULL, NULL, 0);
  if (result == 0) _exit(125);
  if (result > 0) {
    kill((pid_t)result, SIGKILL);
    (void)waitpid((pid_t)result, NULL, 0);
    return 0;
  }
  return errno == EPERM;
}

static int process_creation_is_denied(void) {
  int denied = 1;
#ifdef __NR_fork
  denied = denied && denied_process_syscall(__NR_fork, 0);
#endif
#ifdef __NR_vfork
  denied = denied && denied_process_syscall(__NR_vfork, 0);
#endif
#ifdef __NR_clone
  denied = denied && denied_process_syscall(__NR_clone, SIGCHLD);
#endif
#ifdef __NR_clone3
  errno = 0;
  denied = denied && syscall(__NR_clone3, NULL, 0) == -1 && errno == EPERM;
#endif
  pid_t spawned = -1;
  char *const spawn_argv[] = {(char *)"/loopeix-s37-probe", NULL};
  int spawn_result = posix_spawn(&spawned, spawn_argv[0], NULL, NULL, spawn_argv,
                                 environ);
  if (spawn_result == 0) {
    kill(spawned, SIGKILL);
    (void)waitpid(spawned, NULL, 0);
    denied = 0;
  } else if (spawn_result != EPERM) {
    denied = 0;
  }
  return denied;
}

static int exec_reentry_is_denied(void) {
  char *const argv[] = {(char *)"/loopeix-s37-probe", NULL};
  char *const envp[] = {NULL};
  errno = 0;
  execve(argv[0], argv, envp);
  if (errno != EPERM) return 0;
#ifdef __NR_execveat
  errno = 0;
  syscall(__NR_execveat, AT_FDCWD, argv[0], argv, envp, 0);
  return errno == EPERM;
#else
  return 1;
#endif
}

static int socket_creation_is_denied(int domain, int type, int protocol) {
  errno = 0;
  int fd = socket(domain, type | SOCK_CLOEXEC, protocol);
  if (fd >= 0) {
    close(fd);
    return 0;
  }
  return errno == EPERM;
}

static int network_is_denied(void) {
  return socket_creation_is_denied(AF_INET, SOCK_STREAM, 0) &&
         socket_creation_is_denied(AF_INET, SOCK_DGRAM, 0) &&
         socket_creation_is_denied(AF_INET6, SOCK_STREAM, 0) &&
         socket_creation_is_denied(AF_INET6, SOCK_DGRAM, 0) &&
         socket_creation_is_denied(AF_UNIX, SOCK_STREAM, 0) &&
         socket_creation_is_denied(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
}

static int tools_and_credentials_are_absent(void) {
  static const char *const paths[] = {
      "/bin/sh",
      "/usr/bin/env",
      "/etc/passwd",
      "/root/.ssh/id_rsa",
      "/run/secrets",
      "/proc/self/environ",
  };
  for (size_t index = 0; index < sizeof(paths) / sizeof(paths[0]); ++index) {
    errno = 0;
    if (faccessat(AT_FDCWD, paths[index], F_OK, AT_EACCESS) == 0 || errno != ENOENT) return 0;
  }
  return 1;
}

static int private_memory_is_bounded_and_writable(void) {
  const size_t length = 4096;
  uint8_t *memory = mmap(NULL, length, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (memory == MAP_FAILED) return 0;
  memory[0] = 0x5a;
  memory[length - 1] = 0xa5;
  int ok = memory[0] == 0x5a && memory[length - 1] == 0xa5;
  if (munmap(memory, length) != 0) ok = 0;
  return ok;
}

static int write_full(int fd, const void *buffer, size_t length) {
  const uint8_t *cursor = buffer;
  while (length > 0) {
    ssize_t written = write(fd, cursor, length);
    if (written < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    if (written == 0) return -1;
    cursor += (size_t)written;
    length -= (size_t)written;
  }
  return 0;
}

static void record_check(struct probe_report *report, uint32_t bit, int passed) {
  if (passed) report->passed |= bit;
  else report->failed |= bit;
}

int main(int argc, char **argv) {
  (void)argv;
  struct probe_report report = {
      .magic = {'L', 'X', 'S', '3', '7', 'P', 'B', '1'},
      .version = 1,
      .size = sizeof(struct probe_report),
      .passed = 0,
      .failed = 0,
      .reserved = {0},
  };

  if (argc != 1) return 120;

  int filter_ok = install_second_filter() == 0;
  record_check(&report, CHECK_NO_NEW_PRIVS,
               filter_ok && prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
  record_check(&report, CHECK_SECOND_FILTER, filter_ok);
  if (filter_ok) {
    record_check(&report, CHECK_EMPTY_ENV, has_empty_environment());
    record_check(&report, CHECK_EXACT_FDS, has_exact_file_descriptors());
    record_check(&report, CHECK_FILESYSTEM, filesystem_writes_are_denied());
    record_check(&report, CHECK_FORK_CLONE, process_creation_is_denied());
    record_check(&report, CHECK_EXEC_REENTRY, exec_reentry_is_denied());
    record_check(&report, CHECK_NETWORK, network_is_denied());
    record_check(&report, CHECK_ABSENT_PATHS, tools_and_credentials_are_absent());
    record_check(&report, CHECK_PRIVATE_MMAP, private_memory_is_bounded_and_writable());
  }

  if (write_full(STDOUT_FILENO, &report, sizeof(report)) != 0) return 121;
  return report.passed == ALL_CHECKS && report.failed == 0 ? 0 : 122;
}
