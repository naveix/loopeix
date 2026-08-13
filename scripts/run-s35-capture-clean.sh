#!/bin/sh

set -eu

bootstrap_exec() {
  /usr/bin/env -i \
    HOME=/var/empty \
    LANG=C \
    LC_ALL=C \
    PATH=/usr/bin:/bin \
    TMPDIR=/private/tmp \
    "$@"
}

trusted_node_root=/opt/homebrew/Cellar/node/26.0.0
trusted_node=/opt/homebrew/Cellar/node/26.0.0/bin/node
trusted_libnode=/opt/homebrew/Cellar/node/26.0.0/lib/libnode.147.dylib
trusted_pnpm_root=/opt/homebrew/lib/node_modules/pnpm
trusted_pnpm=/opt/homebrew/lib/node_modules/pnpm/bin/pnpm.mjs
trusted_pnpm_bundle=/opt/homebrew/lib/node_modules/pnpm/dist/pnpm.mjs
expected_node_sha256=08dad0581f00a0cabf4d49ec92ca1f25fdfd01c2c18fa8e92b35f04d4c24c164
expected_libnode_sha256=0afe378c904a35194671ca1b19c7e1df8947fd1da01a7ce2efa1576d9ce21b10
expected_pnpm_entry_sha256=ff3224d46b47fbb24a7e9fe15fededef7e00892d07d4e376b6762d4899906bfd
expected_pnpm_bundle_sha256=edcb104ad0d162af32b3c8a24ba0c391513bb66c74cba852d072db0bf490c067
expected_launcher_sha256=ccfda9bcb78b59629b72cdfe617034133bccbb4b0862ce277fcc873104e2da8e
expected_driver_sha256=ad1e7c54572469d8ae227337ec99dd44b66bb24d0635d66b50c8aa47ead33fb0
expected_package_driver_sha256=c9c525d24f343e37b230547c5ee8d31e49dbee60c30a09db259f708c251f5927
expected_tsconfig_sha256=c92c34a5ae9152bfddef7a84ff546b1d4cb2f00ee5db814e5b99040040f7e433
expected_supervisor_sha256=0dd6659a74e8a34242037c30e0e14e0324aa0c735d192509dfcd064d3b8961f7
supervisor_deadline_ms=300000
supervisor_output_limit_bytes=1048576
supervisor_term_grace_ms=2000
supervisor_reap_ms=2000

if [ "$#" -eq 0 ]; then
  printf '%s\n' 'S35 clean capture launcher requires a command' >&2
  exit 64
fi

command_name=$1
shift
case "$command_name" in
  node|pnpm)
    ;;
  *)
    printf '%s\n' 'S35 clean capture launcher rejects an untrusted command name' >&2
    exit 64
    ;;
esac

# Discard any caller-owned descriptor before selectively minting package-only
# transactional announcement authority below.
exec 3>&-
umask 077
canonical_cwd=$(bootstrap_exec /bin/pwd -P)
reviewed_tool_root="$canonical_cwd/scripts"
operation_root=$(bootstrap_exec /usr/bin/mktemp -d /private/tmp/loopeix-s35-capture.XXXXXXXX)
bootstrap_exec /bin/chmod 0700 "$operation_root"
operation_root_identity=$(bootstrap_exec /usr/bin/stat -f '%d:%i' "$operation_root")
supervisor_pid=
target_pgid=
cleanup_keeper_pid=
target_pgid_file="$operation_root/target-pgid"
target_shell_ack_file="$operation_root/shell-pgid-ack"
target_shell_ack_part="$operation_root/shell-pgid-ack.part"
target_release_file="$operation_root/target-release"
transactional_success_mode=disabled

claim_target_pgid() {
  attempt=0
  while [ "$attempt" -lt 200 ]; do
    if [ -f "$target_pgid_file" ]; then
      if ! target_pgid=$(bootstrap_exec /bin/cat "$target_pgid_file"); then
        return 1
      fi
      case "$target_pgid" in
        ''|*[!0-9]*)
          return 1
          ;;
      esac
      if [ "$target_pgid" -le 1 ]; then
        return 1
      fi
      if ! printf '%s\n' "$target_pgid" >"$target_shell_ack_part"; then
        return 1
      fi
      if ! bootstrap_exec /bin/chmod 0600 "$target_shell_ack_part"; then
        return 1
      fi
      if ! bootstrap_exec /bin/mv "$target_shell_ack_part" "$target_shell_ack_file"; then
        return 1
      fi
      return 0
    fi
    if [ -n "$supervisor_pid" ] && ! kill -0 "$supervisor_pid" 2>/dev/null; then
      return 1
    fi
    bootstrap_exec /bin/sleep 0.01
    attempt=$((attempt + 1))
  done
  return 1
}

terminate_target_group() {
  if [ -z "$target_pgid" ]; then
    return 0
  fi
  if ! bootstrap_exec /bin/kill -0 -- "-$target_pgid" 2>/dev/null; then
    return 0
  fi
  bootstrap_exec /bin/kill -TERM -- "-$target_pgid" 2>/dev/null || :
  attempt=0
  while [ "$attempt" -lt 200 ]; do
    if ! bootstrap_exec /bin/kill -0 -- "-$target_pgid" 2>/dev/null; then
      return 0
    fi
    bootstrap_exec /bin/sleep 0.01
    attempt=$((attempt + 1))
  done
  bootstrap_exec /bin/kill -KILL -- "-$target_pgid" 2>/dev/null || :
  attempt=0
  while [ "$attempt" -lt 200 ]; do
    if ! bootstrap_exec /bin/kill -0 -- "-$target_pgid" 2>/dev/null; then
      return 0
    fi
    bootstrap_exec /bin/sleep 0.01
    attempt=$((attempt + 1))
  done
  return 1
}

path_identity() {
  bootstrap_exec /usr/bin/stat -f '%d:%i' "$1"
}

cleanup_owned_contents() {
  bootstrap_exec /bin/chmod -R -P u+rwX . || return 1
  bootstrap_exec /bin/rm -rf -x -- ./* ./.[!.]* ./..?* || return 1
  remaining=$(bootstrap_exec /bin/ls -A .) || return 1
  [ -z "$remaining" ]
}

cleanup_keeper() {
  trap - 0 HUP INT TERM
  cd "$operation_root" || exit 71
  anchored_identity=$(path_identity .) || exit 71
  [ "$anchored_identity" = "$operation_root_identity" ] || exit 71
  trap 'cleanup_owned_contents; exit $?' USR1
  trap 'exit 72' HUP INT TERM
  while :; do
    bootstrap_exec /bin/sleep 1
  done
}

stop_cleanup_keeper() {
  if [ -n "$cleanup_keeper_pid" ] && kill -0 "$cleanup_keeper_pid" 2>/dev/null; then
    kill -TERM "$cleanup_keeper_pid" 2>/dev/null || :
    wait "$cleanup_keeper_pid" 2>/dev/null || :
  fi
}

cleanup() {
  command_status=$?
  cleanup_failed=0
  quarantine_parent=
  quarantine_root=
  trap - 0 HUP INT TERM
  if [ -n "$supervisor_pid" ] && kill -0 "$supervisor_pid" 2>/dev/null; then
    kill -TERM "$supervisor_pid" 2>/dev/null || :
    wait "$supervisor_pid" 2>/dev/null || :
  fi
  if ! terminate_target_group; then
    printf '%s\n' "S35 clean capture launcher could not extinguish the target process group after command status $command_status" >&2
    cleanup_failed=1
  fi

  if [ "$cleanup_failed" -eq 0 ]; then
    if ! named_identity=$(path_identity "$operation_root" 2>/dev/null) ||
      [ "$named_identity" != "$operation_root_identity" ]; then
      printf '%s\n' "S35 clean capture launcher operation-root identity changed after command status $command_status" >&2
      cleanup_failed=1
    fi
  fi

  if [ "$cleanup_failed" -eq 0 ]; then
    if ! quarantine_parent=$(bootstrap_exec /usr/bin/mktemp -d /private/tmp/loopeix-s35-quarantine.XXXXXXXX); then
      printf '%s\n' "S35 clean capture launcher could not reserve private quarantine after command status $command_status" >&2
      cleanup_failed=1
    else
      bootstrap_exec /bin/chmod 0700 "$quarantine_parent" || cleanup_failed=1
      quarantine_root="$quarantine_parent/root"
    fi
  fi

  if [ "$cleanup_failed" -eq 0 ]; then
    if ! bootstrap_exec /bin/mv "$operation_root" "$quarantine_root"; then
      printf '%s\n' "S35 clean capture launcher could not quarantine its operation root after command status $command_status" >&2
      cleanup_failed=1
    elif ! quarantined_identity=$(path_identity "$quarantine_root" 2>/dev/null) ||
      [ "$quarantined_identity" != "$operation_root_identity" ]; then
      printf '%s\n' "S35 clean capture launcher quarantined an unexpected operation root after command status $command_status" >&2
      cleanup_failed=1
    fi
  fi

  if [ "$cleanup_failed" -eq 0 ]; then
    if ! kill -USR1 "$cleanup_keeper_pid" 2>/dev/null || ! wait "$cleanup_keeper_pid"; then
      printf '%s\n' "S35 clean capture launcher anchored cleanup failed after command status $command_status" >&2
      cleanup_failed=1
    fi
  else
    stop_cleanup_keeper
  fi

  if [ "$cleanup_failed" -eq 0 ]; then
    if ! quarantined_identity=$(path_identity "$quarantine_root" 2>/dev/null) ||
      [ "$quarantined_identity" != "$operation_root_identity" ]; then
      printf '%s\n' "S35 clean capture launcher quarantine finalization failed after command status $command_status" >&2
      cleanup_failed=1
    elif ! quarantine_members=$(bootstrap_exec /bin/ls -A "$quarantine_root"); then
      printf '%s\n' "S35 clean capture launcher could not inspect quarantine finalization after command status $command_status" >&2
      cleanup_failed=1
    elif [ -n "$quarantine_members" ] ||
      ! bootstrap_exec /bin/rmdir "$quarantine_root" ||
      ! bootstrap_exec /bin/rmdir "$quarantine_parent"; then
      printf '%s\n' "S35 clean capture launcher quarantine finalization failed after command status $command_status" >&2
      cleanup_failed=1
    fi
  elif [ -n "$quarantine_parent" ] && [ -d "$quarantine_parent" ] && [ ! -e "$quarantine_root" ]; then
    bootstrap_exec /bin/rmdir "$quarantine_parent" 2>/dev/null || :
  fi

  if [ "$cleanup_failed" -ne 0 ]; then
    stop_cleanup_keeper
    exit 70
  fi
  exit "$command_status"
}

forward_signal() {
  signal=$1
  if [ -n "$supervisor_pid" ] && kill -0 "$supervisor_pid" 2>/dev/null; then
    kill "-$signal" "$supervisor_pid" 2>/dev/null || :
  fi
}

fail_with_status() {
  status=$1
  message=$2
  printf '%s\n' "$message" >&2
  exit "$status"
}

hash_private_copy() {
  path=$1
  expected=$2
  if ! hash_output=$(bootstrap_exec "/usr/bin/shasum" -a 256 "$path"); then
    fail_with_status 74 'S35 clean capture launcher could not hash a private runtime copy'
  fi
  actual=${hash_output%% *}
  if [ "$actual" != "$expected" ]; then
    fail_with_status 69 'S35 clean capture launcher private runtime admission failed'
  fi
}

assert_reviewed_launcher_driver() {
  driver_seen=0
  driver_value_pending=0
  for argument do
    if [ "$driver_value_pending" -eq 1 ]; then
      if [ "$argument" != "$reviewed_tool_root/capture-v01-oracles-s35.ts" ]; then
        fail_with_status 64 'S35 clean capture launcher rejects a noncanonical reviewed driver path'
      fi
      driver_seen=1
      driver_value_pending=0
      continue
    fi
    if [ "$argument" = "--driver" ]; then
      if [ "$driver_seen" -eq 1 ]; then
        fail_with_status 64 'S35 clean capture launcher rejects duplicate reviewed driver bindings'
      fi
      driver_value_pending=1
    fi
  done
  if [ "$driver_seen" -ne 1 ] || [ "$driver_value_pending" -ne 0 ]; then
    fail_with_status 64 'S35 clean capture launcher requires one canonical reviewed driver binding'
  fi
}

assert_no_caller_driver_bindings() {
  for argument do
    case "$argument" in
      --tool-source-root|--tool-source-root=*)
        fail_with_status 64 'S35 clean capture launcher owns the direct-driver tool source root'
        ;;
      --transactional-success-fd|--transactional-success-fd=*)
        fail_with_status 64 'S35 clean capture launcher owns the package transactional success descriptor'
        ;;
    esac
  done
}

trap cleanup 0
trap 'forward_signal HUP' HUP
trap 'forward_signal INT' INT
trap 'forward_signal TERM' TERM

cleanup_keeper &
cleanup_keeper_pid=$!
if ! kill -0 "$cleanup_keeper_pid" 2>/dev/null; then
  fail_with_status 70 'S35 clean capture launcher could not retain operation-root cleanup custody'
fi

admitted_root="$operation_root/admitted"
node_part="$admitted_root/node.part"
node_root="$admitted_root/node"
pnpm_part="$admitted_root/pnpm.part"
pnpm_root="$admitted_root/pnpm"
private_tool_root="$operation_root/tools"
private_tool_package="$private_tool_root/package.json"
bootstrap_exec /bin/mkdir "$admitted_root"
bootstrap_exec /bin/mkdir "$private_tool_root"
if ! printf '%s\n' '{"type":"module"}' >"$private_tool_package"; then
  fail_with_status 74 'S35 clean capture launcher could not create private tool module metadata'
fi
bootstrap_exec /bin/chmod 0400 "$private_tool_package"

if ! bootstrap_exec "/bin/cp" -cR "$trusted_node_root" "$node_part"; then
  fail_with_status 74 'S35 clean capture launcher could not copy the Node runtime'
fi
if ! bootstrap_exec "/bin/cp" -cR "$trusted_pnpm_root" "$pnpm_part"; then
  fail_with_status 74 'S35 clean capture launcher could not copy the pnpm runtime'
fi

hash_private_copy "$node_part/bin/node" "$expected_node_sha256"
hash_private_copy "$node_part/lib/libnode.147.dylib" "$expected_libnode_sha256"
hash_private_copy "$pnpm_part/bin/pnpm.mjs" "$expected_pnpm_entry_sha256"
hash_private_copy "$pnpm_part/dist/pnpm.mjs" "$expected_pnpm_bundle_sha256"

bootstrap_exec /bin/cp -c "$reviewed_tool_root/launch-v01-oracles-s35.mjs" "$private_tool_root/launch-v01-oracles-s35.mjs"
bootstrap_exec /bin/cp -c "$reviewed_tool_root/capture-v01-oracles-s35.ts" "$private_tool_root/capture-v01-oracles-s35.ts"
bootstrap_exec /bin/cp -c "$reviewed_tool_root/capture-s35-package-oracles.mjs" "$private_tool_root/capture-s35-package-oracles.mjs"
bootstrap_exec /bin/cp -c "$reviewed_tool_root/tsconfig.capture-v01-oracles-s35.json" "$private_tool_root/tsconfig.capture-v01-oracles-s35.json"
hash_private_copy "$private_tool_root/launch-v01-oracles-s35.mjs" "$expected_launcher_sha256"
hash_private_copy "$private_tool_root/capture-v01-oracles-s35.ts" "$expected_driver_sha256"
hash_private_copy "$private_tool_root/capture-s35-package-oracles.mjs" "$expected_package_driver_sha256"
hash_private_copy "$private_tool_root/tsconfig.capture-v01-oracles-s35.json" "$expected_tsconfig_sha256"

bootstrap_exec /bin/chmod -R u-w,go-rwx "$node_part" "$pnpm_part"
bootstrap_exec /bin/chmod -R u-w,go-rwx "$private_tool_root"
bootstrap_exec /bin/mv "$node_part" "$node_root"
bootstrap_exec /bin/mv "$pnpm_part" "$pnpm_root"

admitted_node="$node_root/bin/node"
admitted_pnpm="$pnpm_root/bin/pnpm.mjs"
private_command_root="$admitted_root/bin"
private_pnpm_command="$private_command_root/pnpm"
bootstrap_exec /bin/mkdir "$private_command_root"
if ! bootstrap_exec /usr/bin/printf '#!/bin/sh\nexec "%s" "%s" "$@"\n' \
  "$admitted_node" "$admitted_pnpm" >"$private_pnpm_command"; then
  fail_with_status 74 'S35 clean capture launcher could not create the admitted pnpm command'
fi
bootstrap_exec /bin/chmod 0500 "$private_pnpm_command"
bootstrap_exec /bin/chmod 0500 "$private_command_root"
trusted_path="$private_command_root:$node_root/bin:/opt/homebrew/Cellar/git/2.53.0/bin:/usr/bin:/bin"
supervisor_part="$operation_root/supervisor.mjs.part"
supervisor_path="$operation_root/supervisor.mjs"

bootstrap_exec /bin/cat >"$supervisor_part" <<'LOOPEIX_S35_SUPERVISOR'
import { spawn } from "node:child_process";
import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  linkSync,
  openSync,
  readSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { isAbsolute } from "node:path";
import { isMainThread, parentPort, Worker, workerData } from "node:worker_threads";

function parsePositiveInteger(value, label) {
  if (!/^[1-9][0-9]*$/.test(value ?? "")) {
    throw new Error(`${label} must be a positive integer`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`${label} exceeds the safe integer range`);
  }
  return parsed;
}

function closedEnvironment() {
  const environment = {
    HOME: process.env.HOME,
    LANG: "C",
    LC_ALL: "C",
    PATH: process.env.PATH,
    TMPDIR: process.env.TMPDIR,
  };
  for (const name of ["HOME", "PATH", "TMPDIR"]) {
    if (typeof environment[name] !== "string" || environment[name].length === 0) {
      throw new Error(`supervised child ${name} is required`);
    }
  }
  return environment;
}

const signalNumbers = new Map([
  ["SIGHUP", 1],
  ["SIGINT", 2],
  ["SIGQUIT", 3],
  ["SIGKILL", 9],
  ["SIGTERM", 15],
]);

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function writeAll(fd, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const written = writeSync(fd, bytes, offset, bytes.length - offset);
    if (!Number.isInteger(written) || written <= 0) {
      throw new Error("control write made no progress");
    }
    offset += written;
  }
}

function writePrivateControlFile(path, text) {
  const bytes = Buffer.from(text, "ascii");
  const partPath = `${path}.part`;
  const descriptor = openSync(
    partPath,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error("control path is not a regular file");
    }
    writeAll(descriptor, bytes);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  linkSync(partPath, path);
  unlinkSync(partPath);
}

function readPrivateControlFile(path) {
  const descriptor = openSync(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 64) {
      throw new Error("control path is invalid");
    }
    const bytes = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count <= 0) throw new Error("control read was incomplete");
      offset += count;
    }
    return bytes.toString("ascii");
  } finally {
    closeSync(descriptor);
  }
}

function runOutputWorker() {
  if (parentPort === null || ![1, 2].includes(workerData?.fd)) {
    throw new Error("output worker authority is invalid");
  }
  const queue = [];
  let pumping = false;
  const pump = () => {
    if (pumping) return;
    pumping = true;
    while (queue.length > 0) {
      const item = queue[0];
      try {
        const written = writeSync(
          workerData.fd,
          item.bytes,
          item.offset,
          item.bytes.length - item.offset,
        );
        if (!Number.isInteger(written) || written <= 0) {
          throw new Error("output worker write made no progress");
        }
        item.offset += written;
      } catch (error) {
        if (error?.code === "EAGAIN" || error?.code === "EWOULDBLOCK") {
          pumping = false;
          setTimeout(pump, 10);
          return;
        }
        queue.shift();
        parentPort.postMessage("failed");
        continue;
      }
      if (item.offset === item.bytes.length) {
        queue.shift();
        parentPort.postMessage("written");
      }
    }
    pumping = false;
  };
  parentPort.on("message", (bytes) => {
    queue.push({ bytes: Buffer.from(bytes), offset: 0 });
    pump();
  });
}

async function runGate(gateArguments) {
  const [
    expectedParentText,
    handshakeText,
    targetPgidPath,
    releasePath,
    transactionalSuccessMode,
    executable,
    ...args
  ] = gateArguments;
  const expectedParentPid = parsePositiveInteger(expectedParentText, "gate parent PID");
  const handshakeMs = parsePositiveInteger(handshakeText, "gate handshake deadline");
  if (
    !isAbsolute(targetPgidPath ?? "") ||
    !isAbsolute(releasePath ?? "") ||
    !isAbsolute(executable ?? "")
  ) {
    throw new Error("gate paths and executable must be absolute");
  }
  if (!["disabled", "enabled"].includes(transactionalSuccessMode)) {
    throw new Error("gate transactional success mode is invalid");
  }
  writePrivateControlFile(targetPgidPath, `${process.pid}\n`);
  const releaseDeadline =
    process.hrtime.bigint() + BigInt(handshakeMs) * 1_000_000n;
  while (true) {
    if (process.ppid !== expectedParentPid) {
      throw new Error("gate supervisor identity changed before release");
    }
    try {
      if (readPrivateControlFile(releasePath) !== "release\n") {
        throw new Error("gate release content is invalid");
      }
      break;
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    if (process.hrtime.bigint() >= releaseDeadline) {
      throw new Error("gate release deadline expired");
    }
    await sleep(10);
  }

  const result = await new Promise((resolve) => {
    let target;
    try {
      target = spawn(executable, args, {
        cwd: process.cwd(),
        detached: false,
        env: closedEnvironment(),
        stdio: transactionalSuccessMode === "enabled"
          ? ["ignore", "inherit", "inherit", 3]
          : ["ignore", "inherit", "inherit"],
      });
    } catch {
      resolve({ code: null, signal: null });
      return;
    }
    target.once("error", () => resolve({ code: null, signal: null }));
    target.once("close", (code, signal) => resolve({ code, signal }));
  });
  if (result.signal !== null) {
    process.exitCode = 128 + (signalNumbers.get(result.signal) ?? 0);
  } else if (
    Number.isInteger(result.code) &&
    result.code >= 0 &&
    result.code <= 255
  ) {
    process.exitCode = result.code;
  } else {
    process.exitCode = 70;
  }
}

if (!isMainThread) {
  runOutputWorker();
} else if (process.argv[2] === "--gate") {
  await runGate(process.argv.slice(3));
} else {
const [
  deadlineText,
  outputLimitText,
  termGraceText,
  reapText,
  targetPgidPath,
  shellAckPath,
  releasePath,
  transactionalSuccessMode,
  executable,
  ...args
] = process.argv.slice(2);
const deadlineMs = parsePositiveInteger(deadlineText, "deadline");
const outputLimitBytes = parsePositiveInteger(outputLimitText, "output limit");
const termGraceMs = parsePositiveInteger(termGraceText, "termination grace");
const reapMs = parsePositiveInteger(reapText, "reap deadline");
const handshakeMs = Math.min(deadlineMs, 5_000);
if (
  !isAbsolute(targetPgidPath ?? "") ||
  !isAbsolute(shellAckPath ?? "") ||
  !isAbsolute(releasePath ?? "") ||
  !isAbsolute(executable ?? "")
) {
  throw new Error("supervised control paths and executable must be absolute");
}
if (!["disabled", "enabled"].includes(transactionalSuccessMode)) {
  throw new Error("supervised transactional success mode is invalid");
}
const transactionalFlagIndexes = args
  .map((argument, index) => argument === "--transactional-success-fd" ? index : -1)
  .filter((index) => index >= 0);
if (transactionalSuccessMode === "enabled") {
  if (
    executable !== process.execPath ||
    !args[0]?.endsWith("/capture-s35-package-oracles.mjs") ||
    transactionalFlagIndexes.length !== 1 ||
    args[transactionalFlagIndexes[0] + 1] !== "3"
  ) {
    throw new Error("package transactional success capability binding is invalid");
  }
} else if (transactionalFlagIndexes.length !== 0) {
  throw new Error("disabled transactional success mode received a capability binding");
}
const childEnvironment = closedEnvironment();

let child;
let forwardedBytes = 0;
let terminationReason = null;
let externalSignal = null;
let spawnFailure = false;
let killTimer = null;
let outputAbortTimer = null;
let pendingOutputWrites = 0;
let outputAbandoned = false;
let outputWorkersStopping = false;
const outputWorkers = new Map();

function createOutputWorker(fd) {
  const worker = new Worker(new URL(import.meta.url), { workerData: { fd } });
  worker.on("message", (result) => {
    pendingOutputWrites -= 1;
    if (result !== "written" && !outputAbandoned) beginTermination("invariant");
  });
  worker.on("error", () => {
    if (!outputAbandoned) beginTermination("invariant");
  });
  worker.on("exit", (code) => {
    if (!outputWorkersStopping && !outputAbandoned && code !== 0) {
      beginTermination("invariant");
    }
  });
  outputWorkers.set(fd, worker);
}

createOutputWorker(1);
createOutputWorker(2);

function groupExists() {
  if (!Number.isSafeInteger(child?.pid) || child.pid <= 1) return false;
  try {
    process.kill(-child.pid, 0);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    if (error?.code === "EPERM") return true;
    throw error;
  }
}

function signalGroup(signal) {
  if (!Number.isSafeInteger(child?.pid) || child.pid <= 1) return;
  try {
    process.kill(-child.pid, signal);
  } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
}

function beginTermination(reason, signal = null) {
  if (terminationReason !== null) return;
  terminationReason = reason;
  externalSignal = signal;
  signalGroup("SIGTERM");
  killTimer = setTimeout(() => {
    try {
      signalGroup("SIGKILL");
    } catch {
      terminationReason = "invariant";
    }
  }, termGraceMs);
  if (pendingOutputWrites > 0 && outputAbortTimer === null) {
    outputAbortTimer = setTimeout(() => {
      outputAbandoned = true;
      outputWorkersStopping = true;
      for (const worker of outputWorkers.values()) void worker.terminate();
    }, termGraceMs);
  }
}

function forward(fd, chunk) {
  if (terminationReason !== null) return;
  const remaining = outputLimitBytes - forwardedBytes;
  if (remaining <= 0) {
    beginTermination("output");
    return;
  }
  const admitted = chunk.length <= remaining ? chunk : chunk.subarray(0, remaining);
  const destination = outputWorkers.get(fd);
  try {
    if (admitted.length > 0) {
      pendingOutputWrites += 1;
      forwardedBytes += admitted.length;
      destination.postMessage(admitted);
    }
  } catch {
    pendingOutputWrites -= 1;
    beginTermination("invariant");
    return;
  }
  if (admitted.length !== chunk.length) beginTermination("output");
}

async function waitForOutputSettlement() {
  while (pendingOutputWrites > 0 && !outputAbandoned) await sleep(10);
}

async function waitForGroupExit(milliseconds) {
  const deadline = process.hrtime.bigint() + BigInt(milliseconds) * 1_000_000n;
  while (groupExists() && process.hrtime.bigint() < deadline) {
    await sleep(10);
  }
  return !groupExists();
}

async function ensureGroupExtinct() {
  if (!groupExists()) return true;
  if (terminationReason === null) beginTermination("invariant");
  await sleep(termGraceMs);
  if (groupExists()) signalGroup("SIGKILL");
  return waitForGroupExit(reapMs);
}

const completion = new Promise((resolve) => {
  try {
    child = spawn(process.execPath, [
      process.argv[1],
      "--gate",
      String(process.pid),
      String(handshakeMs),
      targetPgidPath,
      releasePath,
      transactionalSuccessMode,
      executable,
      ...args,
    ], {
      cwd: process.cwd(),
      detached: true,
      env: childEnvironment,
      stdio: transactionalSuccessMode === "enabled"
        ? ["ignore", "pipe", "pipe", 3]
        : ["ignore", "pipe", "pipe"],
    });
  } catch {
    spawnFailure = true;
    resolve({ code: null, signal: null });
    return;
  }

  child.stdout.on("data", (chunk) => forward(1, chunk));
  child.stderr.on("data", (chunk) => forward(2, chunk));
  child.once("error", () => {
    spawnFailure = true;
    beginTermination("invariant");
  });
  child.once("close", (code, signal) => resolve({ code, signal }));
});

const deadlineTimer = setTimeout(() => beginTermination("deadline"), deadlineMs);
const signalHandlers = new Map();
for (const signal of ["SIGHUP", "SIGINT", "SIGTERM"]) {
  const handler = () => beginTermination("signal", signal);
  signalHandlers.set(signal, handler);
  process.on(signal, handler);
}

let gateReady = false;
const handshakeDeadline =
  process.hrtime.bigint() + BigInt(handshakeMs) * 1_000_000n;
while (!gateReady && terminationReason === null) {
  try {
    const recordedPgid = readPrivateControlFile(targetPgidPath);
    if (recordedPgid !== `${child.pid}\n`) {
      throw new Error("gate process-group identity is invalid");
    }
    const shellAck = readPrivateControlFile(shellAckPath);
    if (shellAck !== `${child.pid}\n`) {
      throw new Error("shell process-group acknowledgement is invalid");
    }
    writePrivateControlFile(releasePath, "release\n");
    gateReady = true;
  } catch (error) {
    if (error?.code !== "ENOENT") {
      beginTermination("invariant");
      break;
    }
  }
  if (!gateReady) {
    if (process.hrtime.bigint() >= handshakeDeadline) {
      beginTermination("invariant");
      break;
    }
    await sleep(10);
  }
}

const { code, signal } = await completion;
if (killTimer !== null) clearTimeout(killTimer);
const extinct = await ensureGroupExtinct();
if (!extinct) terminationReason = "invariant";
await waitForOutputSettlement();
clearTimeout(deadlineTimer);
if (outputAbortTimer !== null) clearTimeout(outputAbortTimer);
outputWorkersStopping = true;
if (!outputAbandoned) {
  await Promise.all([...outputWorkers.values()].map((worker) => worker.terminate()));
}
for (const [name, handler] of signalHandlers) process.off(name, handler);
for (const controlPath of [releasePath, shellAckPath, targetPgidPath]) {
  try {
    unlinkSync(controlPath);
  } catch (error) {
    if (error?.code !== "ENOENT") terminationReason = "invariant";
  }
}

if (spawnFailure || terminationReason === "output" || terminationReason === "invariant") {
  process.exitCode = 70;
} else if (terminationReason === "deadline") {
  process.exitCode = 124;
} else if (terminationReason === "signal") {
  process.exitCode = 128 + signalNumbers.get(externalSignal);
} else if (signal !== null) {
  process.exitCode = 128 + (signalNumbers.get(signal) ?? 0);
} else if (Number.isInteger(code) && code >= 0 && code <= 255) {
  process.exitCode = code;
} else {
  process.exitCode = 70;
}
process.exit(process.exitCode);
}
LOOPEIX_S35_SUPERVISOR

hash_private_copy "$supervisor_part" "$expected_supervisor_sha256"
bootstrap_exec /bin/chmod 0400 "$supervisor_part"
bootstrap_exec /bin/mv "$supervisor_part" "$supervisor_path"

case "$command_name" in
  node)
    command_path=$admitted_node
    if [ "$#" -eq 0 ]; then
      fail_with_status 64 'S35 clean capture launcher requires a reviewed Node target'
    fi
    node_target=$1
    shift
    case "$node_target" in
      "$reviewed_tool_root/launch-v01-oracles-s35.mjs"|scripts/launch-v01-oracles-s35.mjs)
        assert_reviewed_launcher_driver "$@"
        set -- "$private_tool_root/launch-v01-oracles-s35.mjs" "$@"
        ;;
      "$reviewed_tool_root/capture-v01-oracles-s35.ts"|scripts/capture-v01-oracles-s35.ts)
        assert_no_caller_driver_bindings "$@"
        set -- "$private_tool_root/capture-v01-oracles-s35.ts" "$@" \
          --tool-source-root "$reviewed_tool_root"
        ;;
      "$reviewed_tool_root/capture-s35-package-oracles.mjs"|scripts/capture-s35-package-oracles.mjs)
        assert_no_caller_driver_bindings "$@"
        transactional_success_mode=enabled
        exec 3>&1
        set -- "$private_tool_root/capture-s35-package-oracles.mjs" "$@" \
          --tool-source-root "$reviewed_tool_root" \
          --transactional-success-fd 3
        ;;
      *)
        fail_with_status 64 'S35 clean capture launcher rejects an unreviewed Node target'
        ;;
    esac
    ;;
  pnpm)
    # The enclosing capture root remains private; pnpm must reproduce the
    # standard package modes committed by runtime and package provenance.
    umask 022
    command_path=$admitted_node
    set -- "$admitted_pnpm" "$@"
    ;;
esac

cd "$canonical_cwd"
/usr/bin/env -i \
  HOME="$operation_root" \
  LANG=C \
  LC_ALL=C \
  PATH="$trusted_path" \
  TMPDIR="$operation_root" \
  "$admitted_node" "$supervisor_path" \
  "$supervisor_deadline_ms" \
  "$supervisor_output_limit_bytes" \
  "$supervisor_term_grace_ms" \
  "$supervisor_reap_ms" \
  "$target_pgid_file" \
  "$target_shell_ack_file" \
  "$target_release_file" \
  "$transactional_success_mode" \
  "$command_path" "$@" &
supervisor_pid=$!

if ! claim_target_pgid; then
  fail_with_status 70 'S35 clean capture launcher could not claim target process-group custody before release'
fi

set +e
while :; do
  wait "$supervisor_pid"
  status=$?
  if ! kill -0 "$supervisor_pid" 2>/dev/null; then
    break
  fi
done
set -e
exit "$status"
