import { linkSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";

/**
 * Advisory file lock for safe ledger appends (S13-C). Two concurrent run processes doing a
 * read-modify-append on the same ledger would interleave and corrupt it; `withLock` serializes them.
 *
 * Atomicity (both directions matter for cross-process correctness):
 *  - ACQUIRE writes the holder record to a unique temp file and `link()`s it into place. `link`
 *    fails with EEXIST if the lock exists, and the lock file NEVER appears empty (the linked inode
 *    already carries the pid) — closing the "read an empty half-created lock and false-steal a live
 *    holder" window that an `open(O_EXCL)`+write would leave.
 *  - STEAL (only when the holder is demonstrably stale) is a filesystem compare-and-swap: write a
 *    temp, `rename()` it over the lock (atomic replace), then re-read and confirm the lock is OURS.
 *    If two processes steal the same stale lock, exactly one wins the rename; the other reads the
 *    winner's record and fails closed with LockHeldError. No double-hold.
 *
 * A lock is stolen ONLY when stale: older than `staleMs`, or held by a pid that is no longer alive.
 * `now`/`pid`/`isAlive` are injectable for deterministic tests. (Requires a filesystem with hardlink
 * support — true for local disks; Loopeix V1 is local-first. `host` is recorded for a future
 * cross-host mode; local staleness uses pid liveness, which is meaningful only on this machine.)
 */

export interface LockInfo {
  pid: number;
  acquired_at: number;
  host: string;
}

export interface LockOptions {
  staleMs?: number;
  now?: () => number;
  pid?: number;
  host?: string;
  isAlive?: (pid: number) => boolean;
}

export interface LockHandle {
  path: string;
  release(): void;
}

export class LockHeldError extends Error {
  readonly holder: LockInfo | null;
  constructor(path: string, holder: LockInfo | null) {
    super(
      holder
        ? `lock '${path}' is held by pid ${holder.pid} on ${holder.host} (since ${holder.acquired_at})`
        : `lock '${path}' is held (holder metadata unreadable)`,
    );
    this.name = "LockHeldError";
    this.holder = holder;
  }
}

const DEFAULT_STALE_MS = 30_000;

function defaultIsAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0); // signal 0 = liveness probe, no signal delivered
    return true;
  } catch (e) {
    // ESRCH = no such process (dead); EPERM = exists but not ours (alive).
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

function readLockFile(lockPath: string): LockInfo | null {
  try {
    const raw = JSON.parse(readFileSync(lockPath, "utf8")) as Record<string, unknown>;
    // A malformed/half/NaN record is treated as unreadable → stealable (never a permanent wedge).
    if (!Number.isInteger(raw.pid) || (raw.pid as number) <= 0) return null;
    if (typeof raw.acquired_at !== "number" || !Number.isFinite(raw.acquired_at)) return null;
    return { pid: raw.pid as number, acquired_at: raw.acquired_at, host: typeof raw.host === "string" ? raw.host : "" };
  } catch {
    return null;
  }
}

/** Atomic create-if-absent: prepare a temp then link it into place (EEXIST if the lock exists). */
function acquireViaLink(lockPath: string, info: LockInfo): void {
  const tmp = `${lockPath}.${info.pid}.${info.acquired_at}.acq.tmp`;
  writeFileSync(tmp, JSON.stringify(info));
  try {
    linkSync(tmp, lockPath); // throws EEXIST if already held
  } finally {
    try {
      unlinkSync(tmp);
    } catch {
      /* best-effort temp cleanup */
    }
  }
}

/** Atomic steal: rename our record over the (stale) lock, then confirm WE won. */
function stealViaRename(lockPath: string, info: LockInfo): boolean {
  const tmp = `${lockPath}.${info.pid}.${info.acquired_at}.steal.tmp`;
  writeFileSync(tmp, JSON.stringify(info));
  try {
    renameSync(tmp, lockPath); // atomic replace; consumes tmp
  } catch (e) {
    try {
      unlinkSync(tmp);
    } catch {
      /* best-effort */
    }
    throw e;
  }
  const after = readLockFile(lockPath);
  return after !== null && after.pid === info.pid && after.acquired_at === info.acquired_at;
}

export function acquireLock(lockPath: string, opts: LockOptions = {}): LockHandle {
  const now = opts.now ?? Date.now;
  const pid = opts.pid ?? process.pid;
  const staleMs = opts.staleMs ?? DEFAULT_STALE_MS;
  const isAlive = opts.isAlive ?? defaultIsAlive;
  const info: LockInfo = { pid, acquired_at: now(), host: opts.host ?? hostname() };

  try {
    acquireViaLink(lockPath, info);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    const holder = readLockFile(lockPath);
    const stale =
      holder === null || now() - holder.acquired_at > staleMs || (holder.pid !== pid && !isAlive(holder.pid));
    if (!stale) throw new LockHeldError(lockPath, holder);
    if (!stealViaRename(lockPath, info)) throw new LockHeldError(lockPath, readLockFile(lockPath));
  }

  let released = false;
  return {
    path: lockPath,
    release() {
      if (released) return;
      released = true;
      // Only remove the lock if it is still OURS. If our lock was already stolen as stale by
      // another holder, unlinking would clobber THEIR lock — so verify ownership first.
      const current = readLockFile(lockPath);
      if (current && current.pid === info.pid && current.acquired_at === info.acquired_at) {
        try {
          unlinkSync(lockPath);
        } catch {
          /* already gone */
        }
      }
    },
  };
}

/** Run `fn` while holding `lockPath`; always releases, even if `fn` throws. */
export function withLock<T>(lockPath: string, fn: () => T, opts: LockOptions = {}): T {
  const handle = acquireLock(lockPath, opts);
  try {
    return fn();
  } finally {
    handle.release();
  }
}
