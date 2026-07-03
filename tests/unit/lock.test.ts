import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { acquireLock, LockHeldError, withLock } from "../../src/index.js";

let dir: string;
let lock: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "loopeix-lock-"));
  lock = join(dir, "ledger.lock");
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const held = (pid: number, at: number) => ({ now: () => at, pid, isAlive: () => true, staleMs: 30_000 });

describe("acquireLock", () => {
  it("acquires a free lock, writes the sidecar file, and releases it", () => {
    const h = acquireLock(lock, held(100, 1000));
    expect(existsSync(lock)).toBe(true);
    h.release();
    expect(existsSync(lock)).toBe(false);
  });
  it("refuses a lock held by a live, fresh holder", () => {
    acquireLock(lock, held(100, 1000));
    expect(() => acquireLock(lock, { now: () => 1001, pid: 200, isAlive: () => true, staleMs: 30_000 })).toThrow(LockHeldError);
  });
  it("steals a STALE lock (older than staleMs)", () => {
    acquireLock(lock, held(100, 1000));
    const h = acquireLock(lock, { now: () => 1000 + 40_000, pid: 200, isAlive: () => true, staleMs: 30_000 });
    expect(h.path).toBe(lock);
    h.release();
  });
  it("steals a lock held by a DEAD pid", () => {
    acquireLock(lock, held(100, 1000));
    const h = acquireLock(lock, { now: () => 1001, pid: 200, isAlive: (p) => p !== 100, staleMs: 30_000 });
    expect(existsSync(lock)).toBe(true);
    h.release();
  });
  it("release is idempotent", () => {
    const h = acquireLock(lock, held(100, 1000));
    h.release();
    h.release();
    expect(existsSync(lock)).toBe(false);
  });
  it("a lock with a non-numeric/garbage timestamp is stealable (no permanent wedge)", () => {
    writeFileSync(lock, '{"pid":999999,"acquired_at":"nope","host":"x"}');
    const h = acquireLock(lock, { now: () => 1000, pid: 200, isAlive: () => true, staleMs: 30_000 });
    expect(existsSync(lock)).toBe(true);
    h.release();
  });
  it("a stolen lock is NOT clobbered when the original holder later releases", () => {
    const a = acquireLock(lock, held(100, 1000));
    const b = acquireLock(lock, { now: () => 1000 + 40_000, pid: 200, isAlive: () => true, staleMs: 30_000 }); // steals A's stale lock
    a.release(); // must not delete B's lock
    expect(existsSync(lock)).toBe(true);
    b.release();
    expect(existsSync(lock)).toBe(false);
  });
});

describe("withLock", () => {
  it("runs fn under the lock and releases after", () => {
    const out = withLock(
      lock,
      () => {
        expect(existsSync(lock)).toBe(true);
        return 42;
      },
      held(100, 1000),
    );
    expect(out).toBe(42);
    expect(existsSync(lock)).toBe(false);
  });
  it("releases the lock even when fn throws", () => {
    expect(() =>
      withLock(
        lock,
        () => {
          throw new Error("boom");
        },
        held(100, 1000),
      ),
    ).toThrow("boom");
    expect(existsSync(lock)).toBe(false);
  });
  it("serializes: a second holder acquires only after the first releases", () => {
    withLock(lock, () => undefined, held(100, 1000));
    const h = acquireLock(lock, held(200, 2000));
    expect(h.path).toBe(lock);
    h.release();
  });
});
