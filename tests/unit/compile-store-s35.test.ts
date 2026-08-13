import { constants, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  COMPILE_STORE_SENTINEL_TEXT,
  verifyCompileStoreV02,
  type CompileStoreIo,
} from "../../src/compiler/compile-store.js";
import { allocateAndCommitCompileIdentityV02 } from "../../src/compiler/compile-id.js";

const roots: string[] = [];

function makeWorkspace(): { workspace: string; store: string; sentinel: string } {
  const workspace = mkdtempSync(join(tmpdir(), "loopeix-s35-compile-store-"));
  roots.push(workspace);
  const store = join(workspace, ".loopeix", "compiles");
  mkdirSync(store, { recursive: true });
  const sentinel = join(store, ".gitignore");
  writeFileSync(sentinel, COMPILE_STORE_SENTINEL_TEXT, { mode: 0o600 });
  return { workspace, store, sentinel };
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("S35 compile-store verification", () => {
  it("admits only the exact direct regular sentinel without writing or repairing", async () => {
    const { workspace, store, sentinel } = makeWorkspace();
    const before = lstatSync(sentinel);

    const result = await verifyCompileStoreV02(workspace);

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.message);
    expect(result.store).toMatchObject({
      boundary_kind: "compile-store",
      root_identity: { device: lstatSync(store, { bigint: true }).dev.toString(), inode: lstatSync(store, { bigint: true }).ino.toString() },
    });
    expect(Object.isFrozen(result.store)).toBe(true);
    expect(readFileSync(sentinel, "utf8")).toBe(COMPILE_STORE_SENTINEL_TEXT);
    expect(lstatSync(sentinel).ino).toBe(before.ino);
  });

  it.each(["missing", "stale", "symlink", "directory"] as const)(
    "rejects an %s sentinel without repair or traversal",
    async (kind) => {
      const { workspace, sentinel } = makeWorkspace();
      rmSync(sentinel);
      if (kind === "stale") writeFileSync(sentinel, "stale\n");
      if (kind === "symlink") symlinkSync(join(workspace, "missing-target"), sentinel);
      if (kind === "directory") mkdirSync(sentinel);

      const result = await verifyCompileStoreV02(workspace);

      expect(result).toEqual({
        ok: false,
        reason: "COMPILE_STORE_INVALID",
        message: "The compile store or its sentinel is unavailable or invalid.",
      });
      if (kind === "stale") expect(readFileSync(sentinel, "utf8")).toBe("stale\n");
      if (kind === "symlink") expect(lstatSync(sentinel).isSymbolicLink()).toBe(true);
      if (kind === "directory") expect(lstatSync(sentinel).isDirectory()).toBe(true);
    },
  );

  it("opens the sentinel read-only with no-follow semantics and rejects an identity race", async () => {
    const { workspace, sentinel } = makeWorkspace();
    const real = await import("node:fs/promises");
    const open = vi.fn<CompileStoreIo["open"]>(async (path, flags) => {
      expect(path).toBe(sentinel);
      expect(flags & constants.O_NOFOLLOW).toBe(constants.O_NOFOLLOW);
      expect(flags & constants.O_ACCMODE).toBe(constants.O_RDONLY);
      const handle = await real.open(path, flags);
      return {
        stat: (options) => handle.stat(options),
        read: (buffer, offset, length, position) => handle.read(buffer, offset, length, position),
        close: async () => {
          await handle.close();
          writeFileSync(sentinel, COMPILE_STORE_SENTINEL_TEXT, { mode: 0o600 });
        },
      };
    });

    const result = await verifyCompileStoreV02(workspace, { io: { open } });

    expect(open).toHaveBeenCalledOnce();
    expect(result).toMatchObject({ ok: false, reason: "COMPILE_STORE_INVALID" });
  });

  it("does not let a structural lookalike allocate a destination", async () => {
    const randomBytes = vi.fn(() => new Uint8Array(8));
    const result = await allocateAndCommitCompileIdentityV02(
      { boundary_kind: "compile-store", root_identity: { device: "1", inode: "2" } } as never,
      { now: () => 1, randomBytes, commitCandidate: vi.fn() },
    );

    expect(result).toMatchObject({ ok: false, reason: "COMPILE_STORE_INVALID" });
    expect(randomBytes).not.toHaveBeenCalled();
  });

  it("rejects a store whose admitted sentinel becomes stale before allocation", async () => {
    const { workspace, sentinel } = makeWorkspace();
    const verified = await verifyCompileStoreV02(workspace);
    if (!verified.ok) throw new Error(verified.message);
    writeFileSync(sentinel, "stale\n");
    const randomBytes = vi.fn(() => new Uint8Array(8));

    const result = await allocateAndCommitCompileIdentityV02(verified.store, {
      now: () => 1,
      randomBytes,
      commitCandidate: vi.fn(),
    });

    expect(result).toMatchObject({ ok: false, reason: "COMPILE_STORE_INVALID" });
    expect(randomBytes).not.toHaveBeenCalled();
  });
});
