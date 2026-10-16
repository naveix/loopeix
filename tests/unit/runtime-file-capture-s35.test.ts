import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import * as rootExports from "../../src/index.js";
import {
  captureRunFileForRuntimeV02,
  captureRunFileForRuntimeInspectionV02,
  captureRunFileForRuntimeInspectionV02ForTest,
  captureRunFileForRuntimeV02ForTest,
  isAnchoredRunDirectoryReadCapabilityV02,
  isCapturedRunFileMetadataV02,
  isHelperOwnedRunFileCaptureV02,
  issueAnchoredRunDirectoryReadCapabilityV02,
} from "../../src/io/runtime-file-capture-v02.js";

const roots: string[] = [];

function makeRoot(): string {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "loopeix-runtime-capture-")));
  roots.push(root);
  return root;
}

function writeRuntimeFile(root: string, relativePath: string, bytes: Uint8Array, mode = 0o600): string {
  const segments = relativePath.split("/");
  const file = segments.pop()!;
  const parent = join(root, ...segments);
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  const path = join(parent, file);
  writeFileSync(path, bytes, { mode });
  chmodSync(path, mode);
  return path;
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("S35 helper-owned runtime file capture", () => {
  it("captures exact nested 0600 bytes with matching immutable metadata", async () => {
    const root = makeRoot();
    const source = new Uint8Array([0, 1, 2, 250, 255]);
    writeRuntimeFile(root, "evidence/records/result.json", source);

    const issued = await issueAnchoredRunDirectoryReadCapabilityV02(root);
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;
    const result = await captureRunFileForRuntimeV02({
      anchored_run_directory: issued.value,
      relative_path: "evidence/records/result.json",
      max_bytes: source.byteLength,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.relative_path).toBe("evidence/records/result.json");
    expect([...result.value.bytes]).toEqual([...source]);
    expect(result.value.metadata).toMatchObject({
      mode: 384,
      size_bytes: source.byteLength,
      sha256: `sha256:${createHash("sha256").update(source).digest("hex")}`,
    });
    expect(isAnchoredRunDirectoryReadCapabilityV02(issued.value)).toBe(true);
    expect(isCapturedRunFileMetadataV02(result.value.metadata)).toBe(true);
    expect(isHelperOwnedRunFileCaptureV02(result.value)).toBe(true);

    const exposed = result.value.bytes;
    exposed[0] = 99;
    source[1] = 88;
    expect([...result.value.bytes]).toEqual([0, 1, 2, 250, 255]);
  });

  it("admits legacy 0644 files for read-only inspection and preserves the exact mode", async () => {
    const root = makeRoot();
    const source = new Uint8Array([7, 8, 9]);
    writeRuntimeFile(root, "ledger.jsonl", source, 0o644);

    const issued = await issueAnchoredRunDirectoryReadCapabilityV02(root);
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;
    const result = await captureRunFileForRuntimeInspectionV02({
      anchored_run_directory: issued.value,
      relative_path: "ledger.jsonl",
      max_bytes: source.byteLength,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.metadata).toMatchObject({
      mode: 420,
      size_bytes: source.byteLength,
      sha256: `sha256:${createHash("sha256").update(source).digest("hex")}`,
    });
  });

  it("rejects structural capability and capture lookalikes and stays off root exports", async () => {
    expect(isAnchoredRunDirectoryReadCapabilityV02({})).toBe(false);
    expect(isCapturedRunFileMetadataV02({ mode: 384, size_bytes: 0, sha256: `sha256:${"0".repeat(64)}` })).toBe(false);
    expect(isHelperOwnedRunFileCaptureV02({ relative_path: "x", bytes: new Uint8Array(), metadata: {} })).toBe(false);
    expect("captureRunFileForRuntimeV02" in rootExports).toBe(false);
    expect("issueAnchoredRunDirectoryReadCapabilityV02" in rootExports).toBe(false);
    await expect(captureRunFileForRuntimeV02({
      anchored_run_directory: {} as never,
      relative_path: "ledger.jsonl",
      max_bytes: 1,
    })).resolves.toEqual({ ok: false, error: "RUNTIME_FILE_PATH_INVALID" });
    await expect(captureRunFileForRuntimeV02(null as never)).resolves.toEqual({
      ok: false,
      error: "RUNTIME_FILE_PATH_INVALID",
    });
    const hostile = new Proxy({}, {
      get: () => {
        throw new Error("hostile getter");
      },
    });
    await expect(captureRunFileForRuntimeV02(hostile as never)).resolves.toEqual({
      ok: false,
      error: "RUNTIME_FILE_PATH_INVALID",
    });
  });

  it("rejects invalid roots, paths, and byte limits without throwing", async () => {
    await expect(issueAnchoredRunDirectoryReadCapabilityV02("relative/root")).resolves.toEqual({
      ok: false,
      error: "RUNTIME_FILE_PATH_INVALID",
    });
    const root = makeRoot();
    writeRuntimeFile(root, "ledger.jsonl", new Uint8Array([1]));
    const issued = await issueAnchoredRunDirectoryReadCapabilityV02(root);
    if (!issued.ok) throw new Error("fixture capability issuance failed");
    for (const relative_path of ["../ledger.jsonl", "/ledger.jsonl", "a\\b", "a//b"] as const) {
      await expect(captureRunFileForRuntimeV02({
        anchored_run_directory: issued.value,
        relative_path,
        max_bytes: 1,
      })).resolves.toEqual({ ok: false, error: "RUNTIME_FILE_PATH_INVALID" });
    }
    for (const max_bytes of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1] as const) {
      await expect(captureRunFileForRuntimeV02({
        anchored_run_directory: issued.value,
        relative_path: "ledger.jsonl",
        max_bytes,
      })).resolves.toEqual({ ok: false, error: "RUNTIME_INPUT_RESOURCE_LIMIT" });
    }
  });

  it("rejects symlinks, non-regular files, wrong mode, and oversize input", async () => {
    const root = makeRoot();
    const issued = await issueAnchoredRunDirectoryReadCapabilityV02(root);
    if (!issued.ok) throw new Error("fixture capability issuance failed");

    writeRuntimeFile(root, "target.json", new Uint8Array([1]));
    symlinkSync("target.json", join(root, "link.json"));
    await expect(captureRunFileForRuntimeV02({ anchored_run_directory: issued.value, relative_path: "link.json", max_bytes: 8 }))
      .resolves.toEqual({ ok: false, error: "RUNTIME_FILE_NOT_REGULAR" });

    mkdirSync(join(root, "directory"));
    await expect(captureRunFileForRuntimeV02({ anchored_run_directory: issued.value, relative_path: "directory", max_bytes: 8 }))
      .resolves.toEqual({ ok: false, error: "RUNTIME_FILE_NOT_REGULAR" });

    writeRuntimeFile(root, "wrong-mode.json", new Uint8Array([1]), 0o644);
    await expect(captureRunFileForRuntimeV02({ anchored_run_directory: issued.value, relative_path: "wrong-mode.json", max_bytes: 8 }))
      .resolves.toEqual({ ok: false, error: "RUNTIME_FILE_MODE_INVALID" });

    writeRuntimeFile(root, "special-mode.json", new Uint8Array([1]), 0o1600);
    await expect(captureRunFileForRuntimeV02({ anchored_run_directory: issued.value, relative_path: "special-mode.json", max_bytes: 8 }))
      .resolves.toEqual({ ok: false, error: "RUNTIME_FILE_MODE_INVALID" });

    writeRuntimeFile(root, "large.json", new Uint8Array([1, 2]));
    await expect(captureRunFileForRuntimeV02({ anchored_run_directory: issued.value, relative_path: "large.json", max_bytes: 1 }))
      .resolves.toEqual({ ok: false, error: "RUNTIME_INPUT_RESOURCE_LIMIT" });

    mkdirSync(join(root, "real-parent"));
    writeRuntimeFile(root, "real-parent/value.json", new Uint8Array([1]));
    symlinkSync("real-parent", join(root, "linked-parent"));
    await expect(captureRunFileForRuntimeV02({ anchored_run_directory: issued.value, relative_path: "linked-parent/value.json", max_bytes: 8 }))
      .resolves.toEqual({ ok: false, error: "RUNTIME_FILE_PATH_INVALID" });
  });

  it("detects a same-path replacement between read and identity recheck", async () => {
    const root = makeRoot();
    const path = writeRuntimeFile(root, "records/value.json", new Uint8Array([1, 2, 3]));
    const replacement = writeRuntimeFile(root, "records/replacement.json", new Uint8Array([4, 5, 6]));
    const issued = await issueAnchoredRunDirectoryReadCapabilityV02(root);
    if (!issued.ok) throw new Error("fixture capability issuance failed");

    await expect(captureRunFileForRuntimeV02ForTest({
      anchored_run_directory: issued.value,
      relative_path: "records/value.json",
      max_bytes: 3,
    }, {
      after_read_before_recheck: () => renameSync(replacement, path),
    })).resolves.toEqual({ ok: false, error: "RUNTIME_FILE_IDENTITY_CHANGED" });
  });

  it("keeps inspection capture fail-closed for symlinks and same-path swaps", async () => {
    const root = makeRoot();
    const issued = await issueAnchoredRunDirectoryReadCapabilityV02(root);
    if (!issued.ok) throw new Error("fixture capability issuance failed");

    writeRuntimeFile(root, "target.jsonl", new Uint8Array([1]), 0o644);
    symlinkSync("target.jsonl", join(root, "link.jsonl"));
    await expect(captureRunFileForRuntimeInspectionV02({
      anchored_run_directory: issued.value,
      relative_path: "link.jsonl",
      max_bytes: 8,
    })).resolves.toEqual({ ok: false, error: "RUNTIME_FILE_NOT_REGULAR" });

    const path = writeRuntimeFile(root, "records/value.json", new Uint8Array([1, 2, 3]), 0o644);
    const replacement = writeRuntimeFile(root, "records/replacement.json", new Uint8Array([4, 5, 6]), 0o644);
    await expect(captureRunFileForRuntimeInspectionV02ForTest({
      anchored_run_directory: issued.value,
      relative_path: "records/value.json",
      max_bytes: 3,
    }, {
      after_read_before_recheck: () => renameSync(replacement, path),
    })).resolves.toEqual({ ok: false, error: "RUNTIME_FILE_IDENTITY_CHANGED" });
  });
});
