import {
  chmodSync,
  mkdtempSync,
  mkdirSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  readAnchoredRuntimeDirectoryMemberText,
  readAnchoredRuntimeDirectoryMemberTextForTest,
  readAnchoredRuntimeTextFile,
  readAnchoredRuntimeTextFileForTest,
  resolveRunInspectionTarget,
} from "../../src/run/runtime-inspection-read.js";

const roots: string[] = [];

function makeRoot(): string {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "loopeix-runtime-inspection-")));
  roots.push(root);
  return root;
}

function writeRuntimeFile(root: string, relativePath: string, contents: string, mode = 0o600): string {
  const segments = relativePath.split("/");
  const fileName = segments.pop()!;
  const parent = join(root, ...segments);
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  const path = join(parent, fileName);
  writeFileSync(path, contents, { mode });
  chmodSync(path, mode);
  return path;
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("runtime inspection anchored reads", () => {
  it("classifies direct files and directories, then captures exact UTF-8 text", async () => {
    const root = makeRoot();
    const ledger = writeRuntimeFile(root, "ledger.jsonl", '{"event":1}\n');
    writeRuntimeFile(root, "resolved-run-plan.json", '{"schema_version":"0.1"}\n');

    await expect(resolveRunInspectionTarget(ledger)).resolves.toEqual({
      ok: true,
      target: { kind: "file", path: ledger },
    });
    await expect(resolveRunInspectionTarget(root)).resolves.toEqual({
      ok: true,
      target: { kind: "directory", path: root },
    });
    await expect(readAnchoredRuntimeTextFile(ledger, 1024)).resolves.toEqual({
      ok: true,
      path: ledger,
      text: '{"event":1}\n',
    });
    await expect(readAnchoredRuntimeDirectoryMemberText(root, "resolved-run-plan.json", 1024)).resolves.toEqual({
      ok: true,
      path: join(root, "resolved-run-plan.json"),
      text: '{"schema_version":"0.1"}\n',
    });
  });

  it("fails closed on symlinked direct files while admitting legacy 0644 inspection reads", async () => {
    const root = makeRoot();
    const target = writeRuntimeFile(root, "ledger.jsonl", '{"event":1}\n');
    const link = join(root, "ledger-link.jsonl");
    symlinkSync("ledger.jsonl", link);
    await expect(readAnchoredRuntimeTextFile(link, 1024)).resolves.toEqual({
      ok: false,
      reason: "FILE_CAPTURE_INVALID",
      message: "The runtime file path must not be a symlink.",
    });

    const wrongMode = writeRuntimeFile(root, "wrong-mode.jsonl", '{"event":2}\n', 0o644);
    await expect(readAnchoredRuntimeTextFile(wrongMode, 1024)).resolves.toEqual({
      ok: true,
      path: wrongMode,
      text: '{"event":2}\n',
    });

    const specialMode = writeRuntimeFile(root, "special-mode.jsonl", '{"event":3}\n', 0o1600);
    await expect(readAnchoredRuntimeTextFile(specialMode, 1024)).resolves.toEqual({
      ok: false,
      reason: "FILE_CAPTURE_MODE_INVALID",
      message: "The runtime file must be a direct regular 0600 file, or a legacy 0644 file for read-only inspection.",
    });

    expect(target).toContain("ledger.jsonl");
  });

  it("maps an absent direct directory member to not-found before planned fallback", async () => {
    const root = makeRoot();

    await expect(readAnchoredRuntimeDirectoryMemberText(root, "ledger.jsonl", 1024)).resolves.toEqual({
      ok: false,
      reason: "FILE_NOT_FOUND",
      message: `The runtime file does not exist: ${join(root, "ledger.jsonl")}`,
    });
  });

  it("keeps directory-member inspection fail-closed for symlinks and same-path swaps", async () => {
    const root = makeRoot();
    writeRuntimeFile(root, "target.jsonl", '{"event":1}\n', 0o644);
    symlinkSync("target.jsonl", join(root, "ledger.jsonl"));
    await expect(readAnchoredRuntimeDirectoryMemberText(root, "ledger.jsonl", 1024)).resolves.toEqual({
      ok: false,
      reason: "FILE_CAPTURE_INVALID",
      message: "The runtime file path is invalid or not a regular file.",
    });

    rmSync(join(root, "ledger.jsonl"));
    const ledger = writeRuntimeFile(root, "ledger.jsonl", '{"event":1}\n', 0o644);
    const replacement = writeRuntimeFile(root, "replacement.jsonl", '{"event":2}\n', 0o644);
    await expect(readAnchoredRuntimeDirectoryMemberTextForTest(root, "ledger.jsonl", 1024, {
      after_read_before_recheck: () => renameSync(replacement, ledger),
    })).resolves.toEqual({
      ok: false,
      reason: "FILE_CAPTURE_IDENTITY_CHANGED",
      message: "The runtime file identity changed during capture.",
    });
  });

  it("detects a same-path replacement during anchored capture", async () => {
    const root = makeRoot();
    const ledger = writeRuntimeFile(root, "ledger.jsonl", '{"event":1}\n');
    const replacement = writeRuntimeFile(root, "replacement.jsonl", '{"event":2}\n');

    await expect(readAnchoredRuntimeTextFileForTest(ledger, 1024, {
      after_read_before_recheck: () => renameSync(replacement, ledger),
    })).resolves.toEqual({
      ok: false,
      reason: "FILE_CAPTURE_IDENTITY_CHANGED",
      message: "The runtime file identity changed during capture.",
    });
  });
});
