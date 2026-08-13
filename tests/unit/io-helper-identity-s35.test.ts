import { mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  parseDirectChildName,
  requestLegacyReplayChild,
  type LegacyCompatibilityPolicy,
} from "../../src/io/captured-file.js";

const roots: string[] = [];
const TEST_POLICY: LegacyCompatibilityPolicy = {
  mode: "operator-approved-finite",
  max_member_bytes: 1_024,
  max_total_bytes: 4_096,
  max_heap_bytes: 16_777_216,
  max_elapsed_ms: 5_000,
  approved_by: "operator",
};

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("S35 compatibility helper identity", () => {
  it("rejects a working-directory identity mismatch before reading the child", async () => {
    const root = mkdtempSync(join(tmpdir(), "loopeix-s35-helper-identity-"));
    roots.push(root);
    writeFileSync(join(root, "source.loop.yaml"), "schema_version: '0.1'\n");
    const directory = statSync(root, { bigint: true });

    const response = await requestLegacyReplayChild(
      root,
      {
        direct_child_name: "source.loop.yaml",
        expected_directory_device: directory.dev.toString(),
        expected_directory_inode: (directory.ino + 1n).toString(),
        max_bytes: 1_024,
      },
      TEST_POLICY,
    );

    expect(response).toMatchObject({ ok: false, reason: "IO_IDENTITY_MISMATCH" });
  });

  it("rejects path syntax and non-normalized direct child names", () => {
    expect(parseDirectChildName("../source.loop.yaml")).toBeNull();
    expect(parseDirectChildName("source\\child.loop.yaml")).toBeNull();
    expect(parseDirectChildName("e\u0301.loop.yaml")).toBeNull();
    expect(parseDirectChildName("é.loop.yaml")).toBe("é.loop.yaml");
  });
});
