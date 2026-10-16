import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { hashRawBytes } from "../../src/hash.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("S35 captured structured file", () => {
  it("captures a direct regular file once and preserves identity through family selection and V01 parse", async () => {
    const { captureStructuredFile } = await import("../../src/io/captured-file.js");
    const root = mkdtempSync(join(tmpdir(), "loopeix-s35-capture-"));
    roots.push(root);
    const sourceFixture = join(import.meta.dirname, "../fixtures/valid/specs/minimal-bugfix.loop.yaml");
    const path = join(root, "source.loop.yaml");
    writeFileSync(path, readFileSync(sourceFixture));
    const expected = new Uint8Array(readFileSync(path));

    const result = await captureStructuredFile(path, null);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.message);
    expect(result.capture.byte_length).toBe(expected.byteLength);
    writeFileSync(path, "schema_version: '9.9'\n");

    const selected = await result.capture.selectFamily("authoring");
    expect(selected).toMatchObject({ ok: true, schema_version: "0.1" });
    if (!selected.ok) throw new Error(selected.message);
    expect(selected.capture).toBe(result.capture);

    const parsed = await result.capture.parseV01("authoring");
    expect(parsed).toMatchObject({
      ok: true,
      schema_version: "0.1",
      kind: "authoring",
      byte_length: expected.byteLength,
      raw_hash: hashRawBytes(expected),
    });

    const firstSnapshot = await result.capture.snapshotBytes();
    expect(firstSnapshot.ok).toBe(true);
    if (!firstSnapshot.ok) throw new Error(firstSnapshot.message);
    firstSnapshot.bytes.fill(0);
    const secondSnapshot = await result.capture.snapshotBytes();
    expect(secondSnapshot.ok).toBe(true);
    if (!secondSnapshot.ok) throw new Error(secondSnapshot.message);
    expect(secondSnapshot.bytes).toEqual(expected);
  });
});
