import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { hashRawBytes } from "../../src/hash.js";
import { captureStructuredFile } from "../../src/io/captured-file.js";

describe("S35 frozen V01 file compatibility", () => {
  it("keeps an above-V02-ceiling authoring oracle on one exact V01 capture", async () => {
    const path = join(
      import.meta.dirname,
      "../fixtures/compat/s35/v01/large-compiled-pack/generated.loop.yaml",
    );
    const exactBytes = new Uint8Array(readFileSync(path));
    expect(exactBytes.byteLength).toBe(4_660_929);
    expect(hashRawBytes(exactBytes)).toBe(
      "sha256:77d168de4aea9abcb40c31a9caedaaa1891661cd973664de7417242d4516e097",
    );

    const captured = await captureStructuredFile(path, null);
    expect(captured.ok).toBe(true);
    if (!captured.ok) throw new Error(captured.message);
    expect(captured.capture.byte_length).toBe(exactBytes.byteLength);

    const selected = await captured.capture.selectFamily("authoring");
    expect(selected).toMatchObject({ ok: true, schema_version: "0.1" });
    if (!selected.ok) throw new Error(selected.message);
    expect(selected.capture).toBe(captured.capture);

    const parsed = await selected.capture.parseV01("authoring");
    expect(parsed).toMatchObject({
      ok: true,
      schema_version: "0.1",
      kind: "authoring",
      byte_length: exactBytes.byteLength,
      raw_hash: hashRawBytes(exactBytes),
    });
  });

  it(
    "parses every frozen V01 file family from its exact captured bytes",
    async () => {
      const fixtureRoot = join(import.meta.dirname, "../fixtures/compat/s35/v01");
      const cases = [
        ["compiled-safe-bugfix/generated.loop.yaml", "authoring"],
        ["planned-run-oracles/claude-20260710T000100Z/resolved-run-plan.json", "resolved-run-plan"],
        ["compiled-safe-bugfix/work-item.json", "work-item"],
        ["compiled-safe-bugfix/intake-record.json", "intake-record"],
        ["compiled-safe-bugfix/catalog-resolution.json", "catalog-resolution"],
        ["compiled-safe-bugfix/compilation-record.json", "compilation-record"],
        ["planned-run-oracles/claude-20260710T000100Z/intake-brief.json", "approved-intake-brief"],
        ["compiled-safe-bugfix/generated.loop.yaml", "generated-loop"],
        ["large-ledger/ledger.jsonl", "ledger-jsonl"],
        ["large-report-input/report-input.json", "report-input"],
        ["large-receipt/receipt.json", "receipt"],
      ] as const;

      for (const [relativePath, kind] of cases) {
        const path = join(fixtureRoot, relativePath);
        const exactBytes = new Uint8Array(readFileSync(path));
        const captured = await captureStructuredFile(path, null);
        expect(captured.ok, relativePath).toBe(true);
        if (!captured.ok) throw new Error(captured.message);

        const parsed = await captured.capture.parseV01(kind);
        expect(parsed, relativePath).toMatchObject({
          ok: true,
          schema_version: "0.1",
          kind,
          byte_length: exactBytes.byteLength,
          raw_hash: hashRawBytes(exactBytes),
        });
      }
    },
    60_000,
  );
});
