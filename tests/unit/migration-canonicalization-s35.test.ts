import { describe, expect, it } from "vitest";
import { parse as parseYaml } from "yaml";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const utf8 = (value: string): Uint8Array => new TextEncoder().encode(value);

describe("S35 bounded structured decode", () => {
  it("accepts one bounded document and rejects duplicate keys, aliases, and oversize input", async () => {
    const { decodeStructuredDocumentV02 } = await import("../../src/schema/decode-envelope.js");

    expect(decodeStructuredDocumentV02(utf8('{"a":1}'), "json")).toEqual({ ok: true, value: { a: 1 } });
    expect(decodeStructuredDocumentV02(utf8('{"a":1,"a":2}'), "json")).toMatchObject({
      ok: false,
      reason: "INVALID_DOCUMENT_ENVELOPE",
    });
    expect(decodeStructuredDocumentV02(utf8("a: &shared 1\nb: *shared\n"), "yaml")).toMatchObject({
      ok: false,
      reason: "INVALID_DOCUMENT_ENVELOPE",
    });
    expect(decodeStructuredDocumentV02(new Uint8Array(4_194_305), "json")).toMatchObject({
      ok: false,
      reason: "INPUT_TOO_LARGE",
    });
  });

  it("maps a recognized V01 lone surrogate to its canonical value location without throwing", async () => {
    const { migrateV01ToV02 } = await import("../../src/schema/migration.js");
    const baseline = parseYaml(
      readFileSync(join(import.meta.dirname, "../fixtures/valid/specs/minimal-bugfix.loop.yaml"), "utf8"),
    ) as Record<string, unknown>;
    const outcome = baseline.outcome as Record<string, unknown>;
    outcome.summary = "before\ud800after";
    const source = utf8(JSON.stringify(baseline));

    const result = migrateV01ToV02({
      source_bytes: source,
      source_format: "json",
      migration_id: "migration_surrogate",
      migrator_version: "1.0.0",
      created_at: "2026-08-03T12:00:00Z",
      bindings_bytes: utf8("[]"),
    });

    expect(result).toMatchObject({
      status: "rejected",
      reason: "UNSUPPORTED_CANONICAL_VALUE",
      source_version: "0.1",
      input_part: "source",
      field: "/outcome/summary",
      location_kind: "string-value",
      member_ordinal: null,
      utf16_code_unit_index: 6,
      utf16_code_unit: 0xd800,
    });
  });
});
