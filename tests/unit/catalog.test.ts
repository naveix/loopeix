import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { DEFAULT_LOOP_CATALOG, LoopCatalogEntrySchema, LoopCatalogSchema } from "../../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const fx = join(here, "..", "fixtures");
const loadJson = (p: string): unknown => JSON.parse(readFileSync(p, "utf8"));

describe("LoopCatalogEntry", () => {
  it("parses the valid authoring fixture", () => {
    expect(LoopCatalogSchema.safeParse(loadJson(join(fx, "valid", "authoring", "item-catalog-basic.json"))).success).toBe(true);
  });

  it("default catalog entries are valid and declare proof boundaries", () => {
    const parsed = LoopCatalogSchema.safeParse(DEFAULT_LOOP_CATALOG);
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.map((i) => i.item_id)).toContain("safe-bugfix");
      for (const item of parsed.data) {
        expect(item.can_prove.length).toBeGreaterThan(0);
        expect(item.cannot_prove.length).toBeGreaterThan(0);
      }
    }
  });

  it("rejects duplicate proof claims", () => {
    const entry = {
      ...DEFAULT_LOOP_CATALOG[0],
      can_prove: ["same", "same"],
    };
    const parsed = LoopCatalogEntrySchema.safeParse(entry);
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(parsed.error.issues.some((i) => i.message.includes("duplicate can_prove"))).toBe(true);
    }
  });

  it("requires cannot_prove so catalog items cannot overclaim", () => {
    const entry = {
      ...DEFAULT_LOOP_CATALOG[0],
      cannot_prove: [],
    };
    expect(LoopCatalogEntrySchema.safeParse(entry).success).toBe(false);
  });
});

