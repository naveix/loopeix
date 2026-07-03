import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { validateLoopeix } from "../../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));

describe("dogfood — Loopeix describes its own build (S13-A)", () => {
  it("examples/dogfood/loopeix-oss-build.loopeix.yaml validates against Loopeix's own validator", () => {
    const text = readFileSync(
      join(here, "..", "..", "examples", "dogfood", "loopeix-oss-build.loopeix.yaml"),
      "utf8",
    );
    const result = validateLoopeix(parse(text));
    expect(result.errors).toEqual([]);
    expect(result.ok).toBe(true);
  });
});
