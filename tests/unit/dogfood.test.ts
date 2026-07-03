import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { validateLoopSpec } from "../../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));

describe("dogfood — LoopSpec describes its own build (S13-A)", () => {
  it("examples/dogfood/loopspec-oss-build.loopspec.yaml validates against LoopSpec's own validator", () => {
    const text = readFileSync(
      join(here, "..", "..", "examples", "dogfood", "loopspec-oss-build.loopspec.yaml"),
      "utf8",
    );
    const result = validateLoopSpec(parse(text));
    expect(result.errors).toEqual([]);
    expect(result.ok).toBe(true);
  });
});
