import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import SpecInspect from "../../src/commands/spec/inspect.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("S35 spec inspect V02 dispatch", () => {
  it("does not inspect a V02 discriminator through the permissive V01 schema", async () => {
    const root = mkdtempSync(join(tmpdir(), "loopeix-s35-spec-inspect-"));
    roots.push(root);
    const fixture = readFileSync(
      join(import.meta.dirname, "../fixtures/valid/specs/minimal-bugfix.loop.yaml"),
      "utf8",
    );
    const path = join(root, "incomplete-v02.loop.yaml");
    writeFileSync(path, fixture.replace('schema_version: "0.1"', 'schema_version: "0.2"'));

    await expect(SpecInspect.run([path], import.meta.dirname)).rejects.toThrow(
      /not a valid V02 Loopeix/,
    );
  });
});
