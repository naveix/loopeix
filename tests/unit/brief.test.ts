import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { loadBrief, sealedBriefPayload } from "../../src/brief.js";
import { computeBriefHash } from "../../src/schema/receipt.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): string => readFileSync(join(here, "..", "fixtures", "run-seal", name), "utf8");

describe("loadBrief — structured clauses (claim-families-v1.md)", () => {
  it("loads the snitch fixture brief with structured acceptance/forbidden clauses", () => {
    const brief = loadBrief(fixture("snitch-brief.yaml"));
    expect(brief.brief_version).toBe("0.1");
    expect(brief.acceptance).toEqual([{ id: "tests-pass", label: "all tests pass", kind: "tests-pass" }]);
    expect(brief.forbidden).toEqual([
      { id: "no-test-deletion", label: "deleting or skipping tests", kind: "delete_paths", globs: ["tests/**"] },
    ]);
    expect(brief.scope).toEqual(["src/**", "tests/**"]);
  });

  it("defaults forbidden and scope to empty arrays", () => {
    const brief = loadBrief('brief_version: "0.1"\ntask: t\nacceptance:\n  - { id: a, label: l, kind: freeform }\n');
    expect(brief.forbidden).toEqual([]);
    expect(brief.scope).toEqual([]);
  });

  it("REJECTS a path-kind forbidden clause without globs (structural rule)", () => {
    const yaml =
      'brief_version: "0.1"\ntask: t\nacceptance:\n  - { id: a, label: l, kind: tests-pass }\nforbidden:\n  - { id: f, label: no, kind: delete_paths }\n';
    expect(() => loadBrief(yaml)).toThrow(/invalid brief/);
  });

  it("REJECTS a freeform forbidden clause WITH globs (strict branch has no globs key)", () => {
    const yaml =
      'brief_version: "0.1"\ntask: t\nacceptance:\n  - { id: a, label: l, kind: tests-pass }\nforbidden:\n  - { id: f, label: no, kind: freeform, globs: ["x/**"] }\n';
    expect(() => loadBrief(yaml)).toThrow(/invalid brief/);
  });

  it("REJECTS duplicate clause ids across acceptance and forbidden", () => {
    const yaml =
      'brief_version: "0.1"\ntask: t\nacceptance:\n  - { id: same, label: l, kind: tests-pass }\nforbidden:\n  - { id: same, label: no, kind: freeform }\n';
    expect(() => loadBrief(yaml)).toThrow(/duplicate clause id/);
  });

  it("REJECTS the reserved clause id 'scope' with a precise error (F7a: prevents collision with the built-in F3 clause)", () => {
    const yaml =
      'brief_version: "0.1"\ntask: t\nacceptance:\n  - { id: scope, label: l, kind: tests-pass }\n';
    expect(() => loadBrief(yaml)).toThrow(/reserved/);
  });

  it("REJECTS empty acceptance, unknown clause keys, and non-YAML input, each with a precise error", () => {
    expect(() => loadBrief('brief_version: "0.1"\ntask: t\nacceptance: []\n')).toThrow(/invalid brief/);
    expect(() =>
      loadBrief('brief_version: "0.1"\ntask: t\nacceptance:\n  - { id: a, label: l, kind: tests-pass, extra: 1 }\n'),
    ).toThrow(/invalid brief/);
    expect(() => loadBrief("{{ not yaml")).toThrow(/not valid YAML/);
  });
});

describe("sealedBriefPayload", () => {
  it("pairs the brief with the SAME hash buildReceipt embeds, and does not share references", () => {
    const brief = loadBrief(fixture("clean-brief.yaml"));
    const sealed = sealedBriefPayload(brief);
    expect(sealed.brief_hash).toBe(computeBriefHash(brief));
    expect(sealed.brief).toEqual(brief);
    expect(sealed.brief).not.toBe(brief); // cloned — sealing can never mutate the caller's brief
  });
});
