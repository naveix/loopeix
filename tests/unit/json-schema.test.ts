import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { beforeAll, describe, expect, it } from "vitest";
import { LoopeixShape } from "../../src/schema/loopeix.js";
import { ReceiptShape } from "../../src/schema/receipt.js";

const here = dirname(fileURLToPath(import.meta.url));
const specs = join(here, "..", "fixtures", "valid", "specs");
const invalid = join(here, "..", "fixtures", "invalid", "specs");
const receipts = join(here, "..", "fixtures", "receipts");
const loadYaml = (p: string): unknown => parseYaml(readFileSync(p, "utf8"));
const loadJson = (p: string): unknown => JSON.parse(readFileSync(p, "utf8"));

let validate: (d: unknown) => boolean;

beforeAll(() => {
  const jsonSchema = z.toJSONSchema(LoopeixShape, {
    target: "draft-2020-12",
    unrepresentable: "throw",
    reused: "ref",
  });
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  addFormats(ajv);
  const compiled = ajv.compile(jsonSchema);
  validate = (d: unknown): boolean => compiled(d) === true;
});

describe("generated JSON Schema accepts every valid spec", () => {
  for (const f of ["minimal-bugfix", "expert-sprint", "refactor-dependency-trace", "gate-failure-correction", "improvement-proposal"]) {
    it(`${f}.loop.yaml`, () => {
      expect(validate(loadYaml(join(specs, `${f}.loop.yaml`)))).toBe(true);
    });
  }
});

describe("JSON Schema catches STRUCTURAL defects", () => {
  for (const f of [
    "missing-schema-version",
    "t5-allowed",
    "t5-max-tier",
    "t5-tool-grant",
    "malformed-loop-family",
    "bad-version",
  ]) {
    it(`${f}.loop.yaml → rejected`, () => {
      expect(validate(loadYaml(join(invalid, `${f}.loop.yaml`)))).toBe(false);
    });
  }
});

describe("JSON Schema alone CANNOT catch relational defects (two-layer boundary)", () => {
  // These are structurally valid; only the full validator's invariant pass catches them.
  for (const f of [
    "duplicate-task-id",
    "task-unknown-role",
    "required-artifact-without-producer",
    "blocking-gate-without-evidence-rule",
    "forbidden-context-also-required",
  ]) {
    it(`${f}.loop.yaml → passes JSON Schema (caught later by validateLoopeix)`, () => {
      expect(validate(loadYaml(join(invalid, `${f}.loop.yaml`)))).toBe(true);
    });
  }
});

describe("generated receipt JSON Schema (schemas/receipt.schema.json) vs receipt fixtures", () => {
  let validateReceipt: (d: unknown) => boolean;

  beforeAll(() => {
    // Validate against the COMMITTED artifact — the file a stranger's ajv would use.
    const onDisk = loadJson(join(here, "..", "..", "schemas", "receipt.schema.json")) as Record<string, unknown>;
    const ajv = new Ajv2020({ strict: false, allErrors: true });
    addFormats(ajv);
    const compiled = ajv.compile(onDisk);
    validateReceipt = (d: unknown): boolean => compiled(d) === true;

    // Drift guard: the committed file must be exactly what the Zod source generates today.
    const fresh = z.toJSONSchema(ReceiptShape, { target: "draft-2020-12", unrepresentable: "throw", reused: "ref" });
    // z.toJSONSchema emits `$schema` itself; only $id/title/x-* are stamped additions.
    const { $id, title, ...stripped } = onDisk;
    delete stripped["x-loopeix-schema-version"];
    delete stripped["x-compatibility-policy"];
    expect(stripped).toEqual(fresh);
  });

  for (const f of ["clean-pass", "snitch", "snitch.tampered-verdict", "snitch.bad-signature"]) {
    it(`${f}.receipt.json → accepted (the schema cannot check signatures — verifyReceipt does)`, () => {
      expect(validateReceipt(loadJson(join(receipts, `${f}.receipt.json`)))).toBe(true);
    });
  }

  it("snitch.uncited-contradiction.receipt.json → rejected (the doctrine is STRUCTURAL: even plain ajv refuses an uncited CONTRADICTED)", () => {
    expect(validateReceipt(loadJson(join(receipts, "snitch.uncited-contradiction.receipt.json")))).toBe(false);
  });
});
