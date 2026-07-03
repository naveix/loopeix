import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { beforeAll, describe, expect, it } from "vitest";
import { LoopeixShape } from "../../src/schema/loopeix.js";

const here = dirname(fileURLToPath(import.meta.url));
const specs = join(here, "..", "fixtures", "valid", "specs");
const invalid = join(here, "..", "fixtures", "invalid", "specs");
const loadYaml = (p: string): unknown => parseYaml(readFileSync(p, "utf8"));

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
