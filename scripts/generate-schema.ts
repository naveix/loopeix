import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { LoopeixShape } from "../src/schema/loopeix.js";

/**
 * Generate the public JSON Schema from the Zod source (ADR 0001).
 * Zod emits neither `$schema` (dialect) nor a root `$id`/version, so we stamp them.
 * `unrepresentable: "throw"` fails the build if a public schema ever depends on a
 * non-serializable construct — that is the guard, keep it on.
 */
const DIALECT = "https://json-schema.org/draft/2020-12/schema";
const SCHEMA_VERSION = "0.1";

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, "..", "schemas");
mkdirSync(outDir, { recursive: true });

const body = z.toJSONSchema(LoopeixShape, {
  target: "draft-2020-12",
  unrepresentable: "throw",
  reused: "ref",
});

const schema = {
  $schema: DIALECT,
  $id: `https://loopeix.dev/schemas/loopeix-${SCHEMA_VERSION}.schema.json`,
  title: "Loopeix",
  "x-loopeix-schema-version": SCHEMA_VERSION,
  "x-compatibility-policy": "additive within a minor version; breaking changes bump the version",
  ...body,
};

const outFile = join(outDir, "loopeix.schema.json");
writeFileSync(outFile, `${JSON.stringify(schema, null, 2)}\n`);
console.log(`wrote ${outFile}`);
