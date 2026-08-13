import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { LoopeixV01Shape } from "../src/schema/loopeix-v01.js";
import { LoopeixV02Shape } from "../src/schema/loopeix-v02.js";
import { ReceiptShape } from "../src/schema/receipt.js";

/**
 * Generate the public JSON Schemas from the Zod sources (ADR 0001).
 * Zod emits neither `$schema` (dialect) nor a root `$id`/version, so we stamp them.
 * `unrepresentable: "throw"` fails the build if a public schema ever depends on a
 * non-serializable construct — that is the guard, keep it on.
 */
const DIALECT = "https://json-schema.org/draft/2020-12/schema";
const COMPATIBILITY_POLICY = "additive within a minor version; breaking changes bump the version";

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, "..", "schemas");
mkdirSync(outDir, { recursive: true });

type JsonObject = Record<string, unknown>;

function schemaBody(shape: z.ZodType): JsonObject {
  return z.toJSONSchema(shape, {
    target: "draft-2020-12",
    unrepresentable: "throw",
    reused: "ref",
  }) as JsonObject;
}

function closeFixedTuples(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(closeFixedTuples);
  if (typeof value !== "object" || value === null) return value;
  const output = Object.fromEntries(
    Object.entries(value).map(([key, child]) => [key, closeFixedTuples(child)]),
  ) as JsonObject;
  if (Array.isArray(output.prefixItems) && output.items === undefined) {
    output.minItems = output.prefixItems.length;
    output.maxItems = output.prefixItems.length;
    output.items = false;
  }
  return output;
}

function versionedAuthoringSchema(
  shape: z.ZodType,
  version: "0.1" | "0.2",
  title: string,
): JsonObject {
  const schema = {
    $schema: DIALECT,
    $id: `https://loopeix.dev/schemas/loopeix-${version}.schema.json`,
    title,
    "x-loopeix-schema-version": version,
    "x-compatibility-policy": COMPATIBILITY_POLICY,
    ...(version === "0.2" ? closeFixedTuples(schemaBody(shape)) as JsonObject : schemaBody(shape)),
  };
  return schema;
}

function rebaseInternalRefs(value: unknown, namespace: "v01" | "v02"): unknown {
  if (Array.isArray(value)) return value.map((item) => rebaseInternalRefs(item, namespace));
  if (typeof value !== "object" || value === null) return value;
  const output: JsonObject = {};
  for (const [key, child] of Object.entries(value)) {
    output[key] =
      key === "$ref" && typeof child === "string" && child.startsWith("#/$defs/")
        ? `#/$defs/${namespace}/$defs/${child.slice("#/$defs/".length)}`
        : rebaseInternalRefs(child, namespace);
  }
  return output;
}

function embeddedVersionSchema(schema: JsonObject, namespace: "v01" | "v02"): JsonObject {
  const copy = structuredClone(schema);
  delete copy.$schema;
  delete copy.$id;
  return rebaseInternalRefs(copy, namespace) as JsonObject;
}

function receiptSchema(): JsonObject {
  return {
    $schema: DIALECT,
    $id: "https://loopeix.dev/schemas/receipt-0.1.schema.json",
    title: "Loopeix Receipt",
    "x-loopeix-schema-version": "0.1",
    "x-compatibility-policy": COMPATIBILITY_POLICY,
    ...schemaBody(ReceiptShape),
  };
}

function emit(fileName: string, schema: JsonObject): void {
  const outFile = join(outDir, fileName);
  writeFileSync(outFile, `${JSON.stringify(schema, null, 2)}\n`);
  console.log(`wrote ${outFile}`);
}

const v01 = versionedAuthoringSchema(LoopeixV01Shape, "0.1", "Loopeix");
const v02 = versionedAuthoringSchema(LoopeixV02Shape, "0.2", "Loopeix 0.2");
const dispatcher: JsonObject = {
  $schema: DIALECT,
  $id: "https://loopeix.dev/schemas/loopeix.schema.json",
  title: "Loopeix Supported Authoring Versions",
  "x-loopeix-supported-schema-versions": ["0.1", "0.2"],
  "x-compatibility-policy": COMPATIBILITY_POLICY,
  oneOf: [{ $ref: "#/$defs/v01" }, { $ref: "#/$defs/v02" }],
  $defs: {
    v01: embeddedVersionSchema(v01, "v01"),
    v02: embeddedVersionSchema(v02, "v02"),
  },
};

emit("loopeix-0.1.schema.json", v01);
emit("loopeix-0.2.schema.json", v02);
emit("loopeix.schema.json", dispatcher);
emit("receipt.schema.json", receiptSchema());
