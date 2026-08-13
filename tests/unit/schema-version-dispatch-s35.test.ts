import { readFileSync } from "node:fs";
import { basename, join } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import { parse as parseYaml } from "yaml";
import { describe, expect, it, vi } from "vitest";
import { LoopeixShape } from "../../src/schema/loopeix.js";
import { validateLoopeix } from "../../src/validate.js";
import type {
  LoopeixV01Value,
  LoopeixV02Value,
  LoopeixDocumentParseResult,
  MigratorVersion,
  MigrateV01ToV02Input,
  LoopeixMigrationResult,
} from "../../src/index.js";

type Assert<T extends true> = T;
type IsAssignable<T, U> = T extends U ? true : false;
type _StagedPublicTypeContract = [
  Assert<IsAssignable<LoopeixV01Value["schema_version"], "0.1">>,
  Assert<IsAssignable<LoopeixV02Value["schema_version"], "0.2">>,
  Assert<IsAssignable<LoopeixDocumentParseResult, { ok: boolean }>>,
  Assert<IsAssignable<MigratorVersion, string>>,
  Assert<IsAssignable<MigrateV01ToV02Input["migrator_version"], MigratorVersion>>,
  Assert<IsAssignable<LoopeixMigrationResult, { migration_contract_version: "0.1" }>>,
];

const baseline = parseYaml(
  readFileSync(join(import.meta.dirname, "../fixtures/valid/specs/minimal-bugfix.loop.yaml"), "utf8"),
) as Record<string, unknown>;

describe("S35 literal authoring version dispatch", () => {
  it("exposes only the implemented staged Gate 1.5 package-root facade", async () => {
    const root = await import("../../src/index.js");
    const v01 = await import("../../src/schema/loopeix-v01.js");
    const v02 = await import("../../src/schema/loopeix-v02.js");
    const dispatch = await import("../../src/schema/version-dispatch.js");
    const migration = await import("../../src/schema/migration.js");

    expect(root.LoopeixV01).toBeDefined();
    expect(root.LoopeixV01).toBe(v01.LoopeixV01Shape);
    expect(root.LoopeixV02).toBeDefined();
    expect(root.LoopeixV02).toBe(v02.LoopeixV02Shape);
    expect(root.parseLoopeixDocument).toBeDefined();
    expect(root.parseLoopeixDocument).toBe(dispatch.parseLoopeixDocument);
    expect(root.migrateV01ToV02).toBeDefined();
    expect(root.migrateV01ToV02).toBe(migration.migrateV01ToV02);
    for (const privateName of [
      "dispatchLoopeixValue", "validateLoopeixV01", "validateLoopeixV02",
      "LoopeixV01Shape", "LoopeixV02Shape", "decodeStructuredDocumentV02",
      "classifyV02PlannedDirectory", "openAnchoredWriteSession",
    ]) {
      expect(privateName in root, privateName).toBe(false);
    }
  });

  it("keeps direct legacy validation broad while the named V01 schema is literal", async () => {
    const candidate = { ...baseline, schema_version: "0.3" };

    expect(LoopeixShape.safeParse(candidate).success).toBe(true);
    expect(validateLoopeix(candidate).ok).toBe(true);

    const module = await import("../../src/schema/loopeix-v01.js");
    expect(module.LoopeixV01Shape.safeParse(candidate).success).toBe(false);
    expect(module.LoopeixV01Shape.safeParse(baseline).success).toBe(true);
  });

  it("rejects an unsupported well-formed version before family structural validation", async () => {
    const unsupportedVersion = "12345678901234567890.09876543210987654321";
    const candidate = { ...baseline, schema_version: unsupportedVersion, roles: "not-an-array" };
    const module = await import("../../src/schema/version-dispatch.js");

    const parsed = module.parseLoopeixDocument(candidate);
    expect(parsed).toEqual({
      ok: false,
      schema_version: null,
      reason: "UNSUPPORTED_SCHEMA_VERSION",
      message: "schema_version is not supported; supported versions are '0.1' and '0.2'.",
    });
    expect(JSON.stringify(parsed)).not.toContain(unsupportedVersion);
  });

  it("is total and never coerces or executes a raw schema_version accessor", async () => {
    const module = await import("../../src/schema/version-dispatch.js");
    const accessor = Object.defineProperty({}, "schema_version", {
      enumerable: true,
      get(): never {
        throw new Error("getter must not execute");
      },
    });

    expect(module.parseLoopeixDocument([])).toMatchObject({ reason: "MISSING_SCHEMA_VERSION" });
    expect(module.parseLoopeixDocument({ schema_version: 0.2 })).toMatchObject({ reason: "MALFORMED_SCHEMA_VERSION" });
    expect(module.parseLoopeixDocument({ schema_version: " 0.2" })).toMatchObject({ reason: "MALFORMED_SCHEMA_VERSION" });
    expect(module.parseLoopeixDocument(accessor)).toMatchObject({ reason: "MALFORMED_SCHEMA_VERSION" });
  });

  it("keeps explicit family validators separate from the unsuffixed legacy validator", async () => {
    const validators = await import("../../src/validate.js");
    const broadCandidate = { ...baseline, schema_version: "0.3" };

    expect(validators.validateLoopeix(broadCandidate).ok).toBe(true);
    expect(validators.validateLoopeixV01(broadCandidate).ok).toBe(false);
    expect(validators.validateLoopeixV01(baseline).ok).toBe(true);
    expect(validators.validateLoopeixV02(baseline).ok).toBe(false);
  });

  it("generates literal V01/V02 schemas plus a self-contained ordered dispatcher", async () => {
    const writes = new Map<string, string>();
    vi.doMock("node:fs", async () => {
      const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
      return {
        ...actual,
        mkdirSync: vi.fn(),
        writeFileSync: vi.fn((path: import("node:fs").PathOrFileDescriptor, data: string | NodeJS.ArrayBufferView) => {
          writes.set(basename(String(path)), String(data));
        }),
      };
    });
    try {
      await import("../../scripts/generate-schema.js");
    } finally {
      vi.doUnmock("node:fs");
    }

    expect([...writes.keys()].sort()).toEqual([
      "loopeix-0.1.schema.json",
      "loopeix-0.2.schema.json",
      "loopeix.schema.json",
      "receipt.schema.json",
    ]);
    const v01 = JSON.parse(writes.get("loopeix-0.1.schema.json")!) as Record<string, unknown>;
    const v02 = JSON.parse(writes.get("loopeix-0.2.schema.json")!) as Record<string, unknown>;
    const dispatcher = JSON.parse(writes.get("loopeix.schema.json")!) as Record<string, unknown>;
    expect(v01).toMatchObject({
      $id: "https://loopeix.dev/schemas/loopeix-0.1.schema.json",
      title: "Loopeix",
      properties: { schema_version: { type: "string", const: "0.1" } },
    });
    expect(dispatcher).toMatchObject({
      $id: "https://loopeix.dev/schemas/loopeix.schema.json",
      title: "Loopeix Supported Authoring Versions",
      "x-loopeix-supported-schema-versions": ["0.1", "0.2"],
      oneOf: [{ $ref: "#/$defs/v01" }, { $ref: "#/$defs/v02" }],
    });
    expect(v02).toMatchObject({
      properties: {
        recovery_policy: {
          properties: {
            activation_reasons: {
              minItems: 4,
              maxItems: 4,
              items: false,
            },
          },
        },
      },
    });
    const ajv = new Ajv2020({ strict: false });
    const validate = ajv.compile(dispatcher);
    expect(validate(baseline)).toBe(true);
    expect(validate({ ...baseline, schema_version: "0.3" })).toBe(false);
    expect(writes.get("receipt.schema.json")).toBe(
      readFileSync(join(import.meta.dirname, "../../schemas/receipt.schema.json"), "utf8"),
    );
  });
});
