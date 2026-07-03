import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import { describe, expect, it } from "vitest";
import { validateLoopeix } from "../../src/validate.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "..", "fixtures");

const loadYaml = (p: string): unknown => parseYaml(readFileSync(p, "utf8"));
const listYaml = (dir: string): string[] =>
  readdirSync(dir)
    .filter((f) => f.endsWith(".yaml") || f.endsWith(".yml"))
    .sort();

describe("valid/specs — must pass validation", () => {
  const dir = join(fixtures, "valid", "specs");
  for (const file of listYaml(dir)) {
    it(file, () => {
      const res = validateLoopeix(loadYaml(join(dir, file)));
      // Show any errors in the failure output.
      expect(res.errors).toEqual([]);
      expect(res.ok).toBe(true);
    });
  }
});

describe("valid/versions — must pass validation", () => {
  const dir = join(fixtures, "valid", "versions");
  for (const file of listYaml(dir)) {
    it(file, () => {
      const res = validateLoopeix(loadYaml(join(dir, file)));
      expect(res.errors).toEqual([]);
      expect(res.ok).toBe(true);
    });
  }
});

describe("invalid/specs — must fail validation for the INTENDED defect", () => {
  const dir = join(fixtures, "invalid", "specs");
  // Each invalid fixture must produce an error whose path or message contains this token.
  const expectedDefect: Record<string, string> = {
    "missing-schema-version.loop.yaml": "schema_version",
    "duplicate-task-id.loop.yaml": "duplicate",
    "task-unknown-role.loop.yaml": "unknown role",
    "required-artifact-without-producer.loop.yaml": "no producing task",
    "blocking-gate-without-evidence-rule.loop.yaml": "evidence_rule",
    "t5-allowed.loop.yaml": "t5_allowed",
    "forbidden-context-also-required.loop.yaml": "required and forbidden",
    "t5-max-tier.loop.yaml": "max_tier_without_approval",
    "t5-tool-grant.loop.yaml": "risk_tier",
    "malformed-loop-family.loop.yaml": "loop_family",
    "bad-version.loop.yaml": "version",
  };
  for (const file of listYaml(dir)) {
    it(file, () => {
      const res = validateLoopeix(loadYaml(join(dir, file)));
      expect(res.ok).toBe(false);
      expect(res.errors.length).toBeGreaterThan(0);
      const token = expectedDefect[file];
      expect(token, `no expected-defect token registered for ${file}`).toBeDefined();
      const matched = res.errors.some((e) => `${e.path} ${e.message}`.includes(token!));
      expect(
        matched,
        `expected an error containing "${token}" but got:\n${res.errors.map((e) => `  ${e.path}: ${e.message}`).join("\n")}`,
      ).toBe(true);
    });
  }
});
