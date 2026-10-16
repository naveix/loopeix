import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { DEFAULT_LOOP_CATALOG, type IntakeRecord, resolveCatalog } from "../../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const evals = join(here, "..", "fixtures", "evals");
const loadJson = <T>(p: string): T => JSON.parse(readFileSync(p, "utf8")) as T;

interface EvalCase {
  case_id: string;
  prompt: string;
  expected: string;
  risk_flags?: string[];
  ambiguities?: string[];
}

const opts = {
  catalog_version_hash: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
  ambiguity_delta: 2,
  minimum_score: 2,
};

function intakeFor(c: EvalCase): IntakeRecord {
  return {
    schema_version: "0.1",
    intake_id: `intake_${c.case_id.replaceAll("-", "_")}`,
    work_item_id: `wi_${c.case_id.replaceAll("-", "_")}`,
    objective: c.prompt,
    requested_outcome: c.prompt,
    candidate_scope: [],
    forbidden_actions: [],
    required_inputs: [],
    risk_flags: c.risk_flags ?? [],
    ambiguities: c.ambiguities ?? [],
    untrusted_source_refs: [],
  };
}

function actualFor(c: EvalCase): string {
  const r = resolveCatalog(intakeFor(c), DEFAULT_LOOP_CATALOG, opts);
  return r.selected_item_id ?? r.terminal_state;
}

describe("compiler eval corpus — golden authoring", () => {
  for (const c of loadJson<EvalCase[]>(join(evals, "golden-authoring.json"))) {
    it(c.case_id, () => {
      expect(actualFor(c)).toBe(c.expected);
    });
  }
});

describe("compiler eval corpus — adversarial prompts", () => {
  for (const c of loadJson<EvalCase[]>(join(evals, "adversarial-prompts.json"))) {
    it(c.case_id, () => {
      expect(actualFor(c)).toBe(c.expected);
    });
  }
});

