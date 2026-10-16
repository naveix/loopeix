import { describe, expect, it } from "vitest";
import { DEFAULT_LOOP_CATALOG, type IntakeRecord, resolveCatalog } from "../../src/index.js";

const baseIntake = (objective: string, extra: Partial<IntakeRecord> = {}): IntakeRecord => ({
  schema_version: "0.1",
  intake_id: "intake_test",
  work_item_id: "wi_test",
  objective,
  requested_outcome: objective,
  candidate_scope: [],
  forbidden_actions: [],
  required_inputs: [],
  risk_flags: [],
  ambiguities: [],
  untrusted_source_refs: [],
  ...extra,
});

const opts = {
  catalog_version_hash: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
  ambiguity_delta: 2,
  minimum_score: 2,
};

describe("resolveCatalog", () => {
  it("selects safe-bugfix for failing test bugfix prompts", () => {
    const r = resolveCatalog(baseIntake("Fix the failing test in the date parser bug"), DEFAULT_LOOP_CATALOG, opts);
    expect(r.terminal_state).toBe("compiled");
    expect(r.selected_item_id).toBe("safe-bugfix");
  });

  it("selects claims-check-pr for PR claim prompts", () => {
    const r = resolveCatalog(baseIntake("Check this PR claims and verify receipt evidence"), DEFAULT_LOOP_CATALOG, opts);
    expect(r.terminal_state).toBe("compiled");
    expect(r.selected_item_id).toBe("claims-check-pr");
  });

  it("selects research-need-cluster for multi-platform research prompts", () => {
    const r = resolveCatalog(baseIntake("Research HN Reddit X and competitor sources for user needs"), DEFAULT_LOOP_CATALOG, opts);
    expect(r.terminal_state).toBe("compiled");
    expect(r.selected_item_id).toBe("research-need-cluster");
  });

  it("holds ambiguous cleanup and ship prompts", () => {
    const r = resolveCatalog(
      baseIntake("Clean this repo up and ship it", { ambiguities: ["clean up", "ship"] }),
      DEFAULT_LOOP_CATALOG,
      opts,
    );
    expect(r.terminal_state).toBe("hold-no-item");
    expect(r.selected_item_id).toBeNull();
  });

  it("holds risk for background prompts", () => {
    const r = resolveCatalog(
      baseIntake("Run in the background until it is green", { risk_flags: ["t5"] }),
      DEFAULT_LOOP_CATALOG,
      opts,
    );
    expect(r.terminal_state).toBe("hold-risk");
    expect(r.selected_item_id).toBeNull();
  });

  it("never selects an out-of-catalog item", () => {
    const r = resolveCatalog(baseIntake("something unknown"), DEFAULT_LOOP_CATALOG, opts);
    const ids = new Set(DEFAULT_LOOP_CATALOG.map((i) => i.item_id));
    expect(r.selected_item_id === null || ids.has(r.selected_item_id)).toBe(true);
  });
});

