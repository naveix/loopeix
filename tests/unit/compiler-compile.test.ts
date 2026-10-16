import { parse as parseYaml } from "yaml";
import { describe, expect, it } from "vitest";
import { DEFAULT_LOOP_CATALOG, hashCanonical, validateLoopeix } from "../../src/index.js";
import { compilePrompt } from "../../src/compiler/compile.js";

const hash = "sha256:3333333333333333333333333333333333333333333333333333333333333333";

describe("compilePrompt", () => {
  it("turns a scoped bug prompt into a valid safe-bugfix loop", () => {
    const prompt = "Fix the failing date parser test and prove the fix.";
    const result = compilePrompt({
      prompt,
      workspaceRoot: "/repo",
      submittedAt: "2026-07-09T12:00:00.000Z",
      catalog: DEFAULT_LOOP_CATALOG,
      catalogVersionHash: hash,
    });

    expect(result.ok).toBe(true);
    expect(result.catalog_resolution.terminal_state).toBe("compiled");
    expect(result.catalog_resolution.selected_item_id).toBe("safe-bugfix");
    expect(result.compilation?.input_bindings).toEqual({ "bug-statement": prompt });
    expect(result.loop?.loop_family).toBe("minimal-bugfix");
    expect(result.loop?.risk_controls).toEqual({ max_tier_without_approval: "T2", t5_allowed: false });
    expect(validateLoopeix(result.loop).errors).toEqual([]);
    expect(validateLoopeix(parseYaml(result.yaml ?? "")).ok).toBe(true);
  });

  it("holds risky connector/payment prompts and does not produce YAML", () => {
    const result = compilePrompt({
      prompt: "Log into Stripe if needed and fix billing in production.",
      workspaceRoot: "/repo",
      submittedAt: "2026-07-09T12:00:00.000Z",
      catalog: DEFAULT_LOOP_CATALOG,
      catalogVersionHash: hash,
    });

    expect(result.ok).toBe(false);
    expect(result.catalog_resolution.terminal_state).toBe("hold-risk");
    expect(result.loop).toBeUndefined();
    expect(result.yaml).toBeUndefined();
    expect(result.clarification_questions.join("\n")).toContain("approval");
  });

  it("selects the research loop for multi-platform research prompts", () => {
    const result = compilePrompt({
      prompt: "Research HN Reddit X and competitor sources for loop-engineering user needs.",
      workspaceRoot: "/repo",
      submittedAt: "2026-07-09T12:00:00.000Z",
      catalog: DEFAULT_LOOP_CATALOG,
      catalogVersionHash: hash,
    });

    expect(result.ok).toBe(true);
    expect(result.catalog_resolution.selected_item_id).toBe("research-need-cluster");
    expect(result.loop?.evaluations.some((e) => e.type === "source-citation")).toBe(true);
    expect(validateLoopeix(result.loop).ok).toBe(true);
  });

  it("uses a deterministic catalog hash when the caller does not provide one", () => {
    const result = compilePrompt({
      prompt: "Fix the failing date parser test and prove the fix.",
      workspaceRoot: "/repo",
      submittedAt: "2026-07-09T12:00:00.000Z",
      catalog: DEFAULT_LOOP_CATALOG,
    });

    expect(result.catalog_resolution.catalog_version_hash).toBe(hashCanonical(DEFAULT_LOOP_CATALOG));
  });

  it("holds instead of inventing a loop when no catalog item fits", () => {
    const result = compilePrompt({
      prompt: "Polish this thing and make it nicer.",
      workspaceRoot: "/repo",
      submittedAt: "2026-07-09T12:00:00.000Z",
      catalog: DEFAULT_LOOP_CATALOG,
      catalogVersionHash: hash,
    });

    expect(result.ok).toBe(false);
    expect(result.catalog_resolution.terminal_state).toBe("hold-no-item");
    expect(result.catalog_resolution.selected_item_id).toBeNull();
    expect(result.loop).toBeUndefined();
  });
});
