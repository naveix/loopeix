import { describe, expect, it } from "vitest";
import {
  derivePlanReportGenerationIdV02,
  parsePlanReportInputV02,
} from "../../src/report/plan-input.js";
import {
  encodePlanReportMarkdownLiteralV02,
  escapePlanReportHtmlTextV02,
} from "../../src/report/plan-escaping.js";

const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;
const HASH_C = `sha256:${"c".repeat(64)}`;
const HASH_E = `sha256:${"e".repeat(64)}`;

const lineage = {
  schema_version: "0.2" as const,
  report_projection_version: "0.1" as const,
  run_id: "run_main",
  resolved_run_plan_hash: HASH_A,
  compile_pack_manifest_hash: HASH_B,
  generated_loop_hash: HASH_C,
  renderer_bundle_id: `renderer_${"d".repeat(32)}`,
  renderer_bundle_hash: HASH_E,
};

describe("S35 planned-report core", () => {
  it("derives the frozen generation ID from only canonical lineage", () => {
    expect(derivePlanReportGenerationIdV02(lineage)).toBe("prg_81a007c076682e50347e44b0dc7575af");
    expect(derivePlanReportGenerationIdV02({ ...lineage })).toBe("prg_81a007c076682e50347e44b0dc7575af");
  });

  it("parses the exact strict metadata-only commit marker", () => {
    const input = {
      ...lineage,
      generation_id: "prg_81a007c076682e50347e44b0dc7575af",
      markdown_hash: HASH_A,
      html_hash: HASH_B,
      state: "planned",
      reason: "UNSUPPORTED_EXECUTION_PROFILE",
    };

    expect(parsePlanReportInputV02(input)).toEqual({ ok: true, input });
    expect(parsePlanReportInputV02({ ...input, extra: true })).toEqual({
      ok: false,
      reason: "INVALID_PLAN_REPORT_INPUT",
      message: "The plan-report commit marker is invalid.",
    });
    expect(parsePlanReportInputV02({ ...input, generation_id: "prg_wrong" }).ok).toBe(false);
    expect(parsePlanReportInputV02({ ...input, state: "completed" }).ok).toBe(false);
  });

  it("encodes every Markdown metacharacter as lowercase UTF-16 escapes", () => {
    expect(encodePlanReportMarkdownLiteralV02("Safe AZaz09 .,:;/_-"))
      .toBe("Safe AZaz09 .,:;/_-");
    expect(encodePlanReportMarkdownLiteralV02("# [x](y) `z` | <tag> & \\ \n😀"))
      .toBe("\\u0023 \\u005bx\\u005d\\u0028y\\u0029 \\u0060z\\u0060 \\u007c \\u003ctag\\u003e \\u0026 \\u005c \\u000a\\ud83d\\ude00");
  });

  it("escapes HTML text nodes without creating markup or attributes", () => {
    expect(escapePlanReportHtmlTextV02(`<&>"'`)).toBe("&lt;&amp;&gt;&quot;&#39;");
    expect(escapePlanReportHtmlTextV02("plain / text")).toBe("plain / text");
  });
});
