import { describe, expect, it } from "vitest";
import { renderPlanReportV02 } from "../../src/report/plan-renderer.js";

const PLAN_HASH = `sha256:${"a".repeat(64)}`;

describe("S35 planned-report renderer", () => {
  it("renders frozen metadata, truthful status, and every escaped control exactly once", () => {
    const rendered = renderPlanReportV02({
      generation_id: "prg_81a007c076682e50347e44b0dc7575af",
      resolved_run_plan_hash: PLAN_HASH,
      run_id: "run_main",
      execution_profile: "bounded-v02",
      controls: [
        { category: "trigger", control_ref: "trigger-main", label: "When # ready", value: "<script>[untrusted](https://example.test)</script>" },
        { category: "limit", control_ref: "max-output-bytes", label: "Output bytes", value: "1024" },
      ],
    });

    expect(rendered.markdown.startsWith(`<!-- loopeix-plan-report-v0.1 generation=prg_81a007c076682e50347e44b0dc7575af source=${PLAN_HASH} -->\n`)).toBe(true);
    expect(rendered.markdown).toContain("State: planned");
    expect(rendered.markdown).toContain("Reason: UNSUPPORTED_EXECUTION_PROFILE");
    expect(rendered.markdown).toContain("Work execution: NOT EXECUTED");
    expect(rendered.markdown).toContain("Control enforcement: NOT ENFORCED");
    expect(rendered.markdown.match(/trigger-main/g)).toHaveLength(1);
    expect(rendered.markdown).not.toContain("[untrusted](https://example.test)");

    expect(rendered.html).toContain('<meta name="loopeix-plan-report-version" content="0.1">');
    expect(rendered.html).toContain('<meta name="loopeix-generation-id" content="prg_81a007c076682e50347e44b0dc7575af">');
    expect(rendered.html).toContain(`<meta name="loopeix-source-plan-hash" content="${PLAN_HASH}">`);
    expect(rendered.html.match(/trigger-main/g)).toHaveLength(1);
    expect(rendered.html).toContain("&lt;script&gt;[untrusted](https://example.test)&lt;/script&gt;");
    expect(rendered.html).not.toContain("<script");
  });

  it("rejects duplicate or non-canonical control rows", () => {
    expect(() => renderPlanReportV02({
      generation_id: "prg_81a007c076682e50347e44b0dc7575af",
      resolved_run_plan_hash: PLAN_HASH,
      run_id: "run_main",
      execution_profile: "bounded-v02",
      controls: [
        { category: "limit", control_ref: "z", label: "Z", value: "1" },
        { category: "limit", control_ref: "a", label: "A", value: "2" },
      ],
    })).toThrow("controls must be unique and sorted");
  });
});
