import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import ReportOpen from "../../src/commands/report/open.js";
import { hashRawBytes } from "../../src/hash.js";
import {
  derivePlanReportGenerationIdV02,
  type PlanReportInputV02,
} from "../../src/report/plan-input.js";
import {
  decidePlanReportOpenV02,
  validatePlanReportGenerationV02,
} from "../../src/report/plan-open.js";

const encoder = new TextEncoder();
const roots: string[] = [];
const coreNames = [
  "work-item.json",
  "binding-input.json",
  "intake-record.json",
  "catalog-resolution.json",
  "compilation-record.json",
  "compile-pack-manifest.json",
  "generated.loop.yaml",
  "intake-brief.json",
  "resolved-run-plan.json",
] as const;
const reportNames = ["plan-report-input.json", "plan-report.md", "plan-report.html"] as const;

const entries = (names: readonly string[]) => names.map((name) => ({ name, kind: "regular-file" as const }));

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function generation() {
  const resolvedPlan = encoder.encode('{"schema_version":"0.2","run_id":"run_report"}\n');
  const compileManifest = encoder.encode('{"schema_version":"0.2","kind":"compile-pack"}\n');
  const generatedLoop = encoder.encode('schema_version: "0.2"\nloop_family: report-loop\n');
  const lineage = {
    schema_version: "0.2" as const,
    report_projection_version: "0.1" as const,
    run_id: "run_report",
    resolved_run_plan_hash: hashRawBytes(resolvedPlan),
    compile_pack_manifest_hash: hashRawBytes(compileManifest),
    generated_loop_hash: hashRawBytes(generatedLoop),
    renderer_bundle_id: "renderer_report_bundle",
    renderer_bundle_hash: `sha256:${"d".repeat(64)}`,
  };
  const generationId = derivePlanReportGenerationIdV02(lineage);
  const markdown = encoder.encode(`<!-- loopeix-plan-report-v0.1 generation=${generationId} source=${lineage.resolved_run_plan_hash} -->\n# Report\n`);
  const html = encoder.encode(`<!doctype html>\n<html><head>\n<meta name="loopeix-plan-report-version" content="0.1">\n<meta name="loopeix-generation-id" content="${generationId}">\n<meta name="loopeix-source-plan-hash" content="${lineage.resolved_run_plan_hash}">\n</head><body>Report</body></html>\n`);
  const input: PlanReportInputV02 = {
    ...lineage,
    generation_id: generationId,
    markdown_hash: hashRawBytes(markdown),
    html_hash: hashRawBytes(html),
    state: "planned",
    reason: "UNSUPPORTED_EXECUTION_PROFILE",
  };
  return {
    plan_report_input: encoder.encode(`${JSON.stringify(input)}\n`),
    markdown,
    html,
    resolved_plan: resolvedPlan,
    compile_manifest: compileManifest,
    generated_loop: generatedLoop,
  };
}

describe("S35 report open", () => {
  it("validates one complete hash-bound V02 report generation", () => {
    const bytes = generation();
    const result = validatePlanReportGenerationV02(bytes);
    expect(result).toMatchObject({
      ok: true,
      input: { schema_version: "0.2", state: "planned", reason: "UNSUPPORTED_EXECUTION_PROFILE" },
    });
  });

  it("owns exact classifier-to-open outcomes without a command-local allowlist", () => {
    expect(decidePlanReportOpenV02(entries(coreNames), null)).toEqual({
      ok: false,
      reason: "PLAN_REPORT_NOT_BUILT",
      message: "The planned report has not been built.",
    });
    expect(decidePlanReportOpenV02(entries([...coreNames, reportNames[0]]), null)).toEqual({
      ok: false,
      reason: "V02_RUN_LAYOUT_CONTAMINATED",
      message: "The planned V02 run directory layout is contaminated.",
    });
    expect(decidePlanReportOpenV02(entries([...coreNames, ...reportNames]), generation()).ok).toBe(true);
  });

  it("enumerates direct entry kinds through the identity-bound read session", async () => {
    const root = mkdtempSync(join(tmpdir(), "loopeix-report-enumeration-s35-"));
    roots.push(root);
    writeFileSync(join(root, "regular.json"), "{}\n");
    mkdirSync(join(root, "directory"));
    symlinkSync(join(root, "regular.json"), join(root, "alias.json"));
    const { openAnchoredReadSession } = await import("../../src/io/output-capabilities.js");
    const opened = await openAnchoredReadSession(root);
    expect(opened.ok).toBe(true);
    if (!opened.ok) throw new Error(opened.message);
    const listed = await opened.session.listDirectEntries();
    expect(listed).toEqual({
      ok: true,
      entries: expect.arrayContaining([
        { name: "regular.json", kind: "regular-file" },
        { name: "directory", kind: "directory" },
        { name: "alias.json", kind: "symlink" },
      ]),
    });
    expect(await opened.session.close()).toEqual({ ok: true });
    expect(await opened.session.listDirectEntries()).toMatchObject({ ok: false, reason: "INVALID_INPUT_ROOT" });
  });

  it("rejects every source/report hash mismatch and mixed generation marker", () => {
    const keys = ["resolved_plan", "compile_manifest", "generated_loop", "markdown", "html"] as const;
    for (const key of keys) {
      const bytes = generation();
      bytes[key] = new Uint8Array([...bytes[key], 0x20]);
      expect(validatePlanReportGenerationV02(bytes), key).toEqual({
        ok: false,
        reason: "PLAN_REPORT_GENERATION_INVALID",
        message: "Planned report generation is incomplete or invalid.",
      });
    }

    const mixed = generation();
    mixed.markdown = encoder.encode(new TextDecoder().decode(mixed.markdown).replace("generation=prg_", "generation=prg_dead"));
    expect(validatePlanReportGenerationV02(mixed).ok).toBe(false);
  });

  it("rejects malformed commit markers and duplicate or missing HTML metadata", () => {
    const malformed = generation();
    malformed.plan_report_input = encoder.encode('{"schema_version":"0.2","schema_version":"0.2"}\n');
    expect(validatePlanReportGenerationV02(malformed).ok).toBe(false);

    const duplicate = generation();
    const html = new TextDecoder().decode(duplicate.html);
    duplicate.html = encoder.encode(html.replace("</head>", '<meta name="loopeix-generation-id" content="prg_duplicate">\n</head>'));
    expect(validatePlanReportGenerationV02(duplicate).ok).toBe(false);

    const missing = generation();
    missing.html = encoder.encode(html.replace(/^.*loopeix-source-plan-hash.*\n/mu, ""));
    expect(validatePlanReportGenerationV02(missing).ok).toBe(false);
  });

  it("preserves frozen V01 two-line output and rejects a symlinked report", async () => {
    const root = mkdtempSync(join(tmpdir(), "loopeix-report-open-s35-"));
    roots.push(root);
    writeFileSync(join(root, "report.html"), "<!doctype html>\n");
    const lines: string[] = [];
    const log = vi.spyOn(ReportOpen.prototype, "log").mockImplementation((message?: unknown) => lines.push(String(message ?? "")));
    const priorExitCode = process.exitCode;
    try {
      process.exitCode = 0;
      await ReportOpen.run([root], join(import.meta.dirname, "..", ".."));
      expect(process.exitCode).toBe(0);
      expect(lines).toEqual([
        `Report: ${join(root, "report.html")}`,
        `Open in a browser: file://${resolve(root, "report.html")}`,
      ]);

      lines.length = 0;
      rmSync(join(root, "report.html"));
      writeFileSync(join(root, "target.html"), "<!doctype html>\n");
      symlinkSync(join(root, "target.html"), join(root, "report.html"));
      process.exitCode = 0;
      await ReportOpen.run([root], join(import.meta.dirname, "..", ".."));
      expect(process.exitCode).not.toBe(0);
      expect(lines.join("\n")).not.toContain("Open in a browser");
    } finally {
      log.mockRestore();
      process.exitCode = priorExitCode;
    }
  });
});
