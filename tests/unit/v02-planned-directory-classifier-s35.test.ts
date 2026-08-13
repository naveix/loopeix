import { describe, expect, it } from "vitest";
import type { CapturedDirectEntry } from "../../src/run/planned-directory-classifier.js";

const CORE_NAMES = [
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
const REPORT_NAMES = ["plan-report-input.json", "plan-report.md", "plan-report.html"] as const;

function regular(names: readonly string[]): CapturedDirectEntry[] {
  return names.map((name) => ({ name, kind: "regular-file" }));
}

describe("S35 V02 planned-directory classifier", () => {
  it("recognizes only the exact core and complete report layouts independent of enumeration order", async () => {
    const { classifyV02PlannedDirectory } = await import(
      "../../src/run/planned-directory-classifier.js"
    );
    expect(classifyV02PlannedDirectory(regular([...CORE_NAMES].reverse()))).toEqual({
      ok: true,
      layout: "core-only",
    });
    expect(
      classifyV02PlannedDirectory(regular([...REPORT_NAMES, ...CORE_NAMES].reverse())),
    ).toEqual({ ok: true, layout: "core-with-report" });
  });

  it.each([
    ["missing core", regular(CORE_NAMES.slice(1))],
    ["partial report", regular([...CORE_NAMES, REPORT_NAMES[0]])],
    ["extra entry", regular([...CORE_NAMES, "notes.txt"])],
    ["duplicate", regular([...CORE_NAMES, CORE_NAMES[0]])],
    [
      "symlink",
      regular(CORE_NAMES).map((entry) =>
        entry.name === "generated.loop.yaml" ? { ...entry, kind: "symlink" as const } : entry,
      ),
    ],
    ["report lock", regular([...CORE_NAMES, "plan-report.lock"])],
  ])("rejects %s as contaminated", async (_label, entries) => {
    const { classifyV02PlannedDirectory } = await import(
      "../../src/run/planned-directory-classifier.js"
    );
    expect(classifyV02PlannedDirectory(entries)).toEqual({
      ok: false,
      reason: "V02_RUN_LAYOUT_CONTAMINATED",
      report_writer_maintenance: null,
    });
  });

  it("does not trust a caller-authored report lock lookalike", async () => {
    const { classifyV02PlannedDirectory } = await import(
      "../../src/run/planned-directory-classifier.js"
    );
    expect(
      classifyV02PlannedDirectory(
        regular([...CORE_NAMES, "plan-report.lock"]),
        {} as never,
      ),
    ).toMatchObject({ ok: false, report_writer_maintenance: null });
  });

  it("admits only the exact entry set bound by a privately registered strict report lock", async () => {
    const { classifyV02PlannedDirectory, registerValidatedPlanReportWriterLockV02 } = await import(
      "../../src/run/planned-directory-classifier.js"
    );
    const crashStage = regular([
      ...CORE_NAMES,
      "plan-report.lock",
      "plan-report.md.invocation-1.tmp",
    ]);
    const lock = registerValidatedPlanReportWriterLockV02(crashStage);
    expect(lock).not.toBeNull();
    if (lock === null) throw new Error("strict lock registration failed");

    expect(classifyV02PlannedDirectory(crashStage, lock)).toEqual({
      ok: false,
      reason: "V02_RUN_LAYOUT_CONTAMINATED",
      report_writer_maintenance: "lock-bound-next-step",
    });
    expect(
      classifyV02PlannedDirectory(
        regular([...CORE_NAMES, "plan-report.lock", "plan-report.html.invocation-1.tmp"]),
        lock,
      ),
    ).toMatchObject({ ok: false, report_writer_maintenance: null });
  });
});
