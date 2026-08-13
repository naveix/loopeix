export type CapturedDirectEntry = {
  name: string;
  kind: "regular-file" | "directory" | "symlink" | "other";
};

export type CapturedPlanReportWriterLockV02 = {
  readonly __captured_plan_report_writer_lock_v02: unique symbol;
};

export type V02PlannedDirectoryClassification =
  | { ok: true; layout: "core-only" }
  | { ok: true; layout: "core-with-report" }
  | {
      ok: false;
      reason: "V02_RUN_LAYOUT_CONTAMINATED";
      report_writer_maintenance: "lock-bound-next-step" | null;
    };

const CORE_NAMES = Object.freeze([
  "work-item.json",
  "binding-input.json",
  "intake-record.json",
  "catalog-resolution.json",
  "compilation-record.json",
  "compile-pack-manifest.json",
  "generated.loop.yaml",
  "intake-brief.json",
  "resolved-run-plan.json",
]);

const REPORT_NAMES = Object.freeze([
  "plan-report-input.json",
  "plan-report.md",
  "plan-report.html",
]);
const REPORT_LOCK_NAME = "plan-report.lock";
const registeredLockStages = new WeakMap<CapturedPlanReportWriterLockV02, string>();

function entrySignature(entries: readonly CapturedDirectEntry[]): string | null {
  const rows: string[] = [];
  const seen = new Set<string>();
  for (const entry of entries) {
    if (entry.kind !== "regular-file" || seen.has(entry.name)) return null;
    seen.add(entry.name);
    rows.push(entry.name);
  }
  return rows.sort().join("\n");
}

/** Package-internal: report-build calls this only after strict lock/byte/stage validation. */
export function registerValidatedPlanReportWriterLockV02(
  entries: readonly CapturedDirectEntry[],
): CapturedPlanReportWriterLockV02 | null {
  const signature = entrySignature(entries);
  if (signature === null) return null;
  const names = new Set(entries.map((entry) => entry.name));
  if (!CORE_NAMES.every((name) => names.has(name)) || !names.has(REPORT_LOCK_NAME)) return null;
  const maintenanceNames = entries.filter((entry) => !CORE_NAMES.includes(entry.name));
  const tempNames = maintenanceNames.filter((entry) => entry.name.endsWith(".tmp"));
  if (
    tempNames.length > 3 ||
    maintenanceNames.some((entry) =>
      entry.name !== REPORT_LOCK_NAME &&
      !REPORT_NAMES.includes(entry.name) &&
      !(entry.name.startsWith("plan-report.") && entry.name.endsWith(".tmp")),
    )
  ) return null;
  const lock = Object.freeze({}) as CapturedPlanReportWriterLockV02;
  registeredLockStages.set(lock, signature);
  return lock;
}

function exactRegularSet(entries: readonly CapturedDirectEntry[], expected: readonly string[]): boolean {
  if (entries.length !== expected.length) return false;
  const seen = new Set<string>();
  for (const entry of entries) {
    if (entry.kind !== "regular-file" || seen.has(entry.name)) return false;
    seen.add(entry.name);
  }
  return expected.every((name) => seen.has(name));
}

export function classifyV02PlannedDirectory(
  entries: readonly CapturedDirectEntry[],
  report_build_lock?: CapturedPlanReportWriterLockV02,
): V02PlannedDirectoryClassification {
  if (exactRegularSet(entries, CORE_NAMES)) return { ok: true, layout: "core-only" };
  if (exactRegularSet(entries, [...CORE_NAMES, ...REPORT_NAMES])) {
    return { ok: true, layout: "core-with-report" };
  }
  const signature = entrySignature(entries);
  if (
    report_build_lock !== undefined && signature !== null &&
    registeredLockStages.get(report_build_lock) === signature
  ) {
    return {
      ok: false,
      reason: "V02_RUN_LAYOUT_CONTAMINATED",
      report_writer_maintenance: "lock-bound-next-step",
    };
  }
  return {
    ok: false,
    reason: "V02_RUN_LAYOUT_CONTAMINATED",
    report_writer_maintenance: null,
  };
}
