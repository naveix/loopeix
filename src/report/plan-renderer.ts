import {
  encodePlanReportMarkdownLiteralV02,
  escapePlanReportHtmlTextV02,
} from "./plan-escaping.js";

export const PlanReportControlCategoriesV02 = [
  "trigger",
  "goal",
  "context",
  "progress",
  "stop",
  "limit",
  "retry",
  "recovery",
  "side-effect",
  "compensation",
  "gate",
  "evaluation",
  "terminal",
  "engine",
  "proof-boundary",
] as const;

export type PlanReportControlCategoryV02 = (typeof PlanReportControlCategoriesV02)[number];

export type PlanReportControlRowV02 = {
  readonly category: PlanReportControlCategoryV02;
  readonly control_ref: string;
  readonly label: string;
  readonly value: string;
};

export type PlanReportRenderInputV02 = {
  readonly generation_id: string;
  readonly resolved_run_plan_hash: string;
  readonly run_id: string;
  readonly execution_profile: "bounded-v02";
  readonly controls: readonly PlanReportControlRowV02[];
};

export type RenderedPlanReportV02 = {
  readonly markdown: string;
  readonly html: string;
};

const UTF8 = new TextEncoder();
const CATEGORY_INDEX = new Map(PlanReportControlCategoriesV02.map((category, index) => [category, index]));

function compareUtf8(left: string, right: string): number {
  const leftBytes = UTF8.encode(left);
  const rightBytes = UTF8.encode(right);
  const length = Math.min(leftBytes.length, rightBytes.length);
  for (let index = 0; index < length; index += 1) {
    const difference = leftBytes[index]! - rightBytes[index]!;
    if (difference !== 0) return difference;
  }
  return leftBytes.length - rightBytes.length;
}

function validateRenderInput(input: PlanReportRenderInputV02): void {
  if (!/^prg_[a-f0-9]{32}$/.test(input.generation_id)) {
    throw new Error("generation_id is invalid");
  }
  if (!/^sha256:[a-f0-9]{64}$/.test(input.resolved_run_plan_hash)) {
    throw new Error("resolved_run_plan_hash is invalid");
  }
  if (!/^[a-z]+_[a-z0-9]+(?:_[a-z0-9]+)*$/.test(input.run_id)) {
    throw new Error("run_id is invalid");
  }
  for (let index = 0; index < input.controls.length; index += 1) {
    const row = input.controls[index]!;
    const categoryIndex = CATEGORY_INDEX.get(row.category);
    if (categoryIndex === undefined || row.control_ref.length === 0 || row.label.length === 0) {
      throw new Error("control row is invalid");
    }
    if (index === 0) continue;
    const previous = input.controls[index - 1]!;
    const previousCategoryIndex = CATEGORY_INDEX.get(previous.category)!;
    if (previousCategoryIndex > categoryIndex
      || (previousCategoryIndex === categoryIndex && compareUtf8(previous.control_ref, row.control_ref) >= 0)) {
      throw new Error("controls must be unique and sorted");
    }
  }
}

function renderMarkdown(input: PlanReportRenderInputV02): string {
  const lines = [
    `<!-- loopeix-plan-report-v0.1 generation=${input.generation_id} source=${input.resolved_run_plan_hash} -->`,
    "# Loopeix Planned Run Report",
    "",
    `- Run: ${encodePlanReportMarkdownLiteralV02(input.run_id)}`,
    "- Execution profile: bounded-v02",
    "- State: planned",
    "- Reason: UNSUPPORTED_EXECUTION_PROFILE",
    "- Work execution: NOT EXECUTED",
    "- Control enforcement: NOT ENFORCED",
    "",
    "## Planned controls",
    "",
    "| Category | Control | Label | Planned value |",
    "|---|---|---|---|",
  ];
  for (const row of input.controls) {
    lines.push(`| ${encodePlanReportMarkdownLiteralV02(row.category)} | ${encodePlanReportMarkdownLiteralV02(row.control_ref)} | ${encodePlanReportMarkdownLiteralV02(row.label)} | ${encodePlanReportMarkdownLiteralV02(row.value)} |`);
  }
  lines.push("", "No work was executed. No limit, retry, recovery, side-effect, compensation, gate, evaluation, or delegated-approval control was enforced.", "");
  return lines.join("\n");
}

function renderHtml(input: PlanReportRenderInputV02): string {
  const rows = input.controls.map((row) => `      <tr><td>${escapePlanReportHtmlTextV02(row.category)}</td><td>${escapePlanReportHtmlTextV02(row.control_ref)}</td><td>${escapePlanReportHtmlTextV02(row.label)}</td><td>${escapePlanReportHtmlTextV02(row.value)}</td></tr>`).join("\n");
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="loopeix-plan-report-version" content="0.1">
  <meta name="loopeix-generation-id" content="${escapePlanReportHtmlTextV02(input.generation_id)}">
  <meta name="loopeix-source-plan-hash" content="${escapePlanReportHtmlTextV02(input.resolved_run_plan_hash)}">
  <title>Loopeix Planned Run Report</title>
</head>
<body>
  <h1>Loopeix Planned Run Report</h1>
  <dl>
    <dt>Run</dt><dd>${escapePlanReportHtmlTextV02(input.run_id)}</dd>
    <dt>Execution profile</dt><dd>bounded-v02</dd>
    <dt>State</dt><dd>planned</dd>
    <dt>Reason</dt><dd>UNSUPPORTED_EXECUTION_PROFILE</dd>
    <dt>Work execution</dt><dd>NOT EXECUTED</dd>
    <dt>Control enforcement</dt><dd>NOT ENFORCED</dd>
  </dl>
  <h2>Planned controls</h2>
  <table>
    <thead><tr><th>Category</th><th>Control</th><th>Label</th><th>Planned value</th></tr></thead>
    <tbody>
${rows}
    </tbody>
  </table>
  <p>No work was executed. No limit, retry, recovery, side-effect, compensation, gate, evaluation, or delegated-approval control was enforced.</p>
</body>
</html>
`;
}

export function renderPlanReportV02(input: PlanReportRenderInputV02): RenderedPlanReportV02 {
  validateRenderInput(input);
  return { markdown: renderMarkdown(input), html: renderHtml(input) };
}
