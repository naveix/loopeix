import { z } from "zod";
import { hashCanonical } from "../hash.js";
import { Hash, MachineId } from "../schema/scalars.js";

const PlanReportLineageV02 = z.object({
  schema_version: z.literal("0.2"),
  report_projection_version: z.literal("0.1"),
  run_id: MachineId,
  resolved_run_plan_hash: Hash,
  compile_pack_manifest_hash: Hash,
  generated_loop_hash: Hash,
  renderer_bundle_id: MachineId,
  renderer_bundle_hash: Hash,
}).strict();

export type PlanReportLineageV02 = z.infer<typeof PlanReportLineageV02>;

const PlanReportInputV02 = PlanReportLineageV02.extend({
  generation_id: MachineId,
  markdown_hash: Hash,
  html_hash: Hash,
  state: z.literal("planned"),
  reason: z.literal("UNSUPPORTED_EXECUTION_PROFILE"),
}).strict();

export type PlanReportInputV02 = z.infer<typeof PlanReportInputV02>;

export type ParsePlanReportInputV02Result =
  | { ok: true; input: PlanReportInputV02 }
  | { ok: false; reason: "INVALID_PLAN_REPORT_INPUT"; message: "The plan-report commit marker is invalid." };

const INVALID_PLAN_REPORT_INPUT = {
  ok: false,
  reason: "INVALID_PLAN_REPORT_INPUT",
  message: "The plan-report commit marker is invalid.",
} as const;

export function derivePlanReportGenerationIdV02(input: PlanReportLineageV02): string {
  const lineage = PlanReportLineageV02.parse(input);
  const digest = hashCanonical({ purpose: "plan-report-v02", ...lineage });
  return `prg_${digest.slice("sha256:".length, "sha256:".length + 32)}`;
}

function projectPlanReportLineageV02(input: PlanReportInputV02): PlanReportLineageV02 {
  return {
    schema_version: input.schema_version,
    report_projection_version: input.report_projection_version,
    run_id: input.run_id,
    resolved_run_plan_hash: input.resolved_run_plan_hash,
    compile_pack_manifest_hash: input.compile_pack_manifest_hash,
    generated_loop_hash: input.generated_loop_hash,
    renderer_bundle_id: input.renderer_bundle_id,
    renderer_bundle_hash: input.renderer_bundle_hash,
  };
}

export function parsePlanReportInputV02(input: unknown): ParsePlanReportInputV02Result {
  const parsed = PlanReportInputV02.safeParse(input);
  if (!parsed.success) return INVALID_PLAN_REPORT_INPUT;
  try {
    if (parsed.data.generation_id !== derivePlanReportGenerationIdV02(projectPlanReportLineageV02(parsed.data))) {
      return INVALID_PLAN_REPORT_INPUT;
    }
  } catch {
    return INVALID_PLAN_REPORT_INPUT;
  }
  return { ok: true, input: parsed.data };
}
