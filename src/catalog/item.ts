import { z } from "zod";
import { HumanId, LoopVersion, RiskTierV1 } from "../schema/scalars.js";
import { WorkflowPatternType } from "../schema/loopeix.js";

export const LoopCatalogEntrySchema = z
  .object({
    item_id: HumanId,
    loop_family: HumanId,
    version: LoopVersion,
    title: z.string().min(1),
    summary: z.string().min(1),
    intent_tags: z.array(HumanId).min(1),
    positive_signals: z.array(z.string().min(1)),
    negative_signals: z.array(z.string().min(1)),
    required_inputs: z.array(HumanId),
    optional_inputs: z.array(HumanId),
    workflow_pattern: WorkflowPatternType,
    max_risk_tier_without_approval: RiskTierV1,
    allowed_tool_grants: z.array(HumanId),
    required_gates: z.array(HumanId).min(1),
    required_evaluations: z.array(HumanId),
    primary_artifacts: z.array(HumanId),
    can_prove: z.array(z.string().min(1)).min(1),
    cannot_prove: z.array(z.string().min(1)).min(1),
    avoid_when: z.array(z.string().min(1)),
  })
  .strict()
  .superRefine((entry, ctx) => {
    const checkUnique = (values: readonly string[], path: string): void => {
      const seen = new Set<string>();
      for (const value of values) {
        if (seen.has(value)) {
          ctx.addIssue({
            code: "custom",
            path: [path],
            message: `duplicate ${path} value: '${value}'`,
          });
        }
        seen.add(value);
      }
    };

    checkUnique(entry.intent_tags, "intent_tags");
    checkUnique(entry.required_inputs, "required_inputs");
    checkUnique(entry.optional_inputs, "optional_inputs");
    checkUnique(entry.allowed_tool_grants, "allowed_tool_grants");
    checkUnique(entry.required_gates, "required_gates");
    checkUnique(entry.required_evaluations, "required_evaluations");
    checkUnique(entry.primary_artifacts, "primary_artifacts");
    checkUnique(entry.can_prove, "can_prove");
    checkUnique(entry.cannot_prove, "cannot_prove");

    const required = new Set(entry.required_inputs);
    for (const optional of entry.optional_inputs) {
      if (required.has(optional)) {
        ctx.addIssue({
          code: "custom",
          path: ["optional_inputs"],
          message: `input '${optional}' cannot be both required and optional`,
        });
      }
    }
  });

export const LoopCatalogSchema = z.array(LoopCatalogEntrySchema).superRefine((entries, ctx) => {
  const seen = new Set<string>();
  for (const entry of entries) {
    if (seen.has(entry.item_id)) {
      ctx.addIssue({
        code: "custom",
        path: ["item_id"],
        message: `duplicate item_id: '${entry.item_id}'`,
      });
    }
    seen.add(entry.item_id);
  }
});

export const LoopCatalogEntrySchemaV01 = LoopCatalogEntrySchema;
export const LoopCatalogSchemaV01 = LoopCatalogSchema;

export type LoopCatalogEntry = z.infer<typeof LoopCatalogEntrySchema>;
export type LoopCatalog = z.infer<typeof LoopCatalogSchema>;
export type LoopCatalogEntryV01 = LoopCatalogEntry;
export type LoopCatalogV01 = LoopCatalog;

export function validateCatalogEntry(input: unknown): LoopCatalogEntry {
  return LoopCatalogEntrySchema.parse(input);
}
