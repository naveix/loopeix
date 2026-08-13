import type { LoopCatalogEntry } from "../catalog/item.js";
import type { CatalogResolution, IntakeRecord } from "./records.js";

export interface ResolveCatalogOptions {
  catalog_version_hash: string;
  resolution_id?: string;
  ambiguity_delta?: number;
  minimum_score?: number;
}

const DEFAULT_AMBIGUITY_DELTA = 2;
const DEFAULT_MINIMUM_SCORE = 2;

function includesSignal(text: string, signal: string): boolean {
  const normalized = signal.toLowerCase();
  if (normalized.length <= 3) {
    return new RegExp(`\\b${normalized.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`).test(text);
  }
  return text.includes(normalized);
}

function riskForcesHold(intake: IntakeRecord): boolean {
  const haystack = [
    intake.objective,
    intake.requested_outcome,
    ...intake.risk_flags,
    ...intake.forbidden_actions,
    ...intake.ambiguities,
  ]
    .join(" ")
    .toLowerCase();
  return [
    "t5",
    "background",
    "schedule",
    "recurring",
    "unattended",
    "stripe",
    "payment",
    "dm",
    "post",
    "delete",
    "deploy",
    "production",
    "secret",
    "any means",
    "whatever tools",
    "don't ask",
    "dont ask",
  ].some((term) => includesSignal(haystack, term));
}

export function resolveCatalog(
  intake: IntakeRecord,
  catalog: readonly LoopCatalogEntry[],
  options: ResolveCatalogOptions,
): CatalogResolution {
  const ambiguityDelta = options.ambiguity_delta ?? DEFAULT_AMBIGUITY_DELTA;
  const minimumScore = options.minimum_score ?? DEFAULT_MINIMUM_SCORE;
  const resolutionId = options.resolution_id ?? "resolution_default";
  const prompt = [intake.objective, intake.requested_outcome, ...intake.candidate_scope].join(" ").toLowerCase();

  if (riskForcesHold(intake)) {
    return {
      schema_version: intake.schema_version,
      resolution_id: resolutionId,
      catalog_version_hash: options.catalog_version_hash,
      terminal_state: "hold-risk",
      ranked_candidates: [],
      selected_item_id: null,
      selection_evidence: ["risk flag requires approval before catalog selection"],
      rejected_candidates: [],
      needs_clarification: true,
    };
  }

  const ranked = catalog
    .map((entry) => {
      const positive = entry.positive_signals.filter((signal) => includesSignal(prompt, signal));
      const tags = entry.intent_tags.filter((tag) => includesSignal(prompt, tag));
      const negative = entry.negative_signals.filter((signal) => includesSignal(prompt, signal));
      const score = positive.length * 3 + tags.length * 2 - negative.length * 4;
      const reasons = [
        ...positive.map((s) => `positive:${s}`),
        ...tags.map((s) => `tag:${s}`),
        ...negative.map((s) => `negative:${s}`),
      ];
      return { item_id: entry.item_id, score, reasons: reasons.length > 0 ? reasons : ["no direct signal"] };
    })
    .sort((a, b) => b.score - a.score || a.item_id.localeCompare(b.item_id));

  const [first, second] = ranked;
  if (first === undefined || first.score < minimumScore) {
    return {
      schema_version: intake.schema_version,
      resolution_id: resolutionId,
      catalog_version_hash: options.catalog_version_hash,
      terminal_state: "hold-no-item",
      ranked_candidates: ranked,
      selected_item_id: null,
      selection_evidence: ["no catalog item met minimum score"],
      rejected_candidates: ranked,
      needs_clarification: true,
    };
  }

  if (second !== undefined && first.score - second.score < ambiguityDelta) {
    return {
      schema_version: intake.schema_version,
      resolution_id: resolutionId,
      catalog_version_hash: options.catalog_version_hash,
      terminal_state: "hold-ambiguous",
      ranked_candidates: ranked,
      selected_item_id: null,
      selection_evidence: [`top candidates '${first.item_id}' and '${second.item_id}' are too close`],
      rejected_candidates: ranked.slice(2),
      needs_clarification: true,
    };
  }

  return {
    schema_version: intake.schema_version,
    resolution_id: resolutionId,
    catalog_version_hash: options.catalog_version_hash,
    terminal_state: "compiled",
    ranked_candidates: ranked,
    selected_item_id: first.item_id,
    selection_evidence: first.reasons,
    rejected_candidates: ranked.slice(1),
    needs_clarification: false,
  };
}

export const resolveCatalogV01 = resolveCatalog;
