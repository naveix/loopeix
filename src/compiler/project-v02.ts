import type { z } from "zod";
import {
  CatalogEntryV02,
  IMMUTABLE_SAFETY_CONTEXT_V02,
  PlanInputV02,
  compareUtf8BytesV02,
  type CatalogEntryV02 as CatalogEntryV02Value,
  type PlanInputV02 as PlanInputV02Value,
} from "../catalog/item-v02.js";
import {
  REQUIRED_CONTROL_GATE_BLUEPRINTS_V02,
  REQUIRED_CONTROL_GATE_SET_ID_V02,
  bindRequiredControlGatesV02,
} from "../catalog/required-controls-v02.js";
import { hashCanonical } from "../hash.js";
import {
  LoopeixV02Shape,
  checkLoopeixV02Invariants,
  type LoopeixV02,
  type EvaluationSpecV02,
  type EvidenceRequirementSpecV02,
  type GateSpecV02,
} from "../schema/loopeix-v02.js";
import {
  BindingInputRecordV02,
  validateBindingsForCatalogEntryV02,
  type BindingInputRecordV02 as BindingInputRecordV02Value,
  type JsonValueV02,
} from "./binding-input-v02.js";

type EvaluationSpecV02Value = z.infer<typeof EvaluationSpecV02>;
type EvidenceRequirementSpecV02Value = z.infer<typeof EvidenceRequirementSpecV02>;
type GateSpecV02Value = z.infer<typeof GateSpecV02>;

export interface CatalogDestinationProjectionV02 {
  authoring: LoopeixV02;
  intake_record: { objective: string };
  approved_intake_brief: { objective: string };
  plan_input: PlanInputV02Value;
  resolved_plan_input: {
    adapter_plan: {
      engine: "codex_cli" | "claude_code_cli";
      command: string;
      permission_mode: "workspace-write" | "read-only" | "danger-full-access";
      known_gaps: string[];
    };
    workspace_boundary: { workspace_root: string; read: string[]; write: string[] };
  };
}

export type CatalogProjectionResultV02 =
  | { ok: true; value: CatalogDestinationProjectionV02 }
  | { ok: false; reason: "PROJECT_BINDING_REQUIRED"; required_binding_keys: string[] }
  | { ok: false; reason: "INVALID_CATALOG" | "INVALID_BINDING_INPUT"; message: string }
  | { ok: false; reason: "PLAN_BINDING_MISMATCH"; message: string };

function freezeDeep<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) freezeDeep(child);
  return Object.freeze(value);
}

function sameUtf8Set(actual: readonly string[], expected: readonly string[]): boolean {
  if (new Set(actual).size !== actual.length || actual.length !== expected.length) return false;
  const sorted = [...actual].sort(compareUtf8BytesV02);
  return sorted.every((value, index) => value === expected[index]);
}

function invalidCatalog(): CatalogProjectionResultV02 {
  return { ok: false, reason: "INVALID_CATALOG", message: "The selected V02 catalog entry is invalid." };
}

function invalidBinding(): CatalogProjectionResultV02 {
  return { ok: false, reason: "INVALID_BINDING_INPUT", message: "Binding input is invalid." };
}

function planBindingMismatch(): CatalogProjectionResultV02 {
  return { ok: false, reason: "PLAN_BINDING_MISMATCH", message: "Plan inputs do not match the compiled bindings." };
}

function resolveControlComposition(
  entry: CatalogEntryV02Value,
  evaluations: readonly EvaluationSpecV02Value[],
  evidenceRequirements: readonly EvidenceRequirementSpecV02Value[],
): readonly GateSpecV02Value[] | null {
  if (entry.blueprint.required_control_gate_set_id !== REQUIRED_CONTROL_GATE_SET_ID_V02) return null;
  const expectedEvaluationIds = entry.blueprint.evaluation_refs;
  const expectedEvidenceIds = entry.blueprint.evidence_requirement_refs;
  if (!sameUtf8Set(evaluations.map(({ id }) => id), expectedEvaluationIds)) return null;
  if (!sameUtf8Set(evidenceRequirements.map(({ id }) => id), expectedEvidenceIds)) return null;

  const roles = new Set(entry.blueprint.roles.map(({ id }) => id));
  const evidenceIds = new Set(evidenceRequirements.map(({ id }) => id));
  const evaluationById = new Map(evaluations.map((evaluation) => [evaluation.id, evaluation]));
  const requiredControlIds = new Set(REQUIRED_CONTROL_GATE_BLUEPRINTS_V02.map(({ id }) => id));
  if (entry.blueprint.gate_blueprints.some(({ id }) => requiredControlIds.has(id))) return null;
  for (const evaluation of evaluations) {
    if (!roles.has(evaluation.evaluator_binding.role_ref)) return null;
    if (evaluation.evaluator_binding.export_check_role !== null) return null;
    if (evaluation.evidence_requirement_refs.some((id) => !evidenceIds.has(id))) return null;
  }

  const controlEvaluation = evaluationById.get("control-review");
  if (controlEvaluation === undefined || controlEvaluation.applicability.mode !== "always") return null;
  if (!controlEvaluation.evidence_requirement_refs.includes("control-evidence")) return null;
  const controls = bindRequiredControlGatesV02(controlEvaluation.evaluator_binding);
  if (controls.length !== REQUIRED_CONTROL_GATE_BLUEPRINTS_V02.length) return null;

  const itemGates: GateSpecV02Value[] = [];
  for (const blueprint of entry.blueprint.gate_blueprints) {
    const evaluation = evaluationById.get(blueprint.evaluator_ref);
    if (evaluation === undefined) return null;
    if (hashCanonical(evaluation.applicability) !== hashCanonical(blueprint.applicability)) return null;
    if (blueprint.evidence_requirement_refs.some((id) => !evidenceIds.has(id))) return null;
    if (blueprint.evidence_requirement_refs.some((id) => !evaluation.evidence_requirement_refs.includes(id))) return null;
    const { evaluator_ref: _evaluatorRef, ...gate } = blueprint;
    itemGates.push({
      ...structuredClone(gate),
      evaluator_binding: structuredClone(evaluation.evaluator_binding),
    });
  }
  return [...controls, ...itemGates];
}

export const S35_ADAPTER_REGISTRY_V02 = Object.freeze({
  codex: Object.freeze({
    resolved_engine: "codex_cli" as const,
    command: "codex exec --json",
  }),
  claude: Object.freeze({
    resolved_engine: "claude_code_cli" as const,
    command: "claude -p --output-format stream-json --include-hook-events",
  }),
});

function pathFitsScope(path: string, scopes: readonly string[]): boolean {
  return scopes.some((scope) => scope === "." || path === scope || path.startsWith(`${scope}/`));
}

function projectResolvedPlanInput(
  entry: CatalogEntryV02Value,
  planInput: PlanInputV02Value,
  sideEffects: JsonValueV02,
): CatalogDestinationProjectionV02["resolved_plan_input"] | null {
  const adapter = S35_ADAPTER_REGISTRY_V02[planInput.adapter_plan.engine];
  if (planInput.adapter_plan.command !== adapter.command) return null;
  const effectClasses = Array.isArray(sideEffects)
    ? sideEffects.flatMap((container) =>
      typeof container === "object" && container !== null && !Array.isArray(container) && Array.isArray(container.effects)
        ? container.effects.map((effect) =>
          typeof effect === "object" && effect !== null && !Array.isArray(effect) ? effect.effect_class : null)
        : [])
    : [];
  if (planInput.adapter_plan.permission_mode === "read-only" && effectClasses.some((effect) => effect !== "none" && effect !== "external-read")) return null;
  if (planInput.adapter_plan.permission_mode === "workspace-write" && effectClasses.some((effect) => effect === "external-write" || effect === "destructive")) return null;
  if (planInput.adapter_plan.permission_mode === "danger-full-access" && entry.blueprint.risk_controls.max_tier_without_approval !== "T4") return null;
  const grantIds = new Set(entry.blueprint.tool_grants.map(({ id }) => id));
  if (planInput.adapter_plan.permission_mode === "workspace-write" && !grantIds.has("workspace-shell")) return null;
  if (effectClasses.includes("workspace-write") && !grantIds.has("workspace-shell")) return null;
  if (effectClasses.includes("external-read") && !grantIds.has("current-docs-web")) return null;
  if (entry.blueprint.artifacts.some(({ path }) => !pathFitsScope(path, planInput.workspace_boundary.write))) return null;

  return {
    adapter_plan: {
      engine: adapter.resolved_engine,
      command: planInput.adapter_plan.command,
      permission_mode: planInput.adapter_plan.permission_mode,
      known_gaps: structuredClone(planInput.adapter_plan.known_gaps),
    },
    workspace_boundary: {
      workspace_root: planInput.workspace_boundary.root,
      read: structuredClone(planInput.workspace_boundary.read),
      write: structuredClone(planInput.workspace_boundary.write),
    },
  };
}

export function projectCatalogEntryV02(input: {
  entry: unknown;
  binding_input: unknown;
}): CatalogProjectionResultV02 {
  const parsedEntry = CatalogEntryV02.safeParse(input.entry);
  if (!parsedEntry.success) return invalidCatalog();
  const parsedBindingInput = BindingInputRecordV02.safeParse(input.binding_input);
  if (!parsedBindingInput.success) return invalidBinding();

  const payload = {
    bindings: parsedBindingInput.data.bindings.map(({ approved_by: _approvedBy, ...binding }) => binding),
  };
  const validation = validateBindingsForCatalogEntryV02(payload, parsedEntry.data);
  if (!validation.ok) return invalidBinding();
  if (validation.required_binding_keys.length > 0) {
    return {
      ok: false,
      reason: "PROJECT_BINDING_REQUIRED",
      required_binding_keys: [...validation.required_binding_keys],
    };
  }

  const values = new Map<string, JsonValueV02>(
    parsedBindingInput.data.bindings.map((binding) => [binding.key, binding.value]),
  );
  const objective = values.get("project.objective");
  const evaluations = values.get("project.validation");
  const evidenceRequirements = values.get("project.evidence-requirements");
  const requiredContext = values.get("project.required-context");
  const projectForbidden = values.get("project.forbidden-context");
  if (
    typeof objective !== "string" ||
    !Array.isArray(evaluations) ||
    !Array.isArray(evidenceRequirements) ||
    !Array.isArray(requiredContext) ||
    !Array.isArray(projectForbidden)
  ) return invalidBinding();

  const gates = resolveControlComposition(
    parsedEntry.data,
    evaluations as EvaluationSpecV02Value[],
    evidenceRequirements as EvidenceRequirementSpecV02Value[],
  );
  if (gates === null) return invalidCatalog();
  const boundEvaluations = evaluations as EvaluationSpecV02Value[];
  const boundEvidenceRequirements = evidenceRequirements as EvidenceRequirementSpecV02Value[];

  const required = [...(requiredContext as string[])].sort(compareUtf8BytesV02);
  const forbidden = [...new Set<string>([
    ...IMMUTABLE_SAFETY_CONTEXT_V02,
    ...(projectForbidden as string[]),
  ])].sort(compareUtf8BytesV02);
  const requiredSet = new Set(required);
  if (forbidden.some((value) => requiredSet.has(value))) return invalidBinding();

  const planInput = PlanInputV02.safeParse({
    adapter_plan: values.get("project.engine"),
    workspace_boundary: values.get("project.workspace-root"),
  });
  if (!planInput.success) return invalidBinding();
  const resolvedPlanInput = projectResolvedPlanInput(
    parsedEntry.data,
    planInput.data,
    values.get("project.side-effects")!,
  );
  if (resolvedPlanInput === null) return planBindingMismatch();

  const authoringCandidate = {
    schema_version: "0.2" as const,
    loop_family: parsedEntry.data.loop_family,
    version: parsedEntry.data.version,
    trigger: structuredClone(parsedEntry.data.blueprint.trigger),
    goal: structuredClone(values.get("project.goal")),
    inputs: [],
    context_contract: {
      required: structuredClone(required),
      forbidden,
      untrusted_sources: structuredClone(parsedEntry.data.blueprint.context_contract.untrusted_sources),
    },
    workflow_pattern: structuredClone(parsedEntry.data.blueprint.workflow_pattern),
    roles: structuredClone(parsedEntry.data.blueprint.roles),
    tasks: structuredClone(parsedEntry.data.blueprint.tasks),
    tool_grants: structuredClone(parsedEntry.data.blueprint.tool_grants),
    artifacts: structuredClone(parsedEntry.data.blueprint.artifacts),
    gates,
    evaluations: structuredClone(boundEvaluations).sort((left, right) => compareUtf8BytesV02(left.id, right.id)),
    evidence_requirements: structuredClone(boundEvidenceRequirements).sort((left, right) => compareUtf8BytesV02(left.id, right.id)),
    risk_controls: structuredClone(parsedEntry.data.blueprint.risk_controls),
    progress: structuredClone(values.get("project.progress")),
    stop_policy: structuredClone(values.get("project.stop-policy")),
    limit_policy: structuredClone(values.get("project.hard-limits")),
    retry_policy: structuredClone(values.get("project.retry-policy")),
    recovery_policy: structuredClone(values.get("project.recovery-policy")),
    side_effects: structuredClone(values.get("project.side-effects")),
    compensations: structuredClone(values.get("project.compensations")),
    retro: structuredClone(parsedEntry.data.blueprint.retro),
  };
  const authoring = LoopeixV02Shape.safeParse(authoringCandidate);
  if (!authoring.success || checkLoopeixV02Invariants(authoring.data).length > 0) return invalidBinding();

  return {
    ok: true,
    value: freezeDeep({
      authoring: structuredClone(authoring.data),
      intake_record: { objective },
      approved_intake_brief: { objective },
      plan_input: structuredClone(planInput.data),
      resolved_plan_input: resolvedPlanInput,
    }),
  };
}
