import { z } from "zod";
import { GateSpecV02, RequiredGateKindV02 } from "../schema/loopeix-v02.js";
import type { GateBlueprintV02 } from "./item-v02.js";

type GateSpecV02Value = z.infer<typeof GateSpecV02>;

export const REQUIRED_CONTROL_KINDS_V02 = Object.freeze([
  ...RequiredGateKindV02.options,
] as const);

export const REQUIRED_CONTROL_GATE_SET_ID_V02 = "s35-required-controls-v01" as const;

function freezeDeep<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) freezeDeep(child);
  return Object.freeze(value);
}

function requiredControlBlueprint(kind: (typeof REQUIRED_CONTROL_KINDS_V02)[number]): GateBlueprintV02 {
  return {
    id: kind,
    blocking: true,
    inputs_required: ["validated plan projection"],
    evidence_rule: `The '${kind}' control is judged only from admitted control evidence.`,
    pass_condition: `The '${kind}' control is satisfied by admitted evidence.`,
    hold_condition: `Evidence for the '${kind}' control is incomplete or unavailable.`,
    fail_condition: `Admitted evidence contradicts the '${kind}' control.`,
    waiver_allowed: false,
    control_kind: kind,
    applicability: { mode: "always" },
    risk_tier: "T2",
    prerequisites: [{ kind: "run-initialized" }],
    evidence_requirement_refs: ["control-evidence"],
    evaluator_ref: "control-review",
  };
}

export const REQUIRED_CONTROL_GATE_BLUEPRINTS_V02: readonly GateBlueprintV02[] = freezeDeep(
  REQUIRED_CONTROL_KINDS_V02.map(requiredControlBlueprint),
);

export function bindRequiredControlGatesV02(
  evaluatorBinding: GateSpecV02Value["evaluator_binding"],
): readonly GateSpecV02Value[] {
  return REQUIRED_CONTROL_GATE_BLUEPRINTS_V02.map(({ evaluator_ref: _evaluatorRef, ...gate }) => ({
    ...structuredClone(gate),
    evaluator_binding: structuredClone(evaluatorBinding),
  }));
}
