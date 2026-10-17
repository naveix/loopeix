import { z } from "zod";

import { canonicalize } from "../hash.js";
import { Hash } from "../schema/scalars.js";
import { MachineIdV02 as MachineId } from "../schema/scalars-v02.js";
import {
  hashCanonicalV03,
  parseS37LocalProductHostAnchorV03,
} from "./s37-product-host-contract-v03.js";
import {
  HumanAuthorizationProofV02,
  isCapturedAuthorityTrustContextV02,
  verifyHumanAuthorizationProofV02,
  type CapturedAuthorityTrustContextForS36V02,
} from "./runtime-record-admission-v02.js";

const safeGeneration = z.number().int().positive().refine(Number.isSafeInteger);
const S37_V03_ANCHOR_PATH = "/etc/loopeix/s37.1/product-host-v03/anchor.json";
const S37_V03_LIFECYCLE_PATH = "/etc/loopeix/s37.1/product-host-v03/lifecycle-state.json";

const S37OperatorAuthorityV03 = z.object({
  authorization_id: MachineId,
  authenticated_principal_ref: MachineId,
  operator_key_id: MachineId,
  authorization_transaction_id: MachineId,
  mutation_plan_hash: Hash,
  authorization_subject_hash: Hash,
  action_scope_hash: Hash,
  approval_nonce: Hash,
  authorization_statement_hash: Hash,
  proof_record_hash: Hash,
  revocation_epoch: z.number().int().nonnegative().refine(Number.isSafeInteger),
  expires_at: z.iso.datetime({ offset: false, local: false, precision: 0 }),
}).strict();

const S37AnchorMutationPlanV03 = z.object({
  purpose: z.literal("s37-anchor-mutation-plan-v03"),
  operation: z.enum(["install", "transition"]),
  authorization_transaction_id: MachineId,
  anchor_subject_hash: Hash,
  anchor_path: z.literal(S37_V03_ANCHOR_PATH),
  lifecycle_path: z.literal(S37_V03_LIFECYCLE_PATH),
  generation: safeGeneration,
  predecessor_anchor_hash: Hash.nullable(),
}).strict();

const S37ParsedAnchorBindingFieldsV03 = z.object({
  anchor_subject_hash: Hash,
  operator_authority: S37OperatorAuthorityV03,
  generation: safeGeneration,
  predecessor_anchor_hash: Hash.nullable(),
  anchor_hash: Hash,
}).loose();

const S37AnchorAuthorizationInputV03 = z.object({
  trust_context: z.custom<CapturedAuthorityTrustContextForS36V02>(isCapturedAuthorityTrustContextV02),
  authorization_proof: HumanAuthorizationProofV02,
  required_risk_tier: z.literal("T4"),
  mutation_plan: S37AnchorMutationPlanV03,
  proposed_anchor: z.unknown(),
}).strict();

export type S37AnchorMutationOperatorAuthorityV03 = Readonly<z.infer<typeof S37OperatorAuthorityV03>>;
export type S37AnchorMutationPlanV03 = Readonly<z.infer<typeof S37AnchorMutationPlanV03>>;

export type S37AuthorizedAnchorMutationBindingV03 = Readonly<{
  operation: "install" | "transition";
  authorization_transaction_id: string;
  mutation_plan_hash: string;
  anchor_subject_hash: string;
  action_scope_hash: string;
  generation: number;
  predecessor_anchor_hash: string | null;
  operator_authority: S37AnchorMutationOperatorAuthorityV03;
  mutation_plan: S37AnchorMutationPlanV03;
  proposed_anchor: Readonly<Record<string, unknown>>;
  proposed_anchor_hash: string;
}>;

class AuthorizedS37AnchorMutationTokenV03 {
  readonly #authorizedS37AnchorMutationV03 = true;

  private constructor() {
    void this.#authorizedS37AnchorMutationV03;
    Object.freeze(this);
  }

  static create(): AuthorizedS37AnchorMutationTokenV03 {
    return new AuthorizedS37AnchorMutationTokenV03();
  }
}

export type AuthorizedS37AnchorMutationV03 = AuthorizedS37AnchorMutationTokenV03;

export type AuthorizeS37AnchorMutationResultV03 =
  | Readonly<{ ok: true; value: AuthorizedS37AnchorMutationV03 }>
  | Readonly<{ ok: false; error: "ANCHOR_AUTHORIZATION_INVALID" }>;

const authorizedMutations = new WeakMap<object, S37AuthorizedAnchorMutationBindingV03>();

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function invalid(): Readonly<{ ok: false; error: "ANCHOR_AUTHORIZATION_INVALID" }> {
  return Object.freeze({ ok: false, error: "ANCHOR_AUTHORIZATION_INVALID" });
}

/**
 * Package-private S37.1-F2 bridge. Production callers must supply only an opaque
 * S36 trust capture and its already durable, authenticated proof. Raw clocks,
 * keys, nonce stores, and verifier callbacks are deliberately outside this API.
 */
export function authorizeS37AnchorMutationV03(input: unknown): AuthorizeS37AnchorMutationResultV03 {
  try {
    const parsed = S37AnchorAuthorizationInputV03.safeParse(input);
    if (!parsed.success) return invalid();
    const value = parsed.data;
    const proof = value.authorization_proof;
    const plan = value.mutation_plan;
    const planHash = hashCanonicalV03(plan);
    const parsedAnchor = parseS37LocalProductHostAnchorV03(value.proposed_anchor);
    if (!planHash.ok || !parsedAnchor.ok) return invalid();
    const anchorFields = S37ParsedAnchorBindingFieldsV03.safeParse(parsedAnchor.value);
    if (!anchorFields.success) return invalid();
    const anchor = anchorFields.data;
    if (!verifyHumanAuthorizationProofV02(value.trust_context, proof).ok
      || proof.approved_risk_tier !== value.required_risk_tier
      || proof.run_id !== plan.authorization_transaction_id
      || proof.plan_hash !== planHash.value
      || proof.authorization_subject_hash !== plan.anchor_subject_hash
      || anchor.anchor_subject_hash !== plan.anchor_subject_hash
      || anchor.generation !== plan.generation
      || anchor.predecessor_anchor_hash !== plan.predecessor_anchor_hash
      || (plan.operation === "install" && (plan.generation !== 1 || plan.predecessor_anchor_hash !== null))
      || (plan.operation === "transition" && (plan.generation < 2 || plan.predecessor_anchor_hash === null))) {
      return invalid();
    }
    const operatorAuthority: S37AnchorMutationOperatorAuthorityV03 = {
      authorization_id: proof.authorization_id,
      authenticated_principal_ref: proof.authenticated_principal_ref,
      operator_key_id: proof.operator_key_id,
      authorization_transaction_id: proof.run_id,
      mutation_plan_hash: proof.plan_hash,
      authorization_subject_hash: proof.authorization_subject_hash,
      action_scope_hash: proof.action_scope_hash,
      approval_nonce: proof.approval_nonce,
      authorization_statement_hash: proof.authorization_statement_hash,
      proof_record_hash: proof.record_hash,
      revocation_epoch: proof.revocation_epoch,
      expires_at: proof.expires_at,
    };
    if (canonicalize(operatorAuthority) !== canonicalize(anchor.operator_authority)) return invalid();
    const binding = deepFreeze({
      operation: plan.operation,
      authorization_transaction_id: plan.authorization_transaction_id,
      mutation_plan_hash: planHash.value,
      anchor_subject_hash: plan.anchor_subject_hash,
      action_scope_hash: proof.action_scope_hash,
      generation: plan.generation,
      predecessor_anchor_hash: plan.predecessor_anchor_hash,
      operator_authority: operatorAuthority,
      mutation_plan: plan,
      proposed_anchor: parsedAnchor.value,
      proposed_anchor_hash: anchor.anchor_hash,
    });
    const capability = AuthorizedS37AnchorMutationTokenV03.create();
    authorizedMutations.set(capability, binding);
    return Object.freeze({ ok: true, value: capability });
  } catch {
    return invalid();
  }
}

export function consumeAuthorizedS37AnchorMutationV03(
  capability: unknown,
): S37AuthorizedAnchorMutationBindingV03 | null {
  if ((typeof capability !== "object" && typeof capability !== "function") || capability === null) return null;
  const binding = authorizedMutations.get(capability);
  if (binding === undefined) return null;
  authorizedMutations.delete(capability);
  return binding;
}
