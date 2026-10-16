import { z } from "zod";
import { hashCanonical } from "../hash.js";
import { decodeStructuredDocumentV02 } from "../schema/decode-envelope.js";
import { Hash } from "../schema/scalars.js";
import {
  HumanIdV02,
  MachineIdV02,
  NonBlankStringV02,
} from "../schema/scalars-v02.js";

const strictObject = <T extends z.ZodRawShape>(shape: T): z.ZodObject<T> => z.object(shape).strict();
const UTF8 = new TextEncoder();

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

const GitObjectIdV02 = z.discriminatedUnion("algorithm", [
  strictObject({ algorithm: z.literal("sha1"), value: z.string().regex(/^[a-f0-9]{40}$/) }),
  strictObject({ algorithm: z.literal("sha256"), value: z.string().regex(/^[a-f0-9]{64}$/) }),
]);

const RepositoryBaseRefInputV02 = strictObject({
  kind: z.literal("git-ref"),
  canonical_ref_name: NonBlankStringV02.regex(/^refs\/(?:heads|remotes)\/.+/),
  object_id: GitObjectIdV02,
  identity_hash: Hash,
});

const HumanExceptionDestinationInputV02 = strictObject({
  operator_role_ref: HumanIdV02,
  operator_actor_ref: MachineIdV02,
  operator_stable_identity_hash: Hash,
});

const RoleAssignmentInputV02 = strictObject({
  role_ref: HumanIdV02,
  actor_ref: MachineIdV02,
  actor_kind: z.enum(["operator", "agent", "service"]),
  stable_identity_hash: Hash,
});

export const AuthorityPlanningInputV02 = strictObject({
  schema_version: z.literal("0.2"),
  authority_planning_input_id: MachineIdV02,
  compile_pack_manifest_hash: Hash,
  forbidden_outcomes: z.array(NonBlankStringV02).min(1),
  delegation_mode: z.enum(["none", "strict-subset-once"]),
  role_assignments: z.array(RoleAssignmentInputV02).min(1),
  human_exception_destination: HumanExceptionDestinationInputV02,
  repository: strictObject({
    repository_root_ref: MachineIdV02,
    object_format: z.enum(["sha1", "sha256"]),
    base_ref: RepositoryBaseRefInputV02,
    transition_mode: z.enum(["read-only", "linear-settled-writes"]),
  }),
  policy_digest: Hash,
  approval_hash: Hash,
}).superRefine((input, context) => {
  for (let index = 1; index < input.forbidden_outcomes.length; index += 1) {
    if (compareUtf8(input.forbidden_outcomes[index - 1]!, input.forbidden_outcomes[index]!) >= 0) {
      context.addIssue({
        code: "custom",
        path: ["forbidden_outcomes", index],
        message: "must be unique and sorted by UTF-8 bytes",
      });
    }
  }
  const actorByRef = new Map<string, { actor_kind: string; stable_identity_hash: string }>();
  const actorByStableIdentity = new Map<string, string>();
  const assignedRoles = new Set<string>();
  for (let index = 0; index < input.role_assignments.length; index += 1) {
    const assignment = input.role_assignments[index]!;
    if (index > 0) {
      const previous = input.role_assignments[index - 1]!;
      const order = compareUtf8(previous.role_ref, assignment.role_ref)
        || compareUtf8(previous.actor_ref, assignment.actor_ref);
      if (order >= 0) {
        context.addIssue({
          code: "custom",
          path: ["role_assignments", index],
          message: "must be unique and sorted by role then actor using UTF-8 bytes",
        });
      }
    }
    if (assignedRoles.has(assignment.role_ref)) {
      context.addIssue({
        code: "custom",
        path: ["role_assignments", index, "role_ref"],
        message: "must have exactly one actor assignment",
      });
    }
    assignedRoles.add(assignment.role_ref);
    const existing = actorByRef.get(assignment.actor_ref);
    if (existing !== undefined && (existing.actor_kind !== assignment.actor_kind
      || existing.stable_identity_hash !== assignment.stable_identity_hash)) {
      context.addIssue({
        code: "custom",
        path: ["role_assignments", index, "actor_ref"],
        message: "must map to one actor kind and stable identity",
      });
    }
    actorByRef.set(assignment.actor_ref, assignment);
    const alias = actorByStableIdentity.get(assignment.stable_identity_hash);
    if (alias !== undefined && alias !== assignment.actor_ref) {
      context.addIssue({
        code: "custom",
        path: ["role_assignments", index, "stable_identity_hash"],
        message: "must not alias another actor",
      });
    }
    actorByStableIdentity.set(assignment.stable_identity_hash, assignment.actor_ref);
  }
  const destination = input.human_exception_destination;
  const operatorAssignments = input.role_assignments.filter((assignment) =>
    assignment.role_ref === destination.operator_role_ref
    && assignment.actor_ref === destination.operator_actor_ref
    && assignment.actor_kind === "operator"
    && assignment.stable_identity_hash === destination.operator_stable_identity_hash);
  if (operatorAssignments.length !== 1) {
    context.addIssue({
      code: "custom",
      path: ["human_exception_destination"],
      message: "must resolve to exactly one matching operator role assignment",
    });
  }
  if (input.repository.base_ref.object_id.algorithm !== input.repository.object_format) {
    context.addIssue({
      code: "custom",
      path: ["repository", "base_ref", "object_id", "algorithm"],
      message: "must equal repository.object_format",
    });
  }
  const expectedBaseRefHash = hashCanonical({
    purpose: "repository-base-ref-v02",
    repository_root_ref: input.repository.repository_root_ref,
    object_format: input.repository.object_format,
    kind: input.repository.base_ref.kind,
    canonical_ref_name: input.repository.base_ref.canonical_ref_name,
    object_id: input.repository.base_ref.object_id,
  });
  if (input.repository.base_ref.identity_hash !== expectedBaseRefHash) {
    context.addIssue({
      code: "custom",
      path: ["repository", "base_ref", "identity_hash"],
      message: "must match the exact repository base-ref preimage",
    });
  }
});

export type AuthorityPlanningInputV02Value = z.infer<typeof AuthorityPlanningInputV02>;

export type ApprovedAuthorityPlanningInputV02 = Readonly<{
  approval_hash: string;
  readonly __approved_authority_planning_input_v02: unique symbol;
}>;

export type AdmitAuthorityPlanningInputV02Result =
  | { ok: true; approved: ApprovedAuthorityPlanningInputV02 }
  | {
      ok: false;
      reason: "INVALID_AUTHORITY_PLANNING_INPUT" | "AUTHORITY_PLANNING_APPROVAL_MISMATCH";
      message: string;
    };

const approvedRegistry = new WeakMap<ApprovedAuthorityPlanningInputV02, {
  input: AuthorityPlanningInputV02Value;
  repository_claimed: boolean;
}>();

function approvalHash(input: AuthorityPlanningInputV02Value): string {
  return hashCanonical({
    purpose: "authority-planning-input-v02",
    schema_version: input.schema_version,
    authority_planning_input_id: input.authority_planning_input_id,
    compile_pack_manifest_hash: input.compile_pack_manifest_hash,
    forbidden_outcomes: input.forbidden_outcomes,
    delegation_mode: input.delegation_mode,
    role_assignments: input.role_assignments,
    human_exception_destination: input.human_exception_destination,
    repository: input.repository,
    policy_digest: input.policy_digest,
  });
}

export function admitAuthorityPlanningInputV02(
  bytes: Uint8Array,
  acknowledgedApprovalHash: string,
): AdmitAuthorityPlanningInputV02Result {
  const decoded = decodeStructuredDocumentV02(bytes, "json");
  if (!decoded.ok) {
    return {
      ok: false,
      reason: "INVALID_AUTHORITY_PLANNING_INPUT",
      message: "Authority planning input is not one bounded strict JSON document.",
    };
  }
  const parsed = AuthorityPlanningInputV02.safeParse(decoded.value);
  if (!parsed.success) {
    return {
      ok: false,
      reason: "INVALID_AUTHORITY_PLANNING_INPUT",
      message: "Authority planning input does not satisfy the V02 contract.",
    };
  }
  const recomputed = approvalHash(parsed.data);
  if (parsed.data.approval_hash !== recomputed || acknowledgedApprovalHash !== recomputed) {
    return {
      ok: false,
      reason: "AUTHORITY_PLANNING_APPROVAL_MISMATCH",
      message: "Embedded, recomputed, and acknowledged authority approval hashes must match.",
    };
  }
  const approved = Object.freeze({ approval_hash: recomputed }) as ApprovedAuthorityPlanningInputV02;
  approvedRegistry.set(approved, { input: structuredClone(parsed.data), repository_claimed: false });
  return { ok: true, approved };
}

export function claimApprovedAuthorityRepositoryV02(
  approved: ApprovedAuthorityPlanningInputV02,
): AuthorityPlanningInputV02Value["repository"] | null {
  const state = approvedRegistry.get(approved);
  if (state === undefined || state.repository_claimed) return null;
  state.repository_claimed = true;
  return structuredClone(state.input.repository);
}

export function consumeApprovedAuthorityPlanningInputV02(
  approved: ApprovedAuthorityPlanningInputV02,
): AuthorityPlanningInputV02Value | null {
  const state = approvedRegistry.get(approved);
  if (state === undefined) return null;
  approvedRegistry.delete(approved);
  return structuredClone(state.input);
}
