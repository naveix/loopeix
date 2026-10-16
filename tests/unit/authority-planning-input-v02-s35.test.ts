import { describe, expect, it } from "vitest";
import { hashCanonical } from "../../src/hash.js";
import {
  admitAuthorityPlanningInputV02,
  claimApprovedAuthorityRepositoryV02,
  consumeApprovedAuthorityPlanningInputV02,
} from "../../src/run/authority-planning-input-v02.js";

const HASH = `sha256:${"a".repeat(64)}`;

function validInput(): Record<string, unknown> {
  const repository = {
    repository_root_ref: "repository_root_01",
    object_format: "sha1" as const,
    base_ref: {
      kind: "git-ref" as const,
      canonical_ref_name: "refs/heads/main",
      object_id: { algorithm: "sha1" as const, value: "b".repeat(40) },
      identity_hash: "",
    },
    transition_mode: "linear-settled-writes" as const,
  };
  repository.base_ref.identity_hash = hashCanonical({
    purpose: "repository-base-ref-v02",
    repository_root_ref: repository.repository_root_ref,
    object_format: repository.object_format,
    kind: repository.base_ref.kind,
    canonical_ref_name: repository.base_ref.canonical_ref_name,
    object_id: repository.base_ref.object_id,
  });
  const input = {
    schema_version: "0.2" as const,
    authority_planning_input_id: "authority_input_01",
    compile_pack_manifest_hash: HASH,
    forbidden_outcomes: ["data loss", "secret disclosure"],
    delegation_mode: "strict-subset-once" as const,
    role_assignments: [{
      role_ref: "operator",
      actor_ref: "operator_actor_01",
      actor_kind: "operator" as const,
      stable_identity_hash: `sha256:${"c".repeat(64)}`,
    }],
    human_exception_destination: {
      operator_role_ref: "operator",
      operator_actor_ref: "operator_actor_01",
      operator_stable_identity_hash: `sha256:${"c".repeat(64)}`,
    },
    repository,
    policy_digest: `sha256:${"d".repeat(64)}`,
    approval_hash: "",
  };
  input.approval_hash = hashCanonical({
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
  return input;
}

function encode(value: unknown): Uint8Array {
  return Buffer.from(JSON.stringify(value), "utf8");
}

describe("S35 AuthorityPlanningInputV02 admission", () => {
  it("admits exact strict input and allows one private consumption", () => {
    const input = validInput();
    const result = admitAuthorityPlanningInputV02(encode(input), input.approval_hash as string);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(claimApprovedAuthorityRepositoryV02(result.approved)).toEqual(input.repository);
    expect(claimApprovedAuthorityRepositoryV02(result.approved)).toBeNull();
    expect(consumeApprovedAuthorityPlanningInputV02(result.approved)).toEqual(input);
    expect(consumeApprovedAuthorityPlanningInputV02(result.approved)).toBeNull();
  });

  it.each([
    ["unknown field", (input: Record<string, unknown>) => Object.assign(input, { extra: true })],
    ["unsorted outcomes", (input: Record<string, unknown>) => Object.assign(input, { forbidden_outcomes: ["z", "a"] })],
    ["duplicate outcomes", (input: Record<string, unknown>) => Object.assign(input, { forbidden_outcomes: ["same", "same"] })],
    ["unsorted role assignments", (input: Record<string, unknown>) => Object.assign(input, { role_assignments: [
      { role_ref: "z-role", actor_ref: "actor_z", actor_kind: "agent", stable_identity_hash: `sha256:${"1".repeat(64)}` },
      { role_ref: "a-role", actor_ref: "actor_a", actor_kind: "agent", stable_identity_hash: `sha256:${"2".repeat(64)}` },
    ] })],
    ["stable identity alias", (input: Record<string, unknown>) => Object.assign(input, { role_assignments: [
      { role_ref: "a-role", actor_ref: "actor_a", actor_kind: "agent", stable_identity_hash: `sha256:${"1".repeat(64)}` },
      { role_ref: "z-role", actor_ref: "actor_z", actor_kind: "agent", stable_identity_hash: `sha256:${"1".repeat(64)}` },
    ] })],
    ["duplicate role assignment", (input: Record<string, unknown>) => Object.assign(input, { role_assignments: [
      { role_ref: "operator", actor_ref: "actor_a", actor_kind: "operator", stable_identity_hash: `sha256:${"1".repeat(64)}` },
      { role_ref: "operator", actor_ref: "actor_z", actor_kind: "agent", stable_identity_hash: `sha256:${"2".repeat(64)}` },
    ] })],
    ["non-operator exception destination", (input: Record<string, unknown>) => {
      const assignments = input.role_assignments as Array<{ actor_kind: string }>;
      assignments[0]!.actor_kind = "agent";
    }],
    ["mismatched exception destination", (input: Record<string, unknown>) => {
      const destination = input.human_exception_destination as { operator_actor_ref: string };
      destination.operator_actor_ref = "different_actor_01";
    }],
    ["object format mismatch", (input: Record<string, unknown>) => {
      const repository = input.repository as { object_format: string };
      repository.object_format = "sha256";
    }],
    ["stale base-ref hash", (input: Record<string, unknown>) => {
      const repository = input.repository as { base_ref: { identity_hash: string } };
      repository.base_ref.identity_hash = HASH;
    }],
  ])("rejects %s as invalid before approval", (_name, mutate) => {
    const input = validInput();
    mutate(input);
    expect(admitAuthorityPlanningInputV02(encode(input), input.approval_hash as string)).toMatchObject({
      ok: false,
      reason: "INVALID_AUTHORITY_PLANNING_INPUT",
    });
  });

  it("distinguishes an approval mismatch from structural invalidity", () => {
    const input = validInput();
    expect(admitAuthorityPlanningInputV02(encode(input), HASH)).toMatchObject({
      ok: false,
      reason: "AUTHORITY_PLANNING_APPROVAL_MISMATCH",
    });
    input.approval_hash = HASH;
    expect(admitAuthorityPlanningInputV02(encode(input), HASH)).toMatchObject({
      ok: false,
      reason: "AUTHORITY_PLANNING_APPROVAL_MISMATCH",
    });
  });

  it("rejects malformed, duplicate-key, and forged handles", () => {
    expect(admitAuthorityPlanningInputV02(Buffer.from("{", "utf8"), HASH)).toMatchObject({
      ok: false,
      reason: "INVALID_AUTHORITY_PLANNING_INPUT",
    });
    expect(admitAuthorityPlanningInputV02(Buffer.from('{"schema_version":"0.2","schema_version":"0.2"}'), HASH)).toMatchObject({
      ok: false,
      reason: "INVALID_AUTHORITY_PLANNING_INPUT",
    });
    expect(consumeApprovedAuthorityPlanningInputV02({ approval_hash: HASH } as never)).toBeNull();
  });
});
