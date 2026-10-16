import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import {
  S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
  resolveAgencyQuorumRequirementV02,
  simulateAuthorityDecisionV02,
} from "../../src/run/action-classifier-policy-v02.js";

const roots: string[] = [];
const hash = (digit: string) => `sha256:${digit.repeat(64)}`;
const roles = ["authority-governor", "evidence-reviewer", "scope-guardian", "security-information-flow-reviewer"] as const;

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function baseAgencyInput() {
  const proposal = {
    action_proposal_id: "proposal_1",
    action_proposal_hash: hash("1"),
    action_class: "tool" as const,
    policy_action_kind: "authenticated-read" as const,
    action_approval_class: "agency" as const,
    policy_digest: S35_BUILT_IN_ACTION_APPROVAL_POLICY_DIGEST_V02,
    action_scope_hash: hash("2"),
    normalized_dispatch_hash: hash("3"),
    repository_pre_state_hash: hash("4"),
    classifier_rule_hash: hash("5"),
    data_flow_hash: hash("6"),
    effective_risk_tier: "T2" as const,
  };
  const reviewed_through_ref = { ledger_sequence: 10, event_hash: hash("7") };
  const quorum = resolveAgencyQuorumRequirementV02({
    policy_digest: proposal.policy_digest,
    action_class: proposal.action_class,
    policy_action_kind: proposal.policy_action_kind,
    action_approval_class: proposal.action_approval_class,
  });
  if (quorum === null) throw new Error("agency quorum fixture must resolve");
  const recommendations = roles.map((role, index) => ({
    verified: true as const,
    event_ref: { ledger_sequence: 11 + index, event_hash: hash(String(index + 1)) },
    recommendation_id: `recommendation_${index}`,
    action_proposal_hash: proposal.action_proposal_hash,
    reviewer_view_hash: hash("8"),
    quorum_requirement_hash: quorum.quorum_requirement_hash,
    reviewed_through_ref,
    evaluator_role_ref: role,
    evaluator_stable_identity_hash: hash(String(index + 1)),
    decision: "allow" as const,
    conditions: [],
    evidence_refs: [{ ledger_sequence: 101 + index, event_hash: hash(String(index + 1)) }],
    evidence_independence_keys: [hash(String(index + 5))],
    issued_at: "2026-08-13T12:00:00Z",
    expires_at: "2026-08-13T12:05:00Z",
  }));
  return {
    proposal,
    reviewer_view_hash: hash("8"),
    reviewed_through_ref,
    recommendations,
    authority: { envelope_verified: true, contained: true, proof_fresh: true, revocation_epoch_current: true },
    enforcement: { available: true, information_flow_allowed: true, gates_passed: true, immediate_revalidation_passed: true },
    condition_results: [],
    issued_at: "2026-08-13T12:02:00Z",
    expires_at: "2026-08-13T12:03:00Z",
    fence_epoch: 0,
  };
}

describe("S36 integrated authority simulator corpus", () => {
  it("keeps the core automatic, agency, human-exception, and blocked branches deterministic", () => {
    const agency = baseAgencyInput();
    const automatic = {
      ...agency,
      proposal: {
        ...agency.proposal,
        action_proposal_id: "proposal_automatic",
        action_proposal_hash: hash("9"),
        action_class: "task" as const,
        policy_action_kind: "planning" as const,
        action_approval_class: "automatic" as const,
        effective_risk_tier: "T1" as const,
      },
      recommendations: [],
    };
    const humanException = {
      ...agency,
      proposal: {
        ...agency.proposal,
        action_proposal_id: "proposal_human",
        action_proposal_hash: hash("a"),
        policy_action_kind: "send" as const,
        action_approval_class: "human_exception" as const,
      },
      recommendations: [],
    };
    const blocked = {
      ...agency,
      proposal: {
        ...agency.proposal,
        action_proposal_id: "proposal_blocked",
        action_proposal_hash: hash("b"),
        policy_action_kind: "self-widening" as const,
        action_approval_class: "blocked" as const,
      },
      recommendations: [],
    };

    const corpus = [
      { name: "agency", input: agency, expected: { decision: "allow", decision_disposition: "lease-eligible", lease: true } },
      { name: "automatic", input: automatic, expected: { decision: "allow", decision_disposition: "lease-eligible", lease: true } },
      { name: "human_exception", input: humanException, expected: { decision: "hold", decision_disposition: "non-resumable", lease: false } },
      { name: "blocked", input: blocked, expected: { decision: "hold", decision_disposition: "non-resumable", lease: false } },
    ] as const;

    for (const row of corpus) {
      const first = simulateAuthorityDecisionV02(row.input);
      const second = simulateAuthorityDecisionV02(structuredClone(row.input));
      expect(first, row.name).toEqual(second);
      expect(first).toMatchObject({ ok: true, value: { decision: row.expected.decision, decision_disposition: row.expected.decision_disposition } });
      if (!first.ok) continue;
      expect(first.value.simulated_lease !== null).toBe(row.expected.lease);
      expect(hashCanonical(first.value)).toBe(hashCanonical(second.ok ? second.value : second));
    }
  });

  it("ships a passing static boundary proof over the committed S36 authority modules", () => {
    const result = spawnSync(process.execPath, ["scripts/check-s36-boundaries.mjs"], {
      cwd: process.cwd(),
      encoding: "utf8",
      shell: false,
      timeout: 15_000,
      maxBuffer: 2 * 1024 * 1024,
    });
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("");
  });

  it("rejects a forbidden import in an isolated trap file", () => {
    const root = mkdtempSync(join(tmpdir(), "loopeix-s36-boundary-"));
    roots.push(root);
    const trap = join(root, "trap.ts");
    writeFileSync(trap, "import { readFileSync } from \"node:fs\";\n");
    const result = spawnSync(process.execPath, ["scripts/check-s36-boundaries.mjs", trap], {
      cwd: process.cwd(),
      encoding: "utf8",
      shell: false,
      timeout: 15_000,
      maxBuffer: 2 * 1024 * 1024,
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("filesystem-write");
  });
});
