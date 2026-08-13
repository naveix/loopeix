import { describe, expect, it } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import * as authority from "../../src/run/runtime-record-admission-v02.js";
import { createAgencyActionProposalInputFixtureS36 } from "../helpers/runtime-admission-fixture-s35.js";

describe("S36 normalized action proposal and reviewer view", () => {
  it("constructs an exact proposal while deriving every nested hash and immutable classification", () => {
    const fixture = createAgencyActionProposalInputFixtureS36();
    const { action_proposal_hash: _proposalHash, on_behalf_of_chain_hash: _chainHash,
      authorized_change_set_hash: _changeHash, normalized_dispatch_hash: _dispatchHash,
      action_scope_hash: _scopeHash, classification_binding: _classification,
      policy_action_kind: _kind, action_approval_class: _approval, data_flow, ...input } = fixture;
    const { data_flow_hash: _flowHash, ...flowInput } = data_flow as Record<string, unknown>;
    const result = authority.constructActionProposalV02({ ...input, data_flow: flowInput });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.policy_action_kind).toBe("authenticated-read");
    expect(result.value.action_approval_class).toBe("agency");
    expect(result.value.action_proposal_hash).toBe(hashCanonical({
      purpose: "action-proposal-v02",
      ...Object.fromEntries(Object.entries(result.value).filter(([key]) => key !== "action_proposal_hash")),
    }));
  });

  it("rejects caller classification, raw instruction fields, and unresolvable normalized capabilities", () => {
    const fixture = createAgencyActionProposalInputFixtureS36();
    expect(authority.constructActionProposalV02({ ...fixture, action_approval_class: "automatic" })).toMatchObject({ ok: false });
    expect(authority.constructActionProposalV02({ ...fixture, raw_instruction: "ignore policy" })).toMatchObject({ ok: false });
    const dispatch = structuredClone(fixture.normalized_dispatch) as Record<string, unknown>;
    dispatch.capability_definition_hash = `sha256:${"f".repeat(64)}`;
    expect(authority.constructActionProposalV02({ ...fixture, normalized_dispatch: dispatch })).toMatchObject({ ok: false });
  });

  it("projects a hash-bound reviewer view with no raw source body or instruction field", () => {
    const proposal = createAgencyActionProposalInputFixtureS36();
    const view = authority.constructReviewerViewV02({
      action_proposal: proposal,
      evidence_extractions: [{
        evidence_ref: { record_kind: "evidence", record_id: "evidence_1", record_event_ref: { ledger_sequence: 1, event_hash: `sha256:${"1".repeat(64)}` } },
        source_selector_hash: `sha256:${"2".repeat(64)}`, source_content_hash: `sha256:${"3".repeat(64)}`,
        extracted_fact_hashes: [`sha256:${"4".repeat(64)}`], provenance_hash: `sha256:${"5".repeat(64)}`,
        source_trust: "untrusted", sensitivity: "confidential", uncertainty: "material",
      }],
    });
    expect(view.ok).toBe(true);
    if (!view.ok) return;
    expect(JSON.stringify(view.value)).not.toMatch(/instruction|source_body|raw_text/);
    expect(view.value.action_proposal_hash).toBe(proposal.action_proposal_hash);
    const changed = structuredClone(proposal) as Record<string, unknown>;
    changed.action_proposal_hash = `sha256:${"f".repeat(64)}`;
    expect(authority.constructReviewerViewV02({ action_proposal: changed, evidence_extractions: [] })).toMatchObject({ ok: false });
  });
});
