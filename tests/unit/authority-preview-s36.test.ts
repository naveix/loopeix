import { describe, expect, it } from "vitest";
import { expandDelegationProfileV02, projectAuthorityInteractionViewV02 } from "../../src/run/present-planned-v02.js";

const H1 = `sha256:${"1".repeat(64)}`;
const H2 = `sha256:${"2".repeat(64)}`;
const subject = {
  preview_kind: "exception", action_proposal_hash: H1, action_scope_hash: H2,
  scope_delta: { operations_added: [], selectors_added: [], risk_change: null },
  reversible: true, evidence_needed: ["authenticated-source"], safe_default: "hold",
  smallest_safe_alternative: { operation: "read", target_ref: "task-main" },
  requested_decision: "answer", reason_ref: "decision-agency-quorum-hold",
  resume_boundary: "new-reviewed-prefix", policy_digest: H1,
} as const;

describe("S36 typed authority previews", () => {
  it("expands only the three conservative transient delegation profiles", () => {
    expect(expandDelegationProfileV02("manual_every_action")).toMatchObject({ ok: true, value: { delegated_action_classes: [], operations: [] } });
    expect(expandDelegationProfileV02("read_only_research")).toMatchObject({ ok: true, value: { operations: ["read", "list", "search"], workspace_write: false } });
    expect(expandDelegationProfileV02("bounded_workspace")).toMatchObject({ ok: true, value: { operations: ["create", "append", "update", "rename"], reversible_only: true } });
    expect(expandDelegationProfileV02("admin_everything")).toMatchObject({ ok: false });
    expect(expandDelegationProfileV02("toString")).toMatchObject({ ok: false });
  });

  it("renders guided, standard, and expert density over one immutable authority fingerprint", () => {
    const guided = projectAuthorityInteractionViewV02({ view: "guided", subject });
    const standard = projectAuthorityInteractionViewV02({ view: "standard", subject });
    const expert = projectAuthorityInteractionViewV02({ view: "expert", subject });
    expect(guided).toMatchObject({ ok: true, value: { view: "guided", action_proposal_hash: H1, safe_default: "hold" } });
    expect(standard).toMatchObject({ ok: true, value: { view: "standard", action_proposal_hash: H1 } });
    expect(expert).toMatchObject({ ok: true, value: { view: "expert", action_proposal_hash: H1, action_scope_hash: H2 } });
    if (!guided.ok || !standard.ok || !expert.ok) return;
    expect(new Set([guided.value.authority_fingerprint, standard.value.authority_fingerprint, expert.value.authority_fingerprint]).size).toBe(1);
    expect(guided.value).toHaveProperty("scope_delta", subject.scope_delta);
    expect(guided.value).not.toHaveProperty("policy_digest");
    expect(standard.value).not.toHaveProperty("policy_digest");
    expect(expert.value).toHaveProperty("policy_digest", H1);
  });

  it("supports every typed decision preview and rejects vague/free-form or authority-widening fields", () => {
    for (const previewKind of ["mandate", "exception", "pause", "resume", "revoke", "deny", "answer", "abort"] as const) {
      expect(projectAuthorityInteractionViewV02({ view: "expert", subject: { ...subject, preview_kind: previewKind } })).toMatchObject({ ok: true });
    }
    expect(projectAuthorityInteractionViewV02({ view: "expert", subject: { ...subject, explanation: "trust me" } })).toMatchObject({ ok: false });
    expect(projectAuthorityInteractionViewV02({ view: "expert", subject: { ...subject, scope_delta: { operations_added: ["delete"], selectors_added: [], risk_change: null } } })).toMatchObject({ ok: false });
  });

  it("does not mutate profile or preview inputs", () => {
    const input = structuredClone(subject);
    const before = structuredClone(input);
    projectAuthorityInteractionViewV02({ view: "guided", subject: input });
    expect(input).toEqual(before);
  });
});
