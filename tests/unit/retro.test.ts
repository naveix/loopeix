import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import {
  assertProposalApplicable,
  canTransition,
  checkProposalImmutability,
  checkProposalInvariants,
  nextVersion,
  parseRetro,
  proposeSpecChange,
  SpecChangeProposal,
  type SpecChangeProposalRecord,
} from "../../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (p: string) => readFileSync(join(here, "..", "fixtures", "valid", "runtime", p), "utf8");
const retroMd = fixture("retro-with-proposal.md");
const proposalYaml = parse(fixture("spec-change-proposal-v002.yaml")) as unknown;

describe("parseRetro — against the real RetroRecord fixture", () => {
  const r = parseRetro(retroMd);
  it("extracts loop identity and run state", () => {
    expect(r.loop_family).toBe("minimal-bugfix");
    expect(r.version).toBe("v001");
    expect(r.run_state).toBe("completed");
  });
  it("collects referenced finding ids and detects the proposal", () => {
    expect(r.findings).toEqual(["find_0001"]);
    expect(r.creates_proposal).toBe(true);
  });
});

describe("SpecChangeProposal schema — against the real fixture", () => {
  it("the fixture validates and satisfies the forward-version invariant", () => {
    const parsed = SpecChangeProposal.safeParse(proposalYaml);
    expect(parsed.success).toBe(true);
    if (parsed.success) expect(checkProposalInvariants(parsed.data)).toEqual([]);
  });
});

describe("checkProposalInvariants — forward-only versioning", () => {
  const base = SpecChangeProposal.parse(proposalYaml);
  it("flags to_version equal to from_version", () => {
    expect(checkProposalInvariants({ ...base, to_version: base.from_version }).length).toBeGreaterThan(0);
  });
  it("flags to_version lower than from_version", () => {
    expect(checkProposalInvariants({ ...base, from_version: "v005", to_version: "v002" }).length).toBeGreaterThan(0);
  });
});

describe("checkProposalImmutability — only ever ADD a new version", () => {
  const base: SpecChangeProposalRecord = SpecChangeProposal.parse(proposalYaml); // v001 -> v002
  it("OK when from exists and to is new", () => {
    expect(checkProposalImmutability(base, { existingVersions: ["v001"] }).ok).toBe(true);
  });
  it("rejects overwriting an existing (immutable) to_version", () => {
    const r = checkProposalImmutability(base, { existingVersions: ["v001", "v002"] });
    expect(r.ok).toBe(false);
    expect(r.issues.some((i) => i.includes("already exists"))).toBe(true);
  });
  it("rejects a from_version that does not exist", () => {
    expect(checkProposalImmutability(base, { existingVersions: [] }).ok).toBe(false);
  });
});

describe("approval flow — allowed status transitions", () => {
  it("proposed → approved/rejected only (not straight to applied)", () => {
    expect(canTransition("proposed", "approved")).toBe(true);
    expect(canTransition("proposed", "rejected")).toBe(true);
    expect(canTransition("proposed", "applied")).toBe(false);
  });
  it("approved → applied; terminal states go nowhere", () => {
    expect(canTransition("approved", "applied")).toBe(true);
    expect(canTransition("applied", "proposed")).toBe(false);
    expect(canTransition("rejected", "approved")).toBe(false);
  });
});

describe("proposeSpecChange — generate a proposal without mutating a spec", () => {
  it("produces a schema-valid, forward-versioned, proposed proposal from a retro", () => {
    const p = proposeSpecChange(parseRetro(retroMd), {
      proposal_id: "scp_0002",
      source_retro: "run_minimal_bugfix",
      rationale: "Declare the known-flaky timing test rather than skipping it ad hoc.",
      changes: [{ type: "add", target: "evaluations", description: "Add a known-flaky-timing evaluation (required=false)." }],
    });
    expect(p.from_version).toBe("v001");
    expect(p.to_version).toBe("v002");
    expect(p.status).toBe("proposed");
    expect(SpecChangeProposal.safeParse(p).success).toBe(true);
    expect(checkProposalInvariants(p)).toEqual([]);
  });
  it("throws if the retro lacks a loop_family/version to anchor the proposal", () => {
    expect(() =>
      proposeSpecChange(
        { loop_family: null, version: null, run_state: null, findings: [], creates_proposal: false },
        { proposal_id: "scp_0003", source_retro: "r", rationale: "x", changes: [{ type: "add", target: "t", description: "d" }] },
      ),
    ).toThrow(/loop_family/);
  });
});

describe("S14 review hardening", () => {
  const base: SpecChangeProposalRecord = SpecChangeProposal.parse(proposalYaml); // v001 -> v002, proposed

  it("proposeSpecChange rejects a backward/equal to_version override (forward invariant enforced, not just shape)", () => {
    expect(() =>
      proposeSpecChange(parseRetro(retroMd), {
        proposal_id: "scp_back",
        source_retro: "r",
        rationale: "x",
        changes: [{ type: "add", target: "t", description: "d" }],
        to_version: "v001", // == from_version
      }),
    ).toThrow(/invalid proposal/);
  });

  it("assertProposalApplicable requires 'approved' status AND immutability", () => {
    expect(() => assertProposalApplicable(base, { existingVersions: ["v001"] })).toThrow(/must be 'approved'/);
    const ok = assertProposalApplicable({ ...base, status: "approved" }, { existingVersions: ["v001"] });
    expect(ok.to_version).toBe("v002");
    expect(() => assertProposalApplicable({ ...base, status: "approved" }, { existingVersions: ["v001", "v002"] })).toThrow(/immutability/);
  });

  it("creates_proposal is false without a ## Proposal section", () => {
    expect(parseRetro("# Retro\n\nMentions SpecChangeProposal in prose but has no section.").creates_proposal).toBe(false);
  });
  it("checkProposalImmutability flags to_version <= from_version", () => {
    expect(checkProposalImmutability({ ...base, from_version: "v003", to_version: "v002" }, { existingVersions: ["v003"] }).ok).toBe(false);
  });
  it("canTransition returns false for an unknown status", () => {
    expect(canTransition("bogus" as never, "applied")).toBe(false);
  });
  it("nextVersion throws at the v999 ceiling", () => {
    expect(() => nextVersion("v999")).toThrow(/version space exhausted/);
    expect(nextVersion("v001")).toBe("v002");
  });
  it("proposeSpecChange does not mutate the caller's changes array", () => {
    const changes = [{ type: "add" as const, target: "t", description: "d" }];
    proposeSpecChange(parseRetro(retroMd), { proposal_id: "scp_x", source_retro: "r", rationale: "x", changes });
    expect(changes).toEqual([{ type: "add", target: "t", description: "d" }]);
  });
});
