import {
  checkProposalInvariants,
  SpecChangeProposal,
  versionNumber,
  type ProposalStatusValue,
  type SpecChangeProposalRecord,
} from "./schema/proposal.js";

/**
 * Retro → improvement engine (S14). A RetroRecord (markdown) is parsed for the run's identity and
 * referenced findings; a SpecChangeProposal is then GENERATED without mutating any spec, gated by an
 * immutability check (only ever ADD a new version) and an explicit approval flow.
 */

export interface ParsedRetro {
  loop_family: string | null;
  version: string | null;
  run_state: string | null;
  findings: string[];
  creates_proposal: boolean;
}

export function parseRetro(markdown: string): ParsedRetro {
  const cap = (re: RegExp): string | null => {
    const r = re.exec(markdown);
    return r ? (r[1] as string) : null;
  };
  const findings = [...new Set([...markdown.matchAll(/\bfind_\d+\b/g)].map((x) => x[0]))];
  return {
    loop_family: cap(/Loop family:\s*`([^`]+)`/),
    version: cap(/Version:\s*`([^`]+)`/),
    run_state: cap(/Run state:\s*([A-Za-z][\w-]*)/),
    findings,
    // Structural signal: a dedicated `## Proposal` section — not a bare mention (which a "this run
    // does NOT create a SpecChangeProposal" line would falsely trigger).
    creates_proposal: /^##\s+Proposal\b/m.test(markdown),
  };
}

/** Next version id: v001 → v002. Throws at the v999 ceiling rather than emitting a malformed id. */
export function nextVersion(v: string): string {
  const n = versionNumber(v) + 1;
  if (n > 999) throw new Error(`version space exhausted: cannot advance past v999 (from '${v}')`);
  return `v${String(n).padStart(3, "0")}`;
}

// Approval flow — the ONLY allowed status transitions. A proposal must be approved before applied;
// rejected/applied are terminal.
const ALLOWED_TRANSITIONS: Record<ProposalStatusValue, ProposalStatusValue[]> = {
  proposed: ["approved", "rejected"],
  approved: ["applied", "rejected"],
  rejected: [],
  applied: [],
};

export function canTransition(from: ProposalStatusValue, to: ProposalStatusValue): boolean {
  return ALLOWED_TRANSITIONS[from]?.includes(to) ?? false;
}

/**
 * Immutability check: a proposal may only ADD a new version. `from_version` must exist; `to_version`
 * must NOT already exist (overwriting an immutable version is forbidden); to_version > from_version.
 */
export function checkProposalImmutability(
  p: SpecChangeProposalRecord,
  opts: { existingVersions: readonly string[] },
): { ok: boolean; issues: string[] } {
  const issues: string[] = [];
  const existing = new Set(opts.existingVersions);
  if (!existing.has(p.from_version)) issues.push(`from_version '${p.from_version}' does not exist among known versions`);
  if (existing.has(p.to_version)) issues.push(`to_version '${p.to_version}' already exists — a proposal must not overwrite an immutable version`);
  if (versionNumber(p.to_version) <= versionNumber(p.from_version))
    issues.push(`to_version '${p.to_version}' must be greater than from_version '${p.from_version}'`);
  return { ok: issues.length === 0, issues };
}

export interface ProposeOptions {
  proposal_id: string;
  source_retro: string;
  rationale: string;
  changes: readonly { type: "add" | "modify" | "remove"; target: string; description: string }[];
  to_version?: string;
  schema_version?: string;
}

/**
 * Generate a SpecChangeProposal from a parsed retro + intended changes, WITHOUT mutating any spec.
 * from_version is the retro's version; to_version defaults to the next version; status is "proposed".
 * The result is validated against the SpecChangeProposal schema before it is returned.
 */
export function proposeSpecChange(retro: ParsedRetro, opts: ProposeOptions): SpecChangeProposalRecord {
  if (!retro.loop_family || !retro.version) {
    throw new Error("retro is missing loop_family/version; cannot propose a change");
  }
  const to_version = opts.to_version ?? nextVersion(retro.version);
  const proposal = SpecChangeProposal.parse({
    schema_version: opts.schema_version ?? "0.1",
    proposal_id: opts.proposal_id,
    loop_family: retro.loop_family,
    from_version: retro.version,
    to_version,
    status: "proposed",
    source_retro: opts.source_retro,
    rationale: opts.rationale,
    changes: opts.changes.map((c) => ({ ...c })),
    immutability_note: `Introduces ${to_version} and does not modify the immutable ${retro.version} version file.`,
  });
  // Shape alone is not enough: enforce the forward-only invariant that guards immutability, so a
  // caller-supplied `to_version` override cannot emit a backward/equal (mutating-intent) proposal.
  const issues = checkProposalInvariants(proposal);
  if (issues.length > 0) {
    throw new Error(`invalid proposal: ${issues.map((i) => `${i.path}: ${i.message}`).join("; ")}`);
  }
  return proposal;
}

/**
 * The single SAFE entry point to apply a proposal, before any version is written. Makes "only via
 * the approval flow, never mutate the source" a GUARANTEE rather than a convention: the proposal
 * must be `approved` (so applying is the legal approved → applied transition) AND pass the
 * immutability check (from exists, to is new, forward-only). Throws otherwise; on success returns
 * the target version + the changes to write.
 */
export function assertProposalApplicable(
  p: SpecChangeProposalRecord,
  opts: { existingVersions: readonly string[] },
): { to_version: string; changes: SpecChangeProposalRecord["changes"] } {
  if (!canTransition(p.status, "applied")) {
    throw new Error(`proposal '${p.proposal_id}' cannot be applied from status '${p.status}' (must be 'approved')`);
  }
  const imm = checkProposalImmutability(p, opts);
  if (!imm.ok) throw new Error(`proposal '${p.proposal_id}' violates immutability: ${imm.issues.join("; ")}`);
  return { to_version: p.to_version, changes: p.changes };
}
