import { z } from "zod";
import type { Issue } from "./loopeix.js";

/**
 * SpecChangeProposal (S14): a proposed change to FUTURE loop behavior. Accepted proposals create a
 * new immutable LoopeixVersion — they never modify the version they came from. This finalizes the
 * shape the S5 fixture marked provisional (spec-change-proposal-v002.yaml).
 */

const VERSION_RE = /^v\d{3}$/;

export const ProposalStatus = z.enum(["proposed", "approved", "rejected", "applied"]);
export type ProposalStatusValue = z.infer<typeof ProposalStatus>;

export const ChangeType = z.enum(["add", "modify", "remove"]);

export const SpecChange = z
  .object({
    type: ChangeType,
    target: z.string().min(1),
    description: z.string().min(1),
  })
  .strict();

export const SpecChangeProposal = z
  .object({
    schema_version: z.string().min(1),
    proposal_id: z.string().regex(/^scp_[a-z0-9_]+$/),
    loop_family: z.string().min(1),
    from_version: z.string().regex(VERSION_RE),
    to_version: z.string().regex(VERSION_RE),
    status: ProposalStatus,
    source_retro: z.string().min(1),
    rationale: z.string().min(1),
    changes: z.array(SpecChange).min(1),
    immutability_note: z.string().optional(),
  })
  .strict();

export type SpecChangeProposalRecord = z.infer<typeof SpecChangeProposal>;

export const versionNumber = (v: string): number => Number.parseInt(v.slice(1), 10);

/**
 * Cross-field invariants a JSON Schema cannot express: a proposal must move FORWARD to a distinct,
 * higher version than its source (it introduces a new version, never edits the source).
 */
export function checkProposalInvariants(p: SpecChangeProposalRecord): Issue[] {
  const issues: Issue[] = [];
  if (p.to_version === p.from_version) {
    issues.push({ path: "to_version", message: "to_version must differ from from_version (a proposal creates a NEW version)" });
  } else if (versionNumber(p.to_version) <= versionNumber(p.from_version)) {
    issues.push({ path: "to_version", message: `to_version '${p.to_version}' must be greater than from_version '${p.from_version}'` });
  }
  return issues;
}
