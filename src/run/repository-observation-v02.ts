import { execFileSync } from "node:child_process";
import { lstatSync, realpathSync } from "node:fs";
import { join } from "node:path";

import { hashCanonical, hashRawBytes } from "../hash.js";
import type { AuthorityPlanningInputV02Value } from "./authority-planning-input-v02.js";

type RepositoryInputV02 = AuthorityPlanningInputV02Value["repository"];
type GitObjectIdV02 = Readonly<{ algorithm: "sha1" | "sha256"; value: string }>;

export type RepositoryStateObservationV02 = Readonly<{
  repository_root_ref: string;
  base_ref_identity_hash: string;
  head: GitObjectIdV02;
  merge_base: GitObjectIdV02;
  head_state_hash: string;
  tracked_diff_hash: string;
  staged_diff_hash: string;
  untracked_content_hash: string;
  submodule_state_hash: string;
  repository_state_hash: string;
}>;

export type ApprovedRepositoryObservationV02 = Readonly<{
  repository_state_hash: string;
  readonly __approved_repository_observation_v02: unique symbol;
}>;

export type ObserveRepositoryStateV02Result =
  | { ok: true; observation: ApprovedRepositoryObservationV02 }
  | {
      ok: false;
      reason: "REPOSITORY_OBSERVATION_INVALID" | "IO_HELPER_UNAVAILABLE" | "IO_IDENTITY_MISMATCH";
      message: string;
    };

const registry = new WeakMap<ApprovedRepositoryObservationV02, RepositoryStateObservationV02>();
const UTF8 = new TextEncoder();

export type InvocationRepositoryRootV02Result =
  | { ok: true; canonical_root: string; repository_root_ref: string }
  | {
      ok: false;
      reason: "REPOSITORY_OBSERVATION_INVALID" | "IO_HELPER_UNAVAILABLE";
      message: string;
    };

function failure(
  reason: Exclude<ObserveRepositoryStateV02Result, { ok: true }> ["reason"],
  message: string,
): ObserveRepositoryStateV02Result {
  return { ok: false, reason, message };
}

function git(root: string, args: readonly string[]): Buffer {
  return execFileSync("/usr/bin/git", ["-C", root, ...args], {
    encoding: "buffer",
    env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
    maxBuffer: 16_777_216,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function lines(root: string, args: readonly string[]): string[] {
  const bytes = git(root, args);
  if (bytes.byteLength === 0 || bytes[bytes.byteLength - 1] !== 0x0a) throw new Error("Git output is not LF terminated.");
  const value = bytes.subarray(0, -1).toString("utf8");
  if (value.includes("\r") || value.includes("\0")) throw new Error("Git output contains a forbidden delimiter.");
  return value.split("\n");
}

function line(root: string, args: readonly string[]): string {
  const values = lines(root, args);
  if (values.length !== 1 || values[0] === "") throw new Error("Git output is not exactly one non-empty line.");
  return values[0]!;
}

function objectId(algorithm: "sha1" | "sha256", value: string): GitObjectIdV02 | null {
  const pattern = algorithm === "sha1" ? /^[0-9a-f]{40}$/u : /^[0-9a-f]{64}$/u;
  return pattern.test(value) ? Object.freeze({ algorithm, value }) : null;
}

export function deriveInvocationRepositoryRootV02(workspaceRoot: string): InvocationRepositoryRootV02Result {
  try {
    const root = realpathSync(workspaceRoot);
    const gitDirectory = lstatSync(join(root, ".git"));
    if (!gitDirectory.isDirectory() || gitDirectory.isSymbolicLink()) {
      return {
        ok: false,
        reason: "REPOSITORY_OBSERVATION_INVALID",
        message: "The workspace is not a direct non-symlink Git worktree.",
      };
    }
    const topLevel = realpathSync(line(root, ["rev-parse", "--show-toplevel"]));
    if (topLevel !== root) {
      return {
        ok: false,
        reason: "REPOSITORY_OBSERVATION_INVALID",
        message: "The workspace does not equal the captured Git worktree root.",
      };
    }
    const digest = hashRawBytes(UTF8.encode(root)).slice("sha256:".length);
    return {
      ok: true,
      canonical_root: root,
      repository_root_ref: `repository_${digest.slice(0, 32)}`,
    };
  } catch {
    return {
      ok: false,
      reason: "REPOSITORY_OBSERVATION_INVALID",
      message: "The workspace is not an admissible direct Git worktree.",
    };
  }
}

function captureCleanRepository(
  root: string,
  approved: RepositoryInputV02,
): RepositoryStateObservationV02 | null {
  const format = line(root, ["rev-parse", "--show-object-format"]);
  if (format !== approved.object_format) return null;
  const topLevel = realpathSync(line(root, ["rev-parse", "--show-toplevel"]));
  if (topLevel !== root) return null;
  const gitDirectory = lstatSync(join(root, ".git"));
  if (!gitDirectory.isDirectory() || gitDirectory.isSymbolicLink()) return null;

  const status = git(root, ["status", "--porcelain=v2", "--untracked-files=all", "--ignored=matching", "-z"]);
  if (status.byteLength !== 0) return null;
  const index = git(root, ["ls-files", "--stage", "-z"]);
  if (index.toString("utf8").split("\0").filter(Boolean).some((row) => row.startsWith("160000 "))) return null;

  const baseValue = line(root, ["show-ref", "--verify", "--hash", approved.base_ref.canonical_ref_name]);
  if (baseValue !== approved.base_ref.object_id.value) return null;
  const head = objectId(approved.object_format, line(root, ["rev-parse", "--verify", "HEAD"]));
  const base = objectId(approved.object_format, baseValue);
  if (head === null || base === null) return null;
  const mergeBases = lines(root, ["merge-base", "--all", head.value, base.value]);
  if (mergeBases.length !== 1) return null;
  const mergeBase = objectId(approved.object_format, mergeBases[0]!);
  if (mergeBase === null) return null;

  const baseRefIdentityHash = hashCanonical({
    purpose: "repository-base-ref-v02",
    repository_root_ref: approved.repository_root_ref,
    object_format: approved.object_format,
    kind: approved.base_ref.kind,
    canonical_ref_name: approved.base_ref.canonical_ref_name,
    object_id: approved.base_ref.object_id,
  });
  if (baseRefIdentityHash !== approved.base_ref.identity_hash) return null;
  const headStateHash = hashCanonical({
    purpose: "repository-head-state-v02",
    repository_root_ref: approved.repository_root_ref,
    base_ref_identity_hash: baseRefIdentityHash,
    head,
    merge_base: mergeBase,
  });
  const trackedDiffHash = hashCanonical({
    purpose: "repository-tracked-diff-v02",
    repository_root_ref: approved.repository_root_ref,
    entries: [],
  });
  const stagedDiffHash = hashCanonical({
    purpose: "repository-staged-diff-v02",
    repository_root_ref: approved.repository_root_ref,
    entries: [],
  });
  const untrackedContentHash = hashCanonical({
    purpose: "repository-untracked-content-v02",
    repository_root_ref: approved.repository_root_ref,
    entries: [],
  });
  const submoduleStateHash = hashCanonical({
    purpose: "repository-submodule-state-v02",
    repository_root_ref: approved.repository_root_ref,
    entries: [],
  });
  const repositoryStateHash = hashCanonical({
    purpose: "repository-state-v02",
    repository_root_ref: approved.repository_root_ref,
    base_ref_identity_hash: baseRefIdentityHash,
    head,
    merge_base: mergeBase,
    head_state_hash: headStateHash,
    tracked_diff_hash: trackedDiffHash,
    staged_diff_hash: stagedDiffHash,
    untracked_content_hash: untrackedContentHash,
    submodule_state_hash: submoduleStateHash,
  });
  return Object.freeze({
    repository_root_ref: approved.repository_root_ref,
    base_ref_identity_hash: baseRefIdentityHash,
    head,
    merge_base: mergeBase,
    head_state_hash: headStateHash,
    tracked_diff_hash: trackedDiffHash,
    staged_diff_hash: stagedDiffHash,
    untracked_content_hash: untrackedContentHash,
    submodule_state_hash: submoduleStateHash,
    repository_state_hash: repositoryStateHash,
  });
}

export function observeCleanRepositoryStateV02(
  workspaceRoot: string,
  approved: RepositoryInputV02,
): ObserveRepositoryStateV02Result {
  let root: string;
  try {
    root = realpathSync(workspaceRoot);
    const first = captureCleanRepository(root, approved);
    if (first === null) {
      return failure("REPOSITORY_OBSERVATION_INVALID", "The repository does not satisfy the approved clean-state boundary.");
    }
    const second = captureCleanRepository(root, approved);
    if (second === null || JSON.stringify(first) !== JSON.stringify(second)) {
      return failure("IO_IDENTITY_MISMATCH", "The repository changed during observation.");
    }
    const observation = Object.freeze({ repository_state_hash: first.repository_state_hash }) as ApprovedRepositoryObservationV02;
    registry.set(observation, structuredClone(first));
    return { ok: true, observation };
  } catch {
    return failure("IO_HELPER_UNAVAILABLE", "The repository observation helper is unavailable.");
  }
}

export function consumeApprovedRepositoryObservationV02(
  observation: ApprovedRepositoryObservationV02,
): RepositoryStateObservationV02 | null {
  const value = registry.get(observation);
  if (value === undefined) return null;
  registry.delete(observation);
  return structuredClone(value);
}
