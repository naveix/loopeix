import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { hashCanonical } from "../../src/hash.js";
import {
  consumeApprovedRepositoryObservationV02,
  observeCleanRepositoryStateV02,
  type ApprovedRepositoryObservationV02,
} from "../../src/run/repository-observation-v02.js";
import type { ResolvedRunPlanV02Value } from "../../src/schema/runtime.js";

export type RuntimeRepositoryObservationFixture = Readonly<{
  root: string;
  plan: ResolvedRunPlanV02Value;
  observation: ApprovedRepositoryObservationV02;
  freshObservation: () => ApprovedRepositoryObservationV02;
  cleanup: () => void;
}>;

function git(root: string, args: readonly string[]): string {
  return execFileSync("/usr/bin/git", ["-C", root, ...args], {
    encoding: "utf8",
    env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

export function createRuntimeRepositoryObservationFixture(
  sourcePlan: ResolvedRunPlanV02Value,
  label: string,
): RuntimeRepositoryObservationFixture {
  const root = mkdtempSync(join(tmpdir(), `loopeix-s41-recovery-${label}-`));
  try {
    git(root, ["init", "-b", "main"]);
    git(root, ["config", "user.email", "fixture@example.invalid"]);
    git(root, ["config", "user.name", "S41 Fixture"]);
    writeFileSync(join(root, "tracked.txt"), `reviewed ${label}\n`, { mode: 0o600 });
    git(root, ["add", "tracked.txt"]);
    git(root, ["commit", "-m", "fixture"]);

    const objectFormat = git(root, ["rev-parse", "--show-object-format"]) as "sha1" | "sha256";
    const objectId = git(root, ["rev-parse", "HEAD"]);
    const repositoryRootRef = `repository_s41_${label}`;
    const baseRef = {
      kind: "git-ref" as const,
      canonical_ref_name: "refs/heads/main",
      object_id: { algorithm: objectFormat, value: objectId },
      identity_hash: "",
    };
    baseRef.identity_hash = hashCanonical({
      purpose: "repository-base-ref-v02",
      repository_root_ref: repositoryRootRef,
      object_format: objectFormat,
      kind: baseRef.kind,
      canonical_ref_name: baseRef.canonical_ref_name,
      object_id: baseRef.object_id,
    });
    const approved = {
      repository_root_ref: repositoryRootRef,
      object_format: objectFormat,
      base_ref: baseRef,
      transition_mode: "read-only" as const,
    };
    const first = observeCleanRepositoryStateV02(root, approved);
    if (!first.ok) throw new Error(first.reason);
    const initialState = consumeApprovedRepositoryObservationV02(first.observation);
    if (initialState === null) throw new Error("repository observation was not consumable");
    const second = observeCleanRepositoryStateV02(root, approved);
    if (!second.ok) throw new Error(second.reason);

    const plan = structuredClone(sourcePlan);
    plan.authority_subject.repository = {
      ...plan.authority_subject.repository,
      ...approved,
      initial_state: initialState,
    };
    return Object.freeze({
      root,
      plan,
      observation: second.observation,
      freshObservation: () => {
        const next = observeCleanRepositoryStateV02(root, approved);
        if (!next.ok) throw new Error(next.reason);
        return next.observation;
      },
      cleanup: () => rmSync(root, { recursive: true, force: true }),
    });
  } catch (error) {
    rmSync(root, { recursive: true, force: true });
    throw error;
  }
}
