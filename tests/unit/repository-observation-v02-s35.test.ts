import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { hashCanonical } from "../../src/hash.js";
import {
  consumeApprovedRepositoryObservationV02,
  deriveInvocationRepositoryRootV02,
  observeCleanRepositoryStateV02,
} from "../../src/run/repository-observation-v02.js";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function git(root: string, args: string[]): string {
  return execFileSync("git", ["-C", root, ...args], { encoding: "utf8" }).trim();
}

function repository() {
  const root = mkdtempSync(join(tmpdir(), "loopeix-s35-repository-observation-"));
  roots.push(root);
  git(root, ["init", "-b", "main"]);
  git(root, ["config", "user.email", "fixture@example.invalid"]);
  git(root, ["config", "user.name", "S35 Fixture"]);
  writeFileSync(join(root, "tracked.txt"), "reviewed fixture\n");
  git(root, ["add", "tracked.txt"]);
  git(root, ["commit", "-m", "fixture"]);
  const objectFormat = git(root, ["rev-parse", "--show-object-format"]) as "sha1" | "sha256";
  const value = git(root, ["rev-parse", "HEAD"]);
  const approved = {
    repository_root_ref: "repository_s35_fixture_01",
    object_format: objectFormat,
    base_ref: {
      kind: "git-ref" as const,
      canonical_ref_name: "refs/heads/main",
      object_id: { algorithm: objectFormat, value },
      identity_hash: "",
    },
    transition_mode: "read-only" as const,
  };
  approved.base_ref.identity_hash = hashCanonical({
    purpose: "repository-base-ref-v02",
    repository_root_ref: approved.repository_root_ref,
    object_format: approved.object_format,
    kind: approved.base_ref.kind,
    canonical_ref_name: approved.base_ref.canonical_ref_name,
    object_id: approved.base_ref.object_id,
  });
  return { root, approved };
}

describe("S35 clean repository observation", () => {
  it("derives the invocation-local repository reference from the canonical direct worktree root", () => {
    const fixture = repository();
    const canonicalRoot = realpathSync(fixture.root);
    const expectedDigest = createHash("sha256").update(Buffer.from(canonicalRoot, "utf8")).digest("hex").slice(0, 32);
    expect(deriveInvocationRepositoryRootV02(fixture.root)).toEqual({
      ok: true,
      canonical_root: canonicalRoot,
      repository_root_ref: `repository_${expectedDigest}`,
    });
    const plainDirectory = mkdtempSync(join(tmpdir(), "loopeix-s35-not-repository-"));
    roots.push(plainDirectory);
    expect(deriveInvocationRepositoryRootV02(plainDirectory)).toMatchObject({
      ok: false,
      reason: "REPOSITORY_OBSERVATION_INVALID",
    });
  });

  it("admits one two-pass-stable clean observation and consumes it once", () => {
    const fixture = repository();
    const result = observeCleanRepositoryStateV02(fixture.root, fixture.approved);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const value = consumeApprovedRepositoryObservationV02(result.observation);
    expect(value).toMatchObject({
      repository_root_ref: fixture.approved.repository_root_ref,
      base_ref_identity_hash: fixture.approved.base_ref.identity_hash,
      head: fixture.approved.base_ref.object_id,
      merge_base: fixture.approved.base_ref.object_id,
      repository_state_hash: result.observation.repository_state_hash,
    });
    expect(consumeApprovedRepositoryObservationV02(result.observation)).toBeNull();
  });

  it.each([
    ["tracked drift", (root: string) => writeFileSync(join(root, "tracked.txt"), "changed\n")],
    ["untracked content", (root: string) => writeFileSync(join(root, "untracked.txt"), "new\n")],
    ["ignored content", (root: string) => {
      writeFileSync(join(root, ".gitignore"), "ignored.txt\n");
      git(root, ["add", ".gitignore"]);
      git(root, ["commit", "-m", "ignore rule"]);
      writeFileSync(join(root, "ignored.txt"), "ignored but authority-relevant\n");
    }],
  ])("rejects %s rather than claiming partial capture", (_name, mutate) => {
    const fixture = repository();
    mutate(fixture.root);
    expect(observeCleanRepositoryStateV02(fixture.root, fixture.approved)).toMatchObject({
      ok: false,
      reason: "REPOSITORY_OBSERVATION_INVALID",
    });
  });

  it("rejects base-ref substitution and forged handles", () => {
    const fixture = repository();
    fixture.approved.base_ref.object_id.value = "0".repeat(fixture.approved.object_format === "sha1" ? 40 : 64);
    expect(observeCleanRepositoryStateV02(fixture.root, fixture.approved)).toMatchObject({
      ok: false,
      reason: "REPOSITORY_OBSERVATION_INVALID",
    });
    expect(consumeApprovedRepositoryObservationV02({ repository_state_hash: `sha256:${"0".repeat(64)}` } as never)).toBeNull();
  });
});
