import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { readCompilePackV01 } from "../../src/compiler/read-pack.js";
import { replayCompilePackV01 } from "../../src/compiler/replay-v01.js";

const FIXTURE_ROOT = join(import.meta.dirname, "../fixtures/compat/s35/v01");
const CATALOG_HASH = "sha256:4bba5fca6ce73a6d21598890001a45e03c349a3a1fa78148b802497a22eda823";

const PACK_FIXTURES = Object.freeze([
  ["compiled-explicit-destination", "compiled", 7],
  ["compiled-safe-bugfix", "compiled", 7],
  ["credential-shaped-replay-pack", "compiled", 7],
  ["hold-ambiguous", "hold-ambiguous", 5],
  ["hold-no-item", "hold-no-item", 5],
  ["hold-risk", "hold-risk", 5],
  ["large-compiled-pack", "compiled", 7],
  ["planned-run-source-pack", "compiled", 7],
] as const);

describe("S35 frozen V01 fixture compatibility", () => {
  it.each(PACK_FIXTURES)(
    "strictly reads and exactly replays %s without granting V02 eligibility",
    async (fixtureName, terminalState, memberCount) => {
      const read = await readCompilePackV01(join(FIXTURE_ROOT, fixtureName));
      expect(read.ok, read.ok ? undefined : read.message).toBe(true);
      if (!read.ok) return;

      expect(read.manifest.schema_version).toBe("0.1");
      expect(read.manifest.terminal_state).toBe(terminalState);
      expect(read.identity.members).toHaveLength(memberCount);
      expect(read.selector).toEqual({
        schema_version: "0.1",
        catalog_version_hash: CATALOG_HASH,
      });

      const replay = await replayCompilePackV01(read);
      expect(replay.ok, replay.ok ? undefined : replay.message).toBe(true);
      if (!replay.ok) return;

      expect(replay.authority.selector).toEqual(read.selector);
      expect(replay.authority.source_pack_root_hash).toBe(read.identity.source_pack_root_hash);
      expect(Object.keys(replay.authority).sort()).toEqual([
        "mintDestinationCapability",
        "mintFrozenPlanProjection",
        "mintPackMemberCopy",
        "selector",
        "source_pack_root_hash",
      ]);
      expect(replay.authority).not.toHaveProperty("execution_profile");
      expect(replay.authority).not.toHaveProperty("authority_subject");
    },
    60_000,
  );
});
