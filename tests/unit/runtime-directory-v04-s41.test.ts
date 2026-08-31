import { chmodSync, renameSync } from "node:fs";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import * as rootExports from "../../src/index.js";
import { inspectRuntimeDirectoryV04 } from "../../src/run/runtime-directory-v04.js";
import { createRuntimeCommandFixtureV04 } from "../helpers/runtime-v04-command-fixture.js";

const cleanups: Array<() => void> = [];

afterEach(() => {
  for (const cleanup of cleanups.splice(0)) cleanup();
});

describe("S41-D anchored V04 runtime directory inspection", () => {
  it("admits one exact V04 directory and keeps active-owner staleness ambiguous", async () => {
    const fixture = createRuntimeCommandFixtureV04();
    cleanups.push(fixture.cleanup);
    await expect(inspectRuntimeDirectoryV04(fixture.root)).resolves.toMatchObject({
      ok: true,
      inspected: {
        owner_status: {
          status: "ambiguous",
          ambiguous_reason: "stale-owner-proof-missing",
        },
        summary: null,
      },
    });
    expect("inspectRuntimeDirectoryV04" in rootExports).toBe(false);
  });

  it("returns not-present only when the V04 manifest is genuinely absent", async () => {
    const fixture = createRuntimeCommandFixtureV04();
    cleanups.push(fixture.cleanup);
    renameSync(
      join(fixture.root, "run-manifest.json"),
      join(fixture.root, "run-manifest.absent"),
    );
    await expect(inspectRuntimeDirectoryV04(fixture.root)).resolves.toMatchObject({
      ok: false,
      reason: "RUNTIME_V04_NOT_PRESENT",
    });
  });

  it("uses the captured filesystem mode instead of trusting the manifest row", async () => {
    const fixture = createRuntimeCommandFixtureV04();
    cleanups.push(fixture.cleanup);
    chmodSync(join(fixture.root, "ledger.jsonl"), 0o644);
    await expect(inspectRuntimeDirectoryV04(fixture.root)).resolves.toMatchObject({
      ok: false,
      reason: "RUNTIME_V04_INVALID",
    });

    chmodSync(join(fixture.root, "ledger.jsonl"), 0o600);
    chmodSync(join(fixture.root, "run-manifest.json"), 0o644);
    await expect(inspectRuntimeDirectoryV04(fixture.root)).resolves.toMatchObject({
      ok: false,
      reason: "RUNTIME_V04_INVALID",
    });
  });

  it("rejects hostile non-string input without invoking accessors", async () => {
    let getterCalls = 0;
    const hostile = Object.defineProperty({}, "path", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return "/tmp/should-not-be-read";
      },
    });
    await expect(inspectRuntimeDirectoryV04(hostile)).resolves.toMatchObject({
      ok: false,
      reason: "RUNTIME_V04_INVALID",
    });
    expect(getterCalls).toBe(0);
  });
});
