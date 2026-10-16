import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

const REPOSITORY_ROOT = join(import.meta.dirname, "..", "..");
const COMMAND_ROOT = join(REPOSITORY_ROOT, "src", "commands");
const BASELINE_SNAPSHOT = join(
  REPOSITORY_ROOT,
  "tests",
  "fixtures",
  "compat",
  "s35",
  "v01",
  "baseline-command-snapshot.json",
);

const LEGACY_COMMAND_IDS = Object.freeze([
  "compile",
  "doctor",
  "init",
  "pr",
  "report:build",
  "report:open",
  "run:plan",
  "run:preflight",
  "run:prompt",
  "run:recover",
  "run:start",
  "run:status",
  "spec:inspect",
  "spec:validate",
  "verify",
]);

const AVAILABLE_COMMAND_IDS = Object.freeze(
  [...LEGACY_COMMAND_IDS, "spec:new"].sort(),
);

const LATER_CONTRACT_IDS = Object.freeze([
  "adapter:probe",
  "evidence:inspect",
  "gate:check",
  "improve:propose",
  "privacy:list-quarantine",
  "privacy:purge-run",
  "privacy:redact-artifact",
  "support:bundle",
]);

type BaselineCommandSnapshot = {
  readonly baseline_commit: string;
  readonly commands: readonly {
    readonly id: string;
    readonly relative_path: readonly string[];
  }[];
};

function commandSourcePaths(directory: string): string[] {
  const paths: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const absolute = join(directory, entry.name);
    if (entry.isSymbolicLink()) throw new Error(`command path must not be a symlink: ${absolute}`);
    if (entry.isDirectory()) {
      paths.push(...commandSourcePaths(absolute));
    } else if (entry.isFile() && entry.name.endsWith(".ts")) {
      const metadata = lstatSync(absolute);
      if (!metadata.isFile() || metadata.isSymbolicLink()) {
        throw new Error(`command module must be a regular non-symlink file: ${absolute}`);
      }
      paths.push(relative(COMMAND_ROOT, absolute).split("\\").join("/"));
    }
  }
  return paths.sort();
}

function commandId(path: string): string {
  return path.replace(/\.ts$/u, "").split("/").join(":");
}

describe("S35 canonical command inventory", () => {
  it("retains the reviewed 15-command S34 oracle exactly once", () => {
    const snapshot = JSON.parse(readFileSync(BASELINE_SNAPSHOT, "utf8")) as BaselineCommandSnapshot;
    expect(snapshot.baseline_commit).toBe("13a8906fdd32b005d29c1eb07ee54f55f80c7fc2");
    const ids = snapshot.commands.map((command) => command.id);
    expect(ids).toEqual(LEGACY_COMMAND_IDS);
    expect(new Set(ids).size).toBe(15);
    expect(snapshot.commands.map((command) => command.relative_path.join("/"))).toEqual(
      LEGACY_COMMAND_IDS.map((id) => `dist/commands/${id.replaceAll(":", "/")}.js`),
    );
  });

  it("ships exactly the 15 legacy modules plus the authorized spec:new addition", () => {
    const sourceIds = commandSourcePaths(COMMAND_ROOT).map(commandId).sort();
    expect(sourceIds).toEqual(AVAILABLE_COMMAND_IDS);
  });

  it.each(LATER_CONTRACT_IDS)("keeps later-contract command %s absent", (id) => {
    const sourceIds = new Set(commandSourcePaths(COMMAND_ROOT).map(commandId));
    expect(sourceIds.has(id)).toBe(false);
  });
});
