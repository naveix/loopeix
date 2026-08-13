import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, join, relative, resolve } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";

const SCANNER = resolve("scripts/scan-secrets-s35.mjs");
const HASH_PREFIX = "sha256:";

type RuleId =
  | "CRED_PRIVATE_KEY_PEM"
  | "CRED_AWS_ACCESS_KEY_ID"
  | "CRED_GITHUB_TOKEN"
  | "CRED_ANTHROPIC_API_KEY"
  | "CRED_OPENAI_API_KEY"
  | "CRED_SLACK_TOKEN"
  | "CRED_GOOGLE_API_KEY"
  | "CRED_COMPOSIO_CONSUMER_KEY"
  | "CRED_URI_USERINFO"
  | "CRED_ASSIGNMENT";

type Candidate = Readonly<{ ruleId: RuleId; value: string }>;
type AllowlistEntry = Readonly<{
  repository_id: string;
  path: string;
  rule_id: RuleId;
  candidate_sha256: string;
  occurrence_count: number;
  justification: string;
}>;

const candidates = Object.freeze({
  pem: { ruleId: "CRED_PRIVATE_KEY_PEM", value: ["-----", "BEGIN ", "SYNTHETIC ", "PRIVATE KEY", "-----"].join("") },
  aws: { ruleId: "CRED_AWS_ACCESS_KEY_ID", value: ["AK", "IA", "A".repeat(16)].join("") },
  github: { ruleId: "CRED_GITHUB_TOKEN", value: ["gh", "p_", "b".repeat(20)].join("") },
  anthropic: { ruleId: "CRED_ANTHROPIC_API_KEY", value: ["sk", "-ant-", "c".repeat(20)].join("") },
  openai: { ruleId: "CRED_OPENAI_API_KEY", value: ["sk", "-proj-", "d".repeat(20)].join("") },
  slack: { ruleId: "CRED_SLACK_TOKEN", value: ["xo", "xb-", "e".repeat(10)].join("") },
  google: { ruleId: "CRED_GOOGLE_API_KEY", value: ["AI", "za", "f".repeat(35)].join("") },
  composio: { ruleId: "CRED_COMPOSIO_CONSUMER_KEY", value: ["c", "k_", "g".repeat(20)].join("") },
  uri: { ruleId: "CRED_URI_USERINFO", value: ["https", "://", "synthetic-user", ":", "synthetic-password", "@"].join("") },
  assignment: { ruleId: "CRED_ASSIGNMENT", value: ["client_", "secret=", "h".repeat(12)].join("") },
} satisfies Readonly<Record<string, Candidate>>);

const temporaryRoots: string[] = [];

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function run(command: string, args: readonly string[], cwd?: string): SpawnSyncReturns<string> {
  return spawnSync(command, [...args], {
    cwd,
    encoding: "utf8",
    shell: false,
    timeout: 15_000,
    maxBuffer: 4 * 1024 * 1024,
  });
}

function mustRun(command: string, args: readonly string[], cwd?: string): SpawnSyncReturns<string> {
  const result = run(command, args, cwd);
  expect(result.error).toBeUndefined();
  expect(result.status, result.stderr).toBe(0);
  return result;
}

function candidateHash(value: string): string {
  return `${HASH_PREFIX}${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function allow(repositoryId: string, path: string, candidate: Candidate, occurrenceCount = 1): AllowlistEntry {
  return {
    repository_id: repositoryId,
    path,
    rule_id: candidate.ruleId,
    candidate_sha256: candidateHash(candidate.value),
    occurrence_count: occurrenceCount,
    justification: "synthetic integration fixture",
  };
}

function writeAllowlist(root: string, entries: readonly AllowlistEntry[]): string {
  const path = join(root, `allowlist-${Math.random().toString(16).slice(2)}.json`);
  writeFileSync(path, `${JSON.stringify({ schema_version: "0.1", entries })}\n`, { mode: 0o600 });
  return path;
}

function scan(root: string, repository: string, entries: readonly AllowlistEntry[]): SpawnSyncReturns<string> {
  return run(process.execPath, [
    SCANNER,
    "--allowlist", writeAllowlist(root, entries),
    "--filenames-only",
    "--exclude-env",
    "--exclude-playwright",
    repository,
  ]);
}

function createFixture(): {
  root: string;
  repository: string;
  entries: AllowlistEntry[];
  trackedCandidates: readonly Candidate[];
  untrackedCandidates: readonly Candidate[];
} {
  const root = mkdtempSync(join(tmpdir(), "loopeix-s35-secret-scan-"));
  temporaryRoots.push(root);
  const repository = join(root, "fixture-repository");
  mkdirSync(repository);
  mustRun("git", ["init", "--quiet", repository]);

  const trackedCandidates = [candidates.pem, candidates.aws, candidates.anthropic, candidates.uri, candidates.assignment] as const;
  const untrackedCandidates = [candidates.github, candidates.openai, candidates.slack, candidates.google, candidates.composio] as const;
  const tracked = [
    `left!${candidates.pem.value}!right`,
    `left!${candidates.aws.value}!right`,
    `client_secret=${candidates.anthropic.value}`,
    `${candidates.uri.value}example.invalid/path`,
    candidates.assignment.value,
    candidates.assignment.value,
  ].join("\n");
  const untracked = untrackedCandidates.map((candidate) => `left!${candidate.value}!right`).join("\n");
  writeFileSync(join(repository, "tracked-candidates.txt"), `${tracked}\n`);
  writeFileSync(join(repository, "untracked-candidates.txt"), `${untracked}\n`);
  writeFileSync(join(repository, "benign-boundaries.txt"), [
    "task-main risk-T5",
    `${candidates.aws.value}A`,
    `_${candidates.github.value}_`,
  ].join("\n"));
  mustRun("git", ["-C", repository, "add", "tracked-candidates.txt", "benign-boundaries.txt"]);

  const excludedFiles = [
    join(repository, ".env"),
    join(repository, ".env-private", "trap.txt"),
    join(repository, ".playwright-mcp", "trap.txt"),
    join(repository, "nested", ".env.local"),
    join(repository, "nested", ".playwright-mcp", "trap.txt"),
  ];
  for (const path of excludedFiles) {
    mkdirSync(resolve(path, ".."), { recursive: true });
    writeFileSync(path, `${candidates.openai.value}\n`, { mode: 0o600 });
    chmodSync(path, 0o000);
  }

  const externalFile = join(root, "external-file.txt");
  const externalDirectory = join(root, "external-directory");
  writeFileSync(externalFile, `${candidates.github.value}\n`);
  mkdirSync(externalDirectory);
  writeFileSync(join(externalDirectory, "candidate.txt"), `${candidates.slack.value}\n`);
  symlinkSync(externalFile, join(repository, "visible-file-symlink"));
  symlinkSync(externalDirectory, join(repository, "visible-directory-symlink"));

  const repositoryId = basename(repository);
  const entries = [
    ...trackedCandidates.map((candidate) => allow(repositoryId, "tracked-candidates.txt", candidate, candidate === candidates.assignment ? 2 : 1)),
    ...untrackedCandidates.map((candidate) => allow(repositoryId, "untracked-candidates.txt", candidate)),
  ];
  return { root, repository, entries, trackedCandidates, untrackedCandidates };
}

function sanitizedOutput(result: SpawnSyncReturns<string>): string {
  return `${result.stdout}\n${result.stderr}`;
}

function expectNoCandidateEcho(result: SpawnSyncReturns<string>): void {
  const output = sanitizedOutput(result);
  for (const candidate of Object.values(candidates)) {
    expect(output).not.toContain(candidate.value);
    expect(output).not.toContain(candidateHash(candidate.value));
  }
}

function listedPaths(output: string, repository: string): string[] {
  return output.trim().split(/\r?\n/).filter(Boolean).map((path) => {
    const absolute = resolve(path);
    return absolute.startsWith(`${repository}/`) ? relative(repository, absolute) : path;
  }).sort();
}

describe("S35 authoritative secret scanner", () => {
  it("runs the authoritative scanner against the checked-out repository in CI", () => {
    const workflow = readFileSync(resolve(".github/workflows/ci.yml"), "utf8");
    expect(workflow).toContain([
      "node scripts/scan-secrets-s35.mjs",
      "--allowlist scripts/secret-scan-allowlist-s35.json",
      "--filenames-only",
      "--exclude-env",
      "--exclude-playwright",
      ".",
    ].join("\n          "));
  });

  it("scans tracked and untracked candidates while excluding unreadable and symlink traps", () => {
    const fixture = createFixture();
    const result = scan(fixture.root, fixture.repository, fixture.entries);
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("");

    const enumerated = mustRun("git", [
      "-C", fixture.repository, "ls-files", "-co", "--exclude-standard", "--", ".",
      ":(exclude).env*", ":(exclude).env*/**", ":(exclude)**/.env*", ":(exclude)**/.env*/**",
      ":(exclude).playwright-mcp/**", ":(exclude)**/.playwright-mcp/**",
    ]).stdout.split(/\r?\n/);
    expect(enumerated).toContain("visible-file-symlink");
    expect(enumerated).toContain("visible-directory-symlink");
    expect(enumerated.some((path) => path.includes(".env") || path.includes(".playwright-mcp"))).toBe(false);

    const printed = mustRun(process.execPath, [SCANNER, "--print-grep-ere"]);
    const ere = printed.stdout.trimEnd();
    expect(ere.length).toBeGreaterThan(0);
    const gitResult = mustRun("git", [
      "-C", fixture.repository, "grep", "-l", "-E", ere, "--", ".",
      ":(exclude).env*", ":(exclude).env*/**", ":(exclude)**/.env*", ":(exclude)**/.env*/**",
      ":(exclude).playwright-mcp/**", ":(exclude)**/.playwright-mcp/**",
    ]);
    expect(listedPaths(gitResult.stdout, fixture.repository)).toEqual(["tracked-candidates.txt"]);

    const rgResult = mustRun("rg", [
      "-l", "--hidden", "-g", "!**/.git/**", "-g", "!**/.env*", "-g", "!**/.env*/**",
      "-g", "!**/.playwright-mcp/**", ere, fixture.repository,
    ]);
    expect(listedPaths(rgResult.stdout, fixture.repository)).toEqual([
      "tracked-candidates.txt",
      "untracked-candidates.txt",
    ]);
  }, 20_000);

  it("fails closed for boundary, overlap, and occurrence-count mutations without echoing candidate bytes", () => {
    const fixture = createFixture();

    const wrongCount = fixture.entries.map((entry) => entry.rule_id === "CRED_ASSIGNMENT"
      ? { ...entry, occurrence_count: entry.occurrence_count - 1 }
      : entry);
    const countResult = scan(fixture.root, fixture.repository, wrongCount);
    expect(countResult.status).toBe(1);
    expect(countResult.stderr).toContain("tracked-candidates.txt");
    expect(countResult.stderr).toContain("CRED_ASSIGNMENT");
    expectNoCandidateEcho(countResult);

    const boundaryEntries = fixture.entries.filter((entry) => entry.rule_id !== "CRED_AWS_ACCESS_KEY_ID");
    writeFileSync(join(fixture.repository, "boundary-mutation.txt"), `${candidates.aws.value}A\n`);
    boundaryEntries.push(allow(basename(fixture.repository), "boundary-mutation.txt", candidates.aws));
    const boundaryResult = scan(fixture.root, fixture.repository, boundaryEntries);
    expect(boundaryResult.status).toBe(1);
    expect(boundaryResult.stderr).toContain("boundary-mutation.txt");
    expect(boundaryResult.stderr).toContain("CRED_AWS_ACCESS_KEY_ID");
    expectNoCandidateEcho(boundaryResult);

    const overlapEntries = [...fixture.entries, allow(
      basename(fixture.repository),
      "tracked-candidates.txt",
      { ruleId: "CRED_ASSIGNMENT", value: `client_secret=${candidates.anthropic.value}` },
    )];
    const overlapResult = scan(fixture.root, fixture.repository, overlapEntries);
    expect(overlapResult.status).toBe(1);
    expect(overlapResult.stderr).toContain("tracked-candidates.txt");
    expect(overlapResult.stderr).toContain("CRED_ASSIGNMENT");
    expectNoCandidateEcho(overlapResult);

    const unknownPath = "unknown-candidate.txt";
    writeFileSync(join(fixture.repository, unknownPath), `${candidates.composio.value}\n`);
    const unknownResult = scan(fixture.root, fixture.repository, fixture.entries);
    expect(unknownResult.status).toBe(1);
    expect(unknownResult.stderr).toContain(unknownPath);
    expect(unknownResult.stderr).toContain("CRED_COMPOSIO_CONSUMER_KEY");
    expectNoCandidateEcho(unknownResult);
  }, 20_000);
});
