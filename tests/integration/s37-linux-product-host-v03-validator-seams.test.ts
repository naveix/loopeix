import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import { evaluateS37LinuxPhaseBConformanceEvidence } from "../../scripts/check-s37-linux-phase-b-conformance-evidence.mjs";
import { evaluateS37LinuxPhaseBReadiness } from "../../scripts/check-s37-linux-phase-b-readiness.mjs";

const READINESS_SCRIPT = "scripts/check-s37-linux-phase-b-readiness.mjs";
const CONFORMANCE_SCRIPT = "scripts/check-s37-linux-phase-b-conformance-evidence.mjs";
const CANONICAL_PASS_ARCHIVE = resolve(
  process.cwd(), "../loopeix-specs/docs/evidence/s37-1/trial-7-pass",
);
const roots: string[] = [];

function importModule(path: string) {
  const url = pathToFileURL(path).href;
  return spawnSync(
    process.execPath,
    ["--input-type=module", "--eval", `await import(${JSON.stringify(url)})`],
    { cwd: process.cwd(), encoding: "utf8", shell: false },
  );
}

function readinessCli(evidence: unknown, envelope: unknown, asOf: string) {
  const root = mkdtempSync(join(tmpdir(), "loopeix-s37f1-seam-"));
  roots.push(root);
  const evidencePath = join(root, "readiness.json");
  const envelopePath = join(root, "envelope.json");
  writeFileSync(evidencePath, `${JSON.stringify(evidence)}\n`, "utf8");
  writeFileSync(envelopePath, `${JSON.stringify(envelope)}\n`, "utf8");
  return spawnSync(
    process.execPath,
    [READINESS_SCRIPT, "--evidence", evidencePath, "--envelope", envelopePath, "--as-of", asOf],
    { cwd: process.cwd(), encoding: "utf8", shell: false },
  );
}

function conformanceCli(documents: Record<string, unknown>) {
  const root = mkdtempSync(join(tmpdir(), "loopeix-s37f1-seam-"));
  roots.push(root);
  const mapping = [
    ["--manifest", "manifest"],
    ["--readiness-evidence", "readiness"],
    ["--readiness-envelope", "envelope"],
    ["--profile", "profile"],
    ["--evidence", "evidence"],
    ["--receipt", "receipt"],
  ] as const;
  const args: string[] = [];
  for (const [flag, key] of mapping) {
    const path = join(root, `${key}.json`);
    writeFileSync(path, `${JSON.stringify(documents[key])}\n`, "utf8");
    args.push(flag, path);
  }
  return spawnSync(process.execPath, [CONFORMANCE_SCRIPT, ...args], {
    cwd: process.cwd(), encoding: "utf8", shell: false,
  });
}

function holdLines(stderr: string): string[] {
  return stderr
    .split(/\r?\n/u)
    .filter((line) => line.startsWith("HOLD: "))
    .map((line) => line.slice("HOLD: ".length));
}

function canonicalPassDocument(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(CANONICAL_PASS_ARCHIVE, name), "utf8")) as Record<string, unknown>;
}

afterEach(() => {
  while (roots.length > 0) rmSync(roots.pop()!, { force: true, recursive: true });
});

describe("S37.1-F1 authoritative validator seams", () => {
  it("imports the readiness validator without executing its CLI", () => {
    const result = importModule(READINESS_SCRIPT);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("");
  });

  it("imports the conformance validator without executing its CLI", () => {
    const result = importModule(CONFORMANCE_SCRIPT);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("");
  });

  it("returns the same readiness decision as the CLI for parsed documents", () => {
    const documents = { evidence: {}, envelope: {} };
    const asOf = "2026-08-23T12:00:00.000Z";
    const cli = readinessCli(documents.evidence, documents.envelope, asOf);

    expect(cli.status).toBe(1);
    expect(evaluateS37LinuxPhaseBReadiness({ ...documents, asOf })).toEqual({
      ok: false,
      violations: holdLines(cli.stderr),
    });
  });

  it("returns the same conformance decision as the CLI for parsed documents", () => {
    const documents = {
      manifest: {}, readiness: {}, envelope: {}, profile: {}, evidence: {}, receipt: {},
      asOf: "2026-08-23T12:00:00.000Z",
    };
    const cli = conformanceCli(documents);

    expect(cli.status).toBe(1);
    expect(evaluateS37LinuxPhaseBConformanceEvidence(documents)).toEqual({
      ok: false,
      violations: holdLines(cli.stderr),
    });
  });

  it("returns the same PASS decisions as the CLIs for the canonical trial-seven archive", () => {
    const readiness = canonicalPassDocument("readiness.json");
    const envelope = canonicalPassDocument("envelope.json");
    const evidence = canonicalPassDocument("evidence.json");
    const hostTuple = evidence.host_tuple as Record<string, unknown>;
    const asOf = hostTuple.observed_at;
    expect(typeof asOf).toBe("string");

    const readinessResult = readinessCli(readiness, envelope, asOf as string);
    expect(readinessResult.status, readinessResult.stderr).toBe(0);
    expect(readinessResult.stdout).toBe(
      "S37.1-B passive readiness gate: PASS\nhistorical readiness validation only; not current execution readiness\n",
    );
    expect(evaluateS37LinuxPhaseBReadiness({ evidence: readiness, envelope, asOf })).toEqual({
      ok: true,
      violations: [],
    });

    const documents = {
      manifest: canonicalPassDocument("manifest.json"),
      readiness,
      envelope,
      profile: canonicalPassDocument("product-profile.json"),
      evidence,
      receipt: canonicalPassDocument("receipt.json"),
      asOf,
    };
    const conformanceResult = conformanceCli(documents);
    expect(conformanceResult.status, conformanceResult.stderr).toBe(0);
    expect(conformanceResult.stdout).toBe(
      "S37.1-B conformance evidence gate: PASS\nsealed evidence only; no live host action performed\n",
    );
    expect(evaluateS37LinuxPhaseBConformanceEvidence(documents)).toEqual({
      ok: true,
      violations: [],
    });
  });
});
