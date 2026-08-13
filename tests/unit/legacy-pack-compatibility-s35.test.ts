import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  captureStructuredFile,
  releaseCapturedStructuredFile,
  type LegacyCompatibilityPolicy,
} from "../../src/io/captured-file.js";

const roots: string[] = [];
const fixtureRoot = join(import.meta.dirname, "../fixtures/compat/s35/v01");
const finitePolicy: LegacyCompatibilityPolicy = Object.freeze({
  mode: "operator-approved-finite",
  max_member_bytes: 16_777_216,
  max_total_bytes: 33_554_432,
  max_heap_bytes: 134_217_728,
  max_elapsed_ms: 30_000,
  approved_by: "operator",
});

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("S35 finite V01 ledger compatibility", () => {
  it("selects coherent V01 lineage before parsing and preserves the exact oversized bytes", async () => {
    const ledgerPath = join(fixtureRoot, "large-ledger/ledger.jsonl");
    const expected = new Uint8Array(readFileSync(ledgerPath));
    expect(expected.byteLength).toBe(4_196_413);
    expect(createHash("sha256").update(expected).digest("hex")).toBe(
      "b80e811911d1c774391f9c5b44b77bfe4a0622cf094ae08245bdd164d3fbdba8",
    );

    const captured = await captureStructuredFile(ledgerPath, finitePolicy);
    expect(captured.ok).toBe(true);
    if (!captured.ok) throw new Error(captured.message);
    try {
      await expect(captured.capture.selectLedgerV01Lineage("run_s35_large_ledger")).resolves.toEqual({
        ok: true,
        schema_version: "0.1",
        run_id: "run_s35_large_ledger",
      });
      const parsed = await captured.capture.parseV01("ledger-jsonl");
      expect(parsed).toMatchObject({ ok: true, schema_version: "0.1", kind: "ledger-jsonl", byte_length: 4_196_413 });
      const snapshot = await captured.capture.snapshotBytes();
      expect(snapshot.ok).toBe(true);
      if (!snapshot.ok) throw new Error(snapshot.message);
      expect(snapshot.bytes).toEqual(expected);
    } finally {
      await releaseCapturedStructuredFile(captured.capture);
    }
  }, 30_000);

  it("rejects a mismatched receipt run id and never infers V01 from a ledger with no complete event", async () => {
    const large = await captureStructuredFile(join(fixtureRoot, "large-ledger/ledger.jsonl"), finitePolicy);
    expect(large.ok).toBe(true);
    if (!large.ok) throw new Error(large.message);
    try {
      await expect(large.capture.selectLedgerV01Lineage("run_other")).resolves.toMatchObject({
        ok: false,
        reason: "INVALID_V01_DOCUMENT",
      });
    } finally {
      await releaseCapturedStructuredFile(large.capture);
    }

    const root = mkdtempSync(join(tmpdir(), "loopeix-s35-empty-ledger-"));
    roots.push(root);
    const ledgerPath = join(root, "ledger.jsonl");
    writeFileSync(ledgerPath, "\n  \n");
    const empty = await captureStructuredFile(ledgerPath, finitePolicy);
    expect(empty.ok).toBe(true);
    if (!empty.ok) throw new Error(empty.message);
    try {
      await expect(empty.capture.selectLedgerV01Lineage("run_any")).resolves.toMatchObject({
        ok: false,
        reason: "INVALID_V01_DOCUMENT",
      });
    } finally {
      await releaseCapturedStructuredFile(empty.capture);
    }

    writeFileSync(
      ledgerPath,
      '{"schema_version":"0.1","schema_version":"0.1","run_id":"run_any"}\n',
    );
    const duplicate = await captureStructuredFile(ledgerPath, finitePolicy);
    expect(duplicate.ok).toBe(true);
    if (!duplicate.ok) throw new Error(duplicate.message);
    try {
      await expect(duplicate.capture.selectLedgerV01Lineage("run_any")).resolves.toMatchObject({
        ok: false,
        reason: "INVALID_V01_DOCUMENT",
      });
    } finally {
      await releaseCapturedStructuredFile(duplicate.capture);
    }
  }, 30_000);
});
