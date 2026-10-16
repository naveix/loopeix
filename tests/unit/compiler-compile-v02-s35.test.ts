import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { compileV02ForTest } from "../../src/compiler/compile-v02.js";
import { COMPILE_STORE_SENTINEL_TEXT } from "../../src/compiler/compile-store.js";
import {
  S35_PROJECTION_ORACLES,
  bindingInputForProjectionOracle,
} from "../helpers/s35-projection-oracles.js";

const UTF8 = new TextEncoder();
const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function workspace() {
  const root = mkdtempSync(join(tmpdir(), "loopeix-s35-compile-v02-"));
  roots.push(root);
  const store = join(root, ".loopeix", "compiles");
  mkdirSync(store, { recursive: true });
  writeFileSync(join(store, ".gitignore"), COMPILE_STORE_SENTINEL_TEXT, { mode: 0o600 });
  return { root, store };
}

function safeBugfixPayloadBytes() {
  const oracle = S35_PROJECTION_ORACLES.find(({ entry_id }) => entry_id === "safe-bugfix")!;
  const record = bindingInputForProjectionOracle(oracle) as {
    bindings: Array<Record<string, unknown> & { approved_by: string }>;
  };
  return UTF8.encode(JSON.stringify({
    bindings: record.bindings.map(({ approved_by: _approvedBy, ...binding }) => binding),
  }));
}

const deterministic = {
  now: () => 146,
  randomBytes: () => Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]),
} as const;

describe("S35 V02 compiler coordinator", () => {
  it("writes a manifest-last project-binding HOLD pack without standalone output", async () => {
    const { root, store } = workspace();
    const out = join(root, "draft.loop.yaml");
    const result = await compileV02ForTest({
      prompt: "Fix the failing parser bug and prove the correction.",
      workspace_root: root,
      standalone_output_path: out,
    }, deterministic);

    expect(result).toMatchObject({
      ok: false,
      disposition: "hold",
      terminal_state: "hold-project-binding-required",
      reason: "PROJECT_BINDING_REQUIRED",
      pack_ref: "compile_42_deadbeefcafebabe",
      standalone_ref: null,
    });
    expect(readFileSync(join(store, result.pack_ref!, "pack-manifest.json"), "utf8"))
      .toContain('"terminal_state": "hold-project-binding-required"');
    expect(existsSync(out)).toBe(false);
  });

  it("atomically writes byte-identical compiled pack and standalone YAML", async () => {
    const { root, store } = workspace();
    const out = join(root, "draft.loop.yaml");
    const result = await compileV02ForTest({
      prompt: "Fix the failing parser bug and prove the correction.",
      workspace_root: root,
      binding_payload_bytes: safeBugfixPayloadBytes(),
      standalone_output_path: out,
    }, deterministic);

    expect(result).toEqual({
      ok: true,
      disposition: "compiled",
      terminal_state: "compiled",
      reason: null,
      pack_ref: "compile_42_deadbeefcafebabe",
      standalone_ref: "draft.loop.yaml",
      findings: [],
    });
    expect(readFileSync(join(store, result.pack_ref, "generated.loop.yaml")))
      .toEqual(readFileSync(out));
  });

  it("rejects invalid or sensitive input before clock, entropy, or output", async () => {
    const { root, store } = workspace();
    const now = vi.fn(() => 146);
    const randomBytes = vi.fn(() => new Uint8Array(8));

    await expect(compileV02ForTest({
      prompt: "Fix the failing parser bug.",
      workspace_root: root,
      binding_payload_bytes: UTF8.encode("[]"),
    }, { now, randomBytes })).resolves.toMatchObject({
      ok: false,
      disposition: "rejected",
      reason: "INVALID_DOCUMENT_ENVELOPE",
      pack_ref: null,
    });
    await expect(compileV02ForTest({
      prompt: "Use sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOP.",
      workspace_root: root,
    }, { now, randomBytes })).resolves.toMatchObject({
      ok: false,
      disposition: "rejected",
      reason: "SENSITIVE_INPUT_REJECTED",
      location: "prompt",
      findings: [],
    });
    expect(now).not.toHaveBeenCalled();
    expect(randomBytes).not.toHaveBeenCalled();
    expect(readFileSync(join(store, ".gitignore"), "utf8")).toBe(COMPILE_STORE_SENTINEL_TEXT);
  });

  it("rebuilds candidate-bound bytes after one exclusive-create collision", async () => {
    const { root, store } = workspace();
    mkdirSync(join(store, "compile_42_deadbeefcafebabe"));
    const entropy = [
      Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]),
      Uint8Array.from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
    ];
    const result = await compileV02ForTest({
      prompt: "Fix the failing parser bug and prove the correction.",
      workspace_root: root,
    }, {
      now: () => 146,
      randomBytes: () => entropy.shift()!,
    });

    expect(result.pack_ref).toBe("compile_42_1122334455667788");
    expect(readFileSync(join(store, result.pack_ref!, "work-item.json"), "utf8"))
      .toContain('"work_item_id": "wi_42_1122334455667788"');
  });

  it("does not retry a fixed standalone collision or alter the existing file", async () => {
    const { root, store } = workspace();
    const out = join(root, "existing.loop.yaml");
    writeFileSync(out, "operator-owned\n", { mode: 0o600 });
    const randomBytes = vi.fn(() => Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]));

    const result = await compileV02ForTest({
      prompt: "Fix the failing parser bug and prove the correction.",
      workspace_root: root,
      binding_payload_bytes: safeBugfixPayloadBytes(),
      standalone_output_path: out,
    }, { now: () => 146, randomBytes });

    expect(result).toEqual({
      ok: false,
      disposition: "rejected",
      terminal_state: null,
      reason: "DESTINATION_EXISTS",
      pack_ref: null,
      standalone_ref: null,
      findings: [],
    });
    expect(randomBytes).toHaveBeenCalledOnce();
    expect(readFileSync(out, "utf8")).toBe("operator-owned\n");
    expect(existsSync(join(store, "compile_42_deadbeefcafebabe"))).toBe(false);
  });

  it("returns the collision limit only after sixteen genuine pack collisions", async () => {
    const { root, store } = workspace();
    mkdirSync(join(store, "compile_42_0000000000000000"));
    const randomBytes = vi.fn(() => new Uint8Array(8));

    const result = await compileV02ForTest({
      prompt: "Fix the failing parser bug and prove the correction.",
      workspace_root: root,
    }, { now: () => 146, randomBytes });

    expect(result).toEqual({
      ok: false,
      disposition: "rejected",
      terminal_state: null,
      reason: "COMPILE_ID_COLLISION_LIMIT",
      pack_ref: null,
      standalone_ref: null,
      findings: [],
    });
    expect(randomBytes).toHaveBeenCalledTimes(16);
  });

  it("writes a HOLD pack while leaving an existing requested standalone path untouched", async () => {
    const { root } = workspace();
    const out = join(root, "existing.loop.yaml");
    writeFileSync(out, "operator-owned\n", { mode: 0o600 });

    const result = await compileV02ForTest({
      prompt: "Fix the failing parser bug and prove the correction.",
      workspace_root: root,
      standalone_output_path: out,
    }, deterministic);

    expect(result).toMatchObject({
      ok: false,
      disposition: "hold",
      reason: "PROJECT_BINDING_REQUIRED",
      pack_ref: "compile_42_deadbeefcafebabe",
      standalone_ref: null,
    });
    expect(readFileSync(out, "utf8")).toBe("operator-owned\n");
  });
});
