import { describe, expect, it } from "vitest";

import {
  bindPreflightedCompileBindingPayloadV02,
  preflightCompileBindingPayloadV02,
} from "../../src/compiler/binding-input-v02.js";

const UTF8 = new TextEncoder();

const lineage = {
  binding_input_id: "binding_42_deadbeefcafebabe",
  work_item_id: "wi_42_deadbeefcafebabe",
  submitted_at: "1970-01-01T00:00:00Z",
} as const;

describe("S35 V02 binding preflight", () => {
  it("retains omitted bindings as the exact empty envelope before IDs exist", () => {
    const preflight = preflightCompileBindingPayloadV02({
      prompt: "Fix the failing parser test.",
    });

    expect(preflight.ok).toBe(true);
    if (!preflight.ok) return;
    const bound = bindPreflightedCompileBindingPayloadV02(preflight.preflight, lineage);
    expect(bound).toEqual({
      ok: true,
      record: {
        schema_version: "0.2",
        ...lineage,
        bindings: [],
      },
    });
  });

  it("measures exact supplied bytes and rejects a bare array envelope before binding", () => {
    expect(preflightCompileBindingPayloadV02({
      prompt: "Fix the failing parser test.",
      binding_payload_bytes: UTF8.encode("[]"),
    })).toEqual({
      ok: false,
      reason: "INVALID_DOCUMENT_ENVELOPE",
      message: "Binding input must be one object envelope.",
    });

    const oversizedWhitespace = UTF8.encode(`{\"bindings\":[]}${" ".repeat(4_194_304)}`);
    expect(preflightCompileBindingPayloadV02({
      prompt: "x",
      binding_payload_bytes: oversizedWhitespace,
    })).toEqual({
      ok: false,
      reason: "INPUT_TOO_LARGE",
      message: "Prompt and binding input exceed 4194304 bytes.",
    });
  });

  it("scans sensitive input before IDs and exposes no rejected value", () => {
    const result = preflightCompileBindingPayloadV02({
      prompt: "Use sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOP.",
    });

    expect(result).toMatchObject({
      ok: false,
      reason: "SENSITIVE_INPUT_REJECTED",
      location: "prompt",
      binding_key: null,
    });
    expect(JSON.stringify(result)).not.toContain("abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOP");
  });

  it("rebuilds candidate records while rejecting forged preflight lookalikes", () => {
    const preflight = preflightCompileBindingPayloadV02({ prompt: "Fix the parser." });
    expect(preflight.ok).toBe(true);
    if (!preflight.ok) return;

    expect(bindPreflightedCompileBindingPayloadV02(preflight.preflight, lineage).ok).toBe(true);
    expect(bindPreflightedCompileBindingPayloadV02(preflight.preflight, lineage).ok).toBe(true);
    expect(bindPreflightedCompileBindingPayloadV02(preflight.preflight, {
      ...lineage,
      binding_input_id: "binding_42_0011223344556677",
      work_item_id: "wi_42_0011223344556677",
    }).ok).toBe(true);
    expect(bindPreflightedCompileBindingPayloadV02({} as never, lineage)).toEqual({
      ok: false,
      reason: "INVALID_BINDING_INPUT",
      message: "Binding preflight is invalid.",
    });
  });
});
