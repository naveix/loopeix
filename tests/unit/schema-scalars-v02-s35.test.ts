import { describe, expect, it } from "vitest";

import {
  FreeControlStringV02,
  HumanIdV02,
  IsoTimestampV02,
  MachineIdV02,
  NonBlankStringV02,
  RelativeRunPathV02,
  UnicodeScalarStringV02,
  boundedArrayV02,
  boundedNonBlankStringV02,
  boundedStringV02,
} from "../../src/schema/scalars-v02.js";

describe("V02 canonical scalar contracts", () => {
  it("accepts only canonical HumanId values within 1..128 ASCII bytes", () => {
    expect(HumanIdV02.parse("a")).toBe("a");
    expect(HumanIdV02.parse(`a${"0".repeat(127)}`)).toHaveLength(128);

    for (const value of ["0abc", "A", "a_b", "a--b", "a-", `a${"0".repeat(128)}`, "é"]) {
      expect(HumanIdV02.safeParse(value).success, value).toBe(false);
    }
  });

  it("accepts only canonical MachineId values within 3..160 ASCII bytes", () => {
    expect(MachineIdV02.parse("a_b")).toBe("a_b");
    expect(MachineIdV02.parse(`a_${"0".repeat(158)}`)).toHaveLength(160);

    for (const value of ["ab", "0_ab", "a-b", "a__b", "a_", `a_${"0".repeat(159)}`, "é_a"]) {
      expect(MachineIdV02.safeParse(value).success, value).toBe(false);
    }
  });

  it("keeps HumanId and MachineId domains disjoint", () => {
    for (const value of ["expert-sprint", "run_abc123"]) {
      expect(Number(HumanIdV02.safeParse(value).success) + Number(MachineIdV02.safeParse(value).success)).toBe(1);
    }
  });

  it("accepts only valid second-precision UTC timestamps in the exact 20-byte form", () => {
    expect(IsoTimestampV02.parse("2026-08-10T13:14:15Z")).toBe("2026-08-10T13:14:15Z");
    expect(IsoTimestampV02.parse("2024-02-29T00:00:00Z")).toBe("2024-02-29T00:00:00Z");

    for (const value of [
      "2026-08-10T13:14:15.000Z",
      "2026-08-10T13:14:15+00:00",
      "2026-08-10t13:14:15z",
      "2026-02-30T13:14:15Z",
      "2025-02-29T00:00:00Z",
      "2026-08-10T24:00:00Z",
    ]) {
      expect(IsoTimestampV02.safeParse(value).success, value).toBe(false);
    }
  });

  it("rejects unpaired UTF-16 surrogates without rejecting astral scalar values", () => {
    expect(UnicodeScalarStringV02.parse("A😀Z")).toBe("A😀Z");
    expect(UnicodeScalarStringV02.safeParse("\ud800").success).toBe(false);
    expect(UnicodeScalarStringV02.safeParse("\udc00").success).toBe(false);
    expect(UnicodeScalarStringV02.safeParse("ok\ud800tail").success).toBe(false);
  });

  it("requires non-blank strings without replacing their stored value", () => {
    expect(NonBlankStringV02.parse("  value  ")).toBe("  value  ");
    expect(NonBlankStringV02.safeParse(" \n\t ").success).toBe(false);
    expect(NonBlankStringV02.safeParse("a".repeat(16_384)).success).toBe(true);
    expect(NonBlankStringV02.safeParse("a".repeat(16_385)).success).toBe(false);
    expect(NonBlankStringV02.safeParse("😀".repeat(4_096)).success).toBe(true);
    expect(NonBlankStringV02.safeParse(`${"😀".repeat(4_096)}a`).success).toBe(false);
  });

  it("enforces UTF-8 byte ceilings, not UTF-16 code-unit counts", () => {
    const fourByteScalar = "😀";
    expect(boundedStringV02(4).parse(fourByteScalar)).toBe(fourByteScalar);
    expect(boundedStringV02(3).safeParse(fourByteScalar).success).toBe(false);
    expect(boundedNonBlankStringV02(4).parse(fourByteScalar)).toBe(fourByteScalar);

    expect(FreeControlStringV02.parse("x".repeat(16_384))).toHaveLength(16_384);
    expect(FreeControlStringV02.safeParse("x".repeat(16_385)).success).toBe(false);
  });

  it("accepts only normalized run-relative paths within byte and segment ceilings", () => {
    expect(RelativeRunPathV02.parse("artifacts/😀.json")).toBe("artifacts/😀.json");
    expect(RelativeRunPathV02.parse("a".repeat(1_024))).toHaveLength(1_024);
    expect(RelativeRunPathV02.parse(Array.from({ length: 32 }, (_, index) => `s${index}`).join("/"))).toContain("/");

    const invalid = [
      "",
      "/absolute",
      "C:/drive",
      "C:\\drive",
      "a\\b",
      "a//b",
      "./a",
      "a/./b",
      "a/../b",
      "a/",
      "a\0b",
      Array.from({ length: 33 }, () => "s").join("/"),
      "a".repeat(1_025),
      "😀".repeat(257),
      "\ud800",
    ];
    for (const value of invalid) expect(RelativeRunPathV02.safeParse(value).success, value).toBe(false);
  });

  it("provides an explicit bounded-array primitive with enforced cardinality", () => {
    const Pair = boundedArrayV02(HumanIdV02, { min: 1, max: 2 });
    expect(Pair.parse(["a", "b"])).toEqual(["a", "b"]);
    expect(Pair.safeParse([]).success).toBe(false);
    expect(Pair.safeParse(["a", "b", "c"]).success).toBe(false);
  });

  it("rejects invalid reusable-bound declarations immediately", () => {
    expect(() => boundedStringV02(0)).toThrow(/positive integer/);
    expect(() => boundedArrayV02(HumanIdV02, { min: 3, max: 2 })).toThrow(/valid integer range/);
  });
});
