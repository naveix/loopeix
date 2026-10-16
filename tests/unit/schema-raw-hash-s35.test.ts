import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import * as hashing from "../../src/hash.js";

describe("S35 raw byte hashing", () => {
  it("hashes the exact Uint8Array bytes without changing string hashing", () => {
    const raw = Uint8Array.from([0xef, 0xbb, 0xbf, 0x0a, 0xff, 0x00]);
    const expected = `sha256:${createHash("sha256").update(raw).digest("hex")}`;

    expect(hashing.hashBytes("hello")).toBe(
      "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    );
    expect(hashing.hashRawBytes(raw)).toBe(expected);
  });
});
