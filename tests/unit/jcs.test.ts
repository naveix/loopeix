/**
 * RFC 8785 (JSON Canonicalization Scheme) compliance test.
 *
 * Input/output pairs are vendored from the cyberphone/json-canonicalization
 * reference testdata (github.com/cyberphone/json-canonicalization).  Each test
 * parses the input JSON, runs it through the project's canonicalize() wrapper,
 * and compares byte-for-byte against the reference output.
 *
 * Output fixture files are stored without a trailing newline; .trim() is applied
 * defensively for editors that add one.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { canonicalize } from "../../src/hash.js";

const fixturesDir = join(import.meta.dirname, "../fixtures/jcs");

function load(name: string): { input: unknown; expected: string } {
  const input = JSON.parse(
    readFileSync(join(fixturesDir, `${name}.input.json`), "utf8"),
  ) as unknown;
  const expected = readFileSync(
    join(fixturesDir, `${name}.output.json`),
    "utf8",
  ).trim();
  return { input, expected };
}

describe("RFC 8785 JCS canonicalization", () => {
  it("structures — nested objects, special keys, Unicode escape in key", () => {
    const { input, expected } = load("structures");
    expect(canonicalize(input)).toBe(expected);
  });

  it("unicode — key sort follows UTF-16 code-unit order (U+0070 < U+00C4)", () => {
    const { input, expected } = load("unicode");
    expect(canonicalize(input)).toBe(expected);
  });

  it("arrays — array element order is preserved, nested object keys sorted", () => {
    const { input, expected } = load("arrays");
    expect(canonicalize(input)).toBe(expected);
  });

  it("values — numbers use ES6 serialisation (-0 → 0, no unnecessary exponents)", () => {
    const { input, expected } = load("values");
    expect(canonicalize(input)).toBe(expected);
  });

  it("integer-like key ordering — RFC 8785 UTF-16 code-point order, not V8 numeric hoisting", () => {
    // V8's plain JSON.stringify hoists integer-like keys ("9","10") into numeric order
    // giving {"9":2,"10":1}; JCS sorts by code-unit value so "1" (0x31) < "9" (0x39),
    // yielding {"10":1,"9":2}.  This is the latent bug the old sorted-key impl shared.
    expect(canonicalize({ "9": 2, "10": 1 })).toBe('{"10":1,"9":2}');
  });
});
