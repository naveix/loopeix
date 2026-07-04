import { createPublicKey, generateKeyPairSync, verify as cryptoVerify } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalize } from "../../src/hash.js";
import { generateSigningKeyPair, signCanonical, verifySignatureBlock } from "../../src/sign.js";

// ECDSA signing is RANDOMIZED (see src/sign.ts NOTE), so these tests do sign→verify
// roundtrips with ephemeral keys; byte-golden signature assertions live only against the
// committed pre-signed receipt fixtures (receipt.test.ts).

const keys = generateSigningKeyPair();
const value = { b: 2, a: [1, "x"], nested: { z: true, n: null } };
const block = signCanonical(value, keys.privateKeyPem);

describe("sign→verify roundtrip", () => {
  it("a freshly signed value verifies", () => {
    expect(verifySignatureBlock(value, block)).toBe(true);
  });

  it("the preimage is canonical: key insertion order does not matter", () => {
    const reordered = { nested: { n: null, z: true }, a: [1, "x"], b: 2 };
    expect(verifySignatureBlock(reordered, block)).toBe(true);
  });

  it("the embedded public key matches the generated pair", () => {
    expect(block.public_key_spki_b64).toBe(keys.publicKeySpkiB64);
  });

  it("two signatures over the same value differ (randomized nonce) and both verify", () => {
    const again = signCanonical(value, keys.privateKeyPem);
    expect(again.signature_b64).not.toBe(block.signature_b64);
    expect(verifySignatureBlock(value, again)).toBe(true);
  });

  it("a tampered value fails verification", () => {
    expect(verifySignatureBlock({ ...value, b: 3 }, block)).toBe(false);
  });

  it("a wrong (substituted) public key fails verification", () => {
    const other = generateSigningKeyPair();
    expect(verifySignatureBlock(value, { ...block, public_key_spki_b64: other.publicKeySpkiB64 })).toBe(false);
  });

  it("a signature from a different key fails against this key's block layout", () => {
    const other = generateSigningKeyPair();
    const otherBlock = signCanonical(value, other.privateKeyPem);
    expect(verifySignatureBlock(value, { ...block, signature_b64: otherBlock.signature_b64 })).toBe(false);
  });
});

describe("verifySignatureBlock never throws on malformed input (fails closed)", () => {
  const cases: [string, unknown][] = [
    ["null block", null],
    ["number block", 42],
    ["empty object", {}],
    ["wrong algorithm", { ...block, algorithm: "ed25519" }],
    ["wrong encoding", { ...block, encoding: "ieee-p1363-base64" }],
    ["non-string key field", { ...block, public_key_spki_b64: 7 }],
    ["non-string signature field", { ...block, signature_b64: ["x"] }],
    ["garbage base64 key", { ...block, public_key_spki_b64: "AAAA////" }],
    ["garbage base64 signature", { ...block, signature_b64: "AAAA" }],
    ["empty-string fields", { ...block, public_key_spki_b64: "", signature_b64: "" }],
  ];
  for (const [name, bad] of cases) {
    it(name, () => {
      expect(verifySignatureBlock(value, bad)).toBe(false);
    });
  }

  it("a non-P-256 key (Ed25519 SPKI) is rejected even with the right labels", () => {
    const ed = generateKeyPairSync("ed25519", { publicKeyEncoding: { type: "spki", format: "der" } });
    expect(verifySignatureBlock(value, { ...block, public_key_spki_b64: ed.publicKey.toString("base64") })).toBe(false);
  });

  it("a non-canonicalizable value is a verification failure, not a crash", () => {
    expect(verifySignatureBlock(undefined, block)).toBe(false);
    expect(verifySignatureBlock({ x: Number.POSITIVE_INFINITY }, block)).toBe(false);
  });
});

describe("algorithm introspection (node:crypto)", () => {
  it("block carries the pinned algorithm labels", () => {
    expect(block.algorithm).toBe("ecdsa-p256-sha256");
    expect(block.encoding).toBe("der-base64");
  });

  it("the embedded SPKI decodes to an EC P-256 (prime256v1) key", () => {
    const key = createPublicKey({ key: Buffer.from(block.public_key_spki_b64, "base64"), format: "der", type: "spki" });
    expect(key.asymmetricKeyType).toBe("ec");
    expect(key.asymmetricKeyDetails?.namedCurve).toBe("prime256v1");
  });

  it("the signature is DER: SEQUENCE of two INTEGERs with exact length framing", () => {
    const sig = Buffer.from(block.signature_b64, "base64");
    expect(sig[0]).toBe(0x30); // SEQUENCE
    expect(sig[1]).toBe(sig.length - 2); // single-byte length (P-256 sigs are < 128 bytes)
    expect(sig[2]).toBe(0x02); // first INTEGER (r)
    const rLen = sig[3]!;
    expect(sig[4 + rLen]).toBe(0x02); // second INTEGER (s)
  });

  it("the digest is SHA-256: manual node:crypto verification agrees, SHA-512 does not", () => {
    const key = createPublicKey({ key: Buffer.from(block.public_key_spki_b64, "base64"), format: "der", type: "spki" });
    const preimage = Buffer.from(canonicalize(value), "utf8");
    const sig = Buffer.from(block.signature_b64, "base64");
    expect(cryptoVerify("sha256", preimage, { key, dsaEncoding: "der" }, sig)).toBe(true);
    expect(cryptoVerify("sha512", preimage, { key, dsaEncoding: "der" }, sig)).toBe(false);
  });
});
