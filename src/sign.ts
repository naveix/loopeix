import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from "node:crypto";
import { canonicalize } from "./hash.js";

/**
 * Local receipt signer (flagship-decision.md §Signing decision, north-star cosign-compatible path).
 *
 * ECDSA P-256 (prime256v1) with SHA-256 and DER-encoded signatures (`dsaEncoding: "der"`), via
 * node:crypto only — no dependencies, fully offline. The signed preimage is always the UTF-8 bytes
 * of the RFC 8785 canonical form of a value (`canonicalize`), so key insertion order can never
 * change what was signed.
 *
 * Key material convention: the PRIVATE key is PKCS#8 PEM (never persisted by Loopeix — receipt
 * authoring uses an ephemeral in-process key); the PUBLIC key travels inside the signature block
 * as base64 DER SPKI (compact, JSON-embeddable, and directly loadable by any crypto stack).
 *
 * NOTE ON DETERMINISM: node:crypto ECDSA uses a RANDOMIZED nonce (no RFC 6979 deterministic
 * signing), so signing the same value twice yields DIFFERENT signature bytes; only VERIFICATION
 * is deterministic. Tests must therefore do sign→verify roundtrips with ephemeral keys, and
 * byte-golden assertions only against committed pre-signed fixtures.
 *
 * Trust boundary: the SIGNING side (`generateSigningKeyPair`, `signCanonical`) is the trusted
 * producer and throws explicitly on bad inputs. The VERIFYING side (`verifySignatureBlock`) runs
 * against hostile input and NEVER throws — a malformed key, signature, or block is a verification
 * failure (false), not a crash.
 *
 * ECDSA low-S signature malleability is accepted: signatures here carry no identity or
 * anti-replay semantics, so a third party re-encoding a valid signature proves nothing new.
 */

export const SIGNATURE_ALGORITHM = "ecdsa-p256-sha256" as const;
export const SIGNATURE_ENCODING = "der-base64" as const;

export interface SignatureBlockValue {
  algorithm: typeof SIGNATURE_ALGORITHM;
  encoding: typeof SIGNATURE_ENCODING;
  /** DER SPKI public key, base64. */
  public_key_spki_b64: string;
  /** DER-encoded ECDSA signature over SHA-256 of the canonical bytes, base64. */
  signature_b64: string;
}

export interface SigningKeyPair {
  /** PKCS#8 PEM private key. Ephemeral by convention — never commit or persist it. */
  privateKeyPem: string;
  /** DER SPKI public key, base64 (the form embedded in signature blocks). */
  publicKeySpkiB64: string;
}

/** Assert a key is EC P-256; anything else is a caller bug on the trusted signing side. */
function assertP256(key: KeyObject, label: string): void {
  const curve = key.asymmetricKeyDetails?.namedCurve;
  if (key.asymmetricKeyType !== "ec" || curve !== "prime256v1") {
    throw new Error(`${label} must be an EC P-256 (prime256v1) key, got ${key.asymmetricKeyType}/${curve ?? "unknown"}`);
  }
}

/** Generate an ephemeral P-256 signing key pair. */
export function generateSigningKeyPair(): SigningKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { privateKeyPem: privateKey, publicKeySpkiB64: publicKey.toString("base64") };
}

/** Derive the base64 DER SPKI public key from a PKCS#8 private-key PEM (P-256 enforced). */
export function derivePublicKeySpkiB64(privateKeyPem: string): string {
  const key = createPrivateKey(privateKeyPem);
  assertP256(key, "signing key");
  return createPublicKey(key).export({ type: "spki", format: "der" }).toString("base64");
}

/** Sign the RFC 8785 canonical bytes of `value`. Throws on a non-P-256 or malformed private key. */
export function signCanonical(value: unknown, privateKeyPem: string): SignatureBlockValue {
  const key = createPrivateKey(privateKeyPem);
  assertP256(key, "signing key");
  const preimage = Buffer.from(canonicalize(value), "utf8");
  const signature = cryptoSign("sha256", preimage, { key, dsaEncoding: "der" });
  const spki = createPublicKey(key).export({ type: "spki", format: "der" });
  return {
    algorithm: SIGNATURE_ALGORITHM,
    encoding: SIGNATURE_ENCODING,
    public_key_spki_b64: spki.toString("base64"),
    signature_b64: signature.toString("base64"),
  };
}

/**
 * Verify a signature block against the RFC 8785 canonical bytes of `value`.
 * NEVER throws: a malformed block, a non-P-256 or garbage key, undecodable base64, or a
 * non-canonicalizable value all return false (verification failure, not a crash).
 */
export function verifySignatureBlock(value: unknown, block: unknown): boolean {
  try {
    if (typeof block !== "object" || block === null) return false;
    const b = block as Record<string, unknown>;
    if (b.algorithm !== SIGNATURE_ALGORITHM || b.encoding !== SIGNATURE_ENCODING) return false;
    if (typeof b.public_key_spki_b64 !== "string" || typeof b.signature_b64 !== "string") return false;

    const key = createPublicKey({
      key: Buffer.from(b.public_key_spki_b64, "base64"),
      format: "der",
      type: "spki",
    });
    // Fail closed on any key that is not EC P-256 — a different curve/type cannot attest this block.
    if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") return false;

    const preimage = Buffer.from(canonicalize(value), "utf8");
    return cryptoVerify("sha256", preimage, { key, dsaEncoding: "der" }, Buffer.from(b.signature_b64, "base64"));
  } catch {
    return false;
  }
}
