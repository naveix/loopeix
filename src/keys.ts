import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { derivePublicKeySpkiB64, generateSigningKeyPair } from "./sign.js";
import { withLock } from "./lock.js";

/**
 * Workspace signing-key management (flagship M2). The receipt-signing private key lives at
 * `.loopeix/keys/signing-key.pem` (PKCS#8 PEM, file mode 0600) inside the workspace.
 *
 * KEY HYGIENE (non-negotiable): the private key is written to that ONE file and nowhere else —
 * never logged, never embedded in errors, never returned in any CLI output. Callers may print
 * only the short PUBLIC-key fingerprint. The keys directory carries its own `.gitignore` (`*`)
 * written defensively at creation, in addition to the `loopeix init` scaffold, so the key cannot
 * be committed even in a workspace that skipped `init`.
 *
 * CONCURRENT FIRST-GENERATION: first-generation is wrapped in a file lock to prevent two
 * parallel `run start --seal` processes from both generating a key at the same time (TOCTOU
 * race). The lock is `<keysDir>/.gen.lock` and uses the advisory link-based protocol from
 * src/lock.ts. The lock is held only for the write; reads of existing keys are lock-free.
 *
 * PERMISSION ENFORCEMENT: if an existing key file has mode ≠ 0600, it is chmod'd to 0600 before
 * use and the correction is surfaced via `mode_corrected: true` in the returned record.
 */

export interface EnsuredSigningKey {
  /** PKCS#8 PEM. Handle like a secret: sign with it, never print or persist it elsewhere. */
  privateKeyPem: string;
  /** DER SPKI public key, base64 — what receipts embed. */
  publicKeySpkiB64: string;
  /** True when this call generated a new key (callers should announce the fingerprint once). */
  created: boolean;
  /** True when an existing key's file permissions were corrected to 0600. */
  mode_corrected: boolean;
  keyPath: string;
}

/**
 * Load the workspace signing key, generating it (mode 0600, git-ignored) on first use.
 * Throws explicitly on an unreadable or non-P-256 existing key — never signs with garbage.
 */
export function ensureSigningKey(workspaceDir: string): EnsuredSigningKey {
  const keysDir = join(workspaceDir, ".loopeix", "keys");
  const keyPath = join(keysDir, "signing-key.pem");

  if (existsSync(keyPath)) {
    const privateKeyPem = readFileSync(keyPath, "utf8");
    try {
      const publicKeySpkiB64 = derivePublicKeySpkiB64(privateKeyPem);
      // Enforce 0600 on an existing key that may have been created with wrong permissions.
      let mode_corrected = false;
      const mode = statSync(keyPath).mode & 0o777;
      if (mode !== 0o600) {
        chmodSync(keyPath, 0o600);
        mode_corrected = true;
      }
      return { privateKeyPem, publicKeySpkiB64, created: false, mode_corrected, keyPath };
    } catch (err) {
      throw new Error(`existing signing key at ${keyPath} is unusable: ${(err as Error).message}`);
    }
  }

  // First generation: use a file lock to prevent concurrent processes racing to generate.
  const lockPath = join(keysDir, ".gen.lock");
  mkdirSync(keysDir, { recursive: true }); // mkdir before lock so the path exists

  return withLock(lockPath, (): EnsuredSigningKey => {
    // Re-check inside the lock: another process may have generated while we waited.
    if (existsSync(keyPath)) {
      const privateKeyPem = readFileSync(keyPath, "utf8");
      try {
        const publicKeySpkiB64 = derivePublicKeySpkiB64(privateKeyPem);
        let mode_corrected = false;
        const mode = statSync(keyPath).mode & 0o777;
        if (mode !== 0o600) {
          chmodSync(keyPath, 0o600);
          mode_corrected = true;
        }
        return { privateKeyPem, publicKeySpkiB64, created: false, mode_corrected, keyPath };
      } catch (err) {
        throw new Error(`existing signing key at ${keyPath} is unusable: ${(err as Error).message}`);
      }
    }
    writeFileSync(join(keysDir, ".gitignore"), "*\n"); // defensive: key material must never be committed
    const pair = generateSigningKeyPair();
    writeFileSync(keyPath, pair.privateKeyPem, { mode: 0o600 });
    return { privateKeyPem: pair.privateKeyPem, publicKeySpkiB64: pair.publicKeySpkiB64, created: true, mode_corrected: false, keyPath };
  });
}

/** Short display fingerprint of a public key: sha256 over the DER SPKI bytes, first 16 hex. */
export function publicKeyFingerprint(publicKeySpkiB64: string): string {
  return `sha256:${createHash("sha256").update(Buffer.from(publicKeySpkiB64, "base64")).digest("hex").slice(0, 16)}`;
}
