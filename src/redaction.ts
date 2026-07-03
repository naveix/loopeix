/**
 * Redaction, retention, and support-bundle enforcement (S16; redaction-retention-policy.md).
 *
 * Defense-in-depth, FAIL-CLOSED:
 *  - `redact` deep-scrubs (a) values under secret-like KEYS and (b) string values matching secret
 *    PATTERNS. Conservative (privacy over completeness): may over-redact a field whose key merely
 *    resembles a secret (e.g. `*_tokens`, `session_id`). Preserves ledger hashes (not secrets).
 *  - `scanForLeaks` is an INDEPENDENT quarantine check, NOT a replay of the redactor: it walks the
 *    structure and flags (a) any value under a sensitive key that is not exactly `<REDACTED>`, (b) any
 *    secret PATTERN, and (c) any high-entropy token-shaped string (the backstop for unknown secret
 *    shapes the redactor's key/pattern signals miss). `buildSupportBundle` redacts THEN scans; a
 *    bundle is `safe_to_share` only if the independent scan is clean.
 */

export const REDACTION_POLICY_VERSION = "0.1";
const REDACTED = "<REDACTED>";

const SENSITIVE_KEY_TERMS: readonly string[] = [
  "apikey",
  "key",
  "token",
  "authorization",
  "password",
  "passwd",
  "pwd",
  "pgpassword",
  "secret",
  "cookie",
  "credential",
  "privatekey",
  "databaseurl",
  "dburl",
  "connectionstring",
  "accesskey",
  "clientsecret",
  "bearer",
  "oauth",
  "session",
  "pat",
  "pin",
  "ssh",
  "gpg",
  "salt",
  "pem",
  "cert",
];

/** String value patterns that indicate a secret regardless of key. */
export const SECRET_VALUE_PATTERNS: readonly RegExp[] = [
  /sk-ant-[A-Za-z0-9_-]{12,}/g, // Anthropic
  /sk-[A-Za-z0-9_-]{16,}/g, // OpenAI-style
  /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/g, // Stripe secret/restricted keys (underscore)
  /\bAKIA[0-9A-Z]{16}\b/g, // AWS access key id
  /\bAIza[0-9A-Za-z_-]{20,}\b/g, // Google API key
  /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}/g, // JWT (OAuth/session)
  /\bgithub_pat_[A-Za-z0-9_]{20,}/g, // GitHub fine-grained PAT
  /\bgh[pousr]_[A-Za-z0-9]{16,}/g, // GitHub classic tokens
  /\bxox[baprs]-[A-Za-z0-9-]{8,}/g, // Slack
  /\bnpm_[A-Za-z0-9]{20,}/g, // npm
  /\bpypi-[A-Za-z0-9_-]{16,}/g, // PyPI
  /Bearer\s+[A-Za-z0-9._-]{12,}/gi, // bearer tokens
  /Basic\s+[A-Za-z0-9+/=]{12,}/g, // HTTP Basic auth
  /(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s"']+/gi, // DB connection URLs
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/g, // PEM private keys
  // .env / assignment style: an identifier that CONTAINS a secret word, `=`/`:`, then a value.
  /\b[\w.-]*(?:password|passwd|pwd|pgpassword|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)[\w.-]*\s*[=:]\s*["']?[^\s"']{3,}/gi,
];

const normKey = (k: string): string => k.toLowerCase().replace(/[^a-z0-9]/g, "");
const keyIsSensitive = (k: string): boolean => {
  const nk = normKey(k);
  return SENSITIVE_KEY_TERMS.some((t) => nk.includes(t));
};

function shannonEntropy(s: string): number {
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let e = 0;
  for (const c of freq.values()) {
    const p = c / s.length;
    e -= p * Math.log2(p);
  }
  return e;
}

/** Token-shaped, random-looking string likely to be a secret the key/pattern signals missed. */
function looksHighEntropy(s: string): boolean {
  const t = s.trim();
  if (t.length < 24 || t === REDACTED) return false;
  if (/\s/.test(t)) return false; // sentences/commands have whitespace
  if (/^(?:sha256:|sha1:|md5:)?[0-9a-f]{32,128}$/i.test(t)) return false; // ledger/content hashes
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(t)) return false; // UUID
  if (!/[A-Za-z]/.test(t) || !/[0-9]/.test(t)) return false; // require mixed letters + digits
  return shannonEntropy(t) >= 3.6;
}

export function redact(data: unknown): { redacted: unknown; count: number } {
  let count = 0;
  const seen = new WeakSet<object>();
  const redactString = (s: string): string => {
    let out = s;
    for (const re of SECRET_VALUE_PATTERNS) {
      out = out.replace(re, () => {
        count += 1;
        return REDACTED;
      });
    }
    return out;
  };
  const walk = (v: unknown, forced: boolean): unknown => {
    if (forced) {
      count += 1;
      return REDACTED;
    }
    if (typeof v === "string") return redactString(v);
    if (Array.isArray(v)) return v.map((x) => walk(x, false));
    if (v !== null && typeof v === "object") {
      if (seen.has(v)) return "[circular]";
      seen.add(v);
      const out: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(v)) out[k] = walk(val, keyIsSensitive(k));
      return out;
    }
    return v;
  };
  return { redacted: walk(data, false), count };
}

/**
 * INDEPENDENT quarantine scan (does not reuse the redactor's decisions). Flags a value left under a
 * sensitive key, any secret pattern, or a high-entropy token-shaped string. Never throws.
 */
export function scanForLeaks(data: unknown): { clean: boolean; hits: string[] } {
  const hits: string[] = [];
  const checkString = (s: string, ctx: string): void => {
    for (const re of SECRET_VALUE_PATTERNS) {
      if (new RegExp(re.source, re.flags.replace("g", "")).test(s)) hits.push(`pattern ${re.source} @ ${ctx}`);
    }
    if (looksHighEntropy(s)) hits.push(`high-entropy string @ ${ctx}`);
  };
  const seen = new WeakSet<object>();
  const walk = (v: unknown, keySensitive: boolean, ctx: string): void => {
    if (typeof v === "string") {
      if (keySensitive && v !== REDACTED) hits.push(`unredacted value under sensitive key @ ${ctx}`);
      checkString(v, ctx);
      return;
    }
    if (Array.isArray(v)) {
      v.forEach((x, i) => walk(x, false, `${ctx}[${i}]`));
      return;
    }
    if (v !== null && typeof v === "object") {
      if (seen.has(v)) return;
      seen.add(v);
      for (const [k, val] of Object.entries(v)) walk(val, keyIsSensitive(k), ctx ? `${ctx}.${k}` : k);
    }
  };
  walk(data, false, "");
  return { clean: hits.length === 0, hits: [...new Set(hits)] };
}

export const RETENTION_CLASSES = ["short", "run", "project", "quarantine"] as const;

/** Default retention TTL per class in ms; null = kept until explicit run/workspace/user deletion. */
export const RETENTION_TTL_MS: Record<string, number | null> = {
  short: 7 * 24 * 60 * 60 * 1000, // 7 days
  run: null,
  project: null,
  quarantine: null,
};

/** Fail-closed: an unknown class is treated as `short` (age out) rather than kept forever. */
export function isExpired(retentionClass: string, ageMs: number): boolean {
  const ttl = retentionClass in RETENTION_TTL_MS ? RETENTION_TTL_MS[retentionClass] : RETENTION_TTL_MS.short;
  return typeof ttl === "number" && ageMs > ttl;
}

export interface SupportBundle {
  run_id: string;
  redaction: { policy_version: string; count: number };
  contents: unknown;
}

/**
 * Build a redacted support bundle and verify it before it can be shared: redact, then run the
 * INDEPENDENT quarantine scan. Fails closed (`safe_to_share:false`) on any residual leak OR on a
 * redaction/serialisation error (e.g. non-serialisable input).
 */
export function buildSupportBundle(input: { run_id: string; contents: unknown }): {
  bundle: SupportBundle;
  leak_scan: { clean: boolean; hits: string[] };
  safe_to_share: boolean;
} {
  try {
    const { redacted, count } = redact(input.contents);
    const bundle: SupportBundle = {
      run_id: input.run_id,
      redaction: { policy_version: REDACTION_POLICY_VERSION, count },
      contents: redacted,
    };
    const leak_scan = scanForLeaks(bundle);
    return { bundle, leak_scan, safe_to_share: leak_scan.clean };
  } catch (e) {
    return {
      bundle: { run_id: input.run_id, redaction: { policy_version: REDACTION_POLICY_VERSION, count: 0 }, contents: null },
      leak_scan: { clean: false, hits: [`redaction failed: ${(e as Error).message}`] },
      safe_to_share: false,
    };
  }
}
