import { describe, expect, it } from "vitest";
import { buildSupportBundle, isExpired, redact, scanForLeaks } from "../../src/index.js";

const DAY = 24 * 60 * 60 * 1000;
const asObj = (v: unknown) => v as Record<string, unknown>;

describe("redact — sensitive keys and secret value patterns", () => {
  it("scrubs the value of a sensitive KEY regardless of content", () => {
    const { redacted } = redact({ api_key: "abc123", authorization: "whatever", password: "hunter2" });
    const o = asObj(redacted);
    expect(o.api_key).toBe("<REDACTED>");
    expect(o.authorization).toBe("<REDACTED>");
    expect(o.password).toBe("<REDACTED>");
  });
  it("scrubs a secret VALUE pattern even under an innocuous key", () => {
    const { redacted } = redact({ note: "the key is sk-ant-abcdefghijklmnop and a token" });
    expect(asObj(redacted).note).not.toContain("sk-ant-");
    expect(asObj(redacted).note).toContain("<REDACTED>");
  });
  it("scrubs a database URL with credentials", () => {
    const { redacted } = redact({ dsn: "postgres://user:pass@host:5432/db" });
    expect(asObj(redacted).dsn).toBe("<REDACTED>");
  });
  it("PRESERVES a non-secret ledger hash under a non-sensitive key", () => {
    const hash = `sha256:${"a".repeat(64)}`;
    const { redacted } = redact({ event_hash: hash, sequence: 3, run_id: "run_abc" });
    const o = asObj(redacted);
    expect(o.event_hash).toBe(hash); // NOT redacted — hashes are not secrets
    expect(o.sequence).toBe(3);
    expect(o.run_id).toBe("run_abc");
  });
  it("recurses into nested objects and arrays", () => {
    const { redacted, count } = redact({ outer: { items: [{ token: "sekret" }, { ok: 1 }] } });
    const items = (asObj(asObj(redacted).outer).items as Record<string, unknown>[]);
    expect(items[0]!.token).toBe("<REDACTED>");
    expect(items[1]!.ok).toBe(1);
    expect(count).toBeGreaterThan(0);
  });
});

describe("scanForLeaks — the quarantine check", () => {
  it("flags raw secrets, and is clean after redaction", () => {
    const raw = { note: "Bearer abcdefghijklmnop12345" };
    expect(scanForLeaks(raw).clean).toBe(false);
    const { redacted } = redact(raw);
    expect(scanForLeaks(redacted).clean).toBe(true);
  });
});

describe("isExpired — retention classes", () => {
  it("short expires after 7 days", () => {
    expect(isExpired("short", 8 * DAY)).toBe(true);
    expect(isExpired("short", 1 * DAY)).toBe(false);
  });
  it("run / project / quarantine never age out automatically", () => {
    expect(isExpired("run", 3650 * DAY)).toBe(false);
    expect(isExpired("project", 3650 * DAY)).toBe(false);
    expect(isExpired("quarantine", 3650 * DAY)).toBe(false);
  });
});

describe("buildSupportBundle — redact then verify no leak", () => {
  it("produces a redacted bundle that passes the leak scan (safe to share)", () => {
    const r = buildSupportBundle({
      run_id: "run_x",
      contents: { command: "curl -H 'Authorization: Bearer abcdefghijklmnop12345'", api_key: "sk-abcdefghijklmnopqrstuvwx" },
    });
    expect(r.safe_to_share).toBe(true);
    expect(r.leak_scan.clean).toBe(true);
    expect(r.bundle.redaction.count).toBeGreaterThan(0);
    expect(JSON.stringify(r.bundle)).not.toContain("sk-abcdefghijkl");
  });
});

describe("redaction — expanded provider + .env coverage (S16 audit fixes)", () => {
  const providers: Array<[string, string]> = [
    ["Stripe secret key", "sk_live_51Habcdefghijklmnopqrstuv"],
    ["AWS access key", "AKIAIOSFODNN7EXAMPLE"],
    ["Google API key", "AIzaSyD-abcdefghijklmnopqrstuvwxyz12"],
    ["JWT", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij"],
    ["GitHub PAT", "github_pat_11ABCDEFG0abcdefghijklmnop"],
  ];
  for (const [name, secret] of providers) {
    it(`redacts a ${name} under an innocuous key`, () => {
      const { redacted } = redact({ note: `value ${secret}` });
      expect(String(asObj(redacted).note)).not.toContain(secret);
    });
  }
  it("redacts a .env-style assignment", () => {
    const { redacted } = redact({ stdout: "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIabcdefghijklmnop" });
    expect(String(asObj(redacted).stdout)).not.toContain("wJalrXUtnFEMI");
  });
  it("redacts a value under a bare 'key' or 'pwd' field", () => {
    const { redacted } = redact({ key: "9f8a7b6c5d4e3f2a", db_pwd: "s3cr3tvalue" });
    expect(asObj(redacted).key).toBe("<REDACTED>");
    expect(asObj(redacted).db_pwd).toBe("<REDACTED>");
  });
});

describe("scanForLeaks — independent backstop (not a redactor replay)", () => {
  it("flags a high-entropy token the pattern set does not recognize", () => {
    expect(scanForLeaks({ note: "Zx9Qw3Er7Ty1Ui5Op2As8Df4Gh6Jk0Lm3Nb7Vc1X" }).clean).toBe(false);
  });
  it("flags a value left under a sensitive key that was not redacted", () => {
    expect(scanForLeaks({ api_key: "not-redacted-somehow" }).clean).toBe(false);
  });
  it("does NOT flag a ledger hash or UUID (not secrets)", () => {
    expect(scanForLeaks({ event_hash: `sha256:${"a".repeat(64)}`, id: "12345678-1234-1234-1234-123456789abc" }).clean).toBe(true);
  });
});

describe("retention + bundle robustness (S16 audit)", () => {
  it("isExpired fails closed on an unknown class (treated as short)", () => {
    expect(isExpired("bogus", 8 * DAY)).toBe(true);
    expect(isExpired("bogus", 1 * DAY)).toBe(false);
  });
  it("buildSupportBundle refuses to share an unredacted high-entropy secret (backstop end-to-end)", () => {
    const r = buildSupportBundle({ run_id: "run_x", contents: { misc: "Zx9Qw3Er7Ty1Ui5Op2As8Df4Gh6Jk0Lm3Nb7Vc1X" } });
    expect(r.safe_to_share).toBe(false);
  });
  it("buildSupportBundle handles circular input without crashing (cycle-guarded)", () => {
    const circular: Record<string, unknown> = { a: 1 };
    circular.self = circular;
    expect(() => buildSupportBundle({ run_id: "run_x", contents: circular })).not.toThrow();
  });
});
