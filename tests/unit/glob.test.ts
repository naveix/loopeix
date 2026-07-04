import { describe, expect, it } from "vitest";
import { globToRegExp, matchesAnyGlob, matchesGlob, normalizePath } from "../../src/glob.js";

describe("glob matcher — the exact documented subset", () => {
  it("`src/**` matches everything under src/, NOT the bare file and NOT prefix collisions", () => {
    expect(matchesGlob("src/a.ts", "src/**")).toBe(true);
    expect(matchesGlob("src/a/b/c.ts", "src/**")).toBe(true);
    expect(matchesGlob("src", "src/**")).toBe(false); // the bare file `src` is not under src/
    expect(matchesGlob("src2/a.ts", "src/**")).toBe(false); // src2/ vs src/** prefix collision
    expect(matchesGlob("mysrc/a.ts", "src/**")).toBe(false);
  });

  it("nested ** matches zero or more whole segments", () => {
    expect(matchesGlob("a/b", "a/**/b")).toBe(true); // zero segments
    expect(matchesGlob("a/x/b", "a/**/b")).toBe(true);
    expect(matchesGlob("a/x/y/z/b", "a/**/b")).toBe(true);
    expect(matchesGlob("a/xb", "a/**/b")).toBe(false);
    expect(matchesGlob("**/x", "**/x")).toBe(true);
    expect(matchesGlob("x", "**/x")).toBe(true);
    expect(matchesGlob("deep/er/x", "**/x")).toBe(true);
    expect(matchesGlob("deep/er/xy", "**/x")).toBe(false);
  });

  it("a trailing / means the directory and everything under it", () => {
    expect(matchesGlob("tests/unit/a.test.ts", "tests/")).toBe(true);
    expect(matchesGlob("tests", "tests/")).toBe(false);
    expect(matchesGlob("tests2/a.ts", "tests/")).toBe(false);
  });

  it("* stays within one segment and matches dotfiles; ? is exactly one character", () => {
    expect(matchesGlob("src/a.ts", "src/*.ts")).toBe(true);
    expect(matchesGlob("src/a/b.ts", "src/*.ts")).toBe(false); // * never crosses /
    expect(matchesGlob("src/.env", "src/*")).toBe(true); // dotfiles are matched (documented)
    expect(matchesGlob(".github/workflows/ci.yml", ".github/**")).toBe(true);
    expect(matchesGlob("a/b1.ts", "a/b?.ts")).toBe(true);
    expect(matchesGlob("a/b12.ts", "a/b?.ts")).toBe(false);
    expect(matchesGlob("a/b/c.ts", "a/b?.ts")).toBe(false); // ? never matches /
  });

  it("regex metacharacters in patterns and paths are literal", () => {
    expect(matchesGlob("a.b/c", "a.b/c")).toBe(true);
    expect(matchesGlob("axb/c", "a.b/c")).toBe(false); // `.` is not a regex dot
    expect(matchesGlob("a+b/c(1)", "a+b/c(1)")).toBe(true);
  });

  it("`**` alone matches everything; empty pattern list matches nothing", () => {
    expect(matchesGlob("any/depth/of/path.ts", "**")).toBe(true);
    expect(matchesGlob("x", "**")).toBe(true);
    expect(matchesAnyGlob("x", [])).toBe(false);
    expect(matchesAnyGlob("tests/u/a.ts", ["src/**", "tests/**"])).toBe(true);
  });

  it("a leading ./ on the PATH is normalized away", () => {
    expect(matchesGlob("./src/a.ts", "src/**")).toBe(true);
  });

  it("globToRegExp anchors both ends", () => {
    const re = globToRegExp("src/*.ts");
    expect(re.test("src/a.ts")).toBe(true);
    expect(re.test("xsrc/a.ts")).toBe(false);
    expect(re.test("src/a.tsx")).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Path normalization corpus (F3 + F8 adversarial fix)
// ─────────────────────────────────────────────────────────────────────────────

describe("normalizePath — traversal, NFC, absolute-path, and workspace-root corpus", () => {
  it("resolves . and .. segments correctly", () => {
    expect(normalizePath("src/./a.ts")).toBe("src/a.ts");
    expect(normalizePath("tests/../src/index.ts")).toBe("src/index.ts");
    expect(normalizePath("a/b/../../src/x.ts")).toBe("src/x.ts");
    expect(normalizePath("src/a/../b/c.ts")).toBe("src/b/c.ts");
  });

  it("strips leading ./", () => {
    expect(normalizePath("./src/a.ts")).toBe("src/a.ts");
    expect(normalizePath("./tests/unit/x.test.ts")).toBe("tests/unit/x.test.ts");
  });

  it("returns null for paths that escape the root", () => {
    expect(normalizePath("../../etc/passwd")).toBeNull();
    expect(normalizePath("../sibling/file.ts")).toBeNull();
    expect(normalizePath("a/../../escape.ts")).toBeNull();
  });

  it("NFC-normalizes Unicode paths (uses Unicode escapes to avoid source-file encoding ambiguity)", () => {
    // NFD é: e (U+0065) + combining acute accent (U+0301)
    const nfd = "caf\u0065\u0301"; // NFD: e + combining accent
    // NFC é: precomposed U+00E9
    const nfc = "caf\u00e9"; // NFC: precomposed
    expect(normalizePath("src/" + nfd + "/file.ts")).toBe("src/" + nfc + "/file.ts");
  });

  it("handles absolute paths without workspaceRoot — returns null (excluded)", () => {
    expect(normalizePath("/abs/path/to/file.ts")).toBeNull();
    expect(normalizePath("/etc/passwd")).toBeNull();
  });

  it("strips workspaceRoot prefix from absolute paths when it matches", () => {
    expect(normalizePath("/ws/src/a.ts", "/ws")).toBe("src/a.ts");
    expect(normalizePath("/ws/src/a.ts", "/ws/")).toBe("src/a.ts"); // trailing slash on root
    expect(normalizePath("/ws/tests/x.test.ts", "/ws")).toBe("tests/x.test.ts");
  });

  it("returns null for absolute paths that do not match the workspaceRoot", () => {
    expect(normalizePath("/other/src/a.ts", "/ws")).toBeNull();
    expect(normalizePath("/etc/passwd", "/ws")).toBeNull();
  });

  it("traversal after stripping root prefix is resolved correctly", () => {
    // /ws/tests/../src/index.ts → strip prefix → tests/../src/index.ts → src/index.ts
    expect(normalizePath("/ws/tests/../src/index.ts", "/ws")).toBe("src/index.ts");
  });

  it("an empty path after normalization produces an empty string (not null)", () => {
    expect(normalizePath("./")).toBe(""); // trailing dot-slash resolves to root itself
    expect(normalizePath(".")).toBe("");
  });

  it("consecutive and trailing slashes are collapsed", () => {
    expect(normalizePath("src//a.ts")).toBe("src/a.ts");
    expect(normalizePath("src/a.ts/")).toBe("src/a.ts"); // trailing slash treated as empty segment
  });
});

// matchesGlob with path normalization applied internally
describe("matchesGlob — normalization applied before matching", () => {
  it("tests/../src/index.ts normalizes to src/index.ts before matching src/**", () => {
    expect(matchesGlob("tests/../src/index.ts", "src/**")).toBe(true);
  });

  it("../../etc/passwd normalizes to null (escapes root) → matchesGlob returns false, never matches", () => {
    expect(matchesGlob("../../etc/passwd", "**")).toBe(false);
    expect(matchesGlob("../../etc/passwd", "etc/**")).toBe(false);
  });

  it("NFD path matches NFC glob pattern (uses Unicode escapes to avoid encoding ambiguity)", () => {
    // NFD é: e (U+0065) + combining acute accent (U+0301); NFC é: precomposed U+00E9
    const nfdPath = "src/caf\u0065\u0301/index.ts"; // NFD: e + combining accent
    const nfcPat  = "src/caf\u00e9/**";               // NFC: precomposed é
    expect(matchesGlob(nfdPath, nfcPat)).toBe(true);
  });
});
