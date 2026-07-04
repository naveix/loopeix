/**
 * Minimal glob matcher for brief clause adjudication (claim-families-v1.md F2/F3). Zero
 * dependencies, pure functions.
 *
 * DOCTRINE: "observed events can convict; missing events can never acquit." (claim-families-v1.md
 * §Presence convicts; absence never acquits). Path normalization is therefore mandatory: a
 * malformed path may never convict (it is excluded from adjudication), and a path that escapes
 * the workspace root is also excluded. Only a clean, normalizable path may produce a verdict.
 *
 * EXACT SUPPORTED GLOB SUBSET (anything else is matched literally):
 *  - `/` is the only separator; paths are workspace-relative POSIX paths (a leading `./` on the
 *    PATH is stripped; backslashes are NOT translated).
 *  - `*`  matches any run of characters WITHIN one segment (including none, including dotfiles).
 *  - `?`  matches exactly one character within a segment.
 *  - `**` as a FULL segment matches zero or more whole segments. `src/**` therefore matches
 *    `src/a.ts` and `src/a/b.ts` but NOT the bare file `src` and NOT `src2/a.ts` (no prefix
 *    collision — the `/` after `src` is required).
 *  - A trailing `/` means "the directory and everything under it": `tests/` ≡ `tests/**`.
 *  - NOT supported: braces, extglobs, character classes, negation, escapes. Matching is
 *    case-sensitive. `*`/`?` never cross a `/`.
 *
 * Matching is CONSERVATIVE by construction: an unsupported construct can only make a pattern
 * match LESS (literally), never more — a verdict can miss a violation but cannot invent one
 * from a mis-parsed pattern.
 *
 * PATH NORMALIZATION (`normalizePath`): resolves `.`/`..` segments, NFC-normalizes, strips a
 * workspace-root prefix when provided, and handles absolute paths. Returns `null` for paths
 * that cannot be normalized safely (would escape root, or absolute with no/mismatched root).
 */

const REGEX_SPECIALS = /[.+^${}()|[\]\\]/g;

function segmentToRegex(segment: string): string {
  let out = "";
  for (const ch of segment) {
    if (ch === "*") out += "[^/]*";
    else if (ch === "?") out += "[^/]";
    else out += ch.replace(REGEX_SPECIALS, "\\$&");
  }
  return out;
}

/** Compile one glob pattern to an anchored RegExp (see header for the exact subset). */
export function globToRegExp(pattern: string): RegExp {
  const normalized = pattern.endsWith("/") ? `${pattern}**` : pattern;
  const segments = normalized.split("/");
  let re = "^";
  segments.forEach((seg, i) => {
    const last = i === segments.length - 1;
    if (seg === "**") {
      // Zero or more whole segments; as the last segment it may also match "nothing after the /".
      re += last ? "(?:.*)?" : "(?:[^/]+/)*";
    } else {
      re += segmentToRegex(seg) + (last ? "" : "/");
    }
  });
  return new RegExp(`${re}$`);
}

/**
 * Normalize a workspace-relative or absolute path for glob adjudication.
 *
 * Steps (in order):
 *  1. If absolute: strip workspaceRoot prefix (trailing-slash-tolerant) or return null.
 *  2. Strip a leading `./`.
 *  3. NFC-normalize the string (Unicode canonical composition — affects multi-byte filenames).
 *  4. Resolve `.` and `..` segments; return null if the path would escape the root.
 *
 * Returns `null` when the path cannot be safely normalized (escapes root, absolute with no
 * or mismatched workspaceRoot). A null path is EXCLUDED from adjudication — it can never
 * convict or acquit.
 */
export function normalizePath(path: string, workspaceRoot?: string): string | null {
  let p = path;

  // Handle absolute paths.
  if (p.startsWith("/")) {
    if (workspaceRoot !== undefined) {
      const root = workspaceRoot.endsWith("/") ? workspaceRoot : `${workspaceRoot}/`;
      if (p.startsWith(root)) {
        p = p.slice(root.length);
      } else if (p === workspaceRoot) {
        p = "";
      } else {
        return null; // absolute path outside the declared workspace root
      }
    } else {
      return null; // absolute path with no workspace root context
    }
  }

  // Strip leading ./
  if (p.startsWith("./")) p = p.slice(2);

  // NFC normalize (affects Unicode filenames; safe no-op on ASCII).
  p = p.normalize("NFC");

  // Resolve . and .. segments.
  const segments = p.split("/");
  const resolved: string[] = [];
  for (const seg of segments) {
    if (seg === "" || seg === ".") {
      // skip empty (consecutive slashes or trailing slash) and dot segments
    } else if (seg === "..") {
      if (resolved.length > 0) {
        resolved.pop();
      } else {
        return null; // path escapes workspace root
      }
    } else {
      resolved.push(seg);
    }
  }

  return resolved.join("/");
}

/** Match one workspace-relative path against one glob pattern. Path and pattern are both
 *  NFC-normalized first so that Unicode filenames with different composition forms match. */
export function matchesGlob(path: string, pattern: string): boolean {
  const p = normalizePath(path);
  if (p === null) return false; // excluded path never matches
  // NFC-normalize the pattern too (its literal characters, not its `*`/`?` specials).
  return globToRegExp(pattern.normalize("NFC")).test(p);
}

/** Match one path against a pattern list (true if ANY pattern matches; empty list ⇒ false). */
export function matchesAnyGlob(path: string, patterns: readonly string[]): boolean {
  return patterns.some((pattern) => matchesGlob(path, pattern));
}
