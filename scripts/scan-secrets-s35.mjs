import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readFile, realpath } from "node:fs/promises";
import { basename, relative, resolve, sep } from "node:path";

const GREP_ERE = `(${[
  "-----BEGIN [^-]*PRIVATE KEY-----",
  "(^|[^A-Z0-9])(AKIA|ASIA)[A-Z0-9]{16}([^A-Z0-9]|$)",
  "(^|[^A-Za-z0-9_])(gh[pousr]_|github_pat_)[A-Za-z0-9_-]{20,255}",
  "(^|[^A-Za-z0-9_])sk-ant-[A-Za-z0-9_-]{20,255}",
  "(^|[^A-Za-z0-9_])(sk-proj-|sk-)[A-Za-z0-9_-]{20,255}",
  "(^|[^A-Za-z0-9_])xox[bpars]-[A-Za-z0-9-]{10,255}",
  "(^|[^A-Za-z0-9_])AIza[A-Za-z0-9_-]{35}",
  "(^|[^A-Za-z0-9_])ck_[A-Za-z0-9_-]{20,255}",
  "[A-Za-z][A-Za-z0-9+.-]*://[^[:space:]/:@]+:[^[:space:]/@]+@",
  "(^|[^A-Za-z0-9_])[A-Za-z0-9_]*(api_key|apikey|access_token|auth_token|client_secret|password|private_key)[[:space:]]*[:=][[:space:]]*[^[:space:]]{12,255}",
].join("|")})`;

const RULES = [
  { rule_id: "CRED_PRIVATE_KEY_PEM", pattern: /-----BEGIN [^-\r\n]*PRIVATE KEY-----/g, candidate_group: 0 },
  { rule_id: "CRED_AWS_ACCESS_KEY_ID", pattern: /(?:^|[^A-Z0-9])((?:AKIA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])/g, candidate_group: 1 },
  { rule_id: "CRED_GITHUB_TOKEN", pattern: /(?:^|[^A-Za-z0-9_])((?:gh[pousr]_|github_pat_)[A-Za-z0-9_-]{20,255})/g, candidate_group: 1 },
  { rule_id: "CRED_ANTHROPIC_API_KEY", pattern: /(?:^|[^A-Za-z0-9_])(sk-ant-[A-Za-z0-9_-]{20,255})/g, candidate_group: 1 },
  { rule_id: "CRED_OPENAI_API_KEY", pattern: /(?:^|[^A-Za-z0-9_])((?:sk-proj-|sk-)(?!ant-)[A-Za-z0-9_-]{20,255})/g, candidate_group: 1 },
  { rule_id: "CRED_SLACK_TOKEN", pattern: /(?:^|[^A-Za-z0-9_])(xox[bpars]-[A-Za-z0-9-]{10,255})/g, candidate_group: 1 },
  { rule_id: "CRED_GOOGLE_API_KEY", pattern: /(?:^|[^A-Za-z0-9_])(AIza[A-Za-z0-9_-]{35})/g, candidate_group: 1 },
  { rule_id: "CRED_COMPOSIO_CONSUMER_KEY", pattern: /(?:^|[^A-Za-z0-9_])(ck_[A-Za-z0-9_-]{20,255})/g, candidate_group: 1 },
];

const RULE_IDS = new Set([
  ...RULES.map((rule) => rule.rule_id),
  "CRED_URI_USERINFO",
  "CRED_ASSIGNMENT",
]);

const ASSIGNMENT_SUFFIX_PATTERN = /(?:api_key|apikey|access_token|auth_token|client_secret|password|private_key)\s*[:=]\s*["']?[^\s"']{12,255}/gi;

const EXCLUDED_PATHSPECS = [
  ":(exclude).env*", ":(exclude).env*/**", ":(exclude)**/.env*", ":(exclude)**/.env*/**",
  ":(exclude).playwright-mcp/**", ":(exclude)**/.playwright-mcp/**",
];

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
}

function parseArguments(argv) {
  if (argv.length === 1 && argv[0] === "--print-grep-ere") return { print: true };
  let allowlist = null;
  let filenamesOnly = false;
  let excludeEnv = false;
  let excludePlaywright = false;
  const roots = [];
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--allowlist") {
      const value = argv[index + 1];
      if (value === undefined) throw new Error("--allowlist requires one path");
      allowlist = value;
      index += 1;
    } else if (argument === "--filenames-only") filenamesOnly = true;
    else if (argument === "--exclude-env") excludeEnv = true;
    else if (argument === "--exclude-playwright") excludePlaywright = true;
    else if (argument?.startsWith("-")) throw new Error(`unknown option ${argument}`);
    else if (argument !== undefined) roots.push(argument);
  }
  if (allowlist === null || roots.length === 0 || !filenamesOnly || !excludeEnv || !excludePlaywright) {
    throw new Error("required usage: --allowlist PATH --filenames-only --exclude-env --exclude-playwright REPOSITORY...");
  }
  return { print: false, allowlist, roots };
}

function gitFiles(root) {
  const result = spawnSync(
    "git",
    ["-C", root, "ls-files", "-co", "--exclude-standard", "-z", "--", ".", ...EXCLUDED_PATHSPECS],
    { encoding: "buffer", shell: false, maxBuffer: 64 * 1024 * 1024 },
  );
  if (result.status !== 0 || result.error !== undefined) throw new Error(`cannot enumerate repository ${basename(root)}`);
  const deleted = spawnSync(
    "git",
    ["-C", root, "ls-files", "--deleted", "-z", "--", ".", ...EXCLUDED_PATHSPECS],
    { encoding: "buffer", shell: false, maxBuffer: 64 * 1024 * 1024 },
  );
  if (deleted.status !== 0 || deleted.error !== undefined) throw new Error(`cannot enumerate deleted paths in repository ${basename(root)}`);
  const deletedPaths = new Set(deleted.stdout.toString("utf8").split("\0").filter(Boolean));
  return result.stdout.toString("utf8").split("\0").filter((path) => path.length > 0 && !deletedPaths.has(path))
    .sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
}

function isExcludedPath(path) {
  return path.split("/").some((segment) => segment.startsWith(".env") || segment === ".playwright-mcp");
}

async function scanStableRegularFile(path) {
  const before = await lstat(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) return null;
  const noFollow = "O_NOFOLLOW" in constants ? constants.O_NOFOLLOW : 0;
  const handle = await open(path, constants.O_RDONLY | noFollow);
  try {
    const openedBefore = await handle.stat({ bigint: true });
    if (!openedBefore.isFile() || openedBefore.dev !== before.dev || openedBefore.ino !== before.ino) {
      throw new Error("file identity changed before scan");
    }
    const detections = [];
    let tail = Buffer.alloc(0);
    let position = 0;
    for (;;) {
      const chunk = Buffer.allocUnsafe(1_048_576);
      const { bytesRead } = await handle.read(chunk, 0, chunk.byteLength, null);
      if (bytesRead === 0) break;
      const bytes = chunk.subarray(0, bytesRead);
      const window = Buffer.concat([tail, bytes]);
      const windowBase = position - tail.byteLength;
      for (const detection of detectCandidates(window)) {
        const absoluteEnd = windowBase + detection.end;
        if (absoluteEnd > position) detections.push(detection);
      }
      position += bytesRead;
      tail = window.subarray(Math.max(0, window.byteLength - 1_024));
    }
    const openedAfter = await handle.stat({ bigint: true });
    if (openedAfter.dev !== openedBefore.dev || openedAfter.ino !== openedBefore.ino ||
      openedAfter.size !== openedBefore.size || openedAfter.mtimeNs !== openedBefore.mtimeNs ||
      BigInt(position) !== openedBefore.size) {
      throw new Error("file changed during scan");
    }
    return detections;
  } finally {
    await handle.close();
  }
}

function detectCandidates(bytes) {
  const text = bytes.toString("latin1");
  const claimed = [];
  const detections = [];
  for (const rule of RULES) {
    rule.pattern.lastIndex = 0;
    for (;;) {
      const match = rule.pattern.exec(text);
      if (match === null) break;
      const candidate = match[rule.candidate_group];
      if (candidate === undefined) throw new Error(`detector ${rule.rule_id} produced no candidate`);
      const offset = match.index + match[0].indexOf(candidate);
      const end = offset + candidate.length;
      if (!claimed.some(([left, right]) => offset < right && end > left)) {
        claimed.push([offset, end]);
        detections.push({
          rule_id: rule.rule_id,
          candidate_sha256: `sha256:${createHash("sha256").update(Buffer.from(candidate, "latin1")).digest("hex")}`,
          start: offset,
          end,
        });
      }
      if (match[0].length === 0) rule.pattern.lastIndex += 1;
    }
  }
  let uriSearchFrom = 0;
  for (;;) {
    const separator = text.indexOf("://", uriSearchFrom);
    if (separator < 0) break;
    let start = separator;
    while (start > 0 && /[A-Za-z0-9+.-]/.test(text[start - 1])) start -= 1;
    const scheme = text.slice(start, separator);
    const authorityStart = separator + 3;
    const at = text.indexOf("@", authorityStart);
    if (/^[A-Za-z][A-Za-z0-9+.-]*$/.test(scheme) && at >= 0) {
      const authority = text.slice(authorityStart, at);
      const colon = authority.indexOf(":");
      const end = at + 1;
      if (colon > 0 && colon < authority.length - 1 && !/[\s/@]/.test(authority)
        && !claimed.some(([left, right]) => start < right && end > left)) {
        const candidate = text.slice(start, end);
        claimed.push([start, end]);
        detections.push({
          rule_id: "CRED_URI_USERINFO",
          candidate_sha256: `sha256:${createHash("sha256").update(Buffer.from(candidate, "latin1")).digest("hex")}`,
          start,
          end,
        });
      }
    }
    uriSearchFrom = separator + 3;
  }
  ASSIGNMENT_SUFFIX_PATTERN.lastIndex = 0;
  for (;;) {
    const match = ASSIGNMENT_SUFFIX_PATTERN.exec(text);
    if (match === null) break;
    let start = match.index;
    while (start > 0 && /[A-Za-z0-9_]/.test(text[start - 1])) start -= 1;
    const end = match.index + match[0].length;
    if (!claimed.some(([left, right]) => start < right && end > left)) {
      const candidate = text.slice(start, end);
      claimed.push([start, end]);
      detections.push({
        rule_id: "CRED_ASSIGNMENT",
        candidate_sha256: `sha256:${createHash("sha256").update(Buffer.from(candidate, "latin1")).digest("hex")}`,
        start,
        end,
      });
    }
  }
  return detections;
}

function exactKeys(value, keys) {
  return typeof value === "object" && value !== null && !Array.isArray(value) &&
    Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}

async function parseAllowlist(path) {
  const value = JSON.parse(await readFile(path, "utf8"));
  if (!exactKeys(value, ["schema_version", "entries"]) || value.schema_version !== "0.1" || !Array.isArray(value.entries)) {
    throw new Error("secret scan allowlist envelope is invalid");
  }
  const entries = value.entries.map((entry) => {
    const keys = ["repository_id", "path", "rule_id", "candidate_sha256", "occurrence_count", "justification"];
    if (!exactKeys(entry, keys) || typeof entry.repository_id !== "string" || typeof entry.path !== "string" ||
      typeof entry.rule_id !== "string" || !RULE_IDS.has(entry.rule_id) ||
      typeof entry.candidate_sha256 !== "string" || !/^sha256:[a-f0-9]{64}$/.test(entry.candidate_sha256) ||
      !Number.isSafeInteger(entry.occurrence_count) || entry.occurrence_count < 1 ||
      typeof entry.justification !== "string" || entry.justification.trim().length === 0 || isExcludedPath(entry.path)) {
      throw new Error("secret scan allowlist entry is invalid");
    }
    return entry;
  });
  const identities = entries.map((entry) => `${entry.repository_id}\0${entry.path}\0${entry.rule_id}\0${entry.candidate_sha256}`);
  if (new Set(identities).size !== identities.length) throw new Error("secret scan allowlist contains duplicate entries");
  return entries;
}

function identity(row) {
  return `${row.repository_id}\0${row.path}\0${row.rule_id}\0${row.candidate_sha256}`;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.print) {
    process.stdout.write(`${GREP_ERE}\n`);
    return;
  }

  const allowlist = await parseAllowlist(options.allowlist);
  const observed = new Map();
  const repositoryIds = new Set();
  for (const suppliedRoot of options.roots) {
    const root = await realpath(resolve(suppliedRoot));
    const rootMetadata = await lstat(root);
    if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) throw new Error("repository root must be a direct directory");
    const repositoryId = basename(root);
    if (repositoryIds.has(repositoryId)) throw new Error("repository IDs must be unique");
    repositoryIds.add(repositoryId);
    for (const repositoryPath of gitFiles(root)) {
      if (isExcludedPath(repositoryPath)) throw new Error("excluded path escaped Git pathspec filtering");
      const absolutePath = resolve(root, repositoryPath);
      const relativePath = relative(root, absolutePath);
      if (relativePath.startsWith(`..${sep}`) || relativePath === ".." || relativePath.includes("\\")) throw new Error("repository path escaped its root");
      const detections = await scanStableRegularFile(absolutePath);
      if (detections === null) continue;
      for (const { start: _start, end: _end, ...detection } of detections) {
        const row = { repository_id: repositoryId, path: repositoryPath, ...detection };
        const key = identity(row);
        observed.set(key, { ...row, occurrence_count: (observed.get(key)?.occurrence_count ?? 0) + 1 });
      }
    }
  }

  const expected = new Map(allowlist.map((row) => [identity(row), row]));
  const mismatches = [];
  for (const [key, row] of observed) {
    const allowed = expected.get(key);
    if (allowed === undefined || allowed.occurrence_count !== row.occurrence_count) mismatches.push(row);
  }
  for (const [key, row] of expected) {
    if (!observed.has(key)) mismatches.push(row);
  }
  if (mismatches.length > 0) {
    const sanitized = [...new Map(mismatches.map((row) => [
      `${row.repository_id}\0${row.path}\0${row.rule_id}`,
      { repository_id: row.repository_id, path: row.path, rule_id: row.rule_id },
    ])).values()].sort((left, right) => Buffer.compare(Buffer.from(`${left.repository_id}/${left.path}/${left.rule_id}`), Buffer.from(`${right.repository_id}/${right.path}/${right.rule_id}`)));
    process.stderr.write(`${JSON.stringify({ ok: false, mismatches: sanitized })}\n`);
    process.exitCode = 1;
  }
}

main().catch((error) => fail(error instanceof Error ? error.message : "secret scan failed"));
