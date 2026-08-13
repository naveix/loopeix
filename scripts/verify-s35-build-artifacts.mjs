import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";

const MANIFEST_NAME = "s35-build-artifact-manifest-v01.json";
const HARNESS_ROOT = "loopeix-s35-runtime-smoke-v01";
const HARNESS_NAME = `${HARNESS_ROOT}.tar`;
const HARNESS_MANIFEST_NAME = "smoke-harness-manifest.json";
const CHECKSUM_NAME = "SHA256SUMS";
const VERIFIER_NAME = "verify-s35-build-artifacts.mjs";
const FILE_MODE = 0o600;
const DIRECTORY_MODE = 0o700;
const TAR_BLOCK_BYTES = 512;

function fail(message) { throw new Error(`S35 build-artifact verification failed: ${message}`); }
function assert(value, message) { if (!value) fail(message); }
function hash(bytes) { return createHash("sha256").update(bytes).digest("hex"); }
function utf8Compare(left, right) { return Buffer.compare(Buffer.from(left), Buffer.from(right)); }
function canonical(value) {
  const normalize = (input) => Array.isArray(input) ? input.map(normalize)
    : input !== null && typeof input === "object"
      ? Object.fromEntries(Object.keys(input).sort().map((key) => [key, normalize(input[key])]))
      : input;
  return `${JSON.stringify(normalize(value), null, 2)}\n`;
}
function stable(path, maximum = 536_870_912) {
  const before = lstatSync(path, { bigint: true });
  assert(before.isFile() && !before.isSymbolicLink() && before.size <= BigInt(maximum), `unsafe or oversized artifact ${path}`);
  const bytes = readFileSync(path); const after = statSync(path, { bigint: true });
  assert(before.dev === after.dev && before.ino === after.ino && before.size === after.size && before.mtimeNs === after.mtimeNs, `artifact changed during capture: ${path}`);
  return bytes;
}
function parse(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]; const value = argv[index + 1];
    assert(["--artifact-dir", "--expected-source-commit"].includes(key) && value !== undefined && !values.has(key), `invalid argument ${key}`);
    values.set(key, value);
  }
  assert(isAbsolute(values.get("--artifact-dir") ?? ""), "--artifact-dir must be absolute");
  assert(/^[0-9a-f]{40}$/.test(values.get("--expected-source-commit") ?? ""), "expected source commit is invalid");
  return { directory: resolve(values.get("--artifact-dir")), commit: values.get("--expected-source-commit") };
}
function exactKeys(value, keys) {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    && Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}
function assertFileMode(path, expected) {
  const mode = statSync(path).mode & 0o777;
  assert(mode === expected, `artifact mode drifted for ${path}`);
}
function assertSafeBareName(value, label) {
  assert(typeof value === "string" && value.length > 0, `${label} must be a non-empty string`);
  assert(!value.includes("/") && !value.includes("\\") && value !== "." && value !== "..", `${label} is unsafe`);
}
function assertSafeRelativeFilePath(value, label) {
  assert(typeof value === "string" && value.length > 0, `${label} must be a non-empty string`);
  assert(!value.startsWith("/") && !value.startsWith("\\") && !value.endsWith("/"), `${label} is unsafe`);
  const segments = value.split("/");
  assert(segments.every((segment) => segment.length > 0 && segment !== "." && segment !== ".." && !segment.includes("\\")), `${label} is unsafe`);
}
function parseTarString(bytes, start, length) {
  return bytes.subarray(start, start + length).toString("utf8").replace(/\0.*$/su, "");
}
function parseTarNumber(field, label) {
  if ((field[0] & 0x80) !== 0) {
    let value = BigInt(field[0] & 0x7f);
    for (let index = 1; index < field.length; index += 1) value = (value << 8n) | BigInt(field[index]);
    assert(value <= BigInt(Number.MAX_SAFE_INTEGER), `${label} exceeds the safe integer range`);
    return Number(value);
  }
  const text = field.toString("ascii").replace(/\0.*$/su, "").trim();
  if (text === "") return 0;
  assert(/^[0-7]+$/.test(text), `${label} is not an octal tar number`);
  const value = Number.parseInt(text, 8);
  assert(Number.isSafeInteger(value), `${label} exceeds the safe integer range`);
  return value;
}
function assertTarHeaderChecksum(header) {
  const expected = parseTarNumber(header.subarray(148, 156), "tar header checksum");
  let actual = 0;
  for (let index = 0; index < header.length; index += 1) actual += index >= 148 && index < 156 ? 0x20 : header[index];
  assert(actual === expected, "tar header checksum is invalid");
}
function isZeroTarBlock(block) {
  return block.every((byte) => byte === 0);
}
function inspectTarEntries(bytes) {
  assert(bytes.length > 0 && bytes.length % TAR_BLOCK_BYTES === 0, "tar archive length is not block aligned");
  const entries = [];
  let offset = 0;
  let terminated = false;
  while (offset < bytes.length) {
    const header = bytes.subarray(offset, offset + TAR_BLOCK_BYTES);
    if (isZeroTarBlock(header)) {
      const trailer = bytes.subarray(offset);
      assert(trailer.length >= TAR_BLOCK_BYTES * 2, "tar archive lacks two terminating zero blocks");
      assert(trailer.every((byte) => byte === 0), "tar archive contains data after its zero trailer");
      terminated = true;
      break;
    }
    assertTarHeaderChecksum(header);
    assert(parseTarString(header, 257, 6) === "ustar", "tar member does not use USTAR format");
    assert(parseTarString(header, 263, 2) === "00", "tar member USTAR version drifted");
    const rawType = String.fromCharCode(header[156] || 0x30);
    const type = rawType === "\0" ? "0" : rawType;
    assert(type === "0" || type === "5", `tar entry type ${JSON.stringify(type)} is not allowed`);
    const name = parseTarString(header, 0, 100);
    const prefix = parseTarString(header, 345, 155);
    let path = prefix === "" ? name : `${prefix}/${name}`;
    assert(path.length > 0, "tar entry path is empty");
    if (type === "5" && !path.endsWith("/")) path = `${path}/`;
    const size = parseTarNumber(header.subarray(124, 136), "tar member size");
    const contentStart = offset + TAR_BLOCK_BYTES;
    const contentEnd = contentStart + size;
    assert(contentEnd <= bytes.length, `tar member exceeds archive bounds: ${path}`);
    const content = bytes.subarray(contentStart, contentEnd);
    entries.push({
      path,
      type,
      mode: parseTarNumber(header.subarray(100, 108), "tar member mode") & 0o777,
      uid: parseTarNumber(header.subarray(108, 116), "tar member uid"),
      gid: parseTarNumber(header.subarray(116, 124), "tar member gid"),
      mtime: parseTarNumber(header.subarray(136, 148), "tar member mtime"),
      uname: parseTarString(header, 265, 32),
      gname: parseTarString(header, 297, 32),
      size,
      bytes: content,
      sha256: hash(content),
    });
    offset = contentStart + Math.ceil(size / TAR_BLOCK_BYTES) * TAR_BLOCK_BYTES;
  }
  assert(terminated, "tar archive lacks a zero-block trailer");
  return entries;
}
function validateOuterRecord(record, label) {
  assert(exactKeys(record, ["name", "size", "sha256"]), `${label} record is invalid`);
  assertSafeBareName(record.name, `${label}.name`);
  assert(Number.isSafeInteger(record.size) && record.size >= 0, `${label}.size is invalid`);
  assert(typeof record.sha256 === "string" && /^[0-9a-f]{64}$/.test(record.sha256), `${label}.sha256 is invalid`);
}
function validateOuterManifest(value, expectedCommit) {
  assert(exactKeys(value, ["format", "manifest_hash", "product_tarball", "smoke_harness", "source_commit"]), "outer manifest shape is invalid");
  assert(value.format === "loopeix-s35-build-artifact-v01" && value.source_commit === expectedCommit, "outer manifest identity or source commit mismatch");
  assert(typeof value.manifest_hash === "string" && /^[0-9a-f]{64}$/.test(value.manifest_hash), "outer manifest self-hash is invalid");
  validateOuterRecord(value.product_tarball, "product_tarball");
  validateOuterRecord(value.smoke_harness, "smoke_harness");
  assert(value.smoke_harness.name === HARNESS_NAME, "smoke harness file name drifted");
  const { manifest_hash: recordedHash, ...base } = value;
  assert(recordedHash === hash(Buffer.from(canonical(base))), "outer manifest self-hash mismatch");
}
function validateInnerManifest(value, outerProduct, expectedCommit) {
  assert(exactKeys(value, ["files", "fixture_root", "harness_id", "manifest_hash", "product_tarball_name", "product_tarball_sha256", "product_tarball_size_bytes", "schema_version", "smoke_script_path", "source_commit"]), "inner harness manifest shape is invalid");
  assert(value.schema_version === "0.1", "inner harness schema version drifted");
  assert(value.harness_id === HARNESS_ROOT, "inner harness id drifted");
  assert(typeof value.source_commit === "string" && /^[0-9a-f]{40}$/u.test(value.source_commit), "inner harness source commit is invalid");
  assert(value.source_commit === expectedCommit, "inner harness source commit differs from trusted provenance");
  assert(typeof value.manifest_hash === "string" && /^[0-9a-f]{64}$/.test(value.manifest_hash), "inner manifest self-hash is invalid");
  assertSafeBareName(value.product_tarball_name, "inner product_tarball_name");
  assert(typeof value.product_tarball_sha256 === "string" && /^[0-9a-f]{64}$/u.test(value.product_tarball_sha256), "inner product_tarball_sha256 is invalid");
  assert(Number.isSafeInteger(value.product_tarball_size_bytes) && value.product_tarball_size_bytes >= 0, "inner product_tarball_size_bytes is invalid");
  assertSafeRelativeFilePath(value.smoke_script_path, "inner smoke_script_path");
  assertSafeRelativeFilePath(value.fixture_root, "inner fixture_root");
  assert(value.product_tarball_name === outerProduct.name, "inner product tarball name differs from outer manifest");
  assert(value.product_tarball_sha256 === outerProduct.sha256, "inner product tarball hash differs from outer manifest");
  assert(value.product_tarball_size_bytes === outerProduct.size, "inner product tarball size differs from outer manifest");
  assert(Array.isArray(value.files) && value.files.length >= 1, "inner harness files are invalid");
  const memberPaths = [];
  for (const [index, member] of value.files.entries()) {
    assert(exactKeys(member, ["mode", "path", "sha256", "size_bytes"]), `inner harness file ${index} is invalid`);
    assertSafeRelativeFilePath(member.path, `inner harness member ${index}.path`);
    assert(Number.isSafeInteger(member.size_bytes) && member.size_bytes >= 0, `inner harness file ${index}.size_bytes is invalid`);
    assert(typeof member.sha256 === "string" && /^[0-9a-f]{64}$/.test(member.sha256), `inner harness file ${index}.sha256 is invalid`);
    assert(member.mode === "0600", `inner harness file ${index}.mode drifted`);
    assert(member.path !== HARNESS_MANIFEST_NAME && member.path !== CHECKSUM_NAME, "fixed harness files must not be listed as mutable members");
    memberPaths.push(member.path);
  }
  assert(new Set(memberPaths).size === memberPaths.length, "inner harness member paths contain duplicates");
  assert(JSON.stringify([...memberPaths].sort(utf8Compare)) === JSON.stringify(memberPaths), "inner harness member paths must be UTF-8 sorted");
  assert(memberPaths.includes(value.smoke_script_path), "inner smoke script path is not present in files");
  assert(memberPaths.some((path) => path.startsWith(`${value.fixture_root}/`)), "inner fixture root has no captured files");
  const { manifest_hash: recordedHash, ...base } = value;
  assert(recordedHash === hash(Buffer.from(canonical(base))), "inner manifest self-hash mismatch");
}
function deriveExpectedHarnessPaths(innerManifest) {
  const directories = new Set([`${HARNESS_ROOT}/`]);
  const files = new Set([`${HARNESS_ROOT}/${HARNESS_MANIFEST_NAME}`, `${HARNESS_ROOT}/${CHECKSUM_NAME}`]);
  for (const member of innerManifest.files) {
    let current = `${HARNESS_ROOT}/${member.path}`;
    files.add(current);
    while (current.includes("/")) {
      current = current.slice(0, current.lastIndexOf("/"));
      if (current === HARNESS_ROOT) {
        directories.add(`${HARNESS_ROOT}/`);
        break;
      }
      directories.add(`${current}/`);
    }
  }
  return {
    directories: [...directories].sort(utf8Compare),
    files: [...files].sort(utf8Compare),
  };
}
function validateHarnessArchive(entries, innerManifestBytes, innerManifest, checksumBytes) {
  const actualPaths = entries.map((entry) => entry.path);
  assert(new Set(actualPaths).size === actualPaths.length, "smoke archive contains duplicate entries");
  assert(JSON.stringify(actualPaths) === JSON.stringify([...actualPaths].sort(utf8Compare)), "smoke archive paths are not UTF-8 sorted");
  for (const entry of entries) {
    assert(entry.uid === 0 && entry.gid === 0, `archive ownership drifted for ${entry.path}`);
    assert(entry.uname === "" && entry.gname === "", `archive owner/group names drifted for ${entry.path}`);
    assert(entry.mtime === 0, `archive mtime drifted for ${entry.path}`);
    if (entry.type === "5") {
      assert(entry.path.endsWith("/"), `directory entry is not normalized: ${entry.path}`);
      assertSafeRelativeFilePath(entry.path.slice(0, -1), `directory entry ${entry.path}`);
      assert(entry.size === 0, `directory entry size drifted for ${entry.path}`);
      assert(entry.mode === DIRECTORY_MODE, `directory entry mode drifted for ${entry.path}`);
    } else {
      assert(!entry.path.endsWith("/"), `regular-file entry is not normalized: ${entry.path}`);
      assertSafeRelativeFilePath(entry.path, `regular-file entry ${entry.path}`);
      assert(entry.mode === FILE_MODE, `regular-file entry mode drifted for ${entry.path}`);
    }
  }
  const expected = deriveExpectedHarnessPaths(innerManifest);
  const expectedPaths = [...expected.directories, ...expected.files].sort(utf8Compare);
  assert(JSON.stringify([...actualPaths].sort(utf8Compare)) === JSON.stringify(expectedPaths), "smoke archive entry inventory is not exact");

  const entryByPath = new Map(entries.map((entry) => [entry.path, entry]));
  for (const path of expected.directories) assert(entryByPath.get(path)?.type === "5", `archive directory is missing: ${path}`);
  for (const member of innerManifest.files) {
    const path = `${HARNESS_ROOT}/${member.path}`;
    const entry = entryByPath.get(path);
    assert(entry?.type === "0", `archive member is missing: ${path}`);
    assert(entry.size === member.size_bytes, `archive member size drifted for ${path}`);
    assert(entry.sha256 === member.sha256, `archive member hash drifted for ${path}`);
  }
  const manifestEntry = entryByPath.get(`${HARNESS_ROOT}/${HARNESS_MANIFEST_NAME}`);
  assert(manifestEntry?.type === "0", "archive harness manifest is missing");
  assert(manifestEntry.size === innerManifestBytes.byteLength && manifestEntry.sha256 === hash(innerManifestBytes), "archive harness manifest drifted");
  const checksumEntry = entryByPath.get(`${HARNESS_ROOT}/${CHECKSUM_NAME}`);
  assert(checksumEntry?.type === "0", "archive checksum file is missing");
  assert(checksumEntry.size === checksumBytes.byteLength && checksumEntry.sha256 === hash(checksumBytes), "archive checksum file drifted");
}
function validateChecksumFile(checksumBytes, entries, innerManifest) {
  const text = checksumBytes.toString("utf8");
  assert(text.endsWith("\n"), "checksum file must end with one newline");
  const lines = text.trimEnd().split("\n").filter(Boolean);
  const expectedPaths = [HARNESS_MANIFEST_NAME, ...innerManifest.files.map((member) => member.path)].sort(utf8Compare);
  assert(lines.length === expectedPaths.length, "checksum file membership drifted");
  const actualPaths = [];
  const expectedHashes = new Map(entries
    .filter((entry) => entry.type === "0" && entry.path !== `${HARNESS_ROOT}/${CHECKSUM_NAME}`)
    .map((entry) => [entry.path.slice(`${HARNESS_ROOT}/`.length), entry.sha256]));
  for (const line of lines) {
    const match = /^([0-9a-f]{64})  ([^/\\].*)$/u.exec(line);
    assert(match !== null, "checksum row is malformed");
    const path = match[2];
    assertSafeRelativeFilePath(path, `checksum path ${path}`);
    assert(!actualPaths.includes(path), `checksum path is duplicated: ${path}`);
    actualPaths.push(path);
    assert(expectedHashes.get(path) === match[1], `checksum binding mismatch: ${path}`);
  }
  assert(JSON.stringify(actualPaths) === JSON.stringify(expectedPaths), "checksum path inventory is not exact");
}

const input = parse(process.argv.slice(2));
const manifestBytes = stable(join(input.directory, MANIFEST_NAME), 1_048_576);
const manifest = JSON.parse(manifestBytes.toString("utf8"));
validateOuterManifest(manifest, input.commit);
const expectedNames = [MANIFEST_NAME, VERIFIER_NAME, manifest.product_tarball.name, manifest.smoke_harness.name].sort(utf8Compare);
assert(JSON.stringify(readdirSync(input.directory).sort(utf8Compare)) === JSON.stringify(expectedNames), "artifact directory inventory is not exact");
for (const record of [manifest.product_tarball, manifest.smoke_harness]) {
  const path = join(input.directory, record.name);
  const bytes = stable(path);
  assert(bytes.byteLength === record.size && hash(bytes) === record.sha256, `artifact binding mismatch: ${record.name}`);
}
stable(join(input.directory, VERIFIER_NAME), 1_048_576);

const harnessBytes = stable(join(input.directory, manifest.smoke_harness.name));
const harnessEntries = inspectTarEntries(harnessBytes);
const entryByPath = new Map(harnessEntries.map((entry) => [entry.path, entry]));
const innerManifestEntry = entryByPath.get(`${HARNESS_ROOT}/${HARNESS_MANIFEST_NAME}`);
assert(innerManifestEntry?.type === "0", "archive harness manifest is missing");
const checksumEntry = entryByPath.get(`${HARNESS_ROOT}/${CHECKSUM_NAME}`);
assert(checksumEntry?.type === "0", "archive checksum file is missing");
const innerManifest = JSON.parse(innerManifestEntry.bytes.toString("utf8"));
validateInnerManifest(innerManifest, manifest.product_tarball, input.commit);
validateHarnessArchive(harnessEntries, innerManifestEntry.bytes, innerManifest, checksumEntry.bytes);
validateChecksumFile(checksumEntry.bytes, harnessEntries, innerManifest);

const scratch = mkdtempSync(join(tmpdir(), "loopeix-s35-artifact-verify-")); chmodSync(scratch, DIRECTORY_MODE);
let operationError;
try {
  const retainedHarness = join(scratch, HARNESS_NAME);
  writeFileSync(retainedHarness, harnessBytes, { mode: FILE_MODE, flag: "wx" });
  execFileSync("/usr/bin/tar", ["-xf", retainedHarness, "-C", scratch], { env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" }, stdio: "pipe" });
  const root = join(scratch, HARNESS_ROOT);
  const extractedManifest = stable(join(root, HARNESS_MANIFEST_NAME), 1_048_576);
  const extractedChecksum = stable(join(root, CHECKSUM_NAME), 4_194_304);
  assert(hash(extractedManifest) === hash(innerManifestEntry.bytes), "extracted harness manifest drifted after archive validation");
  assert(hash(extractedChecksum) === hash(checksumEntry.bytes), "extracted checksum file drifted after archive validation");
  for (const member of innerManifest.files) {
    const path = join(root, member.path);
    const bytes = stable(path);
    assertFileMode(path, FILE_MODE);
    assert(bytes.byteLength === member.size_bytes && hash(bytes) === member.sha256, `extracted member drifted: ${member.path}`);
  }
  execFileSync(process.execPath, [join(root, innerManifest.smoke_script_path), "--mode", "runtime", "--tarball", join(input.directory, manifest.product_tarball.name), "--fixtures-root", join(root, innerManifest.fixture_root), "--harness-manifest", join(root, HARNESS_MANIFEST_NAME)], {
    cwd: dirname(root),
    env: { HOME: scratch, LANG: "C", LC_ALL: "C", PATH: process.env.PATH ?? "/usr/bin:/bin", TMPDIR: scratch, npm_execpath: process.env.npm_execpath ?? "/opt/homebrew/lib/node_modules/npm/bin/npm-cli.js" },
    stdio: "pipe", timeout: 300_000,
  });
  process.stdout.write(`${JSON.stringify({ ok: true, source_commit: input.commit })}\n`);
} catch (error) { operationError = error; }
finally {
  try { rmSync(scratch, { recursive: true, force: false }); }
  catch (error) { operationError = operationError === undefined ? error : new AggregateError([operationError, error]); }
}
if (operationError !== undefined) throw operationError;
