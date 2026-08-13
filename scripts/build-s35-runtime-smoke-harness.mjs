import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync, copyFileSync, cpSync, lstatSync, mkdirSync, mkdtempSync, readFileSync,
  readdirSync, realpathSync, rmSync, statSync, utimesSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, isAbsolute, join, relative, resolve, sep } from "node:path";

const MAX_FILE_BYTES = 536_870_912;
const FIXED_TIME = new Date(0);
const ROOT_DIRECTORY_NAME = "loopeix-s35-runtime-smoke-v01";
const HARNESS_MANIFEST_NAME = "smoke-harness-manifest.json";
const CHECKSUM_NAME = "SHA256SUMS";
const VERIFIER_NAME = "verify-s35-build-artifacts.mjs";
const SMOKE_SCRIPT_NAME = "scripts/smoke-packed-package-s35.mjs";
const V02_FIXTURE_VERIFIER_NAME = "scripts/verify-v02-fixtures-s35.mjs";
const FIXTURE_ROOT_NAME = "fixtures";
const FILE_MODE = 0o600;
const DIRECTORY_MODE = 0o700;
function fail(message) { throw new Error(`S35 runtime harness build failed: ${message}`); }
function assert(value, message) { if (!value) fail(message); }
function hash(bytes) { return createHash("sha256").update(bytes).digest("hex"); }
function utf8Compare(left, right) { return Buffer.compare(Buffer.from(left), Buffer.from(right)); }
function stable(path) {
  const before = lstatSync(path, { bigint: true });
  assert(before.isFile() && !before.isSymbolicLink() && before.size <= BigInt(MAX_FILE_BYTES), `unsafe or oversized file ${path}`);
  const bytes = readFileSync(path); const after = statSync(path, { bigint: true });
  assert(before.dev === after.dev && before.ino === after.ino && before.size === after.size && before.mtimeNs === after.mtimeNs, `file changed during capture: ${path}`);
  return bytes;
}
function parse(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]; const value = argv[index + 1];
    assert(["--tarball", "--fixtures-root", "--output-dir", "--smoke-script"].includes(key) && value !== undefined && !values.has(key), `invalid argument ${key}`);
    values.set(key, value);
  }
  for (const key of ["--tarball", "--fixtures-root", "--output-dir"]) assert(isAbsolute(values.get(key) ?? ""), `${key} must be absolute`);
  if (values.has("--smoke-script")) assert(isAbsolute(values.get("--smoke-script") ?? ""), "--smoke-script must be absolute");
  return {
    tarball: resolve(values.get("--tarball")),
    fixtures: resolve(values.get("--fixtures-root")),
    output: resolve(values.get("--output-dir")),
    smokeScript: resolve(values.get("--smoke-script") ?? new URL("./smoke-packed-package-s35.mjs", import.meta.url).pathname),
    v02FixtureVerifier: resolve(new URL("./verify-v02-fixtures-s35.mjs", import.meta.url).pathname),
  };
}
function walk(root) {
  const paths = [];
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => utf8Compare(a.name, b.name))) {
      const path = join(directory, entry.name); const name = relative(root, path).split(sep).join("/");
      assert(!entry.isSymbolicLink(), `fixture symlink is forbidden: ${name}`);
      if (entry.isDirectory()) visit(path);
      else { assert(entry.isFile(), `non-regular fixture is forbidden: ${name}`); paths.push(name); }
    }
  };
  visit(root); return paths.sort(utf8Compare);
}
function walkDirectories(root) {
  const paths = [];
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => utf8Compare(a.name, b.name))) {
      const path = join(directory, entry.name); const name = relative(root, path).split(sep).join("/");
      assert(!entry.isSymbolicLink(), `fixture symlink is forbidden: ${name}`);
      if (entry.isDirectory()) {
        paths.push(path);
        visit(path);
      } else assert(entry.isFile(), `non-regular fixture is forbidden: ${name}`);
    }
  };
  visit(root); return paths;
}
function normalizeModes(root) {
  const visit = (directory) => {
    chmodSync(directory, DIRECTORY_MODE);
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => utf8Compare(a.name, b.name))) {
      const path = join(directory, entry.name);
      assert(!entry.isSymbolicLink(), `tree symlink is forbidden: ${relative(root, path).split(sep).join("/") || "."}`);
      if (entry.isDirectory()) visit(path);
      else {
        assert(entry.isFile(), `non-regular tree member is forbidden: ${relative(root, path).split(sep).join("/") || "."}`);
        chmodSync(path, FILE_MODE);
      }
    }
  };
  visit(root);
}
function canonical(value) {
  const normalize = (input) => Array.isArray(input) ? input.map(normalize)
    : input !== null && typeof input === "object"
      ? Object.fromEntries(Object.keys(input).sort().map((key) => [key, normalize(input[key])]))
      : input;
  return `${JSON.stringify(normalize(value), null, 2)}\n`;
}
function manifestHash(preimage) {
  return hash(Buffer.from(canonical(preimage)));
}
function writeTarText(header, offset, length, value, label) {
  const bytes = Buffer.from(value, "utf8");
  assert(bytes.byteLength <= length, `${label} does not fit the USTAR header`);
  bytes.copy(header, offset);
}
function writeTarOctal(header, offset, length, value, label) {
  assert(Number.isSafeInteger(value) && value >= 0, `${label} is invalid`);
  const text = value.toString(8).padStart(length - 1, "0");
  assert(text.length === length - 1, `${label} does not fit the USTAR header`);
  writeTarText(header, offset, length, `${text}\0`, label);
}
function splitTarPath(path) {
  const bytes = Buffer.from(path, "utf8");
  if (bytes.byteLength <= 100) return { name: path, prefix: "" };
  for (let index = path.lastIndexOf("/"); index > 0; index = path.lastIndexOf("/", index - 1)) {
    const prefix = path.slice(0, index);
    const name = path.slice(index + 1);
    if (Buffer.byteLength(prefix) <= 155 && Buffer.byteLength(name) <= 100) return { name, prefix };
  }
  fail(`archive path does not fit USTAR: ${path}`);
}
function tarHeader(path, type, size, mode) {
  const header = Buffer.alloc(512);
  const split = splitTarPath(path);
  writeTarText(header, 0, 100, split.name, "tar member name");
  writeTarOctal(header, 100, 8, mode, "tar member mode");
  writeTarOctal(header, 108, 8, 0, "tar member uid");
  writeTarOctal(header, 116, 8, 0, "tar member gid");
  writeTarOctal(header, 124, 12, size, "tar member size");
  writeTarOctal(header, 136, 12, 0, "tar member mtime");
  header.fill(0x20, 148, 156);
  writeTarText(header, 156, 1, type, "tar member type");
  writeTarText(header, 257, 6, "ustar\0", "tar magic");
  writeTarText(header, 263, 2, "00", "tar version");
  writeTarText(header, 345, 155, split.prefix, "tar member prefix");
  let checksum = 0;
  for (const byte of header) checksum += byte;
  const checksumText = checksum.toString(8).padStart(6, "0");
  assert(checksumText.length === 6, "tar checksum does not fit the USTAR header");
  writeTarText(header, 148, 8, `${checksumText}\0 `, "tar checksum");
  return header;
}
function createDeterministicTar(stage, output) {
  const parent = resolve(stage, "..");
  const rootName = basename(stage);
  const rows = [{ path: rootName, source: stage, type: "5", mode: DIRECTORY_MODE }];
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => utf8Compare(a.name, b.name))) {
      const source = join(directory, entry.name);
      const path = relative(parent, source).split(sep).join("/");
      assert(!entry.isSymbolicLink(), `archive symlink is forbidden: ${path}`);
      if (entry.isDirectory()) {
        rows.push({ path, source, type: "5", mode: DIRECTORY_MODE });
        visit(source);
      } else {
        assert(entry.isFile(), `non-regular archive member is forbidden: ${path}`);
        rows.push({ path, source, type: "0", mode: FILE_MODE });
      }
    }
  };
  visit(stage);
  const chunks = [];
  for (const row of rows) {
    const bytes = row.type === "0" ? stable(row.source) : Buffer.alloc(0);
    chunks.push(tarHeader(row.path, row.type, bytes.byteLength, row.mode), bytes);
    const padding = (512 - (bytes.byteLength % 512)) % 512;
    if (padding > 0) chunks.push(Buffer.alloc(padding));
  }
  chunks.push(Buffer.alloc(1024));
  writeFileSync(output, Buffer.concat(chunks), { mode: FILE_MODE, flag: "wx" });
}

const input = parse(process.argv.slice(2));
assert(statSync(input.fixtures).isDirectory(), "fixture root is not a directory");
assert(statSync(input.output).isDirectory() && readdirSync(input.output).length === 0, "output directory must exist and be empty");
const productBytes = stable(input.tarball); const productName = basename(input.tarball);
const verifierBytes = stable(new URL(`./${VERIFIER_NAME}`, import.meta.url).pathname);
assert(/^loopeix-[0-9].*\.tgz$/.test(productName), "product tarball name is invalid");
const productOut = join(input.output, productName); copyFileSync(input.tarball, productOut); chmodSync(productOut, 0o600);
const commit = execFileSync("/usr/bin/git", ["rev-parse", "HEAD"], { cwd: realpathSync(process.cwd()), encoding: "utf8", env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" } }).trim();
assert(/^[0-9a-f]{40}$/.test(commit), "source commit is invalid");

const scratch = mkdtempSync(join(tmpdir(), "loopeix-s35-harness-build-")); chmodSync(scratch, 0o700);
let operationError;
try {
  const stage = join(scratch, ROOT_DIRECTORY_NAME); mkdirSync(stage, { mode: DIRECTORY_MODE });
  const fixtureTarget = join(stage, FIXTURE_ROOT_NAME);
  mkdirSync(join(stage, "scripts"), { mode: DIRECTORY_MODE });
  cpSync(input.fixtures, fixtureTarget, { recursive: true, dereference: false, errorOnExist: true });
  copyFileSync(input.smokeScript, join(stage, SMOKE_SCRIPT_NAME));
  copyFileSync(input.v02FixtureVerifier, join(stage, V02_FIXTURE_VERIFIER_NAME));
  normalizeModes(stage);
  const fixtureRows = walk(fixtureTarget).map((name) => {
    const bytes = stable(join(fixtureTarget, name));
    return Object.freeze({ path: `${FIXTURE_ROOT_NAME}/${name}`, size_bytes: bytes.byteLength, sha256: hash(bytes), mode: "0600" });
  }).sort((left, right) => utf8Compare(left.path, right.path));
  assert(new Set(fixtureRows.map(({ path }) => path)).size === fixtureRows.length, "fixture member inventory contains duplicates");
  const smokeBytes = stable(join(stage, SMOKE_SCRIPT_NAME));
  const v02FixtureVerifierBytes = stable(join(stage, V02_FIXTURE_VERIFIER_NAME));
  const fileRows = Object.freeze([
    Object.freeze({ path: SMOKE_SCRIPT_NAME, size_bytes: smokeBytes.byteLength, sha256: hash(smokeBytes), mode: "0600" }),
    Object.freeze({ path: V02_FIXTURE_VERIFIER_NAME, size_bytes: v02FixtureVerifierBytes.byteLength, sha256: hash(v02FixtureVerifierBytes), mode: "0600" }),
    ...fixtureRows,
  ].sort((left, right) => utf8Compare(left.path, right.path)));
  assert(new Set(fileRows.map(({ path }) => path)).size === fileRows.length, "harness member inventory contains duplicates");
  const innerBase = {
    schema_version: "0.1",
    harness_id: ROOT_DIRECTORY_NAME,
    source_commit: commit,
    product_tarball_name: productName,
    product_tarball_sha256: hash(productBytes),
    product_tarball_size_bytes: productBytes.byteLength,
    smoke_script_path: SMOKE_SCRIPT_NAME,
    fixture_root: FIXTURE_ROOT_NAME,
    files: fileRows,
  };
  const inner = { ...innerBase, manifest_hash: manifestHash(innerBase) };
  writeFileSync(join(stage, HARNESS_MANIFEST_NAME), canonical(inner), { mode: FILE_MODE });
  const checksumRows = walk(stage)
    .filter((name) => name !== CHECKSUM_NAME)
    .map((name) => `${hash(stable(join(stage, name)))}  ${name}`);
  writeFileSync(join(stage, CHECKSUM_NAME), `${checksumRows.join("\n")}\n`, { mode: FILE_MODE });
  normalizeModes(stage);
  for (const name of walk(stage)) utimesSync(join(stage, name), FIXED_TIME, FIXED_TIME);
  const touchedDirectories = [stage, ...walkDirectories(stage)];
  for (const directory of touchedDirectories) if (statSync(directory).isDirectory()) utimesSync(directory, FIXED_TIME, FIXED_TIME);
  const harnessName = `${ROOT_DIRECTORY_NAME}.tar`; const harnessOut = join(input.output, harnessName);
  createDeterministicTar(stage, harnessOut);
  chmodSync(harnessOut, FILE_MODE);
  const harnessBytes = stable(harnessOut);
  const outerBase = {
    format: "loopeix-s35-build-artifact-v01",
    source_commit: commit,
    product_tarball: { name: productName, size: productBytes.byteLength, sha256: hash(productBytes) },
    smoke_harness: { name: harnessName, size: harnessBytes.byteLength, sha256: hash(harnessBytes) },
  };
  const outer = { ...outerBase, manifest_hash: manifestHash(outerBase) };
  writeFileSync(join(input.output, "s35-build-artifact-manifest-v01.json"), canonical(outer), { mode: FILE_MODE });
  writeFileSync(join(input.output, VERIFIER_NAME), verifierBytes, { mode: FILE_MODE, flag: "wx" });
  process.stdout.write(`${JSON.stringify({ ok: true, product: productName, harness: harnessName })}\n`);
} catch (error) { operationError = error; }
finally {
  try { rmSync(scratch, { recursive: true, force: false }); }
  catch (error) { operationError = operationError === undefined ? error : new AggregateError([operationError, error]); }
}
if (operationError !== undefined) throw operationError;
