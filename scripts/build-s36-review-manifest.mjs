#!/usr/bin/env node
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmodSync, lstatSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const implementationRoot = realpathSync(resolve(dirname(fileURLToPath(import.meta.url)), ".."));
const planningRoot = realpathSync(resolve(implementationRoot, "../loopeix-specs"));
const roots = [implementationRoot, planningRoot];
const excluded = /(^|\/)(?:\.claude|\.playwright-mcp)(?:\/|$)/u;
const sensitive = /(^|\/)(?:\.env(?:\.|$)|[^/]*(?:credential|secret|token|private[-_]?key)[^/]*)/iu;
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const canonical = (value) => `${JSON.stringify(value, null, 2)}\n`;

function fail(message) { process.stderr.write(`S36 review manifest failed: ${message}\n`); process.exit(1); }
function git(root, args, encoding = "utf8") {
  return execFileSync("git", ["-C", root, ...args], { encoding, maxBuffer: 64 * 1024 * 1024, timeout: 30_000, stdio: ["ignore", "pipe", "pipe"] });
}
function changedPaths(root) {
  const bytes = git(root, ["ls-files", "-m", "-d", "-o", "--exclude-standard", "-z"], "buffer");
  return [...new Set(bytes.toString("utf8").split("\0").filter(Boolean))].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
}
function stableFile(path) {
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) fail(`changed path is not a direct regular file: ${path}`);
  const bytes = readFileSync(path); const after = statSync(path, { bigint: true });
  if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs) fail(`changed during capture: ${path}`);
  return { bytes, mode: Number(before.mode & 0o777n), size: Number(before.size) };
}

const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== "--output" || !isAbsolute(args[1] ?? "")) fail("usage: --output <absolute-create-new-json-path>");
const output = resolve(args[1]);
if ([implementationRoot, planningRoot].some((root) => { const rel = relative(root, output); return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel)); })) fail("output must be outside both repositories");
const parent = realpathSync(dirname(output));
if ((statSync(parent).mode & 0o077) !== 0) fail("output parent must be private");

const repositories = roots.map((root) => {
  const files = [];
  for (const path of changedPaths(root)) {
    if (excluded.test(path)) continue;
    if (sensitive.test(path)) fail(`sensitive-looking changed path: ${basename(root)}/${path}`);
    const absolute = resolve(root, path); const rel = relative(root, absolute);
    if (rel.startsWith("..") || isAbsolute(rel)) fail(`path escaped repository: ${path}`);
    let current = null;
    try { const captured = stableFile(absolute); current = { mode: captured.mode, size: captured.size, sha256: sha256(captured.bytes) }; }
    catch (error) { if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) throw error; }
    let baseline = null;
    try { const bytes = git(root, ["show", `HEAD:${path}`], "buffer"); baseline = { size: bytes.byteLength, sha256: sha256(bytes) }; }
    catch { baseline = null; }
    files.push({ path, baseline, current });
  }
  return { repository_id: basename(root), head: git(root, ["rev-parse", "HEAD"]).trim(), files };
});
const body = { schema_version: "0.1", purpose: "s36-integrated-review-manifest", repositories };
const manifest = { ...body, manifest_sha256: sha256(Buffer.from(canonical(body))) };
writeFileSync(output, canonical(manifest), { flag: "wx", mode: 0o600 }); chmodSync(output, 0o600);
process.stdout.write(`${manifest.manifest_sha256}\n`);
