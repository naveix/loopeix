import { createHash, randomBytes } from "node:crypto";
import { lstat, open, rename, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import canonicalize from "canonicalize";

if (process.argv.slice(2).length !== 0) {
  throw new Error("generate-plan-renderer-bundle-s35 accepts no arguments");
}

const outputDirectory = "dist/report";
const targetPath = join(outputDirectory, "plan-renderer-bundle.json");
const memberPaths = [
  "dist/report/plan-renderer.js",
  "dist/report/plan-escaping.js",
].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));

function hashBytes(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

async function readStableRegularFile(path) {
  const before = await lstat(path);
  if (!before.isFile() || before.isSymbolicLink()) throw new Error(`${path} must be a regular non-symlink file`);
  const handle = await open(path, "r");
  try {
    const openedBefore = await handle.stat();
    if (!openedBefore.isFile() || openedBefore.dev !== before.dev || openedBefore.ino !== before.ino) {
      throw new Error(`${path} identity changed before read`);
    }
    const bytes = await handle.readFile();
    const openedAfter = await handle.stat();
    if (openedAfter.dev !== openedBefore.dev || openedAfter.ino !== openedBefore.ino
      || openedAfter.size !== openedBefore.size || openedAfter.mtimeMs !== openedBefore.mtimeMs
      || bytes.byteLength !== openedBefore.size) {
      throw new Error(`${path} changed during read`);
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

const members = [];
for (const path of memberPaths) {
  members.push({ path, hash: hashBytes(await readStableRegularFile(path)) });
}
const inventory = { purpose: "plan-report-renderer-bundle-v02", members };
const inventoryBytes = Buffer.from(canonicalize(inventory), "utf8");
const rendererBundleHash = hashBytes(inventoryBytes);
const rendererBundleId = `renderer_${rendererBundleHash.slice("sha256:".length, "sha256:".length + 32)}`;
const outputBytes = Buffer.from(`${canonicalize({
  purpose: inventory.purpose,
  members,
  renderer_bundle_hash: rendererBundleHash,
  renderer_bundle_id: rendererBundleId,
})}\n`, "utf8");

try {
  const target = await lstat(targetPath);
  if (!target.isFile() || target.isSymbolicLink()) throw new Error(`${targetPath} must be a regular non-symlink file`);
} catch (error) {
  if (error?.code !== "ENOENT") throw error;
}

const temporaryPath = join(dirname(targetPath), `.plan-renderer-bundle.${randomBytes(16).toString("hex")}.tmp`);
let temporaryCreated = false;
try {
  const temporary = await open(temporaryPath, "wx", 0o600);
  temporaryCreated = true;
  try {
    await temporary.writeFile(outputBytes);
    await temporary.sync();
  } finally {
    await temporary.close();
  }
  await rename(temporaryPath, targetPath);
  temporaryCreated = false;
  const directory = await open(outputDirectory, "r");
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
} finally {
  if (temporaryCreated) await unlink(temporaryPath).catch(() => undefined);
}
