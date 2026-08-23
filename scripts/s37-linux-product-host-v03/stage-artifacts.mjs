import { createHash } from "node:crypto";
import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ARTIFACT_NAMES = Object.freeze(["supervisor", "probe", "bwrap"]);

function digest(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

export async function stageS37ProductHostArtifactsV03({ uid, workDirectory, artifacts, io }) {
  if (!Number.isSafeInteger(uid) || uid <= 0 || !isAbsolute(workDirectory) || artifacts === null
    || typeof artifacts !== "object" || io === null || typeof io !== "object") {
    return { ok: false, error: "STAGE_PRECONDITION_HOLD" };
  }
  const planned = [];
  for (const name of ARTIFACT_NAMES) {
    const artifact = artifacts[name];
    if (artifact === null || typeof artifact !== "object" || !isAbsolute(artifact.source_path)
      || !/^sha256:[a-f0-9]{64}$/u.test(artifact.sha256 ?? "")) {
      return { ok: false, error: "STAGE_PRECONDITION_HOLD" };
    }
    planned.push({ name, source: artifact.source_path, destination: `${workDirectory}/${name}`, expected: artifact.sha256 });
  }
  const verified = [];
  try {
    for (const item of planned) {
      const metadata = await io.lstat(item.source);
      if (metadata?.type !== "file" || metadata?.nlink !== 1) return { ok: false, error: "STAGE_SOURCE_UNSAFE" };
      const bytes = await io.readFile(item.source);
      if (digest(bytes) !== item.expected) return { ok: false, error: "STAGE_DIGEST_MISMATCH" };
      verified.push({ ...item, bytes });
    }
    const staged = [];
    for (const item of verified) {
      await io.writeExclusive(item.destination, item.bytes, { mode: 0o500, noFollow: true });
      await io.fsyncFile(item.destination);
      staged.push({ name: item.name, path: item.destination, sha256: item.expected, mode: "0500", setuid: false });
    }
    await io.fsyncDirectory(workDirectory);
    return { ok: true, artifacts: Object.freeze(staged) };
  } catch {
    return { ok: false, error: "STAGE_OUTCOME_UNKNOWN" };
  }
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.stderr.write("HOLD: stage-artifacts requires explicit local source and filesystem adapters\n");
  process.exitCode = 64;
}
