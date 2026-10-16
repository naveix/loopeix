import { createHash } from "node:crypto";
import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const TARGETS = Object.freeze({
  supervisor: "/opt/loopeix/s37.1/supervisor",
  probe: "/opt/loopeix/s37.1/probe",
  bwrap: "/opt/loopeix/s37.1/bwrap",
});
const OPEN_FLAGS = Object.freeze(["O_WRONLY", "O_CREAT", "O_EXCL", "O_NOFOLLOW", "O_CLOEXEC"]);

export async function installS37ProductHostArtifactsV03({ uid, artifacts, io }) {
  if (uid !== 0 || artifacts === null || typeof artifacts !== "object" || io === null || typeof io !== "object") {
    return { ok: false, error: "INSTALL_PRECONDITION_HOLD" };
  }
  const plan = [];
  for (const [name, target] of Object.entries(TARGETS)) {
    const artifact = artifacts[name];
    if (artifact === null || typeof artifact !== "object" || !isAbsolute(artifact.path)
      || !/^sha256:[a-f0-9]{64}$/u.test(artifact.sha256 ?? "")) {
      return { ok: false, error: "INSTALL_PRECONDITION_HOLD" };
    }
    plan.push({ name, target, artifact });
  }
  let published = 0;
  try {
    const verified = [];
    for (const item of plan) {
      const source = await io.readFile(item.artifact.path);
      const actual = `sha256:${createHash("sha256").update(source).digest("hex")}`;
      if (actual !== item.artifact.sha256) return { ok: false, error: "INSTALL_DIGEST_MISMATCH" };
      verified.push({ ...item, source });
    }
    for (const { name, target, artifact, source } of verified) {
      const descriptor = await io.open(target, OPEN_FLAGS, 0o500);
      let descriptorMetadata;
      try {
        await io.writeAll(descriptor, source);
        await io.fchown(descriptor, 0, 0);
        await io.fchmod(descriptor, 0o555);
        await io.fsync(descriptor);
        descriptorMetadata = await io.fstat(descriptor);
      } finally {
        await io.close(descriptor);
      }
      const metadata = await io.lstat(target);
      if (descriptorMetadata?.type !== "file" || descriptorMetadata?.uid !== 0 || descriptorMetadata?.gid !== 0
        || descriptorMetadata?.mode !== 0o555 || descriptorMetadata?.nlink !== 1
        || metadata?.type !== "file" || metadata?.uid !== 0 || metadata?.gid !== 0
        || metadata?.mode !== 0o555 || metadata?.nlink !== 1
        || metadata?.dev !== descriptorMetadata?.dev || metadata?.ino !== descriptorMetadata?.ino) {
        return { ok: false, error: "INSTALL_OUTCOME_UNKNOWN" };
      }
      published += 1;
      void name;
    }
    await io.fsyncDirectory("/opt/loopeix/s37.1");
    return { ok: true, installed: Object.freeze({ ...TARGETS }) };
  } catch (error) {
    if (error?.code === "EEXIST" && published === 0) return { ok: false, error: "INSTALL_ALREADY_EXISTS" };
    return { ok: false, error: "INSTALL_OUTCOME_UNKNOWN" };
  }
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.stderr.write("HOLD: install-artifacts requires an explicit root filesystem adapter\n");
  process.exitCode = 64;
}
