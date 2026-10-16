import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HOLD = Object.freeze({ ok: false, error: "QUALIFICATION_AUTHORITY_INVALID" });

export function commandS37ProductHostIssueQualificationV03() {
  return HOLD;
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.stderr.write("HOLD: issue-qualification requires a genuine same-process qualification issuer capability\n");
  process.exitCode = 64;
}
