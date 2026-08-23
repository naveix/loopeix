import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HOLD = Object.freeze({ ok: false, outcome: "HOLD_PRECONDITION" });

export function commandS37ProductHostInstallAnchorV03() {
  return HOLD;
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.stderr.write("HOLD: install-anchor requires a genuine same-process S40/S36 authorization capability\n");
  process.exitCode = 64;
}
