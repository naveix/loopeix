// Pre-build hygiene, run before every `pnpm build`:
//  1. Remove a stale oclif.manifest.json — generated transiently during `prepack` and gitignored;
//     if it lingers, oclif loads it in dev and misses newly added commands.
//  2. Remove the whole dist/ — tsc does NOT delete orphaned outputs, so a renamed/removed source
//     (e.g. the old schema/loopspec.ts) leaves a stale dist/schema/loopspec.js behind that would
//     then ship in the npm tarball (package.json `files` includes dist). A full clean guarantees
//     the built + packed artifact contains only current sources.
import { rmSync } from "node:fs";

rmSync("oclif.manifest.json", { force: true });
rmSync("dist", { recursive: true, force: true });
