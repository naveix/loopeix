// Remove a stale oclif.manifest.json before a dev build. The manifest is generated
// transiently during `prepack` (packaging) and gitignored; if it lingers after a
// `pnpm pack`, oclif would load it in dev and miss newly added commands. Running this
// before every `pnpm build` guarantees dev mode scans the fresh dist/commands.
import { rmSync } from "node:fs";

rmSync("oclif.manifest.json", { force: true });
