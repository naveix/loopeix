import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const defaultFiles = [
  "src/run/action-classifier-policy-v02.ts",
  "src/run/runtime-record-admission-v02.ts",
  "src/run/present-planned-v02.ts",
];

const forbiddenPatterns = [
  { label: "child-process", pattern: /\bfrom\s+["']node:child_process["']|\bfrom\s+["']child_process["']|\brequire\(["']node:child_process["']\)|\brequire\(["']child_process["']\)/u },
  { label: "filesystem-write", pattern: /\bfrom\s+["']node:fs(?:\/promises)?["']|\bfrom\s+["']fs(?:\/promises)?["']|\brequire\(["']node:fs(?:\/promises)?["']\)|\brequire\(["']fs(?:\/promises)?["']\)/u },
  { label: "process-module", pattern: /\bfrom\s+["']node:process["']|\bfrom\s+["']process["']|\brequire\(["']node:process["']\)|\brequire\(["']process["']\)/u },
  { label: "runtime-ledger-writer", pattern: /\bfrom\s+["'][^"']*runtime-ledger-v02(?:\.js)?["']|\brequire\(["'][^"']*runtime-ledger-v02(?:\.js)?["']\)/u },
  { label: "package-root-export", pattern: /\bfrom\s+["']\.\.\/index(?:\.js)?["']|\brequire\(["']\.\.\/index(?:\.js)?["']\)/u },
  { label: "connector-import", pattern: /\bfrom\s+["'][^"']*connectors?\/|(\brequire\(["'][^"']*connectors?\/)/u },
  { label: "tool-adapter-import", pattern: /\bfrom\s+["'][^"']*(adapter|connector|tool-runner|workspace-writer)[^"']*["']|\brequire\(["'][^"']*(adapter|connector|tool-runner|workspace-writer)[^"']*["']\)/u },
];

const targets = process.argv.slice(2);
const files = (targets.length === 0 ? defaultFiles : targets).map((file) => resolve(file));

const violations = [];
for (const file of files) {
  const source = readFileSync(file, "utf8");
  for (const { label, pattern } of forbiddenPatterns) {
    if (pattern.test(source)) violations.push(`${label}: ${file}`);
  }
}

if (violations.length > 0) {
  process.stderr.write(`${violations.join("\n")}\n`);
  process.exit(1);
}
