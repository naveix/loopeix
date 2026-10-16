import { spawn } from "node:child_process";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { CompilerWriterHelperRequest, CompilerWriterHelperResponse } from "./compiler-writer-protocol.js";

function helperPath(): string {
  const currentPath = fileURLToPath(import.meta.url);
  return join(dirname(currentPath), `compiler-writer-child${extname(currentPath)}`);
}

export function requestCompilerWriterHelper(
  workingDirectory: string,
  request: CompilerWriterHelperRequest,
): Promise<CompilerWriterHelperResponse> {
  const path = helperPath();
  const sourceLoader = extname(path) === ".ts" ? ["--import", import.meta.resolve("tsx")] : [];
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [...sourceLoader, path], {
      cwd: workingDirectory,
      env: { LANG: "C", LC_ALL: "C", PATH: process.env.PATH ?? "/usr/bin:/bin" },
      shell: false,
      stdio: ["pipe", "pipe", "ignore"],
    });
    let settled = false;
    let output = "";
    const finish = (result: CompilerWriterHelperResponse): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };
    const unavailable = (): CompilerWriterHelperResponse => ({
      ok: false,
      reason: "IO_HELPER_UNAVAILABLE",
      message: "Required filesystem helper is unavailable.",
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(unavailable());
    }, 30_000);
    child.once("error", () => finish(unavailable()));
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      output += chunk;
      if (Buffer.byteLength(output, "utf8") > 16_384) {
        child.kill("SIGKILL");
        finish(unavailable());
      }
    });
    child.once("close", (code) => {
      if (settled) return;
      if (code !== 0) return finish(unavailable());
      try {
        const parsed = JSON.parse(output) as unknown;
        if (typeof parsed !== "object" || parsed === null || !("ok" in parsed) || typeof parsed.ok !== "boolean" ||
            (!parsed.ok && (!("reason" in parsed) || typeof parsed.reason !== "string" ||
              !("message" in parsed) || typeof parsed.message !== "string"))) throw new Error("invalid helper response");
        finish(parsed as CompilerWriterHelperResponse);
      } catch { finish(unavailable()); }
    });
    child.stdin.end(JSON.stringify(request));
  });
}
