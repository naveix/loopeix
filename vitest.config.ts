import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/unit/**/*.test.ts", "tests/integration/**/*.test.ts"],
    allowOnly: false,
    passWithNoTests: false,
    // CLI boundary tests exercise process.exitCode; parallel files can race on that process-global state.
    fileParallelism: false,
  },
});
