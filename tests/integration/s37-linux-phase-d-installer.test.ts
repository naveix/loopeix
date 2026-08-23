import { describe, expect, it } from "vitest";

import {
  parseInstallBindingArgs,
  publishBindingPlan,
  writeInstallBindingOutcome,
} from "../../scripts/s37-linux-phase-d/install-binding.mjs";

function cliArgs(overrides: Partial<Record<string, string>> = {}): string[] {
  const paths = {
    qualification: "/private/tmp/qualification.json",
    manifest: "/private/tmp/phase-b-manifest.json",
    readinessEvidence: "/private/tmp/phase-b-readiness-evidence.json",
    readinessEnvelope: "/private/tmp/phase-b-readiness-envelope.json",
    conformanceEvidence: "/private/tmp/phase-b-conformance-evidence.json",
    receipt: "/private/tmp/phase-b-receipt.json",
    ...overrides,
  };
  return [
    "--qualification", paths.qualification,
    "--manifest", paths.manifest,
    "--readiness-evidence", paths.readinessEvidence,
    "--readiness-envelope", paths.readinessEnvelope,
    "--conformance-evidence", paths.conformanceEvidence,
    "--receipt", paths.receipt,
    "--controller-uid", "1001",
    "--apply-exact-s37-local-product-binding",
  ];
}

function expectCliError(fn: () => unknown, detail: string, exitCode = 64): void {
  try {
    fn();
    throw new Error("expected cli error");
  } catch (error) {
    expect(error).toBeInstanceOf(Error);
    expect(error).toMatchObject({ detail, exitCode });
  }
}

function createRecordingIo(options: {
  linkError?: Error;
  unlinkError?: Error;
  directoryFsyncError?: Error;
} = {}) {
  const calls: Array<readonly [string, ...unknown[]]> = [];
  const constants = { O_CREAT: 1, O_EXCL: 2, O_WRONLY: 4, O_NOFOLLOW: 8, O_RDONLY: 16, O_DIRECTORY: 32 };
  const tempDescriptor = 11;
  const directoryDescriptor = 12;
  const io = {
    constants,
    randomBytesHex: () => "0123456789abcdef01234567",
    openSync: (path: string, flags: number, mode?: number) => {
      calls.push(["openSync", path, flags, mode ?? null]);
      return path.endsWith(".tmp") ? tempDescriptor : directoryDescriptor;
    },
    writeFileSync: (descriptor: number, bytes: Uint8Array | string) => {
      calls.push(["writeFileSync", descriptor, bytes]);
    },
    fsyncSync: (descriptor: number) => {
      calls.push(["fsyncSync", descriptor]);
      if (descriptor === directoryDescriptor && options.directoryFsyncError !== undefined) {
        throw options.directoryFsyncError;
      }
    },
    fchownSync: (descriptor: number, uid: number, gid: number) => {
      calls.push(["fchownSync", descriptor, uid, gid]);
    },
    fchmodSync: (descriptor: number, mode: number) => {
      calls.push(["fchmodSync", descriptor, mode]);
    },
    chownSync: (path: string, uid: number, gid: number) => {
      calls.push(["chownSync", path, uid, gid]);
    },
    chmodSync: (path: string, mode: number) => {
      calls.push(["chmodSync", path, mode]);
    },
    closeSync: (descriptor: number) => {
      calls.push(["closeSync", descriptor]);
    },
    linkSync: (source: string, destination: string) => {
      calls.push(["linkSync", source, destination]);
      if (options.linkError !== undefined) throw options.linkError;
    },
    unlinkSync: (path: string) => {
      calls.push(["unlinkSync", path]);
      if (options.unlinkError !== undefined) throw options.unlinkError;
    },
  };
  return { io, calls };
}

describe("S37.1-D binding installer", () => {
  it("rejects any non-absolute sealed evidence input path before host gating", () => {
    expectCliError(
      () => parseInstallBindingArgs(cliArgs({ receipt: "relative-receipt.json" }), 1001),
      "receipt path must be absolute",
    );
    expectCliError(
      () => parseInstallBindingArgs(cliArgs({ manifest: "relative-manifest.json" }), 1001),
      "manifest path must be absolute",
    );
  });

  it("fsyncs content and descriptor metadata before publication and prefers descriptor metadata ops", () => {
    const { io, calls } = createRecordingIo();
    const destination = "/private/tmp/loopeix-s37d-installer/local-product-binding.json";

    const result = publishBindingPlan({
      destination,
      bytes: Buffer.from("{\"binding\":true}\n", "utf8"),
      sha256: "sha256:abc",
      uid: 0,
      gid: 0,
      mode: 0o444,
      overwrite: false,
    }, io);

    expect(result).toEqual({ ok: true, destination, sha256: "sha256:abc", warnings: [] });
    expect(calls).toEqual([
      ["openSync", "/private/tmp/loopeix-s37d-installer/.local-product-binding.0123456789abcdef01234567.tmp", 15, 0o600],
      ["writeFileSync", 11, Buffer.from("{\"binding\":true}\n", "utf8")],
      ["fsyncSync", 11],
      ["fchownSync", 11, 0, 0],
      ["fchmodSync", 11, 0o444],
      ["fsyncSync", 11],
      ["closeSync", 11],
      ["linkSync", "/private/tmp/loopeix-s37d-installer/.local-product-binding.0123456789abcdef01234567.tmp", destination],
      ["unlinkSync", "/private/tmp/loopeix-s37d-installer/.local-product-binding.0123456789abcdef01234567.tmp"],
      ["openSync", "/private/tmp/loopeix-s37d-installer", 48, null],
      ["fsyncSync", 12],
      ["closeSync", 12],
    ]);
    expect(calls.some(([name]) => name === "chownSync")).toBe(false);
    expect(calls.some(([name]) => name === "chmodSync")).toBe(false);
  });

  it("reports installed success with a deterministic cleanup warning when temp unlink fails after publication", () => {
    const { io, calls } = createRecordingIo({ unlinkError: new Error("temp-unlink-failed") });
    const destination = "/private/tmp/loopeix-s37d-installer-warning/local-product-binding.json";

    const result = publishBindingPlan({
      destination,
      bytes: Buffer.from("binding\n", "utf8"),
      sha256: "sha256:def",
      uid: 0,
      gid: 0,
      mode: 0o444,
      overwrite: false,
    }, io);

    expect(result).toEqual({
      ok: true,
      destination,
      sha256: "sha256:def",
      warnings: [
        "/private/tmp/loopeix-s37d-installer-warning/.local-product-binding.0123456789abcdef01234567.tmp",
      ].map((path) => `temporary-path-cleanup-required:${path}`),
    });
    expect(calls.filter(([name]) => name === "linkSync")).toHaveLength(1);
    expect(calls.filter(([name]) => name === "unlinkSync")).toHaveLength(1);
  });

  it("cleans up only the exact temp path on a pre-publication failure and rethrows", () => {
    const { io, calls } = createRecordingIo({ linkError: new Error("destination-exists") });

    expect(() => publishBindingPlan({
      destination: "/private/tmp/loopeix-s37d-installer-existing/binding.json",
      bytes: Buffer.from("binding\n", "utf8"),
      sha256: "sha256:ghi",
      uid: 0,
      gid: 0,
      mode: 0o444,
      overwrite: false,
    }, io)).toThrow("destination-exists");
    expect(calls.filter(([name]) => name === "unlinkSync")).toEqual([
      ["unlinkSync", "/private/tmp/loopeix-s37d-installer-existing/.local-product-binding.0123456789abcdef01234567.tmp"],
    ]);
  });

  it("keeps installed success and warns if directory fsync fails after publication", () => {
    const { io } = createRecordingIo({ directoryFsyncError: new Error("directory-fsync-failed") });
    const destination = "/private/tmp/loopeix-s37d-installer-fsync/local-product-binding.json";

    const result = publishBindingPlan({
      destination,
      bytes: Buffer.from("binding\n", "utf8"),
      sha256: "sha256:jkl",
      uid: 0,
      gid: 0,
      mode: 0o444,
      overwrite: false,
    }, io);

    expect(result).toEqual({
      ok: false,
      terminal: "OUTCOME_UNKNOWN",
      destination,
      sha256: "sha256:jkl",
      warnings: [],
      detail: "directory-fsync-after-publication-failed:/private/tmp/loopeix-s37d-installer-fsync",
    });
  });

  it("reports published-but-durability-unknown outcomes on stderr with a nonzero exit status", () => {
    const writes = { stdout: "", stderr: "" };
    const processLike = {
      stdout: { write: (chunk: string) => { writes.stdout += chunk; } },
      stderr: { write: (chunk: string) => { writes.stderr += chunk; } },
      exitCode: 0,
    };

    const exitCode = writeInstallBindingOutcome({
      ok: false,
      terminal: "OUTCOME_UNKNOWN",
      destination: "/private/tmp/loopeix-s37d-installer-fsync/local-product-binding.json",
      sha256: "sha256:jkl",
      warnings: ["temporary-path-cleanup-required:/private/tmp/loopeix-s37d-installer-fsync/.temp"],
      detail: "directory-fsync-after-publication-failed:/private/tmp/loopeix-s37d-installer-fsync",
    }, processLike);

    expect(exitCode).toBe(1);
    expect(processLike.exitCode).toBe(1);
    expect(writes.stdout).toBe("");
    expect(writes.stderr).toBe(
      "OUTCOME_UNKNOWN: published /private/tmp/loopeix-s37d-installer-fsync/local-product-binding.json sha256:jkl directory-fsync-after-publication-failed:/private/tmp/loopeix-s37d-installer-fsync\n"
      + "WARN: temporary-path-cleanup-required:/private/tmp/loopeix-s37d-installer-fsync/.temp\n",
    );
  });
});
