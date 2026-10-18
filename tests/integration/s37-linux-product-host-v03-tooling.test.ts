import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it, vi } from "vitest";

import { inspectS37ProductHostBootstrapV03, loadV03Contract } from "../../scripts/s37-linux-product-host-v03/inspect-bootstrap.mjs";
import { stageS37ProductHostArtifactsV03 } from "../../scripts/s37-linux-product-host-v03/stage-artifacts.mjs";
import { installS37ProductHostArtifactsV03 } from "../../scripts/s37-linux-product-host-v03/install-artifacts.mjs";
import { collectS37LinuxPhaseBReadinessV03 } from "../../scripts/s37-linux-product-host-v03/collect-readiness.mjs";
import { runS37LinuxConformanceOnceV03 } from "../../scripts/s37-linux-product-host-v03/run-conformance-once.mjs";
import { finalizeS37LinuxConformanceV03 } from "../../scripts/s37-linux-product-host-v03/finalize-conformance.mjs";
import { commandS37ProductHostInstallAnchorV03 } from "../../scripts/s37-linux-product-host-v03/install-anchor.mjs";
import { commandS37ProductHostTransitionAnchorV03 } from "../../scripts/s37-linux-product-host-v03/transition-anchor.mjs";
import { commandS37ProductHostIssueQualificationV03 } from "../../scripts/s37-linux-product-host-v03/issue-qualification.mjs";
import { commandS37ProductHostReconcileAnchorV03 } from "../../scripts/s37-linux-product-host-v03/reconcile-anchor.mjs";

const ARCHIVE = fileURLToPath(new URL("../fixtures/s37-linux-product-host-v03/trial-7-pass/", import.meta.url));

function archive(name: string): unknown {
  return JSON.parse(readFileSync(resolve(ARCHIVE, name), "utf8")) as unknown;
}

function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("expected record");
  return value as Record<string, unknown>;
}

function array(value: unknown): unknown[] {
  if (!Array.isArray(value)) throw new Error("expected array");
  return value;
}

function sha(bytes: Uint8Array): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

describe("S37.1-F3 host-neutral product tooling", () => {
  const inertCommands = [
    {
      file: "install-anchor.mjs",
      stderr: "HOLD: install-anchor requires a genuine same-process S40/S36 authorization capability\n",
      invoke: commandS37ProductHostInstallAnchorV03,
      result: { ok: false, outcome: "HOLD_PRECONDITION" },
    },
    {
      file: "transition-anchor.mjs",
      stderr: "HOLD: transition-anchor requires a genuine same-process S40/S36 authorization capability\n",
      invoke: commandS37ProductHostTransitionAnchorV03,
      result: { ok: false, outcome: "HOLD_PRECONDITION" },
    },
    {
      file: "issue-qualification.mjs",
      stderr: "HOLD: issue-qualification requires a genuine same-process qualification issuer capability\n",
      invoke: commandS37ProductHostIssueQualificationV03,
      result: { ok: false, error: "QUALIFICATION_AUTHORITY_INVALID" },
    },
    {
      file: "reconcile-anchor.mjs",
      stderr: "HOLD: reconcile-anchor requires a genuine same-process lifecycle I/O capability\n",
      invoke: commandS37ProductHostReconcileAnchorV03,
      result: { ok: false, outcome: "RECOVERY_REQUIRED" },
    },
  ] as const;

  it.each(inertCommands)("keeps $file import-safe and fixed HOLD", ({ invoke, result }) => {
    const first = invoke();
    const second = invoke();
    expect(first).toEqual(result);
    expect(second).toBe(first);
    expect(Object.isFrozen(first)).toBe(true);
  });

  it.each(inertCommands)("runs $file with zero work and exact sanitized CLI HOLD", ({ file, stderr }) => {
    const cwd = mkdtempSync(resolve(tmpdir(), "loopeix-s37-f-command-hold-"));
    try {
      const before = readdirSync(cwd);
      const result = spawnSync(process.execPath, [resolve(process.cwd(), "scripts/s37-linux-product-host-v03", file)], {
        cwd,
        encoding: "utf8",
        env: {},
      });
      expect(result.status).toBe(64);
      expect(result.signal).toBeNull();
      expect(result.stdout).toBe("");
      expect(result.stderr).toBe(stderr);
      expect(readdirSync(cwd)).toEqual(before);
    } finally {
      rmSync(cwd, { recursive: true });
    }
  });

  it.each(inertCommands)("keeps $file free of duplicated authority and host effects", ({ file }) => {
    const source = readFileSync(resolve(process.cwd(), "scripts/s37-linux-product-host-v03", file), "utf8");
    const approvedReconcileApi = "reconcileS37ProductHostActivationV01";
    if (file === "reconcile-anchor.mjs") {
      expect(source.match(new RegExp(approvedReconcileApi, "gu"))).toHaveLength(2);
      expect(source).toContain(
        `import { ${approvedReconcileApi} } from "../../dist/run/s37-product-host-activation-v01.js";`,
      );
    }
    const inspectedSource = file === "reconcile-anchor.mjs"
      ? source.replaceAll(approvedReconcileApi, "")
      : source;
    expect(source).not.toMatch(/node:(?:crypto|fs|child_process|net|http|https)/u);
    expect(inspectedSource).not.toMatch(/(?:sign|verify|canonical|schema_version|parseS37|applyS37|reconcileS37|issueS37)/u);
    expect(inspectedSource).not.toMatch(/(?:ssh|scp|https?:\/\/|vps|retry)/iu);
  });

  it("fails clearly when the built V03 contract is unavailable", async () => {
    await expect(loadV03Contract(async () => { throw new Error("missing"); }))
      .rejects.toThrow("V03_CONTRACT_NOT_BUILT: run pnpm build");
  });

  it("inspects only exact Debian 13 x86_64 nonroot controller/systemd/cgroup observations", async () => {
    const observe = vi.fn(async () => ({
      observed_at: "2026-08-23T12:00:00Z",
      platform: "linux",
      distribution: { id: "debian", version_id: "13" },
      architecture: "x86_64",
      kernel_release: "6.12.0",
      systemd_version: "257",
      cgroup_version: "v2",
      cgroup_controllers: ["pids", "memory", "cpu", "io", "cpuset"],
      host_identity_hash: `sha256:${"b".repeat(64)}`,
      boot_id_hash: `sha256:${"c".repeat(64)}`,
      observed_controller: { username: "loopeix", uid: 1001, gid: 1001, home: "/home/loopeix", shell: "/bin/bash" },
      user_manager: { active: true, runtime_directory: "/run/user/1001", bus_path: "/run/user/1001/bus" },
    }));
    const result = await inspectS37ProductHostBootstrapV03({
      expectedController: { username: "loopeix", uid: 1001 }, observe,
    });

    expect(result.ok).toBe(true);
    expect(observe).toHaveBeenCalledTimes(1);
    expect(record(result.inspection).required_cgroup_controllers).toEqual(["cpu", "io", "memory", "pids"]);
  });

  it("holds bootstrap inspection before loading the contract on incompatible hosts", async () => {
    const result = await inspectS37ProductHostBootstrapV03({
      expectedController: { username: "loopeix", uid: 1001 },
      observe: async () => ({ platform: "linux", distribution: { id: "debian", version_id: "12" } }),
    });
    expect(result).toEqual({ ok: false, error: "BOOTSTRAP_PRECONDITION_HOLD" });
  });

  it("stages three digest-pinned local files exclusively and durably as nonroot", async () => {
    const bytes = {
      supervisor: Buffer.from("supervisor"), probe: Buffer.from("probe"), bwrap: Buffer.from("bwrap"),
    };
    const trace: string[] = [];
    const io = {
      lstat: vi.fn(async () => ({ type: "file", nlink: 1 })),
      readFile: vi.fn(async (path: string) => bytes[path.split("/").at(-1)! as keyof typeof bytes]),
      writeExclusive: vi.fn(async (path: string, _data: Uint8Array, options: unknown) => { trace.push(`write:${path}:${JSON.stringify(options)}`); }),
      fsyncFile: vi.fn(async (path: string) => { trace.push(`fsync:${path}`); }),
      fsyncDirectory: vi.fn(async (path: string) => { trace.push(`dir:${path}`); }),
    };
    const artifacts = Object.fromEntries(Object.entries(bytes).map(([name, data]) => [name, {
      source_path: `/local/${name}`, sha256: sha(data),
    }]));
    const result = await stageS37ProductHostArtifactsV03({ uid: 1001, workDirectory: "/work/stage", artifacts, io });
    expect(result.ok).toBe(true);
    expect(io.writeExclusive).toHaveBeenCalledTimes(3);
    expect(trace.at(-1)).toBe("dir:/work/stage");
    expect(trace.join("\n")).toContain('"noFollow":true');
  });

  it("rejects a staging digest mismatch before creating a destination", async () => {
    const io = {
      lstat: vi.fn(async () => ({ type: "file", nlink: 1 })),
      readFile: vi.fn(async (path: string) => path.endsWith("bwrap") ? Buffer.from("wrong") : Buffer.from(path.split("/").at(-1)!)),
      writeExclusive: vi.fn(), fsyncFile: vi.fn(), fsyncDirectory: vi.fn(),
    };
    const artifacts = Object.fromEntries(["supervisor", "probe", "bwrap"].map((name) => [name, {
      source_path: `/local/${name}`, sha256: sha(Buffer.from(name)),
    }]));
    expect(await stageS37ProductHostArtifactsV03({ uid: 1001, workDirectory: "/work", artifacts, io }))
      .toEqual({ ok: false, error: "STAGE_DIGEST_MISMATCH" });
    expect(io.writeExclusive).not.toHaveBeenCalled();
  });

  it("installs only fixed root-owned paths with exclusive no-follow descriptors and directory sync", async () => {
    const trace: string[] = [];
    const digest = `sha256:${"d".repeat(64)}`;
    const io = {
      readFile: vi.fn(async () => Buffer.from("artifact")),
      open: vi.fn(async (path: string, flags: string[], mode: number) => { trace.push(`open:${path}:${flags.join(",")}:${mode}`); return path; }),
      writeAll: vi.fn(async (fd: string) => { trace.push(`write:${fd}`); }),
      fchown: vi.fn(async (fd: string) => { trace.push(`chown:${fd}`); }),
      fchmod: vi.fn(async (fd: string) => { trace.push(`chmod:${fd}`); }),
      fsync: vi.fn(async (fd: string) => { trace.push(`fsync:${fd}`); }),
      close: vi.fn(async (fd: string) => { trace.push(`close:${fd}`); }),
      fstat: vi.fn(async () => ({ type: "file", uid: 0, gid: 0, mode: 0o555, nlink: 1, dev: 1, ino: 2 })),
      lstat: vi.fn(async () => ({ type: "file", uid: 0, gid: 0, mode: 0o555, nlink: 1, dev: 1, ino: 2 })),
      fsyncDirectory: vi.fn(async (path: string) => { trace.push(`dir:${path}`); }),
    };
    const artifacts = Object.fromEntries(["supervisor", "probe", "bwrap"].map((name) => [name, { path: `/stage/${name}`, sha256: sha(Buffer.from("artifact")) }]));
    const result = await installS37ProductHostArtifactsV03({ uid: 0, artifacts, io });
    expect(result.ok).toBe(true);
    expect(io.open).toHaveBeenCalledTimes(3);
    expect(trace[0]).toContain("O_EXCL,O_NOFOLLOW");
    expect(trace.at(-1)).toBe("dir:/opt/loopeix/s37.1");
  });

  it("does not retry or overwrite an existing installed artifact", async () => {
    const exists = Object.assign(new Error("exists"), { code: "EEXIST" });
    const io = {
      readFile: vi.fn(async () => Buffer.from("artifact")), open: vi.fn(async () => { throw exists; }),
    };
    const digest = sha(Buffer.from("artifact"));
    const artifacts = Object.fromEntries(["supervisor", "probe", "bwrap"].map((name) => [name, { path: `/stage/${name}`, sha256: digest }]));
    expect(await installS37ProductHostArtifactsV03({ uid: 0, artifacts, io }))
      .toEqual({ ok: false, error: "INSTALL_ALREADY_EXISTS" });
    expect(io.open).toHaveBeenCalledTimes(1);
  });

  it("collects exactly five fixed-interval samples and passes the authoritative readiness evaluator", async () => {
    const evidence = record(archive("readiness.json"));
    const envelope = record(archive("envelope.json"));
    const samples = array(evidence.capacity_samples);
    const interval = envelope.sample_interval_seconds;
    expect(typeof interval).toBe("number");
    const sleep = vi.fn(async () => undefined);
    const result = await collectS37LinuxPhaseBReadinessV03({
      evidenceBase: evidence, envelope,
      observeSample: async (index: number) => samples[index], sleep,
    });
    expect(result.ok, JSON.stringify(result.violations)).toBe(true);
    expect(array(record(result.evidence).capacity_samples)).toHaveLength(5);
    expect(sleep).toHaveBeenCalledTimes(4);
    expect(sleep).toHaveBeenCalledWith((interval as number) * 1000);
  });

  it("runs one exact random unit without retry and seals an empty container snapshot when no observer exists", async () => {
    const executeOnce = vi.fn(async ({ unitName }: { unitName: string }) => ({ unitName, exit_code: 0 }));
    const observeNeighbors = vi.fn()
      .mockResolvedValueOnce({ ports: "before", services: "before" })
      .mockResolvedValueOnce({ ports: "after", services: "after" });
    const result = await runS37LinuxConformanceOnceV03({
      randomBytes: vi.fn(async (size: number) => { expect(size).toBe(6); return Uint8Array.from([0x51, 0x5c, 0x7f, 0xa5, 0xe6, 0xba]); }),
      observeNeighbors, executeOnce,
    });
    expect(result.ok).toBe(true);
    expect(executeOnce).toHaveBeenCalledTimes(1);
    const capture = record(result.capture);
    expect(capture.unitName).toBe("loopeix-s37.1-conformance-515c7fa5e6ba");
    expect(capture.containers_before).toEqual(capture.containers_after);
    expect(record(capture.containers_before).count).toBe(0);
  });

  it("pure-finalizes the canonical synthetic archive only through both authoritative evaluators", () => {
    const evidence = record(archive("evidence.json"));
    const hostTuple = record(evidence.host_tuple);
    const documents = {
      manifest: archive("manifest.json"), readiness: archive("readiness.json"), envelope: archive("envelope.json"),
      profile: archive("product-profile.json"), evidence, receipt: archive("receipt.json"),
      asOf: hostTuple.observed_at,
    };
    const finalized = finalizeS37LinuxConformanceV03(documents);
    expect(finalized.ok).toBe(true);
    expect(Object.isFrozen(finalized)).toBe(true);
    expect(Object.isFrozen(record(finalized.finalized).manifest)).toBe(true);
    record(documents.manifest).created_at = "hostile-mutation";
    expect(record(record(finalized.finalized).manifest).created_at).not.toBe("hostile-mutation");
    const held = finalizeS37LinuxConformanceV03({ ...documents, readiness: {} });
    expect(held).toMatchObject({
      ok: false,
      failure: {
        stage: "readiness",
        error: "FINALIZE_READINESS_HOLD",
        readiness_ok: false,
        conformance_ok: false,
        pass_artifacts_minted: false,
      },
    });
  });

  it("rejects hostile accessors without invoking them or echoing input", () => {
    let getterCalls = 0;
    const hostile = Object.fromEntries([
      "readiness", "envelope", "profile", "evidence", "receipt", "asOf",
    ].map((key) => [key, null]));
    Object.defineProperty(hostile, "manifest", {
      enumerable: true,
      get() { getterCalls += 1; throw new Error("secret-hostile-value"); },
    });
    const result = finalizeS37LinuxConformanceV03(hostile);
    expect(result).toEqual({ ok: false, error: "FINALIZE_INPUT_INVALID" });
    expect(getterCalls).toBe(0);
    expect(JSON.stringify(result)).not.toContain("secret-hostile-value");
  });

  it("rejects oversized object keys within the inert snapshot byte budget", () => {
    const oversizedKey = "k".repeat((4 * 1024 * 1024) + 1);
    const documents: Record<string, unknown> = Object.create(null);
    for (const key of ["manifest", "readiness", "envelope", "profile", "evidence", "receipt", "asOf"]) {
      documents[key] = key === "manifest" ? { [oversizedKey]: true } : {};
    }
    expect(finalizeS37LinuxConformanceV03(documents)).toEqual({
      ok: false,
      error: "FINALIZE_INPUT_INVALID",
    });
  });

  it("does not echo hostile nested keys from authoritative validation failures", () => {
    const evidence = record(archive("evidence.json"));
    const documents = {
      manifest: { ...record(archive("manifest.json")), secret_hostile_key: "secret-hostile-value" },
      readiness: archive("readiness.json"), envelope: archive("envelope.json"), profile: archive("product-profile.json"),
      evidence, receipt: archive("receipt.json"), asOf: record(evidence.host_tuple).observed_at,
    };
    const result = finalizeS37LinuxConformanceV03(documents);
    expect(result).toMatchObject({ ok: false, failure: { error: "FINALIZE_CONFORMANCE_HOLD" } });
    expect(JSON.stringify(result)).not.toContain("secret_hostile_key");
    expect(JSON.stringify(result)).not.toContain("secret-hostile-value");
  });
});
