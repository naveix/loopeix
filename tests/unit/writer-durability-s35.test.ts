import { existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { allocateAndCommitCompileIdentityV02 } from "../../src/compiler/compile-id.js";
import { COMPILE_STORE_SENTINEL_TEXT, verifyCompileStoreV02 } from "../../src/compiler/compile-store.js";
import {
  anchorDestinationRootV02,
  captureOutputBytes,
  confirmV02CompilerProjection,
  createV02CompilerWriteAuthoritySet,
  createV02PlannedRunWriteAuthority,
  openV02OutputAdmissionSession,
  parseDirectChildName,
  prepareV02PlannedRunsRoot,
  scanAndAdmitOutputBytes,
  sealV02OutputAdmissionSession,
  writeV02CompilerOutputs,
  writeV02PlannedRunOutputs,
  type V02CompilerWriteAuthoritySet,
  type V02OutputPurpose,
  type V02PlannedRunWriteAuthority,
} from "../../src/io/output-capabilities.js";
import type { CompilerWriterHelperResponse } from "../../src/io/compiler-writer-protocol.js";

const roots: string[] = [];
let sequence = 0;
const hash = (character: string): string => `sha256:${character.repeat(64)}`;

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function bytes(name: string): Uint8Array {
  return new TextEncoder().encode(name === "generated.loop.yaml" ? "schema_version: 0.2\n" : `${name}\n`);
}

async function authority(
  compileRoot: string,
  standaloneRoot: string | null = null,
  compileId: string | null = null,
): Promise<V02CompilerWriteAuthoritySet> {
  sequence += 1;
  const purposes = (standaloneRoot === null ? ["compile-pack"] : ["standalone-loop", "compile-pack"]) as V02OutputPurpose[];
  const projection = confirmV02CompilerProjection({
    kind: "compiler",
    schema_version: "0.2",
    compiler_bundle_id: `bundle_test_${sequence}`,
    catalog_version_hash: hash("a"),
    binding_input_hash: hash("b"),
    requested_output_purposes: purposes,
    output_budget_bytes: 33_554_432,
    compile_id: compileId ?? `compile_test_${sequence}`,
    source_authoring_hash: hash("c"),
    terminal_state: "compiled",
  });
  if (!projection.ok) throw new Error(projection.message);
  const sets = [];
  for (const purpose of purposes) {
    const session = openV02OutputAdmissionSession(projection.projection, purpose);
    if (!session.ok) throw new Error(session.message);
    for (const name of session.session.allowed_members) {
      const captured = captureOutputBytes(session.session, name, bytes(name));
      if (!captured.ok) throw new Error(captured.message);
      const admitted = scanAndAdmitOutputBytes(captured.capture);
      if (!admitted.ok) throw new Error("message" in admitted ? admitted.message : admitted.reason);
    }
    const sealed = sealV02OutputAdmissionSession(session.session);
    if (!sealed.ok) throw new Error(sealed.message);
    sets.push(sealed.output_set);
  }
  const compileAnchor = await anchorDestinationRootV02(compileRoot, "compile-store");
  if (!compileAnchor.ok) throw new Error(compileAnchor.message);
  const standaloneAnchor = standaloneRoot === null ? null : await anchorDestinationRootV02(standaloneRoot, "standalone-parent");
  if (standaloneAnchor !== null && !standaloneAnchor.ok) throw new Error(standaloneAnchor.message);
  const created = createV02CompilerWriteAuthoritySet(
    projection.projection,
    { compile_pack: compileAnchor.root, standalone_loop: standaloneAnchor?.root ?? null },
    sets,
  );
  if (!created.ok) throw new Error(created.message);
  return created.authorities;
}

async function plannedAuthority(workspace: string, runId = "run_test_0011223344556677"): Promise<{
  authority: V02PlannedRunWriteAuthority;
  bytesByName: ReadonlyMap<string, Uint8Array>;
}> {
  mkdirSync(join(workspace, ".loopeix", "loops"), { recursive: true, mode: 0o700 });
  const prepared = await prepareV02PlannedRunsRoot(workspace, "minimal-loop");
  if (!prepared.ok) throw new Error(prepared.message);
  const projection = (await import("../../src/io/output-capabilities.js")).confirmV02PlanProjection({
    kind: "plan", schema_version: "0.2", source_pack_root_hash: hash("a"), run_id: runId,
    output_budget_bytes: 33_554_432, loop_family: "minimal-loop", workspace_root_hash: hash("b"), engine: "codex",
  });
  if (!projection.ok) throw new Error(projection.message);
  const opened = openV02OutputAdmissionSession(projection.projection, "planned-run");
  if (!opened.ok) throw new Error(opened.message);
  const bytesByName = new Map<string, Uint8Array>();
  for (const name of opened.session.allowed_members) {
    const memberBytes = new TextEncoder().encode(`${name}\n`);
    bytesByName.set(name, memberBytes);
    const captured = captureOutputBytes(opened.session, name, memberBytes);
    if (!captured.ok) throw new Error(captured.message);
    const admitted = scanAndAdmitOutputBytes(captured.capture);
    if (!admitted.ok) throw new Error("message" in admitted ? admitted.message : admitted.reason);
  }
  const sealed = sealV02OutputAdmissionSession(opened.session);
  if (!sealed.ok) throw new Error(sealed.message);
  const created = createV02PlannedRunWriteAuthority(projection.projection, prepared.root, sealed.output_set);
  if (!created.ok || created.authority.purpose !== "planned-run") throw new Error(created.message);
  return { authority: created.authority, bytesByName };
}

describe("S35 compiler writer durability", () => {
  it("rebuilds fresh candidate-bound authority after a real writer collision", async () => {
    const workspace = mkdtempSync(join(tmpdir(), "loopeix-s35-writer-allocation-"));
    const compileRoot = join(workspace, ".loopeix", "compiles");
    mkdirSync(compileRoot, { recursive: true });
    writeFileSync(join(compileRoot, ".gitignore"), COMPILE_STORE_SENTINEL_TEXT, { mode: 0o600 });
    roots.push(workspace);
    const verified = await verifyCompileStoreV02(workspace);
    if (!verified.ok) throw new Error(verified.message);

    const firstId = "compile_1_deadbeefcafebabe";
    mkdirSync(join(compileRoot, firstId), { mode: 0o700 });
    const entropy = [
      Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]),
      Uint8Array.from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
    ];
    const attempted: string[] = [];

    const result = await allocateAndCommitCompileIdentityV02(verified.store, {
      now: () => 1,
      randomBytes: () => entropy.shift()!,
      commitCandidate: async (_store, identity) => {
        attempted.push(identity.compile_id);
        const output = await authority(compileRoot, null, identity.compile_id);
        const written = await writeV02CompilerOutputs(output, null);
        return written.ok
          ? { ok: true, pack_ref: identity.compile_id }
          : { ok: false, reason: written.reason, message: written.message };
      },
    });

    expect(result).toMatchObject({ ok: true, identity: { compile_id: "compile_1_1122334455667788" } });
    expect(attempted).toEqual([firstId, "compile_1_1122334455667788"]);
    expect(readdirSync(join(compileRoot, firstId))).toEqual([]);
    expect(readdirSync(join(compileRoot, "compile_1_1122334455667788"))).toContain("pack-manifest.json");
  });

  it("never treats an ambient empty compile-ID reservation as writer success", async () => {
    const compileRoot = mkdtempSync(join(tmpdir(), "loopeix-s35-empty-reservation-"));
    roots.push(compileRoot);
    const output = await authority(compileRoot);
    const reservedPath = join(compileRoot, output.compile_pack.compile_id);
    mkdirSync(reservedPath, { mode: 0o700 });

    await expect(writeV02CompilerOutputs(output, null)).resolves.toMatchObject({
      ok: false,
      reason: "DESTINATION_EXISTS",
      pack_ref: null,
      standalone_ref: null,
    });
    expect(existsSync(reservedPath)).toBe(true);
    expect(readdirSync(reservedPath)).toEqual([]);
  });

  it("reserves pack first, then removes only its empty reservation when standalone already exists", async () => {
    const compileRoot = mkdtempSync(join(tmpdir(), "loopeix-s35-pack-first-"));
    const standaloneRoot = mkdtempSync(join(tmpdir(), "loopeix-s35-pack-first-out-"));
    roots.push(compileRoot, standaloneRoot);
    const output = await authority(compileRoot, standaloneRoot);
    const standaloneName = parseDirectChildName("existing.loop.yaml")!;
    const existingPath = join(standaloneRoot, standaloneName);
    writeFileSync(existingPath, "operator-owned\n", { mode: 0o600 });

    await expect(writeV02CompilerOutputs(output, standaloneName)).resolves.toMatchObject({
      ok: false,
      reason: "DESTINATION_EXISTS",
      pack_ref: null,
      standalone_ref: null,
    });
    expect(readFileSync(existingPath, "utf8")).toBe("operator-owned\n");
    expect(existsSync(join(compileRoot, output.compile_pack.compile_id))).toBe(false);
  });

  it.each([
    "DESTINATION_EXISTS",
    "INVALID_OUTPUT_CAPTURE",
    "IO_HELPER_UNAVAILABLE",
    "IO_IDENTITY_MISMATCH",
    "IO_DURABILITY_UNCONFIRMED",
  ] as const)("returns no destination reference for helper failure %s", async (reason) => {
    const compileRoot = mkdtempSync(join(tmpdir(), "loopeix-s35-writer-failure-"));
    roots.push(compileRoot);
    const output = await authority(compileRoot);
    const response: CompilerWriterHelperResponse = reason === "DESTINATION_EXISTS"
      ? { ok: false, reason, message: "sanitized failure", collision_destination: "compile-pack" }
      : { ok: false, reason, message: "sanitized failure" };
    await expect(writeV02CompilerOutputs(output, null, { runHelper: async () => response })).resolves.toEqual({
      ok: false,
      reason,
      ...(reason === "DESTINATION_EXISTS" ? { collision_destination: "compile-pack" } : {}),
      message: {
        DESTINATION_EXISTS: "Destination already exists.",
        INVALID_OUTPUT_CAPTURE: "The compiler output authority or captured output is invalid.",
        IO_HELPER_UNAVAILABLE: "Required filesystem helper is unavailable.",
        IO_IDENTITY_MISMATCH: "Filesystem identity validation failed.",
        IO_DURABILITY_UNCONFIRMED: "Filesystem durability could not be confirmed.",
      }[reason],
      pack_ref: null,
      standalone_ref: null,
    });
    expect(readdirSync(compileRoot)).toEqual([]);
  });

  it("maps a rejected helper promise to the closed unavailable result", async () => {
    const compileRoot = mkdtempSync(join(tmpdir(), "loopeix-s35-writer-reject-"));
    roots.push(compileRoot);
    const output = await authority(compileRoot);
    await expect(writeV02CompilerOutputs(output, null, {
      runHelper: async () => { throw new Error("private detail"); },
    })).resolves.toEqual({
      ok: false,
      reason: "IO_HELPER_UNAVAILABLE",
      message: "Required filesystem helper is unavailable.",
      pack_ref: null,
      standalone_ref: null,
    });
  });
});

describe("S35 planned-run writer durability", () => {
  it("reserves every canonical member before writing any content", async () => {
    const workspace = realpathSync(mkdtempSync(join(tmpdir(), "loopeix-s35-planned-reserve-")));
    roots.push(workspace);
    const planned = await plannedAuthority(workspace);
    const runPath = join(workspace, ".loopeix", "loops", "minimal-loop", "runs", planned.authority.run_id);
    let inspected = false;

    const result = await writeV02PlannedRunOutputs(planned.authority, {
      after_all_reservations: () => {
        inspected = true;
        expect(readdirSync(runPath).sort()).toEqual([
          "binding-input.json", "catalog-resolution.json", "compilation-record.json",
          "compile-pack-manifest.json", "generated.loop.yaml", "intake-brief.json",
          "intake-record.json", "resolved-run-plan.json", "work-item.json",
        ]);
        for (const name of readdirSync(runPath)) expect(statSync(join(runPath, name)).size).toBe(0);
      },
    });

    expect(inspected).toBe(true);
    expect(result.ok).toBe(true);
  });

  it("commits all nine members in order and derives the public plan hash and relative run ref", async () => {
    const workspace = realpathSync(mkdtempSync(join(tmpdir(), "loopeix-s35-planned-write-")));
    roots.push(workspace);
    const planned = await plannedAuthority(workspace);

    const result = await writeV02PlannedRunOutputs(planned.authority);
    expect(result).toEqual({
      ok: true,
      run_id: planned.authority.run_id,
      resolved_run_plan_hash: hashRaw(planned.bytesByName.get("resolved-run-plan.json")!),
      run_ref: `.loopeix/loops/minimal-loop/runs/${planned.authority.run_id}`,
    });
    const runPath = join(workspace, result.run_ref);
    expect(readdirSync(runPath).sort()).toEqual([
      "binding-input.json", "catalog-resolution.json", "compilation-record.json",
      "compile-pack-manifest.json", "generated.loop.yaml", "intake-brief.json",
      "intake-record.json", "resolved-run-plan.json", "work-item.json",
    ]);
    for (const [name, memberBytes] of planned.bytesByName) {
      expect(readFileSync(join(runPath, name))).toEqual(Buffer.from(memberBytes));
      expect(statSync(join(runPath, name)).mode & 0o777).toBe(0o600);
    }
    expect(statSync(runPath).mode & 0o777).toBe(0o700);
  });

  it("returns a retryable collision without consuming or changing the existing candidate", async () => {
    const workspace = realpathSync(mkdtempSync(join(tmpdir(), "loopeix-s35-planned-collision-")));
    roots.push(workspace);
    const planned = await plannedAuthority(workspace);
    const runPath = join(workspace, ".loopeix", "loops", "minimal-loop", "runs", planned.authority.run_id);
    mkdirSync(runPath, { mode: 0o700 });
    writeFileSync(join(runPath, "operator-owned"), "preserve\n");

    await expect(writeV02PlannedRunOutputs(planned.authority)).resolves.toEqual({
      ok: false, reason: "DESTINATION_EXISTS", message: "Destination already exists.",
      run_id: null, resolved_run_plan_hash: null, run_ref: null,
    });
    expect(readFileSync(join(runPath, "operator-owned"), "utf8")).toBe("preserve\n");
  });

  it("retains an inspectable candidate and withholds success identity after content durability ambiguity", async () => {
    const workspace = realpathSync(mkdtempSync(join(tmpdir(), "loopeix-s35-planned-ambiguous-")));
    roots.push(workspace);
    const planned = await plannedAuthority(workspace);
    const expectedRef = `.loopeix/loops/minimal-loop/runs/${planned.authority.run_id}`;

    await expect(writeV02PlannedRunOutputs(planned.authority, {
      after_member_fsync: (name) => { if (name === "work-item.json") throw new Error("injected"); },
    })).resolves.toEqual({
      ok: false, reason: "IO_DURABILITY_UNCONFIRMED", message: "Filesystem durability could not be confirmed.",
      run_id: null, resolved_run_plan_hash: null, run_ref: expectedRef,
    });
    expect(existsSync(join(workspace, expectedRef))).toBe(true);
    expect(readFileSync(join(workspace, expectedRef, "work-item.json"), "utf8")).toBe("work-item.json\n");
    expect(statSync(join(workspace, expectedRef, "binding-input.json")).size).toBe(0);
    await expect(writeV02PlannedRunOutputs(planned.authority)).resolves.toMatchObject({ ok: false, reason: "INVALID_OUTPUT_CAPTURE" });
  });
});

function hashRaw(input: Uint8Array): string {
  return `sha256:${createHash("sha256").update(input).digest("hex")}`;
}
