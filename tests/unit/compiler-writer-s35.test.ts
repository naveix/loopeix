import { lstatSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  anchorDestinationRootV02,
  captureOutputBytes,
  confirmV02CompilerProjection,
  createV02CompilerWriteAuthoritySet,
  openV02OutputAdmissionSession,
  parseDirectChildName,
  scanAndAdmitOutputBytes,
  sealV02OutputAdmissionSession,
  writeV02CompilerOutputs,
  type V02CompilerWriteAuthoritySet,
  type V02OutputPurpose,
} from "../../src/io/output-capabilities.js";
import type { CompilerWriterHelperRequest } from "../../src/io/compiler-writer-protocol.js";

const roots: string[] = [];
const hash = (character: string): string => `sha256:${character.repeat(64)}`;

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function memberBytes(name: string): Uint8Array {
  if (name === "generated.loop.yaml") return new TextEncoder().encode("schema_version: 0.2\nloop_family: test\n");
  if (name === "compile-report.md") return new TextEncoder().encode("# Compile report\n");
  return new TextEncoder().encode(`${JSON.stringify({ schema_version: "0.2", member: name })}\n`);
}

async function makeAuthoritySet(
  compileRoot: string,
  standaloneRoot: string | null,
  terminalState: "compiled" | "hold-risk" = "compiled",
): Promise<V02CompilerWriteAuthoritySet> {
  const purposes = standaloneRoot === null ? ["compile-pack"] : ["standalone-loop", "compile-pack"];
  const confirmed = confirmV02CompilerProjection({
    kind: "compiler",
    schema_version: "0.2",
    compiler_bundle_id: "bundle_test",
    catalog_version_hash: hash("a"),
    binding_input_hash: hash("b"),
    requested_output_purposes: purposes,
    output_budget_bytes: 33_554_432,
    compile_id: "compile_test",
    source_authoring_hash: hash("c"),
    terminal_state: terminalState,
  });
  if (!confirmed.ok) throw new Error(confirmed.message);

  const sealed = [];
  for (const purpose of purposes as V02OutputPurpose[]) {
    const opened = openV02OutputAdmissionSession(confirmed.projection, purpose);
    if (!opened.ok) throw new Error(opened.message);
    for (const name of opened.session.allowed_members) {
      const captured = captureOutputBytes(opened.session, name, memberBytes(name));
      if (!captured.ok) throw new Error(captured.message);
      const admitted = scanAndAdmitOutputBytes(captured.capture);
      if (!admitted.ok) throw new Error("message" in admitted ? admitted.message : admitted.reason);
    }
    const output = sealV02OutputAdmissionSession(opened.session);
    if (!output.ok) throw new Error(output.message);
    sealed.push(output.output_set);
  }
  const compileAnchor = await anchorDestinationRootV02(compileRoot, "compile-store");
  if (!compileAnchor.ok) throw new Error(compileAnchor.message);
  const standaloneAnchor = standaloneRoot === null
    ? null
    : await anchorDestinationRootV02(standaloneRoot, "standalone-parent");
  if (standaloneAnchor !== null && !standaloneAnchor.ok) throw new Error(standaloneAnchor.message);
  const authority = createV02CompilerWriteAuthoritySet(
    confirmed.projection,
    {
      compile_pack: compileAnchor.root,
      standalone_loop: standaloneAnchor?.root ?? null,
    },
    sealed,
  );
  if (!authority.ok) throw new Error(authority.message);
  return authority.authorities;
}

describe("S35 V02 compiler writer", () => {
  it("writes a dual-destination compiled result with exact modes and manifest-last inventory", async () => {
    const compileRoot = mkdtempSync(join(tmpdir(), "loopeix-s35-writer-store-"));
    const standaloneRoot = mkdtempSync(join(tmpdir(), "loopeix-s35-writer-out-"));
    roots.push(compileRoot, standaloneRoot);
    const authority = await makeAuthoritySet(compileRoot, standaloneRoot);
    const standaloneName = parseDirectChildName("compiled.loop.yaml")!;

    await expect(writeV02CompilerOutputs(authority, standaloneName)).resolves.toEqual({
      ok: true,
      pack_ref: "compile_test",
      standalone_ref: standaloneName,
    });

    const packPath = join(compileRoot, "compile_test");
    expect(statSync(packPath).mode & 0o777).toBe(0o700);
    expect(statSync(join(standaloneRoot, standaloneName)).mode & 0o777).toBe(0o600);
    const names = readdirSync(packPath).sort();
    expect(names).toEqual([
      "binding-input.json",
      "catalog-resolution.json",
      "compilation-record.json",
      "compile-report.md",
      "generated.loop.yaml",
      "intake-record.json",
      "pack-manifest.json",
      "work-item.json",
    ]);
    for (const name of names) expect(lstatSync(join(packPath, name)).mode & 0o777).toBe(0o600);
    expect(readFileSync(join(packPath, "generated.loop.yaml"))).toEqual(readFileSync(join(standaloneRoot, standaloneName)));
    await expect(writeV02CompilerOutputs(authority, standaloneName)).resolves.toMatchObject({
      ok: false,
      reason: "INVALID_OUTPUT_CAPTURE",
      pack_ref: null,
      standalone_ref: null,
    });
  });

  it("writes a HOLD pack without compiled-only or standalone members", async () => {
    const compileRoot = mkdtempSync(join(tmpdir(), "loopeix-s35-writer-hold-"));
    roots.push(compileRoot);
    const authority = await makeAuthoritySet(compileRoot, null, "hold-risk");
    await expect(writeV02CompilerOutputs(authority, null)).resolves.toMatchObject({ ok: true, standalone_ref: null });
    expect(readdirSync(join(compileRoot, "compile_test")).sort()).toEqual([
      "binding-input.json",
      "catalog-resolution.json",
      "compile-report.md",
      "intake-record.json",
      "pack-manifest.json",
      "work-item.json",
    ]);
  });

  it("clones the complete request before the helper boundary and preserves manifest-last ordering", async () => {
    const compileRoot = mkdtempSync(join(tmpdir(), "loopeix-s35-writer-request-"));
    const standaloneRoot = mkdtempSync(join(tmpdir(), "loopeix-s35-writer-request-out-"));
    roots.push(compileRoot, standaloneRoot);
    const authority = await makeAuthoritySet(compileRoot, standaloneRoot);
    const standaloneName = parseDirectChildName("output.loop.yaml")!;
    let observed: { workingDirectory: string; request: CompilerWriterHelperRequest } | null = null;
    const result = await writeV02CompilerOutputs(authority, standaloneName, {
      runHelper: async (workingDirectory, request) => {
        observed = { workingDirectory, request };
        return { ok: true };
      },
    });
    expect(observed).not.toBeNull();
    expect(observed!.workingDirectory).toBe(realpathSync(compileRoot));
    expect(observed!.request.pack_members.at(-1)?.name).toBe("pack-manifest.json");
    expect(observed!.request.pack_members.map((member) => member.name)).toContain("generated.loop.yaml");
    expect(observed!.request.standalone?.basename).toBe(standaloneName);
    const packYaml = observed!.request.pack_members.find((member) => member.name === "generated.loop.yaml")?.bytes_base64;
    expect(observed!.request.standalone?.bytes_base64).toBe(packYaml);
    expect(result).toMatchObject({ ok: true, pack_ref: "compile_test", standalone_ref: standaloneName });
    expect(readdirSync(compileRoot)).toEqual([]);
    expect(readdirSync(standaloneRoot)).toEqual([]);
  });
});
