import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { readCompilePackV01 } from "../../src/compiler/read-pack.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

async function loadV01Harness() {
  const output = await import("../../src/io/output-capabilities.js");
  const api = output as unknown as Record<string, (...args: any[]) => any>;
  const packRoot = join(import.meta.dirname, "../fixtures/compat/s35/v01/compiled-safe-bugfix");
  const names = ["catalog-resolution.json", "compilation-record.json", "compile-report.md", "generated.loop.yaml", "intake-record.json", "pack-manifest.json", "work-item.json"].map((name) => output.parseDirectChildName(name)!);
  const catalog = JSON.parse(readFileSync(join(packRoot, "catalog-resolution.json"), "utf8")) as { catalog_version_hash: string };
  return { output, api, packRoot, names, catalogVersionHash: catalog.catalog_version_hash };
}

async function makeV01Identity(harness: Awaited<ReturnType<typeof loadV01Harness>>) {
  const { output, api, packRoot, names, catalogVersionHash } = harness;
  const read = await output.openAnchoredReadSession(packRoot);
  if (!read.ok) throw new Error(read.message);
  const adapter = await api.issueV01SourcePackRegistrationAdapter(read.session, names, null);
  const pack = await api.createRegisteredSourceCompilePackV01(adapter.adapter);
  const access = api.issueV01SourcePackAccess(pack.pack);
  const identity = await api.registerCapturedPackIdentityV01(access.access, { schema_version: "0.1", catalog_version_hash: catalogVersionHash }, null);
  return { pack, identity };
}

describe("S35 output capability facade", () => {
  it("rejects a symlinked loop-family boundary during planned-root preparation", async () => {
    const workspace = realpathSync(mkdtempSync(join(tmpdir(), "loopeix-s35-planned-symlink-")));
    const outside = realpathSync(mkdtempSync(join(tmpdir(), "loopeix-s35-planned-outside-")));
    roots.push(workspace, outside);
    mkdirSync(join(workspace, ".loopeix", "loops"), { recursive: true, mode: 0o700 });
    symlinkSync(outside, join(workspace, ".loopeix", "loops", "minimal-loop"));

    await expect((await import("../../src/io/output-capabilities.js")).prepareV02PlannedRunsRoot(
      workspace,
      "minimal-loop",
    )).resolves.toMatchObject({ ok: false, reason: "IO_IDENTITY_MISMATCH" });
  });

  it("permits planned-run authority only from the securely prepared family runs root", async () => {
    const output = await import("../../src/io/output-capabilities.js");
    const workspace = realpathSync(mkdtempSync(join(tmpdir(), "loopeix-s35-planned-root-")));
    roots.push(workspace);
    mkdirSync(join(workspace, ".loopeix", "loops"), { recursive: true, mode: 0o700 });

    const prepared = await output.prepareV02PlannedRunsRoot(workspace, "minimal-loop");
    expect(prepared).toMatchObject({ ok: true });
    if (!prepared.ok) throw new Error(prepared.message);

    const projection = output.confirmV02PlanProjection({
      kind: "plan",
      schema_version: "0.2",
      source_pack_root_hash: `sha256:${"a".repeat(64)}`,
      run_id: "run_test_0011223344556677",
      output_budget_bytes: 33_554_432,
      loop_family: "minimal-loop",
      workspace_root_hash: `sha256:${"b".repeat(64)}`,
      engine: "codex",
    });
    if (!projection.ok) throw new Error(projection.message);
    const session = output.openV02OutputAdmissionSession(projection.projection, "planned-run");
    if (!session.ok) throw new Error(session.message);
    for (const name of session.session.allowed_members) {
      const captured = output.captureOutputBytes(session.session, name, new TextEncoder().encode(`${name}\n`));
      if (!captured.ok) throw new Error(captured.message);
      const admitted = output.scanAndAdmitOutputBytes(captured.capture);
      if (!admitted.ok) throw new Error("message" in admitted ? admitted.message : admitted.reason);
    }
    const sealed = output.sealV02OutputAdmissionSession(session.session);
    if (!sealed.ok) throw new Error(sealed.message);
    const genericAnchor = await output.anchorDestinationRootV02(
      join(workspace, ".loopeix", "loops", "minimal-loop", "runs"),
      "runs-root",
    );
    if (!genericAnchor.ok) throw new Error(genericAnchor.message);
    expect(output.createV02PlannedRunWriteAuthority(
      projection.projection,
      genericAnchor.root,
      sealed.output_set,
    )).toMatchObject({ ok: false, reason: "INVALID_INPUT_ROOT" });
    expect(output.createV02PlannedRunWriteAuthority(
      projection.projection,
      prepared.root,
      sealed.output_set,
    )).toMatchObject({ ok: true });
  });

  it("rejects caller-authored V02 projection/session/capture lookalikes without writing", async () => {
    const output = await import("../../src/io/output-capabilities.js");
    const root = mkdtempSync(join(tmpdir(), "loopeix-s35-output-capabilities-"));
    roots.push(root);
    const forgedProjection = {
      schema_version: "0.2",
      compiler_bundle_id: "bundle_test",
      catalog_version_hash: `sha256:${"a".repeat(64)}`,
      binding_input_hash: `sha256:${"b".repeat(64)}`,
      requested_output_purposes: ["compile-pack"],
      output_budget_bytes: 33_554_432,
    };

    expect(output.confirmV02CompilerProjection(forgedProjection)).toMatchObject({
      ok: false,
      reason: "INVALID_V02_PROJECTION",
    });
    expect(output.confirmV02PlanProjection(forgedProjection)).toMatchObject({
      ok: false,
      reason: "INVALID_V02_PROJECTION",
    });
    expect(output.confirmV02ReportProjection(forgedProjection)).toMatchObject({
      ok: false,
      reason: "INVALID_V02_PROJECTION",
    });
    expect(output.openV02OutputAdmissionSession(forgedProjection as never, "compile-pack")).toMatchObject({
      ok: false,
      reason: "INVALID_V02_PROJECTION",
    });
    expect(
      output.captureOutputBytes(
        forgedProjection as never,
        output.parseDirectChildName("pack-manifest.json")!,
        new Uint8Array([1, 2, 3]),
      ),
    ).toMatchObject({ ok: false, reason: "INVALID_OUTPUT_CAPTURE" });
    expect(output.scanAndAdmitOutputBytes(forgedProjection as never)).toMatchObject({
      ok: false,
      reason: "INVALID_OUTPUT_CAPTURE",
    });
    expect(output.sealV02OutputAdmissionSession(forgedProjection as never)).toMatchObject({
      ok: false,
      reason: "INVALID_OUTPUT_CAPTURE",
    });
    expect(await output.issueV02DestinationCapability(forgedProjection as never)).toMatchObject({
      ok: false,
      reason: "INVALID_OUTPUT_CAPTURE",
    });
    expect(await output.openAnchoredWriteSession(root, forgedProjection as never)).toMatchObject({
      ok: false,
      reason: "INVALID_OUTPUT_CAPTURE",
    });
    expect(readdirSync(root)).toEqual([]);
  });

  it("keeps V01 replay authority inert for every structural forgery", async () => {
    const output = await import("../../src/io/output-capabilities.js");
    const forged = {
      schema_version: "0.1",
      source_pack_root_hash: `sha256:${"c".repeat(64)}`,
      catalog_version_hash: `sha256:${"d".repeat(64)}`,
      origin: "captured-source",
    };

    expect(await output.createRegisteredSourceCompilePackV01(forged as never)).toMatchObject({
      ok: false,
      reason: "INVALID_V01_REPLAY_OUTPUT",
    });
    expect(await output.createRegisteredRegeneratedCompilePackV01(forged as never, forged as never)).toMatchObject({
      ok: false,
      reason: "INVALID_V01_REPLAY_OUTPUT",
    });
    expect(output.issueV01SourcePackAccess(forged as never)).toMatchObject({
      ok: false,
      reason: "INVALID_V01_REPLAY_OUTPUT",
    });
    expect(output.issueV01RegeneratedPackAccess(forged as never, forged as never)).toMatchObject({
      ok: false,
      reason: "INVALID_V01_REPLAY_OUTPUT",
    });
    expect(output.createV01ReplayOutputAuthority(forged as never, forged as never)).toMatchObject({
      ok: false,
      reason: "INVALID_V01_REPLAY_OUTPUT",
    });
  });

  it("registers V01 source and regeneration scaffolding without proving exact replay success", async () => {
    const output = await import("../../src/io/output-capabilities.js");
    const api = output as unknown as Record<string, (...args: any[]) => any>;
    const packRoot = join(import.meta.dirname, "../fixtures/compat/s35/v01/compiled-safe-bugfix");
    const names = [
      "catalog-resolution.json", "compilation-record.json", "compile-report.md",
      "generated.loop.yaml", "intake-record.json", "pack-manifest.json", "work-item.json",
    ].map((name) => output.parseDirectChildName(name)!);
    const catalog = JSON.parse(readFileSync(join(packRoot, "catalog-resolution.json"), "utf8")) as { catalog_version_hash: string };

    const read = await output.openAnchoredReadSession(packRoot);
    expect(read.ok).toBe(true);
    if (!read.ok) throw new Error(read.message);
    const sourceAdapter = await api.issueV01SourcePackRegistrationAdapter(read.session, names, null);
    expect(sourceAdapter.ok).toBe(true);
    const sourcePack = await api.createRegisteredSourceCompilePackV01(sourceAdapter.adapter);
    expect(sourcePack.ok).toBe(true);
    const workItemName = output.parseDirectChildName("work-item.json")!;
    const firstWorkItem = await sourcePack.pack.parseV01Member(workItemName, "work-item");
    expect(firstWorkItem.ok).toBe(true);
    if (!firstWorkItem.ok || typeof firstWorkItem.value !== "object" || firstWorkItem.value === null) throw new Error("missing work item");
    (firstWorkItem.value as { prompt?: string }).prompt = "mutated caller copy";
    const secondWorkItem = await sourcePack.pack.parseV01Member(workItemName, "work-item");
    expect(secondWorkItem.ok).toBe(true);
    if (!secondWorkItem.ok || typeof secondWorkItem.value !== "object" || secondWorkItem.value === null) throw new Error("missing work item");
    expect((secondWorkItem.value as { prompt?: string }).prompt).not.toBe("mutated caller copy");
    expect(await api.createRegisteredSourceCompilePackV01(sourceAdapter.adapter)).toMatchObject({ ok: false, reason: "INVALID_V01_REPLAY_OUTPUT" });
    const sourceAccess = api.issueV01SourcePackAccess(sourcePack.pack);
    expect(sourceAccess.ok).toBe(true);
    expect(api.issueV01SourcePackAccess(sourcePack.pack)).toMatchObject({ ok: false, reason: "INVALID_V01_REPLAY_OUTPUT" });
    const identity = await api.registerCapturedPackIdentityV01(sourceAccess.access, { schema_version: "0.1", catalog_version_hash: catalog.catalog_version_hash }, null);
    expect(identity.ok).toBe(true);

    const regeneration = await api.openFrozenV01RegenerationCapture(identity.identity, names, null);
    expect(regeneration.ok).toBe(true);
    for (const name of names) {
      const snapshot = await sourcePack.pack.snapshotMemberBytes(name);
      expect(snapshot.ok, name).toBe(true);
      expect((await regeneration.session.captureMember(name, snapshot.bytes)).ok, name).toBe(true);
    }
    const regeneratedAdapter = await regeneration.session.seal();
    expect(regeneratedAdapter.ok).toBe(true);
    expect(await regeneration.session.seal()).toMatchObject({ ok: false });
    expect(await api.createRegisteredSourceCompilePackV01(regeneratedAdapter.adapter)).toMatchObject({ ok: false, reason: "INVALID_V01_REPLAY_OUTPUT" });
    const regeneratedPack = await api.createRegisteredRegeneratedCompilePackV01(regeneratedAdapter.adapter, identity.identity);
    expect(regeneratedPack.ok).toBe(true);
    const regeneratedAccess = api.issueV01RegeneratedPackAccess(regeneratedPack.pack, identity.identity);
    expect(regeneratedAccess.ok).toBe(true);
  });

  it("rejects a V01 source pack with a catalog selector outside the frozen registry", async () => {
    const { output, api, packRoot, names } = await loadV01Harness();
    const alternatePackRoot = mkdtempSync(join(tmpdir(), "loopeix-s35-v01-alternate-catalog-"));
    roots.push(alternatePackRoot);
    cpSync(packRoot, alternatePackRoot, { recursive: true });
    const alternateCatalogHash = `sha256:${"d".repeat(64)}`;
    const alternateCatalogPath = join(alternatePackRoot, "catalog-resolution.json");
    const alternateCatalog = JSON.parse(readFileSync(alternateCatalogPath, "utf8")) as Record<string, unknown>;
    alternateCatalog.catalog_version_hash = alternateCatalogHash;
    writeFileSync(alternateCatalogPath, `${JSON.stringify(alternateCatalog, null, 2)}\n`);
    const alternateManifestPath = join(alternatePackRoot, "pack-manifest.json");
    const alternateManifest = JSON.parse(readFileSync(alternateManifestPath, "utf8")) as { file_hashes: { catalog_resolution: string } };
    alternateManifest.file_hashes.catalog_resolution = `sha256:${createHash("sha256").update(readFileSync(alternateCatalogPath)).digest("hex")}`;
    writeFileSync(alternateManifestPath, `${JSON.stringify(alternateManifest, null, 2)}\n`);
    const wrongSelectorRead = await output.openAnchoredReadSession(alternatePackRoot);
    if (!wrongSelectorRead.ok) throw new Error(wrongSelectorRead.message);
    const wrongSelectorAdapter = await api.issueV01SourcePackRegistrationAdapter(wrongSelectorRead.session, names, null);
    const wrongSelectorPack = await api.createRegisteredSourceCompilePackV01(wrongSelectorAdapter.adapter);
    const wrongSelectorAccess = api.issueV01SourcePackAccess(wrongSelectorPack.pack);
    expect(await api.registerCapturedPackIdentityV01(wrongSelectorAccess.access, { schema_version: "0.1", catalog_version_hash: alternateCatalogHash }, null)).toMatchObject({ ok: false, reason: "INVALID_V01_REPLAY_OUTPUT" });
  });

  it("rejects an invalid finite V01 compatibility policy before member capture", async () => {
    const { output, api, packRoot, names } = await loadV01Harness();
    const invalidPolicyRead = await output.openAnchoredReadSession(packRoot);
    if (!invalidPolicyRead.ok) throw new Error(invalidPolicyRead.message);
    expect(await api.issueV01SourcePackRegistrationAdapter(invalidPolicyRead.session, names, { mode: "operator-approved-finite", max_member_bytes: 0, max_total_bytes: 1, max_heap_bytes: 1, max_elapsed_ms: 1, approved_by: "operator" })).toMatchObject({ ok: false, reason: "INVALID_V01_REPLAY_OUTPUT" });
  });

  it("rejects the wrong V01 factory and an aborted regeneration capture", async () => {
    const harness = await loadV01Harness();
    const { output, api, packRoot, names } = harness;
    const sourceA = await makeV01Identity(harness);
    const freshRead = await output.openAnchoredReadSession(packRoot);
    if (!freshRead.ok) throw new Error(freshRead.message);
    const freshAdapter = await api.issueV01SourcePackRegistrationAdapter(freshRead.session, names, null);
    expect(await api.createRegisteredRegeneratedCompilePackV01(freshAdapter.adapter, sourceA.identity.identity)).toMatchObject({ ok: false, reason: "INVALID_V01_REPLAY_OUTPUT" });
    expect((await api.createRegisteredSourceCompilePackV01(freshAdapter.adapter)).ok).toBe(true);

    const aborted = await api.openFrozenV01RegenerationCapture(sourceA.identity.identity, names, null);
    expect((await aborted.session.abort()).ok).toBe(true);
    expect(await aborted.session.seal()).toMatchObject({ ok: false, reason: "INVALID_V01_REPLAY_OUTPUT" });
  });

  it("rejects byte-different V01 regeneration and cross-identity replay access", async () => {
    const harness = await loadV01Harness();
    const { api, names } = harness;
    const sourceA = await readCompilePackV01(harness.packRoot);
    if (!sourceA.ok) throw new Error(sourceA.message);
    const sourceB = await readCompilePackV01(harness.packRoot);
    if (!sourceB.ok) throw new Error(sourceB.message);
    const regeneration = await api.openFrozenV01RegenerationCapture(sourceA.identity, names, null);
    for (const name of names) {
      const snapshot = await sourceA.pack.snapshotMemberBytes(name);
      if (!snapshot.ok) throw new Error(snapshot.message);
      const bytes = new Uint8Array(snapshot.bytes);
      if (name === "work-item.json") bytes[0] = bytes[0] === 0x7b ? 0x5b : 0x7b;
      expect((await regeneration.session.captureMember(name, bytes)).ok).toBe(true);
    }
    const adapter = await regeneration.session.seal();
    expect(await api.createRegisteredRegeneratedCompilePackV01(adapter.adapter, sourceB.identity)).toMatchObject({ ok: false, reason: "INVALID_V01_REPLAY_OUTPUT" });
    const pack = await api.createRegisteredRegeneratedCompilePackV01(adapter.adapter, sourceA.identity);
    expect(pack.ok).toBe(true);
    expect(api.issueV01RegeneratedPackAccess(pack.pack, sourceB.identity)).toMatchObject({ ok: false, reason: "INVALID_V01_REPLAY_OUTPUT" });
    const access = api.issueV01RegeneratedPackAccess(pack.pack, sourceA.identity);
    expect(access.ok).toBe(true);
    expect(await api.registerExactV01ReplaySuccess(sourceA.identity, access.access)).toMatchObject({ ok: false, reason: "INVALID_V01_REPLAY_OUTPUT" });
  });

});
