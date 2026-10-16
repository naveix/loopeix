import type { DirectChildName, LegacyCompatibilityPolicy } from "../io/captured-file.js";
import { hashRawBytes } from "../hash.js";
import {
  createRegisteredRegeneratedCompilePackV01,
  createV01ReplayOutputAuthority,
  issueV01RegeneratedPackAccess,
  openFrozenV01RegenerationCapture,
  registerExactV01ReplaySuccess,
  type V01ReplayOutputAuthority,
} from "../io/output-capabilities.js";
import { compilePrompt, type CompilePromptResult } from "./compile.js";
import { CompilePackManifestV01 } from "./pack.js";
import type { ReadCompilePackV01Result } from "./read-pack.js";
import { getFrozenLoopCatalogV01, V01_CATALOG_VERSION_HASH } from "./strategy-v01.js";

type ReadSuccess = Extract<ReadCompilePackV01Result, { ok: true }>;
type ReplayReason = "INVALID_V01_REPLAY_OUTPUT" | "LEGACY_REPLAY_RESOURCE_LIMIT" | "IO_HELPER_UNAVAILABLE";

export type ReplayCompilePackV01Result =
  | { readonly ok: true; readonly authority: V01ReplayOutputAuthority }
  | { readonly ok: false; readonly reason: ReplayReason; readonly message: string };

const encoder = new TextEncoder();

function failure(reason: ReplayReason, message: string): ReplayCompilePackV01Result {
  return { ok: false, reason, message };
}

function invalidReplay(message = "The V01 compile pack did not match its exact frozen replay."): ReplayCompilePackV01Result {
  return failure("INVALID_V01_REPLAY_OUTPUT", message);
}

function jsonBytes(value: unknown): Uint8Array {
  return encoder.encode(`${JSON.stringify(value, null, 2)}\n`);
}

function list(values: readonly string[]): string {
  if (values.length === 0) return "- None recorded\n";
  return values.map((value) => `- ${value}`).join("\n") + "\n";
}

function renderCompileReportV01(result: CompilePromptResult): string {
  const selected = result.catalog_resolution.selected_item_id ?? "none";
  const lines: string[] = [
    "# Loopeix Compile Report",
    "",
    `Terminal state: ${result.catalog_resolution.terminal_state}`,
    `Selected item: ${selected}`,
    `Work item: ${result.work_item.work_item_id}`,
    `Catalog hash: ${result.catalog_resolution.catalog_version_hash}`,
    "",
    "## Selection Evidence",
    "",
    list(result.catalog_resolution.selection_evidence),
    "## Ranked Candidates",
    "",
    list(result.catalog_resolution.ranked_candidates.map((candidate) => `${candidate.item_id} (${candidate.score}): ${candidate.reasons.join(", ")}`)),
  ];
  if (result.compilation !== undefined) {
    lines.push(
      "## Bound Inputs",
      "",
      list(Object.entries(result.compilation.input_bindings).map(([key, value]) => `${key}: ${value}`)),
      "## Risk Controls",
      "",
      `- Max tier without approval: ${result.compilation.effective_risk_controls.max_tier_without_approval}`,
      `- T5 allowed: ${String(result.compilation.effective_risk_controls.t5_allowed)}`,
      "",
      "## Can prove",
      "",
      list(result.compilation.proof_boundary.can_prove),
      "## Cannot prove",
      "",
      list(result.compilation.proof_boundary.cannot_prove),
    );
  }
  if (result.clarification_questions.length > 0) {
    lines.push("## Clarification questions", "", list(result.clarification_questions));
  }
  lines.push(
    "## Next action",
    "",
    result.ok
      ? "- Review `generated.loop.yaml`, then approve it before creating a run plan."
      : "- Resolve the HOLD questions, then run `loopeix compile` again.",
    "",
  );
  return lines.join("\n");
}

function tokenFromMachineId(id: string, prefix: string): string {
  return id.startsWith(`${prefix}_`) ? id.slice(prefix.length + 1) : id.replace(/^[a-z]+_/, "");
}

function regenerateMembers(result: CompilePromptResult): ReadonlyMap<string, Uint8Array> | null {
  const members = new Map<string, Uint8Array>();
  members.set("work-item.json", jsonBytes(result.work_item));
  members.set("intake-record.json", jsonBytes(result.intake));
  members.set("catalog-resolution.json", jsonBytes(result.catalog_resolution));
  if (result.ok) {
    if (result.compilation === undefined || result.yaml === undefined) return null;
    members.set("compilation-record.json", jsonBytes(result.compilation));
    members.set("generated.loop.yaml", encoder.encode(result.yaml));
  }
  members.set("compile-report.md", encoder.encode(renderCompileReportV01(result)));

  const hash = (name: string): string => {
    const bytes = members.get(name);
    if (bytes === undefined) throw new Error(`missing regenerated V01 member ${name}`);
    return hashRawBytes(bytes);
  };
  const fileHashes: Record<string, string> = {
    work_item: hash("work-item.json"),
    intake: hash("intake-record.json"),
    catalog_resolution: hash("catalog-resolution.json"),
    report: hash("compile-report.md"),
  };
  if (result.ok) {
    fileHashes.compilation = hash("compilation-record.json");
    fileHashes.generated_loop = hash("generated.loop.yaml");
  }
  const manifest = CompilePackManifestV01.safeParse({
    schema_version: "0.1",
    pack_manifest_id: `pack_${tokenFromMachineId(result.catalog_resolution.resolution_id, "resolution")}`,
    terminal_state: result.catalog_resolution.terminal_state,
    work_item_id: result.work_item.work_item_id,
    intake_id: result.intake.intake_id,
    resolution_id: result.catalog_resolution.resolution_id,
    selected_item_id: result.catalog_resolution.selected_item_id,
    compilation_id: result.compilation?.compilation_id ?? null,
    generated_loop_hash: result.ok ? fileHashes.generated_loop : null,
    file_hashes: fileHashes,
  });
  if (!manifest.success || manifest.data.schema_version !== "0.1") return null;
  members.set("pack-manifest.json", jsonBytes(manifest.data));
  return members;
}

export async function replayCompilePackV01(
  read: ReadSuccess,
  legacyPolicy: LegacyCompatibilityPolicy | null = null,
): Promise<ReplayCompilePackV01Result> {
  const prompt = read.work_item.prompt;
  const workspaceRoot = read.work_item.workspace_root;
  const submittedAt = read.work_item.submitted_at;
  if (typeof prompt !== "string" || prompt.trim() !== prompt || prompt.length === 0
    || typeof workspaceRoot !== "string" || workspaceRoot.length === 0
    || typeof submittedAt !== "string"
    || read.selector.catalog_version_hash !== V01_CATALOG_VERSION_HASH) return invalidReplay();

  let result: CompilePromptResult;
  try {
    result = compilePrompt({
      prompt,
      workspaceRoot,
      submittedAt,
      catalog: [...getFrozenLoopCatalogV01()],
      catalogVersionHash: V01_CATALOG_VERSION_HASH,
    });
  } catch {
    return invalidReplay();
  }
  const members = regenerateMembers(result);
  if (members === null) return invalidReplay();
  const expectedNames = read.identity.members.map((row) => row.name);
  if (members.size !== expectedNames.length || expectedNames.some((name) => !members.has(name))) return invalidReplay();

  const regeneration = await openFrozenV01RegenerationCapture(read.identity, expectedNames, legacyPolicy);
  if (!regeneration.ok) return failure(regeneration.reason, regeneration.message);
  for (const name of expectedNames) {
    const bytes = members.get(name);
    if (bytes === undefined) {
      await regeneration.session.abort();
      return invalidReplay();
    }
    const captured = await regeneration.session.captureMember(name as DirectChildName, bytes);
    if (!captured.ok) {
      await regeneration.session.abort();
      return captured.reason === "INPUT_TOO_LARGE"
        ? failure("LEGACY_REPLAY_RESOURCE_LIMIT", captured.message)
        : invalidReplay(captured.message);
    }
  }
  const sealed = await regeneration.session.seal();
  if (!sealed.ok) return failure(sealed.reason, sealed.message);
  const regenerated = await createRegisteredRegeneratedCompilePackV01(sealed.adapter, read.identity);
  if (!regenerated.ok) return failure(regenerated.reason, regenerated.message);
  const access = issueV01RegeneratedPackAccess(regenerated.pack, read.identity);
  if (!access.ok) return invalidReplay(access.message);
  const exact = await registerExactV01ReplaySuccess(read.identity, access.access);
  if (!exact.ok) return failure(exact.reason, exact.message);
  const authority = createV01ReplayOutputAuthority(read.identity, exact.replay);
  return authority.ok ? { ok: true, authority: authority.authority } : invalidReplay(authority.message);
}
