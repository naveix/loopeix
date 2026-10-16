import { createHash } from "node:crypto";
import { lstatSync, readFileSync, readdirSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";

const ROOT_FILES = Object.freeze(["authoring-invalid.loop.yaml", "authoring-valid.loop.yaml"]);
const PLANNED_FILES = Object.freeze([
  "binding-input.json", "catalog-resolution.json", "compilation-record.json",
  "compile-pack-manifest.json", "generated.loop.yaml", "intake-brief.json",
  "intake-record.json", "resolved-run-plan.json", "work-item.json",
]);
const JSON_KEYS = Object.freeze({
  "work-item.json": ["schema_version", "work_item_id", "submitted_at", "prompt", "workspace_root", "operator_constraints", "source_context"],
  "binding-input.json": ["schema_version", "binding_input_id", "work_item_id", "submitted_at", "bindings"],
  "intake-record.json": ["schema_version", "intake_id", "work_item_id", "objective", "requested_outcome", "candidate_scope", "forbidden_actions", "required_inputs", "risk_flags", "ambiguities", "untrusted_source_refs"],
  "catalog-resolution.json": ["schema_version", "compiler_bundle_id", "resolution_id", "catalog_version_hash", "terminal_state", "reason_code", "ranked_candidates", "selected_item_id", "selection_evidence", "rejected_candidates", "needs_clarification", "required_binding_keys"],
  "compilation-record.json": ["schema_version", "compilation_id", "compiler_bundle_id", "catalog_version_hash", "binding_input_id", "binding_input_hash", "selected_loop_family", "selected_loop_version", "input_bindings", "context_snapshot", "effective_risk_controls", "approval_requirements", "compiler_findings", "proof_boundary"],
  "compile-pack-manifest.json": ["schema_version", "compiler_bundle_id", "catalog_version_hash", "pack_manifest_id", "terminal_state", "reason_code", "work_item_id", "binding_input_id", "intake_id", "resolution_id", "selected_item_id", "compilation_id", "generated_loop_hash", "file_hashes"],
  "intake-brief.json": ["schema_version", "intake_brief_id", "objective", "scope", "allowed_context", "forbidden_context", "allowed_tools", "allowed_connectors", "max_risk_tier", "approval_bindings"],
  "resolved-run-plan.json": ["schema_version", "execution_profile", "run_id", "loop_family", "loopeix_version", "loopeix_version_hash", "source_authoring_hash", "compiler_bundle_id", "catalog_version_hash", "binding_input_id", "binding_input_hash", "compile_pack_manifest_hash", "work_item_id", "intake_brief_id", "created_at", "trigger", "goal", "roles", "tasks", "artifacts", "gates", "evaluations", "evidence_requirements", "progress", "stop_policy", "limit_policy", "retry_policy", "recovery_policy", "side_effects", "compensations", "runtime_record_limits", "required_control_plane_output_bytes", "assurance_profile", "context_snapshot", "authority_subject", "role_assignments", "tool_grants", "workspace_boundary", "adapter_plan", "risk_controls"],
});
const HASH = /^sha256:[0-9a-f]{64}$/u;
const MACHINE = /^[a-z]+_[a-z0-9]+(?:_[a-z0-9]+)*$/u;
const HUMAN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
function fail(message) { throw new Error(`S35 V02 fixture verification failed: ${message}`); }
function assert(value, message) { if (!value) fail(message); }
function hash(bytes) { return `sha256:${createHash("sha256").update(bytes).digest("hex")}`; }
function exactKeys(value, keys, label) {
  assert(value !== null && typeof value === "object" && !Array.isArray(value), `${label} must be one object`);
  assert(Object.keys(value).sort().join("\0") === [...keys].sort().join("\0"), `${label} has a non-canonical key inventory`);
}
function stableFile(path, label) {
  const before = lstatSync(path, { bigint: true });
  assert(before.isFile() && !before.isSymbolicLink(), `${label} must be a direct regular file`);
  assert(before.size > 0n && before.size <= 33_554_432n, `${label} has an invalid size`);
  const bytes = readFileSync(path);
  const after = statSync(path, { bigint: true });
  assert(before.dev === after.dev && before.ino === after.ino && before.size === after.size && before.mtimeNs === after.mtimeNs, `${label} changed during capture`);
  return bytes;
}
function directDirectory(path, label) {
  const metadata = lstatSync(path, { bigint: true });
  assert(metadata.isDirectory() && !metadata.isSymbolicLink() && realpathSync(path) === path, `${label} must be a canonical direct directory`);
}
function parseJson(bytes, name) {
  let value;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { fail(`${name} is not strict UTF-8 JSON`); }
  assert(Buffer.from(`${JSON.stringify(value, null, 2)}\n`).equals(bytes), `${name} is not canonical two-space JSON with final LF`);
  exactKeys(value, JSON_KEYS[name], name);
  assert(value.schema_version === "0.2", `${name} is not schema_version 0.2`);
  return value;
}
function same(actual, expected, label) { assert(actual === expected, `${label} relationship drifted`); }
function parseArgs(argv) {
  assert(argv.length === 2 && argv[0] === "--fixtures-root" && isAbsolute(argv[1] ?? ""), "expected --fixtures-root <absolute-path>");
  return resolve(argv[1]);
}

const fixturesRoot = parseArgs(process.argv.slice(2));
const v02Root = join(fixturesRoot, "v02");
const plannedRoot = join(v02Root, "planned-run");
directDirectory(fixturesRoot, "fixture root");
directDirectory(v02Root, "V02 fixture root");
directDirectory(plannedRoot, "planned-run fixture root");
assert(readdirSync(v02Root).sort().join("\0") === [...ROOT_FILES, "planned-run"].sort().join("\0"), "V02 root inventory is not exact");
assert(readdirSync(plannedRoot).sort().join("\0") === PLANNED_FILES.join("\0"), "planned-run inventory is not the exact nine files");

const validAuthoring = stableFile(join(v02Root, "authoring-valid.loop.yaml"), "valid authoring fixture");
const invalidAuthoring = stableFile(join(v02Root, "authoring-invalid.loop.yaml"), "invalid authoring fixture");
for (const [label, bytes] of [["valid", validAuthoring], ["invalid", invalidAuthoring]]) {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  assert(text.endsWith("\n") && !text.includes("\r"), `${label} authoring fixture must use LF with final LF`);
  assert(/^schema_version:\s*["']?0\.2["']?\s*$/mu.test(text), `${label} authoring fixture does not declare literal 0.2`);
}
assert(!Buffer.from(validAuthoring).equals(invalidAuthoring), "valid and invalid authoring fixtures must be distinct");

const bytes = new Map();
const documents = new Map();
for (const name of PLANNED_FILES) {
  const captured = stableFile(join(plannedRoot, name), `planned fixture ${name}`);
  bytes.set(name, captured);
  if (name.endsWith(".json")) documents.set(name, parseJson(captured, name));
}
const work = documents.get("work-item.json");
const binding = documents.get("binding-input.json");
const intake = documents.get("intake-record.json");
const catalog = documents.get("catalog-resolution.json");
const compilation = documents.get("compilation-record.json");
const manifest = documents.get("compile-pack-manifest.json");
const brief = documents.get("intake-brief.json");
const plan = documents.get("resolved-run-plan.json");
exactKeys(manifest.file_hashes, ["work_item", "binding_input", "intake", "catalog_resolution", "report", "compilation", "generated_loop"], "compile-pack-manifest.json.file_hashes");
assert(Array.isArray(binding.bindings) && Array.isArray(compilation.input_bindings), "binding inventories must be arrays");
const bindingKeys = binding.bindings.map((entry) => entry?.key);
const compilationBindingKeys = compilation.input_bindings.map((entry) => entry?.key);
assert(JSON.stringify(bindingKeys) === JSON.stringify([...bindingKeys].sort()) && new Set(bindingKeys).size === bindingKeys.length, "binding keys are not uniquely sorted");
assert(JSON.stringify(compilationBindingKeys) === JSON.stringify(bindingKeys), "compilation binding-key projection drifted");
const generatedText = new TextDecoder("utf-8", { fatal: true }).decode(bytes.get("generated.loop.yaml"));
assert(generatedText.endsWith("\n") && !generatedText.includes("\r") && /^schema_version:\s*["']?0\.2["']?\s*$/mu.test(generatedText), "generated authoring is not canonical LF V02 YAML");

for (const [label, value] of [
  ["work_item_id", work.work_item_id], ["binding_input_id", binding.binding_input_id],
  ["intake_id", intake.intake_id], ["resolution_id", catalog.resolution_id],
  ["compilation_id", compilation.compilation_id], ["pack_manifest_id", manifest.pack_manifest_id],
  ["intake_brief_id", brief.intake_brief_id], ["run_id", plan.run_id],
]) assert(typeof value === "string" && MACHINE.test(value), `${label} is not a machine ID`);
for (const [label, value] of [["loop_family", plan.loop_family], ["selected_loop_family", compilation.selected_loop_family]]) {
  assert(typeof value === "string" && HUMAN.test(value), `${label} is not a human ID`);
}
for (const [label, value] of Object.entries({
  catalog_version_hash: catalog.catalog_version_hash,
  binding_input_hash: plan.binding_input_hash,
  compile_pack_manifest_hash: plan.compile_pack_manifest_hash,
  source_authoring_hash: plan.source_authoring_hash,
  generated_loop_hash: manifest.generated_loop_hash,
})) assert(typeof value === "string" && HASH.test(value), `${label} is not a SHA-256 hash`);

same(binding.work_item_id, work.work_item_id, "binding/work-item ID");
same(intake.work_item_id, work.work_item_id, "intake/work-item ID");
same(manifest.work_item_id, work.work_item_id, "manifest/work-item ID");
same(plan.work_item_id, work.work_item_id, "plan/work-item ID");
same(compilation.binding_input_id, binding.binding_input_id, "compilation/binding ID");
same(manifest.binding_input_id, binding.binding_input_id, "manifest/binding ID");
same(plan.binding_input_id, binding.binding_input_id, "plan/binding ID");
same(manifest.intake_id, intake.intake_id, "manifest/intake ID");
same(manifest.resolution_id, catalog.resolution_id, "manifest/resolution ID");
same(manifest.compilation_id, compilation.compilation_id, "manifest/compilation ID");
same(plan.intake_brief_id, brief.intake_brief_id, "plan/intake-brief ID");
for (const [label, left, right] of [
  ["catalog/compilation compiler bundle", catalog.compiler_bundle_id, compilation.compiler_bundle_id],
  ["catalog/manifest compiler bundle", catalog.compiler_bundle_id, manifest.compiler_bundle_id],
  ["catalog/plan compiler bundle", catalog.compiler_bundle_id, plan.compiler_bundle_id],
  ["catalog/compilation catalog hash", catalog.catalog_version_hash, compilation.catalog_version_hash],
  ["catalog/manifest catalog hash", catalog.catalog_version_hash, manifest.catalog_version_hash],
  ["catalog/plan catalog hash", catalog.catalog_version_hash, plan.catalog_version_hash],
  ["family", compilation.selected_loop_family, plan.loop_family],
  ["loop version", compilation.selected_loop_version, plan.loopeix_version],
]) same(left, right, label);

assert(manifest.terminal_state === "compiled" && manifest.reason_code === null && catalog.terminal_state === "compiled" && catalog.reason_code === null, "fixture compile terminal is not compiled");
same(manifest.selected_item_id, catalog.selected_item_id, "selected item");
same(compilation.binding_input_hash, hash(bytes.get("binding-input.json")), "compilation binding hash");
same(manifest.file_hashes.binding_input, hash(bytes.get("binding-input.json")), "manifest binding hash");
same(plan.binding_input_hash, hash(bytes.get("binding-input.json")), "plan binding hash");
same(manifest.file_hashes.work_item, hash(bytes.get("work-item.json")), "manifest work-item hash");
same(manifest.file_hashes.intake, hash(bytes.get("intake-record.json")), "manifest intake hash");
same(manifest.file_hashes.catalog_resolution, hash(bytes.get("catalog-resolution.json")), "manifest catalog hash");
same(manifest.file_hashes.compilation, hash(bytes.get("compilation-record.json")), "manifest compilation hash");
same(manifest.file_hashes.generated_loop, hash(bytes.get("generated.loop.yaml")), "manifest generated-loop hash");
same(manifest.generated_loop_hash, hash(bytes.get("generated.loop.yaml")), "generated-loop hash");
same(plan.source_authoring_hash, hash(bytes.get("generated.loop.yaml")), "plan source-authoring hash");
same(plan.compile_pack_manifest_hash, hash(bytes.get("compile-pack-manifest.json")), "plan manifest hash");
same(plan.execution_profile, "bounded-v02", "execution profile");
same(brief.objective, plan.goal?.statement, "brief/plan objective");
same(plan.source_authoring_hash, plan.authority_subject?.repository?.spec_subject?.source_authoring_hash, "authority spec hash");
same(plan.loopeix_version_hash, plan.authority_subject?.repository?.spec_subject?.loopeix_version_hash, "authority loop-version hash");
same(plan.compile_pack_manifest_hash, plan.authority_subject?.repository?.compile_subject?.compile_pack_manifest_hash, "authority manifest hash");
same(plan.compiler_bundle_id, plan.authority_subject?.repository?.compile_subject?.compiler_bundle_id, "authority compiler bundle");
same(plan.catalog_version_hash, plan.authority_subject?.repository?.compile_subject?.catalog_version_hash, "authority catalog hash");
same(plan.binding_input_hash, plan.authority_subject?.repository?.compile_subject?.binding_input_hash, "authority binding hash");
same(plan.authority_subject?.policy_digest, plan.authority_subject?.protection?.action_approval_policy?.policy_digest, "authority policy digest");
assert(JSON.stringify(plan.goal?.success_criteria) === JSON.stringify(plan.authority_subject?.mission?.success_criteria), "authority success criteria drifted");
assert(JSON.stringify(plan.stop_policy?.terminal_states) === JSON.stringify(plan.authority_subject?.mission?.terminal_states), "authority terminal states drifted");

process.stdout.write(`${JSON.stringify({
  ok: true,
  fixture_count: 11,
  planned_member_count: 9,
  run_id: plan.run_id,
  resolved_run_plan_hash: hash(bytes.get("resolved-run-plan.json")),
})}\n`);
