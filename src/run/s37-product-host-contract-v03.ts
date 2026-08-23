import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import jcsCanonicalize from "canonicalize";

type V03ErrorCode =
  | "V03_INPUT_INVALID"
  | "V03_LIMIT_EXCEEDED"
  | "V03_VERSION_UNSUPPORTED"
  | "V03_VERSION_MIXED"
  | "V03_SHAPE_INVALID"
  | "V03_SCALAR_INVALID"
  | "V03_SEMANTIC_INVALID"
  | "V03_HASH_INVALID"
  | "V03_SIGNATURE_INVALID";

type V03Result<T> = Readonly<{ ok: true; value: T }> | Readonly<{ ok: false; error: V03ErrorCode }>;
type UnknownRecord = Record<string, unknown>;
type JsonGraphFrame = Readonly<{ phase: "enter" | "exit"; entry: unknown; depth: number }>;
type UnsignedQualificationValidation = Readonly<{ unsigned: UnknownRecord; header: UnknownRecord }>;
type QualificationIssuerShape = UnknownRecord & Readonly<{
  key_ref: unknown;
  algorithm: unknown;
  public_key_spki_base64: unknown;
  public_key_spki_sha256: unknown;
}>;
type QualificationIssuerRecord = QualificationIssuerShape & Readonly<{
  key_ref: string;
  algorithm: "ed25519";
  public_key_spki_base64: string;
  public_key_spki_sha256: string;
}>;
type QualificationAttestationShape = UnknownRecord & Readonly<{
  issuer_key_ref: unknown;
  signature_algorithm: unknown;
  statement_hash: unknown;
  signature_value: unknown;
}>;
type QualificationAttestationRecord = QualificationAttestationShape & Readonly<{
  issuer_key_ref: string;
  signature_algorithm: "ed25519";
  statement_hash: string;
  signature_value: string;
}>;
type OperatorAuthorityShape = UnknownRecord & Readonly<{
  authorization_subject_hash: unknown;
  expires_at: unknown;
}>;
type OperatorAuthorityRecord = OperatorAuthorityShape & Readonly<{
  authorization_subject_hash: string;
  expires_at: string;
}>;
type QualificationShapeRecord = UnknownRecord & Readonly<{
  attestation: QualificationAttestationShape;
  qualification_hash: unknown;
}>;
type QualificationRecord = QualificationShapeRecord & Readonly<{
  attestation: QualificationAttestationRecord;
  qualification_hash: string;
}>;

const MAX_CANONICAL_BYTES = 65_536;
const MAX_DEPTH = 8;
const MAX_NODES = 512;
const MAX_STRING_BYTES = 1_024;
const HASH = /^sha256:[a-f0-9]{64}$/u;
const MACHINE_ID = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$/u;
const EXACT_UTC_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u;
const PRODUCT_PROFILE = "s37-local-product-inert-v03";
const V03_SCHEMAS = new Set([
  "s37-local-product-host-anchor-v03",
  "s37-product-host-lifecycle-state-v01",
  "s37-linux-launch-qualification-v03",
  "s37-product-host-bootstrap-inspection-v01",
  "s37-product-host-install-bundle-v01",
  "s37-product-host-qualification-request-v01",
  "s37-product-host-transition-lock-v01",
]);
const DENY_ROWS = Object.freeze([
  "ambient-credentials", "child-process", "durable-state", "environment",
  "filesystem-write", "network", "output-limits", "retry", "stdin",
  "timeout", "tool-server", "unknown-outcome",
]);

function failure(error: V03ErrorCode): Readonly<{ ok: false; error: V03ErrorCode }> {
  return Object.freeze({ ok: false, error });
}

function success<T>(value: T): Readonly<{ ok: true; value: T }> {
  return Object.freeze({ ok: true, value });
}

function isPlainObject(value: unknown): value is UnknownRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isUnicodeScalarString(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return false;
  }
  return true;
}

function inspectJsonGraph(value: unknown): V03ErrorCode | null {
  const active = new WeakSet<object>();
  let nodes = 0;
  let inputInvalid = false;
  let limitExceeded = false;
  const stack: JsonGraphFrame[] = [{ phase: "enter", entry: value, depth: 1 }];

  function inspectString(entry: string): void {
    if (!isUnicodeScalarString(entry)) inputInvalid = true;
    if (Buffer.byteLength(entry, "utf8") > MAX_STRING_BYTES) limitExceeded = true;
  }

  while (stack.length > 0) {
    const frame = stack.pop();
    if (frame === undefined) break;
    const entry = frame.entry;
    if (frame.phase === "exit") {
      if (typeof entry === "object" && entry !== null) active.delete(entry);
      continue;
    }
    nodes += 1;
    if (nodes > MAX_NODES || frame.depth > MAX_DEPTH) limitExceeded = true;
    if (typeof entry === "string") {
      inspectString(entry);
      continue;
    }
    if (entry === null || typeof entry === "boolean") continue;
    if (typeof entry === "number") {
      if (!Number.isSafeInteger(entry) || Object.is(entry, -0)) inputInvalid = true;
      continue;
    }
    if (typeof entry !== "object" || (!Array.isArray(entry) && !isPlainObject(entry))) {
      inputInvalid = true;
      continue;
    }
    if (active.has(entry)) {
      inputInvalid = true;
      continue;
    }
    active.add(entry);
    stack.push({ phase: "exit", entry, depth: frame.depth });
    const ownKeys = Reflect.ownKeys(entry);
    const array = Array.isArray(entry);
    let arrayIndexes = 0;
    for (const key of ownKeys) {
      const descriptor = Object.getOwnPropertyDescriptor(entry, key);
      if (descriptor === undefined) {
        inputInvalid = true;
        continue;
      }
      if (typeof key === "symbol") {
        inputInvalid = true;
        continue;
      }
      inspectString(key);
      if (array && key === "length") {
        if (!Object.hasOwn(descriptor, "value")) inputInvalid = true;
        continue;
      }
      const canonicalArrayIndex = array && /^(?:0|[1-9]\d*)$/u.test(key)
        && Number(key) < entry.length && Number(key) <= 4_294_967_294;
      if ((array && !canonicalArrayIndex) || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) {
        inputInvalid = true;
        continue;
      }
      if (array) arrayIndexes += 1;
      stack.push({ phase: "enter", entry: descriptor.value, depth: frame.depth + 1 });
    }
    if (array && arrayIndexes !== entry.length) inputInvalid = true;
  }
  return inputInvalid ? "V03_INPUT_INVALID" : limitExceeded ? "V03_LIMIT_EXCEEDED" : null;
}

function canonicalResult(value: unknown): V03Result<string> {
  try {
    const finding = inspectJsonGraph(value);
    if (finding !== null) return failure(finding);
    const canonical = jcsCanonicalize(value);
    if (canonical === undefined) return failure("V03_INPUT_INVALID");
    if (Buffer.byteLength(canonical, "utf8") > MAX_CANONICAL_BYTES) return failure("V03_LIMIT_EXCEEDED");
    return success(canonical);
  } catch {
    return failure("V03_INPUT_INVALID");
  }
}

function deepFreeze<T>(value: T): Readonly<T> {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  if (Array.isArray(value)) {
    for (const child of value) deepFreeze(child);
    return Object.freeze(value);
  }
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function exactKeys(value: unknown, keys: readonly string[]): value is UnknownRecord {
  if (!isPlainObject(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function nestedObjects(value: unknown, root = true): UnknownRecord[] {
  if (value === null || typeof value !== "object") return [];
  const result: UnknownRecord[] = [];
  if (!root && isPlainObject(value)) result.push(value);
  for (const child of Object.values(value)) result.push(...nestedObjects(child, false));
  return result;
}

function hasMixedVersion(value: UnknownRecord): boolean {
  if (Object.hasOwn(value, "product_profile") && value.product_profile !== PRODUCT_PROFILE) return true;
  if (nestedObjects(value).some((entry) => Object.hasOwn(entry, "schema_version"))) return true;
  if (isPlainObject(value.qualification_issuer)
    && Object.hasOwn(value.qualification_issuer, "algorithm")
    && value.qualification_issuer.algorithm !== "ed25519") return true;
  return isPlainObject(value.attestation)
    && Object.hasOwn(value.attestation, "signature_algorithm")
    && value.attestation.signature_algorithm !== "ed25519";
}

function prepareRecord(candidate: unknown, expectedSchema: string): V03Result<UnknownRecord> {
  if (!isPlainObject(candidate)) return failure("V03_INPUT_INVALID");
  const serialized = canonicalResult(candidate);
  if (!serialized.ok) return serialized;
  const clone: unknown = JSON.parse(serialized.value);
  if (!isPlainObject(clone)) return failure("V03_INPUT_INVALID");
  if (clone.schema_version !== expectedSchema || !V03_SCHEMAS.has(clone.schema_version)) {
    return failure("V03_VERSION_UNSUPPORTED");
  }
  if (hasMixedVersion(clone)) return failure("V03_VERSION_MIXED");
  return success(clone);
}

function isHash(value: unknown): value is string {
  return typeof value === "string" && HASH.test(value);
}

function isMachineId(value: unknown): value is string {
  return typeof value === "string" && value.length >= 3 && value.length <= 160 && MACHINE_ID.test(value);
}

function isExactUtcSecond(value: unknown): value is string {
  if (typeof value !== "string" || !EXACT_UTC_SECOND.test(value)) return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value.replace("Z", ".000Z");
}

function isSafeUint(value: unknown, positive = false): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= (positive ? 1 : 0);
}

function isAbsolutePath(value: unknown): value is string {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > 1_024
    || !value.startsWith("/") || value.startsWith("//") || /[\0\r\n\\]/u.test(value)) return false;
  if (value === "/") return true;
  return value.slice(1).split("/").every((part) => part.length > 0 && part !== "." && part !== "..");
}

function isBoundedNonBlank(value: unknown, bytes = 128): value is string {
  return typeof value === "string" && value.trim().length > 0 && Buffer.byteLength(value, "utf8") <= bytes;
}

function isCanonicalBase64(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) return false;
  try { return Buffer.from(value, "base64").toString("base64") === value; } catch { return false; }
}

function rawHash(bytes: Uint8Array): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function canonicalHash(value: unknown): string {
  const result = hashCanonicalV03(value);
  if (!result.ok) throw new TypeError("validated V03 preimage was not canonicalizable");
  return result.value;
}

function issuerShape(value: unknown): value is QualificationIssuerShape {
  return exactKeys(value, ["key_ref", "algorithm", "public_key_spki_base64", "public_key_spki_sha256"]);
}

function issuerScalars(value: unknown): value is QualificationIssuerRecord {
  if (!issuerShape(value)) return false;
  if (!isMachineId(value.key_ref) || value.algorithm !== "ed25519"
    || !isCanonicalBase64(value.public_key_spki_base64) || !isHash(value.public_key_spki_sha256)) return false;
  try {
    const key = createPublicKey({ key: Buffer.from(value.public_key_spki_base64, "base64"), format: "der", type: "spki" });
    return key.asymmetricKeyType === "ed25519"
      && key.export({ format: "der", type: "spki" }).toString("base64") === value.public_key_spki_base64;
  } catch { return false; }
}

function issuerHashValid(value: unknown): boolean {
  if (!issuerShape(value) || !isCanonicalBase64(value.public_key_spki_base64) || !isHash(value.public_key_spki_sha256)) {
    return false;
  }
  return rawHash(Buffer.from(value.public_key_spki_base64, "base64")) === value.public_key_spki_sha256;
}

function managedShape(value: unknown, bwrap = false): value is UnknownRecord {
  const keys = ["path", "source_sha256", "sha256", "mode", "uid", "gid", "nlink", "setuid"];
  if (bwrap) keys.push("version");
  return exactKeys(value, keys);
}

function hostExecutableShape(value: unknown): value is UnknownRecord {
  return exactKeys(value, ["path", "sha256", "mode", "uid", "gid", "nlink", "setuid"]);
}

function artifactsShape(value: unknown): value is UnknownRecord {
  if (!exactKeys(value, ["supervisor", "probe", "bwrap", "systemd_run", "systemctl", "embedded_seccomp_policy_sha256"])) {
    return false;
  }
  return exactKeys(value, ["supervisor", "probe", "bwrap", "systemd_run", "systemctl", "embedded_seccomp_policy_sha256"])
    && managedShape(value.supervisor) && managedShape(value.probe) && managedShape(value.bwrap, true)
    && hostExecutableShape(value.systemd_run) && hostExecutableShape(value.systemctl);
}

function managedScalars(value: unknown, path: string, bwrap = false): boolean {
  if (!managedShape(value, bwrap)) return false;
  return value.path === path && isAbsolutePath(value.path) && isHash(value.source_sha256) && isHash(value.sha256)
    && value.mode === "0555" && value.uid === 0 && value.gid === 0 && value.nlink === 1 && value.setuid === false
    && (!bwrap || isBoundedNonBlank(value.version));
}

function hostExecutableScalars(value: unknown, path: string): boolean {
  if (!hostExecutableShape(value)) return false;
  return value.path === path && isAbsolutePath(value.path) && isHash(value.sha256)
    && value.mode === "0755" && value.uid === 0 && value.gid === 0 && value.nlink === 1 && value.setuid === false;
}

function artifactsScalars(value: unknown): boolean {
  if (!artifactsShape(value)) return false;
  return managedScalars(value.supervisor, "/opt/loopeix/s37.1/supervisor")
    && managedScalars(value.probe, "/opt/loopeix/s37.1/probe")
    && managedScalars(value.bwrap, "/opt/loopeix/s37.1/bwrap", true)
    && hostExecutableScalars(value.systemd_run, "/usr/bin/systemd-run")
    && hostExecutableScalars(value.systemctl, "/usr/bin/systemctl")
    && isHash(value.embedded_seccomp_policy_sha256);
}

function hostShape(value: unknown): value is UnknownRecord {
  return exactKeys(value, ["platform", "distribution_id", "distribution_version_id", "architecture", "kernel_release", "systemd_version", "cgroup_version", "host_identity_hash", "controller_uid"]);
}

function hostScalars(value: unknown): boolean {
  if (!hostShape(value)) return false;
  return value.platform === "linux" && value.distribution_id === "debian" && value.distribution_version_id === "13"
    && value.architecture === "x86_64" && isBoundedNonBlank(value.kernel_release)
    && isBoundedNonBlank(value.systemd_version) && value.cgroup_version === "v2"
    && isHash(value.host_identity_hash) && isSafeUint(value.controller_uid, true);
}

function operatorAuthorityShape(value: unknown): value is OperatorAuthorityShape {
  return exactKeys(value, ["authorization_id", "authenticated_principal_ref", "operator_key_id", "authorization_transaction_id", "mutation_plan_hash", "authorization_subject_hash", "action_scope_hash", "approval_nonce", "authorization_statement_hash", "proof_record_hash", "revocation_epoch", "expires_at"]);
}

function operatorAuthorityScalars(value: unknown): value is OperatorAuthorityRecord {
  if (!operatorAuthorityShape(value)) return false;
  return ["authorization_id", "authenticated_principal_ref", "operator_key_id", "authorization_transaction_id"].every((key) => isMachineId(value[key]))
    && ["mutation_plan_hash", "authorization_subject_hash", "action_scope_hash", "approval_nonce", "authorization_statement_hash", "proof_record_hash"].every((key) => isHash(value[key]))
    && isSafeUint(value.revocation_epoch) && isExactUtcSecond(value.expires_at);
}

/** @param {unknown} candidate @returns {V03Result<Readonly<Record<string, unknown>>>} */
export function parseS37LocalProductHostAnchorV03(candidate: unknown): V03Result<Readonly<UnknownRecord>> {
  try {
    const prepared = prepareRecord(candidate, "s37-local-product-host-anchor-v03");
    if (!prepared.ok) return prepared;
    const value = prepared.value;
    if (!exactKeys(value, ["schema_version", "product_profile", "runtime_profile_version", "runtime_profile_hash", "host_role", "transport", "host", "artifacts", "cwd", "install_bundle_hash", "qualification_issuer", "anchor_subject_hash", "operator_authority", "generation", "predecessor_anchor_hash", "installed_at", "anchor_hash"])
      || !hostShape(value.host) || !artifactsShape(value.artifacts)
      || !exactKeys(value.cwd, ["path", "identity_hash"]) || !issuerShape(value.qualification_issuer)
      || !operatorAuthorityShape(value.operator_authority)) return failure("V03_SHAPE_INVALID");
    if (value.product_profile !== PRODUCT_PROFILE || value.runtime_profile_version !== "0.1"
      || !isHash(value.runtime_profile_hash) || value.host_role !== "local-product" || value.transport !== "local-only"
      || !hostScalars(value.host) || !artifactsScalars(value.artifacts)
      || value.cwd.path !== "/" || !isHash(value.cwd.identity_hash) || !isHash(value.install_bundle_hash)
      || !issuerScalars(value.qualification_issuer) || !isHash(value.anchor_subject_hash)
      || !operatorAuthorityScalars(value.operator_authority) || !isSafeUint(value.generation, true)
      || !(value.predecessor_anchor_hash === null || isHash(value.predecessor_anchor_hash))
      || !isExactUtcSecond(value.installed_at) || !isHash(value.anchor_hash)) return failure("V03_SCALAR_INVALID");
    if ((value.generation === 1) !== (value.predecessor_anchor_hash === null)
      || value.operator_authority.authorization_subject_hash !== value.anchor_subject_hash
      || Date.parse(value.installed_at) >= Date.parse(value.operator_authority.expires_at)) return failure("V03_SEMANTIC_INVALID");
    const subject = {
      purpose: "s37-local-product-host-anchor-subject-v03",
      schema_version: value.schema_version, product_profile: value.product_profile,
      runtime_profile_version: value.runtime_profile_version, runtime_profile_hash: value.runtime_profile_hash,
      host_role: value.host_role, transport: value.transport, host: value.host, artifacts: value.artifacts,
      cwd: value.cwd, install_bundle_hash: value.install_bundle_hash, qualification_issuer: value.qualification_issuer,
      generation: value.generation, predecessor_anchor_hash: value.predecessor_anchor_hash,
    };
    const { anchor_hash: _anchorHash, ...withoutHash } = value;
    if (!issuerHashValid(value.qualification_issuer) || value.anchor_subject_hash !== canonicalHash(subject)
      || value.anchor_hash !== canonicalHash({ purpose: "s37-local-product-host-anchor-v03", ...withoutHash })) {
      return failure("V03_HASH_INVALID");
    }
    return success(deepFreeze(value));
  } catch { return failure("V03_INPUT_INVALID"); }
}

/** @param {unknown} candidate @returns {V03Result<Readonly<Record<string, unknown>>>} */
export function parseS37ProductHostLifecycleStateV01(candidate: unknown): V03Result<Readonly<UnknownRecord>> {
  try {
    const prepared = prepareRecord(candidate, "s37-product-host-lifecycle-state-v01");
    if (!prepared.ok) return prepared;
    const value = prepared.value;
    if (!exactKeys(value, ["schema_version", "status", "generation", "stable_anchor_hash", "expected_previous_anchor_hash", "proposed_anchor_hash", "authorization_transaction_id", "authorization_record_hash", "updated_at", "state_hash"])) {
      return failure("V03_SHAPE_INVALID");
    }
    if (!(typeof value.status === "string" && ["STABLE", "PREPARING"].includes(value.status)) || !isSafeUint(value.generation, true)
      || ![value.stable_anchor_hash, value.expected_previous_anchor_hash, value.proposed_anchor_hash, value.authorization_record_hash].every((entry) => entry === null || isHash(entry))
      || !(value.authorization_transaction_id === null || isMachineId(value.authorization_transaction_id))
      || !isExactUtcSecond(value.updated_at) || !isHash(value.state_hash)) return failure("V03_SCALAR_INVALID");
    const stable = value.status === "STABLE" && value.stable_anchor_hash !== null
      && value.expected_previous_anchor_hash === null && value.proposed_anchor_hash === null
      && value.authorization_transaction_id === null && value.authorization_record_hash === null;
    const preparingInitial = value.status === "PREPARING" && value.generation === 1
      && value.stable_anchor_hash === null && value.expected_previous_anchor_hash === null
      && value.proposed_anchor_hash !== null && value.authorization_transaction_id !== null
      && value.authorization_record_hash !== null;
    const preparingTransition = value.status === "PREPARING" && value.generation >= 2
      && value.stable_anchor_hash !== null && value.expected_previous_anchor_hash === value.stable_anchor_hash
      && value.proposed_anchor_hash !== null && value.proposed_anchor_hash !== value.stable_anchor_hash
      && value.authorization_transaction_id !== null && value.authorization_record_hash !== null;
    if (!stable && !preparingInitial && !preparingTransition) return failure("V03_SEMANTIC_INVALID");
    const { state_hash: _stateHash, ...withoutHash } = value;
    if (value.state_hash !== canonicalHash({ purpose: "s37-product-host-lifecycle-state-v01", ...withoutHash })) {
      return failure("V03_HASH_INVALID");
    }
    return success(deepFreeze(value));
  } catch { return failure("V03_INPUT_INVALID"); }
}

/** @param {unknown} candidate @returns {V03Result<Readonly<Record<string, unknown>>>} */
export function parseS37ProductHostInstallBundleV01(candidate: unknown): V03Result<Readonly<UnknownRecord>> {
  try {
    const prepared = prepareRecord(candidate, "s37-product-host-install-bundle-v01");
    if (!prepared.ok) return prepared;
    const value = prepared.value;
    if (!exactKeys(value, ["schema_version", "product_profile", "runtime_profile_version", "runtime_profile_hash", "host_role", "transport", "target", "artifacts", "cwd", "qualification_issuer", "created_at", "bundle_hash"])
      || !exactKeys(value.target, ["platform", "distribution_id", "distribution_version_id", "architecture", "cgroup_version", "controller_uid", "anchor_path", "lifecycle_path"])
      || !artifactsShape(value.artifacts) || !exactKeys(value.cwd, ["path", "identity_hash"])
      || !issuerShape(value.qualification_issuer)) return failure("V03_SHAPE_INVALID");
    if (value.product_profile !== PRODUCT_PROFILE || value.runtime_profile_version !== "0.1" || !isHash(value.runtime_profile_hash)
      || value.host_role !== "local-product" || value.transport !== "local-only"
      || value.target.platform !== "linux" || value.target.distribution_id !== "debian"
      || value.target.distribution_version_id !== "13" || value.target.architecture !== "x86_64"
      || value.target.cgroup_version !== "v2" || !isSafeUint(value.target.controller_uid, true)
      || value.target.anchor_path !== "/etc/loopeix/s37.1/product-host-v03/anchor.json"
      || value.target.lifecycle_path !== "/etc/loopeix/s37.1/product-host-v03/lifecycle-state.json"
      || !artifactsScalars(value.artifacts) || value.cwd.path !== "/" || !isHash(value.cwd.identity_hash)
      || !issuerScalars(value.qualification_issuer) || !isExactUtcSecond(value.created_at) || !isHash(value.bundle_hash)) {
      return failure("V03_SCALAR_INVALID");
    }
    const { bundle_hash: _bundleHash, ...withoutHash } = value;
    if (!issuerHashValid(value.qualification_issuer)
      || value.bundle_hash !== canonicalHash({ purpose: "s37-product-host-install-bundle-v01", ...withoutHash })) {
      return failure("V03_HASH_INVALID");
    }
    return success(deepFreeze(value));
  } catch { return failure("V03_INPUT_INVALID"); }
}

/** @param {unknown} candidate @returns {V03Result<Readonly<Record<string, unknown>>>} */
export function parseS37ProductHostBootstrapInspectionV01(candidate: unknown): V03Result<Readonly<UnknownRecord>> {
  try {
    const prepared = prepareRecord(candidate, "s37-product-host-bootstrap-inspection-v01");
    if (!prepared.ok) return prepared;
    const value = prepared.value;
    if (!exactKeys(value, ["schema_version", "observed_at", "platform", "distribution", "architecture", "kernel_release", "systemd_version", "cgroup_version", "required_cgroup_controllers", "host_identity_hash", "boot_id_hash", "expected_controller", "observed_controller", "user_manager", "checks", "inspection_hash"])
      || !exactKeys(value.distribution, ["id", "version_id"])
      || !Array.isArray(value.required_cgroup_controllers) || value.required_cgroup_controllers.length !== 4
      || !exactKeys(value.expected_controller, ["username", "uid"])
      || !exactKeys(value.observed_controller, ["username", "uid", "gid", "home", "shell"])
      || !exactKeys(value.user_manager, ["active", "runtime_directory", "bus_path"])
      || !exactKeys(value.checks, ["controller_nonroot", "username_uid_mapping_exact", "user_manager_active", "cgroup_controllers_complete"])) {
      return failure("V03_SHAPE_INVALID");
    }
    const username = /^[a-z_][a-z0-9_-]{0,31}$/u;
    if (!isExactUtcSecond(value.observed_at) || value.platform !== "linux"
      || value.distribution.id !== "debian" || value.distribution.version_id !== "13"
      || value.architecture !== "x86_64" || !isBoundedNonBlank(value.kernel_release)
      || !isBoundedNonBlank(value.systemd_version) || value.cgroup_version !== "v2"
      || (() => {
        const controllers = canonicalResult(value.required_cgroup_controllers);
        return !controllers.ok || controllers.value !== '["cpu","io","memory","pids"]';
      })()
      || !isHash(value.host_identity_hash) || !isHash(value.boot_id_hash)
      || typeof value.expected_controller.username !== "string" || !username.test(value.expected_controller.username)
      || !isSafeUint(value.expected_controller.uid, true)
      || typeof value.observed_controller.username !== "string" || !username.test(value.observed_controller.username)
      || !isSafeUint(value.observed_controller.uid, true) || !isSafeUint(value.observed_controller.gid)
      || !isAbsolutePath(value.observed_controller.home) || !isAbsolutePath(value.observed_controller.shell)
      || value.user_manager.active !== true || !isAbsolutePath(value.user_manager.runtime_directory)
      || !isAbsolutePath(value.user_manager.bus_path)
      || Object.values(value.checks).some((entry) => entry !== true) || !isHash(value.inspection_hash)) {
      return failure("V03_SCALAR_INVALID");
    }
    if (value.expected_controller.username !== value.observed_controller.username
      || value.expected_controller.uid !== value.observed_controller.uid
      || value.observed_controller.uid === 0
      || value.user_manager.runtime_directory !== `/run/user/${value.observed_controller.uid}`
      || value.user_manager.bus_path !== `${value.user_manager.runtime_directory}/bus`) {
      return failure("V03_SEMANTIC_INVALID");
    }
    const { inspection_hash: _inspectionHash, ...withoutHash } = value;
    if (value.inspection_hash !== canonicalHash({ purpose: "s37-product-host-bootstrap-inspection-v01", ...withoutHash })) {
      return failure("V03_HASH_INVALID");
    }
    return success(deepFreeze(value));
  } catch { return failure("V03_INPUT_INVALID"); }
}

/** @param {unknown} candidate @returns {V03Result<Readonly<Record<string, unknown>>>} */
export function parseS37ProductHostQualificationRequestV01(candidate: unknown): V03Result<Readonly<UnknownRecord>> {
  try {
    const prepared = prepareRecord(candidate, "s37-product-host-qualification-request-v01");
    if (!prepared.ok) return prepared;
    const value = prepared.value;
    if (!exactKeys(value, ["schema_version", "product_profile", "anchor_hash", "anchor_generation", "runtime_profile_hash", "action_proposal_hash", "decision_input_hash", "decision_simulation_hash", "lease_simulation_hash", "launch_nonce", "requested_at", "expires_at", "request_hash"])) {
      return failure("V03_SHAPE_INVALID");
    }
    if (value.product_profile !== PRODUCT_PROFILE || !isSafeUint(value.anchor_generation, true)
      || !["anchor_hash", "runtime_profile_hash", "action_proposal_hash", "decision_input_hash", "decision_simulation_hash", "lease_simulation_hash", "launch_nonce", "request_hash"].every((key) => isHash(value[key]))
      || !isExactUtcSecond(value.requested_at) || !isExactUtcSecond(value.expires_at)) return failure("V03_SCALAR_INVALID");
    const requested = Date.parse(value.requested_at);
    const expires = Date.parse(value.expires_at);
    if (requested >= expires || expires - requested > 600_000) return failure("V03_SEMANTIC_INVALID");
    const { request_hash: _requestHash, ...withoutHash } = value;
    if (value.request_hash !== canonicalHash({ purpose: "s37-product-host-qualification-request-v01", ...withoutHash })) {
      return failure("V03_HASH_INVALID");
    }
    return success(deepFreeze(value));
  } catch { return failure("V03_INPUT_INVALID"); }
}

/** @param {unknown} candidate @returns {V03Result<Readonly<Record<string, unknown>>>} */
export function parseS37ProductHostTransitionLockV01(candidate: unknown): V03Result<Readonly<UnknownRecord>> {
  try {
    const prepared = prepareRecord(candidate, "s37-product-host-transition-lock-v01");
    if (!prepared.ok) return prepared;
    const value = prepared.value;
    if (!exactKeys(value, ["schema_version", "operation", "authorization_transaction_id", "generation", "expected_previous_anchor_hash", "proposed_anchor_hash", "authorization_record_hash", "lock_hash"])) {
      return failure("V03_SHAPE_INVALID");
    }
    if (!(typeof value.operation === "string" && ["install", "transition"].includes(value.operation)) || !isMachineId(value.authorization_transaction_id)
      || !isSafeUint(value.generation, true) || !(value.expected_previous_anchor_hash === null || isHash(value.expected_previous_anchor_hash))
      || !isHash(value.proposed_anchor_hash) || !isHash(value.authorization_record_hash) || !isHash(value.lock_hash)) {
      return failure("V03_SCALAR_INVALID");
    }
    const install = value.operation === "install" && value.generation === 1 && value.expected_previous_anchor_hash === null;
    const transition = value.operation === "transition" && value.generation >= 2 && value.expected_previous_anchor_hash !== null;
    if (!install && !transition) return failure("V03_SEMANTIC_INVALID");
    const { lock_hash: _lockHash, ...withoutHash } = value;
    if (value.lock_hash !== canonicalHash({ purpose: "s37-product-host-transition-lock-v01", ...withoutHash })) {
      return failure("V03_HASH_INVALID");
    }
    return success(deepFreeze(value));
  } catch { return failure("V03_INPUT_INVALID"); }
}

function phaseBShape(value: unknown): value is UnknownRecord {
  return exactKeys(value, ["manifest_sha256", "readiness_evidence_sha256", "readiness_envelope_sha256", "conformance_evidence_sha256", "receipt_hash"]);
}

const UNSIGNED_QUALIFICATION_KEYS = Object.freeze([
  "schema_version", "product_profile", "anchor_hash", "anchor_generation", "boot_id_hash", "host",
  "observed_at", "runtime_profile_hash", "phase_b", "artifacts", "deny_witnesses", "request_hash",
  "decision_input_hash", "decision_simulation_hash", "lease_simulation_hash", "action_proposal_hash",
  "launch_nonce", "issued_at", "expires_at",
]);

function unsignedQualificationShape(value: unknown): value is UnknownRecord {
  return exactKeys(value, UNSIGNED_QUALIFICATION_KEYS)
    && hostShape(value.host) && phaseBShape(value.phase_b) && artifactsShape(value.artifacts)
    && Array.isArray(value.deny_witnesses) && value.deny_witnesses.length === DENY_ROWS.length
    && value.deny_witnesses.every((entry) => exactKeys(entry, ["row", "witness_sha256"]));
}

function qualificationShape(value: unknown): value is QualificationShapeRecord {
  return exactKeys(value, ["schema_version", "product_profile", "anchor_hash", "anchor_generation", "boot_id_hash", "host", "observed_at", "runtime_profile_hash", "phase_b", "artifacts", "deny_witnesses", "request_hash", "decision_input_hash", "decision_simulation_hash", "lease_simulation_hash", "action_proposal_hash", "launch_nonce", "issued_at", "expires_at", "attestation", "qualification_hash"])
    && unsignedQualificationShape(unsignedQualification(value))
    && exactKeys(value.attestation, ["issuer_key_ref", "signature_algorithm", "statement_hash", "signature_value"]);
}

function unsignedQualificationScalars(value: UnknownRecord): boolean {
  return value.product_profile === PRODUCT_PROFILE && isHash(value.anchor_hash) && isSafeUint(value.anchor_generation, true)
    && isHash(value.boot_id_hash) && hostScalars(value.host) && isExactUtcSecond(value.observed_at)
    && isHash(value.runtime_profile_hash) && phaseBShape(value.phase_b) && Object.values(value.phase_b).every(isHash)
    && artifactsScalars(value.artifacts)
    && Array.isArray(value.deny_witnesses)
    && value.deny_witnesses.every((entry: unknown) => isPlainObject(entry)
      && typeof entry.row === "string" && DENY_ROWS.includes(entry.row) && isHash(entry.witness_sha256))
    && ["request_hash", "decision_input_hash", "decision_simulation_hash", "lease_simulation_hash", "action_proposal_hash", "launch_nonce"].every((key) => isHash(value[key]))
    && isExactUtcSecond(value.issued_at) && isExactUtcSecond(value.expires_at);
}

function qualificationScalars(value: QualificationShapeRecord): value is QualificationRecord {
  return unsignedQualificationScalars(unsignedQualification(value))
    && isMachineId(value.attestation.issuer_key_ref) && value.attestation.signature_algorithm === "ed25519"
    && isHash(value.attestation.statement_hash) && isCanonicalBase64(value.attestation.signature_value)
    && Buffer.from(value.attestation.signature_value, "base64").byteLength === 64 && isHash(value.qualification_hash);
}

function unsignedQualificationSemanticValid(value: UnknownRecord): boolean {
  if (!isExactUtcSecond(value.observed_at) || !isExactUtcSecond(value.issued_at)
    || !isExactUtcSecond(value.expires_at)) return false;
  const observed = Date.parse(value.observed_at);
  const issued = Date.parse(value.issued_at);
  const expires = Date.parse(value.expires_at);
  return observed <= issued && issued < expires && expires - issued <= 30_000
    && Array.isArray(value.deny_witnesses)
    && value.deny_witnesses.every((entry: unknown, index: number) => isPlainObject(entry) && entry.row === DENY_ROWS[index]);
}

function qualificationSemanticValid(value: QualificationRecord): boolean {
  return unsignedQualificationSemanticValid(unsignedQualification(value));
}

function unsignedQualification(value: UnknownRecord): UnknownRecord {
  return {
    schema_version: value.schema_version, product_profile: value.product_profile,
    anchor_hash: value.anchor_hash, anchor_generation: value.anchor_generation,
    boot_id_hash: value.boot_id_hash, host: value.host, observed_at: value.observed_at,
    runtime_profile_hash: value.runtime_profile_hash, phase_b: value.phase_b, artifacts: value.artifacts,
    deny_witnesses: value.deny_witnesses, request_hash: value.request_hash,
    decision_input_hash: value.decision_input_hash, decision_simulation_hash: value.decision_simulation_hash,
    lease_simulation_hash: value.lease_simulation_hash, action_proposal_hash: value.action_proposal_hash,
    launch_nonce: value.launch_nonce, issued_at: value.issued_at, expires_at: value.expires_at,
  };
}

function expectedQualificationStatementHash(unsigned: UnknownRecord, header: UnknownRecord): string {
  return canonicalHash({
    purpose: "s37-linux-launch-qualification-statement-v03",
    ...unsigned,
    attestation: header,
  });
}

function validateUnsignedQualification(unsignedCandidate: unknown, headerCandidate: unknown): V03Result<UnsignedQualificationValidation> {
  if (!isPlainObject(unsignedCandidate) || !isPlainObject(headerCandidate)) return failure("V03_INPUT_INVALID");
  const combined = canonicalResult({ unsigned_qualification: unsignedCandidate, attestation_header: headerCandidate });
  if (!combined.ok) return combined;
  const cloned: unknown = JSON.parse(combined.value);
  if (!isPlainObject(cloned) || !isPlainObject(cloned.unsigned_qualification)
    || !isPlainObject(cloned.attestation_header)) return failure("V03_INPUT_INVALID");
  const unsigned = cloned.unsigned_qualification;
  const header = cloned.attestation_header;
  if (unsigned.schema_version !== "s37-linux-launch-qualification-v03") return failure("V03_VERSION_UNSUPPORTED");
  if (hasMixedVersion(unsigned) || (Object.hasOwn(header, "signature_algorithm") && header.signature_algorithm !== "ed25519")
    || nestedObjects(header).some((entry) => Object.hasOwn(entry, "schema_version"))) return failure("V03_VERSION_MIXED");
  if (!unsignedQualificationShape(unsigned) || !exactKeys(header, ["issuer_key_ref", "signature_algorithm"])) {
    return failure("V03_SHAPE_INVALID");
  }
  if (!unsignedQualificationScalars(unsigned) || !isMachineId(header.issuer_key_ref)
    || header.signature_algorithm !== "ed25519") return failure("V03_SCALAR_INVALID");
  if (!unsignedQualificationSemanticValid(unsigned)) return failure("V03_SEMANTIC_INVALID");
  const statementPreimage = canonicalResult({
    purpose: "s37-linux-launch-qualification-statement-v03",
    ...unsigned,
    attestation: header,
  });
  if (!statementPreimage.ok) return statementPreimage;
  return success(deepFreeze({ unsigned, header }));
}

function validateQualification(candidate: unknown): V03Result<Readonly<QualificationRecord>> {
  const prepared = prepareRecord(candidate, "s37-linux-launch-qualification-v03");
  if (!prepared.ok) return prepared;
  const value = prepared.value;
  if (!qualificationShape(value)) return failure("V03_SHAPE_INVALID");
  if (!qualificationScalars(value)) return failure("V03_SCALAR_INVALID");
  if (!qualificationSemanticValid(value)) return failure("V03_SEMANTIC_INVALID");
  const { qualification_hash: _qualificationHash, ...withoutHash } = value;
  if (value.attestation.statement_hash !== expectedQualificationStatementHash(unsignedQualification(value), {
    issuer_key_ref: value.attestation.issuer_key_ref,
    signature_algorithm: value.attestation.signature_algorithm,
  })
    || value.qualification_hash !== canonicalHash({ purpose: "s37-linux-launch-qualification-v03", ...withoutHash })) {
    return failure("V03_HASH_INVALID");
  }
  return success(deepFreeze(value));
}

/** @param {unknown} candidate @returns {V03Result<Readonly<Record<string, unknown>>>} */
export function parseS37LinuxLaunchQualificationV03(candidate: unknown): V03Result<Readonly<QualificationRecord>> {
  try { return validateQualification(candidate); } catch { return failure("V03_INPUT_INVALID"); }
}

/** @param {unknown} unsignedQualificationCandidate @param {unknown} attestationHeaderCandidate @returns {V03Result<string>} */
export function qualificationStatementHashV03(
  unsignedQualificationCandidate: unknown,
  attestationHeaderCandidate: unknown,
): V03Result<string> {
  try {
    const parsed = validateUnsignedQualification(unsignedQualificationCandidate, attestationHeaderCandidate);
    return parsed.ok ? success(expectedQualificationStatementHash(parsed.value.unsigned, parsed.value.header)) : parsed;
  } catch { return failure("V03_INPUT_INVALID"); }
}

/** @param {unknown} unsignedQualificationCandidate @param {unknown} attestationHeaderCandidate @returns {V03Result<Uint8Array>} */
export function qualificationSigningBytesV03(
  unsignedQualificationCandidate: unknown,
  attestationHeaderCandidate: unknown,
): V03Result<Uint8Array> {
  try {
    const statement = qualificationStatementHashV03(unsignedQualificationCandidate, attestationHeaderCandidate);
    if (!statement.ok) return statement;
    return success(new Uint8Array(Buffer.from(statement.value, "ascii")));
  } catch { return failure("V03_INPUT_INVALID"); }
}

/** @param {unknown} qualification @param {unknown} qualificationIssuerFromAnchor @returns {V03Result<Readonly<Record<string, unknown>>>} */
export function verifyS37LinuxLaunchQualificationSignatureV03(
  qualification: unknown,
  qualificationIssuerFromAnchor: unknown,
): V03Result<Readonly<QualificationRecord>> {
  try {
    const parsed = parseS37LinuxLaunchQualificationV03(qualification);
    if (!parsed.ok) return parsed;
    const issuer = qualificationIssuerFromAnchor;
    if (!issuerShape(issuer) || !issuerScalars(issuer) || !issuerHashValid(issuer)
      || issuer.key_ref !== parsed.value.attestation.issuer_key_ref
      || issuer.algorithm !== parsed.value.attestation.signature_algorithm) return failure("V03_SIGNATURE_INVALID");
    const publicKey = createPublicKey({ key: Buffer.from(issuer.public_key_spki_base64, "base64"), format: "der", type: "spki" });
    const valid = cryptoVerify(null, Buffer.from(parsed.value.attestation.statement_hash, "ascii"), publicKey,
      Buffer.from(parsed.value.attestation.signature_value, "base64"));
    return valid ? success(parsed.value) : failure("V03_SIGNATURE_INVALID");
  } catch { return failure("V03_SIGNATURE_INVALID"); }
}

/** @param {unknown} value @returns {V03Result<string>} */
export function canonicalV03(value: unknown): V03Result<string> {
  return canonicalResult(value);
}

/** @param {unknown} value @returns {V03Result<string>} */
export function hashCanonicalV03(value: unknown): V03Result<string> {
  const serialized = canonicalResult(value);
  if (!serialized.ok) return serialized;
  return success(`sha256:${createHash("sha256").update(serialized.value, "utf8").digest("hex")}`);
}
