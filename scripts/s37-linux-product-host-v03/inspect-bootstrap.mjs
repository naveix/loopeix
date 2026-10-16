import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REQUIRED_CONTROLLERS = Object.freeze(["cpu", "io", "memory", "pids"]);
const CONTRACT_URL = new URL("../../dist/run/s37-product-host-contract-v03.js", import.meta.url);

export async function loadV03Contract(importer = (url) => import(url)) {
  try {
    return await importer(CONTRACT_URL.href);
  } catch {
    throw new Error("V03_CONTRACT_NOT_BUILT: run pnpm build before using product-host tooling");
  }
}

export async function inspectS37ProductHostBootstrapV03({ expectedController, observe }) {
  if (typeof observe !== "function" || expectedController === null || typeof expectedController !== "object") {
    return { ok: false, error: "BOOTSTRAP_INPUT_INVALID" };
  }
  let raw;
  try {
    raw = await observe();
  } catch {
    return { ok: false, error: "BOOTSTRAP_OBSERVATION_UNAVAILABLE" };
  }
  const controllers = Array.isArray(raw?.cgroup_controllers) ? raw.cgroup_controllers : [];
  const controllerComplete = REQUIRED_CONTROLLERS.every((name) => controllers.includes(name));
  const candidate = {
    schema_version: "s37-product-host-bootstrap-inspection-v01",
    observed_at: raw?.observed_at,
    platform: raw?.platform,
    distribution: raw?.distribution,
    architecture: raw?.architecture,
    kernel_release: raw?.kernel_release,
    systemd_version: raw?.systemd_version,
    cgroup_version: raw?.cgroup_version,
    required_cgroup_controllers: [...REQUIRED_CONTROLLERS],
    host_identity_hash: raw?.host_identity_hash,
    boot_id_hash: raw?.boot_id_hash,
    expected_controller: { ...expectedController },
    observed_controller: raw?.observed_controller,
    user_manager: raw?.user_manager,
    checks: {
      controller_nonroot: raw?.observed_controller?.uid > 0,
      username_uid_mapping_exact: raw?.observed_controller?.username === expectedController.username
        && raw?.observed_controller?.uid === expectedController.uid,
      user_manager_active: raw?.user_manager?.active === true,
      cgroup_controllers_complete: controllerComplete,
    },
  };
  if (candidate.platform !== "linux" || candidate.distribution?.id !== "debian"
    || candidate.distribution?.version_id !== "13" || candidate.architecture !== "x86_64"
    || candidate.cgroup_version !== "v2" || !Object.values(candidate.checks).every(Boolean)) {
    return { ok: false, error: "BOOTSTRAP_PRECONDITION_HOLD" };
  }
  let contract;
  try {
    contract = await loadV03Contract();
  } catch {
    return { ok: false, error: "V03_CONTRACT_NOT_BUILT" };
  }
  const hash = contract.hashCanonicalV03({
    purpose: "s37-product-host-bootstrap-inspection-v01",
    ...candidate,
  });
  if (!hash.ok) return { ok: false, error: hash.error };
  const parsed = contract.parseS37ProductHostBootstrapInspectionV01({ ...candidate, inspection_hash: hash.value });
  return parsed.ok ? { ok: true, inspection: parsed.value } : { ok: false, error: parsed.error };
}

function isDirectExecution() {
  return process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
}

if (isDirectExecution()) {
  process.stderr.write("HOLD: inspect-bootstrap requires an explicit same-host observation adapter\n");
  process.exitCode = 64;
}
