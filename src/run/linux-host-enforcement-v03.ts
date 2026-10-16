import { canonicalV03 } from "./s37-product-host-contract-v03.js";
import {
  consumeAuthorizedS37LinuxLaunchQualificationV03,
  type AuthorizedS37LinuxLaunchQualificationV03,
  type S37AuthorizedLinuxLaunchQualificationBindingV03,
} from "./s37-linux-launch-qualification-v03.js";
import { runS37LinuxHostProbeV02 } from "./linux-host-enforcement-v02.js";
import {
  prepareS37LinuxProbeAdmissionV02,
  type S37ActionInterpositionProfileV02,
  type S37LinuxBackendIdentityReceiptV02,
  type S37LinuxHostTupleV02,
} from "./pre-spawn-capability-broker-v02.js";

type V02Runtime = Parameters<typeof runS37LinuxHostProbeV02>[1];
type V02RuntimeInput = Parameters<V02Runtime["start"]>[0];
type V02RuntimeOutcome = Awaited<ReturnType<V02Runtime["start"]> >;

type ProductHostCustodyV03 = Readonly<{
  ok: true;
  status: "STABLE";
  generation: number;
  anchor_hash: string;
}>;

type SyntheticCapabilityV03 = Readonly<{
  observe_custody(): ProductHostCustodyV03 | unknown | Promise<ProductHostCustodyV03 | unknown>;
  observe_host(): unknown | Promise<unknown>;
  runtime: Readonly<{
    start(input: V02RuntimeInput): Promise<V02RuntimeOutcome>;
  }>;
}>;

type ProbeInputV03 = Readonly<{
  qualification: AuthorizedS37LinuxLaunchQualificationV03;
  profile: S37ActionInterpositionProfileV02;
  conformance_tuple: S37LinuxHostTupleV02;
  backend_receipt: S37LinuxBackendIdentityReceiptV02;
  phase_b_manifest_sha256: string;
}>;

type EnforcementUnavailableV03 = Readonly<{
  ok: false;
  reason: "ENFORCEMENT_UNAVAILABLE";
  terminal: "hold";
  retryable: false;
  process_started: false;
}>;

const ENFORCEMENT_UNAVAILABLE = Object.freeze({
  ok: false as const,
  reason: "ENFORCEMENT_UNAVAILABLE" as const,
  terminal: "hold" as const,
  retryable: false as const,
  process_started: false as const,
});

function hold(): EnforcementUnavailableV03 {
  return ENFORCEMENT_UNAVAILABLE;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactEqual(left: unknown, right: unknown): boolean {
  const a = canonicalV03(left);
  const b = canonicalV03(right);
  return a.ok && b.ok && a.value === b.value;
}

function stableCustody(value: unknown, binding: S37AuthorizedLinuxLaunchQualificationBindingV03): value is ProductHostCustodyV03 {
  if (!isRecord(value) || value.ok !== true || value.status !== "STABLE"
    || typeof value.generation !== "number" || typeof value.anchor_hash !== "string") return false;
  const anchor = binding.anchor;
  return typeof anchor.generation === "number" && typeof anchor.anchor_hash === "string"
    && value.generation === anchor.generation && value.anchor_hash === anchor.anchor_hash
    && value.generation === binding.qualification.anchor_generation
    && value.anchor_hash === binding.qualification.anchor_hash;
}

function observationValid(value: unknown, binding: S37AuthorizedLinuxLaunchQualificationBindingV03): boolean {
  if (!isRecord(value) || typeof value.observed_at !== "string" || !exactEqual(value, binding.observation)) return false;
  const observed = Date.parse(value.observed_at);
  const qualificationObserved = Date.parse(binding.qualification.observed_at);
  const expires = Date.parse(binding.qualification.expires_at);
  return Number.isFinite(observed) && Number.isFinite(qualificationObserved) && Number.isFinite(expires)
    && observed >= qualificationObserved && expires - observed >= 15_000;
}

function inputMatchesBinding(input: ProbeInputV03, binding: S37AuthorizedLinuxLaunchQualificationBindingV03): boolean {
  const qualification = binding.qualification;
  return input.phase_b_manifest_sha256 === qualification.phase_b.manifest_sha256
    && input.backend_receipt.receipt_hash === qualification.phase_b.receipt_hash
    && exactEqual(binding.observation.phase_b, qualification.phase_b)
    && exactEqual(binding.observation.artifacts, qualification.artifacts)
    && exactEqual(binding.observation.deny_witnesses, qualification.deny_witnesses)
    && binding.observation.boot_id_hash === qualification.boot_id_hash
    && binding.observation.runtime_profile_hash === qualification.runtime_profile_hash
    && exactEqual(binding.observation.host, qualification.host);
}

function confirmedNotStarted(): Readonly<{ ok: false; confirmed_not_started: true; detail: "ENFORCEMENT_UNAVAILABLE" }> {
  return Object.freeze({ ok: false, confirmed_not_started: true, detail: "ENFORCEMENT_UNAVAILABLE" });
}

export function createS37LocalLinuxProductProbeV03ForTest(capabilities: SyntheticCapabilityV03) {
  let state: "available" | "in-flight" | "consumed" = "available";
  return async (input: ProbeInputV03): Promise<unknown> => {
    if (state !== "available") return hold();
    state = "in-flight";
    try {
      let firstCustody: unknown;
      let firstObservation: unknown;
      try {
        firstCustody = await capabilities.observe_custody();
        firstObservation = await capabilities.observe_host();
      } catch {
        return hold();
      }

      const binding = consumeAuthorizedS37LinuxLaunchQualificationV03(input?.qualification);
      if (binding === null || !stableCustody(firstCustody, binding)
        || !observationValid(firstObservation, binding) || !inputMatchesBinding(input, binding)) return hold();

      const observation = binding.observation;
      if (!isRecord(observation.host) || typeof observation.host.architecture !== "string") return hold();
      const prepared = prepareS37LinuxProbeAdmissionV02({
        request: {
          decision_input: binding.decision_input,
          decision: binding.decision,
          simulated_lease: binding.simulated_lease,
          observed_at: observation.observed_at,
          host: {
            platform: "linux",
            architecture: observation.host.architecture,
            available_backends: ["s37-linux-v02"],
          },
          adapter: "s37_inert_probe",
        },
        profile: input.profile,
        host_tuple: input.conformance_tuple,
        backend_receipt: input.backend_receipt,
      });
      if (!prepared.ok) return hold();

      const runtime: V02Runtime = Object.freeze({
        start: async (runtimeInput) => {
          let secondCustody: unknown;
          let secondObservation: unknown;
          try {
            secondCustody = await capabilities.observe_custody();
            secondObservation = await capabilities.observe_host();
          } catch {
            return confirmedNotStarted();
          }
          if (!stableCustody(secondCustody, binding) || !exactEqual(secondCustody, firstCustody)
            || !observationValid(secondObservation, binding) || !exactEqual(secondObservation, firstObservation)) {
            return confirmedNotStarted();
          }
          try { return await capabilities.runtime.start(runtimeInput); }
          catch { return confirmedNotStarted(); }
        },
      });
      try {
        const result = await runS37LinuxHostProbeV02(prepared.value, runtime);
        return !result.ok && result.process_started === false ? hold() : result;
      } catch {
        return hold();
      }
    } finally {
      state = "consumed";
    }
  };
}

export async function runS37LocalLinuxProductProbeV03(
  _input: ProbeInputV03,
): Promise<EnforcementUnavailableV03> {
  return hold();
}
