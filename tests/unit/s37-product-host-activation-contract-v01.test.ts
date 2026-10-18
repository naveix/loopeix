import { describe, expect, it } from "vitest";

import { hashCanonical, hashRawBytes } from "../../src/hash.js";
import {
  buildS37ProductHostActivationManifestV01,
  hashS37ProductHostActivationEventV01,
  hashS37ProductHostActivationLedgerV01,
  hashS37ProductHostActivationManifestV01,
  inspectS37ProductHostActivationV01,
  isValidatedS37ProductHostActivationV01,
  reduceS37ProductHostActivationPrefixV01,
  resolveS37ProductHostActivationOutcomeV01,
  S37ProductHostActivationEventV01,
  S37ProductHostActivationManifestV01,
  type S37ProductHostActivationEventV01Value,
} from "../../src/run/s37-product-host-activation-contract-v01.js";

const E = new TextEncoder();
const H = (character: string): string => `sha256:${character.repeat(64)}`;

const EVENT_DOMAIN = "s37-product-host-activation-event-v01";
const LEDGER_DOMAIN = "s37-product-host-activation-ledger-v01";
const MANIFEST_DOMAIN = "s37-product-host-activation-manifest-v01";
const ACTIVATION_ID = `activation_${"1".repeat(64)}`;
const SECOND_ACTIVATION_ID = `activation_${"2".repeat(64)}`;
const THIRD_ACTIVATION_ID = `activation_${"3".repeat(64)}`;
const ANCHOR_HASH = H("a");
const BOOT_ID_HASH = H("b");

const COMMON_EVENT_KEYS = [
  "schema_version",
  "activation_id",
  "operation",
  "sequence",
  "event_type",
  "previous_event_hash",
  "anchor_generation",
  "anchor_hash",
  "boot_id_hash",
  "controller_uid",
  "fence_epoch",
  "payload",
  "event_hash",
] as const;

const MANIFEST_KEYS = [
  "schema_version",
  "active_activation_id",
  "operation",
  "status",
  "ledger_bytes_hash",
  "ledger_sequence",
  "ledger_head_hash",
  "activation_request_hash",
  "anchor_generation",
  "anchor_hash",
  "launch_admission_hash",
  "broker_request_hash",
  "fence_epoch",
  "manifest_hash",
] as const;

const EVENT_CASES = [
  {
    event_type: "activation.requested",
    payload: {
      request_hash: H("1"),
      bundle_hash: H("2"),
      proof_request_hash: H("3"),
      qualification_intent_hash: H("4"),
      action_scope_hash: H("5"),
      initial_absence_observation_hash: H("6"),
    },
  },
  {
    event_type: "activation.nonces-reserved",
    payload: {
      proof_record_hash: H("7"),
      authorization_nonce_record_hash: H("8"),
      launch_nonce_record_hash: H("9"),
    },
  },
  {
    event_type: "activation.anchor-stable",
    payload: {
      mutation_plan_hash: H("a"),
      proposed_anchor_hash: ANCHOR_HASH,
      anchor_observation_hash: H("c"),
    },
  },
  {
    event_type: "activation.qualification-issued",
    payload: {
      qualification_intent_hash: H("4"),
      activation_decision_facts_hash: H("d"),
      decision_input_hash: H("e"),
      decision_simulation_hash: H("f"),
      lease_simulation_hash: H("0"),
      qualification_absence_observation_hash: H("1"),
      qualification_request_hash: H("2"),
      qualification_hash: H("3"),
      qualification_nonce_record_hash: H("4"),
      boot_observation_hash: H("5"),
    },
  },
  {
    event_type: "activation.launch-admitted",
    payload: {
      launch_admission_hash: H("6"),
      qualification_hash: H("3"),
      prelaunch_authorization_revalidation_hash: H("7"),
      final_observation_hash: H("8"),
      broker_request_hash: H("9"),
    },
  },
  {
    event_type: "activation.dispatch-entered",
    payload: {
      launch_admission_hash: H("6"),
      broker_request_hash: H("9"),
      conformance_receipt_hash: H("a"),
      systemd_run_hash: H("c"),
      runtime_profile_hash: H("d"),
      artifact_set_hash: H("e"),
      controller_uid: 64037,
      primary_gid: 64038,
      controller_identity_hash: H("f"),
      unit_name_hash: H("0"),
      cgroup_path_hash: H("1"),
      broker_entry_evidence_hash: H("2"),
    },
  },
  {
    event_type: "activation.completed",
    payload: {
      outcome: "COMPLETED",
      broker_entry_evidence_hash: H("2"),
      completion_evidence_hash: H("3"),
    },
  },
] as const;

const PAYLOAD_KEYS = {
  "activation.requested": [
    "request_hash", "bundle_hash", "proof_request_hash", "qualification_intent_hash", "action_scope_hash",
    "initial_absence_observation_hash",
  ],
  "activation.nonces-reserved": ["proof_record_hash", "authorization_nonce_record_hash", "launch_nonce_record_hash"],
  "activation.anchor-stable": ["mutation_plan_hash", "proposed_anchor_hash", "anchor_observation_hash"],
  "activation.qualification-issued": [
    "qualification_intent_hash", "activation_decision_facts_hash", "decision_input_hash", "decision_simulation_hash",
    "lease_simulation_hash", "qualification_absence_observation_hash", "qualification_request_hash",
    "qualification_hash", "qualification_nonce_record_hash", "boot_observation_hash",
  ],
  "activation.launch-admitted": [
    "launch_admission_hash", "qualification_hash", "prelaunch_authorization_revalidation_hash",
    "final_observation_hash", "broker_request_hash",
  ],
  "activation.dispatch-entered": [
    "launch_admission_hash", "broker_request_hash", "conformance_receipt_hash", "systemd_run_hash",
    "runtime_profile_hash", "artifact_set_hash", "controller_uid", "primary_gid", "controller_identity_hash",
    "unit_name_hash", "cgroup_path_hash", "broker_entry_evidence_hash",
  ],
  "activation.completed": ["outcome", "broker_entry_evidence_hash", "completion_evidence_hash"],
} as const;

const PRELAUNCH_DEADLINE_BINDINGS = [
  ["final-observation", "prelaunch_authorization_valid_until"],
  ["broker-request", "prelaunch_authorization_valid_until"],
  ["launch-admission", "prelaunch_authorization_valid_until"],
] as const;

const POST_COMMIT_DEADLINE_BINDINGS = [
  ["permit", "post_commit_authorization_valid_until"],
  ["broker-entry-evidence", "post_commit_authorization_valid_until"],
] as const;

const IRREVERSIBLE_LAUNCH_ORDER = [
  "activation.launch-admitted",
  "event-five-manifest-readback",
  "c3-post-commit-revalidation",
  "permit-mint",
  "permit-claim",
  "permit-consume",
  "final-trusted-clock-check",
  "synchronous-spawn",
  "activation.dispatch-entered",
] as const;

function eventPreimage(
  sequence: number,
  eventCase: (typeof EVENT_CASES)[number],
  previousEventHash: string | null,
  context: Readonly<{
    activationId: string;
    operation: "install-and-launch" | "transition-and-launch" | "launch-stable";
    anchorGeneration: number;
    anchorHash: string;
    controllerUid: number;
    fenceEpoch: number;
  }>,
): Record<string, unknown> {
  return {
    schema_version: EVENT_DOMAIN,
    activation_id: context.activationId,
    operation: context.operation,
    sequence,
    event_type: eventCase.event_type,
    previous_event_hash: previousEventHash,
    anchor_generation: context.anchorGeneration,
    anchor_hash: context.anchorHash,
    boot_id_hash: BOOT_ID_HASH,
    controller_uid: context.controllerUid,
    fence_epoch: context.fenceEpoch,
    payload: eventCase.payload,
  };
}

function event(
  sequence: number,
  eventCase: (typeof EVENT_CASES)[number],
  previousEventHash: string | null,
  context: Parameters<typeof eventPreimage>[3],
): S37ProductHostActivationEventV01Value {
  const preimage = eventPreimage(sequence, eventCase, previousEventHash, context);
  return S37ProductHostActivationEventV01.parse({
    ...preimage,
    event_hash: hashCanonical({ purpose: EVENT_DOMAIN, event: preimage }),
  });
}

function events(
  count = EVENT_CASES.length,
  options: Readonly<{
    activationId?: string;
    operation?: "install-and-launch" | "transition-and-launch" | "launch-stable";
    startSequence?: number;
    previousEventHash?: string | null;
    anchorGeneration?: number;
    anchorHash?: string;
    controllerUid?: number;
    fenceEpoch?: number;
  }> = {},
): S37ProductHostActivationEventV01Value[] {
  const result: S37ProductHostActivationEventV01Value[] = [];
  const operation = options.operation ?? "install-and-launch";
  for (const [index, eventCase] of EVENT_CASES.slice(0, count).entries()) {
    const payload = operation === "launch-stable" && eventCase.event_type === "activation.requested"
      ? { ...eventCase, payload: { ...eventCase.payload, bundle_hash: null } }
      : operation === "launch-stable" && eventCase.event_type === "activation.anchor-stable"
        ? { ...eventCase, payload: { ...eventCase.payload, mutation_plan_hash: null, proposed_anchor_hash: null } }
        : eventCase;
    result.push(event(
      (options.startSequence ?? 1) + index,
      payload as (typeof EVENT_CASES)[number],
      result.at(-1)?.event_hash ?? options.previousEventHash ?? null,
      {
        activationId: options.activationId ?? ACTIVATION_ID,
        operation,
        anchorGeneration: options.anchorGeneration ?? 1,
        anchorHash: options.anchorHash ?? ANCHOR_HASH,
        controllerUid: options.controllerUid ?? 64037,
        fenceEpoch: options.fenceEpoch ?? 7,
      },
    ));
  }
  return result;
}

function ledgerBytes(count = EVENT_CASES.length): Uint8Array {
  return E.encode(`${events(count).map((candidate) => JSON.stringify(candidate)).join("\n")}\n`);
}

function ledgerBytesFor(candidates: readonly S37ProductHostActivationEventV01Value[]): Uint8Array {
  return E.encode(`${candidates.map((candidate) => JSON.stringify(candidate)).join("\n")}\n`);
}

function twoCompletedActivations(): S37ProductHostActivationEventV01Value[] {
  const first = events();
  const second = events(EVENT_CASES.length, {
    activationId: SECOND_ACTIVATION_ID,
    operation: "launch-stable",
    startSequence: 8,
    previousEventHash: first.at(-1)!.event_hash,
    fenceEpoch: 8,
  });
  return [...first, ...second];
}

function manifestAndLedger(count = EVENT_CASES.length) {
  const ledger = ledgerBytes(count);
  const built = buildS37ProductHostActivationManifestV01({ ledger_bytes: ledger });
  if (!built.ok) throw new Error(built.reason);
  return { ledger, manifest: built.manifest, manifestBytes: built.bytes };
}

function withEventHash(candidate: Record<string, unknown>): Uint8Array {
  return E.encode(`${JSON.stringify(rehashEvent(candidate))}\n`);
}

function rehashEvent(candidate: Record<string, unknown>): Record<string, unknown> & { event_hash: string } {
  const { event_hash: _eventHash, ...preimage } = candidate;
  return {
    ...preimage,
    event_hash: hashCanonical({ purpose: EVENT_DOMAIN, event: preimage }),
  };
}

function withManifestHash(candidate: Record<string, unknown>): Uint8Array {
  const { manifest_hash: _manifestHash, ...preimage } = candidate;
  return E.encode(JSON.stringify({
    ...preimage,
    manifest_hash: hashCanonical({ purpose: MANIFEST_DOMAIN, manifest: preimage }),
  }));
}

function mutatedLedger(
  targetIndex: number,
  mutate: (candidate: Record<string, unknown>) => Record<string, unknown>,
): Uint8Array {
  let previousEventHash: string | null = null;
  const mutated = events().map((candidate, index) => {
    const { event_hash: _eventHash, ...originalPreimage } = candidate;
    const chained = { ...originalPreimage, previous_event_hash: previousEventHash };
    const preimage = index === targetIndex ? mutate(chained) : chained;
    const next = {
      ...preimage,
      event_hash: hashCanonical({ purpose: EVENT_DOMAIN, event: preimage }),
    };
    previousEventHash = next.event_hash;
    return next;
  });
  return E.encode(`${mutated.map((candidate) => JSON.stringify(candidate)).join("\n")}\n`);
}

function rehashCandidates(
  candidates: readonly S37ProductHostActivationEventV01Value[],
  targetIndex: number,
  mutate: (candidate: Record<string, unknown>) => Record<string, unknown>,
): readonly S37ProductHostActivationEventV01Value[] {
  return rehashCandidatesWhere(candidates, (candidate, index) => index === targetIndex ? mutate(candidate) : candidate);
}

function rehashCandidatesWhere(
  candidates: readonly S37ProductHostActivationEventV01Value[],
  mutate: (candidate: Record<string, unknown>, index: number) => Record<string, unknown>,
): readonly S37ProductHostActivationEventV01Value[] {
  let previousEventHash: string | null = null;
  return candidates.map((candidate, index) => {
    const { event_hash: _eventHash, ...originalPreimage } = candidate;
    const chained = { ...originalPreimage, previous_event_hash: previousEventHash };
    const preimage = mutate(chained, index);
    const next = {
      ...preimage,
      event_hash: hashCanonical({ purpose: EVENT_DOMAIN, event: preimage }),
    };
    previousEventHash = next.event_hash;
    return next as S37ProductHostActivationEventV01Value;
  });
}

describe("S37.1-G1 root-owned activation contract", () => {
  it("admits exactly the closed seven-event union with exact common and payload keys", () => {
    const complete = events();
    expect(complete.map((candidate) => candidate.event_type)).toEqual(EVENT_CASES.map((candidate) => candidate.event_type));

    for (const candidate of complete) {
      expect(Object.keys(candidate)).toEqual(COMMON_EVENT_KEYS);
      expect(Object.keys(candidate.payload)).toEqual(PAYLOAD_KEYS[candidate.event_type]);
      expect(Object.isFrozen(candidate)).toBe(true);
      expect(Object.isFrozen(candidate.payload)).toBe(true);
      expect(S37ProductHostActivationEventV01.safeParse(rehashEvent({ ...candidate, invented: true })).success).toBe(false);
      expect(S37ProductHostActivationEventV01.safeParse(rehashEvent({
        ...candidate,
        payload: { ...candidate.payload, invented: true },
      })).success).toBe(false);
    }

    expect(S37ProductHostActivationEventV01.safeParse(rehashEvent({
      ...complete[0],
      event_type: "activation.retried",
    })).success).toBe(false);
    expect(S37ProductHostActivationEventV01.safeParse(rehashEvent({
      ...complete[0],
      operation: "install",
    })).success).toBe(false);
  });

  it("enforces operation-specific bundle and anchor-mutation nullability", () => {
    for (const operation of ["install-and-launch", "transition-and-launch"] as const) {
      const complete = events(EVENT_CASES.length, { operation });
      expect(complete[0]!.payload).toMatchObject({ bundle_hash: H("2") });
      expect(complete[2]!.payload).toMatchObject({
        mutation_plan_hash: H("a"),
        proposed_anchor_hash: ANCHOR_HASH,
      });
    }

    const stable = events(EVENT_CASES.length, { operation: "launch-stable" });
    expect(stable[0]!.payload).toMatchObject({ bundle_hash: null });
    expect(stable[2]!.payload).toMatchObject({ mutation_plan_hash: null, proposed_anchor_hash: null });

    const invalid = [
      { ...stable[0], payload: { ...stable[0]!.payload, bundle_hash: H("f") } },
      { ...stable[2], payload: { ...stable[2]!.payload, mutation_plan_hash: H("f") } },
      { ...events()[0], payload: { ...events()[0]!.payload, bundle_hash: null } },
      { ...events()[2], payload: { ...events()[2]!.payload, proposed_anchor_hash: null } },
    ];
    for (const candidate of invalid) {
      expect(S37ProductHostActivationEventV01.safeParse(rehashEvent(candidate)).success).toBe(false);
    }
  });

  it("keeps authorization deadlines distinct and orders the irreversible launch path", () => {
    expect(PRELAUNCH_DEADLINE_BINDINGS).toEqual([
      ["final-observation", "prelaunch_authorization_valid_until"],
      ["broker-request", "prelaunch_authorization_valid_until"],
      ["launch-admission", "prelaunch_authorization_valid_until"],
    ]);
    expect(POST_COMMIT_DEADLINE_BINDINGS).toEqual([
      ["permit", "post_commit_authorization_valid_until"],
      ["broker-entry-evidence", "post_commit_authorization_valid_until"],
    ]);
    expect(new Set(PRELAUNCH_DEADLINE_BINDINGS.map(([, field]) => field))).toEqual(
      new Set(["prelaunch_authorization_valid_until"]),
    );
    expect(new Set(POST_COMMIT_DEADLINE_BINDINGS.map(([, field]) => field))).toEqual(
      new Set(["post_commit_authorization_valid_until"]),
    );
    expect(IRREVERSIBLE_LAUNCH_ORDER).toEqual([
      "activation.launch-admitted",
      "event-five-manifest-readback",
      "c3-post-commit-revalidation",
      "permit-mint",
      "permit-claim",
      "permit-consume",
      "final-trusted-clock-check",
      "synchronous-spawn",
      "activation.dispatch-entered",
    ]);
    expect(IRREVERSIBLE_LAUNCH_ORDER.indexOf("c3-post-commit-revalidation")).toBeLessThan(
      IRREVERSIBLE_LAUNCH_ORDER.indexOf("permit-mint"),
    );
    expect(IRREVERSIBLE_LAUNCH_ORDER.indexOf("permit-consume")).toBeLessThan(
      IRREVERSIBLE_LAUNCH_ORDER.indexOf("synchronous-spawn"),
    );
    expect(IRREVERSIBLE_LAUNCH_ORDER.indexOf("synchronous-spawn")).toBeLessThan(
      IRREVERSIBLE_LAUNCH_ORDER.indexOf("activation.dispatch-entered"),
    );
  });

  it("rejects invalid machine IDs, scalar bounds, hash case, and boot binding drift", () => {
    const complete = events();
    const invalid: ReadonlyArray<Record<string, unknown>> = [
      { ...complete[0], activation_id: "Activation-1" },
      { ...complete[0], sequence: 0 },
      { ...complete[0], anchor_generation: 0 },
      { ...complete[0], anchor_hash: `sha256:${"A".repeat(64)}` },
      { ...complete[0], controller_uid: 0 },
      { ...complete[0], fence_epoch: -1 },
      { ...complete[0], boot_id_hash: null },
      { ...complete[3], boot_id_hash: null },
      { ...complete[1], previous_event_hash: null },
    ];
    for (const candidate of invalid) {
      expect(S37ProductHostActivationEventV01.safeParse(rehashEvent(candidate)).success).toBe(false);
    }
  });

  it("uses independent RFC 8785 domains for event, ledger, and manifest hashes", () => {
    const first = events(1)[0]!;
    const { event_hash: _eventHash, ...eventHashPreimage } = first;
    expect(first.event_hash).toBe(hashCanonical({ purpose: EVENT_DOMAIN, event: eventHashPreimage }));
    expect(hashS37ProductHostActivationEventV01(eventHashPreimage)).toBe(first.event_hash);

    const { ledger, manifest } = manifestAndLedger();
    const rawLedgerHash = hashRawBytes(ledger);
    expect(hashS37ProductHostActivationLedgerV01(ledger)).toBe(hashCanonical({
      purpose: LEDGER_DOMAIN,
      ledger_bytes_sha256: rawLedgerHash,
    }));
    expect(manifest.ledger_bytes_hash).toBe(hashS37ProductHostActivationLedgerV01(ledger));

    const { manifest_hash: _manifestHash, ...manifestHashPreimage } = manifest;
    expect(manifest.manifest_hash).toBe(hashCanonical({
      purpose: MANIFEST_DOMAIN,
      manifest: manifestHashPreimage,
    }));
    expect(hashS37ProductHostActivationManifestV01(manifestHashPreimage)).toBe(manifest.manifest_hash);

    expect(first.event_hash).not.toBe(hashCanonical(eventHashPreimage));
    expect(manifest.ledger_bytes_hash).not.toBe(rawLedgerHash);
    expect(manifest.manifest_hash).not.toBe(hashCanonical(manifestHashPreimage));
  });

  it("builds the exact immutable committed-head manifest projection", () => {
    const { ledger, manifest, manifestBytes } = manifestAndLedger();
    const last = events().at(-1)!;
    expect(Object.keys(manifest)).toEqual(MANIFEST_KEYS);
    expect(manifest).toMatchObject({
      schema_version: MANIFEST_DOMAIN,
      active_activation_id: ACTIVATION_ID,
      operation: "install-and-launch",
      status: "COMPLETED",
      ledger_sequence: 7,
      ledger_head_hash: last.event_hash,
      anchor_generation: 1,
      anchor_hash: ANCHOR_HASH,
      fence_epoch: 7,
    });
    expect(manifest.ledger_bytes_hash).toBe(hashS37ProductHostActivationLedgerV01(ledger));
    expect(JSON.parse(new TextDecoder().decode(manifestBytes))).toEqual(manifest);
    expect(Object.isFrozen(manifest)).toBe(true);
    expect(S37ProductHostActivationManifestV01.safeParse({ ...manifest, invented: true }).success).toBe(false);

    const launchAdmitted = manifestAndLedger(5).manifest;
    expect(launchAdmitted.status).toBe("LAUNCH_ADMITTED");
    expect(launchAdmitted.ledger_sequence).toBe(5);
  });

  it("cross-checks every manifest head field against the exact ledger", () => {
    const { ledger, manifest } = manifestAndLedger();
    const mutations: ReadonlyArray<Record<string, unknown>> = [
      { ...manifest, active_activation_id: `activation_${"f".repeat(64)}` },
      { ...manifest, operation: "transition-and-launch" },
      { ...manifest, status: "DISPATCH_ENTERED" },
      { ...manifest, ledger_bytes_hash: H("f") },
      { ...manifest, ledger_sequence: 6 },
      { ...manifest, ledger_head_hash: H("f") },
      { ...manifest, anchor_generation: 2 },
      { ...manifest, anchor_hash: H("f") },
      { ...manifest, fence_epoch: 8 },
    ];
    for (const mutation of mutations) {
      expect(inspectS37ProductHostActivationV01({
        ledger_bytes: ledger,
        manifest_bytes: withManifestHash(mutation),
      })).toMatchObject({ ok: false, reason: "MANIFEST_CROSS_CHECK_INVALID" });
    }
  });

  it("rejects sequence, chain, identity, binding, hash, and closed-union drift", () => {
    const base = events();
    const invalid: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
      ["sequence gap", { ...base[0], sequence: 2 }],
      ["non-null genesis predecessor", { ...base[0], previous_event_hash: H("f") }],
      ["unknown event", { ...base[0], event_type: "activation.retried" }],
      ["extra event key", { ...base[0], retry: true }],
      ["extra payload key", { ...base[0], payload: { ...base[0]!.payload, retry: true } }],
    ];
    for (const [label, mutation] of invalid) {
      expect(S37ProductHostActivationEventV01.safeParse(rehashEvent(mutation)).success, label).toBe(false);
    }

    const brokenPrevious = { ...base[1], previous_event_hash: H("f") };
    const twoLineLedger = E.encode(`${JSON.stringify(base[0])}\n${new TextDecoder().decode(withEventHash(brokenPrevious))}`);
    expect(inspectS37ProductHostActivationV01({
      ledger_bytes: twoLineLedger,
      manifest_bytes: manifestAndLedger(2).manifestBytes,
    })).toMatchObject({ ok: false, reason: "LEDGER_HASH_CHAIN_INVALID" });
  });

  it("rejects independently rehashed cross-event identity and payload binding drift", () => {
    const { manifestBytes } = manifestAndLedger();
    const mutations: ReadonlyArray<readonly [string, number, (candidate: Record<string, unknown>) => Record<string, unknown>]> = [
      ["activation", 1, (candidate) => ({ ...candidate, activation_id: `activation_${"f".repeat(64)}` })],
      ["operation", 1, (candidate) => ({ ...candidate, operation: "transition-and-launch" })],
      ["anchor generation", 2, (candidate) => ({ ...candidate, anchor_generation: 2 })],
      ["anchor hash", 2, (candidate) => ({ ...candidate, anchor_hash: H("f") })],
      ["proposed anchor", 2, (candidate) => ({
        ...candidate,
        payload: { ...(candidate.payload as Record<string, unknown>), proposed_anchor_hash: H("f") },
      })],
      ["qualification request", 3, (candidate) => ({
        ...candidate,
        payload: { ...(candidate.payload as Record<string, unknown>), qualification_request_hash: H("f") },
      })],
      ["qualification admission", 4, (candidate) => ({
        ...candidate,
        payload: { ...(candidate.payload as Record<string, unknown>), qualification_hash: H("f") },
      })],
      ["boot", 4, (candidate) => ({ ...candidate, boot_id_hash: H("f") })],
      ["controller UID", 4, (candidate) => ({ ...candidate, controller_uid: 64038 })],
      ["fence", 4, (candidate) => ({ ...candidate, fence_epoch: 8 })],
    ];
    for (const [label, index, mutate] of mutations) {
      expect(inspectS37ProductHostActivationV01({
        ledger_bytes: mutatedLedger(index, mutate),
        manifest_bytes: manifestBytes,
      }), label).toMatchObject({ ok: false, reason: "LEDGER_HISTORY_INVALID" });
    }

    expect(inspectS37ProductHostActivationV01({
      ledger_bytes: mutatedLedger(6, (candidate) => ({
        ...candidate,
        payload: { ...(candidate.payload as Record<string, unknown>), outcome: "NOT_STARTED" },
      })),
      manifest_bytes: manifestBytes,
    })).toMatchObject({ ok: false, reason: "LEDGER_EVENT_SCHEMA_INVALID" });
  });

  it("reduces every durable prefix without inventing retry or clean non-entry", () => {
    const expected = [
      [0, "EMPTY", "NOT_STARTED"],
      [1, "REQUESTED", "RECOVERY_REQUIRED"],
      [2, "NONCES_RESERVED", "RECOVERY_REQUIRED"],
      [3, "ANCHOR_STABLE", "RECOVERY_REQUIRED"],
      [4, "QUALIFICATION_ISSUED", "RECOVERY_REQUIRED"],
      [5, "LAUNCH_ADMITTED", "OUTCOME_UNKNOWN"],
      [6, "DISPATCH_ENTERED", "OUTCOME_UNKNOWN"],
      [7, "COMPLETED", "COMPLETED"],
    ] as const;
    for (const [count, status, outcome] of expected) {
      expect(reduceS37ProductHostActivationPrefixV01(events(count))).toMatchObject({
        ok: true,
        state: { status, outcome },
      });
    }
  });

  it("rejects skipped, reordered, duplicate, and post-completion transitions", () => {
    const complete = events();
    const cases: ReadonlyArray<readonly [string, readonly S37ProductHostActivationEventV01Value[]]> = [
      ["skipped", [complete[0]!, complete[2]!]],
      ["reordered", [complete[0]!, complete[2]!, complete[1]!]],
      ["duplicate", [complete[0]!, complete[1]!, complete[1]!]],
      ["post-completion", [...complete, complete[6]!]],
    ];
    for (const [label, candidate] of cases) {
      expect(reduceS37ProductHostActivationPrefixV01(candidate), label).toMatchObject({ ok: false });
    }
  });

  it("accepts multiple activations only as adjacent seven-event global-sequence blocks", () => {
    const chained = twoCompletedActivations();
    expect(chained).toHaveLength(14);
    expect(chained.map((candidate) => candidate.sequence)).toEqual([
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    ]);
    expect(new Set(chained.slice(0, 7).map((candidate) => candidate.activation_id))).toEqual(new Set([ACTIVATION_ID]));
    expect(new Set(chained.slice(7).map((candidate) => candidate.activation_id))).toEqual(new Set([SECOND_ACTIVATION_ID]));
    expect(new Set(chained.slice(0, 7).map((candidate) => candidate.fence_epoch))).toEqual(new Set([7]));
    expect(new Set(chained.slice(7).map((candidate) => candidate.fence_epoch))).toEqual(new Set([8]));
    expect(reduceS37ProductHostActivationPrefixV01(chained)).toMatchObject({
      ok: true,
      state: {
        activation_id: SECOND_ACTIVATION_ID,
        status: "COMPLETED",
        outcome: "COMPLETED",
        sequence: 14,
        fence_epoch: 8,
      },
    });

    const ledger = ledgerBytesFor(chained);
    const built = buildS37ProductHostActivationManifestV01({ ledger_bytes: ledger });
    expect(built).toMatchObject({
      ok: true,
      manifest: {
        active_activation_id: SECOND_ACTIVATION_ID,
        operation: "launch-stable",
        status: "COMPLETED",
        ledger_sequence: 14,
        fence_epoch: 8,
      },
    });
  });

  it("rejects sequence reset, interleaving, premature successors, and every fence-epoch violation", () => {
    const first = events();
    const secondRequested = events(1, {
      activationId: SECOND_ACTIVATION_ID,
      operation: "launch-stable",
      startSequence: 8,
      previousEventHash: first.at(-1)!.event_hash,
      fenceEpoch: 8,
    })[0]!;
    const interleaved = [
      first[0]!,
      ...events(1, {
        activationId: SECOND_ACTIVATION_ID,
        operation: "launch-stable",
        startSequence: 2,
        previousEventHash: first[0]!.event_hash,
        fenceEpoch: 8,
      }),
    ];
    const premature = [
      ...first.slice(0, 6),
      ...events(1, {
        activationId: SECOND_ACTIVATION_ID,
        operation: "launch-stable",
        startSequence: 7,
        previousEventHash: first[5]!.event_hash,
        fenceEpoch: 8,
      }),
    ];
    const valid = twoCompletedActivations();
    const partialSecond = valid.slice(0, 13);
    expect(reduceS37ProductHostActivationPrefixV01(partialSecond)).toMatchObject({
      ok: true,
      state: {
        activation_id: SECOND_ACTIVATION_ID,
        status: "DISPATCH_ENTERED",
        outcome: "OUTCOME_UNKNOWN",
      },
    });
    const thirdAfterPartial = [
      ...partialSecond,
      ...events(1, {
        activationId: THIRD_ACTIVATION_ID,
        operation: "launch-stable",
        startSequence: 14,
        previousEventHash: partialSecond.at(-1)!.event_hash,
        fenceEpoch: 9,
      }),
    ];
    const cases: ReadonlyArray<readonly [string, readonly S37ProductHostActivationEventV01Value[]]> = [
      ["global sequence reset", rehashCandidatesWhere(valid, (candidate, index) => ({
        ...candidate,
        sequence: index < 7 ? index + 1 : index - 6,
      }))],
      ["activation interleaving", interleaved],
      ["successor before completed predecessor", premature],
      ["fence did not increment", rehashCandidatesWhere(valid, (candidate, index) => ({
        ...candidate,
        fence_epoch: index < 7 ? 7 : 7,
      }))],
      ["fence skipped an epoch", rehashCandidatesWhere(valid, (candidate, index) => ({
        ...candidate,
        fence_epoch: index < 7 ? 7 : 9,
      }))],
      ["fence changed within activation", rehashCandidates(valid, 9, (candidate) => ({ ...candidate, fence_epoch: 9 }))],
      ["third activation after incomplete second", thirdAfterPartial],
    ];
    for (const [label, candidate] of cases) {
      expect(reduceS37ProductHostActivationPrefixV01(candidate), label).toMatchObject({ ok: false });
    }
  });

  it("applies exact closed outcome precedence with highest severity winning", () => {
    const precedence = [
      "OUTCOME_UNKNOWN",
      "RECOVERY_REQUIRED",
      "NOT_COMMITTED",
      "NOT_STARTED",
      "COMPLETED",
    ] as const;
    for (const [index, expected] of precedence.entries()) {
      expect(resolveS37ProductHostActivationOutcomeV01(precedence.slice(index))).toBe(expected);
      expect(resolveS37ProductHostActivationOutcomeV01([...precedence.slice(index)].reverse())).toBe(expected);
    }
    expect(resolveS37ProductHostActivationOutcomeV01(["COMPLETED"])).toBe("COMPLETED");
    expect(resolveS37ProductHostActivationOutcomeV01([])).toBe("NOT_STARTED");
    expect(() => resolveS37ProductHostActivationOutcomeV01(["RETRY" as never])).toThrow();
  });

  it("is the sole validated-state brand minter and does not trust structural clones", () => {
    const { ledger, manifestBytes } = manifestAndLedger();
    const inspected = inspectS37ProductHostActivationV01({
      ledger_bytes: ledger,
      manifest_bytes: manifestBytes,
    });
    expect(inspected).toMatchObject({
      ok: true,
      state: { status: "COMPLETED", outcome: "COMPLETED" },
    });
    if (!inspected.ok) return;
    expect(isValidatedS37ProductHostActivationV01(inspected.validated_activation)).toBe(true);
    expect(Object.isFrozen(inspected.validated_activation)).toBe(true);
    expect(isValidatedS37ProductHostActivationV01({ ...inspected.validated_activation })).toBe(false);
    expect(isValidatedS37ProductHostActivationV01(structuredClone(inspected.validated_activation))).toBe(false);
  });

  it("strictly captures bounded, non-shared bytes and rejects hostile syntax", () => {
    const { ledger, manifestBytes } = manifestAndLedger();
    expect(inspectS37ProductHostActivationV01({
      ledger_bytes: E.encode('{"schema_version":"x","schema_version":"x"}\n'),
      manifest_bytes: manifestBytes,
    })).toMatchObject({ ok: false, reason: "LEDGER_SYNTAX_INVALID" });
    expect(inspectS37ProductHostActivationV01({
      ledger_bytes: ledger.slice(0, -1),
      manifest_bytes: manifestBytes,
    })).toMatchObject({ ok: false, reason: "LEDGER_SYNTAX_INVALID" });
    expect(inspectS37ProductHostActivationV01({
      ledger_bytes: ledger,
      manifest_bytes: E.encode('{"schema_version":"x","schema_version":"x"}'),
    })).toMatchObject({ ok: false, reason: "MANIFEST_SYNTAX_INVALID" });

    const shared = new Uint8Array(new SharedArrayBuffer(ledger.byteLength));
    shared.set(ledger);
    expect(inspectS37ProductHostActivationV01({
      ledger_bytes: shared,
      manifest_bytes: manifestBytes,
    })).toEqual({ ok: false, reason: "ACTIVATION_INPUT_INVALID" });

    const hostile = new Proxy({ ledger_bytes: ledger, manifest_bytes: manifestBytes }, {
      getPrototypeOf: () => { throw new Error("trap"); },
    });
    expect(inspectS37ProductHostActivationV01(hostile)).toEqual({
      ok: false,
      reason: "ACTIVATION_INPUT_INVALID",
    });
  });
});
