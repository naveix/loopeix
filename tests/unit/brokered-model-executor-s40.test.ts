import { describe, expect, it, vi } from "vitest";

import {
  captureBrokeredModelExecutorAdapterV01,
  createSyntheticBrokeredModelExecutorAdapterV01ForTest,
  runCapturedBrokeredModelExecutorV01,
  runBrokeredModelExecutorV01,
  type CapturedBrokeredModelExecutorAdapterV01,
  type SyntheticBrokeredModelExecutorAdapterV01,
} from "../../src/run/brokered-model-executor-v01.js";
import { hashBytes } from "../../src/hash.js";

const H = `sha256:${"a".repeat(64)}`;
const HB = `sha256:${"b".repeat(64)}`;
const CAPTURED_ADAPTER_IDENTITY = Object.freeze({
  executor_profile_hash: H,
  adapter_ref: "model_adapter_s40_v01",
  adapter_version_hash: `sha256:${"c".repeat(64)}`,
  eligible_adapter_evidence_hash: `sha256:${"d".repeat(64)}`,
  bypass_evidence_hash: `sha256:${"e".repeat(64)}`,
});

function capturedAdapterSource(invoke: (approvedContext: unknown) => unknown | Promise<unknown>) {
  return { invoke, ...CAPTURED_ADAPTER_IDENTITY };
}

function context() {
  return {
    context_version: "0.1",
    executor_profile_hash: H,
    run_id: "run_s40_0001",
    plan_hash: H,
    task_ref: "task-s40",
    attempt_id: "attempt_s40_0001",
    turn_id: "turn_s40_0001",
    actor_identity_hash: H,
    on_behalf_of_chain_hash: H,
    prompt: "Propose the smallest safe next action.",
    context_items: [{ context_ref: "source-main", content_hash: hashBytes("bounded context"), sensitivity: "internal", content: "bounded context" }],
    allowed_references: {
      effect_refs: ["effect-read"],
      evidence_refs: ["evidence-a"],
      program_refs: ["git-readonly"],
      path_refs: ["workspace-root", "file-target", "network-path"],
      origin_refs: ["api-origin"],
      tool_refs: ["registered-tool"],
      connector_refs: ["registered-connector"],
      account_refs: ["registered-account"],
      operation_refs: ["registered-operation"],
      target_refs: ["registered-target"],
      content_refs: ["registered-content"],
      body_refs: ["registered-body"],
      argument_refs: ["registered-arguments"],
    },
  };
}

describe("BrokeredModelExecutorV01", () => {
  it("returns a frozen untrusted completion suggestion from a synthetic adapter", async () => {
    const adapter = createSyntheticBrokeredModelExecutorAdapterV01ForTest(async () => ({
      response_version: "0.1",
      kind: "completion-suggestion",
      summary: "The model suggests completion; the kernel must still verify it.",
      evidence_refs: ["evidence-a"],
    }));

    const result = await runBrokeredModelExecutorV01(context(), adapter);

    expect(result).toEqual({
      ok: true,
      value: {
        response_version: "0.1",
        kind: "completion-suggestion",
        summary: "The model suggests completion; the kernel must still verify it.",
        evidence_refs: ["evidence-a"],
        trust: "untrusted-suggestion",
      },
    });
    if (result.ok && result.value.kind === "completion-suggestion") {
      expect(Object.isFrozen(result.value)).toBe(true);
      expect(Object.isFrozen(result.value.evidence_refs)).toBe(true);
    }
  });

  it("snapshots context before the synthetic adapter can mutate caller aliases", async () => {
    const input = context();
    const seen = vi.fn();
    const adapter = createSyntheticBrokeredModelExecutorAdapterV01ForTest(async (captured) => {
      seen(captured);
      return {
        response_version: "0.1",
        kind: "completion-suggestion",
        summary: "done",
        evidence_refs: [],
      };
    });
    const pending = runBrokeredModelExecutorV01(input, adapter);
    input.prompt = "mutated";
    input.context_items[0]!.content = "mutated";
    await pending;

    expect(seen.mock.calls[0]![0]).toMatchObject({
      prompt: "Propose the smallest safe next action.",
      context_items: [{ content: "bounded context" }],
    });
    expect(Object.isFrozen(seen.mock.calls[0]![0])).toBe(true);
    expect(Object.isFrozen(seen.mock.calls[0]![0].allowed_references)).toBe(true);
    expect(Object.isFrozen(seen.mock.calls[0]![0].allowed_references.program_refs)).toBe(true);
  });

  it("requires the exact executor profile binding before invoking the adapter", async () => {
    const invoke = vi.fn(async () => ({
      response_version: "0.1", kind: "completion-suggestion", summary: "done", evidence_refs: [],
    }));
    const adapter = createSyntheticBrokeredModelExecutorAdapterV01ForTest(invoke);
    const missingProfile = context() as Record<string, unknown>;
    delete missingProfile.executor_profile_hash;

    await expect(runBrokeredModelExecutorV01(missingProfile, adapter))
      .resolves.toEqual({ ok: false, error: "MODEL_CONTEXT_INVALID" });
    await expect(runBrokeredModelExecutorV01({ ...context(), executor_profile_hash: "sha256:invalid" }, adapter))
      .resolves.toEqual({ ok: false, error: "MODEL_CONTEXT_INVALID" });
    expect(invoke).not.toHaveBeenCalled();
  });

  it("accepts only a strict typed action proposal without granting authority", async () => {
    const adapter = createSyntheticBrokeredModelExecutorAdapterV01ForTest(async () => ({
      response_version: "0.1",
      kind: "action-proposal",
      proposal_ordinal: 1,
      task_ref: "task-s40",
      effect_refs: ["effect-read"],
      data_classes: ["internal"],
      action: {
        action_kind: "command", program_ref: "git-readonly",
        arguments_ref: "registered-arguments", arguments_hash: H, cwd_ref: "workspace-root",
      },
    }));

    const result = await runBrokeredModelExecutorV01(context(), adapter);

    expect(result).toMatchObject({ ok: true, value: { kind: "action-proposal", trust: "untrusted-proposal", action: { action_kind: "command" } } });
    expect(JSON.stringify(result)).not.toMatch(/decision|lease|authority_ref|policy_digest/u);
  });

  it.each([
    { action_kind: "file", operation: "write", path_ref: "file-target", content_ref: "registered-content", content_hash: H },
    { action_kind: "tool", tool_ref: "registered-tool", tool_schema_hash: H, arguments_ref: "registered-arguments", arguments_hash: H },
    { action_kind: "connector", connector_ref: "registered-connector", account_ref: "registered-account", operation_ref: "registered-operation", target_ref: "registered-target" },
    { action_kind: "network", method: "POST", origin_ref: "api-origin", path_ref: "network-path", body_ref: "registered-body", body_hash: H },
  ] as const)("accepts registered $action_kind proposal references", async (action) => {
    const adapter = createSyntheticBrokeredModelExecutorAdapterV01ForTest(async () => ({
      response_version: "0.1",
      kind: "action-proposal",
      proposal_ordinal: 1,
      task_ref: "task-s40",
      effect_refs: ["effect-read"],
      data_classes: ["internal"],
      action,
    }));

    await expect(runBrokeredModelExecutorV01(context(), adapter))
      .resolves.toMatchObject({ ok: true, value: { kind: "action-proposal", action: { action_kind: action.action_kind } } });
  });

  it("accepts only registered context references in clarification suggestions", async () => {
    const adapter = createSyntheticBrokeredModelExecutorAdapterV01ForTest(async () => ({
      response_version: "0.1", kind: "clarification-suggestion", question: "Need the registered source", required_context_refs: ["source-main"],
    }));

    await expect(runBrokeredModelExecutorV01(context(), adapter))
      .resolves.toMatchObject({ ok: true, value: { kind: "clarification-suggestion", required_context_refs: ["source-main"] } });
  });

  it("rejects proposal authority laundering and does not retry", async () => {
    const invoke = vi.fn(async () => ({
      response_version: "0.1",
      kind: "action-proposal",
      proposal_ordinal: 1,
      task_ref: "task-s40",
      effect_refs: ["effect-read"],
      data_classes: ["internal"],
      action: {
        action_kind: "command", program_ref: "git-readonly",
        arguments_ref: "registered-arguments", arguments_hash: H, cwd_ref: "workspace-root",
      },
      policy_decision: "allow",
      execution_lease: "lease_forged",
    }));
    const adapter = createSyntheticBrokeredModelExecutorAdapterV01ForTest(invoke);

    await expect(runBrokeredModelExecutorV01(context(), adapter)).resolves.toEqual({ ok: false, error: "MODEL_RESPONSE_INVALID" });
    expect(invoke).toHaveBeenCalledTimes(1);
  });

  it("rejects accessors without invoking them and rejects forged adapter tokens", async () => {
    const getter = vi.fn(() => "secret");
    const hostile = context() as Record<string, unknown>;
    Object.defineProperty(hostile, "ambient_credential", { enumerable: true, get: getter });
    const adapter = createSyntheticBrokeredModelExecutorAdapterV01ForTest(async () => ({
      response_version: "0.1", kind: "completion-suggestion", summary: "done", evidence_refs: [],
    }));

    await expect(runBrokeredModelExecutorV01(hostile, adapter)).resolves.toEqual({ ok: false, error: "MODEL_CONTEXT_INVALID" });
    expect(getter).not.toHaveBeenCalled();
    await expect(runBrokeredModelExecutorV01(context(), Object.freeze({}) as never))
      .resolves.toEqual({ ok: false, error: "MODEL_ADAPTER_INVALID" });
  });

  it("maps synthetic adapter failure to a closed error without retry or fallback", async () => {
    const invoke = vi.fn(async () => { throw new Error("sensitive provider detail"); });
    const adapter = createSyntheticBrokeredModelExecutorAdapterV01ForTest(invoke);

    await expect(runBrokeredModelExecutorV01(context(), adapter)).resolves.toEqual({ ok: false, error: "MODEL_ADAPTER_FAILURE" });
    expect(invoke).toHaveBeenCalledTimes(1);
  });

  it("rejects mismatched context bytes and cross-task proposals", async () => {
    const mismatched = context();
    mismatched.context_items[0]!.content_hash = H;
    const unused = vi.fn();
    const unusedAdapter = createSyntheticBrokeredModelExecutorAdapterV01ForTest(unused);
    await expect(runBrokeredModelExecutorV01(mismatched, unusedAdapter))
      .resolves.toEqual({ ok: false, error: "MODEL_CONTEXT_INVALID" });
    expect(unused).not.toHaveBeenCalled();

    const crossTask = createSyntheticBrokeredModelExecutorAdapterV01ForTest(async () => ({
      response_version: "0.1",
      kind: "action-proposal",
      proposal_ordinal: 1,
      task_ref: "another-task",
      effect_refs: ["effect-read"],
      data_classes: ["internal"],
      action: {
        action_kind: "command", program_ref: "git-readonly",
        arguments_ref: "registered-arguments", arguments_hash: H, cwd_ref: "workspace-root",
      },
    }));
    await expect(runBrokeredModelExecutorV01(context(), crossTask))
      .resolves.toEqual({ ok: false, error: "MODEL_RESPONSE_INVALID" });
  });

  it.each([
    ["effect", { effect_refs: ["effect-unregistered"] }, { action_kind: "command", program_ref: "git-readonly", arguments_ref: "registered-arguments", arguments_hash: H, cwd_ref: "workspace-root" }],
    ["program", {}, { action_kind: "command", program_ref: "evidence-a", arguments_ref: "registered-arguments", arguments_hash: H, cwd_ref: "workspace-root" }],
    ["command arguments", {}, { action_kind: "command", program_ref: "git-readonly", arguments_ref: "arguments-unregistered", arguments_hash: H, cwd_ref: "workspace-root" }],
    ["command path", {}, { action_kind: "command", program_ref: "git-readonly", arguments_ref: "registered-arguments", arguments_hash: H, cwd_ref: "file-unregistered" }],
    ["file path", {}, { action_kind: "file", operation: "read", path_ref: "file-unregistered", content_ref: null, content_hash: null }],
    ["content", {}, { action_kind: "file", operation: "write", path_ref: "file-target", content_ref: "content-unregistered", content_hash: H }],
    ["tool", {}, { action_kind: "tool", tool_ref: "tool-unregistered", tool_schema_hash: H, arguments_ref: "registered-arguments", arguments_hash: H }],
    ["arguments", {}, { action_kind: "tool", tool_ref: "registered-tool", tool_schema_hash: H, arguments_ref: "arguments-unregistered", arguments_hash: H }],
    ["connector", {}, { action_kind: "connector", connector_ref: "connector-unregistered", account_ref: "registered-account", operation_ref: "registered-operation", target_ref: "registered-target" }],
    ["account", {}, { action_kind: "connector", connector_ref: "registered-connector", account_ref: "account-unregistered", operation_ref: "registered-operation", target_ref: "registered-target" }],
    ["operation", {}, { action_kind: "connector", connector_ref: "registered-connector", account_ref: "registered-account", operation_ref: "operation-unregistered", target_ref: "registered-target" }],
    ["target", {}, { action_kind: "connector", connector_ref: "registered-connector", account_ref: "registered-account", operation_ref: "registered-operation", target_ref: "target-unregistered" }],
    ["origin", {}, { action_kind: "network", method: "GET", origin_ref: "origin-unregistered", path_ref: "network-path", body_ref: null, body_hash: null }],
    ["network path", {}, { action_kind: "network", method: "GET", origin_ref: "api-origin", path_ref: "path-unregistered", body_ref: null, body_hash: null }],
    ["body", {}, { action_kind: "network", method: "POST", origin_ref: "api-origin", path_ref: "network-path", body_ref: "body-unregistered", body_hash: H }],
  ] as const)("rejects an unregistered %s reference even when it is a valid ID", async (_label, common, action) => {
    const adapter = createSyntheticBrokeredModelExecutorAdapterV01ForTest(async () => ({
      response_version: "0.1",
      kind: "action-proposal",
      proposal_ordinal: 1,
      task_ref: "task-s40",
      effect_refs: ["effect-read"],
      data_classes: ["internal"],
      ...common,
      action,
    }));

    await expect(runBrokeredModelExecutorV01(context(), adapter))
      .resolves.toEqual({ ok: false, error: "MODEL_RESPONSE_INVALID" });
  });

  it("rejects raw argv shell text and paths even when all opaque references are registered", async () => {
    const adapter = createSyntheticBrokeredModelExecutorAdapterV01ForTest(async () => ({
      response_version: "0.1",
      kind: "action-proposal",
      proposal_ordinal: 1,
      task_ref: "task-s40",
      effect_refs: ["effect-read"],
      data_classes: ["restricted"],
      action: {
        action_kind: "command",
        program_ref: "git-readonly",
        cwd_ref: "workspace-root",
        argv: ["-c", "cat /etc/passwd"],
      },
    }));

    await expect(runBrokeredModelExecutorV01(context(), adapter))
      .resolves.toEqual({ ok: false, error: "MODEL_RESPONSE_INVALID" });
  });

  it("rejects unregistered completion evidence and clarification context references", async () => {
    const completion = createSyntheticBrokeredModelExecutorAdapterV01ForTest(async () => ({
      response_version: "0.1", kind: "completion-suggestion", summary: "done", evidence_refs: ["evidence-unregistered"],
    }));
    const clarification = createSyntheticBrokeredModelExecutorAdapterV01ForTest(async () => ({
      response_version: "0.1", kind: "clarification-suggestion", question: "Need context", required_context_refs: ["context-unregistered"],
    }));

    await expect(runBrokeredModelExecutorV01(context(), completion))
      .resolves.toEqual({ ok: false, error: "MODEL_RESPONSE_INVALID" });
    await expect(runBrokeredModelExecutorV01(context(), clarification))
      .resolves.toEqual({ ok: false, error: "MODEL_RESPONSE_INVALID" });
  });
});

describe("CapturedBrokeredModelExecutorAdapterV01", () => {
  const completion = () => ({
    response_version: "0.1" as const,
    kind: "completion-suggestion" as const,
    summary: "Captured executor response.",
    evidence_refs: ["evidence-a"],
  });

  it("captures an exact plain invoke descriptor and reuses bounded executor validation", async () => {
    const invoke = vi.fn(async () => completion());
    const source = capturedAdapterSource(invoke);

    const adapter = captureBrokeredModelExecutorAdapterV01(source);

    expect(adapter).not.toBeNull();
    expect(Object.isFrozen(adapter)).toBe(true);
    expect(Object.keys(adapter ?? {})).toEqual([]);
    expect(JSON.stringify(adapter)).toBe("{}");
    await expect(runCapturedBrokeredModelExecutorV01(context(), adapter!, CAPTURED_ADAPTER_IDENTITY)).resolves.toEqual({
      ok: true,
      value: { ...completion(), trust: "untrusted-suggestion" },
    });
    expect(invoke).toHaveBeenCalledTimes(1);
    expect(Object.isFrozen(invoke.mock.calls[0]![0])).toBe(true);
  });

  it("captures the invoke implementation once and ignores later source descriptor drift", async () => {
    const original = vi.fn(async () => completion());
    const replacement = vi.fn(async () => ({ ...completion(), summary: "replacement" }));
    const source = capturedAdapterSource(original);
    const adapter = captureBrokeredModelExecutorAdapterV01(source);
    expect(adapter).not.toBeNull();

    source.invoke = replacement;
    source.executor_profile_hash = HB;
    source.adapter_ref = "mutated_adapter_s40_v01";
    source.adapter_version_hash = HB;
    source.eligible_adapter_evidence_hash = HB;
    source.bypass_evidence_hash = HB;
    await runCapturedBrokeredModelExecutorV01(context(), adapter!, CAPTURED_ADAPTER_IDENTITY);

    expect(original).toHaveBeenCalledTimes(1);
    expect(replacement).not.toHaveBeenCalled();
  });

  it("rejects missing, extra, accessor, prototype, and symbol-bearing descriptors", () => {
    const exact = capturedAdapterSource(async () => completion());
    for (const key of Object.keys(exact)) {
      const missing = { ...exact } as Record<string, unknown>;
      delete missing[key];
      expect(captureBrokeredModelExecutorAdapterV01(missing)).toBeNull();
    }

    const getter = vi.fn(() => H);
    const accessor = capturedAdapterSource(async () => completion());
    Object.defineProperty(accessor, "executor_profile_hash", { enumerable: true, get: getter });
    const nullPrototype = Object.assign(Object.create(null) as object, exact);
    class Executor {
      readonly invoke = exact.invoke;
      readonly executor_profile_hash = exact.executor_profile_hash;
      readonly adapter_ref = exact.adapter_ref;
      readonly adapter_version_hash = exact.adapter_version_hash;
      readonly eligible_adapter_evidence_hash = exact.eligible_adapter_evidence_hash;
      readonly bypass_evidence_hash = exact.bypass_evidence_hash;
    }
    const withSymbol = { ...exact, [Symbol("ambient")]: true };

    expect(captureBrokeredModelExecutorAdapterV01(accessor)).toBeNull();
    expect(getter).not.toHaveBeenCalled();
    expect(captureBrokeredModelExecutorAdapterV01({ ...exact, extra: true })).toBeNull();
    expect(captureBrokeredModelExecutorAdapterV01(nullPrototype)).toBeNull();
    expect(captureBrokeredModelExecutorAdapterV01(new Executor())).toBeNull();
    expect(captureBrokeredModelExecutorAdapterV01(withSymbol)).toBeNull();
    expect(captureBrokeredModelExecutorAdapterV01(async () => completion())).toBeNull();
  });

  it.each([
    ["executor profile", "executor_profile_hash", "sha256:invalid"],
    ["adapter reference", "adapter_ref", "not-kebab-or-machine"],
    ["adapter version", "adapter_version_hash", null],
    ["eligible-adapter evidence", "eligible_adapter_evidence_hash", HB.slice(0, -1)],
    ["bypass evidence", "bypass_evidence_hash", `${HB}0`],
  ])("rejects an invalid %s identity value", (_label, field, value) => {
    const source: Record<string, unknown> = capturedAdapterSource(async () => completion());
    source[field] = value;

    expect(captureBrokeredModelExecutorAdapterV01(source)).toBeNull();
  });

  it("accepts an exact frozen plain identity descriptor", async () => {
    const source = Object.freeze(capturedAdapterSource(async () => completion()));
    const adapter = captureBrokeredModelExecutorAdapterV01(source);

    expect(adapter).not.toBeNull();
    await expect(runCapturedBrokeredModelExecutorV01(context(), adapter!, CAPTURED_ADAPTER_IDENTITY))
      .resolves.toMatchObject({ ok: true });
  });

  it.each([
    ["executor profile", "executor_profile_hash", HB],
    ["adapter reference", "adapter_ref", "model_adapter_s40_other_v01"],
    ["adapter version", "adapter_version_hash", HB],
    ["eligible-adapter evidence", "eligible_adapter_evidence_hash", HB],
    ["bypass evidence", "bypass_evidence_hash", HB],
  ])("rejects an expected %s mismatch before invoking the captured adapter", async (_label, field, value) => {
    const invoke = vi.fn(async () => completion());
    const adapter = captureBrokeredModelExecutorAdapterV01(capturedAdapterSource(invoke));
    expect(adapter).not.toBeNull();

    await expect(runCapturedBrokeredModelExecutorV01(
      context(),
      adapter!,
      { ...CAPTURED_ADAPTER_IDENTITY, [field]: value },
    )).resolves.toEqual({ ok: false, error: "MODEL_ADAPTER_INVALID" });
    expect(invoke).not.toHaveBeenCalled();
  });

  it("fails closed on an accessor-bearing expected identity without invoking it", async () => {
    const invoke = vi.fn(async () => completion());
    const adapter = captureBrokeredModelExecutorAdapterV01(capturedAdapterSource(invoke));
    const getter = vi.fn(() => H);
    const expectedIdentity = { ...CAPTURED_ADAPTER_IDENTITY };
    Object.defineProperty(expectedIdentity, "executor_profile_hash", { enumerable: true, get: getter });

    await expect(runCapturedBrokeredModelExecutorV01(context(), adapter!, expectedIdentity))
      .resolves.toEqual({ ok: false, error: "MODEL_ADAPTER_INVALID" });
    expect(getter).not.toHaveBeenCalled();
    expect(invoke).not.toHaveBeenCalled();
  });

  it("rejects an executor-profile mismatch before invoking the captured adapter", async () => {
    const invoke = vi.fn(async () => completion());
    const adapter = captureBrokeredModelExecutorAdapterV01(capturedAdapterSource(invoke));
    expect(adapter).not.toBeNull();

    await expect(runCapturedBrokeredModelExecutorV01(
      { ...context(), executor_profile_hash: HB },
      adapter!,
      CAPTURED_ADAPTER_IDENTITY,
    )).resolves.toEqual({ ok: false, error: "MODEL_ADAPTER_INVALID" });
    expect(invoke).not.toHaveBeenCalled();
  });

  it("fails closed for a revoked proxy descriptor source", () => {
    const { proxy, revoke } = Proxy.revocable(capturedAdapterSource(async () => completion()), {});
    revoke();

    expect(captureBrokeredModelExecutorAdapterV01(proxy)).toBeNull();
  });

  it("keeps captured and synthetic capabilities mutually unforgeable", async () => {
    const captured = captureBrokeredModelExecutorAdapterV01(capturedAdapterSource(async () => completion()));
    const synthetic = createSyntheticBrokeredModelExecutorAdapterV01ForTest(async () => completion());
    expect(captured).not.toBeNull();

    await expect(runCapturedBrokeredModelExecutorV01(
      context(),
      synthetic as unknown as CapturedBrokeredModelExecutorAdapterV01,
      CAPTURED_ADAPTER_IDENTITY,
    )).resolves.toEqual({ ok: false, error: "MODEL_ADAPTER_INVALID" });
    await expect(runBrokeredModelExecutorV01(
      context(),
      captured as unknown as SyntheticBrokeredModelExecutorAdapterV01,
    )).resolves.toEqual({ ok: false, error: "MODEL_ADAPTER_INVALID" });
  });

  it("applies the existing response-reference checks to captured executors", async () => {
    const adapter = captureBrokeredModelExecutorAdapterV01({
      invoke: async () => ({ ...completion(), evidence_refs: ["evidence-unregistered"] }),
      ...CAPTURED_ADAPTER_IDENTITY,
    });
    expect(adapter).not.toBeNull();

    await expect(runCapturedBrokeredModelExecutorV01(context(), adapter!, CAPTURED_ADAPTER_IDENTITY))
      .resolves.toEqual({ ok: false, error: "MODEL_RESPONSE_INVALID" });
  });
});
