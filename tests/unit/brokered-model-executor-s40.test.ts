import { describe, expect, it, vi } from "vitest";

import {
  createSyntheticBrokeredModelExecutorAdapterV01ForTest,
  runBrokeredModelExecutorV01,
} from "../../src/run/brokered-model-executor-v01.js";
import { hashBytes } from "../../src/hash.js";

const H = `sha256:${"a".repeat(64)}`;

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
