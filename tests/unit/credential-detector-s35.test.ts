import { describe, expect, it } from "vitest";

import {
  CREDENTIAL_RULE_IDS_V02,
  detectCredentialV02,
} from "../../src/security/credential-detector-v02.js";

const candidateByRule = {
  CRED_PRIVATE_KEY_PEM: ["-----", "BEGIN ", "SYNTHETIC ", "PRIVATE KEY", "-----"].join(""),
  CRED_AWS_ACCESS_KEY_ID: `AKIA${"A".repeat(16)}`,
  CRED_GITHUB_TOKEN: `ghp_${"a".repeat(20)}`,
  CRED_ANTHROPIC_API_KEY: `sk-ant-${"a".repeat(20)}`,
  CRED_OPENAI_API_KEY: `sk-proj-${"a".repeat(20)}`,
  CRED_SLACK_TOKEN: `xoxb-${"a".repeat(10)}`,
  CRED_GOOGLE_API_KEY: `AIza${"a".repeat(35)}`,
  CRED_COMPOSIO_CONSUMER_KEY: `ck_${"a".repeat(20)}`,
  CRED_URI_USERINFO: ["https", "://", "synthetic-user", ":", "synthetic-password", "@", "example.invalid/"].join(""),
  CRED_ASSIGNMENT: `client_secret=${"a".repeat(12)}`,
} as const;

describe("V02 deterministic credential detector", () => {
  it("classifies every closed rule without returning candidate-derived metadata", () => {
    expect(CREDENTIAL_RULE_IDS_V02).toEqual(Object.keys(candidateByRule));
    for (const ruleId of CREDENTIAL_RULE_IDS_V02) {
      const candidate = candidateByRule[ruleId];
      const result = detectCredentialV02(`prefix ${candidate} suffix`);
      expect(result).toEqual({ rule_id: ruleId });
      expect(JSON.stringify(result)).not.toContain(candidate);
    }
  });

  it("applies the specific Anthropic rule before the generic OpenAI namespace", () => {
    expect(detectCredentialV02(`sk-ant-${"z".repeat(20)}`)).toEqual({
      rule_id: "CRED_ANTHROPIC_API_KEY",
    });
  });

  it("honors frozen length and token boundaries", () => {
    for (const admitted of [
      `ghp_${"a".repeat(19)}`,
      `sk-ant-${"a".repeat(19)}`,
      `xoxb-${"a".repeat(9)}`,
      `AIza${"a".repeat(34)}`,
      `ck_${"a".repeat(19)}`,
      `XAKIA${"A".repeat(16)}Y`,
      `password=${"a".repeat(11)}`,
    ]) {
      expect(detectCredentialV02(admitted), admitted).toBeNull();
    }
  });

  it("reports only the first rule in canonical order", () => {
    const text = `${candidateByRule.CRED_OPENAI_API_KEY} ${candidateByRule.CRED_PRIVATE_KEY_PEM}`;
    expect(detectCredentialV02(text)).toEqual({ rule_id: "CRED_PRIVATE_KEY_PEM" });
  });
});
