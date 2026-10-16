export const CREDENTIAL_RULE_IDS_V02 = [
  "CRED_PRIVATE_KEY_PEM",
  "CRED_AWS_ACCESS_KEY_ID",
  "CRED_GITHUB_TOKEN",
  "CRED_ANTHROPIC_API_KEY",
  "CRED_OPENAI_API_KEY",
  "CRED_SLACK_TOKEN",
  "CRED_GOOGLE_API_KEY",
  "CRED_COMPOSIO_CONSUMER_KEY",
  "CRED_URI_USERINFO",
  "CRED_ASSIGNMENT",
] as const;

export type CredentialRuleIdV02 = (typeof CREDENTIAL_RULE_IDS_V02)[number];

type CredentialRuleV02 = Readonly<{
  rule_id: CredentialRuleIdV02;
  pattern: RegExp;
}>;

const CREDENTIAL_RULES_V02: readonly CredentialRuleV02[] = Object.freeze([
  { rule_id: "CRED_PRIVATE_KEY_PEM", pattern: /-----BEGIN [^-\r\n]*PRIVATE KEY-----/ },
  { rule_id: "CRED_AWS_ACCESS_KEY_ID", pattern: /(?:^|[^A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])/ },
  { rule_id: "CRED_GITHUB_TOKEN", pattern: /(?:^|[^A-Za-z0-9_])(?:gh[pousr]_|github_pat_)[A-Za-z0-9_-]{20,255}/ },
  { rule_id: "CRED_ANTHROPIC_API_KEY", pattern: /(?:^|[^A-Za-z0-9_])sk-ant-[A-Za-z0-9_-]{20,255}/ },
  { rule_id: "CRED_OPENAI_API_KEY", pattern: /(?:^|[^A-Za-z0-9_])(?:sk-proj-|sk-)(?!ant-)[A-Za-z0-9_-]{20,255}/ },
  { rule_id: "CRED_SLACK_TOKEN", pattern: /(?:^|[^A-Za-z0-9_])xox[bpars]-[A-Za-z0-9-]{10,255}/ },
  { rule_id: "CRED_GOOGLE_API_KEY", pattern: /(?:^|[^A-Za-z0-9_])AIza[A-Za-z0-9_-]{35}/ },
  { rule_id: "CRED_COMPOSIO_CONSUMER_KEY", pattern: /(?:^|[^A-Za-z0-9_])ck_[A-Za-z0-9_-]{20,255}/ },
]);

const ASSIGNMENT_SUFFIX_PATTERN = /(?:api_key|apikey|access_token|auth_token|client_secret|password|private_key)\s*[:=]\s*["']?[^\s"']{12,255}/gi;

function containsCredentialAssignment(value: string): boolean {
  ASSIGNMENT_SUFFIX_PATTERN.lastIndex = 0;
  for (;;) {
    const match = ASSIGNMENT_SUFFIX_PATTERN.exec(value);
    if (match === null) return false;
    let keyStart = match.index;
    while (keyStart > 0 && /[A-Za-z0-9_]/.test(value[keyStart - 1]!)) keyStart -= 1;
    if (keyStart === 0 || !/[A-Za-z0-9_]/.test(value[keyStart - 1]!)) return true;
  }
}

function containsUriUserinfo(value: string): boolean {
  let searchFrom = 0;
  for (;;) {
    const separator = value.indexOf("://", searchFrom);
    if (separator < 0) return false;
    let schemeStart = separator;
    while (schemeStart > 0 && /[A-Za-z0-9+.-]/.test(value[schemeStart - 1]!)) schemeStart -= 1;
    const scheme = value.slice(schemeStart, separator);
    if (/^[A-Za-z][A-Za-z0-9+.-]*$/.test(scheme)) {
      const authorityStart = separator + 3;
      const at = value.indexOf("@", authorityStart);
      if (at >= 0) {
        const authority = value.slice(authorityStart, at);
        const colon = authority.indexOf(":");
        if (colon > 0 && colon < authority.length - 1 && !/[\s/@]/.test(authority)) return true;
      }
    }
    searchFrom = separator + 3;
  }
}

export type CredentialDetectionV02 = Readonly<{ rule_id: CredentialRuleIdV02 }>;

export function detectCredentialV02(value: string): CredentialDetectionV02 | null {
  for (const rule of CREDENTIAL_RULES_V02) {
    if (rule.pattern.test(value)) return Object.freeze({ rule_id: rule.rule_id });
  }
  if (containsUriUserinfo(value)) return Object.freeze({ rule_id: "CRED_URI_USERINFO" });
  if (containsCredentialAssignment(value)) return Object.freeze({ rule_id: "CRED_ASSIGNMENT" });
  return null;
}
