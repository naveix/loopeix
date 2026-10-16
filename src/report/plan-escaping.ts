/**
 * Encode untrusted planned-report text as Markdown-inert ASCII.
 * Only the contract allowlist remains literal; every other UTF-16 code unit is
 * rendered as a lowercase, four-digit `\\uXXXX` escape.
 */
export function encodePlanReportMarkdownLiteralV02(input: string): string {
  let encoded = "";
  for (let index = 0; index < input.length; index += 1) {
    const unit = input.charCodeAt(index);
    const allowed = (unit >= 0x41 && unit <= 0x5a)
      || (unit >= 0x61 && unit <= 0x7a)
      || (unit >= 0x30 && unit <= 0x39)
      || unit === 0x20
      || unit === 0x2e
      || unit === 0x2c
      || unit === 0x3a
      || unit === 0x3b
      || unit === 0x2f
      || unit === 0x5f
      || unit === 0x2d;
    encoded += allowed ? input[index]! : `\\u${unit.toString(16).padStart(4, "0")}`;
  }
  return encoded;
}

/** Escape an untrusted value for insertion into an HTML text node. */
export function escapePlanReportHtmlTextV02(input: string): string {
  return input
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
