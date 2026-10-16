/**
 * The S35 package root keeps this baseline name for source compatibility, but
 * caller-authored structural objects never carry compiler write authority.
 * Product compilation persists through the private V02 coordinator instead.
 */
export function writeCompilePack(_result: unknown, _targetDir: string): never {
  throw new TypeError("writeCompilePack requires package-private compiler authority; structural caller input is not accepted.");
}
