import type { LoopCatalogEntry } from "./item.js";
import type { CatalogEntryV02 } from "./item-v02.js";
import { getFrozenLoopCatalogV01, V01_CATALOG_VERSION_HASH } from "../compiler/strategy-v01.js";
import {
  DEFAULT_CATALOG_SNAPSHOT_V02,
  S35_COMPILER_BUNDLE_ID_V02,
} from "./default-items.js";

export type FrozenCatalogLookupResultV01 =
  | { ok: true; schema_version: "0.1"; catalog_version_hash: string; entries: readonly LoopCatalogEntry[] }
  | { ok: false; reason: "UNAVAILABLE_REPLAY_BUNDLE"; message: string };

export function lookupFrozenCatalogV01(selector: {
  schema_version: string;
  catalog_version_hash: string;
}): FrozenCatalogLookupResultV01 {
  if (selector.schema_version !== "0.1" || selector.catalog_version_hash !== V01_CATALOG_VERSION_HASH) {
    return {
      ok: false,
      reason: "UNAVAILABLE_REPLAY_BUNDLE",
      message: "The exact V01 replay bundle is unavailable.",
    };
  }
  return {
    ok: true,
    schema_version: "0.1",
    catalog_version_hash: V01_CATALOG_VERSION_HASH,
    entries: getFrozenLoopCatalogV01(),
  };
}

export type RegisteredCatalogLookupResultV02 =
  | {
      ok: true;
      schema_version: "0.2";
      compiler_bundle_id: typeof S35_COMPILER_BUNDLE_ID_V02;
      catalog_version_hash: string;
      entries: readonly CatalogEntryV02[];
    }
  | { ok: false; reason: "UNAVAILABLE_COMPILER_BUNDLE"; message: string };

export function lookupRegisteredCatalogV02(selector: {
  schema_version: string;
  compiler_bundle_id: string;
  catalog_version_hash: string;
}): RegisteredCatalogLookupResultV02 {
  if (
    selector.schema_version !== "0.2" ||
    selector.compiler_bundle_id !== S35_COMPILER_BUNDLE_ID_V02 ||
    selector.catalog_version_hash !== DEFAULT_CATALOG_SNAPSHOT_V02.catalog_hash
  ) {
    return {
      ok: false,
      reason: "UNAVAILABLE_COMPILER_BUNDLE",
      message: "The exact V02 compiler bundle and catalog snapshot are unavailable.",
    };
  }
  return {
    ok: true,
    schema_version: "0.2",
    compiler_bundle_id: S35_COMPILER_BUNDLE_ID_V02,
    catalog_version_hash: DEFAULT_CATALOG_SNAPSHOT_V02.catalog_hash,
    entries: DEFAULT_CATALOG_SNAPSHOT_V02.entries,
  };
}
