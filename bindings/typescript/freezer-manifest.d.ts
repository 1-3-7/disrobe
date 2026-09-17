export interface FreezerManifest {
  entries: Array<Record<string, unknown>>;
  entry_count: number;
  interpreter_hint?: null | string;
  kind: "cx-freeze" | "py2exe" | "bbfreeze" | "shiv" | "pex" | "zipapp" | "pyc" | "py-oxidizer" | "briefcase" | "unknown";
  module_inventory?: Array<Record<string, unknown>>;
  primary_module?: null | string;
  python_major?: null | number;
  python_minor?: null | number;
  schema: "disrobe.pyfreeze.manifest/v0";
  source_path: string;
}
