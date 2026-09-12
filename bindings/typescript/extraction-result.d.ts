export interface ExtractionResult {
  encoding: Record<string, string>;
  entries: Array<Record<string, unknown>>;
  integrity_violations: Array<string>;
  kind: string;
  quota: Record<string, unknown>;
}
