export interface PyarmorDetection {
  confidence: "low" | "medium" | "high";
  diagnostics?: Array<string>;
  protection: "standard" | "super-mode" | "bcc" | "no-wrap";
  serial?: null | string;
  version: "v3" | "v4" | "v5" | "v6" | "v7" | "v8" | "v9";
}
