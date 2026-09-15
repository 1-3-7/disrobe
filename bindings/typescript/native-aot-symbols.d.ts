export interface CodeRange {
  end_rva: number;
  start_rva: number;
}

export interface ManagedSignatureBody {
  pseudo_c: string;
  signature_source: "managed";
  status: "recovered";
}

export type MetadataStatus = "NotPresent" | "Recovered" | UnsupportedVersionStatus | RejectedStatus;

export type MethodBody = ManagedSignatureBody | RegisterSignatureBody | RefusedBody;

export interface MethodEntry {
  body?: MethodBody;
  code_range?: CodeRange;
  declaring_type: null | string;
  declaring_types: Array<string>;
  entrypoint_rva?: number;
  name: string;
  record_offset: number;
  signature: MethodSignature | null;
}

export interface MethodSignature {
  calling_convention: number;
  generic_parameter_count: number;
  parameter_types: Array<TypeSignature>;
  record_offset: number;
  return_type: TypeSignature;
  vararg_parameter_types: Array<TypeSignature>;
}

export interface RefusedBody {
  reason: string;
  status: "refused";
}

export interface RegisterSignatureBody {
  pseudo_c: string;
  signature_abstention: "absent-managed-signature" | "unsupported-calling-convention" | "explicit-this" | "generic-signature" | "vararg-signature" | "argument-positions-exceeded" | "type-signature-kind-unsupported" | "type-record-absent" | "type-namespace-not-system" | "type-outside-primitive-table" | "non-microsoft-x64-recovery" | "hidden-struct-return" | "return-class-disagreement" | "argument-count-disagreement" | "argument-register-disagreement" | "floating-point-register-disagreement" | "unobserved-argument-position" | "vector-argument-binding" | "prototype-not-isolated" | "argument-binding-not-isolated" | "return-statement-not-isolated" | "shared-code-range" | "allocation-failed";
  signature_source: "registers";
  status: "recovered";
}

export interface RejectedStatus {
  Rejected: Record<string, unknown>;
}

export interface SignatureSourceCounts {
  managed: number;
  registers: number;
}

export interface TypeEntry {
  method_record_offsets: Array<number>;
  qualified_name: string;
  record_offset: number;
}

export interface TypeSignature {
  kind: "definition" | "reference" | "specification" | "modified";
  record_offset: number;
}

export interface UnsupportedVersionStatus {
  UnsupportedVersion: Record<string, unknown>;
}

export interface NativeAotSymbols {
  metadata_status: MetadataStatus;
  methods: Array<MethodEntry>;
  runtime: "net7" | "net8" | "net9" | "net10" | "unknown";
  schema: "disrobe.dotnet.native-aot-symbols/v1";
  signature_source_counts: SignatureSourceCounts;
  types: Array<TypeEntry>;
}
