export type Severity = "benign" | "suspicious" | "overtly_malicious";

export type ConfidenceTier = "signature_certain" | "pattern_inferred" | "context_dependent";

export type DetectedFormat = "pyc" | "pickle" | "wasm" | "unknown";

export interface ErrorResult {
  readonly ok: false;
  readonly error: string;
}

export type Outcome<T> = T | ErrorResult;

export interface FormatResult {
  readonly ok: true;
  readonly format: "formatted-source";
  readonly language: "js" | "jsx" | "ts" | "tsx";
  readonly source: string;
}

export interface BundleModule {
  readonly id: string;
  readonly chunk_id: string | null;
  readonly source: string;
}

export type BundleResult = { readonly ok: true; readonly format: "javascript-bundle" } & (
  | { readonly state: "unrecognized" }
  | {
      readonly state: "recognized";
      readonly bundler: string;
      readonly markers: readonly string[];
      readonly modules: readonly BundleModule[];
    }
);

export interface SourceMapFile {
  readonly path: string;
  readonly source: string;
  readonly ignored: boolean;
}

export type SourceMapResult = { readonly ok: true; readonly format: "source-map" } & (
  | { readonly state: "no-map" }
  | { readonly state: "external-reference"; readonly url: string }
  | {
      readonly state: "recovered";
      readonly generated_file: string | null;
      readonly source_root: string | null;
      readonly total_sources: number;
      readonly embedded_sources: number;
      readonly missing_sources: readonly string[];
      readonly mapped_segments: number;
      readonly names: readonly string[];
      readonly files: readonly SourceMapFile[];
    }
);

export type GoAddress = `0x${string}`;

export interface GoFunction {
  readonly name: string;
  readonly entry: GoAddress;
  readonly end: GoAddress;
  readonly address: GoAddress | null;
  readonly file: string | null;
  readonly start_line: number | null;
  readonly linker_symbol: string | null;
  readonly abi0: boolean;
}

export interface GoModule {
  readonly path: string;
  readonly version: string;
  readonly sum?: string;
  readonly replace?: GoModule;
}

export interface GoBuildInfo {
  readonly go_version?: string;
  readonly path?: string;
  readonly main?: GoModule;
  readonly deps?: readonly GoModule[];
  readonly settings?: Readonly<Record<string, string>>;
}

export interface GoType {
  readonly address: GoAddress;
  readonly name: string | null;
  readonly kind: number | null;
  readonly kind_label: string | null;
  readonly fields_rejected: boolean;
  readonly interface_methods_rejected: boolean;
  readonly fields: readonly {
    readonly name: string;
    readonly type_address: GoAddress;
    readonly type_name: string;
    readonly kind: number;
    readonly kind_label: string;
    readonly offset: GoAddress;
    readonly tag: string | null;
    readonly embedded: boolean;
    readonly exported: boolean;
  }[];
  readonly methods: readonly {
    readonly name: string | null;
    readonly address: GoAddress;
    readonly linker_name: string | null;
    readonly exported: boolean;
  }[];
  readonly interface_methods: readonly {
    readonly name: string | null;
    readonly signature: string | null;
    readonly type_address: GoAddress;
    readonly exported: boolean;
  }[];
}

export interface GoResult {
  readonly ok: true;
  readonly format: "go";
  readonly container: "ELF" | "PE" | "Mach-O";
  readonly pointer_width: 32 | 64;
  readonly build_info: GoBuildInfo | null;
  readonly symbols: {
    readonly version: string;
    readonly functions: readonly GoFunction[];
    readonly source_files: readonly string[];
    readonly packages: readonly string[];
  } | null;
  readonly types: {
    readonly types: readonly GoType[];
    readonly interfaces: readonly {
      readonly address: GoAddress;
      readonly interface_name: string | null;
      readonly concrete_name: string | null;
      readonly unimplemented: boolean;
      readonly functions: readonly {
        readonly index: number;
        readonly address: GoAddress;
        readonly method_name: string | null;
        readonly linker_name: string | null;
      }[];
    }[];
    readonly strings: readonly string[];
    readonly generics: readonly {
      readonly full: string;
      readonly base: string;
      readonly type_args: readonly string[];
      readonly shape_args: boolean;
      readonly from_function: boolean;
      readonly concrete_candidates?: readonly (readonly string[])[];
    }[];
    readonly traversal_limit_reached: boolean;
  } | null;
  readonly module: {
    readonly source: "SymbolRuntimeFirstmoduledata" | "PclntabBacksearch" | "None";
    readonly pclntab: GoAddress;
    readonly type_links: GoAddress;
    readonly type_links_count: number;
    readonly interface_links: GoAddress;
    readonly interface_links_count: number;
    readonly types_start: GoAddress;
    readonly types_end: GoAddress;
    readonly text_start: GoAddress;
    readonly text_end: GoAddress;
    readonly name: string | null;
    readonly build_version: string | null;
  } | null;
}

export interface PharArtifact {
  readonly ok: true;
  readonly bytes: ArrayBuffer;
}

export interface PharMember {
  readonly index: number;
  readonly extractable: boolean;
  readonly name: string;
  readonly uncompressed_size: number;
  readonly stored_size: number;
  readonly timestamp: number;
  readonly crc32: number;
  readonly flags: number;
  readonly compression: "None" | "Deflate" | "Bzip2";
  readonly data_offset: number;
}

export interface PharResult {
  readonly ok: true;
  readonly format: "phar";
  readonly api_version: number;
  readonly global_flags: number;
  readonly metadata_bytes: number;
  readonly member_limit_bytes: number;
  readonly entries: readonly PharMember[];
}

export interface DetectResult {
  readonly ok: true;
  readonly format: DetectedFormat;
  readonly detail: string;
  readonly suggested_command: string;
}

export interface RouteCandidate {
  readonly ecosystem: string;
  readonly mode: string;
  readonly detail: string;
}

export interface AutoRouteResult {
  readonly ok: true;
  readonly format: "any";
  readonly byte_len: number;
  readonly primary: RouteCandidate | null;
  readonly candidates: readonly RouteCandidate[];
}

export interface PyInstruction {
  readonly offset: number;
  readonly opcode: number;
  readonly opname: string;
  readonly arg: number | null;
  readonly argrepr: string | null;
  readonly line: number | null;
  readonly is_jump_target: boolean;
}

export interface PyDisasmResult {
  readonly ok: true;
  readonly format: "pyc";
  readonly python_version: string;
  readonly instruction_count: number;
  readonly instructions: readonly PyInstruction[];
  readonly listing: string;
}

export interface PyDecompileResult {
  readonly ok: true;
  readonly format: "pyc";
  readonly python_version: string;
  readonly recovered_directly: boolean;
  readonly fallback_reason: string | null;
  readonly source: string;
}

export interface PyarmorModuleMetadata {
  readonly ok: true;
  readonly format: "pyarmor-module";
  readonly runtime_format: "8" | "9";
  readonly python_version: string;
  readonly runtime_arch: string;
  readonly marshal_offset: number;
  readonly code_objects: number;
  readonly names: readonly string[];
  readonly strings: readonly string[];
}

export interface PyarmorModuleResult extends PyarmorModuleMetadata {
  readonly bytes: ArrayBuffer;
}

export interface PyarmorDetectionView {
  readonly version: string;
  readonly protection: string;
  readonly confidence: string;
  readonly serial: string | null;
  readonly python_version: string | null;
  readonly pyc_magic: number | null;
  readonly has_iv: boolean;
  readonly diagnostics: readonly string[];
}

export interface PyarmorDetectResult {
  readonly ok: true;
  readonly format: "pyarmor";
  readonly detection: PyarmorDetectionView;
  readonly payload_len: number;
}

export interface ModeClassification {
  readonly script_type: string;
  readonly bootstrap_import: string;
  readonly rft_enabled: boolean;
  readonly ecc_enabled: boolean;
  readonly mix_str_enabled: boolean;
  readonly disposition: string;
  readonly min_format_version: string;
  readonly markers: readonly string[];
  readonly notes: readonly string[];
}

export interface PyarmorClassifyResult {
  readonly ok: true;
  readonly format: "pyarmor";
  readonly detection: PyarmorDetectionView;
  readonly classification: ModeClassification;
}

export interface PickleInsn {
  readonly offset: number;
  readonly opcode: number;
  readonly name: string;
  readonly effect: string;
  readonly proto: number;
  readonly arg: unknown;
}

export interface PickleDisassembly {
  readonly protocol: number;
  readonly instructions: readonly PickleInsn[];
  readonly frame_count: number;
  readonly stop_offset: number | null;
}

export interface PickleDisasmResult {
  readonly ok: true;
  readonly format: "pickle";
  readonly protocol: number;
  readonly opcode_count: number;
  readonly disassembly: PickleDisassembly;
  readonly listing: string;
}

export interface PickleFinding {
  readonly severity: Severity;
  readonly confidence: ConfidenceTier;
  readonly category: string;
  readonly detail: string;
  readonly offset: number | null;
}

export interface SafetyReport {
  readonly severity: Severity;
  readonly findings: readonly PickleFinding[];
  readonly imports: readonly string[];
  readonly reduce_count: number;
  readonly unused_memo_count: number;
}

export interface PickleSafetyResult {
  readonly ok: true;
  readonly format: "pickle";
  readonly protocol: number;
  readonly severity: Severity;
  readonly finding_count: number;
  readonly report: SafetyReport;
}

export interface PickleDecompileResult {
  readonly ok: true;
  readonly format: "pickle";
  readonly protocol: number;
  readonly reduce_count: number;
  readonly source: string;
  readonly assignment: string;
}

export interface PickleTraceResult {
  readonly ok: true;
  readonly format: "pickle";
  readonly protocol: number;
  readonly memo_count: number;
  readonly max_stack_depth: number;
  readonly reduce_count: number;
  readonly result: unknown;
  readonly trace: unknown;
}

export interface PolyglotReport {
  readonly is_pickle: boolean;
  readonly kinds: readonly string[];
  readonly is_polyglot: boolean;
  readonly notes: readonly string[];
}

export interface PicklePolyglotResult {
  readonly ok: true;
  readonly format: "pickle";
  readonly report: PolyglotReport;
}

export interface WasmDetection {
  readonly obfuscator: string;
  readonly confidence: number;
  readonly markers: readonly string[];
  readonly has_name_section: boolean;
  readonly has_dwarf: boolean;
  readonly function_count: number;
  readonly export_count: number;
  readonly import_count: number;
}

export interface WasmNameInfo {
  readonly module_name: string | null;
  readonly function_count: number;
  readonly function_names: readonly (readonly [number, string])[];
}

export interface WasmModuleSummary {
  readonly imports: readonly string[];
  readonly exports: readonly string[];
  readonly names: WasmNameInfo;
  readonly type_count: number;
  readonly func_count: number;
  readonly table_count: number;
  readonly memory_count: number;
  readonly global_count: number;
  readonly data_segments: number;
  readonly element_segments: number;
  readonly code_size_bytes: number;
  readonly has_dwarf: boolean;
  readonly dwarf_section_count: number;
}

export interface WasmAnalyzeResult {
  readonly ok: true;
  readonly format: "wasm";
  readonly detection: WasmDetection;
  readonly summary: WasmModuleSummary;
}

export interface WasmDetectResult {
  readonly ok: true;
  readonly format: "wasm";
  readonly detection: WasmDetection;
}

export interface WasmWatResult {
  readonly ok: true;
  readonly format: "wasm";
  readonly variant: "structured" | "faithful";
  readonly function_count: number;
  readonly wat: string;
}

export interface WasmHighLevelResult {
  readonly ok: true;
  readonly format: "wasm";
  readonly target: "rust" | "typescript" | "c";
  readonly function_count: number;
  readonly source: string;
}

export interface WasmCfgFunction {
  readonly function_index: number;
  readonly block_count: number;
  readonly edge_count: number;
  readonly entry: number;
  readonly cfg: unknown;
}

export interface WasmCfgResult {
  readonly ok: true;
  readonly format: "wasm";
  readonly function_count: number;
  readonly functions: readonly WasmCfgFunction[];
}

export interface WasmGcTypesResult {
  readonly ok: true;
  readonly format: "wasm";
  readonly struct_count: number;
  readonly array_count: number;
  readonly abstract_ref_count: number;
  readonly graph: unknown;
  readonly hir: {
    readonly rust_source: string;
    readonly ts_source: string;
    readonly [key: string]: unknown;
  };
}

export interface WasmEhResult {
  readonly ok: true;
  readonly format: "wasm";
  readonly uses_exception_handling: boolean;
  readonly uses_legacy_eh: boolean;
  readonly uses_modern_eh: boolean;
  readonly tag_section_count: number;
  readonly function_count: number;
  readonly summary: unknown;
}

export interface WasmComponentResult {
  readonly ok: true;
  readonly format: "wasm";
  readonly classification: string;
  readonly world_import_count: number;
  readonly world_export_count: number;
  readonly embedded_module_count: number;
  readonly embedded_component_count: number;
  readonly adapter_func_count: number;
  readonly manifest: unknown;
  readonly bindings: {
    readonly world_name: string;
    readonly rust_source: string;
    readonly ts_source: string;
    readonly wit_source: string;
    readonly [key: string]: unknown;
  };
}

export interface WasmMemoryRecord {
  readonly index: number;
  readonly memory64: boolean;
  readonly shared: boolean;
  readonly initial: number;
  readonly maximum: number | null;
  readonly page_size_log2: number | null;
}

export interface WasmMemoriesResult {
  readonly ok: true;
  readonly format: "wasm";
  readonly memory_count: number;
  readonly report: {
    readonly memories: Readonly<Record<string, WasmMemoryRecord>>;
    readonly uses_memory64: boolean;
    readonly multi_memory: boolean;
  };
}

export interface WasmFunctionSig {
  readonly name: string;
  readonly exported: boolean;
  readonly imported: boolean;
  readonly [key: string]: unknown;
}

export type BoundaryLinkCollectionStatus =
  | { readonly status: "complete" }
  | { readonly status: "truncated"; readonly link_count: number; readonly retained_link_count: number };

export interface WasmSignaturesResult {
  readonly ok: true;
  readonly format: "wasm";
  readonly imported_function_count: number;
  readonly defined_function_count: number;
  readonly defined: readonly WasmFunctionSig[];
  readonly export_aliases: readonly unknown[];
  readonly boundary_link_collection_status: BoundaryLinkCollectionStatus;
  readonly summary: WasmModuleSummary;
  readonly recovery: Readonly<Record<string, unknown>>;
  readonly recovered_byte_len: number;
}

export interface WasmPreludesResult {
  readonly ok: true;
  readonly format: "wasm";
  readonly rust: string;
  readonly c: string;
  readonly typescript: string;
}

export interface WasmSourceMapResult {
  readonly ok: true;
  readonly format: "wasm";
  readonly version: number;
  readonly source_count: number;
  readonly name_count: number;
  readonly segment_count: number;
  readonly source_map: unknown;
}

export interface LuaObfuscatorDetection {
  readonly kind: string;
  readonly confidence: number;
}

export interface LuaDetectResult {
  readonly ok: true;
  readonly format: "lua";
  readonly dialect: string;
  readonly obfuscator: LuaObfuscatorDetection | null;
}

export interface LuaDecompiledChunk {
  readonly source: string;
  readonly fidelity: string;
  readonly warnings: readonly string[];
}

export interface LuaDecompileResult {
  readonly ok: true;
  readonly format: "lua";
  readonly dialect: string;
  readonly fidelity: string;
  readonly warning_count: number;
  readonly chunk: LuaDecompiledChunk;
}

export type YarvOperand =
  | { readonly kind: "literal" | "str-literal" | "sym-literal" | "num-literal" | "id" | "builtin"; readonly value: string }
  | { readonly kind: "object-ref" | "iseq-ref" | "offset" | "num"; readonly value: number }
  | { readonly kind: "call"; readonly value: { readonly method: string; readonly argc: number; readonly flags: number } };

export interface YarvAnalysis {
  readonly version: { readonly major: number; readonly minor: number };
  readonly decompiled: {
    readonly source: string;
    readonly statement_count: number;
    readonly fidelity: "lossy" | "structural-only" | "literal-pool-only";
  };
  readonly ibf: {
    readonly iseq_offsets: readonly number[];
    readonly recovered_literal_count: number;
    readonly recovered_instruction_count: number;
    readonly iseqs: readonly {
      readonly index: number;
      readonly instructions: readonly {
        readonly pc: number;
        readonly mnemonic: string;
        readonly operands: readonly YarvOperand[];
      }[];
    }[];
  };
}

export interface MrubyAnalysis {
  readonly decompiled: {
    readonly source: string;
    readonly irep_count: number;
    readonly instruction_count: number;
    readonly has_body: boolean;
    readonly modeled_opcodes: number;
    readonly unmodeled_opcodes: number;
    readonly lifted_opcodes: number;
  };
}

export interface ApkManifest {
  readonly package: string;
  readonly version_name: string | null;
  readonly version_code: string | null;
  readonly min_sdk_version: string | null;
  readonly target_sdk_version: string | null;
  readonly permissions: readonly string[];
}

export interface KernelSource {
  readonly uri: string;
  readonly text: string;
}

export interface KernelProcedure {
  readonly name: string;
  readonly kind: "method" | "getter" | "setter" | "operator" | "factory" | "unknown";
  readonly is_private: boolean;
  readonly is_abstract: boolean;
  readonly start_offset: number;
  readonly end_offset: number;
  readonly recovered_source: string | null;
}

export interface DartKernelResult {
  readonly ok: true;
  readonly format: "dart-kernel";
  readonly kernel: {
    readonly format_version: number;
    readonly string_count: number;
    readonly sources: readonly KernelSource[];
    readonly libraries: readonly {
      readonly name: string | null;
      readonly import_uri: string | null;
      readonly file_uri: string | null;
      readonly procedures: readonly KernelProcedure[];
      readonly classes: readonly {
        readonly name: string;
        readonly is_abstract: boolean;
        readonly fields: readonly string[];
        readonly procedures: readonly KernelProcedure[];
        readonly recovered_source: string | null;
      }[];
    }[];
    readonly class_count: number;
    readonly procedure_count: number;
    readonly field_count: number;
    readonly bodies_recovered: number;
  };
}

export interface ApkResult {
  readonly ok: true;
  readonly format: "apk";
  readonly entry_count: number;
  readonly decoded_bytes: number;
  readonly resource_xml_entries: number;
  readonly resource_table_status: "missing" | "decoded" | "undecoded";
  readonly report: {
    readonly manifest: ApkManifest;
    readonly manifest_xml: string;
    readonly resources_decoded: {
      readonly decoded_xml: readonly { readonly path: string; readonly xml: string }[];
      readonly values_files: readonly { readonly virtual_path: string; readonly config: string; readonly xml: string }[];
    };
    readonly native_libraries: readonly { readonly container_path: string; readonly abi: string | null; readonly size: number; readonly is_elf: boolean }[];
    readonly abis: readonly string[];
    readonly signing: {
      readonly signing_block_present: boolean;
      readonly schemes: readonly { readonly scheme: "v2" | "v3" | "v3-1" }[];
    };
  };
}

export interface RubyDetectResult {
  readonly ok: true;
  readonly format: "ruby";
  readonly analysis: {
    readonly flavor: string;
    readonly source_path: string;
    readonly input_len: number;
    readonly yarv: YarvAnalysis | null;
    readonly mruby: MrubyAnalysis | null;
  };
}

export interface PhpDetection {
  readonly kind: string;
  readonly confidence: string;
  readonly open_tag_offset: number | null;
  readonly has_halt_compiler: boolean;
}

export interface PhpRecoveryReport {
  readonly stage: string;
  readonly php_kind: string;
  readonly encoder: string | null;
  readonly key_provenance: string | null;
  readonly output: string;
  readonly residual_ciphertext_len: number;
  readonly notes: readonly string[];
  readonly [key: string]: unknown;
}

export interface PhpDetectResult {
  readonly ok: true;
  readonly format: "php";
  readonly detection: PhpDetection;
  readonly recovery: PhpRecoveryReport;
}

export interface StringTaggingPlain {
  readonly Plain?: { readonly wide: boolean };
}

export interface ExtractedString {
  readonly value: string;
  readonly offset: number;
  readonly [key: string]: unknown;
}

export interface StringsReport {
  readonly schema: string;
  readonly uri?: string;
  readonly byte_len: number;
  readonly min_len: number;
  readonly total: number;
  readonly strings: readonly ExtractedString[];
}

export interface StringsResult {
  readonly ok: true;
  readonly format: "any";
  readonly report: StringsReport;
}

export interface Indicator {
  readonly kind: string;
  readonly value: string;
  readonly offset: number;
  readonly encoding: string;
  readonly context: string | null;
}

export interface IocReport {
  readonly schema: string;
  readonly uri?: string;
  readonly byte_len: number;
  readonly total: number;
  readonly indicators: readonly Indicator[];
}

export interface IocResult {
  readonly ok: true;
  readonly format: "any";
  readonly report: IocReport;
}

export interface BehaviorCategoryFinding {
  readonly category: string;
  readonly evidence: readonly unknown[];
  readonly [key: string]: unknown;
}

export interface BehaviorReport {
  readonly schema: string;
  readonly uri?: string;
  readonly byte_len: number;
  readonly categories: readonly BehaviorCategoryFinding[];
  readonly [key: string]: unknown;
}

export interface BehaviorResult {
  readonly ok: true;
  readonly format: "any";
  readonly report: BehaviorReport;
}

export interface SecretFinding {
  readonly kind: string;
  readonly severity: string;
  readonly [key: string]: unknown;
}

export interface SecretScanReport {
  readonly schema: string;
  readonly findings: readonly SecretFinding[];
  readonly [key: string]: unknown;
}

export interface SecretsResult {
  readonly ok: true;
  readonly format: "any";
  readonly report: SecretScanReport;
}

export interface AntiAnalysisFinding {
  readonly technique: string;
  readonly [key: string]: unknown;
}

export interface AntiAnalysisReport {
  readonly schema: string;
  readonly findings: readonly AntiAnalysisFinding[];
  readonly [key: string]: unknown;
}

export interface AntiAnalysisResult {
  readonly ok: true;
  readonly format: "any";
  readonly report: AntiAnalysisReport;
}

export interface YaraRule {
  readonly name: string;
  readonly condition: string;
  readonly [key: string]: unknown;
}

export interface GeneratedRule {
  readonly schema: string;
  readonly rule: YaraRule;
  readonly source: string;
  readonly [key: string]: unknown;
}

export interface YaraGenResult {
  readonly ok: true;
  readonly format: "any";
  readonly rule: GeneratedRule;
}

export interface EntropyBlock {
  readonly offset: number;
  readonly len: number;
  readonly entropy: number;
  readonly high: boolean;
}

export interface EntropyResult {
  readonly ok: true;
  readonly format: "any";
  readonly byte_len: number;
  readonly window: number;
  readonly overall: number;
  readonly high_block_count: number;
  readonly blocks: readonly EntropyBlock[];
}

export interface ElixirRecovery {
  readonly module: string;
  readonly backend: string;
  readonly module_doc: string | null;
  readonly source: string;
  readonly [key: string]: unknown;
}

export interface BeamResult {
  readonly ok: true;
  readonly format: "beam";
  readonly module: string;
  readonly recovered_from: string;
  readonly erlang_source: string;
  readonly elixir: ElixirRecovery | null;
}

export interface As3ObfuscationReport {
  readonly printable_string_ratio_percent: number;
  readonly identifier_mangle_ratio_percent: number;
  readonly control_flow_jump_density_percent: number;
  readonly register_shuffle_density_percent: number;
  readonly string_pool_rebuild_percent: number;
  readonly tools: readonly string[];
  readonly [key: string]: unknown;
}

export interface As3Result {
  readonly ok: true;
  readonly format: "as3";
  readonly method_body_count: number;
  readonly class_count: number;
  readonly obfuscation: As3ObfuscationReport;
  readonly program: string;
}

export interface ScriptLangResult {
  readonly ok: true;
  readonly format: "scriptlang";
  readonly classified: string | null;
  readonly artifact: {
    readonly lang: string;
    readonly [key: string]: unknown;
  };
}

export interface ShellDetection {
  readonly dialect: string;
  readonly family: string;
  readonly confidence: number;
  readonly markers: readonly string[];
}

export interface BatchDeobReport {
  readonly output: string;
  readonly for_loops_unrolled: number;
  readonly if_branches_folded: number;
  readonly commands_emulated: number;
  readonly embedded_payloads: readonly unknown[];
  readonly decrypted_stages: readonly unknown[];
  readonly [key: string]: unknown;
}

export interface ShellResult {
  readonly ok: true;
  readonly format: "shell";
  readonly detection: ShellDetection;
  readonly batch: BatchDeobReport;
}

export interface SwiftSliceReport {
  readonly cpu_label: string;
  readonly bitness_bits: number;
  readonly metadata_summary: {
    readonly objc_classes: number;
    readonly swift_nominal_types: number;
    readonly swift_protocols: number;
    readonly swift_demangled_symbols: number;
    readonly function_starts_recovered: number;
    readonly exported_symbols_recovered: number;
  };
  readonly swift: {
    readonly type_dump: {
      readonly nominal_types: readonly {
        readonly qualified_name: string;
        readonly kind: string;
        readonly fields: readonly { readonly name: string; readonly demangled_type: string | null; readonly mangled_type: string }[];
      }[];
      readonly protocols: readonly { readonly qualified_name: string }[];
    };
  };
  readonly objc: { readonly unique_selectors: readonly string[] };
}

export interface SwiftObjcReport {
  readonly container: string;
  readonly ipa: unknown;
  readonly fat_entries: readonly unknown[];
  readonly slices: readonly SwiftSliceReport[];
}

export interface SwiftObjcResult {
  readonly ok: true;
  readonly format: "swift-objc";
  readonly slice_count: number;
  readonly report: SwiftObjcReport;
}

export interface MobileChild {
  readonly name: string;
  readonly byte_len: number;
}

export interface HermesFunction {
  readonly index: number;
  readonly name: string;
  readonly source: string;
  readonly instruction_count: number;
  readonly reconstructed_ops: number;
  readonly fallback_ops: number;
  readonly unaccounted_ops: number;
}

export interface HermesResult {
  readonly ok: true;
  readonly format: "hermes";
  readonly header: { readonly version: number; readonly function_count: number; readonly string_count: number; readonly identifier_count: number };
  readonly string_table: readonly { readonly index: number; readonly kind: "string" | "identifier"; readonly value: string }[];
  readonly report: {
    readonly lift_supported: boolean;
    readonly function_count: number;
    readonly functions_with_body: number;
    readonly total_reconstructed_ops: number;
    readonly total_fallback_ops: number;
    readonly total_unaccounted_ops: number;
    readonly functions: readonly HermesFunction[];
  };
  readonly disassembly: readonly { readonly index: number; readonly listing: string }[];
}

export interface MobileResult {
  readonly ok: true;
  readonly format: "mobile";
  readonly kind: string;
  readonly child_count: number;
  readonly children: readonly MobileChild[];
}

export type JvmOperands =
  | "None"
  | { readonly Byte: number } | { readonly Short: number } | { readonly Local: number }
  | { readonly Branch: number } | { readonly ConstPool: number }
  | { readonly Iinc: { readonly index: number; readonly delta: number } }
  | { readonly NewArray: number }
  | { readonly InvokeInterface: { readonly index: number; readonly count: number } }
  | { readonly InvokeDynamic: number }
  | { readonly MultiANewArray: { readonly index: number; readonly dimensions: number } }
  | { readonly TableSwitch: { readonly default: number; readonly low: number; readonly high: number; readonly offsets: readonly number[] } }
  | { readonly LookupSwitch: { readonly default: number; readonly pairs: readonly (readonly [number, number])[] } };

export interface JvmInstruction {
  readonly pc: number;
  readonly mnemonic: string;
  readonly operands: JvmOperands;
  readonly reference: string | null;
}

export type JvmMethodCode =
  | { readonly state: "absent" }
  | { readonly state: "invalid"; readonly error: string }
  | {
    readonly state: "available";
    readonly max_stack: number;
    readonly max_locals: number;
    readonly instructions: readonly JvmInstruction[];
    readonly exceptions: readonly { readonly start_pc: number; readonly end_pc: number; readonly handler_pc: number; readonly catch_type: number }[];
    readonly dropped_exceptions: number;
  };

export interface JvmMethod {
  readonly name: string;
  readonly descriptor: string;
  readonly access_flags: number;
  readonly code: JvmMethodCode;
}

export interface JvmClassResult {
  readonly ok: true;
  readonly format: "jvm-class";
  readonly name: string;
  readonly source_filename: string;
  readonly superclass: string | null;
  readonly interfaces: readonly string[];
  readonly major_version: number;
  readonly minor_version: number;
  readonly access_flags: number;
  readonly constant_pool_entries: number;
  readonly fields: readonly { readonly name: string; readonly descriptor: string; readonly access_flags: number }[];
  readonly methods: readonly JvmMethod[];
  readonly decompiled: {
    readonly source: string;
    readonly method_count: number;
    readonly field_count: number;
    readonly fully_lifted_methods: number;
    readonly fallback_methods: number;
    readonly decode_error_count: number;
  };
}

export interface DotnetMethod {
  readonly token: number;
  readonly name: string;
  readonly flags: number;
  readonly impl_flags: number;
  readonly rva: number;
  readonly parameters: readonly { readonly sequence: number; readonly name: string }[];
}

export interface DotnetType {
  readonly token: number;
  readonly namespace: string;
  readonly name: string;
  readonly full_name: string;
  readonly flags: number;
  readonly base_type: string | null;
  readonly fields: readonly { readonly token: number; readonly name: string; readonly flags: number }[];
  readonly methods: readonly DotnetMethod[];
}

export type DotnetMethodCode =
  | { readonly state: "absent" }
  | { readonly state: "invalid"; readonly error: string }
  | {
    readonly state: "available";
    readonly max_stack: number;
    readonly code_size: number;
    readonly local_signature_token: number;
    readonly init_locals: boolean;
    readonly instructions: readonly { readonly offset: number; readonly name: string; readonly operand: string; readonly reference: string | null }[];
    readonly exceptions: readonly { readonly kind: "Catch" | "Filter" | "Finally" | "Fault"; readonly try_offset: number; readonly try_length: number; readonly handler_offset: number; readonly handler_length: number; readonly class_token_or_filter: number }[];
  };

export interface DotnetSource {
  readonly module_name: string;
  readonly methods_decompiled: number;
  readonly methods_bodyless: number;
  readonly methods_failed: number;
  readonly methods: readonly {
    readonly token: number;
    readonly signature: string;
    readonly body: string;
    readonly statement_count: number;
    readonly recovered_locals: number;
    readonly recovered_branches: number;
    readonly typed_locals: number;
    readonly named_params: number;
  }[];
}

export interface DotnetResult {
  readonly ok: true;
  readonly format: "dotnet";
  readonly bitness: "Pe32" | "Pe32Plus";
  readonly runtime: string;
  readonly model: {
    readonly module_name: string;
    readonly assembly_name: string | null;
    readonly types: readonly DotnetType[];
    readonly method_count: number;
    readonly field_count: number;
    readonly type_count: number;
  };
  readonly bytecode: readonly { readonly token: number; readonly code: DotnetMethodCode }[];
  readonly csharp: DotnetSource;
  readonly fsharp: DotnetSource;
  readonly vbnet: DotnetSource;
}
