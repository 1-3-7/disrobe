export type Severity = "benign" | "suspicious" | "overtly_malicious";

export type ConfidenceTier = "signature_certain" | "pattern_inferred" | "context_dependent";

export type DetectedFormat = "pyc" | "pickle" | "wasm" | "unknown";

export interface ErrorResult {
  readonly ok: false;
  readonly error: string;
}

export type Outcome<T> = T | ErrorResult;

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

export interface WasmSignaturesResult {
  readonly ok: true;
  readonly format: "wasm";
  readonly imported_function_count: number;
  readonly defined_function_count: number;
  readonly defined: readonly WasmFunctionSig[];
  readonly export_aliases: readonly unknown[];
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

export interface RubyDetectResult {
  readonly ok: true;
  readonly format: "ruby";
  readonly analysis: {
    readonly flavor: string;
    readonly source_path: string;
    readonly input_len: number;
    readonly [key: string]: unknown;
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
  readonly [key: string]: unknown;
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

export interface MobileResult {
  readonly ok: true;
  readonly format: "mobile";
  readonly kind: string;
  readonly child_count: number;
  readonly children: readonly MobileChild[];
}
