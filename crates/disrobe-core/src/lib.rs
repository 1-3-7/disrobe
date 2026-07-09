#![forbid(unsafe_code)]
pub mod anti_analysis;
pub mod anti_analysis_sigs;
pub mod artifact;
pub mod behavior;
pub mod byte_search;
#[cfg(feature = "cache")]
pub mod cache;
pub mod capability;
pub mod chain;
pub mod codec;
pub mod complexity;
pub mod debug;
pub mod dominators;
pub mod error;
pub mod format;
pub mod pass;
pub mod progress;
pub mod provenance;
pub mod provenance_map;
pub mod recon;
pub mod recovery;
pub mod rng;
pub mod rung;
pub mod strings;
pub mod subprocess;
pub mod time;
pub mod yara;
pub mod yara_gen;
pub mod yara_match;

pub use anti_analysis::{
    ANTI_ANALYSIS_SCHEMA, AntiAnalysisFinding, AntiAnalysisReport,
    ChainEvidence as AntiChainEvidence, DefeatStatus, FindingSeverity, Mechanism as AntiMechanism,
    TargetFamily as AntiTargetFamily, Technique as AntiTechnique,
    classify_family as classify_anti_family, scan as scan_anti_analysis,
    scan_with_chain as scan_anti_analysis_with_chain,
};
pub use artifact::Artifact;
pub use behavior::{
    BEHAVIOR_SCHEMA, BehaviorReport, Category as BehaviorCategory, CategoryFinding,
    Evidence as BehaviorEvidence, analyze as analyze_behavior,
    analyze_with_uri as analyze_behavior_with_uri,
};
#[cfg(feature = "cache")]
pub use cache::{CACHE_FORMAT_VERSION, Cache, CacheKey, CacheKeyBuilder, default_cache_dir};
pub use capability::{Capability, CapabilityKind};
pub use codec::{
    Base58Variant, CascadeHit, CascadeRecovery, CryptoWall, CryptoWallKind, DecodeError,
    Scheme as CodecScheme, StreamCipher, TeaVariant, ValidationReason,
    blind_cascade as codec_blind_cascade, cascade_or_wall as codec_cascade_or_wall,
    classify_crypto_wall, decode as codec_decode,
};
pub use complexity::{Cfg, FunctionComplexity, cyclomatic_complexity, from_decision_points};
pub use dominators::{AdjGraph, DiGraph, Dominators, dominator_sets, immediate_post_dominators};
pub use error::{CoreError, Result};
pub use format::{
    CClangFormatFormatter, CSharpDotnetFormatFormatter, CppClangFormatFormatter, DartFormatter,
    FormatConfig, FormatError, FormatterLanguage, GoGofmtFormatter, IdentityFormatter,
    JavaGoogleJavaFormatFormatter, JsPrettierFormatter, KotlinKtlintFormatter, LuaStyluaFormatter,
    ObjcClangFormatFormatter, PhpPhpcsFormatter, PythonRuffFormatter, RubyRubocopFormatter,
    RustRustfmtFormatter, ScalaScalafmtFormatter, SourceFormatter, SwiftSwiftFormatFormatter,
    TsPrettierFormatter, WatWasmFmtFormatter, current_config, format_or_passthrough, formatter_for,
    set_config,
};
pub use recon::{interop, ioc, malware_config, secret_scan};

pub use interop::{
    ArtifactSchema, INDICATORS_SCHEMA, IndicatorAggregator, IndicatorBundle, IndicatorClass,
    UnifiedIndicator, aggregate as interop_aggregate, identify_schema as interop_identify_schema,
};

pub use ioc::{
    Encoding as IocEncoding, IOC_SCHEMA, Indicator, IocKind, IocReport, defang as ioc_defang,
    extract as ioc_extract, extract_with_extra as ioc_extract_with_extra, report as ioc_report,
    report_with_extra as ioc_report_with_extra,
};
pub use pass::{Pass, PassId};
pub use progress::{CapturingProgress, NoopProgress, Progress, ProgressEvent};
pub use provenance::{
    CommentStyle, Language, PROVENANCE_JSON_KEY, PROVENANCE_SCHEMA, Protocol, ProvenanceHeader,
    REPO_URL, comment_prefix, header_for, pretty_duration,
};
pub use provenance_map::{
    LineProvenance, MAX_NOTE_LINES, PROVENANCE_MAP_SCHEMA, ProvenanceMap, ProvenanceMapBuilder,
    ProvenanceMapError,
};
pub use recon::{
    CustomPattern, RECON_SCHEMA, ReconCategory, ReconConfig, ReconError, ReconFinding, ReconReport,
    categories as recon_categories, fingerprint as recon_fingerprint,
    report_bytes as recon_report_bytes, report_tree as recon_report_tree,
    scan_bytes as recon_scan_bytes,
};
pub use recovery::{
    ConfidenceTier, PassRecovery, RECOVERY_SCHEMA, RecoveryReport, RecoverySignal, TierHistogram,
    assign_tier,
};
pub use rng::{SeededRng, os as rng_os, seeded as rng_seeded};
pub use rung::Rung;
pub use secret_scan::{
    Confidence, Finding, SCAN_SCHEMA, SecretKind, SecretScanReport, Severity, scan_bytes,
    scan_report, scan_strings, shannon_entropy, validate as secret_validate,
};
pub use strings::{
    DEFAULT_MIN_LEN as STRINGS_DEFAULT_MIN_LEN, ExtractedString, Options as StringsOptions,
    STRINGS_SCHEMA, StringsReport, Tagging as StringTagging, extract as strings_extract,
    report as strings_report,
};
pub use time::{now as time_now, now_secs as time_now_secs};
pub use yara::{
    Rule as YaraRule, YARA_SCHEMA, YaraLoaderReport, YaraParseError, YaraRuleset, YaraString,
    YaraStringKind, parse_report as parse_yara_report, parse_rule as parse_yara_rule,
    parse_ruleset as parse_yara_ruleset,
};
pub use yara_gen::{
    GenerateOptions as YaraGenerateOptions, GeneratedRule, YARA_GEN_SCHEMA, YaraGenError,
    generate as generate_yara_rule,
};
pub use yara_match::{
    CompiledRuleset, RuleMatch, ScanReport, StringMatch, UnevaluatedRule, YARA_MATCH_SCHEMA,
    YaraMatchError,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
