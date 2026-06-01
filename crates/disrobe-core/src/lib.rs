#![forbid(unsafe_code)]

pub mod artifact;
pub mod capability;
#[cfg(feature = "chain")]
pub mod chain;
pub mod error;
pub mod format;
pub mod pass;
pub mod progress;
pub mod provenance;
pub mod resolver;
pub mod rng;
pub mod rung;
pub mod secret_scan;
pub mod time;

pub use artifact::Artifact;
pub use capability::{Capability, CapabilityKind};
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
#[cfg(feature = "chain")]
pub use pass::Pass;
pub use pass::{LegacyPass, PassId, PassMetadata};
pub use progress::{CapturingProgress, NoopProgress, Progress, ProgressEvent};
pub use provenance::{
    CommentStyle, Language, PROVENANCE_JSON_KEY, PROVENANCE_SCHEMA, Protocol, ProvenanceHeader,
    REPO_URL, comment_prefix, header_for, pretty_duration,
};
pub use resolver::{
    CapabilityResolver, MigrationShim, MigrationShimRegistry, ShimStep, ShimTransform,
};
pub use rng::{SeededRng, os as rng_os, seeded as rng_seeded};
pub use rung::Rung;
pub use secret_scan::{
    Finding, SCAN_SCHEMA, SecretKind, SecretScanReport, Severity, scan_bytes, scan_report,
    scan_strings,
};
pub use time::{now as time_now, now_secs as time_now_secs};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
