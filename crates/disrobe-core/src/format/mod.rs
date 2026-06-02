use std::fmt::{self, Display, Formatter};
use std::sync::LazyLock;

mod c_clangformat;
mod cpp_clangformat;
mod csharp_dotnetformat;
mod dart_dart;
mod go_gofmt;
mod identity;
mod java_googlejavaformat;
mod js_prettier;
mod kotlin_ktlint;
mod lua_stylua;
mod objc_clangformat;
mod php_phpcs;
mod process;
mod python_ruff;
mod ruby_rubocop;
mod rust_rustfmt;
mod scala_scalafmt;
mod swift_swiftformat;
mod ts_prettier;
mod wat_wasmfmt;

pub use c_clangformat::CClangFormatFormatter;
pub use cpp_clangformat::CppClangFormatFormatter;
pub use csharp_dotnetformat::CSharpDotnetFormatFormatter;
pub use dart_dart::DartFormatter;
pub use go_gofmt::GoGofmtFormatter;
pub use identity::IdentityFormatter;
pub use java_googlejavaformat::JavaGoogleJavaFormatFormatter;
pub use js_prettier::JsPrettierFormatter;
pub use kotlin_ktlint::KotlinKtlintFormatter;
pub use lua_stylua::LuaStyluaFormatter;
pub use objc_clangformat::ObjcClangFormatFormatter;
pub use php_phpcs::PhpPhpcsFormatter;
pub use python_ruff::PythonRuffFormatter;
pub use ruby_rubocop::RubyRubocopFormatter;
pub use rust_rustfmt::RustRustfmtFormatter;
pub use scala_scalafmt::ScalaScalafmtFormatter;
pub use swift_swiftformat::SwiftSwiftFormatFormatter;
pub use ts_prettier::TsPrettierFormatter;
pub use wat_wasmfmt::WatWasmFmtFormatter;

#[doc(hidden)]
pub mod test_helpers {
    use super::FormatError;

    pub fn run_subprocess(
        binary: &'static str,
        args: &[&str],
        input: &str,
        timeout_secs: u32,
    ) -> Result<String, FormatError> {
        super::process::run_or_fail(binary, args, input, timeout_secs)
    }

    #[must_use]
    pub fn is_available(binary: &'static str) -> bool {
        super::process::tool_available(binary)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FormatterLanguage {
    Python,
    JavaScript,
    TypeScript,
    Rust,
    Go,
    C,
    Cpp,
    Dart,
    Lua,
    Php,
    Ruby,
    Java,
    Kotlin,
    Scala,
    CSharp,
    Swift,
    ObjectiveC,
    Wat,
    Identity,
}

impl FormatterLanguage {
    #[inline]
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
            Self::Rust => "rust",
            Self::Go => "go",
            Self::C => "c",
            Self::Cpp => "cpp",
            Self::Dart => "dart",
            Self::Lua => "lua",
            Self::Php => "php",
            Self::Ruby => "ruby",
            Self::Java => "java",
            Self::Kotlin => "kotlin",
            Self::Scala => "scala",
            Self::CSharp => "csharp",
            Self::Swift => "swift",
            Self::ObjectiveC => "objc",
            Self::Wat => "wat",
            Self::Identity => "identity",
        }
    }
}

impl Display for FormatterLanguage {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("required formatter tool not available on PATH: {0}")]
    ToolMissing(&'static str),
    #[error("formatter tool failed (exit {exit}): {stderr}")]
    ToolFailed { stderr: String, exit: i32 },
    #[error("formatter rejected source as syntactically invalid: {0}")]
    SyntaxError(String),
    #[error("formatter timed out")]
    Timeout,
}

#[derive(Debug, Clone, Copy)]
pub struct FormatConfig {
    pub enabled: bool,
    pub timeout_secs: u32,
}

impl Default for FormatConfig {
    #[inline]
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_secs: 5,
        }
    }
}

static ACTIVE_CONFIG: LazyLock<std::sync::RwLock<FormatConfig>> =
    LazyLock::new(|| std::sync::RwLock::new(FormatConfig::default()));

pub fn set_config(cfg: FormatConfig) {
    if let Ok(mut guard) = ACTIVE_CONFIG.write() {
        *guard = cfg;
    }
}

#[must_use]
pub fn current_config() -> FormatConfig {
    ACTIVE_CONFIG.read().map_or(
        FormatConfig {
            enabled: true,
            timeout_secs: 5,
        },
        |g| *g,
    )
}

pub trait SourceFormatter: std::fmt::Debug + Send + Sync {
    fn language(&self) -> FormatterLanguage;
    fn format(&self, source: &str) -> Result<String, FormatError>;
    fn is_available(&self) -> bool;
    fn external_tool(&self) -> Option<&'static str>;
}

#[must_use]
pub fn formatter_for(lang: FormatterLanguage) -> Box<dyn SourceFormatter> {
    match lang {
        FormatterLanguage::Python => Box::new(PythonRuffFormatter),
        FormatterLanguage::JavaScript => Box::new(JsPrettierFormatter),
        FormatterLanguage::TypeScript => Box::new(TsPrettierFormatter),
        FormatterLanguage::Rust => Box::new(RustRustfmtFormatter),
        FormatterLanguage::Go => Box::new(GoGofmtFormatter),
        FormatterLanguage::C => Box::new(CClangFormatFormatter),
        FormatterLanguage::Cpp => Box::new(CppClangFormatFormatter),
        FormatterLanguage::Dart => Box::new(DartFormatter),
        FormatterLanguage::Lua => Box::new(LuaStyluaFormatter),
        FormatterLanguage::Php => Box::new(PhpPhpcsFormatter),
        FormatterLanguage::Ruby => Box::new(RubyRubocopFormatter),
        FormatterLanguage::Java => Box::new(JavaGoogleJavaFormatFormatter),
        FormatterLanguage::Kotlin => Box::new(KotlinKtlintFormatter),
        FormatterLanguage::Scala => Box::new(ScalaScalafmtFormatter),
        FormatterLanguage::CSharp => Box::new(CSharpDotnetFormatFormatter),
        FormatterLanguage::Swift => Box::new(SwiftSwiftFormatFormatter),
        FormatterLanguage::ObjectiveC => Box::new(ObjcClangFormatFormatter),
        FormatterLanguage::Wat => Box::new(WatWasmFmtFormatter),
        FormatterLanguage::Identity => Box::new(IdentityFormatter),
    }
}

#[must_use]
pub fn format_or_passthrough(source: &str, lang: FormatterLanguage) -> String {
    let cfg: FormatConfig = current_config();
    if !cfg.enabled || matches!(lang, FormatterLanguage::Identity) {
        return source.to_owned();
    }
    let impl_box: Box<dyn SourceFormatter> = formatter_for(lang);
    match impl_box.format(source) {
        Ok(out) => out,
        Err(err) => {
            tracing::warn!(
                target = "disrobe::format",
                language = %lang,
                tool = ?impl_box.external_tool(),
                ?err,
                "formatter unavailable or failed; emitting unformatted source"
            );
            source.to_owned()
        }
    }
}
