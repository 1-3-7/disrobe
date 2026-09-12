#![allow(clippy::expect_used)]
use disrobe_core::format::{
    CClangFormatFormatter, CSharpDotnetFormatFormatter, CppClangFormatFormatter, DartFormatter,
    FormatterLanguage, GoGofmtFormatter, IdentityFormatter, JavaGoogleJavaFormatFormatter,
    JsPrettierFormatter, KotlinKtlintFormatter, LuaStyluaFormatter, ObjcClangFormatFormatter,
    PhpPhpcsFormatter, PythonRuffFormatter, RubyRubocopFormatter, RustRustfmtFormatter,
    ScalaScalafmtFormatter, SourceFormatter, SwiftSwiftFormatFormatter, TsPrettierFormatter,
    WatWasmFmtFormatter, formatter_for,
};

fn smoke<F: SourceFormatter>(f: &F, expect_lang: FormatterLanguage) {
    let avail: bool = f.is_available();
    let _: bool = avail;
    let tool: Option<&'static str> = f.external_tool();
    let _: Option<&'static str> = tool;
    assert_eq!(f.language(), expect_lang);
}

#[test]
fn each_language_formatter_smokes_cleanly() {
    smoke(&PythonRuffFormatter, FormatterLanguage::Python);
    smoke(&JsPrettierFormatter, FormatterLanguage::JavaScript);
    smoke(&TsPrettierFormatter, FormatterLanguage::TypeScript);
    smoke(&RustRustfmtFormatter, FormatterLanguage::Rust);
    smoke(&GoGofmtFormatter, FormatterLanguage::Go);
    smoke(&CClangFormatFormatter, FormatterLanguage::C);
    smoke(&CppClangFormatFormatter, FormatterLanguage::Cpp);
    smoke(&DartFormatter, FormatterLanguage::Dart);
    smoke(&LuaStyluaFormatter, FormatterLanguage::Lua);
    smoke(&PhpPhpcsFormatter, FormatterLanguage::Php);
    smoke(&RubyRubocopFormatter, FormatterLanguage::Ruby);
    smoke(&JavaGoogleJavaFormatFormatter, FormatterLanguage::Java);
    smoke(&KotlinKtlintFormatter, FormatterLanguage::Kotlin);
    smoke(&ScalaScalafmtFormatter, FormatterLanguage::Scala);
    smoke(&CSharpDotnetFormatFormatter, FormatterLanguage::CSharp);
    smoke(&SwiftSwiftFormatFormatter, FormatterLanguage::Swift);
    smoke(&ObjcClangFormatFormatter, FormatterLanguage::ObjectiveC);
    smoke(&WatWasmFmtFormatter, FormatterLanguage::Wat);
    smoke(&IdentityFormatter, FormatterLanguage::Identity);
}

#[test]
fn dispatch_factory_returns_correct_language() {
    let langs: [FormatterLanguage; 19] = [
        FormatterLanguage::Python,
        FormatterLanguage::JavaScript,
        FormatterLanguage::TypeScript,
        FormatterLanguage::Rust,
        FormatterLanguage::Go,
        FormatterLanguage::C,
        FormatterLanguage::Cpp,
        FormatterLanguage::Dart,
        FormatterLanguage::Lua,
        FormatterLanguage::Php,
        FormatterLanguage::Ruby,
        FormatterLanguage::Java,
        FormatterLanguage::Kotlin,
        FormatterLanguage::Scala,
        FormatterLanguage::CSharp,
        FormatterLanguage::Swift,
        FormatterLanguage::ObjectiveC,
        FormatterLanguage::Wat,
        FormatterLanguage::Identity,
    ];
    for lang in langs {
        let f: Box<dyn SourceFormatter> = formatter_for(lang);
        assert_eq!(f.language(), lang);
    }
}
