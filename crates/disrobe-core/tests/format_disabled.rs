#![allow(clippy::expect_used)]
use disrobe_core::format::{FormatConfig, FormatterLanguage, format_or_passthrough, set_config};

#[test]
fn disabled_config_returns_identity_for_all_languages() {
    set_config(FormatConfig {
        enabled: false,
        timeout_secs: 5,
    });
    let src: &str = "def    weird(  x,y ):return    x+y\n";
    let langs: [FormatterLanguage; 4] = [
        FormatterLanguage::Python,
        FormatterLanguage::JavaScript,
        FormatterLanguage::Rust,
        FormatterLanguage::Go,
    ];
    for lang in langs {
        let out: String = format_or_passthrough(src, lang);
        assert_eq!(
            out, src,
            "disabled formatter must return source unchanged for {lang}"
        );
    }
    set_config(FormatConfig::default());
}
