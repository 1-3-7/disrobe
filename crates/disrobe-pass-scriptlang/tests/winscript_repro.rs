#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_scriptlang::WinScriptLang;
use disrobe_pass_scriptlang::lang::winscript;

#[test]
fn format_operator_multibyte_template_does_not_panic() {
    let bytes: [u8; 39] = [
        112, 111, 119, 101, 114, 115, 104, 101, 108, 108, 32, 45, 99, 32, 34, 36, 120, 61, 40, 39,
        123, 48, 125, 123, 49, 165, 39, 32, 45, 102, 32, 39, 73, 69, 39, 44, 39, 88, 39,
    ];
    let text: String = winscript::decode_text(&bytes);
    let _ = winscript::rebuild_format_operator(&text);
    let recovery: winscript::WinScriptRecovery =
        winscript::recover(WinScriptLang::PowerShell, &text);
    assert_eq!(recovery.language, WinScriptLang::PowerShell);
}

#[test]
fn format_operator_repeated_rewrite_shrinking_buffer() {
    let text: &str =
        "$a=('{0}{1}' -f 'A','B'); $b=('{0}' -f 'CD'); $c=('{0}{1}{2}' -f 'x','y','z')";
    let rebuilt: Option<String> = winscript::rebuild_format_operator(text);
    let Some(out): Option<String> = rebuilt else {
        panic!("expected at least one format-operator rewrite");
    };
    assert!(out.contains("'AB'"));
    assert!(out.contains("'CD'"));
    assert!(out.contains("'xyz'"));
}

#[test]
fn rebuilt_literals_double_embedded_single_quotes() {
    let concat: Option<String> = winscript::rebuild_string_concat("'a''b' + 'c'");
    assert_eq!(concat.as_deref(), Some("'a''bc'"));

    let char_codes: Option<String> = winscript::rebuild_char_codes("String.fromCharCode(39,97)");
    assert_eq!(char_codes.as_deref(), Some("'''a'"));

    let char_builder: Option<String> = winscript::rebuild_char_builder("Chr(39) & Chr(97)");
    assert_eq!(char_builder.as_deref(), Some("'''a'"));
}
