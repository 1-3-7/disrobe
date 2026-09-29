use serde::Serialize;
use std::sync::LazyLock;

use lazy_regex::regex;
use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Dialect {
    PowerShell,
    Bash,
    Dash,
    Ksh,
    Zsh,
    Batch,
    Vba,
    Xlm,
    Vbs,
    Wsh,
    Pdf,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Family {
    Plain,
    InvokeObfuscationToken,
    InvokeObfuscationAst,
    InvokeObfuscationString,
    InvokeObfuscationEncoding,
    InvokeObfuscationCompress,
    InvokeObfuscationLauncher,
    InvokeStealth,
    PowerHell,
    Chameleon,
    Psobf,
    IseSteroids,
    BashfuscatorToken,
    BashfuscatorString,
    BashfuscatorObfuscate,
    BashfuscatorCompress,
    NodeBashObfuscate,
    BashIndirection,
    BatchRandom,
    BatchSetIndirection,
    VbaMacro,
    VbsWshObfuscated,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    pub dialect: Dialect,
    pub family: Family,
    pub confidence: f32,
    pub markers: Vec<String>,
    pub obfuscation_constructs: bool,
}

const POWERSHELL_SHEBANGS: &[&str] = &["#!/usr/bin/env pwsh", "#!/usr/bin/pwsh"];
const BASH_SHEBANGS: &[&str] = &["#!/bin/bash", "#!/usr/bin/env bash", "#!/usr/bin/bash"];
const DASH_SHEBANG: &str = "#!/bin/dash";
const KSH_SHEBANG: &str = "#!/bin/ksh";
const ZSH_SHEBANG: &str = "#!/bin/zsh";

static PS_TICKED_COMMAND: LazyLock<&'static Regex> = LazyLock::new(|| {
    regex!(
        r"(?:\b[A-Za-z]+`[A-Za-z][A-Za-z`]*-[A-Za-z`]+|\b[A-Za-z]+-[A-Za-z]*`[A-Za-z][A-Za-z`]*)"
    )
});

static PS_TOKEN_OBF: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r"(?i)\$\{[A-Za-z0-9_]+\}\s*=\s*\(\s*\[(?:char|byte)\]"));

static PS_ENCODING_FLAG: LazyLock<&'static Regex> = LazyLock::new(|| {
    regex!(
        r"(?i)(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]*?\s-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]+"
    )
});

static PS_COMPRESS_HINT: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r"(?i)IO\.Compression\.(?:GZip|Deflate)Stream"));

static PS_STRING_FORMAT_OBF: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r#"(?i)\(\s*['"][^'"]*\{0\}[^'"]*['"]\s*-f\s*"#));

static PS_LITERAL_STRING_OPS: LazyLock<&'static Regex> = LazyLock::new(|| {
    regex!(
        r"(?i)\(\s*'[^']*'\s*-c?(?:replace|split)\s*'|\[string\]::join\(\s*'[^']*'\s*,\s*\(\s*'|-join\s*\[char\[\]\]\s*\(\s*(?:0x)?[0-9a-f]+\s*,|\(\s*'[^']*'\s*\[\s*-1\s*\.\.\s*-\d+\s*\]\s*-join"
    )
});

static PS_AST_REORDER: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r"(?i)&\s*\(\s*\$ExecutionContext\.InvokeCommand\.GetCommand"));

static BASHFUSCATOR_BANNER: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r"(?i)bashfuscator"));

static BASH_IFS_INDIRECT: LazyLock<&'static Regex> = LazyLock::new(|| regex!(r"\$\{?IFS\}?"));

static BATCH_RANDOM: LazyLock<&'static Regex> = LazyLock::new(|| regex!(r"(?i)%random[:!]"));

static BATCH_SET_INDIRECT: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r"(?i)set\s+[A-Za-z_][A-Za-z0-9_]*="));

static BATCH_ECHO_OFF_LINE: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r"(?im)^[ \t]*@echo[ \t]+o(?:ff|n)\b"));

static BATCH_OBFUSCATION_CONSTRUCTS: LazyLock<[&'static Regex; 4]> = LazyLock::new(|| {
    [
        regex!(r"\^[a-z0-9]"),
        regex!(r"[%!][a-z_][a-z0-9_]*:~-?\d+(?:,-?\d+)?[%!]"),
        regex!(
            r#"\bset\s+/a\s+"?[a-z_][a-z0-9_]*\s*=\s*"?\s*(?:0x[0-9a-f]+|\d+)\s*(?:[-+*/]|<<|>>)"#
        ),
        regex!(r#"\bfor\s+/f\b[^\r\n]*\bin\s*\(\s*"[!%][a-z_][a-z0-9_]*[!%]"\s*\)"#),
    ]
});

static PS_CONCAT_INVOCATION: LazyLock<&'static Regex> = LazyLock::new(|| {
    regex!(r#"(?i)(?:\biex|invoke-expression|[&.])\s*\(\s*\(?\s*['"][^'"\r\n]{2,}['"]\s*\+\s*['"]"#)
});

static PS_CHAR_CODE_RUN: LazyLock<&'static Regex> = LazyLock::new(|| {
    regex!(
        r"(?i)\[char\]\s*\d{1,3}\s*\+\s*\[char\]\s*\d{1,3}|\[char\[\]\]\s*\(\s*\d{1,3}(?:\s*,\s*\d{1,3}){3,}"
    )
});

static PS_GET_COMMAND_CALL: LazyLock<&'static Regex> =
    LazyLock::new(|| regex!(r"(?i)&\s*\(\s*(?:Get-Command|gcm)\s"));

static PS_CONSTRUCTS: LazyLock<[&'static Regex; 6]> = LazyLock::new(|| {
    [
        regex!(r"\[[A-Za-z_][A-Za-z0-9_.]*(?:\[\])?\]::[A-Za-z_]"),
        regex!(
            r"(?im)(?:^|[\s(|;{=])(?:get|set|new|invoke|write|out|add|remove|start|stop|select|where|foreach|import|export|convertto|convertfrom|test)-[a-z]{2,}\b"
        ),
        regex!(r"(?i)\b(?:iex|invoke-expression)\b"),
        regex!(r"(?i)\bparam\s*\(|\[cmdletbinding\s*\("),
        regex!(r"(?im)(?:^|[\s(])-(?:join|split|replace|creplace|bxor|band|bor)\b"),
        regex!(
            r"(?i)\$(?:env:[a-z_]|psversiontable\b|executioncontext\b|null\b|true\b|false\b|_\.)"
        ),
    ]
});

const MIN_PS_CONSTRUCT_KINDS: usize = 2;
const TEXT_PROBE_BYTES: usize = 8 * 1024;
const BINARY_SCAN_BYTES: usize = 4 * 1024;
const MAX_SCRIPT_SCAN_BYTES: usize = 16 * 1024 * 1024;
const OBFUSCATED_BATCH_CONFIDENCE: f32 = 0.88;
const UTF16LE_BOM_REENCODED_AS_UTF8: [u8; 4] = [0xC3, 0xBF, 0xC3, 0xBE];

#[must_use]
pub fn decode_script_bytes(bytes: &[u8]) -> Option<String> {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return Some(String::from_utf8_lossy(rest).into_owned());
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return Some(decode_utf16(rest, u16::from_le_bytes));
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return Some(decode_utf16(rest, u16::from_be_bytes));
    }
    if let Some(rest) = bytes.strip_prefix(&UTF16LE_BOM_REENCODED_AS_UTF8)
        && reads_as_utf16le_text(rest)
    {
        return Some(decode_utf16(rest, u16::from_le_bytes));
    }
    reads_as_utf16le_text(bytes).then(|| decode_utf16(bytes, u16::from_le_bytes))
}

fn decode_utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair: &[u8]| unit([pair[0], pair[1]]))
        .collect();
    char::decode_utf16(units)
        .map(|decoded: Result<char, std::char::DecodeUtf16Error>| {
            decoded.unwrap_or(char::REPLACEMENT_CHARACTER)
        })
        .collect()
}

fn reads_as_utf16le_text(bytes: &[u8]) -> bool {
    const SAMPLE_UNITS: usize = 64;
    if bytes.len() < 8 || !bytes.len().is_multiple_of(2) {
        return false;
    }
    bytes.chunks_exact(2).take(SAMPLE_UNITS).all(|pair: &[u8]| {
        pair[1] == 0
            && (pair[0].is_ascii_graphic() || matches!(pair[0], b' ' | b'\t' | b'\r' | b'\n'))
    })
}

#[must_use]
pub fn detect(source: &[u8]) -> Detection {
    if let Some(decoded) = decode_script_bytes(source) {
        return detect(decoded.as_bytes());
    }
    if source.is_empty() {
        return Detection {
            dialect: Dialect::Unknown,
            family: Family::Unknown,
            confidence: 0.0_f32,
            markers: Vec::new(),
            obfuscation_constructs: false,
        };
    }
    let text_like: bool = !source[..source.len().min(TEXT_PROBE_BYTES)].contains(&0);
    let scan_limit: usize = if text_like {
        MAX_SCRIPT_SCAN_BYTES
    } else {
        BINARY_SCAN_BYTES
    };
    let text: std::borrow::Cow<'_, str> =
        String::from_utf8_lossy(&source[..source.len().min(scan_limit)]);
    let scan: &str = text.as_ref();
    let lower: String = scan.to_ascii_lowercase();
    let mut markers: Vec<String> = Vec::new();
    let dialect: Dialect = detect_dialect(source, scan, &lower, &mut markers);
    let family: Family = detect_family(dialect, scan, &lower, &mut markers);
    let obfuscation_constructs: bool = text_like && has_obfuscation_constructs(dialect, &lower);
    let confidence: f32 = score(dialect, family, &markers, obfuscation_constructs);
    Detection {
        dialect,
        family,
        confidence,
        markers,
        obfuscation_constructs,
    }
}

fn has_obfuscation_constructs(dialect: Dialect, lower: &str) -> bool {
    match dialect {
        Dialect::Batch => BATCH_OBFUSCATION_CONSTRUCTS
            .iter()
            .any(|construct: &&'static Regex| construct.is_match(lower)),
        Dialect::PowerShell
        | Dialect::Bash
        | Dialect::Dash
        | Dialect::Ksh
        | Dialect::Zsh
        | Dialect::Vba
        | Dialect::Xlm
        | Dialect::Vbs
        | Dialect::Wsh
        | Dialect::Pdf
        | Dialect::Unknown => false,
    }
}

fn powershell_construct_kinds(scan: &str) -> usize {
    PS_CONSTRUCTS
        .iter()
        .filter(|construct: &&&'static Regex| construct.is_match(scan))
        .count()
}

fn has_powershell_obfuscation_shape(scan: &str) -> bool {
    PS_STRING_FORMAT_OBF.is_match(scan)
        || PS_TOKEN_OBF.is_match(scan)
        || PS_TICKED_COMMAND.is_match(scan)
        || PS_AST_REORDER.is_match(scan)
        || PS_GET_COMMAND_CALL.is_match(scan)
        || PS_CONCAT_INVOCATION.is_match(scan)
        || PS_CHAR_CODE_RUN.is_match(scan)
        || crate::powershell::psobf::has_obfus_wrappers(scan)
        || crate::powershell::invoke_stealth::has_reversed_base64_shape(scan)
}

fn detect_dialect(raw: &[u8], scan: &str, lower: &str, markers: &mut Vec<String>) -> Dialect {
    for shebang in POWERSHELL_SHEBANGS {
        if scan.starts_with(shebang) {
            markers.push("shebang-pwsh".to_owned());
            return Dialect::PowerShell;
        }
    }
    for shebang in BASH_SHEBANGS {
        if scan.starts_with(shebang) {
            markers.push("shebang-bash".to_owned());
            return Dialect::Bash;
        }
    }
    if crate::bash::is_node_bash_obfuscate(scan) {
        markers.push("node-bash-obfuscate-eval-table".to_owned());
        return Dialect::Bash;
    }
    if scan.starts_with(DASH_SHEBANG) {
        markers.push("shebang-dash".to_owned());
        return Dialect::Dash;
    }
    if scan.starts_with(KSH_SHEBANG) {
        markers.push("shebang-ksh".to_owned());
        return Dialect::Ksh;
    }
    if scan.starts_with(ZSH_SHEBANG) {
        markers.push("shebang-zsh".to_owned());
        return Dialect::Zsh;
    }
    let pdf_scan: &[u8] = &raw[..raw.len().min(1024)];
    if pdf_scan.windows(5).any(|window: &[u8]| window == b"%PDF-") {
        markers.push("pdf-header".to_owned());
        return Dialect::Pdf;
    }
    if raw.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
        if crate::xlm::is_xlm_macro_document(raw) {
            markers.push("xlm-macro-sheet".to_owned());
            return Dialect::Xlm;
        }
        markers.push("ole-cfb-header".to_owned());
        return Dialect::Vba;
    }
    if raw.starts_with(b"PK\x03\x04") && raw.len() > 30 {
        if crate::xlm::is_xlm_macro_document(raw) {
            markers.push("xlm-macro-sheet".to_owned());
            return Dialect::Xlm;
        }
        if ooxml_has_vba_project(raw) {
            markers.push("ooxml-vba-project".to_owned());
            return Dialect::Vba;
        }
    }
    if lower.contains("attribute vb_name")
        || lower.contains("sub workbook_open")
        || lower.contains("sub auto_open")
        || lower.contains("sub document_open")
    {
        markers.push("vba-attribute".to_owned());
        return Dialect::Vba;
    }
    if lower.contains("createobject(\"scripting.filesystemobject\"")
        || lower.contains("createobject(\"wscript.shell\"")
    {
        markers.push("vbs-wsh-createobject".to_owned());
        return Dialect::Vbs;
    }
    if lower.contains("<job") && lower.contains("<script language=\"vbscript\"") {
        markers.push("wsf-wsh-job".to_owned());
        return Dialect::Wsh;
    }
    if lower.contains("wscript.echo")
        || lower.contains("wscript.shell")
        || (lower.contains("createobject(") && !lower.contains("new-object"))
        || ((lower.contains("execute(") || lower.contains("executeglobal"))
            && lower.matches("chr(").count() >= 2)
    {
        markers.push("vbs-wsh-runtime".to_owned());
        return Dialect::Vbs;
    }
    if lower.contains("@echo off") {
        markers.push("batch-echo-off".to_owned());
        return Dialect::Batch;
    }
    if BATCH_ECHO_OFF_LINE.is_match(&lower.replace('^', "")) {
        markers.push("batch-caret-echo-off".to_owned());
        return Dialect::Batch;
    }
    if lower.starts_with("powershell")
        || lower.starts_with("pwsh")
        || lower.contains("powershell.exe ")
        || lower.contains("pwsh.exe ")
        || lower.contains(" powershell ")
        || lower.contains(" pwsh ")
    {
        markers.push("ps-launcher-prefix".to_owned());
        return Dialect::PowerShell;
    }
    if scan.contains("[char[]]")
        || scan.contains("Invoke-Expression")
        || scan.contains("IEX")
        || scan.contains("$PSVersionTable")
    {
        markers.push("ps-token".to_owned());
        return Dialect::PowerShell;
    }
    if scan.contains("function ") && (scan.contains("{ ") || scan.contains(" {\n")) {
        markers.push("ps-function".to_owned());
        return Dialect::PowerShell;
    }
    if has_powershell_obfuscation_shape(scan) {
        markers.push("ps-obfuscation-shape".to_owned());
        return Dialect::PowerShell;
    }
    if powershell_construct_kinds(scan) >= MIN_PS_CONSTRUCT_KINDS {
        markers.push("ps-constructs".to_owned());
        return Dialect::PowerShell;
    }
    if scan.contains("$(")
        || scan.contains("$IFS")
        || scan.contains("eval ")
        || scan.contains("printf ")
        || scan.contains("base64 -d")
        || scan.contains("base64 --decode")
    {
        markers.push("bash-tokens".to_owned());
        return Dialect::Bash;
    }
    if scan.starts_with("echo ") {
        markers.push("echo-leader".to_owned());
        return Dialect::Bash;
    }
    Dialect::Unknown
}

fn ooxml_has_vba_project(raw: &[u8]) -> bool {
    let Ok(mut zip): Result<zip::ZipArchive<std::io::Cursor<&[u8]>>, zip::result::ZipError> =
        zip::ZipArchive::new(std::io::Cursor::new(raw))
    else {
        return false;
    };
    for index in 0..zip.len() {
        if let Ok(entry) = zip.by_index(index)
            && entry.name().ends_with("vbaProject.bin")
        {
            return true;
        }
    }
    false
}

fn detect_family(dialect: Dialect, scan: &str, lower: &str, markers: &mut Vec<String>) -> Family {
    match dialect {
        Dialect::PowerShell => detect_ps_family(scan, lower, markers),
        Dialect::Bash | Dialect::Dash | Dialect::Ksh | Dialect::Zsh => {
            detect_bash_family(scan, markers)
        }
        Dialect::Batch => detect_batch_family(scan, markers),
        Dialect::Vba | Dialect::Vbs | Dialect::Wsh => detect_vba_family(scan, markers),
        Dialect::Xlm | Dialect::Pdf => Family::Plain,
        Dialect::Unknown => Family::Unknown,
    }
}

fn detect_ps_family(scan: &str, lower: &str, markers: &mut Vec<String>) -> Family {
    if scan.contains("Invoke-Stealth") {
        markers.push("invoke-stealth-banner".to_owned());
        return Family::InvokeStealth;
    }
    if scan.contains("PowerHell") || scan.contains("Power-Hell") {
        markers.push("powerhell-banner".to_owned());
        return Family::PowerHell;
    }
    if scan.contains("Chameleon") {
        markers.push("chameleon-banner".to_owned());
        return Family::Chameleon;
    }
    if scan.contains("psobf") || scan.contains("TaurusOmar") {
        markers.push("psobf-banner".to_owned());
        return Family::Psobf;
    }
    if scan.contains("ISESteroids") {
        markers.push("isesteroids-banner".to_owned());
        return Family::IseSteroids;
    }
    if PS_ENCODING_FLAG.is_match(scan) {
        markers.push("ps-encodedcommand".to_owned());
        return Family::InvokeObfuscationEncoding;
    }
    if PS_COMPRESS_HINT.is_match(scan) {
        markers.push("ps-gzip-stream".to_owned());
        return Family::InvokeObfuscationCompress;
    }
    if crate::powershell::invoke_stealth::has_reversed_base64_shape(scan) {
        markers.push("invoke-stealth-reversed-base64".to_owned());
        return Family::InvokeStealth;
    }
    if crate::powershell::psobf::has_obfus_wrappers(scan) {
        markers.push("psobf-obfus-wrapper".to_owned());
        return Family::Psobf;
    }
    if PS_AST_REORDER.is_match(scan) || PS_GET_COMMAND_CALL.is_match(scan) {
        markers.push("ps-ast-getcommand".to_owned());
        return Family::InvokeObfuscationAst;
    }
    if PS_STRING_FORMAT_OBF.is_match(scan) {
        markers.push("ps-string-format".to_owned());
        return Family::InvokeObfuscationString;
    }
    if PS_LITERAL_STRING_OPS.is_match(scan) {
        markers.push("ps-literal-string-ops".to_owned());
        return Family::InvokeObfuscationString;
    }
    if PS_TOKEN_OBF.is_match(scan) {
        markers.push("ps-token-charbyte".to_owned());
        return Family::InvokeObfuscationToken;
    }
    if PS_CHAR_CODE_RUN.is_match(scan) {
        markers.push("ps-char-code-run".to_owned());
        return Family::InvokeObfuscationToken;
    }
    if PS_TICKED_COMMAND.is_match(scan) {
        markers.push("ps-ticked-command".to_owned());
        return Family::InvokeObfuscationToken;
    }
    if PS_CONCAT_INVOCATION.is_match(scan) {
        markers.push("ps-concatenated-invocation".to_owned());
        return Family::InvokeObfuscationString;
    }
    if crate::powershell::chameleon::has_chameleon_shape(scan) {
        markers.push("chameleon-case-or-rename".to_owned());
        return Family::Chameleon;
    }
    if lower.contains("powershell")
        && (scan.contains("-w hidden")
            || scan.contains("-WindowStyle Hidden")
            || scan.contains("-nop")
            || scan.contains("-NoProfile"))
    {
        markers.push("ps-launcher-flags".to_owned());
        return Family::InvokeObfuscationLauncher;
    }
    Family::Plain
}

fn detect_bash_family(scan: &str, markers: &mut Vec<String>) -> Family {
    if crate::bash::is_node_bash_obfuscate(scan) {
        markers.push("node-bash-obfuscate-chunk-table".to_owned());
        return Family::NodeBashObfuscate;
    }
    if BASHFUSCATOR_BANNER.is_match(scan) {
        markers.push("bashfuscator-banner".to_owned());
        return Family::BashfuscatorToken;
    }
    if scan.contains("base64 -d") || scan.contains("base64 --decode") {
        markers.push("bash-base64-pipe".to_owned());
        return Family::BashfuscatorCompress;
    }
    if BASH_IFS_INDIRECT.is_match(scan) && scan.contains("eval") {
        markers.push("bash-ifs-eval".to_owned());
        return Family::BashIndirection;
    }
    if scan.contains("printf '%s'") || scan.contains("printf '\\x") {
        markers.push("bash-printf".to_owned());
        return Family::BashfuscatorString;
    }
    if let Some(family) = detect_bashfuscator_soup(scan, markers) {
        return family;
    }
    Family::Plain
}

fn detect_bashfuscator_soup(scan: &str, markers: &mut Vec<String>) -> Option<Family> {
    let soup_expansions: usize = scan.matches("${@").count() + scan.matches("${*").count();
    if soup_expansions < 6 {
        return None;
    }
    let has_ansi_c_quote: bool = scan.contains("$'\\x") || scan.contains("$'\\u");
    let has_base_arith: bool = scan.contains("#1)") || scan.contains("#2)") || scan.contains("$[");
    if !has_ansi_c_quote && !has_base_arith {
        return None;
    }
    markers.push("bashfuscator-parameter-soup".to_owned());
    if scan.contains("gz") && (scan.contains("H4sI") || scan.contains("-d ") || scan.contains("-d"))
    {
        markers.push("bashfuscator-compress-shape".to_owned());
        return Some(Family::BashfuscatorCompress);
    }
    Some(Family::BashfuscatorObfuscate)
}

fn detect_batch_family(scan: &str, markers: &mut Vec<String>) -> Family {
    if BATCH_RANDOM.is_match(scan) {
        markers.push("batch-random".to_owned());
        return Family::BatchRandom;
    }
    if BATCH_SET_INDIRECT.is_match(scan) {
        markers.push("batch-set".to_owned());
        return Family::BatchSetIndirection;
    }
    Family::Plain
}

fn detect_vba_family(scan: &str, markers: &mut Vec<String>) -> Family {
    if scan.contains("Chr(")
        || scan.contains("StrReverse")
        || scan.contains("Execute(")
        || scan.contains("ExecuteGlobal")
    {
        markers.push("vbs-eval".to_owned());
        return Family::VbsWshObfuscated;
    }
    Family::VbaMacro
}

fn score(
    dialect: Dialect,
    family: Family,
    markers: &[String],
    obfuscation_constructs: bool,
) -> f32 {
    let base: f32 = if dialect == Dialect::Unknown {
        0.0
    } else {
        0.6
    };
    let bump: f32 = if family == Family::Plain || family == Family::Unknown {
        0.0
    } else {
        0.25
    };
    let depth: f32 = (markers.len() as f32).min(4.0) * 0.05;
    let scored: f32 = (base + bump + depth).min(0.99);
    if obfuscation_constructs {
        scored.max(OBFUSCATED_BATCH_CONFIDENCE)
    } else {
        scored
    }
}

#[cfg(test)]
mod ticked_command_tests {
    use super::{Dialect, Family, detect};

    #[test]
    fn a_backticked_cmdlet_is_powershell_token_obfuscation() {
        for script in ["wR`I`TE-oU`TpUt 'x'\n", "W`rite-`Output 'x'\n"] {
            let found = detect(script.as_bytes());
            assert_eq!(found.dialect, Dialect::PowerShell, "{script}");
            assert_eq!(found.family, Family::InvokeObfuscationToken, "{script}");
        }
        assert_ne!(
            detect(b"echo `date`-stamp\n").family,
            Family::InvokeObfuscationToken
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_powershell_encoded() {
        let src: &[u8] = b"powershell -NoP -W Hidden -EncodedCommand QQBBAEEA";
        let det: Detection = detect(src);
        assert_eq!(det.dialect, Dialect::PowerShell);
        assert_eq!(det.family, Family::InvokeObfuscationEncoding);
    }

    #[test]
    fn detects_bash_shebang() {
        let src: &[u8] = b"#!/bin/bash\necho hi\n";
        let det: Detection = detect(src);
        assert_eq!(det.dialect, Dialect::Bash);
    }

    #[test]
    fn detects_bash_shebang_with_non_utf8_payload() {
        let src: &[u8] = b"#!/bin/bash\nprintf '\xff'\n";
        let det: Detection = detect(src);
        assert_eq!(det.dialect, Dialect::Bash);
    }

    #[test]
    fn detects_batch_random() {
        let src: &[u8] = b"@echo off\nset r=%random:~0,4%\necho %r%\n";
        let det: Detection = detect(src);
        assert_eq!(det.dialect, Dialect::Batch);
        assert_eq!(det.family, Family::BatchRandom);
    }

    #[test]
    fn detects_vba_attribute() {
        let src: &[u8] = b"Attribute VB_Name = \"Module1\"\nSub Auto_Open()\nEnd Sub\n";
        let det: Detection = detect(src);
        assert_eq!(det.dialect, Dialect::Vba);
    }

    #[test]
    fn zip_without_vba_project_is_not_misdetected_as_vba() {
        let mut src: Vec<u8> = Vec::with_capacity(64);
        src.extend_from_slice(b"PK\x03\x04");
        src.extend_from_slice(&[0u8; 60]);
        let det: Detection = detect(&src);
        assert_ne!(det.dialect, Dialect::Vba);
    }
}
