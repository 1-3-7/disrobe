use serde::Serialize;
use std::sync::LazyLock;

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
    Vbs,
    Wsh,
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
}

const POWERSHELL_SHEBANGS: &[&str] = &["#!/usr/bin/env pwsh", "#!/usr/bin/pwsh"];
const BASH_SHEBANGS: &[&str] = &["#!/bin/bash", "#!/usr/bin/env bash", "#!/usr/bin/bash"];
const DASH_SHEBANG: &str = "#!/bin/dash";
const KSH_SHEBANG: &str = "#!/bin/ksh";
const ZSH_SHEBANG: &str = "#!/bin/zsh";

static PS_TOKEN_OBF: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(r"(?i)\$\{[A-Za-z0-9_]+\}\s*=\s*\(\s*\[(?:char|byte)\]")
});

static PS_ENCODING_FLAG: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(
        r"(?i)(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]*?\s-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]+",
    )
});

static PS_COMPRESS_HINT: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"(?i)IO\.Compression\.(?:GZip|Deflate)Stream"));

static PS_STRING_FORMAT_OBF: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(r#"(?i)\(\s*['"][^'"]*\{0\}[^'"]*['"]\s*-f\s*"#)
});

static PS_AST_REORDER: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(r"(?i)&\s*\(\s*\$ExecutionContext\.InvokeCommand\.GetCommand")
});

static BASHFUSCATOR_BANNER: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"(?i)bashfuscator"));

static BASH_IFS_INDIRECT: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"\$\{?IFS\}?"));

static BATCH_RANDOM: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"(?i)%random[:!]"));

static BATCH_SET_INDIRECT: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"(?i)set\s+[A-Za-z_][A-Za-z0-9_]*="));

#[must_use]
pub fn detect(source: &[u8]) -> Detection {
    if source.is_empty() {
        return Detection {
            dialect: Dialect::Unknown,
            family: Family::Unknown,
            confidence: 0.0_f32,
            markers: Vec::new(),
        };
    }
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(source);
    let head: &str = disrobe_core::strings::head(text.as_ref(), 4096);
    let mut markers: Vec<String> = Vec::new();
    let dialect: Dialect = detect_dialect(source, head, &mut markers);
    let family: Family = detect_family(dialect, head, &mut markers);
    let confidence: f32 = score(dialect, family, &markers);
    Detection {
        dialect,
        family,
        confidence,
        markers,
    }
}

fn detect_dialect(raw: &[u8], head: &str, markers: &mut Vec<String>) -> Dialect {
    for shebang in POWERSHELL_SHEBANGS {
        if head.starts_with(shebang) {
            markers.push("shebang-pwsh".to_owned());
            return Dialect::PowerShell;
        }
    }
    for shebang in BASH_SHEBANGS {
        if head.starts_with(shebang) {
            markers.push("shebang-bash".to_owned());
            return Dialect::Bash;
        }
    }
    if crate::bash::is_node_bash_obfuscate(head) {
        markers.push("node-bash-obfuscate-eval-table".to_owned());
        return Dialect::Bash;
    }
    if head.starts_with(DASH_SHEBANG) {
        markers.push("shebang-dash".to_owned());
        return Dialect::Dash;
    }
    if head.starts_with(KSH_SHEBANG) {
        markers.push("shebang-ksh".to_owned());
        return Dialect::Ksh;
    }
    if head.starts_with(ZSH_SHEBANG) {
        markers.push("shebang-zsh".to_owned());
        return Dialect::Zsh;
    }
    if raw.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
        markers.push("ole-cfb-header".to_owned());
        return Dialect::Vba;
    }
    if raw.starts_with(b"PK\x03\x04") && raw.len() > 30 && ooxml_has_vba_project(raw) {
        markers.push("ooxml-vba-project".to_owned());
        return Dialect::Vba;
    }
    let lower: String = head.to_ascii_lowercase();
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
    if lower.contains("@echo off") || head.starts_with("@echo off") {
        markers.push("batch-echo-off".to_owned());
        return Dialect::Batch;
    }
    let lower_head: String = head.to_ascii_lowercase();
    if lower_head.starts_with("powershell")
        || lower_head.starts_with("pwsh")
        || lower_head.contains("powershell.exe ")
        || lower_head.contains("pwsh.exe ")
        || lower_head.contains(" powershell ")
        || lower_head.contains(" pwsh ")
    {
        markers.push("ps-launcher-prefix".to_owned());
        return Dialect::PowerShell;
    }
    if head.contains("[char[]]")
        || head.contains("Invoke-Expression")
        || head.contains("IEX")
        || head.contains("$PSVersionTable")
    {
        markers.push("ps-token".to_owned());
        return Dialect::PowerShell;
    }
    if head.contains("function ") && (head.contains("{ ") || head.contains(" {\n")) {
        markers.push("ps-function".to_owned());
        return Dialect::PowerShell;
    }
    if head.contains("$(")
        || head.contains("$IFS")
        || head.contains("eval ")
        || head.contains("printf ")
        || head.contains("base64 -d")
        || head.contains("base64 --decode")
    {
        markers.push("bash-tokens".to_owned());
        return Dialect::Bash;
    }
    if head.starts_with("echo ") {
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

fn detect_family(dialect: Dialect, head: &str, markers: &mut Vec<String>) -> Family {
    match dialect {
        Dialect::PowerShell => detect_ps_family(head, markers),
        Dialect::Bash | Dialect::Dash | Dialect::Ksh | Dialect::Zsh => {
            detect_bash_family(head, markers)
        }
        Dialect::Batch => detect_batch_family(head, markers),
        Dialect::Vba | Dialect::Vbs | Dialect::Wsh => detect_vba_family(head, markers),
        Dialect::Unknown => Family::Unknown,
    }
}

fn detect_ps_family(head: &str, markers: &mut Vec<String>) -> Family {
    if head.contains("Invoke-Stealth") {
        markers.push("invoke-stealth-banner".to_owned());
        return Family::InvokeStealth;
    }
    if head.contains("PowerHell") || head.contains("Power-Hell") {
        markers.push("powerhell-banner".to_owned());
        return Family::PowerHell;
    }
    if head.contains("Chameleon") {
        markers.push("chameleon-banner".to_owned());
        return Family::Chameleon;
    }
    if head.contains("psobf") || head.contains("TaurusOmar") {
        markers.push("psobf-banner".to_owned());
        return Family::Psobf;
    }
    if head.contains("ISESteroids") {
        markers.push("isesteroids-banner".to_owned());
        return Family::IseSteroids;
    }
    if PS_ENCODING_FLAG.is_match(head) {
        markers.push("ps-encodedcommand".to_owned());
        return Family::InvokeObfuscationEncoding;
    }
    if PS_COMPRESS_HINT.is_match(head) {
        markers.push("ps-gzip-stream".to_owned());
        return Family::InvokeObfuscationCompress;
    }
    if PS_AST_REORDER.is_match(head) {
        markers.push("ps-ast-getcommand".to_owned());
        return Family::InvokeObfuscationAst;
    }
    if PS_STRING_FORMAT_OBF.is_match(head) {
        markers.push("ps-string-format".to_owned());
        return Family::InvokeObfuscationString;
    }
    if PS_TOKEN_OBF.is_match(head) {
        markers.push("ps-token-charbyte".to_owned());
        return Family::InvokeObfuscationToken;
    }
    if head.to_ascii_lowercase().contains("powershell")
        && (head.contains("-w hidden")
            || head.contains("-WindowStyle Hidden")
            || head.contains("-nop")
            || head.contains("-NoProfile"))
    {
        markers.push("ps-launcher-flags".to_owned());
        return Family::InvokeObfuscationLauncher;
    }
    Family::Plain
}

fn detect_bash_family(head: &str, markers: &mut Vec<String>) -> Family {
    if crate::bash::is_node_bash_obfuscate(head) {
        markers.push("node-bash-obfuscate-chunk-table".to_owned());
        return Family::NodeBashObfuscate;
    }
    if BASHFUSCATOR_BANNER.is_match(head) {
        markers.push("bashfuscator-banner".to_owned());
        return Family::BashfuscatorToken;
    }
    if head.contains("base64 -d") || head.contains("base64 --decode") {
        markers.push("bash-base64-pipe".to_owned());
        return Family::BashfuscatorCompress;
    }
    if BASH_IFS_INDIRECT.is_match(head) && head.contains("eval") {
        markers.push("bash-ifs-eval".to_owned());
        return Family::BashIndirection;
    }
    if head.contains("printf '%s'") || head.contains("printf '\\x") {
        markers.push("bash-printf".to_owned());
        return Family::BashfuscatorString;
    }
    if let Some(family) = detect_bashfuscator_soup(head, markers) {
        return family;
    }
    Family::Plain
}

fn detect_bashfuscator_soup(head: &str, markers: &mut Vec<String>) -> Option<Family> {
    let soup_expansions: usize = head.matches("${@").count() + head.matches("${*").count();
    if soup_expansions < 6 {
        return None;
    }
    let has_ansi_c_quote: bool = head.contains("$'\\x") || head.contains("$'\\u");
    let has_base_arith: bool = head.contains("#1)") || head.contains("#2)") || head.contains("$[");
    if !has_ansi_c_quote && !has_base_arith {
        return None;
    }
    markers.push("bashfuscator-parameter-soup".to_owned());
    if head.contains("gz") && (head.contains("H4sI") || head.contains("-d ") || head.contains("-d"))
    {
        markers.push("bashfuscator-compress-shape".to_owned());
        return Some(Family::BashfuscatorCompress);
    }
    Some(Family::BashfuscatorObfuscate)
}

fn detect_batch_family(head: &str, markers: &mut Vec<String>) -> Family {
    if BATCH_RANDOM.is_match(head) {
        markers.push("batch-random".to_owned());
        return Family::BatchRandom;
    }
    if BATCH_SET_INDIRECT.is_match(head) {
        markers.push("batch-set".to_owned());
        return Family::BatchSetIndirection;
    }
    Family::Plain
}

fn detect_vba_family(head: &str, markers: &mut Vec<String>) -> Family {
    if head.contains("Chr(")
        || head.contains("StrReverse")
        || head.contains("Execute(")
        || head.contains("ExecuteGlobal")
    {
        markers.push("vbs-eval".to_owned());
        return Family::VbsWshObfuscated;
    }
    Family::VbaMacro
}

fn score(dialect: Dialect, family: Family, markers: &[String]) -> f32 {
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
    (base + bump + depth).min(0.99)
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
