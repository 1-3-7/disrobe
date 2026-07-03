#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
use serde::Serialize;

use super::output::{OutputFormat, emit};
use codes::CODE_SLICES;

mod codes;

#[derive(Debug, Serialize)]
struct ExplainResult<'a> {
    code: &'a str,
    title: &'a str,
    description: &'a str,
    common_causes: &'a [&'a str],
    common_fixes: &'a [&'a str],
    crate_path: &'a str,
}

#[derive(Debug)]
pub(crate) struct CodeEntry {
    pub(crate) code: &'static str,
    pub(crate) title: &'static str,
    pub(crate) description: &'static str,
    common_causes: &'static [&'static str],
    common_fixes: &'static [&'static str],
    pub(crate) crate_path: &'static str,
}

pub(crate) fn lookup_for_serve(code: &str) -> Option<&'static CodeEntry> {
    let normalized: String = normalize(code);
    lookup(&normalized)
}

pub(crate) fn run(code: String, fmt: OutputFormat) -> miette::Result<()> {
    let normalized: String = normalize(&code);
    let Some(entry): Option<&'static CodeEntry> = lookup(&normalized) else {
        let unknown_msg: String = format!(
            "no documentation registered for `{normalized}`. please file an issue at https://github.com/1-3-7/disrobe/issues including the full error message you saw."
        );
        if fmt.is_machine() {
            let payload: serde_json::Value = serde_json::json!({
                "code": normalized,
                "known": false,
                "message": unknown_msg,
            });
            return emit(fmt, &payload, || {});
        }
        return Err(miette::miette!("DR-CLI-0102: {unknown_msg}"));
    };

    let result: ExplainResult<'_> = ExplainResult {
        code: entry.code,
        title: entry.title,
        description: entry.description,
        common_causes: entry.common_causes,
        common_fixes: entry.common_fixes,
        crate_path: entry.crate_path,
    };
    emit(fmt, &result, || {
        println!("{}", entry.code);
        println!("  title:       {}", entry.title);
        println!("  description: {}", entry.description);
        println!("  crate:       {}", entry.crate_path);
        if !entry.common_causes.is_empty() {
            println!("  common causes:");
            for c in entry.common_causes {
                println!("    - {c}");
            }
        }
        if !entry.common_fixes.is_empty() {
            println!("  common fixes:");
            for f in entry.common_fixes {
                println!("    - {f}");
            }
        }
    })
}

fn normalize(code: &str) -> String {
    let trimmed: &str = code.trim();
    let upper: String = trimmed.to_ascii_uppercase();
    if upper.starts_with("DR-") && upper.matches('-').count() == 2 {
        return upper;
    }
    let bytes: &[u8] = upper.as_bytes();
    let dash: Option<usize> = bytes.iter().position(|&b| b == b'-');
    let Some(dash_pos): Option<usize> = dash else {
        return upper;
    };
    let domain: &str = &upper[..dash_pos];
    let num_part: &str = &upper[dash_pos + 1..];
    let domain_full: &str = canonicalize_domain(domain);
    if let Ok(n) = num_part.parse::<u32>() {
        return format!("DR-{domain_full}-{n:04}");
    }
    upper
}

fn canonicalize_domain(d: &str) -> &str {
    match d {
        "PYARM" | "PYARMOR" => "PYARM",
        "PYINST" | "PYINSTALLER" => "PYINST",
        "PYFRZ" | "PYFREEZE" => "PYFRZ",
        "NUITKA" => "NUITKA",
        "SDEF" | "SOURCEDEFENDER" => "SDEF",
        "PYDEOB" => "PYDEOB",
        "JSDEOB" => "JSDEOB",
        "WASMDEOB" => "WASMDEOB",
        "MARSHAL" => "MARSHAL",
        "CLI" => "CLI",
        other => other,
    }
}

fn lookup(code: &str) -> Option<&'static CodeEntry> {
    CODE_SLICES
        .iter()
        .flat_map(|slice: &&[CodeEntry]| slice.iter())
        .find(|e: &&CodeEntry| e.code == code)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn normalize_long_form_passes_through() {
        assert_eq!(normalize("DR-PYARM-0007"), "DR-PYARM-0007");
        assert_eq!(normalize("dr-pyarm-0007"), "DR-PYARM-0007");
    }

    #[test]
    fn normalize_short_form_expands_with_padding() {
        assert_eq!(normalize("pyarm-7"), "DR-PYARM-0007");
        assert_eq!(normalize("nuitka-3"), "DR-NUITKA-0003");
        assert_eq!(normalize("pyarmor-7"), "DR-PYARM-0007");
        assert_eq!(normalize("pyinstaller-1"), "DR-PYINST-0001");
        assert_eq!(normalize("pyfreeze-20"), "DR-PYFRZ-0020");
        assert_eq!(normalize("sourcedefender-5"), "DR-SDEF-0005");
    }

    #[test]
    fn every_registered_code_is_well_formed() {
        for entry in CODE_SLICES.iter().flat_map(|s: &&[CodeEntry]| s.iter()) {
            assert!(entry.code.starts_with("DR-"), "{}", entry.code);
            assert_eq!(entry.code.matches('-').count(), 2, "{}", entry.code);
            let num_part: &str = entry.code.rsplit('-').next().unwrap_or("");
            assert_eq!(num_part.len(), 4, "{}", entry.code);
            assert!(
                num_part.parse::<u32>().is_ok(),
                "non-numeric tail in {}",
                entry.code
            );
            assert!(!entry.title.is_empty());
            assert!(!entry.description.is_empty());
            assert!(!entry.crate_path.is_empty());
        }
    }

    #[test]
    fn lookup_finds_pyarm_seven() {
        let e: &CodeEntry = lookup("DR-PYARM-0007").expect("present");
        assert!(e.title.contains("v6/v7"));
    }

    #[test]
    fn lookup_misses_made_up_code() {
        assert!(lookup("DR-MADEUP-9999").is_none());
    }
}
