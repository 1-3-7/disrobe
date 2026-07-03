use disrobe_pass_py_decompile::{NativeDecompile, Result as DecompileResult, decompile_pyc};
use disrobe_py_marshal::PyVersion;
use serde::Serialize;

use crate::debug::{dbg_kv, dbg_line, dbg_section};
use crate::detect::{Detection, Family, detect};
use crate::obfuscators::{Obfuscator, ObfuscatorPass, iter_passes};
use crate::peel::{PeelResult, peel_with_pyver};

#[derive(Debug, Clone, Serialize)]
pub struct SupportedObfuscator {
    pub id: Obfuscator,
    pub display_name: &'static str,
    pub aliases: &'static [&'static str],
}

#[must_use]
pub fn supported_obfuscators() -> Vec<SupportedObfuscator> {
    iter_passes()
        .into_iter()
        .map(|pass: &'static dyn ObfuscatorPass| describe_obfuscator(pass.id()))
        .collect()
}

const fn describe_obfuscator(id: Obfuscator) -> SupportedObfuscator {
    let (display_name, aliases): (&'static str, &'static [&'static str]) = match id {
        Obfuscator::Kramer => ("Kramer / Specter", &["specter"]),
        Obfuscator::Berserker => ("Berserker", &["hyperion-successor"]),
        Obfuscator::Jawbreaker => ("Jawbreaker", &[]),
        Obfuscator::BlankObf => ("BlankOBF", &["blankobfv2"]),
        Obfuscator::PlusObf => ("PlusOBF", &[]),
        Obfuscator::Wodx => ("Wodx", &[]),
        Obfuscator::PyobfuscateCom => ("pyobfuscate.com", &["pyobfuscate-online"]),
        Obfuscator::PyobfuscateComXor => (
            "pyobfuscate.com (2026 XOR/lambda)",
            &["pyobfuscate-xor", "pyobfuscate-lambda"],
        ),
        Obfuscator::PyObfuscatorMauricelambert => {
            ("PyObfuscator (mauricelambert)", &["pyobfuscator"])
        }
        Obfuscator::PythonObfuscatorPypi => ("python-obfuscator (PyPI)", &["python_obfuscator"]),
        Obfuscator::ObfuXtreme => ("ObfuXtreme", &[]),
        Obfuscator::Manglify => ("Manglify", &[]),
        Obfuscator::Oxyry => ("Oxyry", &["oxyry-shrinker"]),
        Obfuscator::Pyminifier => ("pyminifier", &[]),
        Obfuscator::OnlineFamily => ("online obfuscator family", &["pyobfuscate-family"]),
        Obfuscator::XindexObf => ("Xindex", &[]),
        Obfuscator::Pyobfus => ("pyobfus", &["lambda-chain"]),
        Obfuscator::Pypacker => ("Pypacker", &["marshal-packer"]),
        Obfuscator::Patchwork => ("Patchwork", &["patchwork-obfuscator"]),
        Obfuscator::PycZipper => ("pyc-zipper", &["pyc_zipper", "pyc-packer"]),
    };
    SupportedObfuscator {
        id,
        display_name,
        aliases,
    }
}

#[must_use]
pub const fn supported_families() -> &'static [(Family, &'static str)] {
    &[
        (Family::Hyperion, "Hyperion"),
        (
            Family::KramerSpecterBerserker,
            "Kramer / Specter / Berserker",
        ),
        (Family::BlankObf, "BlankOBF"),
        (Family::Pyfuscator, "Pyfuscator"),
        (
            Family::GenericDropper,
            "generic base64/zlib/marshal dropper",
        ),
        (Family::PyObfuscator, "PyObfuscator"),
        (Family::Opy, "Opy"),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RouteKind {
    Deobfuscated,
    CleanPyc,
    Unidentified,
}

#[derive(Debug, Clone, Serialize)]
pub struct AutoDeobOutcome {
    pub kind: RouteKind,
    pub detection: Detection,
    pub peel: Option<PeelResult>,
    pub source: Option<String>,
    pub chain: Vec<String>,
    pub guidance: Option<String>,
}

#[must_use]
pub fn auto_deobfuscate(bytes: &[u8], pyver_hint: Option<PyVersion>) -> AutoDeobOutcome {
    dbg_section("auto-route");
    dbg_kv("input_len", || bytes.len().to_string());
    dbg_kv("pyver_hint", || {
        pyver_hint.map_or_else(|| "none".to_owned(), |v: PyVersion| format!("{v:?}"))
    });
    let detection: Detection = detect(bytes);
    dbg_kv("detect_family", || format!("{:?}", detection.family));
    dbg_kv("detect_confidence", || {
        format!("{:.2}", detection.confidence)
    });
    dbg_kv("detect_markers", || detection.markers.join(","));

    if let Ok(result) = peel_with_pyver(bytes, pyver_hint)
        && result.recovered
        && !result.final_source.trim().is_empty()
    {
        let chain: Vec<String> = deob_chain_labels(&result);
        dbg_kv("route", || "deobfuscated".to_owned());
        dbg_kv("recovered_len", || result.final_source.len().to_string());
        dbg_kv("chain", || chain.join(" | "));
        return AutoDeobOutcome {
            kind: RouteKind::Deobfuscated,
            detection,
            source: Some(result.final_source.clone()),
            chain,
            peel: Some(result),
            guidance: None,
        };
    }

    let native_decompile: DecompileResult<NativeDecompile> = decompile_pyc(bytes);
    if let Ok(native) = native_decompile {
        let chain: Vec<String> = vec!["clean .pyc -> native decompile".to_owned()];
        dbg_kv("route", || "clean-pyc".to_owned());
        dbg_kv("recovered_len", || native.source.len().to_string());
        return AutoDeobOutcome {
            kind: RouteKind::CleanPyc,
            detection,
            peel: None,
            source: Some(native.source),
            chain,
            guidance: None,
        };
    }

    dbg_kv("route", || "unidentified".to_owned());
    dbg_line(|| {
        if looks_obfuscated(bytes) {
            "wall: looks obfuscated but no obfuscator matched".to_owned()
        } else {
            "wall: not a known obfuscator and not a decompilable .pyc".to_owned()
        }
    });
    AutoDeobOutcome {
        kind: RouteKind::Unidentified,
        detection,
        peel: None,
        source: None,
        chain: Vec::new(),
        guidance: Some(unidentified_guidance(bytes)),
    }
}

fn deob_chain_labels(result: &PeelResult) -> Vec<String> {
    let detected: String = format!("detected {family:?}", family = result.initial.family);
    let mut chain: Vec<String> = vec![detected];
    if let Some(summary) = result.obfuscator.as_ref() {
        let stages: String = if summary.stages_applied.is_empty() {
            String::new()
        } else {
            format!(" ({})", summary.stages_applied.join("+"))
        };
        chain.push(format!(
            "deobfuscated via {obf:?}{stages}",
            obf = summary.obfuscator
        ));
    } else if let Some(marshal) = result.marshal.as_ref() {
        chain.push(format!(
            "deobfuscated via marshal/{}",
            marshal.chain.join("+")
        ));
    } else if !result.steps.is_empty() {
        let decoders: String = result
            .steps
            .iter()
            .map(|s| s.decoder.clone())
            .collect::<Vec<String>>()
            .join(" -> ");
        chain.push(format!("deobfuscated via {decoders}"));
    } else {
        chain.push("deobfuscated".to_owned());
    }
    chain.push("decompiled".to_owned());
    chain
}

#[must_use]
pub fn looks_obfuscated(bytes: &[u8]) -> bool {
    let head: &[u8] = &bytes[..bytes.len().min(65_536)];
    let Ok(text): Result<&str, _> = std::str::from_utf8(head) else {
        return true;
    };
    if text.contains("exec(") || text.contains("eval(") {
        return true;
    }
    let longest_line: usize = text.lines().map(str::len).max().unwrap_or(0);
    if longest_line > 2_000 {
        return true;
    }
    let long_literal: bool = text
        .split(['\'', '"'])
        .any(|seg: &str| seg.len() > 1_000 && is_mostly_token(seg));
    long_literal
}

fn is_mostly_token(seg: &str) -> bool {
    if seg.is_empty() {
        return false;
    }
    let token: usize = seg
        .bytes()
        .filter(|b: &u8| {
            b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'\\' | b'x' | b'_')
        })
        .count();
    token * 100 >= seg.len() * 95
}

#[must_use]
pub fn unidentified_guidance(bytes: &[u8]) -> String {
    let mut out: String = String::new();
    if looks_obfuscated(bytes) {
        out.push_str(
            "This input looks obfuscated, but disrobe could not confidently identify the obfuscator.\n",
        );
    } else {
        out.push_str(
            "disrobe could not identify a known Python obfuscator (and the input is not a decompilable .pyc).\n",
        );
    }
    out.push_str("disrobe currently supports these Python obfuscators:\n");
    for entry in supported_obfuscators() {
        out.push_str("  - ");
        out.push_str(entry.display_name);
        if entry.aliases.is_empty() {
            out.push('\n');
        } else {
            out.push_str(" (aka ");
            out.push_str(&entry.aliases.join(", "));
            out.push_str(")\n");
        }
    }
    out.push_str("plus generic exec/eval droppers and marshal/base64/zlib/lzma packers.\n");
    out.push('\n');
    out.push_str(
        "If you know which obfuscator produced this file, tell us so we can prioritise it.\n",
    );
    out.push_str("To inspect or force the source-level peel pass, run:\n");
    out.push_str("  disrobe py deob <input> --out <output.py>\n");
    out.push_str("List the supported obfuscators any time with:\n");
    out.push_str("  disrobe py deob --list\n");
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn supported_list_covers_all_registered_passes() {
        let supported: Vec<SupportedObfuscator> = supported_obfuscators();
        assert_eq!(supported.len(), iter_passes().len());
        for entry in &supported {
            assert!(
                !entry.display_name.is_empty(),
                "{:?} has empty display name",
                entry.id
            );
        }
    }

    #[test]
    fn guidance_lists_known_obfuscators_and_command() {
        let guidance: String = unidentified_guidance(b"def foo():\n    return 1\n");
        assert!(guidance.contains("BlankOBF"));
        assert!(guidance.contains("Kramer"));
        assert!(guidance.contains("disrobe py deob"));
        assert!(guidance.contains("--list"));
    }

    #[test]
    fn clean_plain_source_is_not_flagged_obfuscated() {
        assert!(!looks_obfuscated(b"def foo(x):\n    return x + 1\n"));
    }

    #[test]
    fn exec_dropper_is_flagged_obfuscated() {
        assert!(looks_obfuscated(
            b"exec(__import__('base64').b64decode(b'aaaa'))\n"
        ));
    }

    #[test]
    fn unidentified_route_on_garbage_yields_guidance() {
        let outcome: AutoDeobOutcome = auto_deobfuscate(&[0x00u8, 0x01, 0x02, 0x03, 0x99], None);
        assert_eq!(outcome.kind, RouteKind::Unidentified);
        let guidance: String = outcome.guidance.expect("guidance present");
        assert!(guidance.contains("supports these Python obfuscators"));
        assert!(outcome.source.is_none());
    }
}
