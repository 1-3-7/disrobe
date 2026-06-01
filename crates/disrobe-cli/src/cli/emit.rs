use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) enum EmitKind {
    Source,
    Disasm,
    Ast,
    Cfg,
    Ir,
    Manifest,
    Sourcemap,
    Symbols,
    Strings,
    Imports,
    Signatures,
    Report,
    Recovery,
}

impl EmitKind {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Disasm => "disasm",
            Self::Ast => "ast",
            Self::Cfg => "cfg",
            Self::Ir => "ir",
            Self::Manifest => "manifest",
            Self::Sourcemap => "sourcemap",
            Self::Symbols => "symbols",
            Self::Strings => "strings",
            Self::Imports => "imports",
            Self::Signatures => "signatures",
            Self::Report => "report",
            Self::Recovery => "recovery",
        }
    }

    pub(crate) const fn all() -> &'static [Self] {
        &[
            Self::Source,
            Self::Disasm,
            Self::Ast,
            Self::Cfg,
            Self::Ir,
            Self::Manifest,
            Self::Sourcemap,
            Self::Symbols,
            Self::Strings,
            Self::Imports,
            Self::Signatures,
            Self::Report,
            Self::Recovery,
        ]
    }

    pub(crate) fn parse(raw: &str) -> Option<Self> {
        Self::all()
            .iter()
            .copied()
            .find(|k| k.label().eq_ignore_ascii_case(raw.trim()))
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct EmitSpec {
    kinds: BTreeSet<EmitKind>,
}

impl EmitSpec {
    pub(crate) fn parse(values: &[String]) -> miette::Result<Self> {
        let mut kinds: BTreeSet<EmitKind> = BTreeSet::new();
        let mut unknown: Vec<String> = Vec::new();
        for raw in values {
            for piece in raw.split(',') {
                let piece: &str = piece.trim();
                if piece.is_empty() {
                    continue;
                }
                match EmitKind::parse(piece) {
                    Some(kind) => {
                        kinds.insert(kind);
                    }
                    None => unknown.push(piece.to_owned()),
                }
            }
        }
        if !unknown.is_empty() {
            let known: Vec<&'static str> = EmitKind::all().iter().map(|k| k.label()).collect();
            return Err(miette::miette!(
                "DR-CLI-0163: unknown emit kind(s) {unknown:?}; valid kinds: {known:?}"
            ));
        }
        Ok(Self { kinds })
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.kinds.is_empty()
    }

    #[inline]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn contains(&self, kind: EmitKind) -> bool {
        self.kinds.contains(&kind)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = EmitKind> + '_ {
        self.kinds.iter().copied()
    }
}

pub(crate) fn write_not_applicable_stub(
    out_dir: &Path,
    stem: &str,
    pass: &str,
    kind: EmitKind,
    reason: &str,
) -> miette::Result<PathBuf> {
    std::fs::create_dir_all(out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0160: cannot create emit dir: {e}"))?;
    let path: PathBuf = out_dir.join(format!("{stem}.{}.json", kind.label()));
    let payload: serde_json::Value = serde_json::json!({
        "schema": "disrobe.emit.stub/v0",
        "pass": pass,
        "emit_kind": kind.label(),
        "applicable": false,
        "reason": reason,
    });
    let bytes: Vec<u8> = serde_json::to_vec_pretty(&payload)
        .map_err(|e| miette::miette!("DR-CLI-0161: emit stub serialize: {e}"))?;
    std::fs::write(&path, bytes)
        .map_err(|e| miette::miette!("DR-CLI-0162: cannot write emit stub: {e}"))?;
    Ok(path)
}

#[cfg_attr(not(any(feature = "wasm", test)), allow(dead_code))]
pub(crate) fn write_applicable_payload<T: Serialize>(
    out_dir: &Path,
    stem: &str,
    kind: EmitKind,
    value: &T,
) -> miette::Result<PathBuf> {
    std::fs::create_dir_all(out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0160: cannot create emit dir: {e}"))?;
    let path: PathBuf = out_dir.join(format!("{stem}.{}.json", kind.label()));
    let bytes: Vec<u8> = serde_json::to_vec_pretty(value)
        .map_err(|e| miette::miette!("DR-CLI-0161: emit payload serialize: {e}"))?;
    std::fs::write(&path, bytes)
        .map_err(|e| miette::miette!("DR-CLI-0162: cannot write emit payload: {e}"))?;
    Ok(path)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_is_empty() {
        let spec: EmitSpec = EmitSpec::parse(&[]).expect("empty parses");
        assert!(spec.is_empty());
    }

    #[test]
    fn parse_csv_splits_correctly() {
        let raw: Vec<String> = vec!["source,disasm,ast".to_owned()];
        let spec: EmitSpec = EmitSpec::parse(&raw).expect("known kinds parse");
        assert!(spec.contains(EmitKind::Source));
        assert!(spec.contains(EmitKind::Disasm));
        assert!(spec.contains(EmitKind::Ast));
        assert!(!spec.contains(EmitKind::Cfg));
    }

    #[test]
    fn parse_case_insensitive() {
        let raw: Vec<String> = vec!["SOURCE".to_owned(), "Report".to_owned()];
        let spec: EmitSpec = EmitSpec::parse(&raw).expect("case-insensitive parse");
        assert!(spec.contains(EmitKind::Source));
        assert!(spec.contains(EmitKind::Report));
    }

    #[test]
    fn parse_rejects_unknown() {
        let raw: Vec<String> = vec!["source,nonsense,disasm".to_owned()];
        let err: miette::Report = EmitSpec::parse(&raw).expect_err("unknown kind must be rejected");
        let msg: String = format!("{err}");
        assert!(msg.contains("DR-CLI-0163"), "got: {msg}");
        assert!(msg.contains("nonsense"), "got: {msg}");
    }

    #[test]
    fn label_round_trip() {
        for k in EmitKind::all() {
            let parsed: EmitKind = EmitKind::parse(k.label()).expect("round-trip");
            assert_eq!(parsed, *k);
        }
    }
}
