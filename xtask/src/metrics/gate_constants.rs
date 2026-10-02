use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail, eyre};

use super::{MetricSources, MetricValue, PY_BANDS, Spec, group_thousands, spec_for};
use crate::fileio::read_text_bounded;

const MAX_GATE_BYTES: u64 = 8 * 1024 * 1024;
const PINNED_GATE: &str = "crates/disrobe-pass-py-decompile/tests/arbitrary_recompile_gate.rs";
const FULL_GATE: &str = "crates/disrobe-pass-py-decompile/tests/full_stdlib_recompile_gate.rs";

const GATE_CONSTANTS: [(&str, &str, &str); 10] = [
    (
        PINNED_GATE,
        "OBJECT_PCT_FLOOR",
        "py_stdlib_pinned_floor_pct",
    ),
    (
        PINNED_GATE,
        "MODULES_EXACT_FLOOR",
        "py_stdlib_pinned_modules_exact",
    ),
    (
        PINNED_GATE,
        "PINNED_MODULE_COUNT",
        "py_stdlib_pinned_modules",
    ),
    (FULL_GATE, "FULL_MODULES", "py_stdlib_full_modules"),
    (FULL_GATE, "FULL_CODE_OBJECTS", "py_stdlib_full_objects"),
    (
        FULL_GATE,
        "FULL_OBJECTS_OK_FLOOR",
        "py_stdlib_full_objects_ok",
    ),
    (FULL_GATE, "FULL_OBJECT_PCT_FLOOR", "py_stdlib_full_pct"),
    (FULL_GATE, "PINNED_MODULES", "py_stdlib_pinned_modules"),
    (FULL_GATE, "PINNED_CODE_OBJECTS", "py_stdlib_pinned_objects"),
    (
        FULL_GATE,
        "PINNED_OBJECTS_OK",
        "py_stdlib_pinned_objects_ok",
    ),
];

const BAND_GATE_CONSTANTS: [(&str, &str); 4] = [
    ("OBJECT_PCT_FLOOR", "_pct"),
    ("BAND_OBJECTS_OK", "_objects_ok"),
    ("BAND_CODE_OBJECTS", "_objects"),
    ("BAND_MODULES", "_modules"),
];

#[derive(Debug, PartialEq, Eq)]
struct GateConstant {
    constant: &'static str,
    key: String,
}

fn registry() -> BTreeMap<&'static str, Vec<GateConstant>> {
    let mut gates: BTreeMap<&'static str, Vec<GateConstant>> = BTreeMap::new();
    for (path, constant, key) in GATE_CONSTANTS {
        gates.entry(path).or_default().push(GateConstant {
            constant,
            key: key.to_owned(),
        });
    }
    for band in PY_BANDS {
        let Some(path): Option<&'static str> = band.gate else {
            continue;
        };
        for (constant, suffix) in BAND_GATE_CONSTANTS {
            gates.entry(path).or_default().push(GateConstant {
                constant,
                key: format!("{}{suffix}", band.stem),
            });
        }
    }
    gates
}

#[derive(Debug, PartialEq, Eq)]
struct ConstantSite<'src> {
    declared_type: &'src str,
    literal: &'src str,
    literal_start: usize,
}

fn locate<'src>(text: &'src str, constant: &str) -> Result<ConstantSite<'src>> {
    let mut found: Vec<ConstantSite<'src>> = Vec::new();
    let mut offset: usize = 0;
    for line in text.split_inclusive('\n') {
        let line_start: usize = offset;
        offset += line.len();
        let Some(declaration): Option<&str> = line
            .trim_start()
            .strip_prefix("const ")
            .and_then(|rest: &str| rest.strip_prefix(constant))
            .and_then(|rest: &str| rest.strip_prefix(':'))
        else {
            continue;
        };
        let Some((declared_type, assigned)): Option<(&str, &str)> = declaration.split_once(" = ")
        else {
            bail!("`const {constant}` is not declared as `const {constant}: <type> = <literal>;`");
        };
        let Some((literal, tail)): Option<(&str, &str)> = assigned.split_once(';') else {
            bail!("`const {constant}` does not end its literal with `;` on the declaring line");
        };
        if !tail.trim().is_empty() || literal.trim() != literal || literal.is_empty() {
            bail!(
                "`const {constant}` carries `{}` after its type, which is not one literal alone on \
                 its line",
                assigned.trim_end()
            );
        }
        found.push(ConstantSite {
            declared_type: declared_type.trim(),
            literal,
            literal_start: line_start + (line.len() - assigned.len()),
        });
    }
    match found.len() {
        1 => found
            .pop()
            .ok_or_else(|| eyre!("`const {constant}` vanished while it was being read")),
        0 => bail!("no `const {constant}` is declared"),
        count => bail!("`const {constant}` is declared {count} times"),
    }
}

fn rust_literal(value: MetricValue, declared_type: &str) -> Result<String> {
    match (declared_type, value) {
        ("f64", MetricValue::Percent(percent)) => Ok(format!("{percent:?}")),
        ("u64", MetricValue::Int(count)) => Ok(group_thousands(count).replace(',', "_")),
        (declared, other) => {
            bail!("a `{declared}` constant cannot carry the metric value {other:?}")
        }
    }
}

fn expected_literal(
    sources: &MetricSources,
    site: &ConstantSite<'_>,
    constant: &GateConstant,
) -> Result<String> {
    let spec: Spec =
        spec_for(&constant.key).ok_or_else(|| eyre!("`{}` names no metric key", constant.key))?;
    let value: MetricValue = spec
        .value(sources)
        .wrap_err_with(|| format!("extracting metric `{}`", constant.key))?;
    rust_literal(value, site.declared_type).wrap_err_with(|| {
        format!(
            "rendering `m:{}` into `{}`",
            constant.key, constant.constant
        )
    })
}

fn render_gate(text: &str, sources: &MetricSources, constants: &[GateConstant]) -> Result<String> {
    let mut rendered: String = text.to_owned();
    for constant in constants {
        let site: ConstantSite<'_> = locate(&rendered, constant.constant)?;
        let literal: String = expected_literal(sources, &site, constant)?;
        let start: usize = site.literal_start;
        let end: usize = start + site.literal.len();
        rendered.replace_range(start..end, &literal);
    }
    Ok(rendered)
}

pub(super) fn write(root: &Path, sources: &MetricSources) -> Result<usize> {
    let mut rewritten: usize = 0;
    for (path, constants) in registry() {
        let full: PathBuf = root.join(path);
        let text: String = read_text_bounded(&full, MAX_GATE_BYTES)
            .wrap_err_with(|| format!("reading gate {path}"))?;
        let rendered: String = render_gate(&text, sources, &constants)
            .wrap_err_with(|| format!("rendering the published constants of {path}"))?;
        if rendered != text {
            std::fs::write(&full, &rendered).wrap_err_with(|| format!("writing gate {path}"))?;
            rewritten += 1;
        }
    }
    Ok(rewritten)
}

pub(super) fn check(root: &Path, sources: &MetricSources, issues: &mut Vec<String>) -> Result<()> {
    for (path, constants) in registry() {
        let text: String = read_text_bounded(&root.join(path), MAX_GATE_BYTES)
            .wrap_err_with(|| format!("reading gate {path}"))?;
        for constant in &constants {
            let site: ConstantSite<'_> = locate(&text, constant.constant)
                .wrap_err_with(|| format!("reading the published constants of {path}"))?;
            let expected: String = expected_literal(sources, &site, constant)?;
            if site.literal != expected {
                issues.push(format!(
                    "{path}: `const {}` is `{}` but xtask/data/recovery.json publishes `{expected}` \
                     through `m:{}`, so the gate enforces a figure the documents do not state",
                    constant.constant, site.literal, constant.key
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PINNED_LABEL: &str = "200-module pinned corpus (normalized opcode-structure agreement)";
    const MIRROR_LABEL: &str = "CPython 3.14 (all 200 pinned modules)";

    const PCT_COPIES: [&str; 7] = [
        "README.md",
        "docs/src/introduction.md",
        "docs/src/languages/python.md",
        "docs/src/python-bindings.md",
        "evidence/edge-comparison.md",
        "xtask/data/verification.json",
        PINNED_GATE,
    ];

    #[derive(Debug, Clone, Copy)]
    struct PinnedFigure {
        pct: f64,
        objects_ok: u64,
        objects: u64,
        modules_exact: u64,
    }

    impl PinnedFigure {
        fn published(recovery: &Path) -> Result<Self> {
            let doc: serde_json::Value =
                serde_json::from_str(&read_text_bounded(recovery, MAX_GATE_BYTES)?)?;
            let bar: &serde_json::Value = doc["groups"]
                .as_array()
                .ok_or_else(|| eyre!("recovery.json carries no groups array"))?
                .iter()
                .filter_map(|group: &serde_json::Value| group["bars"].as_array())
                .flatten()
                .find(|bar: &&serde_json::Value| bar["label"].as_str() == Some(PINNED_LABEL))
                .ok_or_else(|| eyre!("recovery.json carries no `{PINNED_LABEL}` bar"))?;
            let field = |name: &str| -> Result<u64> {
                bar[name]
                    .as_u64()
                    .ok_or_else(|| eyre!("the pinned bar carries no integer `{name}`"))
            };
            Ok(Self {
                pct: bar["value"]
                    .as_f64()
                    .ok_or_else(|| eyre!("the pinned bar carries no `value`"))?,
                objects_ok: field("num")?,
                objects: field("den")?,
                modules_exact: field("modules_exact")?,
            })
        }

        fn raised(self) -> Result<Self> {
            let current: String = self.pct.to_string();
            for objects_ok in self.objects_ok + 1..self.objects {
                let hundredths: u32 = u32::try_from(objects_ok * 10_000 / self.objects)?;
                let pct: f64 = f64::from(hundredths) / 100.0;
                if !hundredths.is_multiple_of(10)
                    && pct > self.pct
                    && !pct.to_string().contains(&current)
                {
                    return Ok(Self {
                        pct,
                        objects_ok,
                        objects: self.objects,
                        modules_exact: self.modules_exact + 1,
                    });
                }
            }
            bail!("no raised figure fits above {current} of {}", self.objects)
        }

        fn raised_sites(self) -> [(&'static str, String); 9] {
            let Self {
                pct,
                objects_ok,
                objects,
                modules_exact,
            } = self;
            let grouped: String = group_thousands(objects_ok).replace(',', "_");
            [
                (
                    "docs/src/languages/python.md",
                    format!(
                        "with a <!-- m:py_stdlib_pinned_floor_pct -->{pct}%<!-- /m --> regression threshold"
                    ),
                ),
                (
                    "docs/src/python-bindings.md",
                    format!(
                        "regression threshold <!-- m:py_stdlib_pinned_floor_pct -->{pct}%<!-- /m -->"
                    ),
                ),
                (
                    "docs/src/introduction.md",
                    format!(
                        "<!-- m:py_stdlib_pinned_modules_exact -->{modules_exact}<!-- /m --> of"
                    ),
                ),
                (
                    "README.md",
                    format!(
                        "<!-- m:py_stdlib_pinned_count -->{objects_ok} of {objects}<!-- /m -->"
                    ),
                ),
                (
                    "xtask/data/verification.json",
                    format!("<!-- m:py_stdlib_pinned_pct -->{pct}%<!-- /m --> of"),
                ),
                (
                    "xtask/data/verification.json",
                    format!(
                        "code-object floor <!-- m:py_stdlib_pinned_floor_pct -->{pct}%<!-- /m -->"
                    ),
                ),
                (PINNED_GATE, format!("const OBJECT_PCT_FLOOR: f64 = {pct};")),
                (
                    PINNED_GATE,
                    format!("const MODULES_EXACT_FLOOR: u64 = {modules_exact};"),
                ),
                (
                    FULL_GATE,
                    format!("const PINNED_OBJECTS_OK: u64 = {grouped};"),
                ),
            ]
        }
    }

    fn raise(bar: &mut serde_json::Value, fields: &[(&str, serde_json::Value)]) {
        for (field, value) in fields {
            bar[*field] = value.clone();
        }
    }

    fn raise_pinned_figure(recovery: &Path, figure: PinnedFigure) -> Result<()> {
        let mut doc: serde_json::Value =
            serde_json::from_str(&read_text_bounded(recovery, MAX_GATE_BYTES)?)?;
        let groups: &mut Vec<serde_json::Value> = doc["groups"]
            .as_array_mut()
            .ok_or_else(|| eyre!("recovery.json carries no groups array"))?;
        let mut raised: usize = 0;
        for bar in groups
            .iter_mut()
            .filter_map(|group: &mut serde_json::Value| group["bars"].as_array_mut())
            .flatten()
        {
            let label: Option<&str> = bar["label"].as_str();
            if label == Some(PINNED_LABEL) {
                raise(
                    bar,
                    &[
                        ("value", serde_json::json!(figure.pct)),
                        ("num", serde_json::json!(figure.objects_ok)),
                        ("floor_pct", serde_json::json!(figure.pct)),
                        ("modules_exact", serde_json::json!(figure.modules_exact)),
                    ],
                );
                raised += 1;
            } else if label == Some(MIRROR_LABEL) {
                raise(
                    bar,
                    &[
                        ("value", serde_json::json!(figure.pct)),
                        ("num", serde_json::json!(figure.objects_ok)),
                    ],
                );
                raised += 1;
            }
        }
        assert_eq!(
            raised, 2,
            "the pinned bar and its band mirror must both be raised"
        );
        std::fs::write(recovery, serde_json::to_string_pretty(&doc)?)?;
        Ok(())
    }

    fn copy_into(repo: &Path, scratch: &Path, relative: &str) -> Result<()> {
        let target: PathBuf = scratch.join(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(repo.join(relative), &target)
            .wrap_err_with(|| format!("copying {relative}"))?;
        Ok(())
    }

    #[test]
    fn a_raised_pinned_figure_reaches_every_published_copy() -> Result<()> {
        let repo: PathBuf = crate::workspace_root()?;
        let scratch: tempfile::TempDir = tempfile::tempdir()?;
        let copy: &Path = scratch.path();
        copy_into(&repo, copy, "xtask/data/recovery.json")?;
        for (gate, _) in registry() {
            copy_into(&repo, copy, gate)?;
        }
        let published: PinnedFigure =
            PinnedFigure::published(&copy.join("xtask/data/recovery.json"))?;
        let raised: PinnedFigure = published.raised()?;
        let current_pct: String = published.pct.to_string();
        let current_objects: String = group_thousands(published.objects_ok).replace(',', "_");
        let published_copies: Vec<(&str, &str)> = PCT_COPIES
            .iter()
            .map(|relative: &&str| (*relative, current_pct.as_str()))
            .chain(std::iter::once((FULL_GATE, current_objects.as_str())))
            .collect();
        for &(relative, current) in &published_copies {
            copy_into(&repo, copy, relative)?;
            let text: String = read_text_bounded(&copy.join(relative), MAX_GATE_BYTES)?;
            assert!(
                text.contains(current),
                "{relative} no longer states `{current}`, so this test would pass without \
                 rendering anything into it"
            );
        }
        raise_pinned_figure(&copy.join("xtask/data/recovery.json"), raised)?;

        let sources: MetricSources = MetricSources {
            recovery: super::super::load_recovery(copy)?,
            catalog: crate::catalog_counts::sample_tables(),
        };
        super::super::write_published(copy, &sources)?;

        for &(relative, stale) in &published_copies {
            let text: String = read_text_bounded(&copy.join(relative), MAX_GATE_BYTES)?;
            assert!(
                !text.contains(stale),
                "{relative} still states `{stale}` after the pinned figure moved, so one copy of \
                 it is written by hand or skipped by the generator"
            );
        }
        for (relative, expected) in raised.raised_sites() {
            let text: String = read_text_bounded(&copy.join(relative), MAX_GATE_BYTES)?;
            assert!(
                text.contains(&expected),
                "{relative} does not state `{expected}` after the pinned figure moved"
            );
        }
        Ok(())
    }

    #[test]
    fn every_registered_constant_names_a_metric_key() -> Result<()> {
        let repo: PathBuf = crate::workspace_root()?;
        for (path, constants) in registry() {
            assert!(repo.join(path).is_file(), "{path} is not a gate file");
            for constant in constants {
                assert!(
                    spec_for(&constant.key).is_some(),
                    "{path} `{}` names the unknown metric key `{}`",
                    constant.constant,
                    constant.key
                );
            }
        }
        Ok(())
    }

    #[test]
    fn a_declared_constant_is_located_once_with_its_type_and_literal() -> Result<()> {
        let text: &str = "const A: u64 = 1;\nconst OBJECT_PCT_FLOOR: f64 = 96.83;\n";
        let site: ConstantSite<'_> = locate(text, "OBJECT_PCT_FLOOR")?;
        assert_eq!(site.declared_type, "f64");
        assert_eq!(site.literal, "96.83");
        assert_eq!(
            text.get(site.literal_start..site.literal_start + site.literal.len()),
            Some("96.83")
        );
        assert!(locate(text, "OBJECT_PCT").is_err());
        assert!(locate("const B: u64 = 1; const C: u64 = 2;\n", "B").is_err());
        assert!(locate("const D: u64 = 1;\nconst D: u64 = 2;\n", "D").is_err());
        Ok(())
    }

    #[test]
    fn a_literal_keeps_the_type_and_grouping_the_gate_declares() -> Result<()> {
        assert_eq!(rust_literal(MetricValue::Percent(96.83), "f64")?, "96.83");
        assert_eq!(rust_literal(MetricValue::Percent(62.0), "f64")?, "62.0");
        assert_eq!(rust_literal(MetricValue::Int(200), "u64")?, "200");
        assert_eq!(rust_literal(MetricValue::Int(6087), "u64")?, "6_087");
        assert_eq!(rust_literal(MetricValue::Int(18_276), "u64")?, "18_276");
        assert!(rust_literal(MetricValue::Int(200), "f64").is_err());
        assert!(rust_literal(MetricValue::Percent(96.83), "u64").is_err());
        Ok(())
    }
}
