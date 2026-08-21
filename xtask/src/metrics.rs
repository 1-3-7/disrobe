use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail, eyre};
use serde::Deserialize;

use crate::catalog_counts::CatalogTables;
use crate::fileio::read_text_bounded;

const MAX_RECOVERY_JSON_BYTES: u64 = 4 * 1024 * 1024;
const MAX_DOC_BYTES: u64 = 8 * 1024 * 1024;

const OPEN_PREFIX: &str = "<!-- m:";
const OPEN_SUFFIX: &str = " -->";
const CLOSE: &str = "<!-- /m -->";
const IGNORE_MARKER: &str = "<!-- m:ignore -->";
const PYARMOR_STRUCTURAL_GROUP: &str = "PyArmor structural marshal coverage";
const PYARMOR_STRUCTURAL_BAR: &str = "v8/v9 default-trial wrappers";
const NATIVE_CFF_GROUP: &str = "OLLVM control-flow-flattening dispatcher cover";
const NATIVE_CFF_BAR: &str = "OLLVM -fla dispatcher states";
const PY_BAND_GROUP: &str = "Python bytecode by interpreter band";
const INTERPRETER_PREAMBLE: &str = "on CPython ";

#[derive(Debug, Clone, Copy)]
pub(crate) enum Mode {
    Write,
    Check,
}

#[derive(Debug, Deserialize)]
struct Recovery {
    groups: Vec<Group>,
}

#[derive(Debug, Deserialize)]
struct Group {
    heading: String,
    bars: Vec<Bar>,
}

#[derive(Debug, Deserialize)]
struct Bar {
    label: String,
    #[serde(default)]
    value: Option<f64>,
    #[serde(default)]
    num: Option<u64>,
    #[serde(default)]
    den: Option<u64>,
    #[serde(default)]
    detected: Option<u64>,
    #[serde(default)]
    delivered: Option<u64>,
    #[serde(default)]
    modules: Option<u64>,
    #[serde(default)]
    floor_pct: Option<f64>,
    #[serde(default)]
    attested_num: Option<u64>,
    #[serde(default)]
    attested_den: Option<u64>,
    #[serde(default)]
    link_skipped_num: Option<u64>,
    #[serde(default)]
    link_skipped_den: Option<u64>,
    #[serde(default)]
    detail: Option<String>,
}

impl Recovery {
    fn bar(&self, heading_substr: &str, label: &str) -> Result<&Bar> {
        for group in &self.groups {
            if group.heading.contains(heading_substr) {
                for bar in &group.bars {
                    if bar.label == label {
                        return Ok(bar);
                    }
                }
            }
        }
        bail!("recovery.json has no bar `{label}` under a heading containing `{heading_substr}`")
    }

    fn band_bar(&self, label_prefix: &str) -> Result<&Bar> {
        let mut found: Option<&Bar> = None;
        for group in &self.groups {
            if !group.heading.contains(PY_BAND_GROUP) {
                continue;
            }
            for bar in &group.bars {
                if !bar.label.starts_with(label_prefix) {
                    continue;
                }
                if let Some(earlier) = found {
                    bail!(
                        "recovery.json publishes two bars under `{PY_BAND_GROUP}` whose labels \
                         start with `{label_prefix}`, `{}` and `{}`, so a marker keyed to that \
                         prefix cannot say which band it renders",
                        earlier.label,
                        bar.label
                    );
                }
                found = Some(bar);
            }
        }
        found.ok_or_else(|| {
            eyre!(
                "recovery.json publishes no bar under `{PY_BAND_GROUP}` whose label starts with \
                 `{label_prefix}`, so the documentation row keyed to that band would render \
                 nothing; publish the bar or remove the row"
            )
        })
    }
}

impl Bar {
    fn percent(&self) -> Result<MetricValue> {
        let raw: f64 = self
            .value
            .ok_or_else(|| eyre!("bar `{}` has no percent value", self.label))?;
        Ok(MetricValue::Percent(raw))
    }

    fn floor_percent(&self) -> Result<MetricValue> {
        let raw: f64 = self.floor_pct.ok_or_else(|| {
            eyre!(
                "bar `{}` publishes a floor in prose but carries no `floor_pct`, so the documents \
                 that state that floor are checked against nothing",
                self.label
            )
        })?;
        Ok(MetricValue::Percent(raw))
    }

    fn count(&self) -> Result<MetricValue> {
        let raw: f64 = self
            .value
            .ok_or_else(|| eyre!("bar `{}` has no count value", self.label))?;
        Ok(MetricValue::Int(f64_to_u64_exact(raw, &self.label)?))
    }

    fn count_ratio(&self) -> Result<MetricValue> {
        let num: u64 = self
            .num
            .ok_or_else(|| eyre!("bar `{}` has no `num` count", self.label))?;
        let den: u64 = self
            .den
            .ok_or_else(|| eyre!("bar `{}` has no `den` count", self.label))?;
        Ok(MetricValue::Ratio { num, den })
    }

    fn module_count(&self) -> Result<MetricValue> {
        let modules: u64 = self
            .modules
            .ok_or_else(|| eyre!("bar `{}` has no `modules` count", self.label))?;
        Ok(MetricValue::Int(modules))
    }

    fn label_module_count(&self) -> Result<MetricValue> {
        let inside: &str = self
            .label
            .split_once('(')
            .and_then(|(_, rest): (&str, &str)| rest.split_once(')'))
            .map(|(inside, _): (&str, &str)| inside)
            .ok_or_else(|| {
                eyre!(
                    "band bar `{}` carries no parenthesized module count, and an interpreter band \
                     has no `modules` field, so its label is the only place that count is \
                     published",
                    self.label
                )
            })?;
        let digits: &str = inside
            .split(|c: char| !c.is_ascii_digit())
            .find(|run: &&str| !run.is_empty())
            .ok_or_else(|| {
                eyre!(
                    "band bar `{}` states no module count between its parentheses",
                    self.label
                )
            })?;
        let modules: u64 = digits.parse::<u64>().wrap_err_with(|| {
            format!(
                "module count `{digits}` in band label `{}` does not parse",
                self.label
            )
        })?;
        Ok(MetricValue::Int(modules))
    }

    fn interpreter_release(&self) -> Result<MetricValue> {
        let detail: &str = self.detail.as_deref().ok_or_else(|| {
            eyre!(
                "band bar `{}` carries no `detail`, the only place it records the interpreter \
                 release its counts were measured on",
                self.label
            )
        })?;
        let after: &str = detail
            .split_once(INTERPRETER_PREAMBLE)
            .map(|(_, rest): (&str, &str)| rest)
            .ok_or_else(|| {
                eyre!(
                    "the `{}` detail never says `{INTERPRETER_PREAMBLE}<release>`, so the \
                     interpreter its counts were measured on cannot be rendered: {detail}",
                    self.label
                )
            })?;
        let release: &str = after
            .split_once(". ")
            .map_or(after, |(head, _): (&str, &str)| head)
            .trim_end_matches('.');
        if !release.starts_with(|c: char| c.is_ascii_digit())
            || release.contains(char::is_whitespace)
        {
            bail!(
                "the `{}` detail names `{release}` after `{INTERPRETER_PREAMBLE}`, which is not an \
                 interpreter release",
                self.label
            );
        }
        Ok(MetricValue::Text(release.to_owned()))
    }

    fn delivered(&self) -> Result<u64> {
        self.delivered
            .ok_or_else(|| eyre!("bar `{}` has no delivered count", self.label))
    }

    fn detected(&self) -> Result<u64> {
        self.detected
            .ok_or_else(|| eyre!("bar `{}` has no detected count", self.label))
    }

    fn numerator(&self) -> Result<u64> {
        self.num
            .ok_or_else(|| eyre!("bar `{}` has no `num` count", self.label))
    }

    fn denominator(&self) -> Result<u64> {
        self.den
            .ok_or_else(|| eyre!("bar `{}` has no `den` count", self.label))
    }

    fn attested_ratio(&self) -> Result<MetricValue> {
        let num: u64 = self
            .attested_num
            .ok_or_else(|| eyre!("bar `{}` has no `attested_num` count", self.label))?;
        let den: u64 = self
            .attested_den
            .ok_or_else(|| eyre!("bar `{}` has no `attested_den` count", self.label))?;
        Ok(MetricValue::Ratio { num, den })
    }

    fn link_skipped_ratio(&self) -> Result<MetricValue> {
        let num: u64 = self
            .link_skipped_num
            .ok_or_else(|| eyre!("bar `{}` has no `link_skipped_num` count", self.label))?;
        let den: u64 = self
            .link_skipped_den
            .ok_or_else(|| eyre!("bar `{}` has no `link_skipped_den` count", self.label))?;
        Ok(MetricValue::Ratio { num, den })
    }
}

#[derive(Debug, Clone)]
enum MetricValue {
    Int(u64),
    Ratio { num: u64, den: u64 },
    Percent(f64),
    Text(String),
}

#[derive(Debug, Clone, Copy)]
enum Formatter {
    Int,
    Thousands,
    Pct,
    DerivedPct,
    Frac,
    OfPlain,
    OfGrouped,
    Text,
}

impl Formatter {
    fn render(self, value: MetricValue) -> Result<String> {
        match (self, value) {
            (Self::Int, MetricValue::Int(n)) => Ok(n.to_string()),
            (Self::Thousands, MetricValue::Int(n)) => Ok(group_thousands(n)),
            (Self::Pct, MetricValue::Percent(p)) => Ok(format_percent(p)),
            (Self::DerivedPct, MetricValue::Ratio { num, den }) => derive_percent(num, den),
            (Self::Frac, MetricValue::Ratio { num, den }) => Ok(format!("{num} / {den}")),
            (Self::OfPlain, MetricValue::Ratio { num, den }) => Ok(format!("{num} of {den}")),
            (Self::OfGrouped, MetricValue::Ratio { num, den }) => Ok(format!(
                "{} of {}",
                group_thousands(num),
                group_thousands(den)
            )),
            (Self::Text, MetricValue::Text(text)) => Ok(text),
            (formatter, other) => {
                bail!("formatter {formatter:?} cannot render metric value {other:?}")
            }
        }
    }
}

fn derive_percent(num: u64, den: u64) -> Result<String> {
    if den == 0 {
        bail!("a rate derived from {num} over a zero denominator has no value");
    }
    let exact: f64 = (num as f64) * 100.0 / (den as f64);
    Ok(format!(
        "{:.2}%",
        exact.mul_add(100.0, 1e-9).floor() / 100.0
    ))
}

#[derive(Debug)]
struct MetricSources {
    recovery: Recovery,
    catalog: CatalogTables,
}

struct KeySpec {
    name: &'static str,
    formatter: Formatter,
    nouns: &'static [&'static str],
    extract: fn(&Recovery) -> Result<MetricValue>,
}

struct CatalogKeySpec {
    name: &'static str,
    formatter: Formatter,
    extract: fn(&CatalogTables) -> Result<MetricValue>,
}

#[derive(Debug)]
struct BandKeySpec {
    stem: &'static str,
    label_prefix: &'static str,
}

#[derive(Debug, Clone, Copy)]
enum BandFacet {
    Frac,
    Rate,
    Modules,
    Interpreter,
}

impl BandFacet {
    const SUFFIXES: [(&'static str, Self); 4] = [
        ("_frac", Self::Frac),
        ("_rate", Self::Rate),
        ("_modules", Self::Modules),
        ("_interpreter", Self::Interpreter),
    ];

    fn from_suffix(suffix: &str) -> Option<Self> {
        Self::SUFFIXES
            .iter()
            .copied()
            .find_map(|(text, facet): (&'static str, Self)| (text == suffix).then_some(facet))
    }

    const fn formatter(self) -> Formatter {
        match self {
            Self::Frac => Formatter::Frac,
            Self::Rate => Formatter::DerivedPct,
            Self::Modules => Formatter::Int,
            Self::Interpreter => Formatter::Text,
        }
    }

    const fn nouns(self) -> &'static [&'static str] {
        match self {
            Self::Modules => &["modules"],
            Self::Frac | Self::Rate | Self::Interpreter => &[],
        }
    }

    fn extract(self, bar: &Bar) -> Result<MetricValue> {
        match self {
            Self::Frac | Self::Rate => bar.count_ratio(),
            Self::Modules => bar.label_module_count(),
            Self::Interpreter => bar.interpreter_release(),
        }
    }
}

const PY_BANDS: &[BandKeySpec] = &[
    BandKeySpec {
        stem: "py_band_310",
        label_prefix: "CPython 3.10",
    },
    BandKeySpec {
        stem: "py_band_311",
        label_prefix: "CPython 3.11",
    },
    BandKeySpec {
        stem: "py_band_312",
        label_prefix: "CPython 3.12",
    },
    BandKeySpec {
        stem: "py_band_313",
        label_prefix: "CPython 3.13",
    },
    BandKeySpec {
        stem: "py_band_314",
        label_prefix: "CPython 3.14",
    },
    BandKeySpec {
        stem: "py_band_315",
        label_prefix: "CPython 3.15",
    },
];

#[derive(Clone, Copy)]
enum Spec {
    Measured(&'static KeySpec),
    Catalog(&'static CatalogKeySpec),
    Band(BandFacet, &'static BandKeySpec),
}

impl Spec {
    const fn formatter(self) -> Formatter {
        match self {
            Self::Measured(spec) => spec.formatter,
            Self::Catalog(spec) => spec.formatter,
            Self::Band(facet, _) => facet.formatter(),
        }
    }

    fn value(self, sources: &MetricSources) -> Result<MetricValue> {
        match self {
            Self::Measured(spec) => (spec.extract)(&sources.recovery),
            Self::Catalog(spec) => (spec.extract)(&sources.catalog),
            Self::Band(facet, spec) => facet.extract(sources.recovery.band_bar(spec.label_prefix)?),
        }
    }

    fn render(self, sources: &MetricSources, name: &str) -> Result<String> {
        let value: MetricValue = self
            .value(sources)
            .wrap_err_with(|| format!("extracting metric `{name}`"))?;
        self.formatter().render(value)
    }
}

fn catalog_int(value: usize) -> Result<MetricValue> {
    Ok(MetricValue::Int(u64::try_from(value).wrap_err_with(
        || format!("catalog count {value} does not fit in a u64"),
    )?))
}

const KEYS: &[KeySpec] = &[
    KeySpec {
        name: "py_stdlib_full_pct",
        formatter: Formatter::Pct,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar("Python bytecode", "full 574-module stdlib (representative)")?
                .percent()
        },
    },
    KeySpec {
        name: "py_stdlib_pinned_pct",
        formatter: Formatter::Pct,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar("Python bytecode", "200-module pinned corpus")?
                .percent()
        },
    },
    KeySpec {
        name: "py_stdlib_full_count",
        formatter: Formatter::OfPlain,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar("Python bytecode", "full 574-module stdlib (representative)")?
                .count_ratio()
        },
    },
    KeySpec {
        name: "py_stdlib_full_count_grouped",
        formatter: Formatter::OfGrouped,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar("Python bytecode", "full 574-module stdlib (representative)")?
                .count_ratio()
        },
    },
    KeySpec {
        name: "py_stdlib_full_modules",
        formatter: Formatter::Int,
        nouns: &["modules", "module corpus"],
        extract: |r: &Recovery| {
            r.bar("Python bytecode", "full 574-module stdlib (representative)")?
                .module_count()
        },
    },
    KeySpec {
        name: "py_stdlib_pinned_modules",
        formatter: Formatter::Int,
        nouns: &["modules", "module corpus"],
        extract: |r: &Recovery| {
            r.bar("Python bytecode", "200-module pinned corpus")?
                .module_count()
        },
    },
    KeySpec {
        name: "py_stdlib_pinned_count",
        formatter: Formatter::OfPlain,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar("Python bytecode", "200-module pinned corpus")?
                .count_ratio()
        },
    },
    KeySpec {
        name: "py_stdlib_pinned_count_grouped",
        formatter: Formatter::OfGrouped,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar("Python bytecode", "200-module pinned corpus")?
                .count_ratio()
        },
    },
    KeySpec {
        name: "py_legacy_count",
        formatter: Formatter::OfPlain,
        nouns: &[],
        extract: |r: &Recovery| r.bar("CPython legacy", "proven-correct")?.count_ratio(),
    },
    KeySpec {
        name: "py_legacy_frac",
        formatter: Formatter::Frac,
        nouns: &[],
        extract: |r: &Recovery| r.bar("CPython legacy", "proven-correct")?.count_ratio(),
    },
    KeySpec {
        name: "py_legacy_local_count",
        formatter: Formatter::OfPlain,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar(
                "CPython legacy",
                "proven-correct (local, full period interpreter set)",
            )?
            .count_ratio()
        },
    },
    KeySpec {
        name: "wasm_opcoverage_count",
        formatter: Formatter::OfPlain,
        nouns: &[],
        extract: |r: &Recovery| r.bar("WebAssembly", "op-coverage")?.count_ratio(),
    },
    KeySpec {
        name: "luau_opcode_lift_count",
        formatter: Formatter::OfPlain,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar("Luau opcode lifting", "Luau declared-table opcodes lifted")?
                .count_ratio()
        },
    },
    KeySpec {
        name: "jvm_per_method_count",
        formatter: Formatter::OfPlain,
        nouns: &[],
        extract: |r: &Recovery| r.bar("JVM classfile", "per-method")?.count_ratio(),
    },
    KeySpec {
        name: "go_typename_count",
        formatter: Formatter::OfPlain,
        nouns: &[],
        extract: |r: &Recovery| r.bar("Go type-name", "type names")?.count_ratio(),
    },
    KeySpec {
        name: "dalvik_verifier_count",
        formatter: Formatter::OfPlain,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar("Dalvik recovered bodies", "verifier-clean (committed, CI)")?
                .count_ratio()
        },
    },
    KeySpec {
        name: "dalvik_verifier_frac",
        formatter: Formatter::Frac,
        nouns: &["verifier-presented classes"],
        extract: |r: &Recovery| {
            r.bar("Dalvik recovered bodies", "verifier-clean (committed, CI)")?
                .count_ratio()
        },
    },
    KeySpec {
        name: "wasm_execution_frac",
        formatter: Formatter::Frac,
        nouns: &["eligible functions"],
        extract: |r: &Recovery| r.bar("WebAssembly", "execution-equivalence")?.count_ratio(),
    },
    KeySpec {
        name: "pickle_roundtrip_frac",
        formatter: Formatter::Frac,
        nouns: &["reconstructed fixtures"],
        extract: |r: &Recovery| {
            r.bar("Pickle corpus", "reconstruction roundtrip, re-executed")?
                .count_ratio()
        },
    },
    KeySpec {
        name: "beam_recompile_frac",
        formatter: Formatter::Frac,
        nouns: &["stripped Core Erlang cases"],
        extract: |r: &Recovery| {
            r.bar("BEAM stripped Core Erlang", "recompile-execution")?
                .count_ratio()
        },
    },
    KeySpec {
        name: "dalvik_link_skipped_count",
        formatter: Formatter::OfPlain,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar("Dalvik recovered bodies", "verifier-clean (committed, CI)")?
                .link_skipped_ratio()
        },
    },
    KeySpec {
        name: "hermes_opcoverage_count",
        formatter: Formatter::OfPlain,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar("React Native Hermes (committed", "op-coverage")?
                .count_ratio()
        },
    },
    KeySpec {
        name: "py_legacy_pct",
        formatter: Formatter::Pct,
        nouns: &[],
        extract: |r: &Recovery| r.bar("CPython legacy", "proven-correct")?.percent(),
    },
    KeySpec {
        name: "go_typename_pct",
        formatter: Formatter::Pct,
        nouns: &[],
        extract: |r: &Recovery| r.bar("Go type-name", "type names")?.floor_percent(),
    },
    KeySpec {
        name: "dalvik_verifier_pct",
        formatter: Formatter::Pct,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar("Dalvik recovered bodies", "verifier-clean (committed, CI)")?
                .percent()
        },
    },
    KeySpec {
        name: "dalvik_body_attested_frac",
        formatter: Formatter::OfPlain,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar(
                "Dalvik recovered bodies",
                "body-lowering (real apks, local)",
            )?
            .attested_ratio()
        },
    },
    KeySpec {
        name: "dalvik_body_frac",
        formatter: Formatter::Frac,
        nouns: &[],
        extract: |r: &Recovery| {
            let bar: &Bar = r.bar(
                "Dalvik recovered bodies",
                "body-lowering (real apks, local)",
            )?;
            Ok(MetricValue::Ratio {
                num: bar.numerator()?,
                den: bar.denominator()?,
            })
        },
    },
    KeySpec {
        name: "dalvik_body_pct",
        formatter: Formatter::Pct,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar(
                "Dalvik recovered bodies",
                "body-lowering (real apks, local)",
            )?
            .percent()
        },
    },
    KeySpec {
        name: "ruby_greeter_pct",
        formatter: Formatter::Pct,
        nouns: &[],
        extract: |r: &Recovery| r.bar("Ruby YARV", "greeter")?.percent(),
    },
    KeySpec {
        name: "ruby_megafile_pct",
        formatter: Formatter::Pct,
        nouns: &[],
        extract: |r: &Recovery| r.bar("Ruby YARV", "megafile")?.percent(),
    },
    KeySpec {
        name: "dotnet_protectors",
        formatter: Formatter::Int,
        nouns: &["protectors", "protector"],
        extract: |r: &Recovery| {
            r.bar("Detection and routing rosters", ".NET protectors")?
                .count()
        },
    },
    KeySpec {
        name: "dotnet_obfuscar_hidden_strings",
        formatter: Formatter::Frac,
        nouns: &[],
        extract: |r: &Recovery| {
            let bar: &Bar = r.bar(
                "Dotnet protector sample recovery",
                "Obfuscar hidden strings",
            )?;
            Ok(MetricValue::Ratio {
                num: bar.numerator()?,
                den: bar.denominator()?,
            })
        },
    },
    KeySpec {
        name: "dotnet_smartassembly_resources",
        formatter: Formatter::Frac,
        nouns: &[],
        extract: |r: &Recovery| {
            let bar: &Bar = r.bar(
                "Dotnet protector sample recovery",
                "SmartAssembly embedded resources",
            )?;
            Ok(MetricValue::Ratio {
                num: bar.numerator()?,
                den: bar.denominator()?,
            })
        },
    },
    KeySpec {
        name: "pyarmor_samples",
        formatter: Formatter::Int,
        nouns: &[],
        extract: |r: &Recovery| {
            Ok(MetricValue::Int(
                r.bar(PYARMOR_STRUCTURAL_GROUP, PYARMOR_STRUCTURAL_BAR)?
                    .delivered()?,
            ))
        },
    },
    KeySpec {
        name: "native_cff_dispatcher_states",
        formatter: Formatter::Int,
        nouns: &[],
        extract: |r: &Recovery| {
            Ok(MetricValue::Int(
                r.bar(NATIVE_CFF_GROUP, NATIVE_CFF_BAR)?.detected()?,
            ))
        },
    },
    KeySpec {
        name: "native_cff_cover_states",
        formatter: Formatter::Int,
        nouns: &[],
        extract: |r: &Recovery| {
            Ok(MetricValue::Int(
                r.bar(NATIVE_CFF_GROUP, NATIVE_CFF_BAR)?.delivered()?,
            ))
        },
    },
    KeySpec {
        name: "py_source_obfuscators",
        formatter: Formatter::Int,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar("Detection and routing rosters", "Python source obfuscators")?
                .count()
        },
    },
    KeySpec {
        name: "jvm_families",
        formatter: Formatter::Int,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar("Detection and routing rosters", "JVM / Android families")?
                .count()
        },
    },
    KeySpec {
        name: "shell_families",
        formatter: Formatter::Int,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar("Detection and routing rosters", "Shell obfuscation modes")?
                .count()
        },
    },
    KeySpec {
        name: "pyarmor_frac",
        formatter: Formatter::Frac,
        nouns: &[],
        extract: |r: &Recovery| {
            let bar: &Bar = r.bar(PYARMOR_STRUCTURAL_GROUP, PYARMOR_STRUCTURAL_BAR)?;
            Ok(MetricValue::Ratio {
                num: bar.delivered()?,
                den: bar.detected()?,
            })
        },
    },
    KeySpec {
        name: "containers_formats",
        formatter: Formatter::Int,
        nouns: &["formats"],
        extract: |r: &Recovery| {
            Ok(MetricValue::Int(
                r.bar("Detection and extraction breadth", "Containers")?
                    .detected()?,
            ))
        },
    },
    KeySpec {
        name: "containers_frac",
        formatter: Formatter::Frac,
        nouns: &[],
        extract: |r: &Recovery| {
            let bar: &Bar = r.bar("Detection and extraction breadth", "Containers")?;
            Ok(MetricValue::Ratio {
                num: bar.delivered()?,
                den: bar.detected()?,
            })
        },
    },
    KeySpec {
        name: "js_bundlers",
        formatter: Formatter::Int,
        nouns: &["bundlers"],
        extract: |r: &Recovery| {
            r.bar("Obfuscator and bundler family coverage", "JS bundlers")?
                .count()
        },
    },
    KeySpec {
        name: "lua_catalog_entries",
        formatter: Formatter::Int,
        nouns: &["catalog entries"],
        extract: |r: &Recovery| {
            r.bar(
                "Obfuscator and bundler family coverage",
                "Lua chain catalog entries",
            )?
            .count()
        },
    },
    KeySpec {
        name: "wasm_direct_helpers",
        formatter: Formatter::Int,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar(
                "Obfuscator and bundler family coverage",
                "WASM direct transformation helper families",
            )?
            .count()
        },
    },
    KeySpec {
        name: "hermes_functions",
        formatter: Formatter::Thousands,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar(
                "React Native Hermes production-bundle parse scale",
                "functions parsed",
            )?
            .count()
        },
    },
    KeySpec {
        name: "flutter_rustdesk_function_boundaries",
        formatter: Formatter::Thousands,
        nouns: &[],
        extract: |r: &Recovery| {
            r.bar(
                "Flutter Dart AOT RAW static recovery on a real RustDesk",
                "function boundaries recovered",
            )?
            .count()
        },
    },
];

const CATALOG_KEYS: &[CatalogKeySpec] = &[
    CatalogKeySpec {
        name: "catalog_family_total",
        formatter: Formatter::Int,
        extract: |c: &CatalogTables| catalog_int(c.family_total),
    },
    CatalogKeySpec {
        name: "catalog_ecosystems",
        formatter: Formatter::Int,
        extract: |c: &CatalogTables| catalog_int(c.ecosystems),
    },
    CatalogKeySpec {
        name: "native_packer_variants",
        formatter: Formatter::Int,
        extract: |c: &CatalogTables| catalog_int(c.packer_variants),
    },
    CatalogKeySpec {
        name: "native_tier_implemented",
        formatter: Formatter::Int,
        extract: |c: &CatalogTables| catalog_int(c.native_tiers.implemented),
    },
    CatalogKeySpec {
        name: "native_tier_stub_eval_pending",
        formatter: Formatter::Int,
        extract: |c: &CatalogTables| catalog_int(c.native_tiers.stub_eval_pending),
    },
    CatalogKeySpec {
        name: "native_tier_grey_carve",
        formatter: Formatter::Int,
        extract: |c: &CatalogTables| catalog_int(c.native_tiers.grey_carve),
    },
    CatalogKeySpec {
        name: "native_tier_grey_detect_only",
        formatter: Formatter::Int,
        extract: |c: &CatalogTables| catalog_int(c.native_tiers.grey_detect_only),
    },
    CatalogKeySpec {
        name: "native_tier_delegated",
        formatter: Formatter::Int,
        extract: |c: &CatalogTables| catalog_int(c.native_tiers.delegated),
    },
    CatalogKeySpec {
        name: "native_catalog_entries",
        formatter: Formatter::Int,
        extract: |c: &CatalogTables| catalog_int(c.pass_count("native.packer-unpack")?),
    },
    CatalogKeySpec {
        name: "pyarmor_catalog_versions",
        formatter: Formatter::Int,
        extract: |c: &CatalogTables| catalog_int(c.pass_count("pyarmor.unpack")?),
    },
    CatalogKeySpec {
        name: "js_catalog_entries",
        formatter: Formatter::Int,
        extract: |c: &CatalogTables| catalog_int(c.pass_count("js.deob")?),
    },
    CatalogKeySpec {
        name: "wasm_catalog_entries",
        formatter: Formatter::Int,
        extract: |c: &CatalogTables| catalog_int(c.pass_count("wasm.deob")?),
    },
    CatalogKeySpec {
        name: "php_catalog_entries",
        formatter: Formatter::Int,
        extract: |c: &CatalogTables| catalog_int(c.pass_count("php.peel")?),
    },
    CatalogKeySpec {
        name: "lua_catalog_obfuscators",
        formatter: Formatter::Int,
        extract: |c: &CatalogTables| catalog_int(c.lua_obfuscators),
    },
    CatalogKeySpec {
        name: "lua_catalog_dialects",
        formatter: Formatter::Int,
        extract: |c: &CatalogTables| catalog_int(c.lua_dialects),
    },
    CatalogKeySpec {
        name: "rasp_vendors",
        formatter: Formatter::Int,
        extract: |c: &CatalogTables| catalog_int(c.rasp_vendors),
    },
];

fn band_spec_for(name: &str) -> Option<Spec> {
    PY_BANDS.iter().find_map(|spec: &'static BandKeySpec| {
        name.strip_prefix(spec.stem)
            .and_then(BandFacet::from_suffix)
            .map(|facet: BandFacet| Spec::Band(facet, spec))
    })
}

fn spec_for(name: &str) -> Option<Spec> {
    KEYS.iter()
        .find(|spec: &&KeySpec| spec.name == name)
        .map(Spec::Measured)
        .or_else(|| {
            CATALOG_KEYS
                .iter()
                .find(|spec: &&CatalogKeySpec| spec.name == name)
                .map(Spec::Catalog)
        })
        .or_else(|| band_spec_for(name))
}

fn collect_nouns() -> Vec<&'static str> {
    let mut nouns: Vec<&'static str> = Vec::new();
    let declared = KEYS
        .iter()
        .flat_map(|spec: &KeySpec| spec.nouns.iter().copied())
        .chain(
            BandFacet::SUFFIXES
                .iter()
                .flat_map(|(_, facet): &(&'static str, BandFacet)| facet.nouns().iter().copied()),
        );
    for noun in declared {
        if !nouns.contains(&noun) {
            nouns.push(noun);
        }
    }
    nouns.sort_unstable_by(|a: &&str, b: &&str| b.len().cmp(&a.len()).then(a.cmp(b)));
    nouns
}

#[derive(Debug)]
struct MarkerSpan {
    name: String,
    line: usize,
    content: String,
    content_start: usize,
    content_end: usize,
}

fn parse_spans(text: &str, suppressed: &mut Vec<usize>) -> Result<Vec<MarkerSpan>> {
    let mut spans: Vec<MarkerSpan> = Vec::new();
    let mut in_fence: bool = false;
    let mut offset: usize = 0;
    for (idx, line) in text.split_inclusive('\n').enumerate() {
        let line_no: usize = idx + 1;
        let trimmed: &str = line.trim_start();
        let is_fence_delim: bool = trimmed.starts_with("```") || trimmed.starts_with("~~~");
        scan_line(line, line_no, offset, in_fence, &mut spans, suppressed)?;
        if is_fence_delim {
            in_fence = !in_fence;
        }
        offset += line.len();
    }
    Ok(spans)
}

fn scan_line(
    line: &str,
    line_no: usize,
    line_offset: usize,
    in_fence: bool,
    spans: &mut Vec<MarkerSpan>,
    suppressed: &mut Vec<usize>,
) -> Result<()> {
    let mut search_from: usize = 0;
    while let Some(rel) = line[search_from..].find(OPEN_PREFIX) {
        let open_at: usize = search_from + rel;
        if line[open_at..].starts_with(IGNORE_MARKER) {
            if !suppressed.contains(&line_no) {
                suppressed.push(line_no);
            }
            search_from = open_at + IGNORE_MARKER.len();
            continue;
        }
        let after_prefix: usize = open_at + OPEN_PREFIX.len();
        let Some(suffix_rel) = line[after_prefix..].find(OPEN_SUFFIX) else {
            bail!(
                "line {line_no}: marker opening `{OPEN_PREFIX}` has no closing `{OPEN_SUFFIX}` on the same line (unclosed or multi-line span)"
            );
        };
        let key_name: &str = &line[after_prefix..after_prefix + suffix_rel];
        let content_from: usize = after_prefix + suffix_rel + OPEN_SUFFIX.len();
        let Some(close_rel) = line[content_from..].find(CLOSE) else {
            bail!(
                "line {line_no}: marker span for `m:{key_name}` has no `{CLOSE}` on the same line (unclosed or multi-line span)"
            );
        };
        let content_end: usize = content_from + close_rel;
        let content: &str = &line[content_from..content_end];
        if content.contains(OPEN_PREFIX) {
            bail!("line {line_no}: marker span for `m:{key_name}` contains a nested marker");
        }
        if in_fence {
            bail!("line {line_no}: marker `m:{key_name}` sits inside a fenced code block");
        }
        if spec_for(key_name).is_none() {
            bail!("line {line_no}: unknown metric key `m:{key_name}`");
        }
        spans.push(MarkerSpan {
            name: key_name.to_owned(),
            line: line_no,
            content: content.to_owned(),
            content_start: line_offset + content_from,
            content_end: line_offset + content_end,
        });
        search_from = content_end + CLOSE.len();
    }
    Ok(())
}

#[derive(Debug, Default)]
pub(crate) struct MarkerCoverage {
    pub(crate) spans: Vec<(usize, usize)>,
    pub(crate) suppressed_lines: Vec<usize>,
}

pub(crate) fn marker_coverage(text: &str) -> Result<MarkerCoverage> {
    let mut suppressed_lines: Vec<usize> = Vec::new();
    let spans: Vec<MarkerSpan> = parse_spans(text, &mut suppressed_lines)?;
    Ok(MarkerCoverage {
        spans: spans
            .iter()
            .map(|span: &MarkerSpan| (span.content_start, span.content_end))
            .collect(),
        suppressed_lines,
    })
}

fn rewrite_text(text: &str, sources: &MetricSources) -> Result<String> {
    let mut suppressed: Vec<usize> = Vec::new();
    let spans: Vec<MarkerSpan> = parse_spans(text, &mut suppressed)?;
    if spans.is_empty() {
        return Ok(text.to_owned());
    }
    let mut out: String = String::with_capacity(text.len());
    let mut cursor: usize = 0;
    for span in &spans {
        let Some(spec) = spec_for(&span.name) else {
            bail!("line {}: unknown metric key `m:{}`", span.line, span.name);
        };
        let rendered: String = spec.render(sources, &span.name)?;
        out.push_str(&text[cursor..span.content_start]);
        out.push_str(&rendered);
        cursor = span.content_end;
    }
    out.push_str(&text[cursor..]);
    Ok(out)
}

fn check_text(
    text: &str,
    sources: &MetricSources,
    label: &str,
    issues: &mut Vec<String>,
) -> Result<()> {
    let mut suppressed: Vec<usize> = Vec::new();
    let spans: Vec<MarkerSpan> = parse_spans(text, &mut suppressed)
        .wrap_err_with(|| format!("parsing marker spans in {label}"))?;
    for span in &spans {
        let Some(spec) = spec_for(&span.name) else {
            issues.push(format!(
                "{label}:{}: unknown metric key `m:{}`",
                span.line, span.name
            ));
            continue;
        };
        let expected: String = spec.render(sources, &span.name)?;
        if span.content != expected {
            issues.push(format!(
                "{label}:{}: marker `m:{}` expected `{expected}` found `{}`",
                span.line, span.name, span.content
            ));
        }
    }
    backstop(text, &spans, &suppressed, label, issues);
    Ok(())
}

fn backstop(
    text: &str,
    spans: &[MarkerSpan],
    suppressed: &[usize],
    label: &str,
    issues: &mut Vec<String>,
) {
    let nouns: Vec<&'static str> = collect_nouns();
    if nouns.is_empty() {
        return;
    }
    let bytes: &[u8] = text.as_bytes();
    let mut in_fence: bool = false;
    let mut offset: usize = 0;
    for (idx, line) in text.split_inclusive('\n').enumerate() {
        let line_no: usize = idx + 1;
        let trimmed: &str = line.trim_start();
        let is_fence_delim: bool = trimmed.starts_with("```") || trimmed.starts_with("~~~");
        if !in_fence && !is_fence_delim && !suppressed.contains(&line_no) {
            let tracked_line: bool = line.contains(OPEN_PREFIX);
            let scan: BackstopScan<'_> = BackstopScan {
                file_bytes: bytes,
                nouns: &nouns,
                spans,
                label,
            };
            scan_backstop_line(&scan, line, offset, line_no, tracked_line, issues);
        }
        if is_fence_delim {
            in_fence = !in_fence;
        }
        offset += line.len();
    }
}

struct BackstopScan<'doc> {
    file_bytes: &'doc [u8],
    nouns: &'doc [&'static str],
    spans: &'doc [MarkerSpan],
    label: &'doc str,
}

fn scan_backstop_line(
    scan: &BackstopScan<'_>,
    line: &str,
    line_offset: usize,
    line_no: usize,
    tracked_line: bool,
    issues: &mut Vec<String>,
) {
    let BackstopScan {
        file_bytes,
        nouns,
        spans,
        label,
    } = *scan;
    let raw: &[u8] = line.as_bytes();
    let mut idx: usize = 0;
    while idx < raw.len() {
        if !raw[idx].is_ascii_digit() {
            idx += 1;
            continue;
        }
        let start_abs: usize = line_offset + idx;
        if is_word_byte(prev_byte(file_bytes, start_abs)) {
            idx += 1;
            continue;
        }
        let mut end: usize = idx;
        while end < raw.len() && is_number_byte(raw[end]) {
            end += 1;
        }
        let mut noun_at: usize = end;
        while noun_at < raw.len() && (raw[noun_at] == b' ' || raw[noun_at] == b'\t') {
            noun_at += 1;
        }
        let covered: bool = spans.iter().any(|span: &MarkerSpan| {
            start_abs >= span.content_start && start_abs < span.content_end
        });
        if let Some(noun) = matching_noun(&line[noun_at..], nouns) {
            if !covered {
                let digits: &str = &line[idx..end];
                issues.push(format!(
                    "{label}:{line_no}: bare number `{digits}` before unit noun `{noun}` is not inside a marker span (wrap it in `{OPEN_PREFIX}KEY{OPEN_SUFFIX}...{CLOSE}` or add `{IGNORE_MARKER}` to the line)"
                ));
            }
        } else if tracked_line && !covered && denominator_follows(&line[end..]) {
            let digits: &str = &line[idx..end];
            issues.push(format!(
                "{label}:{line_no}: hand-typed fraction starting `{digits}` shares a line with a tracked metric but sits outside every marker span, which is how a fraction drifts out of step with the percentage beside it (wrap it in `{OPEN_PREFIX}KEY{OPEN_SUFFIX}...{CLOSE}` or add `{IGNORE_MARKER}` to the line)"
            ));
        }
        idx = end.max(idx + 1);
    }
}

fn denominator_follows(rest: &str) -> bool {
    let trimmed: &str = rest.trim_start_matches([' ', '\t']);
    let after_separator: &str = match trimmed.strip_prefix('/') {
        Some(tail) => tail,
        None => match trimmed.strip_prefix("of") {
            Some(tail) if tail.starts_with([' ', '\t']) => tail,
            _ => return false,
        },
    };
    after_separator
        .trim_start_matches([' ', '\t'])
        .starts_with(|c: char| c.is_ascii_digit())
}

fn matching_noun(rest: &str, nouns: &[&'static str]) -> Option<&'static str> {
    let rest_bytes: &[u8] = rest.as_bytes();
    for noun in nouns {
        if rest.starts_with(noun) {
            let after: Option<u8> = rest_bytes.get(noun.len()).copied();
            if !is_word_byte(after) {
                return Some(noun);
            }
        }
    }
    None
}

const fn prev_byte(bytes: &[u8], at: usize) -> Option<u8> {
    if at == 0 { None } else { Some(bytes[at - 1]) }
}

const fn is_word_byte(byte: Option<u8>) -> bool {
    match byte {
        Some(b) => b.is_ascii_alphanumeric() || b == b'_',
        None => false,
    }
}

const fn is_number_byte(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b',' | b'.' | b'/' | b'%')
}

pub(crate) fn format_percent(percent: f64) -> String {
    let raw: String = format!("{percent:.6}");
    let trimmed: &str = raw.trim_end_matches('0').trim_end_matches('.');
    format!("{trimmed}%")
}

pub(crate) fn group_thousands(value: u64) -> String {
    let digits: String = value.to_string();
    let len: usize = digits.len();
    let mut out: String = String::with_capacity(len + len / 3);
    for (idx, ch) in digits.chars().enumerate() {
        if idx > 0 && (len - idx).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

fn f64_to_u64_exact(value: f64, label: &str) -> Result<u64> {
    if !value.is_finite() || value < 0.0 || value.fract() > f64::EPSILON {
        bail!("bar `{label}` value {value} is not a non-negative integer");
    }
    Ok(value as u64)
}

const MARKER_TREE: [&str; 2] = ["docs", "src"];
const MARKER_FLAT: [&str; 1] = ["evidence"];

fn markdown_in(dir: &Path, recursive: bool) -> Result<Vec<PathBuf>> {
    if !dir.is_dir() {
        bail!(
            "{} is not a directory, so every marker it holds would go unchecked",
            dir.display()
        );
    }
    let depth: usize = if recursive { usize::MAX } else { 1 };
    let mut found: Vec<PathBuf> = Vec::new();
    for entry in walkdir::WalkDir::new(dir).max_depth(depth) {
        let dirent: walkdir::DirEntry =
            entry.wrap_err_with(|| format!("walking {}", dir.display()))?;
        let path: &Path = dirent.path();
        if path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("md") {
            found.push(path.to_path_buf());
        }
    }
    Ok(found)
}

fn manifest(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = vec![root.join("README.md")];
    let mut tree: PathBuf = root.to_path_buf();
    for part in MARKER_TREE {
        tree.push(part);
    }
    files.extend(markdown_in(&tree, true)?);
    let mut flat: PathBuf = root.to_path_buf();
    for part in MARKER_FLAT {
        flat.push(part);
    }
    files.extend(markdown_in(&flat, false)?);
    files.sort();
    Ok(files)
}

fn load_recovery(root: &Path) -> Result<Recovery> {
    let path: PathBuf = root.join("xtask").join("data").join("recovery.json");
    let raw: String = read_text_bounded(&path, MAX_RECOVERY_JSON_BYTES)
        .wrap_err_with(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&raw).wrap_err_with(|| format!("parsing {}", path.display()))
}

fn load_sources(root: &Path) -> Result<MetricSources> {
    Ok(MetricSources {
        recovery: load_recovery(root)?,
        catalog: crate::catalog_counts::tables(root)?,
    })
}

pub(crate) fn run(root: &Path, mode: Mode) -> Result<()> {
    let sources: MetricSources = load_sources(root)?;
    let files: Vec<PathBuf> = manifest(root)?;
    match mode {
        Mode::Write => {
            let mut rewritten: usize = 0;
            for path in &files {
                let text: String = read_text_bounded(path, MAX_DOC_BYTES)
                    .wrap_err_with(|| format!("reading {}", path.display()))?;
                let updated: String = rewrite_text(&text, &sources)
                    .wrap_err_with(|| format!("rewriting markers in {}", path.display()))?;
                if updated != text {
                    std::fs::write(path, &updated)
                        .wrap_err_with(|| format!("writing {}", path.display()))?;
                    rewritten += 1;
                }
            }
            println!(
                "xtask metrics: {rewritten} file(s) rewritten across {} manifest file(s) from \
                 xtask/data/recovery.json and the catalog tables the binary carries",
                files.len()
            );
            Ok(())
        }
        Mode::Check => {
            let mut issues: Vec<String> = Vec::new();
            for path in &files {
                let text: String = read_text_bounded(path, MAX_DOC_BYTES)
                    .wrap_err_with(|| format!("reading {}", path.display()))?;
                let label: String = display_label(root, path);
                check_text(&text, &sources, &label, &mut issues)?;
            }
            if issues.is_empty() {
                println!(
                    "xtask metrics --check: every marker span and unit-noun number across {} file(s) matches xtask/data/recovery.json and the catalog tables the binary carries",
                    files.len()
                );
                Ok(())
            } else {
                bail!(
                    "documentation metric markers are stale or bare; run `cargo run -p xtask -- metrics --write`:\n  {}",
                    issues.join("\n  ")
                )
            }
        }
    }
}

fn display_label(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn band_key_names() -> Vec<String> {
        let mut names: Vec<String> = Vec::with_capacity(PY_BANDS.len() * BandFacet::SUFFIXES.len());
        for spec in PY_BANDS {
            for (suffix, _) in BandFacet::SUFFIXES {
                names.push(format!("{}{suffix}", spec.stem));
            }
        }
        names
    }

    fn test_recovery() -> Result<Recovery> {
        let raw: &str = r#"{
            "groups": [
                {
                    "heading": "Detection and extraction breadth (counts, not percentages)",
                    "bars": [
                        {"label": "Containers", "detected": 98, "delivered": 98}
                    ]
                },
                {
                    "heading": "PyArmor structural marshal coverage",
                    "bars": [
                        {"label": "v8/v9 default-trial wrappers", "detected": 72, "delivered": 72}
                    ]
                },
                {
                    "heading": "Detection and routing rosters (counts)",
                    "bars": [
                        {"label": ".NET protectors", "value": 23},
                        {"label": "Python source obfuscators", "value": 20},
                        {"label": "JVM / Android families", "value": 10},
                        {"label": "Shell obfuscation modes", "value": 19}
                    ]
                },
                {
                    "heading": "Dotnet protector sample recovery",
                    "bars": [
                        {"label": "Obfuscar hidden strings", "value": 100.0, "num": 15, "den": 15},
                        {"label": "SmartAssembly embedded resources", "value": 100.0, "num": 1, "den": 1}
                    ]
                },
                {
                    "heading": "Python bytecode (CPython 3.14 stdlib)",
                    "bars": [
                        {"label": "full 574-module stdlib (representative)", "value": 92.43, "num": 16880, "den": 18262},
                        {"label": "200-module pinned corpus", "value": 94.18, "num": 6051, "den": 6286}
                    ]
                },
                {
                    "heading": "Python bytecode by interpreter band (same pinned module list)",
                    "bars": [
                        {
                            "label": "CPython 3.12 (177 of the pinned modules)",
                            "value": 95.42,
                            "num": 5400,
                            "den": 5659,
                            "detail": "5400 / 5659 code objects over 177 modules on CPython 3.12.13. 23 of the 200 pinned modules do not exist in this interpreter's Lib."
                        },
                        {
                            "label": "CPython 3.14 (all 200 pinned modules)",
                            "value": 96.6,
                            "num": 6072,
                            "den": 6286,
                            "detail": "6072 / 6286 code objects over 200 modules on CPython 3.14.5. 0 of the 200 pinned modules do not exist in this interpreter's Lib."
                        }
                    ]
                },
                {
                    "heading": "React Native Hermes production-bundle parse scale",
                    "bars": [
                        {"label": "functions parsed", "value": 122633}
                    ]
                },
                {
                    "heading": "Dalvik recovered bodies (committed dex corpus, real JVM verifier)",
                    "bars": [
                        {"label": "verifier-clean (committed, CI)", "value": 100.0, "num": 118, "den": 118, "link_skipped_num": 37, "link_skipped_den": 155}
                    ]
                }
            ]
        }"#;
        serde_json::from_str(raw).map_err(|err| eyre!("{err}"))
    }

    fn test_sources() -> Result<MetricSources> {
        Ok(MetricSources {
            recovery: test_recovery()?,
            catalog: crate::catalog_counts::sample_tables(),
        })
    }

    #[test]
    fn percent_formatter_strips_trailing_zeros() {
        assert_eq!(format_percent(92.43), "92.43%");
        assert_eq!(format_percent(94.18), "94.18%");
        assert_eq!(format_percent(92.5), "92.5%");
        assert_eq!(format_percent(85.0), "85%");
        assert_eq!(format_percent(100.0), "100%");
    }

    #[test]
    fn thousands_formatter_groups() {
        assert_eq!(group_thousands(122_633), "122,633");
        assert_eq!(group_thousands(98), "98");
        assert_eq!(group_thousands(1_000), "1,000");
    }

    #[test]
    fn of_formatters_render_the_pinned_count() -> Result<()> {
        let recovery: Recovery = test_recovery()?;
        let plain: MetricValue = recovery
            .bar("Python bytecode", "200-module pinned corpus")?
            .count_ratio()?;
        assert_eq!(Formatter::OfPlain.render(plain.clone())?, "6051 of 6286");
        assert_eq!(Formatter::OfGrouped.render(plain)?, "6,051 of 6,286");
        let full: MetricValue = recovery
            .bar("Python bytecode", "full 574-module stdlib (representative)")?
            .count_ratio()?;
        assert_eq!(Formatter::OfPlain.render(full.clone())?, "16880 of 18262");
        assert_eq!(Formatter::OfGrouped.render(full)?, "16,880 of 18,262");
        Ok(())
    }

    #[test]
    fn count_marker_is_a_fixpoint() -> Result<()> {
        let sources: MetricSources = test_sources()?;
        let source: &str = "pinned (<!-- m:py_stdlib_pinned_count -->0 of 0<!-- /m -->), \
             grouped (<!-- m:py_stdlib_pinned_count_grouped -->0 of 0<!-- /m --> code objects).\n";
        let once: String = rewrite_text(source, &sources)?;
        let twice: String = rewrite_text(&once, &sources)?;
        assert!(once.contains("-->6051 of 6286<!-- /m -->"));
        assert!(once.contains("-->6,051 of 6,286<!-- /m --> code objects"));
        assert_eq!(once, twice);
        Ok(())
    }

    #[test]
    fn dalvik_link_skipped_marker_renders_and_rejects_a_stale_value() -> Result<()> {
        let sources: MetricSources = test_sources()?;
        let stale: &str =
            "<!-- m:dalvik_link_skipped_count -->53 of 155<!-- /m --> classes are link-skipped.\n";
        let rewritten: String = rewrite_text(stale, &sources)?;
        assert_eq!(
            rewritten,
            "<!-- m:dalvik_link_skipped_count -->37 of 155<!-- /m --> classes are link-skipped.\n"
        );
        let mut issues: Vec<String> = Vec::new();
        check_text(stale, &sources, "fixture.md", &mut issues)?;
        assert_eq!(
            issues.len(),
            1,
            "expected one stale-marker issue: {issues:?}"
        );
        assert!(issues[0].contains("expected `37 of 155` found `53 of 155`"));
        Ok(())
    }

    #[test]
    fn write_is_a_fixpoint() -> Result<()> {
        let sources: MetricSources = test_sources()?;
        let source: &str = "we detect <!-- m:dotnet_protectors -->0<!-- /m --> protector families, \
             <!-- m:containers_frac -->1 / 1<!-- /m --> formats, and \
             <!-- m:hermes_functions -->0<!-- /m -->-function bundles.\n";
        let once: String = rewrite_text(source, &sources)?;
        let twice: String = rewrite_text(&once, &sources)?;
        assert!(once.contains("-->23<!-- /m --> protector families"));
        assert!(once.contains("-->98 / 98<!-- /m --> formats"));
        assert!(once.contains("-->122,633<!-- /m -->-function"));
        assert_eq!(once, twice);
        Ok(())
    }

    #[test]
    fn pyarmor_markers_render_the_structural_count_pair() -> Result<()> {
        let sources: MetricSources = test_sources()?;
        let source: &str = "PyArmor has <!-- m:pyarmor_samples -->0<!-- /m --> samples \
             (<!-- m:pyarmor_frac -->0 / 0<!-- /m -->).\n";
        let rendered: String = rewrite_text(source, &sources)?;
        assert_eq!(
            rendered,
            "PyArmor has <!-- m:pyarmor_samples -->72<!-- /m --> samples \
             (<!-- m:pyarmor_frac -->72 / 72<!-- /m -->).\n"
        );
        Ok(())
    }

    #[test]
    fn dotnet_protector_sample_markers_render_the_graded_ratios() -> Result<()> {
        let sources: MetricSources = test_sources()?;
        let source: &str = "Obfuscar <!-- m:dotnet_obfuscar_hidden_strings -->0 / 0<!-- /m -->; \
             SmartAssembly <!-- m:dotnet_smartassembly_resources -->0 / 0<!-- /m -->.\n";
        let rendered: String = rewrite_text(source, &sources)?;
        assert_eq!(
            rendered,
            "Obfuscar <!-- m:dotnet_obfuscar_hidden_strings -->15 / 15<!-- /m -->; \
             SmartAssembly <!-- m:dotnet_smartassembly_resources -->1 / 1<!-- /m -->.\n"
        );
        Ok(())
    }

    #[test]
    fn check_passes_after_write() -> Result<()> {
        let sources: MetricSources = test_sources()?;
        let source: &str =
            "we detect <!-- m:dotnet_protectors -->0<!-- /m --> protector families.\n";
        let written: String = rewrite_text(source, &sources)?;
        let mut issues: Vec<String> = Vec::new();
        check_text(&written, &sources, "fixture.md", &mut issues)?;
        assert!(issues.is_empty(), "unexpected issues: {issues:?}");
        Ok(())
    }

    #[test]
    fn catalog_keys_render_the_tables_the_binary_carries() -> Result<()> {
        let sources: MetricSources = test_sources()?;
        let source: &str = "carries <!-- m:native_packer_variants -->0<!-- /m --> variants \
             (<!-- m:native_tier_implemented -->0<!-- /m --> + \
             <!-- m:native_tier_delegated -->0<!-- /m -->), lists \
             <!-- m:native_catalog_entries -->0<!-- /m -->, reports \
             <!-- m:catalog_family_total -->0<!-- /m --> across \
             <!-- m:catalog_ecosystems -->0<!-- /m -->, with \
             <!-- m:rasp_vendors -->0<!-- /m --> and \
             <!-- m:lua_catalog_obfuscators -->0<!-- /m -->.\n";
        let once: String = rewrite_text(source, &sources)?;
        let twice: String = rewrite_text(&once, &sources)?;
        assert!(once.contains("carries <!-- m:native_packer_variants -->29<!-- /m --> variants"));
        assert!(once.contains("(<!-- m:native_tier_implemented -->12<!-- /m --> +"));
        assert!(once.contains("<!-- m:native_tier_delegated -->2<!-- /m -->), lists"));
        assert!(once.contains("<!-- m:native_catalog_entries -->27<!-- /m -->, reports"));
        assert!(once.contains("<!-- m:catalog_family_total -->169<!-- /m --> across"));
        assert!(once.contains("<!-- m:catalog_ecosystems -->15<!-- /m -->, with"));
        assert!(once.contains("<!-- m:rasp_vendors -->8<!-- /m --> and"));
        assert!(once.contains("<!-- m:lua_catalog_obfuscators -->14<!-- /m -->."));
        assert_eq!(once, twice);
        let mut issues: Vec<String> = Vec::new();
        check_text(&once, &sources, "fixture.md", &mut issues)?;
        assert!(issues.is_empty(), "unexpected issues: {issues:?}");
        Ok(())
    }

    #[test]
    fn a_key_name_is_claimed_by_exactly_one_registry() {
        let mut names: Vec<String> = KEYS
            .iter()
            .map(|spec: &KeySpec| spec.name.to_owned())
            .chain(
                CATALOG_KEYS
                    .iter()
                    .map(|spec: &CatalogKeySpec| spec.name.to_owned()),
            )
            .chain(band_key_names())
            .collect();
        let total: usize = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "duplicate metric key name");
    }

    #[test]
    fn every_band_key_resolves_to_its_own_band() -> Result<()> {
        for name in band_key_names() {
            let resolved: Spec =
                spec_for(&name).ok_or_else(|| eyre!("band key `{name}` resolves to no spec"))?;
            let Spec::Band(_, spec) = resolved else {
                bail!("band key `{name}` resolved outside the band registry");
            };
            assert!(
                name.starts_with(spec.stem),
                "band key `{name}` resolved to the `{}` band",
                spec.label_prefix
            );
        }
        Ok(())
    }

    #[test]
    fn a_band_marker_renders_the_fraction_and_derives_the_rate() -> Result<()> {
        let sources: MetricSources = test_sources()?;
        let source: &str = "3.12 recompiles <!-- m:py_band_312_frac -->0 / 0<!-- /m --> \
             (<!-- m:py_band_312_rate -->0%<!-- /m -->) over \
             <!-- m:py_band_312_modules -->0<!-- /m --> modules on CPython \
             <!-- m:py_band_312_interpreter -->0.0.0<!-- /m -->.\n";
        let once: String = rewrite_text(source, &sources)?;
        let twice: String = rewrite_text(&once, &sources)?;
        assert!(once.contains("-->5400 / 5659<!-- /m -->"));
        assert!(once.contains("-->95.42%<!-- /m -->"));
        assert!(once.contains("-->177<!-- /m --> modules"));
        assert!(once.contains("-->3.12.13<!-- /m -->"));
        assert_eq!(once, twice);
        let mut issues: Vec<String> = Vec::new();
        check_text(&once, &sources, "fixture.md", &mut issues)?;
        assert!(issues.is_empty(), "unexpected issues: {issues:?}");
        Ok(())
    }

    #[test]
    fn a_derived_band_rate_never_reads_the_stored_percentage() -> Result<()> {
        let sources: MetricSources = test_sources()?;
        let source: &str = "3.14 <!-- m:py_band_314_rate -->0%<!-- /m -->\n";
        let rendered: String = rewrite_text(source, &sources)?;
        assert!(
            rendered.contains("-->96.59%<!-- /m -->"),
            "the 3.14 band stores 96.6 and measures 6072 of 6286, so the marker must render the \
             rate cut from the fraction: {rendered}"
        );
        Ok(())
    }

    #[test]
    fn a_band_with_no_bar_fails_regeneration() -> Result<()> {
        let sources: MetricSources = test_sources()?;
        let source: &str = "3.15 recompiles <!-- m:py_band_315_frac -->0 / 0<!-- /m -->.\n";
        let failure: eyre::Report = rewrite_text(source, &sources)
            .err()
            .ok_or_else(|| eyre!("a band with no bar rendered an empty span instead of failing"))?;
        let text: String = format!("{failure:#}");
        assert!(
            text.contains("CPython 3.15"),
            "the failure must name the band that has no bar: {text}"
        );
        Ok(())
    }

    #[test]
    fn a_band_bar_with_no_module_count_in_its_label_fails() -> Result<()> {
        let bar: Bar = serde_json::from_str(
            r#"{"label": "CPython 3.12", "num": 1, "den": 2, "detail": "on CPython 3.12.13. x"}"#,
        )
        .map_err(|err: serde_json::Error| eyre!("{err}"))?;
        assert!(bar.label_module_count().is_err());
        Ok(())
    }

    #[test]
    fn a_band_detail_that_names_no_interpreter_fails() -> Result<()> {
        let bar: Bar = serde_json::from_str(
            r#"{"label": "CPython 3.12 (177 of the pinned modules)", "num": 1, "den": 2, "detail": "measured somewhere"}"#,
        )
        .map_err(|err: serde_json::Error| eyre!("{err}"))?;
        assert!(bar.interpreter_release().is_err());
        Ok(())
    }

    #[test]
    fn a_rate_derived_from_a_zero_denominator_fails() {
        assert!(derive_percent(0, 0).is_err());
        assert!(derive_percent(1, 0).is_err());
    }

    #[test]
    fn a_derived_rate_truncates_to_two_places() -> Result<()> {
        assert_eq!(derive_percent(5_170, 5_458)?, "94.72%");
        assert_eq!(derive_percent(6_072, 6_286)?, "96.59%");
        assert_eq!(derive_percent(6_219, 6_480)?, "95.97%");
        Ok(())
    }

    #[test]
    fn an_unregistered_catalog_pass_id_fails_loudly() -> Result<()> {
        let tables: CatalogTables = crate::catalog_counts::sample_tables();
        assert!(tables.pass_count("does.not.exist").is_err());
        assert_eq!(tables.pass_count("native.packer-unpack")?, 27);
        Ok(())
    }

    #[test]
    fn check_flags_a_bare_unit_noun_number() -> Result<()> {
        let sources: MetricSources = test_sources()?;
        let source: &str = "we detect 23 protectors here.\n";
        let mut issues: Vec<String> = Vec::new();
        check_text(source, &sources, "fixture.md", &mut issues)?;
        assert_eq!(
            issues.len(),
            1,
            "expected one bare-number issue: {issues:?}"
        );
        Ok(())
    }

    #[test]
    fn ignore_marker_suppresses_the_backstop() -> Result<()> {
        let sources: MetricSources = test_sources()?;
        let source: &str = "legacy note: 23 protectors from another era. <!-- m:ignore -->\n";
        let mut issues: Vec<String> = Vec::new();
        check_text(source, &sources, "fixture.md", &mut issues)?;
        assert!(issues.is_empty(), "ignore should suppress: {issues:?}");
        Ok(())
    }

    #[test]
    fn check_flags_a_stale_marker_value() -> Result<()> {
        let sources: MetricSources = test_sources()?;
        let source: &str = "detect <!-- m:dotnet_protectors -->21<!-- /m --> protectors.\n";
        let mut issues: Vec<String> = Vec::new();
        check_text(source, &sources, "fixture.md", &mut issues)?;
        assert_eq!(issues.len(), 1, "expected a stale-value issue: {issues:?}");
        assert!(issues[0].contains("expected `23` found `21`"));
        Ok(())
    }

    #[test]
    fn check_flags_a_stale_catalog_table_value() -> Result<()> {
        let sources: MetricSources = test_sources()?;
        let source: &str = "the tier holds <!-- m:native_tier_implemented -->11<!-- /m -->.\n";
        let mut issues: Vec<String> = Vec::new();
        check_text(source, &sources, "fixture.md", &mut issues)?;
        assert_eq!(issues.len(), 1, "expected a stale-value issue: {issues:?}");
        assert!(issues[0].contains("expected `12` found `11`"));
        Ok(())
    }

    #[test]
    fn unknown_key_is_rejected() {
        let mut suppressed: Vec<usize> = Vec::new();
        let result: Result<Vec<MarkerSpan>> =
            parse_spans("a <!-- m:not_a_key -->0<!-- /m --> b\n", &mut suppressed);
        assert!(result.is_err());
    }

    #[test]
    fn marker_inside_fence_is_rejected() {
        let mut suppressed: Vec<usize> = Vec::new();
        let source: &str = "```\n<!-- m:dotnet_protectors -->23<!-- /m -->\n```\n";
        let result: Result<Vec<MarkerSpan>> = parse_spans(source, &mut suppressed);
        assert!(result.is_err());
    }

    #[test]
    fn unclosed_span_is_rejected() {
        let mut suppressed: Vec<usize> = Vec::new();
        let result: Result<Vec<MarkerSpan>> = parse_spans(
            "a <!-- m:dotnet_protectors -->23 and no close\n",
            &mut suppressed,
        );
        assert!(result.is_err());
    }
}
