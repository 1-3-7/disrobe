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

#[derive(Debug, Clone, Copy)]
enum MetricValue {
    Int(u64),
    Ratio { num: u64, den: u64 },
    Percent(f64),
}

#[derive(Debug, Clone, Copy)]
enum Formatter {
    Int,
    Thousands,
    Pct,
    Frac,
    OfPlain,
    OfGrouped,
}

impl Formatter {
    fn render(self, value: MetricValue) -> Result<String> {
        match (self, value) {
            (Self::Int, MetricValue::Int(n)) => Ok(n.to_string()),
            (Self::Thousands, MetricValue::Int(n)) => Ok(group_thousands(n)),
            (Self::Pct, MetricValue::Percent(p)) => Ok(format_percent(p)),
            (Self::Frac, MetricValue::Ratio { num, den }) => Ok(format!("{num} / {den}")),
            (Self::OfPlain, MetricValue::Ratio { num, den }) => Ok(format!("{num} of {den}")),
            (Self::OfGrouped, MetricValue::Ratio { num, den }) => Ok(format!(
                "{} of {}",
                group_thousands(num),
                group_thousands(den)
            )),
            (formatter, other) => {
                bail!("formatter {formatter:?} cannot render metric value {other:?}")
            }
        }
    }
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

#[derive(Clone, Copy)]
enum Spec {
    Measured(&'static KeySpec),
    Catalog(&'static CatalogKeySpec),
}

impl Spec {
    const fn formatter(self) -> Formatter {
        match self {
            Self::Measured(spec) => spec.formatter,
            Self::Catalog(spec) => spec.formatter,
        }
    }

    fn value(self, sources: &MetricSources) -> Result<MetricValue> {
        match self {
            Self::Measured(spec) => (spec.extract)(&sources.recovery),
            Self::Catalog(spec) => (spec.extract)(&sources.catalog),
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
        name: "pyarmor_samples",
        formatter: Formatter::Int,
        nouns: &[],
        extract: |r: &Recovery| {
            Ok(MetricValue::Int(
                r.bar("Detection and extraction breadth", "PyArmor samples")?
                    .delivered()?,
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
            let bar: &Bar = r.bar("Detection and extraction breadth", "PyArmor samples")?;
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
}

fn collect_nouns() -> Vec<&'static str> {
    let mut nouns: Vec<&'static str> = Vec::new();
    for spec in KEYS {
        for noun in spec.nouns {
            if !nouns.contains(noun) {
                nouns.push(noun);
            }
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

fn group_thousands(value: u64) -> String {
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

    fn test_recovery() -> Result<Recovery> {
        let raw: &str = r#"{
            "groups": [
                {
                    "heading": "Detection and extraction breadth (counts, not percentages)",
                    "bars": [
                        {"label": "PyArmor samples", "detected": 72, "delivered": 72},
                        {"label": "Containers", "detected": 98, "delivered": 98}
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
                    "heading": "Python bytecode (CPython 3.14 stdlib)",
                    "bars": [
                        {"label": "full 574-module stdlib (representative)", "value": 92.43, "num": 16880, "den": 18262},
                        {"label": "200-module pinned corpus", "value": 94.18, "num": 6051, "den": 6286}
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
        assert_eq!(Formatter::OfPlain.render(plain)?, "6051 of 6286");
        assert_eq!(Formatter::OfGrouped.render(plain)?, "6,051 of 6,286");
        let full: MetricValue = recovery
            .bar("Python bytecode", "full 574-module stdlib (representative)")?
            .count_ratio()?;
        assert_eq!(Formatter::OfPlain.render(full)?, "16880 of 18262");
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
        let mut names: Vec<&'static str> = KEYS
            .iter()
            .map(|spec: &KeySpec| spec.name)
            .chain(CATALOG_KEYS.iter().map(|spec: &CatalogKeySpec| spec.name))
            .collect();
        let total: usize = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "duplicate metric key name");
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
