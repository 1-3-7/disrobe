use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use toml::Value;

use crate::oracle::{OracleKind, ResolvedFixture};
use crate::read_text_bounded;

const MAX_MANIFEST_FILES: usize = 4096;
const MAX_MANIFEST_TOML_BYTES: u64 = 1024 * 1024;
const MAX_DISCOVERED_RECOMPILE_PYC: usize = 4096;
const MAX_DISCOVERED_PACKED_PAIRS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleFixture {
    pub oracle: OracleKind,
    pub pass_under_test: String,
    pub fixture_id: String,
    pub input_rel: String,
    pub baseline_rel: Option<String>,
    pub baseline_sha256: Option<String>,
    pub expected_detection: Option<String>,
    pub byte_identical_floor_bp: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct ManifestIndex {
    fixtures: Vec<OracleFixture>,
    manifests_parsed: usize,
}

impl ManifestIndex {
    #[must_use]
    pub fn fixtures(&self) -> &[OracleFixture] {
        &self.fixtures
    }

    #[must_use]
    pub const fn manifests_parsed(&self) -> usize {
        self.manifests_parsed
    }

    #[must_use]
    pub fn by_kind(&self, kind: OracleKind) -> Vec<&OracleFixture> {
        self.fixtures
            .iter()
            .filter(|f: &&OracleFixture| f.oracle == kind)
            .collect()
    }

    #[must_use]
    pub fn build(corpus_root: &Path) -> Self {
        let mut fixtures: Vec<OracleFixture> = Vec::new();
        let mut manifests_parsed: usize = 0;
        let mut manifests_seen: usize = 0;
        for entry in walkdir::WalkDir::new(corpus_root)
            .into_iter()
            .filter_map(core::result::Result::ok)
        {
            let path: &Path = entry.path();
            let is_manifest: bool = path
                .file_name()
                .and_then(|n: &std::ffi::OsStr| n.to_str())
                .is_some_and(|n: &str| n == "MANIFEST.toml");
            if !is_manifest {
                continue;
            }
            if manifests_seen >= MAX_MANIFEST_FILES {
                break;
            }
            manifests_seen += 1;
            let Some(text): Option<String> = read_text_bounded(path, MAX_MANIFEST_TOML_BYTES)
            else {
                continue;
            };
            let Ok(value): Result<Value, toml::de::Error> = toml::from_str::<Value>(&text) else {
                continue;
            };
            manifests_parsed += 1;
            extract_fixtures(corpus_root, path, &value, &mut fixtures);
        }
        discover_recompile_pyc(corpus_root, &mut fixtures);
        discover_packed_pairs(corpus_root, &mut fixtures);
        fixtures.sort_by(|a: &OracleFixture, b: &OracleFixture| {
            (a.oracle, &a.pass_under_test, &a.fixture_id).cmp(&(
                b.oracle,
                &b.pass_under_test,
                &b.fixture_id,
            ))
        });
        fixtures.dedup();
        Self {
            fixtures,
            manifests_parsed,
        }
    }

    #[must_use]
    pub fn resolve(&self, corpus_root: &Path) -> Vec<ResolvedFixture> {
        self.fixtures
            .iter()
            .map(|f: &OracleFixture| ResolvedFixture {
                oracle: f.oracle,
                pass_under_test: f.pass_under_test.clone(),
                fixture_id: f.fixture_id.clone(),
                input_path: join_rel(corpus_root, &f.input_rel),
                input_rel: f.input_rel.clone(),
                baseline_path: f
                    .baseline_rel
                    .as_ref()
                    .map(|r: &String| join_rel(corpus_root, r)),
                baseline_rel: f.baseline_rel.clone(),
                baseline_sha256: f.baseline_sha256.clone(),
                expected_detection: f.expected_detection.clone(),
                byte_identical_floor_bp: f.byte_identical_floor_bp,
            })
            .collect()
    }
}

fn join_rel(corpus_root: &Path, rel: &str) -> PathBuf {
    rel.strip_prefix("corpus/")
        .map_or_else(|| corpus_root.join(rel), |s: &str| corpus_root.join(s))
}

fn manifest_category(corpus_root: &Path, manifest_path: &Path) -> String {
    manifest_path
        .parent()
        .and_then(|p: &Path| p.strip_prefix(corpus_root).ok())
        .map_or_else(String::new, |p: &Path| {
            p.to_string_lossy().replace('\\', "/")
        })
}

fn extract_fixtures(
    corpus_root: &Path,
    manifest_path: &Path,
    value: &Value,
    out: &mut Vec<OracleFixture>,
) {
    let category: String = manifest_category(corpus_root, manifest_path);
    match category.as_str() {
        "native/packers" => extract_native_packers(value, out),
        "python/obfuscators" => extract_python_obfuscators(value, out),
        "dotnet" | "jvm" | "beam" | "ruby" | "lua" | "php" | "shell" => {
            extract_detection_manifest(&category, value, out);
        }
        _ => {}
    }
}

fn extract_native_packers(value: &Value, out: &mut Vec<OracleFixture>) {
    let Some(packers): Option<&Vec<Value>> = value.get("packers").and_then(Value::as_array) else {
        return;
    };
    for packer in packers {
        let packer_name: String = packer
            .get("name")
            .and_then(Value::as_str)
            .map_or("unknown", |value: &str| value)
            .to_ascii_lowercase();
        let Some(runs): Option<&Vec<Value>> = packer.get("runs").and_then(Value::as_array) else {
            continue;
        };
        for run in runs {
            push_packer_run(&packer_name, run, out);
        }
    }
}

fn push_packer_run(packer_name: &str, run: &Value, out: &mut Vec<OracleFixture>) {
    let packed_rel: Option<&str> = run
        .get("packed_path")
        .and_then(Value::as_str)
        .filter(|s: &&str| !s.is_empty());
    let baseline_rel: Option<&str> = run
        .get("original_path")
        .or_else(|| run.get("unpacked_path"))
        .and_then(Value::as_str)
        .filter(|s: &&str| !s.is_empty());
    let (Some(packed), Some(baseline)): (Option<&str>, Option<&str>) = (packed_rel, baseline_rel)
    else {
        return;
    };
    let diff_count: Option<i64> = run
        .get("unpacked_byte_diff_count")
        .and_then(Value::as_integer);
    let byte_exact_status: bool = run
        .get("unpacker_status")
        .and_then(Value::as_str)
        .is_some_and(|s: &str| s == "byte-exact" || s == "near-byte-exact");
    let qualifies_byte_identical: bool = diff_count == Some(0) || byte_exact_status;
    if !qualifies_byte_identical {
        return;
    }
    let input: &str = run
        .get("input")
        .and_then(Value::as_str)
        .map_or("input", |value: &str| value);
    let fixture_id: String = format!("{packer_name}:{}", sanitize(input));
    out.push(OracleFixture {
        oracle: OracleKind::ByteIdenticalUnpack,
        pass_under_test: "native.packer-unpack".to_owned(),
        fixture_id,
        input_rel: packed.to_owned(),
        baseline_sha256: None,
        baseline_rel: Some(baseline.to_owned()),
        expected_detection: None,
        byte_identical_floor_bp: Some(0),
    });
}

fn extract_python_obfuscators(value: &Value, out: &mut Vec<OracleFixture>) {
    let Some(table): Option<&toml::map::Map<String, Value>> =
        value.get("obfuscators").and_then(Value::as_table)
    else {
        return;
    };
    for (tool, body) in table {
        collect_obfuscator_entries(tool, body, out);
    }
}

fn collect_obfuscator_entries(tool: &str, body: &Value, out: &mut Vec<OracleFixture>) {
    let Some(map): Option<&toml::map::Map<String, Value>> = body.as_table() else {
        return;
    };
    if let Some(fx_table) = map.get("fixtures").and_then(Value::as_table) {
        for (name, entry) in fx_table {
            push_obfuscator_entry(tool, name, entry, out);
        }
    }
    for (name, entry) in map {
        if name == "fixtures" || name == "metadata" || name == "variants" {
            continue;
        }
        if entry.is_table() && entry.get("path").is_some() {
            push_obfuscator_entry(tool, name, entry, out);
        }
    }
}

fn push_obfuscator_entry(tool: &str, name: &str, entry: &Value, out: &mut Vec<OracleFixture>) {
    let Some(path): Option<&str> = entry.get("path").and_then(Value::as_str) else {
        return;
    };
    let is_pyc: bool = ends_with_ci(path, ".pyc");
    let is_py: bool = ends_with_ci(path, ".py") || ends_with_ci(path, ".py.fixture");
    if !(is_py || is_pyc) {
        return;
    }
    let pass: &str = if is_pyc { "py.decompile" } else { "py.deob" };
    let baseline_rel: Option<String> = entry
        .get("clean_source")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let baseline_sha256: Option<String> = entry
        .get("clean_sha256")
        .and_then(Value::as_str)
        .map(str::to_owned);
    out.push(OracleFixture {
        oracle: OracleKind::DifferentialVsSource,
        pass_under_test: pass.to_owned(),
        fixture_id: format!("{tool}:{name}"),
        input_rel: path.to_owned(),
        baseline_rel,
        baseline_sha256,
        expected_detection: None,
        byte_identical_floor_bp: None,
    });
}

fn extract_detection_manifest(category: &str, value: &Value, out: &mut Vec<OracleFixture>) {
    let expected_pass: &str = detection_pass_for(category);
    let path_prefix: String = format!("corpus/{category}/");
    let mut emit = |path: &str, id: String| {
        out.push(OracleFixture {
            oracle: OracleKind::DetectionDeterministic,
            pass_under_test: expected_pass.to_owned(),
            fixture_id: format!("{category}:{id}"),
            input_rel: format!("{path_prefix}{path}"),
            baseline_sha256: None,
            baseline_rel: None,
            expected_detection: Some(expected_pass.to_owned()),
            byte_identical_floor_bp: None,
        });
    };
    if let Some(fixtures) = value.get("fixture").and_then(Value::as_array) {
        for fx in fixtures {
            collect_detection_array_entry(fx, &mut emit);
        }
    }
    if let Some(samples) = value.get("sample").and_then(Value::as_array) {
        for sample in samples {
            if let Some(name) = sample.get("name").and_then(Value::as_str) {
                emit(name, sanitize(name));
            }
        }
    }
}

fn collect_detection_array_entry(fx: &Value, emit: &mut impl FnMut(&str, String)) {
    let Some(path): Option<&str> = fx.get("path").and_then(Value::as_str) else {
        return;
    };
    let kind: &str = fx
        .get("kind")
        .and_then(Value::as_str)
        .map_or("", |value: &str| value);
    if kind == "source" {
        return;
    }
    if kind.contains("nativeaot") || kind.contains("r2r") {
        return;
    }
    if ends_with_ci(path, ".cs") || ends_with_ci(path, ".erl") || ends_with_ci(path, ".ex") {
        return;
    }
    let id: String = fx
        .get("name")
        .and_then(Value::as_str)
        .map_or_else(|| sanitize(path), sanitize);
    emit(path, id);
}

fn ends_with_ci(haystack: &str, suffix: &str) -> bool {
    let hlen: usize = haystack.len();
    let slen: usize = suffix.len();
    hlen >= slen && haystack[hlen - slen..].eq_ignore_ascii_case(suffix)
}

fn discover_recompile_pyc(corpus_root: &Path, out: &mut Vec<OracleFixture>) {
    let playground_dir: PathBuf = corpus_root
        .join("python")
        .join("decompile")
        .join("playground");
    if !playground_dir.is_dir() {
        return;
    }
    let mut discovered: usize = 0;
    for entry in walkdir::WalkDir::new(&playground_dir)
        .into_iter()
        .filter_map(core::result::Result::ok)
    {
        let path: &Path = entry.path();
        if !path.is_file() {
            continue;
        }
        let is_pyc: bool = path
            .extension()
            .and_then(|e: &std::ffi::OsStr| e.to_str())
            .is_some_and(|e: &str| e.eq_ignore_ascii_case("pyc"));
        if !is_pyc {
            continue;
        }
        if discovered >= MAX_DISCOVERED_RECOMPILE_PYC {
            break;
        }
        let Ok(rel): Result<&Path, std::path::StripPrefixError> = path.strip_prefix(corpus_root)
        else {
            continue;
        };
        let rel_str: String = format!("corpus/{}", rel.to_string_lossy().replace('\\', "/"));
        let id: String = path
            .file_stem()
            .and_then(|s: &std::ffi::OsStr| s.to_str())
            .map_or_else(|| sanitize(&rel_str), sanitize);
        out.push(OracleFixture {
            oracle: OracleKind::RecompileEquiv,
            pass_under_test: "py.decompile".to_owned(),
            fixture_id: format!("decompile:{id}"),
            input_rel: rel_str,
            baseline_sha256: None,
            baseline_rel: None,
            expected_detection: None,
            byte_identical_floor_bp: None,
        });
        discovered += 1;
    }
}

fn discover_packed_pairs(corpus_root: &Path, out: &mut Vec<OracleFixture>) {
    let packers_dir: PathBuf = corpus_root.join("native").join("packers");
    if !packers_dir.is_dir() {
        return;
    }
    let mut discovered: usize = 0;
    for entry in walkdir::WalkDir::new(&packers_dir)
        .into_iter()
        .filter_map(core::result::Result::ok)
    {
        let path: &Path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name): Option<&str> = path.file_name().and_then(|n: &std::ffi::OsStr| n.to_str())
        else {
            continue;
        };
        if !name.contains(".packed.") {
            continue;
        }
        let Some(parent): Option<&Path> = path.parent() else {
            continue;
        };
        let packer: String = parent
            .file_name()
            .and_then(|n: &std::ffi::OsStr| n.to_str())
            .map_or("native", |value: &str| value)
            .to_ascii_lowercase();
        if !matches!(packer.as_str(), "upx" | "fsg" | "mew") {
            continue;
        }
        if discovered >= MAX_DISCOVERED_PACKED_PAIRS {
            break;
        }
        let stem: &str = name.split(".packed.").next().unwrap_or(name);
        let Some(baseline): Option<PathBuf> = find_baseline(parent, stem) else {
            continue;
        };
        let Ok(packed_rel): Result<&Path, std::path::StripPrefixError> =
            path.strip_prefix(corpus_root)
        else {
            continue;
        };
        let Ok(base_rel): Result<&Path, std::path::StripPrefixError> =
            baseline.strip_prefix(corpus_root)
        else {
            continue;
        };
        out.push(OracleFixture {
            oracle: OracleKind::ByteIdenticalUnpack,
            pass_under_test: "native.packer-unpack".to_owned(),
            fixture_id: format!("{packer}:{}", sanitize(stem)),
            input_rel: format!("corpus/{}", packed_rel.to_string_lossy().replace('\\', "/")),
            baseline_sha256: None,
            baseline_rel: Some(format!(
                "corpus/{}",
                base_rel.to_string_lossy().replace('\\', "/")
            )),
            expected_detection: None,
            byte_identical_floor_bp: Some(0),
        });
        discovered += 1;
    }
}

fn find_baseline(dir: &Path, stem: &str) -> Option<PathBuf> {
    for suffix in [".original.exe", ".unpacked.exe", ".original.dll"] {
        let candidate: PathBuf = dir.join(format!("{stem}{suffix}"));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn detection_pass_for(category: &str) -> &'static str {
    match category {
        "dotnet" => "dotnet.classify",
        "jvm" => "jvm.classify",
        "beam" => "beam.classify",
        "ruby" => "ruby.classify",
        "lua" => "lua.deob",
        "php" => "php.peel",
        "shell" => "shell.deob",
        _ => "unknown",
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c: char| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

#[must_use]
pub fn group_by_category(fixtures: &[OracleFixture]) -> BTreeMap<OracleKind, usize> {
    let mut counts: BTreeMap<OracleKind, usize> = BTreeMap::new();
    for f in fixtures {
        *counts.entry(f.oracle).or_insert(0) += 1;
    }
    counts
}
