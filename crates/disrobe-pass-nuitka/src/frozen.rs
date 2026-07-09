use disrobe_core::debug::DebugLog;
use disrobe_py_marshal::{Object, PyVersion, RefTableDump, load_with_reftable};
use serde::{Deserialize, Serialize};

use crate::bytecode_table::{BytecodeModule, recover_frozen_module};
use crate::util::{find_subslice, pe_data_section_ranges};

const STREAM_MARKER: &[u8] = b".bytecode\0";
const TYPE_CODE: u8 = b'c';
const TYPE_CODE_REF: u8 = b'c' | 0x80;
const MAX_FROZEN_MODULES: usize = 1 << 16;
const MIN_MODULE_BYTES: usize = 16;
const MAX_MARSHAL_BYTES: usize = 32 * 1024 * 1024;
const RECOMPILE_TIMEOUT_SECS: u64 = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FrozenStatus {
    Decompiled,
    Empty,
    Failed,
}

#[must_use]
pub fn frozen_status(module: &BytecodeModule) -> FrozenStatus {
    if !module.recovered_directly {
        return FrozenStatus::Failed;
    }
    if module.source.trim().is_empty() {
        FrozenStatus::Empty
    } else {
        FrozenStatus::Decompiled
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecompileReport {
    pub interpreter: String,
    pub checked: usize,
    pub clean: usize,
    pub failed: Vec<String>,
}

impl RecompileReport {
    #[must_use]
    pub fn pass_rate(&self) -> f64 {
        if self.checked == 0 {
            return 0.0;
        }
        self.clean as f64 / self.checked as f64
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenModules {
    pub stream_offset: u64,
    pub marshal_version: (u8, u8),
    pub modules: Vec<BytecodeModule>,
    pub recompile: Option<RecompileReport>,
    pub notes: Vec<String>,
}

impl FrozenModules {
    #[must_use]
    pub fn decompiled_count(&self) -> usize {
        self.modules
            .iter()
            .filter(|m: &&BytecodeModule| matches!(frozen_status(m), FrozenStatus::Decompiled))
            .count()
    }

    #[must_use]
    pub fn empty_count(&self) -> usize {
        self.modules
            .iter()
            .filter(|m: &&BytecodeModule| matches!(frozen_status(m), FrozenStatus::Empty))
            .count()
    }

    #[must_use]
    pub fn failed_count(&self) -> usize {
        self.modules
            .iter()
            .filter(|m: &&BytecodeModule| matches!(frozen_status(m), FrozenStatus::Failed))
            .count()
    }
}

#[must_use]
pub fn recover_frozen_bytecode(
    image: &[u8],
    python_abi: Option<(u8, u8)>,
) -> Option<FrozenModules> {
    let dbg: DebugLog = DebugLog::for_scope("nuitka");
    dbg.section("frozen-bytecode");
    let marker_at: usize = find_stream_marker(image)?;
    let after_marker: usize = marker_at + STREAM_MARKER.len();
    dbg.kv("marker", || format!("{marker_at:#x}"));

    let version: PyVersion = python_abi.map_or(PyVersion::PY314, |(major, minor): (u8, u8)| {
        PyVersion::new(major, minor)
    });

    let first: usize = first_code_start(image, after_marker, version)?;
    dbg.kv("first_code", || format!("{first:#x}"));

    let mut modules: Vec<BytecodeModule> = Vec::new();
    let mut cursor: usize = first;
    let probe_version: PyVersion = version;

    while cursor < image.len() && modules.len() < MAX_FROZEN_MODULES {
        let Some((object, consumed)): Option<(Object, usize)> =
            load_code(&image[cursor..], probe_version)
        else {
            break;
        };
        if consumed < MIN_MODULE_BYTES {
            break;
        }
        let Object::Code(code) = &object else {
            break;
        };
        let module_name: String = module_name_from_filename(&code.filename);
        let recovered: BytecodeModule = recover_frozen_module(
            &module_name,
            &image[cursor..cursor + consumed],
            probe_version,
        );
        dbg.line(|| {
            format!(
                "frozen module {} @ {cursor:#x} consumed={} recovered={}",
                recovered.module_name, consumed, recovered.recovered_directly
            )
        });
        modules.push(recovered);
        let scan_from: usize = cursor + consumed;
        let Some(next): Option<usize> = next_code_start(image, scan_from, probe_version) else {
            break;
        };
        cursor = next;
    }

    if modules.is_empty() {
        return None;
    }

    let mut table: FrozenModules = FrozenModules {
        stream_offset: marker_at as u64,
        marshal_version: (probe_version.major, probe_version.minor),
        modules,
        recompile: None,
        notes: Vec::new(),
    };
    let decompiled: usize = table.decompiled_count();
    let empty: usize = table.empty_count();
    let failed: usize = table.failed_count();
    table.notes.push(format!(
        "frozen-bytecode stream: walked {} module(s) (python {}.{}); {decompiled} decompiled to source, {empty} empty/comment-only, {failed} failed (recompile correctness not verified at parse time)",
        table.modules.len(),
        probe_version.major,
        probe_version.minor,
    ));
    Some(table)
}

#[must_use]
pub fn verify_recompile(table: &FrozenModules, interpreter: &std::path::Path) -> RecompileReport {
    let dbg: DebugLog = DebugLog::for_scope("nuitka");
    dbg.section("frozen-recompile");
    let targets: Vec<&BytecodeModule> = table
        .modules
        .iter()
        .filter(|m: &&BytecodeModule| matches!(frozen_status(m), FrozenStatus::Decompiled))
        .collect();

    let interpreter_label: String = interpreter.display().to_string();
    let unchecked = |count: usize| -> RecompileReport {
        RecompileReport {
            interpreter: interpreter_label.clone(),
            checked: count,
            clean: 0,
            failed: Vec::new(),
        }
    };

    let mut dir: std::path::PathBuf = std::env::temp_dir();
    dir.push(format!("disrobe-frozen-{}", std::process::id()));
    if std::fs::create_dir_all(&dir).is_err() {
        return unchecked(0);
    }

    let mut manifest: Vec<(String, std::path::PathBuf)> = Vec::with_capacity(targets.len());
    for (index, module) in targets.iter().enumerate() {
        let file: std::path::PathBuf = dir.join(format!("m{index}.py"));
        if std::fs::write(&file, module.source.as_bytes()).is_ok() {
            manifest.push((module.module_name.clone(), file));
        }
    }

    let manifest_path: std::path::PathBuf = dir.join("_manifest.tsv");
    let mut manifest_text: String = String::new();
    for (name, path) in &manifest {
        manifest_text.push_str(name);
        manifest_text.push('\t');
        manifest_text.push_str(&path.display().to_string());
        manifest_text.push('\n');
    }
    if std::fs::write(&manifest_path, manifest_text.as_bytes()).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return unchecked(0);
    }

    let result_path: std::path::PathBuf = dir.join("_failed.txt");
    let checker: std::path::PathBuf = dir.join("_check.py");
    let script: &str = "import sys\nmanifest, out = sys.argv[1], sys.argv[2]\nfailed = []\nwith open(manifest, 'r', encoding='utf-8') as mf:\n    for line in mf:\n        name, _, path = line.rstrip('\\n').partition('\\t')\n        if not path:\n            continue\n        try:\n            with open(path, 'r', encoding='utf-8') as fh:\n                compile(fh.read(), path, 'exec')\n        except SyntaxError:\n            failed.append(name)\nwith open(out, 'w', encoding='utf-8') as of:\n    of.write('\\n'.join(failed))\n";
    if std::fs::write(&checker, script).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return unchecked(0);
    }

    let spawned: std::io::Result<std::process::Child> = std::process::Command::new(interpreter)
        .arg(&checker)
        .arg(&manifest_path)
        .arg(&result_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    let Ok(child): std::io::Result<std::process::Child> = spawned else {
        let _ = std::fs::remove_dir_all(&dir);
        return unchecked(0);
    };

    let timeout: std::time::Duration = std::time::Duration::from_secs(RECOMPILE_TIMEOUT_SECS);
    if disrobe_core::subprocess::wait_with_output_timeout(child, timeout, 0).is_none() {
        let _ = std::fs::remove_dir_all(&dir);
        dbg.line(|| "recompile interpreter exceeded timeout; killed".to_owned());
        return unchecked(manifest.len());
    }

    let stdout: String = std::fs::read_to_string(&result_path).unwrap_or_default();
    let failed: Vec<String> = stdout
        .lines()
        .map(str::trim)
        .filter(|s: &&str| !s.is_empty())
        .map(str::to_owned)
        .collect();
    let _ = std::fs::remove_dir_all(&dir);

    let checked: usize = manifest.len();
    let clean: usize = checked.saturating_sub(failed.len());
    dbg.kv("checked", || checked.to_string());
    dbg.kv("clean", || clean.to_string());
    RecompileReport {
        interpreter: interpreter_label,
        checked,
        clean,
        failed,
    }
}

const FIRST_CODE_WINDOW: usize = 64;
const INTER_MODULE_WINDOW: usize = 32;

fn first_code_start(image: &[u8], from: usize, version: PyVersion) -> Option<usize> {
    scan_code_start(image, from, FIRST_CODE_WINDOW, version)
}

fn next_code_start(image: &[u8], from: usize, version: PyVersion) -> Option<usize> {
    scan_code_start(image, from, INTER_MODULE_WINDOW, version)
}

fn scan_code_start(image: &[u8], from: usize, window: usize, version: PyVersion) -> Option<usize> {
    let limit: usize = from.saturating_add(window).min(image.len());
    (from..limit).find(|&candidate: &usize| {
        matches!(image.get(candidate), Some(&TYPE_CODE | &TYPE_CODE_REF))
            && load_code(&image[candidate..], version).is_some_and(
                |(object, consumed): (Object, usize)| {
                    matches!(object, Object::Code(_)) && consumed >= MIN_MODULE_BYTES
                },
            )
    })
}

fn find_stream_marker(image: &[u8]) -> Option<usize> {
    pe_data_section_ranges(image).map_or_else(
        || find_subslice(image, STREAM_MARKER),
        |ranges: Vec<(usize, usize)>| {
            ranges.into_iter().find_map(|(start, end): (usize, usize)| {
                let section: &[u8] = image.get(start..end)?;
                find_subslice(section, STREAM_MARKER).map(|rel: usize| start + rel)
            })
        },
    )
}

fn load_code(slice: &[u8], version: PyVersion) -> Option<(Object, usize)> {
    let window: &[u8] = &slice[..slice.len().min(MAX_MARSHAL_BYTES)];
    let (object, dump): (Object, RefTableDump) = load_with_reftable(window, version).ok()?;
    if !matches!(object, Object::Code(_)) {
        return None;
    }
    Some((object, dump.total_bytes))
}

fn module_name_from_filename(filename: &Object) -> String {
    let raw: &str = match filename {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => value.as_str(),
        _ => return "<frozen>".to_owned(),
    };
    let no_ext: &str = raw
        .strip_suffix(".py")
        .or_else(|| raw.strip_suffix(".pyc"))
        .unwrap_or(raw);
    let normalized: String = no_ext.replace(['\\', '/'], ".");
    let trimmed: &str = normalized.trim_matches('.');
    let cleaned: &str = trimmed.strip_suffix(".__init__").unwrap_or(trimmed);
    if cleaned.is_empty() {
        "<frozen>".to_owned()
    } else {
        cleaned.to_owned()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn corpus_standalone() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/python/nuitka/real/sample_app-standalone.exe")
    }

    #[test]
    fn huge_marshal_length_after_marker_does_not_oom() {
        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(STREAM_MARKER);
        blob.push(b'c');
        blob.extend_from_slice(&238_319_529u32.to_le_bytes());
        blob.extend_from_slice(&[0u8; 64]);
        assert!(
            recover_frozen_bytecode(&blob, Some((3, 14))).is_none(),
            "a garbage 238MB marshal length over a tiny buffer must be rejected, not allocated"
        );
    }

    #[test]
    fn module_name_strips_path_and_ext() {
        let obj: Object = Object::Unicode {
            value: "_pyrepl\\reader.py".to_owned(),
            interned: false,
        };
        assert_eq!(module_name_from_filename(&obj), "_pyrepl.reader");
        let obj2: Object = Object::Unicode {
            value: "__future__.py".to_owned(),
            interned: false,
        };
        assert_eq!(module_name_from_filename(&obj2), "__future__");
    }

    #[test]
    fn recovers_real_frozen_stdlib_to_source() {
        let path: std::path::PathBuf = corpus_standalone();
        if !path.is_file() {
            eprintln!("skipping: real nuitka corpus exe absent");
            return;
        }
        let image: Vec<u8> = std::fs::read(&path).expect("read corpus exe");
        let frozen: FrozenModules =
            recover_frozen_bytecode(&image, Some((3, 14))).expect("frozen stream recovered");
        assert_eq!(frozen.marshal_version, (3, 14));
        assert!(
            frozen.modules.len() >= 20,
            "expected many frozen stdlib modules, got {}",
            frozen.modules.len()
        );
        let names: std::collections::BTreeSet<&str> = frozen
            .modules
            .iter()
            .map(|m: &BytecodeModule| m.module_name.as_str())
            .collect();
        for expected in ["__future__", "_collections_abc"] {
            assert!(names.contains(expected), "frozen module {expected} missing");
        }
        let future: &BytecodeModule = frozen
            .modules
            .iter()
            .find(|m: &&BytecodeModule| m.module_name == "__future__")
            .expect("__future__ present");
        assert!(
            matches!(frozen_status(future), FrozenStatus::Decompiled),
            "__future__ must decompile; reason {:?}",
            future.fallback_reason
        );
        assert!(
            future.source.contains("all_feature_names"),
            "__future__ source missing a known identifier:\n{}",
            &future.source[..future.source.len().min(400)]
        );
        assert!(
            frozen.decompiled_count() >= 15,
            "too few decompiled modules"
        );
    }

    fn on_box_cpython_314() -> Option<std::path::PathBuf> {
        let candidate: std::path::PathBuf = std::path::PathBuf::from("C:/Python314/python.exe");
        candidate.is_file().then_some(candidate)
    }

    #[test]
    fn frozen_modules_recompile_clean_against_on_box_cpython() {
        let path: std::path::PathBuf = corpus_standalone();
        if !path.is_file() {
            eprintln!("skipping: real nuitka corpus exe absent");
            return;
        }
        let Some(python): Option<std::path::PathBuf> = on_box_cpython_314() else {
            eprintln!("skipping: on-box CPython 3.14 not found, recompile oracle unavailable");
            return;
        };
        let image: Vec<u8> = std::fs::read(&path).expect("read corpus exe");
        let frozen: FrozenModules =
            recover_frozen_bytecode(&image, Some((3, 14))).expect("frozen stream recovered");
        let report: RecompileReport = verify_recompile(&frozen, &python);
        assert!(
            report.checked >= 100,
            "expected many decompiled modules to recompile-check, got {}",
            report.checked
        );
        assert!(
            report.pass_rate() >= 0.90,
            "frozen recompile pass rate too low: {}/{} clean ({:.1}%); failures: {:?}",
            report.clean,
            report.checked,
            report.pass_rate() * 100.0,
            &report.failed[..report.failed.len().min(10)]
        );
        let abc: &BytecodeModule = frozen
            .modules
            .iter()
            .find(|m: &&BytecodeModule| m.module_name == "_collections_abc")
            .expect("_collections_abc present");
        assert!(
            abc.source.contains("class ") && abc.source.contains("def "),
            "_collections_abc must reconstruct classes and methods"
        );
        assert!(
            !report.failed.contains(&"_collections_abc".to_owned()),
            "_collections_abc must recompile clean"
        );
    }
}
