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
pub struct FrozenModules {
    pub stream_offset: u64,
    pub marshal_version: (u8, u8),
    pub modules: Vec<BytecodeModule>,
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
}
