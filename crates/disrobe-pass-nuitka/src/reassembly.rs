use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::error::{Error, Result};
use crate::onefile::OnefileEntry;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntryRole {
    EntryExe,
    PythonRuntime,
    NativeLibrary,
    PythonExtension,
    FrozenModule,
    BytecodeModule,
    DataResource,
    BuildInfo,
    DistInfo,
    ConfigResource,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReassembledTree {
    pub normalized_path: String,
    pub byte_len: usize,
    pub role: EntryRole,
    pub permissions: Option<u8>,
    pub source_filename: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ReassemblyStats {
    pub by_role: BTreeMap<EntryRole, u32>,
    pub total_bytes: u64,
    pub dll_count: u32,
    pub frozen_modules: u32,
    pub bytecode_modules: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReassemblyPlan {
    pub schema: String,
    pub entry_executable: Option<String>,
    pub python_runtime: Option<String>,
    pub directories: Vec<String>,
    pub tree: Vec<ReassembledTree>,
    pub stats: ReassemblyStats,
}

pub fn plan_reassembly(entries: &[OnefileEntry]) -> Result<ReassemblyPlan> {
    if entries.is_empty() {
        return Err(Error::EmptyPayload);
    }

    let mut tree: Vec<ReassembledTree> = Vec::with_capacity(entries.len());
    let mut directories: BTreeSet<String> = BTreeSet::new();
    let mut stats: ReassemblyStats = ReassemblyStats::default();

    for entry in entries {
        let normalized: String = normalize_path(&entry.filename);
        let role: EntryRole = classify_entry(&normalized);
        let parent_dirs: Vec<String> = parent_dirs(&normalized);
        for d in parent_dirs {
            directories.insert(d);
        }
        accumulate_stats(&mut stats, role, entry.data.len() as u64);
        tree.push(ReassembledTree {
            normalized_path: normalized,
            byte_len: entry.data.len(),
            role,
            permissions: entry.permissions,
            source_filename: entry.filename.clone(),
        });
    }

    let entry_executable: Option<String> = pick_entry_executable(&tree);
    let python_runtime: Option<String> = pick_python_runtime(&tree);

    Ok(ReassemblyPlan {
        schema: "disrobe.nuitka.reassembly/v0".to_owned(),
        entry_executable,
        python_runtime,
        directories: directories.into_iter().collect(),
        tree,
        stats,
    })
}

fn normalize_path(raw: &str) -> String {
    raw.replace('\\', "/")
        .trim_start_matches("./")
        .trim_start_matches('/')
        .to_owned()
}

#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn classify_entry(path: &str) -> EntryRole {
    let lower: String = path.to_ascii_lowercase();
    if lower.ends_with("/__nuitka_build_info") || lower == "__nuitka_build_info" {
        return EntryRole::BuildInfo;
    }
    if lower.contains(".dist-info/") {
        return EntryRole::DistInfo;
    }
    if lower.ends_with(".exe") {
        return EntryRole::EntryExe;
    }
    if is_python_runtime_dll(&lower) {
        return EntryRole::PythonRuntime;
    }
    if lower.ends_with(".pyd") {
        return EntryRole::PythonExtension;
    }
    if lower.ends_with(".dll") || lower.ends_with(".dylib") {
        return EntryRole::NativeLibrary;
    }
    if lower.ends_with(".so") || (lower.contains(".so.") && lower.starts_with("lib")) {
        if lower.starts_with("libpython") {
            return EntryRole::PythonRuntime;
        }
        return EntryRole::NativeLibrary;
    }
    if lower.ends_with(".pyc") {
        return EntryRole::BytecodeModule;
    }
    if lower.ends_with(".py") {
        return EntryRole::FrozenModule;
    }
    if lower.ends_with(".toml")
        || lower.ends_with(".cfg")
        || lower.ends_with(".ini")
        || lower.ends_with(".yaml")
        || lower.ends_with(".yml")
    {
        return EntryRole::ConfigResource;
    }
    if has_resource_extension(&lower) {
        return EntryRole::DataResource;
    }
    EntryRole::Unknown
}

#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn is_python_runtime_dll(lower: &str) -> bool {
    if !lower.ends_with(".dll") {
        return false;
    }
    let basename: &str = lower.rsplit('/').next().unwrap_or(lower);
    basename.starts_with("python3") || basename.starts_with("python2") || basename == "python.dll"
}

#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn has_resource_extension(lower: &str) -> bool {
    const EXTENSIONS: &[&str] = &[
        ".json", ".xml", ".txt", ".html", ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".ico", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".pem", ".crt", ".key", ".pak", ".dat",
        ".bin", ".zip", ".tar", ".gz", ".db", ".sqlite",
    ];
    EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

fn parent_dirs(path: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() <= 1 {
        return out;
    }
    let mut acc: String = String::new();
    for seg in &segments[..segments.len() - 1] {
        if seg.is_empty() {
            continue;
        }
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(seg);
        out.push(acc.clone());
    }
    out
}

#[inline]
fn accumulate_stats(stats: &mut ReassemblyStats, role: EntryRole, byte_len: u64) {
    *stats.by_role.entry(role).or_insert(0) += 1;
    stats.total_bytes = stats.total_bytes.saturating_add(byte_len);
    match role {
        EntryRole::NativeLibrary | EntryRole::PythonRuntime | EntryRole::PythonExtension => {
            stats.dll_count += 1;
        }
        EntryRole::FrozenModule => stats.frozen_modules += 1,
        EntryRole::BytecodeModule => stats.bytecode_modules += 1,
        _ => {}
    }
}

fn pick_entry_executable(tree: &[ReassembledTree]) -> Option<String> {
    tree.iter()
        .filter(|t| t.role == EntryRole::EntryExe)
        .min_by_key(|t| depth_of(&t.normalized_path))
        .map(|t| t.normalized_path.clone())
}

fn pick_python_runtime(tree: &[ReassembledTree]) -> Option<String> {
    tree.iter()
        .find(|t| t.role == EntryRole::PythonRuntime)
        .map(|t| t.normalized_path.clone())
}

#[inline]
fn depth_of(path: &str) -> usize {
    path.bytes().filter(|&b| b == b'/').count()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn synth_entry(name: &str, data_len: usize) -> OnefileEntry {
        OnefileEntry {
            filename: name.to_owned(),
            size: data_len as u64,
            data_offset: 0,
            data: vec![0u8; data_len],
            permissions: None,
            crc32: None,
            symlink_target: None,
        }
    }

    #[test]
    fn empty_entries_errors() {
        let Err(err): Result<ReassemblyPlan> = plan_reassembly(&[]) else {
            panic!("empty must error");
        };
        assert!(matches!(err, Error::EmptyPayload));
    }

    #[test]
    fn classifies_python_runtime_dll() {
        let entries: Vec<OnefileEntry> = vec![
            synth_entry("python311.dll", 1024),
            synth_entry("libpython3.12.so.1.0", 2048),
            synth_entry("app.exe", 512),
        ];
        let plan: ReassemblyPlan = plan_reassembly(&entries).expect("plan");
        assert!(
            plan.tree
                .iter()
                .any(|t| t.role == EntryRole::PythonRuntime && t.normalized_path == "python311.dll")
        );
        assert_eq!(plan.entry_executable.as_deref(), Some("app.exe"));
        assert_eq!(
            plan.python_runtime.as_deref(),
            Some("python311.dll").or(Some("libpython3.12.so.1.0"))
        );
    }

    #[test]
    fn classifies_native_lib_and_extension() {
        let entries: Vec<OnefileEntry> = vec![
            synth_entry("zlib.dll", 100),
            synth_entry("_ctypes.pyd", 200),
            synth_entry("ssl/libssl.dylib", 300),
        ];
        let plan: ReassemblyPlan = plan_reassembly(&entries).expect("plan");
        let by_role: BTreeMap<&str, EntryRole> = plan
            .tree
            .iter()
            .map(|t| (t.normalized_path.as_str(), t.role))
            .collect();
        assert_eq!(
            by_role.get("zlib.dll").copied(),
            Some(EntryRole::NativeLibrary)
        );
        assert_eq!(
            by_role.get("_ctypes.pyd").copied(),
            Some(EntryRole::PythonExtension)
        );
        assert_eq!(
            by_role.get("ssl/libssl.dylib").copied(),
            Some(EntryRole::NativeLibrary)
        );
    }

    #[test]
    fn normalizes_backslash_and_drive_relative_paths() {
        let entries: Vec<OnefileEntry> = vec![synth_entry(r".\subdir\nested.dll", 100)];
        let plan: ReassemblyPlan = plan_reassembly(&entries).expect("plan");
        assert_eq!(plan.tree[0].normalized_path, "subdir/nested.dll");
    }

    #[test]
    fn entry_exe_prefers_root_level() {
        let entries: Vec<OnefileEntry> = vec![
            synth_entry("deep/nested/dir/sub.exe", 100),
            synth_entry("app.exe", 100),
        ];
        let plan: ReassemblyPlan = plan_reassembly(&entries).expect("plan");
        assert_eq!(plan.entry_executable.as_deref(), Some("app.exe"));
    }

    #[test]
    fn stats_count_per_role() {
        let entries: Vec<OnefileEntry> = vec![
            synth_entry("app.exe", 10),
            synth_entry("python312.dll", 20),
            synth_entry("foo.dll", 30),
            synth_entry("bar.pyd", 40),
            synth_entry("__main__.py", 50),
            synth_entry("data/icon.png", 60),
        ];
        let plan: ReassemblyPlan = plan_reassembly(&entries).expect("plan");
        assert_eq!(plan.stats.by_role.get(&EntryRole::EntryExe), Some(&1));
        assert_eq!(plan.stats.by_role.get(&EntryRole::PythonRuntime), Some(&1));
        assert_eq!(plan.stats.by_role.get(&EntryRole::NativeLibrary), Some(&1));
        assert_eq!(
            plan.stats.by_role.get(&EntryRole::PythonExtension),
            Some(&1)
        );
        assert_eq!(plan.stats.by_role.get(&EntryRole::FrozenModule), Some(&1));
        assert_eq!(plan.stats.by_role.get(&EntryRole::DataResource), Some(&1));
        assert_eq!(plan.stats.total_bytes, 10 + 20 + 30 + 40 + 50 + 60);
        assert_eq!(plan.stats.dll_count, 3);
        assert_eq!(plan.stats.frozen_modules, 1);
    }

    #[test]
    fn parent_dirs_are_collected_unique_and_sorted() {
        let entries: Vec<OnefileEntry> = vec![
            synth_entry("a/b/c/file.dll", 10),
            synth_entry("a/b/sibling.dll", 10),
            synth_entry("a/other.dll", 10),
        ];
        let plan: ReassemblyPlan = plan_reassembly(&entries).expect("plan");
        assert!(plan.directories.iter().any(|d| d == "a"));
        assert!(plan.directories.iter().any(|d| d == "a/b"));
        assert!(plan.directories.iter().any(|d| d == "a/b/c"));
        let mut sorted_copy: Vec<String> = plan.directories.clone();
        sorted_copy.sort();
        assert_eq!(plan.directories, sorted_copy);
    }

    #[test]
    fn dist_info_files_classified() {
        let entries: Vec<OnefileEntry> = vec![
            synth_entry("urllib3-2.0.dist-info/METADATA", 100),
            synth_entry("urllib3-2.0.dist-info/RECORD", 100),
        ];
        let plan: ReassemblyPlan = plan_reassembly(&entries).expect("plan");
        assert!(plan.tree.iter().all(|t| t.role == EntryRole::DistInfo));
    }

    #[test]
    fn build_info_resource_classified() {
        let entries: Vec<OnefileEntry> = vec![synth_entry("__nuitka_build_info", 256)];
        let plan: ReassemblyPlan = plan_reassembly(&entries).expect("plan");
        assert_eq!(plan.tree[0].role, EntryRole::BuildInfo);
    }

    #[test]
    fn unknown_extension_yields_unknown_role() {
        let entries: Vec<OnefileEntry> = vec![synth_entry("strange.xyz", 16)];
        let plan: ReassemblyPlan = plan_reassembly(&entries).expect("plan");
        assert_eq!(plan.tree[0].role, EntryRole::Unknown);
    }
}
