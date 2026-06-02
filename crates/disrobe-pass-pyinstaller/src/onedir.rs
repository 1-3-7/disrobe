use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::extract::{ExtractOutput, ExtractedEntry};
use crate::toc::EntryType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OnedirLayout {
    PyInstallerLegacy,
    PyInstallerInternalDir,
}

impl OnedirLayout {
    pub const fn label(self) -> &'static str {
        match self {
            Self::PyInstallerLegacy => "pyinstaller-legacy",
            Self::PyInstallerInternalDir => "pyinstaller-internal-dir",
        }
    }

    pub const fn base_prefix(self) -> &'static str {
        match self {
            Self::PyInstallerLegacy => "",
            Self::PyInstallerInternalDir => "_internal/",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnedirFile {
    pub relative_path: String,
    pub byte_len: usize,
    pub source_entry_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnedirPlan {
    pub schema: String,
    pub layout: OnedirLayout,
    pub root_executable_name: Option<String>,
    pub python_major: u8,
    pub python_minor: u8,
    pub files: Vec<OnedirFile>,
    pub directories: Vec<String>,
    pub total_bytes: u64,
}

impl OnedirPlan {
    pub fn materialize_blobs<'a>(
        &'a self,
        output: &'a ExtractOutput,
    ) -> BTreeMap<&'a str, &'a [u8]> {
        let by_name: BTreeMap<&str, &ExtractedEntry> = output
            .entries
            .iter()
            .map(|e| (e.toc.name.as_str(), e))
            .collect();

        let mut map: BTreeMap<&'a str, &'a [u8]> = BTreeMap::new();
        for f in &self.files {
            if let Some(entry) = by_name.get(f.source_entry_name.as_str()) {
                map.insert(f.relative_path.as_str(), entry.data.as_slice());
            }
        }
        map
    }
}

pub fn plan_onedir(
    output: &ExtractOutput,
    layout: OnedirLayout,
    executable_name: Option<&str>,
) -> OnedirPlan {
    let prefix: &'static str = layout.base_prefix();
    let mut files: Vec<OnedirFile> = Vec::new();
    let mut dir_set: BTreeSet<String> = BTreeSet::new();

    if !prefix.is_empty() {
        dir_set.insert(prefix.trim_end_matches('/').to_owned());
    }

    for entry in &output.entries {
        let Some((rel, kind_dirs)) = compute_relative_path(prefix, entry) else {
            continue;
        };
        for d in kind_dirs {
            dir_set.insert(d);
        }
        files.push(OnedirFile {
            relative_path: rel,
            byte_len: entry.data.len(),
            source_entry_name: entry.toc.name.clone(),
        });
    }

    let total_bytes: u64 = files.iter().map(|f| f.byte_len as u64).sum();

    OnedirPlan {
        schema: "disrobe.pyinstaller.onedir/v0".to_owned(),
        layout,
        root_executable_name: executable_name.map(str::to_owned),
        python_major: output.cookie.python_major,
        python_minor: output.cookie.python_minor,
        files,
        directories: dir_set.into_iter().collect(),
        total_bytes,
    }
}

fn compute_relative_path(prefix: &str, entry: &ExtractedEntry) -> Option<(String, Vec<String>)> {
    if entry.toc.entry_type.should_skip() {
        return None;
    }
    let logical: String = entry.toc.name.replace('\\', "/");
    let final_path: String = match entry.toc.entry_type {
        EntryType::Script => format!("{prefix}{logical}.pyc"),
        EntryType::Module => format!("{prefix}{}.pyc", logical.replace('.', "/")),
        EntryType::Package => {
            format!("{prefix}{}/__init__.pyc", logical.replace('.', "/"))
        }
        EntryType::Pyz | EntryType::PyzZipfile => {
            let safe_name: String = if has_extension_ignore_case(&logical, "pyz") {
                logical
            } else {
                format!("{logical}.pyz")
            };
            format!("{prefix}{safe_name}")
        }
        EntryType::Binary | EntryType::Data | EntryType::Symlink => {
            format!("{prefix}{logical}")
        }
        EntryType::Splash => format!("{prefix}_pyi_splash/{logical}"),
        EntryType::Dependency | EntryType::RuntimeOption | EntryType::Unknown(_) => return None,
    };
    let dirs: Vec<String> = iterate_parent_dirs(&final_path);
    Some((final_path, dirs))
}

fn has_extension_ignore_case(path: &str, ext: &str) -> bool {
    std::path::Path::new(path)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case(ext))
}

fn iterate_parent_dirs(path: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut accumulator: String = String::new();
    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() <= 1 {
        return out;
    }
    for seg in &segments[..segments.len() - 1] {
        if !accumulator.is_empty() {
            accumulator.push('/');
        }
        accumulator.push_str(seg);
        if !accumulator.is_empty() {
            out.push(accumulator.clone());
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::cookie::{Cookie, CookieVariant};
    use crate::toc::TocEntry;

    fn synthetic_cookie() -> Cookie {
        Cookie {
            variant: CookieVariant::V21Plus,
            magic_offset: 0,
            length_of_package: 0,
            toc_offset: 0,
            toc_length: 0,
            pyver: 312,
            python_libname: Some("python312.dll".to_owned()),
            python_major: 3,
            python_minor: 12,
        }
    }

    fn entry(name: &str, kind: EntryType, data: Vec<u8>) -> ExtractedEntry {
        let entry_size: u32 = u32::try_from(18 + name.len()).expect("name fits u32");
        let size_u32: u32 = u32::try_from(data.len()).expect("data fits u32");
        ExtractedEntry {
            toc: TocEntry {
                entry_size,
                entry_position: 0,
                compressed_size: size_u32,
                uncompressed_size: size_u32,
                compressed_flag: 0,
                entry_type: kind,
                name: name.to_owned(),
            },
            data,
            written_path: None,
            decrypted: false,
        }
    }

    fn output_with(entries: Vec<ExtractedEntry>) -> ExtractOutput {
        ExtractOutput {
            cookie: synthetic_cookie(),
            bare_pyc_paths: Vec::new(),
            encryption_key: None,
            entries,
        }
    }

    #[test]
    fn legacy_layout_places_at_root() {
        let entries: Vec<ExtractedEntry> = vec![
            entry("main", EntryType::Script, vec![0u8; 4]),
            entry("requests", EntryType::Package, vec![0u8; 4]),
            entry("requests.api", EntryType::Module, vec![0u8; 4]),
            entry("python312.dll", EntryType::Binary, vec![0u8; 4]),
        ];
        let out: ExtractOutput = output_with(entries);
        let plan: OnedirPlan = plan_onedir(&out, OnedirLayout::PyInstallerLegacy, Some("app.exe"));
        let paths: Vec<&str> = plan
            .files
            .iter()
            .map(|f| f.relative_path.as_str())
            .collect();
        assert!(paths.contains(&"main.pyc"));
        assert!(paths.contains(&"requests/__init__.pyc"));
        assert!(paths.contains(&"requests/api.pyc"));
        assert!(paths.contains(&"python312.dll"));
        assert_eq!(plan.layout, OnedirLayout::PyInstallerLegacy);
        assert_eq!(plan.root_executable_name.as_deref(), Some("app.exe"));
    }

    #[test]
    fn internal_dir_layout_prefixes_internal() {
        let entries: Vec<ExtractedEntry> = vec![
            entry("main", EntryType::Script, vec![0u8; 4]),
            entry("pkg.sub", EntryType::Module, vec![0u8; 4]),
            entry("base_library.zip", EntryType::Data, vec![0u8; 4]),
        ];
        let out: ExtractOutput = output_with(entries);
        let plan: OnedirPlan = plan_onedir(&out, OnedirLayout::PyInstallerInternalDir, None);
        let paths: Vec<&str> = plan
            .files
            .iter()
            .map(|f| f.relative_path.as_str())
            .collect();
        assert!(paths.contains(&"_internal/main.pyc"));
        assert!(paths.contains(&"_internal/pkg/sub.pyc"));
        assert!(paths.contains(&"_internal/base_library.zip"));
        assert!(plan.directories.iter().any(|d| d == "_internal"));
    }

    #[test]
    fn pyz_entries_get_pyz_extension() {
        let entries: Vec<ExtractedEntry> = vec![
            entry("PYZ-00", EntryType::Pyz, vec![0u8; 4]),
            entry("inner.pyz", EntryType::Pyz, vec![0u8; 4]),
        ];
        let out: ExtractOutput = output_with(entries);
        let plan: OnedirPlan = plan_onedir(&out, OnedirLayout::PyInstallerLegacy, None);
        let paths: Vec<&str> = plan
            .files
            .iter()
            .map(|f| f.relative_path.as_str())
            .collect();
        assert!(paths.contains(&"PYZ-00.pyz"));
        assert!(paths.contains(&"inner.pyz"));
    }

    #[test]
    fn skips_dependency_and_runtime_option_entries() {
        let entries: Vec<ExtractedEntry> = vec![
            entry("dep", EntryType::Dependency, vec![0u8; 4]),
            entry("opt", EntryType::RuntimeOption, vec![0u8; 4]),
            entry("main", EntryType::Script, vec![0u8; 4]),
        ];
        let out: ExtractOutput = output_with(entries);
        let plan: OnedirPlan = plan_onedir(&out, OnedirLayout::PyInstallerLegacy, None);
        assert_eq!(plan.files.len(), 1);
        assert_eq!(plan.files[0].relative_path, "main.pyc");
    }

    #[test]
    fn materialize_blobs_maps_relative_path_to_data() {
        let entries: Vec<ExtractedEntry> = vec![entry("main", EntryType::Script, vec![1, 2, 3, 4])];
        let out: ExtractOutput = output_with(entries);
        let plan: OnedirPlan = plan_onedir(&out, OnedirLayout::PyInstallerLegacy, None);
        let blobs: BTreeMap<&str, &[u8]> = plan.materialize_blobs(&out);
        assert_eq!(
            blobs.get("main.pyc").copied(),
            Some([1, 2, 3, 4].as_slice())
        );
    }

    #[test]
    fn directories_contain_parent_paths_for_nested_modules() {
        let entries: Vec<ExtractedEntry> =
            vec![entry("requests.adapters", EntryType::Module, vec![0u8; 4])];
        let out: ExtractOutput = output_with(entries);
        let plan: OnedirPlan = plan_onedir(&out, OnedirLayout::PyInstallerInternalDir, None);
        assert!(plan.directories.iter().any(|d| d == "_internal/requests"));
    }

    #[test]
    fn total_bytes_sums_file_sizes() {
        let entries: Vec<ExtractedEntry> = vec![
            entry("main", EntryType::Script, vec![0u8; 10]),
            entry("a", EntryType::Module, vec![0u8; 20]),
        ];
        let out: ExtractOutput = output_with(entries);
        let plan: OnedirPlan = plan_onedir(&out, OnedirLayout::PyInstallerLegacy, None);
        assert_eq!(plan.total_bytes, 30);
    }

    #[test]
    fn layout_label_and_prefix_match() {
        assert_eq!(
            OnedirLayout::PyInstallerLegacy.label(),
            "pyinstaller-legacy"
        );
        assert_eq!(OnedirLayout::PyInstallerLegacy.base_prefix(), "");
        assert_eq!(
            OnedirLayout::PyInstallerInternalDir.label(),
            "pyinstaller-internal-dir"
        );
        assert_eq!(
            OnedirLayout::PyInstallerInternalDir.base_prefix(),
            "_internal/"
        );
    }
}
