use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::extract::ExtractOutput;
use crate::pyz::{PyzEntry, PyzTocKind};
use crate::toc::EntryType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModuleKind {
    EntryScript,
    Module,
    Package,
    Resource,
    NativeBinding,
    Bootstrap,
}

impl ModuleKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::EntryScript => "entry-script",
            Self::Module => "module",
            Self::Package => "package",
            Self::Resource => "resource",
            Self::NativeBinding => "native-binding",
            Self::Bootstrap => "bootstrap",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyNode {
    pub qualified_name: String,
    pub kind: ModuleKind,
    pub origin: String,
    pub byte_size: u64,
    pub children: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyTree {
    pub schema: String,
    pub python_major: u8,
    pub python_minor: u8,
    pub entry_point: Option<String>,
    pub roots: Vec<String>,
    pub nodes: BTreeMap<String, DependencyNode>,
    pub total_modules: usize,
    pub total_packages: usize,
}

#[must_use]
pub fn build_dependency_tree(output: &ExtractOutput, pyz_entries: &[PyzEntry]) -> DependencyTree {
    let mut nodes: BTreeMap<String, DependencyNode> = BTreeMap::new();
    let mut entry_point: Option<String> = None;

    for e in &output.entries {
        let name: String = e.toc.name.replace('\\', "/");
        match e.toc.entry_type {
            EntryType::Script => {
                entry_point = Some(name.clone());
                upsert(
                    &mut nodes,
                    name,
                    ModuleKind::EntryScript,
                    "carchive-toc",
                    u64::from(e.toc.uncompressed_size),
                );
            }
            EntryType::Module => {
                let kind: ModuleKind = if is_bootstrap(&name) {
                    ModuleKind::Bootstrap
                } else {
                    ModuleKind::Module
                };
                upsert(
                    &mut nodes,
                    name,
                    kind,
                    "carchive-toc",
                    u64::from(e.toc.uncompressed_size),
                );
            }
            EntryType::Package => {
                upsert(
                    &mut nodes,
                    name,
                    ModuleKind::Package,
                    "carchive-toc",
                    u64::from(e.toc.uncompressed_size),
                );
            }
            EntryType::Binary => {
                upsert(
                    &mut nodes,
                    name,
                    ModuleKind::NativeBinding,
                    "carchive-toc",
                    u64::from(e.toc.uncompressed_size),
                );
            }
            EntryType::Data => {
                upsert(
                    &mut nodes,
                    name,
                    ModuleKind::Resource,
                    "carchive-toc",
                    u64::from(e.toc.uncompressed_size),
                );
            }
            _ => {}
        }
    }

    for p in pyz_entries {
        let kind: ModuleKind = match p.kind {
            PyzTocKind::Module => ModuleKind::Module,
            PyzTocKind::Package => ModuleKind::Package,
            PyzTocKind::Data | PyzTocKind::Unknown(_) => ModuleKind::Resource,
        };
        upsert(
            &mut nodes,
            p.name.clone(),
            kind,
            "pyz-toc",
            p.bytes.len() as u64,
        );
    }

    link_parent_child(&mut nodes);

    let roots: Vec<String> = collect_roots(&nodes);
    let mut total_modules: usize = 0usize;
    let mut total_packages: usize = 0usize;
    for n in nodes.values() {
        match n.kind {
            ModuleKind::Module | ModuleKind::EntryScript | ModuleKind::Bootstrap => {
                total_modules += 1;
            }
            ModuleKind::Package => total_packages += 1,
            ModuleKind::Resource | ModuleKind::NativeBinding => {}
        }
    }

    DependencyTree {
        schema: "disrobe.pyinstaller.deptree/v0".to_owned(),
        python_major: output.cookie.python_major,
        python_minor: output.cookie.python_minor,
        entry_point,
        roots,
        nodes,
        total_modules,
        total_packages,
    }
}

fn is_bootstrap(name: &str) -> bool {
    name.starts_with("pyiboot") || name.starts_with("pyimod") || name == "struct"
}

fn upsert(
    nodes: &mut BTreeMap<String, DependencyNode>,
    name: String,
    kind: ModuleKind,
    origin: &'static str,
    byte_size: u64,
) {
    let key: String = name.clone();
    nodes
        .entry(key)
        .and_modify(|n| {
            n.byte_size = n.byte_size.max(byte_size);
            if kind_priority(kind) > kind_priority(n.kind) {
                n.kind = kind;
                origin.clone_into(&mut n.origin);
            }
        })
        .or_insert_with(|| DependencyNode {
            qualified_name: name,
            kind,
            origin: origin.to_owned(),
            byte_size,
            children: Vec::new(),
        });
}

const fn kind_priority(k: ModuleKind) -> u8 {
    match k {
        ModuleKind::Resource => 0,
        ModuleKind::NativeBinding => 1,
        ModuleKind::Bootstrap => 2,
        ModuleKind::Module => 3,
        ModuleKind::Package => 4,
        ModuleKind::EntryScript => 5,
    }
}

fn link_parent_child(nodes: &mut BTreeMap<String, DependencyNode>) {
    let names: Vec<String> = nodes.keys().cloned().collect();
    for name in names {
        let Some(parent) = parent_of(&name) else {
            continue;
        };
        if let Some(parent_node) = nodes.get_mut(&parent)
            && !parent_node.children.iter().any(|c| c == &name)
        {
            parent_node.children.push(name);
        }
    }
    for node in nodes.values_mut() {
        node.children.sort();
        node.children.dedup();
    }
}

fn parent_of(name: &str) -> Option<String> {
    let idx: usize = name.rfind('.')?;
    if idx == 0 {
        return None;
    }
    Some(name[..idx].to_owned())
}

fn collect_roots(nodes: &BTreeMap<String, DependencyNode>) -> Vec<String> {
    let mut roots: Vec<String> = Vec::new();
    for n in nodes.keys() {
        if let Some(parent) = parent_of(n)
            && nodes.contains_key(&parent)
        {
            continue;
        }
        roots.push(n.clone());
    }
    roots
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::cookie::{Cookie, CookieVariant};
    use crate::extract::{ExtractOutput, ExtractedEntry};
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

    fn entry(name: &str, kind: EntryType) -> ExtractedEntry {
        let entry_size: u32 = u32::try_from(18 + name.len()).expect("name fits u32");
        ExtractedEntry {
            toc: TocEntry {
                entry_size,
                entry_position: 0,
                compressed_size: 10,
                uncompressed_size: 10,
                compressed_flag: 0,
                entry_type: kind,
                name: name.to_owned(),
            },
            data: vec![0u8; 10],
            written_path: None,
            decrypted: false,
            pyc_unzipped: false,
            pyc_compression: None,
        }
    }

    fn output_with(entries: Vec<ExtractedEntry>) -> ExtractOutput {
        ExtractOutput {
            cookie: synthetic_cookie(),
            bare_pyc_paths: Vec::new(),
            encryption_key: None,
            entries,
            pyz_module_count: 0,
            pyc_unzipped_count: 0,
            base_library_module_count: 0,
        }
    }

    fn pyz_entry(name: &str, kind: PyzTocKind, sz: usize) -> PyzEntry {
        let length: i32 = i32::try_from(sz).expect("size fits i32");
        PyzEntry {
            name: name.to_owned(),
            kind,
            position: 0,
            length,
            bytes: vec![0u8; sz],
        }
    }

    #[test]
    fn entry_point_is_first_script() {
        let entries: Vec<ExtractedEntry> = vec![
            entry("main", EntryType::Script),
            entry("util", EntryType::Module),
        ];
        let out: ExtractOutput = output_with(entries);
        let tree: DependencyTree = build_dependency_tree(&out, &[]);
        assert_eq!(tree.entry_point.as_deref(), Some("main"));
    }

    #[test]
    fn parents_link_to_children() {
        let pyz: Vec<PyzEntry> = vec![
            pyz_entry("requests", PyzTocKind::Package, 8),
            pyz_entry("requests.api", PyzTocKind::Module, 8),
            pyz_entry("requests.adapters", PyzTocKind::Module, 8),
            pyz_entry("requests.api.helpers", PyzTocKind::Module, 8),
        ];
        let out: ExtractOutput = output_with(vec![]);
        let tree: DependencyTree = build_dependency_tree(&out, &pyz);
        let requests: &DependencyNode = tree.nodes.get("requests").expect("requests node");
        assert!(requests.children.iter().any(|c| c == "requests.api"));
        assert!(requests.children.iter().any(|c| c == "requests.adapters"));
        let api: &DependencyNode = tree.nodes.get("requests.api").expect("requests.api node");
        assert!(api.children.iter().any(|c| c == "requests.api.helpers"));
    }

    #[test]
    fn roots_exclude_nodes_with_known_parents() {
        let pyz: Vec<PyzEntry> = vec![
            pyz_entry("a", PyzTocKind::Package, 4),
            pyz_entry("a.b", PyzTocKind::Module, 4),
            pyz_entry("c", PyzTocKind::Module, 4),
        ];
        let out: ExtractOutput = output_with(vec![]);
        let tree: DependencyTree = build_dependency_tree(&out, &pyz);
        assert!(tree.roots.iter().any(|r| r == "a"));
        assert!(tree.roots.iter().any(|r| r == "c"));
        assert!(!tree.roots.iter().any(|r| r == "a.b"));
    }

    #[test]
    fn carchive_module_is_bootstrap_when_named_pyiboot_or_pyimod() {
        let entries: Vec<ExtractedEntry> = vec![
            entry("pyiboot01_bootstrap", EntryType::Module),
            entry("pyimod02_importers", EntryType::Module),
            entry("user", EntryType::Module),
        ];
        let out: ExtractOutput = output_with(entries);
        let tree: DependencyTree = build_dependency_tree(&out, &[]);
        assert_eq!(
            tree.nodes.get("pyiboot01_bootstrap").map(|n| n.kind),
            Some(ModuleKind::Bootstrap)
        );
        assert_eq!(
            tree.nodes.get("pyimod02_importers").map(|n| n.kind),
            Some(ModuleKind::Bootstrap)
        );
        assert_eq!(
            tree.nodes.get("user").map(|n| n.kind),
            Some(ModuleKind::Module)
        );
    }

    #[test]
    fn totals_count_modules_and_packages_separately() {
        let pyz: Vec<PyzEntry> = vec![
            pyz_entry("a", PyzTocKind::Package, 4),
            pyz_entry("a.b", PyzTocKind::Module, 4),
            pyz_entry("a.c", PyzTocKind::Module, 4),
        ];
        let out: ExtractOutput = output_with(vec![entry("main", EntryType::Script)]);
        let tree: DependencyTree = build_dependency_tree(&out, &pyz);
        assert_eq!(tree.total_packages, 1);
        assert_eq!(tree.total_modules, 3);
    }

    #[test]
    fn kind_promotion_keeps_higher_priority_label() {
        let entries: Vec<ExtractedEntry> = vec![entry("pkg", EntryType::Package)];
        let out: ExtractOutput = output_with(entries);
        let pyz: Vec<PyzEntry> = vec![pyz_entry("pkg", PyzTocKind::Module, 4)];
        let tree: DependencyTree = build_dependency_tree(&out, &pyz);
        assert_eq!(
            tree.nodes.get("pkg").map(|n| n.kind),
            Some(ModuleKind::Package)
        );
    }

    #[test]
    fn module_kind_labels_are_ascii_and_unique() {
        let labels: [&'static str; 6] = [
            ModuleKind::EntryScript.label(),
            ModuleKind::Module.label(),
            ModuleKind::Package.label(),
            ModuleKind::Resource.label(),
            ModuleKind::NativeBinding.label(),
            ModuleKind::Bootstrap.label(),
        ];
        for l in labels {
            assert!(l.is_ascii());
            assert!(!l.is_empty());
        }
        let mut sorted: Vec<&str> = labels.into_iter().collect();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 6);
    }
}
