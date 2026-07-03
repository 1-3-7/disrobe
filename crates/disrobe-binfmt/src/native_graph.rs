#![allow(clippy::module_name_repetitions)]
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use crate::native::NativeFile;

pub const ELF_IMPORT_ROOT: &str = "(no-library)";
const GRAPH_NAME: &str = "imports";
const EXPORTS_NODE: &str = "(exports)";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImportGraph {
    pub modules: BTreeMap<String, Vec<String>>,
    pub exports: Vec<String>,
}

impl ImportGraph {
    #[must_use]
    pub fn from_native(nf: &NativeFile) -> Self {
        let mut grouped: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for import in &nf.imports {
            let library: String = if import.library.is_empty() {
                ELF_IMPORT_ROOT.to_owned()
            } else {
                import.library.clone()
            };
            grouped
                .entry(library)
                .or_default()
                .insert(import.name.clone());
        }
        let modules: BTreeMap<String, Vec<String>> = grouped
            .into_iter()
            .map(|(library, names): (String, BTreeSet<String>)| {
                (library, names.into_iter().collect::<Vec<String>>())
            })
            .collect();

        let mut export_set: BTreeSet<String> = BTreeSet::new();
        for export in &nf.exports {
            export_set.insert(export.name.clone());
        }
        let exports: Vec<String> = export_set.into_iter().collect();

        Self { modules, exports }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty() && self.exports.is_empty()
    }

    #[must_use]
    pub fn emit_dot(&self) -> String {
        let mut out: String = String::new();
        out.push_str("digraph \"");
        out.push_str(&escape_dot_id(GRAPH_NAME));
        out.push_str("\" {\n");
        out.push_str("rankdir=LR;\n");
        for (library, names) in &self.modules {
            let lib_id: String = escape_dot_id(library);
            for name in names {
                out.push('"');
                out.push_str(&lib_id);
                out.push_str("\" -> \"");
                out.push_str(&escape_dot_id(name));
                out.push_str("\";\n");
            }
        }
        if !self.exports.is_empty() {
            let root_id: String = escape_dot_id(EXPORTS_NODE);
            for name in &self.exports {
                out.push('"');
                out.push_str(&root_id);
                out.push_str("\" -> \"");
                out.push_str(&escape_dot_id(name));
                out.push_str("\";\n");
            }
        }
        out.push_str("}\n");
        out
    }
}

#[must_use]
pub fn import_graph_dot(nf: &NativeFile) -> String {
    ImportGraph::from_native(nf).emit_dot()
}

fn escape_dot_id(raw: &str) -> String {
    let mut out: String = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' | '\r' => out.push(' '),
            other => out.push(other),
        }
    }
    out
}
