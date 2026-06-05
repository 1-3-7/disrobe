#![allow(clippy::panic)]

use disrobe_binfmt::{
    Arch, Endian, ExportInfo, ImportGraph, ImportInfo, NativeFile, ParsedNativeFormat,
    import_graph_dot,
};

const fn nf(imports: Vec<ImportInfo>, exports: Vec<ExportInfo>) -> NativeFile {
    NativeFile {
        format: ParsedNativeFormat::Pe64,
        arch: Arch::X86_64,
        bits: 64,
        endian: Endian::Little,
        sections: Vec::new(),
        symbols: Vec::new(),
        imports,
        exports,
        debug_info_present: false,
        segments: Vec::new(),
    }
}

fn imp(library: &str, name: &str) -> ImportInfo {
    ImportInfo {
        library: library.to_owned(),
        name: name.to_owned(),
    }
}

fn exp(name: &str, address: u64) -> ExportInfo {
    ExportInfo {
        name: name.to_owned(),
        address,
    }
}

#[test]
fn header_and_trailer_present() {
    let file: NativeFile = nf(vec![imp("kernel32.dll", "GetProcAddress")], Vec::new());
    let dot: String = import_graph_dot(&file);
    assert!(dot.starts_with("digraph \"imports\" {"));
    assert!(dot.trim_end().ends_with('}'));
    assert!(dot.contains("rankdir=LR;"));
}

#[test]
fn known_import_edges_present() {
    let file: NativeFile = nf(
        vec![
            imp("kernel32.dll", "GetProcAddress"),
            imp("kernel32.dll", "LoadLibraryA"),
        ],
        Vec::new(),
    );
    let dot: String = import_graph_dot(&file);
    assert!(dot.contains("\"kernel32.dll\" -> \"GetProcAddress\";"));
    assert!(dot.contains("\"kernel32.dll\" -> \"LoadLibraryA\";"));
}

#[test]
fn multi_library_grouping() {
    let file: NativeFile = nf(
        vec![
            imp("kernel32.dll", "GetProcAddress"),
            imp("user32.dll", "MessageBoxA"),
        ],
        Vec::new(),
    );
    let dot: String = import_graph_dot(&file);
    assert!(dot.contains("\"kernel32.dll\" -> \"GetProcAddress\";"));
    assert!(dot.contains("\"user32.dll\" -> \"MessageBoxA\";"));
    let Some(k32): Option<usize> = dot.find("\"kernel32.dll\"") else {
        panic!("kernel32 node missing");
    };
    let Some(u32_pos): Option<usize> = dot.find("\"user32.dll\"") else {
        panic!("user32 node missing");
    };
    assert!(k32 < u32_pos);
}

#[test]
fn exports_cluster_present() {
    let file: NativeFile = nf(Vec::new(), vec![exp("DllMain", 0x1000)]);
    let dot: String = import_graph_dot(&file);
    assert!(dot.contains("\"(exports)\" -> \"DllMain\";"));
}

#[test]
fn elf_empty_library_bucket() {
    let file: NativeFile = nf(vec![imp("", "puts")], Vec::new());
    let dot: String = import_graph_dot(&file);
    assert!(dot.contains("\"(no-library)\" -> \"puts\";"));
    assert!(!dot.contains("\"\" ->"));
}

#[test]
fn escaping_quote_and_backslash() {
    let file: NativeFile = nf(vec![imp("kernel32.dll", "a\"b\\c")], Vec::new());
    let dot: String = import_graph_dot(&file);
    assert!(dot.contains("\"kernel32.dll\" -> \"a\\\"b\\\\c\";"));
    assert!(!dot.contains("\"a\"b"));
}

#[test]
fn dedup_and_determinism() {
    let file: NativeFile = nf(
        vec![
            imp("kernel32.dll", "GetProcAddress"),
            imp("kernel32.dll", "GetProcAddress"),
        ],
        Vec::new(),
    );
    let dot: String = import_graph_dot(&file);
    assert_eq!(
        dot.matches("\"kernel32.dll\" -> \"GetProcAddress\";")
            .count(),
        1
    );
    let graph: ImportGraph = ImportGraph::from_native(&file);
    assert_eq!(graph.emit_dot(), graph.emit_dot());
}

#[test]
fn empty_graph_still_valid() {
    let file: NativeFile = nf(Vec::new(), Vec::new());
    let dot: String = import_graph_dot(&file);
    assert_eq!(dot, "digraph \"imports\" {\nrankdir=LR;\n}\n");
    assert!(dot.contains("digraph \"imports\" {"));
    assert!(dot.contains('}'));
    assert!(!dot.contains("->"));
    assert!(ImportGraph::from_native(&file).is_empty());
}

#[test]
fn every_body_line_matches_edge_grammar() {
    let file: NativeFile = nf(
        vec![
            imp("kernel32.dll", "GetProcAddress"),
            imp("user32.dll", "MessageBoxA"),
            imp("", "puts"),
        ],
        vec![exp("DllMain", 0x1000)],
    );
    let dot: String = import_graph_dot(&file);
    for line in dot.lines() {
        if line == "digraph \"imports\" {" || line == "rankdir=LR;" || line == "}" {
            continue;
        }
        assert!(
            line.starts_with('"') && line.contains("\" -> \"") && line.ends_with("\";"),
            "malformed DOT line leaked: {line:?}"
        );
    }
}
