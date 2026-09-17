#![allow(
    dead_code,
    unreachable_pub,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic
)]

use std::fs;
use std::path::{Component, Path, PathBuf};

use disrobe_pass_wasm_deob::{CalleeNames, ModuleSignatures};
use wasmparser::{FunctionBody, Parser, Payload};

pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

pub fn corpus_dirs() -> Vec<PathBuf> {
    let root: PathBuf = workspace_root();
    vec![
        root.join("corpus").join("src").join("wasm").join("sources"),
        root.join("corpus")
            .join("src")
            .join("wasm")
            .join("edge_cases"),
        root.join("corpus").join("wasm").join("wat"),
        root.join("corpus").join("wasm").join("plugins"),
    ]
}

pub fn corpus_key(path: &Path) -> String {
    let root: PathBuf = workspace_root();
    let relative: &Path = path.strip_prefix(&root).unwrap_or(path);
    relative
        .components()
        .filter_map(|component: Component<'_>| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<String>>()
        .join("/")
}

pub fn wat_files() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for dir in corpus_dirs() {
        let Ok(entries): Result<fs::ReadDir, _> = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path: PathBuf = entry.path();
            if path.extension().is_some_and(|e| e == "wat") {
                out.push(path);
            }
        }
    }
    out.sort_by_key(|path: &PathBuf| corpus_key(path));
    out
}

pub fn callees(sigs: &ModuleSignatures) -> CalleeNames {
    CalleeNames::with_signatures(
        sigs.callee_names(),
        sigs.call_signatures(),
        sigs.call_signatures(),
    )
}

pub fn defined_bodies(bytes: &[u8]) -> Vec<FunctionBody<'_>> {
    let mut out: Vec<FunctionBody<'_>> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        if let Ok(Payload::CodeSectionEntry(body)) = payload {
            out.push(body);
        }
    }
    out
}
