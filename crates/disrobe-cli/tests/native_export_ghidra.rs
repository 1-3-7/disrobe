#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::panic,
    clippy::unnecessary_debug_formatting
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use object::{Object, ObjectSymbol};

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn corpus_path(rel: &str) -> PathBuf {
    workspace_root().join("corpus").join(rel)
}

fn cargo_bin() -> PathBuf {
    let exe_name: &str = if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    };
    let mut p: PathBuf = workspace_root();
    p.push("target");
    p.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    p.push(exe_name);
    p
}

#[allow(clippy::disallowed_methods)]
fn tmp_dir(name: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-export-{name}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

fn run_export(input: &Path, out_dir: &Path, format: &str) -> Output {
    let bin: PathBuf = cargo_bin();
    assert!(
        bin.exists(),
        "disrobe binary missing at {bin:?}; run `cargo build -p disrobe-cli` first"
    );
    Command::new(&bin)
        .arg("native")
        .arg("export")
        .arg(input)
        .arg("--out")
        .arg(out_dir)
        .arg("--format")
        .arg(format)
        .output()
        .unwrap_or_else(|e: std::io::Error| panic!("failed to spawn disrobe export: {e}"))
}

fn locate_analyze_headless() -> Option<PathBuf> {
    let names: [&str; 2] = if cfg!(windows) {
        ["analyzeHeadless.bat", "analyzeHeadless"]
    } else {
        ["analyzeHeadless", "analyzeHeadless.bat"]
    };
    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            for name in names {
                let cand: PathBuf = dir.join(name);
                if cand.is_file() {
                    return Some(cand);
                }
            }
        }
    }
    for var in ["GHIDRA_HOME", "GHIDRA_INSTALL_DIR"] {
        if let Ok(home) = std::env::var(var) {
            let base: PathBuf = PathBuf::from(home);
            for name in names {
                let cand: PathBuf = base.join("support").join(name);
                if cand.is_file() {
                    return Some(cand);
                }
            }
        }
    }
    None
}

fn count_object_functions(bytes: &[u8]) -> usize {
    let Ok(file): Result<object::File<'_>, object::Error> = object::File::parse(bytes) else {
        return 0;
    };
    let mut names: BTreeSet<String> = BTreeSet::new();
    for sym in file.symbols() {
        if sym.kind() != object::SymbolKind::Text || sym.address() == 0 {
            continue;
        }
        let Ok(name) = sym.name() else {
            continue;
        };
        if !name.is_empty() {
            names.insert(name.to_owned());
        }
    }
    names.len()
}

const HEADLESS_SCRIPT: &str = "DisrobeCountScript.java";

fn write_count_script(dir: &Path) -> PathBuf {
    let body: &str = "import ghidra.app.script.GhidraScript;\n\
        import ghidra.program.model.listing.Function;\n\
        import ghidra.program.model.listing.FunctionIterator;\n\
        import ghidra.program.model.symbol.Symbol;\n\
        import ghidra.program.model.symbol.SymbolIterator;\n\n\
        public class DisrobeCountScript extends GhidraScript {\n\
        \x20\x20\x20\x20@Override\n\
        \x20\x20\x20\x20public void run() throws Exception {\n\
        \x20\x20\x20\x20\x20\x20\x20\x20int funcs = 0;\n\
        \x20\x20\x20\x20\x20\x20\x20\x20FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);\n\
        \x20\x20\x20\x20\x20\x20\x20\x20while (fi.hasNext()) { fi.next(); funcs++; }\n\
        \x20\x20\x20\x20\x20\x20\x20\x20int syms = 0;\n\
        \x20\x20\x20\x20\x20\x20\x20\x20SymbolIterator si = currentProgram.getSymbolTable().getAllSymbols(true);\n\
        \x20\x20\x20\x20\x20\x20\x20\x20while (si.hasNext()) { si.next(); syms++; }\n\
        \x20\x20\x20\x20\x20\x20\x20\x20println(\"DISROBE_COUNT functions=\" + funcs + \" symbols=\" + syms);\n\
        \x20\x20\x20\x20}\n\
        }\n";
    let path: PathBuf = dir.join(HEADLESS_SCRIPT);
    std::fs::write(&path, body).expect("write count script");
    path
}

fn run_ghidra_count(
    ghidra: &Path,
    project: &Path,
    input: &Path,
    script_dir: &Path,
) -> Option<usize> {
    std::fs::create_dir_all(project).expect("mk project");
    let out: Output = Command::new(ghidra)
        .arg(project)
        .arg("disrobe-bench")
        .arg("-import")
        .arg(input)
        .arg("-postScript")
        .arg(HEADLESS_SCRIPT)
        .arg("-scriptPath")
        .arg(script_dir)
        .arg("-deleteProject")
        .arg("-overwrite")
        .output()
        .unwrap_or_else(|e: std::io::Error| {
            panic!(
                "failed to spawn {} for {}: {e}",
                ghidra.display(),
                input.display()
            )
        });
    let text: String = String::from_utf8_lossy(&out.stdout).into_owned();
    for line in text.lines() {
        if let Some(rest) = line.split_once("DISROBE_COUNT functions=") {
            let tail: &str = rest.1;
            let num: String = tail
                .chars()
                .take_while(|c: &char| c.is_ascii_digit())
                .collect();
            if let Ok(n) = num.parse::<usize>() {
                return Some(n);
            }
        }
    }
    None
}

#[test]
fn native_export_produces_loadable_pe_and_parseable_sidecar() {
    let packed: PathBuf = corpus_path("native/packers/upx/hello.packed.nrv2b.exe");
    if !packed.exists() {
        eprintln!("SKIP: fixture missing: {packed:?}");
        return;
    }
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = tmp_dir("wellformed");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();

    let proc_out: Output = run_export(&packed, &out_dir, "ghidra");
    assert!(
        proc_out.status.success(),
        "native export must succeed; stderr: {}",
        String::from_utf8_lossy(&proc_out.stderr)
    );

    let rebuilt_path: PathBuf = out_dir.join("hello.packed.nrv2b.unpacked.exe");
    let sidecar_path: PathBuf = out_dir.join("hello.packed.nrv2b.ghidra.java");
    let map_path: PathBuf = out_dir.join("hello.packed.nrv2b.symbols.json");

    let rebuilt: Vec<u8> = std::fs::read(&rebuilt_path)
        .unwrap_or_else(|e: std::io::Error| panic!("read rebuilt image: {e}"));
    assert!(
        object::File::parse(rebuilt.as_slice()).is_ok(),
        "the disrobe-exported unpacked image must re-parse as a valid object file"
    );

    let java: String = std::fs::read_to_string(&sidecar_path)
        .unwrap_or_else(|e: std::io::Error| panic!("read ghidra sidecar: {e}"));
    assert!(
        java.contains("public class DisrobeApplySymbols extends GhidraScript"),
        "ghidra post-script must declare the apply class"
    );
    assert_eq!(
        java.matches('{').count(),
        java.matches('}').count(),
        "ghidra post-script braces must balance (parseable Java)"
    );

    let map_text: String = std::fs::read_to_string(&map_path)
        .unwrap_or_else(|e: std::io::Error| panic!("read symbol map: {e}"));
    let map: serde_json::Value =
        serde_json::from_str(&map_text).expect("symbol map must be valid JSON");
    assert_eq!(map["schema"], "disrobe.native.symbol-map/v1");
    assert!(
        map["symbol_count"].as_u64().unwrap_or(0) >= 1,
        "symbol map must carry at least one recovered symbol"
    );

    let _ = std::fs::remove_dir_all(&out_dir);
    eprintln!("export well-formedness OK: rebuilt PE re-parses, ghidra .java + symbols.json valid");
}

#[test]
fn native_export_before_after_ghidra_recovers_more() {
    let packed: PathBuf = corpus_path("native/packers/upx/hello.packed.nrv2b.exe");
    if !packed.exists() {
        eprintln!("SKIP: fixture missing: {packed:?}");
        return;
    }

    let out_dir_scratch: disrobe_core::scratch::ScratchDir = tmp_dir("delta");

    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
    let proc_out: Output = run_export(&packed, &out_dir, "json");
    assert!(
        proc_out.status.success(),
        "native export must succeed; stderr: {}",
        String::from_utf8_lossy(&proc_out.stderr)
    );
    let exported: PathBuf = out_dir.join("hello.packed.nrv2b.unpacked.exe");
    assert!(exported.exists(), "exported image must exist");

    let packed_bytes: Vec<u8> =
        std::fs::read(&packed).unwrap_or_else(|e: std::io::Error| panic!("read packed: {e}"));
    let exported_bytes: Vec<u8> =
        std::fs::read(&exported).unwrap_or_else(|e: std::io::Error| panic!("read exported: {e}"));
    assert_ne!(
        packed_bytes, exported_bytes,
        "the exported image must differ from the raw packed input (else the unpack is a no-op)"
    );

    let Some(ghidra): Option<PathBuf> = locate_analyze_headless() else {
        let raw_static: usize = count_object_functions(&packed_bytes);
        let exported_static: usize = count_object_functions(&exported_bytes);
        eprintln!(
            "SKIP(ghidra-absent): analyzeHeadless not on PATH/GHIDRA_HOME; before/after recovery \
             delta is PENDING a runner with Ghidra. Static object-symbol function counts (a weak \
             proxy, NOT the Ghidra oracle): raw_packed={raw_static}, disrobe_exported={exported_static}. \
             The exported image differs from the raw input ({} vs {} bytes) and re-parses cleanly.",
            packed_bytes.len(),
            exported_bytes.len()
        );
        let _ = std::fs::remove_dir_all(&out_dir);
        return;
    };

    let script_dir: PathBuf = out_dir.join("scripts");
    std::fs::create_dir_all(&script_dir).expect("mk script dir");
    write_count_script(&script_dir);

    let raw_funcs: usize =
        run_ghidra_count(&ghidra, &out_dir.join("proj-raw"), &packed, &script_dir)
            .expect("ghidra count on raw packed input");
    let exported_funcs: usize =
        run_ghidra_count(&ghidra, &out_dir.join("proj-exp"), &exported, &script_dir)
            .expect("ghidra count on disrobe-exported input");

    eprintln!(
        "GHIDRA before/after: raw_packed functions={raw_funcs}, disrobe_exported functions={exported_funcs}"
    );
    assert!(
        exported_funcs > raw_funcs,
        "Ghidra must recover materially MORE functions from the disrobe-exported unpacked image \
         ({exported_funcs}) than from the raw packed input ({raw_funcs})"
    );

    let _ = std::fs::remove_dir_all(&out_dir);
}
