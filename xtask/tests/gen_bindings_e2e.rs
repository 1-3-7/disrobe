#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask manifest dir has a parent")
        .to_path_buf()
}

fn schemas_dir() -> PathBuf {
    workspace_root().join("schemas").join("v0").join("json")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e: std::io::Error| panic!("reading {}: {e}", path.display()))
}

fn resolve_node_tool(base: &str) -> Option<String> {
    let candidates: [String; 3] = if cfg!(windows) {
        [
            format!("{base}.cmd"),
            format!("{base}.exe"),
            base.to_owned(),
        ]
    } else {
        [base.to_owned(), base.to_owned(), base.to_owned()]
    };
    for cand in candidates {
        let ok: bool = Command::new(&cand)
            .arg("--version")
            .output()
            .is_ok_and(|o: Output| o.status.success());
        if ok {
            return Some(cand);
        }
    }
    None
}

fn tool_available(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .output()
        .is_ok_and(|o: Output| o.status.success())
}

fn pascal(input: &str) -> String {
    let mut out: String = String::with_capacity(input.len());
    let mut capitalize: bool = true;
    for ch in input.chars() {
        if matches!(ch, '-' | '_' | '.' | '/' | ' ') {
            capitalize = true;
            continue;
        }
        if capitalize {
            out.extend(ch.to_uppercase());
            capitalize = false;
        } else {
            out.push(ch);
        }
    }
    out
}

struct SchemaGroundTruth {
    base: String,
    title: String,
    properties: BTreeSet<String>,
}

fn load_ground_truth() -> Vec<SchemaGroundTruth> {
    let dir: PathBuf = schemas_dir();
    assert!(dir.is_dir(), "schemas dir missing: {}", dir.display());
    let mut out: Vec<SchemaGroundTruth> = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("reading schemas dir") {
        let path: PathBuf = entry.expect("dir entry").path();
        let Some(ext): Option<&str> = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        if !ext.eq_ignore_ascii_case("json") {
            continue;
        }
        let stem: String = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("schema stem is utf-8")
            .to_owned();
        let base: String = stem.replace(".schema", "");
        let value: serde_json::Value =
            serde_json::from_str(&read(&path)).expect("schema JSON parses");
        let title: String = value
            .get("title")
            .and_then(serde_json::Value::as_str)
            .map_or_else(|| pascal(&base), str::to_owned);
        let properties: BTreeSet<String> = value
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        out.push(SchemaGroundTruth {
            base,
            title,
            properties,
        });
    }
    out.sort_by(|a: &SchemaGroundTruth, b: &SchemaGroundTruth| a.base.cmp(&b.base));
    out
}

fn run_gen_bindings(out_dir: &Path) -> Output {
    let bin: &str = env!("CARGO_BIN_EXE_xtask");
    Command::new(bin)
        .arg("gen-bindings")
        .arg("--out-dir")
        .arg(out_dir)
        .output()
        .unwrap_or_else(|e: std::io::Error| panic!("spawning xtask gen-bindings: {e}"))
}

fn validate_pyi_parses(path: &Path) {
    let script: String = format!(
        "import ast,sys; ast.parse(open(r'{}', encoding='utf-8').read())",
        path.display()
    );
    let out: Output = Command::new("python")
        .arg("-c")
        .arg(&script)
        .output()
        .unwrap_or_else(|e: std::io::Error| panic!("spawning python for {}: {e}", path.display()));
    assert!(
        out.status.success(),
        "generated {} is not valid Python (ast.parse failed): {}",
        path.display(),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn structural_dts_check(path: &Path, ground_truth: &SchemaGroundTruth) {
    let body: String = read(path);
    let declares_root: bool = body.contains(&format!("export interface {} ", ground_truth.title))
        || body.contains(&format!("export interface {} {{", ground_truth.title))
        || body.contains(&format!("export type {} =", ground_truth.title));
    assert!(
        declares_root,
        "{} does not declare its root type `{}`",
        path.display(),
        ground_truth.title
    );
    assert_eq!(
        body.matches('{').count(),
        body.matches('}').count(),
        "{} has unbalanced braces",
        path.display()
    );
    assert_eq!(
        body.matches('<').count(),
        body.matches('>').count(),
        "{} has unbalanced angle brackets",
        path.display()
    );
    for prop in &ground_truth.properties {
        assert!(
            body.contains(prop.as_str()),
            "{} omits schema property `{}`",
            path.display(),
            prop
        );
    }
}

fn tsc_check(dir: &Path) -> bool {
    let Some(tsc): Option<String> = resolve_node_tool("tsc") else {
        eprintln!("SKIP: tsc not on PATH; falling back to structural .d.ts validation only");
        return false;
    };
    let mut decls: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(dir).expect("reading typescript out dir") {
        let path: PathBuf = entry.expect("dir entry").path();
        if path.to_str().is_some_and(|s: &str| s.ends_with(".d.ts")) {
            decls.push(path);
        }
    }
    decls.sort();
    let mut cmd: Command = Command::new(&tsc);
    cmd.arg("--noEmit").arg("--strict").arg("--skipLibCheck");
    for decl in &decls {
        cmd.arg(decl);
    }
    let out: Output = cmd
        .output()
        .unwrap_or_else(|e: std::io::Error| panic!("spawning tsc: {e}"));
    assert!(
        out.status.success(),
        "tsc --noEmit rejected generated .d.ts files:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    true
}

#[test]
fn gen_bindings_emits_valid_python_and_typescript() {
    let ground_truth: Vec<SchemaGroundTruth> = load_ground_truth();
    assert!(
        ground_truth.len() >= 4,
        "expected >=4 source schemas, found {}",
        ground_truth.len()
    );

    let tmp: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let out_dir: PathBuf = tmp.path().to_path_buf();

    let run: Output = run_gen_bindings(&out_dir);
    assert!(
        run.status.success(),
        "xtask gen-bindings failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    let py_dir: PathBuf = out_dir.join("python");
    let ts_dir: PathBuf = out_dir.join("typescript");
    assert!(py_dir.is_dir(), "missing {}", py_dir.display());
    assert!(ts_dir.is_dir(), "missing {}", ts_dir.display());

    let by_base: BTreeMap<&str, &SchemaGroundTruth> = ground_truth
        .iter()
        .map(|g: &SchemaGroundTruth| (g.base.as_str(), g))
        .collect();

    let python_ok: bool = tool_available("python", &["--version"]);
    if !python_ok {
        eprintln!("SKIP: python not on PATH; cannot ast.parse generated .pyi stubs");
    }

    for (base, truth) in &by_base {
        let pyi: PathBuf = py_dir.join(format!("{base}.pyi"));
        let dts: PathBuf = ts_dir.join(format!("{base}.d.ts"));
        assert!(pyi.is_file(), "missing generated {}", pyi.display());
        assert!(dts.is_file(), "missing generated {}", dts.display());

        if python_ok {
            validate_pyi_parses(&pyi);
            let body: String = read(&pyi);
            let declares_root: bool = body.contains(&format!("class {}(", truth.title))
                || body.contains(&format!("{} = ", truth.title));
            assert!(
                declares_root,
                "{} does not declare its root type `{}`",
                pyi.display(),
                truth.title
            );
            for prop in &truth.properties {
                assert!(
                    body.contains(prop.as_str()),
                    "{} omits schema property `{}`",
                    pyi.display(),
                    prop
                );
            }
        }

        structural_dts_check(&dts, truth);
    }

    let _: bool = tsc_check(&ts_dir);
}
