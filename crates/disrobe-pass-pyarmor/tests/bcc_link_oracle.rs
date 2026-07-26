#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_core::scratch::ScratchFile;
use disrobe_pass_pyarmor::{
    BccArch, BccBlob, BccLinkOutput, FunctionRecord, LinkConfidence, NameStatus, UnpackOptions,
    link_bcc_from_unpack, link_bcc_module, unpack_wrapper_text_with_options,
};
use disrobe_py_marshal::{CodeObject, Object, PyVersion, load};

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bcc_pkgtest")
}

fn python() -> Option<String> {
    for candidate in ["python", "python3", "py"] {
        let ok: bool = Command::new(candidate)
            .arg("--version")
            .output()
            .is_ok_and(|o: std::process::Output| o.status.success());
        if ok {
            return Some(candidate.to_owned());
        }
    }
    None
}

#[derive(Debug, Clone)]
struct AuthoredFact {
    qualname: String,
    class: Option<String>,
    argcount: u32,
    posonly: u32,
    kwonly: u32,
    varargs: bool,
    varkeywords: bool,
    is_async: bool,
    is_generator: bool,
    firstlineno: i32,
}

const GROUND_TRUTH_SCRIPT: &str = "
import json, sys

path = sys.argv[1]
src = open(path, 'r', encoding='utf-8').read()
co = compile(src, path, 'exec')

def class_of(qual):
    parts = qual.split('.')
    if len(parts) <= 1:
        return None
    prefix = parts[:-1]
    if '<locals>' in prefix:
        return None
    return '.'.join(prefix)

CO_VARARGS = 0x04
CO_VARKEYWORDS = 0x08
CO_GENERATOR = 0x20
CO_COROUTINE = 0x80
CO_ASYNC_GENERATOR = 0x200
COMP = {'<listcomp>', '<setcomp>', '<dictcomp>', '<genexpr>'}

out = []

def walk(c):
    for k in c.co_consts:
        if hasattr(k, 'co_code'):
            name = k.co_name
            flags = k.co_flags
            is_func = bool(flags & 0x1)
            if is_func and name not in COMP:
                qual = getattr(k, 'co_qualname', name)
                is_async = bool(flags & (CO_COROUTINE | CO_ASYNC_GENERATOR))
                is_gen = bool(flags & (CO_GENERATOR | CO_ASYNC_GENERATOR))
                out.append({
                    'qualname': qual,
                    'class': class_of(qual),
                    'argcount': k.co_argcount,
                    'posonly': k.co_posonlyargcount,
                    'kwonly': k.co_kwonlyargcount,
                    'varargs': bool(flags & CO_VARARGS),
                    'varkeywords': bool(flags & CO_VARKEYWORDS),
                    'async': is_async,
                    'generator': is_gen,
                    'line': k.co_firstlineno,
                })
            walk(k)

walk(co)
print(json.dumps(out))
";

fn authored_facts(py: &str, authored: &Path) -> Vec<AuthoredFact> {
    let (guard, mut handle): (ScratchFile, std::fs::File) =
        ScratchFile::create("pyarmor-bcc-ground-truth", "py").expect("scratch script");
    std::io::Write::write_all(&mut handle, GROUND_TRUTH_SCRIPT.as_bytes())
        .expect("write ground-truth script");
    std::io::Write::flush(&mut handle).expect("flush ground-truth script");
    drop(handle);
    let output: std::process::Output = Command::new(py)
        .arg(guard.path())
        .arg(authored)
        .output()
        .expect("run ground-truth compiler");
    assert!(
        output.status.success(),
        "ground-truth compile failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse ground-truth json");
    let array: &Vec<serde_json::Value> = value.as_array().expect("ground truth is an array");
    array
        .iter()
        .map(|item: &serde_json::Value| AuthoredFact {
            qualname: item["qualname"].as_str().unwrap().to_owned(),
            class: item["class"].as_str().map(str::to_owned),
            argcount: u32::try_from(item["argcount"].as_i64().unwrap()).unwrap(),
            posonly: u32::try_from(item["posonly"].as_i64().unwrap()).unwrap(),
            kwonly: u32::try_from(item["kwonly"].as_i64().unwrap()).unwrap(),
            varargs: item["varargs"].as_bool().unwrap(),
            varkeywords: item["varkeywords"].as_bool().unwrap(),
            is_async: item["async"].as_bool().unwrap(),
            is_generator: item["generator"].as_bool().unwrap(),
            firstlineno: i32::try_from(item["line"].as_i64().unwrap()).unwrap(),
        })
        .collect()
}

fn load_module(marshal_path: &Path) -> CodeObject {
    let bytes: Vec<u8> = std::fs::read(marshal_path).expect("read residual marshal");
    let object: Object = load(&bytes, PyVersion::new(3, 14)).expect("marshal decode");
    match object {
        Object::Code(code) => *code,
        _ => panic!("residual marshal root is not a code object"),
    }
}

fn link_from_fixture(name: &str) -> BccLinkOutput {
    let dir: PathBuf = fixture_dir();
    let wrapper_path: PathBuf = dir.join("pkg/mypkg").join(format!("{name}.py"));
    let wrapper_text: String = std::fs::read_to_string(&wrapper_path).expect("read wrapper stub");
    let module: CodeObject = load_module(&dir.join(format!("residual/{name}.marshal.bin")));
    let blob_bytes: Vec<u8> =
        std::fs::read(dir.join(format!("residual/{name}.bcc-winx64.bin"))).expect("read blob");
    let blobs: Vec<BccBlob> = vec![BccBlob {
        architecture: BccArch::WinX64,
        bytes: blob_bytes,
    }];
    link_bcc_module(&module, &blobs, &wrapper_text, &wrapper_path, "3.14")
}

fn find_record<'a>(output: &'a BccLinkOutput, qualname: &str) -> Option<&'a FunctionRecord> {
    output
        .map
        .records
        .iter()
        .find(|r: &&FunctionRecord| r.source.qualname == qualname)
}

fn assert_matches_authored(record: &FunctionRecord, fact: &AuthoredFact) {
    assert_eq!(
        record.source.class, fact.class,
        "class for {}",
        fact.qualname
    );
    assert_eq!(
        record.signature.argcount, fact.argcount,
        "argcount for {}",
        fact.qualname
    );
    assert_eq!(
        record.signature.posonlyargcount, fact.posonly,
        "posonly for {}",
        fact.qualname
    );
    assert_eq!(
        record.signature.kwonlyargcount, fact.kwonly,
        "kwonly for {}",
        fact.qualname
    );
    assert_eq!(
        record.signature.has_varargs, fact.varargs,
        "varargs for {}",
        fact.qualname
    );
    assert_eq!(
        record.signature.has_varkeywords, fact.varkeywords,
        "varkeywords for {}",
        fact.qualname
    );
    assert_eq!(
        record.signature.is_async, fact.is_async,
        "async for {}",
        fact.qualname
    );
    assert_eq!(
        record.signature.is_generator, fact.is_generator,
        "generator for {}",
        fact.qualname
    );
    assert_eq!(
        record.source.firstlineno, fact.firstlineno,
        "firstlineno for {}",
        fact.qualname
    );
}

#[test]
fn every_bcc_native_function_maps_to_authored_identity() {
    let Some(py): Option<String> = python() else {
        eprintln!("no python interpreter; skipping BCC link oracle");
        return;
    };
    let facts: Vec<AuthoredFact> = authored_facts(&py, &fixture_dir().join("authored/calc.py"));
    assert!(
        facts.len() >= 8,
        "authored calc.py exposes the full battery, got {}",
        facts.len()
    );

    let output: BccLinkOutput = link_from_fixture("calc");

    for record in &output.map.records {
        let Some(fact): Option<&AuthoredFact> = facts
            .iter()
            .find(|f: &&AuthoredFact| f.qualname == record.source.qualname)
        else {
            panic!(
                "linker emitted a function {:?} absent from the authored source",
                record.source.qualname
            );
        };
        assert_matches_authored(record, fact);
        assert_eq!(
            record.source.module.as_deref(),
            Some("mypkg.calc"),
            "module for {}",
            fact.qualname
        );
        assert_eq!(
            record.source.py_path.as_deref(),
            Some("mypkg/calc.py"),
            "py_path for {}",
            fact.qualname
        );
    }

    let native: Vec<&FunctionRecord> = output
        .map
        .records
        .iter()
        .filter(|r: &&FunctionRecord| r.native.is_some())
        .collect();
    assert!(
        !native.is_empty(),
        "at least one function is BCC-compiled to native code"
    );

    let mut recovered_correct: usize = 0;
    for record in &native {
        assert_eq!(
            record.confidence,
            LinkConfidence::Confirmed,
            "native function {} is confirmed (residual + dispatch agree)",
            record.source.qualname
        );
        assert_eq!(
            record.name_status,
            NameStatus::Recovered,
            "native function {} has a recovered name",
            record.source.qualname
        );
        assert!(
            record.native.as_ref().is_some_and(|n| n.offset > 0),
            "native function {} carries a real offset",
            record.source.qualname
        );
        if facts
            .iter()
            .any(|f: &AuthoredFact| f.qualname == record.source.qualname)
        {
            recovered_correct += 1;
        }
    }
    assert_eq!(
        recovered_correct,
        native.len(),
        "recovered_correct / total_bcc == 1.0"
    );

    for qual in ["fetch", "gen_range", "Widget.Inner.deep"] {
        let record: &FunctionRecord =
            find_record(&output, qual).unwrap_or_else(|| panic!("missing record for {qual}"));
        assert!(
            record.native.is_none(),
            "{qual} is not BCC-compiled; it stays decompilable bytecode"
        );
    }
    for native_qual in [
        "add",
        "scale",
        "Widget.__init__",
        "Widget.area",
        "Widget.make",
    ] {
        let record: &FunctionRecord = find_record(&output, native_qual)
            .unwrap_or_else(|| panic!("missing record for {native_qual}"));
        assert!(
            record.native.is_some(),
            "{native_qual} is BCC-compiled and carries a native offset"
        );
    }

    assert!(output.json().contains("\"functions_by_offset\""));
    assert!(output.skeleton.contains("class Widget:"));
    assert!(output.skeleton.contains("@native_wall"));
    println!(
        "linked {} functions ({} native, all confirmed) against authored calc.py",
        output.map.records.len(),
        native.len()
    );
}

#[test]
fn renamed_symbols_track_through_the_map() {
    let output: BccLinkOutput = link_from_fixture("calc_perturbed");
    let quals: Vec<&str> = output
        .map
        .records
        .iter()
        .map(|r: &FunctionRecord| r.source.qualname.as_str())
        .collect();

    for expected in [
        "combine",
        "Gadget.__init__",
        "Gadget.surface",
        "Gadget.build",
    ] {
        assert!(
            quals.contains(&expected),
            "perturbed map tracks the renamed symbol {expected}; got {quals:?}"
        );
    }
    for absent in ["add", "Widget", "Widget.area", "Widget.make"] {
        assert!(
            !quals.contains(&absent),
            "perturbed map does not carry the original symbol {absent}; the map is derived, not hardcoded"
        );
    }

    let combine_native: bool = output
        .map
        .records
        .iter()
        .any(|r: &FunctionRecord| r.native.is_some() && r.source.qualname == "combine");
    assert!(combine_native, "renamed native function combine is linked");
    assert_eq!(
        output.map.module.as_deref(),
        Some("mypkg.calc_perturbed"),
        "module identity follows the perturbed file"
    );
}

fn committed_corpus() -> Option<PathBuf> {
    let dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .parent()?
        .join("corpus/python/pyarmor/v9-bcc/default");
    dir.join("known_plaintext.py").is_file().then_some(dir)
}

#[test]
fn end_to_end_link_from_committed_bcc_sample() {
    let Some(py): Option<String> = python() else {
        eprintln!("no python interpreter; skipping end-to-end BCC link oracle");
        return;
    };
    let Some(dir): Option<PathBuf> = committed_corpus() else {
        eprintln!("v9-bcc corpus absent; skipping end-to-end BCC link oracle");
        return;
    };
    let ground_truth: PathBuf = dir
        .parent()
        .expect("corpus parent")
        .join("bench_mod_original.py");
    let facts: Vec<AuthoredFact> = authored_facts(&py, &ground_truth);

    let wrapper_path: PathBuf = dir.join("known_plaintext.py");
    let wrapper_text: String = std::fs::read_to_string(&wrapper_path).expect("read wrapper");
    let opts: UnpackOptions = UnpackOptions {
        allow_bcc: true,
        ..UnpackOptions::default()
    };
    let unpacked = unpack_wrapper_text_with_options(&wrapper_text, &wrapper_path, &opts)
        .expect("unpack committed BCC wrapper");
    let output: BccLinkOutput =
        link_bcc_from_unpack(&unpacked, &wrapper_text, &wrapper_path).expect("link");

    let native: Vec<&FunctionRecord> = output
        .map
        .records
        .iter()
        .filter(|r: &&FunctionRecord| r.native.is_some())
        .collect();
    assert!(
        native.len() >= 4,
        "the authored mix_add/clamp/poly/main are BCC-compiled; got {}",
        native.len()
    );
    for record in &native {
        assert_eq!(record.confidence, LinkConfidence::Confirmed);
        let fact: &AuthoredFact = facts
            .iter()
            .find(|f: &&AuthoredFact| f.qualname == record.source.qualname)
            .unwrap_or_else(|| {
                panic!(
                    "native {} absent from authored bench_mod",
                    record.source.qualname
                )
            });
        assert_matches_authored(record, fact);
    }
    println!(
        "end-to-end linked {} native functions from the committed v9-bcc sample",
        native.len()
    );
}
