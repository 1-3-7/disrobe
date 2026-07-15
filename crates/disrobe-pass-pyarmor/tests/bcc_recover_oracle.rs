#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_pyarmor::{
    BccArch, MapCallResolver, PyAbi, RecoverOptions, RecoveredBody, UnpackOptions,
    link_bcc_from_unpack, recover_from_code, unpack_wrapper_text_with_options,
};
use object::{Object as _, ObjectSection as _, ObjectSymbol as _, RelocationTarget};

fn cc() -> Option<String> {
    for c in ["gcc", "clang"] {
        if Command::new(c)
            .arg("--version")
            .output()
            .is_ok_and(|o: std::process::Output| o.status.success())
        {
            return Some(c.to_owned());
        }
    }
    None
}

fn python() -> Option<String> {
    for c in ["python", "python3", "py"] {
        if Command::new(c)
            .arg("--version")
            .output()
            .is_ok_and(|o: std::process::Output| o.status.success())
        {
            return Some(c.to_owned());
        }
    }
    None
}

fn scratch_dir() -> PathBuf {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe-bcc-recover-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

const fn host_abi() -> PyAbi {
    if cfg!(windows) {
        PyAbi::Win64
    } else {
        PyAbi::SysV
    }
}

struct Case {
    name: &'static str,
    arity: usize,
    c_expr: &'static str,
    reference_python: &'static str,
    expected_expr: &'static str,
}

const BATTERY: &[Case] = &[
    Case {
        name: "add",
        arity: 2,
        c_expr: "PyNumber_Add(a, b)",
        reference_python: "a + b",
        expected_expr: "arg_0 + arg_1",
    },
    Case {
        name: "madd",
        arity: 3,
        c_expr: "PyNumber_Add(a, PyNumber_Multiply(b, c))",
        reference_python: "a + b * c",
        expected_expr: "arg_0 + arg_1 * arg_2",
    },
    Case {
        name: "mixed",
        arity: 2,
        c_expr: "PyNumber_Subtract(PyNumber_Add(a, b), PyNumber_Xor(a, b))",
        reference_python: "(a + b) - (a ^ b)",
        expected_expr: "arg_0 + arg_1 - (arg_0 ^ arg_1)",
    },
    Case {
        name: "bitwise",
        arity: 3,
        c_expr: "PyNumber_Or(PyNumber_And(a, b), c)",
        reference_python: "(a & b) | c",
        expected_expr: "arg_0 & arg_1 | arg_2",
    },
    Case {
        name: "cmp_lt",
        arity: 2,
        c_expr: "PyObject_RichCompare(a, b, 0)",
        reference_python: "a < b",
        expected_expr: "arg_0 < arg_1",
    },
];

fn c_source(case: &Case) -> String {
    let params: Vec<&str> = ["a", "b", "c"][..case.arity].to_vec();
    let signature: String = params
        .iter()
        .map(|p: &&str| format!("PyObject* {p}"))
        .collect::<Vec<String>>()
        .join(", ");
    format!(
        "typedef void PyObject;\n\
         extern PyObject* PyNumber_Add(PyObject*, PyObject*);\n\
         extern PyObject* PyNumber_Subtract(PyObject*, PyObject*);\n\
         extern PyObject* PyNumber_Multiply(PyObject*, PyObject*);\n\
         extern PyObject* PyNumber_And(PyObject*, PyObject*);\n\
         extern PyObject* PyNumber_Or(PyObject*, PyObject*);\n\
         extern PyObject* PyNumber_Xor(PyObject*, PyObject*);\n\
         extern PyObject* PyObject_RichCompare(PyObject*, PyObject*, int);\n\
         PyObject* {}({}) {{ return {}; }}\n",
        case.name, signature, case.c_expr
    )
}

fn compile_object(compiler: &str, dir: &Path, case: &Case) -> Vec<u8> {
    let c_path: PathBuf = dir.join(format!("{}.c", case.name));
    std::fs::write(&c_path, c_source(case)).expect("write c source");
    let o_path: PathBuf = dir.join(format!("{}.o", case.name));
    let out: std::process::Output = Command::new(compiler)
        .args([
            "-O1",
            "-fno-stack-protector",
            "-fcf-protection=none",
            "-fno-asynchronous-unwind-tables",
            "-c",
            "-o",
        ])
        .arg(&o_path)
        .arg(&c_path)
        .output()
        .expect("invoke cc");
    assert!(
        out.status.success(),
        "compile of {} failed: {}",
        case.name,
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read(&o_path).expect("read object")
}

fn recover_case(object_bytes: &[u8], case: &Case) -> RecoveredBody {
    let file: object::File<'_> = object::File::parse(object_bytes).expect("parse object");
    let symbol: object::Symbol<'_, '_> = file
        .symbols()
        .find(|s: &object::Symbol<'_, '_>| {
            s.name()
                .is_ok_and(|n: &str| n == case.name || n == format!("_{}", case.name))
        })
        .expect("function symbol");
    let section_index: object::SectionIndex = match symbol.section() {
        object::SymbolSection::Section(index) => index,
        _ => panic!("function is not in a section"),
    };
    let section: object::Section<'_, '_> = file.section_by_index(section_index).expect("section");
    let section_addr: u64 = section.address();
    let data: &[u8] = section.data().expect("section data");
    let start: usize = usize::try_from(symbol.address().saturating_sub(section_addr)).unwrap();
    let size: usize = usize::try_from(symbol.size()).unwrap();
    let end: usize = if size == 0 {
        data.len()
    } else {
        start.saturating_add(size).min(data.len())
    };
    let code: &[u8] = &data[start..end];

    let mut resolver: MapCallResolver = MapCallResolver::new();
    for (offset, reloc) in section.relocations() {
        if (offset as usize) < start || (offset as usize) >= end {
            continue;
        }
        if reloc.size() != 32 {
            continue;
        }
        let RelocationTarget::Symbol(sym_index) = reloc.target() else {
            continue;
        };
        let Ok(target): Result<object::Symbol<'_, '_>, _> = file.symbol_by_index(sym_index) else {
            continue;
        };
        let Ok(name): Result<&str, _> = target.name() else {
            continue;
        };
        let call_site: u64 = section_addr.wrapping_add(offset).wrapping_sub(1);
        resolver.insert(call_site, name.trim_start_matches('_'));
    }

    let mut options: RecoverOptions =
        RecoverOptions::new(format!("rec_{}", case.name), host_abi(), case.arity);
    options.param_names = Vec::new();
    recover_from_code(code, symbol.address(), &options, &resolver)
}

fn behavioral_check(py: &str, dir: &Path, case: &Case, recovered_def: &str) {
    let call_args: String = (0..case.arity)
        .map(|i: usize| format!("combo[{i}]"))
        .collect::<Vec<String>>()
        .join(", ");
    let script: String = format!(
        "import itertools, sys\n\
         def reference(a, b, c):\n    return {reference}\n\
         {recovered}\n\
         vals = [-7, -3, -1, 0, 1, 2, 5, 11, 123, -456]\n\
         for combo in itertools.product(vals, repeat=3):\n\
         \x20   want = reference(combo[0], combo[1], combo[2])\n\
         \x20   got = rec_{name}({call_args})\n\
         \x20   if want != got:\n\
         \x20       print('MISMATCH', combo, want, got)\n\
         \x20       sys.exit(1)\n\
         print('OK')\n",
        reference = case.reference_python,
        recovered = recovered_def,
        name = case.name,
        call_args = call_args,
    );
    let script_path: PathBuf = dir.join(format!("check_{}.py", case.name));
    std::fs::write(&script_path, script).expect("write check script");
    let out: std::process::Output = Command::new(py)
        .arg(&script_path)
        .output()
        .expect("run behavioral check");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("OK"),
        "behavioral equivalence FAILED for {}: {}\nstderr: {}\nrecovered def:\n{}",
        case.name,
        stdout,
        String::from_utf8_lossy(&out.stderr),
        recovered_def
    );
}

#[test]
fn recovered_python_matches_ground_truth_over_fuzzed_inputs() {
    if !cfg!(target_arch = "x86_64") {
        eprintln!("skipping: recovery targets x86-64 and the host is a different architecture");
        return;
    }
    let Some(compiler): Option<String> = cc() else {
        eprintln!("skipping: no C compiler (gcc/clang) on PATH");
        return;
    };
    let Some(py): Option<String> = python() else {
        eprintln!("skipping: no python interpreter on PATH");
        return;
    };
    let dir: PathBuf = scratch_dir();
    let mut recovered_count: usize = 0;
    for case in BATTERY {
        let object_bytes: Vec<u8> = compile_object(&compiler, &dir, case);
        let body: RecoveredBody = recover_case(&object_bytes, case);
        let Some(recovered_def): Option<String> = body.recovered_python.clone() else {
            eprintln!(
                "skip {}: this compiler build did not lower it into the straight-line C-API expression shape (coverage {:.0}%)",
                case.name,
                body.coverage() * 100.0
            );
            continue;
        };
        assert!(
            (body.coverage() - 1.0).abs() < f64::EPSILON,
            "{} recovered python at less than full coverage",
            case.name
        );
        let expected_line: String = format!("return {}", case.expected_expr);
        assert!(
            recovered_def.contains(&expected_line),
            "{} recovered `{}` but expected `{}`",
            case.name,
            recovered_def.trim(),
            expected_line
        );
        behavioral_check(&py, &dir, case, &recovered_def);
        recovered_count += 1;
        println!("{}: recovered `{}`", case.name, recovered_def.trim());
    }
    assert!(
        recovered_count >= 3,
        "at least the add/madd/mixed straight-line C-API expressions must recover end to end; got {recovered_count}"
    );
    println!(
        "{recovered_count} C-API expression bodies recovered and behaviorally verified via CPython"
    );
}

fn corpus_default_dir() -> Option<PathBuf> {
    let dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .parent()?
        .join("corpus/python/pyarmor/v9-bcc/default");
    dir.is_dir().then_some(dir)
}

fn text_section(blob: &[u8]) -> Option<(u64, Vec<u8>)> {
    const SHF_EXECINSTR: u64 = 0x4;
    if blob.len() < 64 || blob[..4] != [0x7f, b'E', b'L', b'F'] {
        return None;
    }
    let shoff: usize =
        usize::try_from(u64::from_le_bytes(blob[0x28..0x30].try_into().ok()?)).ok()?;
    let shentsize: usize = usize::from(u16::from_le_bytes(blob[0x3a..0x3c].try_into().ok()?));
    let shnum: usize = usize::from(u16::from_le_bytes(blob[0x3c..0x3e].try_into().ok()?));
    let mut best: Option<(u64, Vec<u8>)> = None;
    for index in 0..shnum {
        let base: usize = shoff.checked_add(index.checked_mul(shentsize)?)?;
        if base
            .checked_add(64)
            .is_none_or(|end: usize| end > blob.len())
        {
            break;
        }
        let flags: u64 = u64::from_le_bytes(blob[base + 8..base + 16].try_into().ok()?);
        let addr: u64 = u64::from_le_bytes(blob[base + 16..base + 24].try_into().ok()?);
        let off: usize = usize::try_from(u64::from_le_bytes(
            blob[base + 24..base + 32].try_into().ok()?,
        ))
        .ok()?;
        let sz: usize = usize::try_from(u64::from_le_bytes(
            blob[base + 32..base + 40].try_into().ok()?,
        ))
        .ok()?;
        if flags & SHF_EXECINSTR == 0 || sz == 0 {
            continue;
        }
        let Some(section): Option<&[u8]> =
            off.checked_add(sz).and_then(|e: usize| blob.get(off..e))
        else {
            continue;
        };
        if best
            .as_ref()
            .is_none_or(|(_, b): &(u64, Vec<u8>)| section.len() > b.len())
        {
            best = Some((addr, section.to_vec()));
        }
    }
    best
}

#[test]
fn real_pyarmor_bcc_body_degrades_honestly() {
    let Some(dir): Option<PathBuf> = corpus_default_dir() else {
        eprintln!("v9-bcc corpus absent; skipping honest-degrade check");
        return;
    };
    let wrapper_path: PathBuf = dir.join("known_plaintext.py");
    let wrapper_text: String = std::fs::read_to_string(&wrapper_path).expect("read wrapper");
    let opts: UnpackOptions = UnpackOptions {
        allow_bcc: true,
        ..UnpackOptions::default()
    };
    let unpacked = unpack_wrapper_text_with_options(&wrapper_text, &wrapper_path, &opts)
        .expect("unpack committed BCC wrapper");
    let map = link_bcc_from_unpack(&unpacked, &wrapper_text, &wrapper_path).expect("link");

    let blob: &Vec<u8> = &unpacked.bcc_blobs.first().expect("one bcc blob").bytes;
    let (text_addr, text): (u64, Vec<u8>) = text_section(blob).expect("executable text section");

    let native: Vec<&disrobe_pass_pyarmor::FunctionRecord> = map.map.native_records().collect();
    assert!(!native.is_empty(), "the sample has BCC-compiled functions");

    let mut degraded_bodies: usize = 0;
    for record in &native {
        let Some(reference): Option<&disrobe_pass_pyarmor::NativeRef> = record.native.as_ref()
        else {
            continue;
        };
        let Some(rel): Option<usize> = usize::try_from(reference.offset.saturating_sub(text_addr))
            .ok()
            .filter(|rel: &usize| *rel < text.len())
        else {
            continue;
        };
        let size: usize = usize::try_from(reference.size)
            .unwrap_or(0)
            .min(text.len().saturating_sub(rel));
        if size == 0 {
            continue;
        }
        let code: &[u8] = &text[rel..rel + size];
        let options: RecoverOptions = RecoverOptions::new(
            record.source.qualname.clone(),
            PyAbi::from_arch(BccArch::WinX64),
            record.signature.argcount as usize,
        );
        let empty: MapCallResolver = MapCallResolver::new();
        let body: RecoveredBody = recover_from_code(code, reference.offset, &options, &empty);

        assert!(
            body.recovered_python.is_none(),
            "{} must not fabricate Python from load-time indirect dispatch",
            record.source.qualname
        );
        assert_eq!(
            body.recognized_call_sites, 0,
            "no C-API symbol is statically named in the indirect-dispatch body of {}",
            record.source.qualname
        );
        if body.total_call_sites > 0 {
            assert!(
                body.annotation.contains("opaque_call(...)"),
                "{} surfaces its unresolved calls as opaque, never invented",
                record.source.qualname
            );
            degraded_bodies += 1;
        }
        println!(
            "{}: {} call sites, {} recognized (honest degrade, indirect dispatch not yet decoded)",
            record.source.qualname, body.total_call_sites, body.recognized_call_sites
        );
    }
    assert!(
        degraded_bodies >= 1,
        "at least one real BCC body exposes indirect-dispatch call sites surfaced as opaque"
    );
}
