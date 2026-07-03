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
    BccArch, PseudoCFunction, UnpackOptions, lift_bcc_code_region, lift_bcc_native,
    unpack_wrapper_text_with_options,
};
use object::{Object as _, ObjectSection as _, ObjectSymbol as _};

#[test]
fn bcc_lift_rejects_empty_blob() {
    let err: disrobe_pass_pyarmor::Error = lift_bcc_native(&[], BccArch::WinX64).unwrap_err();
    assert!(format!("{err}").contains("empty"));
}

#[test]
fn bcc_lift_arch_labels_round_trip() {
    assert_eq!(BccArch::WinX64.label(), "win-x64");
    assert_eq!(BccArch::LinuxX64.label(), "linux-x64");
    assert_eq!(BccArch::DarwinArm64.label(), "darwin-arm64");
}

fn corpus_default_dir() -> Option<PathBuf> {
    let here: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir: PathBuf = here
        .parent()?
        .parent()?
        .join("corpus/python/pyarmor/v9-bcc/default");
    dir.is_dir().then_some(dir)
}

#[test]
fn real_bcc_body_is_surfaced_as_pseudo_c_in_crate() {
    let Some(dir): Option<PathBuf> = corpus_default_dir() else {
        eprintln!("v9-bcc corpus absent; skipping real-body surfacing test");
        return;
    };
    let wrapper_path: PathBuf = dir.join("known_plaintext.py");
    let wrapper_text: String = std::fs::read_to_string(&wrapper_path).expect("read wrapper");
    let opts: UnpackOptions = UnpackOptions {
        allow_bcc: true,
        ..UnpackOptions::default()
    };
    let out = unpack_wrapper_text_with_options(&wrapper_text, &wrapper_path, &opts)
        .expect("v9 BCC wrapper decrypts and carves via sibling runtime key");

    assert_eq!(out.bcc_blobs.len(), 1, "one BCC ELF object is carved");
    assert_eq!(
        out.bcc_lifts.len(),
        1,
        "the carved object is lifted in-crate"
    );
    assert!(
        out.bcc_lift_skipped_reason.is_none(),
        "no Ghidra shell-out: the in-crate lift runs unconditionally under --allow-bcc, got skip reason {:?}",
        out.bcc_lift_skipped_reason
    );

    let lift = &out.bcc_lifts[0];
    assert_eq!(lift.architecture, BccArch::WinX64);
    assert!(
        lift.functions.len() >= 4,
        "the four authored functions (mix_add/clamp/poly/main) plus module bootstrap are recovered as distinct native functions; got {}",
        lift.functions.len()
    );

    for (fid, func) in &lift.functions {
        assert_eq!(fid.name, func.id.name);
        assert!(
            func.size > 0,
            "each function carries a non-zero byte extent"
        );
        assert!(
            func.pseudo_c.contains(&func.id.name),
            "surfaced pseudo-C names the recovered function {}",
            func.id.name
        );
        if func.modeled {
            assert!(
                !func.pseudo_c.contains("declined"),
                "a modeled function emits real recovered C, not a decline marker"
            );
        } else {
            let note: &String = func
                .note
                .as_ref()
                .expect("an unmodeled function records an honest reason");
            assert!(
                !note.is_empty() && func.pseudo_c.contains("/*"),
                "an unmodeled function surfaces verified native disassembly plus the honest reason, never a fabricated body"
            );
            assert!(
                func.pseudo_c.contains("push")
                    || func.pseudo_c.contains("mov")
                    || func.pseudo_c.contains("call"),
                "the disassembly listing carries real x86-64 instructions"
            );
        }
    }
    println!(
        "real BCC body: {} functions surfaced ({} modeled, {} native-disasm markers), text_base={:#x}",
        lift.functions.len(),
        lift.modeled_count,
        lift.unmodeled_count,
        lift.text_base
    );
}

struct Case {
    name: &'static str,
    arity: usize,
    c_source: &'static str,
}

const BATTERY: &[Case] = &[
    Case {
        name: "mix_add",
        arity: 2,
        c_source: "long long mix_add(long long a, long long b){ return (a + b) * 3 - (a ^ b); }",
    },
    Case {
        name: "clamp",
        arity: 3,
        c_source: "long long clamp(long long v, long long lo, long long hi){ long long r = v; if (r < lo) r = lo; if (r > hi) r = hi; return r; }",
    },
    Case {
        name: "poly",
        arity: 1,
        c_source: "long long poly(long long x){ return x * x * x + 2 * x * x - 5 * x + 7; }",
    },
    Case {
        name: "l_add",
        arity: 2,
        c_source: "long long l_add(long long a, long long b){ return a + b; }",
    },
    Case {
        name: "l_sign",
        arity: 1,
        c_source: "long long l_sign(long long a){ if (a > 0) return 1; if (a < 0) return -1; return 0; }",
    },
    Case {
        name: "l_max",
        arity: 2,
        c_source: "long long l_max(long long a, long long b){ return a > b ? a : b; }",
    },
    Case {
        name: "l_abs",
        arity: 1,
        c_source: "long long l_abs(long long a){ return a < 0 ? -a : a; }",
    },
];

fn cc() -> Option<String> {
    for c in ["gcc", "clang", "cc"] {
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
        std::env::temp_dir().join(format!("disrobe-bcc-equiv-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn function_code(object_bytes: &[u8], name: &str) -> Option<(Vec<u8>, u64)> {
    let file: object::File<'_> = object::File::parse(object_bytes).ok()?;
    let candidates: [String; 2] = [name.to_owned(), format!("_{name}")];
    let sym: object::Symbol<'_, '_> = file.symbols().find(|s: &object::Symbol<'_, '_>| {
        s.name()
            .is_ok_and(|n: &str| candidates.iter().any(|c: &String| c == n))
    })?;
    let section_index: object::SectionIndex = match sym.section() {
        object::SymbolSection::Section(idx) => idx,
        _ => return None,
    };
    let section: object::Section<'_, '_> = file.section_by_index(section_index).ok()?;
    let data: &[u8] = section.data().ok()?;
    let sym_addr: u64 = sym.address();
    let start: usize = usize::try_from(sym_addr.saturating_sub(section.address())).ok()?;
    let size: usize = usize::try_from(sym.size()).ok()?;
    let end: usize = if size == 0 {
        data.len()
    } else {
        start.saturating_add(size).min(data.len())
    };
    let slice: &[u8] = data.get(start..end)?;
    Some((slice.to_vec(), sym_addr))
}

fn compile_battery(compiler: &str, dir: &Path) -> Vec<u8> {
    let mut battery_src: String = String::new();
    for case in BATTERY {
        battery_src.push_str(case.c_source);
        battery_src.push('\n');
    }
    let battery_c: PathBuf = dir.join("battery.c");
    std::fs::write(&battery_c, battery_src.as_bytes()).expect("write battery.c");
    let battery_o: PathBuf = dir.join("battery.o");
    let out: std::process::Output = Command::new(compiler)
        .args(["-O1", "-fno-stack-protector", "-c", "-o"])
        .arg(&battery_o)
        .arg(&battery_c)
        .output()
        .expect("invoke cc for battery");
    assert!(
        out.status.success(),
        "battery compile failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read(&battery_o).expect("read battery.o")
}

struct Lifted {
    decls: String,
    driver_snippet: String,
}

fn process_case(case: &Case, object_bytes: &[u8]) -> Option<Lifted> {
    let (code, base): (Vec<u8>, u64) = function_code(object_bytes, case.name)?;
    let funcs: Vec<PseudoCFunction> = lift_bcc_code_region(&code, base, BccArch::WinX64);
    let recovered: &PseudoCFunction = funcs.iter().find(|f: &&PseudoCFunction| f.modeled)?;
    let sub_name: String = format!("sub_{:x}", recovered.id.entry_va);
    let rec_name: String = format!("rec_{}", case.name);
    let renamed_body: String = recovered
        .pseudo_c
        .replacen(&format!("{sub_name}("), &format!("{rec_name}("), 1)
        .lines()
        .filter(|l: &&str| !l.starts_with("#include"))
        .collect::<Vec<&str>>()
        .join("\n");

    let mut decls: String = String::new();
    decls.push_str(&renamed_body);
    decls.push('\n');
    push_format(
        &mut decls,
        format_args!(
            "extern long long {}({});\n",
            case.name,
            vec!["long long"; case.arity].join(", ")
        ),
    );

    let orig_args: Vec<String> = (0..case.arity).map(|i: usize| format!("in[{i}]")).collect();
    let param_count: usize = signature_param_count(&recovered.signature).min(6);
    let rec_args: Vec<String> = (0..param_count)
        .map(|i: usize| format!("(uint64_t)in[{i}]"))
        .collect();

    let mut driver_snippet: String = String::new();
    push_format(
        &mut driver_snippet,
        format_args!(
            "    for (size_t k = 0; k < n_inputs; k++) {{\n\
         \x20       long long in[6] = {{ inputs[k][0], inputs[k][1], inputs[k][2], 0, 0, 0 }};\n\
         \x20       unsigned long long want = (unsigned long long){}({});\n\
         \x20       unsigned long long got = {rec_name}({});\n\
         \x20       if (want != got) {{ printf(\"MISMATCH {} in=%lld,%lld,%lld want=%llu got=%llu\\n\", in[0], in[1], in[2], want, got); return 1; }}\n\
         \x20   }}\n",
            case.name,
            orig_args.join(", "),
            rec_args.join(", "),
            case.name,
        ),
    );
    Some(Lifted {
        decls,
        driver_snippet,
    })
}

fn signature_param_count(signature: &str) -> usize {
    let Some(open): Option<usize> = signature.find('(') else {
        return 0;
    };
    let Some(close): Option<usize> = signature.rfind(')') else {
        return 0;
    };
    let inside: &str = signature[open + 1..close].trim();
    if inside.is_empty() || inside == "void" {
        return 0;
    }
    inside.split(',').count()
}

fn push_format(out: &mut String, args: std::fmt::Arguments<'_>) {
    let result: Result<(), std::fmt::Error> = std::fmt::write(out, args);
    if let Err(error) = result {
        unreachable!("string formatting failed: {error}");
    }
}

fn build_driver(recovered_decls: &str, driver_body: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n{recovered_decls}\n\
         int main(void) {{\n\
         \x20   long long inputs[][3] = {{\n\
         \x20       {{0,0,0}},{{1,1,1}},{{-1,-1,-1}},{{7,3,5}},{{-7,3,-5}},\n\
         \x20       {{123456,-654321,99}},{{2147483647,1,2}},{{-2147483648,-1,-2}},\n\
         \x20       {{9,4,15}},{{100,200,300}},{{-100,50,-25}},\n\
         \x20       {{1<<20,1<<10,1<<5}},{{42,42,42}},{{5,2,9}}\n\
         \x20   }};\n\
         \x20   size_t n_inputs = sizeof(inputs)/sizeof(inputs[0]);\n\
         {driver_body}\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n"
    )
}

#[test]
fn bcc_lift_route_recompiles_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping BCC-lift recompile-equivalence on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; the x86-64 sysv leaf class is proven by disrobe-pass-native's own sysv clang guards"
        );
        return;
    }
    let Some(compiler): Option<String> = cc() else {
        eprintln!("skipping: no C compiler (gcc/clang/cc) on PATH");
        return;
    };
    let dir: PathBuf = scratch_dir();
    let object_bytes: Vec<u8> = compile_battery(&compiler, &dir);

    let mut recovered_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut lifted_count: usize = 0;
    for case in BATTERY {
        if let Some(lifted) = process_case(case, &object_bytes) {
            recovered_decls.push_str(&lifted.decls);
            driver_body.push_str(&lifted.driver_snippet);
            lifted_count += 1;
        } else {
            eprintln!(
                "skip {}: this compiler build did not lower it into the leaf class",
                case.name
            );
        }
    }
    assert!(
        lifted_count > 0,
        "the BCC lift route must recover at least one leaf-class function from the authored battery; got 0"
    );

    let driver: String = build_driver(&recovered_decls, &driver_body);
    let driver_c: PathBuf = dir.join("driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write driver.c");
    let harness_exe: PathBuf = dir.join(if cfg!(windows) {
        "harness.exe"
    } else {
        "harness"
    });
    let battery_o: PathBuf = dir.join("battery.o");
    let link: std::process::Output = Command::new(&compiler)
        .args(["-O1", "-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke cc to link harness");
    assert!(
        link.status.success(),
        "harness link failed: {}\n--- driver.c ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness_exe).output().expect("run harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "BCC lift-route behavioral differential FAILED ({lifted_count} functions): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "BCC lift-route recompile-equivalence PASSED for {lifted_count} leaf-class functions (MS x64)"
    );
}

#[test]
fn bcc_lift_route_discovers_multiple_function_boundaries() {
    let Some(compiler): Option<String> = cc() else {
        eprintln!("skipping: no C compiler on PATH");
        return;
    };
    let dir: PathBuf = scratch_dir();
    let object_bytes: Vec<u8> = compile_battery(&compiler, &dir);
    let file: object::File<'_> =
        object::File::parse(object_bytes.as_slice()).expect("parse object");
    let text: object::Section<'_, '_> = file
        .sections()
        .find(|s: &object::Section<'_, '_>| s.kind() == object::SectionKind::Text)
        .expect("a text section");
    let data: &[u8] = text.data().expect("text data");
    let funcs: Vec<PseudoCFunction> = lift_bcc_code_region(data, text.address(), BccArch::WinX64);
    assert!(
        funcs.len() >= 3,
        "linear boundary discovery must split the concatenated .text into several functions; got {}",
        funcs.len()
    );
}
