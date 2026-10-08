#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::run_captured;
use disrobe_pass_native::{
    ProgramFunction, PseudoAbi, RecoveredFunction, RecoveredProgram, recover_program,
};

use crate::common::{
    COMPILE_TIMEOUT, MAX_CAPTURE_BYTES, PROBE_TIMEOUT, function_code, require_gcc, scratch_dir,
    strip_includes,
};

struct Source {
    path: &'static str,
    functions: &'static [&'static str],
    main_body: &'static str,
}

const PROBE_SOURCE: Source = Source {
    path: "corpus/native/ollvm/probe_src.c",
    functions: &["classify", "sum_to"],
    main_body: "    printf(\"%d\\n\", (int)rec_classify(15));\n    printf(\"%d\\n\", (int)rec_classify(3));\n    printf(\"%d\\n\", (int)rec_sum_to(5));\n",
};

const OBFUSH_SOURCE: Source = Source {
    path: "corpus/native/obfuscators/obfush/sample.c",
    functions: &["classify"],
    main_body: "    printf(\"classify=%d,%d\\n\", (int)rec_classify(7), (int)rec_classify(20));\n    printf(\"secret=%s\\n\", \"the-hidden-flag-value\");\n",
};

struct Fixture {
    file: &'static str,
    pass: &'static str,
    source: &'static Source,
}

const FIXTURES: [Fixture; 6] = [
    Fixture {
        file: "ollvm-probe_src.bcf.elf",
        pass: "bcf",
        source: &PROBE_SOURCE,
    },
    Fixture {
        file: "ollvm-probe_src.sub.elf",
        pass: "sub",
        source: &PROBE_SOURCE,
    },
    Fixture {
        file: "ollvm-probe_src.split.elf",
        pass: "split",
        source: &PROBE_SOURCE,
    },
    Fixture {
        file: "obfush-sample.bcf.elf",
        pass: "bcf",
        source: &OBFUSH_SOURCE,
    },
    Fixture {
        file: "obfush-sample.sub.elf",
        pass: "sub",
        source: &OBFUSH_SOURCE,
    },
    Fixture {
        file: "obfush-sample.split.elf",
        pass: "split",
        source: &OBFUSH_SOURCE,
    },
];

const FULLY_RECOVERED: &[(&str, &str)] = &[
    ("obfush-sample.sub.elf", "classify"),
    ("ollvm-probe_src.split.elf", "classify"),
    ("ollvm-probe_src.sub.elf", "classify"),
    ("ollvm-probe_src.sub.elf", "sum_to"),
];

const SWEEP_INPUTS: &str = "-2147483648, -100000, -1024, -11, -10, -9, -1, 0, 1, 2, 3, 5, 7, 9, 10, 11, 12, 15, 16, 20, 31, 64, 100, 1000, 4096";

fn repo_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn read_fixture(file: &str) -> Vec<u8> {
    let path: PathBuf = repo_root().join("corpus/native/ollvm/real").join(file);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "{} is tracked in the repository and its absence is never a skip: {e}",
            path.display()
        )
    })
}

fn run(program: &Path, args: &[OsString]) -> (Option<i32>, String, String) {
    let captured = run_captured(
        program,
        args,
        COMPILE_TIMEOUT.max(PROBE_TIMEOUT),
        MAX_CAPTURE_BYTES,
    )
    .unwrap_or_else(|e| panic!("{} failed to launch: {e}", program.display()))
    .unwrap_or_else(|| panic!("{} timed out", program.display()));
    (
        captured.exit_code,
        String::from_utf8_lossy(&captured.stdout).into_owned(),
        String::from_utf8_lossy(&captured.stderr).into_owned(),
    )
}

fn gcc_args(parts: &[&OsStr]) -> Vec<OsString> {
    parts.iter().map(|p: &&OsStr| (*p).to_owned()).collect()
}

fn compile_reference(gcc: &str, source: &Source, dir: &Path) -> (PathBuf, PathBuf) {
    let src: PathBuf = repo_root().join(source.path);
    let stem: String = src.file_stem().map_or_else(
        || "source".to_owned(),
        |s: &OsStr| s.to_string_lossy().into_owned(),
    );
    let exe: PathBuf = dir.join(format!("{stem}.original.exe"));
    let (code, _, err): (Option<i32>, String, String) = run(
        Path::new(gcc),
        &gcc_args(&[
            OsStr::new("-O0"),
            OsStr::new("-o"),
            exe.as_os_str(),
            src.as_os_str(),
        ]),
    );
    assert_eq!(code, Some(0), "gcc failed on {}: {err}", source.path);

    let obj: PathBuf = dir.join(format!("{stem}.reference.o"));
    let mut args: Vec<OsString> = gcc_args(&[OsStr::new("-O0"), OsStr::new("-c")]);
    for f in source.functions {
        args.push(OsString::from(format!("-D{f}=ref_{f}")));
    }
    args.push(OsString::from("-Dmain=ref_main"));
    args.push(OsStr::new("-o").to_owned());
    args.push(obj.as_os_str().to_owned());
    args.push(src.as_os_str().to_owned());
    let (code, _, err): (Option<i32>, String, String) = run(Path::new(gcc), &args);
    assert_eq!(code, Some(0), "gcc failed on the renamed reference: {err}");
    (exe, obj)
}

fn compile_off_by_one_reference(gcc: &str, source: &Source, dir: &Path) -> PathBuf {
    let src: String = repo_root()
        .join(source.path)
        .to_string_lossy()
        .replace('\\', "/");
    let mut tu: String = String::new();
    for f in source.functions {
        let _ = writeln!(tu, "#define {f} orig_{f}");
    }
    tu.push_str("#define main orig_main\n");
    let _ = writeln!(tu, "#include \"{src}\"");
    tu.push_str("#undef main\n");
    for f in source.functions {
        let _ = writeln!(tu, "#undef {f}");
        let _ = writeln!(tu, "int ref_{f}(int x) {{ return orig_{f}(x) + 1; }}");
    }
    let stem: String = Path::new(source.path).file_stem().map_or_else(
        || "source".to_owned(),
        |s: &OsStr| s.to_string_lossy().into_owned(),
    );
    let wrapper: PathBuf = dir.join(format!("{stem}.mutant.c"));
    std::fs::write(&wrapper, tu).expect("write mutant reference");
    let obj: PathBuf = dir.join(format!("{stem}.mutant.o"));
    let (code, _, err): (Option<i32>, String, String) = run(
        Path::new(gcc),
        &gcc_args(&[
            OsStr::new("-O0"),
            OsStr::new("-w"),
            OsStr::new("-c"),
            OsStr::new("-o"),
            obj.as_os_str(),
            wrapper.as_os_str(),
        ]),
    );
    assert_eq!(code, Some(0), "gcc failed on the mutant reference: {err}");
    obj
}

struct Recovery {
    sources: Vec<(String, String)>,
    refused: Vec<(String, String)>,
}

fn recover(bytes: &[u8], source: &Source) -> Recovery {
    let mut functions: Vec<ProgramFunction> = Vec::new();
    for name in source.functions {
        let (code, address): (Vec<u8>, u64) = function_code(bytes, name)
            .unwrap_or_else(|| panic!("{name} is a symbol of the unstripped ollvm fixture"));
        functions.push(ProgramFunction {
            name: format!("rec_{name}"),
            address,
            code,
        });
    }
    let program: RecoveredProgram = recover_program(bytes, &functions, PseudoAbi::SysV);
    let mut sources: Vec<(String, String)> = Vec::new();
    for rec in &program.recovered {
        let function: &ProgramFunction = functions
            .iter()
            .find(|f: &&ProgramFunction| f.address == rec.address)
            .expect("recovered function belongs to the request");
        let rec: &RecoveredFunction = rec;
        sources.push((function.name.clone(), strip_includes(&rec.source)));
    }
    let refused: Vec<(String, String)> = program
        .unrecovered
        .iter()
        .map(|bad| (bad.name.clone(), bad.reason.clone()))
        .collect();
    Recovery { sources, refused }
}

fn driver(source: &Source, recovered: &[(String, String)]) -> String {
    let mut tu: String =
        String::from("#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n");
    for (_, body) in recovered {
        tu.push_str(body);
        tu.push('\n');
    }
    for name in source.functions {
        let _ = writeln!(tu, "extern int ref_{name}(int);");
    }
    tu.push_str("int main(void) {\n");
    let _ = writeln!(tu, "    int inputs[] = {{ {SWEEP_INPUTS} }};");
    tu.push_str("    size_t n_inputs = sizeof(inputs) / sizeof(inputs[0]);\n");
    for (name, _) in recovered {
        let bare: &str = name.trim_start_matches("rec_");
        let _ = write!(
            tu,
            "    for (size_t k = 0; k < n_inputs; k++) {{\n\
             \x20       uint32_t want = (uint32_t)ref_{bare}(inputs[k]);\n\
             \x20       uint32_t got = (uint32_t){name}((uint64_t)(int64_t)inputs[k]);\n\
             \x20       if (want != got) {{ printf(\"MISMATCH {bare} in=%d want=%u got=%u\\n\", inputs[k], want, got); return 1; }}\n\
             \x20   }}\n"
        );
    }
    tu.push_str("    printf(\"SWEEP-OK\\n\");\n");
    tu.push_str("    return 0;\n}\n");
    tu
}

fn stdout_driver(source: &Source, recovered: &[(String, String)]) -> String {
    let mut tu: String = String::from("#include <stdint.h>\n#include <stdio.h>\n");
    for (_, body) in recovered {
        tu.push_str(body);
        tu.push('\n');
    }
    tu.push_str("int main(void) {\n");
    tu.push_str(source.main_body);
    tu.push_str("    return 0;\n}\n");
    tu
}

fn compile_and_run(
    gcc: &str,
    dir: &Path,
    tag: &str,
    tu: &str,
    link: Option<&Path>,
) -> Result<String, String> {
    let src: PathBuf = dir.join(format!("{tag}.c"));
    std::fs::write(&src, tu).expect("write driver");
    let exe: PathBuf = dir.join(format!("{tag}.exe"));
    let mut args: Vec<OsString> = gcc_args(&[
        OsStr::new("-O0"),
        OsStr::new("-w"),
        OsStr::new("-o"),
        exe.as_os_str(),
        src.as_os_str(),
    ]);
    if let Some(obj) = link {
        args.push(obj.as_os_str().to_owned());
    }
    let (code, _, err): (Option<i32>, String, String) = run(Path::new(gcc), &args);
    if code != Some(0) {
        return Err(format!(
            "recovered C does not compile: {err}\n--- {tag} ---\n{tu}"
        ));
    }
    let (code, out, err): (Option<i32>, String, String) = run(&exe, &[]);
    if code != Some(0) {
        return Err(format!("exit {code:?}: {out}{err}\n--- {tag} ---\n{tu}"));
    }
    Ok(out)
}

#[test]
fn real_ollvm_elfs_recover_or_refuse_each_function_by_name() {
    let gcc: String = require_gcc();
    let scratch: ScratchDir = scratch_dir("disrobe-ollvm-fold");
    let dir: &Path = scratch.path();
    let pinned: BTreeSet<(&str, &str)> = FULLY_RECOVERED.iter().copied().collect();
    let mut matched: BTreeSet<(String, String)> = BTreeSet::new();
    let mut report: String = String::new();
    let mut mutation_controls: usize = 0;

    for fixture in &FIXTURES {
        let bytes: Vec<u8> = read_fixture(fixture.file);
        let (original_exe, reference_obj): (PathBuf, PathBuf) =
            compile_reference(&gcc, fixture.source, dir);
        let (code, original_stdout, _): (Option<i32>, String, String) = run(&original_exe, &[]);
        assert_eq!(code, Some(0));
        let recovery: Recovery = recover(&bytes, fixture.source);
        for (name, reason) in &recovery.refused {
            assert!(
                !reason.is_empty(),
                "{}: {name} refused without a reason",
                fixture.file
            );
            let _ = writeln!(
                report,
                "{} {}: refused {name}: {reason}",
                fixture.file, fixture.pass
            );
        }
        if recovery.sources.is_empty() {
            continue;
        }
        let tag: String = format!("{}-{}", fixture.file.replace('.', "_"), fixture.pass);
        let sweep: String = driver(fixture.source, &recovery.sources);
        let sweep_out: Result<String, String> = compile_and_run(
            &gcc,
            dir,
            &format!("{tag}-sweep"),
            &sweep,
            Some(&reference_obj),
        );
        match sweep_out {
            Ok(out) if out.contains("SWEEP-OK") => {}
            Ok(out) => panic!(
                "{}: a recovered function computes something else than the authored source: {out}\n{sweep}",
                fixture.file
            ),
            Err(why) => panic!("{}: {why}", fixture.file),
        }
        let mutant_obj: PathBuf = compile_off_by_one_reference(&gcc, fixture.source, dir);
        match compile_and_run(
            &gcc,
            dir,
            &format!("{tag}-mutant"),
            &sweep,
            Some(&mutant_obj),
        ) {
            Err(why) if why.contains("MISMATCH") => mutation_controls += 1,
            other => panic!(
                "{}: the sweep must reject a reference that returns one more than the source: {other:?}",
                fixture.file
            ),
        }
        let all_recovered: bool = recovery.sources.len() == fixture.source.functions.len();
        if all_recovered {
            let stdout_tu: String = stdout_driver(fixture.source, &recovery.sources);
            let out: String =
                compile_and_run(&gcc, dir, &format!("{tag}-stdout"), &stdout_tu, None)
                    .unwrap_or_else(|why| panic!("{}: {why}", fixture.file));
            assert_eq!(
                out, original_stdout,
                "{}: the program rebuilt from recovered functions must print what the authored program prints",
                fixture.file
            );
        }
        for (name, _) in &recovery.sources {
            let bare: String = name.trim_start_matches("rec_").to_owned();
            let _ = writeln!(
                report,
                "{} {}: recovered {bare} matches the source over the sweep",
                fixture.file, fixture.pass
            );
            matched.insert((fixture.file.to_owned(), bare));
        }
    }

    println!("{report}");
    assert!(
        mutation_controls > 0,
        "no fixture recovered a function, so the mutation control never ran\n{report}"
    );
    for (file, function) in &pinned {
        assert!(
            matched.contains(&((*file).to_owned(), (*function).to_owned())),
            "{file}: {function} is pinned as fully recovered but did not recover this run\n{report}"
        );
    }
    let unpinned: Vec<&(String, String)> = matched
        .iter()
        .filter(|(file, function): &&(String, String)| {
            !pinned.contains(&(file.as_str(), function.as_str()))
        })
        .collect();
    assert!(
        unpinned.is_empty(),
        "these functions now recover and must be added to FULLY_RECOVERED so the set only shrinks on purpose: {unpinned:?}\n{report}"
    );
}
