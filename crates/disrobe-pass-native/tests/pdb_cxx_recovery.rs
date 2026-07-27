#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{self, CapturedOutput};
use disrobe_pass_native::{
    EmittedBase, EmittedUdt, PdbCxxReconstruction, perturb_first_offset, reconstruct_pdb_cxx,
    render_static_assert_tu,
};

#[expect(
    clippy::duration_suboptimal_units,
    reason = "from_mins is unstable (duration_constructors, rust#120301); from_secs is the stable form"
)]
const COMPILE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_CAPTURE: usize = 4 * 1024 * 1024;

fn fixture_pdb_bytes() -> Vec<u8> {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("pdb_cxx_recovery.pdb");
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture pdb at {}: {e}", path.display()))
}

#[derive(Debug)]
struct Compiler {
    label: &'static str,
    path: PathBuf,
}

fn find_cl() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("DISROBE_TEST_CL") {
        let pb: PathBuf = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    if let Some(p) = which_on_path("cl.exe") {
        return Some(p);
    }
    let roots: [&str; 2] = [
        "C:/Program Files (x86)/Microsoft Visual Studio",
        "C:/Program Files/Microsoft Visual Studio",
    ];
    for root in roots {
        let Ok(years) = std::fs::read_dir(root) else {
            continue;
        };
        for year in years.flatten() {
            for edition in ["BuildTools", "Community", "Professional", "Enterprise"] {
                let msvc_root: PathBuf = year.path().join(edition).join("VC/Tools/MSVC");
                let Ok(versions) = std::fs::read_dir(&msvc_root) else {
                    continue;
                };
                for version in versions.flatten() {
                    let candidate: PathBuf = version.path().join("bin/Hostx64/x64/cl.exe");
                    if candidate.is_file() {
                        return Some(candidate);
                    }
                }
            }
        }
    }
    None
}

fn find_clang_cl() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("DISROBE_TEST_CLANG_CL") {
        let pb: PathBuf = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    which_on_path("clang-cl.exe")
}

fn which_on_path(name: &str) -> Option<PathBuf> {
    let path_var: String = std::env::var("PATH").ok()?;
    for dir in path_var.split(';') {
        let candidate: PathBuf = PathBuf::from(dir).join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn available_compilers() -> Vec<Compiler> {
    let mut out: Vec<Compiler> = Vec::new();
    if let Some(p) = find_cl() {
        out.push(Compiler {
            label: "cl",
            path: p,
        });
    }
    if let Some(p) = find_clang_cl() {
        out.push(Compiler {
            label: "clang-cl",
            path: p,
        });
    }
    out
}

fn compilers_or_skip(context: &str) -> Option<Vec<Compiler>> {
    let compilers: Vec<Compiler> = available_compilers();
    if compilers.is_empty() {
        eprintln!(
            "[skip] {context}: no msvc-compatible compiler (cl.exe or clang-cl) reachable; install VS Build Tools or LLVM to exercise this layout oracle"
        );
        return None;
    }
    Some(compilers)
}

struct CompileOutcome {
    success: bool,
    stdout: String,
    stderr: String,
}

fn compile_tu(compiler: &Compiler, source: &Path, obj_out: &Path) -> CompileOutcome {
    let args: Vec<String> = vec![
        "/c".to_owned(),
        "/nologo".to_owned(),
        "/std:c++17".to_owned(),
        "/TP".to_owned(),
        format!("/Fo:{}", obj_out.display()),
        source.display().to_string(),
    ];
    let captured: Option<CapturedOutput> =
        subprocess::run_captured(&compiler.path, &args, COMPILE_TIMEOUT, MAX_CAPTURE)
            .unwrap_or_else(|e| panic!("spawn {} failed: {e}", compiler.label));
    let Some(captured) = captured else {
        panic!(
            "{} timed out compiling {}",
            compiler.label,
            source.display()
        );
    };
    CompileOutcome {
        success: captured.exit_code == Some(0),
        stdout: String::from_utf8_lossy(&captured.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&captured.stderr).into_owned(),
    }
}

fn scratch_dir(tag: &str) -> ScratchDir {
    let purpose: String = format!("disrobe-pdb-cxx-{tag}");
    ScratchDir::create(&purpose).expect("create scratch directory")
}

#[test]
fn recovers_the_real_msvc_pdb_type_graph() {
    let bytes: Vec<u8> = fixture_pdb_bytes();
    let rec: PdbCxxReconstruction =
        reconstruct_pdb_cxx(&bytes).expect("reconstruct real compiler-built pdb");

    let udt_names: Vec<&str> = rec
        .udts
        .iter()
        .map(|u: &EmittedUdt| u.original_name.as_str())
        .collect();
    eprintln!("[evidence] recovered udts: {udt_names:?}");
    eprintln!(
        "[evidence] recovered enums: {:?}",
        rec.enums
            .iter()
            .map(|e| &e.original_name)
            .collect::<Vec<_>>()
    );
    eprintln!(
        "[evidence] recovered globals: {:?}",
        rec.globals.iter().map(|g| &g.name).collect::<Vec<_>>()
    );
    eprintln!(
        "[evidence] recovered functions: {:?}",
        rec.functions.iter().map(|f| &f.name).collect::<Vec<_>>()
    );
    eprintln!(
        "[evidence] recovered typedefs: {:?}",
        rec.typedefs
            .iter()
            .map(|t| &t.emitted_name)
            .collect::<Vec<_>>()
    );
    eprintln!("[evidence] rejected: {:?}", rec.rejected);

    assert!(
        udt_names.contains(&"Vector3"),
        "must recover struct Vector3"
    );
    assert!(udt_names.contains(&"Payload"), "must recover union Payload");
    assert!(
        udt_names.contains(&"Flags"),
        "must recover bitfield struct Flags"
    );
    assert!(
        udt_names.contains(&"Node"),
        "must recover self-referential struct Node"
    );
    assert!(
        rec.rejected.is_empty(),
        "the hand-authored fixture must not trip any reject path: {:?}",
        rec.rejected
    );

    let node: &EmittedUdt = rec
        .udts
        .iter()
        .find(|u: &&EmittedUdt| u.original_name == "Node")
        .expect("Node present");
    let next_field = node
        .fields
        .iter()
        .find(|f| f.original_name == "next")
        .expect("Node::next present");
    assert!(
        next_field.declaration.contains('*'),
        "Node::next must resolve as a pointer, got {:?}",
        next_field.declaration
    );
    let matrix_field = node
        .fields
        .iter()
        .find(|f| f.original_name == "matrix")
        .expect("Node::matrix present");
    assert!(
        matrix_field.declaration.contains("[2]") && matrix_field.declaration.contains("[3]"),
        "Node::matrix must preserve both array dimensions, got {:?}",
        matrix_field.declaration
    );

    let flags: &EmittedUdt = rec
        .udts
        .iter()
        .find(|u: &&EmittedUdt| u.original_name == "Flags")
        .expect("Flags present");
    assert!(
        flags.fields.iter().all(|f| f.bitfield.is_some()),
        "every Flags member must be recovered as a bitfield: {:?}",
        flags.fields
    );

    assert_eq!(
        rec.enums.len(),
        2,
        "ColorTag and Priority must both be recovered"
    );
    let color_tag = rec
        .enums
        .iter()
        .find(|e| e.original_name == "ColorTag")
        .expect("ColorTag present");
    assert_eq!(color_tag.underlying_type_text, "unsigned char");

    let find_udt = |name: &str| -> &EmittedUdt {
        rec.udts
            .iter()
            .find(|u: &&EmittedUdt| u.original_name == name)
            .unwrap_or_else(|| panic!("must recover {name}"))
    };

    let derived: &EmittedUdt = find_udt("Derived");
    assert_eq!(
        derived.bases,
        vec![EmittedBase {
            base_name: "Base".to_owned(),
            offset: 0,
        }],
        "Derived must inherit Base at offset 0, got {:?}",
        derived.bases
    );
    assert!(
        derived
            .fields
            .iter()
            .any(|f| f.original_name == "derived_c"),
        "Derived must keep its own member derived_c"
    );

    let multi: &EmittedUdt = find_udt("Multi");
    assert_eq!(
        multi.bases,
        vec![
            EmittedBase {
                base_name: "LeftMix".to_owned(),
                offset: 0,
            },
            EmittedBase {
                base_name: "RightMix".to_owned(),
                offset: 4,
            },
        ],
        "Multi must carry both non-virtual bases at their recorded offsets, got {:?}",
        multi.bases
    );

    let shape: &EmittedUdt = find_udt("Shape");
    let vfptr = shape
        .fields
        .first()
        .expect("Shape must have at least the synthesized vfptr");
    assert_eq!(vfptr.offset, 0, "vfptr must lead the polymorphic layout");
    assert!(
        vfptr.declaration.contains("__vfptr") && vfptr.declaration.contains('*'),
        "Shape must synthesize a leading vfptr member, got {:?}",
        vfptr.declaration
    );
    let shape_tag = shape
        .fields
        .iter()
        .find(|f| f.original_name == "shape_tag")
        .expect("Shape::shape_tag present");
    assert_eq!(
        shape_tag.offset, 8,
        "shape_tag must sit past the 8-byte vfptr, got offset {}",
        shape_tag.offset
    );
}

#[test]
fn real_compiler_confirms_size_and_offset_of_every_recovered_udt() {
    let Some(compilers): Option<Vec<Compiler>> = compilers_or_skip("recovered-udt layout oracle")
    else {
        return;
    };
    eprintln!(
        "[evidence] compiler oracle set: {:?}",
        compilers
            .iter()
            .map(|c| (c.label, &c.path))
            .collect::<Vec<_>>()
    );

    let bytes: Vec<u8> = fixture_pdb_bytes();
    let rec: PdbCxxReconstruction =
        reconstruct_pdb_cxx(&bytes).expect("reconstruct real compiler-built pdb");
    assert!(
        !rec.udts.is_empty(),
        "fixture must yield at least one recovered udt to grade"
    );

    let tu_text: String = render_static_assert_tu(&rec.header_text, &rec.udts);
    eprintln!("[evidence] rendered validation tu:\n{tu_text}");

    let scratch: ScratchDir = scratch_dir("main");
    let dir: PathBuf = scratch.path().to_path_buf();
    let tu_path: PathBuf = dir.join("validate.cpp");
    std::fs::write(&tu_path, &tu_text).expect("write validation tu");

    let mut compiled: usize = 0;
    for compiler in &compilers {
        let obj: PathBuf = dir.join(format!("validate_{}.obj", compiler.label));
        let outcome: CompileOutcome = compile_tu(compiler, &tu_path, &obj);
        eprintln!(
            "[evidence] {} compile: success={} stdout={:?} stderr={:?}",
            compiler.label, outcome.success, outcome.stdout, outcome.stderr
        );
        assert!(
            outcome.success,
            "{} must compile every static_assert clean for the hand-authored fixture (real compiler-generated pdb); stdout={} stderr={}",
            compiler.label, outcome.stdout, outcome.stderr
        );
        compiled += 1;
    }

    println!(
        "[evidence] compiler oracle grade: {}/{} recovered udts compile AND layout-match across {} compiler(s) ({})",
        rec.udts.len(),
        rec.udts.len(),
        compiled,
        compilers
            .iter()
            .map(|c| c.label)
            .collect::<Vec<_>>()
            .join(", ")
    );
}

#[test]
fn perturbing_one_recovered_offset_makes_the_real_compiler_reject_it() {
    let Some(compilers): Option<Vec<Compiler>> = compilers_or_skip("offset-perturbation oracle")
    else {
        return;
    };

    let bytes: Vec<u8> = fixture_pdb_bytes();
    let rec: PdbCxxReconstruction =
        reconstruct_pdb_cxx(&bytes).expect("reconstruct real compiler-built pdb");
    let tu_text: String = render_static_assert_tu(&rec.header_text, &rec.udts);
    let corrupted: String = perturb_first_offset(&tu_text)
        .expect("fixture must contain at least one offsetof assertion to corrupt");
    assert_ne!(
        tu_text, corrupted,
        "the corrupted tu must actually differ from the real one"
    );

    let scratch: ScratchDir = scratch_dir("perturb");
    let dir: PathBuf = scratch.path().to_path_buf();
    let tu_path: PathBuf = dir.join("corrupted.cpp");
    std::fs::write(&tu_path, &corrupted).expect("write corrupted tu");

    let compiler: &Compiler = &compilers[0];
    let obj: PathBuf = dir.join("corrupted.obj");
    let outcome: CompileOutcome = compile_tu(compiler, &tu_path, &obj);
    eprintln!(
        "[evidence] perturbation compile via {}: success={} stdout={:?} stderr={:?}",
        compiler.label, outcome.success, outcome.stdout, outcome.stderr
    );
    assert!(
        !outcome.success,
        "a deliberately corrupted expected-offset must make the real compiler reject the translation unit, \
         proving the static_assert oracle can actually go red instead of always passing"
    );
    let combined: String = format!("{}{}", outcome.stdout, outcome.stderr);
    assert!(
        combined.contains("static_assert")
            || combined.contains("static assertion")
            || combined.contains("offset mismatch"),
        "the compiler failure must be attributable to the static_assert, not some unrelated error: {combined}"
    );
}
