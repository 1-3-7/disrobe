#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(feature = "chain")]
use disrobe_core::chain::{ChildArtifact, Pass};
#[cfg(feature = "chain")]
use disrobe_core::{Artifact, Rung};
#[cfg(feature = "chain")]
use disrobe_pass_dotnet::chain_detector::DOTNET_PASS;
use disrobe_pass_dotnet::peel::eazvm::grade::{
    OrderedInstr, OrderedScore, grade_ordered_lifted, known_method_ordered, ordered_lifted,
};
use disrobe_pass_dotnet::peel::eazvm::{
    EazVmDetection, EazVmMethod, EazVmRecovery, detect, devirtualize, lookup_method,
};
use disrobe_pass_dotnet::peel::{PeelReport, PeelStrategy, peel_eazfuscator};

const EXPECTED_STDOUT: &str = "5\n69\n2147483647\n55\n-1\n9\n";
const CLEAN_BASELINE_INSTRUCTIONS: u32 = 67;

fn corpus_dir() -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../corpus/dotnet/eazvm");
    path
}

fn corpus(rel: &str) -> Vec<u8> {
    let path: PathBuf = corpus_dir().join(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("missing eazvm corpus file {}: {e}", path.display())
    })
}

fn execute_ordered_i4(cil: &[String], arguments: &[i32]) -> i32 {
    let mut stack: Vec<i32> = Vec::new();
    for line in cil {
        let mut fields: std::str::SplitWhitespace<'_> = line.split_whitespace();
        let label: &str = fields.next().unwrap_or_default();
        assert!(label.starts_with("IL_"), "expected ordered CIL, got {line}");
        match fields.next().unwrap_or_default() {
            "ldarg.0" => stack.push(arguments[0]),
            "ldarg.1" => stack.push(arguments[1]),
            "ldc.i4.1" => stack.push(1),
            "ldc.i4.3" => stack.push(3),
            "add" => {
                let right: i32 = stack.pop().expect("right add operand");
                let left: i32 = stack.pop().expect("left add operand");
                stack.push(left.wrapping_add(right));
            }
            "sub" => {
                let right: i32 = stack.pop().expect("right subtract operand");
                let left: i32 = stack.pop().expect("left subtract operand");
                stack.push(left.wrapping_sub(right));
            }
            "mul" => {
                let right: i32 = stack.pop().expect("right multiply operand");
                let left: i32 = stack.pop().expect("left multiply operand");
                stack.push(left.wrapping_mul(right));
            }
            "and" => {
                let right: i32 = stack.pop().expect("right and operand");
                let left: i32 = stack.pop().expect("left and operand");
                stack.push(left & right);
            }
            "xor" => {
                let right: i32 = stack.pop().expect("right xor operand");
                let left: i32 = stack.pop().expect("left xor operand");
                stack.push(left ^ right);
            }
            "ret" => return stack.pop().expect("return value"),
            opcode => panic!("unsupported ordered i4 opcode {opcode} in {line}"),
        }
    }
    panic!("ordered i4 method has no return")
}

const fn clean_poly_i4(argument: i32) -> i32 {
    argument
        .wrapping_mul(argument)
        .wrapping_add(3_i32.wrapping_mul(argument))
        .wrapping_sub(1)
}

#[test]
fn detect_reports_full_vm_structure() {
    let image: Vec<u8> = corpus("EazSample.eazvm.dll");
    let d: EazVmDetection = detect(&image);
    assert!(d.embedded_resource_present);
    assert!(d.dispatch_table_present);
    assert_eq!(d.identified_opcodes, 51);
    assert_eq!(d.stub_count, 6);
}

#[test]
fn clean_assembly_is_not_seen_as_eazvm() {
    let image: Vec<u8> = corpus("EazSample.clean.dll");
    let d: EazVmDetection = detect(&image);
    assert!(
        !d.dispatch_table_present,
        "the unobfuscated baseline must not expose a VM dispatch table"
    );
    assert_eq!(d.stub_count, 0);
    assert!(devirtualize(&image).is_err());
}

#[test]
fn devirtualizes_every_method_to_ordered_cil() {
    let vm: Vec<u8> = corpus("EazSample.eazvm.dll");
    let clean: Vec<u8> = corpus("EazSample.clean.dll");
    let recovery: EazVmRecovery = devirtualize(&vm).expect("devirtualize");
    assert!(
        recovery.undecoded.is_empty(),
        "undecoded={:?}",
        recovery.undecoded
    );
    assert_eq!(recovery.methods.len(), 6);

    let known: BTreeMap<String, Vec<OrderedInstr>> = known_method_ordered(&clean, "Compute");
    let mut total_matched: u32 = 0;
    let mut total_length: u32 = 0;
    for m in &recovery.methods {
        let expected: &Vec<OrderedInstr> = known
            .get(&m.name)
            .unwrap_or_else(|| panic!("{} absent from known CIL", m.name));
        let score: OrderedScore = grade_ordered_lifted(expected, &m.lifted, None);
        total_matched += score.matched;
        total_length += score.length;
        assert!(
            score.is_exact(),
            "{} ordered mismatch {}/{}: recovered={:?} expected={:?}",
            m.name,
            score.matched,
            score.length,
            ordered_lifted(&m.lifted, None),
            expected
        );
    }
    let pct: f64 = f64::from(total_matched) / f64::from(total_length) * 100.0;
    println!(
        "ordered CIL recovery: {total_matched}/{total_length} instructions matched in order ({pct:.2}%)"
    );
    assert_eq!(
        total_length, CLEAN_BASELINE_INSTRUCTIONS,
        "the six Compute bodies hold {CLEAN_BASELINE_INSTRUCTIONS} instructions in the clean \
         baseline, and that count is the denominator the documents publish, so a shorter baseline \
         must fail here rather than raise the rate against a smaller population"
    );
    assert!(
        (pct - 100.0).abs() < f64::EPSILON,
        "ordered CIL recovery against the known original must be 100%; got {pct:.2}% \
         ({total_matched}/{total_length})"
    );
}

#[test]
fn branch_targets_resolve_within_method() {
    let vm: Vec<u8> = corpus("EazSample.eazvm.dll");
    let recovery: EazVmRecovery = devirtualize(&vm).expect("devirtualize");
    let sumto: &EazVmMethod = lookup_method(&recovery, "SumTo").expect("SumTo recovered");
    let branch_count: usize = sumto
        .lifted
        .instrs
        .iter()
        .filter(|i| i.op.is_branch())
        .count();
    assert!(
        branch_count >= 2,
        "SumTo loop must recover at least two branches; got {branch_count}"
    );
}

#[test]
fn peel_path_surfaces_vm_tier_recovery() {
    let image: Vec<u8> = corpus("EazSample.eazvm.dll");
    let report: PeelReport = peel_eazfuscator(&image).expect("peel");
    assert_eq!(
        report.strategy,
        PeelStrategy::EncryptedResourceExtracted,
        "VM-tier recovery must flip the strategy off report-only"
    );
    assert!(
        report.recovered_decoders >= 5,
        "peel must count the recovered virtualized method bodies; got {}",
        report.recovered_decoders
    );
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("VM-tier") && n.contains("lifted")),
        "peel notes must describe the VM-tier lift; got {:?}",
        report.notes
    );
    assert!(
        report.notes.iter().any(|note: &String| {
            note.contains("canonical handler analysis completed for 3 of 6 method body")
        }),
        "the committed EazVM image must reach canonical handler analysis through the public peel caller; got {:?}",
        report.notes
    );
    assert!(
        report.notes.iter().any(|note: &String| {
            note.contains("canonical handler analysis and output refusals:")
                && note.contains("Add: integer width metadata unavailable")
                && note.contains("Classify: virtual instruction has an unknown handler effect")
        }),
        "the public caller must retain the typed refusal when it preserves the ordered lift; got {:?}",
        report.notes
    );
    let add: &disrobe_pass_dotnet::RecoveredMethod = report
        .recovered_methods
        .iter()
        .find(|method: &&disrobe_pass_dotnet::RecoveredMethod| method.method_name == "Add")
        .expect("Add recovery");
    assert!(
        add.cil.iter().any(|line: &String| line == "IL_0002 add")
            && !add.cil.iter().any(|line: &String| line.contains("int64")),
        "the public EazVM peel output must retain the ordered i4 lift until exact integer widths are known; got {:?}",
        add.cil
    );
    let classify: &disrobe_pass_dotnet::RecoveredMethod = report
        .recovered_methods
        .iter()
        .find(|method: &&disrobe_pass_dotnet::RecoveredMethod| method.method_name == "Classify")
        .expect("Classify recovery");
    assert!(
        classify
            .cil
            .iter()
            .any(|line: &String| line.starts_with("IL_")),
        "a refused handler analysis must preserve the ordered opcode lift; got {:?}",
        classify.cil
    );
}

#[test]
fn peel_keeps_i4_overflow_semantics_when_handler_analysis_succeeds() {
    let image: Vec<u8> = corpus("EazSample.eazvm.dll");
    let report: PeelReport = peel_eazfuscator(&image).expect("peel");
    let poly: &disrobe_pass_dotnet::RecoveredMethod = report
        .recovered_methods
        .iter()
        .find(|method: &&disrobe_pass_dotnet::RecoveredMethod| method.method_name == "Poly")
        .expect("Poly recovery");
    assert!(
        report
            .notes
            .iter()
            .any(|note: &String| { note.contains("Poly: integer width metadata unavailable") })
    );

    let argument: i32 = 50_000;
    let recovered: i32 = execute_ordered_i4(&poly.cil, &[argument]);
    let clean_reference: i32 = clean_poly_i4(argument);
    let promoted_i64: i64 =
        i64::from(argument) * i64::from(argument) + 3_i64 * i64::from(argument) - 1_i64;

    assert_eq!(clean_reference, -1_794_817_297);
    assert_eq!(recovered, clean_reference);
    assert_eq!(promoted_i64, 2_500_149_999);
    assert_ne!(i64::from(recovered), promoted_i64);
}

#[test]
fn peel_simplifies_real_mixed_i4_body_before_rendering() {
    let image: Vec<u8> = corpus("EazSample.eazvm.dll");
    let report: PeelReport = peel_eazfuscator(&image).expect("peel");
    let mixed: &disrobe_pass_dotnet::RecoveredMethod = report
        .recovered_methods
        .iter()
        .find(|method: &&disrobe_pass_dotnet::RecoveredMethod| method.method_name == "Mixed")
        .expect("Mixed recovery");

    assert_eq!(
        mixed.cil,
        vec![
            "IL_0000 ldarg.0".to_string(),
            "IL_0001 ldarg.1".to_string(),
            "IL_0002 add".to_string(),
            "IL_0003 ret".to_string(),
        ]
    );
}

#[test]
fn mixed_differential_rejects_a_deliberate_operator_mutation() {
    let image: Vec<u8> = corpus("EazSample.eazvm.dll");
    let report: PeelReport = peel_eazfuscator(&image).expect("peel");
    let mixed: &disrobe_pass_dotnet::RecoveredMethod = report
        .recovered_methods
        .iter()
        .find(|method: &&disrobe_pass_dotnet::RecoveredMethod| method.method_name == "Mixed")
        .expect("Mixed recovery");
    let mut mutated: Vec<String> = mixed.cil.clone();
    mutated[2] = "IL_0002 sub".to_string();

    for argument in [0, 1, -1, i32::MIN, i32::MAX, 0x5555_5555] {
        let reference: i32 = argument.wrapping_add(-1);
        assert_eq!(execute_ordered_i4(&mixed.cil, &[argument, -1]), reference);
        assert_ne!(execute_ordered_i4(&mutated, &[argument, -1]), reference);
    }
}

#[cfg(feature = "chain")]
#[test]
fn auto_chain_emits_width_preserving_eazvm_cil() {
    let image: Vec<u8> = corpus("EazSample.eazvm.dll");
    let artifact: Artifact = Artifact::new(Rung::Raw, image, [0u8; 32]);
    let children: Vec<ChildArtifact> = DOTNET_PASS
        .extract_children(&artifact)
        .expect("EazVM child extraction");
    let recovered_cil: &ChildArtifact = children
        .iter()
        .find(|child: &&ChildArtifact| child.handle.relative_path.ends_with(".recovered-cil.txt"))
        .expect("recovered CIL child");
    let text: &str = std::str::from_utf8(&recovered_cil.bytes).expect("UTF-8 recovered CIL");
    assert!(
        text.contains("method Add token=")
            && text.contains("IL_0000 ldarg.0")
            && text.contains("IL_0001 ldarg.1")
            && text.contains("IL_0002 add")
            && !text.contains("int64"),
        "the auto/chain artifact must retain the width-preserving ordered Add method; got {text}"
    );
    assert!(
        text.contains("method Classify token=") && text.contains("IL_"),
        "the auto/chain artifact must retain the ordered lift for refused handlers; got {text}"
    );
}

fn render_recovered_cil(recovery: &EazVmRecovery) -> String {
    let mut out: String = String::new();
    for m in &recovery.methods {
        let ret: &str = if m.info.returns_void { "void" } else { "i4" };
        writeln!(
            out,
            "method {} params={} locals={} ret={}",
            m.name, m.info.param_count, m.info.local_count, ret
        )
        .expect("write method header");
        for line in m.lifted.render() {
            writeln!(out, "{line}").expect("write il line");
        }
        writeln!(out, "end").expect("write end");
    }
    out
}

#[must_use]
fn find_dotnet() -> Option<PathBuf> {
    let exe: &str = if cfg!(windows) {
        "dotnet.exe"
    } else {
        "dotnet"
    };
    let probe: Result<std::process::Output, _> = Command::new(exe)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output();
    match probe {
        Ok(out) if out.status.success() => Some(PathBuf::from(exe)),
        _ => None,
    }
}

fn run_dotnet(dotnet: &Path, args: &[&Path], cwd: Option<&Path>) -> std::process::Output {
    let mut cmd: Command = Command::new(dotnet);
    for a in args {
        cmd.arg(a);
    }
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    cmd.env("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
        .env("DOTNET_NOLOGO", "1")
        .stdin(Stdio::null())
        .output()
        .expect("spawn dotnet")
}

#[test]
fn recovered_cil_reinjects_and_runs_identically() {
    let vm: Vec<u8> = corpus("EazSample.eazvm.dll");
    let recovery: EazVmRecovery = devirtualize(&vm).expect("devirtualize");
    assert_eq!(
        recovery.methods.len(),
        6,
        "all six bodies must devirtualize"
    );
    let recovered_cil: String = render_recovered_cil(&recovery);
    assert!(
        recovered_cil.contains("method Add") && recovered_cil.contains("method SumTo"),
        "the disrobe-produced CIL artifact is empty or malformed:\n{recovered_cil}"
    );

    let scratch_guard: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_eazvm_reinject")
            .expect("create scratch dir");
    let scratch: PathBuf = scratch_guard.path().to_path_buf();

    let cil_path: PathBuf = scratch.join("EazSample.recovered.cil");
    std::fs::write(&cil_path, recovered_cil.as_bytes()).expect("write recovered cil");

    let Some(dotnet): Option<PathBuf> = find_dotnet() else {
        eprintln!(
            "skip: no dotnet on PATH; the recovered CIL was produced in-process and written to {}, \
             but the .NET runtime is needed to rebuild and execute the re-injected assembly. The \
             in-process ordered-CIL equivalence (devirtualizes_every_method_to_ordered_cil) still \
             gates this run.",
            cil_path.display()
        );
        return;
    };

    let reinject_csproj: PathBuf = corpus_dir().join("reinject").join("reinject.csproj");
    assert!(
        reinject_csproj.is_file(),
        "reinject project missing at {}",
        reinject_csproj.display()
    );

    let build_out: PathBuf = scratch.join("reinject_bin");
    let build: std::process::Output = run_dotnet(
        &dotnet,
        &[
            Path::new("build"),
            reinject_csproj.as_path(),
            Path::new("-c"),
            Path::new("Release"),
            Path::new("-o"),
            build_out.as_path(),
        ],
        None,
    );
    assert!(
        build.status.success(),
        "dotnet build of the re-injection harness failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );

    let reinject_dll: PathBuf = build_out.join("reinject.dll");
    let devirt_dll: PathBuf = scratch.join("EazSample.devirt.dll");
    let reinject_run: std::process::Output = run_dotnet(
        &dotnet,
        &[
            reinject_dll.as_path(),
            cil_path.as_path(),
            devirt_dll.as_path(),
        ],
        None,
    );
    assert!(
        reinject_run.status.success(),
        "re-injection failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&reinject_run.stdout),
        String::from_utf8_lossy(&reinject_run.stderr)
    );
    assert!(
        devirt_dll.is_file(),
        "re-injection did not emit {}",
        devirt_dll.display()
    );

    let runtimeconfig: PathBuf = scratch.join("EazSample.devirt.runtimeconfig.json");
    std::fs::copy(
        corpus_dir().join("EazSample.devirt.runtimeconfig.json"),
        &runtimeconfig,
    )
    .expect("stage runtimeconfig next to rebuilt assembly");

    let exec: std::process::Output = run_dotnet(&dotnet, &[devirt_dll.as_path()], None);
    let stdout: String = String::from_utf8_lossy(&exec.stdout).replace("\r\n", "\n");
    let stderr: String = String::from_utf8_lossy(&exec.stderr).into_owned();
    println!("re-injected assembly stdout:\n{stdout}");
    assert!(
        exec.status.success(),
        "rebuilt assembly exited {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        exec.status.code()
    );
    assert_eq!(
        stdout, EXPECTED_STDOUT,
        "the assembly rebuilt from the devirtualized CIL must print the clean baseline output \
         byte-for-byte; got {stdout:?}"
    );
}
