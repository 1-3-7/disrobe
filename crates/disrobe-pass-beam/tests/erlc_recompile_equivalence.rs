#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_beam::{
    BeamFile, Disassembly, ErlangSurface, Operand, RecoverySource, disassemble, recover_erlang,
};
use wait_timeout::ChildExt;

const CALL_TIMEOUT: Duration = Duration::from_secs(30);

fn run_bounded(mut cmd: Command) -> Option<(bool, String, String)> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child: std::process::Child = cmd.spawn().expect("spawn subprocess");
    match child.wait_timeout(CALL_TIMEOUT).expect("wait_timeout") {
        Some(status) => {
            let mut so: String = String::new();
            let mut se: String = String::new();
            if let Some(mut h) = child.stdout.take() {
                let _ = h.read_to_string(&mut so);
            }
            if let Some(mut h) = child.stderr.take() {
                let _ = h.read_to_string(&mut se);
            }
            Some((status.success(), so, se))
        }
        None => {
            let _ = child.kill();
            let _ = child.wait();
            None
        }
    }
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates")
        .parent()
        .expect("root")
        .join("corpus")
        .join("beam")
        .join("recompile_oracle")
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) {
        &["", ".exe", ".bat", ".cmd"]
    } else {
        &[""]
    };
    for dir in std::env::split_paths(&path_var) {
        for ext in exts {
            let candidate: PathBuf = dir.join(format!("{name}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn strip_chunk(bytes: &[u8], target: &[u8; 4]) -> Vec<u8> {
    let mut inner: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut cursor: usize = 12;
    while cursor + 8 <= bytes.len() {
        let tag: [u8; 4] = [
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ];
        let len: usize = u32::from_be_bytes([
            bytes[cursor + 4],
            bytes[cursor + 5],
            bytes[cursor + 6],
            bytes[cursor + 7],
        ]) as usize;
        let padded: usize = len.div_ceil(4) * 4;
        let total: usize = 8 + padded;
        if &tag != target {
            inner.extend_from_slice(&bytes[cursor..(cursor + total).min(bytes.len())]);
        }
        cursor += total;
    }
    let mut out: Vec<u8> = Vec::with_capacity(12 + inner.len());
    out.extend_from_slice(b"FOR1");
    out.extend_from_slice(
        &u32::try_from(4 + inner.len())
            .expect("form fits")
            .to_be_bytes(),
    );
    out.extend_from_slice(b"BEAM");
    out.extend_from_slice(&inner);
    out
}

fn erlc_compile(erlc: &Path, src: &Path, out_dir: &Path) -> (bool, String) {
    let mut cmd: Command = Command::new(erlc);
    cmd.arg("-o").arg(out_dir).arg(src);
    match run_bounded(cmd) {
        Some((ok, so, se)) => (ok, format!("stdout:\n{so}\nstderr:\n{se}")),
        None => (false, "erlc timed out".to_owned()),
    }
}

const REQUIRE_ERLANG_VAR: &str = "DISROBE_REQUIRE_ERLANG";
const GRADED: &str = "stripped core-lift recompile equivalence over the erlang corpus";

fn erlang_is_mandatory() -> bool {
    let Some(raw): Option<OsString> = std::env::var_os(REQUIRE_ERLANG_VAR) else {
        return false;
    };
    !matches!(
        raw.to_string_lossy().trim().to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "no" | "off" | "optional"
    )
}

fn skip_or_fail(defect: &str) {
    assert!(
        !erlang_is_mandatory(),
        "{REQUIRE_ERLANG_VAR} makes the erlang toolchain mandatory for this run, so {GRADED} \
         cannot be measured and this case must not report success: {defect}. To fix it, install \
         Erlang/OTP and put erlc and erl on PATH; to permit a run that measures nothing here, \
         clear {REQUIRE_ERLANG_VAR}."
    );
    let line: String = format!(
        "\nNOT MEASURED: {GRADED} compared nothing and graded nothing, because {defect}. Set \
         {REQUIRE_ERLANG_VAR}=1 to fail instead of skipping when erlc and erl cannot be run.\n"
    );
    let mut sink: std::io::StdoutLock<'static> = std::io::stdout().lock();
    drop(sink.write_all(line.as_bytes()));
    drop(sink.flush());
}

fn otp_release(erl: &Path) -> Result<String, String> {
    let mut cmd: Command = Command::new(erl);
    cmd.arg("-noshell")
        .arg("-eval")
        .arg("io:format(\"~s\", [erlang:system_info(otp_release)]), halt().");
    match run_bounded(cmd) {
        Some((true, so, _)) if !so.trim().is_empty() => Ok(so.trim().to_owned()),
        Some((_, so, se)) => Err(format!(
            "`erl` is present at {} but did not report its release (stdout {:?}, stderr {:?}), so \
             the toolchain is installed and unusable rather than absent",
            erl.display(),
            so.trim(),
            se.trim()
        )),
        None => Err(format!(
            "`erl` at {} did not exit within {CALL_TIMEOUT:?}",
            erl.display()
        )),
    }
}

fn run_test0(erl: &Path, code_dir: &Path, module: &str) -> (bool, String) {
    let eval: String = format!("io:format(\"~p~n\", [{module}:test()]), halt().");
    let mut cmd: Command = Command::new(erl);
    cmd.current_dir(code_dir)
        .arg("-noshell")
        .arg("-pa")
        .arg(code_dir)
        .arg("-eval")
        .arg(&eval);
    match run_bounded(cmd) {
        Some((ok, so, _)) => (ok, so),
        None => (false, "<timed out>".to_owned()),
    }
}

fn semantic_exports(beam: &BeamFile) -> BTreeSet<(String, u32)> {
    let mut out: BTreeSet<(String, u32)> = BTreeSet::new();
    for entry in &beam.chunks.exports {
        let Some(name): Option<&str> = beam.chunks.atoms.get(entry.function_atom_index) else {
            continue;
        };
        if name == "module_info" {
            continue;
        }
        out.insert((name.to_owned(), entry.arity));
    }
    out
}

fn opcode_sequences(beam: &BeamFile) -> Vec<((String, u32), Vec<&'static str>)> {
    let Some(code) = beam.chunks.code.as_ref() else {
        return Vec::new();
    };
    let Ok(dis): Result<Disassembly, _> = disassemble(code) else {
        return Vec::new();
    };
    let mut out: Vec<((String, u32), Vec<&'static str>)> = Vec::new();
    let mut current: Option<((String, u32), Vec<&'static str>)> = None;
    for instr in &dis.instructions {
        if instr.name == "func_info" {
            if let Some(prev) = current.take() {
                out.push(prev);
            }
            let name: String = match instr.operands.get(1) {
                Some(Operand::Atom(a)) => beam.chunks.atoms.get(*a).unwrap_or("?").to_owned(),
                _ => "?".to_owned(),
            };
            let arity: u32 = match instr.operands.get(2) {
                Some(Operand::Literal(v)) => u32::try_from(*v).unwrap_or(0),
                _ => 0,
            };
            current = Some(((name, arity), Vec::new()));
            continue;
        }
        if let Some((_, ops)) = current.as_mut()
            && instr.name != "label"
            && instr.name != "line"
        {
            ops.push(instr.name);
        }
    }
    if let Some(prev) = current.take() {
        out.push(prev);
    }
    out.retain(|((n, _), _)| n != "module_info" && n != "?");
    out
}

struct Fidelity {
    module: String,
    recompiled: bool,
    exports_match: bool,
    runtime_identical: bool,
    fn_total: usize,
    fn_opcode_exact: usize,
    detail: String,
    rejected_source: Option<String>,
}

impl Fidelity {
    fn behaviorally_equivalent(&self) -> bool {
        self.recompiled && self.exports_match && self.runtime_identical
    }
}

fn measure(erlc: &Path, erl: Option<&Path>, module: &str, src: &Path) -> Fidelity {
    let purpose: String = format!("disrobe_recompile_eq_{module}");
    let scratch: ScratchDir = ScratchDir::create(&purpose).expect("create scratch directory");
    let base: PathBuf = scratch.path().to_path_buf();
    let orig_dir: PathBuf = base.join("orig");
    let rec_dir: PathBuf = base.join("rec");
    std::fs::create_dir_all(&orig_dir).expect("mkdir orig");
    std::fs::create_dir_all(&rec_dir).expect("mkdir rec");

    let (compiled, msg): (bool, String) = erlc_compile(erlc, src, &orig_dir);
    assert!(compiled, "corpus module {module} must compile:\n{msg}");

    let raw: Vec<u8> =
        std::fs::read(orig_dir.join(format!("{module}.beam"))).expect("read orig beam");
    let stripped_bytes: Vec<u8> = strip_chunk(&strip_chunk(&raw, b"Dbgi"), b"Docs");
    let stripped: BeamFile = BeamFile::parse(&stripped_bytes).expect("parse stripped");
    assert!(
        stripped.chunks.dbgi.is_none(),
        "{module}: Dbgi must be stripped so the debug-info path cannot fire"
    );

    let surface: ErlangSurface = recover_erlang(&stripped).expect("recover");
    assert_eq!(
        surface.recovered_from,
        RecoverySource::CoreLifted,
        "{module}: recovery must fall back to bytecode core-lift with Dbgi/Docs stripped"
    );

    let rec_src: PathBuf = rec_dir.join(format!("{module}.erl"));
    std::fs::write(&rec_src, &surface.source).expect("write recovered");
    let (recompiled, rec_msg): (bool, String) = erlc_compile(erlc, &rec_src, &rec_dir);

    let mut exports_match: bool = false;
    let mut runtime_identical: bool = false;
    let mut fn_total: usize = 0;
    let mut fn_opcode_exact: usize = 0;
    let mut detail: String = String::new();

    if recompiled {
        let rec_beam: BeamFile = BeamFile::parse(
            &std::fs::read(rec_dir.join(format!("{module}.beam"))).expect("read recompiled"),
        )
        .expect("parse recompiled");
        exports_match = semantic_exports(&rec_beam) == semantic_exports(&stripped);
        if !exports_match {
            detail = format!(
                "exports differ: orig={:?} rec={:?}",
                semantic_exports(&stripped),
                semantic_exports(&rec_beam)
            );
        }

        let orig_seqs: Vec<((String, u32), Vec<&str>)> = opcode_sequences(&stripped);
        let rec_seqs: Vec<((String, u32), Vec<&str>)> = opcode_sequences(&rec_beam);
        fn_total = orig_seqs.len();
        for (key, ops) in &orig_seqs {
            if let Some((_, rec_ops)) = rec_seqs.iter().find(|(k, _)| k == key)
                && rec_ops == ops
            {
                fn_opcode_exact += 1;
            }
        }

        if let Some(erl) = erl {
            let (orig_ok, orig_out): (bool, String) = run_test0(erl, &orig_dir, module);
            assert!(
                orig_ok,
                "{module}:test() must succeed on the original (corpus precondition):\n{orig_out}"
            );
            let (rec_ok, rec_out): (bool, String) = run_test0(erl, &rec_dir, module);
            runtime_identical = rec_ok && rec_out == orig_out;
            if !runtime_identical {
                detail = format!(
                    "runtime differs:\n  orig: {}\n  rec:  {}",
                    orig_out.trim_end(),
                    rec_out.trim_end()
                );
            }
        }
    } else {
        detail = format!("recompile rejected:\n{rec_msg}");
    }

    Fidelity {
        module: module.to_owned(),
        recompiled,
        exports_match,
        runtime_identical,
        fn_total,
        fn_opcode_exact,
        detail,
        rejected_source: (!recompiled).then(|| surface.source.clone()),
    }
}

const MAX_DETAIL_LINES: usize = 60;
const MAX_SOURCE_LINES: usize = 200;

fn print_verdict(r: &Fidelity) {
    let status: &str = if r.behaviorally_equivalent() {
        "PASS"
    } else if !r.recompiled {
        "FAIL(recompile)"
    } else if !r.exports_match {
        "FAIL(exports)"
    } else {
        "FAIL(runtime)"
    };
    let op_pct: f64 = if r.fn_total == 0 {
        0.0
    } else {
        (r.fn_opcode_exact as f64) * 100.0 / (r.fn_total as f64)
    };
    println!(
        "  {status:<16} {:<16} opcode-exact {}/{} ({op_pct:.0}%)",
        r.module, r.fn_opcode_exact, r.fn_total
    );
    if r.behaviorally_equivalent() {
        return;
    }
    for line in r.detail.lines().take(MAX_DETAIL_LINES) {
        println!("       {line}");
    }
    let Some(source): Option<&String> = r.rejected_source.as_ref() else {
        return;
    };
    println!("       --- recovered {}.erl as erlc saw it ---", r.module);
    for (n, line) in source.lines().take(MAX_SOURCE_LINES).enumerate() {
        println!("       {:>4} | {line}", n + 1);
    }
    let total: usize = source.lines().count();
    if total > MAX_SOURCE_LINES {
        println!(
            "       ... {} further lines elided",
            total - MAX_SOURCE_LINES
        );
    }
}

fn corpus_modules() -> Vec<(String, PathBuf)> {
    let mut mods: Vec<(String, PathBuf)> = std::fs::read_dir(corpus_dir())
        .expect("read corpus dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p: &PathBuf| p.extension().is_some_and(|x| x == "erl"))
        .map(|p: PathBuf| (p.file_stem().unwrap().to_string_lossy().into_owned(), p))
        .collect();
    mods.sort();
    mods
}

const EQUIVALENCE_FLOOR: usize = 18;

#[test]
fn stripped_core_lift_is_recompile_equivalent() {
    let Some((erlc, erl)): Option<(PathBuf, PathBuf)> =
        find_on_path("erlc").zip(find_on_path("erl"))
    else {
        skip_or_fail("erlc and erl are not both on PATH, so Erlang/OTP is not installed here");
        return;
    };
    let release: String = match otp_release(&erl) {
        Ok(release) => release,
        Err(defect) => {
            skip_or_fail(&defect);
            return;
        }
    };

    let modules: Vec<(String, PathBuf)> = corpus_modules();
    assert!(
        modules.len() >= 19,
        "recompile-equivalence corpus regressed to {} modules",
        modules.len()
    );

    let mut results: Vec<Fidelity> = Vec::with_capacity(modules.len());
    for (module, src) in &modules {
        results.push(measure(&erlc, Some(&erl), module, src));
    }

    let equivalent: usize = results
        .iter()
        .filter(|r| r.behaviorally_equivalent())
        .count();
    let recompiled: usize = results.iter().filter(|r| r.recompiled).count();
    let fn_total: usize = results.iter().map(|r| r.fn_total).sum();
    let fn_exact: usize = results.iter().map(|r| r.fn_opcode_exact).sum();

    println!(
        "\n=== STRIPPED CORE-LIFT RECOMPILE-EQUIVALENCE (erlc and erl from OTP {release}) ==="
    );
    for r in &results {
        print_verdict(r);
    }
    let failing: Vec<&str> = results
        .iter()
        .filter(|r: &&Fidelity| !r.behaviorally_equivalent())
        .map(|r: &Fidelity| r.module.as_str())
        .collect();
    if !failing.is_empty() {
        println!("not equivalent under OTP {release}: {}", failing.join(", "));
    }
    let op_overall: f64 = if fn_total == 0 {
        0.0
    } else {
        (fn_exact as f64) * 100.0 / (fn_total as f64)
    };
    println!(
        "behavioral equivalence: {equivalent}/{} = {:.1}%   (recompile {recompiled}/{})",
        modules.len(),
        (equivalent as f64) * 100.0 / (modules.len() as f64),
        modules.len()
    );
    println!(
        "structural opcode fidelity: {fn_exact}/{fn_total} functions byte-for-byte opcode-identical = {op_overall:.1}%\n"
    );

    assert!(
        equivalent >= EQUIVALENCE_FLOOR,
        "recompile-equivalence regressed: {equivalent}/{} (floor {EQUIVALENCE_FLOOR}) under OTP \
         {release}, not equivalent: {}",
        modules.len(),
        failing.join(", ")
    );
}
