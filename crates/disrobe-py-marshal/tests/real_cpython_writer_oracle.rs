#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_py_marshal::{
    Object, PyVersion, PycFile, PycHeader, RefKind, dump_reftable, magic_for, read_pyc, write_pyc,
};

const GEN_TIMEOUT: Duration = Duration::from_secs(30);
const EXEC_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_CAPTURE: usize = 1 << 20;

const SOURCE: &str = r"import sys
sys.stdout.reconfigure(encoding='utf-8')
MARKER = 'café-日本語-☃'
BIG = 123456789012345678901234567890
NEG = -987654321
PAIR = (1, 2, MARKER)

def helper():
    return MARKER

class Holder:
    def method(self):
        return helper()

print('ORACLE', MARKER, BIG, NEG, PAIR, helper(), Holder().method())
";

const COMPILE_AND_DUMP: &str = r"import sys, marshal
with open(sys.argv[1], 'r', encoding='utf-8') as fh:
    src = fh.read()
code = compile(src, '<oracle>', 'exec')
with open(sys.argv[2], 'wb') as fh:
    fh.write(marshal.dumps(code))
";

fn workdir(tag: &str) -> ScratchDir {
    let purpose: String = format!("disrobe-py-marshal-writer-oracle-{tag}");
    ScratchDir::create(&purpose).expect("create scratch dir")
}

fn python_for(major: u8, minor: u8) -> Option<PathBuf> {
    let out: std::process::Output = std::process::Command::new("uv")
        .args(["python", "find", &format!("{major}.{minor}")])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let raw: String = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let path: PathBuf = PathBuf::from(raw);
    path.is_file().then_some(path)
}

fn real_marshal_body(python: &Path, dir: &Path) -> Option<Vec<u8>> {
    let script: PathBuf = dir.join("gen.py");
    let src: PathBuf = dir.join("src.py");
    let out: PathBuf = dir.join("orig.marshal");
    std::fs::write(&script, COMPILE_AND_DUMP).ok()?;
    std::fs::write(&src, SOURCE).ok()?;
    let captured: CapturedOutput =
        run_captured(python, &[&script, &src, &out], GEN_TIMEOUT, MAX_CAPTURE).ok()??;
    if captured.exit_code != Some(0) {
        eprintln!(
            "[real_cpython_writer_oracle] generator failed: {}",
            String::from_utf8_lossy(&captured.stderr)
        );
        return None;
    }
    std::fs::read(&out).ok()
}

fn baseline_stdout(python: &Path, dir: &Path) -> Option<String> {
    let src: PathBuf = dir.join("src.py");
    let captured: CapturedOutput =
        run_captured(python, &[&src], EXEC_TIMEOUT, MAX_CAPTURE).ok()??;
    if captured.exit_code != Some(0) {
        eprintln!(
            "[real_cpython_writer_oracle] baseline run failed: {}",
            String::from_utf8_lossy(&captured.stderr)
        );
        return None;
    }
    Some(String::from_utf8_lossy(&captured.stdout).into_owned())
}

fn pyc_header_bytes(version: PyVersion) -> Vec<u8> {
    let magic: u32 = magic_for(version).expect("known magic for a supported real interpreter");
    let trailing_word_count: usize = if version.has_pep552_header() {
        3
    } else if version.has_source_size() {
        2
    } else {
        1
    };
    let mut header: Vec<u8> = magic.to_le_bytes().to_vec();
    for _ in 0..trailing_word_count {
        header.extend_from_slice(&0u32.to_le_bytes());
    }
    header
}

fn exec_pyc_stdout(python: &Path, pyc_path: &Path) -> Option<String> {
    let captured: CapturedOutput =
        run_captured(python, &[pyc_path], EXEC_TIMEOUT, MAX_CAPTURE).ok()??;
    if captured.exit_code != Some(0) {
        eprintln!(
            "[real_cpython_writer_oracle] reemitted pyc execution failed: {}",
            String::from_utf8_lossy(&captured.stderr)
        );
        return None;
    }
    Some(String::from_utf8_lossy(&captured.stdout).into_owned())
}

struct VersionGrade {
    version: PyVersion,
    ran: bool,
    saw_backreference: bool,
}

fn grade_version(major: u8, minor: u8) -> VersionGrade {
    let version: PyVersion = PyVersion::new(major, minor);
    let Some(python) = python_for(major, minor) else {
        eprintln!(
            "[real_cpython_writer_oracle] HONEST-PARTIAL: no CPython {major}.{minor} resolvable via uv; skipping this version"
        );
        return VersionGrade {
            version,
            ran: false,
            saw_backreference: false,
        };
    };

    let dir: ScratchDir = workdir(&format!("{major}-{minor}"));
    let dir_path: PathBuf = dir.path().to_path_buf();

    let Some(real_body) = real_marshal_body(&python, &dir_path) else {
        return VersionGrade {
            version,
            ran: false,
            saw_backreference: false,
        };
    };
    let Some(baseline) = baseline_stdout(&python, &dir_path) else {
        return VersionGrade {
            version,
            ran: false,
            saw_backreference: false,
        };
    };
    assert!(
        baseline.contains("ORACLE"),
        "{major}.{minor}: baseline run must print the marker line, got {baseline:?}"
    );

    let (_obj, ref_table) = dump_reftable(&real_body, version).unwrap_or_else(|e| {
        panic!("{major}.{minor}: dump_reftable must parse a real CPython marshal stream: {e}")
    });
    let saw_backreference: bool = ref_table
        .entries
        .iter()
        .any(|entry| entry.kind == RefKind::Ref);

    let mut original_pyc: Vec<u8> = pyc_header_bytes(version);
    original_pyc.extend_from_slice(&real_body);

    let decoded: PycFile =
        read_pyc(&original_pyc).unwrap_or_else(|e| panic!("{major}.{minor}: read_pyc: {e}"));
    assert!(
        matches!(decoded.code, Object::Code(_)),
        "{major}.{minor}: a real compiled module must decode to a code object"
    );
    assert_eq!(
        decoded.header.version, version,
        "{major}.{minor}: header magic must resolve to the interpreter that produced the body"
    );

    let reemitted: Vec<u8> = write_pyc(&PycFile {
        header: PycHeader::deterministic(version)
            .unwrap_or_else(|e| panic!("{major}.{minor}: deterministic header: {e}")),
        code: decoded.code,
    })
    .unwrap_or_else(|e| {
        panic!("{major}.{minor}: write_pyc must re-emit the decoded code object: {e}")
    });

    let reemit_path: PathBuf = dir_path.join("reemit.pyc");
    std::fs::write(&reemit_path, &reemitted).expect("write reemitted pyc");

    let reemitted_stdout: String = exec_pyc_stdout(&python, &reemit_path).unwrap_or_else(|| {
        panic!(
            "{major}.{minor}: real CPython must execute disrobe's re-emitted pyc; \
             a writer bug that produces bytes marshal.loads rejects fails here, not inside disrobe"
        )
    });
    assert_eq!(
        reemitted_stdout, baseline,
        "{major}.{minor}: stdout from executing disrobe's re-emitted pyc under real CPython \
         must match the stdout of the original source run under the same interpreter"
    );

    VersionGrade {
        version,
        ran: true,
        saw_backreference,
    }
}

#[test]
fn writer_reemits_real_cpython_marshal_and_the_same_interpreter_executes_it_identically() {
    let candidates: [(u8, u8); 5] = [(3, 9), (3, 11), (3, 12), (3, 13), (3, 14)];
    let mut graded: Vec<VersionGrade> = Vec::new();
    for (major, minor) in candidates {
        graded.push(grade_version(major, minor));
    }

    let ran_count: usize = graded.iter().filter(|g| g.ran).count();
    assert!(
        ran_count > 0,
        "no real CPython interpreter was resolvable via `uv python find`; \
         this grader requires at least one real interpreter to prove anything"
    );

    let any_backreference: bool = graded.iter().any(|g| g.ran && g.saw_backreference);
    assert!(
        any_backreference,
        "expected at least one graded version's real marshal stream to carry a genuine \
         CPython back-reference (the shared co_filename across module and nested code objects); \
         none did, which means dump_reftable was never exercised against a real ref-bearing stream: {:?}",
        graded
            .iter()
            .map(|g| (g.version, g.ran, g.saw_backreference))
            .collect::<Vec<_>>()
    );
}
