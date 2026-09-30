use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_core::scratch::ScratchFile;

pub(crate) const PREREQUISITE: &str = "disrobe-pass-lua::lua";

pub(crate) const INSTALL_HINT: &str =
    "install lua5.4 (apt-get install lua5.4) or luajit and put it on PATH";

pub(crate) const CANDIDATES: [&str; 6] = ["lua", "lua5.4", "lua5.1", "luajit", "lua54", "lua51"];

const BANNER_MARKER: &str = "lua";

static SCRATCH_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub(crate) struct LuaInterpreter {
    pub(crate) program: &'static str,
    pub(crate) banner: String,
}

fn version_probe(program: &'static str, graded: &str) -> Result<String, String> {
    let output: Output = match Command::new(program).arg("-v").output() {
        Ok(output) => output,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Err(format!("`{program}` is not on PATH"));
        }
        Err(err) => panic!(
            "`{program}` is on PATH but could not be launched here ({err}), so {graded} cannot be \
             measured. An interpreter that is present and unrunnable is never a skip, because that \
             is how a permissions or quarantine problem silently stops grading."
        ),
    };
    let stdout: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let banner: String = if stdout.is_empty() { stderr } else { stdout };
    assert!(
        !banner.is_empty(),
        "`{program} -v` ran and printed nothing on either stream, so {graded} would be graded by an \
         interpreter this harness cannot identify. A silent binary is never a skip."
    );
    assert!(
        banner.to_ascii_lowercase().contains(BANNER_MARKER),
        "`{program} -v` reports `{banner}`, which does not name Lua, so the binary on PATH under \
         that name is something else and {graded} must not be graded with it"
    );
    Ok(banner)
}

pub(crate) fn unmeasured(graded: &str, defect: &str) {
    let what: String =
        format!("a real Lua interpreter to grade {graded} ({defect}); {INSTALL_HINT}");
    if let Err(error) = disrobe_testkit::require::<()>(PREREQUISITE, &what, None) {
        panic!("{error}");
    }
}

pub(crate) fn require_interpreter(graded: &str) -> Option<LuaInterpreter> {
    let mut defects: Vec<String> = Vec::new();
    for program in CANDIDATES {
        match version_probe(program, graded) {
            Ok(banner) => return Some(LuaInterpreter { program, banner }),
            Err(defect) => defects.push(defect),
        }
    }
    unmeasured(graded, &defects.join("; "));
    None
}

pub(crate) fn require_interpreter_present(graded: &str) -> LuaInterpreter {
    require_interpreter(graded).unwrap_or_else(|| {
        panic!(
            "tests/optional.toml lists {PREREQUISITE}, but {graded} has no result without a Lua \
             interpreter, so that entry only hides the gap; remove it"
        )
    })
}

pub(crate) fn run_lua(interpreter: &LuaInterpreter, label: &str, source: &str) -> String {
    let unique: u64 = SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed);
    let purpose: String = format!("lua_toolchain_{}_{unique}", std::process::id());
    let (scratch, handle): (ScratchFile, fs::File) = ScratchFile::create(&purpose, "lua")
        .unwrap_or_else(|err: std::io::Error| {
            panic!("{label}: no scratch file for the interpreter run: {err}")
        });
    drop(handle);
    let script: PathBuf = scratch.path().to_path_buf();
    fs::write(&script, source).unwrap_or_else(|err: std::io::Error| {
        panic!(
            "{label}: cannot stage the script at {}: {err}",
            script.display()
        )
    });
    let output: Output = Command::new(interpreter.program)
        .arg(&script)
        .output()
        .unwrap_or_else(|err: std::io::Error| {
            panic!(
                "{label}: `{}` failed to launch on a staged script: {err}",
                interpreter.program
            )
        });
    assert!(
        output.status.success(),
        "{label}: `{}` exited {} on this source, so nothing can be compared against it:\n--- \
         stderr ---\n{}\n--- source ---\n{source}",
        interpreter.program,
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n")
}
