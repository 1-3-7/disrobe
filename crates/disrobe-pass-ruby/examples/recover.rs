//! Dev oracle helper: decompile a `.yarvc` to recovered Ruby source on stdout, for the
//! non-circular recompile-equivalence harness (`.oracle/harness.sh`).

use std::process::ExitCode;

use disrobe_pass_ruby::analyze_bytes;

fn main() -> ExitCode {
    let Some(arg): Option<String> = std::env::args().nth(1) else {
        eprintln!("usage: recover <path.yarvc>");
        return ExitCode::FAILURE;
    };
    let bytes: Vec<u8> = match std::fs::read(&arg) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("read {arg}: {err}");
            return ExitCode::FAILURE;
        }
    };
    let analysis = match analyze_bytes(&bytes, &arg) {
        Ok(analysis) => analysis,
        Err(err) => {
            eprintln!("analyze {arg}: {err}");
            return ExitCode::FAILURE;
        }
    };
    let Some(yarv) = analysis.yarv else {
        eprintln!("no yarv analysis for {arg}");
        return ExitCode::FAILURE;
    };
    print!("{}", yarv.decompiled.source);
    ExitCode::SUCCESS
}
