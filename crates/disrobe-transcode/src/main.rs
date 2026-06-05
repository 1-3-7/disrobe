#![deny(unsafe_code)]

use std::process::ExitCode;

use disrobe_transcode::{Transcoded, transcode_bytes, verify_transcode};

#[derive(Debug)]
struct Args {
    input: String,
    output: String,
    verify: bool,
}

fn parse_args() -> std::result::Result<Args, String> {
    let mut positional: Vec<String> = Vec::with_capacity(2);
    let mut verify: bool = false;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--verify" => verify = true,
            "-h" | "--help" => return Err(usage()),
            flag if flag.starts_with("--") => {
                return Err(format!("unknown flag: {flag}\n{}", usage()));
            }
            _ => positional.push(arg),
        }
    }
    let [input, output]: [String; 2] = positional.try_into().map_err(|v: Vec<String>| {
        format!(
            "expected <in.dr> <out.dr>, got {} args\n{}",
            v.len(),
            usage()
        )
    })?;
    Ok(Args {
        input,
        output,
        verify,
    })
}

fn usage() -> String {
    "usage: disrobe-transcode <in.dr> <out.dr> [--verify]".to_owned()
}

fn run() -> std::result::Result<(), String> {
    let args: Args = parse_args()?;
    let input_bytes: Vec<u8> =
        std::fs::read(&args.input).map_err(|e| format!("read {}: {e}", args.input))?;

    let transcoded: Transcoded =
        transcode_bytes(&input_bytes).map_err(|e| format!("transcode: {e}"))?;

    if args.verify {
        verify_transcode(&input_bytes, &transcoded).map_err(|e| format!("verify failed: {e}"))?;
    }

    std::fs::write(&args.output, &transcoded.bytes)
        .map_err(|e| format!("write {}: {e}", args.output))?;

    println!(
        "transcoded {} -> {} | rung={:?} v{}->v{} hot {}B->{}B cold {}B{}",
        args.input,
        args.output,
        transcoded.rung,
        transcoded.source_version,
        transcoded.target_version,
        transcoded.old_hot_len,
        transcoded.new_hot_len,
        transcoded.cold_len,
        if args.verify { " [verified]" } else { "" },
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("disrobe-transcode: {msg}");
            ExitCode::FAILURE
        }
    }
}
