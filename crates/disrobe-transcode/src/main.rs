#![deny(unsafe_code)]
#![deny(unreachable_pub)]
use std::process::ExitCode;

use disrobe_ir::Envelope;
use disrobe_transcode::{Transcoded, transcode_envelope, verify_transcode_envelope};

#[derive(Debug)]
struct Args {
    input: String,
    output: String,
    verify: bool,
}

fn parse_args() -> std::result::Result<Args, String> {
    parse_args_from(std::env::args().skip(1))
}

fn parse_args_from<I>(args: I) -> std::result::Result<Args, String>
where
    I: IntoIterator<Item = String>,
{
    let mut positional: Vec<String> = Vec::with_capacity(2);
    let mut verify: bool = false;
    for arg in args {
        match arg.as_str() {
            "--verify" => verify = true,
            "-h" | "--help" => return Err(usage()),
            flag if flag.starts_with("--") => {
                return Err(format!("unknown flag: {flag}\n{}", usage()));
            }
            _ if positional.len() == 2 => {
                return Err(format!(
                    "expected <in.dr> <out.dr>, got at least 3 args\n{}",
                    usage()
                ));
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
    let input_env: Envelope =
        Envelope::read_from_path(&args.input).map_err(|e| format!("read {}: {e}", args.input))?;

    let transcoded: Transcoded =
        transcode_envelope(&input_env).map_err(|e| format!("transcode: {e}"))?;

    if args.verify {
        verify_transcode_envelope(&input_env, &transcoded)
            .map_err(|e| format!("verify failed: {e}"))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values
            .iter()
            .map(|value: &&str| (*value).to_owned())
            .collect()
    }

    #[test]
    fn parse_args_accepts_verify_after_paths() {
        let parsed: std::result::Result<Args, String> =
            parse_args_from(strings(&["in.dr", "out.dr", "--verify"]));
        assert!(parsed.is_ok(), "args parse failed: {parsed:?}");
        let args: Args = match parsed {
            Ok(args) => args,
            Err(_) => return,
        };
        assert_eq!(args.input, "in.dr");
        assert_eq!(args.output, "out.dr");
        assert!(args.verify);
    }

    #[test]
    fn parse_args_rejects_third_positional_immediately() {
        let parsed: std::result::Result<Args, String> =
            parse_args_from(strings(&["in.dr", "out.dr", "extra.dr"]));
        assert!(parsed.is_err(), "third positional parsed: {parsed:?}");
        let err: String = match parsed {
            Ok(_) => return,
            Err(err) => err,
        };
        assert!(err.contains("at least 3 args"));
    }
}
