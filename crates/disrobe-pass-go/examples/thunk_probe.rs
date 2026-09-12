use std::path::PathBuf;
use std::process::ExitCode;

use disrobe_pass_go::probe_thunk_literals;

fn run() -> Result<(), String> {
    let mut args: std::env::Args = std::env::args();
    let _bin: Option<String> = args.next();
    let raw_path: String = args
        .next()
        .ok_or_else(|| "usage: thunk_probe <binary> [needle...]".to_owned())?;
    let needles: Vec<String> = args.collect();
    let bytes: Vec<u8> =
        std::fs::read(PathBuf::from(raw_path)).map_err(|e: std::io::Error| e.to_string())?;
    let hits: Vec<(String, u64, u64)> = probe_thunk_literals(&bytes).map_err(|e| e.to_string())?;
    println!("thunk recoveries: {}", hits.len());
    for (text, thunk, data) in &hits {
        println!("  thunk={thunk:#x} data={data:#x} {text:?}");
    }
    for needle in &needles {
        let found: bool = hits
            .iter()
            .any(|(t, _, _): &(String, u64, u64)| t.contains(needle));
        println!(
            "NEEDLE {needle:?} -> {}",
            if found { "RECOVERED" } else { "absent" }
        );
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
