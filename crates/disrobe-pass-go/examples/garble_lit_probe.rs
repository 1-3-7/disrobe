use std::path::PathBuf;
use std::process::ExitCode;

use disrobe_pass_go::{GoImage, probe_simple_literals};

fn run() -> Result<(), String> {
    let mut args: std::env::Args = std::env::args();
    let _bin: Option<String> = args.next();
    let raw_path: String = args
        .next()
        .ok_or_else(|| "usage: garble_lit_probe <binary> [needle...]".to_owned())?;
    let path: PathBuf = PathBuf::from(raw_path);
    let needles: Vec<String> = args.collect();
    let bytes: Vec<u8> = std::fs::read(&path).map_err(|e: std::io::Error| e.to_string())?;
    let image: GoImage<'_> =
        GoImage::parse(&bytes).map_err(|e: disrobe_pass_go::Error| e.to_string())?;
    let mut rodata_total: usize = 0;
    let mut hits: Vec<(String, String, usize)> = Vec::new();
    for sec in &image.sections {
        if !matches!(
            sec.name.as_str(),
            ".rdata" | ".rodata" | "__rodata" | "__const" | ".data.rel.ro"
        ) {
            continue;
        }
        rodata_total += sec.data.len();
        hits.extend(probe_simple_literals(sec.data));
    }
    println!("rodata bytes scanned: {rodata_total}");
    println!("simple-scheme recoveries: {}", hits.len());
    for (text, op, perturbed) in hits.iter().take(60) {
        println!("  [{op}] perturbed={perturbed} {text:?}");
    }
    for needle in &needles {
        let found: bool = hits
            .iter()
            .any(|(t, _, _): &(String, String, usize)| t.contains(needle));
        let status: &str = if found { "RECOVERED" } else { "absent" };
        println!("NEEDLE {needle:?} -> {status}");
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
