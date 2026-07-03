#![allow(
    clippy::missing_panics_doc,
    clippy::print_stdout,
    clippy::expect_used,
    clippy::cast_precision_loss
)]

use std::path::PathBuf;

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};
use disrobe_pass_dotnet::structurize::StructuredMethod;

#[derive(Debug, Clone, Copy, Default)]
struct Tally {
    total: usize,
    type_checkable: usize,
    untyped_var_locals: usize,
    positional_params: usize,
    residual_goto: usize,
    underflow: usize,
    empty_await_guard: usize,
}

fn main() -> std::io::Result<()> {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dll: PathBuf = manifest.join("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
    let bytes: Vec<u8> = std::fs::read(&dll)?;
    let asm: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile baseline");

    let mut all: Tally = Tally::default();
    let mut move_next: Tally = Tally::default();
    for m in &asm.methods {
        let is_move_next: bool = m.signature.contains("MoveNext") || m.body.contains("MoveNext");
        score(&mut all, m);
        if is_move_next {
            score(&mut move_next, m);
        }
    }

    report("ALL recovered bodies", &all);
    report("MoveNext-family bodies", &move_next);
    Ok(())
}

fn score(t: &mut Tally, m: &StructuredMethod) {
    t.total += 1;
    let body: &str = m.body.as_str();
    let goto: bool = residual_goto(body);
    let underflow: bool = body.contains("__stack_underflow");
    let var_local: bool = body
        .lines()
        .any(|l: &str| l.trim_start().starts_with("var local") && l.trim_end().ends_with(';'));
    let pos_param: bool = signature_has_positional_param(&m.signature);
    let empty_guard: bool = has_empty_await_guard(body);
    if goto {
        t.residual_goto += 1;
    }
    if underflow {
        t.underflow += 1;
    }
    if var_local {
        t.untyped_var_locals += 1;
    }
    if pos_param {
        t.positional_params += 1;
    }
    if empty_guard {
        t.empty_await_guard += 1;
    }
    if !goto && !underflow && !var_local && !pos_param && !empty_guard {
        t.type_checkable += 1;
    }
}

fn signature_has_positional_param(signature: &str) -> bool {
    let header: &str = signature
        .lines()
        .find(|l: &&str| l.contains('(') && !l.trim_start().starts_with("//"))
        .unwrap_or("");
    let Some(args): Option<&str> = header.split_once('(').map(|(_, r): (&str, &str)| r) else {
        return false;
    };
    args.split(',').any(|a: &str| {
        a.split_whitespace()
            .next_back()
            .is_some_and(|name: &str| name.trim_end_matches(')').starts_with("arg"))
    })
}

fn has_empty_await_guard(body: &str) -> bool {
    let lines: Vec<&str> = body.lines().collect();
    lines.windows(3).any(|w: &[&str]| {
        let head: &str = w[0].trim_start();
        head.starts_with("if (")
            && (head.contains("IsCompleted") || head.contains("get_IsCompleted"))
            && w[1].trim() == "{"
            && w[2].trim() == "}"
    })
}

fn residual_goto(body: &str) -> bool {
    body.lines().any(|l: &str| {
        let t: &str = l.trim_start();
        t.starts_with("goto IL_")
            || t.contains(" goto IL_")
            || (t.starts_with("IL_") && t.ends_with(":;"))
    })
}

fn report(label: &str, t: &Tally) {
    println!("== {label} ==");
    println!(
        "  type_checkable = {}/{} ({:.1}%)",
        t.type_checkable,
        t.total,
        pct(t.type_checkable, t.total)
    );
    println!("  residual_goto      = {}", t.residual_goto);
    println!("  stack_underflow    = {}", t.underflow);
    println!("  untyped_var_locals = {}", t.untyped_var_locals);
    println!("  positional_params  = {}", t.positional_params);
    println!("  empty_await_guard  = {}", t.empty_await_guard);
}

fn pct(n: usize, d: usize) -> f64 {
    if d == 0 {
        0.0
    } else {
        (n as f64) * 100.0 / (d as f64)
    }
}
