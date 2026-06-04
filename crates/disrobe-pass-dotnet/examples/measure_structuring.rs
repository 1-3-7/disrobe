#![allow(
    clippy::missing_panics_doc,
    clippy::print_stdout,
    clippy::expect_used,
    clippy::cast_precision_loss
)]

use std::path::PathBuf;

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};
use disrobe_pass_dotnet::structurize::StructuredMethod;

fn main() -> std::io::Result<()> {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dll: PathBuf = manifest.join("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
    let bytes: Vec<u8> = std::fs::read(&dll)?;
    let asm: DecompiledAssembly =
        decompile_assembly(&bytes).expect("decompile EdgeCases.baseline.dll");

    let total: usize = asm.methods.len();
    let mut goto_free: usize = 0;
    let mut underflow: usize = 0;
    let mut with_loop: usize = 0;
    let mut with_if: usize = 0;
    let mut with_switch: usize = 0;
    let mut with_trycatch: usize = 0;
    let mut cf_total: usize = 0;
    let mut cf_clean: usize = 0;
    let dump: bool = std::env::args().any(|a: String| a == "--dump");

    for m in &asm.methods {
        let body: &str = m.body.as_str();
        let goto: bool = residual_goto(body);
        let uf: bool = body.contains("__stack_underflow");
        let has_loop: bool = body.contains("while (") || body.contains("for (");
        let has_if: bool = line_has_if(body);
        let has_switch: bool = body.contains("switch (");
        let has_try: bool = body.contains("try") && body.contains("catch");
        let has_cf: bool = has_loop || has_if || has_switch || has_try || goto;

        if !goto {
            goto_free += 1;
        }
        if uf {
            underflow += 1;
        }
        if has_loop {
            with_loop += 1;
        }
        if has_if {
            with_if += 1;
        }
        if has_switch {
            with_switch += 1;
        }
        if has_try {
            with_trycatch += 1;
        }
        if has_cf {
            cf_total += 1;
            if !goto && !uf {
                cf_clean += 1;
            }
        }
    }

    println!("module={}", asm.module_name);
    println!(
        "methods_decompiled={total} bodyless={} failed={}",
        asm.methods_bodyless, asm.methods_failed
    );
    println!(
        "goto_free={goto_free}/{total} ({:.1}%)",
        pct(goto_free, total)
    );
    println!(
        "control_flow_methods={cf_total} fully_structured={cf_clean} ({:.1}% of CF methods)",
        pct(cf_clean, cf_total)
    );
    println!("stack_underflow={underflow}");
    println!(
        "with_loop={with_loop} with_if={with_if} with_switch={with_switch} with_trycatch={with_trycatch}"
    );

    if dump {
        for m in asm.methods.iter().filter(|m: &&StructuredMethod| {
            m.body.contains("while (") || m.body.contains("for (") || residual_goto(&m.body)
        }) {
            println!("==================\n{}", m.body);
        }
    }
    Ok(())
}

fn residual_goto(body: &str) -> bool {
    body.lines().any(|l: &str| {
        let t: &str = l.trim_start();
        t.starts_with("goto IL_")
            || t.contains(" goto IL_")
            || (t.starts_with("IL_") && t.ends_with(":;"))
    })
}

fn line_has_if(body: &str) -> bool {
    body.lines().any(|l: &str| {
        let t: &str = l.trim_start();
        t.starts_with("if (") && !t.contains("goto IL_")
    })
}

fn pct(n: usize, d: usize) -> f64 {
    if d == 0 {
        0.0
    } else {
        (n as f64) * 100.0 / (d as f64)
    }
}
