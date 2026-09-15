use std::ffi::OsString;
use std::fs::File;
use std::io::Read;

use disrobe_pass_wasm_deob::{ModuleSummary, analyze_module, lift_module_faithful_wat};
use miette::{IntoDiagnostic, WrapErr};

fn main() -> miette::Result<()> {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let [path]: &[OsString] = arguments.as_slice() else {
        miette::bail!("usage: inspect_module <module.wasm>");
    };
    let mut bytes: Vec<u8> = Vec::new();
    File::open(path)
        .into_diagnostic()
        .wrap_err("cannot open WebAssembly module")?
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .into_diagnostic()
        .wrap_err("cannot read WebAssembly module")?;
    if bytes.len() > 16 * 1024 * 1024 {
        miette::bail!("this example accepts modules up to 16 MiB");
    }
    let summary: ModuleSummary = analyze_module(&bytes)?;
    let wat: String = lift_module_faithful_wat(&bytes).ok_or_else(|| {
        miette::miette!("module contains a construct this WAT lifter cannot emit")
    })?;
    println!(
        "functions={} imports={} exports={:?}",
        summary.func_count,
        summary.imports.len(),
        summary.exports
    );
    print!("{wat}");
    Ok(())
}
