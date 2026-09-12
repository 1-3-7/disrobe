#![allow(
    clippy::missing_panics_doc,
    clippy::print_stdout,
    clippy::expect_used,
    clippy::collapsible_if
)]

use std::path::PathBuf;

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};

fn main() -> std::io::Result<()> {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dll: PathBuf = manifest.join("tests/fixtures/VerifyCases.dll");
    let bytes: Vec<u8> = std::fs::read(&dll)?;
    let asm: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile VerifyCases.dll");

    let filter: Option<String> = std::env::args().nth(1);
    for m in &asm.methods {
        if m.signature.contains(".ctor") || m.signature.contains(".cctor") {
            continue;
        }
        if let Some(f) = &filter {
            if !m.signature.contains(f.as_str()) {
                continue;
            }
        }
        println!("======================================\n{}", m.body);
    }
    Ok(())
}
