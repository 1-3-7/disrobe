#![allow(
    clippy::missing_panics_doc,
    clippy::print_stdout,
    clippy::expect_used,
    clippy::collapsible_if
)]

use std::path::PathBuf;

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};
use disrobe_pass_dotnet::model::{AssemblyModel, Resolver, TypeModel};
use disrobe_pass_dotnet::pe::{parse, parse_clr_header};
use disrobe_pass_dotnet::state_machine::{StateMachine, StateMachineKind, classify};

fn main() -> std::io::Result<()> {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dll: PathBuf = manifest.join("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
    let bytes: Vec<u8> = std::fs::read(&dll)?;

    if std::env::args().any(|a: String| a == "--count") {
        let pe = parse(&bytes).expect("pe");
        let clr = parse_clr_header(&bytes, &pe).expect("clr");
        let root =
            disrobe_pass_dotnet::metadata::parse_metadata_root(&bytes, &pe, &clr).expect("md");
        let resolver: Resolver = Resolver::build(&bytes, &pe, &clr, &root).expect("resolver");
        let model: AssemblyModel = resolver.model();
        let (mut a, mut i, mut ai): (usize, usize, usize) = (0, 0, 0);
        for ty in &model.types {
            if let Some(sm) = classify(ty) {
                match sm.kind {
                    StateMachineKind::Async => a += 1,
                    StateMachineKind::Iterator => i += 1,
                    StateMachineKind::AsyncIterator => ai += 1,
                }
                let _: &StateMachine = &sm;
                let _: &TypeModel = ty;
            }
        }
        println!(
            "state_machines: async={a} iterator={i} async_iterator={ai} total={}",
            a + i + ai
        );
        return Ok(());
    }

    let asm: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile");
    let needle: String = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "MoveNext".to_owned());
    let mut shown: usize = 0;
    for m in &asm.methods {
        if m.signature.contains(needle.as_str()) {
            let cap: usize = std::env::args()
                .nth(2)
                .and_then(|s: String| s.parse::<usize>().ok())
                .unwrap_or(4);
            println!("======================================\n{}", m.body);
            shown += 1;
            if shown >= cap {
                break;
            }
        }
    }
    println!("(shown {shown} methods matching '{needle}')");
    Ok(())
}
