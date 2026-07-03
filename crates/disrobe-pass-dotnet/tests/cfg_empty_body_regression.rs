#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_pass_dotnet::cfg::Cfg;
use disrobe_pass_dotnet::cil::MethodBody;
use disrobe_pass_dotnet::decompile::{decompile_assembly, decompile_assembly_in};
use disrobe_pass_dotnet::structurize::TargetLang;
use disrobe_pass_dotnet::{analyze, peel_by, protectors::detect_all, recover_static_decoders};

fn corpus(name: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../corpus/dotnet");
    path.push(name);
    std::fs::read(&path).unwrap_or_default()
}

const fn xorshift(state: &mut u32) -> u32 {
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    *state
}

#[test]
fn cfg_build_on_empty_method_body_does_not_panic() {
    let empty: MethodBody = MethodBody {
        max_stack: 0,
        code_size: 0,
        local_var_sig_tok: 0,
        init_locals: false,
        instructions: Vec::new(),
        exception_clauses: Vec::new(),
    };
    let cfg: Cfg = Cfg::build(&empty);
    assert!(cfg.blocks.is_empty());
    assert!(cfg.rpo.is_empty());
    assert!(cfg.idom.is_empty());
}

fn hammer(base: &[u8], seed: u32, flips: usize, iters: usize) {
    if base.is_empty() {
        return;
    }
    let mut rng: u32 = seed;
    for _ in 0..iters {
        let mut m: Vec<u8> = base.to_vec();
        for _ in 0..flips {
            let pos: usize = (xorshift(&mut rng) as usize) % m.len();
            m[pos] = (xorshift(&mut rng) & 0xFF) as u8;
        }
        let _ = analyze(&m);
        let _ = decompile_assembly(&m);
        let _ = decompile_assembly_in(&m, TargetLang::FSharp);
        let _ = decompile_assembly_in(&m, TargetLang::VbNet);
        let _ = recover_static_decoders(&m);
        let report = detect_all(&m);
        if let Some(p) = report.primary {
            let _ = peel_by(p, &m);
        }
    }
}

#[test]
fn deep_panic_hunt_all_fixtures() {
    for name in [
        "HelloApp.dll",
        "HelloAppLegacy.dll",
        "HelloAppLegacy.confuserex2.dll",
        "HelloAppLegacy.obfuscar.dll",
        "SampleConstants.confuserex2.dll",
        "HelloApp.r2r.dll",
        "HelloAppAot.dll",
    ] {
        let base: Vec<u8> = corpus(name);
        hammer(&base, 0x1234_5678, 4, 400);
        hammer(&base, 0x9E37_79B9, 12, 400);
        hammer(&base, 0xDEAD_BEEF, 32, 400);
        hammer(&base, 0x0BAD_F00D, 64, 200);
    }
}
