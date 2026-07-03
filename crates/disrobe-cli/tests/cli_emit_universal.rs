#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use common::{Run, run_disrobe};

const EMIT_SUBCOMMANDS: &[&[&str]] = &[
    &["py", "deob"],
    &["py", "disasm"],
    &["py", "decompile"],
    &["pyarmor", "unpack"],
    &["wasm", "decompile"],
    &["dotnet", "decompile"],
    &["hermes", "decompile"],
    &["lua", "decompile"],
    &["jvm", "decompile"],
    &["macho", "classdump"],
    &["php", "deobfuscate"],
    &["ruby", "decompile"],
    &["beam", "lift"],
    &["beam", "disasm"],
    &["go", "recover"],
    &["js", "deob"],
    &["as3", "disasm"],
    &["flutter", "decompile"],
    &["native", "decompile"],
];

#[test]
fn every_emit_subcommand_accepts_emit_flag() {
    for spec in EMIT_SUBCOMMANDS {
        let mut args: Vec<&str> = spec.to_vec();
        args.push("--help");
        let r: Run = run_disrobe(&args);
        assert_eq!(
            r.code,
            0,
            "`disrobe {} --help` must parse (exit 0). stdout={} stderr={}",
            spec.join(" "),
            r.stdout,
            r.stderr
        );
        assert!(
            r.stdout.contains("--emit"),
            "`disrobe {} --help` must expose --emit (clap must render the threaded EmitSpec arg). stdout={}",
            spec.join(" "),
            r.stdout
        );
    }
}
