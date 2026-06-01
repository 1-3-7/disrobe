#![allow(clippy::needless_pass_by_value)]

use std::io::Read;
use std::path::PathBuf;

use clap::Subcommand;

use disrobe_pass_pickle::{
    Disassembly, MlReport, PolyglotReport, SafetyReport, VmTrace, analyze_polyglot, analyze_safety,
    disassemble, execute, extract_ml, render_disasm, to_python_assignment,
};

#[derive(Subcommand, Debug)]
pub(crate) enum PickleCmd {
    #[command(about = "disassemble a pickle stream into an offset-annotated opcode listing")]
    Disasm {
        #[arg(help = "input pickle file ('-' for stdin)")]
        input: PathBuf,
        #[arg(long, help = "emit JSON instead of human-readable text")]
        json: bool,
    },
    #[command(about = "decompile the symbolic object graph back to equivalent Python source")]
    Decompile {
        #[arg(help = "input pickle file ('-' for stdin)")]
        input: PathBuf,
        #[arg(long, help = "emit JSON {source, graph} instead of bare Python")]
        json: bool,
    },
    #[command(
        about = "static safety analysis: severity tier + dangerous-import / REDUCE / memo findings"
    )]
    Safety {
        #[arg(help = "input pickle file ('-' for stdin)")]
        input: PathBuf,
        #[arg(long, help = "emit JSON instead of human-readable text")]
        json: bool,
    },
    #[command(about = "symbolic VM trace: object graph, memo stats, global refs, reduce count")]
    Trace {
        #[arg(help = "input pickle file ('-' for stdin)")]
        input: PathBuf,
        #[arg(long, help = "emit JSON instead of human-readable text")]
        json: bool,
    },
    #[command(about = "detect pickle/zip/zip64/tar polyglot files (weaponized model archives)")]
    Polyglot {
        #[arg(help = "input file ('-' for stdin)")]
        input: PathBuf,
        #[arg(long, help = "emit JSON instead of human-readable text")]
        json: bool,
    },
    #[command(
        name = "ml-detect",
        about = "detect ML model formats (PyTorch / TorchScript / numpy) & list embedded pickles"
    )]
    MlDetect {
        #[arg(help = "input model file ('-' for stdin)")]
        input: PathBuf,
        #[arg(long, help = "emit JSON instead of human-readable text")]
        json: bool,
    },
}

pub(crate) fn run(action: PickleCmd) -> miette::Result<()> {
    match action {
        PickleCmd::Disasm { input, json } => disasm(input, json),
        PickleCmd::Decompile { input, json } => decompile(input, json),
        PickleCmd::Safety { input, json } => safety(input, json),
        PickleCmd::Trace { input, json } => trace(input, json),
        PickleCmd::Polyglot { input, json } => polyglot(input, json),
        PickleCmd::MlDetect { input, json } => ml_detect(input, json),
    }
}

fn read_input(input: &PathBuf) -> miette::Result<Vec<u8>> {
    if input.as_os_str() == "-" {
        let mut buf: Vec<u8> = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| miette::miette!("DR-CLI-0660: cannot read stdin: {e}"))?;
        Ok(buf)
    } else {
        std::fs::read(input).map_err(|e| miette::miette!("DR-CLI-0661: cannot read input: {e}"))
    }
}

fn emit_json<T: serde::Serialize>(value: &T) -> miette::Result<()> {
    let s: String = serde_json::to_string_pretty(value)
        .map_err(|e| miette::miette!("DR-CLI-0662: serialize: {e}"))?;
    println!("{s}");
    Ok(())
}

fn disasm(input: PathBuf, json: bool) -> miette::Result<()> {
    let bytes: Vec<u8> = read_input(&input)?;
    let dis: Disassembly =
        disassemble(&bytes).map_err(|e| miette::miette!("DR-CLI-0663: pickle disasm: {e}"))?;
    if json {
        emit_json(&dis)
    } else {
        print!("{}", render_disasm(&dis));
        Ok(())
    }
}

fn decompile(input: PathBuf, json: bool) -> miette::Result<()> {
    let bytes: Vec<u8> = read_input(&input)?;
    let dis: Disassembly =
        disassemble(&bytes).map_err(|e| miette::miette!("DR-CLI-0664: pickle disasm: {e}"))?;
    let trace: VmTrace =
        execute(&dis).map_err(|e| miette::miette!("DR-CLI-0665: pickle vm: {e}"))?;
    let source: String = to_python_assignment(&trace.result);
    if json {
        let value: serde_json::Value = serde_json::json!({
            "schema": "disrobe.pickle.decompile/v0",
            "source": source,
            "graph": trace.result,
        });
        emit_json(&value)
    } else {
        print!("{source}");
        Ok(())
    }
}

fn safety(input: PathBuf, json: bool) -> miette::Result<()> {
    let bytes: Vec<u8> = read_input(&input)?;
    let dis: Disassembly =
        disassemble(&bytes).map_err(|e| miette::miette!("DR-CLI-0666: pickle disasm: {e}"))?;
    let trace: VmTrace =
        execute(&dis).map_err(|e| miette::miette!("DR-CLI-0667: pickle vm: {e}"))?;
    let report: SafetyReport = analyze_safety(&trace);
    if json {
        emit_json(&report)
    } else {
        println!("pickle safety: {:?}", report.severity);
        println!("  imports:      {}", report.imports.len());
        for imp in &report.imports {
            println!("    - {imp}");
        }
        println!("  reduce_count: {}", report.reduce_count);
        println!("  findings:     {}", report.findings.len());
        for f in &report.findings {
            println!("    [{:?}] {}: {}", f.severity, f.category, f.detail);
        }
        Ok(())
    }
}

fn trace(input: PathBuf, json: bool) -> miette::Result<()> {
    let bytes: Vec<u8> = read_input(&input)?;
    let dis: Disassembly =
        disassemble(&bytes).map_err(|e| miette::miette!("DR-CLI-0668: pickle disasm: {e}"))?;
    let trace: VmTrace =
        execute(&dis).map_err(|e| miette::miette!("DR-CLI-0669: pickle vm: {e}"))?;
    if json {
        emit_json(&trace)
    } else {
        println!("pickle trace: protocol {}", trace.protocol);
        println!("  memo_count:      {}", trace.memo_count);
        println!("  max_stack_depth: {}", trace.max_stack_depth);
        println!("  reduce_count:    {}", trace.reduce_count);
        println!("  global_refs:     {}", trace.global_refs.len());
        for g in &trace.global_refs {
            println!("    @{} {}.{}", g.offset, g.module, g.name);
        }
        println!("  unused_memos:    {}", trace.unused_memos.len());
        Ok(())
    }
}

fn polyglot(input: PathBuf, json: bool) -> miette::Result<()> {
    let bytes: Vec<u8> = read_input(&input)?;
    let report: PolyglotReport = analyze_polyglot(&bytes);
    if json {
        emit_json(&report)
    } else {
        println!("pickle polyglot: is_pickle={}", report.is_pickle);
        println!("  is_polyglot: {}", report.is_polyglot);
        println!("  kinds:       {:?}", report.kinds);
        for note in &report.notes {
            println!("    - {note}");
        }
        Ok(())
    }
}

fn ml_detect(input: PathBuf, json: bool) -> miette::Result<()> {
    let bytes: Vec<u8> = read_input(&input)?;
    let report: MlReport =
        extract_ml(&bytes).map_err(|e| miette::miette!("DR-CLI-0670: ml extract: {e}"))?;
    if json {
        emit_json(&report)
    } else {
        println!("pickle ml-detect: {:?}", report.format);
        if let Some(framing) = &report.framing {
            println!("  framing:  {framing}");
        }
        println!("  embedded: {}", report.embedded.len());
        for e in &report.embedded {
            println!(
                "    {} ({} bytes, protocol {:?})",
                e.path, e.length, e.protocol
            );
        }
        Ok(())
    }
}
