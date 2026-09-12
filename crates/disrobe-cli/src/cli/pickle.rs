#![allow(clippy::needless_pass_by_value)]
use std::io::Read;
use std::path::PathBuf;

use clap::Subcommand;

use crate::cli::output::OutputFormat;
use crate::cli::sarif::IntoSarif;
use disrobe_pass_pickle::{
    Disassembly, MlReport, PickleValue, PolyglotReport, Reconstruction, SafetyReport, VmTrace,
    analyze_polyglot, analyze_safety, disassemble, execute, execute_full, extract_ml, reconstruct,
    render_disasm, to_python_assignment,
};

const PICKLE_INPUT_MAX_BYTES: u64 = 256 * 1024 * 1024;
const PICKLE_INPUT_PREALLOC: usize = 64 * 1024;

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
        #[arg(
            short,
            long,
            help = "output path for the recovered Python (default: ./out/<stem>.py; '-' input writes ./out/pickle.py)"
        )]
        out: Option<PathBuf>,
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

pub(crate) fn run(action: PickleCmd, fmt: OutputFormat) -> miette::Result<()> {
    match action {
        PickleCmd::Disasm { input, json } => disasm(input, json),
        PickleCmd::Decompile { input, json, out } => decompile(input, json, out),
        PickleCmd::Safety { input, json } => safety(input, json, fmt),
        PickleCmd::Trace { input, json } => trace(input, json),
        PickleCmd::Polyglot { input, json } => polyglot(input, json),
        PickleCmd::MlDetect { input, json } => ml_detect(input, json),
    }
}

fn read_input(input: &PathBuf) -> miette::Result<Vec<u8>> {
    read_input_with_limit(input, PICKLE_INPUT_MAX_BYTES)
}

fn read_input_with_limit(input: &PathBuf, max_bytes: u64) -> miette::Result<Vec<u8>> {
    if input.as_os_str() == "-" {
        let mut stdin: std::io::Stdin = std::io::stdin();
        return read_stream_limited(&mut stdin, max_bytes, "stdin");
    }
    let meta: std::fs::Metadata = std::fs::metadata(input)
        .map_err(|e| miette::miette!("DR-CLI-0661: cannot stat input: {e}"))?;
    if meta.len() > max_bytes {
        return Err(miette::miette!(
            "DR-CLI-0661: input exceeds pickle cap {max_bytes} bytes"
        ));
    }
    let mut file: std::fs::File = std::fs::File::open(input)
        .map_err(|e| miette::miette!("DR-CLI-0661: cannot read input: {e}"))?;
    read_stream_limited(&mut file, max_bytes, "input")
}

fn read_stream_limited<R: Read>(
    reader: &mut R,
    max_bytes: u64,
    label: &'static str,
) -> miette::Result<Vec<u8>> {
    let read_limit: u64 = max_bytes
        .checked_add(1)
        .ok_or_else(|| miette::miette!("DR-CLI-0661: {label} read limit overflow"))?;
    let mut buf: Vec<u8> = Vec::with_capacity(PICKLE_INPUT_PREALLOC);
    reader
        .take(read_limit)
        .read_to_end(&mut buf)
        .map_err(|e| miette::miette!("DR-CLI-0660: cannot read {label}: {e}"))?;
    let actual: u64 = u64::try_from(buf.len()).map_or(u64::MAX, |v: u64| v);
    if actual > max_bytes {
        return Err(miette::miette!(
            "DR-CLI-0661: {label} exceeds pickle cap {max_bytes} bytes"
        ));
    }
    Ok(buf)
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

fn decompile(input: PathBuf, json: bool, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = read_input(&input)?;
    let dis: Disassembly =
        disassemble(&bytes).map_err(|e| miette::miette!("DR-CLI-0664: pickle disasm: {e}"))?;
    let (trace, memo): (VmTrace, std::collections::BTreeMap<u64, PickleValue>) =
        execute_full(&dis).map_err(|e| miette::miette!("DR-CLI-0665: pickle vm: {e}"))?;
    let source: String = to_python_assignment(&trace.result);
    let recovered: Reconstruction = reconstruct(&trace.result, &memo, trace.root_memo_key);
    let stem: String = pickle_stem(&input);
    let out_path: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}.py")));
    let body: String = if recovered.program.ends_with('\n') {
        recovered.program.clone()
    } else {
        format!("{}\n", recovered.program)
    };
    write_text(&out_path, &body)?;
    if json {
        let value: serde_json::Value = serde_json::json!({
            "schema": "disrobe.pickle.decompile/v0",
            "source": source,
            "reconstruction": recovered.program,
            "reexecutable": recovered.reexecutable,
            "unreconstructable": recovered.unsupported,
            "graph": trace.result,
            "out": out_path.display().to_string(),
        });
        emit_json(&value)
    } else {
        print!("{body}");
        eprintln!(
            "pickle decompile: wrote {} (re-executable: {})",
            out_path.display(),
            recovered.reexecutable
        );
        Ok(())
    }
}

fn pickle_stem(input: &std::path::Path) -> String {
    if input.as_os_str() == "-" {
        return "pickle".to_owned();
    }
    input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("pickle")
        .to_owned()
}

fn write_text(out_path: &std::path::Path, body: &str) -> miette::Result<()> {
    if let Some(parent) = out_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0671: cannot create out dir: {e}"))?;
    }
    std::fs::write(out_path, body.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0672: cannot write recovered python: {e}"))
}

fn safety(input: PathBuf, json: bool, fmt: OutputFormat) -> miette::Result<()> {
    let bytes: Vec<u8> = read_input(&input)?;
    let dis: Disassembly =
        disassemble(&bytes).map_err(|e| miette::miette!("DR-CLI-0666: pickle disasm: {e}"))?;
    let trace: VmTrace =
        execute(&dis).map_err(|e| miette::miette!("DR-CLI-0667: pickle vm: {e}"))?;
    let report: SafetyReport = analyze_safety(&trace);
    if matches!(fmt, OutputFormat::Sarif) {
        let uri: String = input.to_string_lossy().into_owned();
        crate::cli::output::emit_sarif_log(&report.to_sarif(&uri))
    } else if json {
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn decompile_writes_real_python_file() {
        let base: PathBuf = std::env::current_dir()
            .expect("cwd")
            .join("tmp")
            .join("pickle-decompile-test");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("mk base");

        let pickle: [u8; 12] = [
            0x80, 0x02, 0x5d, 0x71, 0x00, 0x28, 0x4b, 0x01, 0x4b, 0x02, 0x65, 0x2e,
        ];
        let in_path: PathBuf = base.join("list.pkl");
        std::fs::write(&in_path, pickle).expect("write input");

        let out_path: PathBuf = base.join("recovered.py");
        decompile(in_path, false, Some(out_path.clone())).expect("decompile ok");

        let written: String = std::fs::read_to_string(&out_path).expect("read recovered");
        assert!(written.ends_with('\n'), "must be newline-terminated");
        assert!(
            written.contains('[') && written.contains('1') && written.contains('2'),
            "recovered python must contain the decoded list [1, 2]: got {written:?}"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn read_input_rejects_file_over_cap() {
        let base: PathBuf = std::env::current_dir()
            .expect("cwd")
            .join("tmp")
            .join("pickle-read-cap-test");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("mk base");
        let in_path: PathBuf = base.join("oversize.pkl");
        std::fs::write(&in_path, b"abcd").expect("write input");
        let err: miette::Error = read_input_with_limit(&in_path, 3).expect_err("cap");
        assert!(err.to_string().contains("pickle cap"));
        let _ = std::fs::remove_dir_all(&base);
    }
}
