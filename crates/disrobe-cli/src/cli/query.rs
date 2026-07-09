use std::path::Path;
use std::path::PathBuf;

use disrobe_ir::Envelope;
use disrobe_ir::payload::DisasmPayload;
use disrobe_pass_native::build_disasm_payload;
use disrobe_query::{
    CallSiteMatch, CapabilitySiteMatch, DecoderMatch, FunctionMatch, Module, Query, QueryResult,
    XrefMatch,
};

use crate::cli::output::{self, OutputFormat};

pub(crate) fn run(input: PathBuf, expr: String, fmt: OutputFormat) -> miette::Result<()> {
    let module: Module = load_module(&input)?;
    let query: Query = disrobe_query::parse_query(&expr)
        .map_err(|e| miette::miette!("DR-CLI-0832: invalid query `{expr}`: {e}"))?;
    let result: QueryResult = disrobe_query::run(&module, &query);
    output::emit(fmt, &result, || render_text(&result))
}

fn load_module(input: &Path) -> miette::Result<Module> {
    let bytes: Vec<u8> = std::fs::read(input)
        .map_err(|e| miette::miette!("DR-CLI-0830: cannot read {}: {e}", input.display()))?;
    if let Ok(env) = Envelope::decode(&bytes) {
        return disrobe_query::module_from_envelope(&env).map_err(|e| {
            miette::miette!(
                "DR-CLI-0831: {} is a .dr envelope but not queryable: {e}",
                input.display()
            )
        });
    }
    let payload: DisasmPayload = build_disasm_payload(&bytes).map_err(|e| {
        miette::miette!(
            "DR-CLI-0833: {} is neither a Disasm- or Mir-rung .dr envelope nor a disassemblable native binary: {e}",
            input.display()
        )
    })?;
    Ok(Module::from_disasm(&payload))
}

fn render_text(result: &QueryResult) {
    match result {
        QueryResult::Functions { matches } => render_functions("functions", matches),
        QueryResult::ComplexityOver { threshold, matches } => {
            println!("functions with cyclomatic complexity > {threshold}:");
            render_functions("", matches);
        }
        QueryResult::CallsTo { target, matches } => render_calls(target, matches),
        QueryResult::XrefsTo { symbol, matches } => render_xrefs(symbol, matches),
        QueryResult::StringDecoders { matches } => render_decoders(matches),
        QueryResult::CapabilitySites {
            capability,
            matches,
        } => render_capability(capability.label(), matches),
    }
}

fn render_functions(header: &str, matches: &[FunctionMatch]) {
    if !header.is_empty() {
        println!("{} ({} match(es)):", header, matches.len());
    }
    if matches.is_empty() {
        println!("  (none)");
        return;
    }
    for m in matches {
        let tag: &str = if m.is_export { " [export]" } else { "" };
        println!(
            "  {:#018x}  {:>4} insn  cc={:<3}  {}{}",
            m.address, m.instruction_count, m.complexity, m.name, tag
        );
    }
}

fn render_calls(target: &str, matches: &[CallSiteMatch]) {
    println!("calls to `{target}` ({} site(s)):", matches.len());
    if matches.is_empty() {
        println!("  (none)");
        return;
    }
    for m in matches {
        println!(
            "  {:#018x}  in {} -> {} ({:#x})",
            m.call_offset, m.caller, m.target, m.target_address
        );
    }
}

fn render_xrefs(symbol: &str, matches: &[XrefMatch]) {
    println!("references to `{symbol}` ({} xref(s)):", matches.len());
    if matches.is_empty() {
        println!("  (none)");
        return;
    }
    for m in matches {
        let from: &str = m.from_function.as_deref().unwrap_or("<unknown>");
        println!(
            "  {:#018x}  {:<8} in {} -> {} ({:#x})",
            m.from_offset, m.mnemonic, from, m.to_symbol, m.to_address
        );
    }
}

fn render_decoders(matches: &[DecoderMatch]) {
    println!(
        "string-decoder-shaped functions ({} match(es)):",
        matches.len()
    );
    if matches.is_empty() {
        println!("  (none)");
        return;
    }
    for m in matches {
        println!(
            "  {:#018x}  {}  (loops={}, byte-arith={}, mem-ops={})",
            m.address, m.name, m.loop_back_edges, m.byte_arith_ops, m.memory_ops
        );
    }
}

fn render_capability(label: &str, matches: &[CapabilitySiteMatch]) {
    println!("{label} capability sites ({} match(es)):", matches.len());
    if matches.is_empty() {
        println!("  (none)");
        return;
    }
    for m in matches {
        let func: &str = m.function.as_deref().unwrap_or("<unknown>");
        println!(
            "  {:#018x}  {:<8} in {} -> {}",
            m.offset, m.mnemonic, func, m.symbol
        );
    }
}
