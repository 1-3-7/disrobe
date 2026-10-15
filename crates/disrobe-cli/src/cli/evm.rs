use std::path::{Path, PathBuf};

use clap::{Args, Subcommand, ValueEnum};
use disrobe_pass_evm::{
    Disassembly, EvmReport, FunctionReport, InputFormat, Layout, Limits, Metadata, Options, Proxy,
    analyze, decode_input, decompile, disassemble,
};
use serde::Serialize;

use crate::cli::output::{self, OutputFormat};

#[derive(Serialize)]
struct Written<'a> {
    path: String,
    bytes: usize,
    source: &'a str,
}

#[derive(Serialize)]
struct Source<'a> {
    source: &'a str,
}

const MAX_FILE_BYTES: u64 = 2 * disrobe_pass_evm::MAX_CODE_BYTES as u64 + 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum EvmEncoding {
    Auto,
    Hex,
    Raw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum EvmLayout {
    Auto,
    Runtime,
    Creation,
}

#[derive(Debug, Args)]
pub(crate) struct EvmInput {
    #[arg(
        value_name = "BYTECODE",
        help = "file holding EVM bytecode as hex text (0x optional) or raw bytes"
    )]
    path: PathBuf,
    #[arg(long, value_enum, default_value_t = EvmEncoding::Auto, help = "how the file stores the bytecode")]
    encoding: EvmEncoding,
    #[arg(
        long,
        value_enum,
        default_value_t = EvmLayout::Auto,
        help = "auto splits creation bytecode at the CODECOPY/RETURN of its runtime image; runtime or creation forces one reading"
    )]
    layout: EvmLayout,
}

#[derive(Debug, Subcommand)]
pub(crate) enum EvmCmd {
    #[command(
        about = "disassemble legacy EVM bytecode (every opcode through Osaka) into constructor, runtime and metadata sections"
    )]
    Disasm {
        #[command(flatten)]
        input: EvmInput,
        #[arg(
            long,
            help = "also list basic blocks with successors and entry stack heights"
        )]
        blocks: bool,
    },
    #[command(
        about = "recover the contract interface: dispatcher selectors, payable/nonpayable/view/pure, argument types, known signatures, events, custom errors, proxy kind and solc metadata"
    )]
    Inspect {
        #[command(flatten)]
        input: EvmInput,
    },
    #[command(
        about = "emit pseudo-Solidity per dispatched function: storage reads and writes, events, external calls, decoded reverts"
    )]
    Decompile {
        #[command(flatten)]
        input: EvmInput,
        #[arg(
            short,
            long,
            value_name = "FILE",
            help = "write the pseudo-Solidity here instead of stdout"
        )]
        out: Option<PathBuf>,
    },
}

fn load(input: &EvmInput) -> miette::Result<(Vec<u8>, Options)> {
    let path: &Path = &input.path;
    let size: u64 = std::fs::metadata(path)
        .map_err(|e| miette::miette!("DR-CLI-0990: cannot read {}: {e}", path.display()))?
        .len();
    if size > MAX_FILE_BYTES {
        return Err(miette::miette!(
            "DR-CLI-0990: {} is {size} bytes, above the {MAX_FILE_BYTES}-byte limit",
            path.display()
        ));
    }
    let bytes: Vec<u8> = std::fs::read(path)
        .map_err(|e| miette::miette!("DR-CLI-0990: cannot read {}: {e}", path.display()))?;
    let format: InputFormat = match input.encoding {
        EvmEncoding::Auto => InputFormat::Auto,
        EvmEncoding::Hex => InputFormat::Hex,
        EvmEncoding::Raw => InputFormat::Raw,
    };
    let options: Options = Options {
        limits: Limits::default(),
        layout: match input.layout {
            EvmLayout::Auto => Layout::Auto,
            EvmLayout::Runtime => Layout::Runtime,
            EvmLayout::Creation => Layout::Creation,
        },
    };
    let decoded = decode_input(&bytes, format, &options.limits)
        .map_err(|e| miette::miette!("DR-CLI-0991: {}: {e}", path.display()))?;
    Ok((decoded.bytes, options))
}

pub(crate) fn run(action: EvmCmd, fmt: OutputFormat) -> miette::Result<()> {
    match action {
        EvmCmd::Disasm { input, blocks } => {
            let (code, options) = load(&input)?;
            let listing: Disassembly = disassemble(&code, &options)
                .map_err(|e| miette::miette!("DR-CLI-0991: {}: {e}", input.path.display()))?;
            output::emit(fmt, &listing, || render_disasm(&listing, blocks))
        }
        EvmCmd::Inspect { input } => {
            let (code, options) = load(&input)?;
            let report: EvmReport = analyze(&code, &options)
                .map_err(|e| miette::miette!("DR-CLI-0991: {}: {e}", input.path.display()))?;
            output::emit(fmt, &report, || render_report(&report))
        }
        EvmCmd::Decompile { input, out } => {
            let (code, options) = load(&input)?;
            let source: String = decompile(&code, &options)
                .map_err(|e| miette::miette!("DR-CLI-0991: {}: {e}", input.path.display()))?;
            if let Some(path) = out {
                std::fs::write(&path, &source).map_err(|e| {
                    miette::miette!("DR-CLI-0992: cannot write {}: {e}", path.display())
                })?;
                let written: Written<'_> = Written {
                    path: path.display().to_string(),
                    bytes: source.len(),
                    source: &source,
                };
                return output::emit(fmt, &written, || {
                    println!("wrote {} ({} bytes)", path.display(), source.len());
                });
            }
            output::emit(fmt, &Source { source: &source }, || print!("{source}"))
        }
    }
}

fn metadata_line(metadata: &Metadata) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(compiler) = &metadata.compiler {
        parts.push(format!("{} {}", compiler.name, compiler.version));
    }
    if let Some(ipfs) = &metadata.ipfs {
        parts.push(format!("ipfs {ipfs}"));
    }
    if let Some(hash) = &metadata.bzzr0 {
        parts.push(format!("bzzr0 {hash}"));
    }
    if let Some(hash) = &metadata.bzzr1 {
        parts.push(format!("bzzr1 {hash}"));
    }
    if metadata.experimental {
        parts.push("experimental".to_owned());
    }
    format!(
        "{} (CBOR trailer at {:#x}, {} bytes)",
        parts.join(", "),
        metadata.offset,
        metadata.length
    )
}

fn render_disasm(listing: &Disassembly, blocks: bool) {
    for section in &listing.sections {
        println!(
            "; {} at input offset {:#x}, {} bytes",
            section.name, section.offset, section.bytes
        );
        for instruction in &section.instructions {
            match &instruction.immediate {
                Some(value) if instruction.truncated => {
                    println!(
                        "{:#06x}  {} {value} (truncated by the end of code)",
                        instruction.pc, instruction.name
                    );
                }
                Some(value) => println!("{:#06x}  {} {value}", instruction.pc, instruction.name),
                None => println!("{:#06x}  {}", instruction.pc, instruction.name),
            }
        }
    }
    if let Some(metadata) = &listing.metadata {
        println!("; metadata: {}", metadata_line(metadata));
    }
    if blocks {
        println!("; basic blocks");
        for block in &listing.blocks {
            let successors: Vec<String> = block
                .successors
                .iter()
                .map(|pc: &usize| format!("{pc:#x}"))
                .collect();
            let heights: Vec<String> = block.entry_heights.iter().map(u32::to_string).collect();
            println!(
                "{:#06x}..{:#06x} {:?}{} -> [{}] stack in [{}] needs {} delta {}{}",
                block.start,
                block.end,
                block.exit,
                if block.reachable { "" } else { " unreachable" },
                successors.join(", "),
                heights.join(", "),
                block.stack_needed,
                block.stack_delta,
                if block.unresolved_jump {
                    " unresolved jump"
                } else {
                    ""
                }
            );
        }
    }
}

fn proxy_line(proxy: &Proxy) -> String {
    match proxy {
        Proxy::Eip1167 { implementation } => format!("EIP-1167 minimal proxy to {implementation}"),
        Proxy::Eip7511 { implementation } => {
            format!("EIP-7511 minimal proxy (PUSH0) to {implementation}")
        }
        Proxy::StorageSlot { slot, standard } => standard.map_or_else(
            || format!("delegates to the address in storage slot {slot}"),
            |name: &str| format!("delegates to the address in {name} ({slot})"),
        ),
        Proxy::FixedDelegate { implementation } => format!("delegates to {implementation}"),
        Proxy::DynamicDelegate => "delegates to a computed address".to_owned(),
    }
}

fn function_line(function: &FunctionReport) {
    let name: &str = function.signature.unwrap_or("?");
    let interface: String = function
        .interface
        .map(|interface: &str| format!(" [{interface}]"))
        .unwrap_or_default();
    println!(
        "  {} {:<44} {:<10} entry {:#06x}{interface}{}",
        function.selector,
        name,
        function.mutability.name(),
        function.entry,
        if function.complete {
            ""
        } else {
            " (exploration incomplete)"
        }
    );
    let types: Vec<String> = function
        .arguments
        .iter()
        .map(|arg| {
            if arg.basis.decisive() {
                arg.ty.clone()
            } else {
                format!("{}?", arg.ty)
            }
        })
        .collect();
    println!("      arguments: ({})", types.join(", "));
    let list = |label: &str, items: &std::collections::BTreeSet<String>| {
        if !items.is_empty() {
            let shown: Vec<&str> = items.iter().take(8).map(String::as_str).collect();
            let more: String = if items.len() > 8 {
                format!(" and {} more", items.len() - 8)
            } else {
                String::new()
            };
            println!("      {label}: {}{more}", shown.join("; "));
        }
    };
    list("reads", &function.storage_reads);
    list("writes", &function.storage_writes);
    list("events", &function.events);
    list("calls", &function.calls);
    list("reverts", &function.reverts);
}

fn render_report(report: &EvmReport) {
    match report.layout.runtime_offset {
        Some(offset) => println!(
            "evm: creation bytecode, {} bytes: constructor {:#x} bytes, runtime at {offset:#x} ({} bytes), {} bytes after it",
            report.layout.input_bytes,
            offset,
            report.layout.runtime_bytes,
            report.layout.trailing_bytes.unwrap_or(0)
        ),
        None => println!("evm: runtime bytecode, {} bytes", report.layout.input_bytes),
    }
    println!(
        "  runtime:    {} bytes ({} code), {} instructions, keccak256 {}, needs {} or later",
        report.runtime.bytes,
        report.runtime.code_bytes,
        report.runtime.instructions,
        report.runtime.keccak256,
        report.runtime.minimum_fork.name()
    );
    if report.runtime.undefined_opcodes > 0 {
        println!(
            "  undefined:  {} undefined opcode bytes in code",
            report.runtime.undefined_opcodes
        );
    }
    if let Some(metadata) = &report.metadata {
        println!("  metadata:   {}", metadata_line(metadata));
    }
    println!(
        "  cfg:        {} blocks ({} reachable), {} edges, {} JUMPDESTs, max stack {}{}",
        report.cfg.blocks,
        report.cfg.reachable_blocks,
        report.cfg.edges,
        report.cfg.jumpdests,
        report.cfg.max_stack_height,
        if report.cfg.complete {
            ""
        } else {
            ", context limit reached"
        }
    );
    if !report.cfg.unresolved_jumps.is_empty() {
        println!(
            "  unresolved: {} jumps with a computed target",
            report.cfg.unresolved_jumps.len()
        );
    }
    if let Some(proxy) = &report.proxy {
        println!("  proxy:      {}", proxy_line(proxy));
    }
    println!(
        "  dispatcher: {} functions, fallback {}, receive {}{}",
        report.dispatcher.functions,
        if report.dispatcher.fallback {
            "yes"
        } else {
            "no"
        },
        if report.dispatcher.receive {
            "yes"
        } else {
            "no"
        },
        if report.dispatcher.complete {
            ""
        } else {
            " (exploration incomplete)"
        }
    );
    for function in &report.functions {
        function_line(function);
    }
    if report.budget_exhausted {
        println!("  note: the analysis step budget ran out; later functions may be incomplete");
    }
    println!(
        "  argument types ending in ? are not pinned by a mask, sign extension or stride in the code"
    );
}
