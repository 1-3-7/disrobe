use std::io::Write as _;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use disrobe_dart::{
    Error, ObfuscationHint, RecoveryOptions, RecoveryReport, Result, recover_elf,
    recover_standalone,
};

#[derive(Debug, Parser)]
#[command(
    name = "disrobe-dart",
    about = "Recover declarations from Dart AOT snapshots"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    #[arg(long, value_enum, default_value_t = Names::Auto, global = true)]
    names: Names,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "Recover from a libapp.so ELF image")]
    Elf {
        #[arg(value_name = "LIBAPP_SO")]
        input: PathBuf,
    },
    #[command(about = "Recover from four standalone snapshot blobs")]
    Standalone {
        #[arg(value_name = "VM_DATA")]
        vm_data: PathBuf,
        #[arg(value_name = "VM_INSTRUCTIONS")]
        vm_instructions: PathBuf,
        #[arg(value_name = "ISOLATE_DATA")]
        isolate_data: PathBuf,
        #[arg(value_name = "ISOLATE_INSTRUCTIONS")]
        isolate_instructions: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Names {
    Auto,
    Source,
    Opaque,
}

fn main() -> Result<()> {
    let cli: Cli = Cli::parse();
    let options: RecoveryOptions = RecoveryOptions {
        obfuscation_hint: match cli.names {
            Names::Auto => ObfuscationHint::Auto,
            Names::Source => ObfuscationHint::SourceNames,
            Names::Opaque => ObfuscationHint::OpaqueNames,
        },
        ..RecoveryOptions::default()
    };
    let report: RecoveryReport = match cli.command {
        Command::Elf { input } => {
            let bytes: Vec<u8> = read_file(&input)?;
            recover_elf(&bytes, &options)?
        }
        Command::Standalone {
            vm_data,
            vm_instructions,
            isolate_data,
            isolate_instructions,
        } => {
            let vm_data_bytes: Vec<u8> = read_file(&vm_data)?;
            let vm_instruction_bytes: Vec<u8> = read_file(&vm_instructions)?;
            let isolate_data_bytes: Vec<u8> = read_file(&isolate_data)?;
            let isolate_instruction_bytes: Vec<u8> = read_file(&isolate_instructions)?;
            recover_standalone(
                &vm_data_bytes,
                &vm_instruction_bytes,
                &isolate_data_bytes,
                &isolate_instruction_bytes,
                &options,
            )?
        }
    };
    let stdout: std::io::Stdout = std::io::stdout();
    let mut output: std::io::StdoutLock<'_> = stdout.lock();
    serde_json::to_writer_pretty(&mut output, &report)
        .map_err(|error: serde_json::Error| Error::ReportSerialization(error.to_string()))?;
    output
        .write_all(b"\n")
        .map_err(|error: std::io::Error| Error::ReportSerialization(error.to_string()))?;
    Ok(())
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|error: std::io::Error| Error::FileRead {
        path: path.display().to_string(),
        message: error.to_string(),
    })
}
