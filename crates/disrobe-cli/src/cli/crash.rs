use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use disrobe_dataforensics::crash::{
    Access, CrashLimits, CrashReport, Location, ThreadReport, inspect,
};

use crate::cli::output::{self, OutputFormat};

const MAX_CRASH_BYTES: u64 = 8 * 1024 * 1024 * 1024;

pub(crate) fn run(path: PathBuf, registers: bool, fmt: OutputFormat) -> miette::Result<()> {
    let size: u64 = std::fs::metadata(&path)
        .map_err(|e| miette::miette!("DR-CLI-0448: cannot read {}: {e}", path.display()))?
        .len();
    if size > MAX_CRASH_BYTES {
        return Err(miette::miette!(
            "DR-CLI-0448: {} is {size} bytes, above the {MAX_CRASH_BYTES}-byte limit",
            path.display()
        ));
    }
    let bytes: Vec<u8> = std::fs::read(&path)
        .map_err(|e| miette::miette!("DR-CLI-0448: cannot read {}: {e}", path.display()))?;
    let report: CrashReport = inspect(&bytes, &CrashLimits::default())
        .map_err(|e| miette::miette!("DR-CLI-0449: {}: {e}", path.display()))?;
    output::emit(fmt, &report, || render(&report, registers))?;
    Ok(())
}

fn module_name(path: &str) -> &str {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path)
}

fn place(location: Option<&Location>) -> String {
    location.map_or_else(String::new, |location: &Location| {
        format!(" {}+0x{:x}", module_name(&location.module), location.offset)
    })
}

fn render(report: &CrashReport, registers: bool) {
    let system: String = report
        .system
        .as_ref()
        .map(|system| {
            format!(
                ", {} {}.{}.{}{}",
                system.platform,
                system.major,
                system.minor,
                system.build,
                system
                    .service_pack
                    .as_deref()
                    .map(|pack: &str| format!(" {pack}"))
                    .unwrap_or_default()
            )
        })
        .unwrap_or_default();
    println!(
        "crash record: {:?}, {}{}",
        report.format,
        report.architecture.label(),
        system
    );
    let process = &report.process;
    let mut identity: Vec<String> = Vec::new();
    if let Some(pid) = process.pid {
        identity.push(format!("pid {pid}"));
    }
    if let Some(parent) = process.parent_pid {
        identity.push(format!("parent {parent}"));
    }
    if let Some(name) = process.executable.as_deref().or(process.name.as_deref()) {
        identity.push(name.to_owned());
    }
    if !identity.is_empty() {
        println!("process: {}", identity.join(", "));
    }
    if let Some(command_line) = &process.command_line {
        println!("command line: {command_line}");
    }
    if let Some(fault) = &report.fault {
        let mut line: String = format!(
            "fault: {} (0x{:x})",
            fault.name.unwrap_or("unnamed"),
            fault.code
        );
        if let Some(reason) = fault.reason {
            let _ = write!(line, " {reason}");
        }
        if let Some(access) = fault.access {
            let label: &str = match access {
                Access::Read => "read",
                Access::Write => "write",
                Access::Execute => "execute",
            };
            let _ = write!(line, " {label}");
        }
        if let Some(address) = fault.data_address {
            let _ = write!(
                line,
                " at data 0x{address:x}{}",
                place(fault.data_location.as_ref())
            );
        }
        if let Some(address) = fault.instruction_address {
            let _ = write!(
                line,
                " by instruction 0x{address:x}{}",
                place(fault.instruction_location.as_ref())
            );
        }
        if let Some(thread) = fault.thread_id {
            let _ = write!(line, " on thread {thread}");
        }
        if let Some(sender) = fault.sender {
            let _ = write!(line, " sent by pid {} uid {}", sender.pid, sender.uid);
        }
        println!("{line}");
    }
    println!("threads ({}):", report.threads.len());
    for thread in &report.threads {
        render_thread(thread, registers);
    }
    println!("modules ({}):", report.modules.len());
    for module in &report.modules {
        let identity: String = match (&module.build_id, &module.pdb) {
            (Some(build_id), _) => format!(" build-id {build_id}"),
            (None, Some(pdb)) => format!(" pdb {} {}", module_name(&pdb.name), pdb.id),
            (None, None) => String::new(),
        };
        println!(
            "  0x{:x}-0x{:x} {}{identity}",
            module.base,
            module.base.saturating_add(module.size),
            module.path
        );
    }
    println!(
        "memory: {} segments, {} bytes described, {} bytes captured, {} executable",
        report.memory.segments,
        report.memory.described_bytes,
        report.memory.captured_bytes,
        report.memory.executable_segments
    );
    for problem in &report.problems {
        println!("problem: {problem}");
    }
}

fn render_thread(thread: &ThreadReport, registers: bool) {
    let marker: &str = if thread.crashed { "*" } else { " " };
    let name: String = thread
        .name
        .as_deref()
        .map(|name: &str| format!(" \"{name}\""))
        .unwrap_or_default();
    let pointer = |label: &str, value: Option<u64>| -> String {
        value
            .map(|value: u64| format!(" {label}=0x{value:x}"))
            .unwrap_or_default()
    };
    println!(
        " {marker} {}{name}{}{}{}",
        thread.id,
        pointer("ip", thread.instruction_pointer),
        pointer("sp", thread.stack_pointer),
        place(thread.location.as_ref())
    );
    if registers && !thread.registers.is_empty() {
        let line: Vec<String> = thread
            .registers
            .iter()
            .map(|register| format!("{}=0x{:x}", register.name, register.value))
            .collect();
        println!("      {}", line.join(" "));
    }
    for word in &thread.stack_scan {
        println!(
            "      stack 0x{:x}: 0x{:x}{}",
            word.address,
            word.value,
            place(Some(&word.location))
        );
    }
}
