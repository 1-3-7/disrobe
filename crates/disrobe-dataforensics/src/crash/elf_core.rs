use std::collections::BTreeMap;
use std::fmt::Write as _;

use object::elf::{
    DT_DEBUG, DT_NULL, ET_CORE, FileHeader32, FileHeader64, PF_X, PT_DYNAMIC, PT_LOAD, PT_NOTE,
    PT_PHDR,
};
use object::read::elf::{FileHeader, ProgramHeader};
use object::{Endian, Endianness};

use super::memory::{Fields, Memory, ModuleMap, Protection, Segment};
use super::names::{
    AT_BASE_PLATFORM, AT_ENTRY, AT_EXECFN, AT_PHDR, AT_PHNUM, AT_PLATFORM, EM_386, EM_AARCH64,
    EM_ARM, EM_MIPS, EM_RISCV, EM_X86_64, NT_AUXV, NT_FILE, NT_GNU_BUILD_ID, NT_PRPSINFO,
    NT_PRSTATUS, NT_SIGINFO, SIGBUS, SIGFPE, SIGILL, SIGSEGV, SIGTRAP, aux_name,
    generic_signal_numbers, note_name, signal_code_name, signal_name,
};
use super::{
    Architecture, AuxEntry, CrashError, CrashFormat, CrashLimits, CrashReport, Fault, FaultKind,
    ModuleReport, ProcessInfo, Register, Sender, ThreadReport, scan_stack,
};

const MAX_AUX_STRING: usize = 4096;
const BUILD_ID_WINDOW: usize = 64 * 1024;
const MAX_PROGRAM_HEADERS: u64 = 512;
const MAX_DYNAMIC_ENTRIES: u64 = 4096;
const MAX_LINK_MAP_ENTRIES: usize = 4096;
const MAX_LINK_NAME: usize = 4096;

struct RegisterLayout {
    names: &'static [&'static str],
    ip: &'static str,
    sp: &'static str,
    fp: &'static str,
}

const X86_64: RegisterLayout = RegisterLayout {
    names: &[
        "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx",
        "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds",
        "es", "fs", "gs",
    ],
    ip: "rip",
    sp: "rsp",
    fp: "rbp",
};

const X86: RegisterLayout = RegisterLayout {
    names: &[
        "ebx", "ecx", "edx", "esi", "edi", "ebp", "eax", "ds", "es", "fs", "gs", "orig_eax", "eip",
        "cs", "eflags", "esp", "ss",
    ],
    ip: "eip",
    sp: "esp",
    fp: "ebp",
};

const AARCH64: RegisterLayout = RegisterLayout {
    names: &[
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
        "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26",
        "x27", "x28", "x29", "x30", "sp", "pc", "pstate",
    ],
    ip: "pc",
    sp: "sp",
    fp: "x29",
};

const ARM: RegisterLayout = RegisterLayout {
    names: &[
        "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp",
        "lr", "pc", "cpsr", "orig_r0",
    ],
    ip: "pc",
    sp: "sp",
    fp: "r11",
};

const RISCV64: RegisterLayout = RegisterLayout {
    names: &[
        "pc", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
        "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
        "t5", "t6",
    ],
    ip: "pc",
    sp: "sp",
    fp: "s0",
};

const fn register_layout(machine: u16, pointer_bytes: u8) -> Option<&'static RegisterLayout> {
    match (machine, pointer_bytes) {
        (EM_X86_64, 8) => Some(&X86_64),
        (EM_386, 4) => Some(&X86),
        (EM_AARCH64, 8) => Some(&AARCH64),
        (EM_ARM, 4) => Some(&ARM),
        (EM_RISCV, 8) => Some(&RISCV64),
        _ => None,
    }
}

const fn architecture(machine: u16, pointer_bytes: u8) -> Architecture {
    match (machine, pointer_bytes) {
        (EM_386, _) => Architecture::X86,
        (EM_X86_64, _) => Architecture::X86_64,
        (EM_ARM, _) => Architecture::Arm,
        (EM_AARCH64, _) => Architecture::Aarch64,
        (EM_RISCV, 8) => Architecture::Riscv64,
        _ => Architecture::Other,
    }
}

pub(super) fn is_core_header(bytes: &[u8]) -> bool {
    let big_endian: bool = bytes.get(5) == Some(&2);
    Fields::new(bytes, big_endian).u16(16) == Some(ET_CORE)
}

pub(super) fn inspect(bytes: &[u8], limits: &CrashLimits) -> Result<CrashReport, CrashError> {
    match object::FileKind::parse(bytes) {
        Ok(object::FileKind::Elf32) => read::<FileHeader32<Endianness>>(bytes, 4, limits),
        Ok(object::FileKind::Elf64) => read::<FileHeader64<Endianness>>(bytes, 8, limits),
        Ok(other) => Err(CrashError::ElfCore(format!("{other:?} is not an ELF file"))),
        Err(error) => Err(CrashError::ElfCore(error.to_string())),
    }
}

#[derive(Clone, Copy)]
struct Shape {
    machine: u16,
    pointer_bytes: u8,
    big_endian: bool,
}

struct Status {
    tid: u32,
    parent: u32,
    signal: u32,
    registers: Vec<Register>,
}

struct Psinfo {
    pid: u32,
    parent: u32,
    uid: u32,
    gid: u32,
    name: Option<String>,
    arguments: Option<String>,
}

struct Siginfo {
    signal: u32,
    code: i32,
    address: u64,
    sender: Sender,
}

struct Mapping {
    start: u64,
    end: u64,
    file_offset: u64,
    path: String,
}

#[derive(Default)]
struct Notes {
    statuses: Vec<Status>,
    psinfo: Option<Psinfo>,
    siginfo: Option<Siginfo>,
    auxv: Vec<(u64, u64)>,
    mappings: Vec<Mapping>,
    counts: BTreeMap<String, u64>,
    problems: Vec<String>,
}

fn read<Elf: FileHeader<Endian = Endianness>>(
    bytes: &[u8],
    pointer_bytes: u8,
    limits: &CrashLimits,
) -> Result<CrashReport, CrashError> {
    let header: &Elf = Elf::parse(bytes).map_err(|e| CrashError::ElfCore(e.to_string()))?;
    let endian: Endianness = header
        .endian()
        .map_err(|e| CrashError::ElfCore(e.to_string()))?;
    let kind: u16 = header.e_type(endian);
    if kind != ET_CORE {
        return Err(CrashError::ElfCore(format!(
            "e_type {kind} is not ET_CORE ({ET_CORE}); this is an executable or object, not a core"
        )));
    }
    let machine: u16 = header.e_machine(endian);
    let big_endian: bool = endian.is_big_endian();
    let headers: &[Elf::ProgramHeader] = header
        .program_headers(endian, bytes)
        .map_err(|e| CrashError::ElfCore(e.to_string()))?;
    let shape: Shape = Shape {
        machine,
        pointer_bytes,
        big_endian,
    };
    let mut notes: Notes = Notes::default();
    let listed: &[Elf::ProgramHeader] = if headers.len() > limits.segments {
        notes.problems.push(format!(
            "{} program headers; only the first {} are read",
            headers.len(),
            limits.segments
        ));
        &headers[..limits.segments]
    } else {
        headers
    };

    let mut segments: Vec<Segment> = Vec::new();
    let mut protections: Vec<Protection> = Vec::new();
    let mut note_total: usize = 0;
    for program in listed {
        match program.p_type(endian) {
            PT_LOAD => {
                let start: u64 = program.p_vaddr(endian).into();
                let size: u64 = program.p_memsz(endian).into();
                segments.push(Segment {
                    start,
                    size,
                    file_offset: program.p_offset(endian).into(),
                    captured: program.p_filesz(endian).into(),
                });
                protections.push(Protection {
                    start,
                    end: start.saturating_add(size),
                    executable: program.p_flags(endian) & PF_X != 0,
                });
            }
            PT_NOTE if note_total <= limits.notes => match program.notes(endian, bytes) {
                Ok(Some(mut iterator)) => loop {
                    match iterator.next() {
                        Ok(Some(_)) if note_total >= limits.notes => {
                            notes.problems.push(format!(
                                "more than {} notes; the rest are not read",
                                limits.notes
                            ));
                            note_total += 1;
                            break;
                        }
                        Ok(Some(note)) => {
                            note_total += 1;
                            take_note(
                                &mut notes,
                                note.name(),
                                note.n_type(endian),
                                note.desc(),
                                shape,
                                limits,
                            );
                        }
                        Ok(None) => break,
                        Err(error) => {
                            notes.problems.push(format!("note segment: {error}"));
                            break;
                        }
                    }
                },
                Ok(None) => {}
                Err(error) => notes.problems.push(format!("note segment: {error}")),
            },
            _ => {}
        }
    }

    let memory: Memory<'_> = Memory::new(bytes, segments, protections);
    let (mut modules, module_map): (Vec<ModuleReport>, ModuleMap) =
        modules(&notes.mappings, &memory, limits, &mut notes.problems);
    let loaded: Vec<LoadedObject> = loaded_objects(&memory, &notes.auxv, shape);
    name_loaded_modules(&mut modules, &notes.mappings, &loaded);

    let auxv: Vec<AuxEntry> = notes
        .auxv
        .iter()
        .map(|&(key, value): &(u64, u64)| AuxEntry {
            key,
            name: aux_name(key),
            value,
            string: matches!(key, AT_EXECFN | AT_PLATFORM | AT_BASE_PLATFORM)
                .then(|| memory.c_string(value, MAX_AUX_STRING))
                .flatten(),
        })
        .collect();
    let entry: Option<u64> = notes
        .auxv
        .iter()
        .find(|(key, _): &&(u64, u64)| *key == AT_ENTRY)
        .map(|&(_, value): &(u64, u64)| value);
    let execfn: Option<String> = auxv
        .iter()
        .find(|aux: &&AuxEntry| aux.key == AT_EXECFN)
        .and_then(|aux: &AuxEntry| aux.string.clone());

    let layout: Option<&RegisterLayout> = register_layout(machine, pointer_bytes);
    if layout.is_none() && !notes.statuses.is_empty() {
        notes.problems.push(format!(
            "registers of machine {machine} with {pointer_bytes}-byte words are not decoded"
        ));
    }
    let crashed_index: Option<usize> = (notes.siginfo.is_some()
        || notes
            .statuses
            .first()
            .is_some_and(|status: &Status| status.signal != 0))
    .then_some(0);
    let threads: Vec<ThreadReport> = notes
        .statuses
        .iter()
        .enumerate()
        .map(|(index, status): (usize, &Status)| {
            let lookup = |name: &str| -> Option<u64> {
                status
                    .registers
                    .iter()
                    .find(|register: &&Register| register.name == name)
                    .map(|register: &Register| register.value)
            };
            let instruction_pointer: Option<u64> = layout.and_then(|l| lookup(l.ip));
            let stack_pointer: Option<u64> = layout.and_then(|l| lookup(l.sp));
            ThreadReport {
                id: status.tid,
                name: None,
                crashed: crashed_index == Some(index),
                instruction_pointer,
                stack_pointer,
                frame_pointer: layout.and_then(|l| lookup(l.fp)),
                location: instruction_pointer.and_then(|ip: u64| module_map.locate(ip)),
                registers: status.registers.clone(),
                stack: None,
                stack_scan: stack_pointer
                    .map(|sp: u64| {
                        scan_stack(&memory, &module_map, sp, pointer_bytes, big_endian, limits)
                    })
                    .unwrap_or_default(),
            }
        })
        .collect();

    let fault: Option<Fault> = fault(&notes, &threads, machine, &module_map);
    let first: Option<&Status> = notes.statuses.first();
    let process: ProcessInfo = ProcessInfo {
        pid: notes
            .psinfo
            .as_ref()
            .map(|info: &Psinfo| info.pid)
            .or_else(|| first.map(|status: &Status| status.tid)),
        parent_pid: notes
            .psinfo
            .as_ref()
            .map(|info: &Psinfo| info.parent)
            .or_else(|| first.map(|status: &Status| status.parent)),
        uid: notes.psinfo.as_ref().map(|info: &Psinfo| info.uid),
        gid: notes.psinfo.as_ref().map(|info: &Psinfo| info.gid),
        name: notes
            .psinfo
            .as_ref()
            .and_then(|info: &Psinfo| info.name.clone()),
        command_line: notes
            .psinfo
            .as_ref()
            .and_then(|info: &Psinfo| info.arguments.clone()),
        executable: entry
            .and_then(|address: u64| module_map.locate(address))
            .map(|location| location.module)
            .or(execfn),
        start_time_unix: None,
    };

    Ok(CrashReport {
        format: CrashFormat::ElfCore,
        architecture: architecture(machine, pointer_bytes),
        machine: u32::from(machine),
        pointer_bytes,
        big_endian,
        system: None,
        process,
        fault,
        threads,
        modules,
        memory: memory.summary(),
        auxv,
        records: notes.counts,
        problems: notes.problems,
    })
}

fn take_note(
    notes: &mut Notes,
    owner: &[u8],
    kind: u32,
    desc: &[u8],
    shape: Shape,
    limits: &CrashLimits,
) {
    let Shape {
        machine,
        pointer_bytes,
        big_endian,
    } = shape;
    *notes.counts.entry(note_name(owner, kind)).or_insert(0) += 1;
    if owner != b"CORE" {
        return;
    }
    let fields: Fields<'_> = Fields::new(desc, big_endian);
    match kind {
        NT_PRSTATUS => {
            if notes.statuses.len() >= limits.threads {
                if notes.statuses.len() == limits.threads {
                    notes.problems.push(format!(
                        "more than {} threads; the rest are not listed",
                        limits.threads
                    ));
                }
                return;
            }
            match prstatus(fields, machine, pointer_bytes) {
                Some(status) => notes.statuses.push(status),
                None => notes
                    .problems
                    .push(format!("NT_PRSTATUS of {} bytes is too short", desc.len())),
            }
        }
        NT_PRPSINFO if notes.psinfo.is_none() => {
            notes.psinfo = prpsinfo(fields);
            if notes.psinfo.is_none() {
                notes.problems.push(format!(
                    "NT_PRPSINFO of {} bytes matches no known layout",
                    desc.len()
                ));
            }
        }
        NT_SIGINFO if notes.siginfo.is_none() => {
            notes.siginfo = siginfo(fields, machine, pointer_bytes);
        }
        NT_AUXV if notes.auxv.is_empty() => {
            let step: usize = usize::from(pointer_bytes) * 2;
            for at in (0..desc.len()).step_by(step) {
                if notes.auxv.len() >= limits.auxv {
                    break;
                }
                let (Some(key), Some(value)): (Option<u64>, Option<u64>) = (
                    fields.word(at, pointer_bytes),
                    fields.word(at + usize::from(pointer_bytes), pointer_bytes),
                ) else {
                    break;
                };
                if key == 0 {
                    break;
                }
                notes.auxv.push((key, value));
            }
        }
        NT_FILE if notes.mappings.is_empty() => {
            match file_mappings(fields, pointer_bytes, limits) {
                Ok(mappings) => notes.mappings = mappings,
                Err(problem) => notes.problems.push(problem),
            }
        }
        _ => {}
    }
}

fn prstatus(fields: Fields<'_>, machine: u16, pointer_bytes: u8) -> Option<Status> {
    let (pid_at, register_at): (usize, usize) = if pointer_bytes == 8 {
        (32, 112)
    } else {
        (24, 72)
    };
    let signal: u32 = u32::from(fields.u16(12)?);
    let tid: u32 = fields.u32(pid_at)?;
    let parent: u32 = fields.u32(pid_at + 4)?;
    let mut registers: Vec<Register> = Vec::new();
    if let Some(layout) = register_layout(machine, pointer_bytes) {
        let width: usize = usize::from(pointer_bytes);
        for (index, name) in layout.names.iter().enumerate() {
            let value: u64 = fields.word(register_at + index * width, pointer_bytes)?;
            registers.push(Register { name, value });
        }
    }
    Some(Status {
        tid,
        parent,
        signal,
        registers,
    })
}

fn prpsinfo(fields: Fields<'_>) -> Option<Psinfo> {
    let (uid, gid, pid_at, name_at): (u32, u32, usize, usize) = match fields.data.len() {
        136 => (fields.u32(16)?, fields.u32(20)?, 24, 40),
        124 => (
            u32::from(fields.u16(8)?),
            u32::from(fields.u16(10)?),
            12,
            28,
        ),
        128 => (fields.u32(8)?, fields.u32(12)?, 16, 32),
        _ => return None,
    };
    let arguments: Option<String> = fields
        .c_string(name_at + 16, 80)
        .map(|text: String| text.trim_end().to_owned())
        .filter(|text: &String| !text.is_empty());
    Some(Psinfo {
        pid: fields.u32(pid_at)?,
        parent: fields.u32(pid_at + 4)?,
        uid,
        gid,
        name: fields.c_string(name_at, 16),
        arguments,
    })
}

fn siginfo(fields: Fields<'_>, machine: u16, pointer_bytes: u8) -> Option<Siginfo> {
    let code_at: usize = if machine == EM_MIPS { 4 } else { 8 };
    let union_at: usize = if pointer_bytes == 8 { 16 } else { 12 };
    Some(Siginfo {
        signal: fields.u32(0)?,
        code: fields.i32(code_at)?,
        address: fields.word(union_at, pointer_bytes)?,
        sender: Sender {
            pid: fields.i32(union_at)?,
            uid: fields.u32(union_at + 4)?,
        },
    })
}

fn file_mappings(
    fields: Fields<'_>,
    pointer_bytes: u8,
    limits: &CrashLimits,
) -> Result<Vec<Mapping>, String> {
    let width: usize = usize::from(pointer_bytes);
    let truncated = || "NT_FILE is truncated".to_owned();
    let count: u64 = fields.word(0, pointer_bytes).ok_or_else(truncated)?;
    let page_size: u64 = fields.word(width, pointer_bytes).ok_or_else(truncated)?;
    let table_bytes: u64 = count
        .checked_mul(3 * width as u64)
        .ok_or_else(|| format!("NT_FILE count {count} overflows"))?;
    if table_bytes > fields.data.len() as u64 {
        return Err(format!(
            "NT_FILE lists {count} mappings but holds only {} bytes",
            fields.data.len()
        ));
    }
    let count: usize = usize::try_from(count).map_err(|_| truncated())?;
    let names_at: usize = 2 * width + count * 3 * width;
    let mut names = fields
        .data
        .get(names_at..)
        .unwrap_or_default()
        .split(|byte: &u8| *byte == 0);
    let mut mappings: Vec<Mapping> = Vec::with_capacity(count.min(limits.segments));
    for index in 0..count.min(limits.segments) {
        let at: usize = 2 * width + index * 3 * width;
        let start: u64 = fields.word(at, pointer_bytes).ok_or_else(truncated)?;
        let end: u64 = fields
            .word(at + width, pointer_bytes)
            .ok_or_else(truncated)?;
        let page_offset: u64 = fields
            .word(at + 2 * width, pointer_bytes)
            .ok_or_else(truncated)?;
        let path: String = names
            .next()
            .map(|raw: &[u8]| String::from_utf8_lossy(raw).into_owned())
            .ok_or_else(|| format!("NT_FILE name {index} is missing"))?;
        mappings.push(Mapping {
            start,
            end,
            file_offset: page_offset.saturating_mul(page_size),
            path,
        });
    }
    Ok(mappings)
}

fn modules(
    mappings: &[Mapping],
    memory: &Memory<'_>,
    limits: &CrashLimits,
    problems: &mut Vec<String>,
) -> (Vec<ModuleReport>, ModuleMap) {
    let mut order: Vec<&str> = Vec::new();
    let mut spans: BTreeMap<&str, (u64, u64, Option<u64>)> = BTreeMap::new();
    for mapping in mappings {
        let path: &str = mapping.path.as_str();
        let span: &mut (u64, u64, Option<u64>) = spans.entry(path).or_insert_with(|| {
            order.push(path);
            (u64::MAX, 0, None)
        });
        span.0 = span.0.min(mapping.start);
        span.1 = span.1.max(mapping.end);
        if mapping.file_offset == 0 && span.2.is_none() {
            span.2 = Some(mapping.start);
        }
    }
    if order.len() > limits.modules {
        problems.push(format!(
            "{} mapped files; only the first {} are listed",
            order.len(),
            limits.modules
        ));
        order.truncate(limits.modules);
    }
    let mut map: ModuleMap = ModuleMap::default();
    let mut reports: Vec<ModuleReport> = Vec::with_capacity(order.len());
    let mut indices: BTreeMap<&str, usize> = BTreeMap::new();
    for path in order {
        let Some(&(start, end, header)): Option<&(u64, u64, Option<u64>)> = spans.get(path) else {
            continue;
        };
        let base: u64 = header.unwrap_or(start);
        indices.insert(path, map.add_module(path.to_owned(), base));
        reports.push(ModuleReport {
            path: path.to_owned(),
            loader_name: None,
            base,
            size: end.saturating_sub(start),
            build_id: header.and_then(|address: u64| build_id(memory, address)),
            pdb: None,
            timestamp: None,
            checksum: None,
        });
    }
    for mapping in mappings {
        if let Some(&index) = indices.get(mapping.path.as_str()) {
            map.add_range(index, mapping.start, mapping.end);
        }
    }
    map.finish();
    (reports, map)
}

struct LoadedObject {
    name: String,
    dynamic: u64,
}

fn memory_word(memory: &Memory<'_>, address: u64, shape: Shape) -> Option<u64> {
    let bytes: &[u8] = memory.read_up_to(address, usize::from(shape.pointer_bytes))?;
    Fields::new(bytes, shape.big_endian).word(0, shape.pointer_bytes)
}

fn memory_u32(memory: &Memory<'_>, address: u64, big_endian: bool) -> Option<u32> {
    let bytes: &[u8] = memory.read_up_to(address, 4)?;
    Fields::new(bytes, big_endian).u32(0)
}

fn dynamic_section(memory: &Memory<'_>, auxv: &[(u64, u64)], shape: Shape) -> Option<u64> {
    let aux = |wanted: u64| -> Option<u64> {
        auxv.iter()
            .find(|(key, _): &&(u64, u64)| *key == wanted)
            .map(|&(_, value): &(u64, u64)| value)
    };
    let table: u64 = aux(AT_PHDR)?;
    let count: u64 = aux(AT_PHNUM)?.min(MAX_PROGRAM_HEADERS);
    let wide: bool = shape.pointer_bytes == 8;
    let entry_size: u64 = if wide { 56 } else { 32 };
    let vaddr_at: u64 = if wide { 16 } else { 8 };
    let mut phdr_vaddr: Option<u64> = None;
    let mut dynamic_vaddr: Option<u64> = None;
    for index in 0..count {
        let header: u64 = table.checked_add(index.checked_mul(entry_size)?)?;
        let kind: u32 = memory_u32(memory, header, shape.big_endian)?;
        let vaddr: u64 = memory_word(memory, header.checked_add(vaddr_at)?, shape)?;
        match kind {
            PT_PHDR => phdr_vaddr = Some(vaddr),
            PT_DYNAMIC => dynamic_vaddr = Some(vaddr),
            _ => {}
        }
    }
    let bias: u64 = table.wrapping_sub(phdr_vaddr.unwrap_or(table));
    Some(bias.wrapping_add(dynamic_vaddr?))
}

fn loaded_objects(memory: &Memory<'_>, auxv: &[(u64, u64)], shape: Shape) -> Vec<LoadedObject> {
    let step: u64 = u64::from(shape.pointer_bytes);
    let Some(dynamic) = dynamic_section(memory, auxv, shape) else {
        return Vec::new();
    };
    let mut debug: Option<u64> = None;
    for index in 0..MAX_DYNAMIC_ENTRIES {
        let Some(entry) = dynamic.checked_add(index * step * 2) else {
            break;
        };
        let (Some(tag), Some(value)) = (
            memory_word(memory, entry, shape),
            entry
                .checked_add(step)
                .and_then(|at: u64| memory_word(memory, at, shape)),
        ) else {
            break;
        };
        if tag == u64::from(DT_NULL) {
            break;
        }
        if tag == u64::from(DT_DEBUG) {
            debug = Some(value);
            break;
        }
    }
    let Some(mut node) = debug
        .filter(|address: &u64| *address != 0)
        .and_then(|address: u64| memory_word(memory, address.checked_add(step)?, shape))
    else {
        return Vec::new();
    };
    let mut seen: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    let mut objects: Vec<LoadedObject> = Vec::new();
    while node != 0 && objects.len() < MAX_LINK_MAP_ENTRIES && seen.insert(node) {
        let field = |slot: u64| -> Option<u64> {
            memory_word(memory, node.checked_add(slot.checked_mul(step)?)?, shape)
        };
        let (Some(name_address), Some(dynamic), Some(next)) = (field(1), field(2), field(3)) else {
            break;
        };
        let name: String = memory
            .c_string(name_address, MAX_LINK_NAME)
            .unwrap_or_default();
        objects.push(LoadedObject { name, dynamic });
        node = next;
    }
    objects
}

fn name_loaded_modules(
    modules: &mut [ModuleReport],
    mappings: &[Mapping],
    loaded: &[LoadedObject],
) {
    for object in loaded {
        if object.name.is_empty() {
            continue;
        }
        let Some(mapping) = mappings.iter().find(|mapping: &&Mapping| {
            mapping.start <= object.dynamic && object.dynamic < mapping.end
        }) else {
            continue;
        };
        if let Some(module) = modules
            .iter_mut()
            .find(|module: &&mut ModuleReport| module.path == mapping.path)
        {
            module.loader_name = Some(object.name.clone());
        }
    }
}

fn build_id(memory: &Memory<'_>, base: u64) -> Option<String> {
    let image: &[u8] = memory.read_up_to(base, BUILD_ID_WINDOW)?;
    match object::FileKind::parse(image).ok()? {
        object::FileKind::Elf32 => image_build_id::<FileHeader32<Endianness>>(image),
        object::FileKind::Elf64 => image_build_id::<FileHeader64<Endianness>>(image),
        _ => None,
    }
}

fn image_build_id<Elf: FileHeader<Endian = Endianness>>(image: &[u8]) -> Option<String> {
    let header: &Elf = Elf::parse(image).ok()?;
    let endian: Endianness = header.endian().ok()?;
    for program in header.program_headers(endian, image).ok()? {
        if program.p_type(endian) != PT_NOTE {
            continue;
        }
        let Ok(Some(mut notes)) = program.notes(endian, image) else {
            continue;
        };
        while let Ok(Some(note)) = notes.next() {
            if note.name() == b"GNU" && note.n_type(endian) == NT_GNU_BUILD_ID {
                return Some(note.desc().iter().fold(
                    String::new(),
                    |mut out: String, byte: &u8| {
                        let _ = write!(out, "{byte:02x}");
                        out
                    },
                ));
            }
        }
    }
    None
}

fn fault(
    notes: &Notes,
    threads: &[ThreadReport],
    machine: u16,
    modules: &ModuleMap,
) -> Option<Fault> {
    let crashed: Option<&ThreadReport> = threads.first().filter(|thread| thread.crashed);
    let (signal, code): (u32, Option<i32>) = match &notes.siginfo {
        Some(info) => (info.signal, Some(info.code)),
        None => (notes.statuses.first()?.signal, None),
    };
    if signal == 0 {
        return None;
    }
    let named: bool = generic_signal_numbers(machine);
    let mut fault: Fault = Fault {
        kind: FaultKind::Signal,
        code: signal,
        name: named.then(|| signal_name(signal)).flatten(),
        reason: code.and_then(|code: i32| named.then(|| signal_code_name(signal, code)).flatten()),
        thread_id: crashed.map(|thread: &ThreadReport| thread.id),
        instruction_address: crashed.and_then(|thread: &ThreadReport| thread.instruction_pointer),
        instruction_location: None,
        access: None,
        data_address: None,
        data_location: None,
        sender: None,
        parameters: Vec::new(),
    };
    if let Some(info) = &notes.siginfo {
        let user_sent: bool = info.code <= 0;
        if user_sent {
            fault.sender = Some(info.sender);
        } else if named && matches!(signal, SIGSEGV | SIGBUS) {
            fault.data_address = Some(info.address);
            fault.data_location = modules.locate(info.address);
        } else if named && matches!(signal, SIGILL | SIGFPE | SIGTRAP) {
            fault.instruction_address = Some(info.address);
        }
    }
    fault.instruction_location = fault
        .instruction_address
        .and_then(|address: u64| modules.locate(address));
    Some(fault)
}
