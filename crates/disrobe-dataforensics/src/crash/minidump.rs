use std::collections::BTreeMap;

use disrobe_binfmt::containers::{
    CvKind, CvRecord, MinidumpFile, MinidumpMemoryRegion, MinidumpModule, StreamDirEntry,
    parse_minidump,
};

use super::memory::{Fields, Memory, ModuleMap, Protection, Segment};
use super::names::{exception_name, platform_name, stream_name};
use super::{
    Access, Architecture, CrashError, CrashFormat, CrashLimits, CrashReport, Fault, FaultKind,
    ModuleReport, Pdb, ProcessInfo, Register, Span, SystemInfo, ThreadReport, scan_stack,
};

const THREAD_LIST: u32 = 3;
const EXCEPTION: u32 = 6;
const SYSTEM_INFO: u32 = 7;
const MISC_INFO: u32 = 15;
const MEMORY_INFO_LIST: u32 = 16;
const THREAD_NAMES: u32 = 24;
const LINUX_CMD_LINE: u32 = 0x4767_0006;

const THREAD_ENTRY: usize = 48;
const THREAD_NAME_ENTRY: usize = 12;
const MEMORY_INFO_ENTRY: u32 = 48;
const MAX_STRING_BYTES: usize = 64 * 1024;
const MAX_COMMAND_LINE: usize = 64 * 1024;
const EXCEPTION_PARAMETERS: usize = 15;
const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC000_0005;
const EXCEPTION_IN_PAGE_ERROR: u32 = 0xC000_0006;
const MEM_COMMIT: u32 = 0x1000;
const PAGE_EXECUTE_ANY: u32 = 0xF0;

const ARCH_X86: u16 = 0;
const ARCH_ARM: u16 = 5;
const ARCH_AMD64: u16 = 9;
const ARCH_ARM64: u16 = 12;

struct ContextLayout {
    registers: &'static [(&'static str, usize, u8)],
    minimum: usize,
    ip: &'static str,
    sp: &'static str,
    fp: &'static str,
}

const AMD64: ContextLayout = ContextLayout {
    registers: &[
        ("rax", 0x78, 8),
        ("rbx", 0x90, 8),
        ("rcx", 0x80, 8),
        ("rdx", 0x88, 8),
        ("rsi", 0xA8, 8),
        ("rdi", 0xB0, 8),
        ("rbp", 0xA0, 8),
        ("rsp", 0x98, 8),
        ("r8", 0xB8, 8),
        ("r9", 0xC0, 8),
        ("r10", 0xC8, 8),
        ("r11", 0xD0, 8),
        ("r12", 0xD8, 8),
        ("r13", 0xE0, 8),
        ("r14", 0xE8, 8),
        ("r15", 0xF0, 8),
        ("rip", 0xF8, 8),
        ("eflags", 0x44, 4),
        ("cs", 0x38, 2),
        ("ds", 0x3A, 2),
        ("es", 0x3C, 2),
        ("fs", 0x3E, 2),
        ("gs", 0x40, 2),
        ("ss", 0x42, 2),
    ],
    minimum: 0x100,
    ip: "rip",
    sp: "rsp",
    fp: "rbp",
};

const X86: ContextLayout = ContextLayout {
    registers: &[
        ("eax", 0xB0, 4),
        ("ebx", 0xA4, 4),
        ("ecx", 0xAC, 4),
        ("edx", 0xA8, 4),
        ("esi", 0xA0, 4),
        ("edi", 0x9C, 4),
        ("ebp", 0xB4, 4),
        ("esp", 0xC4, 4),
        ("eip", 0xB8, 4),
        ("eflags", 0xC0, 4),
        ("cs", 0xBC, 4),
        ("ds", 0x98, 4),
        ("es", 0x94, 4),
        ("fs", 0x90, 4),
        ("gs", 0x8C, 4),
        ("ss", 0xC8, 4),
    ],
    minimum: 0xCC,
    ip: "eip",
    sp: "esp",
    fp: "ebp",
};

const ARM64: ContextLayout = ContextLayout {
    registers: &[
        ("x0", 0x08, 8),
        ("x1", 0x10, 8),
        ("x2", 0x18, 8),
        ("x3", 0x20, 8),
        ("x4", 0x28, 8),
        ("x5", 0x30, 8),
        ("x6", 0x38, 8),
        ("x7", 0x40, 8),
        ("x8", 0x48, 8),
        ("x9", 0x50, 8),
        ("x10", 0x58, 8),
        ("x11", 0x60, 8),
        ("x12", 0x68, 8),
        ("x13", 0x70, 8),
        ("x14", 0x78, 8),
        ("x15", 0x80, 8),
        ("x16", 0x88, 8),
        ("x17", 0x90, 8),
        ("x18", 0x98, 8),
        ("x19", 0xA0, 8),
        ("x20", 0xA8, 8),
        ("x21", 0xB0, 8),
        ("x22", 0xB8, 8),
        ("x23", 0xC0, 8),
        ("x24", 0xC8, 8),
        ("x25", 0xD0, 8),
        ("x26", 0xD8, 8),
        ("x27", 0xE0, 8),
        ("x28", 0xE8, 8),
        ("x29", 0xF0, 8),
        ("x30", 0xF8, 8),
        ("sp", 0x100, 8),
        ("pc", 0x108, 8),
        ("cpsr", 0x04, 4),
    ],
    minimum: 0x110,
    ip: "pc",
    sp: "sp",
    fp: "x29",
};

const fn context_layout(arch: u16) -> Option<&'static ContextLayout> {
    match arch {
        ARCH_AMD64 => Some(&AMD64),
        ARCH_X86 => Some(&X86),
        ARCH_ARM64 => Some(&ARM64),
        _ => None,
    }
}

struct Context {
    registers: Vec<Register>,
    ip: Option<u64>,
    sp: Option<u64>,
    fp: Option<u64>,
}

fn context(bytes: &[u8], arch: u16, size: u32, rva: u32) -> Option<Context> {
    let layout: &ContextLayout = context_layout(arch)?;
    let start: usize = rva as usize;
    let end: usize = start.checked_add(size as usize)?;
    let data: &[u8] = bytes.get(start..end)?;
    if data.len() < layout.minimum {
        return None;
    }
    let fields: Fields<'_> = Fields::new(data, false);
    let mut registers: Vec<Register> = Vec::with_capacity(layout.registers.len());
    for &(name, at, width) in layout.registers {
        let value: u64 = match width {
            8 => fields.u64(at)?,
            4 => u64::from(fields.u32(at)?),
            _ => u64::from(fields.u16(at)?),
        };
        registers.push(Register { name, value });
    }
    let find = |name: &str| -> Option<u64> {
        registers
            .iter()
            .find(|register: &&Register| register.name == name)
            .map(|register: &Register| register.value)
    };
    let (ip, sp, fp): (Option<u64>, Option<u64>, Option<u64>) =
        (find(layout.ip), find(layout.sp), find(layout.fp));
    Some(Context {
        registers,
        ip,
        sp,
        fp,
    })
}

fn stream(file: &MinidumpFile, kind: u32) -> Option<&StreamDirEntry> {
    file.streams
        .iter()
        .find(|entry: &&StreamDirEntry| entry.stream_type == kind)
}

fn stream_bytes<'a>(bytes: &'a [u8], entry: &StreamDirEntry) -> Option<&'a [u8]> {
    let start: usize = entry.rva as usize;
    bytes.get(start..start.checked_add(entry.data_size as usize)?)
}

fn utf16_string(bytes: &[u8], rva: u64) -> Option<String> {
    let start: usize = usize::try_from(rva).ok()?;
    let fields: Fields<'_> = Fields::new(bytes, false);
    let length: usize = fields.u32(start)? as usize;
    if length > MAX_STRING_BYTES {
        return None;
    }
    let body: &[u8] = bytes.get(start.checked_add(4)?..start.checked_add(4 + length)?)?;
    let units = body
        .chunks_exact(2)
        .map(|pair: &[u8]| u16::from_le_bytes([pair[0], pair[1]]));
    let text: String = char::decode_utf16(units)
        .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
    Some(text.trim_end_matches('\0').to_owned())
}

struct RawThread {
    id: u32,
    stack: Span,
    context_size: u32,
    context_rva: u32,
}

fn threads(
    bytes: &[u8],
    entry: &StreamDirEntry,
    limits: &CrashLimits,
    problems: &mut Vec<String>,
) -> Vec<RawThread> {
    let Some(data): Option<&[u8]> = stream_bytes(bytes, entry) else {
        return Vec::new();
    };
    let fields: Fields<'_> = Fields::new(data, false);
    let Some(count): Option<u32> = fields.u32(0) else {
        problems.push("ThreadListStream is truncated".to_owned());
        return Vec::new();
    };
    let count: usize = count as usize;
    let padded: bool = count
        .checked_mul(THREAD_ENTRY)
        .and_then(|n| n.checked_add(8))
        == Some(data.len());
    let first: usize = if padded { 8 } else { 4 };
    let listed: usize = count.min(limits.threads);
    if listed < count {
        problems.push(format!(
            "{count} threads; only the first {} are listed",
            limits.threads
        ));
    }
    let mut out: Vec<RawThread> = Vec::with_capacity(listed.min(4096));
    for index in 0..listed {
        let at: usize = first + index * THREAD_ENTRY;
        let (Some(id), Some(stack_start), Some(stack_size), Some(context_size), Some(context_rva)) = (
            fields.u32(at),
            fields.u64(at + 24),
            fields.u32(at + 32),
            fields.u32(at + 40),
            fields.u32(at + 44),
        ) else {
            problems.push(format!(
                "ThreadListStream holds {index} of its {count} threads"
            ));
            break;
        };
        out.push(RawThread {
            id,
            stack: Span {
                start: stack_start,
                size: u64::from(stack_size),
            },
            context_size,
            context_rva,
        });
    }
    out
}

fn thread_names(
    bytes: &[u8],
    entry: &StreamDirEntry,
    limits: &CrashLimits,
) -> BTreeMap<u32, String> {
    let mut names: BTreeMap<u32, String> = BTreeMap::new();
    let Some(data): Option<&[u8]> = stream_bytes(bytes, entry) else {
        return names;
    };
    let fields: Fields<'_> = Fields::new(data, false);
    let count: usize = fields.u32(0).map_or(0, |count: u32| count as usize);
    for index in 0..count.min(limits.threads) {
        let at: usize = 4 + index * THREAD_NAME_ENTRY;
        let (Some(id), Some(rva)) = (fields.u32(at), fields.u64(at + 4)) else {
            break;
        };
        if let Some(name) = utf16_string(bytes, rva).filter(|name: &String| !name.is_empty()) {
            names.insert(id, name);
        }
    }
    names
}

fn protections(
    bytes: &[u8],
    entry: &StreamDirEntry,
    limits: &CrashLimits,
    problems: &mut Vec<String>,
) -> Vec<Protection> {
    let mut out: Vec<Protection> = Vec::new();
    let Some(data): Option<&[u8]> = stream_bytes(bytes, entry) else {
        return out;
    };
    let fields: Fields<'_> = Fields::new(data, false);
    let (Some(header), Some(entry_size), Some(count)) =
        (fields.u32(0), fields.u32(4), fields.u64(8))
    else {
        problems.push("MemoryInfoListStream is truncated".to_owned());
        return out;
    };
    if entry_size < MEMORY_INFO_ENTRY {
        problems.push(format!(
            "MemoryInfoListStream entries of {entry_size} bytes are shorter than {MEMORY_INFO_ENTRY}"
        ));
        return out;
    }
    let listed: usize = usize::try_from(count)
        .unwrap_or(usize::MAX)
        .min(limits.segments);
    for index in 0..listed {
        let Some(at): Option<usize> = (index as u64)
            .checked_mul(u64::from(entry_size))
            .and_then(|offset: u64| offset.checked_add(u64::from(header)))
            .and_then(|offset: u64| usize::try_from(offset).ok())
        else {
            break;
        };
        let (Some(base), Some(size), Some(state), Some(protect)) = (
            fields.u64(at),
            fields.u64(at + 24),
            fields.u32(at + 32),
            fields.u32(at + 36),
        ) else {
            break;
        };
        if state == MEM_COMMIT {
            out.push(Protection {
                start: base,
                end: base.saturating_add(size),
                executable: protect & PAGE_EXECUTE_ANY != 0,
            });
        }
    }
    out
}

fn pdb(record: &CvRecord) -> Pdb {
    let id: String = match record.kind {
        CvKind::Pdb70 => record.debug_identifier(),
        CvKind::Pdb20 => {
            let signature: u32 = u32::from_le_bytes([
                record.guid[0],
                record.guid[1],
                record.guid[2],
                record.guid[3],
            ]);
            format!("{signature:08X}{:X}", record.age)
        }
    };
    Pdb {
        name: record.pdb_path.clone(),
        id,
    }
}

fn system(bytes: &[u8], entry: &StreamDirEntry) -> Option<(u16, SystemInfo)> {
    let fields: Fields<'_> = Fields::new(stream_bytes(bytes, entry)?, false);
    let arch: u16 = fields.u16(0)?;
    let csd_rva: u32 = fields.u32(24)?;
    let service_pack: Option<String> = (csd_rva != 0)
        .then(|| utf16_string(bytes, u64::from(csd_rva)))
        .flatten()
        .filter(|text: &String| !text.is_empty());
    Some((
        arch,
        SystemInfo {
            platform: platform_name(fields.u32(20)?).to_owned(),
            major: fields.u32(8)?,
            minor: fields.u32(12)?,
            build: fields.u32(16)?,
            service_pack,
            processors: *fields.data.get(6)?,
        },
    ))
}

const fn architecture(arch: u16) -> (Architecture, u8) {
    match arch {
        ARCH_X86 => (Architecture::X86, 4),
        ARCH_AMD64 => (Architecture::X86_64, 8),
        ARCH_ARM => (Architecture::Arm, 4),
        ARCH_ARM64 => (Architecture::Aarch64, 8),
        _ => (Architecture::Other, 0),
    }
}

struct Exception {
    thread_id: u32,
    code: u32,
    flags: u32,
    address: u64,
    parameters: Vec<u64>,
    context_size: u32,
    context_rva: u32,
}

fn exception(bytes: &[u8], entry: &StreamDirEntry) -> Option<Exception> {
    let fields: Fields<'_> = Fields::new(stream_bytes(bytes, entry)?, false);
    let count: usize = (fields.u32(32)? as usize).min(EXCEPTION_PARAMETERS);
    let parameters: Vec<u64> = (0..count)
        .map(|index: usize| fields.u64(40 + index * 8))
        .collect::<Option<Vec<u64>>>()?;
    Some(Exception {
        thread_id: fields.u32(0)?,
        code: fields.u32(8)?,
        flags: fields.u32(12)?,
        address: fields.u64(24)?,
        parameters,
        context_size: fields.u32(160)?,
        context_rva: fields.u32(164)?,
    })
}

fn misc(bytes: &[u8], entry: &StreamDirEntry) -> (Option<u32>, Option<u32>) {
    let Some(data): Option<&[u8]> = stream_bytes(bytes, entry) else {
        return (None, None);
    };
    let fields: Fields<'_> = Fields::new(data, false);
    let flags: u32 = fields.u32(4).unwrap_or(0);
    (
        (flags & 1 != 0).then(|| fields.u32(8)).flatten(),
        (flags & 2 != 0).then(|| fields.u32(12)).flatten(),
    )
}

fn command_line(bytes: &[u8], entry: &StreamDirEntry) -> Option<String> {
    let data: &[u8] = stream_bytes(bytes, entry)?;
    let data: &[u8] = data.get(..data.len().min(MAX_COMMAND_LINE))?;
    let text: String = data
        .split(|byte: &u8| *byte == 0)
        .filter(|part: &&[u8]| !part.is_empty())
        .map(|part: &[u8]| String::from_utf8_lossy(part).into_owned())
        .collect::<Vec<String>>()
        .join(" ");
    (!text.is_empty()).then_some(text)
}

pub(super) fn inspect(bytes: &[u8], limits: &CrashLimits) -> Result<CrashReport, CrashError> {
    let file: MinidumpFile =
        parse_minidump(bytes).map_err(|error| CrashError::Minidump(error.to_string()))?;
    let mut problems: Vec<String> = file.notes.clone();
    let mut records: BTreeMap<String, u64> = BTreeMap::new();
    for entry in &file.streams {
        if entry.stream_type != 0 {
            *records.entry(stream_name(entry.stream_type)).or_insert(0) += 1;
        }
    }

    let (arch, system): (Option<u16>, Option<SystemInfo>) = if let Some((arch, info)) =
        stream(&file, SYSTEM_INFO).and_then(|entry| system(bytes, entry))
    {
        (Some(arch), Some(info))
    } else {
        problems.push("no readable SystemInfoStream; registers are not decoded".to_owned());
        (None, None)
    };
    let (architecture, pointer_bytes): (Architecture, u8) =
        arch.map_or((Architecture::Other, 0), architecture);
    if let Some(arch) = arch
        && context_layout(arch).is_none()
    {
        problems.push(format!(
            "thread contexts of processor architecture {arch} are not decoded"
        ));
    }

    let segments: Vec<Segment> = file
        .memory_regions
        .iter()
        .take(limits.segments)
        .map(|region: &MinidumpMemoryRegion| Segment {
            start: region.start_va,
            size: region.data_size,
            file_offset: region.file_offset,
            captured: region.file_available,
        })
        .collect();
    let protections: Vec<Protection> = stream(&file, MEMORY_INFO_LIST)
        .map(|entry| protections(bytes, entry, limits, &mut problems))
        .unwrap_or_default();
    let memory: Memory<'_> = Memory::new(bytes, segments, protections);

    let mut module_map: ModuleMap = ModuleMap::default();
    let listed_modules: &[MinidumpModule] = &file.modules[..file.modules.len().min(limits.modules)];
    if listed_modules.len() < file.modules.len() {
        problems.push(format!(
            "{} modules; only the first {} are listed",
            file.modules.len(),
            limits.modules
        ));
    }
    let modules: Vec<ModuleReport> = listed_modules
        .iter()
        .map(|module: &MinidumpModule| {
            let size: u64 = u64::from(module.size_of_image);
            let index: usize = module_map.add_module(module.name.clone(), module.base_of_image);
            module_map.add_range(
                index,
                module.base_of_image,
                module.base_of_image.saturating_add(size),
            );
            ModuleReport {
                path: module.name.clone(),
                base: module.base_of_image,
                size,
                build_id: None,
                pdb: module.cv_record.as_ref().map(pdb),
                timestamp: Some(module.timestamp),
                checksum: Some(module.checksum),
            }
        })
        .collect();
    module_map.finish();

    let names: BTreeMap<u32, String> = stream(&file, THREAD_NAMES)
        .map(|entry| thread_names(bytes, entry, limits))
        .unwrap_or_default();
    let exception: Option<Exception> = stream(&file, EXCEPTION).and_then(|entry| {
        let parsed: Option<Exception> = exception(bytes, entry);
        if parsed.is_none() {
            problems.push("ExceptionStream is truncated".to_owned());
        }
        parsed
    });
    let raw_threads: Vec<RawThread> = stream(&file, THREAD_LIST)
        .map(|entry| threads(bytes, entry, limits, &mut problems))
        .unwrap_or_default();

    let threads: Vec<ThreadReport> = raw_threads
        .iter()
        .map(|raw: &RawThread| {
            let crashed: bool = exception
                .as_ref()
                .is_some_and(|exception: &Exception| exception.thread_id == raw.id);
            let decoded: Option<Context> = arch.and_then(|arch: u16| {
                let from_exception: Option<Context> = exception
                    .as_ref()
                    .filter(|_| crashed)
                    .and_then(|exception: &Exception| {
                        context(bytes, arch, exception.context_size, exception.context_rva)
                    });
                from_exception.or_else(|| context(bytes, arch, raw.context_size, raw.context_rva))
            });
            let (registers, ip, sp, fp): (Vec<Register>, Option<u64>, Option<u64>, Option<u64>) =
                match decoded {
                    Some(context) => (context.registers, context.ip, context.sp, context.fp),
                    None => (Vec::new(), None, None, None),
                };
            ThreadReport {
                id: raw.id,
                name: names.get(&raw.id).cloned(),
                crashed,
                instruction_pointer: ip,
                stack_pointer: sp,
                frame_pointer: fp,
                location: ip.and_then(|address: u64| module_map.locate(address)),
                registers,
                stack: Some(raw.stack),
                stack_scan: sp
                    .map(|address: u64| {
                        scan_stack(&memory, &module_map, address, pointer_bytes, false, limits)
                    })
                    .unwrap_or_default(),
            }
        })
        .collect();

    let fault: Option<Fault> = exception.as_ref().map(|exception: &Exception| {
        let (access, data_address): (Option<Access>, Option<u64>) = if matches!(
            exception.code,
            EXCEPTION_ACCESS_VIOLATION | EXCEPTION_IN_PAGE_ERROR
        ) {
            let access: Option<Access> = match exception.parameters.first().copied() {
                Some(0) => Some(Access::Read),
                Some(1) => Some(Access::Write),
                Some(8) => Some(Access::Execute),
                _ => None,
            };
            (access, exception.parameters.get(1).copied())
        } else {
            (None, None)
        };
        Fault {
            kind: FaultKind::Exception,
            code: exception.code,
            name: exception_name(exception.code),
            reason: (exception.flags & 1 != 0).then_some("EXCEPTION_NONCONTINUABLE"),
            thread_id: Some(exception.thread_id),
            instruction_address: Some(exception.address),
            instruction_location: module_map.locate(exception.address),
            access,
            data_address,
            data_location: data_address.and_then(|address: u64| module_map.locate(address)),
            sender: None,
            parameters: exception.parameters.clone(),
        }
    });

    let (pid, start_time_unix): (Option<u32>, Option<u32>) =
        stream(&file, MISC_INFO).map_or((None, None), |entry| misc(bytes, entry));
    let process: ProcessInfo = ProcessInfo {
        pid,
        command_line: stream(&file, LINUX_CMD_LINE).and_then(|entry| command_line(bytes, entry)),
        executable: file
            .modules
            .first()
            .map(|module: &MinidumpModule| module.name.clone()),
        start_time_unix,
        ..ProcessInfo::default()
    };

    Ok(CrashReport {
        format: CrashFormat::Minidump,
        architecture,
        machine: u32::from(arch.unwrap_or(u16::MAX)),
        pointer_bytes,
        big_endian: false,
        system,
        process,
        fault,
        threads,
        modules,
        memory: memory.summary(),
        auxv: Vec::new(),
        records,
        problems,
    })
}
