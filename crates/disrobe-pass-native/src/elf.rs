use serde::{Deserialize, Serialize};

const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;

const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_PLTRELSZ: u64 = 2;
const DT_HASH: u64 = 4;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_RELAENT: u64 = 9;
const DT_STRSZ: u64 = 10;
const DT_SYMENT: u64 = 11;
const DT_INIT: u64 = 12;
const DT_FINI: u64 = 13;
const DT_SONAME: u64 = 14;
const DT_RPATH: u64 = 15;
const DT_REL: u64 = 17;
const DT_RELSZ: u64 = 18;
const DT_RELENT: u64 = 19;
const DT_PLTREL: u64 = 20;
const DT_JMPREL: u64 = 23;
const DT_INIT_ARRAY: u64 = 25;
const DT_FINI_ARRAY: u64 = 26;
const DT_INIT_ARRAYSZ: u64 = 27;
const DT_FINI_ARRAYSZ: u64 = 28;
const DT_RUNPATH: u64 = 29;
const DT_GNU_HASH: u64 = 0x6fff_fef5;

const DT_PLTREL_RELA: u64 = 7;

const MAX_DYNAMIC_ENTRIES: usize = 16 * 1024;
const MAX_NEEDED: usize = 4096;
const MAX_SYMBOLS: usize = 256 * 1024;
const MAX_RELOCATIONS: usize = 512 * 1024;
const MAX_STRING_BYTES: usize = 64 * 1024;
const MAX_GNU_HASH_BUCKETS: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ElfClass {
    Elf32,
    Elf64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ElfData {
    Little,
    Big,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentMapping {
    pub kind: String,
    pub file_offset: u64,
    pub file_size: u64,
    pub virtual_addr: u64,
    pub mem_size: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub align: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SymbolBind {
    Local,
    Global,
    Weak,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SymbolType {
    NoType,
    Object,
    Func,
    Section,
    File,
    Common,
    Tls,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicSymbol {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub bind: SymbolBind,
    pub sym_type: SymbolType,
    pub defined: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relocation {
    pub offset: u64,
    pub r_type: u32,
    pub symbol_index: u32,
    pub addend: i64,
    pub symbol_name: Option<String>,
    pub source: RelocSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RelocSource {
    Rela,
    Rel,
    JmpRel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SymbolCountSource {
    GnuHash,
    SysvHash,
    BoundedScan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElfDynamicReport {
    pub class: ElfClass,
    pub data: ElfData,
    pub entry: u64,
    pub segments: Vec<SegmentMapping>,
    pub interpreter: Option<String>,
    pub needed: Vec<String>,
    pub soname: Option<String>,
    pub rpath: Option<String>,
    pub runpath: Option<String>,
    pub init: Option<u64>,
    pub fini: Option<u64>,
    pub init_array: Vec<u64>,
    pub fini_array: Vec<u64>,
    pub dynamic_entry_count: usize,
    pub symbol_count_source: Option<SymbolCountSource>,
    pub symbols: Vec<DynamicSymbol>,
    pub relocations: Vec<Relocation>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct Endian {
    little: bool,
}

impl Endian {
    fn u16(self, b: &[u8]) -> Option<u16> {
        let raw: [u8; 2] = b.get(..2)?.try_into().ok()?;
        Some(if self.little {
            u16::from_le_bytes(raw)
        } else {
            u16::from_be_bytes(raw)
        })
    }

    fn u32(self, b: &[u8]) -> Option<u32> {
        let raw: [u8; 4] = b.get(..4)?.try_into().ok()?;
        Some(if self.little {
            u32::from_le_bytes(raw)
        } else {
            u32::from_be_bytes(raw)
        })
    }

    fn u64(self, b: &[u8]) -> Option<u64> {
        let raw: [u8; 8] = b.get(..8)?.try_into().ok()?;
        Some(if self.little {
            u64::from_le_bytes(raw)
        } else {
            u64::from_be_bytes(raw)
        })
    }
}

fn read_slice(bytes: &[u8], off: usize, len: usize) -> Option<&[u8]> {
    bytes.get(off..off.checked_add(len)?)
}

#[derive(Debug, Clone, Copy)]
struct Header {
    class: ElfClass,
    endian: Endian,
    entry: u64,
    phoff: u64,
    phentsize: u16,
    phnum: u16,
}

#[derive(Debug, Clone, Copy)]
struct ProgramHeader {
    p_type: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

#[must_use]
pub fn analyze(bytes: &[u8]) -> Option<ElfDynamicReport> {
    let header: Header = parse_header(bytes)?;
    let segments: Vec<ProgramHeader> = parse_program_headers(bytes, &header);
    let mut report: ElfDynamicReport = ElfDynamicReport {
        class: header.class,
        data: if header.endian.little {
            ElfData::Little
        } else {
            ElfData::Big
        },
        entry: header.entry,
        segments: segments.iter().map(segment_mapping).collect(),
        interpreter: None,
        needed: Vec::new(),
        soname: None,
        rpath: None,
        runpath: None,
        init: None,
        fini: None,
        init_array: Vec::new(),
        fini_array: Vec::new(),
        dynamic_entry_count: 0,
        symbol_count_source: None,
        symbols: Vec::new(),
        relocations: Vec::new(),
        notes: Vec::new(),
    };

    report.interpreter = read_interpreter(bytes, &segments);

    let Some(dynamic): Option<ProgramHeader> = segments
        .iter()
        .copied()
        .find(|p: &ProgramHeader| p.p_type == PT_DYNAMIC)
    else {
        report
            .notes
            .push("no PT_DYNAMIC segment (static or relocatable object)".to_owned());
        return Some(report);
    };

    let entries: Vec<(u64, u64)> = read_dynamic_entries(bytes, &header, &segments, &dynamic);
    report.dynamic_entry_count = entries.len();

    let strtab_va: Option<u64> = lookup(&entries, DT_STRTAB);
    let strsz: u64 = lookup(&entries, DT_STRSZ).unwrap_or(0);

    for &(tag, value) in &entries {
        match tag {
            DT_NEEDED => {
                if report.needed.len() >= MAX_NEEDED {
                    continue;
                }
                if let Some(name) = resolve_dynstr(bytes, &segments, strtab_va, strsz, value) {
                    report.needed.push(name);
                }
            }
            DT_SONAME => {
                if let Some(name) = resolve_dynstr(bytes, &segments, strtab_va, strsz, value) {
                    report.soname = Some(name);
                }
            }
            DT_RPATH => {
                if let Some(name) = resolve_dynstr(bytes, &segments, strtab_va, strsz, value) {
                    report.rpath = Some(name);
                }
            }
            DT_RUNPATH => {
                if let Some(name) = resolve_dynstr(bytes, &segments, strtab_va, strsz, value) {
                    report.runpath = Some(name);
                }
            }
            DT_INIT => report.init = Some(value),
            DT_FINI => report.fini = Some(value),
            _ => {}
        }
    }

    report.init_array = read_pointer_array(
        bytes,
        &header,
        &segments,
        lookup(&entries, DT_INIT_ARRAY),
        lookup(&entries, DT_INIT_ARRAYSZ),
    );
    report.fini_array = read_pointer_array(
        bytes,
        &header,
        &segments,
        lookup(&entries, DT_FINI_ARRAY),
        lookup(&entries, DT_FINI_ARRAYSZ),
    );

    let symtab_va: Option<u64> = lookup(&entries, DT_SYMTAB);
    let syment: u64 = lookup(&entries, DT_SYMENT).unwrap_or_else(|| default_syment(header.class));
    if let (Some(symtab), Some(strtab)) = (symtab_va, strtab_va) {
        let (count, source): (usize, SymbolCountSource) =
            recover_symbol_count(bytes, &header, &segments, &entries, symtab, syment);
        report.symbol_count_source = Some(source);
        report.symbols = read_dynamic_symbols(
            bytes, &header, &segments, symtab, syment, strtab, strsz, count,
        );
    }

    let symbol_names: Vec<Option<String>> = report
        .symbols
        .iter()
        .map(|s: &DynamicSymbol| {
            if s.name.is_empty() {
                None
            } else {
                Some(s.name.clone())
            }
        })
        .collect();

    report.relocations = read_all_relocations(bytes, &header, &segments, &entries, &symbol_names);

    Some(report)
}

fn parse_header(bytes: &[u8]) -> Option<Header> {
    if bytes.get(..4)? != ELF_MAGIC {
        return None;
    }
    let class: ElfClass = match *bytes.get(EI_CLASS)? {
        ELFCLASS32 => ElfClass::Elf32,
        ELFCLASS64 => ElfClass::Elf64,
        _ => return None,
    };
    let endian: Endian = match *bytes.get(EI_DATA)? {
        ELFDATA2LSB => Endian { little: true },
        ELFDATA2MSB => Endian { little: false },
        _ => return None,
    };
    match class {
        ElfClass::Elf64 => {
            if bytes.len() < 64 {
                return None;
            }
            Some(Header {
                class,
                endian,
                entry: endian.u64(&bytes[24..])?,
                phoff: endian.u64(&bytes[32..])?,
                phentsize: endian.u16(&bytes[54..])?,
                phnum: endian.u16(&bytes[56..])?,
            })
        }
        ElfClass::Elf32 => {
            if bytes.len() < 52 {
                return None;
            }
            Some(Header {
                class,
                endian,
                entry: u64::from(endian.u32(&bytes[24..])?),
                phoff: u64::from(endian.u32(&bytes[28..])?),
                phentsize: endian.u16(&bytes[42..])?,
                phnum: endian.u16(&bytes[44..])?,
            })
        }
    }
}

fn parse_program_headers(bytes: &[u8], header: &Header) -> Vec<ProgramHeader> {
    let mut out: Vec<ProgramHeader> = Vec::new();
    let entsize: usize = usize::from(header.phentsize);
    let min_entsize: usize = match header.class {
        ElfClass::Elf64 => 56,
        ElfClass::Elf32 => 32,
    };
    if entsize < min_entsize {
        return out;
    }
    let phoff: usize = match usize::try_from(header.phoff) {
        Ok(value) => value,
        Err(_) => return out,
    };
    for i in 0..usize::from(header.phnum) {
        let base: usize = match phoff.checked_add(i.saturating_mul(entsize)) {
            Some(value) => value,
            None => break,
        };
        let Some(slice): Option<&[u8]> = read_slice(bytes, base, entsize) else {
            break;
        };
        let Some(ph): Option<ProgramHeader> = parse_one_program_header(slice, header) else {
            break;
        };
        out.push(ph);
    }
    out
}

fn parse_one_program_header(slice: &[u8], header: &Header) -> Option<ProgramHeader> {
    let e: Endian = header.endian;
    match header.class {
        ElfClass::Elf64 => Some(ProgramHeader {
            p_type: e.u32(&slice[0..])?,
            flags: e.u32(&slice[4..])?,
            offset: e.u64(&slice[8..])?,
            vaddr: e.u64(&slice[16..])?,
            filesz: e.u64(&slice[32..])?,
            memsz: e.u64(&slice[40..])?,
            align: e.u64(&slice[48..])?,
        }),
        ElfClass::Elf32 => Some(ProgramHeader {
            p_type: e.u32(&slice[0..])?,
            offset: u64::from(e.u32(&slice[4..])?),
            vaddr: u64::from(e.u32(&slice[8..])?),
            filesz: u64::from(e.u32(&slice[16..])?),
            memsz: u64::from(e.u32(&slice[20..])?),
            flags: e.u32(&slice[24..])?,
            align: u64::from(e.u32(&slice[28..])?),
        }),
    }
}

fn segment_mapping(ph: &ProgramHeader) -> SegmentMapping {
    SegmentMapping {
        kind: segment_kind_label(ph.p_type).to_owned(),
        file_offset: ph.offset,
        file_size: ph.filesz,
        virtual_addr: ph.vaddr,
        mem_size: ph.memsz,
        readable: ph.flags & 0x4 != 0,
        writable: ph.flags & 0x2 != 0,
        executable: ph.flags & 0x1 != 0,
        align: ph.align,
    }
}

fn segment_kind_label(p_type: u32) -> &'static str {
    match p_type {
        0 => "null",
        PT_LOAD => "load",
        PT_DYNAMIC => "dynamic",
        PT_INTERP => "interp",
        4 => "note",
        6 => "phdr",
        7 => "tls",
        0x6474_e550 => "gnu-eh-frame",
        0x6474_e551 => "gnu-stack",
        0x6474_e552 => "gnu-relro",
        0x6474_e553 => "gnu-property",
        _ => "other",
    }
}

fn read_interpreter(bytes: &[u8], segments: &[ProgramHeader]) -> Option<String> {
    let interp: ProgramHeader = segments
        .iter()
        .copied()
        .find(|p: &ProgramHeader| p.p_type == PT_INTERP)?;
    let start: usize = usize::try_from(interp.offset).ok()?;
    let len: usize = usize::try_from(interp.filesz).ok()?.min(MAX_STRING_BYTES);
    let slice: &[u8] = bytes.get(start..start.checked_add(len)?)?;
    let end: usize = slice
        .iter()
        .position(|&b: &u8| b == 0)
        .unwrap_or(slice.len());
    Some(String::from_utf8_lossy(&slice[..end]).into_owned())
}

fn read_dynamic_entries(
    bytes: &[u8],
    header: &Header,
    segments: &[ProgramHeader],
    dynamic: &ProgramHeader,
) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    let entry_size: usize = match header.class {
        ElfClass::Elf64 => 16,
        ElfClass::Elf32 => 8,
    };
    let Some(start): Option<usize> =
        file_offset_for(bytes, header, segments, dynamic.vaddr, dynamic.offset)
    else {
        return out;
    };
    let span: usize = match usize::try_from(dynamic.filesz) {
        Ok(value) => value,
        Err(_) => return out,
    };
    let e: Endian = header.endian;
    let mut cursor: usize = start;
    let limit: usize = start.saturating_add(span);
    while cursor + entry_size <= limit && out.len() < MAX_DYNAMIC_ENTRIES {
        let Some(slice): Option<&[u8]> = read_slice(bytes, cursor, entry_size) else {
            break;
        };
        let (tag, value): (u64, u64) = match header.class {
            ElfClass::Elf64 => {
                let Some(tag): Option<u64> = e.u64(&slice[0..]) else {
                    break;
                };
                let Some(value): Option<u64> = e.u64(&slice[8..]) else {
                    break;
                };
                (tag, value)
            }
            ElfClass::Elf32 => {
                let Some(tag): Option<u32> = e.u32(&slice[0..]) else {
                    break;
                };
                let Some(value): Option<u32> = e.u32(&slice[4..]) else {
                    break;
                };
                (u64::from(tag), u64::from(value))
            }
        };
        out.push((tag, value));
        if tag == DT_NULL {
            break;
        }
        cursor += entry_size;
    }
    out
}

fn lookup(entries: &[(u64, u64)], tag: u64) -> Option<u64> {
    entries
        .iter()
        .find(|(t, _): &&(u64, u64)| *t == tag)
        .map(|(_, value): &(u64, u64)| *value)
}

fn file_offset_for(
    bytes: &[u8],
    header: &Header,
    segments: &[ProgramHeader],
    vaddr: u64,
    self_offset: u64,
) -> Option<usize> {
    let direct: Option<usize> = vaddr_to_file_offset(segments, vaddr);
    let chosen: usize = match direct {
        Some(value) => value,
        None => usize::try_from(self_offset).ok()?,
    };
    let _ = header;
    (chosen <= bytes.len()).then_some(chosen)
}

fn vaddr_to_file_offset(segments: &[ProgramHeader], vaddr: u64) -> Option<usize> {
    for ph in segments {
        if ph.p_type != PT_LOAD {
            continue;
        }
        let end: u64 = ph.vaddr.checked_add(ph.filesz)?;
        if vaddr >= ph.vaddr && vaddr < end {
            let delta: u64 = vaddr - ph.vaddr;
            return usize::try_from(ph.offset.checked_add(delta)?).ok();
        }
    }
    None
}

fn resolve_dynstr(
    bytes: &[u8],
    segments: &[ProgramHeader],
    strtab_va: Option<u64>,
    strsz: u64,
    str_offset: u64,
) -> Option<String> {
    let strtab: u64 = strtab_va?;
    let table_file: usize =
        vaddr_to_file_offset(segments, strtab).or_else(|| usize::try_from(strtab).ok())?;
    let entry_file: usize = table_file.checked_add(usize::try_from(str_offset).ok()?)?;
    let max_end: usize = if strsz > 0 {
        table_file
            .checked_add(usize::try_from(strsz).ok()?)
            .unwrap_or(bytes.len())
            .min(bytes.len())
    } else {
        bytes.len()
    };
    let scan_end: usize = max_end.min(entry_file.saturating_add(MAX_STRING_BYTES));
    let slice: &[u8] = bytes.get(entry_file..scan_end)?;
    let end: usize = slice.iter().position(|&b: &u8| b == 0)?;
    Some(String::from_utf8_lossy(&slice[..end]).into_owned())
}

fn read_pointer_array(
    bytes: &[u8],
    header: &Header,
    segments: &[ProgramHeader],
    addr: Option<u64>,
    size: Option<u64>,
) -> Vec<u64> {
    let mut out: Vec<u64> = Vec::new();
    let (Some(addr), Some(size)): (Option<u64>, Option<u64>) = (addr, size) else {
        return out;
    };
    let ptr_size: usize = match header.class {
        ElfClass::Elf64 => 8,
        ElfClass::Elf32 => 4,
    };
    let Some(start): Option<usize> = vaddr_to_file_offset(segments, addr) else {
        return out;
    };
    let count: usize = (usize::try_from(size).unwrap_or(0) / ptr_size).min(MAX_NEEDED);
    let e: Endian = header.endian;
    for i in 0..count {
        let base: usize = match start.checked_add(i * ptr_size) {
            Some(value) => value,
            None => break,
        };
        let Some(slice): Option<&[u8]> = read_slice(bytes, base, ptr_size) else {
            break;
        };
        let value: u64 = match header.class {
            ElfClass::Elf64 => match e.u64(slice) {
                Some(v) => v,
                None => break,
            },
            ElfClass::Elf32 => match e.u32(slice) {
                Some(v) => u64::from(v),
                None => break,
            },
        };
        out.push(value);
    }
    out
}

const fn default_syment(class: ElfClass) -> u64 {
    match class {
        ElfClass::Elf64 => 24,
        ElfClass::Elf32 => 16,
    }
}

fn recover_symbol_count(
    bytes: &[u8],
    header: &Header,
    segments: &[ProgramHeader],
    entries: &[(u64, u64)],
    symtab_va: u64,
    syment: u64,
) -> (usize, SymbolCountSource) {
    if let Some(gnu_hash) = lookup(entries, DT_GNU_HASH)
        && let Some(count) = gnu_hash_symbol_count(bytes, header, segments, gnu_hash)
    {
        return (count, SymbolCountSource::GnuHash);
    }
    if let Some(sysv_hash) = lookup(entries, DT_HASH)
        && let Some(count) = sysv_hash_symbol_count(bytes, header, segments, sysv_hash)
    {
        return (count, SymbolCountSource::SysvHash);
    }
    (
        bounded_symbol_scan(bytes, segments, entries, symtab_va, syment),
        SymbolCountSource::BoundedScan,
    )
}

fn gnu_hash_symbol_count(
    bytes: &[u8],
    header: &Header,
    segments: &[ProgramHeader],
    gnu_hash_va: u64,
) -> Option<usize> {
    let base: usize = vaddr_to_file_offset(segments, gnu_hash_va)?;
    let e: Endian = header.endian;
    let nbuckets: u32 = e.u32(read_slice(bytes, base, 4)?)?;
    let symoffset: u32 = e.u32(read_slice(bytes, base.checked_add(4)?, 4)?)?;
    let bloom_size: u32 = e.u32(read_slice(bytes, base.checked_add(8)?, 4)?)?;
    if nbuckets == 0 || nbuckets as usize > MAX_GNU_HASH_BUCKETS {
        return None;
    }
    let bloom_word: usize = match header.class {
        ElfClass::Elf64 => 8,
        ElfClass::Elf32 => 4,
    };
    let buckets_off: usize = base
        .checked_add(16)?
        .checked_add((bloom_size as usize).checked_mul(bloom_word)?)?;
    let mut max_symbol: u32 = symoffset;
    for i in 0..nbuckets as usize {
        let off: usize = buckets_off.checked_add(i.checked_mul(4)?)?;
        let bucket: u32 = e.u32(read_slice(bytes, off, 4)?)?;
        if bucket > max_symbol {
            max_symbol = bucket;
        }
    }
    if max_symbol < symoffset {
        return Some(symoffset as usize);
    }
    let chain_base: usize = buckets_off.checked_add((nbuckets as usize).checked_mul(4)?)?;
    let mut symbol_index: u32 = max_symbol;
    loop {
        let rel: u32 = symbol_index.checked_sub(symoffset)?;
        let off: usize = chain_base.checked_add((rel as usize).checked_mul(4)?)?;
        let chain: u32 = e.u32(read_slice(bytes, off, 4)?)?;
        let count: usize = (symbol_index as usize).checked_add(1)?;
        if count > MAX_SYMBOLS {
            return Some(MAX_SYMBOLS);
        }
        if chain & 1 == 1 {
            return Some(count);
        }
        symbol_index = symbol_index.checked_add(1)?;
    }
}

fn sysv_hash_symbol_count(
    bytes: &[u8],
    header: &Header,
    segments: &[ProgramHeader],
    hash_va: u64,
) -> Option<usize> {
    let base: usize = vaddr_to_file_offset(segments, hash_va)?;
    let e: Endian = header.endian;
    let nchain: u32 = e.u32(read_slice(bytes, base.checked_add(4)?, 4)?)?;
    (nchain as usize <= MAX_SYMBOLS).then_some(nchain as usize)
}

fn bounded_symbol_scan(
    bytes: &[u8],
    segments: &[ProgramHeader],
    entries: &[(u64, u64)],
    symtab_va: u64,
    syment: u64,
) -> usize {
    let Some(symtab_off): Option<usize> = vaddr_to_file_offset(segments, symtab_va) else {
        return 0;
    };
    let syment: usize = usize::try_from(syment).unwrap_or(0);
    if syment == 0 {
        return 0;
    }
    let strtab_va: Option<u64> = lookup(entries, DT_STRTAB);
    let ceiling: usize = match strtab_va.and_then(|va: u64| vaddr_to_file_offset(segments, va)) {
        Some(strtab_off) if strtab_off > symtab_off => strtab_off,
        _ => bytes.len(),
    };
    let span: usize = ceiling.saturating_sub(symtab_off);
    (span / syment).min(MAX_SYMBOLS)
}

#[allow(clippy::too_many_arguments)]
fn read_dynamic_symbols(
    bytes: &[u8],
    header: &Header,
    segments: &[ProgramHeader],
    symtab_va: u64,
    syment: u64,
    strtab_va: u64,
    strsz: u64,
    count: usize,
) -> Vec<DynamicSymbol> {
    let mut out: Vec<DynamicSymbol> = Vec::new();
    let Some(symtab_off): Option<usize> = vaddr_to_file_offset(segments, symtab_va) else {
        return out;
    };
    let syment: usize = usize::try_from(syment).unwrap_or(0);
    if syment == 0 {
        return out;
    }
    let count: usize = count.min(MAX_SYMBOLS);
    let e: Endian = header.endian;
    for i in 0..count {
        let base: usize = match symtab_off.checked_add(i.saturating_mul(syment)) {
            Some(value) => value,
            None => break,
        };
        let Some(slice): Option<&[u8]> = read_slice(bytes, base, syment) else {
            break;
        };
        let Some(sym): Option<DynamicSymbol> =
            parse_symbol(slice, e, header.class, bytes, segments, strtab_va, strsz)
        else {
            break;
        };
        out.push(sym);
    }
    out
}

fn parse_symbol(
    slice: &[u8],
    e: Endian,
    class: ElfClass,
    bytes: &[u8],
    segments: &[ProgramHeader],
    strtab_va: u64,
    strsz: u64,
) -> Option<DynamicSymbol> {
    let (name_off, info, shndx, value, size): (u32, u8, u16, u64, u64) = match class {
        ElfClass::Elf64 => (
            e.u32(&slice[0..])?,
            *slice.get(4)?,
            e.u16(&slice[6..])?,
            e.u64(&slice[8..])?,
            e.u64(&slice[16..])?,
        ),
        ElfClass::Elf32 => (
            e.u32(&slice[0..])?,
            *slice.get(12)?,
            e.u16(&slice[14..])?,
            u64::from(e.u32(&slice[4..])?),
            u64::from(e.u32(&slice[8..])?),
        ),
    };
    let name: String = resolve_dynstr(bytes, segments, Some(strtab_va), strsz, u64::from(name_off))
        .unwrap_or_default();
    Some(DynamicSymbol {
        name,
        value,
        size,
        bind: bind_from(info >> 4),
        sym_type: type_from(info & 0xf),
        defined: shndx != 0,
    })
}

const fn bind_from(b: u8) -> SymbolBind {
    match b {
        0 => SymbolBind::Local,
        1 => SymbolBind::Global,
        2 => SymbolBind::Weak,
        _ => SymbolBind::Other,
    }
}

const fn type_from(t: u8) -> SymbolType {
    match t {
        0 => SymbolType::NoType,
        1 => SymbolType::Object,
        2 => SymbolType::Func,
        3 => SymbolType::Section,
        4 => SymbolType::File,
        5 => SymbolType::Common,
        6 => SymbolType::Tls,
        _ => SymbolType::Other,
    }
}

fn read_all_relocations(
    bytes: &[u8],
    header: &Header,
    segments: &[ProgramHeader],
    entries: &[(u64, u64)],
    symbol_names: &[Option<String>],
) -> Vec<Relocation> {
    let mut out: Vec<Relocation> = Vec::new();
    if let (Some(rela), Some(size)) = (lookup(entries, DT_RELA), lookup(entries, DT_RELASZ)) {
        let ent: u64 = lookup(entries, DT_RELAENT).unwrap_or_else(|| rela_entsize(header.class));
        read_rela(
            bytes,
            header,
            segments,
            rela,
            size,
            ent,
            RelocSource::Rela,
            symbol_names,
            &mut out,
        );
    }
    if let (Some(rel), Some(size)) = (lookup(entries, DT_REL), lookup(entries, DT_RELSZ)) {
        let ent: u64 = lookup(entries, DT_RELENT).unwrap_or_else(|| rel_entsize(header.class));
        read_rel(
            bytes,
            header,
            segments,
            rel,
            size,
            ent,
            RelocSource::Rel,
            symbol_names,
            &mut out,
        );
    }
    if let (Some(jmprel), Some(size)) = (lookup(entries, DT_JMPREL), lookup(entries, DT_PLTRELSZ)) {
        let is_rela: bool = lookup(entries, DT_PLTREL) == Some(DT_PLTREL_RELA);
        if is_rela {
            let ent: u64 = rela_entsize(header.class);
            read_rela(
                bytes,
                header,
                segments,
                jmprel,
                size,
                ent,
                RelocSource::JmpRel,
                symbol_names,
                &mut out,
            );
        } else {
            let ent: u64 = rel_entsize(header.class);
            read_rel(
                bytes,
                header,
                segments,
                jmprel,
                size,
                ent,
                RelocSource::JmpRel,
                symbol_names,
                &mut out,
            );
        }
    }
    out
}

const fn rela_entsize(class: ElfClass) -> u64 {
    match class {
        ElfClass::Elf64 => 24,
        ElfClass::Elf32 => 12,
    }
}

const fn rel_entsize(class: ElfClass) -> u64 {
    match class {
        ElfClass::Elf64 => 16,
        ElfClass::Elf32 => 8,
    }
}

#[allow(clippy::too_many_arguments)]
fn read_rela(
    bytes: &[u8],
    header: &Header,
    segments: &[ProgramHeader],
    addr: u64,
    size: u64,
    ent: u64,
    source: RelocSource,
    symbol_names: &[Option<String>],
    out: &mut Vec<Relocation>,
) {
    let Some(start): Option<usize> = vaddr_to_file_offset(segments, addr) else {
        return;
    };
    let ent: usize = usize::try_from(ent).unwrap_or(0);
    if ent == 0 {
        return;
    }
    let count: usize = usize::try_from(size).unwrap_or(0) / ent;
    let e: Endian = header.endian;
    for i in 0..count {
        if out.len() >= MAX_RELOCATIONS {
            return;
        }
        let base: usize = match start.checked_add(i.saturating_mul(ent)) {
            Some(value) => value,
            None => return,
        };
        let Some(slice): Option<&[u8]> = read_slice(bytes, base, ent) else {
            return;
        };
        let reloc: Relocation = match header.class {
            ElfClass::Elf64 => {
                let Some(offset): Option<u64> = e.u64(&slice[0..]) else {
                    return;
                };
                let Some(info): Option<u64> = e.u64(&slice[8..]) else {
                    return;
                };
                let Some(addend): Option<u64> = e.u64(&slice[16..]) else {
                    return;
                };
                let sym: u32 = (info >> 32) as u32;
                Relocation {
                    offset,
                    r_type: (info & 0xffff_ffff) as u32,
                    symbol_index: sym,
                    addend: addend.cast_signed(),
                    symbol_name: symbol_names.get(sym as usize).cloned().flatten(),
                    source,
                }
            }
            ElfClass::Elf32 => {
                let Some(offset): Option<u32> = e.u32(&slice[0..]) else {
                    return;
                };
                let Some(info): Option<u32> = e.u32(&slice[4..]) else {
                    return;
                };
                let Some(addend): Option<u32> = e.u32(&slice[8..]) else {
                    return;
                };
                let sym: u32 = info >> 8;
                Relocation {
                    offset: u64::from(offset),
                    r_type: info & 0xff,
                    symbol_index: sym,
                    addend: i64::from(addend.cast_signed()),
                    symbol_name: symbol_names.get(sym as usize).cloned().flatten(),
                    source,
                }
            }
        };
        out.push(reloc);
    }
}

#[allow(clippy::too_many_arguments)]
fn read_rel(
    bytes: &[u8],
    header: &Header,
    segments: &[ProgramHeader],
    addr: u64,
    size: u64,
    ent: u64,
    source: RelocSource,
    symbol_names: &[Option<String>],
    out: &mut Vec<Relocation>,
) {
    let Some(start): Option<usize> = vaddr_to_file_offset(segments, addr) else {
        return;
    };
    let ent: usize = usize::try_from(ent).unwrap_or(0);
    if ent == 0 {
        return;
    }
    let count: usize = usize::try_from(size).unwrap_or(0) / ent;
    let e: Endian = header.endian;
    for i in 0..count {
        if out.len() >= MAX_RELOCATIONS {
            return;
        }
        let base: usize = match start.checked_add(i.saturating_mul(ent)) {
            Some(value) => value,
            None => return,
        };
        let Some(slice): Option<&[u8]> = read_slice(bytes, base, ent) else {
            return;
        };
        let reloc: Relocation = match header.class {
            ElfClass::Elf64 => {
                let Some(offset): Option<u64> = e.u64(&slice[0..]) else {
                    return;
                };
                let Some(info): Option<u64> = e.u64(&slice[8..]) else {
                    return;
                };
                let sym: u32 = (info >> 32) as u32;
                Relocation {
                    offset,
                    r_type: (info & 0xffff_ffff) as u32,
                    symbol_index: sym,
                    addend: 0,
                    symbol_name: symbol_names.get(sym as usize).cloned().flatten(),
                    source,
                }
            }
            ElfClass::Elf32 => {
                let Some(offset): Option<u32> = e.u32(&slice[0..]) else {
                    return;
                };
                let Some(info): Option<u32> = e.u32(&slice[4..]) else {
                    return;
                };
                let sym: u32 = info >> 8;
                Relocation {
                    offset: u64::from(offset),
                    r_type: info & 0xff,
                    symbol_index: sym,
                    addend: 0,
                    symbol_name: symbol_names.get(sym as usize).cloned().flatten(),
                    source,
                }
            }
        };
        out.push(reloc);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests;
