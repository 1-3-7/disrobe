use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Read as _;
use std::path::Path;

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter as _, Instruction, InstructionInfoFactory,
    MemorySize, Mnemonic, NasmFormatter, OpAccess, OpKind, Register,
};
use object::{Object as _, ObjectKind, ObjectSection as _, ObjectSymbol as _, SectionFlags};
use serde::Serialize;

use disrobe_pass_native::IndexedStringAnnotation;

pub(crate) const MAX_SCOPE_BYTES: u64 = 4 * 1024 * 1024;
pub(crate) const MAX_QUERY_SCAN_BYTES: u64 = 256 * 1024 * 1024;
pub(crate) const MAX_QUERY_MATCHES: usize = 10_000;
pub(crate) const MAX_FIELD_DISPLACEMENTS: usize = 64;
const MAX_PDATA_ENTRIES: usize = 1 << 22;
const MAX_UNWIND_CHAIN_DEPTH: usize = 32;
const MAX_STRING_SCAN_BYTES: usize = 1024;
const MAX_STRING_CHARS: usize = 200;
const MIN_STRING_CHARS: usize = 2;
const MAX_SELECTOR_BYTES: usize = 64;
const RUNTIME_FUNCTION_BYTES: usize = 12;
const RUNTIME_FUNCTION_INDIRECT: u32 = 1;
const UNW_FLAG_CHAININFO: u8 = 0x04;
const LOWEST_MAPPABLE_ADDRESS: u64 = 0x1_0000;
const MAX_IMAGE_INPUT_BYTES: u64 = 512 * 1024 * 1024;

pub(crate) fn read_image(input: &Path) -> miette::Result<Vec<u8>> {
    let file: std::fs::File = std::fs::File::open(input).map_err(|error: std::io::Error| {
        miette::miette!("DR-NATIVE-0300: cannot open {}: {error}", input.display())
    })?;
    let metadata: std::fs::Metadata = file.metadata().map_err(|error: std::io::Error| {
        miette::miette!(
            "DR-NATIVE-0300: cannot inspect {}: {error}",
            input.display()
        )
    })?;
    if !metadata.is_file() || metadata.len() > MAX_IMAGE_INPUT_BYTES {
        return Err(miette::miette!(
            "DR-NATIVE-0300: {} must be a regular file of at most {MAX_IMAGE_INPUT_BYTES} bytes",
            input.display()
        ));
    }
    let mut bytes: Vec<u8> = Vec::new();
    let size: usize = file
        .take(MAX_IMAGE_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error: std::io::Error| {
            miette::miette!("DR-NATIVE-0300: cannot read {}: {error}", input.display())
        })?;
    if u64::try_from(size).map_or(true, |size: u64| size > MAX_IMAGE_INPUT_BYTES) {
        return Err(miette::miette!(
            "DR-NATIVE-0300: {} exceeds the {MAX_IMAGE_INPUT_BYTES}-byte input bound",
            input.display()
        ));
    }
    Ok(bytes)
}

#[derive(Debug)]
struct MappedSection<'data> {
    name: String,
    start: u64,
    end: u64,
    data: &'data [u8],
    executable: bool,
    read_only_data: bool,
}

#[derive(Debug)]
pub(crate) struct Image<'data> {
    bytes: &'data [u8],
    pub(crate) base: u64,
    pub(crate) bitness: u32,
    file: object::File<'data>,
    sections: Vec<MappedSection<'data>>,
}

impl<'data> Image<'data> {
    pub(crate) fn parse(bytes: &'data [u8]) -> miette::Result<Self> {
        let file: object::File<'data> =
            object::File::parse(bytes).map_err(|e: object::Error| {
                miette::miette!("DR-NATIVE-0301: not a parseable native image: {e}")
            })?;
        let bitness: u32 = match file.architecture() {
            object::Architecture::X86_64 => 64,
            object::Architecture::I386 => 32,
            other => {
                return Err(miette::miette!(
                    "DR-NATIVE-0301: function-scoped output and address queries decode x86 and x86-64 code; this image is {other:?}"
                ));
            }
        };
        if file.kind() == ObjectKind::Relocatable {
            return Err(miette::miette!(
                "DR-NATIVE-0301: a relocatable object has no image layout, so its RVAs are ambiguous; link it first"
            ));
        }
        let base: u64 = file.relative_address_base();
        let mut sections: Vec<MappedSection<'data>> = Vec::new();
        for section in file.sections() {
            let flags: SectionFlags = section.flags();
            if let SectionFlags::Elf { sh_flags } = flags
                && sh_flags & u64::from(object::elf::SHF_ALLOC) == 0
            {
                continue;
            }
            let Some(start): Option<u64> = section.address().checked_sub(base) else {
                continue;
            };
            let Some(end): Option<u64> = start.checked_add(section.size()) else {
                continue;
            };
            if end == start {
                continue;
            }
            sections.push(MappedSection {
                name: section.name().unwrap_or("").to_owned(),
                start,
                end,
                data: section.data().unwrap_or(&[]),
                executable: section_is_executable(flags, section.kind()),
                read_only_data: section_is_read_only_data(flags, section.kind()),
            });
        }
        sections.sort_by_key(|section: &MappedSection<'data>| section.start);
        Ok(Self {
            bytes,
            base,
            bitness,
            file,
            sections,
        })
    }

    pub(crate) const fn arch_label(&self) -> &'static str {
        if self.bitness == 64 {
            "x86-64"
        } else {
            "x86-32"
        }
    }

    pub(crate) fn is_pe(&self) -> bool {
        matches!(
            self.file.format(),
            object::BinaryFormat::Pe | object::BinaryFormat::Coff
        )
    }

    pub(crate) const fn va(&self, rva: u64) -> u64 {
        self.base.wrapping_add(rva)
    }

    fn section_containing(&self, rva: u64) -> Option<&MappedSection<'data>> {
        let index: usize = self
            .sections
            .partition_point(|section: &MappedSection<'data>| section.start <= rva);
        let section: &MappedSection<'data> = self.sections.get(index.checked_sub(1)?)?;
        (rva < section.end).then_some(section)
    }

    fn bytes_at(&self, rva: u64, len: usize) -> Option<&'data [u8]> {
        let section: &MappedSection<'data> = self.section_containing(rva)?;
        let offset: usize = usize::try_from(rva - section.start).ok()?;
        section.data.get(offset..offset.checked_add(len)?)
    }

    fn bytes_from(&self, rva: u64, max: usize) -> Option<&'data [u8]> {
        let section: &MappedSection<'data> = self.section_containing(rva)?;
        let offset: usize = usize::try_from(rva - section.start).ok()?;
        let tail: &'data [u8] = section.data.get(offset..)?;
        Some(&tail[..tail.len().min(max)])
    }

    fn is_read_only_data(&self, rva: u64) -> bool {
        self.section_containing(rva)
            .is_some_and(|section: &MappedSection<'data>| section.read_only_data)
    }

    pub(crate) fn code_range(&self, start: u64, end: u64) -> miette::Result<&'data [u8]> {
        if start < end && end - start > MAX_SCOPE_BYTES {
            return Err(miette::miette!(
                "DR-NATIVE-0306: range {start:#x}:{end:#x} spans {} bytes, over the {MAX_SCOPE_BYTES}-byte scope limit",
                end - start
            ));
        }
        self.executable_bytes(start, end)
    }

    fn executable_bytes(&self, start: u64, end: u64) -> miette::Result<&'data [u8]> {
        if start >= end {
            return Err(miette::miette!(
                "DR-NATIVE-0305: range {start:#x}:{end:#x} is empty; the end RVA is exclusive and must exceed the start"
            ));
        }
        let Some(section): Option<&MappedSection<'data>> = self.section_containing(start) else {
            return Err(miette::miette!(
                "DR-NATIVE-0304: RVA {start:#x} lies outside every section of this image"
            ));
        };
        if !section.executable {
            return Err(miette::miette!(
                "DR-NATIVE-0304: RVA {start:#x} lies in section {} ({:#x}..{:#x}), which is not executable",
                section.name,
                section.start,
                section.end
            ));
        }
        if end > section.end {
            return Err(miette::miette!(
                "DR-NATIVE-0304: range {start:#x}:{end:#x} runs past the end of executable section {} at {:#x}",
                section.name,
                section.end
            ));
        }
        let offset: usize = usize::try_from(start - section.start).map_err(|_| {
            miette::miette!("DR-NATIVE-0304: RVA {start:#x} is outside the host address range")
        })?;
        let len: usize = usize::try_from(end - start).map_err(|_| {
            miette::miette!(
                "DR-NATIVE-0304: range {start:#x}:{end:#x} is outside the host address range"
            )
        })?;
        section
            .data
            .get(offset..offset.saturating_add(len))
            .ok_or_else(|| {
                miette::miette!(
                    "DR-NATIVE-0304: range {start:#x}:{end:#x} is not backed by file bytes; section {} stores {} of its {} bytes",
                    section.name,
                    section.data.len(),
                    section.end - section.start
                )
            })
    }

    fn symbol_names(&self) -> BTreeMap<u64, String> {
        let mut names: BTreeMap<u64, String> = BTreeMap::new();
        for symbol in self.file.symbols() {
            if symbol.kind() != object::SymbolKind::Text || symbol.is_undefined() {
                continue;
            }
            let (Ok(name), Some(rva)): (Result<&str, object::Error>, Option<u64>) =
                (symbol.name(), symbol.address().checked_sub(self.base))
            else {
                continue;
            };
            if !name.is_empty() {
                names.entry(rva).or_insert_with(|| name.to_owned());
            }
        }
        if let Ok(exports) = self.file.exports() {
            for export in exports {
                let Some(rva): Option<u64> = export.address().checked_sub(self.base) else {
                    continue;
                };
                if let Ok(name) = std::str::from_utf8(export.name())
                    && !name.is_empty()
                {
                    names.entry(rva).or_insert_with(|| name.to_owned());
                }
            }
        }
        names
    }
}

fn section_is_executable(flags: SectionFlags, kind: object::SectionKind) -> bool {
    match flags {
        SectionFlags::Coff { characteristics } => {
            characteristics & object::pe::IMAGE_SCN_MEM_EXECUTE != 0
        }
        SectionFlags::Elf { sh_flags } => sh_flags & u64::from(object::elf::SHF_EXECINSTR) != 0,
        _ => kind == object::SectionKind::Text,
    }
}

fn section_is_read_only_data(flags: SectionFlags, kind: object::SectionKind) -> bool {
    match flags {
        SectionFlags::Coff { characteristics } => {
            characteristics & object::pe::IMAGE_SCN_MEM_READ != 0
                && characteristics
                    & (object::pe::IMAGE_SCN_MEM_WRITE | object::pe::IMAGE_SCN_MEM_EXECUTE)
                    == 0
        }
        SectionFlags::Elf { sh_flags } => {
            sh_flags & u64::from(object::elf::SHF_WRITE | object::elf::SHF_EXECINSTR) == 0
        }
        _ => matches!(
            kind,
            object::SectionKind::ReadOnlyData
                | object::SectionKind::ReadOnlyString
                | object::SectionKind::ReadOnlyDataWithRel
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RangeSource {
    Pdata,
    Discovery,
    Range,
}

impl RangeSource {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Pdata => ".pdata unwind range",
            Self::Discovery => "function discovery",
            Self::Range => "requested range",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct CodeRange {
    pub(crate) start: u64,
    pub(crate) end: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct FunctionEntry {
    pub(crate) name: String,
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) source: RangeSource,
    pub(crate) chained: Vec<CodeRange>,
}

impl FunctionEntry {
    fn ranges(&self) -> impl Iterator<Item = CodeRange> + '_ {
        std::iter::once(CodeRange {
            start: self.start,
            end: self.end,
        })
        .chain(self.chained.iter().copied())
    }

    fn byte_len(&self) -> u64 {
        self.ranges()
            .map(|range: CodeRange| range.end - range.start)
            .sum()
    }
}

#[derive(Debug, Clone, Copy)]
struct ChainedRange {
    end: u64,
    owner: u64,
}

#[derive(Debug, Clone, Copy)]
struct RuntimeFunction {
    begin: u32,
    end: u32,
    unwind: u32,
}

impl RuntimeFunction {
    fn read(record: &[u8]) -> Option<Self> {
        let word = |at: usize| -> Option<u32> {
            Some(u32::from_le_bytes(record.get(at..at + 4)?.try_into().ok()?))
        };
        Some(Self {
            begin: word(0)?,
            end: word(4)?,
            unwind: word(8)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct FunctionIndex {
    functions: BTreeMap<u64, FunctionEntry>,
    chained: BTreeMap<u64, ChainedRange>,
    discovered: bool,
}

impl FunctionIndex {
    pub(crate) fn from_unwind(image: &Image<'_>) -> Self {
        let names: BTreeMap<u64, String> = image.symbol_names();
        let mut functions: BTreeMap<u64, FunctionEntry> = BTreeMap::new();
        let mut chained: BTreeMap<u64, ChainedRange> = BTreeMap::new();
        let mut pending: Vec<(CodeRange, u64)> = Vec::new();
        for record in runtime_functions(image) {
            let range: CodeRange = CodeRange {
                start: u64::from(record.begin),
                end: u64::from(record.end),
            };
            if image.executable_bytes(range.start, range.end).is_err() {
                continue;
            }
            let Some(owner): Option<u64> = unwind_owner(image, record) else {
                continue;
            };
            if owner == range.start {
                functions
                    .entry(range.start)
                    .or_insert_with(|| FunctionEntry {
                        name: function_name(image, &names, range.start),
                        start: range.start,
                        end: range.end,
                        source: RangeSource::Pdata,
                        chained: Vec::new(),
                    });
            } else {
                pending.push((range, owner));
            }
        }
        for (range, owner) in pending {
            if !functions.contains_key(&owner)
                || overlaps(&functions, range, |entry: &FunctionEntry| entry.end)
                || overlaps(&chained, range, |existing: &ChainedRange| existing.end)
            {
                continue;
            }
            if let Some(entry) = functions.get_mut(&owner) {
                entry.chained.push(range);
            }
            chained.insert(
                range.start,
                ChainedRange {
                    end: range.end,
                    owner,
                },
            );
        }
        for entry in functions.values_mut() {
            entry.chained.sort_by_key(|range: &CodeRange| range.start);
        }
        Self {
            functions,
            chained,
            discovered: false,
        }
    }

    pub(crate) fn add_discovered(&mut self, image: &Image<'_>) -> miette::Result<()> {
        if self.discovered {
            return Ok(());
        }
        self.discovered = true;
        let Some(arch): Option<disrobe_pass_native::Arch> =
            disrobe_pass_native::image_arch(image.bytes)
        else {
            return Err(miette::miette!(
                "DR-NATIVE-0308: function discovery has no decoder for this image's architecture"
            ));
        };
        let payload: disrobe_ir::payload::DisasmPayload =
            disrobe_pass_native::build_disasm_payload(image.bytes).map_err(
                |e: disrobe_pass_native::Error| {
                    miette::miette!("DR-NATIVE-0308: function discovery failed: {e}")
                },
            )?;
        let spans: Vec<disrobe_pass_native::FunctionSpan> =
            disrobe_pass_native::function_spans(&payload, arch);
        let mut starts: BTreeSet<u64> = self.functions.keys().copied().collect();
        starts.extend(self.chained.keys().copied());
        let mut candidates: Vec<FunctionEntry> = Vec::new();
        for span in spans {
            let (Some(start), Some(end)): (Option<u64>, Option<u64>) = (
                span.address.checked_sub(image.base),
                span.end.checked_sub(image.base),
            ) else {
                continue;
            };
            if end <= start || self.covering(start).is_some() {
                continue;
            }
            starts.insert(start);
            candidates.push(FunctionEntry {
                name: span.name,
                start,
                end,
                source: RangeSource::Discovery,
                chained: Vec::new(),
            });
        }
        for mut entry in candidates {
            if let Some(next) = starts.range(entry.start + 1..).next() {
                entry.end = entry.end.min(*next);
            }
            if image.executable_bytes(entry.start, entry.end).is_ok() {
                self.functions.entry(entry.start).or_insert(entry);
            }
        }
        Ok(())
    }

    fn covering(&self, rva: u64) -> Option<u64> {
        if let Some((_, entry)) = self.functions.range(..=rva).next_back()
            && entry.source == RangeSource::Pdata
            && rva < entry.end
        {
            return Some(entry.start);
        }
        self.chained
            .range(..=rva)
            .next_back()
            .and_then(|(_, chained): (&u64, &ChainedRange)| {
                (rva < chained.end).then_some(chained.owner)
            })
    }

    fn containing(&self, rva: u64) -> Option<&FunctionEntry> {
        if let Some((_, entry)) = self.functions.range(..=rva).next_back()
            && rva < entry.end
        {
            return Some(entry);
        }
        let (_, chained): (&u64, &ChainedRange) = self.chained.range(..=rva).next_back()?;
        if rva < chained.end {
            self.functions.get(&chained.owner)
        } else {
            None
        }
    }

    pub(crate) fn function_at(&self, rva: u64) -> Option<&FunctionEntry> {
        self.functions.get(&rva)
    }

    pub(crate) fn functions(&self) -> impl Iterator<Item = &FunctionEntry> {
        self.functions.values()
    }

    pub(crate) fn resolve(&mut self, image: &Image<'_>, rva: u64) -> miette::Result<FunctionEntry> {
        if let Some(entry) = self.functions.get(&rva) {
            return Ok(entry.clone());
        }
        if let Some(chained) = self.chained.get(&rva) {
            let owner: String = self
                .functions
                .get(&chained.owner)
                .map_or_else(String::new, |entry: &FunctionEntry| entry.name.clone());
            return Err(miette::miette!(
                "DR-NATIVE-0307: RVA {rva:#x} starts a chained .pdata unwind range ({rva:#x}..{:#x}) of function {owner} at {:#x}, not a function; select {:#x}",
                chained.end,
                chained.owner,
                chained.owner
            ));
        }
        self.add_discovered(image)?;
        if let Some(entry) = self.functions.get(&rva) {
            return Ok(entry.clone());
        }
        let detail: String = self.containing(rva).map_or_else(
            || "it lies outside every function found in .pdata or by function discovery".to_owned(),
            |entry: &FunctionEntry| {
                format!(
                    "it lies {:#x} bytes into {} ({:#x}..{:#x}, from {})",
                    rva - entry.start,
                    entry.name,
                    entry.start,
                    entry.end,
                    entry.source.label()
                )
            },
        );
        Err(miette::miette!(
            "DR-NATIVE-0303: RVA {rva:#x} is not a function start: no .pdata unwind range begins there and function discovery found no function at it; {detail}"
        ))
    }
}

fn overlaps<T>(ranges: &BTreeMap<u64, T>, range: CodeRange, end: impl Fn(&T) -> u64) -> bool {
    ranges
        .range(..range.end)
        .next_back()
        .is_some_and(|(_, existing): (&u64, &T)| range.start < end(existing))
}

fn function_name(image: &Image<'_>, names: &BTreeMap<u64, String>, rva: u64) -> String {
    names
        .get(&rva)
        .cloned()
        .unwrap_or_else(|| format!("sub_{:x}", image.va(rva)))
}

fn runtime_functions(image: &Image<'_>) -> Vec<RuntimeFunction> {
    let object::File::Pe64(pe) = &image.file else {
        return Vec::new();
    };
    if image.bitness != 64 {
        return Vec::new();
    }
    let Some(directory): Option<&object::pe::ImageDataDirectory> =
        pe.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION)
    else {
        return Vec::new();
    };
    let (address, size): (u32, u32) = directory.address_range();
    let Ok(len): Result<usize, _> = usize::try_from(size) else {
        return Vec::new();
    };
    let Some(table): Option<&[u8]> = image.bytes_at(u64::from(address), len) else {
        return Vec::new();
    };
    table
        .chunks_exact(RUNTIME_FUNCTION_BYTES)
        .take(MAX_PDATA_ENTRIES)
        .filter_map(RuntimeFunction::read)
        .collect()
}

fn unwind_owner(image: &Image<'_>, record: RuntimeFunction) -> Option<u64> {
    let mut current: RuntimeFunction = record;
    for _ in 0..MAX_UNWIND_CHAIN_DEPTH {
        if current.unwind & RUNTIME_FUNCTION_INDIRECT != 0 {
            let at: u64 = u64::from(current.unwind & !RUNTIME_FUNCTION_INDIRECT);
            current = RuntimeFunction::read(image.bytes_at(at, RUNTIME_FUNCTION_BYTES)?)?;
            continue;
        }
        let header: &[u8] = image.bytes_at(u64::from(current.unwind), 4)?;
        if (header[0] >> 3) & UNW_FLAG_CHAININFO == 0 {
            return Some(u64::from(current.begin));
        }
        let codes: u64 = u64::from(header[2]);
        let parent: u64 = u64::from(current.unwind) + 4 + 2 * (codes + (codes & 1));
        current = RuntimeFunction::read(image.bytes_at(parent, RUNTIME_FUNCTION_BYTES)?)?;
    }
    None
}

#[derive(Debug, Clone)]
pub(crate) enum ScopeRequest {
    Function(String),
    Range(String),
}

impl ScopeRequest {
    pub(crate) fn from_args(function: Option<String>, range: Option<String>) -> Option<Self> {
        function
            .map(Self::Function)
            .or_else(|| range.map(Self::Range))
    }
}

pub(crate) fn parse_rva(raw: &str, what: &str) -> miette::Result<u64> {
    let trimmed: &str = raw.trim();
    let digits: &str = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if digits.is_empty()
        || trimmed.len() > MAX_SELECTOR_BYTES
        || !digits.bytes().all(|byte: u8| byte.is_ascii_hexdigit())
    {
        return Err(miette::miette!(
            "DR-NATIVE-0302: {what} {:?} is not a hexadecimal RVA such as 0x1040",
            trimmed.chars().take(MAX_SELECTOR_BYTES).collect::<String>()
        ));
    }
    u64::from_str_radix(digits, 16)
        .map_err(|_| miette::miette!("DR-NATIVE-0302: {what} {trimmed} does not fit in 64 bits"))
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Scope {
    pub(crate) kind: ScopeKind,
    pub(crate) name: Option<String>,
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) source: RangeSource,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) chained: Vec<CodeRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ScopeKind {
    Function,
    Range,
}

impl Scope {
    pub(crate) fn ranges(&self) -> Vec<CodeRange> {
        std::iter::once(CodeRange {
            start: self.start,
            end: self.end,
        })
        .chain(self.chained.iter().copied())
        .collect()
    }
}

pub(crate) fn resolve_scope(
    image: &Image<'_>,
    index: &mut FunctionIndex,
    request: &ScopeRequest,
) -> miette::Result<Scope> {
    match request {
        ScopeRequest::Function(raw) => {
            let rva: u64 = parse_rva(raw, "--function")?;
            let entry: FunctionEntry = index.resolve(image, rva)?;
            for range in entry.ranges() {
                image.code_range(range.start, range.end)?;
            }
            Ok(Scope {
                kind: ScopeKind::Function,
                name: Some(entry.name),
                start: entry.start,
                end: entry.end,
                source: entry.source,
                chained: entry.chained,
            })
        }
        ScopeRequest::Range(raw) => {
            let Some((start_raw, end_raw)): Option<(&str, &str)> = raw.split_once(':') else {
                return Err(miette::miette!(
                    "DR-NATIVE-0302: --range {:?} is not START:END with hexadecimal RVAs such as 0x1040:0x10a3",
                    raw.chars().take(MAX_SELECTOR_BYTES).collect::<String>()
                ));
            };
            let start: u64 = parse_rva(start_raw, "--range start")?;
            let end: u64 = parse_rva(end_raw, "--range end")?;
            image.code_range(start, end)?;
            Ok(Scope {
                kind: ScopeKind::Range,
                name: index
                    .function_at(start)
                    .map(|entry: &FunctionEntry| entry.name.clone())
                    .or_else(|| image.symbol_names().remove(&start)),
                start,
                end,
                source: RangeSource::Range,
                chained: Vec::new(),
            })
        }
    }
}

pub(crate) fn decode_range(
    image: &Image<'_>,
    range: CodeRange,
) -> miette::Result<Vec<Instruction>> {
    let code: &[u8] = image.executable_bytes(range.start, range.end)?;
    let mut decoder: Decoder<'_> =
        Decoder::with_ip(image.bitness, code, range.start, DecoderOptions::NONE);
    let mut out: Vec<Instruction> = Vec::new();
    let mut instruction: Instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        out.push(instruction);
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ConstantKind {
    F32,
    F64,
    U32,
    U64,
    Ascii,
    Utf8,
    Utf16,
}

impl ConstantKind {
    const fn label(self) -> &'static str {
        match self {
            Self::F32 => "f32",
            Self::F64 => "f64",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::Ascii => "ascii",
            Self::Utf8 => "utf8",
            Self::Utf16 => "utf16",
        }
    }

    const fn is_string(self) -> bool {
        matches!(self, Self::Ascii | Self::Utf8 | Self::Utf16)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Constant {
    pub(crate) kind: ConstantKind,
    pub(crate) target: u64,
    pub(crate) values: Vec<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub(crate) truncated: bool,
}

impl Constant {
    pub(crate) fn render(&self) -> String {
        let body: String = if self.kind.is_string() {
            let text: String = self
                .values
                .iter()
                .flat_map(|value: &String| value.chars().flat_map(char::escape_debug))
                .collect();
            let tail: &str = if self.truncated { "..." } else { "" };
            format!("\"{text}\"{tail}")
        } else if let [single] = self.values.as_slice() {
            single.clone()
        } else {
            format!("[{}]", self.values.join(", "))
        };
        let lanes: String = if self.kind.is_string() || self.values.len() < 2 {
            String::new()
        } else {
            format!("x{}", self.values.len())
        };
        format!("{}{lanes} {body}", self.kind.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MemoryReference {
    target: u64,
    access: OpAccess,
}

fn image_memory_reference(
    image: &Image<'_>,
    instruction: &Instruction,
    factory: &mut InstructionInfoFactory,
) -> Option<MemoryReference> {
    let has_memory: bool = (0..instruction.op_count())
        .any(|operand: u32| instruction.op_kind(operand) == OpKind::Memory);
    if !has_memory {
        return None;
    }
    let (raw, target): (u64, u64) = if instruction.is_ip_rel_memory_operand() {
        let address: u64 = instruction.ip_rel_memory_address();
        (address, address)
    } else if instruction.memory_base() == Register::None
        && instruction.memory_index() == Register::None
        && !matches!(instruction.memory_segment(), Register::FS | Register::GS)
    {
        let absolute: u64 = if image.bitness == 32 {
            u64::from(instruction.memory_displacement32())
        } else {
            instruction.memory_displacement64()
        };
        (absolute, absolute.checked_sub(image.base)?)
    } else {
        return None;
    };
    let mask: u64 = if image.bitness == 32 {
        u64::from(u32::MAX)
    } else {
        u64::MAX
    };
    let access: OpAccess = factory
        .info(instruction)
        .used_memory()
        .iter()
        .find(|memory: &&iced_x86::UsedMemory| {
            memory.base() == Register::None
                && memory.index() == Register::None
                && memory.displacement() & mask == raw & mask
        })
        .map_or(OpAccess::Read, iced_x86::UsedMemory::access);
    Some(MemoryReference { target, access })
}

fn lane_values(bytes: &[u8], element: MemorySize) -> Option<(ConstantKind, Vec<String>, Vec<u64>)> {
    let (kind, width, render): (ConstantKind, usize, fn(u64) -> String) = match element {
        MemorySize::Float32 => (ConstantKind::F32, 4, |bits: u64| {
            f32::from_bits(bits as u32).to_string()
        }),
        MemorySize::Float64 => (ConstantKind::F64, 8, |bits: u64| {
            f64::from_bits(bits).to_string()
        }),
        MemorySize::UInt32 | MemorySize::Int32 => {
            (ConstantKind::U32, 4, |bits: u64| format!("{bits:#x}"))
        }
        MemorySize::UInt64 | MemorySize::Int64 => {
            (ConstantKind::U64, 8, |bits: u64| format!("{bits:#x}"))
        }
        _ => return None,
    };
    let mut rendered: Vec<String> = Vec::new();
    let mut bits: Vec<u64> = Vec::new();
    for lane in bytes.chunks_exact(width) {
        let mut word: [u8; 8] = [0; 8];
        word[..width].copy_from_slice(lane);
        let value: u64 = u64::from_le_bytes(word);
        rendered.push(render(value));
        bits.push(value);
    }
    Some((kind, rendered, bits))
}

fn loaded_constant(
    image: &Image<'_>,
    instruction: &Instruction,
    target: u64,
) -> Option<(Constant, Vec<u64>, usize)> {
    if instruction.flow_control() != FlowControl::Next || !image.is_read_only_data(target) {
        return None;
    }
    let size: MemorySize = instruction.memory_size();
    let element: MemorySize = size.element_type();
    if !matches!(element, MemorySize::Float32 | MemorySize::Float64) && size.is_packed() {
        return None;
    }
    let bytes: &[u8] = image.bytes_at(target, size.size())?;
    let (kind, values, bits): (ConstantKind, Vec<String>, Vec<u64>) = lane_values(bytes, element)?;
    Some((
        Constant {
            kind,
            target,
            values,
            truncated: false,
        },
        bits,
        element.size(),
    ))
}

fn string_constant(image: &Image<'_>, target: u64) -> Option<Constant> {
    if !image.is_read_only_data(target) {
        return None;
    }
    let bytes: &[u8] = image.bytes_from(target, MAX_STRING_SCAN_BYTES)?;
    narrow_string(bytes).or_else(|| wide_string(bytes)).map(
        |(kind, text, truncated): (ConstantKind, String, bool)| Constant {
            kind,
            target,
            values: vec![text],
            truncated,
        },
    )
}

fn printable(c: char) -> bool {
    !c.is_control() || matches!(c, '\t' | '\n' | '\r')
}

fn shortened(text: &str) -> (String, bool) {
    let mut chars: std::str::Chars<'_> = text.chars();
    let head: String = chars.by_ref().take(MAX_STRING_CHARS).collect();
    (head, chars.next().is_some())
}

fn narrow_string(bytes: &[u8]) -> Option<(ConstantKind, String, bool)> {
    let end: usize = bytes.iter().position(|byte: &u8| *byte == 0)?;
    let text: &str = std::str::from_utf8(&bytes[..end]).ok()?;
    if text.chars().count() < MIN_STRING_CHARS || !text.chars().all(printable) {
        return None;
    }
    let kind: ConstantKind = if text.is_ascii() {
        ConstantKind::Ascii
    } else {
        ConstantKind::Utf8
    };
    let (head, truncated): (String, bool) = shortened(text);
    Some((kind, head, truncated))
}

fn wide_string(bytes: &[u8]) -> Option<(ConstantKind, String, bool)> {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair: &[u8]| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|unit: &u16| *unit != 0)
        .collect();
    if units.len() * 2 + 2 > bytes.len() {
        return None;
    }
    let text: String = char::decode_utf16(units.iter().copied())
        .collect::<Result<String, std::char::DecodeUtf16Error>>()
        .ok()?;
    if text.chars().count() < MIN_STRING_CHARS || !text.chars().all(printable) {
        return None;
    }
    let (head, truncated): (String, bool) = shortened(&text);
    Some((ConstantKind::Utf16, head, truncated))
}

pub(crate) fn annotate(
    image: &Image<'_>,
    instruction: &Instruction,
    factory: &mut InstructionInfoFactory,
) -> Option<Constant> {
    let reference: MemoryReference = image_memory_reference(image, instruction, factory)?;
    if instruction.mnemonic() == Mnemonic::Lea {
        return string_constant(image, reference.target);
    }
    if reference.access == OpAccess::NoMemAccess {
        return None;
    }
    loaded_constant(image, instruction, reference.target).map(|(constant, _, _)| constant)
}

#[derive(Debug, Serialize)]
pub(crate) struct ListedInstruction {
    pub(crate) rva: u64,
    pub(crate) bytes: String,
    pub(crate) text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) constant: Option<Constant>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) indexed_strings: Vec<IndexedStringAnnotation>,
}

impl ListedInstruction {
    pub(crate) fn line(&self) -> String {
        let mut line: String = self.constant.as_ref().map_or_else(
            || format!("{:#x}: {}", self.rva, self.text),
            |constant: &Constant| {
                format!("{:#x}: {}  ; {}", self.rva, self.text, constant.render())
            },
        );
        for annotation in &self.indexed_strings {
            let escaped: String = format!("{:?}", annotation.literal);
            let _ = write!(
                line,
                "  ; indexed-string index {} via {:#x}: {escaped}",
                annotation.index, annotation.accessor
            );
        }
        line
    }
}

fn listing_formatter() -> NasmFormatter {
    let mut formatter: NasmFormatter = NasmFormatter::new();
    formatter
        .options_mut()
        .set_space_after_operand_separator(true);
    formatter
}

pub(crate) fn list_scope(
    image: &Image<'_>,
    scope: &Scope,
) -> miette::Result<Vec<ListedInstruction>> {
    let mut formatter: NasmFormatter = listing_formatter();
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
    let mut out: Vec<ListedInstruction> = Vec::new();
    let mut ranges: Vec<CodeRange> = scope.ranges();
    ranges.sort_by_key(|range: &CodeRange| range.start);
    for range in ranges {
        let code: &[u8] = image.code_range(range.start, range.end)?;
        for instruction in decode_range(image, range)? {
            let offset: usize = (instruction.ip() - range.start) as usize;
            let raw: &[u8] = code
                .get(offset..offset.saturating_add(instruction.len()))
                .unwrap_or_default();
            let mut text: String = String::new();
            formatter.format(&instruction, &mut text);
            out.push(ListedInstruction {
                rva: instruction.ip(),
                bytes: raw.iter().fold(
                    String::with_capacity(raw.len() * 2),
                    |mut hex: String, byte: &u8| {
                        let _ = write!(hex, "{byte:02x}");
                        hex
                    },
                ),
                text,
                constant: annotate(image, &instruction, &mut factory),
                indexed_strings: Vec::new(),
            });
        }
    }
    Ok(out)
}

pub(crate) fn branch_targets(image: &Image<'_>, scope: &Scope) -> miette::Result<BTreeSet<u64>> {
    let mut targets: BTreeSet<u64> = BTreeSet::new();
    for range in scope.ranges() {
        for instruction in decode_range(image, range)? {
            if is_near_branch(&instruction) {
                targets.insert(instruction.near_branch_target());
            }
        }
    }
    Ok(targets)
}

const fn is_near_branch(instruction: &Instruction) -> bool {
    matches!(
        instruction.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueKind {
    F32,
    F64,
    U32,
    U64,
}

impl ValueKind {
    const fn width(self) -> usize {
        match self {
            Self::F32 | Self::U32 => 4,
            Self::F64 | Self::U64 => 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConstValue {
    pub(crate) kind: ValueKind,
    pub(crate) bits: u64,
}

impl ConstValue {
    pub(crate) fn parse(raw: &str) -> miette::Result<Self> {
        let trimmed: &str = raw.trim();
        let Some((label, value)): Option<(&str, &str)> = trimmed.split_once(':') else {
            return Err(miette::miette!(
                "DR-NATIVE-0311: const-users takes f32:<v>, f64:<v>, u32:<v> or u64:<v>, got {:?}",
                trimmed.chars().take(MAX_SELECTOR_BYTES).collect::<String>()
            ));
        };
        let kind: ValueKind = match label.trim().to_ascii_lowercase().as_str() {
            "f32" => ValueKind::F32,
            "f64" => ValueKind::F64,
            "u32" => ValueKind::U32,
            "u64" => ValueKind::U64,
            _ => {
                return Err(miette::miette!(
                    "DR-NATIVE-0311: const-users value kind {:?} is not one of f32, f64, u32, u64",
                    label.chars().take(MAX_SELECTOR_BYTES).collect::<String>()
                ));
            }
        };
        let value: &str = value.trim();
        let bad = || {
            miette::miette!(
                "DR-NATIVE-0311: {:?} is not a valid {} value",
                value.chars().take(MAX_SELECTOR_BYTES).collect::<String>(),
                label.trim()
            )
        };
        let hex: Option<&str> = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"));
        let bits: u64 = match (kind, hex) {
            (ValueKind::F32 | ValueKind::U32, Some(digits)) => {
                u64::from(u32::from_str_radix(digits, 16).map_err(|_| bad())?)
            }
            (ValueKind::F64 | ValueKind::U64, Some(digits)) => {
                u64::from_str_radix(digits, 16).map_err(|_| bad())?
            }
            (ValueKind::F32, None) => u64::from(value.parse::<f32>().map_err(|_| bad())?.to_bits()),
            (ValueKind::F64, None) => value.parse::<f64>().map_err(|_| bad())?.to_bits(),
            (ValueKind::U32, None) => u64::from(value.parse::<u32>().map_err(|_| bad())?),
            (ValueKind::U64, None) => value.parse::<u64>().map_err(|_| bad())?,
        };
        Ok(Self { kind, bits })
    }

    pub(crate) const fn width(self) -> usize {
        self.kind.width()
    }

    pub(crate) fn display(self) -> String {
        match self.kind {
            ValueKind::F32 => format!("f32:{}", f32::from_bits(self.bits as u32)),
            ValueKind::F64 => format!("f64:{}", f64::from_bits(self.bits)),
            ValueKind::U32 => format!("u32:{:#x}", self.bits),
            ValueKind::U64 => format!("u64:{:#x}", self.bits),
        }
    }
}

pub(crate) fn parse_displacements(raw: &str) -> miette::Result<Vec<i64>> {
    let mut out: BTreeSet<i64> = BTreeSet::new();
    for (index, part) in raw.split(',').enumerate() {
        if index >= MAX_FIELD_DISPLACEMENTS {
            return Err(miette::miette!(
                "DR-NATIVE-0312: field-users takes at most {MAX_FIELD_DISPLACEMENTS} displacements"
            ));
        }
        let trimmed: &str = part.trim();
        let (negative, magnitude): (bool, &str) = trimmed
            .strip_prefix('-')
            .map_or((false, trimmed), |rest: &str| (true, rest));
        let value: u64 = parse_rva(magnitude, "field-users displacement").map_err(|_| {
            miette::miette!(
                "DR-NATIVE-0312: field-users displacement {:?} is not hexadecimal such as 0x1c",
                trimmed.chars().take(MAX_SELECTOR_BYTES).collect::<String>()
            )
        })?;
        let signed: i64 = i64::try_from(value).map_err(|_| {
            miette::miette!(
                "DR-NATIVE-0312: field-users displacement {trimmed} does not fit in 63 bits"
            )
        })?;
        out.insert(if negative { -signed } else { signed });
    }
    Ok(out.into_iter().collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SiteKind {
    Call,
    Jump,
    Read,
    Write,
    ReadWrite,
    Address,
    Immediate,
    ConstantLoad,
    Field,
}

impl SiteKind {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Jump => "jump",
            Self::Read => "read",
            Self::Write => "write",
            Self::ReadWrite => "read-write",
            Self::Address => "address",
            Self::Immediate => "immediate",
            Self::ConstantLoad => "constant-load",
            Self::Field => "field",
        }
    }

    const fn of_access(access: OpAccess) -> Self {
        match access {
            OpAccess::Write | OpAccess::CondWrite => Self::Write,
            OpAccess::ReadWrite | OpAccess::ReadCondWrite => Self::ReadWrite,
            OpAccess::NoMemAccess => Self::Address,
            _ => Self::Read,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Site {
    pub(crate) rva: u64,
    pub(crate) kind: SiteKind,
    pub(crate) instruction: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct FunctionSites {
    pub(crate) function: String,
    pub(crate) function_rva: u64,
    pub(crate) range_source: RangeSource,
    pub(crate) sites: Vec<Site>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct XrefSite {
    pub(crate) rva: u64,
    pub(crate) kind: SiteKind,
    pub(crate) instruction: String,
    pub(crate) function: String,
    pub(crate) function_rva: u64,
}

#[derive(Debug, Clone)]
pub(crate) enum AddressQuery {
    XrefsTo(u64),
    ConstUsers(ConstValue),
    FieldUsers(Vec<i64>),
}

impl AddressQuery {
    pub(crate) fn parse(expr: &str) -> miette::Result<Option<Self>> {
        let trimmed: &str = expr.trim();
        let (verb, rest): (&str, &str) = trimmed
            .split_once(char::is_whitespace)
            .map_or((trimmed, ""), |(verb, rest): (&str, &str)| {
                (verb, rest.trim())
            });
        let normalized: String = verb.to_ascii_lowercase().replace('_', "-");
        match normalized.as_str() {
            "xrefs-to" | "xrefsto" | "xrefs" | "refs"
                if rest.starts_with("0x") || rest.starts_with("0X") =>
            {
                Ok(Some(Self::XrefsTo(parse_rva(rest, "xrefs-to address")?)))
            }
            "const-users" | "constant-users" => {
                Ok(Some(Self::ConstUsers(ConstValue::parse(rest)?)))
            }
            "field-users" => {
                if rest.is_empty() {
                    return Err(miette::miette!(
                        "DR-NATIVE-0312: field-users needs one or more displacements such as 0x10,0x1c"
                    ));
                }
                Ok(Some(Self::FieldUsers(parse_displacements(rest)?)))
            }
            _ => Ok(None),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "query", rename_all = "kebab-case")]
pub(crate) enum AddressQueryResult {
    XrefsTo {
        rva: u64,
        va: u64,
        matches: Vec<XrefSite>,
        truncated: bool,
        functions_scanned: usize,
    },
    ConstUsers {
        value: String,
        width: usize,
        bits: u64,
        matches: Vec<FunctionSites>,
        truncated: bool,
        functions_scanned: usize,
    },
    FieldUsers {
        displacements: Vec<i64>,
        matches: Vec<FunctionSites>,
        truncated: bool,
        functions_scanned: usize,
    },
}

fn immediates(instruction: &Instruction) -> impl Iterator<Item = (usize, u64)> + '_ {
    (0..instruction.op_count()).filter_map(move |operand: u32| {
        let width: usize = match instruction.op_kind(operand) {
            OpKind::Immediate8 | OpKind::Immediate8_2nd => 1,
            OpKind::Immediate16 | OpKind::Immediate8to16 => 2,
            OpKind::Immediate32 | OpKind::Immediate8to32 => 4,
            OpKind::Immediate64 | OpKind::Immediate8to64 | OpKind::Immediate32to64 => 8,
            _ => return None,
        };
        let value: u64 = instruction.immediate(operand);
        let masked: u64 = if width == 8 {
            value
        } else {
            value & ((1u64 << (width * 8)) - 1)
        };
        Some((width, masked))
    })
}

fn field_displacement(image: &Image<'_>, instruction: &Instruction) -> Option<i64> {
    let has_memory: bool = (0..instruction.op_count())
        .any(|operand: u32| instruction.op_kind(operand) == OpKind::Memory);
    if !has_memory {
        return None;
    }
    let base: Register = instruction.memory_base();
    if matches!(
        base,
        Register::None
            | Register::RIP
            | Register::EIP
            | Register::RSP
            | Register::ESP
            | Register::SP
    ) {
        return None;
    }
    Some(if image.bitness == 32 {
        i64::from(instruction.memory_displacement32() as i32)
    } else {
        instruction.memory_displacement64() as i64
    })
}

struct Scan<'image, 'data> {
    image: &'image Image<'data>,
    formatter: NasmFormatter,
    factory: InstructionInfoFactory,
    sites: usize,
    truncated: bool,
}

impl Scan<'_, '_> {
    fn text(&mut self, instruction: &Instruction) -> String {
        let mut text: String = String::new();
        self.formatter.format(instruction, &mut text);
        text
    }

    const fn admit(&mut self) -> bool {
        if self.sites >= MAX_QUERY_MATCHES {
            self.truncated = true;
            return false;
        }
        self.sites += 1;
        true
    }
}

pub(crate) fn run_query(
    image: &Image<'_>,
    index: &mut FunctionIndex,
    query: &AddressQuery,
) -> miette::Result<AddressQueryResult> {
    index.add_discovered(image)?;
    let total: u64 = index.functions().map(FunctionEntry::byte_len).sum();
    if total > MAX_QUERY_SCAN_BYTES {
        return Err(miette::miette!(
            "DR-NATIVE-0313: the image's functions span {total} bytes, over the {MAX_QUERY_SCAN_BYTES}-byte query scan limit"
        ));
    }
    let mut scan: Scan<'_, '_> = Scan {
        image,
        formatter: listing_formatter(),
        factory: InstructionInfoFactory::new(),
        sites: 0,
        truncated: false,
    };
    let mut xrefs: Vec<XrefSite> = Vec::new();
    let mut grouped: Vec<FunctionSites> = Vec::new();
    let mut functions_scanned: usize = 0;
    'functions: for entry in index.functions() {
        functions_scanned += 1;
        let mut sites: Vec<Site> = Vec::new();
        let mut seen_displacements: BTreeSet<i64> = BTreeSet::new();
        for range in entry.ranges() {
            for instruction in decode_range(image, range)? {
                let kind: Option<SiteKind> = match query {
                    AddressQuery::XrefsTo(rva) => xref_kind(&mut scan, &instruction, *rva),
                    AddressQuery::ConstUsers(value) => const_kind(&mut scan, &instruction, *value),
                    AddressQuery::FieldUsers(wanted) => field_displacement(image, &instruction)
                        .filter(|displacement: &i64| wanted.binary_search(displacement).is_ok())
                        .map(|displacement: i64| {
                            seen_displacements.insert(displacement);
                            SiteKind::Field
                        }),
                };
                let Some(kind) = kind else {
                    continue;
                };
                if !scan.admit() {
                    break 'functions;
                }
                let text: String = scan.text(&instruction);
                if let AddressQuery::XrefsTo(_) = query {
                    xrefs.push(XrefSite {
                        rva: instruction.ip(),
                        kind,
                        instruction: text,
                        function: entry.name.clone(),
                        function_rva: entry.start,
                    });
                } else {
                    sites.push(Site {
                        rva: instruction.ip(),
                        kind,
                        instruction: text,
                    });
                }
            }
        }
        let keep: bool = match query {
            AddressQuery::XrefsTo(_) => false,
            AddressQuery::ConstUsers(_) => !sites.is_empty(),
            AddressQuery::FieldUsers(wanted) => seen_displacements.len() == wanted.len(),
        };
        if keep {
            sites.sort_by_key(|site: &Site| site.rva);
            grouped.push(FunctionSites {
                function: entry.name.clone(),
                function_rva: entry.start,
                range_source: entry.source,
                sites,
            });
        }
    }
    let truncated: bool = scan.truncated;
    xrefs.sort_by_key(|site: &XrefSite| site.rva);
    Ok(match query {
        AddressQuery::XrefsTo(rva) => AddressQueryResult::XrefsTo {
            rva: *rva,
            va: image.va(*rva),
            matches: xrefs,
            truncated,
            functions_scanned,
        },
        AddressQuery::ConstUsers(value) => AddressQueryResult::ConstUsers {
            value: value.display(),
            width: value.width(),
            bits: value.bits,
            matches: grouped,
            truncated,
            functions_scanned,
        },
        AddressQuery::FieldUsers(displacements) => AddressQueryResult::FieldUsers {
            displacements: displacements.clone(),
            matches: grouped,
            truncated,
            functions_scanned,
        },
    })
}

fn xref_kind(scan: &mut Scan<'_, '_>, instruction: &Instruction, rva: u64) -> Option<SiteKind> {
    if is_near_branch(instruction) && instruction.near_branch_target() == rva {
        return Some(if instruction.flow_control() == FlowControl::Call {
            SiteKind::Call
        } else {
            SiteKind::Jump
        });
    }
    if let Some(reference) = image_memory_reference(scan.image, instruction, &mut scan.factory)
        && reference.target == rva
    {
        return Some(SiteKind::of_access(reference.access));
    }
    let va: u64 = scan.image.va(rva);
    if va < LOWEST_MAPPABLE_ADDRESS {
        return None;
    }
    immediates(instruction)
        .any(|(width, value): (usize, u64)| width >= 4 && value == va)
        .then_some(SiteKind::Immediate)
}

fn const_kind(
    scan: &mut Scan<'_, '_>,
    instruction: &Instruction,
    value: ConstValue,
) -> Option<SiteKind> {
    if immediates(instruction)
        .any(|(width, bits): (usize, u64)| width == value.width() && bits == value.bits)
    {
        return Some(SiteKind::Immediate);
    }
    let reference: MemoryReference =
        image_memory_reference(scan.image, instruction, &mut scan.factory)?;
    if reference.access == OpAccess::NoMemAccess {
        return None;
    }
    let (_, lanes, width): (Constant, Vec<u64>, usize) =
        loaded_constant(scan.image, instruction, reference.target)?;
    (width == value.width() && lanes.contains(&value.bits)).then_some(SiteKind::ConstantLoad)
}
