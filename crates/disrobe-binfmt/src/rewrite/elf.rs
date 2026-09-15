use disrobe_bytes::{ByteReadError, ByteReader, Endian};

use crate::error::Result;
use crate::native::NativeFormat;

use super::encode::FieldWriter;
use super::{
    DerivedKind, DerivedValue, ImagePlan, PlanBuilder, Structure, bounded_entries, rewrite_error,
    rewrite_read_error, unsupported,
};

const IDENT_SIZE: u64 = 16;
const HEADER_SIZE_32: u64 = 52;
const HEADER_SIZE_64: u64 = 64;
const PHDR_SIZE_32: u64 = 32;
const PHDR_SIZE_64: u64 = 56;
const SHDR_SIZE_32: u64 = 40;
const SHDR_SIZE_64: u64 = 64;
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const CLASS_32: u8 = 1;
const CLASS_64: u8 = 2;
const DATA_LSB: u8 = 1;
const DATA_MSB: u8 = 2;
const PN_XNUM: u16 = 0xFFFF;
const PT_NOTE: u32 = 4;
const NT_GNU_BUILD_ID: u32 = 3;
const GNU_NOTE_NAME: &[u8] = b"GNU\0";
const MAX_NOTES_PER_SEGMENT: usize = 1_024;
const MAX_NOTE_SEGMENT_BYTES: u64 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfIdent {
    pub magic: [u8; 4],
    pub class: u8,
    pub data: u8,
    pub version: u8,
    pub osabi: u8,
    pub abiversion: u8,
    pub pad: [u8; 7],
}

impl ElfIdent {
    fn encode(&self, writer: &mut FieldWriter<'_>) {
        writer.bytes(&self.magic);
        writer.u8(self.class);
        writer.u8(self.data);
        writer.u8(self.version);
        writer.u8(self.osabi);
        writer.u8(self.abiversion);
        writer.bytes(&self.pad);
    }

    fn read(reader: &mut ByteReader<'_>) -> Result<Self> {
        let raw: &[u8] = reader
            .read_bytes(IDENT_SIZE as usize)
            .map_err(|error: ByteReadError| rewrite_read_error("the ELF identification", error))?;
        let magic: [u8; 4] = raw
            .get(..4)
            .and_then(|slice: &[u8]| <[u8; 4]>::try_from(slice).ok())
            .ok_or_else(|| rewrite_error("the ELF identification is short"))?;
        let pad: [u8; 7] = raw
            .get(9..16)
            .and_then(|slice: &[u8]| <[u8; 7]>::try_from(slice).ok())
            .ok_or_else(|| rewrite_error("the ELF identification is short"))?;
        let byte_at = |index: usize| -> Result<u8> {
            raw.get(index)
                .copied()
                .ok_or_else(|| rewrite_error("the ELF identification is short"))
        };

        Ok(Self {
            magic,
            class: byte_at(4)?,
            data: byte_at(5)?,
            version: byte_at(6)?,
            osabi: byte_at(7)?,
            abiversion: byte_at(8)?,
            pad,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfHeader {
    pub endian: Endian,
    pub wide: bool,
    pub ident: ElfIdent,
    pub kind: u16,
    pub machine: u16,
    pub version: u32,
    pub entry: u64,
    pub phoff: u64,
    pub shoff: u64,
    pub flags: u32,
    pub ehsize: u16,
    pub phentsize: u16,
    pub phnum: u16,
    pub shentsize: u16,
    pub shnum: u16,
    pub shstrndx: u16,
}

impl ElfHeader {
    pub(super) const fn encoded_len(&self) -> u64 {
        if self.wide {
            HEADER_SIZE_64
        } else {
            HEADER_SIZE_32
        }
    }

    pub(super) fn encode(&self, writer: &mut FieldWriter<'_>) {
        self.ident.encode(writer);
        writer.u16(self.kind);
        writer.u16(self.machine);
        writer.u32(self.version);
        if self.wide {
            writer.u64(self.entry);
            writer.u64(self.phoff);
            writer.u64(self.shoff);
        } else {
            writer.u32(self.entry as u32);
            writer.u32(self.phoff as u32);
            writer.u32(self.shoff as u32);
        }
        writer.u32(self.flags);
        writer.u16(self.ehsize);
        writer.u16(self.phentsize);
        writer.u16(self.phnum);
        writer.u16(self.shentsize);
        writer.u16(self.shnum);
        writer.u16(self.shstrndx);
    }

    fn read(bytes: &[u8]) -> Result<Self> {
        let mut reader: ByteReader<'_> = ByteReader::new(bytes);
        let ident: ElfIdent = ElfIdent::read(&mut reader)?;
        if ident.magic != ELF_MAGIC {
            return Err(rewrite_error("the ELF magic is not `\\x7fELF`"));
        }
        let wide: bool = match ident.class {
            CLASS_32 => false,
            CLASS_64 => true,
            other => {
                return Err(rewrite_error(format!(
                    "EI_CLASS {other} is neither ELFCLASS32 nor ELFCLASS64"
                )));
            }
        };
        let endian: Endian = match ident.data {
            DATA_LSB => Endian::Little,
            DATA_MSB => Endian::Big,
            other => {
                return Err(rewrite_error(format!(
                    "EI_DATA {other} is neither ELFDATA2LSB nor ELFDATA2MSB"
                )));
            }
        };

        let subject: &str = "the ELF header";
        let word = |reader: &mut ByteReader<'_>| -> Result<u16> {
            reader
                .read_u16(endian)
                .map_err(|error: ByteReadError| rewrite_read_error(subject, error))
        };
        let kind: u16 = word(&mut reader)?;
        let machine: u16 = word(&mut reader)?;
        let version: u32 = reader
            .read_u32(endian)
            .map_err(|error: ByteReadError| rewrite_read_error(subject, error))?;
        let address = |reader: &mut ByteReader<'_>| -> Result<u64> {
            if wide {
                reader
                    .read_u64(endian)
                    .map_err(|error: ByteReadError| rewrite_read_error(subject, error))
            } else {
                reader
                    .read_u32(endian)
                    .map(u64::from)
                    .map_err(|error: ByteReadError| rewrite_read_error(subject, error))
            }
        };
        let entry: u64 = address(&mut reader)?;
        let phoff: u64 = address(&mut reader)?;
        let shoff: u64 = address(&mut reader)?;
        let flags: u32 = reader
            .read_u32(endian)
            .map_err(|error: ByteReadError| rewrite_read_error(subject, error))?;
        let ehsize: u16 = word(&mut reader)?;
        let phentsize: u16 = word(&mut reader)?;
        let phnum: u16 = word(&mut reader)?;
        let shentsize: u16 = word(&mut reader)?;
        let shnum: u16 = word(&mut reader)?;
        let shstrndx: u16 = word(&mut reader)?;

        Ok(Self {
            endian,
            wide,
            ident,
            kind,
            machine,
            version,
            entry,
            phoff,
            shoff,
            flags,
            ehsize,
            phentsize,
            phnum,
            shentsize,
            shnum,
            shstrndx,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfProgramHeader {
    pub kind: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfProgramHeaders {
    pub endian: Endian,
    pub wide: bool,
    pub entries: Vec<ElfProgramHeader>,
}

impl ElfProgramHeaders {
    pub(super) const fn encoded_len(&self) -> u64 {
        let stride: u64 = if self.wide {
            PHDR_SIZE_64
        } else {
            PHDR_SIZE_32
        };
        (self.entries.len() as u64).saturating_mul(stride)
    }

    pub(super) fn encode(&self, writer: &mut FieldWriter<'_>) {
        for entry in &self.entries {
            writer.u32(entry.kind);
            if self.wide {
                writer.u32(entry.flags);
                writer.u64(entry.offset);
                writer.u64(entry.vaddr);
                writer.u64(entry.paddr);
                writer.u64(entry.filesz);
                writer.u64(entry.memsz);
                writer.u64(entry.align);
            } else {
                writer.u32(entry.offset as u32);
                writer.u32(entry.vaddr as u32);
                writer.u32(entry.paddr as u32);
                writer.u32(entry.filesz as u32);
                writer.u32(entry.memsz as u32);
                writer.u32(entry.flags);
                writer.u32(entry.align as u32);
            }
        }
    }

    fn read(reader: &mut ByteReader<'_>, endian: Endian, wide: bool, count: usize) -> Result<Self> {
        let subject: &str = "a program header";
        let dword = |reader: &mut ByteReader<'_>| -> Result<u32> {
            reader
                .read_u32(endian)
                .map_err(|error: ByteReadError| rewrite_read_error(subject, error))
        };
        let wide_field = |reader: &mut ByteReader<'_>| -> Result<u64> {
            reader
                .read_u64(endian)
                .map_err(|error: ByteReadError| rewrite_read_error(subject, error))
        };
        let mut entries: Vec<ElfProgramHeader> = Vec::with_capacity(count);
        for _ in 0..count {
            let kind: u32 = dword(reader)?;
            let entry: ElfProgramHeader = if wide {
                let flags: u32 = dword(reader)?;
                ElfProgramHeader {
                    kind,
                    flags,
                    offset: wide_field(reader)?,
                    vaddr: wide_field(reader)?,
                    paddr: wide_field(reader)?,
                    filesz: wide_field(reader)?,
                    memsz: wide_field(reader)?,
                    align: wide_field(reader)?,
                }
            } else {
                let offset: u32 = dword(reader)?;
                let vaddr: u32 = dword(reader)?;
                let paddr: u32 = dword(reader)?;
                let filesz: u32 = dword(reader)?;
                let memsz: u32 = dword(reader)?;
                let flags: u32 = dword(reader)?;
                let align: u32 = dword(reader)?;
                ElfProgramHeader {
                    kind,
                    flags,
                    offset: u64::from(offset),
                    vaddr: u64::from(vaddr),
                    paddr: u64::from(paddr),
                    filesz: u64::from(filesz),
                    memsz: u64::from(memsz),
                    align: u64::from(align),
                }
            };
            entries.push(entry);
        }

        Ok(Self {
            endian,
            wide,
            entries,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfSectionHeader {
    pub name: u32,
    pub kind: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub addralign: u64,
    pub entsize: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSectionHeaders {
    pub endian: Endian,
    pub wide: bool,
    pub entries: Vec<ElfSectionHeader>,
}

impl ElfSectionHeaders {
    pub(super) const fn encoded_len(&self) -> u64 {
        let stride: u64 = if self.wide {
            SHDR_SIZE_64
        } else {
            SHDR_SIZE_32
        };
        (self.entries.len() as u64).saturating_mul(stride)
    }

    pub(super) fn encode(&self, writer: &mut FieldWriter<'_>) {
        for entry in &self.entries {
            writer.u32(entry.name);
            writer.u32(entry.kind);
            if self.wide {
                writer.u64(entry.flags);
                writer.u64(entry.addr);
                writer.u64(entry.offset);
                writer.u64(entry.size);
                writer.u32(entry.link);
                writer.u32(entry.info);
                writer.u64(entry.addralign);
                writer.u64(entry.entsize);
            } else {
                writer.u32(entry.flags as u32);
                writer.u32(entry.addr as u32);
                writer.u32(entry.offset as u32);
                writer.u32(entry.size as u32);
                writer.u32(entry.link);
                writer.u32(entry.info);
                writer.u32(entry.addralign as u32);
                writer.u32(entry.entsize as u32);
            }
        }
    }

    fn read(reader: &mut ByteReader<'_>, endian: Endian, wide: bool, count: usize) -> Result<Self> {
        let subject: &str = "a section header";
        let dword = |reader: &mut ByteReader<'_>| -> Result<u32> {
            reader
                .read_u32(endian)
                .map_err(|error: ByteReadError| rewrite_read_error(subject, error))
        };
        let wide_field = |reader: &mut ByteReader<'_>| -> Result<u64> {
            reader
                .read_u64(endian)
                .map_err(|error: ByteReadError| rewrite_read_error(subject, error))
        };
        let mut entries: Vec<ElfSectionHeader> = Vec::with_capacity(count);
        for _ in 0..count {
            let name: u32 = dword(reader)?;
            let kind: u32 = dword(reader)?;
            let entry: ElfSectionHeader = if wide {
                let flags: u64 = wide_field(reader)?;
                let addr: u64 = wide_field(reader)?;
                let offset: u64 = wide_field(reader)?;
                let size: u64 = wide_field(reader)?;
                let link: u32 = dword(reader)?;
                let info: u32 = dword(reader)?;
                ElfSectionHeader {
                    name,
                    kind,
                    flags,
                    addr,
                    offset,
                    size,
                    link,
                    info,
                    addralign: wide_field(reader)?,
                    entsize: wide_field(reader)?,
                }
            } else {
                ElfSectionHeader {
                    name,
                    kind,
                    flags: u64::from(dword(reader)?),
                    addr: u64::from(dword(reader)?),
                    offset: u64::from(dword(reader)?),
                    size: u64::from(dword(reader)?),
                    link: dword(reader)?,
                    info: dword(reader)?,
                    addralign: u64::from(dword(reader)?),
                    entsize: u64::from(dword(reader)?),
                }
            };
            entries.push(entry);
        }

        Ok(Self {
            endian,
            wide,
            entries,
        })
    }
}

pub(super) fn plan(bytes: &[u8], format: NativeFormat) -> Result<ImagePlan> {
    let file_len: u64 = u64::try_from(bytes.len())
        .map_err(|_error: std::num::TryFromIntError| rewrite_error("file length overflows"))?;
    let header: ElfHeader = ElfHeader::read(bytes)?;
    let mut builder: PlanBuilder = PlanBuilder::new(format, file_len);
    builder.push(0, Structure::ElfHeader(header))?;

    let phdr_stride: u64 = if header.wide {
        PHDR_SIZE_64
    } else {
        PHDR_SIZE_32
    };
    let shdr_stride: u64 = if header.wide {
        SHDR_SIZE_64
    } else {
        SHDR_SIZE_32
    };

    let sections: Option<ElfSectionHeaders> =
        read_section_headers(bytes, &header, shdr_stride, file_len, format)?;
    let program_count: u64 = resolve_program_count(&header, sections.as_ref());

    let program_headers: Option<ElfProgramHeaders> =
        read_program_headers(bytes, &header, phdr_stride, file_len, format, program_count)?;
    if let Some(table) = program_headers.as_ref() {
        builder.push(header.phoff, Structure::ElfProgramHeaders(table.clone()))?;
    }

    if let Some(table) = sections {
        builder.push(header.shoff, Structure::ElfSectionHeaders(table))?;
    }

    if let Some(table) = program_headers.as_ref() {
        record_build_ids(&mut builder, bytes, table, file_len)?;
    }

    builder.finish()
}

fn read_program_headers(
    bytes: &[u8],
    header: &ElfHeader,
    phdr_stride: u64,
    file_len: u64,
    format: NativeFormat,
    program_count: u64,
) -> Result<Option<ElfProgramHeaders>> {
    if program_count == 0 || header.phoff == 0 {
        return Ok(None);
    }
    if u64::from(header.phentsize) != phdr_stride {
        return Err(unsupported(
            format,
            format!(
                "phentsize {} is not the {phdr_stride} byte program header this class defines, so \
                 its trailing bytes have no typed model in this writer",
                header.phentsize
            ),
        ));
    }
    let available: u64 = file_len.saturating_sub(header.phoff);
    let count: usize = bounded_entries(
        format,
        "the program header table",
        program_count,
        phdr_stride,
        available,
    )?;
    let index: usize = usize::try_from(header.phoff)
        .map_err(|_error: std::num::TryFromIntError| rewrite_error("phoff overflows usize"))?;
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(index)
        .map_err(|error: ByteReadError| rewrite_read_error("the program header table", error))?;

    Ok(Some(ElfProgramHeaders::read(
        &mut reader,
        header.endian,
        header.wide,
        count,
    )?))
}

fn read_section_headers(
    bytes: &[u8],
    header: &ElfHeader,
    shdr_stride: u64,
    file_len: u64,
    format: NativeFormat,
) -> Result<Option<ElfSectionHeaders>> {
    if header.shoff == 0 {
        return Ok(None);
    }
    if u64::from(header.shentsize) != shdr_stride {
        return Err(unsupported(
            format,
            format!(
                "shentsize {} is not the {shdr_stride} byte section header this class defines, \
                 so its trailing bytes have no typed model in this writer",
                header.shentsize
            ),
        ));
    }

    let index: usize = usize::try_from(header.shoff)
        .map_err(|_error: std::num::TryFromIntError| rewrite_error("shoff overflows usize"))?;
    let available: u64 = file_len.saturating_sub(header.shoff);
    let declared: u64 = resolve_section_count(bytes, header, index)?;
    if declared == 0 {
        return Ok(None);
    }

    let count: usize = bounded_entries(
        format,
        "the section header table",
        declared,
        shdr_stride,
        available,
    )?;
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(index)
        .map_err(|error: ByteReadError| rewrite_read_error("the section header table", error))?;

    Ok(Some(ElfSectionHeaders::read(
        &mut reader,
        header.endian,
        header.wide,
        count,
    )?))
}

fn resolve_section_count(bytes: &[u8], header: &ElfHeader, index: usize) -> Result<u64> {
    if header.shnum != 0 {
        return Ok(u64::from(header.shnum));
    }
    let mut probe: ByteReader<'_> = ByteReader::new(bytes);
    probe
        .seek(index)
        .map_err(|error: ByteReadError| rewrite_read_error("the section header table", error))?;
    let first: ElfSectionHeaders =
        ElfSectionHeaders::read(&mut probe, header.endian, header.wide, 1)?;

    Ok(first
        .entries
        .first()
        .map_or(0, |entry: &ElfSectionHeader| entry.size))
}

fn resolve_program_count(header: &ElfHeader, sections: Option<&ElfSectionHeaders>) -> u64 {
    if header.phnum != PN_XNUM {
        return u64::from(header.phnum);
    }
    sections
        .and_then(|table: &ElfSectionHeaders| table.entries.first())
        .map_or_else(
            || u64::from(PN_XNUM),
            |entry: &ElfSectionHeader| u64::from(entry.info),
        )
}

fn record_build_ids(
    builder: &mut PlanBuilder,
    bytes: &[u8],
    table: &ElfProgramHeaders,
    file_len: u64,
) -> Result<()> {
    for segment in &table.entries {
        if segment.kind != PT_NOTE || segment.filesz == 0 {
            continue;
        }
        if segment.filesz > MAX_NOTE_SEGMENT_BYTES {
            return Err(rewrite_error(
                "an ELF note segment exceeds the parsing limit",
            ));
        }
        let Some(end) = segment.offset.checked_add(segment.filesz) else {
            return Err(rewrite_error("an ELF note segment range overflows"));
        };
        if end > file_len {
            return Err(rewrite_error("an ELF note segment exceeds the input"));
        }
        let Some(ranges) = find_build_ids(bytes, table.endian, segment.offset, end) else {
            return Err(rewrite_error("an ELF note segment is malformed"));
        };
        for (desc_start, desc_end) in ranges {
            builder.derive(DerivedValue {
                kind: DerivedKind::ElfGnuBuildId,
                field_start: desc_start,
                field_end: desc_end,
                covered_start: 0,
                covered_end: file_len,
                detail: "the GNU build identifier note is a hash of the linked image and this \
                         writer does not recompute it"
                    .to_owned(),
            });
        }
    }
    Ok(())
}

fn find_build_ids(bytes: &[u8], endian: Endian, start: u64, end: u64) -> Option<Vec<(u64, u64)>> {
    let mut cursor: u64 = start;
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    for _ in 0..MAX_NOTES_PER_SEGMENT {
        if cursor >= end {
            return Some(ranges);
        }
        let index: usize = usize::try_from(cursor).ok()?;
        let mut reader: ByteReader<'_> = ByteReader::new(bytes);
        reader.seek(index).ok()?;
        let namesz: u32 = reader.read_u32(endian).ok()?;
        let descsz: u32 = reader.read_u32(endian).ok()?;
        let note_type: u32 = reader.read_u32(endian).ok()?;
        let name_padded: u64 = u64::from(namesz).checked_next_multiple_of(4)?;
        let desc_padded: u64 = u64::from(descsz).checked_next_multiple_of(4)?;
        let name_start: u64 = cursor.checked_add(12)?;
        let desc_start: u64 = name_start.checked_add(name_padded)?;
        let desc_end: u64 = desc_start.checked_add(u64::from(descsz))?;
        let next: u64 = desc_start.checked_add(desc_padded)?;
        if desc_end > end {
            return None;
        }
        let name_index: usize = usize::try_from(name_start).ok()?;
        let name_end: usize = name_index.checked_add(namesz as usize)?;
        let name: &[u8] = bytes.get(name_index..name_end)?;
        if note_type == NT_GNU_BUILD_ID && name == GNU_NOTE_NAME && descsz != 0 {
            ranges.push((desc_start, desc_end));
        }
        if next <= cursor {
            return None;
        }
        cursor = next;
    }
    (cursor >= end).then_some(ranges)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod build_id_tests {
    use super::find_build_ids;
    use crate::rewrite::{DerivedKind, ImagePlan, plan_native_image};
    use disrobe_bytes::Endian;

    fn elf_with_notes(notes: &[u8]) -> Vec<u8> {
        let note_offset: u64 = 120;
        let mut bytes: Vec<u8> = vec![0; note_offset as usize];
        bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&0xb7_u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&4_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&note_offset.to_le_bytes());
        bytes[96..104].copy_from_slice(&(notes.len() as u64).to_le_bytes());
        bytes[104..112].copy_from_slice(&(notes.len() as u64).to_le_bytes());
        bytes[112..120].copy_from_slice(&4_u64.to_le_bytes());
        bytes.extend_from_slice(notes);
        bytes
    }

    fn variable_note(descriptor: &[u8]) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(16 + descriptor.len());
        bytes.extend_from_slice(&4_u32.to_le_bytes());
        bytes.extend_from_slice(&(descriptor.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(b"GNU\0");
        bytes.extend_from_slice(descriptor);
        bytes
    }

    fn note(descriptor: [u8; 16]) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(32);
        bytes.extend_from_slice(&4_u32.to_le_bytes());
        bytes.extend_from_slice(&16_u32.to_le_bytes());
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(b"GNU\0");
        bytes.extend_from_slice(&descriptor);
        bytes
    }

    #[test]
    fn records_every_build_id_in_a_note_segment() {
        let mut bytes: Vec<u8> = note([0x11; 16]);
        bytes.extend_from_slice(&note([0x22; 16]));

        assert_eq!(
            find_build_ids(&bytes, Endian::Little, 0, bytes.len() as u64),
            Some(vec![(16, 32), (48, 64)])
        );
    }

    #[test]
    fn refuses_a_build_id_descriptor_that_overruns_its_segment() {
        let mut bytes: Vec<u8> = note([0x11; 16]);
        bytes.truncate(24);

        assert_eq!(
            find_build_ids(&bytes, Endian::Little, 0, bytes.len() as u64),
            None
        );
    }

    #[test]
    fn public_plan_records_duplicate_build_ids_for_ambiguity_checks() {
        let mut notes: Vec<u8> = variable_note(&[0x11; 16]);
        notes.extend_from_slice(&variable_note(&[0x22; 16]));

        let plan: ImagePlan =
            plan_native_image(&elf_with_notes(&notes)).expect("plan duplicate build IDs");
        let count: usize = plan
            .derived_values()
            .iter()
            .filter(|value| value.kind == DerivedKind::ElfGnuBuildId)
            .count();

        assert_eq!(count, 2);
    }

    #[test]
    fn public_plan_refuses_a_valid_build_id_followed_by_a_malformed_note() {
        let mut notes: Vec<u8> = variable_note(&[0x11; 16]);
        notes.extend_from_slice(&4_u32.to_le_bytes());
        notes.extend_from_slice(&32_u32.to_le_bytes());
        notes.extend_from_slice(&3_u32.to_le_bytes());
        notes.extend_from_slice(b"GNU\0");

        let error: crate::Error =
            plan_native_image(&elf_with_notes(&notes)).expect_err("malformed trailing note");

        assert!(error.to_string().contains("note segment is malformed"));
    }
}
