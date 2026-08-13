use disrobe_bytes::{ByteReadError, ByteReader};

use crate::error::Result;
use crate::native::NativeFormat;

use super::coff::{COFF_HEADER_SIZE, CoffHeader, plan_header_and_sections};
use super::encode::FieldWriter;
use super::{
    DerivedKind, DerivedValue, ImagePlan, PlanBuilder, Structure, rewrite_error,
    rewrite_read_error, unsupported,
};

const DOS_HEADER_SIZE: u64 = 64;
const PE_SIGNATURE_SIZE: u64 = 4;
const PE_SIGNATURE: u32 = 0x0000_4550;
const OPTIONAL_MAGIC_PE32: u16 = 0x010B;
const OPTIONAL_MAGIC_PE32_PLUS: u16 = 0x020B;
const PE32_FIXED_OPTIONAL: u64 = 0x60;
const PE32_PLUS_FIXED_OPTIONAL: u64 = 0x70;
const DIRECTORY_RECORD_SIZE: u64 = 8;
const CHECKSUM_FIELD_OFFSET: u64 = 0x40;
const CHECKSUM_FIELD_SIZE: u64 = 4;
const CERTIFICATE_DIRECTORY_INDEX: usize = 4;
const MAX_DIRECTORY_SLOTS: u64 = 8_192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeDosHeader {
    pub magic: u16,
    pub cblp: u16,
    pub cp: u16,
    pub crlc: u16,
    pub cparhdr: u16,
    pub minalloc: u16,
    pub maxalloc: u16,
    pub ss: u16,
    pub sp: u16,
    pub csum: u16,
    pub ip: u16,
    pub cs: u16,
    pub lfarlc: u16,
    pub ovno: u16,
    pub res: [u16; 4],
    pub oemid: u16,
    pub oeminfo: u16,
    pub res2: [u16; 10],
    pub lfanew: u32,
}

impl PeDosHeader {
    pub(super) const ENCODED_LEN: u64 = DOS_HEADER_SIZE;

    pub(super) fn encode(&self, writer: &mut FieldWriter<'_>) {
        writer.u16(self.magic);
        writer.u16(self.cblp);
        writer.u16(self.cp);
        writer.u16(self.crlc);
        writer.u16(self.cparhdr);
        writer.u16(self.minalloc);
        writer.u16(self.maxalloc);
        writer.u16(self.ss);
        writer.u16(self.sp);
        writer.u16(self.csum);
        writer.u16(self.ip);
        writer.u16(self.cs);
        writer.u16(self.lfarlc);
        writer.u16(self.ovno);
        writer.u16_slice(&self.res);
        writer.u16(self.oemid);
        writer.u16(self.oeminfo);
        writer.u16_slice(&self.res2);
        writer.u32(self.lfanew);
    }

    fn read(reader: &mut ByteReader<'_>) -> Result<Self> {
        let word = |reader: &mut ByteReader<'_>| -> Result<u16> {
            reader
                .read_u16_le()
                .map_err(|error: ByteReadError| rewrite_read_error("the DOS header", error))
        };
        let magic: u16 = word(reader)?;
        let cblp: u16 = word(reader)?;
        let cp: u16 = word(reader)?;
        let crlc: u16 = word(reader)?;
        let cparhdr: u16 = word(reader)?;
        let minalloc: u16 = word(reader)?;
        let maxalloc: u16 = word(reader)?;
        let ss: u16 = word(reader)?;
        let sp: u16 = word(reader)?;
        let csum: u16 = word(reader)?;
        let ip: u16 = word(reader)?;
        let cs: u16 = word(reader)?;
        let lfarlc: u16 = word(reader)?;
        let ovno: u16 = word(reader)?;
        let mut res: [u16; 4] = [0; 4];
        for slot in &mut res {
            *slot = word(reader)?;
        }
        let oemid: u16 = word(reader)?;
        let oeminfo: u16 = word(reader)?;
        let mut res2: [u16; 10] = [0; 10];
        for slot in &mut res2 {
            *slot = word(reader)?;
        }
        let lfanew: u32 = reader
            .read_u32_le()
            .map_err(|error: ByteReadError| rewrite_read_error("the DOS header", error))?;

        Ok(Self {
            magic,
            cblp,
            cp,
            crlc,
            cparhdr,
            minalloc,
            maxalloc,
            ss,
            sp,
            csum,
            ip,
            cs,
            lfarlc,
            ovno,
            res,
            oemid,
            oeminfo,
            res2,
            lfanew,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeSignature {
    pub magic: u32,
}

impl PeSignature {
    pub(super) const ENCODED_LEN: u64 = PE_SIGNATURE_SIZE;

    pub(super) fn encode(self, writer: &mut FieldWriter<'_>) {
        writer.u32(self.magic);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeOptionalHeader {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: Option<u32>,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

impl PeOptionalHeader {
    #[must_use]
    pub const fn is_pe32_plus(&self) -> bool {
        self.magic == OPTIONAL_MAGIC_PE32_PLUS
    }

    pub(super) const fn encoded_len(&self) -> u64 {
        if self.is_pe32_plus() {
            PE32_PLUS_FIXED_OPTIONAL
        } else {
            PE32_FIXED_OPTIONAL
        }
    }

    pub(super) fn encode(&self, writer: &mut FieldWriter<'_>) {
        let wide: bool = self.is_pe32_plus();
        writer.u16(self.magic);
        writer.u8(self.major_linker_version);
        writer.u8(self.minor_linker_version);
        writer.u32(self.size_of_code);
        writer.u32(self.size_of_initialized_data);
        writer.u32(self.size_of_uninitialized_data);
        writer.u32(self.address_of_entry_point);
        writer.u32(self.base_of_code);
        if let Some(base_of_data) = self.base_of_data {
            writer.u32(base_of_data);
        }
        if wide {
            writer.u64(self.image_base);
        } else {
            writer.u32(self.image_base as u32);
        }
        writer.u32(self.section_alignment);
        writer.u32(self.file_alignment);
        writer.u16(self.major_operating_system_version);
        writer.u16(self.minor_operating_system_version);
        writer.u16(self.major_image_version);
        writer.u16(self.minor_image_version);
        writer.u16(self.major_subsystem_version);
        writer.u16(self.minor_subsystem_version);
        writer.u32(self.win32_version_value);
        writer.u32(self.size_of_image);
        writer.u32(self.size_of_headers);
        writer.u32(self.checksum);
        writer.u16(self.subsystem);
        writer.u16(self.dll_characteristics);
        if wide {
            writer.u64(self.size_of_stack_reserve);
            writer.u64(self.size_of_stack_commit);
            writer.u64(self.size_of_heap_reserve);
            writer.u64(self.size_of_heap_commit);
        } else {
            writer.u32(self.size_of_stack_reserve as u32);
            writer.u32(self.size_of_stack_commit as u32);
            writer.u32(self.size_of_heap_reserve as u32);
            writer.u32(self.size_of_heap_commit as u32);
        }
        writer.u32(self.loader_flags);
        writer.u32(self.number_of_rva_and_sizes);
    }

    fn read(reader: &mut ByteReader<'_>) -> Result<Self> {
        let subject: &str = "the optional header";
        let magic: u16 = reader
            .read_u16_le()
            .map_err(|error: ByteReadError| rewrite_read_error(subject, error))?;
        let wide: bool = match magic {
            OPTIONAL_MAGIC_PE32 => false,
            OPTIONAL_MAGIC_PE32_PLUS => true,
            other => {
                return Err(rewrite_error(format!(
                    "optional header magic {other:#06x} is neither PE32 nor PE32+"
                )));
            }
        };
        let byte = |reader: &mut ByteReader<'_>| -> Result<u8> {
            reader
                .read_u8()
                .map_err(|error: ByteReadError| rewrite_read_error(subject, error))
        };
        let major_linker_version: u8 = byte(reader)?;
        let minor_linker_version: u8 = byte(reader)?;
        let dword = |reader: &mut ByteReader<'_>| -> Result<u32> {
            reader
                .read_u32_le()
                .map_err(|error: ByteReadError| rewrite_read_error(subject, error))
        };
        let size_of_code: u32 = dword(reader)?;
        let size_of_initialized_data: u32 = dword(reader)?;
        let size_of_uninitialized_data: u32 = dword(reader)?;
        let address_of_entry_point: u32 = dword(reader)?;
        let base_of_code: u32 = dword(reader)?;
        let base_of_data: Option<u32> = if wide { None } else { Some(dword(reader)?) };
        let image_base: u64 = if wide {
            reader
                .read_u64_le()
                .map_err(|error: ByteReadError| rewrite_read_error(subject, error))?
        } else {
            u64::from(dword(reader)?)
        };
        let section_alignment: u32 = dword(reader)?;
        let file_alignment: u32 = dword(reader)?;
        let word = |reader: &mut ByteReader<'_>| -> Result<u16> {
            reader
                .read_u16_le()
                .map_err(|error: ByteReadError| rewrite_read_error(subject, error))
        };
        let major_operating_system_version: u16 = word(reader)?;
        let minor_operating_system_version: u16 = word(reader)?;
        let major_image_version: u16 = word(reader)?;
        let minor_image_version: u16 = word(reader)?;
        let major_subsystem_version: u16 = word(reader)?;
        let minor_subsystem_version: u16 = word(reader)?;
        let win32_version_value: u32 = dword(reader)?;
        let size_of_image: u32 = dword(reader)?;
        let size_of_headers: u32 = dword(reader)?;
        let checksum: u32 = dword(reader)?;
        let subsystem: u16 = word(reader)?;
        let dll_characteristics: u16 = word(reader)?;
        let native = |reader: &mut ByteReader<'_>| -> Result<u64> {
            if wide {
                reader
                    .read_u64_le()
                    .map_err(|error: ByteReadError| rewrite_read_error(subject, error))
            } else {
                reader
                    .read_u32_le()
                    .map(u64::from)
                    .map_err(|error: ByteReadError| rewrite_read_error(subject, error))
            }
        };
        let size_of_stack_reserve: u64 = native(reader)?;
        let size_of_stack_commit: u64 = native(reader)?;
        let size_of_heap_reserve: u64 = native(reader)?;
        let size_of_heap_commit: u64 = native(reader)?;
        let loader_flags: u32 = dword(reader)?;
        let number_of_rva_and_sizes: u32 = dword(reader)?;

        Ok(Self {
            magic,
            major_linker_version,
            minor_linker_version,
            size_of_code,
            size_of_initialized_data,
            size_of_uninitialized_data,
            address_of_entry_point,
            base_of_code,
            base_of_data,
            image_base,
            section_alignment,
            file_alignment,
            major_operating_system_version,
            minor_operating_system_version,
            major_image_version,
            minor_image_version,
            major_subsystem_version,
            minor_subsystem_version,
            win32_version_value,
            size_of_image,
            size_of_headers,
            checksum,
            subsystem,
            dll_characteristics,
            size_of_stack_reserve,
            size_of_stack_commit,
            size_of_heap_reserve,
            size_of_heap_commit,
            loader_flags,
            number_of_rva_and_sizes,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeDataDirectories {
    pub entries: Vec<PeDataDirectory>,
}

impl PeDataDirectories {
    pub(super) const fn encoded_len(&self) -> u64 {
        (self.entries.len() as u64).saturating_mul(DIRECTORY_RECORD_SIZE)
    }

    pub(super) fn encode(&self, writer: &mut FieldWriter<'_>) {
        for entry in &self.entries {
            writer.u32(entry.virtual_address);
            writer.u32(entry.size);
        }
    }

    fn read(reader: &mut ByteReader<'_>, count: usize) -> Result<Self> {
        let mut entries: Vec<PeDataDirectory> = Vec::with_capacity(count);
        for _ in 0..count {
            let virtual_address: u32 = reader
                .read_u32_le()
                .map_err(|error: ByteReadError| rewrite_read_error("a data directory", error))?;
            let size: u32 = reader
                .read_u32_le()
                .map_err(|error: ByteReadError| rewrite_read_error("a data directory", error))?;
            entries.push(PeDataDirectory {
                virtual_address,
                size,
            });
        }
        Ok(Self { entries })
    }
}

pub(super) fn plan(bytes: &[u8], format: NativeFormat) -> Result<ImagePlan> {
    let file_len: u64 = u64::try_from(bytes.len())
        .map_err(|_error: std::num::TryFromIntError| rewrite_error("file length overflows"))?;
    let mut builder: PlanBuilder = PlanBuilder::new(format, file_len);

    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    let dos: PeDosHeader = PeDosHeader::read(&mut reader)?;
    let lfanew: u64 = u64::from(dos.lfanew);
    if lfanew >= DOS_HEADER_SIZE {
        builder.push(0, Structure::PeDosHeader(dos))?;
    }

    let signature_index: usize =
        usize::try_from(lfanew).map_err(|_error: std::num::TryFromIntError| {
            rewrite_error("the PE header offset overflows")
        })?;
    reader
        .seek(signature_index)
        .map_err(|error: ByteReadError| rewrite_read_error("the PE signature", error))?;
    let magic: u32 = reader
        .read_u32_le()
        .map_err(|error: ByteReadError| rewrite_read_error("the PE signature", error))?;
    if magic != PE_SIGNATURE {
        return Err(rewrite_error(format!(
            "the PE signature reads {magic:#010x} rather than `PE\\0\\0`"
        )));
    }
    builder.push(lfanew, Structure::PeSignature(PeSignature { magic }))?;

    let coff_start: u64 = lfanew
        .checked_add(PE_SIGNATURE_SIZE)
        .ok_or_else(|| rewrite_error("the COFF header offset overflows"))?;
    let header: CoffHeader = plan_header_and_sections(&mut builder, bytes, coff_start)?;

    let optional_size: u64 = u64::from(header.size_of_optional_header);
    let optional_start: u64 = coff_start
        .checked_add(COFF_HEADER_SIZE)
        .ok_or_else(|| rewrite_error("the optional header offset overflows"))?;
    let optional_end: u64 = optional_start
        .checked_add(optional_size)
        .ok_or_else(|| rewrite_error("the optional header range overflows"))?;
    if optional_end > file_len {
        return Err(rewrite_error(format!(
            "SizeOfOptionalHeader {optional_size} runs past the {file_len} byte input"
        )));
    }
    if optional_size == 0 {
        return Err(unsupported(
            format,
            "an image with no optional header has no PE32 or PE32+ model in this writer",
        ));
    }

    let optional_index: usize =
        usize::try_from(optional_start).map_err(|_error: std::num::TryFromIntError| {
            rewrite_error("the optional header offset overflows")
        })?;
    reader
        .seek(optional_index)
        .map_err(|error: ByteReadError| rewrite_read_error("the optional header", error))?;
    let optional: PeOptionalHeader = PeOptionalHeader::read(&mut reader)?;
    let fixed_size: u64 = optional.encoded_len();
    if optional_size < fixed_size {
        return Err(unsupported(
            format,
            format!(
                "SizeOfOptionalHeader {optional_size} is shorter than the {fixed_size} byte fixed \
                 optional header its magic declares"
            ),
        ));
    }
    builder.push(optional_start, Structure::PeOptionalHeader(optional))?;

    let directory_start: u64 = optional_start
        .checked_add(fixed_size)
        .ok_or_else(|| rewrite_error("the data directory offset overflows"))?;
    let directory_space: u64 = optional_size.saturating_sub(fixed_size);
    let fitting_slots: u64 = directory_space / DIRECTORY_RECORD_SIZE;
    let slots: u64 = u64::from(optional.number_of_rva_and_sizes)
        .min(fitting_slots)
        .min(MAX_DIRECTORY_SLOTS);
    let directories: PeDataDirectories = if slots == 0 {
        PeDataDirectories {
            entries: Vec::new(),
        }
    } else {
        let slot_count: usize =
            usize::try_from(slots).map_err(|_error: std::num::TryFromIntError| {
                rewrite_error("the data directory count overflows")
            })?;
        let directory_index: usize =
            usize::try_from(directory_start).map_err(|_error: std::num::TryFromIntError| {
                rewrite_error("the data directory offset overflows")
            })?;
        reader
            .seek(directory_index)
            .map_err(|error: ByteReadError| rewrite_read_error("the data directories", error))?;
        let parsed: PeDataDirectories = PeDataDirectories::read(&mut reader, slot_count)?;
        builder.push(
            directory_start,
            Structure::PeDataDirectories(parsed.clone()),
        )?;
        parsed
    };

    record_derived_values(
        &mut builder,
        optional_start,
        optional,
        &directories,
        file_len,
    );

    builder.finish()
}

fn record_derived_values(
    builder: &mut PlanBuilder,
    optional_start: u64,
    optional: PeOptionalHeader,
    directories: &PeDataDirectories,
    file_len: u64,
) {
    if optional.checksum != 0
        && let Some(field_start) = optional_start.checked_add(CHECKSUM_FIELD_OFFSET)
        && let Some(field_end) = field_start.checked_add(CHECKSUM_FIELD_SIZE)
        && field_end <= file_len
    {
        builder.derive(DerivedValue {
            kind: DerivedKind::PeChecksum,
            field_start,
            field_end,
            covered_start: 0,
            covered_end: file_len,
            detail: format!(
                "the optional header CheckSum {:#010x} covers the whole file and this writer does \
                 not recompute it",
                optional.checksum
            ),
        });
    }

    let Some(certificate) = directories.entries.get(CERTIFICATE_DIRECTORY_INDEX) else {
        return;
    };
    if certificate.virtual_address == 0 || certificate.size == 0 {
        return;
    }
    let field_start: u64 = u64::from(certificate.virtual_address);
    let Some(field_end) = field_start.checked_add(u64::from(certificate.size)) else {
        return;
    };
    builder.derive(DerivedValue {
        kind: DerivedKind::PeAuthenticode,
        field_start,
        field_end: field_end.min(file_len),
        covered_start: 0,
        covered_end: file_len,
        detail: format!(
            "the authenticode certificate table at {field_start} covers {} bytes of signed image \
             and this writer does not re-sign it",
            certificate.size
        ),
    });
}
