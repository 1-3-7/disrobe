use disrobe_bytes::{ByteReadError, ByteReader, Endian};

use crate::error::Result;
use crate::native::NativeFormat;

use super::encode::FieldWriter;
use super::{
    DerivedKind, DerivedValue, ImagePlan, MAX_FAT_SLICES, MAX_LOAD_COMMANDS, PlanBuilder,
    Structure, rewrite_error, rewrite_read_error, unsupported,
};

const HEADER_SIZE_32: u64 = 28;
const HEADER_SIZE_64: u64 = 32;
const COMMAND_PREFIX: u64 = 8;
const SEGMENT_BODY_32: u64 = 48;
const SEGMENT_BODY_64: u64 = 64;
const SECTION_SIZE_32: u64 = 68;
const SECTION_SIZE_64: u64 = 80;
const SYMTAB_BODY: u64 = 16;
const DYSYMTAB_BODY: u64 = 72;
const DYLD_INFO_BODY: u64 = 40;
const LINKEDIT_DATA_BODY: u64 = 8;
const UUID_BODY: u64 = 16;
const BUILD_VERSION_BODY: u64 = 16;
const BUILD_TOOL_SIZE: u64 = 8;
const FAT_HEADER_SIZE: u64 = 8;
const FAT_ARCH_SIZE_32: u64 = 20;
const FAT_ARCH_SIZE_64: u64 = 32;

const MH_MAGIC: u32 = 0xFEED_FACE;
const MH_MAGIC_64: u32 = 0xFEED_FACF;
const MH_CIGAM: u32 = 0xCEFA_EDFE;
const MH_CIGAM_64: u32 = 0xCFFA_EDFE;
const FAT_MAGIC: u32 = 0xCAFE_BABE;
const FAT_MAGIC_64: u32 = 0xCAFE_BABF;

const LC_SEGMENT: u32 = 0x1;
const LC_SYMTAB: u32 = 0x2;
const LC_DYSYMTAB: u32 = 0xB;
const LC_SEGMENT_64: u32 = 0x19;
const LC_UUID: u32 = 0x1B;
const LC_CODE_SIGNATURE: u32 = 0x1D;
const LC_SEGMENT_SPLIT_INFO: u32 = 0x1E;
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_DATA_IN_CODE: u32 = 0x29;
const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2B;
const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2E;
const LC_BUILD_VERSION: u32 = 0x32;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
const LC_ATOM_INFO: u32 = 0x36;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachHeader {
    pub endian: Endian,
    pub wide: bool,
    pub magic: u32,
    pub cputype: i32,
    pub cpusubtype: i32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
    pub reserved: Option<u32>,
}

impl MachHeader {
    pub(super) const fn encoded_len(&self) -> u64 {
        if self.wide {
            HEADER_SIZE_64
        } else {
            HEADER_SIZE_32
        }
    }

    pub(super) fn encode(&self, writer: &mut FieldWriter<'_>) {
        writer.u32(self.magic);
        writer.i32(self.cputype);
        writer.i32(self.cpusubtype);
        writer.u32(self.filetype);
        writer.u32(self.ncmds);
        writer.u32(self.sizeofcmds);
        writer.u32(self.flags);
        if let Some(reserved) = self.reserved {
            writer.u32(reserved);
        }
    }

    fn read(bytes: &[u8], base: u64) -> Result<Self> {
        let index: usize = usize::try_from(base).map_err(|_error: std::num::TryFromIntError| {
            rewrite_error("a Mach-O slice offset overflows usize")
        })?;
        let mut probe: ByteReader<'_> = ByteReader::new(bytes);
        probe
            .seek(index)
            .map_err(|error: ByteReadError| rewrite_read_error("the Mach-O header", error))?;
        let raw: u32 = probe
            .read_u32_le()
            .map_err(|error: ByteReadError| rewrite_read_error("the Mach-O header", error))?;
        let (endian, wide): (Endian, bool) = match raw {
            MH_MAGIC_64 => (Endian::Little, true),
            MH_MAGIC => (Endian::Little, false),
            MH_CIGAM_64 => (Endian::Big, true),
            MH_CIGAM => (Endian::Big, false),
            other => {
                return Err(rewrite_error(format!(
                    "the Mach-O magic reads {other:#010x}, which names no known header layout"
                )));
            }
        };

        let subject: &str = "the Mach-O header";
        let mut reader: ByteReader<'_> = ByteReader::new(bytes);
        reader
            .seek(index)
            .map_err(|error: ByteReadError| rewrite_read_error(subject, error))?;
        let dword = |reader: &mut ByteReader<'_>| -> Result<u32> {
            reader
                .read_u32(endian)
                .map_err(|error: ByteReadError| rewrite_read_error(subject, error))
        };
        let magic: u32 = dword(&mut reader)?;
        let cputype: i32 = dword(&mut reader)? as i32;
        let cpusubtype: i32 = dword(&mut reader)? as i32;
        let filetype: u32 = dword(&mut reader)?;
        let ncmds: u32 = dword(&mut reader)?;
        let sizeofcmds: u32 = dword(&mut reader)?;
        let flags: u32 = dword(&mut reader)?;
        let reserved: Option<u32> = if wide {
            Some(dword(&mut reader)?)
        } else {
            None
        };

        Ok(Self {
            endian,
            wide,
            magic,
            cputype,
            cpusubtype,
            filetype,
            ncmds,
            sizeofcmds,
            flags,
            reserved,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachSection {
    pub sectname: [u8; 16],
    pub segname: [u8; 16],
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub reserved3: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachSegment {
    pub segname: [u8; 16],
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: i32,
    pub initprot: i32,
    pub nsects: u32,
    pub flags: u32,
    pub sections: Vec<MachSection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachBuildTool {
    pub tool: u32,
    pub version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachCommandBody {
    Prefix,
    Segment(MachSegment),
    Symtab {
        symoff: u32,
        nsyms: u32,
        stroff: u32,
        strsize: u32,
    },
    Dysymtab {
        ilocalsym: u32,
        nlocalsym: u32,
        iextdefsym: u32,
        nextdefsym: u32,
        iundefsym: u32,
        nundefsym: u32,
        tocoff: u32,
        ntoc: u32,
        modtaboff: u32,
        nmodtab: u32,
        extrefsymoff: u32,
        nextrefsyms: u32,
        indirectsymoff: u32,
        nindirectsyms: u32,
        extreloff: u32,
        nextrel: u32,
        locreloff: u32,
        nlocrel: u32,
    },
    DyldInfo {
        rebase_off: u32,
        rebase_size: u32,
        bind_off: u32,
        bind_size: u32,
        weak_bind_off: u32,
        weak_bind_size: u32,
        lazy_bind_off: u32,
        lazy_bind_size: u32,
        export_off: u32,
        export_size: u32,
    },
    LinkeditData {
        dataoff: u32,
        datasize: u32,
    },
    Uuid([u8; 16]),
    BuildVersion {
        platform: u32,
        minos: u32,
        sdk: u32,
        tools: Vec<MachBuildTool>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachLoadCommand {
    pub endian: Endian,
    pub wide: bool,
    pub cmd: u32,
    pub cmdsize: u32,
    pub body: MachCommandBody,
}

impl MachLoadCommand {
    pub(super) const fn encoded_len(&self) -> u64 {
        COMMAND_PREFIX.saturating_add(Self::body_len(self))
    }

    const fn body_len(&self) -> u64 {
        match &self.body {
            MachCommandBody::Prefix => 0,
            MachCommandBody::Segment(segment) => {
                let (body, section): (u64, u64) = if self.wide {
                    (SEGMENT_BODY_64, SECTION_SIZE_64)
                } else {
                    (SEGMENT_BODY_32, SECTION_SIZE_32)
                };
                body.saturating_add((segment.sections.len() as u64).saturating_mul(section))
            }
            MachCommandBody::Symtab { .. } => SYMTAB_BODY,
            MachCommandBody::Dysymtab { .. } => DYSYMTAB_BODY,
            MachCommandBody::DyldInfo { .. } => DYLD_INFO_BODY,
            MachCommandBody::LinkeditData { .. } => LINKEDIT_DATA_BODY,
            MachCommandBody::Uuid(_) => UUID_BODY,
            MachCommandBody::BuildVersion { tools, .. } => BUILD_VERSION_BODY
                .saturating_add((tools.len() as u64).saturating_mul(BUILD_TOOL_SIZE)),
        }
    }

    pub(super) fn encode(&self, writer: &mut FieldWriter<'_>) {
        writer.u32(self.cmd);
        writer.u32(self.cmdsize);
        match &self.body {
            MachCommandBody::Prefix => {}
            MachCommandBody::Segment(segment) => encode_segment(writer, segment, self.wide),
            MachCommandBody::Symtab {
                symoff,
                nsyms,
                stroff,
                strsize,
            } => {
                writer.u32(*symoff);
                writer.u32(*nsyms);
                writer.u32(*stroff);
                writer.u32(*strsize);
            }
            MachCommandBody::Dysymtab {
                ilocalsym,
                nlocalsym,
                iextdefsym,
                nextdefsym,
                iundefsym,
                nundefsym,
                tocoff,
                ntoc,
                modtaboff,
                nmodtab,
                extrefsymoff,
                nextrefsyms,
                indirectsymoff,
                nindirectsyms,
                extreloff,
                nextrel,
                locreloff,
                nlocrel,
            } => {
                writer.u32_slice(&[
                    *ilocalsym,
                    *nlocalsym,
                    *iextdefsym,
                    *nextdefsym,
                    *iundefsym,
                    *nundefsym,
                    *tocoff,
                    *ntoc,
                    *modtaboff,
                    *nmodtab,
                    *extrefsymoff,
                    *nextrefsyms,
                    *indirectsymoff,
                    *nindirectsyms,
                    *extreloff,
                    *nextrel,
                    *locreloff,
                    *nlocrel,
                ]);
            }
            MachCommandBody::DyldInfo {
                rebase_off,
                rebase_size,
                bind_off,
                bind_size,
                weak_bind_off,
                weak_bind_size,
                lazy_bind_off,
                lazy_bind_size,
                export_off,
                export_size,
            } => {
                writer.u32_slice(&[
                    *rebase_off,
                    *rebase_size,
                    *bind_off,
                    *bind_size,
                    *weak_bind_off,
                    *weak_bind_size,
                    *lazy_bind_off,
                    *lazy_bind_size,
                    *export_off,
                    *export_size,
                ]);
            }
            MachCommandBody::LinkeditData { dataoff, datasize } => {
                writer.u32(*dataoff);
                writer.u32(*datasize);
            }
            MachCommandBody::Uuid(uuid) => writer.bytes(uuid),
            MachCommandBody::BuildVersion {
                platform,
                minos,
                sdk,
                tools,
            } => {
                writer.u32(*platform);
                writer.u32(*minos);
                writer.u32(*sdk);
                writer.u32(tools.len() as u32);
                for tool in tools {
                    writer.u32(tool.tool);
                    writer.u32(tool.version);
                }
            }
        }
    }
}

fn encode_segment(writer: &mut FieldWriter<'_>, segment: &MachSegment, wide: bool) {
    writer.bytes(&segment.segname);
    if wide {
        writer.u64(segment.vmaddr);
        writer.u64(segment.vmsize);
        writer.u64(segment.fileoff);
        writer.u64(segment.filesize);
    } else {
        writer.u32(segment.vmaddr as u32);
        writer.u32(segment.vmsize as u32);
        writer.u32(segment.fileoff as u32);
        writer.u32(segment.filesize as u32);
    }
    writer.i32(segment.maxprot);
    writer.i32(segment.initprot);
    writer.u32(segment.nsects);
    writer.u32(segment.flags);
    for section in &segment.sections {
        writer.bytes(&section.sectname);
        writer.bytes(&section.segname);
        if wide {
            writer.u64(section.addr);
            writer.u64(section.size);
        } else {
            writer.u32(section.addr as u32);
            writer.u32(section.size as u32);
        }
        writer.u32(section.offset);
        writer.u32(section.align);
        writer.u32(section.reloff);
        writer.u32(section.nreloc);
        writer.u32(section.flags);
        writer.u32(section.reserved1);
        writer.u32(section.reserved2);
        if let Some(reserved3) = section.reserved3 {
            writer.u32(reserved3);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FatHeader {
    pub endian: Endian,
    pub magic: u32,
    pub nfat_arch: u32,
}

impl FatHeader {
    pub(super) const ENCODED_LEN: u64 = FAT_HEADER_SIZE;

    pub(super) fn encode(self, writer: &mut FieldWriter<'_>) {
        writer.u32(self.magic);
        writer.u32(self.nfat_arch);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FatArch {
    pub cputype: i32,
    pub cpusubtype: i32,
    pub offset: u64,
    pub size: u64,
    pub align: u32,
    pub reserved: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FatArchTable {
    pub endian: Endian,
    pub wide: bool,
    pub entries: Vec<FatArch>,
}

impl FatArchTable {
    pub(super) const fn encoded_len(&self) -> u64 {
        let stride: u64 = if self.wide {
            FAT_ARCH_SIZE_64
        } else {
            FAT_ARCH_SIZE_32
        };
        (self.entries.len() as u64).saturating_mul(stride)
    }

    pub(super) fn encode(&self, writer: &mut FieldWriter<'_>) {
        for entry in &self.entries {
            writer.i32(entry.cputype);
            writer.i32(entry.cpusubtype);
            if self.wide {
                writer.u64(entry.offset);
                writer.u64(entry.size);
            } else {
                writer.u32(entry.offset as u32);
                writer.u32(entry.size as u32);
            }
            writer.u32(entry.align);
            if let Some(reserved) = entry.reserved {
                writer.u32(reserved);
            }
        }
    }
}

pub(super) fn plan_thin(bytes: &[u8], format: NativeFormat) -> Result<ImagePlan> {
    let file_len: u64 = u64::try_from(bytes.len())
        .map_err(|_error: std::num::TryFromIntError| rewrite_error("file length overflows"))?;
    let mut builder: PlanBuilder = PlanBuilder::new(format, file_len);
    plan_slice(&mut builder, bytes, 0, file_len)?;
    builder.finish()
}

pub(super) fn plan_fat(bytes: &[u8]) -> Result<ImagePlan> {
    let file_len: u64 = u64::try_from(bytes.len())
        .map_err(|_error: std::num::TryFromIntError| rewrite_error("file length overflows"))?;
    let format: NativeFormat = NativeFormat::MachOFat;
    let mut builder: PlanBuilder = PlanBuilder::new(format, file_len);

    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    let magic: u32 = reader
        .read_u32_be()
        .map_err(|error: ByteReadError| rewrite_read_error("the fat header", error))?;
    let wide: bool = match magic {
        FAT_MAGIC => false,
        FAT_MAGIC_64 => true,
        other => {
            return Err(rewrite_error(format!(
                "the fat magic reads {other:#010x}, which names no universal binary layout"
            )));
        }
    };
    let nfat_arch: u32 = reader
        .read_u32_be()
        .map_err(|error: ByteReadError| rewrite_read_error("the fat header", error))?;
    if u64::from(nfat_arch) > MAX_FAT_SLICES {
        return Err(unsupported(
            format,
            format!("nfat_arch {nfat_arch} exceeds the {MAX_FAT_SLICES} slice ceiling"),
        ));
    }
    builder.push(
        0,
        Structure::FatHeader(FatHeader {
            endian: Endian::Big,
            magic,
            nfat_arch,
        }),
    )?;

    let stride: u64 = if wide {
        FAT_ARCH_SIZE_64
    } else {
        FAT_ARCH_SIZE_32
    };
    let table_bytes: u64 = u64::from(nfat_arch)
        .checked_mul(stride)
        .ok_or_else(|| rewrite_error("the fat architecture table range overflows"))?;
    let table_end: u64 = FAT_HEADER_SIZE
        .checked_add(table_bytes)
        .ok_or_else(|| rewrite_error("the fat architecture table range overflows"))?;
    if table_end > file_len {
        return Err(rewrite_error(format!(
            "nfat_arch {nfat_arch} needs {table_bytes} bytes, more than the {file_len} byte input \
             holds"
        )));
    }

    let mut entries: Vec<FatArch> = Vec::with_capacity(nfat_arch as usize);
    for _ in 0..nfat_arch {
        let cputype: i32 = reader
            .read_u32_be()
            .map_err(|error: ByteReadError| rewrite_read_error("a fat architecture", error))?
            as i32;
        let cpusubtype: i32 = reader
            .read_u32_be()
            .map_err(|error: ByteReadError| rewrite_read_error("a fat architecture", error))?
            as i32;
        let (offset, size): (u64, u64) = if wide {
            let offset: u64 = reader
                .read_u64_be()
                .map_err(|error: ByteReadError| rewrite_read_error("a fat architecture", error))?;
            let size: u64 = reader
                .read_u64_be()
                .map_err(|error: ByteReadError| rewrite_read_error("a fat architecture", error))?;
            (offset, size)
        } else {
            let offset: u32 = reader
                .read_u32_be()
                .map_err(|error: ByteReadError| rewrite_read_error("a fat architecture", error))?;
            let size: u32 = reader
                .read_u32_be()
                .map_err(|error: ByteReadError| rewrite_read_error("a fat architecture", error))?;
            (u64::from(offset), u64::from(size))
        };
        let align: u32 = reader
            .read_u32_be()
            .map_err(|error: ByteReadError| rewrite_read_error("a fat architecture", error))?;
        let reserved: Option<u32> =
            if wide {
                Some(reader.read_u32_be().map_err(|error: ByteReadError| {
                    rewrite_read_error("a fat architecture", error)
                })?)
            } else {
                None
            };
        entries.push(FatArch {
            cputype,
            cpusubtype,
            offset,
            size,
            align,
            reserved,
        });
    }

    let table: FatArchTable = FatArchTable {
        endian: Endian::Big,
        wide,
        entries: entries.clone(),
    };
    if !entries.is_empty() {
        builder.push(FAT_HEADER_SIZE, Structure::FatArchTable(table))?;
    }

    for entry in &entries {
        let end: u64 = entry
            .offset
            .checked_add(entry.size)
            .ok_or_else(|| rewrite_error("a fat slice range overflows"))?;
        if end > file_len {
            return Err(rewrite_error(format!(
                "a fat slice spans {}..{end}, past the {file_len} byte input",
                entry.offset
            )));
        }
        if entry.size == 0 {
            continue;
        }
        if slice_is_macho(bytes, entry.offset) {
            plan_slice(&mut builder, bytes, entry.offset, end)?;
        }
    }

    builder.finish()
}

fn slice_is_macho(bytes: &[u8], base: u64) -> bool {
    let Ok(index) = usize::try_from(base) else {
        return false;
    };
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    if reader.seek(index).is_err() {
        return false;
    }
    let Ok(magic) = reader.read_u32_le() else {
        return false;
    };
    matches!(magic, MH_MAGIC | MH_MAGIC_64 | MH_CIGAM | MH_CIGAM_64)
}

fn plan_slice(builder: &mut PlanBuilder, bytes: &[u8], base: u64, limit: u64) -> Result<()> {
    let format: NativeFormat = builder.format();
    let header: MachHeader = MachHeader::read(bytes, base)?;
    let header_size: u64 = header.encoded_len();
    builder.push(base, Structure::MachHeader(header))?;

    if u64::from(header.ncmds) > MAX_LOAD_COMMANDS {
        return Err(unsupported(
            format,
            format!(
                "ncmds {} exceeds the {MAX_LOAD_COMMANDS} load command ceiling",
                header.ncmds
            ),
        ));
    }
    let table_start: u64 = base
        .checked_add(header_size)
        .ok_or_else(|| rewrite_error("the load command table offset overflows"))?;
    let table_end: u64 = table_start
        .checked_add(u64::from(header.sizeofcmds))
        .ok_or_else(|| rewrite_error("the load command table range overflows"))?;
    if table_end > limit {
        return Err(rewrite_error(format!(
            "sizeofcmds {} runs past the slice that ends at {limit}",
            header.sizeofcmds
        )));
    }

    let mut cursor: u64 = table_start;
    for index in 0..header.ncmds {
        if cursor >= table_end {
            return Err(rewrite_error(format!(
                "load command {index} starts at {cursor}, past the load command table"
            )));
        }
        let command: MachLoadCommand = read_command(bytes, &header, cursor, table_end, index)?;
        let cmdsize: u64 = u64::from(command.cmdsize);
        let typed_len: u64 = command.encoded_len();
        if typed_len > cmdsize {
            return Err(unsupported(
                format,
                format!(
                    "load command {index} declares cmd {:#010x} with a {cmdsize} byte cmdsize, \
                     shorter than the {typed_len} bytes its layout needs",
                    command.cmd
                ),
            ));
        }
        record_slice_derived(builder, &command, base, cursor);
        builder.push(cursor, Structure::MachLoadCommand(command))?;
        cursor = cursor
            .checked_add(cmdsize)
            .ok_or_else(|| rewrite_error("a load command range overflows"))?;
        if cursor > table_end {
            return Err(rewrite_error(format!(
                "load command {index} runs past the load command table"
            )));
        }
    }

    Ok(())
}

fn record_slice_derived(
    builder: &mut PlanBuilder,
    command: &MachLoadCommand,
    base: u64,
    command_start: u64,
) {
    if command.cmd != LC_CODE_SIGNATURE {
        return;
    }
    let MachCommandBody::LinkeditData { dataoff, datasize } = command.body else {
        return;
    };
    if datasize == 0 {
        return;
    }
    let Some(field_start) = base.checked_add(u64::from(dataoff)) else {
        return;
    };
    let Some(field_end) = field_start.checked_add(u64::from(datasize)) else {
        return;
    };
    builder.derive(DerivedValue {
        kind: DerivedKind::MachCodeSignature,
        field_start,
        field_end,
        covered_start: base,
        covered_end: field_start,
        detail: format!(
            "the code signature named by the LC_CODE_SIGNATURE at {command_start} covers the \
             slice up to its own offset and this writer does not re-sign it"
        ),
    });
}

fn read_command(
    bytes: &[u8],
    header: &MachHeader,
    start: u64,
    table_end: u64,
    index: u32,
) -> Result<MachLoadCommand> {
    let subject: &str = "a load command";
    let start_index: usize =
        usize::try_from(start).map_err(|_error: std::num::TryFromIntError| {
            rewrite_error("a load command offset overflows usize")
        })?;
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(start_index)
        .map_err(|error: ByteReadError| rewrite_read_error(subject, error))?;
    let endian: Endian = header.endian;
    let dword = |reader: &mut ByteReader<'_>| -> Result<u32> {
        reader
            .read_u32(endian)
            .map_err(|error: ByteReadError| rewrite_read_error(subject, error))
    };
    let cmd: u32 = dword(&mut reader)?;
    let cmdsize: u32 = dword(&mut reader)?;
    if u64::from(cmdsize) < COMMAND_PREFIX {
        return Err(rewrite_error(format!(
            "load command {index} declares a {cmdsize} byte cmdsize"
        )));
    }
    let end: u64 = start
        .checked_add(u64::from(cmdsize))
        .ok_or_else(|| rewrite_error("a load command range overflows"))?;
    if end > table_end {
        return Err(rewrite_error(format!(
            "load command {index} runs past the load command table"
        )));
    }

    let body: MachCommandBody = match cmd {
        LC_SEGMENT if !header.wide => read_segment(&mut reader, endian, false, cmdsize)?,
        LC_SEGMENT_64 if header.wide => read_segment(&mut reader, endian, true, cmdsize)?,
        LC_SYMTAB => MachCommandBody::Symtab {
            symoff: dword(&mut reader)?,
            nsyms: dword(&mut reader)?,
            stroff: dword(&mut reader)?,
            strsize: dword(&mut reader)?,
        },
        LC_DYSYMTAB => MachCommandBody::Dysymtab {
            ilocalsym: dword(&mut reader)?,
            nlocalsym: dword(&mut reader)?,
            iextdefsym: dword(&mut reader)?,
            nextdefsym: dword(&mut reader)?,
            iundefsym: dword(&mut reader)?,
            nundefsym: dword(&mut reader)?,
            tocoff: dword(&mut reader)?,
            ntoc: dword(&mut reader)?,
            modtaboff: dword(&mut reader)?,
            nmodtab: dword(&mut reader)?,
            extrefsymoff: dword(&mut reader)?,
            nextrefsyms: dword(&mut reader)?,
            indirectsymoff: dword(&mut reader)?,
            nindirectsyms: dword(&mut reader)?,
            extreloff: dword(&mut reader)?,
            nextrel: dword(&mut reader)?,
            locreloff: dword(&mut reader)?,
            nlocrel: dword(&mut reader)?,
        },
        LC_DYLD_INFO | LC_DYLD_INFO_ONLY => MachCommandBody::DyldInfo {
            rebase_off: dword(&mut reader)?,
            rebase_size: dword(&mut reader)?,
            bind_off: dword(&mut reader)?,
            bind_size: dword(&mut reader)?,
            weak_bind_off: dword(&mut reader)?,
            weak_bind_size: dword(&mut reader)?,
            lazy_bind_off: dword(&mut reader)?,
            lazy_bind_size: dword(&mut reader)?,
            export_off: dword(&mut reader)?,
            export_size: dword(&mut reader)?,
        },
        LC_CODE_SIGNATURE
        | LC_SEGMENT_SPLIT_INFO
        | LC_FUNCTION_STARTS
        | LC_DATA_IN_CODE
        | LC_DYLIB_CODE_SIGN_DRS
        | LC_LINKER_OPTIMIZATION_HINT
        | LC_DYLD_EXPORTS_TRIE
        | LC_DYLD_CHAINED_FIXUPS
        | LC_ATOM_INFO => MachCommandBody::LinkeditData {
            dataoff: dword(&mut reader)?,
            datasize: dword(&mut reader)?,
        },
        LC_UUID => {
            let raw: &[u8] = reader
                .read_bytes(UUID_BODY as usize)
                .map_err(|error: ByteReadError| rewrite_read_error("an LC_UUID payload", error))?;
            let uuid: [u8; 16] =
                <[u8; 16]>::try_from(raw).map_err(|_error: std::array::TryFromSliceError| {
                    rewrite_error("an LC_UUID payload is short")
                })?;
            MachCommandBody::Uuid(uuid)
        }
        LC_BUILD_VERSION => {
            let platform: u32 = dword(&mut reader)?;
            let minos: u32 = dword(&mut reader)?;
            let sdk: u32 = dword(&mut reader)?;
            let ntools: u32 = dword(&mut reader)?;
            let room: u64 = u64::from(cmdsize)
                .saturating_sub(COMMAND_PREFIX)
                .saturating_sub(BUILD_VERSION_BODY)
                / BUILD_TOOL_SIZE;
            if u64::from(ntools) > room {
                return Err(rewrite_error(format!(
                    "load command {index} declares {ntools} build tools, more than its {cmdsize} \
                     byte cmdsize holds"
                )));
            }
            let mut tools: Vec<MachBuildTool> = Vec::with_capacity(ntools as usize);
            for _ in 0..ntools {
                tools.push(MachBuildTool {
                    tool: dword(&mut reader)?,
                    version: dword(&mut reader)?,
                });
            }
            MachCommandBody::BuildVersion {
                platform,
                minos,
                sdk,
                tools,
            }
        }
        _ => MachCommandBody::Prefix,
    };

    Ok(MachLoadCommand {
        endian,
        wide: header.wide,
        cmd,
        cmdsize,
        body,
    })
}

fn read_segment(
    reader: &mut ByteReader<'_>,
    endian: Endian,
    wide: bool,
    cmdsize: u32,
) -> Result<MachCommandBody> {
    let subject: &str = "a segment load command";
    let raw: &[u8] = reader
        .read_bytes(16)
        .map_err(|error: ByteReadError| rewrite_read_error(subject, error))?;
    let segname: [u8; 16] =
        <[u8; 16]>::try_from(raw).map_err(|_error: std::array::TryFromSliceError| {
            rewrite_error("a segment name is short")
        })?;
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
    let vmaddr: u64 = address(reader)?;
    let vmsize: u64 = address(reader)?;
    let fileoff: u64 = address(reader)?;
    let filesize: u64 = address(reader)?;
    let dword = |reader: &mut ByteReader<'_>| -> Result<u32> {
        reader
            .read_u32(endian)
            .map_err(|error: ByteReadError| rewrite_read_error(subject, error))
    };
    let maxprot: i32 = dword(reader)? as i32;
    let initprot: i32 = dword(reader)? as i32;
    let nsects: u32 = dword(reader)?;
    let flags: u32 = dword(reader)?;

    let (body_size, section_size): (u64, u64) = if wide {
        (SEGMENT_BODY_64, SECTION_SIZE_64)
    } else {
        (SEGMENT_BODY_32, SECTION_SIZE_32)
    };
    let room: u64 = u64::from(cmdsize)
        .saturating_sub(COMMAND_PREFIX)
        .saturating_sub(body_size)
        / section_size;
    if u64::from(nsects) > room {
        return Err(rewrite_error(format!(
            "a segment declares {nsects} sections, more than its {cmdsize} byte cmdsize holds"
        )));
    }

    let mut sections: Vec<MachSection> = Vec::with_capacity(nsects as usize);
    for _ in 0..nsects {
        let raw_sect: &[u8] = reader
            .read_bytes(16)
            .map_err(|error: ByteReadError| rewrite_read_error(subject, error))?;
        let sectname: [u8; 16] =
            <[u8; 16]>::try_from(raw_sect).map_err(|_error: std::array::TryFromSliceError| {
                rewrite_error("a section name is short")
            })?;
        let raw_seg: &[u8] = reader
            .read_bytes(16)
            .map_err(|error: ByteReadError| rewrite_read_error(subject, error))?;
        let section_segname: [u8; 16] =
            <[u8; 16]>::try_from(raw_seg).map_err(|_error: std::array::TryFromSliceError| {
                rewrite_error("a section name is short")
            })?;
        let addr: u64 = address(reader)?;
        let size: u64 = address(reader)?;
        let offset: u32 = dword(reader)?;
        let align: u32 = dword(reader)?;
        let reloff: u32 = dword(reader)?;
        let nreloc: u32 = dword(reader)?;
        let section_flags: u32 = dword(reader)?;
        let reserved1: u32 = dword(reader)?;
        let reserved2: u32 = dword(reader)?;
        let reserved3: Option<u32> = if wide { Some(dword(reader)?) } else { None };
        sections.push(MachSection {
            sectname,
            segname: section_segname,
            addr,
            size,
            offset,
            align,
            reloff,
            nreloc,
            flags: section_flags,
            reserved1,
            reserved2,
            reserved3,
        });
    }

    Ok(MachCommandBody::Segment(MachSegment {
        segname,
        vmaddr,
        vmsize,
        fileoff,
        filesize,
        maxprot,
        initprot,
        nsects,
        flags,
        sections,
    }))
}
