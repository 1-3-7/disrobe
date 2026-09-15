use disrobe_bytes::{ByteReadError, Endian};
use serde::{Deserialize, Serialize};

use crate::debug::{dbg_kv, dbg_section};
use crate::error::{Error, Result};
use crate::native::{NativeFormat, detect_native_format};

pub(crate) mod coff;
mod elf;
mod encode;
mod macho;
mod pe;

use encode::FieldWriter;

pub const IMAGE_PLAN_SCHEMA: &str = "disrobe.image-plan/v1";

pub(crate) const MAX_PLAN_STRUCTURES: usize = 65_536;
pub(crate) const MAX_TABLE_ENTRIES: u64 = 262_144;
pub(crate) const MAX_LOAD_COMMANDS: u64 = 65_536;
pub(crate) const MAX_FAT_SLICES: u64 = 4_096;
const MAX_EDITS: usize = 4_096;

pub use coff::{CoffBigObjHeader, CoffHeader, CoffSectionHeader, CoffSectionTable};
pub use elf::{
    ElfHeader, ElfIdent, ElfProgramHeader, ElfProgramHeaders, ElfSectionHeader, ElfSectionHeaders,
};
pub use macho::{
    FatArch, FatArchTable, FatHeader, MachBuildTool, MachCommandBody, MachHeader, MachLoadCommand,
    MachSection, MachSegment,
};
pub use pe::{PeDataDirectories, PeDataDirectory, PeDosHeader, PeOptionalHeader, PeSignature};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StructureKind {
    PeDosHeader,
    PeSignature,
    CoffHeader,
    CoffBigObjHeader,
    PeOptionalHeader,
    PeDataDirectories,
    CoffSectionTable,
    ElfHeader,
    ElfProgramHeaders,
    ElfSectionHeaders,
    MachHeader,
    MachLoadCommand,
    FatHeader,
    FatArchTable,
}

impl StructureKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::PeDosHeader => "pe-dos-header",
            Self::PeSignature => "pe-signature",
            Self::CoffHeader => "coff-header",
            Self::CoffBigObjHeader => "coff-bigobj-header",
            Self::PeOptionalHeader => "pe-optional-header",
            Self::PeDataDirectories => "pe-data-directories",
            Self::CoffSectionTable => "coff-section-table",
            Self::ElfHeader => "elf-header",
            Self::ElfProgramHeaders => "elf-program-headers",
            Self::ElfSectionHeaders => "elf-section-headers",
            Self::MachHeader => "mach-header",
            Self::MachLoadCommand => "mach-load-command",
            Self::FatHeader => "fat-header",
            Self::FatArchTable => "fat-arch-table",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Structure {
    PeDosHeader(PeDosHeader),
    PeSignature(PeSignature),
    CoffHeader(CoffHeader),
    CoffBigObjHeader(CoffBigObjHeader),
    PeOptionalHeader(PeOptionalHeader),
    PeDataDirectories(PeDataDirectories),
    CoffSectionTable(CoffSectionTable),
    ElfHeader(ElfHeader),
    ElfProgramHeaders(ElfProgramHeaders),
    ElfSectionHeaders(ElfSectionHeaders),
    MachHeader(MachHeader),
    MachLoadCommand(MachLoadCommand),
    FatHeader(FatHeader),
    FatArchTable(FatArchTable),
}

impl Structure {
    #[must_use]
    pub const fn kind(&self) -> StructureKind {
        match self {
            Self::PeDosHeader(_) => StructureKind::PeDosHeader,
            Self::PeSignature(_) => StructureKind::PeSignature,
            Self::CoffHeader(_) => StructureKind::CoffHeader,
            Self::CoffBigObjHeader(_) => StructureKind::CoffBigObjHeader,
            Self::PeOptionalHeader(_) => StructureKind::PeOptionalHeader,
            Self::PeDataDirectories(_) => StructureKind::PeDataDirectories,
            Self::CoffSectionTable(_) => StructureKind::CoffSectionTable,
            Self::ElfHeader(_) => StructureKind::ElfHeader,
            Self::ElfProgramHeaders(_) => StructureKind::ElfProgramHeaders,
            Self::ElfSectionHeaders(_) => StructureKind::ElfSectionHeaders,
            Self::MachHeader(_) => StructureKind::MachHeader,
            Self::MachLoadCommand(_) => StructureKind::MachLoadCommand,
            Self::FatHeader(_) => StructureKind::FatHeader,
            Self::FatArchTable(_) => StructureKind::FatArchTable,
        }
    }

    #[must_use]
    pub const fn encoded_len(&self) -> u64 {
        match self {
            Self::PeDosHeader(_) => PeDosHeader::ENCODED_LEN,
            Self::PeSignature(_) => PeSignature::ENCODED_LEN,
            Self::CoffHeader(_) => CoffHeader::ENCODED_LEN,
            Self::CoffBigObjHeader(_) => CoffBigObjHeader::ENCODED_LEN,
            Self::PeOptionalHeader(value) => value.encoded_len(),
            Self::PeDataDirectories(value) => value.encoded_len(),
            Self::CoffSectionTable(value) => value.encoded_len(),
            Self::ElfHeader(value) => value.encoded_len(),
            Self::ElfProgramHeaders(value) => value.encoded_len(),
            Self::ElfSectionHeaders(value) => value.encoded_len(),
            Self::MachHeader(value) => value.encoded_len(),
            Self::MachLoadCommand(value) => value.encoded_len(),
            Self::FatHeader(_) => FatHeader::ENCODED_LEN,
            Self::FatArchTable(value) => value.encoded_len(),
        }
    }

    const fn endian(&self) -> Endian {
        match self {
            Self::PeDosHeader(_)
            | Self::PeSignature(_)
            | Self::CoffHeader(_)
            | Self::CoffBigObjHeader(_)
            | Self::PeOptionalHeader(_)
            | Self::PeDataDirectories(_)
            | Self::CoffSectionTable(_) => Endian::Little,
            Self::ElfHeader(value) => value.endian,
            Self::ElfProgramHeaders(value) => value.endian,
            Self::ElfSectionHeaders(value) => value.endian,
            Self::MachHeader(value) => value.endian,
            Self::MachLoadCommand(value) => value.endian,
            Self::FatHeader(value) => value.endian,
            Self::FatArchTable(value) => value.endian,
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        let mut writer: FieldWriter<'_> = FieldWriter::new(out, self.endian());
        match self {
            Self::PeDosHeader(value) => value.encode(&mut writer),
            Self::PeSignature(value) => value.encode(&mut writer),
            Self::CoffHeader(value) => value.encode(&mut writer),
            Self::CoffBigObjHeader(value) => value.encode(&mut writer),
            Self::PeOptionalHeader(value) => value.encode(&mut writer),
            Self::PeDataDirectories(value) => value.encode(&mut writer),
            Self::CoffSectionTable(value) => value.encode(&mut writer),
            Self::ElfHeader(value) => value.encode(&mut writer),
            Self::ElfProgramHeaders(value) => value.encode(&mut writer),
            Self::ElfSectionHeaders(value) => value.encode(&mut writer),
            Self::MachHeader(value) => value.encode(&mut writer),
            Self::MachLoadCommand(value) => value.encode(&mut writer),
            Self::FatHeader(value) => value.encode(&mut writer),
            Self::FatArchTable(value) => value.encode(&mut writer),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedStructure {
    start: u64,
    len: u64,
    body: Structure,
}

impl PlannedStructure {
    #[must_use]
    pub const fn start(&self) -> u64 {
        self.start
    }

    #[must_use]
    pub const fn end(&self) -> u64 {
        self.start.saturating_add(self.len)
    }

    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[must_use]
    pub const fn kind(&self) -> StructureKind {
        self.body.kind()
    }

    #[must_use]
    pub const fn body(&self) -> &Structure {
        &self.body
    }

    pub const fn body_mut(&mut self) -> &mut Structure {
        &mut self.body
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DerivedKind {
    PeChecksum,
    PeAuthenticode,
    MachCodeSignature,
    ElfGnuBuildId,
}

impl DerivedKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::PeChecksum => "pe-checksum",
            Self::PeAuthenticode => "pe-authenticode",
            Self::MachCodeSignature => "mach-code-signature",
            Self::ElfGnuBuildId => "elf-gnu-build-id",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedValue {
    pub kind: DerivedKind,
    pub field_start: u64,
    pub field_end: u64,
    pub covered_start: u64,
    pub covered_end: u64,
    pub detail: String,
}

impl DerivedValue {
    #[must_use]
    pub const fn invalidated_by(&self, start: u64, end: u64) -> bool {
        intersects(start, end, self.field_start, self.field_end)
            || intersects(start, end, self.covered_start, self.covered_end)
    }
}

const fn intersects(first_start: u64, first_end: u64, second_start: u64, second_end: u64) -> bool {
    first_start < second_end && second_start < first_end
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanCoverage {
    pub file_len: u64,
    pub structure_bytes: u64,
    pub opaque_bytes: u64,
    pub structure_count: usize,
    pub opaque_count: usize,
}

impl PlanCoverage {
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        match self.structure_bytes.checked_add(self.opaque_bytes) {
            Some(total) => total == self.file_len,
            None => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImagePlan {
    schema: &'static str,
    format: NativeFormat,
    file_len: u64,
    structures: Vec<PlannedStructure>,
    derived: Vec<DerivedValue>,
}

impl ImagePlan {
    #[must_use]
    pub const fn schema(&self) -> &'static str {
        self.schema
    }

    #[must_use]
    pub const fn format(&self) -> NativeFormat {
        self.format
    }

    #[must_use]
    pub const fn file_len(&self) -> u64 {
        self.file_len
    }

    #[must_use]
    pub fn structures(&self) -> &[PlannedStructure] {
        &self.structures
    }

    pub const fn structures_mut(&mut self) -> &mut [PlannedStructure] {
        self.structures.as_mut_slice()
    }

    #[must_use]
    pub fn derived_values(&self) -> &[DerivedValue] {
        &self.derived
    }

    #[must_use]
    pub fn coverage(&self) -> PlanCoverage {
        let mut structure_bytes: u64 = 0;
        let mut opaque_bytes: u64 = 0;
        let mut opaque_count: usize = 0;
        let mut cursor: u64 = 0;
        for structure in &self.structures {
            if structure.start > cursor {
                opaque_bytes = opaque_bytes.saturating_add(structure.start - cursor);
                opaque_count = opaque_count.saturating_add(1);
            }
            structure_bytes = structure_bytes.saturating_add(structure.len);
            cursor = structure.end();
        }
        if cursor < self.file_len {
            opaque_bytes = opaque_bytes.saturating_add(self.file_len - cursor);
            opaque_count = opaque_count.saturating_add(1);
        }

        PlanCoverage {
            file_len: self.file_len,
            structure_bytes,
            opaque_bytes,
            structure_count: self.structures.len(),
            opaque_count,
        }
    }

    pub fn emit(&self, source: &[u8]) -> Result<Vec<u8>> {
        let source_len: u64 =
            u64::try_from(source.len()).map_err(|_error: std::num::TryFromIntError| {
                rewrite_error("source length overflows")
            })?;
        if source_len != self.file_len {
            return Err(rewrite_error(format!(
                "the plan describes a {} byte image but the source holds {source_len} bytes",
                self.file_len
            )));
        }

        let capacity: usize =
            usize::try_from(self.file_len).map_err(|_error: std::num::TryFromIntError| {
                rewrite_error("image length overflows usize")
            })?;
        let mut out: Vec<u8> = Vec::with_capacity(capacity);
        let mut cursor: u64 = 0;

        for structure in &self.structures {
            if structure.start < cursor {
                return Err(rewrite_error(format!(
                    "`{}` at {} overlaps the structure that ends at {cursor}",
                    structure.kind().label(),
                    structure.start
                )));
            }
            copy_opaque(&mut out, source, cursor, structure.start)?;
            let before: usize = out.len();
            structure.body.encode_into(&mut out);
            let written: u64 = u64::try_from(out.len().saturating_sub(before)).map_err(
                |_error: std::num::TryFromIntError| rewrite_error("encoded length overflows"),
            )?;
            if written != structure.len {
                return Err(Error::RewriteUnsupported {
                    format: self.format.label(),
                    construct: format!(
                        "`{}` at {} was planned as {} bytes but re-encodes to {written}",
                        structure.kind().label(),
                        structure.start,
                        structure.len
                    ),
                });
            }
            cursor = structure.end();
        }
        copy_opaque(&mut out, source, cursor, self.file_len)?;

        let emitted: u64 =
            u64::try_from(out.len()).map_err(|_error: std::num::TryFromIntError| {
                rewrite_error("output length overflows")
            })?;
        if emitted != self.file_len {
            return Err(rewrite_error(format!(
                "re-emission produced {emitted} bytes for a {} byte image",
                self.file_len
            )));
        }

        Ok(out)
    }

    #[must_use]
    pub fn stale_after(&self, start: u64, end: u64) -> Vec<DerivedValue> {
        self.derived
            .iter()
            .filter(|value: &&DerivedValue| value.invalidated_by(start, end))
            .cloned()
            .collect()
    }
}

fn copy_opaque(out: &mut Vec<u8>, source: &[u8], start: u64, end: u64) -> Result<()> {
    if end <= start {
        return Ok(());
    }
    let start_index: usize = usize::try_from(start)
        .map_err(|_error: std::num::TryFromIntError| rewrite_error("opaque start overflows"))?;
    let end_index: usize = usize::try_from(end)
        .map_err(|_error: std::num::TryFromIntError| rewrite_error("opaque end overflows"))?;
    let slice: &[u8] = source.get(start_index..end_index).ok_or_else(|| {
        rewrite_error(format!(
            "opaque range {start}..{end} falls outside the input"
        ))
    })?;
    out.extend_from_slice(slice);
    Ok(())
}

#[derive(Debug)]
pub(crate) struct PlanBuilder {
    format: NativeFormat,
    file_len: u64,
    structures: Vec<PlannedStructure>,
    derived: Vec<DerivedValue>,
}

impl PlanBuilder {
    pub(crate) const fn new(format: NativeFormat, file_len: u64) -> Self {
        Self {
            format,
            file_len,
            structures: Vec::new(),
            derived: Vec::new(),
        }
    }

    pub(crate) const fn file_len(&self) -> u64 {
        self.file_len
    }

    pub(crate) const fn format(&self) -> NativeFormat {
        self.format
    }

    pub(crate) fn push(&mut self, start: u64, body: Structure) -> Result<()> {
        let len: u64 = body.encoded_len();
        if len == 0 {
            return Err(rewrite_error(format!(
                "`{}` at {start} models zero bytes",
                body.kind().label()
            )));
        }
        let end: u64 = start.checked_add(len).ok_or_else(|| {
            rewrite_error(format!(
                "`{}` at {start} overflows the offset space",
                body.kind().label()
            ))
        })?;
        if end > self.file_len {
            return Err(rewrite_error(format!(
                "`{}` spans {start}..{end}, past the {} byte input",
                body.kind().label(),
                self.file_len
            )));
        }
        if self.structures.len() >= MAX_PLAN_STRUCTURES {
            return Err(rewrite_error(format!(
                "the input models more than {MAX_PLAN_STRUCTURES} structures"
            )));
        }
        self.structures.push(PlannedStructure { start, len, body });
        Ok(())
    }

    pub(crate) fn derive(&mut self, value: DerivedValue) {
        self.derived.push(value);
    }

    pub(crate) fn finish(mut self) -> Result<ImagePlan> {
        self.structures
            .sort_by(|left: &PlannedStructure, right: &PlannedStructure| {
                left.start.cmp(&right.start).then(left.len.cmp(&right.len))
            });

        let mut cursor: u64 = 0;
        for structure in &self.structures {
            if structure.start < cursor {
                return Err(Error::RewriteUnsupported {
                    format: self.format.label(),
                    construct: format!(
                        "`{}` at {} overlaps a structure that ends at {cursor}, so one byte would \
                         be re-encoded twice",
                        structure.kind().label(),
                        structure.start
                    ),
                });
            }
            cursor = structure.end();
        }

        self.derived
            .sort_by(|left: &DerivedValue, right: &DerivedValue| {
                left.field_start
                    .cmp(&right.field_start)
                    .then(left.kind.cmp(&right.kind))
            });
        self.derived
            .dedup_by(|left: &mut DerivedValue, right: &mut DerivedValue| left == right);

        Ok(ImagePlan {
            schema: IMAGE_PLAN_SCHEMA,
            format: self.format,
            file_len: self.file_len,
            structures: self.structures,
            derived: self.derived,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEdit {
    pub offset: u64,
    pub bytes: Vec<u8>,
}

impl FileEdit {
    #[must_use]
    pub const fn new(offset: u64, bytes: Vec<u8>) -> Self {
        Self { offset, bytes }
    }

    #[must_use]
    pub const fn end(&self) -> u64 {
        self.offset.saturating_add(self.bytes.len() as u64)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedFileEdit {
    pub offset: u64,
    pub original: Vec<u8>,
    pub replacement: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchReport {
    pub schema: String,
    pub format: NativeFormat,
    pub file_len: u64,
    pub applied: Vec<AppliedFileEdit>,
    pub bytes_changed: u64,
    pub stale: Vec<DerivedValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchedImage {
    pub bytes: Vec<u8>,
    pub report: PatchReport,
}

pub fn plan_native_image(bytes: &[u8]) -> Result<ImagePlan> {
    dbg_section("image-plan");
    if bytes.is_empty() {
        return Err(rewrite_error("input is empty, so it models no image"));
    }

    let format: NativeFormat = detect_native_format(bytes)?;
    dbg_kv("rewrite.format", || format.label().to_owned());

    let plan: ImagePlan = match format {
        NativeFormat::Pe32 | NativeFormat::Pe64 => pe::plan(bytes, format)?,
        NativeFormat::Elf32 | NativeFormat::Elf64 => elf::plan(bytes, format)?,
        NativeFormat::MachO32 | NativeFormat::MachO64 => macho::plan_thin(bytes, format)?,
        NativeFormat::MachOFat => macho::plan_fat(bytes)?,
        NativeFormat::Coff => coff::plan(bytes)?,
        NativeFormat::NeWindows | NativeFormat::NeOs2 => {
            return Err(Error::RewriteUnsupported {
                format: format.label(),
                construct:
                    "the new-executable segment, resource, relocation and entry tables have \
                            no typed model in this writer"
                        .to_owned(),
            });
        }
        NativeFormat::Wasm => {
            return Err(Error::RewriteUnsupported {
                format: format.label(),
                construct: "the WebAssembly section stream has no typed model in this writer"
                    .to_owned(),
            });
        }
    };

    let coverage: PlanCoverage = plan.coverage();
    if !coverage.is_complete() {
        return Err(rewrite_error(format!(
            "the plan accounts for {} structure and {} opaque bytes of a {} byte image",
            coverage.structure_bytes, coverage.opaque_bytes, coverage.file_len
        )));
    }
    dbg_kv("rewrite.structures", || {
        coverage.structure_count.to_string()
    });
    dbg_kv("rewrite.structure-bytes", || {
        coverage.structure_bytes.to_string()
    });

    Ok(plan)
}

pub fn emit_native_image(bytes: &[u8]) -> Result<Vec<u8>> {
    let plan: ImagePlan = plan_native_image(bytes)?;
    plan.emit(bytes)
}

pub fn patch_native_image(bytes: &[u8], edits: &[FileEdit]) -> Result<PatchedImage> {
    let plan: ImagePlan = plan_native_image(bytes)?;
    if edits.len() > MAX_EDITS {
        return Err(rewrite_error(format!(
            "{} edits exceed the {MAX_EDITS} edit ceiling",
            edits.len()
        )));
    }

    let mut ordered: Vec<&FileEdit> = edits.iter().collect();
    ordered.sort_by_key(|edit: &&FileEdit| (edit.offset, edit.bytes.len()));

    let mut patched: Vec<u8> = bytes.to_vec();
    let mut applied: Vec<AppliedFileEdit> = Vec::with_capacity(ordered.len());
    let mut bytes_changed: u64 = 0;
    let mut stale: Vec<DerivedValue> = Vec::new();
    let mut previous_end: u64 = 0;

    for edit in ordered {
        if edit.bytes.is_empty() {
            return Err(rewrite_error(format!(
                "the edit at {} replaces zero bytes",
                edit.offset
            )));
        }
        let end: u64 = edit
            .offset
            .checked_add(edit.bytes.len() as u64)
            .ok_or_else(|| {
                rewrite_error(format!(
                    "the edit at {} overflows the offset space",
                    edit.offset
                ))
            })?;
        if end > plan.file_len() {
            return Err(rewrite_error(format!(
                "the edit at {} spans past the {} byte image",
                edit.offset,
                plan.file_len()
            )));
        }
        if edit.offset < previous_end {
            return Err(rewrite_error(format!(
                "the edit at {} overlaps the edit that ends at {previous_end}",
                edit.offset
            )));
        }
        previous_end = end;

        let start_index: usize =
            usize::try_from(edit.offset).map_err(|_error: std::num::TryFromIntError| {
                rewrite_error("an edit offset overflows usize")
            })?;
        let end_index: usize =
            usize::try_from(end).map_err(|_error: std::num::TryFromIntError| {
                rewrite_error("an edit range overflows usize")
            })?;
        let window: &mut [u8] = patched
            .get_mut(start_index..end_index)
            .ok_or_else(|| rewrite_error("an edit range falls outside the image"))?;
        let original: Vec<u8> = window.to_vec();
        window.copy_from_slice(&edit.bytes);

        let differing: u64 = original
            .iter()
            .zip(edit.bytes.iter())
            .filter(|(before, after): &(&u8, &u8)| before != after)
            .count() as u64;
        if differing > 0 {
            bytes_changed = bytes_changed.saturating_add(differing);
            for value in plan.stale_after(edit.offset, end) {
                if !stale.contains(&value) {
                    stale.push(value);
                }
            }
        }
        applied.push(AppliedFileEdit {
            offset: edit.offset,
            original,
            replacement: edit.bytes.clone(),
        });
    }

    let repatched: ImagePlan = plan_native_image(&patched)?;
    let emitted: Vec<u8> = repatched.emit(&patched)?;
    if emitted != patched {
        return Err(Error::RewriteUnsupported {
            format: plan.format().label(),
            construct: "the patched image does not re-emit to the bytes it was spliced from, so a \
                        structure the edit touched is not reproducible"
                .to_owned(),
        });
    }

    stale.sort_by(|left: &DerivedValue, right: &DerivedValue| {
        left.field_start
            .cmp(&right.field_start)
            .then(left.kind.cmp(&right.kind))
    });

    Ok(PatchedImage {
        report: PatchReport {
            schema: IMAGE_PLAN_SCHEMA.to_owned(),
            format: plan.format(),
            file_len: plan.file_len(),
            applied,
            bytes_changed,
            stale,
        },
        bytes: emitted,
    })
}

pub(crate) fn rewrite_error(message: impl Into<String>) -> Error {
    Error::Rewrite(message.into())
}

pub(crate) fn rewrite_read_error(subject: &str, error: ByteReadError) -> Error {
    rewrite_error(format!("{subject} is truncated: {error}"))
}

pub(crate) fn unsupported(format: NativeFormat, construct: impl Into<String>) -> Error {
    Error::RewriteUnsupported {
        format: format.label(),
        construct: construct.into(),
    }
}

pub(crate) fn bounded_entries(
    format: NativeFormat,
    subject: &str,
    declared: u64,
    entry_size: u64,
    available: u64,
) -> Result<usize> {
    if declared > MAX_TABLE_ENTRIES {
        return Err(unsupported(
            format,
            format!("{subject} declares {declared} entries, above the {MAX_TABLE_ENTRIES} ceiling"),
        ));
    }
    let needed: u64 = declared
        .checked_mul(entry_size)
        .ok_or_else(|| rewrite_error(format!("{subject} range overflows")))?;
    if needed > available {
        return Err(rewrite_error(format!(
            "{subject} declares {declared} entries needing {needed} bytes, more than the \
             {available} bytes that follow it"
        )));
    }
    usize::try_from(declared)
        .map_err(|_error: std::num::TryFromIntError| rewrite_error(format!("{subject} overflows")))
}
