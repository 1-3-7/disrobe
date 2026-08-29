use disrobe_bytes::ByteReader;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::pe::{ClrHeader, DataDirectory, PeImage};

pub const R2R_MAGIC: u32 = 0x0052_5452;
const R2R_HEADER_LEN: usize = 16;
const R2R_SECTION_LEN: usize = 12;
const MAX_R2R_SECTIONS: u32 = 1024;
const MAX_R2R_RUNTIME_FUNCTIONS: usize = 1_048_576;
const MACHINE_I386: u16 = 0x014C;
const MACHINE_ARM: u16 = 0x01C0;
const MACHINE_ARMNT: u16 = 0x01C4;
const MACHINE_AMD64: u16 = 0x8664;
const MACHINE_ARM64: u16 = 0xAA64;
const MAX_SUPPORTED_R2R_MAJOR_VERSION: u16 = 27;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct R2rHeader {
    pub magic: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub flags: u32,
    pub number_of_sections: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct R2rReport {
    pub present: bool,
    pub header: Option<R2rHeader>,
    pub sections: Vec<R2rSection>,
    pub runtime_functions: R2rRuntimeFunctions,
    pub crossgen2_native_aot: bool,
    pub composite_image: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct R2rSection {
    #[serde(rename = "type")]
    pub section_type: u32,
    pub name: String,
    pub rva: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct R2rAmd64RuntimeFunction {
    #[serde(rename = "unwind_info_start_rva")]
    pub unwind_info_start: R2rRva,
    #[serde(rename = "unwind_info_end_rva")]
    pub unwind_info_end: R2rRva,
    #[serde(rename = "gc_info_start_rva")]
    pub gc_info_start: R2rRva,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct R2rUnwindGcRuntimeFunction {
    pub unwind_info_start_rva: R2rRva,
    pub gc_info_start_rva: R2rRva,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum R2rUnwindGcMachine {
    X86,
    Arm,
    ArmNt,
    Arm64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "layout", rename_all = "snake_case")]
pub enum R2rRuntimeFunctions {
    #[default]
    Absent,
    Amd64 {
        entries: Vec<R2rAmd64RuntimeFunction>,
    },
    UnwindGcInfo {
        machine: R2rUnwindGcMachine,
        entries: Vec<R2rUnwindGcRuntimeFunction>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct R2rRva(pub u32);

pub fn detect(image: &[u8], pe: &PeImage, clr: &ClrHeader) -> Result<R2rReport> {
    if clr.managed_native_header.rva == 0 || clr.managed_native_header.size == 0 {
        return Ok(absent_report());
    }
    let (header, sections, runtime_functions): (R2rHeader, Vec<R2rSection>, R2rRuntimeFunctions) =
        parse(image, pe, clr)?;
    let composite_image: bool = (header.flags & 0x0000_0001) != 0;
    let crossgen2_native_aot: bool = (header.flags & 0x0000_0080) != 0;
    Ok(R2rReport {
        present: true,
        header: Some(header),
        sections,
        runtime_functions,
        crossgen2_native_aot,
        composite_image,
    })
}

const fn absent_report() -> R2rReport {
    R2rReport {
        present: false,
        header: None,
        sections: Vec::new(),
        runtime_functions: R2rRuntimeFunctions::Absent,
        crossgen2_native_aot: false,
        composite_image: false,
    }
}

pub fn parse_header(image: &[u8], pe: &PeImage, clr: &ClrHeader) -> Result<R2rHeader> {
    parse(image, pe, clr)
        .map(|(header, _, _): (R2rHeader, Vec<R2rSection>, R2rRuntimeFunctions)| header)
}

fn parse(
    image: &[u8],
    pe: &PeImage,
    clr: &ClrHeader,
) -> Result<(R2rHeader, Vec<R2rSection>, R2rRuntimeFunctions)> {
    let dir: DataDirectory = clr.managed_native_header;
    if dir.size < R2R_HEADER_LEN as u32 {
        return Err(Error::Truncated {
            offset: dir.rva as usize,
            needed: R2R_HEADER_LEN,
            had: dir.size as usize,
        });
    }
    let directory_size: usize = dir.size as usize;
    let slice: &[u8] = pe
        .slice_exact_file_backed_rva(image, dir.rva, directory_size)
        .ok_or(Error::Truncated {
            offset: dir.rva as usize,
            needed: directory_size,
            had: 0,
        })?;
    let mut reader: ByteReader<'_> = ByteReader::new(slice);
    let magic: u32 = reader.read_u32_le()?;
    if magic != R2R_MAGIC {
        return Err(Error::BadR2rMagic(magic));
    }
    let major_version: u16 = reader.read_u16_le()?;
    let minor_version: u16 = reader.read_u16_le()?;
    if !(1..=MAX_SUPPORTED_R2R_MAJOR_VERSION).contains(&major_version) {
        return Err(Error::UnsupportedR2rVersion(u32::from(major_version)));
    }
    let flags: u32 = reader.read_u32_le()?;
    let number_of_sections: u32 = reader.read_u32_le()?;
    if number_of_sections > MAX_R2R_SECTIONS {
        return Err(Error::TooManyR2rSections {
            count: number_of_sections,
            cap: MAX_R2R_SECTIONS,
        });
    }
    let section_count: usize = number_of_sections as usize;
    let sections_size: usize =
        section_count
            .checked_mul(R2R_SECTION_LEN)
            .ok_or(Error::TooManyR2rSections {
                count: number_of_sections,
                cap: MAX_R2R_SECTIONS,
            })?;
    let required_size: usize =
        R2R_HEADER_LEN
            .checked_add(sections_size)
            .ok_or(Error::TooManyR2rSections {
                count: number_of_sections,
                cap: MAX_R2R_SECTIONS,
            })?;
    if required_size > directory_size {
        return Err(Error::Truncated {
            offset: dir.rva as usize,
            needed: required_size,
            had: directory_size,
        });
    }
    let header: R2rHeader = R2rHeader {
        magic,
        major_version,
        minor_version,
        flags,
        number_of_sections,
    };
    let mut sections: Vec<R2rSection> = Vec::with_capacity(section_count);
    let mut previous_type: Option<u32> = None;
    for index in 0..section_count {
        let section_type: u32 = reader.read_u32_le()?;
        let rva: u32 = reader.read_u32_le()?;
        let size: u32 = reader.read_u32_le()?;
        if previous_type.is_some_and(|previous: u32| section_type <= previous) {
            return Err(Error::InvalidR2rSectionTable {
                index,
                reason: "section types are not strictly increasing",
            });
        }
        if size != 0 {
            let section_size: usize = size as usize;
            if pe
                .slice_exact_file_backed_rva(image, rva, section_size)
                .is_none()
            {
                return Err(Error::InvalidR2rSectionTable {
                    index,
                    reason: "section range is not wholly file backed",
                });
            }
        }
        sections.push(R2rSection {
            section_type,
            name: section_name(section_type),
            rva,
            size,
        });
        previous_type = Some(section_type);
    }
    let runtime_functions: R2rRuntimeFunctions = sections
        .iter()
        .find(|section: &&R2rSection| section.section_type == 102)
        .map_or_else(
            || Ok(R2rRuntimeFunctions::Absent),
            |section: &R2rSection| parse_runtime_functions(image, pe, section),
        )?;
    Ok((header, sections, runtime_functions))
}

fn parse_runtime_functions(
    image: &[u8],
    pe: &PeImage,
    section: &R2rSection,
) -> Result<R2rRuntimeFunctions> {
    let unwind_gc_machine: Option<R2rUnwindGcMachine> = match pe.machine {
        MACHINE_AMD64 => None,
        MACHINE_I386 => Some(R2rUnwindGcMachine::X86),
        MACHINE_ARM => Some(R2rUnwindGcMachine::Arm),
        MACHINE_ARMNT => Some(R2rUnwindGcMachine::ArmNt),
        MACHINE_ARM64 => Some(R2rUnwindGcMachine::Arm64),
        _ => {
            return Err(Error::InvalidR2rRuntimeFunctions {
                index: 0,
                reason: "PE machine has no supported ReadyToRun runtime-function layout",
            });
        }
    };
    let entry_size: usize = if unwind_gc_machine.is_some() { 8 } else { 12 };
    let section_size: usize = section.size as usize;
    if !section_size.is_multiple_of(entry_size) {
        return Err(Error::InvalidR2rRuntimeFunctions {
            index: section_size / entry_size,
            reason: "section size is not divisible by the machine entry width",
        });
    }
    let entry_count: usize = section_size / entry_size;
    if entry_count > MAX_R2R_RUNTIME_FUNCTIONS {
        return Err(Error::InvalidR2rRuntimeFunctions {
            index: entry_count,
            reason: "runtime-function count exceeds parser limit",
        });
    }
    if section_size == 0 {
        return Ok(unwind_gc_machine.map_or_else(
            || R2rRuntimeFunctions::Amd64 {
                entries: Vec::new(),
            },
            |machine: R2rUnwindGcMachine| R2rRuntimeFunctions::UnwindGcInfo {
                machine,
                entries: Vec::new(),
            },
        ));
    }
    let bytes: &[u8] = pe
        .slice_exact_file_backed_rva(image, section.rva, section_size)
        .ok_or(Error::InvalidR2rRuntimeFunctions {
            index: 0,
            reason: "runtime-function table is not wholly file backed",
        })?;
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    if let Some(machine) = unwind_gc_machine {
        let mut entries: Vec<R2rUnwindGcRuntimeFunction> = Vec::with_capacity(entry_count);
        for index in 0..entry_count {
            let unwind_info_start_rva: u32 = reader.read_u32_le()?;
            let gc_info_start_rva: u32 = reader.read_u32_le()?;
            if pe
                .slice_exact_file_backed_rva(image, unwind_info_start_rva, 1)
                .is_none()
            {
                return Err(Error::InvalidR2rRuntimeFunctions {
                    index,
                    reason: "runtime-function unwind-info RVA is not file backed",
                });
            }
            if pe
                .slice_exact_file_backed_rva(image, gc_info_start_rva, 1)
                .is_none()
            {
                return Err(Error::InvalidR2rRuntimeFunctions {
                    index,
                    reason: "runtime-function GC-info RVA is not file backed",
                });
            }
            entries.push(R2rUnwindGcRuntimeFunction {
                unwind_info_start_rva: R2rRva(unwind_info_start_rva),
                gc_info_start_rva: R2rRva(gc_info_start_rva),
            });
        }
        return Ok(R2rRuntimeFunctions::UnwindGcInfo { machine, entries });
    }
    let mut entries: Vec<R2rAmd64RuntimeFunction> = Vec::with_capacity(entry_count);
    for index in 0..entry_count {
        let unwind_info_start_rva: u32 = reader.read_u32_le()?;
        let unwind_info_end_rva: u32 = reader.read_u32_le()?;
        let gc_info_start_rva: u32 = reader.read_u32_le()?;
        let size: u32 = unwind_info_end_rva
            .checked_sub(unwind_info_start_rva)
            .ok_or(Error::InvalidR2rRuntimeFunctions {
                index,
                reason: "unwind-info end is before its start",
            })?;
        if size == 0
            || pe
                .slice_exact_file_backed_rva(image, unwind_info_start_rva, size as usize)
                .is_none()
        {
            return Err(Error::InvalidR2rRuntimeFunctions {
                index,
                reason: "unwind-info range is not wholly file backed",
            });
        }
        if pe
            .slice_exact_file_backed_rva(image, gc_info_start_rva, 1)
            .is_none()
        {
            return Err(Error::InvalidR2rRuntimeFunctions {
                index,
                reason: "GC-info start RVA is not file backed",
            });
        }
        entries.push(R2rAmd64RuntimeFunction {
            unwind_info_start: R2rRva(unwind_info_start_rva),
            unwind_info_end: R2rRva(unwind_info_end_rva),
            gc_info_start: R2rRva(gc_info_start_rva),
        });
    }
    Ok(R2rRuntimeFunctions::Amd64 { entries })
}

fn section_name(section_type: u32) -> String {
    let known: Option<&'static str> = match section_type {
        100 => Some("compiler_identifier"),
        101 => Some("import_sections"),
        102 => Some("runtime_functions"),
        103 => Some("method_def_entry_points"),
        104 => Some("exception_info"),
        105 => Some("debug_info"),
        106 => Some("delay_load_method_call_thunks"),
        108 => Some("available_types"),
        109 => Some("instance_method_entry_points"),
        110 => Some("inlining_info"),
        111 => Some("profile_data_info"),
        112 => Some("manifest_metadata"),
        113 => Some("attribute_presence"),
        114 => Some("inlining_info_2"),
        115 => Some("component_assemblies"),
        116 => Some("owner_composite_executable"),
        117 => Some("pgo_instrumentation_data"),
        118 => Some("manifest_assembly_mvids"),
        119 => Some("cross_module_inline_info"),
        120 => Some("hot_cold_map"),
        121 => Some("method_is_generic_map"),
        122 => Some("enclosing_type_map"),
        123 => Some("type_generic_info_map"),
        124 => Some("external_type_maps"),
        125 => Some("proxy_type_maps"),
        126 => Some("type_map_assembly_targets"),
        _ => None,
    };
    known.map_or_else(|| format!("unknown_{section_type}"), str::to_owned)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::pe::{PeBitness, SectionHeader};

    #[test]
    fn r2r_magic_matches_rtr_ascii() {
        assert_eq!(R2R_MAGIC.to_le_bytes(), [b'R', b'T', b'R', 0]);
    }

    #[test]
    fn arm64_runtime_functions_preserve_unwind_and_gc_fields() {
        let mut image: Vec<u8> = vec![0; 0x80];
        image[0x20..0x24].copy_from_slice(&0x1040u32.to_le_bytes());
        image[0x24..0x28].copy_from_slice(&0x1050u32.to_le_bytes());
        let pe: PeImage = PeImage {
            bitness: PeBitness::Pe32Plus,
            machine: MACHINE_ARM64,
            number_of_sections: 1,
            timestamp: 0,
            characteristics: 0,
            entry_point_rva: 0,
            image_base: 0,
            data_directories: Vec::new(),
            sections: vec![SectionHeader {
                name: ".data".to_owned(),
                virtual_size: 0x80,
                virtual_address: 0x1000,
                raw_size: 0x80,
                raw_pointer: 0,
                characteristics: 0,
            }],
        };
        let section: R2rSection = R2rSection {
            section_type: 102,
            name: "runtime_functions".to_owned(),
            rva: 0x1020,
            size: 8,
        };
        let decoded: R2rRuntimeFunctions =
            parse_runtime_functions(&image, &pe, &section).expect("arm64 runtime functions");

        assert_eq!(
            serde_json::to_value(decoded).expect("serialize arm64 runtime functions"),
            serde_json::json!({
                "layout": "unwind_gc_info",
                "machine": "arm64",
                "entries": [{"unwind_info_start_rva": 4160, "gc_info_start_rva": 4176}]
            })
        );
    }
}
