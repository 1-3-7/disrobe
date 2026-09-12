use std::borrow::Cow;

use disrobe_binfmt::containers::decompress_lznt1;
use disrobe_binfmt::quota::{ExtractionQuota, QuotaGuard};
use disrobe_bytes::ByteReader;
use serde::{Deserialize, Serialize};

use super::{PeImage, parse_pe_image};
use crate::debug::{dbg_kv, dbg_section};
use crate::error::{Error, Result};

const MAX_RECOVERED_BYTES: usize = 64 * 1024 * 1024;
const DONUT_INSTANCE_START: usize = 5;
const DONUT_CLEAR_HEADER_SIZE: usize = 576;
const DONUT_GO_MODULE_OFFSET: usize = 2_336;
const DONUT_MODULE_HEADER_SIZE: usize = 1_320;
const DONUT_MODULE_DATA_OFFSET: usize = DONUT_GO_MODULE_OFFSET + DONUT_MODULE_HEADER_SIZE;
const DONUT_GO_MODULE_LEN_OFFSET: usize = 2_328;
const DONUT_GO_COMPRESSION_OFFSET: usize = DONUT_GO_MODULE_OFFSET + 8;
const DONUT_GO_COMPRESSED_LEN_OFFSET: usize = DONUT_GO_MODULE_OFFSET + 1_312;
const DONUT_GO_ORIGINAL_LEN_OFFSET: usize = DONUT_GO_MODULE_OFFSET + 1_316;
const DONUT_MODULE_SERIALIZED_PADDING: u64 = 8;
const DONUT_MAX_API_HASHES: u32 = 64;
const SRDI_X86_BOOTSTRAP_SIZE: usize = 50;
const SRDI_X64_BOOTSTRAP_SIZE: usize = 69;
const DOS_HEADER_SIZE: usize = 64;
const DOS_LFANEW_OFFSET: usize = 0x3C;
const COFF_HEADER_SIZE: usize = 20;
const PE32_OPTIONAL_HEADER_SIZE: usize = 224;
const PE32_PLUS_OPTIONAL_HEADER_SIZE: usize = 240;
const PE_MACHINE_X86: u16 = 0x014C;
const PE_MACHINE_X64: u16 = 0x8664;
const PE_IMAGE_FILE_DLL: u16 = 0x2000;
const PE_CLR_DIRECTORY_INDEX: usize = 14;
const CLR_HEADER_SIZE: usize = 72;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum RecoveryField<T> {
    Known { value: T },
    Unknown { reason: String },
}

impl<T> RecoveryField<T> {
    fn known(value: T) -> Self {
        Self::Known { value }
    }

    fn unknown(reason: impl Into<String>) -> Self {
        Self::Unknown {
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteRegion {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoaderFamily {
    Donut,
    Srdi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoaderArchitecture {
    X86,
    X64,
    X86AndX64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoaderVariant {
    GoDonutV1,
    DonutUnknown,
    SrdiV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WrappedModuleFormat {
    Pe32,
    Pe32Plus,
    JavaScript,
    VbScript,
    Xsl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DonutEntropy {
    None,
    RandomNames,
    Encrypted,
    Unknown { value: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DonutCompression {
    None,
    Lznt1,
    Xpress,
    XpressHuffman,
    Unknown { value: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DonutModuleType {
    ManagedDll,
    ManagedExe,
    NativeDll,
    NativeExe,
    VbScript,
    JavaScript,
    Xsl,
    Unknown { value: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DonutConfig {
    pub entropy: DonutEntropy,
    pub api_hash_count: RecoveryField<u32>,
    pub module_type: RecoveryField<DonutModuleType>,
    pub compression: RecoveryField<DonutCompression>,
    pub module_header_region: RecoveryField<ByteRegion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SrdiConfig {
    pub function_hash: u32,
    pub flags: u32,
    pub user_data_region: RecoveryField<ByteRegion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "family", content = "value", rename_all = "kebab-case")]
pub enum LoaderConfig {
    Donut(DonutConfig),
    Srdi(SrdiConfig),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedModuleMetadata {
    pub region: RecoveryField<ByteRegion>,
    pub format: RecoveryField<WrappedModuleFormat>,
    pub stored_size: RecoveryField<u64>,
    pub original_size: RecoveryField<u64>,
    pub entry_point_rva: RecoveryField<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoaderInspection {
    pub family: LoaderFamily,
    pub variant: LoaderVariant,
    pub architecture: LoaderArchitecture,
    pub config_region: ByteRegion,
    pub config: LoaderConfig,
    pub wrapped_module: WrappedModuleMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoaderRecovery {
    pub inspection: LoaderInspection,
    pub module: RecoveryField<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoaderFingerprint {
    pub family: LoaderFamily,
    pub architecture: LoaderArchitecture,
    pub config_region: ByteRegion,
    pub wrapped_module_region: ByteRegion,
    pub matched_offset: u64,
}

#[derive(Debug, Clone, Copy)]
struct SrdiBootstrap {
    architecture: LoaderArchitecture,
    size: usize,
    function_hash: u32,
    user_data_location: u32,
    user_data_length: u32,
    dll_offset: u32,
    flags: u32,
}

#[derive(Debug, Clone, Copy)]
struct SrdiRegions {
    module_start: usize,
    module_length: usize,
    user_start: usize,
    user_length: usize,
}

#[derive(Debug, Clone)]
struct DonutOuter {
    architecture: LoaderArchitecture,
    instance_start: usize,
    instance_end: usize,
    instance_length: usize,
    key: [u8; 16],
    counter: [u8; 16],
    entropy: DonutEntropy,
}

#[derive(Debug)]
struct DonutDecoded {
    config: DonutConfig,
    metadata: WrappedModuleMetadata,
    module: RecoveryField<Vec<u8>>,
    validation: DonutModuleValidation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DonutModuleValidation {
    Validated,
    Refused,
}

#[must_use]
pub fn fingerprint_loader(bytes: &[u8]) -> Option<LoaderFingerprint> {
    if let Some(bootstrap) = identify_srdi(bytes) {
        let regions: SrdiRegions = srdi_regions(bytes, bootstrap).ok()?;
        let module_end: usize = regions.module_start.checked_add(regions.module_length)?;
        let module: &[u8] = bytes.get(regions.module_start..module_end)?;
        let _pe: PeImage = parse_loader_pe(module, bootstrap.architecture).ok()?;
        return Some(LoaderFingerprint {
            family: LoaderFamily::Srdi,
            architecture: bootstrap.architecture,
            config_region: region(0, bootstrap.size),
            wrapped_module_region: region(regions.module_start, regions.module_length),
            matched_offset: 0,
        });
    }

    if donut_candidate(bytes) {
        let outer: DonutOuter = parse_donut_outer(bytes).ok()?;
        let decoded: Vec<u8> = decode_donut_instance(bytes, &outer).ok()?;
        let validated: DonutDecoded = parse_donut_decoded(&decoded, &outer, false).ok()?;
        if validated.validation != DonutModuleValidation::Validated {
            return None;
        }
        let RecoveryField::Known {
            value: wrapped_module_region,
        } = validated.metadata.region
        else {
            return None;
        };
        return Some(LoaderFingerprint {
            family: LoaderFamily::Donut,
            architecture: outer.architecture,
            config_region: region(outer.instance_start, outer.instance_length),
            wrapped_module_region,
            matched_offset: 0,
        });
    }

    None
}

pub fn recover_loader(bytes: &[u8]) -> Result<LoaderRecovery> {
    dbg_section("loader-generator-recovery");
    dbg_kv("input_bytes", || bytes.len().to_string());

    if let Some(bootstrap) = identify_srdi(bytes) {
        dbg_kv("loader_family", || "srdi".to_owned());
        return Ok(recover_srdi(bytes, bootstrap));
    }

    if donut_candidate(bytes) {
        dbg_kv("loader_family", || "donut".to_owned());
        let outer: DonutOuter = parse_donut_outer(bytes)?;
        return Ok(recover_donut(bytes, &outer));
    }

    Err(loader_error(
        "identify",
        "input does not match a bounded Donut or sRDI loader fingerprint",
    ))
}

fn identify_srdi(bytes: &[u8]) -> Option<SrdiBootstrap> {
    if fixed_at(bytes, 0, &[0xE8, 0, 0, 0, 0, 0x59, 0x49, 0x89, 0xC8, 0xBA])
        && fixed_at(bytes, 14, &[0x49, 0x81, 0xC0])
        && fixed_at(bytes, 21, &[0x41, 0xB9])
        && fixed_at(
            bytes,
            27,
            &[
                0x56, 0x48, 0x89, 0xE6, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x89,
                0x4C, 0x24, 0x28, 0x48, 0x81, 0xC1,
            ],
        )
        && fixed_at(bytes, 51, &[0xC7, 0x44, 0x24, 0x20])
        && fixed_at(
            bytes,
            59,
            &[0xE8, 0x05, 0, 0, 0, 0x48, 0x89, 0xF4, 0x5E, 0xC3],
        )
    {
        return Some(SrdiBootstrap {
            architecture: LoaderArchitecture::X64,
            size: SRDI_X64_BOOTSTRAP_SIZE,
            function_hash: read_u32_at(bytes, 10, "sRDI function hash").ok()?,
            user_data_location: read_u32_at(bytes, 17, "sRDI user data offset").ok()?,
            user_data_length: read_u32_at(bytes, 23, "sRDI user data length").ok()?,
            dll_offset: read_u32_at(bytes, 47, "sRDI DLL offset").ok()?,
            flags: read_u32_at(bytes, 55, "sRDI flags").ok()?,
        });
    }

    if fixed_at(
        bytes,
        0,
        &[0xE8, 0, 0, 0, 0, 0x58, 0x55, 0x89, 0xE5, 0x89, 0xC2, 0x68],
    ) && fixed_at(bytes, 16, &[0x50, 0x81, 0xC2])
        && fixed_at(bytes, 23, &[0x68])
        && fixed_at(bytes, 28, &[0x52, 0x68])
        && fixed_at(bytes, 34, &[0x05])
        && fixed_at(
            bytes,
            39,
            &[0x50, 0xE8, 0x05, 0, 0, 0, 0x83, 0xC4, 0x14, 0xC9, 0xC3],
        )
    {
        return Some(SrdiBootstrap {
            architecture: LoaderArchitecture::X86,
            size: SRDI_X86_BOOTSTRAP_SIZE,
            function_hash: read_u32_at(bytes, 30, "sRDI function hash").ok()?,
            user_data_location: read_u32_at(bytes, 19, "sRDI user data offset").ok()?,
            user_data_length: read_u32_at(bytes, 24, "sRDI user data length").ok()?,
            dll_offset: read_u32_at(bytes, 35, "sRDI DLL offset").ok()?,
            flags: read_u32_at(bytes, 12, "sRDI flags").ok()?,
        });
    }

    None
}

fn recover_srdi(bytes: &[u8], bootstrap: SrdiBootstrap) -> LoaderRecovery {
    let region_result: Result<SrdiRegions> = srdi_regions(bytes, bootstrap);
    let regions: SrdiRegions = match region_result {
        Ok(value) => value,
        Err(error) => {
            let reason: String = error.to_string();
            dbg_kv("recovery_status", || "unknown".to_owned());
            return LoaderRecovery {
                inspection: LoaderInspection {
                    family: LoaderFamily::Srdi,
                    variant: LoaderVariant::SrdiV1,
                    architecture: bootstrap.architecture,
                    config_region: region(0, bootstrap.size),
                    config: LoaderConfig::Srdi(SrdiConfig {
                        function_hash: bootstrap.function_hash,
                        flags: bootstrap.flags,
                        user_data_region: RecoveryField::unknown(reason.clone()),
                    }),
                    wrapped_module: unknown_metadata(reason.clone()),
                },
                module: RecoveryField::unknown(reason),
            };
        }
    };

    let module_end: usize = regions.module_start + regions.module_length;
    let module_bytes: &[u8] = &bytes[regions.module_start..module_end];
    let user_region: ByteRegion = region(regions.user_start, regions.user_length);
    let module_region: ByteRegion = region(regions.module_start, regions.module_length);
    let pe_result: Result<PeImage> = parse_loader_pe(module_bytes, bootstrap.architecture)
        .and_then(|pe: PeImage| {
            admit_loader_entry(
                "sRDI wrapped module",
                module_region.length,
                module_region.length,
            )?;
            Ok(pe)
        });

    let (metadata, module): (WrappedModuleMetadata, RecoveryField<Vec<u8>>) = match pe_result {
        Ok(pe) => (
            pe_metadata(module_region, module_region.length, &pe),
            RecoveryField::known(module_bytes.to_vec()),
        ),
        Err(error) => {
            let reason: String = error.to_string();
            (
                region_known_metadata(module_region, module_region.length, reason.clone()),
                RecoveryField::unknown(reason),
            )
        }
    };

    if matches!(module, RecoveryField::Known { .. }) {
        dbg_kv("recovered_bytes", || regions.module_length.to_string());
    } else {
        dbg_kv("recovery_status", || "unknown".to_owned());
    }

    LoaderRecovery {
        inspection: LoaderInspection {
            family: LoaderFamily::Srdi,
            variant: LoaderVariant::SrdiV1,
            architecture: bootstrap.architecture,
            config_region: region(0, bootstrap.size),
            config: LoaderConfig::Srdi(SrdiConfig {
                function_hash: bootstrap.function_hash,
                flags: bootstrap.flags,
                user_data_region: RecoveryField::known(user_region),
            }),
            wrapped_module: metadata,
        },
        module,
    }
}

fn srdi_regions(bytes: &[u8], bootstrap: SrdiBootstrap) -> Result<SrdiRegions> {
    let base: usize = 5;
    let dll_offset: usize = usize::try_from(bootstrap.dll_offset).map_err(|_| {
        loader_error(
            "sRDI config",
            "DLL offset does not fit the host address size",
        )
    })?;
    let user_offset: usize = usize::try_from(bootstrap.user_data_location).map_err(|_| {
        loader_error(
            "sRDI config",
            "user data region offset does not fit the host address size",
        )
    })?;
    let user_length: usize = usize::try_from(bootstrap.user_data_length).map_err(|_| {
        loader_error(
            "sRDI config",
            "user data region length does not fit the host address size",
        )
    })?;
    if user_length > MAX_RECOVERED_BYTES {
        return Err(loader_error(
            "sRDI config",
            "user data region exceeds the 64 MiB cap",
        ));
    }
    let module_start: usize = base
        .checked_add(dll_offset)
        .ok_or_else(|| loader_error("sRDI config", "DLL region offset overflow"))?;
    let user_start: usize = base
        .checked_add(user_offset)
        .ok_or_else(|| loader_error("sRDI config", "user data region offset overflow"))?;
    let user_end: usize = user_start
        .checked_add(user_length)
        .ok_or_else(|| loader_error("sRDI config", "user data region length overflow"))?;
    if user_end > bytes.len() {
        return Err(loader_error(
            "sRDI config",
            format!(
                "user data region ends at {user_end}, beyond {} input bytes",
                bytes.len()
            ),
        ));
    }
    if module_start < bootstrap.size {
        return Err(loader_error(
            "sRDI config",
            "DLL region overlaps the bootstrap",
        ));
    }
    let module_length: usize = user_start.checked_sub(module_start).ok_or_else(|| {
        loader_error(
            "sRDI config",
            "user data region precedes the wrapped module",
        )
    })?;
    if module_length == 0 || module_length > MAX_RECOVERED_BYTES {
        return Err(loader_error(
            "sRDI config",
            "wrapped module size is zero or exceeds the 64 MiB cap",
        ));
    }
    Ok(SrdiRegions {
        module_start,
        module_length,
        user_start,
        user_length,
    })
}

fn donut_candidate(bytes: &[u8]) -> bool {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    let Ok(opcode): core::result::Result<u8, _> = reader.read_u8() else {
        return false;
    };
    if opcode != 0xE8 {
        return false;
    }
    let Ok(prefix_length): core::result::Result<u32, _> = reader.read_u32_le() else {
        return false;
    };
    let Ok(nested_length): core::result::Result<u32, _> = reader.read_u32_le() else {
        return false;
    };
    let Ok(prefix_length_usize): core::result::Result<usize, _> = usize::try_from(prefix_length)
    else {
        return false;
    };
    prefix_length == nested_length && prefix_length_usize >= DONUT_MODULE_DATA_OFFSET
}

fn parse_donut_outer(bytes: &[u8]) -> Result<DonutOuter> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    let opcode: u8 = read_u8(&mut reader, "Donut prefix")?;
    if opcode != 0xE8 {
        return Err(loader_error("Donut prefix", "missing call opcode"));
    }
    let declared_length: u32 = read_u32(&mut reader, "Donut instance length")?;
    let instance_length: usize = usize::try_from(declared_length).map_err(|_| {
        loader_error(
            "Donut prefix",
            "instance length does not fit the host address size",
        )
    })?;
    if instance_length > MAX_RECOVERED_BYTES {
        return Err(loader_error(
            "Donut prefix",
            "instance length exceeds the 64 MiB cap",
        ));
    }
    if instance_length < DONUT_MODULE_DATA_OFFSET {
        return Err(loader_error(
            "Donut prefix",
            "instance is shorter than the embedded config layout",
        ));
    }
    let instance_end: usize = DONUT_INSTANCE_START
        .checked_add(instance_length)
        .ok_or_else(|| loader_error("Donut prefix", "instance region overflow"))?;
    let instance: &[u8] = read_bytes_at(
        bytes,
        DONUT_INSTANCE_START,
        instance_length,
        "Donut instance",
    )?;
    let mut instance_reader: ByteReader<'_> = ByteReader::new(instance);
    let nested_length: u32 = read_u32(&mut instance_reader, "Donut nested instance length")?;
    if nested_length != declared_length {
        return Err(loader_error(
            "Donut prefix",
            "outer and nested instance lengths differ",
        ));
    }
    let mut key: [u8; 16] = [0u8; 16];
    key.copy_from_slice(read_bytes(&mut instance_reader, 16, "Donut instance key")?);
    let mut counter: [u8; 16] = [0u8; 16];
    counter.copy_from_slice(read_bytes(
        &mut instance_reader,
        16,
        "Donut instance counter",
    )?);
    instance_reader
        .seek(564)
        .map_err(|error| read_error("Donut entropy", error))?;
    let entropy_raw: u32 = read_u32(&mut instance_reader, "Donut entropy")?;
    let entropy: DonutEntropy = donut_entropy(entropy_raw);
    let pop: u8 = read_u8_at(bytes, instance_end, "Donut pop opcode")?;
    if pop != 0x59 {
        return Err(loader_error(
            "Donut prefix",
            "instance is not followed by the expected pop opcode",
        ));
    }
    let architecture: LoaderArchitecture = donut_architecture(bytes, instance_end + 1)
        .ok_or_else(|| loader_error("Donut stub", "unrecognized architecture preamble"))?;
    Ok(DonutOuter {
        architecture,
        instance_start: DONUT_INSTANCE_START,
        instance_end,
        instance_length,
        key,
        counter,
        entropy,
    })
}

fn recover_donut(bytes: &[u8], outer: &DonutOuter) -> LoaderRecovery {
    let decoded: Vec<u8> = match decode_donut_instance(bytes, outer) {
        Ok(value) => value,
        Err(error) => return unknown_donut(outer, error.to_string()),
    };

    match parse_donut_decoded(&decoded, outer, true) {
        Ok(result) => {
            if let RecoveryField::Known { value } = &result.module {
                dbg_kv("recovered_bytes", || value.len().to_string());
            } else {
                dbg_kv("recovery_status", || "unknown".to_owned());
            }
            LoaderRecovery {
                inspection: LoaderInspection {
                    family: LoaderFamily::Donut,
                    variant: LoaderVariant::GoDonutV1,
                    architecture: outer.architecture,
                    config_region: region(outer.instance_start, outer.instance_length),
                    config: LoaderConfig::Donut(result.config),
                    wrapped_module: result.metadata,
                },
                module: result.module,
            }
        }
        Err(error) => {
            dbg_kv("recovery_status", || "unknown".to_owned());
            unknown_donut(outer, error.to_string())
        }
    }
}

fn decode_donut_instance(bytes: &[u8], outer: &DonutOuter) -> Result<Vec<u8>> {
    let instance: &[u8] = &bytes[outer.instance_start..outer.instance_end];
    let instance_size: u64 = u64::try_from(instance.len())
        .map_err(|_| donut_module_error("instance length does not fit u64"))?;
    admit_loader_entry("Donut decoded instance", instance_size, instance_size)?;
    let mut decoded: Vec<u8> = instance.to_vec();
    match outer.entropy {
        DonutEntropy::Encrypted => {
            chaskey_ctr_xor(
                &mut decoded[DONUT_CLEAR_HEADER_SIZE..],
                outer.key,
                outer.counter,
            );
        }
        DonutEntropy::None | DonutEntropy::RandomNames => {}
        DonutEntropy::Unknown { value } => {
            return Err(donut_module_error(format!(
                "entropy mode {value} is unknown"
            )));
        }
    }
    Ok(decoded)
}

fn parse_donut_decoded(
    decoded: &[u8],
    outer: &DonutOuter,
    materialize: bool,
) -> Result<DonutDecoded> {
    let api_hash_count: u32 = read_u32_at(
        decoded,
        DONUT_CLEAR_HEADER_SIZE,
        "Donut module header API count",
    )?;
    if api_hash_count == 0 || api_hash_count > DONUT_MAX_API_HASHES {
        return Err(donut_module_error(format!(
            "API hash count {api_hash_count} is outside 1..={DONUT_MAX_API_HASHES}"
        )));
    }
    let serialized_module_length: u64 = read_u64_at(
        decoded,
        DONUT_GO_MODULE_LEN_OFFSET,
        "Donut module header length",
    )?;
    let mut reader: ByteReader<'_> = ByteReader::new(decoded);
    reader
        .seek(DONUT_GO_MODULE_OFFSET)
        .map_err(|error| read_error("Donut module header", error))?;
    let module_type_raw: u32 = read_u32(&mut reader, "Donut module type")?;
    let thread: u32 = read_u32(&mut reader, "Donut module thread mode")?;
    if reader.position() != DONUT_GO_COMPRESSION_OFFSET {
        return Err(donut_module_error(
            "serialized compression field offset mismatch",
        ));
    }
    let compression_raw: u32 = read_u32(&mut reader, "Donut module compression")?;
    read_bytes(&mut reader, 5 * 256, "Donut module names")?;
    let unicode: u32 = read_u32(&mut reader, "Donut module Unicode mode")?;
    let signature: &[u8] = read_bytes(&mut reader, 8, "Donut module signature")?;
    let mac: u64 = read_u64(&mut reader, "Donut module MAC")?;
    if reader.position() != DONUT_GO_COMPRESSED_LEN_OFFSET {
        return Err(donut_module_error(
            "serialized compressed length field offset mismatch",
        ));
    }
    let compressed_length: u32 = read_u32(&mut reader, "Donut compressed length")?;
    if reader.position() != DONUT_GO_ORIGINAL_LEN_OFFSET {
        return Err(donut_module_error(
            "serialized original length field offset mismatch",
        ));
    }
    let original_length: u32 = read_u32(&mut reader, "Donut original length")?;
    if reader.position() != DONUT_MODULE_DATA_OFFSET {
        return Err(donut_module_error("serialized header size mismatch"));
    }
    if thread > 1 || unicode > 1 {
        return Err(donut_module_error(
            "thread or Unicode mode is outside the supported boolean range",
        ));
    }
    if signature.iter().any(|byte: &u8| *byte != 0) || mac != 0 {
        return Err(donut_module_error(
            "go-donut PIC module integrity fields are not zero",
        ));
    }
    let module_type: DonutModuleType = donut_module_type(module_type_raw);
    let compression: DonutCompression = go_donut_compression(compression_raw);
    let original_size: usize = usize::try_from(original_length)
        .map_err(|_| donut_module_error("original length does not fit the host address size"))?;
    let original_size_u64: u64 = u64::from(original_length);
    if original_size == 0 || original_size > MAX_RECOVERED_BYTES {
        return Err(donut_module_error(
            "original length is zero or exceeds the 64 MiB cap",
        ));
    }
    let header_region: ByteRegion = region(
        outer.instance_start + DONUT_GO_MODULE_OFFSET,
        DONUT_MODULE_HEADER_SIZE,
    );
    let config: DonutConfig = DonutConfig {
        entropy: outer.entropy,
        api_hash_count: RecoveryField::known(api_hash_count),
        module_type: RecoveryField::known(module_type),
        compression: RecoveryField::known(compression),
        module_header_region: RecoveryField::known(header_region),
    };
    let (stored_size, storage_compression): (usize, DonutCompression) = match compression {
        DonutCompression::None => {
            if compressed_length != 0 {
                return Err(donut_module_error(
                    "uncompressed module has a nonzero compressed length",
                ));
            }
            (original_size, DonutCompression::None)
        }
        DonutCompression::Lznt1 | DonutCompression::Xpress | DonutCompression::XpressHuffman
            if compressed_length == 0 =>
        {
            (original_size, DonutCompression::None)
        }
        DonutCompression::Unknown { .. } if compressed_length == 0 => (original_size, compression),
        DonutCompression::Lznt1
        | DonutCompression::Xpress
        | DonutCompression::XpressHuffman
        | DonutCompression::Unknown { .. } => (
            usize::try_from(compressed_length).map_err(|_| {
                donut_module_error("compressed length does not fit the host address size")
            })?,
            compression,
        ),
    };
    if stored_size == 0 || stored_size > MAX_RECOVERED_BYTES {
        return Err(donut_module_error(
            "stored length is zero or exceeds the 64 MiB cap",
        ));
    }
    let stored_size_u64: u64 = u64::try_from(stored_size)
        .map_err(|_| donut_module_error("stored length does not fit u64"))?;
    let expected_serialized_length: u64 = (DONUT_MODULE_HEADER_SIZE as u64)
        .checked_add(stored_size_u64)
        .and_then(|value: u64| value.checked_add(DONUT_MODULE_SERIALIZED_PADDING))
        .ok_or_else(|| donut_module_error("serialized module length overflow"))?;
    if serialized_module_length != expected_serialized_length {
        return Err(donut_module_error(format!(
            "serialized module length {serialized_module_length} does not match {expected_serialized_length}"
        )));
    }
    let data_end: usize = DONUT_MODULE_DATA_OFFSET
        .checked_add(stored_size)
        .ok_or_else(|| donut_module_error("module data region overflow"))?;
    let module_bytes: &[u8] = decoded
        .get(DONUT_MODULE_DATA_OFFSET..data_end)
        .ok_or_else(|| donut_module_error("module data region exceeds the instance"))?;
    let tail: &[u8] = decoded
        .get(data_end..)
        .ok_or_else(|| donut_module_error("module padding region is invalid"))?;
    if tail.iter().any(|byte: &u8| *byte != 0) {
        return Err(donut_module_error(
            "module padding is nonzero after instance decoding",
        ));
    }
    let module_region: ByteRegion =
        region(outer.instance_start + DONUT_MODULE_DATA_OFFSET, stored_size);
    let (metadata, module, validation): (
        WrappedModuleMetadata,
        RecoveryField<Vec<u8>>,
        DonutModuleValidation,
    ) = donut_module_output(
        module_bytes,
        module_region,
        original_size,
        original_size_u64,
        module_type,
        storage_compression,
        outer.architecture,
        materialize,
    );
    Ok(DonutDecoded {
        config,
        metadata,
        module,
        validation,
    })
}

fn donut_module_output(
    module_bytes: &[u8],
    module_region: ByteRegion,
    original_size: usize,
    original_size_u64: u64,
    module_type: DonutModuleType,
    compression: DonutCompression,
    architecture: LoaderArchitecture,
    materialize: bool,
) -> (
    WrappedModuleMetadata,
    RecoveryField<Vec<u8>>,
    DonutModuleValidation,
) {
    if let DonutModuleType::Unknown { value } = module_type {
        let reason: String = format!("Go Donut module type value {value} is unknown");
        return compressed_module_unknown(module_region, original_size_u64, module_type, reason);
    }
    if let Err(error) = admit_loader_entry(
        "Donut wrapped module",
        original_size_u64,
        module_region.length,
    ) {
        let reason: String = error.to_string();
        return compressed_module_unknown(module_region, original_size_u64, module_type, reason);
    }
    let payload: Cow<'_, [u8]> = match compression {
        DonutCompression::None => Cow::Borrowed(module_bytes),
        DonutCompression::Lznt1 => {
            let decoded: Vec<u8> = match decompress_lznt1(module_bytes, original_size_u64) {
                Ok(value) => value,
                Err(error) => {
                    let reason: String = format!("Go Donut LZNT1 decompression failed: {error}");
                    return compressed_module_unknown(
                        module_region,
                        original_size_u64,
                        module_type,
                        reason,
                    );
                }
            };
            if decoded.len() != original_size {
                let reason: String = format!(
                    "Go Donut LZNT1 decompression produced {} bytes, expected {original_size}",
                    decoded.len()
                );
                return compressed_module_unknown(
                    module_region,
                    original_size_u64,
                    module_type,
                    reason,
                );
            }
            Cow::Owned(decoded)
        }
        DonutCompression::Xpress | DonutCompression::XpressHuffman => {
            let reason: String = format!(
                "Go Donut compression {} has no in-tree static decoder",
                go_donut_compression_label(compression)
            );
            return compressed_module_unknown(
                module_region,
                original_size_u64,
                module_type,
                reason,
            );
        }
        DonutCompression::Unknown { value } => {
            let reason: String = format!("Go Donut compression value {value} is unknown");
            return compressed_module_unknown(
                module_region,
                original_size_u64,
                module_type,
                reason,
            );
        }
    };
    let payload_bytes: &[u8] = payload.as_ref();

    match module_type {
        DonutModuleType::ManagedDll
        | DonutModuleType::ManagedExe
        | DonutModuleType::NativeDll
        | DonutModuleType::NativeExe => match parse_loader_pe(payload_bytes, architecture) {
            Ok(pe) => match validate_donut_pe_module(payload_bytes, &pe, module_type) {
                Ok(()) => {
                    let module: RecoveryField<Vec<u8>> = if materialize {
                        RecoveryField::known(payload.into_owned())
                    } else {
                        RecoveryField::unknown("inspection did not copy the module")
                    };
                    (
                        pe_metadata(module_region, original_size_u64, &pe),
                        module,
                        DonutModuleValidation::Validated,
                    )
                }
                Err(error) => {
                    let reason: String = error.to_string();
                    (
                        pe_metadata(module_region, original_size_u64, &pe),
                        RecoveryField::unknown(reason),
                        DonutModuleValidation::Refused,
                    )
                }
            },
            Err(error) => {
                let reason: String =
                    format!("Donut module header describes PE data that does not parse: {error}");
                (
                    region_known_metadata(module_region, original_size_u64, reason.clone()),
                    RecoveryField::unknown(reason),
                    DonutModuleValidation::Refused,
                )
            }
        },
        DonutModuleType::VbScript => script_output(
            module_region,
            original_size_u64,
            WrappedModuleFormat::VbScript,
        ),
        DonutModuleType::JavaScript => script_output(
            module_region,
            original_size_u64,
            WrappedModuleFormat::JavaScript,
        ),
        DonutModuleType::Xsl => {
            script_output(module_region, original_size_u64, WrappedModuleFormat::Xsl)
        }
        DonutModuleType::Unknown { value } => {
            let reason: String = format!("Donut module type {value} is unknown");
            (
                region_known_metadata(module_region, original_size_u64, reason.clone()),
                RecoveryField::unknown(reason),
                DonutModuleValidation::Refused,
            )
        }
    }
}

fn script_output(
    module_region: ByteRegion,
    original_size: u64,
    format: WrappedModuleFormat,
) -> (
    WrappedModuleMetadata,
    RecoveryField<Vec<u8>>,
    DonutModuleValidation,
) {
    let label: &'static str = wrapped_module_format_label(format);
    let reason: String = donut_module_error(format!(
        "declared {label} module requires a static parser before recovery"
    ))
    .to_string();
    (
        WrappedModuleMetadata {
            region: RecoveryField::known(module_region),
            format: RecoveryField::known(format),
            stored_size: RecoveryField::known(module_region.length),
            original_size: RecoveryField::known(original_size),
            entry_point_rva: RecoveryField::unknown(reason.clone()),
        },
        RecoveryField::unknown(reason),
        DonutModuleValidation::Refused,
    )
}

fn validate_donut_pe_module(
    bytes: &[u8],
    pe: &PeImage,
    module_type: DonutModuleType,
) -> Result<()> {
    let label: &'static str = donut_module_type_label(module_type);
    let declared_dll: bool = matches!(
        module_type,
        DonutModuleType::ManagedDll | DonutModuleType::NativeDll
    );
    let actual_dll: bool = pe.coff_characteristics & PE_IMAGE_FILE_DLL != 0;
    if declared_dll != actual_dll {
        return Err(donut_module_error(format!(
            "declared {label} module conflicts with PE DLL characteristic {actual_dll}"
        )));
    }
    let clr: Option<super::DataDirectory> =
        pe.data_directories.get(PE_CLR_DIRECTORY_INDEX).copied();
    let has_clr: bool = clr.is_some_and(|directory: super::DataDirectory| {
        directory.virtual_address != 0 || directory.size != 0
    });
    match module_type {
        DonutModuleType::ManagedDll | DonutModuleType::ManagedExe => {
            let directory: super::DataDirectory = clr.ok_or_else(|| {
                donut_module_error(format!("declared {label} module has no CLR data directory"))
            })?;
            validate_clr_directory(bytes, pe, directory, label)
        }
        DonutModuleType::NativeDll | DonutModuleType::NativeExe => {
            if has_clr {
                return Err(donut_module_error(format!(
                    "declared {label} module carries a CLR data directory"
                )));
            }
            Ok(())
        }
        DonutModuleType::VbScript
        | DonutModuleType::JavaScript
        | DonutModuleType::Xsl
        | DonutModuleType::Unknown { .. } => Err(donut_module_error(format!(
            "declared {label} module is not a PE type"
        ))),
    }
}

fn validate_clr_directory(
    bytes: &[u8],
    pe: &PeImage,
    directory: super::DataDirectory,
    label: &str,
) -> Result<()> {
    let minimum_size: u32 = u32::try_from(CLR_HEADER_SIZE)
        .map_err(|_| donut_module_error("CLR header size exceeds u32"))?;
    if directory.virtual_address == 0 || directory.size < minimum_size {
        return Err(donut_module_error(format!(
            "declared {label} module has an invalid CLR data directory"
        )));
    }
    let clr_offset: usize = pe
        .file_offset_for_rva(directory.virtual_address, bytes.len())
        .map_err(|error| donut_module_error(format!("CLR header is not file-backed: {error}")))?;
    let header_size: u32 = read_u32_at(bytes, clr_offset, "CLR header size")?;
    let metadata_rva: u32 = read_u32_at(bytes, clr_offset + 8, "CLR metadata RVA")?;
    let metadata_size: u32 = read_u32_at(bytes, clr_offset + 12, "CLR metadata size")?;
    if header_size < minimum_size || header_size > directory.size || metadata_size < 4 {
        return Err(donut_module_error(format!(
            "declared {label} module has an invalid CLR header"
        )));
    }
    let header_size_usize: usize = usize::try_from(header_size)
        .map_err(|_| donut_module_error("CLR header size exceeds usize"))?;
    let clr_end: usize = clr_offset
        .checked_add(header_size_usize)
        .ok_or_else(|| donut_module_error("CLR header range overflows"))?;
    let _: &[u8] = bytes
        .get(clr_offset..clr_end)
        .ok_or_else(|| donut_module_error("CLR header is truncated"))?;
    let metadata_offset: usize = pe
        .file_offset_for_rva(metadata_rva, bytes.len())
        .map_err(|error| donut_module_error(format!("CLR metadata is not file-backed: {error}")))?;
    let metadata_size_usize: usize = usize::try_from(metadata_size)
        .map_err(|_| donut_module_error("CLR metadata size exceeds usize"))?;
    let metadata_end: usize = metadata_offset
        .checked_add(metadata_size_usize)
        .ok_or_else(|| donut_module_error("CLR metadata range overflows"))?;
    let metadata: &[u8] = bytes
        .get(metadata_offset..metadata_end)
        .ok_or_else(|| donut_module_error("CLR metadata is truncated"))?;
    let signature: &[u8] = &metadata[..4];
    if signature != b"BSJB" {
        return Err(donut_module_error(format!(
            "declared {label} module has an invalid CLR metadata signature"
        )));
    }
    Ok(())
}

const fn donut_module_type_label(module_type: DonutModuleType) -> &'static str {
    match module_type {
        DonutModuleType::ManagedDll => "managed-dll",
        DonutModuleType::ManagedExe => "managed-exe",
        DonutModuleType::NativeDll => "native-dll",
        DonutModuleType::NativeExe => "native-exe",
        DonutModuleType::VbScript => "vbscript",
        DonutModuleType::JavaScript => "javascript",
        DonutModuleType::Xsl => "xsl",
        DonutModuleType::Unknown { .. } => "unknown",
    }
}

fn admit_loader_entry(name: &str, uncompressed: u64, stored: u64) -> Result<()> {
    let mut guard: QuotaGuard = QuotaGuard::new(ExtractionQuota::default_safe());
    guard
        .admit_entry(name, uncompressed, stored)
        .map_err(|error| loader_error("loader extraction quota", error.to_string()))
}

const fn wrapped_module_format_label(format: WrappedModuleFormat) -> &'static str {
    match format {
        WrappedModuleFormat::Pe32 => "pe32",
        WrappedModuleFormat::Pe32Plus => "pe32-plus",
        WrappedModuleFormat::JavaScript => "javascript",
        WrappedModuleFormat::VbScript => "vbscript",
        WrappedModuleFormat::Xsl => "xsl",
    }
}

fn compressed_module_unknown(
    module_region: ByteRegion,
    original_size: u64,
    module_type: DonutModuleType,
    reason: String,
) -> (
    WrappedModuleMetadata,
    RecoveryField<Vec<u8>>,
    DonutModuleValidation,
) {
    let format: RecoveryField<WrappedModuleFormat> = compressed_module_format(module_type, &reason);
    (
        WrappedModuleMetadata {
            region: RecoveryField::known(module_region),
            format,
            stored_size: RecoveryField::known(module_region.length),
            original_size: RecoveryField::known(original_size),
            entry_point_rva: RecoveryField::unknown(reason.clone()),
        },
        RecoveryField::unknown(reason),
        DonutModuleValidation::Refused,
    )
}

fn compressed_module_format(
    module_type: DonutModuleType,
    reason: &str,
) -> RecoveryField<WrappedModuleFormat> {
    match module_type {
        DonutModuleType::VbScript => RecoveryField::known(WrappedModuleFormat::VbScript),
        DonutModuleType::JavaScript => RecoveryField::known(WrappedModuleFormat::JavaScript),
        DonutModuleType::Xsl => RecoveryField::known(WrappedModuleFormat::Xsl),
        DonutModuleType::ManagedDll
        | DonutModuleType::ManagedExe
        | DonutModuleType::NativeDll
        | DonutModuleType::NativeExe
        | DonutModuleType::Unknown { .. } => RecoveryField::unknown(reason),
    }
}

fn unknown_donut(outer: &DonutOuter, reason: String) -> LoaderRecovery {
    LoaderRecovery {
        inspection: LoaderInspection {
            family: LoaderFamily::Donut,
            variant: LoaderVariant::DonutUnknown,
            architecture: outer.architecture,
            config_region: region(outer.instance_start, outer.instance_length),
            config: LoaderConfig::Donut(DonutConfig {
                entropy: outer.entropy,
                api_hash_count: RecoveryField::unknown(reason.clone()),
                module_type: RecoveryField::unknown(reason.clone()),
                compression: RecoveryField::unknown(reason.clone()),
                module_header_region: RecoveryField::unknown(reason.clone()),
            }),
            wrapped_module: unknown_metadata(reason.clone()),
        },
        module: RecoveryField::unknown(reason),
    }
}

fn pe_metadata(
    module_region: ByteRegion,
    original_size: u64,
    pe: &PeImage,
) -> WrappedModuleMetadata {
    WrappedModuleMetadata {
        region: RecoveryField::known(module_region),
        format: RecoveryField::known(if pe.is_pe32_plus {
            WrappedModuleFormat::Pe32Plus
        } else {
            WrappedModuleFormat::Pe32
        }),
        stored_size: RecoveryField::known(module_region.length),
        original_size: RecoveryField::known(original_size),
        entry_point_rva: RecoveryField::known(pe.entry_point_rva),
    }
}

fn region_known_metadata(
    module_region: ByteRegion,
    original_size: u64,
    reason: String,
) -> WrappedModuleMetadata {
    WrappedModuleMetadata {
        region: RecoveryField::known(module_region),
        format: RecoveryField::unknown(reason.clone()),
        stored_size: RecoveryField::known(module_region.length),
        original_size: RecoveryField::known(original_size),
        entry_point_rva: RecoveryField::unknown(reason),
    }
}

fn unknown_metadata(reason: String) -> WrappedModuleMetadata {
    WrappedModuleMetadata {
        region: RecoveryField::unknown(reason.clone()),
        format: RecoveryField::unknown(reason.clone()),
        stored_size: RecoveryField::unknown(reason.clone()),
        original_size: RecoveryField::unknown(reason.clone()),
        entry_point_rva: RecoveryField::unknown(reason),
    }
}

const fn donut_entropy(value: u32) -> DonutEntropy {
    match value {
        1 => DonutEntropy::None,
        2 => DonutEntropy::RandomNames,
        3 => DonutEntropy::Encrypted,
        _ => DonutEntropy::Unknown { value },
    }
}

const fn go_donut_compression(value: u32) -> DonutCompression {
    match value {
        1 => DonutCompression::None,
        2 => DonutCompression::Lznt1,
        3 => DonutCompression::Xpress,
        4 => DonutCompression::XpressHuffman,
        _ => DonutCompression::Unknown { value },
    }
}

const fn go_donut_compression_label(compression: DonutCompression) -> &'static str {
    match compression {
        DonutCompression::None => "none",
        DonutCompression::Lznt1 => "LZNT1",
        DonutCompression::Xpress => "XPRESS",
        DonutCompression::XpressHuffman => "XPRESS Huffman",
        DonutCompression::Unknown { .. } => "unknown",
    }
}

const fn donut_module_type(value: u32) -> DonutModuleType {
    match value {
        1 => DonutModuleType::ManagedDll,
        2 => DonutModuleType::ManagedExe,
        3 => DonutModuleType::NativeDll,
        4 => DonutModuleType::NativeExe,
        5 => DonutModuleType::VbScript,
        6 => DonutModuleType::JavaScript,
        7 => DonutModuleType::Xsl,
        _ => DonutModuleType::Unknown { value },
    }
}

fn donut_architecture(bytes: &[u8], offset: usize) -> Option<LoaderArchitecture> {
    if fixed_at(bytes, offset, &[0x5A, 0x51, 0x52]) {
        Some(LoaderArchitecture::X86)
    } else if fixed_at(bytes, offset, &[0x31, 0xC0, 0x48, 0x0F, 0x88]) {
        Some(LoaderArchitecture::X86AndX64)
    } else if fixed_at(bytes, offset, &[0x55, 0x48]) {
        Some(LoaderArchitecture::X64)
    } else {
        None
    }
}

fn parse_loader_pe(bytes: &[u8], architecture: LoaderArchitecture) -> Result<PeImage> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    let dos_magic: &[u8] = read_bytes(&mut reader, 2, "embedded PE DOS header")?;
    if dos_magic != b"MZ" || bytes.len() < DOS_HEADER_SIZE {
        return Err(loader_error(
            "embedded PE",
            "DOS header is missing or truncated",
        ));
    }
    reader
        .seek(DOS_LFANEW_OFFSET)
        .map_err(|error| read_error("embedded PE DOS offset", error))?;
    let pe_offset_raw: u32 = read_u32(&mut reader, "embedded PE DOS offset")?;
    let pe_offset: usize = usize::try_from(pe_offset_raw).map_err(|_| {
        loader_error(
            "embedded PE",
            "PE offset does not fit the host address size",
        )
    })?;
    if pe_offset < DOS_HEADER_SIZE {
        return Err(loader_error(
            "embedded PE",
            "PE header overlaps the DOS header",
        ));
    }
    reader
        .seek(pe_offset)
        .map_err(|error| read_error("embedded PE signature", error))?;
    let signature: &[u8] = read_bytes(&mut reader, 4, "embedded PE signature")?;
    if signature != b"PE\x00\x00" {
        return Err(loader_error("embedded PE", "PE signature is missing"));
    }
    let machine: u16 = read_u16(&mut reader, "embedded PE machine")?;
    let section_count: u16 = read_u16(&mut reader, "embedded PE section count")?;
    if section_count == 0 {
        return Err(loader_error("embedded PE", "PE has no sections"));
    }
    reader
        .skip(12)
        .map_err(|error| read_error("embedded PE COFF header", error))?;
    let optional_size: usize =
        usize::from(read_u16(&mut reader, "embedded PE optional header size")?);
    let _characteristics: u16 = read_u16(&mut reader, "embedded PE characteristics")?;
    let optional_start: usize = pe_offset
        .checked_add(4 + COFF_HEADER_SIZE)
        .ok_or_else(|| loader_error("embedded PE", "optional header offset overflow"))?;
    reader
        .seek(optional_start)
        .map_err(|error| read_error("embedded PE optional header", error))?;
    let optional_magic: u16 = read_u16(&mut reader, "embedded PE optional magic")?;
    let required_optional_size: usize = match optional_magic {
        0x010B => PE32_OPTIONAL_HEADER_SIZE,
        0x020B => PE32_PLUS_OPTIONAL_HEADER_SIZE,
        _ => {
            return Err(loader_error(
                "embedded PE",
                format!("optional header magic 0x{optional_magic:04x} is unsupported"),
            ));
        }
    };
    if optional_size < required_optional_size {
        return Err(loader_error(
            "embedded PE",
            format!(
                "optional header has {optional_size} bytes, fewer than {required_optional_size}"
            ),
        ));
    }
    let optional_end: usize = optional_start
        .checked_add(optional_size)
        .ok_or_else(|| loader_error("embedded PE", "optional header length overflow"))?;
    let section_table_size: usize = usize::from(section_count)
        .checked_mul(40)
        .ok_or_else(|| loader_error("embedded PE", "section table size overflow"))?;
    let section_table_end: usize = optional_end
        .checked_add(section_table_size)
        .ok_or_else(|| loader_error("embedded PE", "section table length overflow"))?;
    if section_table_end > bytes.len() {
        return Err(loader_error(
            "embedded PE",
            "section table extends beyond the module",
        ));
    }
    let machine_matches: bool = match architecture {
        LoaderArchitecture::X86 => machine == PE_MACHINE_X86 && optional_magic == 0x010B,
        LoaderArchitecture::X64 => machine == PE_MACHINE_X64 && optional_magic == 0x020B,
        LoaderArchitecture::X86AndX64 => {
            (machine == PE_MACHINE_X86 && optional_magic == 0x010B)
                || (machine == PE_MACHINE_X64 && optional_magic == 0x020B)
        }
    };
    if !machine_matches {
        return Err(loader_error(
            "embedded PE",
            format!(
                "machine 0x{machine:04x} and optional magic 0x{optional_magic:04x} do not match {architecture:?}"
            ),
        ));
    }
    let pe: PeImage = parse_pe_image(bytes)?;
    for section in &pe.sections {
        if section.raw_size == 0 {
            continue;
        }
        let raw_start: usize = usize::try_from(section.raw_pointer).map_err(|_| {
            loader_error(
                "embedded PE",
                "section offset does not fit the host address size",
            )
        })?;
        let raw_size: usize = usize::try_from(section.raw_size).map_err(|_| {
            loader_error(
                "embedded PE",
                "section size does not fit the host address size",
            )
        })?;
        let raw_end: usize = raw_start
            .checked_add(raw_size)
            .ok_or_else(|| loader_error("embedded PE", "section raw span overflow"))?;
        if raw_end > bytes.len() {
            return Err(loader_error(
                "embedded PE",
                format!(
                    "section raw span {raw_start}..{raw_end} exceeds {} module bytes",
                    bytes.len()
                ),
            ));
        }
    }
    if pe.entry_point_rva != 0 && pe.section_containing_rva(pe.entry_point_rva).is_none() {
        return Err(loader_error(
            "embedded PE",
            "entry point RVA is outside every section",
        ));
    }
    Ok(pe)
}

const fn region(offset: usize, length: usize) -> ByteRegion {
    ByteRegion {
        offset: offset as u64,
        length: length as u64,
    }
}

fn fixed_at(bytes: &[u8], offset: usize, expected: &[u8]) -> bool {
    let Ok(actual): Result<&[u8]> = read_bytes_at(bytes, offset, expected.len(), "fingerprint")
    else {
        return false;
    };
    actual == expected
}

fn read_bytes_at<'a>(
    bytes: &'a [u8],
    offset: usize,
    length: usize,
    stage: &'static str,
) -> Result<&'a [u8]> {
    let mut reader: ByteReader<'a> = ByteReader::new(bytes);
    reader
        .seek(offset)
        .map_err(|error| read_error(stage, error))?;
    read_bytes(&mut reader, length, stage)
}

fn read_u8_at(bytes: &[u8], offset: usize, stage: &'static str) -> Result<u8> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(offset)
        .map_err(|error| read_error(stage, error))?;
    read_u8(&mut reader, stage)
}

fn read_u32_at(bytes: &[u8], offset: usize, stage: &'static str) -> Result<u32> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(offset)
        .map_err(|error| read_error(stage, error))?;
    read_u32(&mut reader, stage)
}

fn read_u64_at(bytes: &[u8], offset: usize, stage: &'static str) -> Result<u64> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader
        .seek(offset)
        .map_err(|error| read_error(stage, error))?;
    read_u64(&mut reader, stage)
}

fn read_bytes<'a>(
    reader: &mut ByteReader<'a>,
    length: usize,
    stage: &'static str,
) -> Result<&'a [u8]> {
    reader
        .read_bytes(length)
        .map_err(|error| read_error(stage, error))
}

fn read_u8(reader: &mut ByteReader<'_>, stage: &'static str) -> Result<u8> {
    reader.read_u8().map_err(|error| read_error(stage, error))
}

fn read_u16(reader: &mut ByteReader<'_>, stage: &'static str) -> Result<u16> {
    reader
        .read_u16_le()
        .map_err(|error| read_error(stage, error))
}

fn read_u32(reader: &mut ByteReader<'_>, stage: &'static str) -> Result<u32> {
    reader
        .read_u32_le()
        .map_err(|error| read_error(stage, error))
}

fn read_u64(reader: &mut ByteReader<'_>, stage: &'static str) -> Result<u64> {
    reader
        .read_u64_le()
        .map_err(|error| read_error(stage, error))
}

fn read_error(stage: &'static str, error: disrobe_bytes::ByteReadError) -> Error {
    loader_error(stage, error.to_string())
}

fn donut_module_error(detail: impl Into<String>) -> Error {
    loader_error(
        "Donut module header",
        format!("validation failed: {}", detail.into()),
    )
}

fn loader_error(stage: &'static str, detail: impl Into<String>) -> Error {
    Error::LoaderRecovery {
        stage,
        detail: detail.into(),
    }
}

fn chaskey_ctr_xor(data: &mut [u8], key: [u8; 16], mut counter: [u8; 16]) {
    for chunk in data.chunks_mut(16) {
        let stream: [u8; 16] = chaskey_block(key, counter);
        for (byte, mask) in chunk.iter_mut().zip(stream) {
            *byte ^= mask;
        }
        for byte in counter.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }
}

fn chaskey_block(key: [u8; 16], block: [u8; 16]) -> [u8; 16] {
    let key_words: [u32; 4] = words(key);
    let mut state: [u32; 4] = words(block);
    for index in 0..4 {
        state[index] ^= key_words[index];
    }
    for _round in 0..16 {
        state[0] = state[0].wrapping_add(state[1]);
        state[1] = state[1].rotate_right(27) ^ state[0];
        state[2] = state[2].wrapping_add(state[3]);
        state[3] = state[3].rotate_right(24) ^ state[2];
        state[2] = state[2].wrapping_add(state[1]);
        state[0] = state[0].rotate_right(16).wrapping_add(state[3]);
        state[3] = state[3].rotate_right(19) ^ state[0];
        state[1] = state[1].rotate_right(25) ^ state[2];
        state[2] = state[2].rotate_right(16);
    }
    for index in 0..4 {
        state[index] ^= key_words[index];
    }
    bytes(state)
}

fn words(input: [u8; 16]) -> [u32; 4] {
    [
        u32::from_le_bytes([input[0], input[1], input[2], input[3]]),
        u32::from_le_bytes([input[4], input[5], input[6], input[7]]),
        u32::from_le_bytes([input[8], input[9], input[10], input[11]]),
        u32::from_le_bytes([input[12], input[13], input[14], input[15]]),
    ]
}

fn bytes(input: [u32; 4]) -> [u8; 16] {
    let mut output: [u8; 16] = [0u8; 16];
    for (index, value) in input.into_iter().enumerate() {
        let start: usize = index * 4;
        output[start..start + 4].copy_from_slice(&value.to_le_bytes());
    }
    output
}

#[cfg(all(test, feature = "chain"))]
pub(crate) fn test_go_donut_wrapper(
    template: &[u8],
    module: &[u8],
    module_type: DonutModuleType,
    architecture: LoaderArchitecture,
) -> Result<Vec<u8>> {
    let outer: DonutOuter = parse_donut_outer(template)?;
    let mut decoded: Vec<u8> = decode_donut_instance(template, &outer)?;
    let module_length: u32 = u32::try_from(module.len())
        .map_err(|_| donut_module_error("test module length exceeds u32"))?;
    let serialized_length: u64 = (DONUT_MODULE_HEADER_SIZE as u64)
        .checked_add(u64::from(module_length))
        .and_then(|value: u64| value.checked_add(DONUT_MODULE_SERIALIZED_PADDING))
        .ok_or_else(|| donut_module_error("test serialized module length overflow"))?;
    let module_type_value: u32 = match module_type {
        DonutModuleType::ManagedDll => 1,
        DonutModuleType::ManagedExe => 2,
        DonutModuleType::NativeDll => 3,
        DonutModuleType::NativeExe => 4,
        DonutModuleType::VbScript => 5,
        DonutModuleType::JavaScript => 6,
        DonutModuleType::Xsl => 7,
        DonutModuleType::Unknown { value } => value,
    };
    decoded[DONUT_GO_MODULE_OFFSET..DONUT_GO_MODULE_OFFSET + 4]
        .copy_from_slice(&module_type_value.to_le_bytes());
    decoded[DONUT_GO_COMPRESSION_OFFSET..DONUT_GO_COMPRESSION_OFFSET + 4]
        .copy_from_slice(&1u32.to_le_bytes());
    decoded[DONUT_GO_COMPRESSED_LEN_OFFSET..DONUT_GO_COMPRESSED_LEN_OFFSET + 4]
        .copy_from_slice(&0u32.to_le_bytes());
    decoded[DONUT_GO_ORIGINAL_LEN_OFFSET..DONUT_GO_ORIGINAL_LEN_OFFSET + 4]
        .copy_from_slice(&module_length.to_le_bytes());
    decoded[DONUT_GO_MODULE_LEN_OFFSET..DONUT_GO_MODULE_LEN_OFFSET + 8]
        .copy_from_slice(&serialized_length.to_le_bytes());
    let module_and_padding: &mut [u8] = decoded
        .get_mut(DONUT_MODULE_DATA_OFFSET..)
        .ok_or_else(|| donut_module_error("test module region is absent"))?;
    module_and_padding.fill(0);
    let module_end: usize = DONUT_MODULE_DATA_OFFSET
        .checked_add(module.len())
        .ok_or_else(|| donut_module_error("test module region overflow"))?;
    decoded
        .get_mut(DONUT_MODULE_DATA_OFFSET..module_end)
        .ok_or_else(|| donut_module_error("test module exceeds the Donut instance"))?
        .copy_from_slice(module);
    let mut encoded: Vec<u8> = decoded;
    if outer.entropy == DonutEntropy::Encrypted {
        chaskey_ctr_xor(
            &mut encoded[DONUT_CLEAR_HEADER_SIZE..],
            outer.key,
            outer.counter,
        );
    }
    let mut wrapper: Vec<u8> = template.to_vec();
    wrapper[outer.instance_start..outer.instance_end].copy_from_slice(&encoded);
    let stub_offset: usize = outer
        .instance_end
        .checked_add(1)
        .ok_or_else(|| donut_module_error("test stub offset overflow"))?;
    let signature: &[u8] = match architecture {
        LoaderArchitecture::X86 => &[0x5a, 0x51, 0x52],
        LoaderArchitecture::X64 => &[0x55, 0x48],
        LoaderArchitecture::X86AndX64 => &[0x31, 0xc0, 0x48, 0x0f, 0x88],
    };
    wrapper
        .get_mut(stub_offset..stub_offset + signature.len())
        .ok_or_else(|| donut_module_error("test stub signature is truncated"))?
        .copy_from_slice(signature);
    Ok(wrapper)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN_DONUT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/loader_generators/known.go-donut.bin"
    ));
    const KNOWN_DLL: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/loader_generators/known.dll"
    ));
    const KNOWN_DLL_LZNT1: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/loader_generators/known.dll.lznt1"
    ));

    fn decoded_with_compressed_module(
        compression: u32,
        stored: &[u8],
        original_length: u32,
    ) -> Result<(DonutOuter, Vec<u8>)> {
        let outer: DonutOuter = parse_donut_outer(KNOWN_DONUT)?;
        let mut decoded: Vec<u8> = decode_donut_instance(KNOWN_DONUT, &outer)?;
        let stored_length: u32 = u32::try_from(stored.len())
            .map_err(|_| loader_error("Donut compression test", "stored length exceeds u32"))?;
        let header_length: u64 = u64::try_from(DONUT_MODULE_HEADER_SIZE).map_err(|_| {
            loader_error("Donut compression test", "module header length exceeds u64")
        })?;
        let serialized_length: u64 = header_length
            .checked_add(u64::from(stored_length))
            .and_then(|value: u64| value.checked_add(DONUT_MODULE_SERIALIZED_PADDING))
            .ok_or_else(|| {
                loader_error(
                    "Donut compression test",
                    "serialized module length overflow",
                )
            })?;
        decoded[DONUT_GO_COMPRESSION_OFFSET..DONUT_GO_COMPRESSION_OFFSET + 4]
            .copy_from_slice(&compression.to_le_bytes());
        decoded[DONUT_GO_COMPRESSED_LEN_OFFSET..DONUT_GO_COMPRESSED_LEN_OFFSET + 4]
            .copy_from_slice(&stored_length.to_le_bytes());
        decoded[DONUT_GO_ORIGINAL_LEN_OFFSET..DONUT_GO_ORIGINAL_LEN_OFFSET + 4]
            .copy_from_slice(&original_length.to_le_bytes());
        decoded[DONUT_GO_MODULE_LEN_OFFSET..DONUT_GO_MODULE_LEN_OFFSET + 8]
            .copy_from_slice(&serialized_length.to_le_bytes());
        let module_and_padding: &mut [u8] = decoded
            .get_mut(DONUT_MODULE_DATA_OFFSET..)
            .ok_or_else(|| loader_error("Donut compression test", "module region is invalid"))?;
        module_and_padding.fill(0);
        let data_end: usize = DONUT_MODULE_DATA_OFFSET
            .checked_add(stored.len())
            .ok_or_else(|| loader_error("Donut compression test", "stored region overflow"))?;
        let data_region: &mut [u8] = decoded
            .get_mut(DONUT_MODULE_DATA_OFFSET..data_end)
            .ok_or_else(|| {
                loader_error("Donut compression test", "stored region exceeds instance")
            })?;
        data_region.copy_from_slice(stored);
        Ok((outer, decoded))
    }

    fn wrapper_from_decoded(outer: &DonutOuter, decoded: &[u8]) -> Result<Vec<u8>> {
        if decoded.len() != outer.instance_length {
            return Err(loader_error(
                "Donut compression test",
                "decoded instance length changed",
            ));
        }
        let mut encoded: Vec<u8> = decoded.to_vec();
        match outer.entropy {
            DonutEntropy::Encrypted => {
                let encrypted_region: &mut [u8] =
                    encoded.get_mut(DONUT_CLEAR_HEADER_SIZE..).ok_or_else(|| {
                        loader_error(
                            "Donut compression test",
                            "instance is shorter than the clear header",
                        )
                    })?;
                chaskey_ctr_xor(encrypted_region, outer.key, outer.counter);
            }
            DonutEntropy::None | DonutEntropy::RandomNames => {}
            DonutEntropy::Unknown { value } => {
                return Err(loader_error(
                    "Donut compression test",
                    format!("unsupported entropy mode {value}"),
                ));
            }
        }
        let mut wrapper: Vec<u8> = KNOWN_DONUT.to_vec();
        let instance: &mut [u8] = wrapper
            .get_mut(outer.instance_start..outer.instance_end)
            .ok_or_else(|| loader_error("Donut compression test", "instance region is invalid"))?;
        instance.copy_from_slice(&encoded);
        Ok(wrapper)
    }

    #[test]
    fn chaskey_matches_upstream_vector() {
        let key: [u8; 16] = [
            0x56, 0x09, 0xE9, 0x68, 0x5F, 0x58, 0xE3, 0x29, 0x40, 0xEC, 0xEC, 0x98, 0xC5, 0x22,
            0x98, 0x2F,
        ];
        let input: [u8; 16] = [
            0xB8, 0x23, 0x28, 0x26, 0xFD, 0x5E, 0x40, 0x5E, 0x69, 0xA3, 0x01, 0xA9, 0x78, 0xEA,
            0x7A, 0xD8,
        ];
        let expected: [u8; 16] = [
            0xD5, 0x60, 0x8D, 0x4D, 0xA2, 0xBF, 0x34, 0x7B, 0xAB, 0xF8, 0x77, 0x2F, 0xDF, 0xED,
            0xDE, 0x07,
        ];
        assert_eq!(chaskey_block(key, input), expected);
    }

    #[test]
    fn reference_lznt1_stream_recovers_go_donut_module() -> Result<()> {
        let original_length: u32 = u32::try_from(KNOWN_DLL.len())
            .map_err(|_| loader_error("Donut compression test", "original length exceeds u32"))?;
        let (outer, decoded): (DonutOuter, Vec<u8>) =
            decoded_with_compressed_module(2, KNOWN_DLL_LZNT1, original_length)?;
        let result: DonutDecoded = parse_donut_decoded(&decoded, &outer, true)?;
        assert_eq!(
            result.config.compression,
            RecoveryField::known(DonutCompression::Lznt1)
        );
        let RecoveryField::Known { value } = result.module else {
            return Err(loader_error(
                "Donut compression test",
                "module was not recovered",
            ));
        };
        assert_eq!(value, KNOWN_DLL);
        assert_eq!(result.metadata.stored_size, RecoveryField::known(7_357));
        assert_eq!(result.metadata.original_size, RecoveryField::known(18_944));
        assert_eq!(
            result.metadata.format,
            RecoveryField::known(WrappedModuleFormat::Pe32Plus)
        );
        let wrapper: Vec<u8> = wrapper_from_decoded(&outer, &decoded)?;
        let recovery: LoaderRecovery = recover_loader(&wrapper)?;
        assert_eq!(
            recovery.inspection.wrapped_module.stored_size,
            RecoveryField::known(7_357)
        );
        assert_eq!(
            recovery.inspection.wrapped_module.original_size,
            RecoveryField::known(18_944)
        );
        assert_eq!(recovery.module, RecoveryField::known(KNOWN_DLL.to_vec()));
        let fingerprint: LoaderFingerprint = fingerprint_loader(&wrapper)
            .ok_or_else(|| loader_error("Donut compression test", "fingerprint missing"))?;
        assert_eq!(fingerprint.wrapped_module_region.length, 7_357);
        Ok(())
    }

    #[test]
    fn zero_compressed_length_recovers_stored_plaintext_module() -> Result<()> {
        let outer: DonutOuter = parse_donut_outer(KNOWN_DONUT)?;
        let mut decoded: Vec<u8> = decode_donut_instance(KNOWN_DONUT, &outer)?;
        decoded[DONUT_GO_COMPRESSION_OFFSET..DONUT_GO_COMPRESSION_OFFSET + 4]
            .copy_from_slice(&2u32.to_le_bytes());
        let result: DonutDecoded = parse_donut_decoded(&decoded, &outer, true)?;
        assert_eq!(
            result.config.compression,
            RecoveryField::known(DonutCompression::Lznt1)
        );
        let RecoveryField::Known { value } = result.module else {
            return Err(loader_error(
                "Donut compression test",
                "stored plaintext module was not recovered",
            ));
        };
        assert_eq!(value, KNOWN_DLL);
        let wrapper: Vec<u8> = wrapper_from_decoded(&outer, &decoded)?;
        let recovery: LoaderRecovery = recover_loader(&wrapper)?;
        let LoaderConfig::Donut(config) = recovery.inspection.config else {
            return Err(loader_error(
                "Donut compression test",
                "Donut config was not retained",
            ));
        };
        assert_eq!(
            config.compression,
            RecoveryField::known(DonutCompression::Lznt1)
        );
        assert_eq!(recovery.module, RecoveryField::known(KNOWN_DLL.to_vec()));
        assert!(fingerprint_loader(&wrapper).is_some());

        let mut invalid: Vec<u8> = decoded;
        let first_module_byte: &mut u8 = invalid
            .get_mut(DONUT_MODULE_DATA_OFFSET)
            .ok_or_else(|| loader_error("Donut compression test", "module byte is missing"))?;
        *first_module_byte = 0;
        let invalid_result: DonutDecoded = parse_donut_decoded(&invalid, &outer, true)?;
        let RecoveryField::Unknown { reason } = invalid_result.module else {
            return Err(loader_error(
                "Donut compression test",
                "invalid stored plaintext was reported recovered",
            ));
        };
        assert!(reason.contains("does not parse"));
        Ok(())
    }

    #[test]
    fn malformed_and_wrong_length_lznt1_streams_stay_unknown() -> Result<()> {
        let malformed: Vec<u8> = vec![0xFF; 1_895];
        let (outer, decoded): (DonutOuter, Vec<u8>) =
            decoded_with_compressed_module(2, &malformed, 18_944)?;
        let result: DonutDecoded = parse_donut_decoded(&decoded, &outer, true)?;
        let RecoveryField::Unknown { reason } = result.module else {
            return Err(loader_error(
                "Donut compression test",
                "malformed compressed module was reported recovered",
            ));
        };
        assert!(reason.contains("LZNT1 decompression failed"));

        let (outer, decoded): (DonutOuter, Vec<u8>) =
            decoded_with_compressed_module(2, KNOWN_DLL_LZNT1, 18_945)?;
        let result: DonutDecoded = parse_donut_decoded(&decoded, &outer, true)?;
        let RecoveryField::Unknown { reason } = result.module else {
            return Err(loader_error(
                "Donut compression test",
                "wrong-length compressed module was reported recovered",
            ));
        };
        assert!(reason.contains("produced 18944 bytes, expected 18945"));
        Ok(())
    }

    #[test]
    fn extraction_quota_refuses_declared_expansion_before_decompression() -> Result<()> {
        let stored: [u8; 1] = [0];
        let (outer, decoded): (DonutOuter, Vec<u8>) =
            decoded_with_compressed_module(2, &stored, 10_000)?;
        let result: DonutDecoded = parse_donut_decoded(&decoded, &outer, true)?;
        assert_eq!(
            result.config.compression,
            RecoveryField::known(DonutCompression::Lznt1)
        );
        assert_eq!(result.metadata.stored_size, RecoveryField::known(1));
        assert_eq!(result.metadata.original_size, RecoveryField::known(10_000));
        let RecoveryField::Unknown { reason } = result.module else {
            return Err(loader_error(
                "Donut quota test",
                "oversized expansion was reported recovered",
            ));
        };
        assert!(reason.contains("loader extraction quota"));
        assert!(reason.contains("ratio"));
        Ok(())
    }

    #[test]
    fn unsupported_donut_compression_emits_unknown_module() -> Result<()> {
        let (outer, mut decoded): (DonutOuter, Vec<u8>) =
            decoded_with_compressed_module(3, KNOWN_DLL, 18_944)?;
        let result: DonutDecoded = parse_donut_decoded(&decoded, &outer, true)?;
        let RecoveryField::Unknown { reason } = result.module else {
            return Err(loader_error(
                "Donut compression test",
                "unsupported compressed module was reported recovered",
            ));
        };
        assert!(reason.contains("XPRESS"));
        decoded[DONUT_GO_COMPRESSION_OFFSET..DONUT_GO_COMPRESSION_OFFSET + 4]
            .copy_from_slice(&99u32.to_le_bytes());
        let result: DonutDecoded = parse_donut_decoded(&decoded, &outer, false)?;
        assert_eq!(
            result.config.compression,
            RecoveryField::known(DonutCompression::Unknown { value: 99 })
        );
        let RecoveryField::Unknown { reason } = result.module else {
            return Err(loader_error(
                "Donut compression test",
                "unknown compression was reported recovered",
            ));
        };
        assert!(reason.contains("99"));

        let wrapper: Vec<u8> = wrapper_from_decoded(&outer, &decoded)?;
        let recovery: LoaderRecovery = recover_loader(&wrapper)?;
        let LoaderConfig::Donut(config) = recovery.inspection.config else {
            return Err(loader_error(
                "Donut compression test",
                "Donut config was not retained",
            ));
        };
        assert_eq!(
            config.compression,
            RecoveryField::known(DonutCompression::Unknown { value: 99 })
        );
        let RecoveryField::Unknown { reason } = recovery.module else {
            return Err(loader_error(
                "Donut compression test",
                "unknown compression recovered a payload",
            ));
        };
        assert!(reason.contains("99"));
        assert!(fingerprint_loader(&wrapper).is_none());
        let detections: Vec<crate::packers::Detection> = crate::packers::detect(&wrapper);
        assert!(
            detections
                .iter()
                .any(|detection| detection.packer == crate::packers::Packer::Donut)
        );
        Ok(())
    }

    #[test]
    fn unknown_donut_module_type_retains_raw_value() -> Result<()> {
        let original_length: u32 = u32::try_from(KNOWN_DLL.len())
            .map_err(|_| loader_error("Donut module type test", "original length exceeds u32"))?;
        let (outer, mut decoded): (DonutOuter, Vec<u8>) =
            decoded_with_compressed_module(2, &[0u8], original_length)?;
        decoded[DONUT_GO_MODULE_OFFSET..DONUT_GO_MODULE_OFFSET + 4]
            .copy_from_slice(&99u32.to_le_bytes());
        let result: DonutDecoded = parse_donut_decoded(&decoded, &outer, true)?;
        assert_eq!(
            result.config.module_type,
            RecoveryField::known(DonutModuleType::Unknown { value: 99 })
        );
        let RecoveryField::Unknown { reason } = result.module else {
            return Err(loader_error(
                "Donut module type test",
                "unknown module type was reported recovered",
            ));
        };
        assert!(reason.contains("99"));

        let wrapper: Vec<u8> = wrapper_from_decoded(&outer, &decoded)?;
        let recovery: LoaderRecovery = recover_loader(&wrapper)?;
        assert_eq!(recovery.inspection.variant, LoaderVariant::GoDonutV1);
        let LoaderConfig::Donut(config) = recovery.inspection.config else {
            return Err(loader_error(
                "Donut module type test",
                "Donut config was not retained",
            ));
        };
        assert_eq!(
            config.module_type,
            RecoveryField::known(DonutModuleType::Unknown { value: 99 })
        );
        assert!(matches!(recovery.module, RecoveryField::Unknown { .. }));
        assert!(fingerprint_loader(&wrapper).is_none());
        let detections: Vec<crate::packers::Detection> = crate::packers::detect(&wrapper);
        assert!(
            detections
                .iter()
                .any(|detection| detection.packer == crate::packers::Packer::Donut)
        );
        Ok(())
    }

    fn module_output_for(
        payload: &[u8],
        module_type: DonutModuleType,
    ) -> (
        WrappedModuleMetadata,
        RecoveryField<Vec<u8>>,
        DonutModuleValidation,
    ) {
        donut_module_output(
            payload,
            region(DONUT_MODULE_DATA_OFFSET, payload.len()),
            payload.len(),
            payload.len() as u64,
            module_type,
            DonutCompression::None,
            LoaderArchitecture::X64,
            true,
        )
    }

    fn pe32_plus_offsets(bytes: &[u8]) -> Result<(usize, usize)> {
        let pe_offset: usize = usize::try_from(read_u32_at(bytes, 0x3c, "test PE offset")?)
            .map_err(|_| loader_error("Donut module type test", "PE offset exceeds usize"))?;
        let coff_offset: usize = pe_offset
            .checked_add(4)
            .ok_or_else(|| loader_error("Donut module type test", "COFF offset overflow"))?;
        let optional_offset: usize = coff_offset
            .checked_add(COFF_HEADER_SIZE)
            .ok_or_else(|| loader_error("Donut module type test", "optional offset overflow"))?;
        Ok((coff_offset, optional_offset))
    }

    fn managed_variant(source: &[u8], dll: bool) -> Result<Vec<u8>> {
        let mut bytes: Vec<u8> = source.to_vec();
        let pe: PeImage = parse_loader_pe(&bytes, LoaderArchitecture::X64)?;
        let section: &crate::packers::PeSection = pe
            .sections
            .iter()
            .find(|section: &&crate::packers::PeSection| section.raw_size >= 0x100)
            .ok_or_else(|| {
                loader_error("Donut module type test", "no section has CLR test room")
            })?;
        let raw_offset: usize = usize::try_from(section.raw_pointer)
            .map_err(|_| loader_error("Donut module type test", "section offset exceeds usize"))?;
        let clr_rva: u32 = section.virtual_address;
        let metadata_offset: usize = raw_offset
            .checked_add(0x80)
            .ok_or_else(|| loader_error("Donut module type test", "metadata offset overflow"))?;
        let metadata_rva: u32 = clr_rva
            .checked_add(0x80)
            .ok_or_else(|| loader_error("Donut module type test", "metadata RVA overflow"))?;
        let (coff_offset, optional_offset): (usize, usize) = pe32_plus_offsets(&bytes)?;
        let characteristics_offset: usize = coff_offset
            .checked_add(18)
            .ok_or_else(|| loader_error("Donut module type test", "characteristics overflow"))?;
        let characteristics_bytes: [u8; 2] = bytes
            .get(characteristics_offset..characteristics_offset + 2)
            .ok_or_else(|| {
                loader_error(
                    "Donut module type test",
                    "characteristics field is truncated",
                )
            })?
            .try_into()
            .map_err(|_| {
                loader_error(
                    "Donut module type test",
                    "characteristics field has the wrong width",
                )
            })?;
        let mut characteristics: u16 = u16::from_le_bytes(characteristics_bytes);
        if dll {
            characteristics |= 0x2000;
        } else {
            characteristics &= !0x2000;
        }
        bytes[characteristics_offset..characteristics_offset + 2]
            .copy_from_slice(&characteristics.to_le_bytes());
        let clr_directory_offset: usize = optional_offset
            .checked_add(112 + 14 * 8)
            .ok_or_else(|| loader_error("Donut module type test", "CLR directory overflow"))?;
        bytes[clr_directory_offset..clr_directory_offset + 4]
            .copy_from_slice(&clr_rva.to_le_bytes());
        bytes[clr_directory_offset + 4..clr_directory_offset + 8]
            .copy_from_slice(&72u32.to_le_bytes());
        bytes[raw_offset..raw_offset + 4].copy_from_slice(&72u32.to_le_bytes());
        bytes[raw_offset + 8..raw_offset + 12].copy_from_slice(&metadata_rva.to_le_bytes());
        bytes[raw_offset + 12..raw_offset + 16].copy_from_slice(&4u32.to_le_bytes());
        bytes[metadata_offset..metadata_offset + 4].copy_from_slice(b"BSJB");
        Ok(bytes)
    }

    #[test]
    fn pe_module_type_must_match_clr_and_dll_categories() -> Result<()> {
        let (_, native_as_managed, native_as_managed_validation): (
            WrappedModuleMetadata,
            RecoveryField<Vec<u8>>,
            DonutModuleValidation,
        ) = module_output_for(KNOWN_DLL, DonutModuleType::ManagedDll);
        assert_eq!(native_as_managed_validation, DonutModuleValidation::Refused);
        let RecoveryField::Unknown { reason } = native_as_managed else {
            return Err(loader_error(
                "Donut module type test",
                "native PE was accepted as managed",
            ));
        };
        assert!(reason.contains("managed-dll"));
        assert!(reason.contains("CLR"));

        let (_, dll_as_exe, dll_as_exe_validation): (
            WrappedModuleMetadata,
            RecoveryField<Vec<u8>>,
            DonutModuleValidation,
        ) = module_output_for(KNOWN_DLL, DonutModuleType::NativeExe);
        assert_eq!(dll_as_exe_validation, DonutModuleValidation::Refused);
        assert!(matches!(dll_as_exe, RecoveryField::Unknown { .. }));

        let managed_dll: Vec<u8> = managed_variant(KNOWN_DLL, true)?;
        let (_, recovered_managed_dll, managed_dll_validation): (
            WrappedModuleMetadata,
            RecoveryField<Vec<u8>>,
            DonutModuleValidation,
        ) = module_output_for(&managed_dll, DonutModuleType::ManagedDll);
        assert_eq!(managed_dll_validation, DonutModuleValidation::Validated);
        assert_eq!(
            recovered_managed_dll,
            RecoveryField::known(managed_dll.clone())
        );

        let (_, managed_as_native, managed_as_native_validation): (
            WrappedModuleMetadata,
            RecoveryField<Vec<u8>>,
            DonutModuleValidation,
        ) = module_output_for(&managed_dll, DonutModuleType::NativeDll);
        assert_eq!(managed_as_native_validation, DonutModuleValidation::Refused);
        assert!(matches!(managed_as_native, RecoveryField::Unknown { .. }));

        let managed_exe: Vec<u8> = managed_variant(KNOWN_DLL, false)?;
        let (_, recovered_managed_exe, managed_exe_validation): (
            WrappedModuleMetadata,
            RecoveryField<Vec<u8>>,
            DonutModuleValidation,
        ) = module_output_for(&managed_exe, DonutModuleType::ManagedExe);
        assert_eq!(managed_exe_validation, DonutModuleValidation::Validated);
        assert_eq!(recovered_managed_exe, RecoveryField::known(managed_exe));
        Ok(())
    }

    #[test]
    fn script_module_types_fail_closed_without_static_parsers() -> Result<()> {
        let cases: [(&[u8], DonutModuleType, WrappedModuleFormat, &str); 6] = [
            (
                b"const answer = 42;",
                DonutModuleType::JavaScript,
                WrappedModuleFormat::JavaScript,
                "javascript",
            ),
            (
                b"const = ;",
                DonutModuleType::JavaScript,
                WrappedModuleFormat::JavaScript,
                "javascript",
            ),
            (
                b"Option Explicit\r\nDim answer\r\nanswer = 42\r\n",
                DonutModuleType::VbScript,
                WrappedModuleFormat::VbScript,
                "vbscript",
            ),
            (
                b"Option Explicit\r\nDim\r\n",
                DonutModuleType::VbScript,
                WrappedModuleFormat::VbScript,
                "vbscript",
            ),
            (
                br#"<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"></xsl:stylesheet>"#,
                DonutModuleType::Xsl,
                WrappedModuleFormat::Xsl,
                "xsl",
            ),
            (
                br#"<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"></xsl:stylesheet><"#,
                DonutModuleType::Xsl,
                WrappedModuleFormat::Xsl,
                "xsl",
            ),
        ];
        for (payload, module_type, format, label) in cases {
            let (metadata, module, validation): (
                WrappedModuleMetadata,
                RecoveryField<Vec<u8>>,
                DonutModuleValidation,
            ) = module_output_for(payload, module_type);
            assert_eq!(validation, DonutModuleValidation::Refused);
            assert_eq!(metadata.format, RecoveryField::known(format));
            assert_eq!(
                metadata.region,
                RecoveryField::known(region(DONUT_MODULE_DATA_OFFSET, payload.len()))
            );
            assert_eq!(
                metadata.stored_size,
                RecoveryField::known(payload.len() as u64)
            );
            assert_eq!(
                metadata.original_size,
                RecoveryField::known(payload.len() as u64)
            );
            let RecoveryField::Unknown { reason } = module else {
                return Err(loader_error(
                    "Donut script test",
                    format!("{label} bytes were reported recovered"),
                ));
            };
            assert!(reason.contains(label));
            assert!(reason.contains("static parser"));
        }
        Ok(())
    }
}
