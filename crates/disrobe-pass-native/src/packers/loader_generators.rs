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
    let pe_result: Result<PeImage> = parse_loader_pe(module_bytes, bootstrap.architecture);

    let (metadata, module): (WrappedModuleMetadata, RecoveryField<Vec<u8>>) = match pe_result {
        Ok(pe) => (
            pe_metadata(module_region, &pe),
            RecoveryField::known(module_bytes.to_vec()),
        ),
        Err(error) => {
            let reason: String = error.to_string();
            (
                region_known_metadata(module_region, regions.module_length, reason.clone()),
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
    let compression_raw: u32 = read_u32(&mut reader, "Donut module compression")?;
    read_bytes(&mut reader, 5 * 256, "Donut module names")?;
    let unicode: u32 = read_u32(&mut reader, "Donut module Unicode mode")?;
    let signature: &[u8] = read_bytes(&mut reader, 8, "Donut module signature")?;
    let mac: u64 = read_u64(&mut reader, "Donut module MAC")?;
    let compressed_length: u32 = read_u32(&mut reader, "Donut compressed length")?;
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
    if matches!(module_type, DonutModuleType::Unknown { .. }) {
        return Err(donut_module_error(format!(
            "module type {module_type_raw} is unknown"
        )));
    }
    let compression: DonutCompression = go_donut_compression(compression_raw);
    if matches!(compression, DonutCompression::Unknown { .. }) {
        return Err(donut_module_error(format!(
            "compression value {compression_raw} is unknown"
        )));
    }
    let original_size: usize = usize::try_from(original_length)
        .map_err(|_| donut_module_error("original length does not fit the host address size"))?;
    if original_size == 0 || original_size > MAX_RECOVERED_BYTES {
        return Err(donut_module_error(
            "original length is zero or exceeds the 64 MiB cap",
        ));
    }
    let stored_size: usize = match compression {
        DonutCompression::None => {
            if compressed_length != 0 {
                return Err(donut_module_error(
                    "uncompressed module has a nonzero compressed length",
                ));
            }
            original_size
        }
        DonutCompression::Lznt1
        | DonutCompression::Xpress
        | DonutCompression::XpressHuffman
        | DonutCompression::Unknown { .. } => usize::try_from(compressed_length).map_err(|_| {
            donut_module_error("compressed length does not fit the host address size")
        })?,
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
        .and_then(|value: u64| value.checked_add(8))
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
    let (metadata, module): (WrappedModuleMetadata, RecoveryField<Vec<u8>>) = donut_module_output(
        module_bytes,
        module_region,
        original_size,
        module_type,
        compression,
        outer.architecture,
        materialize,
    );
    Ok(DonutDecoded {
        config,
        metadata,
        module,
    })
}

fn donut_module_output(
    module_bytes: &[u8],
    module_region: ByteRegion,
    original_size: usize,
    module_type: DonutModuleType,
    compression: DonutCompression,
    architecture: LoaderArchitecture,
    materialize: bool,
) -> (WrappedModuleMetadata, RecoveryField<Vec<u8>>) {
    if compression != DonutCompression::None {
        let reason: String = format!(
            "Go Donut compression {} is unsupported for static recovery",
            go_donut_compression_label(compression)
        );
        let format: RecoveryField<WrappedModuleFormat> = match module_type {
            DonutModuleType::VbScript => RecoveryField::known(WrappedModuleFormat::VbScript),
            DonutModuleType::JavaScript => RecoveryField::known(WrappedModuleFormat::JavaScript),
            DonutModuleType::Xsl => RecoveryField::known(WrappedModuleFormat::Xsl),
            DonutModuleType::ManagedDll
            | DonutModuleType::ManagedExe
            | DonutModuleType::NativeDll
            | DonutModuleType::NativeExe
            | DonutModuleType::Unknown { .. } => RecoveryField::unknown(reason.clone()),
        };
        return (
            WrappedModuleMetadata {
                region: RecoveryField::known(module_region),
                format,
                stored_size: RecoveryField::known(module_region.length),
                original_size: RecoveryField::known(original_size as u64),
                entry_point_rva: RecoveryField::unknown(reason.clone()),
            },
            RecoveryField::unknown(reason),
        );
    }

    match module_type {
        DonutModuleType::ManagedDll
        | DonutModuleType::ManagedExe
        | DonutModuleType::NativeDll
        | DonutModuleType::NativeExe => match parse_loader_pe(module_bytes, architecture) {
            Ok(pe) => {
                let module: RecoveryField<Vec<u8>> = if materialize {
                    RecoveryField::known(module_bytes.to_vec())
                } else {
                    RecoveryField::unknown("inspection did not copy the module")
                };
                (pe_metadata(module_region, &pe), module)
            }
            Err(error) => {
                let reason: String =
                    format!("Donut module header describes PE data that does not parse: {error}");
                (
                    region_known_metadata(module_region, original_size, reason.clone()),
                    RecoveryField::unknown(reason),
                )
            }
        },
        DonutModuleType::VbScript => script_output(
            module_bytes,
            module_region,
            WrappedModuleFormat::VbScript,
            materialize,
        ),
        DonutModuleType::JavaScript => script_output(
            module_bytes,
            module_region,
            WrappedModuleFormat::JavaScript,
            materialize,
        ),
        DonutModuleType::Xsl => script_output(
            module_bytes,
            module_region,
            WrappedModuleFormat::Xsl,
            materialize,
        ),
        DonutModuleType::Unknown { value } => {
            let reason: String = format!("Donut module type {value} is unknown");
            (
                region_known_metadata(module_region, original_size, reason.clone()),
                RecoveryField::unknown(reason),
            )
        }
    }
}

fn script_output(
    module_bytes: &[u8],
    module_region: ByteRegion,
    format: WrappedModuleFormat,
    materialize: bool,
) -> (WrappedModuleMetadata, RecoveryField<Vec<u8>>) {
    let module: RecoveryField<Vec<u8>> = if materialize {
        RecoveryField::known(module_bytes.to_vec())
    } else {
        RecoveryField::unknown("inspection did not copy the module")
    };
    (
        WrappedModuleMetadata {
            region: RecoveryField::known(module_region),
            format: RecoveryField::known(format),
            stored_size: RecoveryField::known(module_region.length),
            original_size: RecoveryField::known(module_region.length),
            entry_point_rva: RecoveryField::unknown(
                "script modules do not carry a PE entry point RVA",
            ),
        },
        module,
    )
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

fn pe_metadata(module_region: ByteRegion, pe: &PeImage) -> WrappedModuleMetadata {
    WrappedModuleMetadata {
        region: RecoveryField::known(module_region),
        format: RecoveryField::known(if pe.is_pe32_plus {
            WrappedModuleFormat::Pe32Plus
        } else {
            WrappedModuleFormat::Pe32
        }),
        stored_size: RecoveryField::known(module_region.length),
        original_size: RecoveryField::known(module_region.length),
        entry_point_rva: RecoveryField::known(pe.entry_point_rva),
    }
}

fn region_known_metadata(
    module_region: ByteRegion,
    original_size: usize,
    reason: String,
) -> WrappedModuleMetadata {
    WrappedModuleMetadata {
        region: RecoveryField::known(module_region),
        format: RecoveryField::unknown(reason.clone()),
        stored_size: RecoveryField::known(module_region.length),
        original_size: RecoveryField::known(original_size as u64),
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn unsupported_donut_compression_emits_unknown_module() -> Result<()> {
        let packed: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/loader_generators/known.go-donut.bin"
        ));
        let outer: DonutOuter = parse_donut_outer(packed)?;
        let mut decoded: Vec<u8> = decode_donut_instance(packed, &outer)?;
        decoded[DONUT_GO_MODULE_OFFSET + 8..DONUT_GO_MODULE_OFFSET + 12]
            .copy_from_slice(&2u32.to_le_bytes());
        decoded[DONUT_GO_MODULE_OFFSET + 1_312..DONUT_GO_MODULE_OFFSET + 1_316]
            .copy_from_slice(&18_944u32.to_le_bytes());
        let result: DonutDecoded = parse_donut_decoded(&decoded, &outer, true)?;
        assert_eq!(
            result.config.compression,
            RecoveryField::known(DonutCompression::Lznt1)
        );
        let RecoveryField::Unknown { reason } = result.module else {
            return Err(loader_error(
                "Donut compression test",
                "compressed module was reported recovered",
            ));
        };
        assert!(reason.contains("compression"));
        decoded[DONUT_GO_MODULE_OFFSET + 8..DONUT_GO_MODULE_OFFSET + 12]
            .copy_from_slice(&99u32.to_le_bytes());
        assert!(parse_donut_decoded(&decoded, &outer, false).is_err());
        Ok(())
    }
}
