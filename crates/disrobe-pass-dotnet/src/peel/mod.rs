#![allow(clippy::doc_markdown)]
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::metadata::{MetadataRoot, parse_metadata_root, read_strings_heap, read_us_heap_strings};
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use crate::protectors::Protector;

pub mod name_check;
pub mod native_surface;
pub mod protector_resources;
pub mod static_decrypt;
pub mod string_emu;

pub mod blowfish_tables;
pub mod cctor_constants;
pub mod dotnet_crypto;
pub mod skater_strings;
pub mod smartassembly_resources;
pub mod smartassembly_strings;
pub mod spices_strings;

pub mod deflatten;
pub mod eazvm;
pub mod koivm;

pub mod agile_net;
pub mod agile_net_bodies;
pub mod armdot;
pub mod babel_net;
pub mod bitmono_strings;
pub mod confuserex_constants;
pub mod confuserex_resources;
pub mod confuserex_seed;
pub mod crypto_obfuscator;
pub mod deepsea;
pub mod dotfuscator;
pub mod dotnet_reactor;
pub mod eazfuscator;
pub mod goliath;
pub mod ilprotector;
pub mod ilprotector_bodies;
pub mod maxtocode;
pub mod maxtocode_bodies;
pub mod obfuscar;
pub mod obfuscar_strings;
pub mod skater;
pub mod smartassembly;
pub mod spices_net;
pub mod themida_dotnet;

pub use agile_net::peel_agile_net;
pub use armdot::peel_armdot;
pub use babel_net::peel_babel_net;
pub use confuserex_constants::{
    ConfuserConstantsRecovery, RecoveredString, peel_confuserex_constants,
};
pub use confuserex_resources::{
    ConfuserExRecovery, KeyDerivation, ManifestResourceClassification, peel_confuserex_resources,
};
pub use crypto_obfuscator::peel_crypto_obfuscator;
pub use deepsea::peel_deepsea;
pub use dotfuscator::peel_dotfuscator;
pub use dotnet_reactor::peel_dotnet_reactor;
pub use eazfuscator::peel_eazfuscator;
pub use goliath::peel_goliath;
pub use ilprotector::peel_ilprotector;
pub use maxtocode::peel_maxtocode;
pub use native_surface::{NativeArch, NativeStubSurface, surface_native_stub};
pub use obfuscar::{ObfuscarEvidence, classify_obfuscar_naming, detect_obfuscar, peel_obfuscar};
pub use protector_resources::RecoveredResource;
pub use skater::peel_skater;
pub use smartassembly::peel_smartassembly;
pub use spices_net::peel_spices_net;
pub use themida_dotnet::peel_themida_dotnet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeelReport {
    pub protector: Protector,
    pub strategy: PeelStrategy,
    pub attributes_stripped: Vec<String>,
    pub strings_total: u32,
    pub strings_obfuscated_count: u32,
    pub us_strings_total: u32,
    pub renamable_identifiers: u32,
    pub unobfuscatable_identifiers: u32,
    pub bytes_in: u32,
    pub bytes_out: u32,

    pub recovered_decoders: u32,

    pub recovered_constants: Vec<static_decrypt::RecoveredConstant>,
    pub recovered_strings: Vec<string_emu::RecoveredString>,
    pub recovered_methods: Vec<RecoveredMethod>,
    #[serde(default)]
    pub recovered_resources: Vec<RecoveredResource>,
    pub native_surface: Option<native_surface::NativeStubSurface>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredMethod {
    pub method_name: String,
    pub metadata_token: u32,
    pub arg_count: u32,
    pub local_count: u32,
    pub cil: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PeelStrategy {
    AttributeStripAndReport,

    ReportOnlyEncryptedResource,

    EncryptedResourceExtracted,

    StaticStringRecovery,

    DetectOnlyNativeOrVm,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringHeapView {
    pub offsets: BTreeMap<u32, String>,
}

#[must_use]
pub fn classify_names(strings: &BTreeMap<u32, String>) -> NameClassification {
    let mut renamable: u32 = 0;
    let mut human: u32 = 0;
    let mut confuser_style: u32 = 0;
    let mut smartassembly_style: u32 = 0;
    for name in strings.values() {
        if name_check::is_confuser_style(name) {
            confuser_style += 1;
            renamable += 1;
        } else if name_check::is_smartassembly_style(name) {
            smartassembly_style += 1;
            renamable += 1;
        } else if name_check::is_random(name) || !name_check::is_non_random(name) {
            renamable += 1;
        } else {
            human += 1;
        }
    }
    NameClassification {
        renamable,
        human,
        confuser_style,
        smartassembly_style,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameClassification {
    pub renamable: u32,
    pub human: u32,
    pub confuser_style: u32,
    pub smartassembly_style: u32,
}

pub(crate) fn read_heaps(image: &[u8]) -> Result<HeapsView> {
    let pe: PeImage = parse(image)?;
    let clr: ClrHeader = parse_clr_header(image, &pe)?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr)?;
    let metadata_slice: &[u8] = crate::metadata::metadata_slice(image, &pe, &clr, &root)?;
    let strings_header_opt: Option<&crate::metadata::StreamHeader> = root.streams.get("#Strings");
    let us_header_opt: Option<&crate::metadata::StreamHeader> = root.streams.get("#US");
    let strings_map: BTreeMap<u32, String> = strings_header_opt
        .map(|h: &crate::metadata::StreamHeader| read_strings_heap(metadata_slice, *h))
        .unwrap_or_default();
    let us_strings: Vec<String> = us_header_opt
        .map(|h: &crate::metadata::StreamHeader| read_us_heap_strings(metadata_slice, *h))
        .unwrap_or_default();
    Ok(HeapsView {
        strings: strings_map,
        us_strings,
    })
}

#[derive(Debug, Clone)]
pub(crate) struct HeapsView {
    pub strings: BTreeMap<u32, String>,
    pub us_strings: Vec<String>,
}

pub(crate) fn strings_containing(heap: &BTreeMap<u32, String>, attrs: &[&str]) -> Vec<String> {
    let mut hits: Vec<String> = Vec::new();
    for s in heap.values() {
        for needle in attrs {
            if s.contains(needle) && !hits.iter().any(|h: &String| h == needle) {
                hits.push((*needle).to_string());
            }
        }
    }
    hits
}

pub(crate) fn report_only_peel(
    protector: Protector,
    image: &[u8],
    watermark_attrs: &[&str],
    notes: Vec<String>,
) -> Result<PeelReport> {
    let heaps: HeapsView = read_heaps(image)?;
    let attributes_stripped: Vec<String> = strings_containing(&heaps.strings, watermark_attrs);
    let classification: NameClassification = classify_names(&heaps.strings);
    let bytes_in: u32 = u32::try_from(image.len()).unwrap_or(u32::MAX);
    let decoders: static_decrypt::StaticDecryptReport =
        static_decrypt::recover_static_decoders(image).unwrap_or_default();
    Ok(PeelReport {
        protector,
        strategy: PeelStrategy::AttributeStripAndReport,
        attributes_stripped,
        strings_total: u32::try_from(heaps.strings.len()).unwrap_or(u32::MAX),
        strings_obfuscated_count: classification.renamable,
        us_strings_total: u32::try_from(heaps.us_strings.len()).unwrap_or(u32::MAX),
        renamable_identifiers: classification.renamable,
        unobfuscatable_identifiers: classification.human,
        bytes_in,
        bytes_out: bytes_in,
        recovered_decoders: decoders.pure_decoders_found,
        recovered_constants: decoders.constants_recovered,
        recovered_strings: Vec::new(),
        recovered_methods: Vec::new(),
        recovered_resources: Vec::new(),
        native_surface: None,
        notes,
    })
}

pub(crate) fn report_only_encrypted_resource(
    protector: Protector,
    image: &[u8],
    watermark_attrs: &[&str],
    decryption_note: &str,
) -> Result<PeelReport> {
    let mut report: PeelReport = report_only_peel(
        protector,
        image,
        watermark_attrs,
        vec![decryption_note.to_string()],
    )?;
    report.strategy = PeelStrategy::ReportOnlyEncryptedResource;
    Ok(report)
}

pub(crate) fn try_managed_string_decryptor(
    report: &mut PeelReport,
    image: &[u8],
    protector_label: &str,
) {
    let heaps: HeapsView = match read_heaps(image) {
        Ok(h) => h,
        Err(_) => return,
    };
    let recovered: Vec<string_emu::RecoveredString> =
        string_emu::recover_emulated_strings(image, &heaps.us_strings);
    if recovered.is_empty() {
        return;
    }
    report.strategy = PeelStrategy::EncryptedResourceExtracted;
    report.notes.push(format!(
        "{protector_label} static string-emulation: recovered {} literal(s) by locating the \
         in-assembly char[]/byte[] decryptor method and executing its CIL over the encrypted #US \
         table",
        recovered.len(),
    ));
    report.recovered_strings = recovered;
}

pub(crate) fn apply_eazvm_tier(image: &[u8], report: &mut PeelReport, protector_label: &str) {
    let Ok(recovery): std::result::Result<eazvm::EazVmRecovery, _> = eazvm::devirtualize(image)
    else {
        return;
    };
    if recovery.methods.is_empty() {
        return;
    }
    report.strategy = PeelStrategy::EncryptedResourceExtracted;
    report.recovered_decoders = report
        .recovered_decoders
        .saturating_add(u32::try_from(recovery.methods.len()).unwrap_or(u32::MAX));
    report.recovered_methods = recovery
        .methods
        .iter()
        .map(|m: &eazvm::EazVmMethod| RecoveredMethod {
            method_name: m.name.clone(),
            metadata_token: m.metadata_token,
            arg_count: m.info.param_count,
            local_count: m.info.local_count,
            cil: m.lifted.render(),
        })
        .collect();
    let total_instrs: usize = recovery
        .methods
        .iter()
        .map(|m: &eazvm::EazVmMethod| m.lifted.instrs.len())
        .sum();
    report.notes.push(format!(
        "{protector_label} VM-tier: recovered the per-build opcode table ({} handlers) and lifted \
         {} virtualized method body(ies) back to CIL ({} instructions) by decrypting the \
         position-keyed stream and resolving members by name",
        recovery.detection.identified_opcodes,
        recovery.methods.len(),
        total_instrs,
    ));
    if recovery.undecoded_count > 0 {
        let reason: &str = recovery
            .first_failure
            .as_ref()
            .map_or("unknown", |f: &eazvm::EazVmDecodeFailure| f.reason.as_str());
        report.notes.push(format!(
            "{protector_label} VM-tier: {} stub(s) did not decode ({}): {}",
            recovery.undecoded_count,
            reason,
            recovery.undecoded.join(", "),
        ));
    }
}

pub(crate) fn detect_only_native(
    protector: Protector,
    image: &[u8],
    watermark_attrs: &[&str],
    rationale: &str,
) -> Result<PeelReport> {
    let mut report: PeelReport = report_only_peel(
        protector,
        image,
        watermark_attrs,
        vec![rationale.to_string()],
    )?;
    report.strategy = PeelStrategy::DetectOnlyNativeOrVm;
    Ok(report)
}

pub fn require_managed_pe(image: &[u8]) -> Result<()> {
    let pe: PeImage = parse(image)?;
    let _clr: ClrHeader = parse_clr_header(image, &pe)?;
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
#[must_use]
pub fn peel_by(protector: Protector, bytes: &[u8]) -> Option<Result<PeelReport>> {
    match protector {
        Protector::DotnetReactor => Some(peel_dotnet_reactor(bytes)),
        Protector::EazfuscatorNet => Some(peel_eazfuscator(bytes)),
        Protector::SmartAssembly => Some(peel_smartassembly(bytes)),
        Protector::BabelDotnet => Some(peel_babel_net(bytes)),
        Protector::DeepSea => Some(peel_deepsea(bytes)),
        Protector::SpicesNet => Some(peel_spices_net(bytes)),
        Protector::Skater => Some(peel_skater(bytes)),
        Protector::ArmDot => Some(peel_armdot(bytes)),
        Protector::CryptoObfuscator => Some(peel_crypto_obfuscator(bytes)),
        Protector::AgileNet => Some(peel_agile_net(bytes)),
        Protector::DotNetPatcher | Protector::NetCryptor => {
            Some(peel_managed_wrapper(protector, bytes))
        }
        Protector::ThemidaDotnet => Some(peel_themida_dotnet(bytes)),
        Protector::Ilprotector => Some(peel_ilprotector(bytes)),
        Protector::MaxToCode => Some(peel_maxtocode(bytes)),
        Protector::Goliath => Some(peel_goliath(bytes)),
        Protector::Obfuscar => Some(peel_obfuscar(bytes)),
        Protector::Dotfuscator => Some(peel_dotfuscator(bytes)),
        Protector::DotfuscatorCe => Some(peel_dotfuscator(bytes).map(|mut r: PeelReport| {
            r.protector = Protector::DotfuscatorCe;
            r
        })),
        Protector::ConfuserEx => Some(peel_confuserex(bytes, Protector::ConfuserEx)),
        Protector::ConfuserEx2 => Some(peel_confuserex(bytes, Protector::ConfuserEx2)),
        Protector::KoiVm => Some(peel_koivm(bytes)),
        Protector::BitMono => Some(peel_bitmono(bytes)),
    }
}

pub(crate) fn peel_managed_wrapper(protector: Protector, image: &[u8]) -> Result<PeelReport> {
    let (watermarks, note): (&[&str], &str) = match protector {
        Protector::DotNetPatcher => (
            &["DNPatcher", "DotNetPatcher"],
            "DotNetPatcher managed wrapper: scan CLR metadata, names, constants, and static string \
             decoders through the .NET pass; native packer recovery does not own this layer",
        ),
        Protector::NetCryptor => (
            &["NETCryptor", "NetCryptor"],
            "NetCryptor managed wrapper: scan CLR metadata, names, constants, and static string \
             decoders through the .NET pass; native packer recovery does not own this layer",
        ),
        _ => (&[], "managed wrapper"),
    };
    let mut report: PeelReport =
        report_only_peel(protector, image, watermarks, vec![note.to_string()])?;
    try_managed_string_decryptor(&mut report, image, protector.label());
    Ok(report)
}

pub(crate) fn peel_bitmono(image: &[u8]) -> Result<PeelReport> {
    let mut report: PeelReport = report_only_peel(
        Protector::BitMono,
        image,
        &["BitMono", "BitMethodDotnet", "AntiDecompiler"],
        Vec::new(),
    )?;
    let Some(recovery): Option<bitmono_strings::BitMonoStringRecovery> =
        bitmono_strings::recover_bitmono_strings(image)
    else {
        return Ok(report);
    };
    if recovery.recovered.is_empty() {
        report.notes.push(format!(
            "BitMono StringsEncryption decryptor located at token 0x{:08x} (AES-{} CBC keyed by \
             PBKDF2-HMAC-SHA1 over {} iterations) but none of its {} call site(s) resolved to an \
             in-assembly ciphertext field",
            recovery.shape.method_token,
            recovery.shape.key_size_bits,
            recovery.shape.iterations,
            recovery.call_sites_total,
        ));
        return Ok(report);
    }
    report.strategy = PeelStrategy::StaticStringRecovery;
    report.recovered_decoders = report.recovered_decoders.saturating_add(1);
    report.recovered_strings = recovery
        .recovered
        .iter()
        .map(
            |value: &bitmono_strings::BitMonoRecoveredString| string_emu::RecoveredString {
                method_token: value.caller_token,
                method_name: format!("call_site+0x{:04x}", value.call_offset),
                text: value.text.clone(),
            },
        )
        .collect();
    report.notes.push(format!(
        "BitMono StringsEncryption reversed: {}/{} call site(s) decrypted by reading the \
         in-assembly password, salt, and ciphertext byte[] fields through their FieldRVA \
         initializers and running the decryptor's own scheme (AES-{} CBC, key and IV derived by \
         PBKDF2-HMAC-SHA1 over {} iterations) found at token 0x{:08x}",
        recovery.recovered.len(),
        recovery.call_sites_total,
        recovery.shape.key_size_bits,
        recovery.shape.iterations,
        recovery.shape.method_token,
    ));
    Ok(report)
}

pub(crate) fn peel_koivm(image: &[u8]) -> Result<PeelReport> {
    let mut report: PeelReport = report_only_peel(
        Protector::KoiVm,
        image,
        &["KoiVM", "VMDispatcher", "VMEntry"],
        Vec::new(),
    )?;
    report.protector = Protector::KoiVm;

    let Ok(recovery): std::result::Result<koivm::KoiVmRecovery, koivm::KoiVmError> =
        koivm::devirtualize(image)
    else {
        report.strategy = PeelStrategy::DetectOnlyNativeOrVm;
        report.notes.push(
            "KoiVM watermark present but the #Koi stream could not be parsed; nothing to \
             devirtualize in this image"
                .to_string(),
        );
        return Ok(report);
    };

    if recovery.methods.is_empty() {
        report.strategy = PeelStrategy::DetectOnlyNativeOrVm;
        report.notes.push(format!(
            "KoiVM #Koi stream parsed but no method body devirtualized ({} export id(s) undecoded)",
            recovery.undecoded_ids.len(),
        ));
        return Ok(report);
    }

    let total_ops: usize = recovery
        .methods
        .iter()
        .map(|m: &koivm::KoiVmMethod| m.lifted.ops.len())
        .sum();
    report.recovered_methods = recovery
        .methods
        .iter()
        .map(|m: &koivm::KoiVmMethod| RecoveredMethod {
            method_name: m.method_name.clone(),
            metadata_token: m.metadata_token,
            arg_count: m.lifted.arg_count,
            local_count: m.lifted.local_count,
            cil: m.lifted.render(),
        })
        .collect();
    report.recovered_decoders = report
        .recovered_decoders
        .saturating_add(u32::try_from(recovery.methods.len()).unwrap_or(u32::MAX));
    report.strategy = PeelStrategy::EncryptedResourceExtracted;
    report.notes.push(format!(
        "KoiVM VM-tier: devirtualized {} method body(ies) back to CIL ({} lifted ops) by decoding \
         the #Koi virtual-instruction stream against the per-build register/opcode descriptors",
        recovery.methods.len(),
        total_ops,
    ));
    if !recovery.undecoded_ids.is_empty() {
        report.notes.push(format!(
            "KoiVM VM-tier: {} export id(s) did not decode: {:?}",
            recovery.undecoded_ids.len(),
            recovery.undecoded_ids,
        ));
    }
    Ok(report)
}

pub(crate) fn peel_confuserex(image: &[u8], protector: Protector) -> Result<PeelReport> {
    let watermarks: &[&str] = match protector {
        Protector::ConfuserEx => &["ConfuserEx v", "ConfusedByAttribute"],
        _ => &["ConfuserEx2", "ConfusedByAttribute", "_CoreModule"],
    };
    let heaps: HeapsView = read_heaps(image)?;
    let attributes_stripped: Vec<String> = strings_containing(&heaps.strings, watermarks);
    let classification: NameClassification = classify_names(&heaps.strings);
    let bytes_in: u32 = u32::try_from(image.len()).unwrap_or(u32::MAX);
    let decoders: static_decrypt::StaticDecryptReport =
        static_decrypt::recover_static_decoders(image).unwrap_or_default();
    let recovery: confuserex_resources::ConfuserExRecovery =
        confuserex_resources::peel_confuserex_resources(image)?;
    let (strategy, note, recovered_resources): (PeelStrategy, String, Vec<RecoveredResource>) =
        match recovery {
            confuserex_resources::ConfuserExRecovery::FullyDecrypted {
                blob_rva,
                blob_size,
                blob_sha256,
                key_seed,
                size_div_four,
                decrypted_sha256,
                lzma_uncompressed_size,
                recovered_resources,
            } => {
                let recovered_count: usize = recovered_resources.len();
                (
                    PeelStrategy::EncryptedResourceExtracted,
                    format!(
                        "ConfuserEx2 resources fully decrypted: blob_rva=0x{blob_rva:x} size={blob_size} \
                     sha256={} key_seed=0x{key_seed:08x} size/4={size_div_four} \
                     decrypted_sha256={} lzma_uncompressed_size={lzma_uncompressed_size} \
                     resources_recovered={recovered_count}",
                        hex_lower(&blob_sha256),
                        hex_lower(&decrypted_sha256),
                    ),
                    recovered_resources,
                )
            }
            confuserex_resources::ConfuserExRecovery::BlobExtractedUnknownKey {
                blob_rva,
                blob_size,
                blob_sha256,
                candidate_seeds_tried,
                runtime_key_derivation,
            } => {
                let reason: &str = match runtime_key_derivation {
                    confuserex_resources::KeyDerivation::AntiTamperEncryptedInitializer => {
                        "the resource seed is stored in an initializer whose CIL body is encrypted \
                         by anti-tamper; this static pass did not recover that initializer"
                    }
                    confuserex_resources::KeyDerivation::InitializerSeedUnresolved => {
                        "no literal or emulated initializer seed produced a decompressible managed \
                         resource assembly"
                    }
                };
                (
                    PeelStrategy::EncryptedResourceExtracted,
                    format!(
                        "ConfuserEx2 encrypted-resource blob extracted: blob_rva=0x{blob_rva:x} \
                     size={blob_size} sha256={} ({reason}; {candidate_seeds_tried} seed \
                     candidates checked)",
                        hex_lower(&blob_sha256),
                    ),
                    Vec::new(),
                )
            }
            confuserex_resources::ConfuserExRecovery::NoEncryptedResourceFound => (
                PeelStrategy::AttributeStripAndReport,
                "ConfuserEx watermark present but no Resources-protection signature found (only \
                 watermark + identifier renaming detected)"
                    .to_string(),
                Vec::new(),
            ),
        };
    let mut notes: Vec<String> = vec![note];
    if let Some(constants) = confuserex_constants::peel_confuserex_constants(image)? {
        notes.push(format!(
            "ConfuserEx2 constants decrypted: blob_rva=0x{:x} size={} seed=0x{:08x} \
             pool_len={} strings_recovered={} [{}]",
            constants.blob_rva,
            constants.blob_size,
            constants.seed,
            constants.constant_pool_len,
            constants.strings_recovered.len(),
            constants
                .strings_recovered
                .iter()
                .map(|s: &confuserex_constants::RecoveredString| s.text.as_str())
                .collect::<Vec<&str>>()
                .join(", "),
        ));
    }
    Ok(PeelReport {
        protector,
        strategy,
        attributes_stripped,
        strings_total: u32::try_from(heaps.strings.len()).unwrap_or(u32::MAX),
        strings_obfuscated_count: classification.renamable,
        us_strings_total: u32::try_from(heaps.us_strings.len()).unwrap_or(u32::MAX),
        renamable_identifiers: classification.renamable,
        unobfuscatable_identifiers: classification.human,
        bytes_in,
        bytes_out: bytes_in,
        recovered_decoders: decoders.pure_decoders_found,
        recovered_constants: decoders.constants_recovered,
        recovered_strings: Vec::new(),
        recovered_methods: Vec::new(),
        recovered_resources,
        native_surface: None,
        notes,
    })
}

fn hex_lower(bytes: &[u8; 32]) -> String {
    let mut s: String = String::with_capacity(64);
    for b in bytes {
        let upper: u8 = b >> 4;
        let lower: u8 = b & 0x0F;
        s.push(if upper < 10 {
            (b'0' + upper) as char
        } else {
            (b'a' + upper - 10) as char
        });
        s.push(if lower < 10 {
            (b'0' + lower) as char
        } else {
            (b'a' + lower - 10) as char
        });
    }
    s
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn synth_with_strings(strings: &[(u32, &str)]) -> BTreeMap<u32, String> {
        let mut m: BTreeMap<u32, String> = BTreeMap::new();
        for (k, v) in strings {
            m.insert(*k, (*v).to_string());
        }
        m
    }

    #[test]
    fn classify_finds_confuser_unprintable_names() {
        let heap: BTreeMap<u32, String> =
            synth_with_strings(&[(1, "\u{200B}abc"), (10, "ParseFile")]);
        let c: NameClassification = classify_names(&heap);
        assert_eq!(c.confuser_style, 1);
        assert_eq!(c.human, 1);
    }

    #[test]
    fn classify_flags_smartassembly_q_prefix() {
        let heap: BTreeMap<u32, String> = synth_with_strings(&[(1, "#=qABCDEF")]);
        let c: NameClassification = classify_names(&heap);
        assert_eq!(c.smartassembly_style, 1);
        assert_eq!(c.renamable, 1);
    }

    #[test]
    fn classify_keeps_human_names() {
        let heap: BTreeMap<u32, String> =
            synth_with_strings(&[(1, "ParseFile"), (10, "Calculator"), (20, "EnumerateAll")]);
        let c: NameClassification = classify_names(&heap);
        assert_eq!(c.human, 3);
        assert_eq!(c.confuser_style, 0);
    }

    #[test]
    fn strings_containing_matches_substring() {
        let heap: BTreeMap<u32, String> =
            synth_with_strings(&[(1, "ConfusedByAttribute"), (10, "ParseHelper")]);
        let hits: Vec<String> =
            strings_containing(&heap, &["ConfusedByAttribute", "BabelAttribute"]);
        assert_eq!(hits, vec!["ConfusedByAttribute".to_string()]);
    }
}
