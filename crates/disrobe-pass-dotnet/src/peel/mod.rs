//! Cross-protector peeling primitives.
//!
//! `peel_*` entry-points return a [`PeelReport`] describing the bytes-level changes that would be
//! or were made to the input. The transforms here are clean-room ports of the universally
//! applicable pieces of de4dot (name classification, attribute identification, string-heap
//! scanning); per-protector algorithm specs live alongside in module siblings.

#![allow(clippy::doc_markdown)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::metadata::{MetadataRoot, parse_metadata_root, read_strings_heap, read_us_heap_strings};
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use crate::protectors::Protector;

pub mod name_check;
pub mod static_decrypt;

pub mod agile_net;
pub mod armdot;
pub mod babel_net;
pub mod confuserex_resources;
pub mod crypto_obfuscator;
pub mod deepsea;
pub mod dotfuscator;
pub mod dotnet_reactor;
pub mod eazfuscator;
pub mod goliath;
pub mod ilprotector;
pub mod maxtocode;
pub mod obfuscar;
pub mod skater;
pub mod smartassembly;
pub mod spices_net;
pub mod themida_dotnet;

pub use agile_net::peel_agile_net;
pub use armdot::peel_armdot;
pub use babel_net::peel_babel_net;
pub use confuserex_resources::{
    ConfuserExRecovery, ManifestResourceClassification, peel_confuserex_resources,
};
pub use crypto_obfuscator::peel_crypto_obfuscator;
pub use deepsea::peel_deepsea;
pub use dotfuscator::peel_dotfuscator;
pub use dotnet_reactor::peel_dotnet_reactor;
pub use eazfuscator::peel_eazfuscator;
pub use goliath::peel_goliath;
pub use ilprotector::peel_ilprotector;
pub use maxtocode::peel_maxtocode;
pub use obfuscar::{ObfuscarEvidence, classify_obfuscar_naming, detect_obfuscar, peel_obfuscar};
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
    /// Pure static decoder methods recovered by CIL emulation (constant/string decrypters that ran
    /// to completion against probe inputs without touching external state).
    pub recovered_decoders: u32,
    /// Decoded values produced by emulating those decoders.
    pub recovered_constants: Vec<static_decrypt::RecoveredConstant>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PeelStrategy {
    /// Stripped watermark attribute names + reported rename candidates. No CIL rewrite.
    AttributeStripAndReport,
    /// Encrypted-resource decrypter required but not implemented; report-only.
    ReportOnlyEncryptedResource,
    /// `ConfuserEx2` encrypted-resource blob located and extracted byte-exactly; per-build `keySeed`
    /// recovered or report keyed-wall.
    EncryptedResourceExtracted,
    /// Native stub / VM tier; cannot peel without out-of-process execution.
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

/// Parse + materialize the strings/us heaps. Shared by every peel routine that needs to look at
/// metadata-name evidence.
pub(crate) fn read_heaps(image: &[u8]) -> Result<HeapsView> {
    let pe: PeImage = parse(image)?;
    let clr: ClrHeader = parse_clr_header(image, &pe)?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr)?;
    let metadata_slice: &[u8] =
        pe.slice_at_rva(image, clr.metadata.rva, clr.metadata.size as usize)?;
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

/// Test if any string in the heap contains a literal watermark from `attrs`. Cheap, in-memory.
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

/// Universal report-only peel: identifies the protector watermark attributes in the #Strings heap,
/// classifies the rest of the names, and emits a [`PeelReport`].
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
        notes,
    })
}

/// Encrypted-resource family peel: parses metadata, locates suspicious encrypted resources via the
/// protector's watermark, but cannot perform full decryption without the runtime decrypter
/// algorithm port. Reports findings and leaves bytes unchanged.
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

/// VM/native peel: protector is layered above a native stub or a homomorphic VM. Detection only.
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

/// Returned by every protector's `peel_*` when the bytes do not parse as a managed PE.
pub fn require_managed_pe(image: &[u8]) -> Result<()> {
    let pe: PeImage = parse(image)?;
    let _clr: ClrHeader = parse_clr_header(image, &pe)?;
    Ok(())
}

/// Dispatch helper: peel by protector enum value. Returns `None` if the variant has no peeler
/// registered.
#[allow(clippy::unnecessary_wraps)]
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
    }
}

/// `ConfuserEx` / `ConfuserEx2` peel: runs the documented FOSS Resources-protection extractor and
/// folds the recovery outcome into a [`PeelReport`]. Always REAL: when the encrypted blob is
/// present in the PE we locate, extract, and byte-exactly report it; when the per-build `keySeed`
/// is recoverable from a clean `ldc.i4` we fully decrypt; otherwise we report the extracted blob
/// plus the keyed-wall (the standard outcome under the "normal" preset where Constants protection
/// nests over Resources).
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
    let (strategy, note): (PeelStrategy, String) = match &recovery {
        confuserex_resources::ConfuserExRecovery::FullyDecrypted {
            blob_rva,
            blob_size,
            blob_sha256,
            key_seed,
            size_div_four,
            decrypted_sha256,
            lzma_uncompressed_size,
        } => (
            PeelStrategy::EncryptedResourceExtracted,
            format!(
                "ConfuserEx2 resources fully decrypted: blob_rva=0x{blob_rva:x} size={blob_size} \
                 sha256={} key_seed=0x{key_seed:08x} size/4={size_div_four} \
                 decrypted_sha256={} lzma_uncompressed_size={lzma_uncompressed_size}",
                hex_lower(blob_sha256),
                hex_lower(decrypted_sha256),
            ),
        ),
        confuserex_resources::ConfuserExRecovery::BlobExtractedKeyedWall {
            blob_rva,
            blob_size,
            blob_sha256,
            candidate_seeds_tried,
        } => (
            PeelStrategy::EncryptedResourceExtracted,
            format!(
                "ConfuserEx2 encrypted-resource blob extracted: blob_rva=0x{blob_rva:x} \
                 size={blob_size} sha256={} keyed-wall: keySeed not recoverable from any of \
                 {candidate_seeds_tried} ldc.i4 immediates (nested Constants protection encodes \
                 the seed; static recovery requires CIL emulation of the constants bootstrap)",
                hex_lower(blob_sha256),
            ),
        ),
        confuserex_resources::ConfuserExRecovery::NoEncryptedResourceFound => (
            PeelStrategy::AttributeStripAndReport,
            "ConfuserEx watermark present but no Resources-protection signature found (only \
             watermark + identifier renaming detected)"
                .to_string(),
        ),
    };
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
        notes: vec![note],
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
