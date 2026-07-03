use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::deobf::{
    Bits as DeobfBits, BogusBranch, CffOutcome, SubstitutionResult, defeat_bogus_control_flow,
    defeat_cff, undo_substitution,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObfuscatorFamily {
    Alcatraz,
    OllvmFlattening,
    OllvmBogusControlFlow,
    OllvmSubstitution,
    TigressCff,
    EmotetCff,
    Mirai,
    Dridex,
    Trickbot,
    ObfusH,
    Cryptify,
    GuardianRs,
    Obfusheader,
    Obfuscxx,
    Amice,
}

impl ObfuscatorFamily {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Alcatraz => "alcatraz",
            Self::OllvmFlattening => "ollvm-cff",
            Self::OllvmBogusControlFlow => "ollvm-bcf",
            Self::OllvmSubstitution => "ollvm-sub",
            Self::TigressCff => "tigress-cff",
            Self::EmotetCff => "emotet-cff",
            Self::Mirai => "mirai",
            Self::Dridex => "dridex",
            Self::Trickbot => "trickbot",
            Self::ObfusH => "obfus.h",
            Self::Cryptify => "cryptify (rust-obfuscator)",
            Self::GuardianRs => "guardian-rs (x86-64 virtualizer)",
            Self::Obfusheader => "obfusheader.h",
            Self::Obfuscxx => "obfuscxx (ngu compile-time xtea)",
            Self::Amice => "amice (rust ollvm-port llvm passes)",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObfuscatorHit {
    pub family: ObfuscatorFamily,
    pub matched_offset: u64,
    pub indicator: String,
}

#[derive(Debug, Clone, Copy)]
struct FamilySignature {
    family: ObfuscatorFamily,
    pattern: &'static [u8],
    indicator: &'static str,
}

const FAMILY_SIGNATURES: &[FamilySignature] = &[
    FamilySignature {
        family: ObfuscatorFamily::Alcatraz,
        pattern: b"AlcatrazRT",
        indicator: "ALCATRAZ runtime tag (Elastic 2024)",
    },
    FamilySignature {
        family: ObfuscatorFamily::Alcatraz,
        pattern: b"alcatraz.cipher",
        indicator: "ALCATRAZ cipher import",
    },
    FamilySignature {
        family: ObfuscatorFamily::OllvmFlattening,
        pattern: b"switch_var",
        indicator: "OLLVM CFF state-variable name",
    },
    FamilySignature {
        family: ObfuscatorFamily::OllvmFlattening,
        pattern: b"ollvm.fla",
        indicator: "OLLVM flatten pass metadata",
    },
    FamilySignature {
        family: ObfuscatorFamily::OllvmBogusControlFlow,
        pattern: b"ollvm.bcf",
        indicator: "OLLVM bogus-control-flow metadata",
    },
    FamilySignature {
        family: ObfuscatorFamily::OllvmSubstitution,
        pattern: b"ollvm.sub",
        indicator: "OLLVM instruction-substitution metadata",
    },
    FamilySignature {
        family: ObfuscatorFamily::TigressCff,
        pattern: b"_TIGRESS_flatten",
        indicator: "Tigress CFF runtime symbol",
    },
    FamilySignature {
        family: ObfuscatorFamily::EmotetCff,
        pattern: b"EmoCFF",
        indicator: "Emotet CFF marker",
    },
    FamilySignature {
        family: ObfuscatorFamily::Mirai,
        pattern: b"/dev/watchdog",
        indicator: "Mirai watchdog string",
    },
    FamilySignature {
        family: ObfuscatorFamily::Dridex,
        pattern: b"DriDex",
        indicator: "Dridex tag",
    },
    FamilySignature {
        family: ObfuscatorFamily::Trickbot,
        pattern: b"ModuleConfig",
        indicator: "Trickbot module config marker",
    },
    FamilySignature {
        family: ObfuscatorFamily::ObfusH,
        pattern: b".obfh\0\0\0",
        indicator: "obfus.h signature section (null-padded PE section name)",
    },
    FamilySignature {
        family: ObfuscatorFamily::Cryptify,
        pattern: b"CRYPTIFY_KEY",
        indicator: "cryptify runtime decrypt env-var lookup (rust-obfuscator)",
    },
    FamilySignature {
        family: ObfuscatorFamily::Obfusheader,
        pattern: b"zyxwvutsrqponmlkjihgfedcba",
        indicator: "obfusheader.h reversed-alphabet pointer-shuffle constant (survives stripping)",
    },
    FamilySignature {
        family: ObfuscatorFamily::Obfusheader,
        pattern: b"obfusheader_watermark",
        indicator: "obfusheader.h watermark hook symbol",
    },
    FamilySignature {
        family: ObfuscatorFamily::Obfuscxx,
        pattern: b"3ngu8obfuscxxI",
        indicator: "obfuscxx ngu::obfuscxx<> template instantiation symbol (Itanium-mangled iv table)",
    },
    FamilySignature {
        family: ObfuscatorFamily::Obfuscxx,
        pattern: b"?$obfuscxx@",
        indicator: "obfuscxx ngu::obfuscxx<> template instantiation symbol (MSVC-mangled)",
    },
    FamilySignature {
        family: ObfuscatorFamily::Amice,
        pattern: b"__amice__decrypt_strings_",
        indicator: "amice string-encryption runtime decryptor symbol (XOR algo emits \
                    __amice__decrypt_strings_<rand>__)",
    },
    FamilySignature {
        family: ObfuscatorFamily::Amice,
        pattern: b"simd_xor_decrypt_stub",
        indicator: "amice SIMD-XOR string-encryption decrypt stub symbol",
    },
    FamilySignature {
        family: ObfuscatorFamily::Amice,
        pattern: b"simd_xor_cipher_",
        indicator: "amice SIMD-XOR string-encryption cipher symbol (emits simd_xor_cipher_<rand>)",
    },
];

#[must_use]
pub fn detect(bytes: &[u8]) -> Vec<ObfuscatorHit> {
    let mut out: Vec<ObfuscatorHit> = Vec::new();
    for sig in FAMILY_SIGNATURES {
        if let Some(offset) = memmem(bytes, sig.pattern) {
            out.push(ObfuscatorHit {
                family: sig.family,
                matched_offset: offset as u64,
                indicator: sig.indicator.to_owned(),
            });
        }
    }
    if !out
        .iter()
        .any(|h: &ObfuscatorHit| h.family == ObfuscatorFamily::OllvmFlattening)
        && crate::deobf::cff::detect_flattening(bytes)
    {
        out.push(ObfuscatorHit {
            family: ObfuscatorFamily::OllvmFlattening,
            matched_offset: 0,
            indicator: "control-flow-flattening dispatcher (state-variable compare tree)"
                .to_owned(),
        });
    }
    augment_with_guardian_structural(bytes, &mut out);
    out
}

fn augment_with_guardian_structural(bytes: &[u8], out: &mut Vec<ObfuscatorHit>) {
    if out
        .iter()
        .any(|h: &ObfuscatorHit| h.family == ObfuscatorFamily::GuardianRs)
    {
        return;
    }
    let Ok(image): Result<crate::packers::pe_sections::PeImage, _> =
        crate::packers::pe_sections::parse_pe_image(bytes)
    else {
        return;
    };
    let Some(vm) = image.section_by_name(b".vm") else {
        return;
    };
    if image.section_by_name(b".byte").is_none() {
        return;
    }
    out.push(ObfuscatorHit {
        family: ObfuscatorFamily::GuardianRs,
        matched_offset: u64::from(vm.virtual_address),
        indicator: "guardian-rs embedded VM (.vm interpreter + .byte bytecode sections); \
                    virtualized functions redirect via push imm32 / jmp to the VM entry"
            .to_owned(),
    });
}

fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CffUnflattenReport {
    pub original_blocks: u32,
    pub recovered_blocks: u32,
    pub dispatcher_address: Option<u64>,
    pub state_variable_register: Option<String>,
    pub fully_recovered: bool,
    pub linear_order: Vec<u64>,
    pub notes: Vec<String>,
}

#[must_use]
pub fn unflatten_ollvm(bits: DeobfBits, base: u64, code: &[u8], entry: u64) -> CffUnflattenReport {
    match defeat_cff(bits, base, code, entry) {
        CffOutcome::Recovered(rec) => CffUnflattenReport {
            original_blocks: rec.original_block_count,
            recovered_blocks: rec.recovered_block_count,
            dispatcher_address: Some(rec.dispatcher_address),
            state_variable_register: Some(rec.state_loc.render()),
            fully_recovered: rec.fully_recovered,
            linear_order: rec.linear_order,
            notes: Vec::new(),
        },
        CffOutcome::NotFlattened => CffUnflattenReport {
            original_blocks: 0,
            recovered_blocks: 0,
            dispatcher_address: None,
            state_variable_register: None,
            fully_recovered: false,
            linear_order: Vec::new(),
            notes: vec!["no cmp-chain control-flow-flattening dispatcher found".to_owned()],
        },
    }
}

#[must_use]
pub fn strip_ollvm_bcf(bits: DeobfBits, base: u64, block: &[u8]) -> Option<BogusBranch> {
    defeat_bogus_control_flow(bits, base, block)
}

#[must_use]
pub fn undo_ollvm_substitution(
    bits: DeobfBits,
    base: u64,
    sequence: &[u8],
) -> Option<SubstitutionResult> {
    undo_substitution(bits, base, sequence)
}

#[must_use]
pub fn unflatten_tigress(
    bits: DeobfBits,
    base: u64,
    code: &[u8],
    entry: u64,
) -> CffUnflattenReport {
    unflatten_ollvm(bits, base, code, entry)
}

pub const AMICE_XOR_KEY: u8 = 0xAA;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringDecryptHit {
    pub family: ObfuscatorFamily,
    pub address: u64,
    pub recovered: String,
}

#[must_use]
pub fn decrypt_strings_for_family(
    family: ObfuscatorFamily,
    encoded: &BTreeMap<u64, Vec<u8>>,
) -> Vec<StringDecryptHit> {
    let mut out: Vec<StringDecryptHit> = Vec::new();
    for (addr, bytes) in encoded {
        let plain: String = match family {
            ObfuscatorFamily::Mirai => xor_decrypt(bytes, &[0x22, 0x54, 0x76, 0xC8]),
            ObfuscatorFamily::Dridex => xor_decrypt(bytes, &[0xDE, 0xAD, 0xBE, 0xEF]),
            ObfuscatorFamily::Trickbot => xor_decrypt(bytes, &[0x4B, 0x53, 0x4E, 0x59]),
            ObfuscatorFamily::Amice => xor_decrypt(bytes, &[AMICE_XOR_KEY]),
            _ => continue,
        };
        out.push(StringDecryptHit {
            family,
            address: *addr,
            recovered: plain,
        });
    }
    out
}

const OBFUSCXX_MAX_HITS: usize = 16;
const OBFUSCXX_VECTOR_BYTES: usize = 32;
const OBFUSCXX_CIPHER_VECTORS: usize = 8;
const OBFUSCXX_VECTOR_REFS: usize = 10;
const OBFUSCXX_TEXT_WINDOW_BEFORE: usize = 96;
const OBFUSCXX_TEXT_WINDOW_AFTER: usize = 192;
const OBFUSCXX_STRING_BYTES: usize = 32;
const OBFUSCXX_DECRYPT_ROUNDS: usize = 2;
const OBFUSCXX_SUM_START: u32 = 0xbbdf_4aae;
const OBFUSCXX_SUM_STEP: u32 = 0x2210_5aa9;

#[must_use]
pub fn recover_obfuscxx_strings(bytes: &[u8]) -> Vec<StringDecryptHit> {
    if !detect(bytes)
        .iter()
        .any(|h: &ObfuscatorHit| h.family == ObfuscatorFamily::Obfuscxx)
    {
        return Vec::new();
    }
    let Ok(image): Result<crate::packers::PeImage, _> = crate::packers::parse_pe_image(bytes)
    else {
        return Vec::new();
    };
    let Some(text) = image.section_by_name(b".text") else {
        return Vec::new();
    };
    let Some((text_start, text_end)) = text.raw_range(bytes.len()) else {
        return Vec::new();
    };
    let text_bytes: &[u8] = &bytes[text_start..text_end];
    let mut out: Vec<StringDecryptHit> = Vec::new();
    for lea_off in find_obfuscxx_key_leas(text_bytes) {
        if out.len() >= OBFUSCXX_MAX_HITS {
            break;
        }
        let Some(key_va) =
            rip_target_va(&image, text, lea_off, 7, read_i32(text_bytes, lea_off + 3))
        else {
            continue;
        };
        let Some(key) = read_obfuscxx_key(bytes, &image, key_va) else {
            continue;
        };
        let refs: Vec<u64> = collect_obfuscxx_vector_refs(&image, text, text_bytes, lea_off);
        let Some(vector_base) = find_obfuscxx_vector_run(&refs) else {
            continue;
        };
        let Some(recovered) = decode_obfuscxx_string(bytes, &image, vector_base, key) else {
            continue;
        };
        if out
            .iter()
            .any(|h: &StringDecryptHit| h.recovered == recovered)
        {
            continue;
        }
        out.push(StringDecryptHit {
            family: ObfuscatorFamily::Obfuscxx,
            address: vector_base,
            recovered,
        });
    }
    out
}

fn find_obfuscxx_key_leas(text: &[u8]) -> Vec<usize> {
    let mut out: Vec<usize> = Vec::new();
    if text.len() < 7 {
        return out;
    }
    for off in 0..=text.len() - 7 {
        if text[off..off + 3] == [0x4c, 0x8d, 0x1d]
            && text
                .get(off..off.saturating_add(256).min(text.len()))
                .is_some_and(|window: &[u8]| {
                    window
                        .windows(4)
                        .any(|w: &[u8]| w == [0x41, 0x8b, 0x3c, 0xd3])
                })
        {
            out.push(off);
        }
    }
    out
}

fn collect_obfuscxx_vector_refs(
    image: &crate::packers::PeImage,
    section: &crate::packers::PeSection,
    text: &[u8],
    lea_off: usize,
) -> Vec<u64> {
    let start: usize = lea_off.saturating_sub(OBFUSCXX_TEXT_WINDOW_BEFORE);
    let end: usize = lea_off
        .saturating_add(OBFUSCXX_TEXT_WINDOW_AFTER)
        .min(text.len());
    let mut refs: BTreeSet<u64> = BTreeSet::new();
    let mut off: usize = start;
    while off + 8 <= end {
        if text[off] == 0xc5
            && text[off + 1] == 0xfd
            && text[off + 2] == 0x6f
            && text[off + 3] & 0b1100_0111 == 0b0000_0101
            && let Some(target) = rip_target_va(image, section, off, 8, read_i32(text, off + 4))
        {
            refs.insert(target);
            off += 8;
            continue;
        }
        off += 1;
    }
    refs.into_iter().collect()
}

fn find_obfuscxx_vector_run(refs: &[u64]) -> Option<u64> {
    for window in refs.windows(OBFUSCXX_VECTOR_REFS) {
        let Some(base) = window.first().copied() else {
            continue;
        };
        let contiguous: bool = window
            .iter()
            .copied()
            .enumerate()
            .all(|(i, va): (usize, u64)| va == base + (i as u64) * OBFUSCXX_VECTOR_BYTES as u64);
        if contiguous {
            return Some(base);
        }
    }
    None
}

fn decode_obfuscxx_string(
    bytes: &[u8],
    image: &crate::packers::PeImage,
    vector_base: u64,
    key: [u32; 4],
) -> Option<String> {
    let mut vectors: [[u32; 8]; OBFUSCXX_VECTOR_REFS] = [[0u32; 8]; OBFUSCXX_VECTOR_REFS];
    for (i, vector) in vectors.iter_mut().enumerate() {
        *vector = read_u32x8_at_va(
            bytes,
            image,
            vector_base + (i as u64) * OBFUSCXX_VECTOR_BYTES as u64,
        )?;
    }
    let mut out: Vec<u8> = Vec::with_capacity(OBFUSCXX_STRING_BYTES);
    for lane_base in (0..OBFUSCXX_CIPHER_VECTORS).step_by(2) {
        let first: [u32; 8] = vectors[lane_base];
        let second: [u32; 8] = vectors[lane_base + 1];
        let perm4_first: [u32; 8] = permute_obfuscxx(first, vectors[8]);
        let perm4_second: [u32; 8] = permute_obfuscxx(second, vectors[8]);
        let perm3_first: [u32; 8] = permute_obfuscxx(first, vectors[9]);
        let perm3_second: [u32; 8] = permute_obfuscxx(second, vectors[9]);
        let mut y: [u32; 8] = [
            perm4_first[0],
            perm4_first[1],
            perm4_first[2],
            perm4_first[3],
            perm4_second[0],
            perm4_second[1],
            perm4_second[2],
            perm4_second[3],
        ];
        let mut z: [u32; 8] = [
            perm3_first[0],
            perm3_first[1],
            perm3_first[2],
            perm3_first[3],
            perm3_second[0],
            perm3_second[1],
            perm3_second[2],
            perm3_second[3],
        ];
        let mut sum: u32 = OBFUSCXX_SUM_START;
        for _ in 0..OBFUSCXX_DECRYPT_ROUNDS {
            let key_index: usize = ((sum >> 11) & 3) as usize;
            let first_key: u32 = key[key_index].wrapping_add(sum);
            for i in 0..8 {
                let mix: u32 = ((y[i] << 4) ^ (y[i] >> 5)).wrapping_add(y[i]) ^ first_key;
                z[i] = z[i].wrapping_sub(mix);
            }
            sum = sum.wrapping_add(OBFUSCXX_SUM_STEP);
            let key_index: usize = (sum & 3) as usize;
            let second_key: u32 = key[key_index].wrapping_add(sum);
            for i in 0..8 {
                let mix: u32 = ((z[i] << 4) ^ (z[i] >> 5)).wrapping_add(z[i]) ^ second_key;
                y[i] = y[i].wrapping_sub(mix);
            }
        }
        out.extend(y.iter().map(|word: &u32| (word & 0xff) as u8));
    }
    let end: usize = out.iter().position(|b: &u8| *b == 0).unwrap_or(out.len());
    let plain: &[u8] = &out[..end];
    if !looks_like_obfuscxx_plaintext(plain) {
        return None;
    }
    String::from_utf8(plain.to_vec()).ok()
}

fn permute_obfuscxx(src: [u32; 8], index: [u32; 8]) -> [u32; 8] {
    let mut out: [u32; 8] = [0u32; 8];
    for i in 0..8 {
        out[i] = src[(index[i] & 7) as usize];
    }
    out
}

fn read_obfuscxx_key(
    bytes: &[u8],
    image: &crate::packers::PeImage,
    key_va: u64,
) -> Option<[u32; 4]> {
    Some([
        read_u32_at_va(bytes, image, key_va)?,
        read_u32_at_va(bytes, image, key_va + 8)?,
        read_u32_at_va(bytes, image, key_va + 16)?,
        read_u32_at_va(bytes, image, key_va + 24)?,
    ])
}

fn read_u32x8_at_va(bytes: &[u8], image: &crate::packers::PeImage, va: u64) -> Option<[u32; 8]> {
    let off: usize = va_to_offset(bytes, image, va, OBFUSCXX_VECTOR_BYTES)?;
    let mut out: [u32; 8] = [0u32; 8];
    for (i, word) in out.iter_mut().enumerate() {
        let start: usize = off + i * 4;
        *word = u32::from_le_bytes(bytes[start..start + 4].try_into().ok()?);
    }
    Some(out)
}

fn read_u32_at_va(bytes: &[u8], image: &crate::packers::PeImage, va: u64) -> Option<u32> {
    let off: usize = va_to_offset(bytes, image, va, 4)?;
    Some(u32::from_le_bytes(bytes[off..off + 4].try_into().ok()?))
}

fn va_to_offset(
    bytes: &[u8],
    image: &crate::packers::PeImage,
    va: u64,
    len: usize,
) -> Option<usize> {
    let rva_u64: u64 = va.checked_sub(image.image_base)?;
    let rva: u32 = u32::try_from(rva_u64).ok()?;
    let section: &crate::packers::PeSection = image.section_containing_rva(rva)?;
    let section_delta: u32 = rva.checked_sub(section.virtual_address)?;
    let offset: usize = (section.raw_pointer as usize).checked_add(section_delta as usize)?;
    let end: usize = offset.checked_add(len)?;
    let raw_end: usize = (section.raw_pointer as usize).checked_add(section.raw_size as usize)?;
    if end <= bytes.len() && end <= raw_end {
        Some(offset)
    } else {
        None
    }
}

fn rip_target_va(
    image: &crate::packers::PeImage,
    section: &crate::packers::PeSection,
    text_off: usize,
    instr_len: u64,
    disp: i32,
) -> Option<u64> {
    let instr_end_rva: i64 = i64::try_from(
        u64::from(section.virtual_address)
            .checked_add(u64::try_from(text_off).ok()?)?
            .checked_add(instr_len)?,
    )
    .ok()?;
    let target_rva: i64 = instr_end_rva.checked_add(i64::from(disp))?;
    if target_rva < 0 {
        return None;
    }
    image
        .image_base
        .checked_add(u64::try_from(target_rva).ok()?)
}

fn read_i32(bytes: &[u8], off: usize) -> i32 {
    i32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

fn looks_like_obfuscxx_plaintext(bytes: &[u8]) -> bool {
    bytes.len() >= 6
        && bytes.iter().all(|b: &u8| is_printable_ascii(*b))
        && bytes
            .iter()
            .any(|b: &u8| b.is_ascii_alphabetic() || *b == b' ')
}

fn xor_decrypt(bytes: &[u8], key: &[u8]) -> String {
    if key.is_empty() {
        return String::new();
    }
    let decoded: Vec<u8> = bytes
        .iter()
        .enumerate()
        .map(|(i, b): (usize, &u8)| b ^ key[i % key.len()])
        .collect();
    String::from_utf8_lossy(&decoded).into_owned()
}

const XOR_MIN_RUN: usize = 6;
const XOR_MIN_SCORE: usize = 24;
const XOR_OUTLIER_MARGIN: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XorStringHit {
    pub key: u8,
    pub recovered: String,
}

#[must_use]
pub fn recover_amice_xor_strings(bytes: &[u8]) -> Vec<XorStringHit> {
    collect_xor_runs(bytes, AMICE_XOR_KEY)
}

#[must_use]
pub fn recover_single_byte_xor_strings(bytes: &[u8]) -> Vec<XorStringHit> {
    let mut histogram: [usize; 256] = [0usize; 256];
    for key in 1u16..=255u16 {
        histogram[key as usize] = count_xor_runs(bytes, key as u8);
    }
    let Some((best_key, best_hits)): Option<(usize, usize)> = histogram
        .iter()
        .copied()
        .enumerate()
        .skip(1)
        .max_by_key(|(_, h): &(usize, usize)| *h)
    else {
        return Vec::new();
    };
    if best_hits < XOR_MIN_SCORE || !xor_key_is_outlier(&histogram, best_hits) {
        return Vec::new();
    }
    collect_xor_runs(bytes, best_key as u8)
}

fn xor_key_is_outlier(histogram: &[usize; 256], best_hits: usize) -> bool {
    let mut nonzero: Vec<usize> = histogram
        .iter()
        .copied()
        .filter(|h: &usize| *h > 0)
        .collect();
    if nonzero.len() < 2 {
        return best_hits >= XOR_MIN_SCORE;
    }
    nonzero.sort_unstable();
    let median: usize = nonzero[nonzero.len() / 2];
    best_hits >= median.saturating_mul(XOR_OUTLIER_MARGIN).max(XOR_MIN_SCORE)
}

fn count_xor_runs(bytes: &[u8], key: u8) -> usize {
    let mut score: usize = 0;
    let mut run: Vec<u8> = Vec::with_capacity(64);
    for &byte in bytes {
        let decoded: u8 = byte ^ key;
        if is_printable_ascii(decoded) {
            run.push(decoded);
            continue;
        }
        score += english_score(&run);
        run.clear();
    }
    score += english_score(&run);
    score
}

fn english_score(run: &[u8]) -> usize {
    if run.len() < XOR_MIN_RUN {
        return 0;
    }
    let mut points: usize = 0;
    for &b in run {
        points += match b {
            b'a'..=b'z' => 3,
            b'A'..=b'Z' => 2,
            b' ' | b'/' | b'\\' | b'.' | b'_' | b'-' | b':' => 2,
            b'0'..=b'9' => 1,
            _ => 0,
        };
    }
    points
}

fn collect_xor_runs(bytes: &[u8], key: u8) -> Vec<XorStringHit> {
    let mut out: Vec<XorStringHit> = Vec::new();
    let mut current: Vec<u8> = Vec::with_capacity(64);
    for &byte in bytes {
        let decoded: u8 = byte ^ key;
        if is_printable_ascii(decoded) {
            current.push(decoded);
            continue;
        }
        if current.len() >= XOR_MIN_RUN
            && let Ok(s) = std::str::from_utf8(&current)
        {
            out.push(XorStringHit {
                key,
                recovered: s.to_owned(),
            });
        }
        current.clear();
    }
    if current.len() >= XOR_MIN_RUN
        && let Ok(s) = std::str::from_utf8(&current)
    {
        out.push(XorStringHit {
            key,
            recovered: s.to_owned(),
        });
    }
    out
}

const fn is_printable_ascii(b: u8) -> bool {
    b == b'\t' || b == b'\n' || b == b'\r' || (0x20 <= b && b <= 0x7e)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn alcatraz_runtime_tag_detected() {
        let mut buf: Vec<u8> = vec![0u8; 1024];
        buf[200..210].copy_from_slice(b"AlcatrazRT");
        let hits: Vec<ObfuscatorHit> = detect(&buf);
        assert!(
            hits.iter()
                .any(|h: &ObfuscatorHit| h.family == ObfuscatorFamily::Alcatraz)
        );
    }

    #[test]
    fn ollvm_cff_detected() {
        let mut buf: Vec<u8> = vec![0u8; 256];
        buf[10..20].copy_from_slice(b"switch_var");
        let hits: Vec<ObfuscatorHit> = detect(&buf);
        assert!(
            hits.iter()
                .any(|h: &ObfuscatorHit| h.family == ObfuscatorFamily::OllvmFlattening)
        );
    }

    #[test]
    fn obfuscxx_template_symbol_detected() {
        let mut buf: Vec<u8> = vec![0u8; 512];
        let needle: &[u8] = b"_ZN3ngu8obfuscxxI";
        buf[100..100 + needle.len()].copy_from_slice(needle);
        let hits: Vec<ObfuscatorHit> = detect(&buf);
        assert!(
            hits.iter()
                .any(|h: &ObfuscatorHit| h.family == ObfuscatorFamily::Obfuscxx)
        );
    }

    #[test]
    fn amice_decrypt_symbol_detected() {
        let mut buf: Vec<u8> = vec![0u8; 512];
        let needle: &[u8] = b"__amice__decrypt_strings_a1b2c3d4__";
        buf[100..100 + needle.len()].copy_from_slice(needle);
        let hits: Vec<ObfuscatorHit> = detect(&buf);
        assert!(
            hits.iter()
                .any(|h: &ObfuscatorHit| h.family == ObfuscatorFamily::Amice)
        );
    }

    #[test]
    fn amice_simd_cipher_symbol_detected() {
        let mut buf: Vec<u8> = vec![0u8; 512];
        let needle: &[u8] = b"simd_xor_cipher_9e8d7c6b";
        buf[40..40 + needle.len()].copy_from_slice(needle);
        let hits: Vec<ObfuscatorHit> = detect(&buf);
        assert!(
            hits.iter()
                .any(|h: &ObfuscatorHit| h.family == ObfuscatorFamily::Amice)
        );
    }

    #[test]
    fn amice_xor_string_round_trip_with_real_key() {
        let plain: &[u8] = b"https://c2.amice-demo.example/gate?id=victim";
        let cipher: Vec<u8> = plain.iter().map(|b: &u8| b ^ AMICE_XOR_KEY).collect();
        let mut map: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        map.insert(0x2000, cipher.clone());
        let out: Vec<StringDecryptHit> = decrypt_strings_for_family(ObfuscatorFamily::Amice, &map);
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].recovered,
            "https://c2.amice-demo.example/gate?id=victim"
        );
        let scanned: Vec<XorStringHit> = recover_amice_xor_strings(&cipher);
        assert!(
            scanned
                .iter()
                .any(|h: &XorStringHit| h.recovered.contains("amice-demo.example")),
            "the fixed 0xAA key must reassemble the planted string: {scanned:?}"
        );
    }

    #[test]
    fn unflatten_on_non_flattened_bytes_reports_no_dispatcher() {
        let linear: [u8; 4] = [0xB8, 0x01, 0x00, 0x00];
        let mut bytes: Vec<u8> = linear.to_vec();
        bytes.extend_from_slice(&[0x00, 0xC3]);
        let report: CffUnflattenReport = unflatten_ollvm(DeobfBits::Bits64, 0x1000, &bytes, 0x1000);
        assert!(!report.fully_recovered);
        assert_eq!(report.recovered_blocks, 0);
        assert!(report.dispatcher_address.is_none());
    }

    #[test]
    fn mirai_string_xor_round_trip() {
        let plain: &[u8] = b"hello-watchdog";
        let key: [u8; 4] = [0x22, 0x54, 0x76, 0xC8];
        let cipher: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect();
        let mut map: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        map.insert(0x1000, cipher);
        let out: Vec<StringDecryptHit> = decrypt_strings_for_family(ObfuscatorFamily::Mirai, &map);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].recovered, "hello-watchdog");
    }

    #[test]
    fn recovers_single_byte_xor_strings_with_auto_key() {
        let key: u8 = 0x5a;
        let secrets: [&str; 8] = [
            "http://malicious.example/c2/gate.php?id=victim",
            "C:\\Windows\\System32\\drivers\\etc\\hosts override path",
            "CreateRemoteThread and VirtualAllocEx injection chain",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run persistence",
            "powershell -enc downloaded second stage loader script",
            "select * from credentials where bank account is present",
            "user agent mozilla compatible windows nt exfil beacon",
            "decrypt key rotated nightly from the command server pool",
        ];
        let mut buf: Vec<u8> = Vec::new();
        for s in secrets {
            for &b in s.as_bytes() {
                buf.push(b ^ key);
            }
            buf.push(0xff ^ key);
        }
        let direct: Vec<XorStringHit> = collect_xor_runs(&buf, key);
        assert!(
            direct
                .iter()
                .any(|h: &XorStringHit| h.recovered.contains("malicious.example")),
            "with the real key every planted string must round-trip: {direct:?}"
        );
        assert!(
            direct.len() >= 6,
            "recovered {} of 8 with the real key",
            direct.len()
        );
        let auto: Vec<XorStringHit> = recover_single_byte_xor_strings(&buf);
        assert!(
            !auto.is_empty(),
            "auto key detection must surface a confident xor-string set on a real-text blob"
        );
        assert!(
            auto.iter().all(|h: &XorStringHit| h.key == auto[0].key),
            "all auto-recovered runs share one detected key"
        );
    }

    #[test]
    fn does_not_invent_xor_strings_from_random_data() {
        let buf: Vec<u8> = (0u16..2048u16)
            .map(|i: u16| (i.wrapping_mul(31) & 0xff) as u8)
            .collect();
        let hits: Vec<XorStringHit> = recover_single_byte_xor_strings(&buf);
        assert!(
            hits.len() < 4,
            "random data must not yield a confident xor-string set: {} hits",
            hits.len()
        );
    }
}
