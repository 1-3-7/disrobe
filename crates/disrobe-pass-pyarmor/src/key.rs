use iced_x86::{Code, Decoder, DecoderOptions, OpKind, Register};
use md5::{Digest, Md5};
use object::{Object, ObjectSection};

use crate::error::{Error, Result};

const PYARMOR_VAX: &[u8] = b"pyarmor-vax";
const ANCHOR_BACKOFF: usize = 0x2C;
const WORKING_BUFFER_SIZE: usize = 1024 * 1024;
const MAX_READ: usize = 16 * 1024 * 1024;

const AES_RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
const AES_SBOX_PREFIX: [u8; 32] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
];

#[rustfmt::skip]
pub(crate) const GLOBAL_CERT: [u8; 270] = [
    0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xbf, 0x65, 0x30, 0xf3, 0xbd, 0x67, 0xe7,
    0xa6, 0x9d, 0xf8, 0xdb, 0x18, 0xb2, 0xb9, 0xc1, 0xc0, 0x5f, 0xfe, 0xfb, 0xe5, 0x4b, 0x91, 0xdf,
    0x6f, 0x38, 0xda, 0x51, 0xcc, 0xea, 0xc4, 0xd3, 0x04, 0xbd, 0x95, 0x27, 0x86, 0xc1, 0x13, 0xca,
    0x73, 0x15, 0x44, 0x4d, 0x97, 0xf5, 0x10, 0xb9, 0x52, 0x21, 0x72, 0x16, 0xc8, 0xb2, 0x84, 0x5f,
    0x45, 0x56, 0x32, 0xe7, 0xc2, 0x6b, 0xad, 0x2b, 0xd9, 0xdf, 0x52, 0xd6, 0xe9, 0xd1, 0x2a, 0xba,
    0x35, 0xe4, 0x43, 0xab, 0x54, 0xe7, 0x91, 0xc5, 0xce, 0xd1, 0xf1, 0xba, 0xa5, 0x9f, 0xf4, 0xca,
    0xdb, 0x89, 0x04, 0x3d, 0xf8, 0x9f, 0x6a, 0x8b, 0x8a, 0x29, 0x39, 0xf8, 0x4c, 0x0d, 0xb8, 0xa0,
    0x6d, 0x51, 0xc4, 0x74, 0x24, 0x64, 0xfe, 0x1a, 0x23, 0x97, 0xf3, 0x61, 0xea, 0xde, 0xc8, 0x97,
    0xdc, 0x57, 0x60, 0x34, 0xbe, 0x2c, 0x18, 0x50, 0x3b, 0xd1, 0x76, 0x3b, 0x49, 0x2a, 0x39, 0x9a,
    0x37, 0x18, 0x53, 0x8f, 0x1d, 0x4c, 0x82, 0xb1, 0xa0, 0x33, 0x43, 0x57, 0x19, 0xad, 0x67, 0xe7,
    0xaf, 0x09, 0xfb, 0x04, 0x54, 0xa9, 0xea, 0xc0, 0xc1, 0xe9, 0x32, 0x6c, 0x77, 0x92, 0x7f, 0x9f,
    0x7c, 0x08, 0x7c, 0xe8, 0xa1, 0x5d, 0xa4, 0xfc, 0x40, 0xe6, 0x6e, 0x18, 0xdb, 0xbf, 0x45, 0x53,
    0x4b, 0x5c, 0xa7, 0x9d, 0xf2, 0x8f, 0x7e, 0x6c, 0x04, 0xb0, 0x4d, 0xee, 0x99, 0x25, 0x9a, 0x87,
    0x84, 0x6e, 0x9e, 0xfe, 0x3c, 0x72, 0xec, 0xb0, 0x64, 0xdd, 0x2e, 0xdb, 0xad, 0x32, 0xfa, 0x1d,
    0x4b, 0x2c, 0x1a, 0x78, 0x85, 0x7c, 0xbc, 0x2c, 0xd0, 0xd7, 0x83, 0x77, 0x5f, 0x92, 0xd5, 0xdb,
    0x59, 0x10, 0x96, 0x53, 0x2e, 0x5d, 0xc7, 0x42, 0x12, 0xb8, 0x61, 0xcb, 0x2c, 0x5f, 0x46, 0x14,
    0x9e, 0x93, 0xb0, 0x53, 0x21, 0xa2, 0x74, 0x34, 0x2d, 0x02, 0x03, 0x01, 0x00, 0x01,
];

#[derive(Clone)]
pub(crate) struct RuntimeKeyMaterial {
    pub serial: String,
    pub aes_key: [u8; 16],
    pub mix_str_nonce: [u8; 12],
}

impl core::fmt::Debug for RuntimeKeyMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RuntimeKeyMaterial")
            .field("serial", &self.serial)
            .field("aes_key", &"[redacted; 16]")
            .field("mix_str_nonce", &"[redacted; 12]")
            .finish()
    }
}

pub(crate) fn extract_runtime_key(runtime_bytes: &[u8]) -> Result<RuntimeKeyMaterial> {
    let read_len: usize = runtime_bytes.len().min(MAX_READ);
    let head: &[u8] = &runtime_bytes[..read_len];

    let anchor: usize = find_subslice(head, PYARMOR_VAX).ok_or_else(|| {
        if find_subslice(head, b"UPX!").is_some() && find_subslice(head, b"UPX0").is_some() {
            Error::KeyExtraction("runtime is UPX-packed; unpack with `upx -d` first".to_owned())
        } else {
            Error::KeyExtraction(
                "runtime does not contain 'pyarmor-vax' (not PyArmor or unsupported version)"
                    .to_owned(),
            )
        }
    })?;

    if anchor + 18 <= head.len() && head[anchor + 11..anchor + 18].iter().all(|&b| b == 0) {
        return Err(Error::KeyExtraction(
            "runtime appears to be a build template, not a real runtime".to_owned(),
        ));
    }
    if anchor < ANCHOR_BACKOFF {
        return Err(Error::KeyExtraction(
            "'pyarmor-vax' anchor located too early in runtime to back off 0x2C".to_owned(),
        ));
    }

    let base: usize = anchor - ANCHOR_BACKOFF;
    let buf_end: usize = (base + WORKING_BUFFER_SIZE).min(head.len());
    let mut buf: Vec<u8> = head[base..buf_end].to_vec();

    if buf.len() < 0x60 {
        return Err(Error::KeyExtraction(
            "working buffer too small (< 0x60 bytes)".to_owned(),
        ));
    }

    if buf[0x5C] & 1 != 0 {
        return Err(Error::KeyExtraction(
            "runtime depends on external '.pyarmor.ikey' file (not supported)".to_owned(),
        ));
    }

    if u32_le(&buf, 0x4C)? != 0 {
        let xor_flag: usize = 0x60usize + u32_le(&buf, 0x48)? as usize;
        let xor_target: usize = 0x60usize + u32_le(&buf, 0x50)? as usize;
        if xor_flag + 4 > buf.len() {
            return Err(Error::KeyExtraction(
                "xor flag record out of bounds".to_owned(),
            ));
        }
        let xor_length: usize = u24_le(&buf, xor_flag + 1)? as usize;
        if buf[xor_flag] == 1 {
            if xor_target + xor_length > buf.len() || xor_flag + 4 + xor_length > buf.len() {
                return Err(Error::KeyExtraction(
                    "streaming xor region out of bounds".to_owned(),
                ));
            }
            for i in 0..xor_length {
                buf[xor_target + i] ^= buf[xor_flag + 4 + i];
            }
        }
    }

    let part_1: Vec<u8> = sub(&buf, 0x2C, 20)?.to_vec();

    let p2_offset: usize = u32_le(&buf, 0x50)? as usize;
    let p2_len: usize = u32_le(&buf, 0x54)? as usize;
    let part_2: Vec<u8> = sub(&buf, 0x60 + p2_offset, p2_len)?.to_vec();

    let p3_record: usize = 0x60usize + u32_le(&buf, 0x58)? as usize;
    let p3_len: usize = u32_le(&buf, p3_record + 4)? as usize;
    let part_3: Vec<u8> = sub(&buf, p3_record + 0x20, p3_len)?.to_vec();

    let mut hasher: Md5 = Md5::new();
    hasher.update(&part_1);
    hasher.update(&part_2);
    hasher.update(&part_3);
    hasher.update(GLOBAL_CERT);
    let aes_key: [u8; 16] = hasher.finalize().into();

    let serial: String = core::str::from_utf8(&part_1[12..18])
        .map_err(|e| Error::KeyExtraction(format!("serial not utf-8: {e}")))?
        .to_owned();

    let mut mix_str_nonce: [u8; 12] = [0u8; 12];
    if part_3.len() >= 12 {
        mix_str_nonce.copy_from_slice(&part_3[..12]);
    }

    Ok(RuntimeKeyMaterial {
        serial,
        aes_key,
        mix_str_nonce,
    })
}

#[derive(Debug, Clone)]
pub(crate) struct V6V7StaticKey {
    pub(crate) key: [u8; 16],
    #[allow(
        dead_code,
        reason = "telemetry-only: which heuristic matched (adjacent-rcon / adjacent-sbox / rip-relative-movdqu) — surfaced in tests and intended for future provenance reporting"
    )]
    pub(crate) source: V6V7KeySource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum V6V7KeySource {
    AdjacentToRcon,
    AdjacentToSbox,
    RipRelativeMovdqu,
}

pub(crate) fn scan_v6v7_rdata_for_key(runtime_bytes: &[u8]) -> Result<[u8; 16]> {
    scan_v6v7_runtime_for_key(runtime_bytes).map(|k: V6V7StaticKey| k.key)
}

pub(crate) fn scan_v6v7_runtime_for_key(runtime_bytes: &[u8]) -> Result<V6V7StaticKey> {
    let parsed: object::File<'_> = object::File::parse(runtime_bytes)
        .map_err(|e: object::Error| Error::RuntimeParse(format!("object parse: {e}")))?;

    let mut rdata_view: Option<SectionView<'_>> = None;
    let mut text_view: Option<SectionView<'_>> = None;
    for section in parsed.sections() {
        let Ok(name): core::result::Result<&str, object::Error> = section.name() else {
            continue;
        };
        let Ok(data): core::result::Result<&[u8], object::Error> = section.data() else {
            continue;
        };
        let va: u64 = section.address();
        match name {
            ".rdata" | ".rodata" | "__const" if rdata_view.is_none() => {
                rdata_view = Some(SectionView { va, data });
            }
            ".text" | "__text" if text_view.is_none() => {
                text_view = Some(SectionView { va, data });
            }
            _ => {}
        }
    }

    if let Some(rdata) = rdata_view.as_ref()
        && let Some(found) = scan_rdata_adjacent_to_constants(rdata.data)
    {
        return Ok(found);
    }

    let (Some(rdata), Some(text)): (Option<SectionView<'_>>, Option<SectionView<'_>>) =
        (rdata_view, text_view)
    else {
        return Err(Error::KeyExtraction(
            "no .rdata/.rodata or .text section found in runtime".to_owned(),
        ));
    };

    let bitness: u32 = match parsed.architecture() {
        object::Architecture::X86_64 => 64,
        object::Architecture::I386 => 32,
        other => {
            return Err(Error::KeyExtraction(format!(
                "v6/v7 static key scan supports x86_64 / i386 only; got {other:?}"
            )));
        }
    };

    scan_text_for_rip_loaded_key(text, rdata, bitness)
        .map(|key: [u8; 16]| V6V7StaticKey {
            key,
            source: V6V7KeySource::RipRelativeMovdqu,
        })
        .ok_or_else(|| {
            Error::KeyExtraction(
                "no AES key recovered by adjacency or rip-relative MOVDQU pattern".to_owned(),
            )
        })
}

#[derive(Debug, Clone, Copy)]
struct SectionView<'a> {
    va: u64,
    data: &'a [u8],
}

fn scan_rdata_adjacent_to_constants(rdata: &[u8]) -> Option<V6V7StaticKey> {
    let rcon_pos: Option<usize> = find_subslice(rdata, &AES_RCON);
    let sbox_pos: Option<usize> = find_subslice(rdata, &AES_SBOX_PREFIX);

    if let Some(rp) = rcon_pos
        && let Some(key) = harvest_aligned_key_near(rdata, rp, AES_RCON.len())
    {
        return Some(V6V7StaticKey {
            key,
            source: V6V7KeySource::AdjacentToRcon,
        });
    }
    if let Some(sp) = sbox_pos
        && let Some(key) = harvest_aligned_key_near(rdata, sp, 256)
    {
        return Some(V6V7StaticKey {
            key,
            source: V6V7KeySource::AdjacentToSbox,
        });
    }
    None
}

fn harvest_aligned_key_near(rdata: &[u8], anchor: usize, anchor_len: usize) -> Option<[u8; 16]> {
    const PROBE_WINDOW: usize = 256;
    let before_start: usize = anchor.saturating_sub(PROBE_WINDOW);
    let after_end: usize = anchor
        .saturating_add(anchor_len)
        .saturating_add(PROBE_WINDOW);
    let after_end_clamped: usize = after_end.min(rdata.len());
    let anchor_end: usize = anchor.saturating_add(anchor_len);

    for start in (before_start..anchor.saturating_sub(15)).step_by(1) {
        if (start & 0xF) != 0 {
            continue;
        }
        if start + 16 > rdata.len() {
            break;
        }
        let candidate: &[u8] = &rdata[start..start + 16];
        if looks_like_aes_key(candidate) {
            let mut k: [u8; 16] = [0u8; 16];
            k.copy_from_slice(candidate);
            return Some(k);
        }
    }
    for start in (anchor_end..after_end_clamped.saturating_sub(15)).step_by(1) {
        if (start & 0xF) != 0 {
            continue;
        }
        if start + 16 > rdata.len() {
            break;
        }
        let candidate: &[u8] = &rdata[start..start + 16];
        if looks_like_aes_key(candidate) {
            let mut k: [u8; 16] = [0u8; 16];
            k.copy_from_slice(candidate);
            return Some(k);
        }
    }
    None
}

fn looks_like_aes_key(candidate: &[u8]) -> bool {
    if candidate.len() != 16 {
        return false;
    }
    let mut counts: [u32; 256] = [0u32; 256];
    for &b in candidate {
        counts[b as usize] = counts[b as usize].saturating_add(1);
    }
    let zero_count: u32 = counts[0];
    let ff_count: u32 = counts[0xFF];
    if zero_count >= 12 || ff_count >= 12 {
        return false;
    }
    let distinct_count: usize = counts.iter().filter(|&&c| c > 0).count();
    if distinct_count < 6 {
        return false;
    }
    #[allow(
        clippy::cast_precision_loss,
        reason = "16-byte key length fits f64 mantissa exactly; Shannon-entropy needs floating point"
    )]
    let n: f64 = candidate.len() as f64;
    let mut h: f64 = 0.0;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p: f64 = f64::from(c) / n;
        h -= p * p.log2();
    }
    h >= 3.0
}

fn scan_text_for_rip_loaded_key(
    text: SectionView<'_>,
    rdata: SectionView<'_>,
    bitness: u32,
) -> Option<[u8; 16]> {
    let mut decoder: Decoder<'_> =
        Decoder::with_ip(bitness, text.data, text.va, DecoderOptions::NONE);
    let mut buf: Vec<[u8; 16]> = Vec::new();
    let mut instr: iced_x86::Instruction = iced_x86::Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if !matches_movdqu_movdqa_movups(instr.code()) {
            continue;
        }
        if instr.op_count() < 2 || instr.op0_kind() != OpKind::Register {
            continue;
        }
        if !is_xmm_register(instr.op0_register()) {
            continue;
        }
        if instr.op1_kind() != OpKind::Memory {
            continue;
        }
        if !instr.is_ip_rel_memory_operand() {
            continue;
        }
        let target_va: u64 = instr.ip_rel_memory_address();
        let Some(offset): Option<usize> = va_to_offset(target_va, rdata) else {
            continue;
        };
        if offset + 16 > rdata.data.len() {
            continue;
        }
        let candidate: &[u8] = &rdata.data[offset..offset + 16];
        if looks_like_aes_key(candidate) {
            let mut k: [u8; 16] = [0u8; 16];
            k.copy_from_slice(candidate);
            buf.push(k);
            if buf.len() >= 16 {
                break;
            }
        }
    }
    buf.into_iter().next()
}

const fn matches_movdqu_movdqa_movups(code: Code) -> bool {
    matches!(
        code,
        Code::Movdqu_xmm_xmmm128
            | Code::Movdqa_xmm_xmmm128
            | Code::Movups_xmm_xmmm128
            | Code::Movaps_xmm_xmmm128
            | Code::Movupd_xmm_xmmm128
            | Code::Movapd_xmm_xmmm128
    )
}

const fn is_xmm_register(reg: Register) -> bool {
    matches!(
        reg,
        Register::XMM0
            | Register::XMM1
            | Register::XMM2
            | Register::XMM3
            | Register::XMM4
            | Register::XMM5
            | Register::XMM6
            | Register::XMM7
            | Register::XMM8
            | Register::XMM9
            | Register::XMM10
            | Register::XMM11
            | Register::XMM12
            | Register::XMM13
            | Register::XMM14
            | Register::XMM15
    )
}

fn va_to_offset(va: u64, section: SectionView<'_>) -> Option<usize> {
    let base: u64 = section.va;
    if va < base {
        return None;
    }
    let delta: u64 = va - base;
    let len_u64: u64 = section.data.len() as u64;
    if delta >= len_u64 {
        return None;
    }
    usize::try_from(delta).ok()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn sub(buf: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    buf.get(offset..offset + len).ok_or_else(|| {
        Error::KeyExtraction(format!(
            "buffer slice out of bounds: offset={offset} len={len} buf_len={}",
            buf.len()
        ))
    })
}

fn u32_le(buf: &[u8], offset: usize) -> Result<u32> {
    let bytes: &[u8] = sub(buf, offset, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn u24_le(buf: &[u8], offset: usize) -> Result<u32> {
    let bytes: &[u8] = sub(buf, offset, 3)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn global_cert_is_270_bytes() {
        assert_eq!(GLOBAL_CERT.len(), 270);
    }

    #[test]
    fn missing_anchor_errors_clearly() {
        let garbage: Vec<u8> = vec![0u8; 8192];
        let err: Error = extract_runtime_key(&garbage).unwrap_err();
        let s: String = format!("{err}");
        assert!(s.contains("pyarmor-vax") || s.contains("not PyArmor"));
    }

    #[test]
    fn upx_packed_diagnostic_kicks_in() {
        let mut data: Vec<u8> = vec![0u8; 8192];
        data[100..104].copy_from_slice(b"UPX!");
        data[200..204].copy_from_slice(b"UPX0");
        let err: Error = extract_runtime_key(&data).unwrap_err();
        let s: String = format!("{err}");
        assert!(s.contains("UPX"));
    }

    #[test]
    fn looks_like_aes_key_rejects_all_zeros_all_ff_low_entropy() {
        assert!(!looks_like_aes_key(&[0u8; 16]));
        assert!(!looks_like_aes_key(&[0xFFu8; 16]));
        assert!(!looks_like_aes_key(&[
            0x41u8, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41
        ]));
    }

    #[test]
    fn looks_like_aes_key_accepts_high_entropy_block() {
        let high_entropy: [u8; 16] = [
            0x4f, 0xa1, 0x39, 0x7c, 0x12, 0xb8, 0xe5, 0x6d, 0x90, 0x3a, 0x77, 0xfe, 0x21, 0xc4,
            0x88, 0x05,
        ];
        assert!(looks_like_aes_key(&high_entropy));
    }

    #[test]
    fn rdata_adjacent_to_rcon_finds_key() {
        let key: [u8; 16] = [
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0,
        ];
        let mut rdata: Vec<u8> = vec![0u8; 256];
        rdata[..16].copy_from_slice(&key);
        rdata[64..64 + AES_RCON.len()].copy_from_slice(&AES_RCON);
        let found: V6V7StaticKey = scan_rdata_adjacent_to_constants(&rdata).expect("found key");
        assert_eq!(found.key, key);
        assert_eq!(found.source, V6V7KeySource::AdjacentToRcon);
    }

    #[test]
    fn rdata_adjacent_to_sbox_finds_key_when_no_rcon() {
        let key: [u8; 16] = [
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
            0x11, 0x22,
        ];
        let mut rdata: Vec<u8> = vec![0u8; 1024];
        rdata[32..32 + AES_SBOX_PREFIX.len()].copy_from_slice(&AES_SBOX_PREFIX);
        rdata[512..512 + 16].copy_from_slice(&key);
        let found: V6V7StaticKey = scan_rdata_adjacent_to_constants(&rdata).expect("found key");
        assert_eq!(found.key, key);
        assert_eq!(found.source, V6V7KeySource::AdjacentToSbox);
    }

    #[test]
    fn synthesized_elf_x86_64_rdata_yields_key() {
        let key: [u8; 16] = [
            0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e,
            0x8f, 0x90,
        ];
        let mut rdata_section: Vec<u8> = vec![0u8; 256];
        rdata_section[..16].copy_from_slice(&key);
        rdata_section[64..64 + AES_RCON.len()].copy_from_slice(&AES_RCON);
        let elf: Vec<u8> = synth_elf64_with_rodata(&rdata_section, &[]);
        let recovered: V6V7StaticKey =
            scan_v6v7_runtime_for_key(&elf).expect("recover via rodata adjacency");
        assert_eq!(recovered.key, key);
        assert_eq!(recovered.source, V6V7KeySource::AdjacentToRcon);
    }

    fn synth_elf64_with_rodata(rodata: &[u8], text: &[u8]) -> Vec<u8> {
        const EHDR_SIZE: u16 = 64;
        const SHDR_SIZE: u16 = 64;
        const SHDR_COUNT: u16 = 4;
        let shstrtab: &[u8] = b"\0.rodata\0.text\0.shstrtab\0";

        let mut layout: Vec<u8> = Vec::new();
        layout.extend_from_slice(&[0u8; 64]);

        let rodata_offset: u64 = layout.len() as u64;
        layout.extend_from_slice(rodata);
        pad_to_align(&mut layout, 16);
        let text_offset: u64 = layout.len() as u64;
        layout.extend_from_slice(text);
        pad_to_align(&mut layout, 16);
        let shstrtab_offset: u64 = layout.len() as u64;
        layout.extend_from_slice(shstrtab);
        pad_to_align(&mut layout, 8);
        let shdr_offset: u64 = layout.len() as u64;
        let shdr_total: usize = usize::from(SHDR_SIZE) * usize::from(SHDR_COUNT);
        layout.extend(core::iter::repeat_n(0u8, shdr_total));

        layout[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        layout[4] = 2;
        layout[5] = 1;
        layout[6] = 1;
        layout[7] = 0;
        layout[16..18].copy_from_slice(&3u16.to_le_bytes());
        layout[18..20].copy_from_slice(&62u16.to_le_bytes());
        layout[20..24].copy_from_slice(&1u32.to_le_bytes());
        layout[40..48].copy_from_slice(&shdr_offset.to_le_bytes());
        layout[52..54].copy_from_slice(&EHDR_SIZE.to_le_bytes());
        layout[58..60].copy_from_slice(&SHDR_SIZE.to_le_bytes());
        layout[60..62].copy_from_slice(&SHDR_COUNT.to_le_bytes());
        layout[62..64].copy_from_slice(&3u16.to_le_bytes());

        let shdr_base: usize = usize::try_from(shdr_offset).expect("shdr_offset fits usize");
        let write_shdr = |buf: &mut Vec<u8>,
                          slot: usize,
                          name_off: u32,
                          sh_type: u32,
                          sh_flags: u64,
                          sh_addr: u64,
                          sh_offset: u64,
                          sh_size: u64| {
            let base: usize = shdr_base + slot * usize::from(SHDR_SIZE);
            buf[base..base + 4].copy_from_slice(&name_off.to_le_bytes());
            buf[base + 4..base + 8].copy_from_slice(&sh_type.to_le_bytes());
            buf[base + 8..base + 16].copy_from_slice(&sh_flags.to_le_bytes());
            buf[base + 16..base + 24].copy_from_slice(&sh_addr.to_le_bytes());
            buf[base + 24..base + 32].copy_from_slice(&sh_offset.to_le_bytes());
            buf[base + 32..base + 40].copy_from_slice(&sh_size.to_le_bytes());
        };

        write_shdr(&mut layout, 0, 0, 0, 0, 0, 0, 0);
        write_shdr(
            &mut layout,
            1,
            1,
            1,
            2,
            0x0040_1000,
            rodata_offset,
            rodata.len() as u64,
        );
        write_shdr(
            &mut layout,
            2,
            9,
            1,
            6,
            0x0040_2000,
            text_offset,
            text.len() as u64,
        );
        write_shdr(
            &mut layout,
            3,
            15,
            3,
            0,
            0,
            shstrtab_offset,
            shstrtab.len() as u64,
        );

        layout
    }

    fn pad_to_align(buf: &mut Vec<u8>, align: usize) {
        let remainder: usize = buf.len() % align;
        if remainder != 0 {
            buf.extend(core::iter::repeat_n(0u8, align - remainder));
        }
    }
}
