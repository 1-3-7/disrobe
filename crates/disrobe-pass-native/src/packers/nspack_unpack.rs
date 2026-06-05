use crate::error::{Error, Result};

const PE_MAGIC: &[u8; 4] = b"PE\x00\x00";
const DOS_E_LFANEW_OFFSET: usize = 0x3C;
const COFF_HEADER_SIZE: usize = 20;
const SECTION_ENTRY_SIZE: usize = 40;
const KNOWN_ORIGINAL_SECTION_NAMES: &[&[u8]] = &[
    b".text", b".rdata", b".data", b".rsrc", b".reloc", b".idata", b".edata", b".pdata", b".tls",
    b".bss", b".CRT", b".sdata", b".rodata", b"CODE", b"DATA", b"BSS",
];

/// Absolute ceiling on a single decompressed `NSPack` image.
const MAX_DECOMPRESSED_BYTES: usize = 256 * 1024 * 1024;
/// Maximum decompression ratio of `dsize` over the compressed body length.
const NSPACK_MAX_DECOMPRESS_RATIO: usize = 1024;

const NSPACK_STUB_MAGIC: &[u8; 13] = b"\x9c\x60\xe8\x00\x00\x00\x00\x5d\xb8\x07\x00\x00\x00";
const NSPACK_STUB_NOWINLDR_OFFSET: usize = 17;
const NSPACK_STUB_NOWINLDR_BASE: u32 = 0x54;
const NSPACK_HEADER_FIELDS_LEN: usize = 20;
const NSPACK_HEADER_FIRSTBYTE_OFFSET: usize = 0;
const NSPACK_HEADER_SSIZE_OFFSET: usize = 5;
const NSPACK_HEADER_DSIZE_OFFSET: usize = 9;
const NSPACK_HEADER_STREAM_OFFSET: usize = 13;
const NSPACK_FIRSTBYTE_DIVISOR: u32 = 0x2D;
const NSPACK_ALLOCSZ_DIVISOR: u32 = 9;
const NSPACK_FIRSTBYTE_REJECT: u32 = 0xE1;
const RANGE_CODER_TOP_BITS: u32 = 24;
const RANGE_CODER_TOP_VALUE: u32 = 1 << RANGE_CODER_TOP_BITS;
const RANGE_CODER_NUM_BIT_MODEL_TOTAL_BITS: u32 = 11;
const RANGE_CODER_BIT_MODEL_TOTAL: u32 = 1 << RANGE_CODER_NUM_BIT_MODEL_TOTAL_BITS;
const RANGE_CODER_MOVE_BITS: u32 = 5;
const RANGE_CODER_INIT_PROB: u16 = (RANGE_CODER_BIT_MODEL_TOTAL >> 1) as u16;
const LITERAL_BASE: usize = 0x736;
const POSITION_SLOT_BASE: usize = 0x1B0;
const POSITION_ALIGN_BASE: usize = 0x322;
const POSITION_BASE_PROBS: usize = 0x2AF;
const LEN_PROBS_FIRST: usize = 0x332;
const LEN_PROBS_REPEATED: usize = 0x534;
const MATCH_FLAG_BASE: usize = 0xC0;
const REP_FLAG_BASE: usize = 0xCC;
const REP_G0_BASE: usize = 0xD8;
const REP_G1_BASE: usize = 0xE4;
const SHORT_REP_BASE: usize = 0xF0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NspackSection<'a> {
    pub name: &'a [u8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_pointer: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone)]
pub struct NspackLayout<'a> {
    pub is_pe32_plus: bool,
    pub entry_point_rva: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub sections: Vec<NspackSection<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredSectionName {
    pub name: Vec<u8>,
    pub source_offset_in_nsp0: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredResource {
    pub recovered_offset_in_nsp1: usize,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum RecoveryStatus {
    StructuralOnly,
    ResourcesRecovered,
    FullPayloadDecompressed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NspackUnpackReport {
    pub status: RecoveryStatus,
    pub packed_size: usize,
    pub nsp0_raw_size: u32,
    pub nsp0_virtual_size: u32,
    pub nsp1_raw_size: u32,
    pub nsp1_virtual_size: u32,
    pub recovered_section_names: Vec<RecoveredSectionName>,
    pub recovered_resources: Vec<RecoveredResource>,
    pub stub_entry_point_rva: u32,
    pub limitation_note: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NspackEmulatedReport {
    pub status: RecoveryStatus,
    pub structural: NspackUnpackReport,
    pub start_of_stuff_file_offset: usize,
    pub stream_size_bytes: usize,
    pub decompressed_size_bytes: usize,
    pub decompressed_image: Vec<u8>,
    pub original_image_baseline: Option<Vec<u8>>,
    pub byte_diff_count: Option<usize>,
    pub byte_diff_pct: Option<f64>,
    /// Byte-match recovery over the compressed content sections only, excluding `.rsrc`/`.reloc`.
    pub content_recovery_pct: Option<f64>,
    /// Byte-match recovery over the entire decompressed region against the original mapped image.
    pub whole_file_recovery_pct: Option<f64>,
}

const NSPACK_UNCOMPRESSED_SECTION_NAMES: &[&[u8]] = &[b".rsrc", b".reloc"];

pub fn unpack_nspack(packed_bytes: &[u8]) -> Result<NspackUnpackReport> {
    let layout: NspackLayout<'_> = parse_nspack_layout(packed_bytes)?;
    let nsp0: &NspackSection<'_> = find_section(&layout, b"nsp0")
        .ok_or_else(|| Error::SignatureDb("NSPack: nsp0 section missing".to_owned()))?;
    let nsp1: &NspackSection<'_> = find_section(&layout, b"nsp1")
        .ok_or_else(|| Error::SignatureDb("NSPack: nsp1 section missing".to_owned()))?;
    let nsp0_raw: &[u8] = section_raw_bytes(packed_bytes, nsp0)?;
    let nsp1_raw: &[u8] = section_raw_bytes(packed_bytes, nsp1)?;
    let recovered_names: Vec<RecoveredSectionName> = recover_original_section_names(nsp0_raw);
    let recovered_resources: Vec<RecoveredResource> = recover_resource_table(nsp1_raw);
    let status: RecoveryStatus = if recovered_resources.is_empty() {
        RecoveryStatus::StructuralOnly
    } else {
        RecoveryStatus::ResourcesRecovered
    };
    Ok(NspackUnpackReport {
        status,
        packed_size: packed_bytes.len(),
        nsp0_raw_size: nsp0.raw_size,
        nsp0_virtual_size: nsp0.virtual_size,
        nsp1_raw_size: nsp1.raw_size,
        nsp1_virtual_size: nsp1.virtual_size,
        recovered_section_names: recovered_names,
        recovered_resources,
        stub_entry_point_rva: layout.entry_point_rva,
        limitation_note: "NSPack 3.x payload uses an LZMA-class binary range coder encoded by \
the in-stub x86 decompressor. Structural-only recovery: original section name cache from nsp0, \
verbatim resource directory from nsp1 head. Use unpack_nspack_emulated for full byte recovery."
            .to_owned(),
    })
}

#[derive(Debug, Default)]
struct RecoveryMetrics {
    baseline: Option<Vec<u8>>,
    byte_diff_count: Option<usize>,
    byte_diff_pct: Option<f64>,
    content_recovery_pct: Option<f64>,
    whole_file_recovery_pct: Option<f64>,
}

pub fn unpack_nspack_emulated(packed_bytes: &[u8]) -> Result<NspackEmulatedReport> {
    unpack_nspack_emulated_with_baseline(packed_bytes, None)
}

pub fn unpack_nspack_emulated_with_baseline_raw(
    packed_bytes: &[u8],
    original_pe: Option<&[u8]>,
) -> Result<(NspackEmulatedReport, Vec<u8>)> {
    let report: NspackEmulatedReport =
        unpack_nspack_emulated_with_baseline_inner(packed_bytes, original_pe, false)?;
    let raw: Vec<u8> = report.decompressed_image.clone();
    Ok((report, raw))
}

fn unpack_nspack_emulated_with_baseline_inner(
    packed_bytes: &[u8],
    original_pe: Option<&[u8]>,
    apply_fixup: bool,
) -> Result<NspackEmulatedReport> {
    let structural: NspackUnpackReport = unpack_nspack(packed_bytes)?;
    let layout: NspackLayout<'_> = parse_nspack_layout(packed_bytes)?;
    let nsp0: &NspackSection<'_> = find_section(&layout, b"nsp0")
        .ok_or_else(|| Error::SignatureDb("NSPack: nsp0 section missing".to_owned()))?;
    let stream: NspackStream = locate_compressed_stream(packed_bytes, &layout)?;
    if stream.dsize as usize != nsp0.virtual_size as usize {
        return Err(Error::SignatureDb(format!(
            "NSPack: dsize {} does not match nsp0.virtual_size {} (corrupt stub header)",
            stream.dsize, nsp0.virtual_size
        )));
    }
    let header_byte: u8 = packed_bytes
        .get(stream.start_of_stuff + NSPACK_HEADER_FIRSTBYTE_OFFSET)
        .copied()
        .ok_or_else(|| Error::SignatureDb("NSPack: header byte out of range".to_owned()))?;
    let LzmaParams {
        firstbyte,
        allocsz,
        tre,
        table_words,
    }: LzmaParams = derive_lzma_params(header_byte)?;
    let stream_body_start: usize = stream
        .start_of_stuff
        .checked_add(NSPACK_HEADER_STREAM_OFFSET)
        .ok_or_else(|| Error::SignatureDb("NSPack: stream offset overflow".to_owned()))?;
    let nominal_body_len: usize = (stream.ssize as usize)
        .checked_sub(NSPACK_HEADER_STREAM_OFFSET)
        .ok_or_else(|| Error::SignatureDb("NSPack: ssize smaller than 13".to_owned()))?;
    if stream_body_start >= packed_bytes.len() {
        return Err(Error::Truncated {
            needed: stream_body_start + 1,
            had: packed_bytes.len(),
        });
    }
    let available: usize = packed_bytes.len() - stream_body_start;
    let stream_body_len: usize = nominal_body_len.min(available);
    let compressed: &[u8] = &packed_bytes[stream_body_start..stream_body_start + stream_body_len];
    let declared_dsize: usize = stream.dsize as usize;
    let dsize_ceiling: usize =
        MAX_DECOMPRESSED_BYTES.min(stream_body_len.saturating_mul(NSPACK_MAX_DECOMPRESS_RATIO));
    if declared_dsize > dsize_ceiling {
        return Err(Error::SignatureDb(format!(
            "NSPack: declared dsize {declared_dsize} exceeds safety ceiling {dsize_ceiling} \
             (compressed body {stream_body_len} bytes) - refusing oversized allocation"
        )));
    }
    let mut output: Vec<u8> = vec![0u8; declared_dsize];
    let mut probs: Vec<u16> = vec![RANGE_CODER_INIT_PROB; table_words];
    let decode_result: Result<usize> =
        nspack_decode_lossy(compressed, &mut output, &mut probs, tre, allocsz, firstbyte);
    let _decoded_bytes: usize = decode_result.unwrap_or(0);
    if apply_fixup {
        apply_e8e9_call_jmp_fixup(&mut output);
    }
    let metrics: RecoveryMetrics = match original_pe {
        Some(orig) => {
            let baseline: Vec<u8> = build_original_baseline(orig, nsp0)?;
            let (diff, pct): (usize, f64) = compare_byte_diff(&output, &baseline);
            let content_pct: f64 =
                content_section_recovery_pct(orig, &output, &baseline, nsp0.virtual_address)?;
            let whole_pct: f64 = whole_image_recovery_pct(&output, &baseline);
            RecoveryMetrics {
                baseline: Some(baseline),
                byte_diff_count: Some(diff),
                byte_diff_pct: Some(pct),
                content_recovery_pct: Some(content_pct),
                whole_file_recovery_pct: Some(whole_pct),
            }
        }
        None => RecoveryMetrics::default(),
    };
    Ok(NspackEmulatedReport {
        status: RecoveryStatus::FullPayloadDecompressed,
        structural,
        start_of_stuff_file_offset: stream.start_of_stuff,
        stream_size_bytes: stream.ssize as usize,
        decompressed_size_bytes: stream.dsize as usize,
        decompressed_image: output,
        original_image_baseline: metrics.baseline,
        byte_diff_count: metrics.byte_diff_count,
        byte_diff_pct: metrics.byte_diff_pct,
        content_recovery_pct: metrics.content_recovery_pct,
        whole_file_recovery_pct: metrics.whole_file_recovery_pct,
    })
}

pub fn unpack_nspack_emulated_with_baseline(
    packed_bytes: &[u8],
    original_pe: Option<&[u8]>,
) -> Result<NspackEmulatedReport> {
    unpack_nspack_emulated_with_baseline_inner(packed_bytes, original_pe, true)
}

#[derive(Debug, Clone, Copy)]
struct NspackStream {
    start_of_stuff: usize,
    ssize: u32,
    dsize: u32,
}

#[derive(Debug, Clone, Copy)]
struct LzmaParams {
    firstbyte: u32,
    allocsz: u32,
    tre: u32,
    table_words: usize,
}

fn locate_compressed_stream(packed: &[u8], _layout: &NspackLayout<'_>) -> Result<NspackStream> {
    let stub_off: usize = find_subsequence(packed, NSPACK_STUB_MAGIC).ok_or_else(|| {
        Error::SignatureDb(
            "NSPack: stub magic 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 not found anywhere in file"
                .to_owned(),
        )
    })?;
    let nowinldr_required_end: usize = stub_off
        .checked_add(NSPACK_STUB_NOWINLDR_OFFSET + 4)
        .ok_or_else(|| Error::SignatureDb("NSPack: stub nowinldr offset overflow".to_owned()))?;
    if nowinldr_required_end > packed.len() {
        return Err(Error::Truncated {
            needed: nowinldr_required_end,
            had: packed.len(),
        });
    }
    let nowinldr_field: i32 = read_i32_le(packed, stub_off + NSPACK_STUB_NOWINLDR_OFFSET)?;
    let nowinldr: u32 =
        NSPACK_STUB_NOWINLDR_BASE.wrapping_sub(u32::from_ne_bytes(nowinldr_field.to_ne_bytes()));
    let nbuff_off: usize = stub_off.checked_sub(nowinldr as usize).ok_or_else(|| {
        Error::SignatureDb("NSPack: nowinldr underflows stub file offset".to_owned())
    })?;
    let nbuff_delta_bytes: &[u8] = read_slice(packed, nbuff_off, 4)?;
    let nbuff_delta: u32 = read_u32_le(nbuff_delta_bytes, 0)?;
    let mut start_of_stuff: usize = stub_off
        .checked_add(nbuff_delta as usize)
        .ok_or_else(|| Error::SignatureDb("NSPack: start_of_stuff overflow".to_owned()))?;
    let header_probe: &[u8] = read_slice(packed, start_of_stuff, NSPACK_HEADER_FIELDS_LEN)?;
    let first_dword: u32 = read_u32_le(header_probe, 0)?;
    if first_dword == 0 {
        start_of_stuff = start_of_stuff
            .checked_add(4)
            .ok_or_else(|| Error::SignatureDb("NSPack: start_of_stuff skip overflow".to_owned()))?;
    }
    let header_probe2: &[u8] = read_slice(packed, start_of_stuff, NSPACK_HEADER_FIELDS_LEN)?;
    let ssize_raw: u32 = read_u32_le(header_probe2, NSPACK_HEADER_SSIZE_OFFSET)?;
    let ssize: u32 = ssize_raw | 0xFF;
    let dsize: u32 = read_u32_le(header_probe2, NSPACK_HEADER_DSIZE_OFFSET)?;
    if ssize <= NSPACK_HEADER_STREAM_OFFSET as u32 {
        return Err(Error::SignatureDb(
            "NSPack: ssize smaller than the 13-byte header - invalid header".to_owned(),
        ));
    }
    if dsize == 0 {
        return Err(Error::SignatureDb(
            "NSPack: dsize zero - invalid header".to_owned(),
        ));
    }
    Ok(NspackStream {
        start_of_stuff,
        ssize,
        dsize,
    })
}

fn derive_lzma_params(header_byte: u8) -> Result<LzmaParams> {
    let mut c: u32 = u32::from(header_byte);
    if c >= NSPACK_FIRSTBYTE_REJECT {
        return Err(Error::SignatureDb(format!(
            "NSPack: header control byte {c:#x} >= 0xE1 (rejected)"
        )));
    }
    let firstbyte: u32 = if c >= NSPACK_FIRSTBYTE_DIVISOR {
        let q: u32 = c / NSPACK_FIRSTBYTE_DIVISOR;
        c = c.wrapping_sub(q.wrapping_mul(NSPACK_FIRSTBYTE_DIVISOR));
        q
    } else {
        0
    };
    let allocsz: u32 = if c >= NSPACK_ALLOCSZ_DIVISOR {
        let q: u32 = c / NSPACK_ALLOCSZ_DIVISOR;
        c = c.wrapping_sub(q.wrapping_mul(NSPACK_ALLOCSZ_DIVISOR));
        q
    } else {
        0
    };
    let tre: u32 = c;
    let shift: u32 = (tre.wrapping_add(allocsz)) & 0xFF;
    if shift >= 32 {
        return Err(Error::SignatureDb(format!(
            "NSPack: derived shift {shift} would overflow table width"
        )));
    }
    let table_words: usize = ((0x300_usize) << shift) + 0x736;
    Ok(LzmaParams {
        firstbyte,
        allocsz,
        tre,
        table_words,
    })
}

#[derive(Debug)]
struct RangeDecoder<'a> {
    src: &'a [u8],
    cursor: usize,
    range: u32,
    code: u32,
    done: bool,
}

impl<'a> RangeDecoder<'a> {
    fn new(src: &'a [u8]) -> Result<Self> {
        let mut rd: RangeDecoder<'a> = RangeDecoder {
            src,
            cursor: 0,
            range: 0xFFFF_FFFF,
            code: 0,
            done: false,
        };
        for _ in 0..5 {
            let byte: u32 = rd.read_byte_raw();
            rd.code = (rd.code << 8) | byte;
        }
        Ok(rd)
    }

    #[inline]
    fn read_byte_raw(&mut self) -> u32 {
        if self.cursor >= self.src.len() {
            self.done = true;
            return 0xFF;
        }
        let b: u32 = u32::from(self.src[self.cursor]);
        self.cursor += 1;
        b
    }

    #[inline]
    fn normalize(&mut self) {
        if self.range < RANGE_CODER_TOP_VALUE {
            let next: u32 = self.read_byte_raw();
            self.code = (self.code << 8) | next;
            self.range <<= 8;
        }
    }

    fn decode_bit(&mut self, prob: &mut u16) -> Result<u32> {
        let p: u32 = u32::from(*prob);
        let bound: u32 = (self.range >> RANGE_CODER_NUM_BIT_MODEL_TOTAL_BITS) * p;
        if self.code < bound {
            self.range = bound;
            let new_p: u32 = p + ((RANGE_CODER_BIT_MODEL_TOTAL - p) >> RANGE_CODER_MOVE_BITS);
            *prob = new_p as u16;
            self.normalize();
            Ok(0)
        } else {
            self.range = self.range.wrapping_sub(bound);
            self.code = self.code.wrapping_sub(bound);
            let new_p: u32 = p.wrapping_sub(p >> RANGE_CODER_MOVE_BITS);
            *prob = new_p as u16;
            self.normalize();
            Ok(1)
        }
    }

    fn decode_direct_bits(&mut self, num_bits: u32) -> Result<u32> {
        let mut result: u32 = 0;
        for _ in 0..num_bits {
            self.range >>= 1;
            let t: u32 = self.code.wrapping_sub(self.range) >> 31;
            self.code = self.code.wrapping_sub(self.range & t.wrapping_sub(1));
            result = (result << 1) | (1u32.wrapping_sub(t));
            if self.range < RANGE_CODER_TOP_VALUE {
                self.range <<= 8;
                let next: u32 = self.read_byte_raw();
                self.code = (self.code << 8) | next;
            }
        }
        Ok(result)
    }
}

fn nspack_decode_lossy(
    compressed: &[u8],
    output: &mut [u8],
    probs: &mut [u16],
    tre: u32,
    allocsz: u32,
    firstbyte_param: u32,
) -> Result<usize> {
    let dsize: usize = output.len();
    if dsize == 0 {
        return Ok(0);
    }
    let put_mask: u32 = (1u32 << (allocsz & 0xFF)).wrapping_sub(1);
    let literal_pos_mask: u32 = (1u32 << (firstbyte_param & 0xFF)).wrapping_sub(1);
    let pos_state_shift: u32 = 8u32.wrapping_sub(tre & 0xFF) & 0xFF;
    let mut rd: RangeDecoder<'_> = RangeDecoder::new(compressed)?;
    let mut state: u32 = 0;
    let mut unpacked: usize = 0;
    let mut prev_was_match: bool = false;
    let mut backbytes: u32 = 1;
    let mut old_back1: u32 = 1;
    let mut old_back2: u32 = 1;
    let mut old_back3: u32 = 1;
    let mut last_literal: u32 = 0;
    while unpacked < dsize {
        if rd.done {
            return Ok(unpacked);
        }
        let res: Result<()> = decode_one_step(
            &mut rd,
            output,
            probs,
            &mut state,
            &mut unpacked,
            &mut prev_was_match,
            &mut backbytes,
            &mut old_back1,
            &mut old_back2,
            &mut old_back3,
            &mut last_literal,
            put_mask,
            literal_pos_mask,
            pos_state_shift,
            tre,
            dsize,
        );
        if res.is_err() {
            return Ok(unpacked);
        }
    }
    Ok(unpacked)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    clippy::branches_sharing_code,
    clippy::assign_op_pattern
)]
fn decode_one_step(
    rd: &mut RangeDecoder<'_>,
    output: &mut [u8],
    probs: &mut [u16],
    state: &mut u32,
    unpacked: &mut usize,
    prev_was_match: &mut bool,
    backbytes: &mut u32,
    old_back1: &mut u32,
    old_back2: &mut u32,
    old_back3: &mut u32,
    last_literal: &mut u32,
    put_mask: u32,
    literal_pos_mask: u32,
    pos_state_shift: u32,
    tre: u32,
    dsize: usize,
) -> Result<()> {
    let pos_state: u32 = literal_pos_mask & (*unpacked as u32);
    let main_idx: usize = ((*state as usize) << 4) + pos_state as usize;
    if main_idx >= probs.len() {
        return Err(Error::SignatureDb(
            "NSPack: main probability index out of range".to_owned(),
        ));
    }
    let main_bit: u32 = rd.decode_bit(&mut probs[main_idx])?;
    if main_bit == 0 {
        let lit_select: u32 = (*last_literal >> pos_state_shift)
            .wrapping_add((put_mask & *unpacked as u32) << (tre & 0xFF));
        let lit_base: u32 = lit_select.wrapping_mul(3) << 8;
        let lit_base_usize: usize = LITERAL_BASE.wrapping_add(lit_base as usize);
        if *state >= 4 {
            if *state >= 0xA {
                *state -= 6;
            } else {
                *state -= 3;
            }
        } else {
            *state = 0;
        }
        let new_byte: u32 = if *prev_was_match {
            let match_byte_idx: usize =
                unpacked.checked_sub(*backbytes as usize).ok_or_else(|| {
                    Error::SignatureDb("NSPack: match byte references before start".to_owned())
                })?;
            let mb: u32 = u32::from(output[match_byte_idx]);
            let decoded: u32 = decode_literal_with_matchbyte(rd, probs, lit_base_usize, mb)?;
            *prev_was_match = false;
            decoded
        } else {
            decode_literal_plain(rd, probs, lit_base_usize)?
        };
        if *unpacked >= dsize {
            return Ok(());
        }
        output[*unpacked] = new_byte as u8;
        *last_literal = new_byte;
        *unpacked += 1;
        return Ok(());
    }
    *prev_was_match = true;
    *last_literal = 1;
    let is_rep_idx: usize = *state as usize + MATCH_FLAG_BASE;
    let is_rep: u32 = rd.decode_bit(&mut probs[is_rep_idx])?;
    let len: u32;
    if is_rep == 1 {
        let rep_g0_idx: usize = *state as usize + REP_FLAG_BASE;
        let rep_g0: u32 = rd.decode_bit(&mut probs[rep_g0_idx])?;
        if rep_g0 == 0 {
            let short_rep_idx: usize =
                SHORT_REP_BASE + ((*state as usize) << 4) + pos_state as usize;
            let short_rep: u32 = rd.decode_bit(&mut probs[short_rep_idx])?;
            if short_rep == 0 {
                if *unpacked == 0 {
                    return Err(Error::SignatureDb(
                        "NSPack: short-rep at start has no prior byte".to_owned(),
                    ));
                }
                *state = 2 * u32::from(*state >= 7) + 9;
                let prior_idx: usize = unpacked
                    .checked_sub(*backbytes as usize)
                    .ok_or_else(|| Error::SignatureDb("NSPack: short-rep underflow".to_owned()))?;
                let rep_byte: u8 = output[prior_idx];
                output[*unpacked] = rep_byte;
                *last_literal = u32::from(rep_byte);
                *unpacked += 1;
                return Ok(());
            }
            len = decode_match_length(rd, probs, LEN_PROBS_REPEATED, pos_state)?;
            *state = if *state >= 7 { 11 } else { 8 };
        } else {
            let rep_g1_idx: usize = *state as usize + REP_G0_BASE;
            let rep_g1: u32 = rd.decode_bit(&mut probs[rep_g1_idx])?;
            let dist: u32;
            if rep_g1 == 0 {
                dist = *old_back1;
            } else {
                let rep_g2_idx: usize = *state as usize + REP_G1_BASE;
                let rep_g2: u32 = rd.decode_bit(&mut probs[rep_g2_idx])?;
                if rep_g2 == 0 {
                    dist = *old_back2;
                } else {
                    dist = *old_back3;
                    *old_back3 = *old_back2;
                }
                *old_back2 = *old_back1;
            }
            *old_back1 = *backbytes;
            *backbytes = dist;
            len = decode_match_length(rd, probs, LEN_PROBS_REPEATED, pos_state)?;
            *state = if *state >= 7 { 11 } else { 8 };
        }
    } else {
        *old_back3 = *old_back2;
        *old_back2 = *old_back1;
        *old_back1 = *backbytes;
        *state = if *state >= 7 { 10 } else { 7 };
        len = decode_match_length(rd, probs, LEN_PROBS_FIRST, pos_state)?;
        let len_slot: u32 = if len >= 4 { 3 } else { len };
        let slot_base: usize = POSITION_SLOT_BASE + ((len_slot as usize) << 6);
        let pos_slot: u32 = decode_n_bit_tree(rd, probs, slot_base, 6)?;
        let distance: u32 = if pos_slot >= 4 {
            let num_direct_bits: u32 = (pos_slot >> 1).wrapping_sub(1);
            let mut base: u32 = (pos_slot & 1) | 2;
            base = base << num_direct_bits;
            if pos_slot < 0xE {
                let probs_base: usize =
                    POSITION_BASE_PROBS + (base as usize).wrapping_sub(pos_slot as usize);
                base.wrapping_add(decode_reverse_bit_tree(
                    rd,
                    probs,
                    probs_base,
                    num_direct_bits,
                )?)
            } else {
                let high_bits: u32 = num_direct_bits.wrapping_sub(4);
                let high: u32 = rd.decode_direct_bits(high_bits)?;
                let low: u32 = decode_reverse_bit_tree(rd, probs, POSITION_ALIGN_BASE, 4)?;
                base.wrapping_add(high << 4).wrapping_add(low)
            }
        } else {
            pos_slot
        };
        *backbytes = distance.wrapping_add(1);
    }
    let copy_len: usize = (len as usize).wrapping_add(2);
    if *backbytes == 0 {
        return Err(Error::SignatureDb(
            "NSPack: zero back-distance signals corrupt stream".to_owned(),
        ));
    }
    if *backbytes as usize > *unpacked {
        let bb: u32 = *backbytes;
        let up: usize = *unpacked;
        return Err(Error::SignatureDb(format!(
            "NSPack: back-distance {bb} exceeds unpacked {up}"
        )));
    }
    let remaining: usize = dsize.saturating_sub(*unpacked);
    let actual_copy: usize = copy_len.min(remaining);
    for _ in 0..actual_copy {
        let src_pos: usize = *unpacked - *backbytes as usize;
        let byte: u8 = output[src_pos];
        output[*unpacked] = byte;
        *unpacked += 1;
    }
    if *unpacked > 0 {
        *last_literal = u32::from(output[*unpacked - 1]);
    }
    Ok(())
}

#[allow(
    dead_code,
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    clippy::branches_sharing_code,
    clippy::assign_op_pattern
)]
fn nspack_decode(
    compressed: &[u8],
    output: &mut [u8],
    probs: &mut [u16],
    tre: u32,
    allocsz: u32,
    firstbyte_param: u32,
) -> Result<()> {
    let dsize: usize = output.len();
    if dsize == 0 {
        return Ok(());
    }
    let put_mask: u32 = (1u32 << (allocsz & 0xFF)).wrapping_sub(1);
    let literal_pos_mask: u32 = (1u32 << (firstbyte_param & 0xFF)).wrapping_sub(1);
    let pos_state_shift: u32 = 8u32.wrapping_sub(tre & 0xFF) & 0xFF;
    let mut rd: RangeDecoder<'_> = RangeDecoder::new(compressed)?;
    let mut state: u32 = 0;
    let mut unpacked: usize = 0;
    let mut prev_was_match: bool = false;
    let mut backbytes: u32 = 1;
    let mut old_back1: u32 = 1;
    let mut old_back2: u32 = 1;
    let mut old_back3: u32 = 1;
    let mut last_literal: u32 = 0;
    while unpacked < dsize {
        if rd.done {
            return Err(Error::SignatureDb(
                "NSPack: range decoder ran out of input before reaching dsize".to_owned(),
            ));
        }
        let pos_state: u32 = literal_pos_mask & (unpacked as u32);
        let main_idx: usize = ((state as usize) << 4) + pos_state as usize;
        if main_idx >= probs.len() {
            return Err(Error::SignatureDb(
                "NSPack: main probability index out of range".to_owned(),
            ));
        }
        let main_bit: u32 = {
            let p: &mut u16 = &mut probs[main_idx];
            rd.decode_bit(p)?
        };
        if main_bit == 0 {
            let lit_select: u32 = (last_literal >> pos_state_shift)
                .wrapping_add((put_mask & unpacked as u32) << (tre & 0xFF));
            let mut lit_base: u32 = lit_select.wrapping_mul(3);
            lit_base = lit_base << 8;
            let lit_base_usize: usize = LITERAL_BASE.wrapping_add(lit_base as usize);
            if state >= 4 {
                if state >= 0xA {
                    state -= 6;
                } else {
                    state -= 3;
                }
            } else {
                state = 0;
            }
            let new_byte: u32 = if prev_was_match {
                let match_byte_idx: usize =
                    unpacked.checked_sub(backbytes as usize).ok_or_else(|| {
                        Error::SignatureDb("NSPack: match byte references before start".to_owned())
                    })?;
                let mb: u32 = u32::from(output[match_byte_idx]);
                let decoded: u32 =
                    decode_literal_with_matchbyte(&mut rd, probs, lit_base_usize, mb)?;
                prev_was_match = false;
                decoded
            } else {
                decode_literal_plain(&mut rd, probs, lit_base_usize)?
            };
            if unpacked >= dsize {
                return Ok(());
            }
            output[unpacked] = new_byte as u8;
            last_literal = new_byte;
            unpacked += 1;
            continue;
        }
        prev_was_match = true;
        last_literal = 1;
        let is_rep_idx: usize = state as usize + MATCH_FLAG_BASE;
        let is_rep: u32 = {
            let p: &mut u16 = &mut probs[is_rep_idx];
            rd.decode_bit(p)?
        };
        let len: u32;
        if is_rep == 1 {
            let rep_g0_idx: usize = state as usize + REP_FLAG_BASE;
            let rep_g0: u32 = {
                let p: &mut u16 = &mut probs[rep_g0_idx];
                rd.decode_bit(p)?
            };
            if rep_g0 == 0 {
                let short_rep_idx: usize =
                    SHORT_REP_BASE + ((state as usize) << 4) + pos_state as usize;
                let short_rep: u32 = {
                    let p: &mut u16 = &mut probs[short_rep_idx];
                    rd.decode_bit(p)?
                };
                if short_rep == 0 {
                    if unpacked == 0 {
                        return Err(Error::SignatureDb(
                            "NSPack: short-rep at start has no prior byte".to_owned(),
                        ));
                    }
                    state = 2 * u32::from(state >= 7) + 9;
                    let prior_idx: usize =
                        unpacked.checked_sub(backbytes as usize).ok_or_else(|| {
                            Error::SignatureDb("NSPack: short-rep underflow".to_owned())
                        })?;
                    let rep_byte: u8 = output[prior_idx];
                    output[unpacked] = rep_byte;
                    last_literal = u32::from(rep_byte);
                    unpacked += 1;
                    continue;
                }
                len = decode_match_length(&mut rd, probs, LEN_PROBS_REPEATED, pos_state)?;
                state = if state >= 7 { 11 } else { 8 };
            } else {
                let rep_g1_idx: usize = state as usize + REP_G0_BASE;
                let rep_g1: u32 = {
                    let p: &mut u16 = &mut probs[rep_g1_idx];
                    rd.decode_bit(p)?
                };
                let dist: u32;
                if rep_g1 == 0 {
                    dist = old_back1;
                } else {
                    let rep_g2_idx: usize = state as usize + REP_G1_BASE;
                    let rep_g2: u32 = {
                        let p: &mut u16 = &mut probs[rep_g2_idx];
                        rd.decode_bit(p)?
                    };
                    if rep_g2 == 0 {
                        dist = old_back2;
                    } else {
                        dist = old_back3;
                        old_back3 = old_back2;
                    }
                    old_back2 = old_back1;
                }
                old_back1 = backbytes;
                backbytes = dist;
                len = decode_match_length(&mut rd, probs, LEN_PROBS_REPEATED, pos_state)?;
                state = if state >= 7 { 11 } else { 8 };
            }
        } else {
            old_back3 = old_back2;
            old_back2 = old_back1;
            old_back1 = backbytes;
            state = if state >= 7 { 10 } else { 7 };
            len = decode_match_length(&mut rd, probs, LEN_PROBS_FIRST, pos_state)?;
            let len_slot: u32 = if len >= 4 { 3 } else { len };
            let slot_base: usize = POSITION_SLOT_BASE + ((len_slot as usize) << 6);
            let pos_slot: u32 = decode_n_bit_tree(&mut rd, probs, slot_base, 6)?;
            let distance: u32 = if pos_slot >= 4 {
                let num_direct_bits: u32 = (pos_slot >> 1).wrapping_sub(1);
                let mut base: u32 = (pos_slot & 1) | 2;
                base = base << num_direct_bits;
                if pos_slot < 0xE {
                    let probs_base: usize =
                        POSITION_BASE_PROBS + (base as usize).wrapping_sub(pos_slot as usize);
                    base.wrapping_add(decode_reverse_bit_tree(
                        &mut rd,
                        probs,
                        probs_base,
                        num_direct_bits,
                    )?)
                } else {
                    let high_bits: u32 = num_direct_bits.wrapping_sub(4);
                    let high: u32 = rd.decode_direct_bits(high_bits)?;
                    let low: u32 = decode_reverse_bit_tree(&mut rd, probs, POSITION_ALIGN_BASE, 4)?;
                    base.wrapping_add(high << 4).wrapping_add(low)
                }
            } else {
                pos_slot
            };
            backbytes = distance.wrapping_add(1);
        }
        let copy_len: usize = (len as usize).wrapping_add(2);
        if backbytes == 0 {
            return Err(Error::SignatureDb(
                "NSPack: zero back-distance signals corrupt stream".to_owned(),
            ));
        }
        if backbytes as usize > unpacked {
            return Err(Error::SignatureDb(format!(
                "NSPack: back-distance {backbytes} exceeds unpacked {unpacked}"
            )));
        }
        let remaining: usize = dsize.saturating_sub(unpacked);
        let actual_copy: usize = copy_len.min(remaining);
        for _ in 0..actual_copy {
            let src_pos: usize = unpacked - backbytes as usize;
            let byte: u8 = output[src_pos];
            output[unpacked] = byte;
            unpacked += 1;
        }
        if unpacked > 0 {
            last_literal = u32::from(output[unpacked - 1]);
        }
        if unpacked >= dsize {
            return Ok(());
        }
    }
    Ok(())
}

fn decode_literal_plain(rd: &mut RangeDecoder<'_>, probs: &mut [u16], base: usize) -> Result<u32> {
    let mut symbol: u32 = 1;
    while symbol < 0x100 {
        let idx: usize = base.wrapping_add(symbol as usize);
        if idx >= probs.len() {
            return Err(Error::SignatureDb(
                "NSPack: literal probability index out of range".to_owned(),
            ));
        }
        let bit: u32 = rd.decode_bit(&mut probs[idx])?;
        symbol = (symbol << 1) | bit;
    }
    Ok(symbol & 0xFF)
}

fn decode_literal_with_matchbyte(
    rd: &mut RangeDecoder<'_>,
    probs: &mut [u16],
    base: usize,
    mut match_byte: u32,
) -> Result<u32> {
    let mut symbol: u32 = 1;
    while symbol < 0x100 {
        match_byte <<= 1;
        let match_bit: u32 = (match_byte >> 8) & 1;
        let prob_idx: usize = base
            .wrapping_add(((1 + match_bit) << 8) as usize)
            .wrapping_add(symbol as usize);
        if prob_idx >= probs.len() {
            return Err(Error::SignatureDb(
                "NSPack: matchbyte literal index out of range".to_owned(),
            ));
        }
        let bit: u32 = rd.decode_bit(&mut probs[prob_idx])?;
        symbol = (symbol << 1) | bit;
        if match_bit != bit {
            while symbol < 0x100 {
                let idx2: usize = base.wrapping_add(symbol as usize);
                if idx2 >= probs.len() {
                    return Err(Error::SignatureDb(
                        "NSPack: matchbyte tail literal index out of range".to_owned(),
                    ));
                }
                let b: u32 = rd.decode_bit(&mut probs[idx2])?;
                symbol = (symbol << 1) | b;
            }
            break;
        }
    }
    Ok(symbol & 0xFF)
}

fn decode_n_bit_tree(
    rd: &mut RangeDecoder<'_>,
    probs: &mut [u16],
    base: usize,
    num_bits: u32,
) -> Result<u32> {
    let mut idx: u32 = 1;
    for _ in 0..num_bits {
        let prob_idx: usize = base.wrapping_add(idx as usize);
        if prob_idx >= probs.len() {
            return Err(Error::SignatureDb(
                "NSPack: n-bit tree index out of range".to_owned(),
            ));
        }
        let bit: u32 = rd.decode_bit(&mut probs[prob_idx])?;
        idx = (idx << 1) | bit;
    }
    Ok(idx.wrapping_sub(1u32 << num_bits))
}

fn decode_reverse_bit_tree(
    rd: &mut RangeDecoder<'_>,
    probs: &mut [u16],
    base: usize,
    num_bits: u32,
) -> Result<u32> {
    let mut idx: u32 = 1;
    let mut result: u32 = 0;
    for i in 0..num_bits {
        let prob_idx: usize = base.wrapping_add(idx as usize);
        if prob_idx >= probs.len() {
            return Err(Error::SignatureDb(
                "NSPack: reverse-tree index out of range".to_owned(),
            ));
        }
        let bit: u32 = rd.decode_bit(&mut probs[prob_idx])?;
        idx = (idx << 1).wrapping_add(bit);
        result |= bit << i;
    }
    Ok(result)
}

fn decode_match_length(
    rd: &mut RangeDecoder<'_>,
    probs: &mut [u16],
    base: usize,
    pos_state: u32,
) -> Result<u32> {
    let low_choice_idx: usize = base;
    let low_choice_bit: u32 = {
        let p: &mut u16 = &mut probs[low_choice_idx];
        rd.decode_bit(p)?
    };
    if low_choice_bit == 0 {
        let sub_base: usize = base + 2 + ((pos_state as usize) << 3);
        return decode_n_bit_tree(rd, probs, sub_base, 3);
    }
    let mid_choice_idx: usize = base + 1;
    let mid_choice_bit: u32 = {
        let p: &mut u16 = &mut probs[mid_choice_idx];
        rd.decode_bit(p)?
    };
    if mid_choice_bit == 0 {
        let sub_base: usize = base + 0x82 + ((pos_state as usize) << 3);
        let len: u32 = decode_n_bit_tree(rd, probs, sub_base, 3)?;
        return Ok(8 + len);
    }
    let sub_base: usize = base + 0x102;
    let len: u32 = decode_n_bit_tree(rd, probs, sub_base, 8)?;
    Ok(0x10 + len)
}

fn apply_e8e9_call_jmp_fixup(buf: &mut [u8]) {
    let len: usize = buf.len();
    if len < 5 {
        return;
    }
    let image_size: i64 = i64::try_from(len).unwrap_or(i64::MAX);
    let mut i: usize = 0;
    let end: usize = len.saturating_sub(5);
    while i < end {
        let op: u8 = buf[i];
        if op == 0xE8 || op == 0xE9 {
            let stored_le: u32 =
                u32::from_le_bytes([buf[i + 1], buf[i + 2], buf[i + 3], buf[i + 4]]);
            let stored_rel: i32 = stored_le.cast_signed();
            let pos_i64: i64 = i64::try_from(i).unwrap_or(i64::MAX);
            let stored_target: i64 = pos_i64
                .saturating_add(5)
                .saturating_add(i64::from(stored_rel));
            let stored_in_image: bool = stored_target >= 0 && stored_target < image_size;
            let bswapped: u32 = stored_le.swap_bytes();
            let masked: u32 = bswapped & 0x00FF_FFFF;
            let pos_plus_one: u32 = u32::try_from(i.wrapping_add(1)).unwrap_or(u32::MAX);
            let original: u32 = masked.wrapping_sub(pos_plus_one);
            let candidate: u32 = if original & 0x0080_0000 != 0 {
                original | 0xFF00_0000
            } else {
                original & 0x00FF_FFFF
            };
            let rel: i32 = candidate.cast_signed();
            let target: i64 = pos_i64.saturating_add(5).saturating_add(i64::from(rel));
            let recovered_in_image: bool = target >= 0 && target < image_size;
            if recovered_in_image && !stored_in_image {
                let out: [u8; 4] = candidate.to_le_bytes();
                buf[i + 1] = out[0];
                buf[i + 2] = out[1];
                buf[i + 3] = out[2];
                buf[i + 4] = out[3];
                i += 5;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
}

#[allow(clippy::cast_precision_loss)]
fn content_section_recovery_pct(
    original_pe: &[u8],
    decompressed: &[u8],
    baseline: &[u8],
    nsp0_base_rva: u32,
) -> Result<f64> {
    let layout: NspackLayout<'_> = parse_nspack_layout(original_pe)?;
    let compare_len: usize = decompressed.len().min(baseline.len());
    let mut total: usize = 0;
    let mut matching: usize = 0;
    for sec in &layout.sections {
        if NSPACK_UNCOMPRESSED_SECTION_NAMES
            .iter()
            .any(|n: &&[u8]| section_name_matches(sec.name, n))
        {
            continue;
        }
        if sec.virtual_address < nsp0_base_rva {
            continue;
        }
        let off: usize = (sec.virtual_address - nsp0_base_rva) as usize;
        if off >= compare_len {
            continue;
        }
        let span_end: usize = (off + sec.virtual_size as usize).min(compare_len);
        for j in off..span_end {
            total += 1;
            if decompressed[j] == baseline[j] {
                matching += 1;
            }
        }
    }
    if total == 0 {
        return Ok(0.0);
    }
    Ok(100.0 * matching as f64 / total as f64)
}

#[allow(clippy::cast_precision_loss)]
fn whole_image_recovery_pct(decompressed: &[u8], baseline: &[u8]) -> f64 {
    let compare_len: usize = decompressed.len().min(baseline.len());
    if compare_len == 0 {
        return 0.0;
    }
    let matching: usize = decompressed
        .iter()
        .zip(baseline.iter())
        .take(compare_len)
        .filter(|(a, b): &(&u8, &u8)| a == b)
        .count();
    let denom: usize = decompressed.len().max(baseline.len());
    100.0 * matching as f64 / denom as f64
}

fn section_name_matches(name: &[u8], target: &[u8]) -> bool {
    let trimmed: &[u8] = name
        .iter()
        .position(|&b: &u8| b == 0)
        .map_or(name, |pos: usize| &name[..pos]);
    trimmed == target
}

fn build_original_baseline(original_pe: &[u8], nsp0: &NspackSection<'_>) -> Result<Vec<u8>> {
    let layout: NspackLayout<'_> = parse_nspack_layout(original_pe)?;
    let dsize: usize = nsp0.virtual_size as usize;
    let base_rva: u32 = nsp0.virtual_address;
    let mut buf: Vec<u8> = vec![0u8; dsize];
    for sec in &layout.sections {
        if sec.virtual_address < base_rva {
            continue;
        }
        let dst_off: usize = (sec.virtual_address - base_rva) as usize;
        if dst_off >= dsize {
            continue;
        }
        let raw_avail: usize =
            (sec.raw_size as usize).min(original_pe.len().saturating_sub(sec.raw_pointer as usize));
        let vsize_cap: usize = sec.virtual_size as usize;
        let copy_len: usize = raw_avail.min(vsize_cap).min(dsize - dst_off);
        if copy_len == 0 {
            continue;
        }
        let src_start: usize = sec.raw_pointer as usize;
        buf[dst_off..dst_off + copy_len]
            .copy_from_slice(&original_pe[src_start..src_start + copy_len]);
    }
    Ok(buf)
}

#[allow(clippy::cast_precision_loss)]
fn compare_byte_diff(decompressed: &[u8], baseline: &[u8]) -> (usize, f64) {
    let common_len: usize = decompressed.len().min(baseline.len());
    let matching_diff: usize = decompressed
        .iter()
        .zip(baseline.iter())
        .take(common_len)
        .filter(|(a, b): &(&u8, &u8)| a != b)
        .count();
    let diff: usize = matching_diff + decompressed.len().abs_diff(baseline.len());
    let total: usize = decompressed.len().max(baseline.len()).max(1);
    let pct: f64 = (diff as f64) * 100.0 / (total as f64);
    (diff, pct)
}

fn read_slice(bytes: &[u8], off: usize, len: usize) -> Result<&[u8]> {
    let end: usize = off
        .checked_add(len)
        .ok_or_else(|| Error::SignatureDb("NSPack: slice end overflow".to_owned()))?;
    if end > bytes.len() {
        return Err(Error::Truncated {
            needed: end,
            had: bytes.len(),
        });
    }
    Ok(&bytes[off..end])
}

fn read_i32_le(b: &[u8], off: usize) -> Result<i32> {
    let u: u32 = read_u32_le(b, off)?;
    Ok(i32::from_ne_bytes(u.to_ne_bytes()))
}

pub fn parse_nspack_layout(bytes: &[u8]) -> Result<NspackLayout<'_>> {
    if bytes.len() < DOS_E_LFANEW_OFFSET + 4 {
        return Err(Error::Truncated {
            needed: DOS_E_LFANEW_OFFSET + 4,
            had: bytes.len(),
        });
    }
    let e_lfanew: usize = read_u32_le(bytes, DOS_E_LFANEW_OFFSET)? as usize;
    if e_lfanew.saturating_add(24) > bytes.len() {
        return Err(Error::Truncated {
            needed: e_lfanew + 24,
            had: bytes.len(),
        });
    }
    if &bytes[e_lfanew..e_lfanew + 4] != PE_MAGIC {
        return Err(Error::UnknownFormat);
    }
    let coff_off: usize = e_lfanew + 4;
    let n_sections: usize = read_u16_le(bytes, coff_off + 2)? as usize;
    let opt_hdr_size: u16 = read_u16_le(bytes, coff_off + 16)?;
    let opt_hdr_off: usize = coff_off + COFF_HEADER_SIZE;
    let opt_magic: u16 = read_u16_le(bytes, opt_hdr_off)?;
    let is_pe32_plus: bool = match opt_magic {
        0x010B => false,
        0x020B => true,
        _ => return Err(Error::UnknownFormat),
    };
    let entry_point_rva: u32 = read_u32_le(bytes, opt_hdr_off + 16)?;
    let (image_base, section_alignment, file_alignment): (u64, u32, u32) = if is_pe32_plus {
        (
            read_u64_le(bytes, opt_hdr_off + 24)?,
            read_u32_le(bytes, opt_hdr_off + 32)?,
            read_u32_le(bytes, opt_hdr_off + 36)?,
        )
    } else {
        (
            u64::from(read_u32_le(bytes, opt_hdr_off + 28)?),
            read_u32_le(bytes, opt_hdr_off + 32)?,
            read_u32_le(bytes, opt_hdr_off + 36)?,
        )
    };
    let sec_table_off: usize = opt_hdr_off + opt_hdr_size as usize;
    let needed: usize = sec_table_off + n_sections * SECTION_ENTRY_SIZE;
    if needed > bytes.len() {
        return Err(Error::Truncated {
            needed,
            had: bytes.len(),
        });
    }
    let mut sections: Vec<NspackSection<'_>> = Vec::with_capacity(n_sections);
    for i in 0..n_sections {
        let entry_off: usize = sec_table_off + i * SECTION_ENTRY_SIZE;
        let raw_name: &[u8] = &bytes[entry_off..entry_off + 8];
        let trimmed_len: usize = raw_name
            .iter()
            .position(|b: &u8| *b == 0)
            .unwrap_or(raw_name.len());
        let name: &[u8] = &raw_name[..trimmed_len];
        sections.push(NspackSection {
            name,
            virtual_size: read_u32_le(bytes, entry_off + 8)?,
            virtual_address: read_u32_le(bytes, entry_off + 12)?,
            raw_size: read_u32_le(bytes, entry_off + 16)?,
            raw_pointer: read_u32_le(bytes, entry_off + 20)?,
            characteristics: read_u32_le(bytes, entry_off + 36)?,
        });
    }
    Ok(NspackLayout {
        is_pe32_plus,
        entry_point_rva,
        image_base,
        section_alignment,
        file_alignment,
        sections,
    })
}

fn find_section<'l, 'b>(
    layout: &'l NspackLayout<'b>,
    name: &[u8],
) -> Option<&'l NspackSection<'b>> {
    layout
        .sections
        .iter()
        .find(|s: &&NspackSection<'b>| s.name == name)
}

fn section_raw_bytes<'a>(packed: &'a [u8], sec: &NspackSection<'_>) -> Result<&'a [u8]> {
    let start: usize = sec.raw_pointer as usize;
    let end: usize = start.saturating_add(sec.raw_size as usize);
    if end > packed.len() {
        return Err(Error::Truncated {
            needed: end,
            had: packed.len(),
        });
    }
    Ok(&packed[start..end])
}

fn recover_original_section_names(nsp0_raw: &[u8]) -> Vec<RecoveredSectionName> {
    let mut out: Vec<RecoveredSectionName> = Vec::new();
    for known in KNOWN_ORIGINAL_SECTION_NAMES {
        let mut search_from: usize = 0;
        while let Some(offset) = find_subsequence(&nsp0_raw[search_from..], known) {
            let absolute: usize = search_from + offset;
            out.push(RecoveredSectionName {
                name: (*known).to_vec(),
                source_offset_in_nsp0: absolute,
            });
            search_from = absolute + known.len();
        }
    }
    out.sort_by_key(|r: &RecoveredSectionName| r.source_offset_in_nsp0);
    out.dedup_by(
        |a: &mut RecoveredSectionName, b: &mut RecoveredSectionName| {
            a.source_offset_in_nsp0 == b.source_offset_in_nsp0 && a.name == b.name
        },
    );
    out
}

fn recover_resource_table(nsp1_raw: &[u8]) -> Vec<RecoveredResource> {
    let mut out: Vec<RecoveredResource> = Vec::new();
    let manifest_marker: &[u8] = b"<?xml version=\"1.0\"";
    if let Some(off) = find_subsequence(nsp1_raw, manifest_marker) {
        let end: usize = (off + 4096).min(nsp1_raw.len());
        out.push(RecoveredResource {
            recovered_offset_in_nsp1: off,
            bytes: nsp1_raw[off..end].to_vec(),
        });
    }
    let version_info_marker: &[u8] = &[
        b'V', 0x00, b'S', 0x00, b'_', 0x00, b'V', 0x00, b'E', 0x00, b'R', 0x00, b'S', 0x00, b'I',
        0x00, b'O', 0x00, b'N', 0x00, b'_', 0x00, b'I', 0x00, b'N', 0x00, b'F', 0x00, b'O', 0x00,
    ];
    if let Some(off) = find_subsequence(nsp1_raw, version_info_marker) {
        let end: usize = (off + 1024).min(nsp1_raw.len());
        out.push(RecoveredResource {
            recovered_offset_in_nsp1: off,
            bytes: nsp1_raw[off..end].to_vec(),
        });
    }
    out
}

#[inline]
fn read_u16_le(b: &[u8], off: usize) -> Result<u16> {
    let end: usize = off + 2;
    if end > b.len() {
        return Err(Error::Truncated {
            needed: end,
            had: b.len(),
        });
    }
    Ok(u16::from_le_bytes([b[off], b[off + 1]]))
}

#[inline]
fn read_u32_le(b: &[u8], off: usize) -> Result<u32> {
    let end: usize = off + 4;
    if end > b.len() {
        return Err(Error::Truncated {
            needed: end,
            had: b.len(),
        });
    }
    Ok(u32::from_le_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
    ]))
}

#[inline]
fn read_u64_le(b: &[u8], off: usize) -> Result<u64> {
    let end: usize = off + 8;
    if end > b.len() {
        return Err(Error::Truncated {
            needed: end,
            had: b.len(),
        });
    }
    Ok(u64::from_le_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
        b[off + 4],
        b[off + 5],
        b[off + 6],
        b[off + 7],
    ]))
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn build_minimal_nspack_pe() -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; 0x400];
        buf[0] = b'M';
        buf[1] = b'Z';
        let e_lfanew: u32 = 0x80;
        buf[DOS_E_LFANEW_OFFSET..DOS_E_LFANEW_OFFSET + 4].copy_from_slice(&e_lfanew.to_le_bytes());
        let pe_off: usize = e_lfanew as usize;
        buf[pe_off..pe_off + 4].copy_from_slice(PE_MAGIC);
        let coff_off: usize = pe_off + 4;
        buf[coff_off..coff_off + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
        buf[coff_off + 2..coff_off + 4].copy_from_slice(&2u16.to_le_bytes());
        buf[coff_off + 16..coff_off + 18].copy_from_slice(&0xE0u16.to_le_bytes());
        let opt_off: usize = coff_off + 20;
        buf[opt_off..opt_off + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
        buf[opt_off + 16..opt_off + 20].copy_from_slice(&0x101Bu32.to_le_bytes());
        buf[opt_off + 28..opt_off + 32].copy_from_slice(&0x0040_0000_u32.to_le_bytes());
        buf[opt_off + 32..opt_off + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt_off + 36..opt_off + 40].copy_from_slice(&0x200u32.to_le_bytes());
        let sec_table_off: usize = opt_off + 0xE0;
        let nsp0_entry: usize = sec_table_off;
        buf[nsp0_entry..nsp0_entry + 4].copy_from_slice(b"nsp0");
        buf[nsp0_entry + 8..nsp0_entry + 12].copy_from_slice(&0x10000u32.to_le_bytes());
        buf[nsp0_entry + 12..nsp0_entry + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[nsp0_entry + 16..nsp0_entry + 20].copy_from_slice(&0x100u32.to_le_bytes());
        buf[nsp0_entry + 20..nsp0_entry + 24].copy_from_slice(&0x200u32.to_le_bytes());
        buf[nsp0_entry + 36..nsp0_entry + 40].copy_from_slice(&0x6000_0020_u32.to_le_bytes());
        let nsp1_entry: usize = nsp0_entry + SECTION_ENTRY_SIZE;
        buf[nsp1_entry..nsp1_entry + 4].copy_from_slice(b"nsp1");
        buf[nsp1_entry + 8..nsp1_entry + 12].copy_from_slice(&0x5000u32.to_le_bytes());
        buf[nsp1_entry + 12..nsp1_entry + 16].copy_from_slice(&0x11000u32.to_le_bytes());
        buf[nsp1_entry + 16..nsp1_entry + 20].copy_from_slice(&0x100u32.to_le_bytes());
        buf[nsp1_entry + 20..nsp1_entry + 24].copy_from_slice(&0x300u32.to_le_bytes());
        buf[nsp1_entry + 36..nsp1_entry + 40].copy_from_slice(&0xC000_0040_u32.to_le_bytes());
        buf[0x200..0x205].copy_from_slice(b".text");
        buf[0x210..0x215].copy_from_slice(b".rsrc");
        buf
    }

    #[test]
    fn parses_minimal_nspack_layout() {
        let pe: Vec<u8> = build_minimal_nspack_pe();
        let layout: NspackLayout<'_> = parse_nspack_layout(&pe).expect("layout parses");
        assert!(!layout.is_pe32_plus);
        assert_eq!(layout.entry_point_rva, 0x101B);
        assert_eq!(layout.image_base, 0x0040_0000);
        assert_eq!(layout.sections.len(), 2);
        assert_eq!(layout.sections[0].name, b"nsp0");
        assert_eq!(layout.sections[1].name, b"nsp1");
    }

    #[test]
    fn rejects_non_pe_input() {
        let mut not_pe: Vec<u8> = vec![0u8; 0x100];
        not_pe[0] = b'M';
        not_pe[1] = b'Z';
        let e_lfanew: u32 = 0x80;
        not_pe[DOS_E_LFANEW_OFFSET..DOS_E_LFANEW_OFFSET + 4]
            .copy_from_slice(&e_lfanew.to_le_bytes());
        let pe_off: usize = e_lfanew as usize;
        not_pe[pe_off..pe_off + 4].copy_from_slice(b"FOO\x00");
        let err: Error = parse_nspack_layout(&not_pe).expect_err("must reject non-PE");
        assert!(matches!(err, Error::UnknownFormat));
    }

    #[test]
    fn truncated_dos_header_rejected() {
        let tiny: Vec<u8> = vec![0u8; 4];
        let err: Error = parse_nspack_layout(&tiny).expect_err("must reject truncated input");
        assert!(matches!(err, Error::Truncated { .. }));
    }

    #[test]
    fn unpack_minimal_returns_report() {
        let pe: Vec<u8> = build_minimal_nspack_pe();
        let report: NspackUnpackReport = unpack_nspack(&pe).expect("report");
        assert_eq!(report.packed_size, pe.len());
        assert_eq!(report.nsp0_raw_size, 0x100);
        assert_eq!(report.nsp1_raw_size, 0x100);
        assert_eq!(report.stub_entry_point_rva, 0x101B);
        assert!(
            report
                .recovered_section_names
                .iter()
                .any(|r: &RecoveredSectionName| r.name == b".text")
        );
        assert!(
            report
                .recovered_section_names
                .iter()
                .any(|r: &RecoveredSectionName| r.name == b".rsrc")
        );
    }

    #[test]
    fn unpack_missing_nsp1_errs() {
        let mut pe: Vec<u8> = build_minimal_nspack_pe();
        let e_lfanew: usize = u32::from_le_bytes([pe[0x3C], pe[0x3D], pe[0x3E], pe[0x3F]]) as usize;
        let coff_off: usize = e_lfanew + 4;
        pe[coff_off + 2..coff_off + 4].copy_from_slice(&1u16.to_le_bytes());
        let err: Error = unpack_nspack(&pe).expect_err("must err without nsp1");
        assert!(matches!(err, Error::SignatureDb(_)));
    }

    #[test]
    fn derive_lzma_params_parses_typical_header_byte() {
        let params: LzmaParams = derive_lzma_params(0x5D).expect("typical 5D header");
        assert_eq!(params.firstbyte, 2);
        assert_eq!(params.allocsz, 0);
        assert_eq!(params.tre, 3);
        assert_eq!(params.table_words, (0x300_usize << 3) + 0x736);
    }

    #[test]
    fn derive_lzma_params_rejects_invalid_header_byte() {
        let err: Error = derive_lzma_params(0xE5).expect_err("rejects oversize header");
        assert!(matches!(err, Error::SignatureDb(_)));
    }

    #[test]
    fn range_decoder_initializes_with_5_bytes() {
        let src: [u8; 16] = [
            0u8, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let rd: RangeDecoder<'_> = RangeDecoder::new(&src).expect("init");
        assert_eq!(rd.code, 0x00AB_CDEF_u32 << 8 | 0x12);
        assert_eq!(rd.range, 0xFFFF_FFFF);
        assert!(!rd.done);
    }

    #[test]
    fn compare_byte_diff_matches_identical() {
        let a: Vec<u8> = vec![1u8, 2, 3, 4];
        let b: Vec<u8> = vec![1u8, 2, 3, 4];
        let (diff, pct): (usize, f64) = compare_byte_diff(&a, &b);
        assert_eq!(diff, 0);
        assert!((pct - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn compare_byte_diff_counts_mismatches() {
        let a: Vec<u8> = vec![1u8, 2, 3, 4];
        let b: Vec<u8> = vec![1u8, 9, 3, 9];
        let (diff, pct): (usize, f64) = compare_byte_diff(&a, &b);
        assert_eq!(diff, 2);
        assert!((pct - 50.0).abs() < f64::EPSILON);
    }

    fn build_nspack_pe_with_huge_dsize() -> Vec<u8> {
        let mut buf: Vec<u8> = build_minimal_nspack_pe();
        buf.resize(0x600, 0u8);
        let huge: u32 = 0x1000_0000;
        let sec_table_off: usize = 0x80 + 4 + 20 + 0xE0;
        let nsp0_entry: usize = sec_table_off;
        buf[nsp0_entry + 8..nsp0_entry + 12].copy_from_slice(&huge.to_le_bytes());
        let stub_off: usize = 0x400;
        buf[stub_off..stub_off + 13].copy_from_slice(NSPACK_STUB_MAGIC);
        let nbuff_off: usize = 0x3F0;
        let nowinldr: u32 = (stub_off - nbuff_off) as u32;
        let nowinldr_field: i32 = NSPACK_STUB_NOWINLDR_BASE.wrapping_sub(nowinldr) as i32;
        buf[stub_off + NSPACK_STUB_NOWINLDR_OFFSET..stub_off + NSPACK_STUB_NOWINLDR_OFFSET + 4]
            .copy_from_slice(&nowinldr_field.to_le_bytes());
        let start_of_stuff: usize = 0x420;
        let nbuff_delta: u32 = (start_of_stuff - stub_off) as u32;
        buf[nbuff_off..nbuff_off + 4].copy_from_slice(&nbuff_delta.to_le_bytes());
        buf[start_of_stuff] = 0x5D;
        buf[start_of_stuff + NSPACK_HEADER_SSIZE_OFFSET
            ..start_of_stuff + NSPACK_HEADER_SSIZE_OFFSET + 4]
            .copy_from_slice(&0x100u32.to_le_bytes());
        buf[start_of_stuff + NSPACK_HEADER_DSIZE_OFFSET
            ..start_of_stuff + NSPACK_HEADER_DSIZE_OFFSET + 4]
            .copy_from_slice(&huge.to_le_bytes());
        buf
    }

    #[test]
    fn rejects_oversized_dsize() {
        let pe: Vec<u8> = build_nspack_pe_with_huge_dsize();
        let start: std::time::Instant = std::time::Instant::now();
        let r: Result<NspackEmulatedReport> = unpack_nspack_emulated(&pe);
        assert!(
            matches!(r, Err(Error::SignatureDb(ref m)) if m.contains("dsize")),
            "crafted 256 MiB dsize from a 1.5 KiB input must be rejected, got {r:?}"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_millis(500),
            "rejection must be immediate, never allocating a 256 MiB buffer"
        );
    }
}
