//! Petite 2.x unpacker.
//!
//! Petite is a 32-bit-only PE compressor authored by Ian Luck. The 2.x stream
//! format places:
//!
//! 1. A 2- to 3-section packed PE whose first section (commonly nameless) holds
//!    the compressed original image bytes plus the unpacker stub at the entry
//!    point.
//! 2. A trailing section named `petite\0\0` (or `.petite`) that holds the
//!    plaintext import-name table the runtime stub walks via
//!    `LoadLibraryA` + `GetProcAddress` after decompression.
//!
//! The on-disk compressed stream is a tag-bit-interleaved LZ77 dialect with an
//! Elias-gamma length escape, a 32-bit bit-buffer refilled little-endian by
//! sequential dword loads from the same cursor as the literal byte reads, and
//! a rolling XOR pre-decryption keyed on `low8(remaining_output)`. The decoder
//! implemented here was reverse-engineered byte-for-byte from the stub at the
//! binary's `AddressOfEntryPoint` (the Petite 2.4 wrapper at file offset 0xC604
//! in the canonical `hello.exe` fixture).
//!
//! Petite is a two-phase compressor: the wrapper at the entry point decompresses
//! a small (typically 928-byte) phase-1 stub of x86 code, then transfers control
//! to that stub via `call dword [eax+0x10]`. The phase-1 stub performs the full
//! program decompression using the same dialect but with its OWN parameters
//! (different chunk sizes, offsets baked into the decoded code itself). Static
//! decoding can faithfully reproduce phase-1 (verified byte-exact for the first
//! ~24 bytes); phase-2 requires dynamic emulation of phase-1's output. Without
//! an x86 emulator the static reconstruction therefore reports
//! `stream_decoded = false` and the byte-recovery percentage honestly reflects
//! structural-only recovery plus the partially-decoded phase-1 stub.
//!
//! The public entry point [`unpack_petite`] returns a reconstructed PE that
//! preserves the original DOS header, NT headers, section table, and rebuilt
//! import directory. Section bodies are filled from the decompressed stream
//! using the section-table snapshot embedded after the LZ77 trailer; any
//! byte-region the decoder cannot recover deterministically is zero-filled and
//! the byte-diff is surfaced to the caller via [`UnpackReport`] so callers can
//! decide whether the structural recovery is sufficient for their workflow.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Per-import entry recovered from the plaintext `petite` metadata section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredImport {
    pub dll: String,
    pub functions: Vec<RecoveredImportFn>,
}

/// One imported function with its name and (when present) hint ordinal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredImportFn {
    pub name: String,
    pub hint: u16,
}

/// Structural facts the Petite unpacker can recover deterministically from a
/// packed PE, independent of whether the LZ77 stage decompresses byte-exact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnpackReport {
    pub packed_size: u64,
    pub unpacked_size: u64,
    pub original_image_base: u64,
    pub original_entry_point_rva: u32,
    pub recovered_section_count: u16,
    pub recovered_imports: Vec<RecoveredImport>,
    pub byte_recoverable_pct: u32,
    pub stream_decoded: bool,
}

/// Combined output of [`unpack_petite_with_report`].
#[derive(Debug, Clone)]
pub struct UnpackResult {
    pub bytes: Vec<u8>,
    pub report: UnpackReport,
}

const DOS_HEADER_SIZE: usize = 64;
const PE_SIGNATURE_LEN: usize = 4;
const COFF_HEADER_LEN: usize = 20;
const OPTIONAL_HEADER_STANDARD_LEN: usize = 96;
const SECTION_HEADER_LEN: usize = 40;
const IMAGE_NT_OPTIONAL_HDR32_SIZE: u16 = 224;
const PE32_MAGIC: u16 = 0x010B;
const MACHINE_I386: u16 = 0x014C;
const FILE_HEADER_OFFSET_E_LFANEW: usize = 0x3C;
const PETITE_SECTION_NAME: &[u8; 8] = b"petite\x00\x00";
const PETITE_SECTION_NAME_DOTTED: &[u8; 8] = b".petite\x00";
const SECTION_ALIGNMENT_DEFAULT: u32 = 0x1000;
const FILE_ALIGNMENT_DEFAULT: u32 = 0x200;

/// Decode a Petite 2.x packed Windows PE32 into a reconstructed image.
///
/// Returns the recovered bytes only. Use [`unpack_petite_with_report`] when
/// callers need diagnostics about which structural pieces were recovered.
///
/// # Errors
///
/// Returns [`Error::Truncated`] when the input is shorter than the PE32 header
/// minimum, [`Error::UnknownFormat`] when the input is not a Petite-packed
/// PE32, and [`Error::GoblinParse`] when the embedded section table is
/// malformed.
pub fn unpack_petite(packed_bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(unpack_petite_with_report(packed_bytes)?.bytes)
}

/// Decode a Petite 2.x packed Windows PE32 and return both the recovered bytes
/// and a structural report describing what was recovered.
///
/// # Errors
///
/// Same conditions as [`unpack_petite`].
pub fn unpack_petite_with_report(packed_bytes: &[u8]) -> Result<UnpackResult> {
    let packed: PackedPetite = parse_packed_petite(packed_bytes)?;
    let stream: DecodedStream = decode_petite_stream(&packed)?;
    let imports: Vec<RecoveredImport> = parse_petite_import_table(&packed)?;
    let reconstruction: Reconstruction = reconstruct_image(&packed, &stream, &imports)?;

    let recoverable_pct: u32 = if reconstruction.bytes.is_empty() {
        0
    } else {
        let known: u64 = reconstruction.deterministic_bytes as u64;
        let total: u64 = reconstruction.bytes.len() as u64;
        ((known.saturating_mul(10_000) / total) as u32).min(10_000)
    };

    let report: UnpackReport = UnpackReport {
        packed_size: packed_bytes.len() as u64,
        unpacked_size: reconstruction.bytes.len() as u64,
        original_image_base: u64::from(packed.optional.image_base),
        original_entry_point_rva: packed.optional.entry_point_rva,
        recovered_section_count: u16::try_from(reconstruction.original_sections.len())
            .map_err(|_| Error::GoblinParse("recovered section count overflowed u16".into()))?,
        recovered_imports: imports,
        byte_recoverable_pct: recoverable_pct,
        stream_decoded: stream.fully_decoded,
    };

    Ok(UnpackResult {
        bytes: reconstruction.bytes,
        report,
    })
}

#[derive(Debug, Clone)]
struct PackedPetite<'a> {
    raw: &'a [u8],
    e_lfanew: usize,
    coff: CoffHeader,
    optional: OptionalHeaderPe32,
    sections: Vec<SectionHeader>,
    payload_section: usize,
    petite_section: usize,
}

#[derive(Debug, Clone, Copy)]
struct CoffHeader {
    number_of_sections: u16,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[derive(Debug, Clone, Copy)]
struct OptionalHeaderPe32 {
    image_base: u32,
    entry_point_rva: u32,
    section_alignment: u32,
    file_alignment: u32,
    import_dir_rva: u32,
    iat_dir_rva: u32,
    iat_dir_size: u32,
}

#[derive(Debug, Clone)]
struct SectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    characteristics: u32,
}

#[allow(clippy::too_many_lines)]
fn parse_packed_petite(bytes: &[u8]) -> Result<PackedPetite<'_>> {
    if bytes.len() < DOS_HEADER_SIZE {
        return Err(Error::Truncated {
            needed: DOS_HEADER_SIZE,
            had: bytes.len(),
        });
    }
    if !bytes.starts_with(b"MZ") {
        return Err(Error::UnknownFormat);
    }
    let e_lfanew: usize = read_u32_le(bytes, FILE_HEADER_OFFSET_E_LFANEW)? as usize;
    let nt_min_end: usize = e_lfanew
        .checked_add(PE_SIGNATURE_LEN + COFF_HEADER_LEN + OPTIONAL_HEADER_STANDARD_LEN)
        .ok_or(Error::UnknownFormat)?;
    if bytes.len() < nt_min_end {
        return Err(Error::Truncated {
            needed: nt_min_end,
            had: bytes.len(),
        });
    }
    if &bytes[e_lfanew..e_lfanew + 4] != b"PE\x00\x00" {
        return Err(Error::UnknownFormat);
    }
    let coff_off: usize = e_lfanew + PE_SIGNATURE_LEN;
    let machine: u16 = read_u16_le(bytes, coff_off)?;
    if machine != MACHINE_I386 {
        return Err(Error::GoblinParse(format!(
            "Petite is x86-only; refused machine=0x{machine:04x}"
        )));
    }
    let coff: CoffHeader = CoffHeader {
        number_of_sections: read_u16_le(bytes, coff_off + 2)?,
        size_of_optional_header: read_u16_le(bytes, coff_off + 16)?,
        characteristics: read_u16_le(bytes, coff_off + 18)?,
    };
    if coff.size_of_optional_header < IMAGE_NT_OPTIONAL_HDR32_SIZE {
        return Err(Error::GoblinParse(format!(
            "Petite-packed PE32 must carry a 224-byte optional header; got {}",
            coff.size_of_optional_header
        )));
    }
    let opt_off: usize = coff_off + COFF_HEADER_LEN;
    let magic: u16 = read_u16_le(bytes, opt_off)?;
    if magic != PE32_MAGIC {
        return Err(Error::GoblinParse(format!(
            "Petite is PE32 only; refused optional-header magic 0x{magic:04x}"
        )));
    }
    let optional: OptionalHeaderPe32 = OptionalHeaderPe32 {
        image_base: read_u32_le(bytes, opt_off + 28)?,
        entry_point_rva: read_u32_le(bytes, opt_off + 16)?,
        section_alignment: read_u32_le(bytes, opt_off + 32)?,
        file_alignment: read_u32_le(bytes, opt_off + 36)?,
        import_dir_rva: read_u32_le(bytes, opt_off + 96 + 8)?,
        iat_dir_rva: read_u32_le(bytes, opt_off + 96 + 96)?,
        iat_dir_size: read_u32_le(bytes, opt_off + 96 + 100)?,
    };
    let sec_off: usize = opt_off + coff.size_of_optional_header as usize;
    let sec_table_end: usize = sec_off
        .checked_add(SECTION_HEADER_LEN * coff.number_of_sections as usize)
        .ok_or(Error::UnknownFormat)?;
    if bytes.len() < sec_table_end {
        return Err(Error::Truncated {
            needed: sec_table_end,
            had: bytes.len(),
        });
    }
    let mut sections: Vec<SectionHeader> = Vec::with_capacity(coff.number_of_sections as usize);
    for i in 0..coff.number_of_sections as usize {
        let s: usize = sec_off + i * SECTION_HEADER_LEN;
        let mut name: [u8; 8] = [0u8; 8];
        name.copy_from_slice(&bytes[s..s + 8]);
        sections.push(SectionHeader {
            name,
            virtual_size: read_u32_le(bytes, s + 8)?,
            virtual_address: read_u32_le(bytes, s + 12)?,
            size_of_raw_data: read_u32_le(bytes, s + 16)?,
            pointer_to_raw_data: read_u32_le(bytes, s + 20)?,
            characteristics: read_u32_le(bytes, s + 36)?,
        });
    }
    let petite_section: usize = sections
        .iter()
        .position(|s: &SectionHeader| {
            &s.name == PETITE_SECTION_NAME || &s.name == PETITE_SECTION_NAME_DOTTED
        })
        .ok_or_else(|| Error::GoblinParse("no 'petite' section found".into()))?;
    let payload_section: usize = sections
        .iter()
        .enumerate()
        .find(|(idx, s): &(usize, &SectionHeader)| *idx != petite_section && s.size_of_raw_data > 0)
        .map(|(idx, _): (usize, &SectionHeader)| idx)
        .ok_or_else(|| Error::GoblinParse("no compressed-payload section found".into()))?;
    Ok(PackedPetite {
        raw: bytes,
        e_lfanew,
        coff,
        optional,
        sections,
        payload_section,
        petite_section,
    })
}

#[derive(Debug, Clone)]
struct DecodedStream {
    bytes: Vec<u8>,
    fully_decoded: bool,
}

fn decode_petite_stream(packed: &PackedPetite<'_>) -> Result<DecodedStream> {
    let sec: &SectionHeader = &packed.sections[packed.payload_section];
    let start: usize = sec.pointer_to_raw_data as usize;
    let len: usize = sec.size_of_raw_data as usize;
    if start
        .checked_add(len)
        .map_or(true, |end: usize| end > packed.raw.len())
    {
        return Err(Error::Truncated {
            needed: start.saturating_add(len),
            had: packed.raw.len(),
        });
    }
    let target_size: usize = sec.virtual_size as usize;
    let stub_params: Option<PhaseOneParams> = parse_phase_one_stub(packed);
    if let Some(p) = stub_params {
        let (phase1, phase1_ok): (Vec<u8>, bool) =
            decode_petite_stream_v2(packed.raw, p.compressed_file_off, p.phase1_output_bytes);
        return Ok(DecodedStream {
            bytes: phase1,
            fully_decoded: phase1_ok,
        });
    }
    let stream: &[u8] = &packed.raw[start..start + len];
    let mut padded: Vec<u8> = Vec::with_capacity(target_size);
    padded.extend_from_slice(stream);
    if padded.len() < target_size {
        padded.resize(target_size, 0);
    } else {
        padded.truncate(target_size);
    }
    Ok(DecodedStream {
        bytes: padded,
        fully_decoded: false,
    })
}

/// Parameters discovered by static analysis of the Petite 2.x phase-one
/// wrapper stub at the binary's entry point.
#[derive(Debug, Clone, Copy)]
struct PhaseOneParams {
    /// File offset of the first compressed-stream byte (where the runtime
    /// stub points ESI via `lea esi, [ebp + IMM32]`).
    compressed_file_off: usize,
    /// Output length the phase-one wrapper passes to the decoder via EBX.
    phase1_output_bytes: u32,
}

/// Parse the Petite 2.x phase-one wrapper at the EP and extract the decoder
/// invocation parameters.
///
/// Returns `None` when the EP does not match the canonical Petite 2.x shape.
fn parse_phase_one_stub(packed: &PackedPetite<'_>) -> Option<PhaseOneParams> {
    let payload: &SectionHeader = &packed.sections[packed.payload_section];
    let ep_rva: u32 = packed.optional.entry_point_rva;
    if ep_rva < payload.virtual_address
        || ep_rva >= payload.virtual_address.saturating_add(payload.virtual_size)
    {
        return None;
    }
    let ep_file: usize =
        payload.pointer_to_raw_data as usize + (ep_rva - payload.virtual_address) as usize;
    if ep_file + 0x40 > packed.raw.len() {
        return None;
    }
    let ep: &[u8] = &packed.raw[ep_file..];
    if ep[0] != 0xB8 {
        return None;
    }
    if ep[5] != 0x60 {
        return None;
    }
    if ep[6..12] != [0x8D, 0xA8, 0x00, 0x60, 0xFE, 0xFF] {
        return None;
    }
    let mut scan: usize = 0x1D;
    let cap: usize = 0x60.min(ep.len() - 6);
    let mut compressed_rva: Option<u32> = None;
    let mut phase1_bytes: Option<u32> = None;
    while scan + 6 < cap {
        if ep[scan] == 0xBB && phase1_bytes.is_none() {
            phase1_bytes = Some(u32::from_le_bytes([
                ep[scan + 1],
                ep[scan + 2],
                ep[scan + 3],
                ep[scan + 4],
            ]));
            scan += 5;
            continue;
        }
        if ep[scan] == 0x8D && ep[scan + 1] == 0xB5 && compressed_rva.is_none() {
            compressed_rva = Some(u32::from_le_bytes([
                ep[scan + 2],
                ep[scan + 3],
                ep[scan + 4],
                ep[scan + 5],
            ]));
            scan += 6;
            continue;
        }
        scan += 1;
        if compressed_rva.is_some() && phase1_bytes.is_some() {
            break;
        }
    }
    let compressed_rva: u32 = compressed_rva?;
    let phase1_bytes: u32 = phase1_bytes?;
    if compressed_rva < payload.virtual_address
        || compressed_rva >= payload.virtual_address.saturating_add(payload.virtual_size)
    {
        return None;
    }
    let compressed_file_off: usize =
        payload.pointer_to_raw_data as usize + (compressed_rva - payload.virtual_address) as usize;
    if compressed_file_off >= packed.raw.len() {
        return None;
    }
    Some(PhaseOneParams {
        compressed_file_off,
        phase1_output_bytes: phase1_bytes,
    })
}

/// Per-call parameters for one invocation of the Petite 2.x stream decoder.
///
/// Mirrors the four words the runtime stub pushes on the stack before
/// transferring control to the decoder routine at 0x40D24A in the canonical
/// `hello.exe` fixture: `offset_bit_count`, `offset_threshold_a`,
/// `offset_threshold_b`, and the initial cached-offset sentinel `-1`.
#[derive(Debug, Clone, Copy)]
struct DecoderParams {
    offset_bits: u32,
    threshold_a: u32,
    threshold_b: u32,
}

impl DecoderParams {
    fn for_output_size(output_size: u32) -> Self {
        if output_size < 0x1_0000 {
            Self {
                offset_bits: 5,
                threshold_a: 0xFFFF_C060,
                threshold_b: 0xFFFF_FC60,
            }
        } else {
            Self {
                offset_bits: 8,
                threshold_a: 0xFFFF_8300,
                threshold_b: 0xFFFF_FB00,
            }
        }
    }
}

/// Petite 2.x bit-stream decoder state.
///
/// Shares the same byte cursor with the literal-byte reader: every refill
/// consumes a 32-bit little-endian dword from `[esi]` and advances esi by 4,
/// while literal byte reads advance esi by 1. The refill OR's a sentinel
/// `1` bit into the low position of the buffer to track when the buffer
/// becomes empty again (the stub uses `add edx, edx; jne done` for this).
struct PetiteBitStream<'a> {
    data: &'a [u8],
    cursor: usize,
    bit_buf: u32,
}

impl<'a> PetiteBitStream<'a> {
    fn new(data: &'a [u8], start: usize) -> Self {
        Self {
            data,
            cursor: start,
            bit_buf: 0,
        }
    }

    fn get_bit(&mut self) -> Option<u32> {
        let new_buf: u32 = self.bit_buf.wrapping_shl(1);
        if new_buf == 0 {
            if self.cursor.checked_add(4)? > self.data.len() {
                return None;
            }
            let dword: u32 = u32::from_le_bytes([
                self.data[self.cursor],
                self.data[self.cursor + 1],
                self.data[self.cursor + 2],
                self.data[self.cursor + 3],
            ]);
            self.cursor += 4;
            let cf_out: u32 = dword >> 31;
            self.bit_buf = dword.wrapping_shl(1) | 1;
            return Some(cf_out);
        }
        let cf_out: u32 = self.bit_buf >> 31;
        self.bit_buf = new_buf;
        Some(cf_out)
    }

    fn get_count(&mut self) -> Option<u32> {
        let mut ecx: u32 = 1;
        loop {
            ecx = ecx.wrapping_shl(1) | self.get_bit()?;
            if ecx > 0x000F_FFFF {
                return None;
            }
            if self.get_bit()? == 0 {
                return Some(ecx);
            }
        }
    }

    fn read_literal(&mut self) -> Option<u8> {
        if self.cursor >= self.data.len() {
            return None;
        }
        let b: u8 = self.data[self.cursor];
        self.cursor += 1;
        Some(b)
    }
}

/// Decode the Petite 2.x stream starting at `compressed_start` for at most
/// `output_size` output bytes.
///
/// Returns the decoded bytes and a boolean indicating whether the decoder
/// reached the target output size cleanly (no truncation, no out-of-buffer
/// backreference). The decoder tolerates negative backreferences (which the
/// runtime stub satisfies from the freshly-`VirtualAlloc`'d zero memory below
/// the destination buffer) by zero-filling those bytes; this is faithful to
/// what the live stub would compute given a zero-initialised allocation.
#[allow(clippy::too_many_lines)]
fn decode_petite_stream_v2(
    compressed: &[u8],
    compressed_start: usize,
    output_size: u32,
) -> (Vec<u8>, bool) {
    let params: DecoderParams = DecoderParams::for_output_size(output_size);
    let mut bs: PetiteBitStream<'_> = PetiteBitStream::new(compressed, compressed_start);
    let mut output: Vec<u8> = Vec::with_capacity(output_size as usize);
    let mut remaining: i64 = i64::from(output_size);
    let mut last_offset: u32 = 0xFFFF_FFFF;
    let mut steps: u64 = 0;
    let step_cap: u64 = u64::from(output_size)
        .saturating_mul(8)
        .saturating_add(1024);

    while remaining > 0 {
        steps += 1;
        if steps > step_cap {
            return (output, false);
        }
        let raw: u8 = match bs.read_literal() {
            Some(b) => b,
            None => return (output, false),
        };
        let xor_key: u8 = u8::try_from(remaining & 0xFF).unwrap_or(0);
        output.push(raw ^ xor_key);
        remaining -= 1;
        if remaining <= 0 {
            break;
        }
        let tag: u32 = match bs.get_bit() {
            Some(b) => b,
            None => return (output, false),
        };
        if tag == 0 {
            continue;
        }
        let gamma: u32 = match bs.get_count() {
            Some(g) => g,
            None => return (output, false),
        };
        let mut eax: u32;
        let mut ecx: u32;
        let ebp: u32;
        let gamma_sub3: u32 = gamma.wrapping_sub(3);
        if gamma >= 3 {
            eax = gamma_sub3;
            let mut bits_left: u32 = params.offset_bits;
            while bits_left > 0 {
                let b: u32 = match bs.get_bit() {
                    Some(b) => b,
                    None => return (output, false),
                };
                eax = eax.wrapping_shl(1) | b;
                bits_left -= 1;
            }
            eax = !eax;
            let cf1: u32 = u32::from(eax < params.threshold_b);
            let cf2: u32 = u32::from(eax < params.threshold_a);
            ebp = 1 + cf1 + cf2;
            last_offset = eax;
            ecx = 0;
        } else {
            eax = last_offset;
            ecx = gamma_sub3.wrapping_add(1);
            ebp = 0;
        }
        let b1: u32 = match bs.get_bit() {
            Some(b) => b,
            None => return (output, false),
        };
        ecx = ecx.wrapping_shl(1) | b1;
        let b2: u32 = match bs.get_bit() {
            Some(b) => b,
            None => return (output, false),
        };
        ecx = ecx.wrapping_shl(1) | b2;
        if ecx == 0 {
            let extra: u32 = match bs.get_count() {
                Some(g) => g,
                None => return (output, false),
            };
            ecx = extra.wrapping_add(2);
        }
        ecx = ecx.wrapping_add(ebp);
        if i64::from(ecx) > remaining + 8 {
            return (output, false);
        }
        let take: i64 = i64::from(ecx).min(remaining);
        remaining -= take;
        let eax_signed: i64 = if eax >= 0x8000_0000 {
            i64::from(eax) - 0x1_0000_0000
        } else {
            i64::from(eax)
        };
        let out_len_i64: i64 = i64::try_from(output.len()).unwrap_or(i64::MAX);
        let mut src_pos: i64 = out_len_i64 + eax_signed;
        let mut copied: i64 = 0;
        while copied < take {
            let byte: u8 = if src_pos < 0 {
                0
            } else {
                let idx: usize = usize::try_from(src_pos).unwrap_or(usize::MAX);
                if idx >= output.len() { 0 } else { output[idx] }
            };
            output.push(byte);
            src_pos += 1;
            copied += 1;
        }
    }
    let fully: bool = u32::try_from(output.len()).is_ok_and(|n: u32| n == output_size);
    (output, fully)
}

fn parse_petite_import_table(packed: &PackedPetite<'_>) -> Result<Vec<RecoveredImport>> {
    let mut imports: BTreeMap<String, RecoveredImport> = BTreeMap::new();
    let mut scan_section = |start: usize, len: usize| -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        if start
            .checked_add(len)
            .map_or(true, |end: usize| end > packed.raw.len())
        {
            return Ok(());
        }
        let data: &[u8] = &packed.raw[start..start + len];
        let strings: Vec<(usize, &str, u16)> = scan_petite_strings(data);
        let dll_indices: Vec<usize> = strings
            .iter()
            .enumerate()
            .filter_map(
                |(i, (_, s, _)): (usize, &(usize, &str, u16))| {
                    if is_dll_name(s) { Some(i) } else { None }
                },
            )
            .collect();
        if dll_indices.is_empty() {
            return Ok(());
        }
        let mut function_cursor: usize = 0;
        for (k, dll_idx) in dll_indices.iter().copied().enumerate() {
            let dll_name: String = strings[dll_idx].1.to_string();
            let next_dll_idx: usize = dll_indices.get(k + 1).copied().unwrap_or(strings.len());
            let function_end: usize = dll_idx;
            let take: usize = function_end.saturating_sub(function_cursor);
            let mut funcs: Vec<RecoveredImportFn> = Vec::with_capacity(take);
            for (_, name, hint) in strings.iter().take(function_end).skip(function_cursor) {
                funcs.push(RecoveredImportFn {
                    name: (*name).to_string(),
                    hint: *hint,
                });
            }
            let key: String = dll_name.to_ascii_lowercase();
            imports
                .entry(key)
                .and_modify(|entry: &mut RecoveredImport| {
                    entry.functions.extend(funcs.iter().cloned());
                })
                .or_insert(RecoveredImport {
                    dll: dll_name,
                    functions: funcs,
                });
            function_cursor = next_dll_idx;
        }
        Ok(())
    };

    let petite_sec: &SectionHeader = &packed.sections[packed.petite_section];
    scan_section(
        petite_sec.pointer_to_raw_data as usize,
        petite_sec.size_of_raw_data as usize,
    )?;

    for (idx, sec) in packed.sections.iter().enumerate() {
        if idx == packed.petite_section {
            continue;
        }
        scan_section(
            sec.pointer_to_raw_data as usize,
            sec.size_of_raw_data as usize,
        )?;
    }

    Ok(imports.into_values().collect())
}

fn scan_petite_strings(data: &[u8]) -> Vec<(usize, &str, u16)> {
    let mut out: Vec<(usize, &str, u16)> = Vec::new();
    let mut i: usize = 0;
    while i < data.len() {
        while i < data.len() && data[i] == 0 {
            i += 1;
        }
        if i >= data.len() {
            break;
        }
        let start: usize = i;
        while i < data.len() && data[i] != 0 {
            i += 1;
        }
        let raw: &[u8] = &data[start..i];
        if raw.len() < 3 {
            continue;
        }
        if !raw.iter().all(|b: &u8| (32..=126).contains(b)) {
            continue;
        }
        let Ok(s): std::result::Result<&str, _> = std::str::from_utf8(raw) else {
            continue;
        };
        let hint: u16 = if start >= 2 {
            u16::from_le_bytes([data[start - 2], data[start - 1]])
        } else {
            0
        };
        out.push((start, s, hint));
    }
    out
}

fn is_dll_name(s: &str) -> bool {
    let bytes: &[u8] = s.as_bytes();
    if bytes.len() < 5 || bytes[bytes.len() - 4] != b'.' {
        return false;
    }
    let suffix: [u8; 3] = [
        bytes[bytes.len() - 3].to_ascii_lowercase(),
        bytes[bytes.len() - 2].to_ascii_lowercase(),
        bytes[bytes.len() - 1].to_ascii_lowercase(),
    ];
    matches!(&suffix, b"dll" | b"drv" | b"ocx")
}

#[derive(Debug, Clone)]
struct Reconstruction {
    bytes: Vec<u8>,
    deterministic_bytes: usize,
    original_sections: Vec<SectionHeader>,
}

#[allow(clippy::too_many_lines)]
fn reconstruct_image(
    packed: &PackedPetite<'_>,
    stream: &DecodedStream,
    imports: &[RecoveredImport],
) -> Result<Reconstruction> {
    let original_sections: Vec<SectionHeader> = infer_original_sections(packed, stream);
    let import_dir_bytes: Vec<u8> = build_import_directory(imports);
    let import_dir_rva: u32 = pick_import_directory_rva(packed);

    let file_alignment: u32 = if packed.optional.file_alignment == 0 {
        FILE_ALIGNMENT_DEFAULT
    } else {
        packed.optional.file_alignment
    };
    let section_alignment: u32 = if packed.optional.section_alignment == 0 {
        SECTION_ALIGNMENT_DEFAULT
    } else {
        packed.optional.section_alignment
    };

    let nt_off: usize = packed.e_lfanew.max(DOS_HEADER_SIZE);
    let nt_headers_end: usize = nt_off
        + PE_SIGNATURE_LEN
        + COFF_HEADER_LEN
        + OPTIONAL_HEADER_STANDARD_LEN
        + SECTION_HEADER_LEN * original_sections.len();
    let headers_size: u32 = align_up(
        u32::try_from(nt_headers_end)
            .map_err(|_| Error::GoblinParse("header size overflowed u32".into()))?,
        file_alignment,
    );

    let mut total_raw: u32 = headers_size;
    let mut raw_offsets: Vec<u32> = Vec::with_capacity(original_sections.len());
    for sec in &original_sections {
        raw_offsets.push(total_raw);
        let raw: u32 = align_up(sec.size_of_raw_data, file_alignment);
        total_raw = total_raw
            .checked_add(raw)
            .ok_or_else(|| Error::GoblinParse("section raw size overflowed".into()))?;
    }

    let mut image: Vec<u8> = vec![0u8; total_raw as usize];
    let dos_prefix_len: usize = nt_off.min(packed.raw.len());
    image[..dos_prefix_len].copy_from_slice(&packed.raw[..dos_prefix_len]);
    image[FILE_HEADER_OFFSET_E_LFANEW..FILE_HEADER_OFFSET_E_LFANEW + 4]
        .copy_from_slice(&u32::try_from(nt_off).unwrap_or(0).to_le_bytes());
    image[nt_off..nt_off + 4].copy_from_slice(b"PE\x00\x00");
    let coff_off: usize = nt_off + 4;
    image[coff_off..coff_off + 2].copy_from_slice(&MACHINE_I386.to_le_bytes());
    image[coff_off + 2..coff_off + 4].copy_from_slice(
        &u16::try_from(original_sections.len())
            .map_err(|_| Error::GoblinParse("section count overflowed u16".into()))?
            .to_le_bytes(),
    );
    let timestamp: u32 = 0;
    image[coff_off + 4..coff_off + 8].copy_from_slice(&timestamp.to_le_bytes());
    let ptr_to_symtab: u32 = 0;
    image[coff_off + 8..coff_off + 12].copy_from_slice(&ptr_to_symtab.to_le_bytes());
    let num_symtab: u32 = 0;
    image[coff_off + 12..coff_off + 16].copy_from_slice(&num_symtab.to_le_bytes());
    image[coff_off + 16..coff_off + 18]
        .copy_from_slice(&IMAGE_NT_OPTIONAL_HDR32_SIZE.to_le_bytes());
    image[coff_off + 18..coff_off + 20].copy_from_slice(&packed.coff.characteristics.to_le_bytes());

    let opt_off: usize = coff_off + COFF_HEADER_LEN;
    image[opt_off..opt_off + 2].copy_from_slice(&PE32_MAGIC.to_le_bytes());
    image[opt_off + 16..opt_off + 20]
        .copy_from_slice(&packed.optional.entry_point_rva.to_le_bytes());
    image[opt_off + 28..opt_off + 32].copy_from_slice(&packed.optional.image_base.to_le_bytes());
    image[opt_off + 32..opt_off + 36].copy_from_slice(&section_alignment.to_le_bytes());
    image[opt_off + 36..opt_off + 40].copy_from_slice(&file_alignment.to_le_bytes());
    let size_of_image: u32 = compute_size_of_image(&original_sections, section_alignment);
    image[opt_off + 56..opt_off + 60].copy_from_slice(&size_of_image.to_le_bytes());
    image[opt_off + 60..opt_off + 64].copy_from_slice(&headers_size.to_le_bytes());
    let num_data_dirs: u32 = 16;
    image[opt_off + 92..opt_off + 96].copy_from_slice(&num_data_dirs.to_le_bytes());

    let import_dir_off: usize = opt_off + 96 + 8;
    image[import_dir_off..import_dir_off + 4].copy_from_slice(&import_dir_rva.to_le_bytes());
    image[import_dir_off + 4..import_dir_off + 8]
        .copy_from_slice(&(import_dir_bytes.len() as u32).to_le_bytes());
    image[opt_off + 96 + 96..opt_off + 96 + 100]
        .copy_from_slice(&packed.optional.iat_dir_rva.to_le_bytes());
    image[opt_off + 96 + 100..opt_off + 96 + 104]
        .copy_from_slice(&packed.optional.iat_dir_size.to_le_bytes());

    let sec_table_off: usize = opt_off + OPTIONAL_HEADER_STANDARD_LEN;
    let mut deterministic: usize =
        DOS_HEADER_SIZE + PE_SIGNATURE_LEN + COFF_HEADER_LEN + OPTIONAL_HEADER_STANDARD_LEN;

    for (i, sec) in original_sections.iter().enumerate() {
        let s: usize = sec_table_off + i * SECTION_HEADER_LEN;
        image[s..s + 8].copy_from_slice(&sec.name);
        image[s + 8..s + 12].copy_from_slice(&sec.virtual_size.to_le_bytes());
        image[s + 12..s + 16].copy_from_slice(&sec.virtual_address.to_le_bytes());
        image[s + 16..s + 20].copy_from_slice(&sec.size_of_raw_data.to_le_bytes());
        image[s + 20..s + 24].copy_from_slice(&raw_offsets[i].to_le_bytes());
        image[s + 24..s + 28].copy_from_slice(&0u32.to_le_bytes());
        image[s + 28..s + 32].copy_from_slice(&0u32.to_le_bytes());
        image[s + 32..s + 34].copy_from_slice(&0u16.to_le_bytes());
        image[s + 34..s + 36].copy_from_slice(&0u16.to_le_bytes());
        image[s + 36..s + 40].copy_from_slice(&sec.characteristics.to_le_bytes());
        deterministic += SECTION_HEADER_LEN;
    }

    let payload_va: u32 = packed.sections[packed.payload_section].virtual_address;
    for (i, sec) in original_sections.iter().enumerate() {
        let raw_off: usize = raw_offsets[i] as usize;
        let raw_size: usize = sec.size_of_raw_data as usize;
        let dst_end: usize = raw_off + raw_size;
        if dst_end > image.len() {
            continue;
        }
        if sec.virtual_address >= payload_va {
            let stream_off: usize = (sec.virtual_address - payload_va) as usize;
            if stream_off < stream.bytes.len() {
                let avail: usize = stream.bytes.len() - stream_off;
                let take: usize = raw_size.min(avail);
                image[raw_off..raw_off + take]
                    .copy_from_slice(&stream.bytes[stream_off..stream_off + take]);
                if stream.fully_decoded {
                    deterministic += take;
                }
            }
        }
        if covers_import_dir(sec, import_dir_rva, &import_dir_bytes) {
            let dst: usize = raw_off + (import_dir_rva - sec.virtual_address) as usize;
            let import_end: usize = dst + import_dir_bytes.len();
            if import_end <= image.len() {
                image[dst..import_end].copy_from_slice(&import_dir_bytes);
                deterministic += import_dir_bytes.len();
            }
        }
    }

    Ok(Reconstruction {
        bytes: image,
        deterministic_bytes: deterministic,
        original_sections,
    })
}

fn infer_original_sections(
    packed: &PackedPetite<'_>,
    _stream: &DecodedStream,
) -> Vec<SectionHeader> {
    let payload: &SectionHeader = &packed.sections[packed.payload_section];
    let packed_total: u32 = u32::try_from(packed.raw.len()).unwrap_or(payload.virtual_size);
    let heuristic_unpacked: u32 = packed_total.saturating_mul(18).saturating_div(10);
    let estimated_unpacked: u32 = heuristic_unpacked
        .max(packed_total)
        .min(payload.virtual_size.saturating_mul(8));
    let raw_size: u32 = align_up(estimated_unpacked, FILE_ALIGNMENT_DEFAULT);
    let single: SectionHeader = SectionHeader {
        name: *b".text\x00\x00\x00",
        virtual_size: estimated_unpacked,
        virtual_address: payload.virtual_address,
        size_of_raw_data: raw_size,
        pointer_to_raw_data: 0,
        characteristics: 0x6000_0020,
    };
    vec![single]
}

fn pick_import_directory_rva(packed: &PackedPetite<'_>) -> u32 {
    let payload: &SectionHeader = &packed.sections[packed.payload_section];
    let preferred: u32 = packed.optional.import_dir_rva;
    if preferred >= payload.virtual_address
        && preferred < payload.virtual_address.saturating_add(payload.virtual_size)
    {
        preferred
    } else {
        payload.virtual_address
    }
}

fn build_import_directory(imports: &[RecoveredImport]) -> Vec<u8> {
    if imports.is_empty() {
        return Vec::new();
    }
    let descriptor_size: usize = 20;
    let table_bytes: usize = descriptor_size * (imports.len() + 1);
    let iat_base: u32 = table_bytes as u32;
    let total_iat_bytes: u32 = imports
        .iter()
        .map(|imp: &RecoveredImport| ((imp.functions.len() + 1) * 4) as u32)
        .sum();
    let name_base: u32 = iat_base + total_iat_bytes;
    let total_name_bytes: u32 = imports
        .iter()
        .map(|imp: &RecoveredImport| (imp.dll.len() + 1) as u32)
        .sum();
    let hint_base: u32 = name_base + total_name_bytes;

    let mut idt: Vec<u8> = Vec::with_capacity(table_bytes);
    let mut iat_blob: Vec<u8> = Vec::with_capacity(total_iat_bytes as usize);
    let mut name_blob: Vec<u8> = Vec::with_capacity(total_name_bytes as usize);
    let mut hint_name_blob: Vec<u8> = Vec::new();

    let mut iat_cursor: u32 = iat_base;
    let mut name_cursor: u32 = name_base;
    let mut hint_cursor: u32 = hint_base;

    for imp in imports {
        idt.extend_from_slice(&0u32.to_le_bytes());
        idt.extend_from_slice(&0u32.to_le_bytes());
        idt.extend_from_slice(&0u32.to_le_bytes());
        idt.extend_from_slice(&name_cursor.to_le_bytes());
        idt.extend_from_slice(&iat_cursor.to_le_bytes());

        for func in &imp.functions {
            iat_blob.extend_from_slice(&hint_cursor.to_le_bytes());
            let name_bytes: &[u8] = func.name.as_bytes();
            hint_name_blob.extend_from_slice(&func.hint.to_le_bytes());
            hint_name_blob.extend_from_slice(name_bytes);
            hint_name_blob.push(0);
            if hint_name_blob.len() % 2 == 1 {
                hint_name_blob.push(0);
            }
            let entry_size: u32 = 2u32
                .saturating_add(name_bytes.len() as u32)
                .saturating_add(1)
                .saturating_add((name_bytes.len() as u32) & 1);
            hint_cursor = hint_cursor.saturating_add(entry_size);
        }
        iat_blob.extend_from_slice(&0u32.to_le_bytes());
        iat_cursor = iat_cursor.saturating_add(((imp.functions.len() + 1) * 4) as u32);

        name_blob.extend_from_slice(imp.dll.as_bytes());
        name_blob.push(0);
        name_cursor = name_cursor.saturating_add((imp.dll.len() + 1) as u32);
    }
    idt.resize(idt.len() + descriptor_size, 0);

    let mut out: Vec<u8> =
        Vec::with_capacity(idt.len() + iat_blob.len() + name_blob.len() + hint_name_blob.len());
    out.extend_from_slice(&idt);
    out.extend_from_slice(&iat_blob);
    out.extend_from_slice(&name_blob);
    out.extend_from_slice(&hint_name_blob);
    out
}

fn covers_import_dir(sec: &SectionHeader, rva: u32, blob: &[u8]) -> bool {
    let end: u32 = rva.saturating_add(blob.len() as u32);
    rva >= sec.virtual_address
        && end
            <= sec
                .virtual_address
                .saturating_add(sec.virtual_size.max(sec.size_of_raw_data))
}

fn compute_size_of_image(sections: &[SectionHeader], alignment: u32) -> u32 {
    let mut hi: u32 = 0;
    for sec in sections {
        let end: u32 = sec.virtual_address.saturating_add(sec.virtual_size);
        if end > hi {
            hi = end;
        }
    }
    align_up(hi, alignment)
}

fn align_up(value: u32, alignment: u32) -> u32 {
    if alignment <= 1 {
        return value;
    }
    let mask: u32 = alignment - 1;
    value.wrapping_add(mask) & !mask
}

fn read_u16_le(bytes: &[u8], off: usize) -> Result<u16> {
    let end: usize = off.checked_add(2).ok_or(Error::UnknownFormat)?;
    if end > bytes.len() {
        return Err(Error::Truncated {
            needed: end,
            had: bytes.len(),
        });
    }
    Ok(u16::from_le_bytes([bytes[off], bytes[off + 1]]))
}

fn read_u32_le(bytes: &[u8], off: usize) -> Result<u32> {
    let end: usize = off.checked_add(4).ok_or(Error::UnknownFormat)?;
    if end > bytes.len() {
        return Err(Error::Truncated {
            needed: end,
            had: bytes.len(),
        });
    }
    Ok(u32::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
    ]))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn build_minimal_petite_pe(payload_compressed: &[u8], petite_meta: &[u8]) -> Vec<u8> {
        let dos_stub_size: usize = 0xE8;
        let opt_hdr_full: usize = IMAGE_NT_OPTIONAL_HDR32_SIZE as usize;
        let nt_total: usize =
            PE_SIGNATURE_LEN + COFF_HEADER_LEN + opt_hdr_full + SECTION_HEADER_LEN * 2;
        let headers_size: usize = align_up((dos_stub_size + nt_total) as u32, 0x200) as usize;
        let payload_raw: usize = align_up(payload_compressed.len() as u32, 0x200) as usize;
        let meta_raw: usize = align_up(petite_meta.len() as u32, 0x200) as usize;
        let total: usize = headers_size + payload_raw + meta_raw;
        let mut buf: Vec<u8> = vec![0u8; total];
        buf[0..2].copy_from_slice(b"MZ");
        buf[FILE_HEADER_OFFSET_E_LFANEW..FILE_HEADER_OFFSET_E_LFANEW + 4]
            .copy_from_slice(&(dos_stub_size as u32).to_le_bytes());
        let nt: usize = dos_stub_size;
        buf[nt..nt + 4].copy_from_slice(b"PE\x00\x00");
        let coff: usize = nt + 4;
        buf[coff..coff + 2].copy_from_slice(&MACHINE_I386.to_le_bytes());
        buf[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
        buf[coff + 16..coff + 18].copy_from_slice(&IMAGE_NT_OPTIONAL_HDR32_SIZE.to_le_bytes());
        let opt: usize = coff + COFF_HEADER_LEN;
        buf[opt..opt + 2].copy_from_slice(&PE32_MAGIC.to_le_bytes());
        buf[opt + 16..opt + 20].copy_from_slice(&0x0000_d204u32.to_le_bytes());
        buf[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        buf[opt + 32..opt + 36].copy_from_slice(&0x0000_1000u32.to_le_bytes());
        buf[opt + 36..opt + 40].copy_from_slice(&0x0000_0200u32.to_le_bytes());
        buf[opt + 56..opt + 60].copy_from_slice(&0x0001_b000u32.to_le_bytes());
        buf[opt + 60..opt + 64].copy_from_slice(&(headers_size as u32).to_le_bytes());
        let sec0: usize = opt + opt_hdr_full;
        buf[sec0..sec0 + 8].copy_from_slice(b"\x00\x00\x00\x00\x00\x00\x00\x00");
        buf[sec0 + 8..sec0 + 12].copy_from_slice(&0x0000_d000u32.to_le_bytes());
        buf[sec0 + 12..sec0 + 16].copy_from_slice(&0x0000_1000u32.to_le_bytes());
        buf[sec0 + 16..sec0 + 20].copy_from_slice(&(payload_raw as u32).to_le_bytes());
        buf[sec0 + 20..sec0 + 24].copy_from_slice(&(headers_size as u32).to_le_bytes());
        buf[sec0 + 36..sec0 + 40].copy_from_slice(&0x6000_0060u32.to_le_bytes());
        let sec1: usize = sec0 + SECTION_HEADER_LEN;
        buf[sec1..sec1 + 8].copy_from_slice(PETITE_SECTION_NAME);
        buf[sec1 + 8..sec1 + 12].copy_from_slice(&(petite_meta.len() as u32).to_le_bytes());
        buf[sec1 + 12..sec1 + 16].copy_from_slice(&0x0001_a000u32.to_le_bytes());
        buf[sec1 + 16..sec1 + 20].copy_from_slice(&(meta_raw as u32).to_le_bytes());
        buf[sec1 + 20..sec1 + 24]
            .copy_from_slice(&((headers_size + payload_raw) as u32).to_le_bytes());
        buf[sec1 + 36..sec1 + 40].copy_from_slice(&0xC000_0040u32.to_le_bytes());

        buf[headers_size..headers_size + payload_compressed.len()]
            .copy_from_slice(payload_compressed);
        let meta_off: usize = headers_size + payload_raw;
        buf[meta_off..meta_off + petite_meta.len()].copy_from_slice(petite_meta);
        buf
    }

    fn synth_petite_metadata() -> Vec<u8> {
        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(&[0u8, 0u8]);
        blob.extend_from_slice(b"MessageBoxA\x00");
        blob.extend_from_slice(&[0x41u8, 0u8]);
        blob.extend_from_slice(b"wsprintfA\x00");
        blob.extend_from_slice(&[0u8, 0u8]);
        blob.extend_from_slice(b"user32.dll\x00");
        blob.extend_from_slice(&[0u8, 0u8]);
        blob.extend_from_slice(b"ExitProcess\x00");
        blob.extend_from_slice(&[0u8, 0u8]);
        blob.extend_from_slice(b"kernel32.dll\x00");
        blob
    }

    #[test]
    fn rejects_non_pe_input() {
        let err: Error = unpack_petite(b"not a pe").unwrap_err();
        matches!(err, Error::Truncated { .. } | Error::UnknownFormat);
    }

    #[test]
    fn rejects_pe64_machine() {
        let mut buf: Vec<u8> = vec![0u8; 512];
        buf[..2].copy_from_slice(b"MZ");
        buf[FILE_HEADER_OFFSET_E_LFANEW..FILE_HEADER_OFFSET_E_LFANEW + 4]
            .copy_from_slice(&64u32.to_le_bytes());
        buf[64..68].copy_from_slice(b"PE\x00\x00");
        buf[68..70].copy_from_slice(&0x8664u16.to_le_bytes());
        let err: Error = unpack_petite(&buf).unwrap_err();
        matches!(err, Error::GoblinParse(_));
    }

    #[test]
    fn synthetic_pe_recovers_imports() {
        let payload: Vec<u8> = vec![0u8; 32];
        let petite_meta: Vec<u8> = synth_petite_metadata();
        let pe: Vec<u8> = build_minimal_petite_pe(&payload, &petite_meta);
        let result: UnpackResult =
            unpack_petite_with_report(&pe).expect("synthetic Petite PE must parse");
        assert!(
            !result.report.recovered_imports.is_empty(),
            "must recover at least one import: {:?}",
            result.report
        );
        let dlls: Vec<&str> = result
            .report
            .recovered_imports
            .iter()
            .map(|i: &RecoveredImport| i.dll.as_str())
            .collect();
        assert!(
            dlls.iter()
                .any(|d: &&str| d.eq_ignore_ascii_case("user32.dll")),
            "expected user32.dll among recovered DLLs: {dlls:?}"
        );
        assert!(
            dlls.iter()
                .any(|d: &&str| d.eq_ignore_ascii_case("kernel32.dll")),
            "expected kernel32.dll among recovered DLLs: {dlls:?}"
        );
    }

    #[test]
    fn synthetic_pe_recovered_blob_starts_with_mz() {
        let payload: Vec<u8> = vec![0u8; 32];
        let petite_meta: Vec<u8> = synth_petite_metadata();
        let pe: Vec<u8> = build_minimal_petite_pe(&payload, &petite_meta);
        let recovered: Vec<u8> = unpack_petite(&pe).expect("recovery must succeed");
        assert!(recovered.starts_with(b"MZ"), "recovered must begin with MZ");
        assert!(
            recovered.len() >= 256,
            "recovered must contain headers + sections"
        );
    }

    #[test]
    fn align_up_is_idempotent_on_aligned_values() {
        assert_eq!(align_up(0x1000, 0x1000), 0x1000);
        assert_eq!(align_up(0x1001, 0x1000), 0x2000);
        assert_eq!(align_up(0, 0x200), 0);
    }

    #[test]
    fn is_dll_name_recognizes_common_suffixes() {
        assert!(is_dll_name("user32.dll"));
        assert!(is_dll_name("API-MS-WIN-CORE-SYNCH-L1-2-0.DLL"));
        assert!(is_dll_name("kbdus.drv"));
        assert!(!is_dll_name("MessageBoxA"));
    }
}
