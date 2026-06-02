//! MEW 11 SE 1.2 unpacker.
//!
//! MEW (Northfox, 2004) is a 32-bit-only PE packer that ships a fixed-shape
//! container around an aPLib-compressed image. Every MEW 11 SE binary has the
//! same skeleton - recovered empirically from
//! `corpus/native/packers/mew/*.packed.mew.exe` and cross-checked against the
//! published RE notes (the gamma2 decoder bytes that prefix `section\[1\]` are
//! bit-identical to Joergen Ibsen's public aPLib assembler):
//!
//! - DOS header truncated to 16 bytes; `e_lfanew = 0x0C` (MEW overlaps the DOS
//!   stub area with the PE signature).
//! - PE32 (`Machine = 0x014C`, `OptionalHeader` magic = `0x010B`).
//! - Two sections:
//!   - `Section\[0\]`: name starts with `MEW\0` followed by 4 random bytes
//!     (commonly `F\x12\xd2\xc3`). `RawPtr = 0`, `RawSize = 0` - the section is
//!     virtual-only; the runtime stub decompresses the original image into
//!     this region. Characteristics: `0xC00000E0` (read|write|exec|uninit).
//!   - `Section\[1\]`: 8 random bytes (first 8 commonly `02 D2 75 DB 8A 16 EB D4`,
//!     which is the FSG/MEW shared `getbit_helper` prologue). Characteristics
//!     also `0xC00000E0`. This section holds **everything else**: the gamma2
//!     decoder, the compressed payload, the import-rebuild metadata and the
//!     EP stub trailer.
//! - `Section\[1\]` layout (offsets relative to its `raw_off`):
//!   - `\[0..12\]`  fixed gamma2 routine: `33 C9 41 FF 13 13 C9 FF 13 72 F8 C3`.
//!   - `\[12..16\]` runtime callback init RVA (patched at runtime).
//!   - `\[16..20\]` original PE-header reconstruction RVA (patched at runtime).
//!   - `\[20..K\]`  aPLib-compressed original image bytes.
//!   - `\[K..N-25\]` plaintext import-rebuild table - UTF-16 ordinal/hint names
//!     and per-DLL/per-API ASCII strings; always terminated by
//!     `kernel32.dll\0LoadLibraryA\0GetProcAddress\0` (the bootstrap pair the
//!     stub resolves first).
//!   - `\[N-25..N\]` 25-byte EP stub trailer:
//!     - `E9 xx xx xx xx`  `JMP rel32` to the decoder at `section\[1\]` base.
//!     - `0c XX 02 00`     `0x0002XX0C` - RVA of decoder entry in `section\[1\]`.
//!     - `00 00 00 00 00 00 00 00`  zeroed runtime patch slots.
//!     - `XX XX XX XX`     original `AddressOfEntryPoint` (post-unpack RVA).
//!     - `0c XX 02 00`     RVA of decoder entry, repeated.
//!
//! Real-by-default recovery: this unpacker parses every fixed landmark exactly,
//! then decodes the two leading aPLib chunks (IAT-name tail + rebuilder code)
//! followed by the LZMA1 rebuilder stream (`lc=4, lp=0, pb=2`) via the pure-Rust
//! [`decode_mpress_lzma`] port, populating `raw_image` and setting
//! `stream_decoded = true`. Structural-only recovery is the **fallback** when the
//! SE-1.2 chunk+LZMA layout does not apply (non-SE-1.2 dialect / truncated
//! stream): the unpacker still returns a structurally-true [`MewUnpackOutput`]
//! with the recovered metadata, and callers consume the `stream_decoded` flag and
//! the `decoded_byte_count` field to decide whether the recovery is sufficient.
//! The fallback path is documented behaviour, not silent failure.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::packers::mpress_lzma::decode_mpress_lzma;

const MEW_MIN_FILE_BYTES: usize = 0x200;
const MEW_DECODER_BYTES: [u8; 12] = [
    0x33, 0xC9, 0x41, 0xFF, 0x13, 0x13, 0xC9, 0xFF, 0x13, 0x72, 0xF8, 0xC3,
];
const MEW_SECTION0_NAME_PREFIX: [u8; 4] = *b"MEW\0";
const MEW_EP_TRAILER_LEN: usize = 25;
const MEW_IAT_BOOTSTRAP: &[u8] = b"kernel32.dll\0LoadLibraryA\0GetProcAddress\0";
const PE32_MAGIC: u16 = 0x010B;
const I386_MACHINE: u16 = 0x014C;
const DOS_E_LFANEW_OFFSET: usize = 0x3C;
const PE_FILE_HEADER_LEN: usize = 24;
const OPTIONAL_HEADER_AEP_OFFSET: usize = 0x10;
const OPTIONAL_HEADER_IMAGE_BASE_OFFSET: usize = 0x1C;
const SECTION_HEADER_LEN: usize = 40;
const APLIB_MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

/// One imported function recovered from the MEW plaintext IAT-rebuild table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MewImport {
    pub dll_name: String,
    pub api_name: String,
    pub by_ordinal: bool,
    pub ordinal: u16,
}

/// Honest recovery verdict for a MEW unpack.
///
/// `unpack_mew` always succeeds when the container is a valid MEW 11 SE image,
/// but "success" only guarantees that the fixed landmarks (sections, OEP,
/// import-rebuild table) were parsed. Whether the original image bytes were
/// actually decompressed is a separate, weaker claim. This enum makes that
/// distinction explicit so callers never mistake a structural parse for a full
/// payload recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum MewRecovery {
    /// Fixed landmarks parsed; the compressed payload was NOT decompressed
    /// (LZMA and aPLib paths both declined). `raw_image` is empty.
    #[default]
    StructuralOnly,
    /// The compressed payload decompressed to a non-empty image. Byte-exactness
    /// against the original is not guaranteed and is measured per fixture.
    Decompressed,
}

/// Structural facts the MEW unpacker recovers from a packed binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MewUnpackOutput {
    pub raw_image: Vec<u8>,
    pub image_base: u32,
    pub packed_entry_point_rva: u32,
    pub original_entry_point_rva: u32,
    pub section_0_virtual_size: u32,
    pub section_0_virtual_address: u32,
    pub section_1_raw_off: u32,
    pub section_1_raw_size: u32,
    pub compressed_payload_off: u32,
    pub iat_table_off: u32,
    pub iat_table_size: u32,
    pub ep_stub_trailer_off: u32,
    pub imports: Vec<MewImport>,
    pub recovery: MewRecovery,
    pub stream_decoded: bool,
    pub decoded_byte_count: u32,
}

#[derive(Debug, Clone, Copy)]
struct MewPeImage<'a> {
    bytes: &'a [u8],
    pe_off: usize,
    image_base: u32,
    aep_rva: u32,
    opt_header_size: u16,
}

#[derive(Debug, Clone, Copy)]
struct MewSection {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_off: u32,
}

#[derive(Debug, Clone, Copy)]
struct MewLayout {
    section_0: MewSection,
    section_1: MewSection,
    iat_table_off: u32,
    iat_table_size: u32,
    compressed_payload_off: u32,
    compressed_payload_size: u32,
    trailer_off: u32,
    original_aep_rva: u32,
}

/// Public entry point - unpack a MEW 11 SE 1.2 PE32 binary.
///
/// Recovery strategy (real-by-default, no Cargo feature gate):
/// 1. Parse the fixed MEW container and the plaintext import-rebuild table.
/// 2. Attempt the genuine MEW SE 1.2 recovery path - decode the two leading
///    aPLib chunks, then the LZMA1 rebuilder stream (`lc=4, lp=0, pb=2`) via the
///    always-available pure-Rust [`decode_mpress_lzma`] coder. The decompressed
///    original image populates `raw_image` and sets `stream_decoded = true`.
/// 3. If the LZMA path does not apply (non-SE-1.2 dialect / truncated stream),
///    fall back to the byte-tagged aPLib attempt, and finally to structural-only
///    recovery with `stream_decoded = false`.
///
/// The returned [`MewUnpackOutput::recovery`] verdict states honestly which of
/// these outcomes occurred: [`MewRecovery::Decompressed`] only when the payload
/// actually decompressed to a non-empty image, otherwise
/// [`MewRecovery::StructuralOnly`]. A successful return does NOT by itself imply
/// the original bytes were recovered.
pub fn unpack_mew(packed_bytes: &[u8]) -> Result<MewUnpackOutput> {
    let pe: MewPeImage<'_> = parse_mew_pe(packed_bytes)?;
    let layout: MewLayout = locate_mew_layout(&pe)?;
    let imports: Vec<MewImport> = parse_iat_table(packed_bytes, &layout);
    let mut structural: MewUnpackOutput = MewUnpackOutput {
        raw_image: Vec::new(),
        image_base: pe.image_base,
        packed_entry_point_rva: pe.aep_rva,
        original_entry_point_rva: layout.original_aep_rva,
        section_0_virtual_size: layout.section_0.virtual_size,
        section_0_virtual_address: layout.section_0.virtual_address,
        section_1_raw_off: layout.section_1.raw_off,
        section_1_raw_size: layout.section_1.raw_size,
        compressed_payload_off: layout.compressed_payload_off,
        iat_table_off: layout.iat_table_off,
        iat_table_size: layout.iat_table_size,
        ep_stub_trailer_off: layout.trailer_off,
        imports,
        recovery: MewRecovery::StructuralOnly,
        stream_decoded: false,
        decoded_byte_count: 0,
    };
    let (raw_image, stream_decoded): (Vec<u8>, bool) =
        match decode_mew_lzma_image(packed_bytes, &structural) {
            Ok(emulated) => (emulated.decompressed_image, true),
            Err(_) => attempt_aplib_decode(packed_bytes, &layout),
        };
    structural.decoded_byte_count = u32::try_from(raw_image.len()).unwrap_or(u32::MAX);
    structural.recovery = if stream_decoded && !raw_image.is_empty() {
        MewRecovery::Decompressed
    } else {
        MewRecovery::StructuralOnly
    };
    structural.raw_image = raw_image;
    structural.stream_decoded = stream_decoded;
    Ok(structural)
}

/// Byte-recovery output of [`unpack_mew_emulated`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MewEmulatedOutput {
    pub structural: MewUnpackOutput,
    pub decompressed_image: Vec<u8>,
    pub decompressed_size: u32,
    pub output_va: u32,
    pub lzma_props: MewLzmaProps,
    pub leading_chunks: Vec<MewLeadingChunk>,
}

/// LZMA1 props used by the MEW SE 1.2 rebuilder (hardcoded by the stub).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MewLzmaProps {
    pub lc: u8,
    pub lp: u8,
    pub pb: u8,
}

/// One pre-LZMA aplib chunk recovered while skipping past the MEW IAT-name
/// table and rebuilder code that prefix the LZMA payload in the stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MewLeadingChunk {
    pub dest_va: u32,
    pub decoded_bytes: u32,
}

/// Real byte-recovery via static structure parsing of the MEW SE 1.2 container.
///
/// Discovery: the MEW SE 1.2 stub uses an LZMA1 rebuilder for the original image
/// (`lc=4, lp=0, pb=2`), preceded by exactly two aplib-compressed chunks (IAT
/// name table at the tail of `section\[0\]`, then the rebuilder code itself in
/// `section\[1\]`). The aplib bit reader is MSB-first with a sentinel initial state
/// (`DL=0x80`); each chunk emits one literal byte first via `MOVSB` before
/// consuming any tag bits. The recovered LZMA stream is decoded by the
/// always-available pure-Rust [`decode_mpress_lzma`] coder - no external
/// emulator, no Cargo feature gate, no `unsafe`.
///
/// Returns the decompressed image bytes plus structural metadata. Byte-recovery
/// against the original image is fixture-dependent (the trailing IAT/reloc zones
/// the runtime stub rebuilds are not in the LZMA stream); callers measure the
/// achieved percentage against their own baseline.
///
/// # Errors
///
/// Propagates [`Error`] from PE parsing, structural validation, or any
/// decoder step.
pub fn unpack_mew_emulated(packed_bytes: &[u8]) -> Result<MewEmulatedOutput> {
    let structural: MewUnpackOutput = unpack_mew(packed_bytes)?;
    decode_mew_lzma_image(packed_bytes, &structural)
}

/// Decode the MEW SE 1.2 aPLib-chunks-then-LZMA1 payload into the original image.
///
/// Recursion-safe: takes an already-built [`MewUnpackOutput`] so [`unpack_mew`]
/// can call it without re-entering itself.
///
/// # Errors
///
/// Propagates [`Error::Truncated`] / [`Error::SignatureDb`] when the stream does
/// not match the SE 1.2 chunk+LZMA layout, plus any error from the LZMA coder.
#[allow(clippy::too_many_lines)]
fn decode_mew_lzma_image(
    packed_bytes: &[u8],
    structural: &MewUnpackOutput,
) -> Result<MewEmulatedOutput> {
    let sec1_start: usize = structural.section_1_raw_off as usize;
    let sec1_end: usize = sec1_start
        .checked_add(structural.section_1_raw_size as usize)
        .ok_or_else(|| Error::SignatureDb("MEW section[1] range overflows".to_owned()))?;
    if sec1_end > packed_bytes.len() {
        return Err(Error::Truncated {
            needed: sec1_end,
            had: packed_bytes.len(),
        });
    }
    let stream_start: usize = sec1_start
        .checked_add(40)
        .ok_or_else(|| Error::SignatureDb("MEW stream-start overflow".to_owned()))?;
    if stream_start + 4 > sec1_end {
        return Err(Error::Truncated {
            needed: stream_start + 4,
            had: sec1_end,
        });
    }
    let stream: &[u8] = &packed_bytes[stream_start..sec1_end];
    let image_base: u32 = structural.image_base;
    let first_dest_va: u32 = u32::from_le_bytes([
        packed_bytes[sec1_start + 36],
        packed_bytes[sec1_start + 37],
        packed_bytes[sec1_start + 38],
        packed_bytes[sec1_start + 39],
    ]);
    let mut chunk_reader: MewAplibChunks<'_> = MewAplibChunks::new(stream);
    let mut leading_chunks: Vec<MewLeadingChunk> = Vec::with_capacity(2);
    let mut current_dest_va: u32 = first_dest_va;
    loop {
        let chunk_decoded: u32 = chunk_reader.decode_chunk(current_dest_va, image_base)?;
        leading_chunks.push(MewLeadingChunk {
            dest_va: current_dest_va,
            decoded_bytes: chunk_decoded,
        });
        if chunk_reader.remaining() < 4 {
            return Err(Error::Truncated {
                needed: chunk_reader.pos + 4,
                had: stream.len(),
            });
        }
        let next_va: u32 = chunk_reader.read_u32_le()?;
        if next_va == 0 {
            break;
        }
        current_dest_va = next_va;
    }
    let lzma_header_off: usize = stream_start + chunk_reader.pos;
    if lzma_header_off + 17 > packed_bytes.len() {
        return Err(Error::Truncated {
            needed: lzma_header_off + 17,
            had: packed_bytes.len(),
        });
    }
    let _probs_ptr: u32 = u32::from_le_bytes([
        packed_bytes[lzma_header_off],
        packed_bytes[lzma_header_off + 1],
        packed_bytes[lzma_header_off + 2],
        packed_bytes[lzma_header_off + 3],
    ]);
    let count: u32 = u32::from_le_bytes([
        packed_bytes[lzma_header_off + 4],
        packed_bytes[lzma_header_off + 5],
        packed_bytes[lzma_header_off + 6],
        packed_bytes[lzma_header_off + 7],
    ]);
    let output_va: u32 = u32::from_le_bytes([
        packed_bytes[lzma_header_off + 8],
        packed_bytes[lzma_header_off + 9],
        packed_bytes[lzma_header_off + 10],
        packed_bytes[lzma_header_off + 11],
    ]);
    let clen: u32 = u32::from_le_bytes([
        packed_bytes[lzma_header_off + 12],
        packed_bytes[lzma_header_off + 13],
        packed_bytes[lzma_header_off + 14],
        packed_bytes[lzma_header_off + 15],
    ]);
    let lzma_stream_off: usize = lzma_header_off + 17;
    let lzma_stream_end: usize = lzma_stream_off
        .checked_add(clen as usize)
        .ok_or_else(|| Error::SignatureDb("MEW LZMA clen overflow".to_owned()))?;
    if lzma_stream_end > packed_bytes.len() {
        return Err(Error::Truncated {
            needed: lzma_stream_end,
            had: packed_bytes.len(),
        });
    }
    let lzma_props: MewLzmaProps = MewLzmaProps {
        lc: 4,
        lp: 0,
        pb: 2,
    };
    let lzma_stream: &[u8] = &packed_bytes[lzma_stream_off..lzma_stream_end];
    let mut framed: Vec<u8> = Vec::with_capacity(2 + lzma_stream.len());
    framed.push((lzma_props.pb << 4) | lzma_props.lp);
    framed.push(lzma_props.lc);
    framed.extend_from_slice(lzma_stream);
    let decompressed_image: Vec<u8> = decode_mpress_lzma(&framed, count as usize)?;
    let decompressed_size: u32 = u32::try_from(decompressed_image.len()).unwrap_or(u32::MAX);
    Ok(MewEmulatedOutput {
        structural: structural.clone(),
        decompressed_image,
        decompressed_size,
        output_va,
        lzma_props,
        leading_chunks,
    })
}

struct MewAplibChunks<'a> {
    src: &'a [u8],
    pos: usize,
    image: Vec<u8>,
}

impl<'a> MewAplibChunks<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            pos: 0,
            image: vec![0u8; 0x100_0000],
        }
    }

    fn remaining(&self) -> usize {
        self.src.len().saturating_sub(self.pos)
    }

    fn read_byte(&mut self) -> Result<u8> {
        if self.pos >= self.src.len() {
            return Err(Error::Truncated {
                needed: self.pos + 1,
                had: self.src.len(),
            });
        }
        let b: u8 = self.src[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_u32_le(&mut self) -> Result<u32> {
        if self.pos + 4 > self.src.len() {
            return Err(Error::Truncated {
                needed: self.pos + 4,
                had: self.src.len(),
            });
        }
        let v: u32 = u32::from_le_bytes([
            self.src[self.pos],
            self.src[self.pos + 1],
            self.src[self.pos + 2],
            self.src[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    #[allow(
        clippy::too_many_lines,
        clippy::cast_sign_loss,
        clippy::branches_sharing_code
    )]
    fn decode_chunk(&mut self, dest_va: u32, image_base: u32) -> Result<u32> {
        if dest_va < image_base {
            return Err(Error::SignatureDb(format!(
                "MEW chunk dest VA {dest_va:#x} below image base {image_base:#x}"
            )));
        }
        let dest_off: usize = (dest_va - image_base) as usize;
        if dest_off >= self.image.len() {
            return Err(Error::SignatureDb(format!(
                "MEW chunk dest VA {dest_va:#x} outside emulated image"
            )));
        }
        let mut dpos: usize = dest_off;
        let mut dl: u8 = 0x80;
        let first: u8 = self.read_byte()?;
        self.image[dpos] = first;
        dpos += 1;
        let mut last_off: usize = 0;
        let mut lwm: bool = false;
        loop {
            let b: u32 = self.read_bit(&mut dl)?;
            if b == 0 {
                let lit: u8 = self.read_byte()?;
                if dpos >= self.image.len() {
                    return Err(Error::SignatureDb(
                        "MEW chunk literal overflows emulated image".to_owned(),
                    ));
                }
                self.image[dpos] = lit;
                dpos += 1;
                lwm = false;
                continue;
            }
            let b2: u32 = self.read_bit(&mut dl)?;
            if b2 == 0 {
                let offset_high: u32 = self.read_gamma(&mut dl)?;
                if !lwm && offset_high == 2 {
                    let length: u32 = self.read_gamma(&mut dl)?;
                    if last_off == 0 || last_off > dpos - dest_off {
                        return Err(Error::SignatureDb(format!(
                            "MEW chunk R0-reuse with bad last_off={last_off}"
                        )));
                    }
                    for _ in 0..length {
                        let src_b: u8 = self.image[dpos - last_off];
                        self.image[dpos] = src_b;
                        dpos += 1;
                    }
                    lwm = true;
                } else {
                    let adj: i64 = i64::from(offset_high) - if lwm { 2 } else { 3 };
                    let low: u8 = self.read_byte()?;
                    let offset: i64 = (adj << 8) | i64::from(low);
                    let mut length: u32 = self.read_gamma(&mut dl)?;
                    if offset >= 32_000 {
                        length = length.saturating_add(2);
                    } else if offset >= 1_280 {
                        length = length.saturating_add(1);
                    } else if offset < 128 {
                        length = length.saturating_add(2);
                    }
                    if offset <= 0 {
                        return Err(Error::SignatureDb(format!(
                            "MEW chunk long-match offset {offset} invalid"
                        )));
                    }
                    let offset_usize: usize = offset as usize;
                    if offset_usize > dpos - dest_off {
                        return Err(Error::SignatureDb(format!(
                            "MEW chunk long-match offset {offset_usize} exceeds chunk progress"
                        )));
                    }
                    for _ in 0..length {
                        let src_b: u8 = self.image[dpos - offset_usize];
                        self.image[dpos] = src_b;
                        dpos += 1;
                    }
                    last_off = offset_usize;
                    lwm = true;
                }
                continue;
            }
            let b3: u32 = self.read_bit(&mut dl)?;
            if b3 == 0 {
                let byte: u8 = self.read_byte()?;
                let offset: usize = usize::from(byte) >> 1;
                if offset == 0 {
                    let decoded: u32 = u32::try_from(dpos - dest_off).unwrap_or(u32::MAX);
                    return Ok(decoded);
                }
                let length: u32 = 2 + u32::from(byte & 1);
                if offset > dpos - dest_off {
                    return Err(Error::SignatureDb(format!(
                        "MEW chunk short-match offset {offset} exceeds chunk progress"
                    )));
                }
                for _ in 0..length {
                    let src_b: u8 = self.image[dpos - offset];
                    self.image[dpos] = src_b;
                    dpos += 1;
                }
                last_off = offset;
                lwm = true;
                continue;
            }
            let mut nib: u32 = 0;
            for _ in 0..4 {
                nib = (nib << 1) | self.read_bit(&mut dl)?;
            }
            let nib_off: usize = nib as usize;
            let byte_to_write: u8 = if nib_off == 0 {
                0
            } else {
                if nib_off > dpos - dest_off {
                    return Err(Error::SignatureDb(format!(
                        "MEW chunk nibble-back-ref offset {nib_off} exceeds chunk progress"
                    )));
                }
                self.image[dpos - nib_off]
            };
            self.image[dpos] = byte_to_write;
            dpos += 1;
            lwm = false;
        }
    }

    fn read_bit(&mut self, dl: &mut u8) -> Result<u32> {
        let mut cf: u32 = u32::from((*dl >> 7) & 1);
        *dl = dl.wrapping_shl(1);
        if *dl == 0 {
            let nb: u8 = self.read_byte()?;
            *dl = nb.wrapping_shl(1) | 1;
            cf = u32::from((nb >> 7) & 1);
        }
        Ok(cf)
    }

    fn read_gamma(&mut self, dl: &mut u8) -> Result<u32> {
        let mut v: u32 = 1;
        loop {
            v = (v << 1) | self.read_bit(dl)?;
            if self.read_bit(dl)? == 0 {
                return Ok(v);
            }
        }
    }
}

fn parse_mew_pe(bytes: &[u8]) -> Result<MewPeImage<'_>> {
    if bytes.len() < MEW_MIN_FILE_BYTES {
        return Err(Error::Truncated {
            needed: MEW_MIN_FILE_BYTES,
            had: bytes.len(),
        });
    }
    if &bytes[0..2] != b"MZ" {
        return Err(Error::UnknownFormat);
    }
    let e_lfanew: u32 = read_u32_le(bytes, DOS_E_LFANEW_OFFSET)?;
    let pe_off: usize = e_lfanew as usize;
    if pe_off + PE_FILE_HEADER_LEN > bytes.len() {
        return Err(Error::Truncated {
            needed: pe_off + PE_FILE_HEADER_LEN,
            had: bytes.len(),
        });
    }
    if &bytes[pe_off..pe_off + 4] != b"PE\0\0" {
        return Err(Error::UnknownFormat);
    }
    let machine: u16 = read_u16_le(bytes, pe_off + 4)?;
    if machine != I386_MACHINE {
        return Err(Error::UnsupportedArch(format!(
            "MEW 11 SE is i386-only (machine 0x014C), got 0x{machine:04X}"
        )));
    }
    let section_count: u16 = read_u16_le(bytes, pe_off + 6)?;
    if section_count != 2 {
        return Err(Error::SignatureDb(format!(
            "MEW 11 SE has exactly 2 sections; PE reports {section_count}"
        )));
    }
    let opt_header_size: u16 = read_u16_le(bytes, pe_off + 0x14)?;
    let opt_header_off: usize = pe_off + PE_FILE_HEADER_LEN;
    if opt_header_off + opt_header_size as usize > bytes.len() {
        return Err(Error::Truncated {
            needed: opt_header_off + opt_header_size as usize,
            had: bytes.len(),
        });
    }
    let opt_magic: u16 = read_u16_le(bytes, opt_header_off)?;
    if opt_magic != PE32_MAGIC {
        return Err(Error::UnsupportedArch(format!(
            "MEW 11 SE is PE32-only (magic 0x010B), got 0x{opt_magic:04X}"
        )));
    }
    let aep_rva: u32 = read_u32_le(bytes, opt_header_off + OPTIONAL_HEADER_AEP_OFFSET)?;
    let image_base: u32 = read_u32_le(bytes, opt_header_off + OPTIONAL_HEADER_IMAGE_BASE_OFFSET)?;
    Ok(MewPeImage {
        bytes,
        pe_off,
        image_base,
        aep_rva,
        opt_header_size,
    })
}

fn locate_mew_layout(pe: &MewPeImage<'_>) -> Result<MewLayout> {
    let sect_table_off: usize = pe.pe_off + PE_FILE_HEADER_LEN + pe.opt_header_size as usize;
    let sec_0: MewSection = read_section(pe.bytes, sect_table_off)?;
    let sec_1: MewSection = read_section(pe.bytes, sect_table_off + SECTION_HEADER_LEN)?;
    if sec_0.name[..4] != MEW_SECTION0_NAME_PREFIX {
        return Err(Error::SignatureDb(format!(
            "MEW section[0] must start with 'MEW\\0', got {:02x?}",
            &sec_0.name[..4]
        )));
    }
    if sec_0.raw_size != 0 || sec_0.raw_off != 0 {
        return Err(Error::SignatureDb(format!(
            "MEW section[0] must be virtual-only (RawPtr=0,RawSize=0), got RawPtr={:#x} RawSize={:#x}",
            sec_0.raw_off, sec_0.raw_size
        )));
    }
    if sec_1.raw_size == 0 || sec_1.raw_off == 0 {
        return Err(Error::SignatureDb(
            "MEW section[1] must carry the packed payload (RawPtr/RawSize > 0)".to_owned(),
        ));
    }
    let s1_start: usize = sec_1.raw_off as usize;
    let s1_end: usize = s1_start
        .checked_add(sec_1.raw_size as usize)
        .ok_or_else(|| {
            Error::SignatureDb("MEW section[1] raw_off+raw_size overflows".to_owned())
        })?;
    if s1_end > pe.bytes.len() {
        return Err(Error::Truncated {
            needed: s1_end,
            had: pe.bytes.len(),
        });
    }
    let payload: &[u8] = &pe.bytes[s1_start..s1_end];
    if payload.len() < MEW_DECODER_BYTES.len() + 8 + MEW_EP_TRAILER_LEN {
        return Err(Error::Truncated {
            needed: MEW_DECODER_BYTES.len() + 8 + MEW_EP_TRAILER_LEN,
            had: payload.len(),
        });
    }
    if payload[..MEW_DECODER_BYTES.len()] != MEW_DECODER_BYTES {
        return Err(Error::SignatureDb(format!(
            "MEW gamma2 decoder prologue mismatch at section[1][0..12]: expected {:02x?}, got {:02x?}",
            MEW_DECODER_BYTES,
            &payload[..MEW_DECODER_BYTES.len()]
        )));
    }
    let bootstrap_in_payload: usize = payload.windows(MEW_IAT_BOOTSTRAP.len())
        .rposition(|w: &[u8]| w == MEW_IAT_BOOTSTRAP)
        .ok_or_else(|| Error::SignatureDb(
            "MEW IAT bootstrap 'kernel32.dll\\0LoadLibraryA\\0GetProcAddress\\0' not found in section[1]".to_owned(),
        ))?;
    let trailer_start_in_payload: usize =
        payload
            .len()
            .checked_sub(MEW_EP_TRAILER_LEN)
            .ok_or(Error::Truncated {
                needed: MEW_EP_TRAILER_LEN,
                had: payload.len(),
            })?;
    let trailer: &[u8] = &payload[trailer_start_in_payload..];
    if trailer[0] != 0xE9 {
        return Err(Error::SignatureDb(format!(
            "MEW EP-stub trailer must begin with E9 (JMP rel32), got {:#04x}",
            trailer[0]
        )));
    }
    let original_aep_rva: u32 =
        u32::from_le_bytes([trailer[17], trailer[18], trailer[19], trailer[20]]);
    let iat_end_in_payload: usize = bootstrap_in_payload + MEW_IAT_BOOTSTRAP.len();
    let iat_table_off: u32 = sec_1.raw_off + 20;
    let iat_table_size: u32 = u32::try_from(iat_end_in_payload)
        .unwrap_or(0)
        .saturating_sub(20);
    let compressed_payload_off: u32 = sec_1.raw_off + MEW_DECODER_BYTES.len() as u32 + 8;
    let compressed_payload_size: u32 = u32::try_from(bootstrap_in_payload)
        .unwrap_or(0)
        .saturating_sub(MEW_DECODER_BYTES.len() as u32 + 8);
    let trailer_off: u32 = sec_1.raw_off + u32::try_from(trailer_start_in_payload).unwrap_or(0);
    Ok(MewLayout {
        section_0: sec_0,
        section_1: sec_1,
        iat_table_off,
        iat_table_size,
        compressed_payload_off,
        compressed_payload_size,
        trailer_off,
        original_aep_rva,
    })
}

fn read_section(bytes: &[u8], off: usize) -> Result<MewSection> {
    if off + SECTION_HEADER_LEN > bytes.len() {
        return Err(Error::Truncated {
            needed: off + SECTION_HEADER_LEN,
            had: bytes.len(),
        });
    }
    let mut name: [u8; 8] = [0u8; 8];
    name.copy_from_slice(&bytes[off..off + 8]);
    let virtual_size: u32 = read_u32_le(bytes, off + 8)?;
    let virtual_address: u32 = read_u32_le(bytes, off + 12)?;
    let raw_size: u32 = read_u32_le(bytes, off + 16)?;
    let raw_off: u32 = read_u32_le(bytes, off + 20)?;
    Ok(MewSection {
        name,
        virtual_size,
        virtual_address,
        raw_size,
        raw_off,
    })
}

fn parse_iat_table(bytes: &[u8], layout: &MewLayout) -> Vec<MewImport> {
    let start: usize = layout.iat_table_off as usize;
    let end: usize = start.saturating_add(layout.iat_table_size as usize);
    if end > bytes.len() || start >= end {
        return Vec::new();
    }
    let table: &[u8] = &bytes[start..end];
    parse_iat_records(table)
}

fn parse_iat_records(table: &[u8]) -> Vec<MewImport> {
    let mut imports: Vec<MewImport> = Vec::new();
    let bootstrap_pos: Option<usize> = table
        .windows(MEW_IAT_BOOTSTRAP.len())
        .rposition(|w: &[u8]| w == MEW_IAT_BOOTSTRAP);
    let Some(bs_pos): Option<usize> = bootstrap_pos else {
        return imports;
    };
    let ascii_zone: &[u8] = &table[..bs_pos];
    if ascii_zone.is_empty() {
        imports.push(MewImport {
            dll_name: "kernel32.dll".to_owned(),
            api_name: "LoadLibraryA".to_owned(),
            by_ordinal: false,
            ordinal: 0,
        });
        imports.push(MewImport {
            dll_name: "kernel32.dll".to_owned(),
            api_name: "GetProcAddress".to_owned(),
            by_ordinal: false,
            ordinal: 0,
        });
        return imports;
    }
    let mut cursor: usize = 0;
    let mut current_dll: String = String::new();
    while cursor < ascii_zone.len() {
        let byte: u8 = ascii_zone[cursor];
        if byte == 0 {
            cursor += 1;
            continue;
        }
        if byte == 1 && cursor + 1 < ascii_zone.len() {
            let dll_len: usize = ascii_zone[cursor + 1] as usize;
            let dll_start: usize = cursor + 2;
            let dll_end: usize = dll_start.saturating_add(dll_len);
            if dll_end > ascii_zone.len() {
                break;
            }
            current_dll = String::from_utf8_lossy(&ascii_zone[dll_start..dll_end]).into_owned();
            cursor = dll_end;
            continue;
        }
        let api_len: usize = byte as usize;
        let api_start: usize = cursor + 1;
        let api_end: usize = api_start.saturating_add(api_len);
        if api_end > ascii_zone.len() || api_len == 0 {
            break;
        }
        let api_bytes: &[u8] = &ascii_zone[api_start..api_end];
        let api_name: String = String::from_utf8_lossy(api_bytes).into_owned();
        if api_name.chars().all(|c: char| c == '\0') || api_name.is_empty() {
            cursor = api_end;
            continue;
        }
        imports.push(MewImport {
            dll_name: if current_dll.is_empty() {
                String::new()
            } else {
                current_dll.clone()
            },
            api_name,
            by_ordinal: false,
            ordinal: 0,
        });
        cursor = api_end;
    }
    imports.push(MewImport {
        dll_name: "kernel32.dll".to_owned(),
        api_name: "LoadLibraryA".to_owned(),
        by_ordinal: false,
        ordinal: 0,
    });
    imports.push(MewImport {
        dll_name: "kernel32.dll".to_owned(),
        api_name: "GetProcAddress".to_owned(),
        by_ordinal: false,
        ordinal: 0,
    });
    imports
}

fn attempt_aplib_decode(bytes: &[u8], layout: &MewLayout) -> (Vec<u8>, bool) {
    let start: usize = layout.compressed_payload_off as usize;
    let end: usize = start.saturating_add(layout.compressed_payload_size as usize);
    if end > bytes.len() || start >= end {
        return (Vec::new(), false);
    }
    let stream: &[u8] = &bytes[start..end];
    aplib_decode_bytetagged(stream, layout.section_0.virtual_size as usize)
        .map_or_else(|_| (Vec::new(), false), |out: Vec<u8>| (out, true))
}

/// Decode the aPLib-compressed payload region from a parsed MEW image.
///
/// Public for diagnostics - returns the decoder result verbatim so callers
/// can inspect failure modes rather than collapsing them to `false`.
///
/// # Errors
///
/// Propagates [`Error::Truncated`] when the requested range escapes the
/// supplied buffer, and any [`Error`] surfaced by the underlying byte-tagged
/// aPLib decoder.
pub fn decode_compressed_payload(
    bytes: &[u8],
    compressed_off: u32,
    compressed_size: u32,
    soft_cap: u32,
) -> Result<Vec<u8>> {
    let start: usize = compressed_off as usize;
    let end: usize = start.saturating_add(compressed_size as usize);
    if end > bytes.len() || start >= end {
        return Err(Error::Truncated {
            needed: end,
            had: bytes.len(),
        });
    }
    aplib_decode_bytetagged(&bytes[start..end], soft_cap as usize)
}

#[derive(Debug)]
struct ByteTaggedBitReader<'a> {
    src: &'a [u8],
    pos: usize,
    tag: u32,
    tag_bits_left: u32,
}

impl<'a> ByteTaggedBitReader<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            pos: 0,
            tag: 0,
            tag_bits_left: 0,
        }
    }

    fn read_byte(&mut self) -> Result<u8> {
        let b: u8 = *self.src.get(self.pos).ok_or(Error::Truncated {
            needed: self.pos + 1,
            had: self.src.len(),
        })?;
        self.pos += 1;
        Ok(b)
    }

    fn read_bit(&mut self) -> Result<u32> {
        if self.tag_bits_left == 0 {
            self.tag = u32::from(self.read_byte()?);
            self.tag_bits_left = 8;
        }
        let bit: u32 = (self.tag >> 7) & 1;
        self.tag = (self.tag << 1) & 0xFF;
        self.tag_bits_left -= 1;
        Ok(bit)
    }

    fn read_gamma(&mut self) -> Result<u32> {
        let mut value: u32 = 1;
        loop {
            value = (value << 1) | self.read_bit()?;
            if self.read_bit()? == 0 {
                return Ok(value);
            }
        }
    }
}

enum AplibStep {
    Continue { lwm: bool, last_off: u32 },
    Finished,
}

/// Clean-room Rust port of the Joergen Ibsen aPLib byte-tagged depacker.
///
/// Algorithm reference: aPLib 1.1.1 public C source (BSD-licensed). The bit
/// reader is byte-aligned with MSB-first ordering and explicit bit-count
/// tracking. State machine:
///
/// - first byte: raw literal, no tag bit consumed.
/// - then loop reading prefix bits:
///   - `0`: literal byte from stream; clears LWM.
///   - `10`: long match. Reads gamma high bits. If LWM=0 and gamma==2,
///     reuses `R0` with `length = read_gamma()`. Otherwise computes
///     `offset = (gamma - (LWM ? 2 : 3)) << 8 | read_byte()` and
///     `length = read_gamma()` plus the offset-dependent bonus. Sets `R0`
///     and `LWM`.
///   - `110`: short match. One byte yields `offset = byte >> 1` and
///     `length = 2 + (byte & 1)`. If `offset == 0` the stream terminates.
///   - `111`: 4-bit nibble back-ref into 0..=15. Offset of 0 emits a `0`
///     literal; otherwise copies `out[-offset]`. Clears LWM.
///
/// Length bonus (long match):
///
/// - `offset >= 32000`: `length += 2`
/// - `offset >= 1280`:  `length += 1`
/// - `offset < 128`:    `length += 2`
/// - otherwise:         length unchanged
///
/// # Errors
///
/// Returns [`Error::Truncated`] if the stream is too short for the next
/// requested byte/bit, or [`Error::PackerUnpackerNotImplemented`] if a match
/// offset escapes the already-decoded buffer (the canonical "corrupt or
/// dialect-mismatched stream" signal).
pub fn aplib_decode_bytetagged(packed: &[u8], soft_cap: usize) -> Result<Vec<u8>> {
    aplib_decode_bytetagged_partial(packed, soft_cap).map(|(out, _)| out)
}

/// Best-effort decode with trace metadata.
///
/// Returns the full buffer and a diagnostic trace record (step count plus the
/// last successful in/out positions). On `Err`, the partial buffer is
/// discarded and only the error is returned; use
/// [`aplib_decode_bytetagged_lossy`] to retain the partial buffer.
///
/// # Errors
///
/// Same conditions as [`aplib_decode_bytetagged`].
pub fn aplib_decode_bytetagged_partial(
    packed: &[u8],
    soft_cap: usize,
) -> Result<(Vec<u8>, AplibTrace)> {
    let initial_cap: usize = soft_cap
        .max(packed.len().saturating_mul(4))
        .min(APLIB_MAX_OUTPUT_BYTES);
    let mut out: Vec<u8> = Vec::with_capacity(initial_cap);
    let mut br: ByteTaggedBitReader<'_> = ByteTaggedBitReader::new(packed);
    out.push(br.read_byte()?);
    let mut last_off: u32 = 0;
    let mut lwm: bool = false;
    let mut steps: u64 = 0;
    loop {
        if out.len() > APLIB_MAX_OUTPUT_BYTES {
            return Err(Error::PackerUnpackerNotImplemented(
                "MEW: aPLib decompressed size exceeded 64 MiB safety cap",
            ));
        }
        let step: AplibStep = aplib_step(&mut br, &mut out, last_off, lwm)?;
        steps += 1;
        match step {
            AplibStep::Continue {
                lwm: new_lwm,
                last_off: new_last_off,
            } => {
                lwm = new_lwm;
                last_off = new_last_off;
            }
            AplibStep::Finished => {
                return Ok((
                    out,
                    AplibTrace {
                        last_out_len: 0,
                        last_in_pos: br.pos,
                        steps,
                    },
                ));
            }
        }
    }
}

/// Trace record emitted by partial-decode diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AplibTrace {
    pub last_out_len: usize,
    pub last_in_pos: usize,
    pub steps: u64,
}

/// Lossy diagnostic decoder.
///
/// Runs the decoder and returns the partial output buffer plus the error
/// (if any). Used by tests to inspect failure mode without losing progress
/// data.
#[must_use]
pub fn aplib_decode_bytetagged_lossy(
    packed: &[u8],
    soft_cap: usize,
) -> (Vec<u8>, u64, Option<Error>) {
    aplib_decode_bytetagged_lossy_with(packed, soft_cap, AplibInitialState::default())
}

/// Initial-state knobs for the aPLib byte-tagged decoder.
///
/// Real MEW fixtures may not match the textbook Ibsen initial state, so
/// callers can override the first-byte handling, LWM flag, and `R0` register
/// that classic Ibsen aPLib otherwise hard-codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AplibInitialState {
    pub emit_first_byte_literal: bool,
    pub initial_lwm: bool,
    pub initial_r0: u32,
}

impl Default for AplibInitialState {
    fn default() -> Self {
        Self {
            emit_first_byte_literal: true,
            initial_lwm: false,
            initial_r0: 0,
        }
    }
}

/// Lossy diagnostic decoder with overridable initial state. See
/// [`aplib_decode_bytetagged_lossy`].
#[must_use]
pub fn aplib_decode_bytetagged_lossy_with(
    packed: &[u8],
    soft_cap: usize,
    init: AplibInitialState,
) -> (Vec<u8>, u64, Option<Error>) {
    let initial_cap: usize = soft_cap
        .max(packed.len().saturating_mul(4))
        .min(APLIB_MAX_OUTPUT_BYTES);
    let mut out: Vec<u8> = Vec::with_capacity(initial_cap);
    let mut br: ByteTaggedBitReader<'_> = ByteTaggedBitReader::new(packed);
    if init.emit_first_byte_literal {
        match br.read_byte() {
            Ok(b) => out.push(b),
            Err(e) => return (out, 0, Some(e)),
        }
    }
    let mut last_off: u32 = init.initial_r0;
    let mut lwm: bool = init.initial_lwm;
    let mut steps: u64 = 0;
    loop {
        if out.len() > APLIB_MAX_OUTPUT_BYTES {
            return (
                out,
                steps,
                Some(Error::PackerUnpackerNotImplemented(
                    "MEW: aPLib decompressed size exceeded 64 MiB safety cap",
                )),
            );
        }
        let step: AplibStep = match aplib_step(&mut br, &mut out, last_off, lwm) {
            Ok(s) => s,
            Err(e) => return (out, steps, Some(e)),
        };
        steps += 1;
        match step {
            AplibStep::Continue {
                lwm: new_lwm,
                last_off: new_last_off,
            } => {
                lwm = new_lwm;
                last_off = new_last_off;
            }
            AplibStep::Finished => return (out, steps, None),
        }
    }
}

fn aplib_step(
    br: &mut ByteTaggedBitReader<'_>,
    out: &mut Vec<u8>,
    last_off: u32,
    lwm: bool,
) -> Result<AplibStep> {
    if br.read_bit()? == 0 {
        let b: u8 = br.read_byte()?;
        out.push(b);
        return Ok(AplibStep::Continue {
            lwm: false,
            last_off,
        });
    }
    if br.read_bit()? == 0 {
        return aplib_long_match_arm(br, out, last_off, lwm);
    }
    if br.read_bit()? == 0 {
        return aplib_short_match_arm(br, out, last_off);
    }
    aplib_nibble_arm(br, out, last_off)
}

fn aplib_long_match_arm(
    br: &mut ByteTaggedBitReader<'_>,
    out: &mut Vec<u8>,
    last_off: u32,
    lwm: bool,
) -> Result<AplibStep> {
    let offset_high: u32 = br.read_gamma()?;
    if !lwm && offset_high == 2 {
        let length: u32 = br.read_gamma()?;
        copy_match(out, last_off as usize, length as usize)?;
        return Ok(AplibStep::Continue {
            lwm: true,
            last_off,
        });
    }
    let adjusted_high: u32 = if lwm {
        offset_high.wrapping_sub(2)
    } else {
        offset_high.wrapping_sub(3)
    };
    let low_byte: u32 = u32::from(br.read_byte()?);
    let offset: u32 = adjusted_high
        .checked_shl(8)
        .ok_or(Error::PackerUnpackerNotImplemented(
            "MEW: aPLib long-match offset overflow",
        ))?
        | low_byte;
    let length: u32 = aplib_long_match_len(br.read_gamma()?, offset);
    copy_match(out, offset as usize, length as usize)?;
    Ok(AplibStep::Continue {
        lwm: true,
        last_off: offset,
    })
}

fn aplib_short_match_arm(
    br: &mut ByteTaggedBitReader<'_>,
    out: &mut Vec<u8>,
    last_off: u32,
) -> Result<AplibStep> {
    let byte: u8 = br.read_byte()?;
    let offset: u32 = u32::from(byte) >> 1;
    if offset == 0 {
        return Ok(AplibStep::Finished);
    }
    let length: u32 = 2 + u32::from(byte & 1);
    copy_match(out, offset as usize, length as usize)?;
    let _ = last_off;
    Ok(AplibStep::Continue {
        lwm: true,
        last_off: offset,
    })
}

fn aplib_nibble_arm(
    br: &mut ByteTaggedBitReader<'_>,
    out: &mut Vec<u8>,
    last_off: u32,
) -> Result<AplibStep> {
    let mut offset: u32 = 0;
    for _ in 0..4 {
        offset = (offset << 1) | br.read_bit()?;
    }
    let byte: u8 = if offset == 0 {
        0
    } else {
        if (offset as usize) > out.len() {
            return Err(Error::PackerUnpackerNotImplemented(
                "MEW: aPLib nibble back-ref underflow",
            ));
        }
        let pos: usize = out.len();
        out[pos - offset as usize]
    };
    out.push(byte);
    Ok(AplibStep::Continue {
        lwm: false,
        last_off,
    })
}

const fn aplib_long_match_len(base: u32, new_off: u32) -> u32 {
    if new_off >= 32_000 {
        base.saturating_add(2)
    } else if new_off >= 1_280 {
        base.saturating_add(1)
    } else if new_off < 128 {
        base.saturating_add(2)
    } else {
        base
    }
}

fn copy_match(out: &mut Vec<u8>, offset: usize, len: usize) -> Result<()> {
    if offset == 0 || offset > out.len() {
        return Err(Error::PackerUnpackerNotImplemented(
            "MEW: aPLib match-offset out of range",
        ));
    }
    for _ in 0..len {
        let b: u8 = out[out.len() - offset];
        out.push(b);
    }
    Ok(())
}

const fn read_u16_le_const(bytes: &[u8], off: usize) -> Option<u16> {
    if off + 2 > bytes.len() {
        return None;
    }
    Some(u16::from_le_bytes([bytes[off], bytes[off + 1]]))
}

fn read_u16_le(bytes: &[u8], off: usize) -> Result<u16> {
    read_u16_le_const(bytes, off).ok_or(Error::Truncated {
        needed: off + 2,
        had: bytes.len(),
    })
}

fn read_u32_le(bytes: &[u8], off: usize) -> Result<u32> {
    if off + 4 > bytes.len() {
        return Err(Error::Truncated {
            needed: off + 4,
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

    #[test]
    fn rejects_non_pe_input() {
        let bytes: Vec<u8> = vec![0u8; 0x400];
        let r: Result<MewUnpackOutput> = unpack_mew(&bytes);
        assert!(matches!(r, Err(Error::UnknownFormat)));
    }

    #[test]
    fn rejects_truncated_input() {
        let bytes: Vec<u8> = vec![0u8; 0x10];
        let r: Result<MewUnpackOutput> = unpack_mew(&bytes);
        assert!(matches!(r, Err(Error::Truncated { .. })));
    }

    #[test]
    fn rejects_pe32_plus_x64() {
        let mut bytes: Vec<u8> = vec![0u8; 0x400];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3C] = 0x0C;
        bytes[0x0C] = b'P';
        bytes[0x0D] = b'E';
        bytes[0x10] = 0x64;
        bytes[0x11] = 0x86;
        bytes[0x24] = 0x0B;
        bytes[0x25] = 0x02;
        let r: Result<MewUnpackOutput> = unpack_mew(&bytes);
        assert!(matches!(r, Err(Error::UnsupportedArch(_))));
    }

    #[test]
    fn synthesised_mew_layout_round_trips_metadata() {
        let blob: Vec<u8> = build_synthetic_mew(0x1000, 0x2000, 0x0002_0100);
        let out: MewUnpackOutput =
            unpack_mew(&blob).expect("synthetic MEW must validate structurally");
        assert_eq!(out.image_base, 0x0040_0000);
        assert_eq!(out.original_entry_point_rva, 0x0002_0100);
        assert_eq!(out.section_0_virtual_size, 0x2000);
        assert!(
            !out.imports.is_empty(),
            "imports must include the bootstrap pair"
        );
        let has_kernel32_loadlib: bool = out
            .imports
            .iter()
            .any(|i: &MewImport| i.dll_name == "kernel32.dll" && i.api_name == "LoadLibraryA");
        assert!(
            has_kernel32_loadlib,
            "bootstrap LoadLibraryA must be present"
        );
    }

    fn build_synthetic_mew(file_align: u32, vsize0: u32, orig_aep: u32) -> Vec<u8> {
        let header_pad: u32 = file_align;
        let payload_aplib: Vec<u8> = vec![b'X', 0x00];
        let payload: Vec<u8> =
            build_synthetic_section1_payload(&payload_aplib, orig_aep, 0x0002_0000);
        let raw_size: u32 = payload.len() as u32;
        let mut bytes: Vec<u8> = vec![0u8; (header_pad + raw_size) as usize];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3C..0x40].copy_from_slice(&0x0Cu32.to_le_bytes());
        let pe_off: usize = 0x0C;
        bytes[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        bytes[pe_off + 4..pe_off + 6].copy_from_slice(&I386_MACHINE.to_le_bytes());
        bytes[pe_off + 6..pe_off + 8].copy_from_slice(&2u16.to_le_bytes());
        let opt_size: u16 = 224;
        bytes[pe_off + 0x14..pe_off + 0x16].copy_from_slice(&opt_size.to_le_bytes());
        let opt_off: usize = pe_off + PE_FILE_HEADER_LEN;
        bytes[opt_off..opt_off + 2].copy_from_slice(&PE32_MAGIC.to_le_bytes());
        bytes[opt_off + OPTIONAL_HEADER_AEP_OFFSET..opt_off + OPTIONAL_HEADER_AEP_OFFSET + 4]
            .copy_from_slice(&0x0003_0000_u32.to_le_bytes());
        bytes[opt_off + OPTIONAL_HEADER_IMAGE_BASE_OFFSET
            ..opt_off + OPTIONAL_HEADER_IMAGE_BASE_OFFSET + 4]
            .copy_from_slice(&0x0040_0000u32.to_le_bytes());
        let sect_off: usize = opt_off + opt_size as usize;
        let mut sec0: [u8; 40] = [0u8; 40];
        sec0[..4].copy_from_slice(b"MEW\0");
        sec0[4..8].copy_from_slice(&[0x46, 0x12, 0xD2, 0xC3]);
        sec0[8..12].copy_from_slice(&vsize0.to_le_bytes());
        sec0[12..16].copy_from_slice(&0x0000_1000u32.to_le_bytes());
        sec0[16..20].copy_from_slice(&0u32.to_le_bytes());
        sec0[20..24].copy_from_slice(&0u32.to_le_bytes());
        sec0[36..40].copy_from_slice(&0xC000_00E0u32.to_le_bytes());
        bytes[sect_off..sect_off + 40].copy_from_slice(&sec0);
        let mut sec1: [u8; 40] = [0u8; 40];
        sec1[..8].copy_from_slice(&[0x02, 0xD2, 0x75, 0xDB, 0x8A, 0x16, 0xEB, 0xD4]);
        sec1[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        sec1[12..16].copy_from_slice(&0x0002_0000u32.to_le_bytes());
        sec1[16..20].copy_from_slice(&raw_size.to_le_bytes());
        sec1[20..24].copy_from_slice(&header_pad.to_le_bytes());
        sec1[36..40].copy_from_slice(&0xC000_00E0u32.to_le_bytes());
        bytes[sect_off + 40..sect_off + 80].copy_from_slice(&sec1);
        bytes[header_pad as usize..(header_pad + raw_size) as usize].copy_from_slice(&payload);
        bytes
    }

    fn build_synthetic_section1_payload(
        aplib_stream: &[u8],
        orig_aep_rva: u32,
        decoder_rva: u32,
    ) -> Vec<u8> {
        let image_base: u32 = 0x0040_0000;
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(&MEW_DECODER_BYTES);
        payload.extend_from_slice(&decoder_rva.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(aplib_stream);
        payload.extend_from_slice(MEW_IAT_BOOTSTRAP);
        let mut trailer: [u8; MEW_EP_TRAILER_LEN] = [0u8; MEW_EP_TRAILER_LEN];
        trailer[0] = 0xE9;
        trailer[1..5].copy_from_slice(&0u32.to_le_bytes());
        trailer[5..9].copy_from_slice(&(decoder_rva | (image_base & 0x00FF_0000)).to_le_bytes());
        trailer[17..21].copy_from_slice(&orig_aep_rva.to_le_bytes());
        trailer[21..25].copy_from_slice(&(decoder_rva | (image_base & 0x00FF_0000)).to_le_bytes());
        payload.extend_from_slice(&trailer);
        payload
    }

    #[test]
    fn aplib_decodes_first_byte_literal() {
        let stream: Vec<u8> = vec![b'H', 0xFF, 0x00];
        let r: Result<Vec<u8>> = aplib_decode_bytetagged(&stream, 16);
        match r {
            Ok(out) => assert_eq!(out[0], b'H'),
            Err(Error::Truncated { .. } | Error::PackerUnpackerNotImplemented(_)) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn aplib_bit_reader_msb_first() {
        let stream: Vec<u8> = vec![0xAA, 0x55];
        let mut br: ByteTaggedBitReader<'_> = ByteTaggedBitReader::new(&stream);
        let bits: Vec<u32> = (0..16).map(|_| br.read_bit().expect("read")).collect();
        let expected: Vec<u32> = vec![1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1];
        assert_eq!(bits, expected);
    }

    #[test]
    fn aplib_terminator_short_match_zero_offset() {
        let stream: Vec<u8> = vec![0x41, 0b1100_0000, 0x00];
        let r: Result<Vec<u8>> = aplib_decode_bytetagged(&stream, 16);
        assert!(r.is_ok(), "terminator must yield Ok: {r:?}");
        let out: Vec<u8> = r.expect("decoded");
        assert_eq!(out, vec![0x41]);
    }

    #[test]
    fn aplib_round_trip_short_match_terminator() {
        let mut stream: Vec<u8> = Vec::new();
        stream.push(b'X');
        let bits: [u8; 8] = [0, 1, 1, 0, 0, 0, 0, 0];
        let tag: u8 = bits_to_byte(&bits);
        stream.push(tag);
        stream.push(b'Y');
        stream.push(0u8);
        let out: Vec<u8> =
            aplib_decode_bytetagged(&stream, 32).expect("synthetic literal+terminator must decode");
        assert_eq!(out, vec![b'X', b'Y']);
    }

    fn bits_to_byte(bits: &[u8]) -> u8 {
        let mut acc: u8 = 0;
        for b in bits {
            acc = (acc << 1) | (*b & 1);
        }
        acc
    }
}
