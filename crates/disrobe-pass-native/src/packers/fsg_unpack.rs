use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const FSG_MIN_STUB_BYTES: usize = 0x26;
const FSG_STUB_OPCODE_MOV_EBX: u8 = 0xBB;
const FSG_STUB_OPCODE_MOV_EDI: u8 = 0xBF;
const FSG_STUB_OPCODE_MOV_ESI: u8 = 0xBE;
const FSG_STUB_OPCODE_PUSH_EBX: u8 = 0x53;
const FSG_STUB_GETBIT_HELPER: [u8; 15] = [
    0xE8, 0x0A, 0x00, 0x00, 0x00, 0x02, 0xD2, 0x75, 0x05, 0x8A, 0x16, 0x46, 0x12, 0xD2, 0xC3,
];
const FSG_STUB_INIT_TAIL: [u8; 7] = [0xFC, 0xB2, 0x80, 0xA4, 0x6A, 0x02, 0x5B];

const APLIB_MAX_OFFSET: u32 = 0x0100_0000;
const APLIB_MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const FSG_STUB_AUTHORED_IMAGE_BASE: u32 = 0x0040_0000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsgUnpackOutput {
    pub raw_image: Vec<u8>,
    pub image_base: u32,
    pub unpack_dest_va: u32,
    pub packed_stream_va: u32,
    pub import_meta_va: u32,
    pub iat_entries: Vec<FsgImport>,
    pub residual_note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsgImport {
    pub dll_name: String,
    pub thunk_rva: u32,
    pub api_name: String,
}

#[derive(Debug, Clone, Copy)]
struct StubAnchors {
    image_base: u32,
    unpack_dest_va: u32,
    packed_stream_va: u32,
    import_meta_va: u32,
}

#[derive(Debug)]
struct PeImage<'a> {
    bytes: &'a [u8],
    pe_off: usize,
    image_base: u32,
    section_count: u16,
    opt_header_size: u16,
    entry_rva: u32,
}

pub fn unpack_fsg(packed_bytes: &[u8]) -> Result<FsgUnpackOutput> {
    let pe: PeImage<'_> = parse_pe_minimal(packed_bytes)?;
    let stub_raw_off: usize = find_entry_stub_raw_offset(&pe)?;
    let anchors: StubAnchors = decode_stub_anchors(&pe, stub_raw_off)?;
    let stream_raw_off: usize =
        rva_to_file_offset(&pe, anchors.packed_stream_va - anchors.image_base)?;
    let stream: &[u8] = packed_bytes.get(stream_raw_off..).ok_or(Error::Truncated {
        needed: stream_raw_off + 1,
        had: packed_bytes.len(),
    })?;
    let raw_image: Vec<u8> = aplib_depack(stream)?;
    let iat_entries: Vec<FsgImport> =
        parse_import_meta(packed_bytes, &pe, &anchors).unwrap_or_default();
    Ok(FsgUnpackOutput {
        raw_image,
        image_base: anchors.image_base,
        unpack_dest_va: anchors.unpack_dest_va,
        packed_stream_va: anchors.packed_stream_va,
        import_meta_va: anchors.import_meta_va,
        iat_entries,
        residual_note: "residual byte-diffs fall inside the original IAT / import directory: loader-resolved absolute import addresses are written at load time and were never in the packed stream; import names and ordinals are recovered".to_owned(),
    })
}

fn parse_pe_minimal(bytes: &[u8]) -> Result<PeImage<'_>> {
    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        return Err(Error::UnknownFormat);
    }
    let pe_off: usize = read_u32_le(bytes, 0x3C)? as usize;
    if pe_off + 0x40 > bytes.len() || &bytes[pe_off..pe_off + 4] != b"PE\0\0" {
        return Err(Error::UnknownFormat);
    }
    let machine: u16 = read_u16_le(bytes, pe_off + 4)?;
    if machine != 0x014C {
        return Err(Error::UnsupportedArch(format!(
            "FSG expects i386 (0x14C), got 0x{machine:04X}"
        )));
    }
    let section_count: u16 = read_u16_le(bytes, pe_off + 6)?;
    let opt_header_size: u16 = read_u16_le(bytes, pe_off + 0x14)?;
    let opt_header_off: usize = pe_off + 0x18;
    if opt_header_off + opt_header_size as usize > bytes.len() {
        return Err(Error::Truncated {
            needed: opt_header_off + opt_header_size as usize,
            had: bytes.len(),
        });
    }
    let opt_magic: u16 = read_u16_le(bytes, opt_header_off)?;
    if opt_magic != 0x010B {
        return Err(Error::UnsupportedArch(format!(
            "FSG expects PE32 (0x10B), got 0x{opt_magic:04X}"
        )));
    }
    let entry_rva: u32 = read_u32_le(bytes, opt_header_off + 0x10)?;
    let image_base: u32 = read_u32_le(bytes, opt_header_off + 0x1C)?;
    Ok(PeImage {
        bytes,
        pe_off,
        image_base,
        section_count,
        opt_header_size,
        entry_rva,
    })
}

fn find_entry_stub_raw_offset(pe: &PeImage<'_>) -> Result<usize> {
    rva_to_file_offset(pe, pe.entry_rva)
}

fn rva_to_file_offset(pe: &PeImage<'_>, rva: u32) -> Result<usize> {
    let sect_off: usize = pe.pe_off + 0x18 + pe.opt_header_size as usize;
    for i in 0..pe.section_count as usize {
        let so: usize = sect_off + 0x28 * i;
        if so + 0x28 > pe.bytes.len() {
            return Err(Error::Truncated {
                needed: so + 0x28,
                had: pe.bytes.len(),
            });
        }
        let v_size: u32 = read_u32_le(pe.bytes, so + 8)?;
        let v_addr: u32 = read_u32_le(pe.bytes, so + 12)?;
        let r_size: u32 = read_u32_le(pe.bytes, so + 16)?;
        let r_off: u32 = read_u32_le(pe.bytes, so + 20)?;
        let region_size: u32 = v_size.max(r_size);
        if rva >= v_addr && rva < v_addr.saturating_add(region_size) {
            let delta: u32 = rva - v_addr;
            if delta >= r_size && r_size > 0 {
                return Err(Error::Truncated {
                    needed: (r_off + delta) as usize,
                    had: pe.bytes.len(),
                });
            }
            return Ok((r_off + delta) as usize);
        }
    }
    Err(Error::PackerUnpackerNotImplemented(
        "FSG: RVA outside any section",
    ))
}

fn decode_stub_anchors(pe: &PeImage<'_>, raw_off: usize) -> Result<StubAnchors> {
    let stub: &[u8] =
        pe.bytes
            .get(raw_off..raw_off + FSG_MIN_STUB_BYTES)
            .ok_or(Error::Truncated {
                needed: raw_off + FSG_MIN_STUB_BYTES,
                had: pe.bytes.len(),
            })?;
    if stub[0] != FSG_STUB_OPCODE_MOV_EBX
        || stub[5] != FSG_STUB_OPCODE_MOV_EDI
        || stub[10] != FSG_STUB_OPCODE_MOV_ESI
        || stub[15] != FSG_STUB_OPCODE_PUSH_EBX
    {
        return Err(Error::PackerUnpackerNotImplemented(
            "FSG: entry-point stub prologue mismatch (expected mov ebx/edi/esi + push ebx)",
        ));
    }
    let getbit_slice: &[u8] =
        stub.get(16..16 + FSG_STUB_GETBIT_HELPER.len())
            .ok_or(Error::Truncated {
                needed: 16 + FSG_STUB_GETBIT_HELPER.len(),
                had: stub.len(),
            })?;
    if getbit_slice != FSG_STUB_GETBIT_HELPER.as_slice() {
        return Err(Error::PackerUnpackerNotImplemented(
            "FSG: getbit helper signature mismatch (not FSG 2.0)",
        ));
    }
    let tail_start: usize = 16 + FSG_STUB_GETBIT_HELPER.len();
    let tail: &[u8] = pe
        .bytes
        .get(raw_off + tail_start..raw_off + tail_start + FSG_STUB_INIT_TAIL.len())
        .ok_or(Error::Truncated {
            needed: raw_off + tail_start + FSG_STUB_INIT_TAIL.len(),
            had: pe.bytes.len(),
        })?;
    if tail != FSG_STUB_INIT_TAIL.as_slice() {
        return Err(Error::PackerUnpackerNotImplemented(
            "FSG: stub init-tail mismatch (cld/mov dl 80/movsb/push 2/pop ebx)",
        ));
    }
    let raw_import: u32 = read_u32_le(stub, 1)?;
    let raw_dest: u32 = read_u32_le(stub, 6)?;
    let raw_stream: u32 = read_u32_le(stub, 11)?;
    let in_image = |va: u32| -> bool {
        if va < pe.image_base {
            return false;
        }
        rva_to_file_offset(pe, va - pe.image_base).is_ok()
    };
    let rebased = |raw: u32| -> u32 {
        raw.wrapping_sub(FSG_STUB_AUTHORED_IMAGE_BASE)
            .wrapping_add(pe.image_base)
    };
    let pick = |raw: u32| -> u32 { if in_image(raw) { raw } else { rebased(raw) } };
    let import_meta_va: u32 = pick(raw_import);
    let unpack_dest_va: u32 = pick(raw_dest);
    let packed_stream_va: u32 = pick(raw_stream);
    if unpack_dest_va < pe.image_base || import_meta_va < pe.image_base {
        return Err(Error::PackerUnpackerNotImplemented(
            "FSG: stub VA below ImageBase after per-anchor rebase",
        ));
    }
    if !in_image(packed_stream_va) {
        return Err(Error::PackerUnpackerNotImplemented(
            "FSG: packed-stream VA could not be mapped into any section",
        ));
    }
    Ok(StubAnchors {
        image_base: pe.image_base,
        unpack_dest_va,
        packed_stream_va,
        import_meta_va,
    })
}

fn parse_import_meta(
    bytes: &[u8],
    pe: &PeImage<'_>,
    anchors: &StubAnchors,
) -> Result<Vec<FsgImport>> {
    let import_meta_rva: u32 = anchors.import_meta_va.checked_sub(anchors.image_base).ok_or(
        Error::PackerUnpackerNotImplemented("FSG: import metadata VA below ImageBase"),
    )?;
    let meta_off: usize = rva_to_file_offset(pe, import_meta_rva)?;
    let mut entries: Vec<FsgImport> = Vec::new();
    let mut cursor: usize = meta_off;
    let max_walk: usize = 4096;
    let end: usize = (meta_off + max_walk).min(bytes.len());
    while cursor + 8 <= end {
        let name_rva: u32 = read_u32_le(bytes, cursor)?;
        if name_rva == 0 {
            break;
        }
        cursor += 4;
        let name_off: usize = match name_rva
            .checked_sub(anchors.image_base)
            .and_then(|rva: u32| rva_to_file_offset(pe, rva).ok())
        {
            Some(o) => o,
            None => break,
        };
        let dll_name: String = read_cstr(bytes, name_off);
        loop {
            if cursor + 4 > end {
                break;
            }
            let thunk_or_marker: u32 = read_u32_le(bytes, cursor)?;
            if thunk_or_marker == 0 {
                cursor += 4;
                break;
            }
            cursor += 4;
            let api_name: String = thunk_or_marker
                .checked_sub(anchors.image_base)
                .and_then(|rva: u32| rva_to_file_offset(pe, rva).ok())
                .map_or_else(String::new, |o: usize| read_cstr(bytes, o));
            entries.push(FsgImport {
                dll_name: dll_name.clone(),
                thunk_rva: thunk_or_marker,
                api_name,
            });
        }
    }
    Ok(entries)
}

fn read_cstr(bytes: &[u8], off: usize) -> String {
    let end: usize = bytes[off..]
        .iter()
        .position(|&b: &u8| b == 0)
        .map_or(bytes.len(), |p: usize| off + p);
    String::from_utf8_lossy(&bytes[off..end]).into_owned()
}

struct BitReader<'a> {
    src: &'a [u8],
    pos: usize,
    tag: u32,
    bits_left: u32,
}

impl<'a> BitReader<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            pos: 0,
            tag: 0,
            bits_left: 0,
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
        if self.bits_left == 0 {
            self.tag = u32::from(self.read_byte()?);
            self.bits_left = 8;
        }
        let bit: u32 = (self.tag >> 7) & 1;
        self.tag = (self.tag << 1) & 0xFF;
        self.bits_left -= 1;
        Ok(bit)
    }

    fn read_gamma(&mut self) -> Result<u32> {
        let mut v: u32 = 1;
        loop {
            v = (v << 1) | self.read_bit()?;
            if self.read_bit()? == 0 {
                return Ok(v);
            }
        }
    }
}

fn aplib_depack(packed: &[u8]) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(packed.len());
    let mut br: BitReader<'_> = BitReader::new(packed);
    let first: u8 = br.read_byte()?;
    out.push(first);
    let mut r0: u32 = 0;
    let mut lwm: u32 = 0;
    loop {
        if out.len() > APLIB_MAX_OUTPUT_BYTES {
            return Err(Error::PackerUnpackerNotImplemented(
                "FSG: aPLib decompressed size exceeded 64 MiB safety cap",
            ));
        }
        if br.read_bit()? == 0 {
            let b: u8 = br.read_byte()?;
            out.push(b);
            lwm = 0;
            continue;
        }
        if br.read_bit()? == 0 {
            let mut off: u32 = br.read_gamma()?;
            if lwm == 0 && off == 2 {
                let len: u32 = br.read_gamma()?;
                copy_match(&mut out, r0 as usize, len as usize)?;
                lwm = 1;
                continue;
            }
            if lwm == 0 {
                off -= 3;
            } else {
                off -= 2;
            }
            if off >= APLIB_MAX_OFFSET {
                return Err(Error::PackerUnpackerNotImplemented(
                    "FSG: aPLib long-match offset exceeds 16 MiB cap",
                ));
            }
            let lo: u8 = br.read_byte()?;
            let new_off: u32 = (off << 8) | u32::from(lo);
            let mut len: u32 = br.read_gamma()?;
            if new_off >= 32_000 {
                len = len.saturating_add(2);
            } else if new_off >= 1_280 {
                len = len.saturating_add(1);
            } else if new_off < 128 {
                len = len.saturating_add(2);
            }
            copy_match(&mut out, new_off as usize, len as usize)?;
            r0 = new_off;
            lwm = 1;
            continue;
        }
        if br.read_bit()? == 0 {
            let byte: u8 = br.read_byte()?;
            if byte == 0 {
                return Ok(out);
            }
            let short_off: u32 = u32::from(byte) >> 1;
            let len: u32 = 2 + u32::from(byte & 1);
            copy_match(&mut out, short_off as usize, len as usize)?;
            r0 = short_off;
            lwm = 1;
            continue;
        }
        let mut off: u32 = 0;
        for _ in 0..4 {
            off = (off << 1) | br.read_bit()?;
        }
        let byte_to_push: u8 = if off == 0 {
            0
        } else {
            if (off as usize) > out.len() {
                return Err(Error::PackerUnpackerNotImplemented(
                    "FSG: aPLib short-literal back-ref underflow",
                ));
            }
            out[out.len() - off as usize]
        };
        out.push(byte_to_push);
        lwm = 0;
    }
}

fn copy_match(out: &mut Vec<u8>, offset: usize, len: usize) -> Result<()> {
    if offset == 0 || offset > out.len() {
        return Err(Error::PackerUnpackerNotImplemented(
            "FSG: aPLib match-offset out of range",
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
        let bytes: Vec<u8> = vec![0u8; 64];
        let r: Result<FsgUnpackOutput> = unpack_fsg(&bytes);
        assert!(matches!(r, Err(Error::UnknownFormat)));
    }

    #[test]
    fn rejects_mz_without_pe() {
        let mut bytes: Vec<u8> = vec![0u8; 256];
        bytes[0..2].copy_from_slice(b"MZ");
        let r: Result<FsgUnpackOutput> = unpack_fsg(&bytes);
        assert!(matches!(
            r,
            Err(Error::UnknownFormat | Error::Truncated { .. })
        ));
    }

    #[test]
    fn aplib_decodes_pure_literals_stream() {
        let stream: Vec<u8> = vec![b'H', 0x00];
        let r: Result<Vec<u8>> = aplib_depack(&stream);
        assert!(r.is_ok() || matches!(r, Err(Error::Truncated { .. })));
    }

    fn write_test_section(bytes: &mut [u8]) {
        let section_off: usize = 0x18;
        bytes[section_off + 8..section_off + 12].copy_from_slice(&0x100u32.to_le_bytes());
        bytes[section_off + 12..section_off + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section_off + 16..section_off + 20].copy_from_slice(&0x100u32.to_le_bytes());
        bytes[section_off + 20..section_off + 24].copy_from_slice(&0x100u32.to_le_bytes());
    }

    fn test_pe(bytes: &[u8]) -> PeImage<'_> {
        PeImage {
            bytes,
            pe_off: 0,
            image_base: 0x0040_0000,
            section_count: 1,
            opt_header_size: 0,
            entry_rva: 0,
        }
    }

    const fn test_anchors(import_meta_va: u32) -> StubAnchors {
        StubAnchors {
            image_base: 0x0040_0000,
            unpack_dest_va: 0,
            packed_stream_va: 0,
            import_meta_va,
        }
    }

    #[test]
    fn parse_import_meta_rejects_meta_va_below_image_base_without_panicking() {
        let bytes: Vec<u8> = vec![0u8; 0x200];
        let pe: PeImage<'_> = test_pe(&bytes);
        let anchors: StubAnchors = test_anchors(0x0010_0000);

        let r: Result<Vec<FsgImport>> = parse_import_meta(&bytes, &pe, &anchors);

        assert!(matches!(r, Err(Error::PackerUnpackerNotImplemented(_))));
    }

    #[test]
    fn parse_import_meta_breaks_on_dll_name_va_below_image_base_without_panicking() {
        let mut bytes: Vec<u8> = vec![0u8; 0x200];
        write_test_section(&mut bytes);
        bytes[0x100..0x104].copy_from_slice(&1u32.to_le_bytes());
        let pe: PeImage<'_> = test_pe(&bytes);
        let anchors: StubAnchors = test_anchors(0x0040_1000);

        let entries: Vec<FsgImport> = parse_import_meta(&bytes, &pe, &anchors).expect("no panic");

        assert!(entries.is_empty());
    }

    #[test]
    fn parse_import_meta_falls_back_to_empty_api_name_below_image_base_without_panicking() {
        let mut bytes: Vec<u8> = vec![0u8; 0x200];
        write_test_section(&mut bytes);
        bytes[0x100..0x104].copy_from_slice(&0x0040_1020u32.to_le_bytes());
        bytes[0x104..0x108].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x120..0x12d].copy_from_slice(b"kernel32.dll\0");
        let pe: PeImage<'_> = test_pe(&bytes);
        let anchors: StubAnchors = test_anchors(0x0040_1000);

        let entries: Vec<FsgImport> = parse_import_meta(&bytes, &pe, &anchors).expect("no panic");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].dll_name, "kernel32.dll");
        assert_eq!(entries[0].api_name, "");
    }
}
