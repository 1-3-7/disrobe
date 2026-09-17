#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::manual_range_contains
)]

use disrobe_pass_native::packers::yodas_emulated_unpack::{
    DESCRIPTOR_TABLE_TAG, YODAS_STUB_SECTION, YodasEmulatedUnpack, YodasSectionDescriptor,
    YodasStubProgress, unpack_yodas_emulated,
};

const IMAGE_BASE: u32 = 0x0040_0000;
const SECTION_ALIGNMENT: u32 = 0x1000;
const FILE_ALIGNMENT: u32 = 0x200;
const OPT_HDR_SIZE: u16 = 0xE0;
const PE32_MAGIC: u16 = 0x010B;
const MACHINE_I386: u16 = 0x014C;

const fn align_up(v: u32, a: u32) -> u32 {
    if a <= 1 {
        return v;
    }
    let mask: u32 = a - 1;
    (v.wrapping_add(mask)) & !mask
}

#[derive(Clone)]
struct OriginalSection {
    name: [u8; 8],
    virtual_address: u32,
    body: Vec<u8>,
    characteristics: u32,
}

fn original_section(name: &[u8], va: u32, body: Vec<u8>, ch: u32) -> OriginalSection {
    let mut n: [u8; 8] = [0u8; 8];
    n[..name.len().min(8)].copy_from_slice(&name[..name.len().min(8)]);
    OriginalSection {
        name: n,
        virtual_address: va,
        body,
        characteristics: ch,
    }
}

fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn build_pe(entry_rva: u32, sections: &[OriginalSection]) -> Vec<u8> {
    let e_lfanew: u32 = 0x80;
    let pe_off: usize = e_lfanew as usize;
    let coff_off: usize = pe_off + 4;
    let opt_off: usize = coff_off + 20;
    let sec_table: usize = opt_off + OPT_HDR_SIZE as usize;
    let headers_raw: u32 = align_up((sec_table + sections.len() * 40) as u32, FILE_ALIGNMENT);

    let mut raw_cursor: u32 = headers_raw;
    let mut raw_offs: Vec<u32> = Vec::with_capacity(sections.len());
    for s in sections {
        raw_offs.push(raw_cursor);
        raw_cursor += align_up(s.body.len() as u32, FILE_ALIGNMENT);
    }
    let total: usize = raw_cursor as usize;
    let mut buf: Vec<u8> = vec![0u8; total];

    buf[0..2].copy_from_slice(b"MZ");
    put_u32(&mut buf, 0x3C, e_lfanew);
    buf[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    put_u16(&mut buf, coff_off, MACHINE_I386);
    put_u16(&mut buf, coff_off + 2, sections.len() as u16);
    put_u16(&mut buf, coff_off + 16, OPT_HDR_SIZE);
    put_u16(&mut buf, coff_off + 18, 0x0102);

    put_u16(&mut buf, opt_off, PE32_MAGIC);
    put_u32(&mut buf, opt_off + 16, entry_rva);
    put_u32(&mut buf, opt_off + 28, IMAGE_BASE);
    put_u32(&mut buf, opt_off + 32, SECTION_ALIGNMENT);
    put_u32(&mut buf, opt_off + 36, FILE_ALIGNMENT);
    let size_of_image: u32 = sections
        .iter()
        .map(|s: &OriginalSection| {
            align_up(s.virtual_address + s.body.len() as u32, SECTION_ALIGNMENT)
        })
        .max()
        .unwrap_or(SECTION_ALIGNMENT)
        .max(align_up(headers_raw, SECTION_ALIGNMENT));
    put_u32(&mut buf, opt_off + 56, size_of_image);
    put_u32(&mut buf, opt_off + 60, headers_raw);
    put_u32(&mut buf, opt_off + 92, 16);

    for (i, s) in sections.iter().enumerate() {
        let off: usize = sec_table + i * 40;
        buf[off..off + 8].copy_from_slice(&s.name);
        put_u32(&mut buf, off + 8, s.body.len() as u32);
        put_u32(&mut buf, off + 12, s.virtual_address);
        put_u32(
            &mut buf,
            off + 16,
            align_up(s.body.len() as u32, FILE_ALIGNMENT),
        );
        put_u32(&mut buf, off + 20, raw_offs[i]);
        put_u32(&mut buf, off + 36, s.characteristics);
        let ro: usize = raw_offs[i] as usize;
        buf[ro..ro + s.body.len()].copy_from_slice(&s.body);
    }
    buf
}

const fn long_match_gamma(length: usize, offset: usize) -> Option<u32> {
    let mut encoded: i64 = length as i64;
    if offset >= 32000 {
        encoded -= 1;
    }
    if offset >= 1280 {
        encoded -= 1;
    }
    if offset < 128 {
        encoded -= 2;
    }
    if encoded >= 2 {
        Some(encoded as u32)
    } else {
        None
    }
}

fn aplib_compress(input: &[u8]) -> Vec<u8> {
    let mut out: BitWriter = BitWriter::new();
    if input.is_empty() {
        return out.finish();
    }
    out.push_byte(input[0]);
    let mut pos: usize = 1;
    let mut lwm: u32 = 0;
    while pos < input.len() {
        let (match_off, match_len): (usize, usize) = longest_match(input, pos);
        let long_gamma: Option<u32> = if match_len >= 2 {
            long_match_gamma(match_len, match_off)
        } else {
            None
        };
        if let Some(len_gamma) = long_gamma {
            let offset: usize = match_off;
            out.push_bit(1);
            out.push_bit(0);
            let high: u32 = if lwm == 0 {
                (offset >> 8) as u32 + 3
            } else {
                (offset >> 8) as u32 + 2
            };
            out.push_gamma(high);
            out.push_byte((offset & 0xFF) as u8);
            out.push_gamma(len_gamma);
            pos += match_len;
            lwm = 1;
            continue;
        }
        if let Some((short_off, length)) = short_match(input, pos) {
            out.push_bit(1);
            out.push_bit(1);
            out.push_bit(0);
            let encoded: u8 = ((short_off as u8) << 1) | ((length - 2) as u8);
            out.push_byte(encoded);
            pos += length;
            lwm = 1;
            continue;
        }
        out.push_bit(0);
        out.push_byte(input[pos]);
        pos += 1;
        lwm = 0;
    }
    out.push_bit(1);
    out.push_bit(1);
    out.push_bit(0);
    out.push_byte(0);
    out.finish()
}

fn longest_match(input: &[u8], pos: usize) -> (usize, usize) {
    let max_off: usize = pos.min(0x1FFF_FFFF);
    let max_len: usize = (input.len() - pos).min(2000);
    let mut best_off: usize = 0;
    let mut best_len: usize = 0;
    let mut off: usize = 3;
    while off <= max_off {
        let start: usize = pos - off;
        let mut l: usize = 0;
        while l < max_len && input[start + l] == input[pos + l] {
            l += 1;
        }
        if l > best_len {
            best_len = l;
            best_off = off;
            if l >= max_len {
                break;
            }
        }
        off += 1;
    }
    (best_off, best_len)
}

fn matches_at(input: &[u8], pos: usize, off: usize, len: usize) -> bool {
    if pos + len > input.len() {
        return false;
    }
    (0..len).all(|k: usize| input[pos + k] == input[pos - off + k])
}

fn short_match(input: &[u8], pos: usize) -> Option<(usize, usize)> {
    let max_off: usize = pos.min(127);
    let mut best: Option<(usize, usize)> = None;
    for off in 1..=max_off {
        if matches_at(input, pos, off, 3) {
            return Some((off, 3));
        }
        if best.is_none() && matches_at(input, pos, off, 2) {
            best = Some((off, 2));
        }
    }
    best
}

struct BitWriter {
    out: Vec<u8>,
    tag_pos: usize,
    bit: u32,
    tag: u8,
}

impl BitWriter {
    const fn new() -> Self {
        Self {
            out: Vec::new(),
            tag_pos: usize::MAX,
            bit: 0,
            tag: 0,
        }
    }

    fn push_bit(&mut self, b: u32) {
        if self.bit == 0 {
            self.flush_tag();
            self.tag_pos = self.out.len();
            self.out.push(0);
            self.tag = 0;
            self.bit = 8;
        }
        self.bit -= 1;
        if b != 0 {
            self.tag |= 1u8 << self.bit;
        }
        if self.bit == 0 {
            self.flush_tag();
        }
    }

    fn flush_tag(&mut self) {
        if self.tag_pos != usize::MAX {
            self.out[self.tag_pos] = self.tag;
            self.tag_pos = usize::MAX;
        }
    }

    fn push_byte(&mut self, b: u8) {
        self.out.push(b);
    }

    fn push_gamma(&mut self, value: u32) {
        let bits: u32 = value.ilog2();
        let mut i: i32 = (bits - 1) as i32;
        while i >= 0 {
            self.push_bit((value >> i) & 1);
            if i > 0 {
                self.push_bit(1);
            } else {
                self.push_bit(0);
            }
            i -= 1;
        }
    }

    fn finish(mut self) -> Vec<u8> {
        self.flush_tag();
        self.out
    }
}

fn build_yodas_stub(
    stub_rva: u32,
    oep_rva: u32,
    descriptors: &[YodasSectionDescriptor],
) -> Vec<u8> {
    let mut stub: Vec<u8> = Vec::new();
    stub.extend_from_slice(b"yC2.0\0");
    let pushad_off: u32 = stub.len() as u32;
    stub.push(0x60);
    stub.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
    let pop_target_off: u32 = stub.len() as u32;
    stub.push(0x5D);
    let delta: u32 = pop_target_off - pushad_off;
    stub.extend_from_slice(&[0x81, 0xED]);
    stub.extend_from_slice(&delta.to_le_bytes());
    stub.extend_from_slice(&[0x8B, 0xC5]);
    stub.extend_from_slice(&[0x2D]);
    stub.extend_from_slice(&(stub_rva + pushad_off).to_le_bytes());
    stub.extend_from_slice(&[0x05]);
    stub.extend_from_slice(&oep_rva.to_le_bytes());
    stub.extend_from_slice(&[0xFF, 0xE0]);
    stub.push(0xCC);
    stub.push(0xCC);
    stub.push(0xCC);

    stub.extend_from_slice(&DESCRIPTOR_TABLE_TAG);
    for d in descriptors {
        stub.extend_from_slice(&d.dest_rva.to_le_bytes());
        stub.extend_from_slice(&d.src_rva.to_le_bytes());
        stub.extend_from_slice(&d.packed_len.to_le_bytes());
        stub.extend_from_slice(&d.unpacked_len.to_le_bytes());
    }
    stub.extend_from_slice(&[0u8; 16]);
    stub
}

struct PackResult {
    packed: Vec<u8>,
    original: Vec<u8>,
}

fn pack_like_yodas(text: &[u8], rdata: &[u8], rsrc: &[u8], oep_offset_in_text: u32) -> PackResult {
    let text_va: u32 = 0x1000;
    let rdata_va: u32 = align_up(text_va + text.len() as u32, SECTION_ALIGNMENT);
    let rsrc_va: u32 = align_up(rdata_va + rdata.len() as u32, SECTION_ALIGNMENT);
    let oep_rva: u32 = text_va + oep_offset_in_text;

    let original_sections: Vec<OriginalSection> = vec![
        original_section(b".text", text_va, text.to_vec(), 0x6000_0020),
        original_section(b".rdata", rdata_va, rdata.to_vec(), 0x4000_0040),
        original_section(b".rsrc", rsrc_va, rsrc.to_vec(), 0x4000_0040),
    ];
    let original: Vec<u8> = build_pe(oep_rva, &original_sections);

    let text_packed: Vec<u8> = aplib_compress(text);
    let rdata_packed: Vec<u8> = aplib_compress(rdata);

    let stub_va: u32 = align_up(rsrc_va + rsrc.len() as u32, SECTION_ALIGNMENT);

    let payload_start_off: u32 = 0x100;
    let text_src_rva: u32 = stub_va + payload_start_off;
    let rdata_src_rva: u32 = text_src_rva + align_up(text_packed.len() as u32, 16);

    let descriptors: Vec<YodasSectionDescriptor> = vec![
        YodasSectionDescriptor {
            dest_rva: text_va,
            src_rva: text_src_rva,
            packed_len: text_packed.len() as u32,
            unpacked_len: text.len() as u32,
        },
        YodasSectionDescriptor {
            dest_rva: rdata_va,
            src_rva: rdata_src_rva,
            packed_len: rdata_packed.len() as u32,
            unpacked_len: rdata.len() as u32,
        },
    ];

    let stub_code: Vec<u8> = build_yodas_stub(stub_va, oep_rva, &descriptors);
    assert!(
        (stub_code.len() as u32) < payload_start_off,
        "stub code+table must fit before the compressed payload area"
    );

    let mut stub_body: Vec<u8> = vec![0u8; payload_start_off as usize];
    stub_body[..stub_code.len()].copy_from_slice(&stub_code);
    let text_src_off: usize = payload_start_off as usize;
    stub_body.resize(text_src_off + text_packed.len(), 0);
    stub_body[text_src_off..text_src_off + text_packed.len()].copy_from_slice(&text_packed);
    let rdata_src_off: usize = (rdata_src_rva - stub_va) as usize;
    if stub_body.len() < rdata_src_off + rdata_packed.len() {
        stub_body.resize(rdata_src_off + rdata_packed.len(), 0);
    }
    stub_body[rdata_src_off..rdata_src_off + rdata_packed.len()].copy_from_slice(&rdata_packed);

    let packed_text: Vec<u8> = vec![0u8; text.len()];
    let packed_rdata: Vec<u8> = vec![0u8; rdata.len()];

    let packed_sections: Vec<OriginalSection> = vec![
        original_section(b".text", text_va, packed_text, 0x6000_0020),
        original_section(b".rdata", rdata_va, packed_rdata, 0x4000_0040),
        original_section(b".rsrc", rsrc_va, rsrc.to_vec(), 0x4000_0040),
        original_section(YODAS_STUB_SECTION, stub_va, stub_body, 0xE000_0060),
    ];
    let packed_entry: u32 = stub_va + (b"yC2.0\0".len() as u32);
    let packed: Vec<u8> = build_pe(packed_entry, &packed_sections);

    PackResult { packed, original }
}

fn section_bytes<'a>(image: &'a [u8], name: &[u8]) -> &'a [u8] {
    use disrobe_pass_native::packers::pe_sections::{PeImage, parse_pe_image};
    let img: PeImage = parse_pe_image(image).expect("pe");
    let sec = img
        .sections
        .iter()
        .find(|s| s.name_trimmed() == name)
        .expect("section present");
    let dst: usize = sec.virtual_address as usize;
    let len: usize = sec.virtual_size as usize;
    &image[dst..dst + len.min(image.len() - dst)]
}

fn section_bytes_on_disk<'a>(image: &'a [u8], name: &[u8]) -> &'a [u8] {
    use disrobe_pass_native::packers::pe_sections::{PeImage, parse_pe_image};
    let img: PeImage = parse_pe_image(image).expect("pe");
    let sec = img
        .sections
        .iter()
        .find(|s| s.name_trimmed() == name)
        .expect("section present");
    let (start, end): (usize, usize) = sec
        .raw_range(image.len())
        .expect("section raw range in bounds");
    &image[start..end]
}

fn sample_text() -> Vec<u8> {
    let mut t: Vec<u8> = Vec::new();
    let block: &[u8] = b"MOV EAX, EBX; PUSH ECX; CALL 0x401000; RET; ";
    for i in 0..40u32 {
        t.extend_from_slice(block);
        t.extend_from_slice(&i.to_le_bytes());
    }
    t.extend_from_slice(&[0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x40, 0x90, 0x90]);
    t
}

fn sample_rdata() -> Vec<u8> {
    let mut d: Vec<u8> = Vec::new();
    for s in [
        "kernel32.dll",
        "GetProcAddress",
        "LoadLibraryA",
        "ExitProcess",
    ] {
        d.extend_from_slice(s.as_bytes());
        d.push(0);
    }
    d.extend_from_slice(&[0xAA; 64]);
    d.extend_from_slice(b"the quick brown fox the quick brown fox the quick brown fox");
    d
}

fn sample_rsrc() -> Vec<u8> {
    (0..256u32)
        .map(|i: u32| (i.wrapping_mul(31) & 0xFF) as u8)
        .collect()
}

struct ReferenceApDepacker<'a> {
    src: &'a [u8],
    pos: usize,
    tag: u32,
    bits_left: u32,
    out: Vec<u8>,
}

impl<'a> ReferenceApDepacker<'a> {
    const fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            pos: 0,
            tag: 0,
            bits_left: 0,
            out: Vec::new(),
        }
    }

    fn next_byte(&mut self) -> Option<u8> {
        let b: u8 = *self.src.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn next_bit(&mut self) -> Option<u32> {
        if self.bits_left == 0 {
            self.tag = u32::from(self.next_byte()?);
            self.bits_left = 8;
        }
        let bit: u32 = (self.tag >> 7) & 1;
        self.tag = (self.tag << 1) & 0xFF;
        self.bits_left -= 1;
        Some(bit)
    }

    fn next_gamma(&mut self) -> Option<u32> {
        let mut value: u32 = 1;
        loop {
            value = (value << 1) | self.next_bit()?;
            if self.next_bit()? == 0 {
                return Some(value);
            }
        }
    }

    fn copy_match(&mut self, offset: usize, length: usize) -> Option<()> {
        if offset == 0 || offset > self.out.len() {
            return None;
        }
        for _ in 0..length {
            let b: u8 = self.out[self.out.len() - offset];
            self.out.push(b);
        }
        Some(())
    }

    fn depack(mut self) -> Option<Vec<u8>> {
        let first: u8 = self.next_byte()?;
        self.out.push(first);
        let mut last_offset: usize = 0;
        let mut prev_was_match: bool = false;
        loop {
            if self.next_bit()? == 0 {
                let literal: u8 = self.next_byte()?;
                self.out.push(literal);
                prev_was_match = false;
                continue;
            }
            if self.next_bit()? == 0 {
                let high: u32 = self.next_gamma()?;
                if !prev_was_match && high == 2 {
                    let length: u32 = self.next_gamma()?;
                    self.copy_match(last_offset, length as usize)?;
                    prev_was_match = true;
                    continue;
                }
                let high_part: u32 = high.checked_sub(if prev_was_match { 2 } else { 3 })?;
                let low: u32 = u32::from(self.next_byte()?);
                let offset: usize = ((high_part << 8) | low) as usize;
                let base: u32 = self.next_gamma()?;
                let length: u32 = if offset >= 32_000 {
                    base + 2
                } else if offset >= 1_280 {
                    base + 1
                } else if offset < 128 {
                    base + 2
                } else {
                    base
                };
                self.copy_match(offset, length as usize)?;
                last_offset = offset;
                prev_was_match = true;
                continue;
            }
            if self.next_bit()? == 0 {
                let encoded: u32 = u32::from(self.next_byte()?);
                let offset: usize = (encoded >> 1) as usize;
                if offset == 0 {
                    return Some(self.out);
                }
                let length: usize = 2 + (encoded & 1) as usize;
                self.copy_match(offset, length)?;
                last_offset = offset;
                prev_was_match = true;
                continue;
            }
            let mut offset: usize = 0;
            for _ in 0..4 {
                offset = (offset << 1) | self.next_bit()? as usize;
            }
            let byte: u8 = if offset == 0 {
                0
            } else {
                if offset > self.out.len() {
                    return None;
                }
                self.out[self.out.len() - offset]
            };
            self.out.push(byte);
            prev_was_match = false;
        }
    }
}

fn reference_ap_depack(packed: &[u8]) -> Option<Vec<u8>> {
    ReferenceApDepacker::new(packed).depack()
}

const EXTERNAL_APLIB_STREAM: [u8; 46] = [
    0x54, 0x00, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0xec, 0x62, 0x0e, 0x72, 0x6f, 0x77,
    0x6e, 0xce, 0x66, 0xae, 0x78, 0x80, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0xed, 0xe4, 0x76, 0x65, 0x75,
    0x72, 0x60, 0x74, 0x3f, 0x6c, 0x61, 0x7a, 0x79, 0xea, 0x64, 0xfe, 0x67, 0xc0, 0x00,
];

const EXTERNAL_APLIB_PLAINTEXT: &[u8] = b"The quick brown fox jumps over the lazy dog";

#[test]
fn aplib_decodes_external_appack_reference_stream() {
    use disrobe_pass_native::packers::aplib_decode_bytetagged;
    let decoded: Vec<u8> =
        aplib_decode_bytetagged(&EXTERNAL_APLIB_STREAM, EXTERNAL_APLIB_PLAINTEXT.len())
            .expect("disrobe must decode a real appack-produced aPLib stream");
    assert_eq!(
        decoded, EXTERNAL_APLIB_PLAINTEXT,
        "disrobe's aPLib decoder must reproduce the plaintext from a stream the real aPLib \
         appack tool emitted, not just round-trip its own encoder"
    );
    let reference: Vec<u8> = reference_ap_depack(&EXTERNAL_APLIB_STREAM)
        .expect("the spec reference depacker must also decode the external stream");
    assert_eq!(
        reference, EXTERNAL_APLIB_PLAINTEXT,
        "the in-test spec reference depacker must agree with the external appack stream, \
         proving it is not tuned only to disrobe's own encoder"
    );
}

#[test]
fn aplib_round_trip_self_authored() {
    use disrobe_pass_native::packers::aplib_decode_bytetagged;
    let cases: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"A".to_vec(),
        b"AAAAAAAAAAAAAAAAAAAA".to_vec(),
        b"the quick brown fox the quick brown fox the quick brown fox".to_vec(),
        sample_text(),
        sample_rdata(),
        sample_rsrc(),
        (0..4096u32).map(|i: u32| (i ^ (i >> 3)) as u8).collect(),
    ];
    for (i, original) in cases.iter().enumerate() {
        let packed: Vec<u8> = aplib_compress(original);
        if original.is_empty() {
            continue;
        }
        let decoded: Vec<u8> =
            aplib_decode_bytetagged(&packed, original.len()).expect("aplib decode");
        let reference: Vec<u8> = reference_ap_depack(&packed)
            .expect("independent aPLib reference must depack the stream");
        assert_eq!(
            &reference,
            original,
            "case {i}: independent aPLib reference depacker disagrees with the source ({} bytes); \
             disrobe's encoder emitted a stream a spec depacker cannot recover",
            original.len()
        );
        assert_eq!(
            &decoded,
            &reference,
            "case {i}: disrobe's aPLib decoder disagrees with the independent spec reference ({} bytes); \
             this is a real decoder bug",
            original.len()
        );
        assert_eq!(
            &decoded,
            original,
            "case {i}: aPLib round-trip must be byte-identical ({} bytes)",
            original.len()
        );
        assert!(
            packed.len() <= original.len() + original.len() / 8 + 16,
            "case {i}: aPLib stream must not blow up vs input"
        );
    }
}

#[test]
fn aplib_compresses_repetitive_input() {
    let original: Vec<u8> = vec![0x42u8; 8192];
    let packed: Vec<u8> = aplib_compress(&original);
    assert!(
        packed.len() < original.len() / 4,
        "highly repetitive input must compress materially: {} -> {}",
        original.len(),
        packed.len()
    );
}

#[test]
fn unpacks_text_byte_identical() {
    let text: Vec<u8> = sample_text();
    let rdata: Vec<u8> = sample_rdata();
    let rsrc: Vec<u8> = sample_rsrc();
    let oep_off: u32 = (text.len() as u32) - 8;
    let pr: PackResult = pack_like_yodas(&text, &rdata, &rsrc, oep_off);

    let packed_text: &[u8] = section_bytes_on_disk(&pr.packed, b".text");
    assert!(
        packed_text.iter().all(|b: &u8| *b == 0),
        "packed .text must carry no plaintext (it is aPLib-compressed in the .yC0 stub)",
    );

    let out: YodasEmulatedUnpack =
        unpack_yodas_emulated(&pr.packed, Some(&pr.original)).expect("unpack must succeed");

    assert!(
        out.has_yc2_marker,
        "yC2.0 marker must be detected in the stub"
    );
    assert_eq!(
        out.descriptors.len(),
        2,
        "two compressed sections must be discovered from the descriptor table"
    );

    match out.stub_progress {
        YodasStubProgress::ReachedOriginalEntry { oep_rva } => {
            assert_eq!(
                oep_rva,
                0x1000 + oep_off,
                "emulated stub must transfer to the true original entry point"
            );
        }
        YodasStubProgress::StalledInStub { final_rva, exit } => {
            panic!("stub stalled at rva=0x{final_rva:x} exit={exit}; expected OEP transfer");
        }
    }
    assert!(out.reached_oep());

    let rec_text: &[u8] = section_bytes(&out.recovered_memory_image, b".text");
    assert_eq!(
        rec_text,
        text.as_slice(),
        ".text must be recovered BYTE-IDENTICALLY to the authored original"
    );

    let rec_rdata: &[u8] = section_bytes(&out.recovered_memory_image, b".rdata");
    assert_eq!(
        rec_rdata,
        rdata.as_slice(),
        ".rdata must be recovered BYTE-IDENTICALLY to the authored original"
    );

    let content: f64 = out.content_recovery_pct.unwrap_or(0.0);
    assert!(
        (content - 100.0).abs() < f64::EPSILON,
        "content (.text/.rdata/.rsrc) recovery must be 100%, got {content:.4}%"
    );
}

#[test]
fn section_report_marks_text_byte_identical() {
    use disrobe_pass_native::packers::section_recovery::{GranuleRecovery, SectionRole};
    let text: Vec<u8> = sample_text();
    let rdata: Vec<u8> = sample_rdata();
    let rsrc: Vec<u8> = sample_rsrc();
    let pr: PackResult = pack_like_yodas(&text, &rdata, &rsrc, 0);
    let out: YodasEmulatedUnpack =
        unpack_yodas_emulated(&pr.packed, Some(&pr.original)).expect("unpack");
    let report = out.section_report.as_ref().expect("report");
    let text_row: &GranuleRecovery = report
        .sections
        .iter()
        .find(|s| s.name == ".text")
        .expect(".text row");
    assert_eq!(text_row.role, SectionRole::Content);
    assert!(
        text_row.is_byte_identical(),
        ".text row must be byte-identical: {}/{}",
        text_row.matching,
        text_row.compared
    );
    assert!(
        !report
            .mismatching_content_sections()
            .iter()
            .any(|s| s.name == ".text"),
        ".text must not appear in the mismatch list"
    );
}

#[test]
fn rejects_non_yodas_image() {
    let text: Vec<u8> = sample_text();
    let original: Vec<u8> = build_pe(
        0x1000,
        &[original_section(b".text", 0x1000, text, 0x6000_0020)],
    );
    let r = unpack_yodas_emulated(&original, None);
    assert!(
        r.is_err(),
        "an image with no .yC0 stub section must be rejected, never faked"
    );
}
