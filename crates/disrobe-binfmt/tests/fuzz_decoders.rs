#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_binfmt::containers::lha_dyn::{self, DynMethod};
use disrobe_binfmt::containers::wim::WimCompression;
use disrobe_binfmt::containers::{
    arc, arc_codec, arj, bare_stream, firmware, lha_huff, lz4_block, lzh, lzms, lzop, par2,
    rar_ppmd, rar_unpack3, rar_unpack5, stuffit, ucl, uzip, wim_codec, xalz,
};
use disrobe_binfmt::quota::ExtractionQuota;

const CAP: u64 = 8 * 1024 * 1024;

struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    const fn next_u64(&mut self) -> u64 {
        let mut x: u64 = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    const fn next_usize(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        (self.next_u64() % bound as u64) as usize
    }

    const fn next_byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }
}

fn magic_seed(magic: &[u8], body_len: usize, rng: &mut Xorshift64) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::with_capacity(magic.len() + body_len);
    v.extend_from_slice(magic);
    for _ in 0..body_len {
        v.push(rng.next_byte());
    }
    v
}

fn mutate(seed: &[u8], rng: &mut Xorshift64) -> Vec<u8> {
    let mut out: Vec<u8> = seed.to_vec();
    let kind: u64 = rng.next_u64() % 6;
    match kind {
        0 => {
            if !out.is_empty() {
                let idx: usize = rng.next_usize(out.len());
                out[idx] ^= 1u8 << rng.next_usize(8);
            }
        }
        1 => {
            if !out.is_empty() {
                let cut: usize = rng.next_usize(out.len());
                out.truncate(cut);
            }
        }
        2 => {
            let count: usize = rng.next_usize(out.len().max(1));
            for _ in 0..count {
                let idx: usize = rng.next_usize(out.len().max(1));
                if idx < out.len() {
                    out[idx] = rng.next_byte();
                }
            }
        }
        3 => {
            for b in &mut out {
                if rng.next_u64().trailing_zeros() >= 2 {
                    *b = 0xff;
                }
            }
        }
        4 => {
            for b in &mut out {
                if rng.next_u64().trailing_zeros() >= 2 {
                    *b = 0;
                }
            }
        }
        _ => {
            let len: usize = rng.next_usize(1024);
            out = (0..len).map(|_| rng.next_byte()).collect();
        }
    }
    out
}

fn exercise(bytes: &[u8]) {
    let _ = bare_stream::decompress_lzip(bytes, CAP);
    let _ = bare_stream::decompress_lz4(bytes, CAP);
    let _ = bare_stream::decompress_compress(bytes, CAP);
    let _ = bare_stream::decompress_gzip_members(bytes, CAP);
    let _ = bare_stream::decompress_bzip2(bytes, CAP);
    let _ = bare_stream::decompress_zstd(bytes, CAP);
    let _ = bare_stream::decompress_lzma_alone(bytes, CAP);
    let _ = bare_stream::decompress_brotli(bytes, CAP);
    let _ = bare_stream::decompress_lznt1(bytes, CAP);
    let _ = lzop::parse_lzop(bytes, CAP);
    let _ = xalz::parse_xalz(bytes, CAP);
    let _ = uzip::parse_uzip(bytes, CAP);
    let _ = lzh::parse_lzh(bytes, CAP);
    let _ = arc::parse_arc(bytes);
    let _ = arj::parse_arj(bytes);
    let _ = par2::parse_par2(bytes);
    let _ = stuffit::parse_classic(bytes);
    if let Some(kind) = firmware::detect_firmware(bytes) {
        let _ = firmware::extract_firmware(kind, bytes);
    }
}

#[test]
fn pure_random_inputs_never_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0xBADC_0FFE_E0DD_F00D);
    for _ in 0..6_000 {
        let len: usize = rng.next_usize(1024);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        exercise(&bytes);
    }
}

#[test]
fn magic_prefixed_inputs_reach_decoders() {
    let magics: [&[u8]; 9] = [
        b"LZIP\x01",
        &[0x04, 0x22, 0x4d, 0x18],
        &[0x1f, 0x9d, 0x90],
        &[0x1f, 0x8b, 0x08],
        b"BZh9",
        &[0x28, 0xb5, 0x2f, 0xfd],
        &[0x5d, 0x00, 0x00, 0x01, 0x00],
        b"\x89LZO\x00\r\n\x1a\n",
        b"XALZ",
    ];
    let mut rng: Xorshift64 = Xorshift64::new(0x0102_0304_0506_0708);
    for magic in magics {
        for _ in 0..4_000 {
            let body_len: usize = 8 + rng.next_usize(256);
            let seed: Vec<u8> = magic_seed(magic, body_len, &mut rng);
            let mutated: Vec<u8> = mutate(&seed, &mut rng);
            exercise(&mutated);
        }
    }
}

#[test]
fn lzw_compress_stream_does_not_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0x1f9d_1f9d_1f9d_1f9d);
    for _ in 0..20_000 {
        let mut bytes: Vec<u8> = vec![0x1f, 0x9d];
        bytes.push(0x80 | (9 + rng.next_usize(8)) as u8);
        let body_len: usize = rng.next_usize(512);
        for _ in 0..body_len {
            bytes.push(rng.next_byte());
        }
        let _ = bare_stream::decompress_compress(&bytes, CAP);
    }
}

#[test]
fn lznt1_chunks_do_not_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0x4c4e_5431_4c4e_5431);
    for _ in 0..20_000 {
        let len: usize = rng.next_usize(1024);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        let _ = bare_stream::decompress_lznt1(&bytes, CAP);
    }
}

#[test]
fn lha_dynamic_huffman_does_not_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0x4c48_4132_4c48_4133);
    let sizes: [u64; 6] = [0, 1, 16, 256, 4096, 65_536];
    for _ in 0..120_000 {
        let len: usize = rng.next_usize(320);
        let body: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        let size: u64 = sizes[rng.next_usize(sizes.len())];
        let method: DynMethod = if rng.next_u64() & 1 == 0 {
            DynMethod::Lh2
        } else {
            DynMethod::Lh3
        };
        let _ = lha_dyn::decode(method, &body, size);
    }
}

#[test]
fn rar_and_arc_hand_decoders_do_not_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0x5241_5232_4152_4333);
    let sizes: [u64; 6] = [0, 1, 16, 256, 4096, 65_536];
    let lhas: [lha_huff::LhaParams; 3] = [lha_huff::LH5, lha_huff::LH6, lha_huff::LH7];
    for _ in 0..120_000 {
        let len: usize = rng.next_usize(400);
        let body: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        let size: u64 = sizes[rng.next_usize(sizes.len())];
        let cap_u: usize = 4 * 1024 * 1024;
        match rng.next_u64() % 6 {
            0 => {
                let _ = rar_unpack3::unpack3(&body, size, CAP);
            }
            1 => {
                let _ = rar_unpack5::unpack5(&body, size, CAP);
            }
            2 => {
                let _ = rar_ppmd::unpack3_ppmd(&body, size, CAP);
            }
            3 => {
                let _ = arc_codec::un_rle(&body, cap_u);
            }
            4 => {
                let _ = arc_codec::un_crunch(&body, cap_u);
                let _ = arc_codec::un_squash(&body, cap_u);
                let _ = arc_codec::un_squeeze(&body, cap_u);
            }
            _ => {
                let lha: lha_huff::LhaParams = lhas[rng.next_usize(lhas.len())];
                let _ = lha_huff::decode(lha, &body, size as usize);
            }
        }
    }
}

#[test]
fn wim_and_stream_codecs_do_not_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0x57_494d_5f43_4f44);
    let sizes: [u64; 6] = [0, 1, 16, 256, 4096, 65_536];
    let chunks: [u32; 4] = [0, 1, 32_768, 0x8000_0000];
    let wcomp: [WimCompression; 4] = [
        WimCompression::Xpress,
        WimCompression::Lzx,
        WimCompression::Lzms,
        WimCompression::None,
    ];
    let nrv: [ucl::NrvVariant; 3] = [
        ucl::NrvVariant::Nrv2b,
        ucl::NrvVariant::Nrv2d,
        ucl::NrvVariant::Nrv2e,
    ];
    let quota: ExtractionQuota = ExtractionQuota::default();
    for _ in 0..120_000 {
        let len: usize = rng.next_usize(400);
        let body: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        let size: u64 = sizes[rng.next_usize(sizes.len())];
        match rng.next_u64() % 5 {
            0 => {
                let chunk: u32 = chunks[rng.next_usize(chunks.len())];
                let comp: WimCompression = wcomp[rng.next_usize(wcomp.len())];
                let _ = wim_codec::decompress_wim_resource(&body, comp, size, chunk, &quota);
            }
            1 => {
                let variant: ucl::NrvVariant = nrv[rng.next_usize(nrv.len())];
                let _ = ucl::decompress(variant, &body, size as usize);
            }
            2 => {
                let variant: ucl::NrvVariant = nrv[rng.next_usize(nrv.len())];
                let _ = ucl::decompress_to_eos(variant, &body, size as usize);
            }
            3 => {
                let _ = lzms::lzms_decompress(&body, size as usize);
            }
            _ => {
                let _ = lz4_block::decompress(&body, size as usize);
                let _ = lz4_block::decompress_bounded(&body, size as usize);
                let _ = lz4_block::decompress_stop_at(&body, size as usize);
            }
        }
    }
}
