#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_binfmt::containers::{
    NrvVariant, decompress_lz4, lzms_decompress, parse_arj, parse_cpio, parse_iso, parse_lzh,
    parse_lzop, parse_msi_minimal, parse_nsis_archive, parse_par2, parse_partclone_v2, parse_rar,
    parse_sit_classic, parse_unityfs, parse_uzip, parse_xalz, ucl_decompress,
};

const CAP: u64 = 4 * 1024 * 1024;

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

fn drive(bytes: &[u8]) {
    let _ = parse_arj(bytes);
    let _ = parse_cpio(bytes);
    let _ = parse_iso(bytes);
    let _ = parse_lzh(bytes, CAP);
    let _ = parse_lzop(bytes, CAP);
    let _ = parse_par2(bytes);
    let _ = parse_partclone_v2(bytes);
    let _ = parse_rar(bytes);
    let _ = parse_sit_classic(bytes);
    let _ = parse_unityfs(bytes);
    let _ = parse_uzip(bytes, CAP);
    let _ = parse_xalz(bytes, CAP);
    let _ = parse_msi_minimal(bytes);
    let _ = parse_nsis_archive(bytes);
    let _ = decompress_lz4(bytes, CAP);
    let _ = ucl_decompress(NrvVariant::Nrv2b, bytes, bytes.len());
    let _ = lzms_decompress(bytes, bytes.len().min(1 << 20));
}

fn seeds() -> Vec<Vec<u8>> {
    let arj: Vec<u8> = {
        let mut v: Vec<u8> = vec![0x60, 0xEA];
        v.extend_from_slice(&40u16.to_le_bytes());
        v.resize(256, 0);
        v
    };
    let cpio_newc: Vec<u8> = {
        let mut v: Vec<u8> = b"070701".to_vec();
        v.resize(256, b'0');
        v
    };
    let cpio_crc: Vec<u8> = {
        let mut v: Vec<u8> = b"070702".to_vec();
        v.resize(256, b'0');
        v
    };
    let cpio_bin: Vec<u8> = {
        let mut v: Vec<u8> = vec![0xc7, 0x71];
        v.resize(256, 0);
        v
    };
    let iso: Vec<u8> = {
        let mut v: Vec<u8> = vec![0u8; 0x8000 + 2048];
        v[0x8000] = 1;
        v[0x8001..0x8006].copy_from_slice(b"CD001");
        v
    };
    let lzh: Vec<u8> = {
        let mut v: Vec<u8> = vec![0u8; 2];
        v.extend_from_slice(b"-lh5-");
        v.resize(256, 0);
        v
    };
    let lzop: Vec<u8> = {
        let mut v: Vec<u8> = vec![0x89, b'L', b'Z', b'O', 0x00, 0x0d, 0x0a, 0x1a, 0x0a];
        v.resize(256, 0);
        v
    };
    let par2: Vec<u8> = {
        let mut v: Vec<u8> = b"PAR2\x00PKT".to_vec();
        v.resize(256, 0);
        v
    };
    let rar4: Vec<u8> = {
        let mut v: Vec<u8> = vec![0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00];
        v.resize(256, 0);
        v
    };
    let rar5: Vec<u8> = {
        let mut v: Vec<u8> = vec![0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00];
        v.resize(256, 0);
        v
    };
    let unityfs: Vec<u8> = {
        let mut v: Vec<u8> = b"UnityFS\x00".to_vec();
        v.resize(256, 0);
        v
    };
    let uzip: Vec<u8> = {
        let mut v: Vec<u8> = b"#!/bin/sh\n".to_vec();
        v.resize(256, 0);
        v
    };
    let xalz: Vec<u8> = {
        let mut v: Vec<u8> = b"XALZ".to_vec();
        v.resize(256, 0);
        v
    };
    let nsis: Vec<u8> = {
        let mut v: Vec<u8> = vec![0u8; 512];
        v[0..16].copy_from_slice(&[
            0xEF, 0xBE, 0xAD, 0xDE, b'N', b'u', b'l', b'l', b's', b'o', b'f', b't', b'I', b'n',
            b's', b't',
        ]);
        v
    };
    vec![
        arj, cpio_newc, cpio_crc, cpio_bin, iso, lzh, lzop, par2, rar4, rar5, unityfs, uzip, xalz,
        nsis,
    ]
}

#[test]
fn pure_random_never_panics() {
    let mut rng: Xorshift64 = Xorshift64::new(0x9E37_79B9_7F4A_7C15);
    for _ in 0..20_000 {
        let len: usize = rng.next_usize(512);
        let mut buf: Vec<u8> = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push(rng.next_byte());
        }
        drive(&buf);
    }
}

#[test]
fn magic_prefixed_mutated_never_panics() {
    let mut rng: Xorshift64 = Xorshift64::new(0x2545_F491_4F6C_DD1D);
    let base: Vec<Vec<u8>> = seeds();
    for _ in 0..40_000 {
        let template: &[u8] = &base[rng.next_usize(base.len())];
        let mut buf: Vec<u8> = template.to_vec();
        let edits: usize = 1 + rng.next_usize(24);
        for _ in 0..edits {
            if buf.is_empty() {
                break;
            }
            let pos: usize = rng.next_usize(buf.len());
            buf[pos] = rng.next_byte();
        }
        if rng.next_u64().trailing_zeros() >= 2 && !buf.is_empty() {
            buf.truncate(rng.next_usize(buf.len()));
        }
        drive(&buf);
    }
}

#[test]
fn seed_templates_parse_without_panic() {
    for seed in seeds() {
        drive(&seed);
    }
}

#[test]
fn ucl_all_zero_bitstream_does_not_overflow_offset_accumulator() {
    let zeros: Vec<u8> = vec![0u8; 64];
    let r2b: disrobe_binfmt::error::Result<Vec<u8>> =
        ucl_decompress(NrvVariant::Nrv2b, &zeros, 4096);
    let r2d: disrobe_binfmt::error::Result<Vec<u8>> =
        ucl_decompress(NrvVariant::Nrv2d, &zeros, 4096);
    let r2e: disrobe_binfmt::error::Result<Vec<u8>> =
        ucl_decompress(NrvVariant::Nrv2e, &zeros, 4096);
    assert!(r2b.is_err());
    assert!(r2d.is_err());
    assert!(r2e.is_err());
}
