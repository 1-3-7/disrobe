#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_binfmt::containers::{
    appimage, cramfs, erofs, jffs2, romfs, snap, squashfs, ubifs, vhd, vhdx,
};

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

fn erofs_seed() -> Vec<u8> {
    let mut v: Vec<u8> = vec![0u8; 1024 + 256];
    v[1024..1028].copy_from_slice(&0xE0F5_E1E2u32.to_le_bytes());
    v[1024 + 12] = 12;
    v[1024 + 16..1024 + 18].copy_from_slice(&0u16.to_le_bytes());
    v[1024 + 36..1024 + 40].copy_from_slice(&0u32.to_le_bytes());
    v
}

fn cramfs_seed() -> Vec<u8> {
    let mut v: Vec<u8> = vec![0u8; 256];
    v[0..4].copy_from_slice(&0x28cd_3d45u32.to_le_bytes());
    v
}

fn jffs2_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(&0x1985u16.to_le_bytes());
    v.extend_from_slice(&0xe001u16.to_le_bytes());
    while v.len() < 256 {
        v.push(0);
    }
    v
}

fn romfs_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(b"-rom1fs-");
    v.extend_from_slice(&0x0000_0100u32.to_be_bytes());
    v.extend_from_slice(&0x0000_0000u32.to_be_bytes());
    v.extend_from_slice(b"vol\0");
    while v.len() < 256 {
        v.push(0);
    }
    v
}

fn squashfs_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(&[0x68, 0x73, 0x71, 0x73]);
    while v.len() < 256 {
        v.push(0);
    }
    v
}

fn ubi_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(b"UBI#");
    while v.len() < 4096 {
        v.push(0);
    }
    v
}

fn ubifs_seed() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(&0x0610_1831u32.to_le_bytes());
    while v.len() < 4096 {
        v.push(0);
    }
    v
}

fn vhd_seed() -> Vec<u8> {
    let mut v: Vec<u8> = vec![0u8; 2048 + 512];
    let footer_at: usize = v.len() - 512;
    v[footer_at..footer_at + 8].copy_from_slice(b"conectix");
    v[footer_at + 60..footer_at + 64].copy_from_slice(&3u32.to_be_bytes());
    v[footer_at + 512 - 512..].copy_from_slice(&[0u8; 512]);
    v[footer_at..footer_at + 8].copy_from_slice(b"conectix");
    v
}

fn vhdx_seed() -> Vec<u8> {
    let mut v: Vec<u8> = vec![0u8; 1024 * 1024 + 64];
    v[0..8].copy_from_slice(b"vhdxfile");
    v[64 * 1024..64 * 1024 + 4].copy_from_slice(b"head");
    v[128 * 1024..128 * 1024 + 4].copy_from_slice(b"head");
    v
}

fn appimage_seed() -> Vec<u8> {
    let mut v: Vec<u8> = vec![0u8; 256];
    v[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    v[8] = b'A';
    v[9] = b'I';
    v[10] = 0x02;
    v
}

fn mutate(seed: &[u8], rng: &mut Xorshift64) -> Vec<u8> {
    let mut out: Vec<u8> = seed.to_vec();
    let kind: u64 = rng.next_u64() % 7;
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
            let count: usize = rng.next_usize(64);
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
        5 => {
            let count: usize = rng.next_usize(32);
            for _ in 0..count {
                let idx: usize = rng.next_usize(out.len().max(1));
                if idx + 4 <= out.len() {
                    out[idx..idx + 4].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
                }
            }
        }
        _ => {
            let len: usize = rng.next_usize(2048);
            out = (0..len).map(|_| rng.next_byte()).collect();
        }
    }
    out
}

fn exercise(bytes: &[u8]) {
    let _ = erofs::detect_erofs(bytes);
    let _ = erofs::walk_erofs(bytes, CAP);
    let _ = cramfs::detect_cramfs(bytes);
    let _ = cramfs::walk_cramfs(bytes, CAP);
    let _ = jffs2::detect_jffs2(bytes);
    let _ = jffs2::walk_jffs2(bytes, CAP);
    let _ = romfs::detect_romfs(bytes);
    let _ = romfs::walk_romfs(bytes, CAP);
    let _ = squashfs::parse_squashfs_superblock(bytes, 0);
    let _ = squashfs::walk_squashfs(bytes, 0, CAP);
    let _ = snap::detect_snap(bytes);
    let _ = ubifs::detect_ubi(bytes);
    let _ = ubifs::detect_ubifs(bytes);
    let _ = ubifs::walk_ubifs(bytes, CAP);
    let _ = vhd::parse_vhd(bytes);
    let _ = vhdx::parse_vhdx(bytes);
    let _ = appimage::parse_appimage(bytes);
}

#[test]
fn pure_random_inputs_never_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0xF11E_5751_E3F5_0001);
    for _ in 0..4_000 {
        let len: usize = rng.next_usize(2048);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        exercise(&bytes);
    }
}

fn erofs_compressed_blkaddr_past_eof() -> Vec<u8> {
    const BLK_BITS: u8 = 12;
    const BLK: usize = 4096;
    const SUPER_OFFSET: usize = 1024;
    const S_IFREG: u16 = 0o100_000;
    let meta_block: usize = 2;
    let mut image: Vec<u8> = vec![0u8; 8 * BLK];
    image[SUPER_OFFSET..SUPER_OFFSET + 4].copy_from_slice(&0xE0F5_E1E2u32.to_le_bytes());
    image[SUPER_OFFSET + 12] = BLK_BITS;
    image[SUPER_OFFSET + 16..SUPER_OFFSET + 18].copy_from_slice(&0u16.to_le_bytes());
    image[SUPER_OFFSET + 24..SUPER_OFFSET + 32].copy_from_slice(&1u64.to_le_bytes());
    image[SUPER_OFFSET + 36..SUPER_OFFSET + 40].copy_from_slice(&(meta_block as u32).to_le_bytes());
    let inode_off: usize = meta_block * BLK;
    let format: u16 = 1u16 << 1;
    image[inode_off..inode_off + 2].copy_from_slice(&format.to_le_bytes());
    image[inode_off + 4..inode_off + 6].copy_from_slice(&(S_IFREG | 0o644).to_le_bytes());
    image[inode_off + 8..inode_off + 12].copy_from_slice(&(BLK as u32).to_le_bytes());
    let header_off: usize = inode_off + 32;
    image[header_off + 6] = 0;
    image[header_off + 7] = 0;
    let index_off: usize = header_off + 8;
    image[index_off..index_off + 2].copy_from_slice(&1u16.to_le_bytes());
    image[index_off + 4..index_off + 8].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
    image
}

#[test]
fn erofs_compressed_pcluster_past_eof_does_not_underflow() {
    let image: Vec<u8> = erofs_compressed_blkaddr_past_eof();
    let _ = erofs::walk_erofs(&image, CAP);
}

#[test]
fn magic_prefixed_inputs_reach_walkers() {
    let seeds: [Vec<u8>; 11] = [
        erofs_seed(),
        cramfs_seed(),
        jffs2_seed(),
        romfs_seed(),
        squashfs_seed(),
        ubi_seed(),
        ubifs_seed(),
        vhd_seed(),
        vhdx_seed(),
        appimage_seed(),
        Vec::new(),
    ];
    let mut rng: Xorshift64 = Xorshift64::new(0x5751_E3F5_0102_0304);
    for seed in &seeds {
        for _ in 0..4_000 {
            let mutated: Vec<u8> = mutate(seed, &mut rng);
            exercise(&mutated);
        }
    }
}
