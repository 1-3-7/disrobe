use serde::{Deserialize, Serialize};

pub const STORED_DIGEST_LEN: usize = 16;

pub type StoredDigest = [u8; STORED_DIGEST_LEN];

const ROUND_CONSTANTS: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

const SHA256_INITIAL: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const NOTSHA256_INITIAL: [u32; 8] = [
    !SHA256_INITIAL[0],
    !SHA256_INITIAL[1],
    !SHA256_INITIAL[2],
    !SHA256_INITIAL[3],
    !SHA256_INITIAL[4],
    !SHA256_INITIAL[5],
    !SHA256_INITIAL[6],
    !SHA256_INITIAL[7],
];

const BLOCK_LEN: usize = 64;

#[derive(Debug, Clone)]
struct Sha256Core {
    state: [u32; 8],
    block: [u8; BLOCK_LEN],
    buffered: usize,
    total_bytes: u64,
}

impl Sha256Core {
    const fn with_initial(initial: [u32; 8]) -> Self {
        Self {
            state: initial,
            block: [0; BLOCK_LEN],
            buffered: 0,
            total_bytes: 0,
        }
    }

    fn update(&mut self, mut bytes: &[u8]) {
        self.total_bytes = self.total_bytes.wrapping_add(bytes.len() as u64);
        if self.buffered > 0 {
            let want: usize = BLOCK_LEN - self.buffered;
            let take: usize = want.min(bytes.len());
            self.block[self.buffered..self.buffered + take].copy_from_slice(&bytes[..take]);
            self.buffered += take;
            bytes = &bytes[take..];
            if self.buffered == BLOCK_LEN {
                let block: [u8; BLOCK_LEN] = self.block;
                compress(&mut self.state, &block);
                self.buffered = 0;
            }
        }
        let mut chunks: std::slice::ChunksExact<'_, u8> = bytes.chunks_exact(BLOCK_LEN);
        for chunk in &mut chunks {
            let mut block: [u8; BLOCK_LEN] = [0; BLOCK_LEN];
            block.copy_from_slice(chunk);
            compress(&mut self.state, &block);
        }
        let rest: &[u8] = chunks.remainder();
        if !rest.is_empty() {
            self.block[..rest.len()].copy_from_slice(rest);
            self.buffered = rest.len();
        }
    }

    fn finish(mut self) -> [u8; 32] {
        let bit_length: u64 = self.total_bytes.wrapping_mul(8);
        self.block[self.buffered] = 0x80;
        self.buffered += 1;
        for slot in &mut self.block[self.buffered..] {
            *slot = 0;
        }
        if self.buffered > BLOCK_LEN - 8 {
            let block: [u8; BLOCK_LEN] = self.block;
            compress(&mut self.state, &block);
            self.block = [0; BLOCK_LEN];
        }
        self.block[BLOCK_LEN - 8..].copy_from_slice(&bit_length.to_be_bytes());
        let block: [u8; BLOCK_LEN] = self.block;
        compress(&mut self.state, &block);
        let mut out: [u8; 32] = [0; 32];
        for (index, word) in self.state.iter().enumerate() {
            out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

fn compress(state: &mut [u32; 8], block: &[u8; BLOCK_LEN]) {
    let mut schedule: [u32; 64] = [0; 64];
    for (index, slot) in schedule.iter_mut().take(16).enumerate() {
        let start: usize = index * 4;
        let word: [u8; 4] = [
            block[start],
            block[start + 1],
            block[start + 2],
            block[start + 3],
        ];
        *slot = u32::from_be_bytes(word);
    }
    for index in 16..64 {
        let previous_15: u32 = schedule[index - 15];
        let previous_2: u32 = schedule[index - 2];
        let s0: u32 =
            previous_15.rotate_right(7) ^ previous_15.rotate_right(18) ^ (previous_15 >> 3);
        let s1: u32 =
            previous_2.rotate_right(17) ^ previous_2.rotate_right(19) ^ (previous_2 >> 10);
        schedule[index] = schedule[index - 16]
            .wrapping_add(s0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(s1);
    }

    let mut working: [u32; 8] = *state;
    for index in 0..64 {
        let sigma1: u32 =
            working[4].rotate_right(6) ^ working[4].rotate_right(11) ^ working[4].rotate_right(25);
        let choose: u32 = (working[4] & working[5]) ^ ((!working[4]) & working[6]);
        let temp1: u32 = working[7]
            .wrapping_add(sigma1)
            .wrapping_add(choose)
            .wrapping_add(ROUND_CONSTANTS[index])
            .wrapping_add(schedule[index]);
        let sigma0: u32 =
            working[0].rotate_right(2) ^ working[0].rotate_right(13) ^ working[0].rotate_right(22);
        let majority: u32 =
            (working[0] & working[1]) ^ (working[0] & working[2]) ^ (working[1] & working[2]);
        let temp2: u32 = sigma0.wrapping_add(majority);
        working[7] = working[6];
        working[6] = working[5];
        working[5] = working[4];
        working[4] = working[3].wrapping_add(temp1);
        working[3] = working[2];
        working[2] = working[1];
        working[1] = working[0];
        working[0] = temp1.wrapping_add(temp2);
    }

    for (slot, added) in state.iter_mut().zip(working) {
        *slot = slot.wrapping_add(added);
    }
}

#[must_use]
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut core: Sha256Core = Sha256Core::with_initial(SHA256_INITIAL);
    core.update(data);
    core.finish()
}

#[must_use]
fn notsha256(data: &[u8]) -> [u8; 32] {
    let mut core: Sha256Core = Sha256Core::with_initial(NOTSHA256_INITIAL);
    core.update(data);
    core.finish()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbedDigestConstruction {
    NotSha256,
    Sha256Plain,
    Sha256FlipLowBit,
    Sha256FlipLowByte,
    Sha256DomainPrefixed,
}

impl EmbedDigestConstruction {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotSha256 => "notsha256",
            Self::Sha256Plain => "sha256",
            Self::Sha256FlipLowBit => "sha256-flip-low-bit",
            Self::Sha256FlipLowByte => "sha256-flip-low-byte",
            Self::Sha256DomainPrefixed => "sha256-domain-prefixed",
        }
    }

    #[must_use]
    pub(crate) fn stored(self, data: &[u8]) -> StoredDigest {
        let full: [u8; 32] = match self {
            Self::NotSha256 => notsha256(data),
            Self::Sha256Plain => sha256(data),
            Self::Sha256FlipLowBit => {
                let mut sum: [u8; 32] = sha256(data);
                sum[0] ^= 0x01;
                sum
            }
            Self::Sha256FlipLowByte => {
                let mut sum: [u8; 32] = sha256(data);
                sum[0] ^= 0xff;
                sum
            }
            Self::Sha256DomainPrefixed => {
                let mut core: Sha256Core = Sha256Core::with_initial(SHA256_INITIAL);
                core.update(&[0x01]);
                core.update(data);
                core.finish()
            }
        };
        let mut stored: StoredDigest = [0; STORED_DIGEST_LEN];
        stored.copy_from_slice(&full[..STORED_DIGEST_LEN]);
        stored
    }
}

pub const ONE_SHOT_MAX_LEN: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbedDigestFamily {
    Notsha256,
    Sha256LowBit,
    Sha256LowByte,
}

impl EmbedDigestFamily {
    pub const CANDIDATES: [Self; 3] = [Self::Sha256LowByte, Self::Sha256LowBit, Self::Notsha256];

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Notsha256 => "notsha256",
            Self::Sha256LowBit => "sha256-low-bit",
            Self::Sha256LowByte => "sha256-low-byte",
        }
    }

    #[must_use]
    pub const fn toolchain_range(self) -> &'static str {
        match self {
            Self::Notsha256 => "go1.16 through go1.23",
            Self::Sha256LowBit => "go1.24",
            Self::Sha256LowByte => "go1.25 and later",
        }
    }

    #[must_use]
    pub const fn construction_for_len(self, len: usize) -> EmbedDigestConstruction {
        match self {
            Self::Notsha256 => EmbedDigestConstruction::NotSha256,
            Self::Sha256LowBit => {
                if len <= ONE_SHOT_MAX_LEN {
                    EmbedDigestConstruction::Sha256FlipLowBit
                } else {
                    EmbedDigestConstruction::Sha256DomainPrefixed
                }
            }
            Self::Sha256LowByte => {
                if len <= ONE_SHOT_MAX_LEN {
                    EmbedDigestConstruction::Sha256FlipLowByte
                } else {
                    EmbedDigestConstruction::Sha256DomainPrefixed
                }
            }
        }
    }

    #[must_use]
    pub(crate) fn stored(self, data: &[u8]) -> StoredDigest {
        self.construction_for_len(data.len()).stored(data)
    }

    #[must_use]
    pub(crate) fn verifies(self, data: &[u8], expected: StoredDigest) -> bool {
        self.stored(data) == expected
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyResolution {
    pub family: EmbedDigestFamily,
    pub verified: usize,
    pub total: usize,
    pub distinguishable: bool,
}

#[must_use]
pub(crate) fn resolve_family(pairs: &[(&[u8], StoredDigest)]) -> Option<FamilyResolution> {
    if pairs.is_empty() {
        return None;
    }
    let mut best: Option<(EmbedDigestFamily, usize)> = None;
    for candidate in EmbedDigestFamily::CANDIDATES {
        let verified: usize = pairs
            .iter()
            .filter(|(data, expected): &&(&[u8], StoredDigest)| candidate.verifies(data, *expected))
            .count();
        if verified == 0 {
            continue;
        }
        let better: bool =
            best.is_none_or(|(_, previous): (EmbedDigestFamily, usize)| verified > previous);
        if better {
            best = Some((candidate, verified));
        }
    }
    let (family, verified): (EmbedDigestFamily, usize) = best?;
    let distinguishable: bool = pairs
        .iter()
        .any(|(data, _): &(&[u8], StoredDigest)| data.len() <= ONE_SHOT_MAX_LEN);
    Some(FamilyResolution {
        family,
        verified,
        total: pairs.len(),
        distinguishable,
    })
}

#[cfg(test)]
mod tests {
    use super::{EmbedDigestConstruction, StoredDigest, notsha256, sha256};

    const ALL: [EmbedDigestConstruction; 5] = [
        EmbedDigestConstruction::NotSha256,
        EmbedDigestConstruction::Sha256DomainPrefixed,
        EmbedDigestConstruction::Sha256FlipLowBit,
        EmbedDigestConstruction::Sha256FlipLowByte,
        EmbedDigestConstruction::Sha256Plain,
    ];

    fn hex(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|byte: &u8| format!("{byte:02x}"))
            .collect::<Vec<String>>()
            .concat()
    }

    #[test]
    fn the_core_matches_the_published_test_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "SHA-256 of the empty string must match FIPS 180-4"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "SHA-256 of \"abc\" must match FIPS 180-4"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            "SHA-256 of the two-block FIPS 180-4 message must match"
        );
        let million: Vec<u8> = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&sha256(&million)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
            "SHA-256 of one million 'a' must match FIPS 180-4"
        );
    }

    #[test]
    fn the_toolchain_core_differs_from_plain_sha256() {
        assert_ne!(
            sha256(b"abc"),
            notsha256(b"abc"),
            "the toolchain digest must not equal plain SHA-256"
        );
    }

    #[test]
    fn every_construction_is_distinct_on_the_same_input() {
        let mut seen: Vec<(EmbedDigestConstruction, StoredDigest)> = Vec::new();
        for candidate in ALL {
            let stored: StoredDigest = candidate.stored(b"disrobe embed digest probe");
            for (other, previous) in &seen {
                assert_ne!(
                    stored,
                    *previous,
                    "{} and {} produce the same stored digest, so family resolution cannot tell \
                     them apart",
                    candidate.label(),
                    other.label()
                );
            }
            seen.push((candidate, stored));
        }
        assert_eq!(seen.len(), 5);
    }
}
