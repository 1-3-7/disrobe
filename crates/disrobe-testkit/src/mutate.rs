use core::fmt;

use crate::rng::{XorShift64, splitmix64};

const MUTATE_DOMAIN: u64 = 0x4D75_7461_7465_0001;
const MIN_RANDOM_SPAN: usize = 32;
const MIN_APPEND_SPAN: usize = 16;
const NEWLINE_SUBSTITUTION_SHIFT: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MutationKind {
    BitFlip,
    Truncate,
    RandomSplice,
    ByteFill,
    Append,
    NewlineSubstitution,
    FullyRandom,
}

impl MutationKind {
    pub const ALL: [Self; 7] = [
        Self::BitFlip,
        Self::Truncate,
        Self::RandomSplice,
        Self::ByteFill,
        Self::Append,
        Self::NewlineSubstitution,
        Self::FullyRandom,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BitFlip => "bit-flip",
            Self::Truncate => "truncate",
            Self::RandomSplice => "random-splice",
            Self::ByteFill => "byte-fill",
            Self::Append => "append",
            Self::NewlineSubstitution => "newline-substitution",
            Self::FullyRandom => "fully-random",
        }
    }

    pub(crate) const fn to_wire(self) -> u8 {
        match self {
            Self::BitFlip => 0,
            Self::Truncate => 1,
            Self::RandomSplice => 2,
            Self::ByteFill => 3,
            Self::Append => 4,
            Self::NewlineSubstitution => 5,
            Self::FullyRandom => 6,
        }
    }

    pub(crate) const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::BitFlip),
            1 => Some(Self::Truncate),
            2 => Some(Self::RandomSplice),
            3 => Some(Self::ByteFill),
            4 => Some(Self::Append),
            5 => Some(Self::NewlineSubstitution),
            6 => Some(Self::FullyRandom),
            _ => None,
        }
    }
}

impl fmt::Display for MutationKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[must_use]
pub fn mutate(input: &[u8], seed: u64) -> (Vec<u8>, MutationKind) {
    let mut rng: XorShift64 = XorShift64::new(splitmix64(seed ^ MUTATE_DOMAIN));
    let choice: usize = rng.below_usize(MutationKind::ALL.len());
    let kind: MutationKind = MutationKind::ALL
        .get(choice)
        .copied()
        .unwrap_or(MutationKind::FullyRandom);
    let bytes: Vec<u8> = match kind {
        MutationKind::BitFlip => bit_flip(input, &mut rng),
        MutationKind::Truncate => truncate(input, &mut rng),
        MutationKind::RandomSplice => random_splice(input, &mut rng),
        MutationKind::ByteFill => byte_fill(input, &mut rng),
        MutationKind::Append => append(input, &mut rng),
        MutationKind::NewlineSubstitution => substitute_newlines(input, &mut rng),
        MutationKind::FullyRandom => fully_random(input, &mut rng),
    };
    (bytes, kind)
}

fn bit_flip(input: &[u8], rng: &mut XorShift64) -> Vec<u8> {
    let mut out: Vec<u8> = input.to_vec();
    let index: usize = rng.below_usize(out.len());
    let shift: u32 = u32::try_from(rng.below(u64::from(u8::BITS))).unwrap_or(0);
    if let Some(byte) = out.get_mut(index) {
        *byte ^= 1u8 << shift;
    }
    out
}

fn truncate(input: &[u8], rng: &mut XorShift64) -> Vec<u8> {
    let keep: usize = rng.below_usize(input.len().saturating_add(1));
    input.get(..keep).unwrap_or(input).to_vec()
}

fn random_splice(input: &[u8], rng: &mut XorShift64) -> Vec<u8> {
    let mut out: Vec<u8> = input.to_vec();
    if input.is_empty() {
        return out;
    }
    let start: usize = rng.below_usize(input.len());
    let available: usize = input.len().saturating_sub(start);
    let span: usize = rng.below_usize(available).saturating_add(1);
    let destination: usize = rng.below_usize(out.len().saturating_add(1));
    let Some(piece): Option<Vec<u8>> = input
        .get(start..start.saturating_add(span))
        .map(<[u8]>::to_vec)
    else {
        return out;
    };
    out.splice(destination..destination, piece);
    out
}

fn byte_fill(input: &[u8], rng: &mut XorShift64) -> Vec<u8> {
    let mut out: Vec<u8> = input.to_vec();
    if out.is_empty() {
        return out;
    }
    let start: usize = rng.below_usize(out.len());
    let span: usize = rng
        .below_usize(out.len().saturating_sub(start))
        .saturating_add(1);
    let end: usize = start.saturating_add(span).min(out.len());
    let value: u8 = rng.next_byte();
    if let Some(window) = out.get_mut(start..end) {
        window.fill(value);
    }
    out
}

fn append(input: &[u8], rng: &mut XorShift64) -> Vec<u8> {
    let mut out: Vec<u8> = input.to_vec();
    let headroom: usize = (input.len() / 4).max(MIN_APPEND_SPAN);
    let extra: usize = rng.below_usize(headroom.saturating_add(1));
    out.reserve(extra);
    for _ in 0..extra {
        out.push(rng.next_byte());
    }
    out
}

fn substitute_newlines(input: &[u8], rng: &mut XorShift64) -> Vec<u8> {
    let mut out: Vec<u8> = input.to_vec();
    for byte in &mut out {
        if rng.next_u64().trailing_zeros() >= NEWLINE_SUBSTITUTION_SHIFT {
            *byte = b'\n';
        }
    }
    out
}

fn fully_random(input: &[u8], rng: &mut XorShift64) -> Vec<u8> {
    let span: usize = input.len().max(MIN_RANDOM_SPAN);
    let len: usize = rng.below_usize(span.saturating_add(1));
    let mut out: Vec<u8> = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(rng.next_byte());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{MutationKind, mutate};

    const SAMPLE: &[u8] = b"the quick brown fox jumps over the lazy dog\n0123456789";

    #[test]
    fn the_same_seed_reproduces_byte_identical_output() {
        for seed in 0..512u64 {
            let (left, left_kind): (Vec<u8>, MutationKind) = mutate(SAMPLE, seed);
            let (right, right_kind): (Vec<u8>, MutationKind) = mutate(SAMPLE, seed);
            assert_eq!(left, right);
            assert_eq!(left_kind, right_kind);
        }
    }

    #[test]
    fn every_kind_is_reachable_and_wire_encodable() {
        let mut seen: Vec<MutationKind> = Vec::new();
        for seed in 0..4096u64 {
            let (_, kind): (Vec<u8>, MutationKind) = mutate(SAMPLE, seed);
            if !seen.contains(&kind) {
                seen.push(kind);
            }
        }
        for kind in MutationKind::ALL {
            assert!(seen.contains(&kind), "{kind} was never selected");
            assert_eq!(MutationKind::from_wire(kind.to_wire()), Some(kind));
        }
        assert_eq!(MutationKind::from_wire(u8::MAX), None);
    }

    #[test]
    fn an_empty_input_is_handled_by_every_kind() {
        for seed in 0..2048u64 {
            let (bytes, kind): (Vec<u8>, MutationKind) = mutate(&[], seed);
            match kind {
                MutationKind::Append | MutationKind::FullyRandom => {}
                _ => assert!(bytes.is_empty(), "{kind} grew an empty input"),
            }
        }
    }

    #[test]
    fn a_single_byte_input_is_handled_by_every_kind() {
        for seed in 0..2048u64 {
            let (bytes, _): (Vec<u8>, MutationKind) = mutate(b"x", seed);
            assert!(bytes.len() <= 64);
        }
    }

    #[test]
    fn output_length_stays_bounded_by_the_input_length() {
        for seed in 0..1024u64 {
            let (bytes, kind): (Vec<u8>, MutationKind) = mutate(SAMPLE, seed);
            let ceiling: usize = SAMPLE.len().saturating_mul(2).saturating_add(64);
            assert!(
                bytes.len() <= ceiling,
                "{kind} produced {} bytes",
                bytes.len()
            );
        }
    }

    #[test]
    fn distinct_seeds_do_not_collapse_to_one_output() {
        let mut distinct: Vec<Vec<u8>> = Vec::new();
        for seed in 0..64u64 {
            let (bytes, _): (Vec<u8>, MutationKind) = mutate(SAMPLE, seed);
            if !distinct.contains(&bytes) {
                distinct.push(bytes);
            }
        }
        assert!(
            distinct.len() > 32,
            "only {} distinct outputs",
            distinct.len()
        );
    }
}
