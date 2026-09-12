use std::collections::BTreeMap;

use disrobe_nir::ValueId;

use crate::report::TaintStep;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub(crate) struct KindSet(u64);

impl KindSet {
    pub(crate) const EMPTY: Self = Self(0);

    pub(crate) const fn from_index(index: u16) -> Self {
        Self(1u64 << (index as u64 & 63))
    }

    pub(crate) const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    pub(crate) const fn bits(self) -> u64 {
        self.0
    }

    pub(crate) const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    pub(crate) const fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub(crate) struct FeatureSet(u64);

impl FeatureSet {
    pub(crate) const EMPTY: Self = Self(0);

    pub(crate) const fn from_index(index: u16) -> Self {
        Self(1u64 << (index as u64 & 63))
    }

    pub(crate) const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    pub(crate) const fn bits(self) -> u64 {
        self.0
    }

    pub(crate) const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub(crate) const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    pub(crate) const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub(crate) const fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Base {
    Register(u32),
    Stack(u32),
    Memory(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Proj {
    Field(i64),
    Deref,
    Star,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct AccessPath {
    pub(crate) base: Base,
    pub(crate) projections: Vec<Proj>,
}

pub(crate) const ACCESS_PATH_K: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct PathId(u32);

#[derive(Debug, Default)]
pub(crate) struct Arena {
    string_index: BTreeMap<String, u32>,
    path_index: BTreeMap<AccessPath, PathId>,
}

impl Arena {
    fn intern_string(&mut self, value: &str) -> u32 {
        if let Some(id) = self.string_index.get(value) {
            return *id;
        }
        let id: u32 = u32::try_from(self.string_index.len()).unwrap_or(u32::MAX);
        self.string_index.insert(value.to_owned(), id);
        id
    }

    fn intern_path(&mut self, mut path: AccessPath) -> PathId {
        if path.projections.len() > ACCESS_PATH_K {
            path.projections.truncate(ACCESS_PATH_K);
            path.projections.push(Proj::Star);
        }
        if let Some(id) = self.path_index.get(&path) {
            return *id;
        }
        let id: PathId = PathId(u32::try_from(self.path_index.len()).unwrap_or(u32::MAX));
        self.path_index.insert(path, id);
        id
    }

    pub(crate) fn intern(&mut self, base: Base, projections: Vec<Proj>) -> PathId {
        self.intern_path(AccessPath { base, projections })
    }

    pub(crate) fn location(&mut self, value: &ValueId) -> PathId {
        match value {
            ValueId::Register(name) => {
                let id: u32 = self.intern_string(name);
                self.intern(Base::Register(id), Vec::new())
            }
            ValueId::Stack(slot) => self.intern(Base::Stack(*slot), Vec::new()),
            ValueId::Memory(expr) => {
                let (base, projections): (Base, Vec<Proj>) = self.parse_memory(expr);
                self.intern(base, projections)
            }
        }
    }

    fn parse_memory(&mut self, expr: &str) -> (Base, Vec<Proj>) {
        let trimmed: &str = expr.trim().trim_start_matches("byte ").trim();
        let depth: usize = trimmed.bytes().filter(|b: &u8| *b == b'[').count();
        let inner: &str = trimmed.trim_start_matches('[').trim_end_matches(']').trim();
        let mut tokens = inner.splitn(2, ['+', '-']);
        let Some(head): Option<&str> = tokens.next() else {
            let id: u32 = self.intern_string(inner);
            return (Base::Memory(id), vec![Proj::Deref]);
        };
        let head: &str = head.trim();
        let base: Base = if head.is_empty() {
            Base::Memory(self.intern_string(inner))
        } else {
            Base::Memory(self.intern_string(head))
        };
        let mut projections: Vec<Proj> = Vec::new();
        if let Some(rest) = tokens.next() {
            let sign: i64 = if inner[head.len()..].starts_with('-') {
                -1
            } else {
                1
            };
            match parse_offset(rest.trim()) {
                Some(offset) => projections.push(Proj::Field(sign * offset)),
                None => projections.push(Proj::Star),
            }
        }
        for _ in 0..depth {
            projections.push(Proj::Deref);
        }
        (base, projections)
    }
}

fn parse_offset(token: &str) -> Option<i64> {
    let core: &str = token.split(['+', '-']).next().unwrap_or(token);
    let core: &str = core.trim();
    if core.contains('*')
        || core
            .bytes()
            .any(|b: u8| b.is_ascii_alphabetic() && b != b'x')
    {
        return None;
    }
    let stripped: &str = core.strip_prefix("0x").unwrap_or(core);
    i64::from_str_radix(stripped, 16).ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum OutPort {
    Return,
    Argument(u16),
}

#[derive(Debug, Clone, Default)]
pub(crate) struct GenValue {
    pub(crate) kinds: KindSet,
    pub(crate) features: FeatureSet,
    pub(crate) path: Vec<TaintStep>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PropValue {
    pub(crate) kinds: KindSet,
    pub(crate) features: FeatureSet,
    pub(crate) path: Vec<TaintStep>,
}

#[derive(Debug, Clone)]
pub(crate) struct SinkFrame {
    pub(crate) in_arg: u16,
    pub(crate) via_flag: bool,
    pub(crate) sink_symbol: String,
    pub(crate) sink_site: u64,
    pub(crate) sink_kinds: KindSet,
    pub(crate) suppress: FeatureSet,
    pub(crate) accumulated: FeatureSet,
    pub(crate) path: Vec<TaintStep>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct FunctionSummary {
    pub(crate) generations: BTreeMap<OutPort, GenValue>,
    pub(crate) propagations: BTreeMap<u16, BTreeMap<OutPort, PropValue>>,
    pub(crate) frames: Vec<SinkFrame>,
}

impl FunctionSummary {
    pub(crate) fn add_generation(
        &mut self,
        port: OutPort,
        kinds: KindSet,
        features: FeatureSet,
        path: &[TaintStep],
    ) {
        let entry: &mut GenValue = self.generations.entry(port).or_default();
        entry.kinds.insert(kinds);
        entry.features.insert(features);
        if entry.path.is_empty() {
            entry.path = path.to_vec();
        }
    }

    pub(crate) fn add_propagation(
        &mut self,
        in_arg: u16,
        out: OutPort,
        kinds: KindSet,
        features: FeatureSet,
        path: &[TaintStep],
    ) {
        let entry: &mut PropValue = self
            .propagations
            .entry(in_arg)
            .or_default()
            .entry(out)
            .or_default();
        entry.kinds.insert(kinds);
        entry.features.insert(features);
        if entry.path.is_empty() {
            entry.path = path.to_vec();
        }
    }

    pub(crate) fn add_frame(&mut self, frame: SinkFrame) {
        let duplicate: bool = self.frames.iter().any(|f: &SinkFrame| {
            f.in_arg == frame.in_arg
                && f.via_flag == frame.via_flag
                && f.sink_site == frame.sink_site
                && f.sink_symbol == frame.sink_symbol
        });
        if !duplicate {
            self.frames.push(frame);
        }
    }

    pub(crate) fn semantic_key(&self) -> SummaryKey {
        let generations: Vec<GenKey> = self
            .generations
            .iter()
            .map(|(port, value): (&OutPort, &GenValue)| {
                (*port, value.kinds.bits(), value.features.bits())
            })
            .collect();
        let propagations: Vec<PropKey> = self
            .propagations
            .iter()
            .flat_map(|(in_arg, outs): (&u16, &BTreeMap<OutPort, PropValue>)| {
                outs.iter()
                    .map(move |(out, value): (&OutPort, &PropValue)| {
                        (*in_arg, *out, value.kinds.bits(), value.features.bits())
                    })
            })
            .collect();
        let mut frames: Vec<FrameKey> = self
            .frames
            .iter()
            .map(|f: &SinkFrame| {
                (
                    f.in_arg,
                    f.via_flag,
                    f.sink_site,
                    f.sink_kinds.bits(),
                    f.suppress.bits(),
                    f.accumulated.bits(),
                )
            })
            .collect();
        frames.sort_unstable();
        SummaryKey {
            generations,
            propagations,
            frames,
        }
    }
}

type GenKey = (OutPort, u64, u64);
type PropKey = (u16, OutPort, u64, u64);
type FrameKey = (u16, bool, u64, u64, u64, u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SummaryKey {
    generations: Vec<GenKey>,
    propagations: Vec<PropKey>,
    frames: Vec<FrameKey>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_paths_are_hash_consed() {
        let mut arena: Arena = Arena::default();
        let left: PathId = arena.intern(Base::Stack(0), Vec::new());
        let right: PathId = arena.intern(Base::Stack(0), Vec::new());
        assert_eq!(left, right);
        let other: PathId = arena.intern(Base::Stack(1), Vec::new());
        assert_ne!(left, other);
    }

    #[test]
    fn deep_access_path_collapses_to_star() {
        let mut arena: Arena = Arena::default();
        let deep: PathId = arena.intern(
            Base::Stack(0),
            vec![
                Proj::Deref,
                Proj::Field(8),
                Proj::Deref,
                Proj::Field(16),
                Proj::Deref,
            ],
        );
        let collapsed: PathId = arena.intern(
            Base::Stack(0),
            vec![Proj::Deref, Proj::Field(8), Proj::Deref, Proj::Star],
        );
        assert_eq!(deep, collapsed);
    }

    #[test]
    fn memory_operand_parses_into_base_and_projections() {
        let mut arena: Arena = Arena::default();
        let cell: PathId = arena.location(&ValueId::memory("[rbp-0x8]"));
        let same: PathId = arena.location(&ValueId::memory("[rbp-0x8]"));
        assert_eq!(cell, same);
        let other: PathId = arena.location(&ValueId::memory("[rbp-0x10]"));
        assert_ne!(cell, other);
    }

    #[test]
    fn kind_bitset_union_and_intersect() {
        let a: KindSet = KindSet::from_index(1);
        let b: KindSet = KindSet::from_index(2);
        assert!(!a.intersects(b));
        let mut both: KindSet = a;
        both.insert(b);
        assert!(both.intersects(a));
        assert!(both.intersects(b));
    }
}
