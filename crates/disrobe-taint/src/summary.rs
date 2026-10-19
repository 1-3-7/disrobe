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
    strings: Vec<String>,
    path_index: BTreeMap<AccessPath, PathId>,
    paths: Vec<AccessPath>,
}

impl Arena {
    fn intern_string(&mut self, value: &str) -> u32 {
        if let Some(id) = self.string_index.get(value) {
            return *id;
        }
        let id: u32 = u32::try_from(self.string_index.len()).unwrap_or(u32::MAX);
        self.string_index.insert(value.to_owned(), id);
        self.strings.push(value.to_owned());
        id
    }

    pub(crate) fn memory_projection(&self, id: PathId) -> Option<(&str, i64)> {
        let path: &AccessPath = self.paths.get(usize::try_from(id.0).ok()?)?;
        let Base::Memory(base) = path.base else {
            return None;
        };
        let base: &str = self.strings.get(usize::try_from(base).ok()?)?;
        match path.projections.as_slice() {
            [Proj::Deref] => Some((base, 0)),
            [Proj::Field(offset), Proj::Deref] => Some((base, *offset)),
            _ => None,
        }
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
        self.path_index.insert(path.clone(), id);
        self.paths.push(path);
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
        let trimmed: &str = expr.trim();
        let trimmed: &str = ["byte ", "word ", "dword ", "qword "]
            .iter()
            .find_map(|prefix: &&str| trimmed.strip_prefix(prefix))
            .unwrap_or(trimmed)
            .trim();
        let depth: usize = trimmed.bytes().filter(|b: &u8| *b == b'[').count();
        let inner: &str = trimmed.trim_start_matches('[').trim_end_matches(']').trim();
        if let Some(address) = relative_address(inner) {
            let id: u32 = self.intern_string(&format!("rel {address:x}"));
            return (Base::Memory(id), vec![Proj::Deref]);
        }
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

pub(crate) fn relative_address(inner: &str) -> Option<u64> {
    let mut address: Option<u64> = None;
    let mut displacement: i64 = 0;
    let body: &str = inner.trim().strip_prefix("rel ")?.trim();
    let mut start: usize = 0;
    let mut terms: Vec<&str> = Vec::new();
    for (offset, ch) in body.char_indices() {
        if offset > start && matches!(ch, '+' | '-') {
            terms.push(&body[start..offset]);
            start = offset;
        }
    }
    terms.push(&body[start..]);
    for term in terms {
        let term: &str = term.trim();
        let negative: bool = term.starts_with('-');
        let value: u64 = parse_hex_literal(term.trim_start_matches(['+', '-']).trim())?;
        if address.is_none() && !negative {
            address = Some(value);
        } else {
            let value: i64 = i64::try_from(value).ok()?;
            displacement = displacement.checked_add(if negative { -value } else { value })?;
        }
    }
    address?.checked_add_signed(displacement)
}

fn parse_hex_literal(token: &str) -> Option<u64> {
    if let Some(stripped) = token.strip_suffix('h') {
        return u64::from_str_radix(stripped, 16).ok();
    }
    if let Some(stripped) = token.strip_prefix("0x") {
        return u64::from_str_radix(stripped, 16).ok();
    }
    token.parse::<u64>().ok()
}

fn parse_offset(token: &str) -> Option<i64> {
    let core: &str = token.split(['+', '-']).next().unwrap_or(token);
    let core: &str = core.trim();
    if core.contains('*') {
        return None;
    }
    if let Some(stripped) = core.strip_suffix('h') {
        return i64::from_str_radix(stripped, 16).ok();
    }
    if let Some(stripped) = core.strip_prefix("0x") {
        return i64::from_str_radix(stripped, 16).ok();
    }
    core.parse::<i64>().ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum OutPort {
    Return,
    Argument(u16),
    ArgumentMemory { argument: u16, offset: i64 },
    ArgumentDeref { argument: u16, offset: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum InPort {
    Argument(u16),
    ArgumentMemory { argument: u16, offset: i64 },
    ArgumentDeref { argument: u16, offset: i64 },
    Global(PathId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum PointerTarget {
    ArgumentMemory { argument: u16, offset: i64 },
    Global(u64),
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
    pub(crate) input: InPort,
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
    pub(crate) propagations: BTreeMap<InPort, BTreeMap<OutPort, PropValue>>,
    pub(crate) frames: Vec<SinkFrame>,
    pub(crate) pointer_stores: BTreeMap<(u16, i64), PointerTarget>,
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
        input: InPort,
        out: OutPort,
        kinds: KindSet,
        features: FeatureSet,
        path: &[TaintStep],
    ) {
        let entry: &mut PropValue = self
            .propagations
            .entry(input)
            .or_default()
            .entry(out)
            .or_default();
        entry.kinds.insert(kinds);
        entry.features.insert(features);
        if entry.path.is_empty() {
            entry.path = path.to_vec();
        }
    }

    pub(crate) fn add_pointer_store(&mut self, argument: u16, offset: i64, target: PointerTarget) {
        self.pointer_stores
            .entry((argument, offset))
            .or_insert(target);
    }

    pub(crate) fn add_frame(&mut self, frame: SinkFrame) {
        let duplicate: bool = self.frames.iter().any(|f: &SinkFrame| {
            f.input == frame.input
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
            .flat_map(|(input, outs): (&InPort, &BTreeMap<OutPort, PropValue>)| {
                outs.iter()
                    .map(move |(out, value): (&OutPort, &PropValue)| {
                        (*input, *out, value.kinds.bits(), value.features.bits())
                    })
            })
            .collect();
        let mut frames: Vec<FrameKey> = self
            .frames
            .iter()
            .map(|f: &SinkFrame| {
                (
                    f.input,
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
            pointer_stores: self.pointer_stores.clone(),
        }
    }
}

type GenKey = (OutPort, u64, u64);
type PropKey = (InPort, OutPort, u64, u64);
type FrameKey = (InPort, bool, u64, u64, u64, u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SummaryKey {
    generations: Vec<GenKey>,
    propagations: Vec<PropKey>,
    frames: Vec<FrameKey>,
    pointer_stores: BTreeMap<(u16, i64), PointerTarget>,
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
    fn a_rip_relative_global_interns_by_address_not_by_spelling() {
        let mut arena: Arena = Arena::default();
        let padded: PathId = arena.location(&ValueId::memory("qword [rel 0A0h]"));
        let bare: PathId = arena.location(&ValueId::memory("[rel A0h]"));
        assert_eq!(padded, bare);
        let displaced: PathId = arena.location(&ValueId::memory("[rel 140007038h+8]"));
        let folded: PathId = arena.location(&ValueId::memory("[rel 140007040h]"));
        assert_eq!(displaced, folded);
        let neighbour: PathId = arena.location(&ValueId::memory("[rel 140007048h]"));
        assert_ne!(folded, neighbour);
    }

    #[test]
    fn an_interned_memory_location_reports_its_base_and_offset() {
        let mut arena: Arena = Arena::default();
        let field: PathId = arena.location(&ValueId::memory("[@rcx+18h]"));
        let whole: PathId = arena.location(&ValueId::memory("[@rcx]"));
        let register: PathId = arena.location(&ValueId::register("rcx"));
        assert_eq!(arena.memory_projection(field), Some(("@rcx", 0x18)));
        assert_eq!(arena.memory_projection(whole), Some(("@rcx", 0)));
        assert_eq!(arena.memory_projection(register), None);
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
