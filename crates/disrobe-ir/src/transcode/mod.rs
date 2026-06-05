use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::Arc;

use crate::Rung;
use crate::envelope::Envelope;
use crate::error::{EnvelopeError, Result};

pub type EnvelopeVersion = u16;

pub type TranscodeFn = Arc<
    dyn Fn(&Envelope, EnvelopeVersion, Rung, EnvelopeVersion, Rung) -> Result<Envelope>
        + Send
        + Sync,
>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TranscodeKey {
    pub from_version: EnvelopeVersion,
    pub from_rung: Rung,
    pub to_version: EnvelopeVersion,
    pub to_rung: Rung,
}

impl TranscodeKey {
    #[inline]
    #[must_use]
    pub const fn new(
        from_version: EnvelopeVersion,
        from_rung: Rung,
        to_version: EnvelopeVersion,
        to_rung: Rung,
    ) -> Self {
        Self {
            from_version,
            from_rung,
            to_version,
            to_rung,
        }
    }
}

#[derive(Clone)]
pub struct TranscodeStep {
    pub key: TranscodeKey,
    pub transform: TranscodeFn,
}

impl fmt::Debug for TranscodeStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TranscodeStep")
            .field("key", &self.key)
            .field("transform", &"<fn>")
            .finish()
    }
}

#[derive(Default, Clone)]
pub struct TranscodeRegistry {
    entries: BTreeMap<TranscodeKey, TranscodeStep>,
}

impl fmt::Debug for TranscodeRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TranscodeRegistry")
            .field(
                "entries",
                &self.entries.keys().collect::<Vec<&TranscodeKey>>(),
            )
            .finish()
    }
}

impl TranscodeRegistry {
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, step: TranscodeStep) -> bool {
        self.entries.insert(step.key, step).is_none()
    }

    pub fn register_fn<F>(
        &mut self,
        from_version: EnvelopeVersion,
        from_rung: Rung,
        to_version: EnvelopeVersion,
        to_rung: Rung,
        transform: F,
    ) -> bool
    where
        F: Fn(&Envelope, EnvelopeVersion, Rung, EnvelopeVersion, Rung) -> Result<Envelope>
            + Send
            + Sync
            + 'static,
    {
        let key: TranscodeKey = TranscodeKey::new(from_version, from_rung, to_version, to_rung);
        let step: TranscodeStep = TranscodeStep {
            key,
            transform: Arc::new(transform),
        };
        self.register(step)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, key: TranscodeKey) -> bool {
        self.entries.contains_key(&key)
    }

    pub fn step(&self, key: TranscodeKey) -> Option<&TranscodeStep> {
        self.entries.get(&key)
    }

    pub fn merge(&mut self, other: Self) {
        for (key, step) in other.entries {
            self.entries.insert(key, step);
        }
    }

    #[must_use]
    pub fn merged_with(mut self, other: Self) -> Self {
        self.merge(other);
        self
    }

    pub fn keys(&self) -> impl Iterator<Item = TranscodeKey> + '_ {
        self.entries.keys().copied()
    }

    pub fn baseline_v0_1() -> Self {
        let mut registry: Self = Self::new();
        let v: EnvelopeVersion = crate::ENVELOPE_FORMAT_VERSION;
        for rung in ALL_RUNGS {
            registry.register_fn(v, rung, v, rung, identity_transcode);
        }
        registry
    }
}

const ALL_RUNGS: [Rung; 5] = [Rung::Raw, Rung::Disasm, Rung::Mir, Rung::Hir, Rung::Surface];

fn identity_transcode(
    envelope: &Envelope,
    from_version: EnvelopeVersion,
    from_rung: Rung,
    to_version: EnvelopeVersion,
    to_rung: Rung,
) -> Result<Envelope> {
    if envelope.version != from_version {
        return Err(EnvelopeError::BadVersion(envelope.version));
    }
    if envelope.rung != from_rung {
        return Err(EnvelopeError::BadRung(envelope.rung as u8));
    }
    let mut next: Envelope = Envelope::new(to_rung, envelope.hot.clone(), envelope.cold.clone());
    next.version = to_version;
    next.flags = envelope.flags;
    Ok(next)
}

impl Envelope {
    pub fn transcode_to(
        &self,
        target_version: EnvelopeVersion,
        target_rung: Rung,
        registry: &TranscodeRegistry,
    ) -> Result<Self> {
        let start: TranscodeNode = TranscodeNode {
            version: self.version,
            rung: self.rung,
        };
        let goal: TranscodeNode = TranscodeNode {
            version: target_version,
            rung: target_rung,
        };

        if start == goal {
            let mut clone: Self = Self::new(self.rung, self.hot.clone(), self.cold.clone());
            clone.version = self.version;
            clone.flags = self.flags;
            return Ok(clone);
        }

        let Some(path): Option<Vec<TranscodeKey>> = shortest_path(registry, start, goal) else {
            return Err(EnvelopeError::RkyvAccess(format!(
                "no transcode path from (v{}, {:?}) to (v{}, {:?})",
                self.version, self.rung, target_version, target_rung
            )));
        };

        let mut current: Self = Self::new(self.rung, self.hot.clone(), self.cold.clone());
        current.version = self.version;
        current.flags = self.flags;

        for key in path {
            let Some(step) = registry.step(key) else {
                return Err(EnvelopeError::RkyvAccess(format!(
                    "registry lost step {key:?} mid-path"
                )));
            };
            current = (step.transform)(
                &current,
                key.from_version,
                key.from_rung,
                key.to_version,
                key.to_rung,
            )?;
            if current.version != key.to_version || current.rung != key.to_rung {
                return Err(EnvelopeError::RkyvAccess(format!(
                    "transcode step {key:?} produced (v{}, {:?})",
                    current.version, current.rung
                )));
            }
        }

        Ok(current)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TranscodeNode {
    version: EnvelopeVersion,
    rung: Rung,
}

fn shortest_path(
    registry: &TranscodeRegistry,
    start: TranscodeNode,
    goal: TranscodeNode,
) -> Option<Vec<TranscodeKey>> {
    let mut visited: BTreeSet<TranscodeNode> = BTreeSet::new();
    let mut predecessor: BTreeMap<TranscodeNode, (TranscodeNode, TranscodeKey)> = BTreeMap::new();
    let mut frontier: VecDeque<TranscodeNode> = VecDeque::new();
    visited.insert(start);
    frontier.push_back(start);

    while let Some(current) = frontier.pop_front() {
        if current == goal {
            return Some(reconstruct(&predecessor, start, goal));
        }
        for key in registry.keys() {
            if key.from_version != current.version || key.from_rung != current.rung {
                continue;
            }
            let next: TranscodeNode = TranscodeNode {
                version: key.to_version,
                rung: key.to_rung,
            };
            if !visited.insert(next) {
                continue;
            }
            predecessor.insert(next, (current, key));
            if next == goal {
                return Some(reconstruct(&predecessor, start, goal));
            }
            frontier.push_back(next);
        }
    }
    None
}

fn reconstruct(
    predecessor: &BTreeMap<TranscodeNode, (TranscodeNode, TranscodeKey)>,
    start: TranscodeNode,
    goal: TranscodeNode,
) -> Vec<TranscodeKey> {
    let mut reverse: Vec<TranscodeKey> = Vec::new();
    let mut node: TranscodeNode = goal;
    while node != start {
        let Some((prev, key)) = predecessor.get(&node) else {
            break;
        };
        reverse.push(*key);
        node = *prev;
    }
    reverse.reverse();
    reverse
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::ENVELOPE_FORMAT_VERSION;
    use crate::payload::{DisasmInstruction, DisasmPayload, RawPayload, encode_disasm, encode_raw};

    fn raw_envelope_for(rung: Rung) -> Envelope {
        let raw: RawPayload = RawPayload {
            source_path: "x.bin".to_owned(),
            source_bytes: vec![1, 2, 3, 4, 5],
            source_hash: [0x33; 32],
            detected_format: Some("bin".to_owned()),
        };
        let hot: Vec<u8> = encode_raw(&raw).expect("encode raw");
        Envelope::new(rung, hot, vec![])
    }

    #[test]
    fn baseline_registry_has_identity_for_every_rung() {
        let registry: TranscodeRegistry = TranscodeRegistry::baseline_v0_1();
        assert_eq!(registry.len(), 5);
        for rung in [Rung::Raw, Rung::Disasm, Rung::Mir, Rung::Hir, Rung::Surface] {
            let key: TranscodeKey =
                TranscodeKey::new(ENVELOPE_FORMAT_VERSION, rung, ENVELOPE_FORMAT_VERSION, rung);
            assert!(registry.contains(key), "missing identity for {rung:?}");
        }
    }

    #[test]
    fn identity_transcode_round_trip_per_rung() {
        let registry: TranscodeRegistry = TranscodeRegistry::baseline_v0_1();
        for rung in [Rung::Raw, Rung::Disasm, Rung::Mir, Rung::Hir, Rung::Surface] {
            let env: Envelope = raw_envelope_for(rung);
            let transcoded: Envelope = env
                .transcode_to(ENVELOPE_FORMAT_VERSION, rung, &registry)
                .expect("identity transcode");
            assert_eq!(transcoded.rung, rung);
            assert_eq!(transcoded.version, ENVELOPE_FORMAT_VERSION);
            assert_eq!(transcoded.hot, env.hot);
            assert_eq!(transcoded.cold, env.cold);
            assert_eq!(transcoded.root_hash, env.root_hash);
        }
    }

    #[test]
    fn cross_rung_transcode_via_mock_pass() {
        let mut registry: TranscodeRegistry = TranscodeRegistry::baseline_v0_1();
        registry.register_fn(
            ENVELOPE_FORMAT_VERSION,
            Rung::Raw,
            ENVELOPE_FORMAT_VERSION,
            Rung::Disasm,
            |env: &Envelope, _fv: EnvelopeVersion, _fr: Rung, tv: EnvelopeVersion, tr: Rung| {
                let raw: RawPayload = crate::payload::decode_raw(&env.hot)?;
                let disasm: DisasmPayload = DisasmPayload {
                    source_hash: raw.source_hash,
                    instructions: raw
                        .source_bytes
                        .iter()
                        .copied()
                        .enumerate()
                        .map(|(i, b): (usize, u8)| DisasmInstruction {
                            offset: i as u64,
                            bytes: vec![b],
                            mnemonic: "db".to_owned(),
                            operands: vec![format!("{b:#x}")],
                        })
                        .collect::<Vec<DisasmInstruction>>(),
                    symbol_table: Vec::new(),
                };
                let hot: Vec<u8> = encode_disasm(&disasm)?;
                let mut next: Envelope = Envelope::new(tr, hot, env.cold.clone());
                next.version = tv;
                next.flags = env.flags;
                Ok(next)
            },
        );

        let raw_env: Envelope = raw_envelope_for(Rung::Raw);
        let disasm_env: Envelope = raw_env
            .transcode_to(ENVELOPE_FORMAT_VERSION, Rung::Disasm, &registry)
            .expect("cross-rung transcode");
        assert_eq!(disasm_env.rung, Rung::Disasm);
        let decoded: DisasmPayload =
            crate::payload::decode_disasm(&disasm_env.hot).expect("decode disasm");
        assert_eq!(decoded.instructions.len(), 5);
        assert_eq!(decoded.instructions[0].mnemonic, "db");
    }

    #[test]
    fn missing_path_hard_fail() {
        let registry: TranscodeRegistry = TranscodeRegistry::baseline_v0_1();
        let raw_env: Envelope = raw_envelope_for(Rung::Raw);
        let err: EnvelopeError = raw_env
            .transcode_to(ENVELOPE_FORMAT_VERSION, Rung::Surface, &registry)
            .expect_err("no path Raw -> Surface in baseline");
        let text: String = format!("{err}");
        assert!(
            text.contains("no transcode path"),
            "unexpected error: {text}"
        );
    }

    #[test]
    fn registry_merging_combines_entries() {
        let mut a: TranscodeRegistry = TranscodeRegistry::new();
        a.register_fn(
            ENVELOPE_FORMAT_VERSION,
            Rung::Raw,
            ENVELOPE_FORMAT_VERSION,
            Rung::Raw,
            identity_transcode,
        );
        let mut b: TranscodeRegistry = TranscodeRegistry::new();
        b.register_fn(
            ENVELOPE_FORMAT_VERSION,
            Rung::Disasm,
            ENVELOPE_FORMAT_VERSION,
            Rung::Disasm,
            identity_transcode,
        );
        let merged: TranscodeRegistry = a.merged_with(b);
        assert_eq!(merged.len(), 2);
        assert!(merged.contains(TranscodeKey::new(
            ENVELOPE_FORMAT_VERSION,
            Rung::Raw,
            ENVELOPE_FORMAT_VERSION,
            Rung::Raw,
        )));
        assert!(merged.contains(TranscodeKey::new(
            ENVELOPE_FORMAT_VERSION,
            Rung::Disasm,
            ENVELOPE_FORMAT_VERSION,
            Rung::Disasm,
        )));
    }

    #[test]
    fn baseline_identity_preserves_root_hash_across_transcode() {
        let registry: TranscodeRegistry = TranscodeRegistry::baseline_v0_1();
        let env: Envelope = raw_envelope_for(Rung::Mir);
        let out: Envelope = env
            .transcode_to(ENVELOPE_FORMAT_VERSION, Rung::Mir, &registry)
            .expect("identity transcode");
        assert_eq!(out.root_hash, env.root_hash);
    }
}
