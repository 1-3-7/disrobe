use std::collections::BTreeMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::rc::Rc;

use crate::expr::{Expr, Val, affine, konst, node};
use crate::u256::U256;

const MAX_CONST_ADDRESS: u64 = 1 << 20;
const MAX_COPY: u64 = 4096;
const MAX_BYTES: usize = 1 << 16;
const MAX_REGIONS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Byte {
    Known(u8),
    Part(Val, u8),
    Unknown(u32),
}

#[derive(Debug, Clone, Default)]
struct Region {
    bytes: BTreeMap<u64, Byte>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Memory {
    regions: Rc<BTreeMap<Vec<u64>, Region>>,
    size: usize,
}

struct Address {
    base: Vec<u64>,
    offset: u64,
}

fn locate(address: &Val) -> Option<Address> {
    let form = affine(address);
    let mut base: Vec<u64> = form.terms.iter().map(|term: &Val| term.hash).collect();
    base.sort_unstable();
    let low: [u8; 32] = form.constant.to_be_bytes();
    let mut word: [u8; 8] = [0; 8];
    word.copy_from_slice(&low[24..]);
    let offset: u64 = u64::from_be_bytes(word);
    if base.is_empty()
        && form
            .constant
            .to_u64()
            .is_none_or(|value: u64| value >= MAX_CONST_ADDRESS)
    {
        return None;
    }
    Some(Address { base, offset })
}

fn count(len: &Val, limit: u64) -> Option<u64> {
    match len.expr {
        Expr::Const(value) => value.to_u64().filter(|count: &u64| *count <= limit),
        _ => None,
    }
}

impl Memory {
    fn region(&mut self, base: &[u64]) -> Option<&mut BTreeMap<u64, Byte>> {
        let regions: &mut BTreeMap<Vec<u64>, Region> = Rc::make_mut(&mut self.regions);
        if !regions.contains_key(base) && regions.len() >= MAX_REGIONS {
            return None;
        }
        Some(&mut regions.entry(base.to_vec()).or_default().bytes)
    }

    fn put(&mut self, address: &Address, bytes: Vec<Byte>) {
        if self.size + bytes.len() > MAX_BYTES {
            return;
        }
        let Some(region) = self.region(&address.base) else {
            return;
        };
        let mut added: usize = 0;
        for (index, byte) in bytes.into_iter().enumerate() {
            if region
                .insert(address.offset.wrapping_add(index as u64), byte)
                .is_none()
            {
                added += 1;
            }
        }
        self.size += added;
    }

    pub(crate) fn store(&mut self, address: &Val, value: &Val) {
        let Some(at) = locate(address) else {
            return;
        };
        if let Expr::Const(constant) = value.expr {
            let bytes: [u8; 32] = constant.to_be_bytes();
            self.put(&at, bytes.into_iter().map(Byte::Known).collect());
        } else {
            let value: Val = value.clone();
            self.put(
                &at,
                (0..32u8)
                    .map(|index: u8| Byte::Part(value.clone(), index))
                    .collect(),
            );
        }
    }

    pub(crate) fn store_byte(&mut self, address: &Val, value: &Val, pc: u32) {
        let Some(at) = locate(address) else {
            return;
        };
        let byte: Byte = match value.expr {
            Expr::Const(constant) => Byte::Known(constant.to_be_bytes()[31]),
            _ => Byte::Unknown(pc),
        };
        self.put(&at, vec![byte]);
    }

    fn byte(&self, address: &Address, index: u64) -> Option<&Byte> {
        self.regions
            .get(&address.base)
            .and_then(|region: &Region| region.bytes.get(&address.offset.wrapping_add(index)))
    }

    pub(crate) fn load(&self, address: &Val, pc: u32) -> Val {
        let Some(at) = locate(address) else {
            return node(Expr::Opaque(pc), pc);
        };
        let concrete: bool = at.base.is_empty();
        let mut known: [u8; 32] = [0; 32];
        let mut whole: Option<&Val> = None;
        let mut all_known: bool = true;
        let mut all_part: bool = true;
        for index in 0..32u64 {
            match self.byte(&at, index) {
                None => {
                    all_part = false;
                    if !concrete {
                        all_known = false;
                    }
                }
                Some(Byte::Known(byte)) => {
                    known[index as usize] = *byte;
                    all_part = false;
                }
                Some(Byte::Part(value, position)) => {
                    all_known = false;
                    if u64::from(*position) != index
                        || whole.is_some_and(|w: &Val| !Rc::ptr_eq(w, value))
                    {
                        all_part = false;
                    }
                    whole = Some(value);
                }
                Some(Byte::Unknown(_)) => {
                    all_known = false;
                    all_part = false;
                }
            }
        }
        if all_known {
            return konst(U256::from_be_bytes(known));
        }
        if all_part && let Some(value) = whole {
            return value.clone();
        }
        node(Expr::Opaque(pc), pc)
    }

    pub(crate) fn clobber(&mut self, address: &Val, len: &Val, pc: u32) {
        let Some(at) = locate(address) else {
            return;
        };
        match count(len, MAX_COPY) {
            Some(0) => {}
            Some(total) => self.put(&at, vec![Byte::Unknown(pc); total as usize]),
            None => {
                if let Some(region) = self.region(&at.base) {
                    let removed: Vec<u64> = region
                        .range(at.offset..)
                        .map(|(key, _): (&u64, &Byte)| *key)
                        .collect();
                    for key in &removed {
                        region.remove(key);
                    }
                    self.size = self.size.saturating_sub(removed.len());
                }
            }
        }
    }

    pub(crate) fn copy_in(&mut self, address: &Val, data: &[u8], len: &Val, pc: u32) {
        let (Some(at), Some(total)) = (locate(address), count(len, MAX_COPY)) else {
            self.clobber(address, len, pc);
            return;
        };
        let bytes: Vec<Byte> = (0..total)
            .map(|index: u64| Byte::Known(data.get(index as usize).copied().unwrap_or(0)))
            .collect();
        self.put(&at, bytes);
    }

    pub(crate) fn copy_within(&mut self, dest: &Val, source: &Val, len: &Val, pc: u32) {
        let (Some(to), Some(from), Some(total)) =
            (locate(dest), locate(source), count(len, MAX_COPY))
        else {
            self.clobber(dest, len, pc);
            return;
        };
        let concrete: bool = from.base.is_empty();
        let snapshot: Vec<Byte> = (0..total)
            .map(|index: u64| match self.byte(&from, index) {
                Some(byte) => byte.clone(),
                None if concrete => Byte::Known(0),
                None => Byte::Unknown(pc),
            })
            .collect();
        self.put(&to, snapshot);
    }

    pub(crate) fn words(&self, address: &Val, len: &Val, pc: u32) -> Option<Vec<Val>> {
        let total: u64 = count(len, MAX_COPY)?;
        locate(address)?;
        let mut words: Vec<Val> = Vec::new();
        let mut offset: u64 = 0;
        while offset < total {
            let at: Val = crate::expr::bin(
                crate::expr::BinOp::Add,
                address.clone(),
                konst(U256::from_u64(offset)),
                pc,
            );
            words.push(self.load(&at, pc));
            offset += 32;
        }
        Some(words)
    }

    pub(crate) fn known_bytes(&self, address: &Val, len: &Val) -> Option<Vec<u8>> {
        let at: Address = locate(address)?;
        let total: u64 = count(len, MAX_COPY)?;
        let concrete: bool = at.base.is_empty();
        (0..total)
            .map(|index: u64| match self.byte(&at, index) {
                None if concrete => Some(0),
                Some(Byte::Known(byte)) => Some(*byte),
                _ => None,
            })
            .collect()
    }

    pub(crate) fn written_bytes(&self, address: &Val, total: u64) -> Option<Vec<u8>> {
        let at: Address = locate(address)?;
        (0..total)
            .map(|index: u64| match self.byte(&at, index) {
                Some(Byte::Known(byte)) => Some(*byte),
                _ => None,
            })
            .collect()
    }

    pub(crate) fn fingerprint(&self) -> u64 {
        let mut hasher: DefaultHasher = DefaultHasher::new();
        for (base, region) in self.regions.iter() {
            base.hash(&mut hasher);
            for (key, byte) in &region.bytes {
                key.hash(&mut hasher);
                byte.hash(&mut hasher);
            }
        }
        hasher.finish()
    }
}
