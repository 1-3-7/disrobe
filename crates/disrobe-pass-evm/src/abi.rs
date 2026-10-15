use std::collections::BTreeMap;

use serde::Serialize;

use crate::exec::Evidence;
use crate::expr::CdLoc;
use crate::function::Trace;
use crate::u256::U256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TypeBasis {
    Mask,
    RangeCheck,
    SignExtension,
    BoolNormalisation,
    SignedArithmetic,
    DynamicStride,
    ElementReads,
    DynamicBytes,
    DynamicUnscaled,
    Unconstrained,
}

impl TypeBasis {
    #[must_use]
    pub const fn decisive(self) -> bool {
        !matches!(self, Self::Unconstrained | Self::DynamicUnscaled)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InferredArg {
    pub index: u16,
    #[serde(rename = "type")]
    pub ty: String,
    pub basis: TypeBasis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mutability {
    Pure,
    View,
    NonPayable,
    Payable,
}

impl Mutability {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pure => "pure",
            Self::View => "view",
            Self::NonPayable => "nonpayable",
            Self::Payable => "payable",
        }
    }
}

const WRITES: [u8; 13] = [
    0x55, 0x5d, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xf0, 0xf1, 0xf2, 0xf4, 0xf5, 0xff,
];
const READS: [u8; 21] = [
    0x54, 0x5c, 0x31, 0x47, 0x32, 0x33, 0x3a, 0x3b, 0x3c, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
    0x46, 0x48, 0x49, 0x4a, 0x30,
];

#[must_use]
pub(crate) fn mutability(trace: &Trace) -> (Mutability, Vec<&'static str>) {
    let writes: Vec<&'static str> = WRITES
        .iter()
        .filter(|op: &&u8| trace.executed(**op))
        .filter_map(|op: &u8| crate::opcode::info(*op).map(|info| info.name))
        .collect();
    let mut reads: Vec<&'static str> = READS
        .iter()
        .filter(|op: &&u8| trace.executed(**op))
        .filter_map(|op: &u8| crate::opcode::info(*op).map(|info| info.name))
        .collect();
    if trace.external_static_call {
        reads.push("STATICCALL");
    }
    if !trace.guarded {
        return (Mutability::Payable, writes);
    }
    if !writes.is_empty() {
        return (Mutability::NonPayable, writes);
    }
    if !reads.is_empty() {
        return (Mutability::View, reads);
    }
    (Mutability::Pure, Vec::new())
}

fn word_type(evidence: &[Evidence], range_checks: bool) -> (String, TypeBasis) {
    for item in evidence {
        match item {
            Evidence::HighZero(bits) if range_checks => match bits {
                160 => return ("address".to_owned(), TypeBasis::RangeCheck),
                1 => return ("bool".to_owned(), TypeBasis::RangeCheck),
                width if width.is_multiple_of(8) => {
                    return (format!("uint{width}"), TypeBasis::RangeCheck);
                }
                _ => {}
            },
            Evidence::LowZero(bits) if range_checks && bits.is_multiple_of(8) => {
                return (format!("bytes{}", bits / 8), TypeBasis::RangeCheck);
            }
            Evidence::Mask(mask) => {
                if let Some(bits) = mask
                    .low_mask_bits()
                    .filter(|bits: &u32| bits.is_multiple_of(8) && *bits < 256)
                {
                    let ty: String = if bits == 160 {
                        "address".to_owned()
                    } else {
                        format!("uint{bits}")
                    };
                    return (ty, TypeBasis::Mask);
                }
                if let Some(bits) = mask
                    .high_mask_bits()
                    .filter(|bits: &u32| bits.is_multiple_of(8) && *bits < 256)
                {
                    return (format!("bytes{}", bits / 8), TypeBasis::Mask);
                }
            }
            Evidence::SignExtend(index) => {
                return (
                    format!("int{}", (u32::from(*index) + 1) * 8),
                    TypeBasis::SignExtension,
                );
            }
            Evidence::Bool => return ("bool".to_owned(), TypeBasis::BoolNormalisation),
            _ => {}
        }
    }
    if evidence.contains(&Evidence::Signed) {
        return ("int256".to_owned(), TypeBasis::SignedArithmetic);
    }
    ("uint256".to_owned(), TypeBasis::Unconstrained)
}

fn bounded_copy(length: &[Evidence]) -> Option<bool> {
    let limit: u64 = length.iter().find_map(|e: &Evidence| match e {
        Evidence::Bound(limit) => Some(*limit),
        _ => None,
    })?;
    let size: u64 = length.iter().find_map(|e: &Evidence| match e {
        Evidence::FixedCopy(size) => Some(*size),
        _ => None,
    })?;
    if limit == 0 {
        return None;
    }
    Some(
        limit
            .checked_mul(32)
            .and_then(|words: u64| words.checked_add(32))
            == Some(size),
    )
}

#[must_use]
pub(crate) fn arguments(trace: &Trace, range_checks: bool) -> Vec<InferredArg> {
    let mut heads: BTreeMap<u16, Vec<Evidence>> = BTreeMap::new();
    let mut elements: BTreeMap<u16, Vec<Evidence>> = BTreeMap::new();
    let mut lengths: BTreeMap<u16, Vec<Evidence>> = BTreeMap::new();
    for (loc, evidence) in &trace.evidence {
        match loc {
            CdLoc::Head(index) => heads.entry(*index).or_default().push(*evidence),
            CdLoc::Element(index) => elements.entry(*index).or_default().push(*evidence),
            CdLoc::Length(index) => lengths.entry(*index).or_default().push(*evidence),
            CdLoc::Word0 | CdLoc::Nested(_) => {}
        }
    }
    let highest_read: Option<u16> = trace
        .evidence
        .iter()
        .filter_map(|(loc, _)| match loc {
            CdLoc::Head(index) => Some(*index),
            _ => None,
        })
        .max();
    let from_reads: u64 = highest_read.map_or(0, |index: u16| u64::from(index) + 1);
    let from_check: u64 = trace.head_bytes.map_or(0, |bytes: u64| bytes / 32);
    let count: u64 = from_reads.max(from_check).min(1024);
    let empty: Vec<Evidence> = Vec::new();
    (0..count as u16)
        .map(|index: u16| {
            let head: &[Evidence] = heads.get(&index).map_or(&empty[..], Vec::as_slice);
            let dynamic: bool = head.iter().any(|e: &Evidence| {
                matches!(
                    e,
                    Evidence::Dynamic | Evidence::Offset | Evidence::NestedDynamic
                )
            });
            let (ty, basis): (String, TypeBasis) = if dynamic {
                let length: &[Evidence] = lengths.get(&index).map_or(&empty[..], Vec::as_slice);
                let stride: Option<U256> = length.iter().find_map(|e: &Evidence| match e {
                    Evidence::Stride(stride) => Some(*stride),
                    _ => None,
                });
                if head.contains(&Evidence::NestedDynamic) {
                    ("bytes[]".to_owned(), TypeBasis::DynamicStride)
                } else if stride == Some(U256::from_u64(32)) {
                    let element: &[Evidence] =
                        elements.get(&index).map_or(&empty[..], Vec::as_slice);
                    let (inner, _) = word_type(element, range_checks);
                    (format!("{inner}[]"), TypeBasis::DynamicStride)
                } else if let Some(element_words) = bounded_copy(length) {
                    if element_words {
                        let element: &[Evidence] =
                            elements.get(&index).map_or(&empty[..], Vec::as_slice);
                        let (inner, _) = word_type(element, range_checks);
                        (format!("{inner}[]"), TypeBasis::DynamicStride)
                    } else {
                        ("bytes".to_owned(), TypeBasis::DynamicBytes)
                    }
                } else if stride == Some(U256::ONE) || length.contains(&Evidence::BytesLength) {
                    ("bytes".to_owned(), TypeBasis::DynamicBytes)
                } else if let Some(element) = elements
                    .get(&index)
                    .filter(|element: &&Vec<Evidence>| element.contains(&Evidence::Loaded))
                {
                    let (inner, _) = word_type(element, range_checks);
                    (format!("{inner}[]"), TypeBasis::ElementReads)
                } else {
                    ("bytes".to_owned(), TypeBasis::DynamicUnscaled)
                }
            } else {
                word_type(head, range_checks)
            };
            InferredArg { index, ty, basis }
        })
        .collect()
}
