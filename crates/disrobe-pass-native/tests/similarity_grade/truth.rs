use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{Decoder, DecoderOptions, Instruction};
use object::{Object, ObjectSection, ObjectSymbol, SectionIndex, SymbolKind};

pub(crate) type Address = u64;

const THUNK_CEILING: u64 = 16;

const SMALL_CEILING: u64 = 64;

const MEDIUM_CEILING: u64 = 256;

const SHAPE_BYTE_LIMIT: u64 = 16384;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;

const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum SizeBand {
    Thunk,
    Small,
    Medium,
    Large,
}

impl SizeBand {
    pub(crate) const ALL: [Self; 4] = [Self::Thunk, Self::Small, Self::Medium, Self::Large];

    pub(crate) const fn of(size: u64) -> Self {
        if size <= THUNK_CEILING {
            Self::Thunk
        } else if size <= SMALL_CEILING {
            Self::Small
        } else if size <= MEDIUM_CEILING {
            Self::Medium
        } else {
            Self::Large
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Thunk => "1 to 16 bytes",
            Self::Small => "17 to 64 bytes",
            Self::Medium => "65 to 256 bytes",
            Self::Large => "over 256 bytes",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct SectionExtent<'a> {
    start: u64,
    end: u64,
    body: &'a [u8],
}

#[derive(Debug)]
pub(crate) struct ImageSymbols {
    names_at: BTreeMap<Address, BTreeSet<String>>,
    address_of: BTreeMap<String, Address>,
    size_at: BTreeMap<Address, u64>,
    shape_at: BTreeMap<Address, u64>,
    format: &'static str,
}

impl ImageSymbols {
    pub(crate) fn read(bytes: &[u8]) -> Option<Self> {
        let file: object::File<'_> = object::File::parse(bytes).ok()?;
        let bitness: u32 = match file.architecture() {
            object::Architecture::X86_64 => 64,
            object::Architecture::I386 => 32,
            _ => 0,
        };

        let mut extents: BTreeMap<usize, SectionExtent<'_>> = BTreeMap::new();
        for section in file.sections() {
            let start: u64 = section.address();
            let Ok(body): Result<&[u8], object::Error> = section.data() else {
                continue;
            };
            extents.insert(
                section.index().0,
                SectionExtent {
                    start,
                    end: start.saturating_add(section.size()),
                    body,
                },
            );
        }

        let mut boundaries: BTreeMap<usize, BTreeSet<u64>> = BTreeMap::new();
        for symbol in file.symbols() {
            let Some(index): Option<SectionIndex> = symbol.section_index() else {
                continue;
            };
            let address: u64 = symbol.address();
            if address == 0 {
                continue;
            }
            boundaries.entry(index.0).or_default().insert(address);
        }

        let mut carried: Self = Self {
            names_at: BTreeMap::new(),
            address_of: BTreeMap::new(),
            size_at: BTreeMap::new(),
            shape_at: BTreeMap::new(),
            format: format_label(file.format()),
        };
        let mut sections_of: BTreeMap<Address, usize> = BTreeMap::new();
        let mut declared: BTreeMap<Address, u64> = BTreeMap::new();
        for symbol in file.symbols() {
            if symbol.kind() != SymbolKind::Text {
                continue;
            }
            let Ok(name): Result<&str, object::Error> = symbol.name() else {
                continue;
            };
            let Some(index): Option<SectionIndex> = symbol.section_index() else {
                continue;
            };
            let address: u64 = symbol.address();
            if name.is_empty() || address == 0 {
                continue;
            }
            carried
                .names_at
                .entry(address)
                .or_default()
                .insert(name.to_owned());
            carried.address_of.entry(name.to_owned()).or_insert(address);
            sections_of.insert(address, index.0);
            let slot: &mut u64 = declared.entry(address).or_default();
            *slot = (*slot).max(symbol.size());
        }

        for address in carried.names_at.keys().copied() {
            let Some(index): Option<&usize> = sections_of.get(&address) else {
                continue;
            };
            let Some(extent): Option<&SectionExtent<'_>> = extents.get(index) else {
                continue;
            };
            let size: u64 = match declared.get(&address).copied().unwrap_or_default() {
                0 => gap_to_next(boundaries.get(index), address, extent.end),
                stated => stated.min(extent.end.saturating_sub(address)),
            };
            carried.size_at.insert(address, size);
            if let Some(shape) = shape_of(extent, address, size, bitness) {
                carried.shape_at.insert(address, shape);
            }
        }

        Some(carried)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.names_at.is_empty()
    }

    pub(crate) fn function_count(&self) -> usize {
        self.names_at.len()
    }

    pub(crate) fn name_count(&self) -> usize {
        self.address_of.len()
    }

    pub(crate) const fn format(&self) -> &'static str {
        self.format
    }
}

const fn format_label(format: object::BinaryFormat) -> &'static str {
    match format {
        object::BinaryFormat::Elf => "elf",
        object::BinaryFormat::Pe => "pe",
        object::BinaryFormat::MachO => "macho",
        object::BinaryFormat::Coff => "coff",
        object::BinaryFormat::Wasm => "wasm",
        object::BinaryFormat::Xcoff => "xcoff",
        _ => "unrecognised container",
    }
}

fn gap_to_next(boundaries: Option<&BTreeSet<u64>>, address: u64, section_end: u64) -> u64 {
    let next: u64 = boundaries
        .and_then(|set: &BTreeSet<u64>| set.range(address.saturating_add(1)..).next().copied())
        .unwrap_or(section_end)
        .min(section_end);
    next.saturating_sub(address)
}

fn shape_of(extent: &SectionExtent<'_>, address: u64, size: u64, bitness: u32) -> Option<u64> {
    if size == 0 || size > SHAPE_BYTE_LIMIT {
        return None;
    }
    let offset: usize = usize::try_from(address.checked_sub(extent.start)?).ok()?;
    let span: usize = usize::try_from(size).ok()?;
    let body: &[u8] = extent.body.get(offset..offset.checked_add(span)?)?;
    Some(match bitness {
        32 | 64 => mnemonic_hash(bitness, body, address),
        _ => byte_hash(body),
    })
}

fn mnemonic_hash(bitness: u32, body: &[u8], address: u64) -> u64 {
    let mut decoder: Decoder<'_> = Decoder::with_ip(bitness, body, address, DecoderOptions::NONE);
    let mut instruction: Instruction = Instruction::default();
    let mut hash: u64 = FNV_OFFSET;
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        if instruction.is_invalid() {
            break;
        }
        hash = fold(hash, instruction.mnemonic() as u64);
    }
    hash
}

fn byte_hash(body: &[u8]) -> u64 {
    body.iter().fold(FNV_OFFSET, |hash: u64, byte: &u8| {
        fold(hash, u64::from(*byte))
    })
}

const fn fold(hash: u64, value: u64) -> u64 {
    (hash ^ value).wrapping_mul(FNV_PRIME)
}

#[derive(Debug, Clone)]
pub(crate) struct Correspondence {
    pub(crate) left: Address,
    pub(crate) accepted: BTreeSet<Address>,
    pub(crate) names: BTreeSet<String>,
    pub(crate) band: SizeBand,
    pub(crate) unchanged: bool,
    pub(crate) folded: bool,
}

#[derive(Debug, Default)]
pub(crate) struct TruthTable {
    pub(crate) entries: BTreeMap<Address, Correspondence>,
    pub(crate) left_only: BTreeSet<Address>,
    pub(crate) band_of: BTreeMap<Address, SizeBand>,
    pub(crate) dropped_left_names: usize,
    pub(crate) dropped_right_names: usize,
    pub(crate) folded_left_addresses: usize,
    pub(crate) folded_right_addresses: usize,
    pub(crate) left_functions: usize,
    pub(crate) right_functions: usize,
    pub(crate) left_names: usize,
    pub(crate) right_names: usize,
}

impl TruthTable {
    pub(crate) fn derive(left: &ImageSymbols, right: &ImageSymbols) -> Self {
        let mut table: Self = Self {
            left_functions: left.function_count(),
            right_functions: right.function_count(),
            left_names: left.name_count(),
            right_names: right.name_count(),
            dropped_left_names: left
                .address_of
                .keys()
                .filter(|name: &&String| !right.address_of.contains_key(*name))
                .count(),
            dropped_right_names: right
                .address_of
                .keys()
                .filter(|name: &&String| !left.address_of.contains_key(*name))
                .count(),
            folded_left_addresses: fold_count(left),
            folded_right_addresses: fold_count(right),
            ..Self::default()
        };

        for (address, names) in &left.names_at {
            let band: SizeBand =
                SizeBand::of(left.size_at.get(address).copied().unwrap_or_default());
            table.band_of.insert(*address, band);
            let accepted: BTreeSet<Address> = names
                .iter()
                .filter_map(|name: &String| right.address_of.get(name).copied())
                .collect();
            if accepted.is_empty() {
                table.left_only.insert(*address);
                continue;
            }
            let own_shape: Option<u64> = left.shape_at.get(address).copied();
            let unchanged: bool = own_shape.is_some_and(|shape: u64| {
                accepted
                    .iter()
                    .any(|other: &Address| right.shape_at.get(other).copied() == Some(shape))
            });
            let folded: bool = names.len() > 1
                || accepted.iter().any(|other: &Address| {
                    right
                        .names_at
                        .get(other)
                        .is_some_and(|held: &BTreeSet<String>| held.len() > 1)
                });
            table.entries.insert(
                *address,
                Correspondence {
                    left: *address,
                    accepted,
                    names: names.clone(),
                    band,
                    unchanged,
                    folded,
                },
            );
        }
        table
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn changed_len(&self) -> usize {
        self.entries
            .values()
            .filter(|entry: &&Correspondence| !entry.unchanged)
            .count()
    }

    pub(crate) fn folded_correspondences(&self) -> usize {
        self.entries
            .values()
            .filter(|entry: &&Correspondence| entry.folded)
            .count()
    }
}

fn fold_count(side: &ImageSymbols) -> usize {
    side.names_at
        .values()
        .filter(|names: &&BTreeSet<String>| names.len() > 1)
        .count()
}
