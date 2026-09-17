use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::packers::pe_sections::{read_u16, read_u32};

pub const RESOURCE_DIRECTORY_HEADER_BYTES: usize = 16;
pub const RESOURCE_DIRECTORY_ENTRY_BYTES: usize = 8;
pub const RESOURCE_DATA_ENTRY_BYTES: usize = 16;

const SUBDIRECTORY_FLAG: u32 = 0x8000_0000;
const NAME_FLAG: u32 = 0x8000_0000;
const MAX_DEPTH: usize = 8;
const MAX_ENTRIES_PER_DIRECTORY: usize = 4096;
const MAX_DIRECTORIES: usize = 4096;
const MAX_LEAVES: usize = 16384;
const STRUCTURE_ALIGNMENT: u32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceKey {
    Id(u32),

    NameOffset(u32),
}

impl ResourceKey {
    const fn encode(self) -> u32 {
        match self {
            Self::Id(id) => id,
            Self::NameOffset(off) => off | NAME_FLAG,
        }
    }

    const fn is_name(self) -> bool {
        matches!(self, Self::NameOffset(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceDirectoryNode {
    pub path: Vec<ResourceKey>,
    pub offset: u32,
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub children: Vec<ResourceKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLeaf {
    pub path: Vec<ResourceKey>,
    pub data_entry_offset: u32,
    pub data_rva: u32,
    pub data_size: u32,
    pub code_page: u32,
    pub reserved: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceTree {
    pub base_rva: u32,
    pub structure_bytes: u32,
    pub directories: Vec<ResourceDirectoryNode>,
    pub leaves: Vec<ResourceLeaf>,
}

impl ResourceTree {
    #[must_use]
    pub fn shape(&self) -> Vec<(Vec<ResourceKey>, u32)> {
        self.leaves
            .iter()
            .map(|l: &ResourceLeaf| (l.path.clone(), l.data_size))
            .collect()
    }

    #[must_use]
    pub fn leaf_inside(&self, region_bytes: u32) -> Vec<&ResourceLeaf> {
        self.leaves
            .iter()
            .filter(|l: &&ResourceLeaf| {
                l.data_rva >= self.base_rva
                    && l.data_rva - self.base_rva < region_bytes
                    && u64::from(l.data_rva - self.base_rva) + u64::from(l.data_size)
                        <= u64::from(region_bytes)
            })
            .collect()
    }

    #[must_use]
    pub fn structure_span(&self, region_bytes: u32) -> u32 {
        let aligned: u32 = self.structure_bytes.next_multiple_of(STRUCTURE_ALIGNMENT);
        self.leaf_inside(region_bytes)
            .iter()
            .map(|l: &&ResourceLeaf| l.data_rva - self.base_rva)
            .filter(|&rel: &u32| rel >= self.structure_bytes)
            .min()
            .map_or(aligned, |rel: u32| rel)
    }
}

fn resource_error(stage: &'static str, detail: String) -> Error {
    Error::LoaderRecovery { stage, detail }
}

struct Walker<'a> {
    bytes: &'a [u8],
    base: usize,
    region_end: usize,
    visited: BTreeSet<u32>,
    directories: Vec<ResourceDirectoryNode>,
    leaves: Vec<ResourceLeaf>,
    structure_end: u32,
}

impl Walker<'_> {
    fn read_directory(&mut self, rel: u32, path: &[ResourceKey], depth: usize) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(resource_error(
                "resource-directory",
                format!("nesting exceeded {MAX_DEPTH} levels at directory offset {rel:#x}"),
            ));
        }
        if !self.visited.insert(rel) {
            return Err(resource_error(
                "resource-directory",
                format!("directory offset {rel:#x} is reachable twice, so the tree is cyclic"),
            ));
        }
        let head: usize = self.base.checked_add(rel as usize).ok_or_else(|| {
            resource_error(
                "resource-directory",
                format!("directory offset {rel:#x} overflows the buffer base"),
            )
        })?;
        if head
            .checked_add(RESOURCE_DIRECTORY_HEADER_BYTES)
            .is_none_or(|end: usize| end > self.region_end)
        {
            return Err(resource_error(
                "resource-directory",
                format!(
                    "IMAGE_RESOURCE_DIRECTORY at offset {rel:#x} needs \
                     {RESOURCE_DIRECTORY_HEADER_BYTES} header bytes, region ends at \
                     {:#x}",
                    self.region_end
                ),
            ));
        }
        let characteristics: u32 = read_u32(self.bytes, head)?;
        let time_date_stamp: u32 = read_u32(self.bytes, head + 4)?;
        let major_version: u16 = read_u16(self.bytes, head + 8)?;
        let minor_version: u16 = read_u16(self.bytes, head + 10)?;
        let named: usize = read_u16(self.bytes, head + 12)? as usize;
        let ided: usize = read_u16(self.bytes, head + 14)? as usize;
        let total: usize = named + ided;
        if total > MAX_ENTRIES_PER_DIRECTORY {
            return Err(resource_error(
                "resource-directory",
                format!(
                    "IMAGE_RESOURCE_DIRECTORY at offset {rel:#x} declares {total} entries, above \
                     the {MAX_ENTRIES_PER_DIRECTORY} cap"
                ),
            ));
        }
        let table_end: usize = head
            .checked_add(RESOURCE_DIRECTORY_HEADER_BYTES + total * RESOURCE_DIRECTORY_ENTRY_BYTES)
            .ok_or_else(|| {
                resource_error(
                    "resource-directory",
                    format!("entry table at offset {rel:#x} overflows the buffer"),
                )
            })?;
        if table_end > self.region_end {
            return Err(resource_error(
                "resource-directory",
                format!(
                    "entry table at offset {rel:#x} runs to {:#x}, past the region end {:#x}",
                    table_end - self.base,
                    self.region_end - self.base
                ),
            ));
        }
        self.structure_end = self
            .structure_end
            .max(u32::try_from(table_end - self.base).map_err(|_| {
                resource_error(
                    "resource-directory",
                    format!("entry table end {table_end:#x} exceeds a 32-bit region offset"),
                )
            })?);
        let node_index: usize = self.directories.len();
        if node_index >= MAX_DIRECTORIES {
            return Err(resource_error(
                "resource-directory",
                format!("directory count exceeded the {MAX_DIRECTORIES} cap"),
            ));
        }
        self.directories.push(ResourceDirectoryNode {
            path: path.to_vec(),
            offset: rel,
            characteristics,
            time_date_stamp,
            major_version,
            minor_version,
            children: Vec::with_capacity(total),
        });
        for index in 0..total {
            let entry: usize =
                head + RESOURCE_DIRECTORY_HEADER_BYTES + index * RESOURCE_DIRECTORY_ENTRY_BYTES;
            let raw_key: u32 = read_u32(self.bytes, entry)?;
            let raw_target: u32 = read_u32(self.bytes, entry + 4)?;
            let key: ResourceKey = if index < named {
                ResourceKey::NameOffset(raw_key & !NAME_FLAG)
            } else {
                ResourceKey::Id(raw_key)
            };
            let Some(node): Option<&mut ResourceDirectoryNode> =
                self.directories.get_mut(node_index)
            else {
                return Err(resource_error(
                    "resource-directory",
                    format!("directory node {node_index} vanished while filling its child list"),
                ));
            };
            node.children.push(key);
            let mut child_path: Vec<ResourceKey> = path.to_vec();
            child_path.push(key);
            if raw_target & SUBDIRECTORY_FLAG == 0 {
                self.read_data_entry(raw_target, &child_path)?;
            } else {
                self.read_directory(raw_target & !SUBDIRECTORY_FLAG, &child_path, depth + 1)?;
            }
        }
        Ok(())
    }

    fn read_data_entry(&mut self, rel: u32, path: &[ResourceKey]) -> Result<()> {
        if self.leaves.len() >= MAX_LEAVES {
            return Err(resource_error(
                "resource-data-entry",
                format!("leaf count exceeded the {MAX_LEAVES} cap"),
            ));
        }
        let at: usize = self.base.checked_add(rel as usize).ok_or_else(|| {
            resource_error(
                "resource-data-entry",
                format!("data entry offset {rel:#x} overflows the buffer base"),
            )
        })?;
        let end: usize = at.checked_add(RESOURCE_DATA_ENTRY_BYTES).ok_or_else(|| {
            resource_error(
                "resource-data-entry",
                format!("data entry offset {rel:#x} overflows the buffer"),
            )
        })?;
        if end > self.region_end {
            return Err(resource_error(
                "resource-data-entry",
                format!(
                    "IMAGE_RESOURCE_DATA_ENTRY at offset {rel:#x} runs past the region end {:#x}",
                    self.region_end - self.base
                ),
            ));
        }
        self.structure_end = self
            .structure_end
            .max(u32::try_from(end - self.base).map_err(|_| {
                resource_error(
                    "resource-data-entry",
                    format!("data entry end {end:#x} exceeds a 32-bit region offset"),
                )
            })?);
        self.leaves.push(ResourceLeaf {
            path: path.to_vec(),
            data_entry_offset: rel,
            data_rva: read_u32(self.bytes, at)?,
            data_size: read_u32(self.bytes, at + 4)?,
            code_page: read_u32(self.bytes, at + 8)?,
            reserved: read_u32(self.bytes, at + 12)?,
        });
        Ok(())
    }
}

pub fn parse_resource_tree(
    bytes: &[u8],
    base_offset: usize,
    base_rva: u32,
    region_bytes: usize,
) -> Result<ResourceTree> {
    if base_offset >= bytes.len() {
        return Err(resource_error(
            "resource-directory",
            format!(
                "resource directory base {base_offset:#x} is past the {:#x}-byte buffer",
                bytes.len()
            ),
        ));
    }
    let region_end: usize = base_offset
        .checked_add(region_bytes)
        .unwrap_or(bytes.len())
        .min(bytes.len());
    let mut walker: Walker<'_> = Walker {
        bytes,
        base: base_offset,
        region_end,
        visited: BTreeSet::new(),
        directories: Vec::new(),
        leaves: Vec::new(),
        structure_end: 0,
    };
    walker.read_directory(0, &[], 0)?;
    if walker.leaves.is_empty() {
        return Err(resource_error(
            "resource-directory",
            format!("resource directory at {base_offset:#x} names no data entries"),
        ));
    }
    Ok(ResourceTree {
        base_rva,
        structure_bytes: walker.structure_end,
        directories: walker.directories,
        leaves: walker.leaves,
    })
}

pub fn canonical_structure_bytes(tree: &ResourceTree) -> Result<Vec<u8>> {
    if tree
        .directories
        .iter()
        .flat_map(|d: &ResourceDirectoryNode| d.children.iter())
        .any(|k: &ResourceKey| k.is_name())
    {
        return Err(resource_error(
            "resource-directory",
            "named type / name entries carry a string table whose original placement is not \
             derivable, so no canonical layout is emitted"
                .to_owned(),
        ));
    }
    let mut by_depth: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (index, node) in tree.directories.iter().enumerate() {
        by_depth.entry(node.path.len()).or_default().push(index);
    }
    let mut directory_offset: BTreeMap<Vec<ResourceKey>, u32> = BTreeMap::new();
    let mut cursor: u32 = 0;
    for indexes in by_depth.values() {
        for &index in indexes {
            let Some(node): Option<&ResourceDirectoryNode> = tree.directories.get(index) else {
                continue;
            };
            directory_offset.insert(node.path.clone(), cursor);
            let bytes: u32 = u32::try_from(
                RESOURCE_DIRECTORY_HEADER_BYTES
                    + node.children.len() * RESOURCE_DIRECTORY_ENTRY_BYTES,
            )
            .map_err(|_| {
                resource_error(
                    "resource-directory",
                    "a directory entry table exceeds a 32-bit size".to_owned(),
                )
            })?;
            cursor = cursor.checked_add(bytes).ok_or_else(|| {
                resource_error(
                    "resource-directory",
                    "canonical directory layout overflows a 32-bit offset".to_owned(),
                )
            })?;
        }
    }
    let mut leaf_offset: BTreeMap<Vec<ResourceKey>, u32> = BTreeMap::new();
    for leaf in &tree.leaves {
        leaf_offset.insert(leaf.path.clone(), cursor);
        cursor = cursor
            .checked_add(u32::try_from(RESOURCE_DATA_ENTRY_BYTES).unwrap_or(u32::MAX))
            .ok_or_else(|| {
                resource_error(
                    "resource-data-entry",
                    "canonical data-entry layout overflows a 32-bit offset".to_owned(),
                )
            })?;
    }
    let mut out: Vec<u8> = vec![0u8; cursor as usize];
    for indexes in by_depth.values() {
        for &index in indexes {
            let Some(node): Option<&ResourceDirectoryNode> = tree.directories.get(index) else {
                continue;
            };
            let Some(&at): Option<&u32> = directory_offset.get(&node.path) else {
                continue;
            };
            let head: usize = at as usize;
            write_u32(&mut out, head, node.characteristics)?;
            write_u32(&mut out, head + 4, node.time_date_stamp)?;
            write_u16(&mut out, head + 8, node.major_version)?;
            write_u16(&mut out, head + 10, node.minor_version)?;
            write_u16(&mut out, head + 12, 0)?;
            write_u16(
                &mut out,
                head + 14,
                u16::try_from(node.children.len()).map_err(|_| {
                    resource_error(
                        "resource-directory",
                        format!(
                            "directory at {:#x} has {} entries, above the 16-bit field",
                            node.offset,
                            node.children.len()
                        ),
                    )
                })?,
            )?;
            for (slot, &key) in node.children.iter().enumerate() {
                let entry: usize =
                    head + RESOURCE_DIRECTORY_HEADER_BYTES + slot * RESOURCE_DIRECTORY_ENTRY_BYTES;
                let mut child_path: Vec<ResourceKey> = node.path.clone();
                child_path.push(key);
                write_u32(&mut out, entry, key.encode())?;
                let target: u32 = if let Some(&sub) = directory_offset.get(&child_path) {
                    sub | SUBDIRECTORY_FLAG
                } else if let Some(&data) = leaf_offset.get(&child_path) {
                    data
                } else {
                    return Err(resource_error(
                        "resource-directory",
                        format!(
                            "directory at {:#x} names a child that is neither a subdirectory nor a \
                             data entry",
                            node.offset
                        ),
                    ));
                };
                write_u32(&mut out, entry + 4, target)?;
            }
        }
    }
    for leaf in &tree.leaves {
        let Some(&at): Option<&u32> = leaf_offset.get(&leaf.path) else {
            continue;
        };
        let head: usize = at as usize;
        write_u32(&mut out, head, leaf.data_rva)?;
        write_u32(&mut out, head + 4, leaf.data_size)?;
        write_u32(&mut out, head + 8, leaf.code_page)?;
        write_u32(&mut out, head + 12, leaf.reserved)?;
    }
    Ok(out)
}

fn write_u32(buf: &mut [u8], at: usize, value: u32) -> Result<()> {
    let end: usize = at.checked_add(4).ok_or_else(|| {
        resource_error(
            "resource-directory",
            format!("write offset {at:#x} overflows"),
        )
    })?;
    let Some(slot): Option<&mut [u8]> = buf.get_mut(at..end) else {
        return Err(resource_error(
            "resource-directory",
            format!(
                "write of 4 bytes at {at:#x} is outside the {}-byte buffer",
                buf.len()
            ),
        ));
    };
    slot.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u16(buf: &mut [u8], at: usize, value: u16) -> Result<()> {
    let end: usize = at.checked_add(2).ok_or_else(|| {
        resource_error(
            "resource-directory",
            format!("write offset {at:#x} overflows"),
        )
    })?;
    let Some(slot): Option<&mut [u8]> = buf.get_mut(at..end) else {
        return Err(resource_error(
            "resource-directory",
            format!(
                "write of 2 bytes at {at:#x} is outside the {}-byte buffer",
                buf.len()
            ),
        ));
    };
    slot.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForcedPlacement {
    pub path: Vec<ResourceKey>,
    pub relative_offset: u32,
    pub data_size: u32,
}

const MAX_GAP_SEARCH_BYTES: u32 = 1 << 22;

#[must_use]
pub fn forced_leaf_placements(
    tree: &ResourceTree,
    region_bytes: u32,
    structure_span: u32,
) -> Vec<ForcedPlacement> {
    let anchored: Vec<u32> = tree
        .leaf_inside(region_bytes)
        .iter()
        .map(|l: &&ResourceLeaf| l.data_rva - tree.base_rva)
        .filter(|&rel: &u32| rel >= structure_span)
        .collect();
    let Some(&gap_hi): Option<&u32> = anchored.iter().min() else {
        return Vec::new();
    };
    if gap_hi <= structure_span {
        return Vec::new();
    }
    if gap_hi - structure_span > MAX_GAP_SEARCH_BYTES {
        return Vec::new();
    }
    let unplaced: Vec<&ResourceLeaf> = tree
        .leaves
        .iter()
        .filter(|l: &&ResourceLeaf| {
            l.data_rva < tree.base_rva
                || l.data_rva - tree.base_rva >= region_bytes
                || l.data_rva - tree.base_rva < structure_span
        })
        .collect();
    let sizes: Vec<u32> = unplaced
        .iter()
        .map(|l: &&ResourceLeaf| l.data_size)
        .collect();
    let mut solutions: Vec<(usize, u32)> = Vec::new();
    for &alignment in CANDIDATE_DATA_ALIGNMENTS {
        let start: u32 = structure_span.next_multiple_of(alignment);
        if start >= gap_hi {
            continue;
        }
        let gap: u32 = gap_hi - start;
        for (index, &size) in sizes.iter().enumerate() {
            if size == gap {
                solutions.push((index, start));
            } else if size < gap && fills_with_predecessors(&sizes, index, gap - size) {
                return Vec::new();
            }
        }
    }
    solutions.dedup();
    let unique_leaf: bool = solutions
        .windows(2)
        .all(|w: &[(usize, u32)]| w.first().map(|p| p.0) == w.get(1).map(|p| p.0));
    if solutions.is_empty() || !unique_leaf {
        return Vec::new();
    }
    let mut starts: Vec<u32> = solutions.iter().map(|&(_, s): &(usize, u32)| s).collect();
    starts.sort_unstable();
    starts.dedup();
    match (solutions.first(), starts.as_slice()) {
        (Some(&(index, _)), [start]) => {
            unplaced
                .get(index)
                .map_or_else(Vec::new, |leaf: &&ResourceLeaf| {
                    vec![ForcedPlacement {
                        path: leaf.path.clone(),
                        relative_offset: *start,
                        data_size: leaf.data_size,
                    }]
                })
        }
        _ => Vec::new(),
    }
}

const CANDIDATE_DATA_ALIGNMENTS: &[u32] = &[4, 8, 16];

fn fills_with_predecessors(sizes: &[u32], last: usize, target: u32) -> bool {
    let span: usize = target as usize + 1;
    let mut reachable: Vec<bool> = vec![false; span];
    if let Some(slot) = reachable.first_mut() {
        *slot = true;
    }
    for (index, &size) in sizes.iter().enumerate() {
        if index == last {
            continue;
        }
        let step: usize = size.next_multiple_of(STRUCTURE_ALIGNMENT) as usize;
        if step == 0 || step > target as usize {
            continue;
        }
        let mut at: usize = target as usize;
        while at >= step {
            if reachable.get(at - step).copied().unwrap_or(false)
                && let Some(slot) = reachable.get_mut(at)
            {
                *slot = true;
            }
            at -= 1;
        }
    }
    reachable.last().copied().unwrap_or(false)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceDirectoryRecovery {
    pub original_base_rva: u32,

    pub structure_bytes_placed: u32,

    pub structure_layout_reemitted: bool,

    pub anchors_preserved: bool,

    pub placed_leaves: Vec<ForcedPlacement>,

    pub unplaced_leaves: usize,

    pub unplaced_leaf_bytes: u64,
}

pub fn recover_resource_directory(
    packed: &[u8],
    tree: &ResourceTree,
    directory_bytes: u32,
    original_base_rva: u32,
    image_base_rva: u32,
    resolve_packed_rva: &dyn Fn(u32) -> Option<usize>,
    image: &mut Vec<u8>,
) -> Result<ResourceDirectoryRecovery> {
    let image_offset: usize = original_base_rva
        .checked_sub(image_base_rva)
        .ok_or_else(|| {
            resource_error(
                "resource-directory",
                format!(
                    "original resource base {original_base_rva:#x} is below the recovered image \
                     base {image_base_rva:#x}"
                ),
            )
        })? as usize;
    let span: u32 = tree.structure_span(directory_bytes);
    let anchors_preserved: bool = !tree.leaves.iter().any(|l: &ResourceLeaf| {
        l.data_rva
            .checked_sub(original_base_rva)
            .is_some_and(|rel: u32| rel < span)
    });
    let mut placed: ResourceTree = tree.clone();
    placed.base_rva = original_base_rva;
    let forced: Vec<ForcedPlacement> = if anchors_preserved {
        forced_leaf_placements(&placed, directory_bytes, span)
    } else {
        Vec::new()
    };
    for entry in &forced {
        if let Some(leaf) = placed
            .leaves
            .iter_mut()
            .find(|l: &&mut ResourceLeaf| l.path == entry.path)
        {
            leaf.data_rva = original_base_rva.saturating_add(entry.relative_offset);
        }
    }
    let structure: Vec<u8> = match canonical_structure_bytes(&placed) {
        Ok(bytes) => bytes,
        Err(_) => {
            let head: usize = resolve_packed_rva(tree.base_rva).ok_or_else(|| {
                resource_error(
                    "resource-directory",
                    format!(
                        "packed resource directory rva {:#x} maps to no file offset",
                        tree.base_rva
                    ),
                )
            })?;
            let end: usize = head.saturating_add(span as usize).min(packed.len());
            packed.get(head..end).map(<[u8]>::to_vec).ok_or_else(|| {
                resource_error(
                    "resource-directory",
                    format!("packed resource structure at {head:#x} is truncated"),
                )
            })?
        }
    };
    let reemitted: bool = {
        let head: Option<usize> = resolve_packed_rva(tree.base_rva);
        head.and_then(|at: usize| packed.get(at..at.saturating_add(structure.len())))
            .is_none_or(|original: &[u8]| original != structure.as_slice())
    };
    write_region(image, image_offset, &structure)?;
    let pad_lo: usize = image_offset + structure.len();
    let pad_hi: usize = image_offset + span as usize;
    if pad_hi > pad_lo {
        write_region(image, pad_lo, &vec![0u8; pad_hi - pad_lo])?;
    }
    let mut unplaced: usize = 0;
    let mut unplaced_bytes: u64 = 0;
    for leaf in &tree.leaves {
        let forced_here: Option<&ForcedPlacement> = forced
            .iter()
            .find(|f: &&ForcedPlacement| f.path == leaf.path);
        let Some(entry): Option<&ForcedPlacement> = forced_here else {
            let inside_original: bool = leaf
                .data_rva
                .checked_sub(original_base_rva)
                .is_some_and(|rel: u32| rel >= span && rel < directory_bytes);
            if !(inside_original && anchors_preserved) {
                unplaced += 1;
                unplaced_bytes += u64::from(leaf.data_size);
            }
            continue;
        };
        let Some(head): Option<usize> = resolve_packed_rva(leaf.data_rva) else {
            unplaced += 1;
            unplaced_bytes += u64::from(leaf.data_size);
            continue;
        };
        let end: usize = head.saturating_add(leaf.data_size as usize);
        let Some(body): Option<&[u8]> = packed.get(head..end) else {
            unplaced += 1;
            unplaced_bytes += u64::from(leaf.data_size);
            continue;
        };
        write_region(image, image_offset + entry.relative_offset as usize, body)?;
    }
    Ok(ResourceDirectoryRecovery {
        original_base_rva,
        structure_bytes_placed: span,
        structure_layout_reemitted: reemitted,
        anchors_preserved,
        placed_leaves: forced,
        unplaced_leaves: unplaced,
        unplaced_leaf_bytes: unplaced_bytes,
    })
}

fn write_region(image: &mut Vec<u8>, at: usize, body: &[u8]) -> Result<()> {
    let end: usize = at.checked_add(body.len()).ok_or_else(|| {
        resource_error(
            "resource-directory",
            format!("placement at {at:#x} overflows the recovered image"),
        )
    })?;
    if end > MAX_RECOVERED_IMAGE_BYTES {
        return Err(resource_error(
            "resource-directory",
            format!(
                "placement to {end:#x} is past the {MAX_RECOVERED_IMAGE_BYTES:#x} recovered-image \
                 cap"
            ),
        ));
    }
    if image.len() < end {
        image.resize(end, 0u8);
    }
    let Some(slot): Option<&mut [u8]> = image.get_mut(at..end) else {
        return Err(resource_error(
            "resource-directory",
            format!("placement window {at:#x}..{end:#x} is outside the recovered image"),
        ));
    };
    slot.copy_from_slice(body);
    Ok(())
}

const MAX_RECOVERED_IMAGE_BYTES: usize = 512 * 1024 * 1024;

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn three_level(sizes: &[(u32, u32, u32)]) -> Vec<u8> {
        let type_count: usize = sizes.len();
        let root: usize =
            RESOURCE_DIRECTORY_HEADER_BYTES + type_count * RESOURCE_DIRECTORY_ENTRY_BYTES;
        let type_dirs: usize = type_count * (RESOURCE_DIRECTORY_HEADER_BYTES + 8);
        let name_dirs: usize = type_count * (RESOURCE_DIRECTORY_HEADER_BYTES + 8);
        let total: usize = root + type_dirs + name_dirs + type_count * RESOURCE_DATA_ENTRY_BYTES;
        let mut buf: Vec<u8> = vec![0u8; total + 64];
        buf[14..16].copy_from_slice(&(type_count as u16).to_le_bytes());
        for (i, &(type_id, name_id, size)) in sizes.iter().enumerate() {
            let entry: usize = RESOURCE_DIRECTORY_HEADER_BYTES + i * RESOURCE_DIRECTORY_ENTRY_BYTES;
            let type_dir: usize = root + i * (RESOURCE_DIRECTORY_HEADER_BYTES + 8);
            let name_dir: usize = root + type_dirs + i * (RESOURCE_DIRECTORY_HEADER_BYTES + 8);
            let data: usize = root + type_dirs + name_dirs + i * RESOURCE_DATA_ENTRY_BYTES;
            buf[entry..entry + 4].copy_from_slice(&type_id.to_le_bytes());
            buf[entry + 4..entry + 8]
                .copy_from_slice(&((type_dir as u32) | SUBDIRECTORY_FLAG).to_le_bytes());
            buf[type_dir + 14..type_dir + 16].copy_from_slice(&1u16.to_le_bytes());
            buf[type_dir + 16..type_dir + 20].copy_from_slice(&name_id.to_le_bytes());
            buf[type_dir + 20..type_dir + 24]
                .copy_from_slice(&((name_dir as u32) | SUBDIRECTORY_FLAG).to_le_bytes());
            buf[name_dir + 14..name_dir + 16].copy_from_slice(&1u16.to_le_bytes());
            buf[name_dir + 16..name_dir + 20].copy_from_slice(&0x409u32.to_le_bytes());
            buf[name_dir + 20..name_dir + 24].copy_from_slice(&(data as u32).to_le_bytes());
            buf[data..data + 4].copy_from_slice(&(0x1_0000u32 + size).to_le_bytes());
            buf[data + 4..data + 8].copy_from_slice(&size.to_le_bytes());
        }
        buf
    }

    #[test]
    fn parses_a_three_level_tree_and_reports_the_structure_extent() {
        let buf: Vec<u8> = three_level(&[(3, 1, 0x100), (5, 0x65, 0x200)]);
        let tree: ResourceTree = parse_resource_tree(&buf, 0, 0x1_0000, buf.len()).expect("tree");
        assert_eq!(tree.leaves.len(), 2);
        assert_eq!(tree.directories.len(), 5);
        assert_eq!(
            tree.structure_bytes, 0xA0,
            "the structure extent must cover the root, both levels of subdirectory and both data \
             entries"
        );
    }

    #[test]
    fn canonical_layout_round_trips_a_canonical_tree_byte_for_byte() {
        let buf: Vec<u8> = three_level(&[(3, 1, 0x100), (5, 0x65, 0x200), (16, 1, 0x40)]);
        let tree: ResourceTree = parse_resource_tree(&buf, 0, 0x1_0000, buf.len()).expect("tree");
        let emitted: Vec<u8> = canonical_structure_bytes(&tree).expect("canonical bytes");
        assert_eq!(
            emitted.as_slice(),
            &buf[..emitted.len()],
            "a tree already in the canonical breadth-first layout must be re-emitted unchanged"
        );
    }

    #[test]
    fn rejects_a_self_referential_directory() {
        let mut buf: Vec<u8> = three_level(&[(3, 1, 0x100)]);
        buf[RESOURCE_DIRECTORY_HEADER_BYTES + 4..RESOURCE_DIRECTORY_HEADER_BYTES + 8]
            .copy_from_slice(&SUBDIRECTORY_FLAG.to_le_bytes());
        let err: Error =
            parse_resource_tree(&buf, 0, 0x1_0000, buf.len()).expect_err("cycle must be rejected");
        assert!(
            format!("{err}").contains("cyclic"),
            "a directory that points at itself must be named as cyclic, got {err}"
        );
    }

    #[test]
    fn rejects_an_entry_table_that_runs_past_the_region() {
        let mut buf: Vec<u8> = three_level(&[(3, 1, 0x100)]);
        buf[14..16].copy_from_slice(&0x40u16.to_le_bytes());
        let err: Error = parse_resource_tree(&buf, 0, 0x1_0000, 32)
            .expect_err("an over-long entry table must be rejected");
        assert!(
            format!("{err}").contains("past the region end"),
            "the error must name the region overrun, got {err}"
        );
    }

    #[test]
    fn rejects_a_directory_base_past_the_buffer() {
        let buf: Vec<u8> = vec![0u8; 16];
        assert!(parse_resource_tree(&buf, 64, 0, 16).is_err());
    }

    #[test]
    fn a_single_gap_that_only_one_leaf_can_fill_is_forced() {
        let mut buf: Vec<u8> = three_level(&[(3, 1, 0x8a8), (5, 0x65, 0x300), (16, 1, 0x2e8)]);
        let root: usize = RESOURCE_DIRECTORY_HEADER_BYTES + 3 * RESOURCE_DIRECTORY_ENTRY_BYTES;
        let dirs: usize = 6 * (RESOURCE_DIRECTORY_HEADER_BYTES + 8);
        let data: usize = root + dirs;
        buf[data..data + 4].copy_from_slice(&0x1_3000u32.to_le_bytes());
        buf[data + RESOURCE_DATA_ENTRY_BYTES..data + RESOURCE_DATA_ENTRY_BYTES + 4]
            .copy_from_slice(&0x1_0468u32.to_le_bytes());
        buf[data + 2 * RESOURCE_DATA_ENTRY_BYTES..data + 2 * RESOURCE_DATA_ENTRY_BYTES + 4]
            .copy_from_slice(&0x1_3200u32.to_le_bytes());
        let tree: ResourceTree = parse_resource_tree(&buf, 0, 0x1_0000, buf.len()).expect("tree");
        let forced: Vec<ForcedPlacement> = forced_leaf_placements(&tree, 0x1240, 0x180);
        assert_eq!(forced.len(), 1, "exactly one leaf fits the 0x2e8-byte gap");
        assert_eq!(forced[0].relative_offset, 0x180);
        assert_eq!(forced[0].data_size, 0x2e8);
    }

    #[test]
    fn an_ambiguous_gap_places_nothing() {
        let mut buf: Vec<u8> = three_level(&[(3, 1, 0x100), (5, 0x65, 0x180), (16, 1, 0x80)]);
        let root: usize = RESOURCE_DIRECTORY_HEADER_BYTES + 3 * RESOURCE_DIRECTORY_ENTRY_BYTES;
        let dirs: usize = 6 * (RESOURCE_DIRECTORY_HEADER_BYTES + 8);
        let data: usize = root + dirs;
        buf[data..data + 4].copy_from_slice(&0x1_3000u32.to_le_bytes());
        buf[data + RESOURCE_DATA_ENTRY_BYTES..data + RESOURCE_DATA_ENTRY_BYTES + 4]
            .copy_from_slice(&0x1_0300u32.to_le_bytes());
        buf[data + 2 * RESOURCE_DATA_ENTRY_BYTES..data + 2 * RESOURCE_DATA_ENTRY_BYTES + 4]
            .copy_from_slice(&0x1_3200u32.to_le_bytes());
        let tree: ResourceTree = parse_resource_tree(&buf, 0, 0x1_0000, buf.len()).expect("tree");
        assert!(
            forced_leaf_placements(&tree, 0x1000, 0x180).is_empty(),
            "a gap two different leaf sets can fill must place nothing, because a guess would \
             score worse than leaving the bytes alone"
        );
    }
}
