use std::collections::BTreeSet;
use std::io::Read;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const SECTOR_SIZE: usize = 2048;
const VOLUME_DESCRIPTOR_LBA: usize = 16;
const VD_PRIMARY: u8 = 1;
const VD_SUPPLEMENTARY: u8 = 2;
const VD_TERMINATOR: u8 = 255;
const STANDARD_ID: &[u8; 5] = b"CD001";
const DIR_FLAG_DIRECTORY: u8 = 0x02;
const DIR_FLAG_MULTI_EXTENT: u8 = 0x80;
const MAX_DIR_DEPTH: usize = 64;
const MAX_RECORDS: usize = 100_000;
const MAX_PATH_BYTES: usize = 16 * 1024 * 1024;
const MAX_EXTENTS: usize = 200_000;
const MAX_DIRECTORIES: usize = 100_000;
const MAX_SUSP_BYTES: usize = 1 << 20;
const MAX_CE_DEPTH: usize = 8;
const MAX_ZISOFS_BLOCK_POINTERS: usize = 131_073;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsoEntryKind {
    Regular,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsoExtent {
    pub extent_lba: u32,
    pub data_len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZisofsInfo {
    pub header_size_words: u8,
    pub block_shift: u8,
    pub uncompressed_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsoEntry {
    pub path: String,
    pub extent_lba: u32,
    pub data_len: u64,
    pub extents: Vec<IsoExtent>,
    pub kind: IsoEntryKind,
    pub is_dir: bool,
    pub mode: Option<u32>,
    pub link_count: Option<u32>,
    pub serial: Option<u32>,
    pub symlink_target: Option<String>,
    pub zisofs: Option<ZisofsInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsoImage {
    pub volume_id: String,
    pub joliet: bool,
    pub rock_ridge: bool,
    pub files: Vec<IsoEntry>,
}

#[derive(Default)]
struct SuspMetadata {
    name: Option<String>,
    name_continues: bool,
    mode: Option<u32>,
    link_count: Option<u32>,
    serial: Option<u32>,
    symlink_target: Option<String>,
    symlink_entry_continues: bool,
    symlink_component_continues: bool,
    child_link_lba: Option<u32>,
    parent_link_lba: Option<u32>,
    relocated: bool,
    zisofs: Option<ZisofsInfo>,
}

struct PendingExtent {
    path: String,
    extent_lba: u32,
    extents: Vec<IsoExtent>,
    data_len: u64,
    mode: Option<u32>,
    link_count: Option<u32>,
    serial: Option<u32>,
}

#[derive(Default)]
struct SuspState {
    bytes_read: usize,
    continuations: BTreeSet<(u32, u32, u32)>,
    rrip_present: bool,
}

#[derive(Default)]
struct IsoWalkState {
    records: usize,
    path_bytes: usize,
    extents: usize,
    directories: usize,
    susp: SuspState,
}

struct IsoWalkContext<'a> {
    bytes: &'a [u8],
    joliet: bool,
    out: &'a mut Vec<IsoEntry>,
    visited: BTreeSet<(u32, u32)>,
    susp_skip: Option<usize>,
    state: IsoWalkState,
}

#[inline]
fn read_both_u16(bytes: &[u8], at: usize, field: &str) -> Result<u16> {
    let raw: &[u8] = bytes
        .get(at..at + 4)
        .ok_or_else(|| Error::Decompression(format!("iso {field} is truncated")))?;
    let little: u16 = u16::from_le_bytes([raw[0], raw[1]]);
    let big: u16 = u16::from_be_bytes([raw[2], raw[3]]);
    if little != big {
        return Err(Error::Decompression(format!(
            "iso {field} both-endian values disagree"
        )));
    }
    Ok(little)
}

fn read_both_u32(bytes: &[u8], at: usize, field: &str) -> Result<u32> {
    let raw: &[u8] = bytes
        .get(at..at + 8)
        .ok_or_else(|| Error::Decompression(format!("iso {field} is truncated")))?;
    let little: u32 = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let big: u32 = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
    if little != big {
        return Err(Error::Decompression(format!(
            "iso {field} both-endian values disagree"
        )));
    }
    Ok(little)
}

fn sector(bytes: &[u8], lba: usize) -> Option<&[u8]> {
    let start: usize = lba.checked_mul(SECTOR_SIZE)?;
    let end: usize = start.checked_add(SECTOR_SIZE)?;
    bytes.get(start..end)
}

fn system_use_start(record: &[u8]) -> Result<usize> {
    let name_len: usize =
        record.get(32).copied().map(usize::from).ok_or_else(|| {
            Error::Decompression("iso directory record name is truncated".to_owned())
        })?;
    let start: usize = 33usize
        .checked_add(name_len)
        .and_then(|value: usize| value.checked_add(usize::from(name_len.is_multiple_of(2))))
        .ok_or_else(|| Error::Decompression("iso system-use offset overflows".to_owned()))?;
    if start > record.len() {
        return Err(Error::Decompression(
            "iso system-use area is truncated".to_owned(),
        ));
    }
    Ok(start)
}

fn susp_skip_from_root(bytes: &[u8], lba: u32, len: u32) -> Result<Option<usize>> {
    let start: usize = usize::try_from(lba)
        .ok()
        .and_then(|value: usize| value.checked_mul(SECTOR_SIZE))
        .ok_or_else(|| Error::Decompression("iso root extent overflows".to_owned()))?;
    let end: usize = start
        .checked_add(len as usize)
        .ok_or_else(|| Error::Decompression("iso root length overflows".to_owned()))?;
    let region: &[u8] = bytes
        .get(start..end)
        .ok_or_else(|| Error::Decompression("iso root extent is truncated".to_owned()))?;
    let record_len: usize = region.first().copied().map_or(0, usize::from);
    let record: &[u8] = region
        .get(..record_len)
        .filter(|record: &&[u8]| record.len() >= 34)
        .ok_or_else(|| Error::Decompression("iso root self record is malformed".to_owned()))?;
    let system_use: &[u8] = &record[system_use_start(record)?..];
    let mut cursor: usize = 0;
    while cursor.saturating_add(4) <= system_use.len() {
        let entry_len: usize = usize::from(system_use[cursor + 2]);
        if entry_len < 4 || cursor.saturating_add(entry_len) > system_use.len() {
            return Err(Error::Decompression(
                "iso SUSP entry is malformed".to_owned(),
            ));
        }
        let entry: &[u8] = &system_use[cursor..cursor + entry_len];
        if &entry[..2] == b"SP" {
            if entry.len() != 7 || entry[3] != 1 || entry[4..6] != [0xbe, 0xef] {
                return Err(Error::Decompression(
                    "iso SUSP sharing protocol entry is malformed".to_owned(),
                ));
            }
            return Ok(Some(usize::from(entry[6])));
        }
        cursor += entry_len;
    }
    Ok(None)
}

fn parse_susp(
    bytes: &[u8],
    area: &[u8],
    depth: usize,
    state: &mut SuspState,
    metadata: &mut SuspMetadata,
) -> Result<()> {
    if depth > MAX_CE_DEPTH {
        return Err(Error::Decompression(
            "iso SUSP continuation depth exceeds limit".to_owned(),
        ));
    }
    state.bytes_read = state
        .bytes_read
        .checked_add(area.len())
        .ok_or_else(|| Error::Decompression("iso SUSP byte count overflows".to_owned()))?;
    if state.bytes_read > MAX_SUSP_BYTES {
        return Err(Error::Decompression(
            "iso SUSP byte count exceeds limit".to_owned(),
        ));
    }
    let mut cursor: usize = 0;
    while cursor.saturating_add(4) <= area.len() {
        let entry_len: usize = usize::from(area[cursor + 2]);
        if entry_len < 4 || cursor.saturating_add(entry_len) > area.len() {
            return Err(Error::Decompression(
                "iso SUSP entry is malformed".to_owned(),
            ));
        }
        let entry: &[u8] = &area[cursor..cursor + entry_len];
        match &entry[..2] {
            b"ST" => {
                if entry.len() != 4 || entry[3] != 1 {
                    return Err(Error::Decompression(
                        "iso SUSP terminator is malformed".to_owned(),
                    ));
                }
                validate_susp_continuations(depth, metadata)?;
                return Ok(());
            }
            b"ER" => parse_er(entry, state)?,
            b"CE" => parse_ce(bytes, entry, depth, state, metadata)?,
            b"RR" => parse_rr(entry)?,
            b"PX" => {
                if metadata.mode.is_some() {
                    return Err(Error::Decompression(
                        "iso RRIP PX entry is duplicated".to_owned(),
                    ));
                }
                parse_px(entry, metadata)?;
            }
            b"NM" => parse_nm(entry, metadata)?,
            b"SL" => parse_sl(entry, metadata)?,
            b"CL" => {
                let value: u32 = parse_link(entry, "CL")?;
                if metadata.child_link_lba.replace(value).is_some() {
                    return Err(Error::Decompression(
                        "iso RRIP CL entry is duplicated".to_owned(),
                    ));
                }
            }
            b"PL" => {
                let value: u32 = parse_link(entry, "PL")?;
                if metadata.parent_link_lba.replace(value).is_some() {
                    return Err(Error::Decompression(
                        "iso RRIP PL entry is duplicated".to_owned(),
                    ));
                }
            }
            b"RE" => {
                if metadata.relocated {
                    return Err(Error::Decompression(
                        "iso RRIP RE entry is duplicated".to_owned(),
                    ));
                }
                parse_re(entry, metadata)?;
            }
            b"TF" => parse_tf(entry)?,
            b"ZF" => {
                let value: ZisofsInfo = parse_zf(entry)?;
                if metadata.zisofs.replace(value).is_some() {
                    return Err(Error::Decompression(
                        "iso RRIP ZF entry is duplicated".to_owned(),
                    ));
                }
            }
            _ => {}
        }
        cursor += entry_len;
    }
    if cursor != area.len() && area[cursor..].iter().any(|byte: &u8| *byte != 0) {
        return Err(Error::Decompression(
            "iso SUSP trailing bytes are malformed".to_owned(),
        ));
    }
    validate_susp_continuations(depth, metadata)?;
    Ok(())
}

fn validate_susp_continuations(depth: usize, metadata: &SuspMetadata) -> Result<()> {
    if depth == 0
        && (metadata.name_continues
            || metadata.symlink_entry_continues
            || metadata.symlink_component_continues)
    {
        return Err(Error::Decompression(
            "iso RRIP continuation sequence is incomplete".to_owned(),
        ));
    }
    Ok(())
}

fn parse_rr(entry: &[u8]) -> Result<()> {
    if entry.len() != 5 || entry[3] != 1 {
        return Err(Error::Decompression(
            "iso RRIP RR entry is malformed".to_owned(),
        ));
    }
    Ok(())
}

fn parse_px(entry: &[u8], metadata: &mut SuspMetadata) -> Result<()> {
    if !matches!(entry.len(), 36 | 44) || entry[3] != 1 {
        return Err(Error::Decompression(
            "iso RRIP PX entry is malformed".to_owned(),
        ));
    }
    metadata.mode = Some(read_both_u32(entry, 4, "RRIP PX mode")?);
    metadata.link_count = Some(read_both_u32(entry, 12, "RRIP PX link count")?);
    read_both_u32(entry, 20, "RRIP PX user id")?;
    read_both_u32(entry, 28, "RRIP PX group id")?;
    if entry.len() == 44 {
        metadata.serial = Some(read_both_u32(entry, 36, "RRIP PX serial")?);
    }
    Ok(())
}

fn parse_link(entry: &[u8], name: &str) -> Result<u32> {
    if entry.len() != 12 || entry[3] != 1 {
        return Err(Error::Decompression(format!(
            "iso RRIP {name} entry is malformed"
        )));
    }
    read_both_u32(entry, 4, &format!("RRIP {name} location"))
}

fn parse_re(entry: &[u8], metadata: &mut SuspMetadata) -> Result<()> {
    if entry.len() != 4 || entry[3] != 1 {
        return Err(Error::Decompression(
            "iso RRIP RE entry is malformed".to_owned(),
        ));
    }
    metadata.relocated = true;
    Ok(())
}

fn parse_tf(entry: &[u8]) -> Result<()> {
    let flags: u8 = *entry
        .get(4)
        .ok_or_else(|| Error::Decompression("iso RRIP TF entry is truncated".to_owned()))?;
    if entry[3] != 1 || flags & 0x80 != 0 && flags.trailing_zeros() >= 7 {
        return Err(Error::Decompression(
            "iso RRIP TF entry is malformed".to_owned(),
        ));
    }
    let timestamps: usize = (flags & 0x7f).count_ones() as usize;
    let width: usize = if flags & 0x80 != 0 { 17 } else { 7 };
    let expected: usize = 5usize
        .checked_add(
            timestamps
                .checked_mul(width)
                .ok_or_else(|| Error::Decompression("iso RRIP TF length overflows".to_owned()))?,
        )
        .ok_or_else(|| Error::Decompression("iso RRIP TF length overflows".to_owned()))?;
    if entry.len() != expected {
        return Err(Error::Decompression(
            "iso RRIP TF entry is malformed".to_owned(),
        ));
    }
    Ok(())
}

fn parse_zf(entry: &[u8]) -> Result<ZisofsInfo> {
    if entry.len() != 16
        || entry[3] != 1
        || entry.get(4..6) != Some(b"pz".as_slice())
        || entry[6] != 4
        || !matches!(entry[7], 15..=17)
    {
        return Err(Error::Decompression(
            "iso zisofs ZF entry is malformed".to_owned(),
        ));
    }
    Ok(ZisofsInfo {
        header_size_words: entry[6],
        block_shift: entry[7],
        uncompressed_size: read_both_u32(entry, 8, "zisofs uncompressed size")?,
    })
}

fn parse_er(entry: &[u8], state: &mut SuspState) -> Result<()> {
    let lengths: &[u8] = entry
        .get(4..8)
        .ok_or_else(|| Error::Decompression("iso SUSP ER entry is truncated".to_owned()))?;
    let identifier_len: usize = usize::from(lengths[0]);
    let total_len: usize = 8usize
        .checked_add(identifier_len)
        .and_then(|value: usize| value.checked_add(usize::from(lengths[1])))
        .and_then(|value: usize| value.checked_add(usize::from(lengths[2])))
        .ok_or_else(|| Error::Decompression("iso SUSP ER length overflows".to_owned()))?;
    if total_len != entry.len() || lengths[3] != 1 {
        return Err(Error::Decompression(
            "iso SUSP ER entry is malformed".to_owned(),
        ));
    }
    if matches!(
        entry.get(8..8 + identifier_len),
        Some(b"RRIP_1991A" | b"IEEE_P1282")
    ) {
        state.rrip_present = true;
    }
    Ok(())
}

fn parse_ce(
    bytes: &[u8],
    entry: &[u8],
    depth: usize,
    state: &mut SuspState,
    metadata: &mut SuspMetadata,
) -> Result<()> {
    if entry.len() != 28 || entry[3] != 1 {
        return Err(Error::Decompression(
            "iso SUSP CE entry is malformed".to_owned(),
        ));
    }
    let block: u32 = read_both_u32(entry, 4, "SUSP CE block")?;
    let offset: u32 = read_both_u32(entry, 12, "SUSP CE offset")?;
    let length: u32 = read_both_u32(entry, 20, "SUSP CE length")?;
    let key: (u32, u32, u32) = (block, offset, length);
    if !state.continuations.insert(key) {
        return Err(Error::Decompression(
            "iso SUSP continuation cycle detected".to_owned(),
        ));
    }
    let start: usize = usize::try_from(block)
        .ok()
        .and_then(|value: usize| value.checked_mul(SECTOR_SIZE))
        .and_then(|value: usize| value.checked_add(offset as usize))
        .ok_or_else(|| Error::Decompression("iso SUSP CE range overflows".to_owned()))?;
    let end: usize = start
        .checked_add(length as usize)
        .ok_or_else(|| Error::Decompression("iso SUSP CE length overflows".to_owned()))?;
    let continuation: &[u8] = bytes
        .get(start..end)
        .ok_or_else(|| Error::Decompression("iso SUSP CE range is truncated".to_owned()))?;
    let result: Result<()> = parse_susp(bytes, continuation, depth + 1, state, metadata);
    state.continuations.remove(&key);
    result
}

fn parse_nm(entry: &[u8], metadata: &mut SuspMetadata) -> Result<()> {
    let flags: u8 = *entry
        .get(4)
        .ok_or_else(|| Error::Decompression("iso RRIP NM entry is truncated".to_owned()))?;
    if entry[3] != 1 || flags & !0x07 != 0 || flags & 0x06 == 0x06 {
        return Err(Error::Decompression(
            "iso RRIP NM flags are malformed".to_owned(),
        ));
    }
    if flags & 0x06 != 0 {
        if entry.len() != 5 || flags & 0x01 != 0 || metadata.name.is_some() {
            return Err(Error::Decompression(
                "iso RRIP NM special name is malformed".to_owned(),
            ));
        }
        metadata.name = Some(if flags & 0x02 != 0 { "." } else { ".." }.to_owned());
        return Ok(());
    }
    if metadata.name.is_some() && !metadata.name_continues {
        return Err(Error::Decompression(
            "iso RRIP NM fragments are not contiguous".to_owned(),
        ));
    }
    let fragment: &str =
        std::str::from_utf8(&entry[5..]).map_err(|_error: std::str::Utf8Error| {
            Error::Decompression("iso RRIP NM name is not UTF-8".to_owned())
        })?;
    let name: &mut String = metadata.name.get_or_insert_with(String::new);
    name.push_str(fragment);
    metadata.name_continues = flags & 0x01 != 0;
    if !metadata.name_continues && name.is_empty() {
        return Err(Error::Decompression("iso RRIP NM name is empty".to_owned()));
    }
    Ok(())
}

fn parse_sl(entry: &[u8], metadata: &mut SuspMetadata) -> Result<()> {
    let flags: u8 = *entry
        .get(4)
        .ok_or_else(|| Error::Decompression("iso RRIP SL entry is truncated".to_owned()))?;
    if entry[3] != 1 || flags & !0x01 != 0 {
        return Err(Error::Decompression(
            "iso RRIP SL flags are unsupported".to_owned(),
        ));
    }
    if metadata.symlink_target.is_some() && !metadata.symlink_entry_continues {
        return Err(Error::Decompression(
            "iso RRIP SL fragments are not contiguous".to_owned(),
        ));
    }
    let target: &mut String = metadata.symlink_target.get_or_insert_with(String::new);
    let mut cursor: usize = 5;
    while cursor.saturating_add(2) <= entry.len() {
        let component_flags: u8 = entry[cursor];
        let component_len: usize = usize::from(entry[cursor + 1]);
        let end: usize = cursor
            .checked_add(2)
            .and_then(|value: usize| value.checked_add(component_len))
            .ok_or_else(|| Error::Decompression("iso RRIP SL component overflows".to_owned()))?;
        let component: &[u8] = entry
            .get(cursor + 2..end)
            .ok_or_else(|| Error::Decompression("iso RRIP SL component is truncated".to_owned()))?;
        if component_flags & !0x3f != 0 {
            return Err(Error::Decompression(
                "iso RRIP SL component flags are unsupported".to_owned(),
            ));
        }
        if component_flags & 0x01 != 0 && component_flags & 0x0e != 0 {
            return Err(Error::Decompression(
                "iso RRIP SL special component cannot continue".to_owned(),
            ));
        }
        let kind: u8 = component_flags & !0x01;
        let value: &str = match kind {
            0 => std::str::from_utf8(component).map_err(|_error: std::str::Utf8Error| {
                Error::Decompression("iso RRIP SL component is not UTF-8".to_owned())
            })?,
            0x02 if component.is_empty() => ".",
            0x04 if component.is_empty() => "..",
            0x08 if component.is_empty() => "",
            _ => {
                return Err(Error::Decompression(
                    "iso RRIP SL component flags are unsupported".to_owned(),
                ));
            }
        };
        if kind == 0x08 && !target.starts_with('/') {
            target.push('/');
        } else if !value.is_empty() {
            if !metadata.symlink_component_continues && !target.is_empty() && !target.ends_with('/')
            {
                target.push('/');
            }
            target.push_str(value);
        }
        metadata.symlink_component_continues = component_flags & 0x01 != 0;
        cursor = end;
    }
    if cursor != entry.len() {
        return Err(Error::Decompression(
            "iso RRIP SL entry has trailing bytes".to_owned(),
        ));
    }
    metadata.symlink_entry_continues = flags & 0x01 != 0;
    if metadata.symlink_component_continues && !metadata.symlink_entry_continues {
        return Err(Error::Decompression(
            "iso RRIP SL component continuation is incomplete".to_owned(),
        ));
    }
    Ok(())
}

pub fn detect_iso(bytes: &[u8]) -> bool {
    sector(bytes, VOLUME_DESCRIPTOR_LBA)
        .and_then(|s: &[u8]| s.get(1..6))
        .is_some_and(|id: &[u8]| id == STANDARD_ID)
}

pub fn parse_iso(bytes: &[u8]) -> Result<IsoImage> {
    if !detect_iso(bytes) {
        return Err(Error::Decompression(
            "iso 9660 primary volume descriptor not found at sector 16".to_owned(),
        ));
    }
    let mut primary: Option<usize> = None;
    let mut supplementary: Option<usize> = None;
    let mut terminated: bool = false;
    for i in 0..32 {
        let lba: usize = VOLUME_DESCRIPTOR_LBA + i;
        let vd: &[u8] = sector(bytes, lba).ok_or_else(|| {
            Error::Decompression("iso volume descriptor sequence is truncated".to_owned())
        })?;
        if vd.get(1..6) != Some(STANDARD_ID.as_slice()) {
            return Err(Error::Decompression(
                "iso volume descriptor identifier is malformed".to_owned(),
            ));
        }
        match vd[0] {
            VD_PRIMARY => primary = Some(lba),
            VD_SUPPLEMENTARY if is_joliet(vd) => supplementary = Some(lba),
            VD_TERMINATOR => {
                terminated = true;
                break;
            }
            _ => {}
        }
    }
    if !terminated {
        return Err(Error::Decompression(
            "iso volume descriptor terminator is missing".to_owned(),
        ));
    }

    let primary_lba: usize = primary
        .ok_or_else(|| Error::Decompression("iso primary volume descriptor missing".to_owned()))?;
    let primary_image: IsoImage = parse_descriptor_tree(bytes, primary_lba, false)?;
    if primary_image.rock_ridge {
        return Ok(primary_image);
    }
    supplementary.map_or(Ok(primary_image), |lba: usize| {
        parse_descriptor_tree(bytes, lba, true)
    })
}

fn parse_descriptor_tree(bytes: &[u8], vd_lba: usize, joliet: bool) -> Result<IsoImage> {
    let vd: &[u8] = sector(bytes, vd_lba)
        .ok_or_else(|| Error::Decompression("iso volume descriptor out of bounds".to_owned()))?;
    let volume_space: u32 = read_both_u32(vd, 80, "volume space size")?;
    let volume_set_size: u16 = read_both_u16(vd, 120, "volume set size")?;
    let volume_sequence: u16 = read_both_u16(vd, 124, "volume sequence number")?;
    let logical_block_size: u16 = read_both_u16(vd, 128, "logical block size")?;
    if volume_space == 0
        || volume_set_size != 1
        || volume_sequence != 1
        || logical_block_size as usize != SECTOR_SIZE
    {
        return Err(Error::Decompression(
            "iso volume geometry is unsupported or malformed".to_owned(),
        ));
    }
    let declared_bytes: usize = usize::try_from(volume_space)
        .ok()
        .and_then(|sectors: usize| sectors.checked_mul(SECTOR_SIZE))
        .ok_or_else(|| Error::Decompression("iso volume size overflows".to_owned()))?;
    if declared_bytes > bytes.len() {
        return Err(Error::Decompression(
            "iso declared volume is truncated".to_owned(),
        ));
    }
    let volume: &[u8] = &bytes[..declared_bytes];

    let volume_id: String = decode_volume_id(&vd[40..72], joliet);
    let root_record: &[u8] = vd
        .get(156..156 + 34)
        .ok_or_else(|| Error::Decompression("iso root directory record truncated".to_owned()))?;
    let root_lba: u32 = read_both_u32(root_record, 2, "root extent")?;
    let root_len: u32 = read_both_u32(root_record, 10, "root length")?;
    read_both_u16(root_record, 28, "root volume sequence")?;
    let susp_skip: Option<usize> = susp_skip_from_root(volume, root_lba, root_len)?;

    let mut files: Vec<IsoEntry> = Vec::new();
    let mut context: IsoWalkContext<'_> = IsoWalkContext {
        bytes: volume,
        joliet,
        out: &mut files,
        visited: BTreeSet::new(),
        susp_skip,
        state: IsoWalkState::default(),
    };
    walk_directory(&mut context, root_lba, root_len, String::new(), 0, None)?;
    let rock_ridge: bool = context.state.susp.rrip_present;
    drop(context);
    Ok(IsoImage {
        volume_id,
        joliet,
        rock_ridge,
        files,
    })
}

fn is_joliet(vd: &[u8]) -> bool {
    matches!(vd.get(88..91), Some([0x25, 0x2f, 0x40 | 0x43 | 0x45]))
}

fn decode_volume_id(raw: &[u8], joliet: bool) -> String {
    if joliet {
        decode_ucs2_be(raw).trim().to_owned()
    } else {
        String::from_utf8_lossy(raw).trim().to_owned()
    }
}

fn decode_ucs2_be(raw: &[u8]) -> String {
    let mut out: String = String::with_capacity(raw.len() / 2);
    for pair in raw.chunks_exact(2) {
        let code: u16 = u16::from_be_bytes([pair[0], pair[1]]);
        if code == 0 {
            continue;
        }
        out.push(char::from_u32(u32::from(code)).map_or('\u{fffd}', |value: char| value));
    }
    out
}

fn walk_directory(
    context: &mut IsoWalkContext<'_>,
    lba: u32,
    len: u32,
    prefix: String,
    depth: usize,
    expected_parent_lba: Option<u32>,
) -> Result<()> {
    if depth > MAX_DIR_DEPTH {
        return Err(Error::Decompression(
            "iso directory depth exceeds limit".to_owned(),
        ));
    }
    if !context.visited.insert((lba, len)) {
        return Err(Error::Decompression(
            "iso directory extent cycle detected".to_owned(),
        ));
    }
    let start: usize = (lba as usize)
        .checked_mul(SECTOR_SIZE)
        .ok_or_else(|| Error::Decompression("iso directory extent overflow".to_owned()))?;
    let end: usize = start
        .checked_add(len as usize)
        .ok_or_else(|| Error::Decompression("iso directory extent overflow".to_owned()))?;
    let region: &[u8] = context
        .bytes
        .get(start..end)
        .ok_or_else(|| Error::Decompression("iso directory extent out of bounds".to_owned()))?;

    let mut pos: usize = 0;
    let mut subdirs: Vec<(String, u32, u32, Option<u32>)> = Vec::new();
    let mut pending_extent: Option<PendingExtent> = None;
    while pos < region.len() {
        let record_len: usize = region[pos] as usize;
        if record_len == 0 {
            let next_sector: usize = (pos / SECTOR_SIZE + 1) * SECTOR_SIZE;
            if next_sector <= pos || next_sector >= region.len() {
                break;
            }
            pos = next_sector;
            continue;
        }
        if record_len < 33 || pos.saturating_add(record_len) > region.len() {
            return Err(Error::Decompression(
                "iso directory record is malformed or truncated".to_owned(),
            ));
        }
        let record: &[u8] = &region[pos..pos + record_len];
        context.state.records = context
            .state
            .records
            .checked_add(1)
            .ok_or_else(|| Error::Decompression("iso record count overflows".to_owned()))?;
        if context.state.records > MAX_RECORDS {
            return Err(Error::Decompression(
                "iso directory record count exceeds limit".to_owned(),
            ));
        }
        let extent_lba: u32 = read_both_u32(record, 2, "directory record extent")?;
        let data_len: u32 = read_both_u32(record, 10, "directory record length")?;
        read_both_u16(record, 28, "directory record volume sequence")?;
        let flags: u8 = record[25];
        let name_len: usize = record[32] as usize;
        if 33usize.saturating_add(name_len) > record.len() {
            return Err(Error::Decompression(
                "iso directory record name is truncated".to_owned(),
            ));
        }
        let name_bytes: &[u8] = record
            .get(33..33 + name_len)
            .map_or(&[] as &[u8], |value: &[u8]| value);
        pos += record_len;
        let mut susp_metadata: SuspMetadata = SuspMetadata::default();
        if let Some(skip) = context.susp_skip {
            let system_use_start: usize = system_use_start(record)?
                .checked_add(skip)
                .ok_or_else(|| Error::Decompression("iso SUSP skip overflows".to_owned()))?;
            let system_use: &[u8] = record
                .get(system_use_start..)
                .ok_or_else(|| Error::Decompression("iso SUSP skip exceeds record".to_owned()))?;
            parse_susp(
                context.bytes,
                system_use,
                0,
                &mut context.state.susp,
                &mut susp_metadata,
            )?;
        }

        if name_len == 1 && name_bytes == [0x00] {
            if susp_metadata.parent_link_lba.is_some()
                || susp_metadata.child_link_lba.is_some()
                || susp_metadata.relocated
            {
                return Err(Error::Decompression(
                    "iso RRIP self entry has misplaced relocation metadata".to_owned(),
                ));
            }
            continue;
        }
        if name_len == 1 && name_bytes == [0x01] {
            if susp_metadata.parent_link_lba != expected_parent_lba
                || susp_metadata.child_link_lba.is_some()
                || susp_metadata.relocated
            {
                return Err(Error::Decompression(
                    "iso RRIP parent link does not match the relocated hierarchy".to_owned(),
                ));
            }
            continue;
        }
        if susp_metadata.parent_link_lba.is_some() {
            return Err(Error::Decompression(
                "iso RRIP parent link is outside a parent entry".to_owned(),
            ));
        }
        let extent_start: usize = usize::try_from(extent_lba)
            .ok()
            .and_then(|value: usize| value.checked_mul(SECTOR_SIZE))
            .ok_or_else(|| Error::Decompression("iso entry extent overflows".to_owned()))?;
        let extent_end: usize = extent_start
            .checked_add(data_len as usize)
            .ok_or_else(|| Error::Decompression("iso entry length overflows".to_owned()))?;
        if extent_end > context.bytes.len() {
            return Err(Error::Decompression(
                "iso entry extent is truncated".to_owned(),
            ));
        }
        let name: String = susp_metadata
            .name
            .filter(|name: &String| !name.is_empty())
            .unwrap_or_else(|| decode_record_name(name_bytes, context.joliet));
        if name.is_empty() {
            continue;
        }
        let is_dir: bool = flags & DIR_FLAG_DIRECTORY != 0;
        if susp_metadata.relocated {
            if !is_dir {
                return Err(Error::Decompression(
                    "iso RRIP relocated marker is attached to a non-directory".to_owned(),
                ));
            }
            continue;
        }
        if susp_metadata.child_link_lba.is_some() && !is_dir {
            return Err(Error::Decompression(
                "iso RRIP child link is attached to a non-directory".to_owned(),
            ));
        }
        let effective_lba: u32 = susp_metadata.child_link_lba.unwrap_or(extent_lba);
        let full_len: usize = prefix
            .len()
            .checked_add(name.len())
            .and_then(|value: usize| value.checked_add(usize::from(!prefix.is_empty())))
            .ok_or_else(|| Error::Decompression("iso path length overflows".to_owned()))?;
        context.state.path_bytes = context
            .state
            .path_bytes
            .checked_add(full_len)
            .ok_or_else(|| Error::Decompression("iso path byte count overflows".to_owned()))?;
        if context.state.path_bytes > MAX_PATH_BYTES {
            return Err(Error::Decompression(
                "iso aggregate path bytes exceed limit".to_owned(),
            ));
        }
        context.state.extents = context
            .state
            .extents
            .checked_add(1)
            .ok_or_else(|| Error::Decompression("iso extent count overflows".to_owned()))?;
        if context.state.extents > MAX_EXTENTS {
            return Err(Error::Decompression(
                "iso extent count exceeds limit".to_owned(),
            ));
        }
        let full: String = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let kind: IsoEntryKind = classify_entry(
            is_dir,
            susp_metadata.mode,
            susp_metadata.symlink_target.as_deref(),
        );
        let extent: IsoExtent = IsoExtent {
            extent_lba: effective_lba,
            data_len,
        };
        if flags & DIR_FLAG_MULTI_EXTENT != 0 {
            if kind != IsoEntryKind::Regular
                || susp_metadata.zisofs.is_some()
                || susp_metadata.child_link_lba.is_some()
            {
                return Err(Error::Decompression(
                    "iso multi-extent record has unsupported metadata".to_owned(),
                ));
            }
            match pending_extent.as_mut() {
                Some(pending) => {
                    if pending.path != full
                        || pending.mode != susp_metadata.mode
                        || pending.link_count != susp_metadata.link_count
                        || pending.serial != susp_metadata.serial
                    {
                        return Err(Error::Decompression(
                            "iso multi-extent records are not consecutive and identical".to_owned(),
                        ));
                    }
                    pending.data_len = pending
                        .data_len
                        .checked_add(u64::from(data_len))
                        .ok_or_else(|| {
                            Error::Decompression("iso multi-extent length overflows".to_owned())
                        })?;
                    pending.extents.push(extent);
                }
                None => {
                    pending_extent = Some(PendingExtent {
                        path: full,
                        extent_lba: effective_lba,
                        extents: vec![extent],
                        data_len: u64::from(data_len),
                        mode: susp_metadata.mode,
                        link_count: susp_metadata.link_count,
                        serial: susp_metadata.serial,
                    });
                }
            }
            continue;
        }
        if let Some(mut pending) = pending_extent.take() {
            if pending.path != full
                || pending.mode != susp_metadata.mode
                || pending.link_count != susp_metadata.link_count
                || pending.serial != susp_metadata.serial
                || kind != IsoEntryKind::Regular
                || susp_metadata.zisofs.is_some()
            {
                return Err(Error::Decompression(
                    "iso multi-extent sequence is incomplete or mismatched".to_owned(),
                ));
            }
            pending.data_len = pending
                .data_len
                .checked_add(u64::from(data_len))
                .ok_or_else(|| {
                    Error::Decompression("iso multi-extent length overflows".to_owned())
                })?;
            pending.extents.push(extent);
            context.out.push(IsoEntry {
                path: pending.path,
                extent_lba: pending.extent_lba,
                data_len: pending.data_len,
                extents: pending.extents,
                kind,
                is_dir: false,
                mode: pending.mode,
                link_count: pending.link_count,
                serial: pending.serial,
                symlink_target: None,
                zisofs: None,
            });
            continue;
        }
        if is_dir {
            context.state.directories =
                context.state.directories.checked_add(1).ok_or_else(|| {
                    Error::Decompression("iso directory count overflows".to_owned())
                })?;
            if context.state.directories > MAX_DIRECTORIES {
                return Err(Error::Decompression(
                    "iso directory count exceeds limit".to_owned(),
                ));
            }
        }
        context.out.push(IsoEntry {
            path: full.clone(),
            extent_lba: effective_lba,
            data_len: u64::from(data_len),
            extents: vec![extent],
            kind,
            is_dir,
            mode: susp_metadata.mode,
            link_count: susp_metadata.link_count,
            serial: susp_metadata.serial,
            symlink_target: susp_metadata.symlink_target,
            zisofs: susp_metadata.zisofs,
        });
        if is_dir {
            subdirs.push((
                full,
                effective_lba,
                data_len,
                susp_metadata.child_link_lba.map(|_child: u32| lba),
            ));
        }
    }
    if pending_extent.is_some() {
        return Err(Error::Decompression(
            "iso multi-extent sequence has no final record".to_owned(),
        ));
    }

    for (sub_prefix, sub_lba, sub_len, sub_parent_lba) in subdirs {
        walk_directory(
            context,
            sub_lba,
            sub_len,
            sub_prefix,
            depth + 1,
            sub_parent_lba,
        )?;
    }
    Ok(())
}

fn classify_entry(is_dir: bool, mode: Option<u32>, symlink_target: Option<&str>) -> IsoEntryKind {
    if symlink_target.is_some() {
        return IsoEntryKind::Symlink;
    }
    match mode.map(|value: u32| value & 0o170_000) {
        Some(0o040_000) => IsoEntryKind::Directory,
        Some(0o120_000) => IsoEntryKind::Symlink,
        Some(0) | None if is_dir => IsoEntryKind::Directory,
        Some(0o100_000 | 0) | None => IsoEntryKind::Regular,
        Some(_) => IsoEntryKind::Other,
    }
}

fn decode_record_name(name_bytes: &[u8], joliet: bool) -> String {
    let decoded: String = if joliet {
        decode_ucs2_be(name_bytes)
    } else {
        String::from_utf8_lossy(name_bytes).into_owned()
    };
    strip_version_suffix(&decoded)
}

fn strip_version_suffix(name: &str) -> String {
    match name.rsplit_once(';') {
        Some((base, ver)) if ver.bytes().all(|b: u8| b.is_ascii_digit()) => base.to_owned(),
        _ => name.to_owned(),
    }
}

pub fn file_data<'a>(bytes: &'a [u8], entry: &IsoEntry) -> Option<&'a [u8]> {
    if entry.kind != IsoEntryKind::Regular || entry.zisofs.is_some() || entry.extents.len() != 1 {
        return None;
    }
    let extent: &IsoExtent = entry.extents.first()?;
    let start: usize = (extent.extent_lba as usize).checked_mul(SECTOR_SIZE)?;
    let end: usize = start.checked_add(extent.data_len as usize)?;
    bytes.get(start..end)
}

pub fn read_file_data(bytes: &[u8], entry: &IsoEntry, max_output: u64) -> Result<Vec<u8>> {
    if entry.kind != IsoEntryKind::Regular {
        return Err(Error::Decompression(
            "iso entry is not a regular file".to_owned(),
        ));
    }
    let output_size: u64 = entry.zisofs.map_or(entry.data_len, |info: ZisofsInfo| {
        u64::from(info.uncompressed_size)
    });
    if output_size > max_output {
        return Err(Error::Decompression(
            "iso file output exceeds limit".to_owned(),
        ));
    }
    let capacity: usize =
        usize::try_from(output_size).map_err(|_error: std::num::TryFromIntError| {
            Error::Decompression("iso file output size overflows".to_owned())
        })?;
    if let Some(info) = entry.zisofs {
        let extent: &IsoExtent = entry
            .extents
            .first()
            .ok_or_else(|| Error::Decompression("iso zisofs file has no extent".to_owned()))?;
        if entry.extents.len() != 1 {
            return Err(Error::Decompression(
                "iso zisofs file has multiple extents".to_owned(),
            ));
        }
        let stored: &[u8] = extent_data(bytes, *extent)?;
        return decode_zisofs(stored, info, capacity);
    }
    let mut output: Vec<u8> = Vec::with_capacity(capacity);
    for extent in &entry.extents {
        output.extend_from_slice(extent_data(bytes, *extent)?);
    }
    if output.len() != capacity {
        return Err(Error::Decompression(
            "iso file extent sizes do not match the declared length".to_owned(),
        ));
    }
    Ok(output)
}

fn extent_data(bytes: &[u8], extent: IsoExtent) -> Result<&[u8]> {
    let start: usize = usize::try_from(extent.extent_lba)
        .ok()
        .and_then(|value: usize| value.checked_mul(SECTOR_SIZE))
        .ok_or_else(|| Error::Decompression("iso file extent overflows".to_owned()))?;
    let end: usize = start
        .checked_add(extent.data_len as usize)
        .ok_or_else(|| Error::Decompression("iso file extent length overflows".to_owned()))?;
    bytes
        .get(start..end)
        .ok_or_else(|| Error::Decompression("iso file extent is truncated".to_owned()))
}

fn decode_zisofs(stored: &[u8], info: ZisofsInfo, output_size: usize) -> Result<Vec<u8>> {
    const MAGIC: &[u8; 8] = b"\x37\xe4\x53\x96\xc9\xdb\xd6\x07";
    let header: &[u8] = stored
        .get(..16)
        .ok_or_else(|| Error::Decompression("iso zisofs header is truncated".to_owned()))?;
    let header_size: u8 = header[12];
    let block_shift: u8 = header[13];
    let uncompressed_size: u32 = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    if header.get(..8) != Some(MAGIC.as_slice())
        || header_size != info.header_size_words
        || block_shift != info.block_shift
        || uncompressed_size != info.uncompressed_size
        || header[14..16] != [0, 0]
    {
        return Err(Error::Decompression(
            "iso zisofs header disagrees with the ZF entry".to_owned(),
        ));
    }
    let block_size: usize = 1usize
        .checked_shl(u32::from(block_shift))
        .ok_or_else(|| Error::Decompression("iso zisofs block size overflows".to_owned()))?;
    let block_count: usize = output_size.div_ceil(block_size);
    let pointer_count: usize = block_count
        .checked_add(1)
        .ok_or_else(|| Error::Decompression("iso zisofs pointer count overflows".to_owned()))?;
    if pointer_count > MAX_ZISOFS_BLOCK_POINTERS {
        return Err(Error::Decompression(
            "iso zisofs pointer count exceeds limit".to_owned(),
        ));
    }
    let table_start: usize = usize::from(header_size)
        .checked_mul(4)
        .ok_or_else(|| Error::Decompression("iso zisofs header size overflows".to_owned()))?;
    let table_end: usize = pointer_count
        .checked_mul(4)
        .and_then(|size: usize| table_start.checked_add(size))
        .ok_or_else(|| Error::Decompression("iso zisofs pointer table overflows".to_owned()))?;
    let table: &[u8] = stored
        .get(table_start..table_end)
        .ok_or_else(|| Error::Decompression("iso zisofs pointer table is truncated".to_owned()))?;
    let mut pointers: Vec<usize> = Vec::with_capacity(pointer_count);
    for raw in table.chunks_exact(4) {
        let pointer: usize = usize::try_from(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
            .map_err(|_error: std::num::TryFromIntError| {
                Error::Decompression("iso zisofs pointer overflows".to_owned())
            })?;
        if pointer > stored.len() || pointers.last().is_some_and(|last: &usize| *last > pointer) {
            return Err(Error::Decompression(
                "iso zisofs pointers are not monotonic and bounded".to_owned(),
            ));
        }
        pointers.push(pointer);
    }
    if pointers.first().copied() != Some(table_end)
        || pointers.last().copied() != Some(stored.len())
    {
        return Err(Error::Decompression(
            "iso zisofs pointer table does not cover the exact stored stream".to_owned(),
        ));
    }
    let mut output: Vec<u8> = Vec::with_capacity(output_size);
    for pair in pointers.windows(2) {
        let start: usize = pair[0];
        let end: usize = pair[1];
        let expected: usize = (output_size - output.len()).min(block_size);
        if start == end {
            output.resize(output.len() + expected, 0);
            continue;
        }
        let decoded: Vec<u8> = inflate_exact(&stored[start..end], expected)?;
        output.extend_from_slice(&decoded);
    }
    if output.len() != output_size {
        return Err(Error::Decompression(
            "iso zisofs output size mismatch".to_owned(),
        ));
    }
    Ok(output)
}

fn inflate_exact(compressed: &[u8], expected: usize) -> Result<Vec<u8>> {
    let cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(compressed);
    let mut decoder: flate2::bufread::ZlibDecoder<std::io::Cursor<&[u8]>> =
        flate2::bufread::ZlibDecoder::new(cursor);
    let limit: u64 = u64::try_from(expected)
        .ok()
        .and_then(|value: u64| value.checked_add(1))
        .ok_or_else(|| Error::Decompression("iso zisofs block size overflows".to_owned()))?;
    let mut decoded: Vec<u8> = Vec::with_capacity(expected);
    decoder
        .by_ref()
        .take(limit)
        .read_to_end(&mut decoded)
        .map_err(|error: std::io::Error| {
            Error::Decompression(format!("iso zisofs zlib block: {error}"))
        })?;
    let consumed: usize = usize::try_from(decoder.get_ref().position()).map_err(
        |_error: std::num::TryFromIntError| {
            Error::Decompression("iso zisofs consumed length overflows".to_owned())
        },
    )?;
    if decoded.len() != expected || consumed != compressed.len() {
        return Err(Error::Decompression(
            "iso zisofs block has a size mismatch or trailing data".to_owned(),
        ));
    }
    Ok(decoded)
}

#[cfg(test)]
fn put_record(buf: &mut Vec<u8>, name: &[u8], lba: u32, len: u32, is_dir: bool) {
    put_record_with_system_use(
        buf,
        name,
        lba,
        len,
        if is_dir { DIR_FLAG_DIRECTORY } else { 0 },
        &[],
    );
}

#[cfg(test)]
fn put_record_with_system_use(
    buf: &mut Vec<u8>,
    name: &[u8],
    lba: u32,
    len: u32,
    flags: u8,
    system_use: &[u8],
) {
    let record_len: usize =
        33 + name.len() + usize::from(name.len().is_multiple_of(2)) + system_use.len();
    let start: usize = buf.len();
    buf.push(record_len as u8);
    buf.push(0);
    buf.extend_from_slice(&lba.to_le_bytes());
    buf.extend_from_slice(&lba.to_be_bytes());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&[0u8; 7]);
    buf.push(flags);
    buf.push(0);
    buf.push(0);
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.push(name.len() as u8);
    buf.extend_from_slice(name);
    let system_use_start: usize = 33 + name.len() + usize::from(name.len().is_multiple_of(2));
    while buf.len() - start < system_use_start {
        buf.push(0);
    }
    buf.extend_from_slice(system_use);
    debug_assert_eq!(buf.len() - start, record_len);
}

#[cfg(test)]
pub(crate) fn build_iso(file_name: &[u8], file_body: &[u8]) -> Vec<u8> {
    let total_sectors: usize = 24;
    let mut image: Vec<u8> = vec![0u8; total_sectors * SECTOR_SIZE];

    let root_lba: u32 = 20;
    let file_lba: u32 = 21;

    let pvd_off: usize = VOLUME_DESCRIPTOR_LBA * SECTOR_SIZE;
    image[pvd_off] = VD_PRIMARY;
    image[pvd_off + 1..pvd_off + 6].copy_from_slice(STANDARD_ID);
    image[pvd_off + 6] = 1;
    image[pvd_off + 80..pvd_off + 84].copy_from_slice(&(total_sectors as u32).to_le_bytes());
    image[pvd_off + 84..pvd_off + 88].copy_from_slice(&(total_sectors as u32).to_be_bytes());
    image[pvd_off + 120..pvd_off + 122].copy_from_slice(&1u16.to_le_bytes());
    image[pvd_off + 122..pvd_off + 124].copy_from_slice(&1u16.to_be_bytes());
    image[pvd_off + 124..pvd_off + 126].copy_from_slice(&1u16.to_le_bytes());
    image[pvd_off + 126..pvd_off + 128].copy_from_slice(&1u16.to_be_bytes());
    image[pvd_off + 128..pvd_off + 130].copy_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
    image[pvd_off + 130..pvd_off + 132].copy_from_slice(&(SECTOR_SIZE as u16).to_be_bytes());
    let vol_id: &[u8] = b"DISROBE_TEST                    ";
    image[pvd_off + 40..pvd_off + 40 + vol_id.len()].copy_from_slice(vol_id);
    let mut root_record: Vec<u8> = Vec::new();
    put_record(
        &mut root_record,
        &[0x00],
        root_lba,
        SECTOR_SIZE as u32,
        true,
    );
    image[pvd_off + 156..pvd_off + 156 + root_record.len()].copy_from_slice(&root_record);

    let term_off: usize = (VOLUME_DESCRIPTOR_LBA + 1) * SECTOR_SIZE;
    image[term_off] = VD_TERMINATOR;
    image[term_off + 1..term_off + 6].copy_from_slice(STANDARD_ID);
    image[term_off + 6] = 1;

    let mut dir: Vec<u8> = Vec::new();
    put_record(&mut dir, &[0x00], root_lba, SECTOR_SIZE as u32, true);
    put_record(&mut dir, &[0x01], root_lba, SECTOR_SIZE as u32, true);
    put_record(&mut dir, file_name, file_lba, file_body.len() as u32, false);
    let root_off: usize = root_lba as usize * SECTOR_SIZE;
    image[root_off..root_off + dir.len()].copy_from_slice(&dir);

    let file_off: usize = file_lba as usize * SECTOR_SIZE;
    image[file_off..file_off + file_body.len()].copy_from_slice(file_body);
    image
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn susp_link(signature: [u8; 2], lba: u32) -> Vec<u8> {
        let mut entry: Vec<u8> = vec![signature[0], signature[1], 12, 1];
        entry.extend_from_slice(&lba.to_le_bytes());
        entry.extend_from_slice(&lba.to_be_bytes());
        entry
    }

    fn susp_name(name: &[u8]) -> Vec<u8> {
        let mut entry: Vec<u8> = vec![b'N', b'M', (5 + name.len()) as u8, 1, 0];
        entry.extend_from_slice(name);
        entry
    }

    fn root_susp() -> Vec<u8> {
        let mut entries: Vec<u8> = vec![b'S', b'P', 7, 1, 0xbe, 0xef, 0];
        entries.extend_from_slice(&[b'E', b'R', 18, 1, 10, 0, 0, 1]);
        entries.extend_from_slice(b"RRIP_1991A");
        entries.extend_from_slice(&[b'S', b'T', 4, 1]);
        entries
    }

    #[test]
    fn detects_and_extracts_iso_file() {
        let body: &[u8] = b"iso 9660 recovered file contents";
        let image: Vec<u8> = build_iso(b"HELLO.TXT;1", body);
        assert!(detect_iso(&image));
        let iso: IsoImage = parse_iso(&image).expect("parse iso");
        assert_eq!(iso.volume_id, "DISROBE_TEST");
        let file: &IsoEntry = iso
            .files
            .iter()
            .find(|e: &&IsoEntry| !e.is_dir)
            .expect("file entry");
        assert_eq!(file.path, "HELLO.TXT");
        let data: &[u8] = file_data(&image, file).expect("file data");
        assert_eq!(data, body);
    }

    #[test]
    fn rejects_non_iso() {
        assert!(!detect_iso(&vec![0u8; 4096]));
        assert!(parse_iso(&vec![0u8; 4096]).is_err());
    }

    #[test]
    fn truncated_iso_does_not_panic() {
        let body: &[u8] = b"payload";
        let full: Vec<u8> = build_iso(b"A.TXT;1", body);
        for cut in (SECTOR_SIZE..full.len()).step_by(1024) {
            let _ = parse_iso(&full[..cut]);
        }
    }

    #[test]
    fn both_endian_mismatches_are_rejected() {
        let body: &[u8] = b"payload";
        let mut pvd_mismatch: Vec<u8> = build_iso(b"A.TXT;1", body);
        let pvd_off: usize = VOLUME_DESCRIPTOR_LBA * SECTOR_SIZE;
        pvd_mismatch[pvd_off + 84] ^= 1;
        assert!(parse_iso(&pvd_mismatch).is_err());

        let mut record_mismatch: Vec<u8> = build_iso(b"A.TXT;1", body);
        let root_off: usize = 20 * SECTOR_SIZE;
        let file_record: usize = root_off + 68;
        record_mismatch[file_record + 6] ^= 1;
        assert!(parse_iso(&record_mismatch).is_err());
    }

    #[test]
    fn a_truncated_file_extent_is_rejected() {
        let body: &[u8] = b"payload";
        let mut image: Vec<u8> = build_iso(b"A.TXT;1", body);
        let root_off: usize = 20 * SECTOR_SIZE;
        let file_record: usize = root_off + 68;
        image[file_record + 10..file_record + 14].copy_from_slice(&8_192u32.to_le_bytes());
        image[file_record + 14..file_record + 18].copy_from_slice(&8_192u32.to_be_bytes());
        assert!(parse_iso(&image).is_err());
    }

    #[test]
    fn an_extent_outside_the_declared_volume_is_rejected() {
        let mut image: Vec<u8> = build_iso(b"A.TXT;1", b"payload");
        image.resize(image.len() + SECTOR_SIZE, 0);
        let root_off: usize = 20 * SECTOR_SIZE;
        let file_record: usize = root_off + 68;
        image[file_record + 2..file_record + 6].copy_from_slice(&24u32.to_le_bytes());
        image[file_record + 6..file_record + 10].copy_from_slice(&24u32.to_be_bytes());
        assert!(parse_iso(&image).is_err());
    }

    #[test]
    fn ordered_multi_extent_files_are_concatenated_exactly() {
        let mut image: Vec<u8> = build_iso(b"SPLIT.BIN;1", b"unused");
        let first: &[u8] = b"first extent";
        let second: &[u8] = b"second extent";
        let mut directory: Vec<u8> = Vec::new();
        put_record(&mut directory, &[0], 20, SECTOR_SIZE as u32, true);
        put_record(&mut directory, &[1], 20, SECTOR_SIZE as u32, true);
        put_record_with_system_use(
            &mut directory,
            b"SPLIT.BIN;1",
            21,
            first.len() as u32,
            DIR_FLAG_MULTI_EXTENT,
            &[],
        );
        let final_record_offset: usize = directory.len();
        put_record_with_system_use(
            &mut directory,
            b"SPLIT.BIN;1",
            22,
            second.len() as u32,
            0,
            &[],
        );
        image[20 * SECTOR_SIZE..21 * SECTOR_SIZE].fill(0);
        image[20 * SECTOR_SIZE..20 * SECTOR_SIZE + directory.len()].copy_from_slice(&directory);
        image[21 * SECTOR_SIZE..21 * SECTOR_SIZE + first.len()].copy_from_slice(first);
        image[22 * SECTOR_SIZE..22 * SECTOR_SIZE + second.len()].copy_from_slice(second);

        let parsed: IsoImage = parse_iso(&image).expect("parse multi-extent ISO");
        let file: &IsoEntry = parsed
            .files
            .iter()
            .find(|entry: &&IsoEntry| entry.path == "SPLIT.BIN")
            .expect("multi-extent file");
        assert_eq!(file.extents.len(), 2);
        assert_eq!(file.data_len, (first.len() + second.len()) as u64);
        assert_eq!(
            read_file_data(&image, file, 1 << 20).expect("read multi-extent file"),
            [first, second].concat()
        );

        let mut missing_final: Vec<u8> = image;
        let final_record: usize = 20 * SECTOR_SIZE + final_record_offset;
        missing_final[final_record + 25] |= DIR_FLAG_MULTI_EXTENT;
        assert!(parse_iso(&missing_final).is_err());
    }

    #[test]
    fn zisofs_v1_decodes_compressed_and_sparse_blocks_exactly() {
        let first: Vec<u8> = (0..(1usize << 15))
            .map(|index: usize| (index % 251) as u8)
            .collect();
        let output_size: usize = first.len() + 7_321;
        let mut encoder: flate2::write::ZlibEncoder<Vec<u8>> =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, &first).expect("compress zisofs block");
        let compressed: Vec<u8> = encoder.finish().expect("finish zisofs block");
        let table_end: u32 = 28;
        let compressed_end: u32 = table_end + compressed.len() as u32;
        let mut stored: Vec<u8> = Vec::new();
        stored.extend_from_slice(b"\x37\xe4\x53\x96\xc9\xdb\xd6\x07");
        stored.extend_from_slice(&(output_size as u32).to_le_bytes());
        stored.extend_from_slice(&[4, 15, 0, 0]);
        stored.extend_from_slice(&table_end.to_le_bytes());
        stored.extend_from_slice(&compressed_end.to_le_bytes());
        stored.extend_from_slice(&compressed_end.to_le_bytes());
        stored.extend_from_slice(&compressed);
        let info: ZisofsInfo = ZisofsInfo {
            header_size_words: 4,
            block_shift: 15,
            uncompressed_size: output_size as u32,
        };
        let decoded: Vec<u8> = decode_zisofs(&stored, info, output_size).expect("decode zisofs");
        assert_eq!(&decoded[..first.len()], first);
        assert!(decoded[first.len()..].iter().all(|byte: &u8| *byte == 0));

        let mut trailing: Vec<u8> = stored;
        trailing.push(0);
        assert!(decode_zisofs(&trailing, info, output_size).is_err());
    }

    #[test]
    fn zisofs_metadata_requires_exact_both_endian_size() {
        let mut entry: Vec<u8> = vec![b'Z', b'F', 16, 1, b'p', b'z', 4, 15];
        entry.extend_from_slice(&12_345u32.to_le_bytes());
        entry.extend_from_slice(&12_345u32.to_be_bytes());
        assert_eq!(
            parse_zf(&entry)
                .expect("parse ZF metadata")
                .uncompressed_size,
            12_345
        );
        entry[12] ^= 1;
        assert!(parse_zf(&entry).is_err());
    }

    #[test]
    fn fragmented_names_and_links_require_complete_continuations() {
        let mut area: Vec<u8> = vec![b'N', b'M', 8, 1, 1, b'l', b'o', b'n'];
        area.extend_from_slice(&[b'N', b'M', 6, 1, 0, b'g']);
        area.extend_from_slice(&[b'S', b'L', 9, 1, 1, 1, 2, b'u', b's']);
        area.extend_from_slice(&[b'S', b'L', 13, 1, 0, 0, 1, b'r', 0, 3, b'b', b'i', b'n']);
        area.extend_from_slice(&[b'S', b'T', 4, 1]);
        let mut metadata: SuspMetadata = SuspMetadata::default();
        parse_susp(&[], &area, 0, &mut SuspState::default(), &mut metadata)
            .expect("parse fragmented RRIP metadata");
        assert_eq!(metadata.name.as_deref(), Some("long"));
        assert_eq!(metadata.symlink_target.as_deref(), Some("usr/bin"));

        let truncated: &[u8] = &[b'N', b'M', 8, 1, 1, b'l', b'o', b'n'];
        assert!(
            parse_susp(
                &[],
                truncated,
                0,
                &mut SuspState::default(),
                &mut SuspMetadata::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn symlink_special_components_cannot_continue() {
        for special in [0x02u8, 0x04, 0x08] {
            let area: Vec<u8> = vec![
                b'S',
                b'L',
                7,
                1,
                1,
                special | 0x01,
                0,
                b'S',
                b'L',
                8,
                1,
                0,
                0,
                1,
                b'x',
                b'S',
                b'T',
                4,
                1,
            ];
            assert!(
                parse_susp(
                    &[],
                    &area,
                    0,
                    &mut SuspState::default(),
                    &mut SuspMetadata::default(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn continuation_ranges_may_repeat_as_siblings_but_not_recurse() {
        let mut bytes: Vec<u8> = vec![0; 2 * SECTOR_SIZE];
        bytes[SECTOR_SIZE..SECTOR_SIZE + 4].copy_from_slice(&[b'S', b'T', 4, 1]);
        let mut ce: Vec<u8> = vec![b'C', b'E', 28, 1];
        for value in [1u32, 0, 4] {
            ce.extend_from_slice(&value.to_le_bytes());
            ce.extend_from_slice(&value.to_be_bytes());
        }
        let mut siblings: Vec<u8> = ce.clone();
        siblings.extend_from_slice(&ce);
        siblings.extend_from_slice(&[b'S', b'T', 4, 1]);
        parse_susp(
            &bytes,
            &siblings,
            0,
            &mut SuspState::default(),
            &mut SuspMetadata::default(),
        )
        .expect("shared sibling CE range");

        bytes[SECTOR_SIZE..SECTOR_SIZE + ce.len()].copy_from_slice(&ce);
        assert!(
            parse_susp(
                &bytes,
                &ce,
                0,
                &mut SuspState::default(),
                &mut SuspMetadata::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn child_parent_and_relocated_entries_restore_the_rrip_hierarchy() {
        let mut image: Vec<u8> = build_iso(b"UNUSED.;1", b"unused");
        let mut root: Vec<u8> = Vec::new();
        put_record_with_system_use(
            &mut root,
            &[0],
            20,
            SECTOR_SIZE as u32,
            DIR_FLAG_DIRECTORY,
            &root_susp(),
        );
        put_record(&mut root, &[1], 20, SECTOR_SIZE as u32, true);
        let mut child_link: Vec<u8> = susp_name(b"deep");
        child_link.extend_from_slice(&susp_link(*b"CL", 22));
        child_link.extend_from_slice(&[b'S', b'T', 4, 1]);
        put_record_with_system_use(
            &mut root,
            b"DEEP.;1",
            21,
            SECTOR_SIZE as u32,
            DIR_FLAG_DIRECTORY,
            &child_link,
        );
        let mut relocated: Vec<u8> = susp_name(b"relocated");
        relocated.extend_from_slice(&[b'R', b'E', 4, 1, b'S', b'T', 4, 1]);
        put_record_with_system_use(
            &mut root,
            b"MOVED.;1",
            22,
            SECTOR_SIZE as u32,
            DIR_FLAG_DIRECTORY,
            &relocated,
        );
        image[20 * SECTOR_SIZE..21 * SECTOR_SIZE].fill(0);
        image[20 * SECTOR_SIZE..20 * SECTOR_SIZE + root.len()].copy_from_slice(&root);

        let mut child: Vec<u8> = Vec::new();
        put_record(&mut child, &[0], 22, SECTOR_SIZE as u32, true);
        let mut parent_link: Vec<u8> = susp_link(*b"PL", 20);
        parent_link.extend_from_slice(&[b'S', b'T', 4, 1]);
        put_record_with_system_use(
            &mut child,
            &[1],
            20,
            SECTOR_SIZE as u32,
            DIR_FLAG_DIRECTORY,
            &parent_link,
        );
        let mut child_name: Vec<u8> = susp_name(b"payload");
        child_name.extend_from_slice(&[b'S', b'T', 4, 1]);
        put_record_with_system_use(&mut child, b"PAYLOAD.;1", 23, 1, 0, &child_name);
        image[22 * SECTOR_SIZE..23 * SECTOR_SIZE].fill(0);
        image[22 * SECTOR_SIZE..22 * SECTOR_SIZE + child.len()].copy_from_slice(&child);
        image[23 * SECTOR_SIZE] = b'x';

        let parsed: IsoImage = parse_iso(&image).expect("parse relocated hierarchy");
        assert!(
            parsed
                .files
                .iter()
                .any(|entry: &IsoEntry| entry.path == "deep/payload")
        );
        assert!(
            !parsed
                .files
                .iter()
                .any(|entry: &IsoEntry| entry.path.contains("relocated"))
        );

        let parent_record: usize = 22 * SECTOR_SIZE + 34;
        image[parent_record + 4] ^= 1;
        assert!(parse_iso(&image).is_err());
    }

    #[test]
    fn relocated_marker_on_a_regular_entry_is_rejected() {
        let mut image: Vec<u8> = build_iso(b"UNUSED.;1", b"unused");
        let mut root: Vec<u8> = Vec::new();
        put_record_with_system_use(
            &mut root,
            &[0],
            20,
            SECTOR_SIZE as u32,
            DIR_FLAG_DIRECTORY,
            &root_susp(),
        );
        put_record(&mut root, &[1], 20, SECTOR_SIZE as u32, true);
        let mut relocated: Vec<u8> = susp_name(b"hidden");
        relocated.extend_from_slice(&[b'R', b'E', 4, 1, b'S', b'T', 4, 1]);
        put_record_with_system_use(&mut root, b"HIDDEN.;1", 21, 1, 0, &relocated);
        image[20 * SECTOR_SIZE..21 * SECTOR_SIZE].fill(0);
        image[20 * SECTOR_SIZE..20 * SECTOR_SIZE + root.len()].copy_from_slice(&root);
        assert!(parse_iso(&image).is_err());
    }
}
