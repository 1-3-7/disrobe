use crate::error::{Error, Result};

pub const ARC_MARKER: u8 = 0x1A;
const FNLEN: usize = 13;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcEntry {
    pub name: String,
    pub method: u8,
    pub compressed_size: u32,
    pub original_size: u32,
    pub crc16: u16,
    pub data_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcArchive {
    pub entries: Vec<ArcEntry>,
}

#[must_use]
pub fn detect_arc(bytes: &[u8]) -> bool {
    if bytes.len() < 2 + FNLEN + 4 || bytes[0] != ARC_MARKER {
        return false;
    }
    let method: u8 = bytes[1] & 0x7f;
    if !(1..=11).contains(&method) {
        return false;
    }
    let name: &[u8] = &bytes[2..2 + FNLEN];
    let nul: usize = name
        .iter()
        .position(|&b: &u8| b == 0)
        .map_or(FNLEN, |value: usize| value);
    nul > 0 && name[..nul].iter().all(|&b: &u8| (0x20..0x7f).contains(&b))
}

pub fn parse_arc(bytes: &[u8]) -> Result<ArcArchive> {
    parse_arc_with_entry_limit(bytes, crate::quota::DEFAULT_MAX_ENTRIES)
}

pub(crate) fn parse_arc_with_entry_limit(bytes: &[u8], max_entries: usize) -> Result<ArcArchive> {
    if bytes.first() != Some(&ARC_MARKER) {
        return Err(Error::Arc("arc: missing 0x1a archive marker".to_owned()));
    }
    let mut cursor: usize = 0;
    let mut entries: Vec<ArcEntry> = Vec::new();
    let mut terminated: bool = false;
    while cursor + 2 <= bytes.len() {
        if bytes[cursor] != ARC_MARKER {
            return Err(Error::Arc(format!(
                "arc: expected 0x1a marker at offset {cursor}, found 0x{:02x}",
                bytes[cursor]
            )));
        }
        let raw_method: u8 = bytes[cursor + 1];
        let method: u8 = raw_method & 0x7f;
        if method == 0 {
            terminated = true;
            break;
        }
        let name_start: usize = cursor + 2;
        let name_end: usize = name_start + FNLEN;
        let name_bytes: &[u8] = bytes
            .get(name_start..name_end)
            .ok_or_else(|| Error::Arc("arc: truncated name field".to_owned()))?;
        let name: String = cstr(name_bytes);
        let comp_off: usize = name_end;
        let compressed_size: u32 = read_u32(bytes, comp_off)?;
        let crc_off: usize = comp_off + 4 + 2 + 2;
        let crc16: u16 = read_u16(bytes, crc_off)?;
        let has_orig: bool = method != 1;
        let (original_size, header_end): (u32, usize) = if has_orig {
            (read_u32(bytes, crc_off + 2)?, crc_off + 2 + 4)
        } else {
            (compressed_size, crc_off + 2)
        };
        let data_offset: usize = if raw_method & 0x80 == 0 {
            header_end
        } else {
            header_end
                .checked_add(12)
                .ok_or_else(|| Error::Arc("arc: Spark header size overflow".to_owned()))?
        };
        let data_end: usize = data_offset
            .checked_add(compressed_size as usize)
            .ok_or_else(|| Error::Arc("arc: data size overflow".to_owned()))?;
        if data_end > bytes.len() {
            return Err(Error::Arc(format!(
                "arc: entry `{name}` data runs past end of archive"
            )));
        }
        if entries.len() >= max_entries {
            return Err(Error::QuotaExceeded {
                entry: name,
                reason: format!("ARC entry count exceeds cap {max_entries}"),
            });
        }
        entries.push(ArcEntry {
            name,
            method,
            compressed_size,
            original_size,
            crc16,
            data_offset,
        });
        cursor = data_end;
    }
    if entries.is_empty() {
        return Err(Error::Arc("arc: no entries before end marker".to_owned()));
    }
    if !terminated {
        return Err(Error::Arc("arc: missing end marker".to_owned()));
    }
    Ok(ArcArchive { entries })
}

#[must_use]
pub const fn entry_is_stored(entry: &ArcEntry) -> bool {
    entry.method == 1 || entry.method == 2
}

pub(crate) fn preflight_entry_quota(
    entry: &ArcEntry,
    quota: crate::quota::ExtractionQuota,
) -> Result<()> {
    let mut guard: crate::quota::QuotaGuard =
        crate::quota::QuotaGuard::new(crate::quota::ExtractionQuota {
            max_entries: 1,
            max_total_uncompressed: quota.max_per_entry_uncompressed,
            max_per_entry_uncompressed: quota.max_per_entry_uncompressed,
            max_per_entry_ratio: quota.max_per_entry_ratio,
            max_aggregate_ratio: u64::MAX,
        });
    guard.admit_entry(
        &entry.name,
        u64::from(entry.original_size),
        u64::from(entry.compressed_size),
    )
}

fn entry_raw<'a>(bytes: &'a [u8], entry: &ArcEntry) -> Result<&'a [u8]> {
    let end: usize = entry
        .data_offset
        .checked_add(entry.compressed_size as usize)
        .ok_or_else(|| Error::Arc(format!("arc: entry `{}` data range overflow", entry.name)))?;
    bytes
        .get(entry.data_offset..end)
        .ok_or_else(|| Error::Arc(format!("arc: entry `{}` data out of bounds", entry.name)))
}

pub fn entry_bytes(bytes: &[u8], entry: &ArcEntry, max_out: u64) -> Result<Vec<u8>> {
    let raw: &[u8] = entry_raw(bytes, entry)?;
    let cap: usize = usize::try_from(max_out).map_or(usize::MAX, |value: usize| value);
    let expected: usize = usize::try_from(entry.original_size).map_err(|_| {
        Error::Arc(format!(
            "arc: entry `{}` original size does not fit this platform",
            entry.name
        ))
    })?;
    if expected > cap {
        return Err(Error::Arc(format!(
            "arc: entry `{}` output exceeds cap",
            entry.name
        )));
    }
    let decoded: Vec<u8> = match entry.method {
        1 | 2 => raw.to_vec(),
        3 => crate::containers::arc_codec::un_rle(raw, cap)?,
        4 => crate::containers::arc_codec::un_squeeze(raw, cap)?,
        5 => crate::containers::arc_codec::un_crunch_fixed(raw, false, cap)?,
        6 | 7 => {
            let intermediate_cap: usize = expected.checked_mul(2).ok_or_else(|| {
                Error::Arc(format!(
                    "arc: entry `{}` intermediate size overflow",
                    entry.name
                ))
            })?;
            let intermediate: Vec<u8> = crate::containers::arc_codec::un_crunch_fixed(
                raw,
                entry.method == 7,
                intermediate_cap,
            )?;
            crate::containers::arc_codec::un_rle(&intermediate, cap)?
        }
        8 => crate::containers::arc_codec::un_crunch(raw, expected)?,
        9 => crate::containers::arc_codec::un_squash(raw, expected)?,
        11 => un_distill(raw, expected, cap)?,
        other => {
            return Err(Error::Arc(format!(
                "arc: entry `{}` uses compression method {other}, which is not decodable in-tree",
                entry.name
            )));
        }
    };
    if decoded.len() != expected {
        return Err(Error::Arc(format!(
            "arc: entry `{}` decoded to {} bytes, header declares {}",
            entry.name,
            decoded.len(),
            entry.original_size
        )));
    }
    let actual_crc: u16 = crate::containers::lzh::crc16_arc(&decoded);
    if actual_crc != entry.crc16 {
        return Err(Error::Arc(format!(
            "arc: entry `{}` CRC mismatch: header {:04x}, decoded {:04x}",
            entry.name, entry.crc16, actual_crc
        )));
    }
    Ok(decoded)
}

fn cstr(field: &[u8]) -> String {
    let end: usize = field
        .iter()
        .position(|&b: &u8| b == 0)
        .map_or(field.len(), |value: usize| value);
    String::from_utf8_lossy(&field[..end]).into_owned()
}

fn read_u16(bytes: &[u8], at: usize) -> Result<u16> {
    disrobe_bytes::read_u16_le_at(bytes, at)
        .map_err(|_| Error::Arc("arc: truncated u16".to_owned()))
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32> {
    disrobe_bytes::read_u32_le_at(bytes, at)
        .map_err(|_| Error::Arc("arc: truncated u32".to_owned()))
}

const DISTILLED_WINDOW_SIZE: usize = 8_192;
const DISTILLED_MAX_NODES: usize = 628;
const DISTILLED_MAX_CODES: usize = 315;
const DISTILLED_STOP_CODE: u16 = 256;
const DISTILLED_MIN_MATCH: u16 = 3;
const DISTILLED_MAX_MATCH: u16 = 60;
const DISTILLED_MATCH_BIAS: u16 = 254;
const DISTILLED_MAX_TRIE_NODES: usize = DISTILLED_MAX_CODES * 2 - 1;
const DISTILLED_OFFSET_CODES: [u8; 64] = [
    0x00, 0x04, 0x02, 0x03, 0x10, 0x0c, 0x0a, 0x0e, 0x11, 0x0d, 0x0b, 0x0f, 0x28, 0x24, 0x2c, 0x2a,
    0x26, 0x2e, 0x29, 0x25, 0x2d, 0x2b, 0x27, 0x2f, 0x60, 0x70, 0x68, 0x64, 0x74, 0x6c, 0x62, 0x72,
    0x6a, 0x66, 0x76, 0x6e, 0x61, 0x71, 0x69, 0x65, 0x75, 0x6d, 0x63, 0x73, 0x6b, 0x67, 0x77, 0x6f,
    0xf0, 0xf8, 0xf4, 0xfc, 0xf2, 0xfa, 0xf6, 0xfe, 0xf1, 0xf9, 0xf5, 0xfd, 0xf3, 0xfb, 0xf7, 0xff,
];

struct DistilledBitReader<'a> {
    src: &'a [u8],
    pos: usize,
    accumulator: u32,
    bits: u32,
}

impl<'a> DistilledBitReader<'a> {
    const fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            pos: 0,
            accumulator: 0,
            bits: 0,
        }
    }

    fn read_bit(&mut self) -> Result<u32> {
        if self.bits == 0 {
            let byte: u8 = *self.src.get(self.pos).ok_or_else(|| {
                Error::Decompression(
                    "arc: distilled stream ended before the decoded data".to_owned(),
                )
            })?;
            self.pos += 1;
            self.accumulator = u32::from(byte);
            self.bits = 8;
        }
        let bit: u32 = self.accumulator & 1;
        self.accumulator >>= 1;
        self.bits -= 1;
        Ok(bit)
    }

    fn read_bits(&mut self, count: u32) -> Result<u32> {
        if count > 32 {
            return Err(Error::Decompression(
                "arc: distilled bit request exceeds the reader width".to_owned(),
            ));
        }
        let mut value: u32 = 0;
        for index in 0..count {
            value |= self.read_bit()? << index;
        }
        Ok(value)
    }
}

struct DistilledTrieNode {
    child: [Option<usize>; 2],
    value: Option<u16>,
}

struct DistilledTrie {
    nodes: Vec<DistilledTrieNode>,
}

impl DistilledTrie {
    fn new() -> Self {
        Self {
            nodes: vec![DistilledTrieNode {
                child: [None, None],
                value: None,
            }],
        }
    }

    fn insert(&mut self, code: u32, bits: u32, value: u16) -> Result<()> {
        if bits == 0 || bits > u32::BITS {
            return Err(Error::Decompression(format!(
                "arc: distilled code length {bits} is outside 1..={}",
                u32::BITS
            )));
        }
        let mut node: usize = 0;
        for depth in (0..bits).rev() {
            let branch: usize = ((code >> depth) & 1) as usize;
            node = self.child(node, branch)?;
        }
        self.assign(node, value)
    }

    fn child(&mut self, node: usize, branch: usize) -> Result<usize> {
        if self.nodes[node].value.is_some() {
            return Err(Error::Decompression(
                "arc: distilled code table has a prefix collision".to_owned(),
            ));
        }
        if let Some(index) = self.nodes[node].child[branch] {
            return Ok(index);
        }
        if self.nodes.len() >= DISTILLED_MAX_TRIE_NODES {
            return Err(Error::Decompression(format!(
                "arc: distilled code table exceeds {DISTILLED_MAX_TRIE_NODES} trie nodes"
            )));
        }
        let index: usize = self.nodes.len();
        self.nodes.push(DistilledTrieNode {
            child: [None, None],
            value: None,
        });
        self.nodes[node].child[branch] = Some(index);
        Ok(index)
    }

    fn assign(&mut self, node: usize, value: u16) -> Result<()> {
        let slot: &mut DistilledTrieNode = self.nodes.get_mut(node).ok_or_else(|| {
            Error::Decompression("arc: distilled trie index is invalid".to_owned())
        })?;
        if slot.value.is_some() || slot.child[0].is_some() || slot.child[1].is_some() {
            return Err(Error::Decompression(
                "arc: distilled code table has a duplicate code".to_owned(),
            ));
        }
        slot.value = Some(value);
        Ok(())
    }

    fn read(&self, reader: &mut DistilledBitReader<'_>) -> Result<u16> {
        let mut node: usize = 0;
        for _ in 0..self.nodes.len() {
            if let Some(value) = self.nodes[node].value {
                return Ok(value);
            }
            let branch: usize = reader.read_bit()? as usize;
            node = self.nodes[node].child[branch].ok_or_else(|| {
                Error::Decompression("arc: distilled stream selects an unassigned code".to_owned())
            })?;
        }
        Err(Error::Decompression(
            "arc: distilled code walk exceeds its depth limit".to_owned(),
        ))
    }
}

const fn distilled_offset_code_bits(index: usize) -> u32 {
    if index == 0 {
        3
    } else if index < 4 {
        4
    } else if index < 12 {
        5
    } else if index < 24 {
        6
    } else if index < 48 {
        7
    } else {
        8
    }
}

fn distilled_offsets_trie() -> Result<DistilledTrie> {
    let mut trie: DistilledTrie = DistilledTrie::new();
    for (index, code) in DISTILLED_OFFSET_CODES.into_iter().enumerate() {
        trie.insert(
            u32::from(code),
            distilled_offset_code_bits(index),
            index as u16,
        )?;
    }
    Ok(trie)
}

struct DistilledNodeTable {
    values: Vec<u16>,
    in_use: Vec<bool>,
}

impl DistilledNodeTable {
    fn descend(&mut self, trie: &mut DistilledTrie, value: u16, trie_node: usize) -> Result<()> {
        let count: u16 = u16::try_from(self.values.len()).map_err(|_| {
            Error::Decompression("arc: distilled node count exceeds u16".to_owned())
        })?;
        if value < count {
            return self.walk(trie, usize::from(value), trie_node);
        }
        let symbol: u16 = value - count;
        if usize::from(symbol) >= DISTILLED_MAX_CODES {
            return Err(Error::Decompression(format!(
                "arc: distilled leaf value {symbol} exceeds the {DISTILLED_MAX_CODES}-code table"
            )));
        }
        trie.assign(trie_node, symbol)
    }

    fn walk(&mut self, trie: &mut DistilledTrie, node: usize, trie_node: usize) -> Result<()> {
        if !node.is_multiple_of(2) || node + 1 >= self.values.len() {
            return Err(Error::Decompression(
                "arc: distilled node table selects an invalid pair".to_owned(),
            ));
        }
        if self.in_use[node] || self.in_use[node + 1] {
            return Err(Error::Decompression(
                "arc: distilled node table contains a cycle".to_owned(),
            ));
        }
        self.in_use[node] = true;
        self.in_use[node + 1] = true;
        let left: u16 = self.values[node];
        let right: u16 = self.values[node + 1];
        let result: Result<()> = (|| {
            let left_node: usize = trie.child(trie_node, 0)?;
            let right_node: usize = trie.child(trie_node, 1)?;
            self.descend(trie, left, left_node)?;
            self.descend(trie, right, right_node)
        })();
        self.in_use[node] = false;
        self.in_use[node + 1] = false;
        result
    }
}

fn distilled_literals_trie(reader: &mut DistilledBitReader<'_>) -> Result<DistilledTrie> {
    let count: usize = reader.read_bits(16)? as usize;
    if !(2..=DISTILLED_MAX_NODES).contains(&count) || !count.is_multiple_of(2) {
        return Err(Error::Decompression(format!(
            "arc: distilled node count {count} is not an even value in 2..={DISTILLED_MAX_NODES}"
        )));
    }
    let width: u32 = reader.read_bits(8)?;
    if !(1..=12).contains(&width) {
        return Err(Error::Decompression(format!(
            "arc: distilled node width {width} is outside 1..=12"
        )));
    }
    let mut values: Vec<u16> = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(reader.read_bits(width)? as u16);
    }
    let mut table: DistilledNodeTable = DistilledNodeTable {
        values,
        in_use: vec![false; count],
    };
    let mut trie: DistilledTrie = DistilledTrie::new();
    table.walk(&mut trie, count - 2, 0)?;
    Ok(trie)
}

fn distilled_extra_offset_bits(produced: usize) -> u32 {
    let reach: usize = produced.saturating_add(60);
    for width in (6..=12).rev() {
        if reach >= (1usize << width) {
            return width - 5;
        }
    }
    0
}

fn un_distill(input: &[u8], expected: usize, cap: usize) -> Result<Vec<u8>> {
    if expected > cap {
        return Err(Error::Decompression(format!(
            "arc: distilled member declares {expected} bytes above the {cap}-byte limit"
        )));
    }
    let mut reader: DistilledBitReader<'_> = DistilledBitReader::new(input);
    let literals: DistilledTrie = distilled_literals_trie(&mut reader)?;
    let offsets: DistilledTrie = distilled_offsets_trie()?;
    let mut window: Box<[u8; DISTILLED_WINDOW_SIZE]> = Box::new([b' '; DISTILLED_WINDOW_SIZE]);
    let mut window_pos: usize = 0;
    let mut out: Vec<u8> = Vec::with_capacity(crate::quota::bounded_prealloc(expected as u64));
    let mut commands: usize = 0;
    while out.len() < expected {
        commands = commands.checked_add(1).ok_or_else(|| {
            Error::Decompression("arc: distilled command counter overflow".to_owned())
        })?;
        if commands > expected.saturating_add(1) {
            return Err(Error::Decompression(format!(
                "arc: distilled stream issued more than {expected} command(s)"
            )));
        }
        let code: u16 = literals.read(&mut reader)?;
        if code == DISTILLED_STOP_CODE {
            break;
        }
        if code < DISTILLED_STOP_CODE {
            let byte: u8 = code as u8;
            window[window_pos] = byte;
            window_pos = (window_pos + 1) % DISTILLED_WINDOW_SIZE;
            out.push(byte);
            continue;
        }
        let length: u16 = code.checked_sub(DISTILLED_MATCH_BIAS).ok_or_else(|| {
            Error::Decompression("arc: distilled match length underflow".to_owned())
        })?;
        if !(DISTILLED_MIN_MATCH..=DISTILLED_MAX_MATCH).contains(&length) {
            return Err(Error::Decompression(format!(
                "arc: distilled match length {length} is outside {DISTILLED_MIN_MATCH}..={DISTILLED_MAX_MATCH}"
            )));
        }
        let remaining: usize = expected - out.len();
        if usize::from(length) > remaining {
            return Err(Error::Decompression(
                "arc: distilled match exceeds the declared output length".to_owned(),
            ));
        }
        let high: usize = usize::from(offsets.read(&mut reader)?);
        let extra: u32 = distilled_extra_offset_bits(out.len());
        let distance: usize = (high << extra) | reader.read_bits(extra)? as usize;
        if distance >= DISTILLED_WINDOW_SIZE {
            return Err(Error::Decompression(format!(
                "arc: distilled match distance {distance} exceeds the {DISTILLED_WINDOW_SIZE}-byte window"
            )));
        }
        let mut source: usize =
            (window_pos + DISTILLED_WINDOW_SIZE - 1 - distance) % DISTILLED_WINDOW_SIZE;
        for _ in 0..length {
            let byte: u8 = window[source];
            window[window_pos] = byte;
            window_pos = (window_pos + 1) % DISTILLED_WINDOW_SIZE;
            source = (source + 1) % DISTILLED_WINDOW_SIZE;
            out.push(byte);
        }
    }
    if out.len() != expected {
        return Err(Error::Decompression(format!(
            "arc: distilled stream stopped after {} of {expected} byte(s)",
            out.len()
        )));
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) fn build_entry(method: u8, name: &str, data: &[u8], orig: u32) -> Vec<u8> {
    let mut out: Vec<u8> = vec![ARC_MARKER, method];
    let mut name_field: [u8; FNLEN] = [0u8; FNLEN];
    let nb: &[u8] = name.as_bytes();
    name_field[..nb.len()].copy_from_slice(nb);
    out.extend_from_slice(&name_field);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&crate::containers::lzh::crc16_arc(data).to_le_bytes());
    if method != 1 {
        out.extend_from_slice(&orig.to_le_bytes());
    }
    out.extend_from_slice(data);
    out
}

#[cfg(test)]
pub(crate) fn synth_stored_arc(name: &str, body: &[u8]) -> Option<Vec<u8>> {
    if name.len() >= FNLEN {
        return None;
    }
    let mut blob: Vec<u8> = build_entry(2, name, body, u32::try_from(body.len()).ok()?);
    blob.push(ARC_MARKER);
    blob.push(0);
    Some(blob)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detect_recognizes_stored_arc() {
        let e: Vec<u8> = build_entry(2, "readme.txt", b"hello arc world", 15);
        assert!(detect_arc(&e));
        assert!(!detect_arc(b"PK\x03\x04 not arc"));
    }

    #[test]
    fn parses_stored_member_byte_exact() {
        let payload: &[u8] = b"stored arc member bytes, method 2";
        let mut blob: Vec<u8> = build_entry(2, "data.txt", payload, payload.len() as u32);
        blob.push(ARC_MARKER);
        blob.push(0);
        let archive: ArcArchive = parse_arc(&blob).expect("parse arc");
        assert_eq!(archive.entries.len(), 1);
        let entry: &ArcEntry = &archive.entries[0];
        assert_eq!(entry.name, "data.txt");
        assert!(entry_is_stored(entry));
        assert_eq!(entry_bytes(&blob, entry, 1 << 20).expect("bytes"), payload);
    }

    fn build_entry_compressed(method: u8, name: &str, comp: &[u8], decoded: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = vec![ARC_MARKER, method];
        let mut name_field: [u8; FNLEN] = [0u8; FNLEN];
        let nb: &[u8] = name.as_bytes();
        name_field[..nb.len()].copy_from_slice(nb);
        out.extend_from_slice(&name_field);
        out.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&crate::containers::lzh::crc16_arc(decoded).to_le_bytes());
        out.extend_from_slice(&(decoded.len() as u32).to_le_bytes());
        out.extend_from_slice(comp);
        out
    }

    fn rle_encode_for_test(input: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let mut i: usize = 0;
        while i < input.len() {
            let byte: u8 = input[i];
            let mut run: usize = 1;
            while i + run < input.len() && input[i + run] == byte && run < 255 {
                run += 1;
            }
            if byte == 0x90 {
                for _ in 0..run {
                    out.push(0x90);
                    out.push(0);
                }
            } else if run >= 4 {
                out.push(byte);
                out.push(0x90);
                out.push(run as u8);
            } else {
                out.push(byte);
                i += 1;
                continue;
            }
            i += run;
        }
        out
    }

    #[test]
    fn method3_rle_round_trips_through_entry_bytes() {
        let payload: Vec<u8> = {
            let mut v: Vec<u8> = b"header".to_vec();
            v.extend(std::iter::repeat_n(b'=', 40));
            v.extend_from_slice(b"footer");
            v
        };
        let comp: Vec<u8> = rle_encode_for_test(&payload);
        let mut blob: Vec<u8> = build_entry_compressed(3, "rle.txt", &comp, &payload);
        blob.push(ARC_MARKER);
        blob.push(0);
        let archive: ArcArchive = parse_arc(&blob).expect("parse arc");
        let decoded: Vec<u8> =
            entry_bytes(&blob, &archive.entries[0], 1 << 20).expect("decode method 3");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn fixed_lzw_methods_decode_reference_wires_through_arc_entries() {
        const METHOD_FIVE: &[u8] = &[
            0x0a, 0x50, 0x82, 0xd6, 0x69, 0x8b, 0x98, 0xb3, 0x77, 0x37, 0x70,
        ];
        const METHOD_SIX: &[u8] = &[
            0x0a, 0x54, 0xff, 0x10, 0x00, 0x82, 0x5a, 0x00, 0xc4, 0x5a, 0x03, 0x13, 0x6d, 0x45,
            0xa0,
        ];
        const METHOD_SEVEN: &[u8] = &[
            0x84, 0x03, 0xaf, 0xb8, 0x43, 0x21, 0x93, 0x4e, 0x02, 0x93, 0x4e, 0xd0, 0x50, 0x69,
            0x34,
        ];
        let cases: [(u8, &str, &[u8], &[u8]); 3] = [
            (5, "method5.bin", METHOD_FIVE, b"ABABABAABABABA"),
            (6, "method6.bin", METHOD_SIX, b"AAAAABBBBBCCCCCAAAAABBBBB"),
            (7, "method7.bin", METHOD_SEVEN, b"AAAAABBBBBCCCCCAAAAABBBBB"),
        ];
        for (method, name, compressed, expected) in cases {
            let mut blob: Vec<u8> = build_entry_compressed(method, name, compressed, expected);
            blob.extend_from_slice(&[ARC_MARKER, 0]);
            let archive: ArcArchive = parse_arc(&blob).expect("parse fixed LZW ARC entry");
            let decoded: Vec<u8> =
                entry_bytes(&blob, &archive.entries[0], 1 << 20).expect("decode fixed LZW ARC");
            assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn fixed_lzw_accepts_an_empty_member_and_preflights_the_ratio_boundary() {
        let mut blob: Vec<u8> = build_entry_compressed(5, "empty.bin", &[], &[]);
        blob.extend_from_slice(&[ARC_MARKER, 0]);
        let archive: ArcArchive = parse_arc(&blob).expect("parse empty fixed LZW ARC entry");
        let decoded: Vec<u8> =
            entry_bytes(&blob, &archive.entries[0], 0).expect("decode empty fixed LZW ARC");
        assert!(decoded.is_empty());

        let entry: ArcEntry = ArcEntry {
            name: "ratio.bin".to_owned(),
            method: 5,
            compressed_size: 1,
            original_size: 100,
            crc16: 0,
            data_offset: 0,
        };
        let exact: crate::quota::ExtractionQuota = crate::quota::ExtractionQuota {
            max_per_entry_uncompressed: 100,
            max_per_entry_ratio: 100,
            ..crate::quota::ExtractionQuota::default_safe()
        };
        preflight_entry_quota(&entry, exact).expect("admit exact ARC ratio boundary");
        let below: crate::quota::ExtractionQuota = crate::quota::ExtractionQuota {
            max_per_entry_ratio: 99,
            ..exact
        };
        assert!(matches!(
            preflight_entry_quota(&entry, below),
            Err(Error::QuotaExceeded { .. })
        ));
    }

    #[test]
    fn distilled_node_table_rejects_odd_pair_references() {
        let mut table: DistilledNodeTable = DistilledNodeTable {
            values: vec![0, 6, 7, 0, 1, 8],
            in_use: vec![false; 6],
        };
        let mut trie: DistilledTrie = DistilledTrie::new();
        let error: Error = table
            .walk(&mut trie, 4, 0)
            .expect_err("reject an odd node-pair reference");
        assert!(matches!(error, Error::Decompression(message) if message.contains("invalid pair")));
    }

    #[test]
    fn distilled_node_table_accepts_the_bounded_maximum_depth() {
        let mut values: Vec<u16> = Vec::with_capacity(DISTILLED_MAX_NODES);
        let count: u16 = DISTILLED_MAX_NODES as u16;
        values.extend([count, count + 1]);
        for pair in 1..(DISTILLED_MAX_NODES / 2) {
            values.push(count + pair as u16 + 1);
            values.push((pair * 2 - 2) as u16);
        }
        let mut table: DistilledNodeTable = DistilledNodeTable {
            values,
            in_use: vec![false; DISTILLED_MAX_NODES],
        };
        let mut trie: DistilledTrie = DistilledTrie::new();
        table
            .walk(&mut trie, DISTILLED_MAX_NODES - 2, 0)
            .expect("accept a finite maximum-depth node table");
        let mut encoded: Vec<u8> = vec![u8::MAX; 39];
        encoded.push(1);
        let mut reader: DistilledBitReader<'_> = DistilledBitReader::new(&encoded);
        assert_eq!(trie.read(&mut reader).expect("read deepest code"), 0);
    }

    #[test]
    fn unsupported_method_errors() {
        let payload: &[u8] = b"\x01\x02\x03 unsupported arc variant";
        let mut blob: Vec<u8> = build_entry_compressed(10, "old.dat", payload, &[0; 16]);
        blob.extend_from_slice(&[ARC_MARKER, 0]);
        let archive: ArcArchive = parse_arc(&blob).expect("parse arc");
        assert!(entry_bytes(&blob, &archive.entries[0], 1 << 20).is_err());
    }

    #[test]
    fn decoded_member_with_a_mismatched_crc_is_rejected() {
        let payload: &[u8] = b"crc protected arc member";
        let mut blob: Vec<u8> = build_entry(2, "crc.txt", payload, payload.len() as u32);
        blob[23..25].copy_from_slice(&0x1234_u16.to_le_bytes());
        blob.extend_from_slice(&[ARC_MARKER, 0]);
        let archive: ArcArchive = parse_arc(&blob).expect("parse arc");
        let decoded: Result<Vec<u8>> = entry_bytes(&blob, &archive.entries[0], 1 << 20);
        assert!(matches!(decoded, Err(Error::Arc(message)) if message.contains("CRC")));
    }

    #[test]
    fn parser_enforces_the_entry_limit_before_retaining_another_member() {
        let mut blob: Vec<u8> = build_entry(2, "one.txt", b"one", 3);
        blob.extend_from_slice(&build_entry(2, "two.txt", b"two", 3));
        blob.extend_from_slice(&[ARC_MARKER, 0]);
        let parsed: Result<ArcArchive> = parse_arc_with_entry_limit(&blob, 1);
        assert!(matches!(parsed, Err(Error::QuotaExceeded { .. })));
    }

    #[test]
    fn parser_rejects_an_archive_without_the_end_marker() {
        let blob: Vec<u8> = build_entry(2, "one.txt", b"one", 3);
        let parsed: Result<ArcArchive> = parse_arc(&blob);
        assert!(matches!(parsed, Err(Error::Arc(message)) if message.contains("end marker")));
    }
}
