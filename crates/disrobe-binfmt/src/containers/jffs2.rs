use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const JFFS2_MAGIC: u16 = 0x1985;
const JFFS2_NODETYPE_DIRENT: u16 = 0xE001;
const JFFS2_NODETYPE_INODE: u16 = 0xE002;
const JFFS2_NODETYPE_CLEANMARKER: u16 = 0x2003;
const JFFS2_NODETYPE_PADDING: u16 = 0x2004;
const JFFS2_NODETYPE_SUMMARY: u16 = 0x2006;
const JFFS2_NODETYPE_XATTR: u16 = 0xE008;
const JFFS2_NODETYPE_XREF: u16 = 0xE009;

const JFFS2_COMPR_NONE: u8 = 0;
const JFFS2_COMPR_ZERO: u8 = 1;
const JFFS2_COMPR_RTIME: u8 = 2;
const JFFS2_COMPR_RUBINMIPS: u8 = 3;
const JFFS2_COMPR_COPY: u8 = 4;
const JFFS2_COMPR_DYNRUBIN: u8 = 5;
const JFFS2_COMPR_ZLIB: u8 = 6;
const JFFS2_COMPR_LZO: u8 = 7;

const DT_DIR: u8 = 4;
const DT_LNK: u8 = 10;
const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;
const ROOT_INO: u32 = 1;
const MAX_NODES: usize = 2_000_000;
const MAX_FILES: usize = 500_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Jffs2Endian {
    Little,
    Big,
}

#[derive(Debug, Clone)]
pub struct Jffs2File {
    pub path: String,
    pub data: Vec<u8>,
    pub is_executable: bool,
    pub is_symlink: bool,
}

#[derive(Debug, Clone)]
pub struct Jffs2Walk {
    pub endian: Jffs2Endian,
    pub files: Vec<Jffs2File>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct Endian(Jffs2Endian);

impl Endian {
    fn u16(self, b: &[u8], at: usize) -> u16 {
        let raw: [u8; 2] = [b[at], b[at + 1]];
        match self.0 {
            Jffs2Endian::Little => u16::from_le_bytes(raw),
            Jffs2Endian::Big => u16::from_be_bytes(raw),
        }
    }

    fn u32(self, b: &[u8], at: usize) -> u32 {
        let raw: [u8; 4] = [b[at], b[at + 1], b[at + 2], b[at + 3]];
        match self.0 {
            Jffs2Endian::Little => u32::from_le_bytes(raw),
            Jffs2Endian::Big => u32::from_be_bytes(raw),
        }
    }
}

#[derive(Debug, Clone)]
struct Dirent {
    pino: u32,
    version: u32,
    ino: u32,
    dtype: u8,
    name: String,
}

#[derive(Debug, Clone)]
struct InodeNode {
    ino: u32,
    version: u32,
    mode: u32,
    isize_field: u32,
    offset: u32,
    dsize: u32,
    compr: u8,
    data: Vec<u8>,
}

const fn align4(n: usize) -> usize {
    n.div_ceil(4) * 4
}

#[must_use]
pub fn detect_jffs2(bytes: &[u8]) -> Option<Jffs2Endian> {
    let mut pos: usize = 0;
    while pos + 4 <= bytes.len().min(0x4000) {
        let le: u16 = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]);
        let be: u16 = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
        if le == JFFS2_MAGIC {
            let nodetype: u16 = u16::from_le_bytes([bytes[pos + 2], bytes[pos + 3]]);
            if is_known_nodetype(nodetype) {
                return Some(Jffs2Endian::Little);
            }
        }
        if be == JFFS2_MAGIC {
            let nodetype: u16 = u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]);
            if is_known_nodetype(nodetype) {
                return Some(Jffs2Endian::Big);
            }
        }
        if le == 0xFFFF || le == 0x0000 {
            pos += 4;
            continue;
        }
        pos += 4;
    }
    None
}

const fn is_known_nodetype(nt: u16) -> bool {
    matches!(
        nt,
        JFFS2_NODETYPE_DIRENT
            | JFFS2_NODETYPE_INODE
            | JFFS2_NODETYPE_CLEANMARKER
            | JFFS2_NODETYPE_PADDING
            | JFFS2_NODETYPE_SUMMARY
            | JFFS2_NODETYPE_XATTR
            | JFFS2_NODETYPE_XREF
    )
}

pub fn walk_jffs2(bytes: &[u8], max_total: u64) -> Result<Jffs2Walk> {
    let endian_kind: Jffs2Endian = detect_jffs2(bytes)
        .ok_or_else(|| Error::Jffs2("jffs2 node magic 0x1985 not found".to_owned()))?;
    let e: Endian = Endian(endian_kind);
    let mut notes: Vec<String> = Vec::new();

    let mut dirents: BTreeMap<(u32, String), Dirent> = BTreeMap::new();
    let mut inode_nodes: BTreeMap<u32, Vec<InodeNode>> = BTreeMap::new();

    let mut pos: usize = 0;
    let mut node_count: usize = 0;
    while pos + 12 <= bytes.len() {
        let magic: u16 = e.u16(bytes, pos);
        if magic != JFFS2_MAGIC {
            if magic == 0xFFFF || magic == 0x0000 {
                pos += 4;
                continue;
            }
            pos += 4;
            continue;
        }
        node_count += 1;
        if node_count > MAX_NODES {
            notes.push("jffs2 node scan truncated at node cap".to_owned());
            break;
        }
        let nodetype: u16 = e.u16(bytes, pos + 2);
        let totlen: u32 = e.u32(bytes, pos + 4);
        if totlen < 12 || pos + totlen as usize > bytes.len() {
            pos += 4;
            continue;
        }
        let node: &[u8] = &bytes[pos..pos + totlen as usize];
        match nodetype {
            JFFS2_NODETYPE_DIRENT => {
                if let Some(d) = parse_dirent(e, node) {
                    let key: (u32, String) = (d.pino, d.name.clone());
                    let replace: bool = dirents
                        .get(&key)
                        .is_none_or(|existing| d.version >= existing.version);
                    if replace {
                        dirents.insert(key, d);
                    }
                }
            }
            JFFS2_NODETYPE_INODE => {
                if let Some(n) = parse_inode(e, node) {
                    inode_nodes.entry(n.ino).or_default().push(n);
                }
            }
            _ => {}
        }
        pos += align4(totlen as usize);
    }

    let inode_modes: BTreeMap<u32, u32> = inode_nodes
        .iter()
        .filter_map(|(ino, nodes)| {
            nodes
                .iter()
                .max_by_key(|n| n.version)
                .map(|n| (*ino, n.mode))
        })
        .collect();

    let mut children: BTreeMap<u32, Vec<Dirent>> = BTreeMap::new();
    for d in dirents.values() {
        if d.ino == 0 {
            continue;
        }
        children.entry(d.pino).or_default().push(d.clone());
    }

    let mut files: Vec<Jffs2File> = Vec::new();
    let mut total: u64 = 0;
    let mut stack: Vec<(u32, String)> = vec![(ROOT_INO, String::new())];
    let mut visited: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    while let Some((ino, prefix)) = stack.pop() {
        if !visited.insert(ino) || files.len() > MAX_FILES {
            continue;
        }
        let Some(kids) = children.get(&ino) else {
            continue;
        };
        for d in kids {
            let child_path: String = if prefix.is_empty() {
                d.name.clone()
            } else {
                format!("{prefix}/{}", d.name)
            };
            let mode: u32 = inode_modes
                .get(&d.ino)
                .copied()
                .map_or(0, |value: u32| value);
            let kind: u32 = mode & S_IFMT;
            if d.dtype == DT_DIR || kind == S_IFDIR {
                stack.push((d.ino, child_path));
            } else if d.dtype == DT_LNK || kind == S_IFLNK {
                if let Some(nodes) = inode_nodes.get(&d.ino) {
                    let data: Vec<u8> = assemble_inode(nodes, &mut notes, &child_path);
                    files.push(Jffs2File {
                        path: child_path,
                        data,
                        is_executable: false,
                        is_symlink: true,
                    });
                }
            } else if (kind == 0 || kind == S_IFREG)
                && let Some(nodes) = inode_nodes.get(&d.ino)
            {
                let data: Vec<u8> = assemble_inode(nodes, &mut notes, &child_path);
                total = total.saturating_add(data.len() as u64);
                if total > max_total {
                    return Err(Error::Jffs2(format!("walk exceeds total cap {max_total}")));
                }
                files.push(Jffs2File {
                    path: child_path,
                    data,
                    is_executable: mode & 0o111 != 0,
                    is_symlink: false,
                });
            }
        }
    }

    Ok(Jffs2Walk {
        endian: endian_kind,
        files,
        notes,
    })
}

fn parse_dirent(e: Endian, node: &[u8]) -> Option<Dirent> {
    if node.len() < 40 {
        return None;
    }
    let pino: u32 = e.u32(node, 12);
    let version: u32 = e.u32(node, 16);
    let ino: u32 = e.u32(node, 20);
    let nsize: usize = node[28] as usize;
    let dtype: u8 = node[29];
    let name_start: usize = 40;
    let name_raw: &[u8] = node.get(name_start..name_start + nsize)?;
    let name: String = String::from_utf8_lossy(name_raw).into_owned();
    Some(Dirent {
        pino,
        version,
        ino,
        dtype,
        name,
    })
}

fn parse_inode(e: Endian, node: &[u8]) -> Option<InodeNode> {
    if node.len() < 68 {
        return None;
    }
    let ino: u32 = e.u32(node, 12);
    let version: u32 = e.u32(node, 16);
    let mode: u32 = e.u32(node, 20);
    let isize_field: u32 = e.u32(node, 28);
    let offset: u32 = e.u32(node, 44);
    let csize: u32 = e.u32(node, 48);
    let dsize: u32 = e.u32(node, 52);
    let compr: u8 = node[56];
    let data_start: usize = 68;
    let data_raw: &[u8] = node.get(data_start..data_start + csize as usize)?;
    Some(InodeNode {
        ino,
        version,
        mode,
        isize_field,
        offset,
        dsize,
        compr,
        data: data_raw.to_vec(),
    })
}

fn assemble_inode(nodes: &[InodeNode], notes: &mut Vec<String>, path: &str) -> Vec<u8> {
    let mut sorted: Vec<&InodeNode> = nodes.iter().collect();
    sorted.sort_by_key(|n| n.version);
    let final_size: usize = sorted
        .iter()
        .max_by_key(|n| n.version)
        .map_or(0, |n| n.isize_field as usize);
    let cap: usize = crate::quota::MAX_ENTRY_PREALLOC;
    let mut out: Vec<u8> = vec![0u8; crate::quota::bounded_prealloc(final_size as u64)];
    for node in sorted {
        let decompressed: Vec<u8> = match decompress_fragment(node) {
            Ok(d) => d,
            Err(reason) => {
                notes.push(format!("jffs2 `{path}` fragment: {reason}"));
                continue;
            }
        };
        let start: usize = node.offset as usize;
        let end: usize = start.saturating_add(decompressed.len());
        if end > cap {
            notes.push(format!("jffs2 `{path}` fragment past inode cap dropped"));
            continue;
        }
        if end > out.len() {
            out.resize(end, 0);
        }
        out[start..end].copy_from_slice(&decompressed);
    }
    if final_size != 0 && out.len() > final_size {
        out.truncate(final_size);
    }
    out
}

fn decompress_fragment(node: &InodeNode) -> std::result::Result<Vec<u8>, String> {
    let dsize: usize = crate::quota::bounded_prealloc(u64::from(node.dsize));
    match node.compr {
        JFFS2_COMPR_NONE | JFFS2_COMPR_COPY => Ok(node.data[..dsize.min(node.data.len())].to_vec()),
        JFFS2_COMPR_ZERO => Ok(vec![0u8; dsize]),
        JFFS2_COMPR_RTIME => Ok(rtime_decompress(&node.data, dsize)),
        JFFS2_COMPR_ZLIB => zlib_inflate(&node.data, dsize),
        JFFS2_COMPR_LZO => lzo_decompress(&node.data, dsize),
        JFFS2_COMPR_RUBINMIPS => Ok(rubinmips_decompress(&node.data, dsize)),
        JFFS2_COMPR_DYNRUBIN => dynrubin_decompress(&node.data, dsize),
        other => Err(format!("unknown compression {other}")),
    }
}

const RUBIN_REG_SIZE: u32 = 16;
const UPPER_BIT_RUBIN: u64 = 1 << (RUBIN_REG_SIZE - 1);
const LOWER_BITS_RUBIN: u64 = UPPER_BIT_RUBIN - 1;
const BIT_DIVIDER_MIPS: u64 = 1043;
const BITS_MIPS: [u64; 8] = [277, 249, 290, 267, 229, 341, 212, 241];

struct RubinState<'a> {
    src: &'a [u8],
    ofs: usize,
    p: u64,
    q: u64,
    rec_q: u64,
    bit_divider: u64,
    bits: [u64; 8],
}

impl<'a> RubinState<'a> {
    fn new(src: &'a [u8], bit_divider: u64, bits: [u64; 8]) -> Self {
        let mut state: Self = Self {
            src,
            ofs: 0,
            p: 2 * UPPER_BIT_RUBIN,
            q: 0,
            rec_q: 0,
            bit_divider,
            bits,
        };
        for _ in 0..RUBIN_REG_SIZE {
            let bit: u64 = state.pull_bit();
            state.rec_q = state.rec_q * 2 + bit;
        }
        state
    }

    fn pull_bit(&mut self) -> u64 {
        let byte: u8 = self
            .src
            .get(self.ofs >> 3)
            .copied()
            .map_or(0, |value: u8| value);
        let bit: u64 = u64::from((byte >> (7 - (self.ofs & 7))) & 1);
        self.ofs += 1;
        bit
    }

    fn renormalize(&mut self) {
        loop {
            self.q = (self.q & LOWER_BITS_RUBIN) << 1;
            self.p <<= 1;
            let bit: u64 = self.pull_bit();
            self.rec_q = ((self.rec_q & LOWER_BITS_RUBIN) << 1) + bit;
            if self.q < UPPER_BIT_RUBIN && (self.p + self.q) > UPPER_BIT_RUBIN {
                break;
            }
        }
    }

    fn decode_bit(&mut self, a: u64, b: u64) -> u64 {
        if self.q >= UPPER_BIT_RUBIN || (self.p + self.q) <= UPPER_BIT_RUBIN {
            self.renormalize();
        }
        let mut i0: u64 = a * self.p / (a + b);
        if i0 == 0 {
            i0 = 1;
        }
        if i0 >= self.p {
            i0 = self.p - 1;
        }
        let threshold: u64 = self.q + i0;
        let symbol: u64 = u64::from(self.rec_q >= threshold);
        if symbol == 1 {
            self.q += i0;
            i0 = self.p - i0;
        }
        self.p = i0;
        symbol
    }

    fn decode_byte(&mut self) -> u8 {
        let mut result: u32 = 0;
        for i in 0..8 {
            let bit: u64 = self.decode_bit(self.bit_divider - self.bits[i], self.bits[i]);
            result |= (bit as u32) << i;
        }
        result as u8
    }
}

fn rubin_do_decompress(src: &[u8], bit_divider: u64, bits: [u64; 8], destlen: usize) -> Vec<u8> {
    if src.is_empty() {
        return vec![0u8; destlen];
    }
    let mut state: RubinState<'_> = RubinState::new(src, bit_divider, bits);
    let mut out: Vec<u8> = Vec::with_capacity(destlen);
    while out.len() < destlen {
        out.push(state.decode_byte());
    }
    out
}

fn rubinmips_decompress(src: &[u8], destlen: usize) -> Vec<u8> {
    rubin_do_decompress(src, BIT_DIVIDER_MIPS, BITS_MIPS, destlen)
}

fn dynrubin_decompress(src: &[u8], destlen: usize) -> std::result::Result<Vec<u8>, String> {
    let header: &[u8] = src
        .get(..8)
        .ok_or_else(|| "dynrubin header shorter than 8 probability bytes".to_owned())?;
    let mut bits: [u64; 8] = [0; 8];
    for (slot, &byte) in bits.iter_mut().zip(header) {
        *slot = u64::from(byte);
    }
    Ok(rubin_do_decompress(&src[8..], 256, bits, destlen))
}

fn zlib_inflate(input: &[u8], expected: usize) -> std::result::Result<Vec<u8>, String> {
    use std::io::Read as _;
    let mut decoder: flate2::read::ZlibDecoder<&[u8]> = flate2::read::ZlibDecoder::new(input);
    let mut out: Vec<u8> = Vec::with_capacity(expected);
    decoder
        .read_to_end(&mut out)
        .map_err(|e| format!("zlib inflate: {e}"))?;
    Ok(out)
}

fn lzo_decompress(input: &[u8], expected: usize) -> std::result::Result<Vec<u8>, String> {
    let mut out: Vec<u8> = vec![0u8; expected];
    lzokay::decompress::decompress(input, &mut out)
        .map_err(|e| format!("lzo: {e:?}"))
        .map(|written| {
            out.truncate(written);
            out
        })
}

fn rtime_decompress(input: &[u8], destlen: usize) -> Vec<u8> {
    let mut positions: [usize; 256] = [0usize; 256];
    let mut out: Vec<u8> = vec![0u8; destlen];
    let mut outpos: usize = 0;
    let mut ip: usize = 0;
    while outpos < destlen && ip + 1 < input.len() {
        let value: u8 = input[ip];
        out[outpos] = value;
        outpos += 1;
        let mut repeat: usize = input[ip + 1] as usize;
        ip += 2;
        let mut backoffs: usize = positions[value as usize];
        positions[value as usize] = outpos;
        while repeat > 0 && outpos < destlen {
            out[outpos] = out[backoffs];
            outpos += 1;
            backoffs += 1;
            repeat -= 1;
        }
    }
    out.truncate(outpos);
    out
}

#[cfg(test)]
pub(crate) fn hostile_named_image(name: &str, body: &[u8]) -> Option<Vec<u8>> {
    let dirent_name_length_field_is_one_byte: bool = name.len() > u8::MAX as usize;
    if name.is_empty() || dirent_name_length_field_is_one_byte {
        return None;
    }
    Some(tests::build_single_file_jffs2(name, body))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    pub(super) fn build_single_file_jffs2(name: &str, body: &[u8]) -> Vec<u8> {
        let mut builder: Jffs2Builder = Jffs2Builder::new(Jffs2Endian::Little);
        builder.dirent(ROOT_INO, 2, 1, 0, name);
        builder.inode(&InodeSpec {
            ino: 2,
            version: 1,
            mode: S_IFREG | 0o644,
            isize_field: body.len() as u32,
            offset: 0,
            dsize: body.len() as u32,
            compr: JFFS2_COMPR_NONE,
            data: body,
        });
        builder.finish()
    }

    struct Jffs2Builder {
        endian: Jffs2Endian,
        out: Vec<u8>,
    }

    fn w16(endian: Jffs2Endian, v: u16) -> [u8; 2] {
        match endian {
            Jffs2Endian::Little => v.to_le_bytes(),
            Jffs2Endian::Big => v.to_be_bytes(),
        }
    }

    fn w32(endian: Jffs2Endian, v: u32) -> [u8; 4] {
        match endian {
            Jffs2Endian::Little => v.to_le_bytes(),
            Jffs2Endian::Big => v.to_be_bytes(),
        }
    }

    impl Jffs2Builder {
        fn new(endian: Jffs2Endian) -> Self {
            Self {
                endian,
                out: Vec::new(),
            }
        }

        fn push_node(&mut self, nodetype: u16, body: &[u8]) {
            let totlen: u32 = (12 + body.len()) as u32;
            let mut node: Vec<u8> = Vec::new();
            node.extend_from_slice(&w16(self.endian, JFFS2_MAGIC));
            node.extend_from_slice(&w16(self.endian, nodetype));
            node.extend_from_slice(&w32(self.endian, totlen));
            node.extend_from_slice(&w32(self.endian, 0));
            node.extend_from_slice(body);
            while !node.len().is_multiple_of(4) {
                node.push(0xFF);
            }
            self.out.extend_from_slice(&node);
        }

        fn dirent(&mut self, pino: u32, ino: u32, version: u32, dtype: u8, name: &str) {
            let mut body: Vec<u8> = Vec::new();
            body.extend_from_slice(&w32(self.endian, pino));
            body.extend_from_slice(&w32(self.endian, version));
            body.extend_from_slice(&w32(self.endian, ino));
            body.extend_from_slice(&w32(self.endian, 0));
            body.push(name.len() as u8);
            body.push(dtype);
            body.extend_from_slice(&[0, 0]);
            body.extend_from_slice(&w32(self.endian, 0));
            body.extend_from_slice(&w32(self.endian, 0));
            body.extend_from_slice(name.as_bytes());
            self.push_node(JFFS2_NODETYPE_DIRENT, &body);
        }

        fn inode(&mut self, spec: &InodeSpec) {
            let mut body: Vec<u8> = Vec::new();
            body.extend_from_slice(&w32(self.endian, spec.ino));
            body.extend_from_slice(&w32(self.endian, spec.version));
            body.extend_from_slice(&w32(self.endian, spec.mode));
            body.extend_from_slice(&w16(self.endian, 0));
            body.extend_from_slice(&w16(self.endian, 0));
            body.extend_from_slice(&w32(self.endian, spec.isize_field));
            body.extend_from_slice(&w32(self.endian, 0));
            body.extend_from_slice(&w32(self.endian, 0));
            body.extend_from_slice(&w32(self.endian, 0));
            body.extend_from_slice(&w32(self.endian, spec.offset));
            body.extend_from_slice(&w32(self.endian, spec.data.len() as u32));
            body.extend_from_slice(&w32(self.endian, spec.dsize));
            body.push(spec.compr);
            body.push(0);
            body.extend_from_slice(&w16(self.endian, 0));
            body.extend_from_slice(&w32(self.endian, 0));
            body.extend_from_slice(&w32(self.endian, 0));
            assert_eq!(
                body.len(),
                68 - 12,
                "jffs2 inode fixed header must be 68 bytes"
            );
            body.extend_from_slice(spec.data);
            self.push_node(JFFS2_NODETYPE_INODE, &body);
        }

        fn finish(self) -> Vec<u8> {
            self.out
        }
    }

    struct InodeSpec<'a> {
        ino: u32,
        version: u32,
        mode: u32,
        isize_field: u32,
        offset: u32,
        dsize: u32,
        compr: u8,
        data: &'a [u8],
    }

    fn zlib_compress(input: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut enc: flate2::write::ZlibEncoder<Vec<u8>> =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(input).unwrap();
        enc.finish().unwrap()
    }

    fn build_image(endian: Jffs2Endian) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let body_a: Vec<u8> = b"jffs2 uncompressed file content byte exact 0123".to_vec();
        let body_b: Vec<u8> = b"jffs2 zlib compressed payload ".repeat(20);
        let mut b: Jffs2Builder = Jffs2Builder::new(endian);
        b.dirent(ROOT_INO, 2, 1, 0, "plain.txt");
        b.inode(&InodeSpec {
            ino: 2,
            version: 1,
            mode: S_IFREG | 0o644,
            isize_field: body_a.len() as u32,
            offset: 0,
            dsize: body_a.len() as u32,
            compr: JFFS2_COMPR_NONE,
            data: &body_a,
        });
        b.dirent(ROOT_INO, 3, 1, 0, "packed.bin");
        let comp_b: Vec<u8> = zlib_compress(&body_b);
        b.inode(&InodeSpec {
            ino: 3,
            version: 1,
            mode: S_IFREG | 0o755,
            isize_field: body_b.len() as u32,
            offset: 0,
            dsize: body_b.len() as u32,
            compr: JFFS2_COMPR_ZLIB,
            data: &comp_b,
        });
        b.dirent(ROOT_INO, 4, 1, DT_DIR, "sub");
        b.inode(&InodeSpec {
            ino: 4,
            version: 1,
            mode: S_IFDIR | 0o755,
            isize_field: 0,
            offset: 0,
            dsize: 0,
            compr: JFFS2_COMPR_NONE,
            data: &[],
        });
        let nested: Vec<u8> = b"nested jffs2 file".to_vec();
        b.dirent(4, 5, 1, 0, "deep.txt");
        b.inode(&InodeSpec {
            ino: 5,
            version: 1,
            mode: S_IFREG | 0o644,
            isize_field: nested.len() as u32,
            offset: 0,
            dsize: nested.len() as u32,
            compr: JFFS2_COMPR_NONE,
            data: &nested,
        });
        (b.finish(), body_a, body_b)
    }

    fn roundtrip(endian: Jffs2Endian) {
        let (image, body_a, body_b): (Vec<u8>, Vec<u8>, Vec<u8>) = build_image(endian);
        assert_eq!(detect_jffs2(&image), Some(endian));
        let walk: Jffs2Walk = walk_jffs2(&image, 64 * 1024 * 1024).expect("walk jffs2");
        let plain: &Jffs2File = walk
            .files
            .iter()
            .find(|f| f.path == "plain.txt")
            .expect("plain");
        assert_eq!(plain.data, body_a, "{endian:?} plain");
        let packed: &Jffs2File = walk
            .files
            .iter()
            .find(|f| f.path == "packed.bin")
            .expect("packed");
        assert_eq!(packed.data, body_b, "{endian:?} zlib");
        assert!(packed.is_executable);
        let deep: &Jffs2File = walk
            .files
            .iter()
            .find(|f| f.path == "sub/deep.txt")
            .expect("deep");
        assert_eq!(deep.data, b"nested jffs2 file");
    }

    #[test]
    fn roundtrip_little_endian() {
        roundtrip(Jffs2Endian::Little);
    }

    #[test]
    fn roundtrip_big_endian() {
        roundtrip(Jffs2Endian::Big);
    }

    #[test]
    fn rejects_non_jffs2() {
        assert!(detect_jffs2(&[0u8; 256]).is_none());
        assert!(detect_jffs2(&[0x55u8; 64]).is_none());
    }

    #[test]
    fn rtime_roundtrip_via_reference_compressor() {
        let original: Vec<u8> = b"aaaabbbbccccaaaabbbbcccc hello hello hello world".to_vec();
        let compressed: Vec<u8> = rtime_compress(&original);
        let restored: Vec<u8> = rtime_decompress(&compressed, original.len());
        assert_eq!(restored, original);
    }

    fn rtime_compress(data: &[u8]) -> Vec<u8> {
        let mut positions: [usize; 256] = [0usize; 256];
        let mut out: Vec<u8> = Vec::new();
        let mut pos: usize = 0;
        while pos < data.len() {
            let value: u8 = data[pos];
            out.push(value);
            pos += 1;
            let backoffs: usize = positions[value as usize];
            positions[value as usize] = pos;
            let mut repeat: usize = 0;
            while pos + repeat < data.len()
                && repeat < 255
                && data[backoffs + repeat] == data[pos + repeat]
            {
                repeat += 1;
            }
            out.push(repeat as u8);
            pos += repeat;
        }
        out
    }

    struct RubinEncoder {
        out_bits: Vec<u8>,
        ofs: usize,
        p: u64,
        q: u64,
        bit_divider: u64,
        bits: [u64; 8],
    }

    impl RubinEncoder {
        fn new(bit_divider: u64, bits: [u64; 8]) -> Self {
            Self {
                out_bits: Vec::new(),
                ofs: 0,
                p: 2 * UPPER_BIT_RUBIN,
                q: 0,
                bit_divider,
                bits,
            }
        }

        fn push_bit(&mut self, bit: u64) {
            let byte_index: usize = self.ofs >> 3;
            if byte_index >= self.out_bits.len() {
                self.out_bits.push(0);
            }
            if bit != 0 {
                self.out_bits[byte_index] |= 1 << (7 - (self.ofs & 7));
            }
            self.ofs += 1;
        }

        fn encode(&mut self, a: u64, b: u64, symbol: u64) {
            while self.q >= UPPER_BIT_RUBIN || (self.p + self.q) <= UPPER_BIT_RUBIN {
                let top: u64 = u64::from(self.q & UPPER_BIT_RUBIN != 0);
                self.push_bit(top);
                self.q = (self.q & LOWER_BITS_RUBIN) << 1;
                self.p <<= 1;
            }
            let mut i0: u64 = a * self.p / (a + b);
            if i0 == 0 {
                i0 = 1;
            }
            if i0 >= self.p {
                i0 = self.p - 1;
            }
            let i1: u64 = self.p - i0;
            if symbol == 0 {
                self.p = i0;
            } else {
                self.p = i1;
                self.q += i0;
            }
        }

        fn out_byte(&mut self, byte: u8) {
            let mut value: u8 = byte;
            for i in 0..8 {
                self.encode(
                    self.bit_divider - self.bits[i],
                    self.bits[i],
                    u64::from(value & 1),
                );
                value >>= 1;
            }
        }

        fn finish(mut self, input: &[u8]) -> Vec<u8> {
            for &byte in input {
                self.out_byte(byte);
            }
            for _ in 0..RUBIN_REG_SIZE {
                let top: u64 = u64::from(self.q & UPPER_BIT_RUBIN != 0);
                self.push_bit(top);
                self.q = (self.q & LOWER_BITS_RUBIN) << 1;
            }
            self.out_bits
        }
    }

    fn rubinmips_compress(input: &[u8]) -> Vec<u8> {
        RubinEncoder::new(BIT_DIVIDER_MIPS, BITS_MIPS).finish(input)
    }

    fn dynrubin_compress(input: &[u8]) -> Vec<u8> {
        let mut histo: [u32; 256] = [0; 256];
        for &byte in input {
            histo[byte as usize] = histo[byte as usize].wrapping_add(1) & 0xFF;
        }
        let mut bits: [u64; 8] = [0; 8];
        for (value, &count) in histo.iter().enumerate() {
            for (slot, bit) in bits.iter_mut().zip(0..8) {
                if value & (1 << bit) != 0 {
                    *slot += u64::from(count);
                }
            }
        }
        let src_len: u64 = input.len() as u64;
        let mut header: Vec<u8> = Vec::with_capacity(8);
        for slot in &mut bits {
            let mut scaled: u64 = (*slot * 256) / src_len;
            if scaled == 0 {
                scaled = 1;
            }
            if scaled > 255 {
                scaled = 255;
            }
            *slot = scaled;
            header.push(scaled as u8);
        }
        let mut out: Vec<u8> = header;
        out.extend(RubinEncoder::new(256, bits).finish(input));
        out
    }

    #[test]
    fn rubinmips_round_trips_via_reference_encoder() {
        let original: Vec<u8> =
            b"jffs2 rubinmips range-coded node payload exercises the 1043 divider ".repeat(8);
        let compressed: Vec<u8> = rubinmips_compress(&original);
        let restored: Vec<u8> = rubinmips_decompress(&compressed, original.len());
        assert_eq!(restored, original);
    }

    #[test]
    fn dynrubin_round_trips_via_reference_encoder() {
        let original: Vec<u8> = {
            let mut v: Vec<u8> = Vec::new();
            for i in 0u32..900 {
                v.push((i.wrapping_mul(37) ^ (i >> 2)) as u8);
            }
            v
        };
        let compressed: Vec<u8> = dynrubin_compress(&original);
        let restored: Vec<u8> = dynrubin_decompress(&compressed, original.len()).expect("dynrubin");
        assert_eq!(restored, original);
    }

    #[test]
    fn rubinmips_decodes_fixed_expected_vector() {
        let original: &[u8] = b"RUBINMIPS";
        let compressed: [u8; 12] = [
            0xa5, 0x49, 0x72, 0x0d, 0x2c, 0xd4, 0xb8, 0xcb, 0xa6, 0xdd, 0x10, 0x40,
        ];
        let restored: Vec<u8> = rubinmips_decompress(&compressed, original.len());
        assert_eq!(restored, original);
    }

    #[test]
    fn rubin_nodes_assemble_through_walk() {
        let plain: Vec<u8> = b"rubin inode content recovered byte exact 0123456789".repeat(4);
        let mips: Vec<u8> = rubinmips_compress(&plain);
        let dyn_body: Vec<u8> = b"dynrubin second fragment payload abcdefghij".repeat(4);
        let dynr: Vec<u8> = dynrubin_compress(&dyn_body);
        let mut b: Jffs2Builder = Jffs2Builder::new(Jffs2Endian::Little);
        b.dirent(ROOT_INO, 2, 1, 0, "mips.bin");
        b.inode(&InodeSpec {
            ino: 2,
            version: 1,
            mode: S_IFREG | 0o644,
            isize_field: plain.len() as u32,
            offset: 0,
            dsize: plain.len() as u32,
            compr: JFFS2_COMPR_RUBINMIPS,
            data: &mips,
        });
        b.dirent(ROOT_INO, 3, 1, 0, "dyn.bin");
        b.inode(&InodeSpec {
            ino: 3,
            version: 1,
            mode: S_IFREG | 0o644,
            isize_field: dyn_body.len() as u32,
            offset: 0,
            dsize: dyn_body.len() as u32,
            compr: JFFS2_COMPR_DYNRUBIN,
            data: &dynr,
        });
        let image: Vec<u8> = b.finish();
        let walk: Jffs2Walk = walk_jffs2(&image, 64 * 1024 * 1024).expect("walk");
        let mips_file: &Jffs2File = walk.files.iter().find(|f| f.path == "mips.bin").expect("m");
        assert_eq!(mips_file.data, plain);
        let dyn_file: &Jffs2File = walk.files.iter().find(|f| f.path == "dyn.bin").expect("d");
        assert_eq!(dyn_file.data, dyn_body);
    }

    #[test]
    fn walk_caps_hostile_inode_allocations() {
        let cap: usize = crate::quota::MAX_ENTRY_PREALLOC;
        let mut b: Jffs2Builder = Jffs2Builder::new(Jffs2Endian::Little);
        b.dirent(ROOT_INO, 2, 1, 0, "bigsize.bin");
        b.inode(&InodeSpec {
            ino: 2,
            version: 1,
            mode: S_IFREG | 0o644,
            isize_field: u32::MAX,
            offset: 0,
            dsize: 7,
            compr: JFFS2_COMPR_NONE,
            data: b"disrobe",
        });
        b.dirent(ROOT_INO, 3, 1, 0, "faroffset.bin");
        b.inode(&InodeSpec {
            ino: 3,
            version: 1,
            mode: S_IFREG | 0o644,
            isize_field: 64,
            offset: 0xFFFF_FFF0,
            dsize: 4,
            compr: JFFS2_COMPR_NONE,
            data: b"AAAA",
        });
        b.dirent(ROOT_INO, 4, 1, 0, "zerobomb.bin");
        b.inode(&InodeSpec {
            ino: 4,
            version: 1,
            mode: S_IFREG | 0o644,
            isize_field: 48,
            offset: 0xFFFF_FFF0,
            dsize: u32::MAX,
            compr: JFFS2_COMPR_ZERO,
            data: &[],
        });
        let image: Vec<u8> = b.finish();
        let walk: Jffs2Walk = walk_jffs2(&image, 256 * 1024 * 1024).expect("walk stays bounded");

        let big: &Jffs2File = walk
            .files
            .iter()
            .find(|f| f.path == "bigsize.bin")
            .expect("bigsize");
        assert!(big.data.len() <= cap, "huge isize preallocation is capped");
        assert_eq!(&big.data[..7], b"disrobe");

        let far: &Jffs2File = walk
            .files
            .iter()
            .find(|f| f.path == "faroffset.bin")
            .expect("faroffset");
        assert!(
            far.data.len() <= 64,
            "far-offset fragment does not force a multi-gigabyte resize"
        );

        let zero: &Jffs2File = walk
            .files
            .iter()
            .find(|f| f.path == "zerobomb.bin")
            .expect("zerobomb");
        assert!(
            zero.data.len() <= 48,
            "zero-fill fragment length is clamped"
        );
    }

    #[test]
    fn extract_to_writes_jffs2_files() {
        let (image, body_a, _): (Vec<u8>, Vec<u8>, Vec<u8>) = build_image(Jffs2Endian::Little);
        let dir: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("binfmt-jffs2-e2e")
                .expect("create scratch dir");
        let result: crate::extract::ExtractionResult =
            crate::extract::extract_to(crate::container::ContainerKind::Jffs2, &image, dir.path())
                .expect("jffs2 extract");
        assert_eq!(result.kind, crate::container::ContainerKind::Jffs2);
        assert_eq!(
            std::fs::read(dir.path().join("plain.txt")).expect("plain"),
            body_a
        );
    }
}
