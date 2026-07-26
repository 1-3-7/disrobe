use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const UBI_EC_HDR_MAGIC: &[u8; 4] = b"UBI#";
const UBI_VID_HDR_MAGIC: &[u8; 4] = b"UBI!";
const UBIFS_NODE_MAGIC: u32 = 0x0610_1831;
const UBIFS_SB_NODE: i32 = 6;

const UBI_VID_STATIC: u8 = 1;
const UBI_VID_DYNAMIC: u8 = 2;
const UBI_INTERNAL_VOL_START: u32 = 0x7FFF_EFFF;

const MAX_PEBS: usize = 1_000_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbiVolume {
    pub vol_id: u32,
    pub used_ebs: u32,
    pub leb_count: usize,
    pub data_pad: u32,
    pub vol_type: u8,
}

#[derive(Debug, Clone)]
pub struct UbifsFile {
    pub path: String,
    pub data: Vec<u8>,
    pub is_executable: bool,
    pub is_symlink: bool,
}

#[derive(Debug, Clone)]
pub struct UbifsWalk {
    pub volumes: Vec<UbiVolume>,
    pub files: Vec<UbifsFile>,
    pub leb_images: BTreeMap<u32, Vec<u8>>,
    pub notes: Vec<String>,
}

fn rd_u32_be(b: &[u8], at: usize) -> Option<u32> {
    disrobe_bytes::read_u32_be_at(b, at).ok()
}

fn rd_u32_le(b: &[u8], at: usize) -> Option<u32> {
    disrobe_bytes::read_u32_le_at(b, at).ok()
}

#[must_use]
pub fn detect_ubi(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes.starts_with(UBI_EC_HDR_MAGIC)
}

#[must_use]
pub fn detect_ubifs(bytes: &[u8]) -> Option<()> {
    if bytes.len() < 8 {
        return None;
    }
    if rd_u32_le(bytes, 0) == Some(UBIFS_NODE_MAGIC) {
        return Some(());
    }
    None
}

fn detect_peb_size(bytes: &[u8]) -> Option<usize> {
    const CANDIDATES: [usize; 8] = [
        16 * 1024,
        32 * 1024,
        64 * 1024,
        128 * 1024,
        256 * 1024,
        512 * 1024,
        1024 * 1024,
        2 * 1024 * 1024,
    ];
    for size in CANDIDATES {
        if bytes.len() >= size
            && bytes.len().is_multiple_of(size)
            && bytes[size..].starts_with(UBI_EC_HDR_MAGIC)
        {
            return Some(size);
        }
    }
    CANDIDATES.into_iter().find(|&size| bytes.len() == size)
}

struct EcHeader {
    vid_hdr_offset: u32,
    data_offset: u32,
}

fn parse_ec_header(peb: &[u8]) -> Option<EcHeader> {
    if !peb.starts_with(UBI_EC_HDR_MAGIC) {
        return None;
    }
    let vid_hdr_offset: u32 = rd_u32_be(peb, 16)?;
    let data_offset: u32 = rd_u32_be(peb, 20)?;
    Some(EcHeader {
        vid_hdr_offset,
        data_offset,
    })
}

struct VidHeader {
    vol_type: u8,
    vol_id: u32,
    lnum: u32,
    data_size: u32,
    used_ebs: u32,
    data_pad: u32,
}

fn parse_vid_header(peb: &[u8], offset: usize) -> Option<VidHeader> {
    let hdr: &[u8] = peb.get(offset..offset + 64)?;
    if !hdr.starts_with(UBI_VID_HDR_MAGIC) {
        return None;
    }
    let vol_type: u8 = hdr[4];
    let vol_id: u32 = rd_u32_be(hdr, 8)?;
    let lnum: u32 = rd_u32_be(hdr, 12)?;
    let data_size: u32 = rd_u32_be(hdr, 20)?;
    let used_ebs: u32 = rd_u32_be(hdr, 24)?;
    let data_pad: u32 = rd_u32_be(hdr, 28)?;
    Some(VidHeader {
        vol_type,
        vol_id,
        lnum,
        data_size,
        used_ebs,
        data_pad,
    })
}

const UBIFS_CH_LEN: usize = 24;
const UBIFS_DATA_NODE: u8 = 1;
const UBIFS_DENT_NODE: u8 = 2;
const UBIFS_BLOCK_SIZE: usize = 4096;

const UBIFS_COMPR_NONE: u16 = 0;
const UBIFS_COMPR_LZO: u16 = 1;
const UBIFS_COMPR_ZLIB: u16 = 2;
const UBIFS_COMPR_ZSTD: u16 = 3;

struct DataNode {
    inode: u32,
    block: u32,
    size: u32,
    compr_type: u16,
    payload_offset: usize,
    payload_len: usize,
}

struct DentNode {
    target_inode: u32,
    name: String,
}

fn scan_nodes(image: &[u8], max_total: u64) -> (Vec<UbifsFile>, Vec<String>) {
    let mut data_nodes: Vec<DataNode> = Vec::new();
    let mut dent_nodes: Vec<DentNode> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut pos: usize = 0;
    while pos + UBIFS_CH_LEN <= image.len() {
        if rd_u32_le(image, pos) != Some(UBIFS_NODE_MAGIC) {
            pos += 8;
            continue;
        }
        let len: u32 = match rd_u32_le(image, pos + 16) {
            Some(l) => l,
            None => break,
        };
        let node_type: u8 = image[pos + 20];
        let node_len: usize = len as usize;
        if node_len < UBIFS_CH_LEN || pos + node_len > image.len() {
            pos += 8;
            continue;
        }
        match node_type {
            UBIFS_DATA_NODE => {
                if let Some(node) = parse_data_node(image, pos, node_len) {
                    data_nodes.push(node);
                }
            }
            UBIFS_DENT_NODE => {
                if let Some(node) = parse_dent_node(image, pos, node_len) {
                    dent_nodes.push(node);
                }
            }
            _ => {}
        }
        pos += (node_len + 7) & !7;
    }

    let mut names: BTreeMap<u32, String> = BTreeMap::new();
    for dent in &dent_nodes {
        names
            .entry(dent.target_inode)
            .or_insert_with(|| dent.name.clone());
    }

    let mut by_inode: BTreeMap<u32, BTreeMap<u32, Vec<u8>>> = BTreeMap::new();
    let mut total: u64 = 0;
    for node in &data_nodes {
        let comp: &[u8] =
            match image.get(node.payload_offset..node.payload_offset + node.payload_len) {
                Some(s) => s,
                None => continue,
            };
        let node_size: usize = (node.size as usize).min(UBIFS_BLOCK_SIZE);
        let decoded: Vec<u8> = match decompress_node(node.compr_type, comp, node_size) {
            Ok(d) => d,
            Err(e) => {
                notes.push(format!(
                    "ubifs-data inode {} block {}: {e}",
                    node.inode, node.block
                ));
                continue;
            }
        };
        total = total.saturating_add(decoded.len() as u64);
        if total > max_total {
            notes.push("ubifs: decompressed data exceeds total cap; stopping".to_owned());
            break;
        }
        by_inode
            .entry(node.inode)
            .or_default()
            .insert(node.block, decoded);
    }

    let mut files: Vec<UbifsFile> = Vec::new();
    for (inode, blocks) in &by_inode {
        let path: String = names
            .get(inode)
            .cloned()
            .unwrap_or_else(|| format!("inode_{inode}"));
        let file_cap: usize = usize::try_from(max_total).map_or(usize::MAX, |value: usize| value);
        let mut data: Vec<u8> = Vec::new();
        for (block, chunk) in blocks {
            let want_start: usize = (*block as usize).saturating_mul(UBIFS_BLOCK_SIZE);
            if want_start > file_cap {
                break;
            }
            if want_start > data.len() {
                data.resize(want_start, 0);
            }
            data.extend_from_slice(chunk);
        }
        files.push(UbifsFile {
            path,
            data,
            is_executable: false,
            is_symlink: false,
        });
    }
    if files.is_empty() && !data_nodes.is_empty() {
        notes.push(
            "ubifs: data nodes were found but none decompressed to a file payload".to_owned(),
        );
    }
    (files, notes)
}

const UBIFS_SK_LEN: usize = 16;

fn parse_data_node(image: &[u8], pos: usize, node_len: usize) -> Option<DataNode> {
    let key_off: usize = pos + UBIFS_CH_LEN;
    let inode: u32 = rd_u32_le(image, key_off)?;
    let key_lo: u32 = rd_u32_le(image, key_off + 4)?;
    let block: u32 = key_lo & 0x1FFF_FFFF;
    let after_key: usize = key_off + UBIFS_SK_LEN;
    let size: u32 = rd_u32_le(image, after_key)?;
    let compr_type: u16 =
        u16::from_le_bytes([*image.get(after_key + 4)?, *image.get(after_key + 5)?]);
    let payload_offset: usize = after_key + 8;
    let payload_len: usize = (pos + node_len).checked_sub(payload_offset)?;
    Some(DataNode {
        inode,
        block,
        size,
        compr_type,
        payload_offset,
        payload_len,
    })
}

fn parse_dent_node(image: &[u8], pos: usize, node_len: usize) -> Option<DentNode> {
    let key_off: usize = pos + UBIFS_CH_LEN;
    let after_key: usize = key_off + UBIFS_SK_LEN;
    let target_inode: u32 = rd_u32_le(image, after_key)?;
    let nlen: usize =
        u16::from_le_bytes([*image.get(after_key + 10)?, *image.get(after_key + 11)?]) as usize;
    let name_off: usize = after_key + 16;
    if nlen == 0 || name_off + nlen > pos + node_len {
        return None;
    }
    let name: String = String::from_utf8_lossy(image.get(name_off..name_off + nlen)?).into_owned();
    if name.is_empty() {
        return None;
    }
    Some(DentNode { target_inode, name })
}

fn decompress_node(compr_type: u16, comp: &[u8], size: usize) -> Result<Vec<u8>> {
    match compr_type {
        UBIFS_COMPR_NONE => Ok(comp.to_vec()),
        UBIFS_COMPR_ZLIB => {
            use std::io::Read as _;
            let decoder: flate2::read::DeflateDecoder<&[u8]> =
                flate2::read::DeflateDecoder::new(comp);
            let mut out: Vec<u8> = Vec::with_capacity(size);
            decoder
                .take(size as u64 + 1)
                .read_to_end(&mut out)
                .map_err(|e| Error::Ubifs(format!("zlib data node: {e}")))?;
            Ok(out)
        }
        UBIFS_COMPR_LZO => {
            let mut out: Vec<u8> = vec![0u8; size];
            let written: usize = lzokay::decompress::decompress(comp, &mut out)
                .map_err(|e: lzokay::Error| Error::Ubifs(format!("lzo data node: {e:?}")))?;
            out.truncate(written);
            Ok(out)
        }
        UBIFS_COMPR_ZSTD => zstd::bulk::decompress(comp, size)
            .map_err(|e| Error::Ubifs(format!("zstd data node: {e}"))),
        other => Err(Error::Ubifs(format!("unknown compression type {other}"))),
    }
}

pub fn walk_ubifs(bytes: &[u8], max_total: u64) -> Result<UbifsWalk> {
    if detect_ubi(bytes) {
        walk_ubi(bytes, max_total)
    } else if detect_ubifs(bytes).is_some() {
        let (files, mut notes): (Vec<UbifsFile>, Vec<String>) = scan_nodes(bytes, max_total);
        notes.insert(
            0,
            "bare ubifs image: per-file payloads recovered by node scan (ino/dent/data nodes) with zlib/lzo/zstd decompression; the wandering-tree index and LPT are not replayed, so deleted/obsolete node versions are not garbage-collected".to_owned(),
        );
        Ok(UbifsWalk {
            volumes: Vec::new(),
            files,
            leb_images: BTreeMap::new(),
            notes,
        })
    } else {
        Err(Error::Ubifs(
            "input is neither a UBI image (UBI#) nor a bare ubifs image (node magic 0x06101831)"
                .to_owned(),
        ))
    }
}

fn walk_ubi(bytes: &[u8], max_total: u64) -> Result<UbifsWalk> {
    let peb_size: usize = detect_peb_size(bytes)
        .ok_or_else(|| Error::Ubifs("could not infer UBI physical erase block size".to_owned()))?;
    let peb_count: usize = bytes.len() / peb_size;
    if peb_count > MAX_PEBS {
        return Err(Error::Ubifs(
            "UBI image has too many erase blocks".to_owned(),
        ));
    }

    let mut leb_data: BTreeMap<u32, BTreeMap<u32, Vec<u8>>> = BTreeMap::new();
    let mut vol_meta: BTreeMap<u32, (u8, u32, u32)> = BTreeMap::new();
    let mut notes: Vec<String> = Vec::new();

    for peb_index in 0..peb_count {
        let peb: &[u8] = &bytes[peb_index * peb_size..(peb_index + 1) * peb_size];
        let Some(ec) = parse_ec_header(peb) else {
            continue;
        };
        let Some(vid) = parse_vid_header(peb, ec.vid_hdr_offset as usize) else {
            continue;
        };
        if vid.vol_id >= UBI_INTERNAL_VOL_START {
            continue;
        }
        let data_start: usize = ec.data_offset as usize;
        let payload: &[u8] = peb
            .get(data_start..)
            .map_or(&[] as &[u8], |value: &[u8]| value);
        let leb_bytes: Vec<u8> = if vid.vol_type == UBI_VID_STATIC && vid.data_size > 0 {
            payload
                .get(..vid.data_size as usize)
                .map_or(payload, |value: &[u8]| value)
                .to_vec()
        } else {
            payload.to_vec()
        };
        leb_data
            .entry(vid.vol_id)
            .or_default()
            .insert(vid.lnum, leb_bytes);
        vol_meta
            .entry(vid.vol_id)
            .or_insert((vid.vol_type, vid.used_ebs, vid.data_pad));
    }

    if leb_data.is_empty() {
        return Err(Error::Ubifs(
            "no UBI volume erase blocks with valid VID headers were found".to_owned(),
        ));
    }

    let mut volumes: Vec<UbiVolume> = Vec::new();
    let mut leb_images: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let mut files: Vec<UbifsFile> = Vec::new();
    let mut saw_ubifs: bool = false;
    for (vol_id, lebs) in &leb_data {
        let (vol_type, used_ebs, data_pad): (u8, u32, u32) = vol_meta
            .get(vol_id)
            .copied()
            .map_or((UBI_VID_DYNAMIC, 0, 0), |value: (u8, u32, u32)| value);
        let mut image: Vec<u8> = Vec::new();
        let max_leb: u32 = lebs.keys().copied().max().map_or(0, |value: u32| value);
        let leb_payload_size: usize = lebs
            .values()
            .map(Vec::len)
            .max()
            .map_or(0, |value: usize| value);
        for lnum in 0..=max_leb {
            match lebs.get(&lnum) {
                Some(data) => image.extend_from_slice(data),
                None => image.extend(std::iter::repeat_n(0xFFu8, leb_payload_size)),
            }
        }
        if image.starts_with(&UBIFS_NODE_MAGIC.to_le_bytes())
            || image
                .windows(4)
                .any(|w| w == UBIFS_NODE_MAGIC.to_le_bytes())
        {
            saw_ubifs = true;
            let (vol_files, vol_notes): (Vec<UbifsFile>, Vec<String>) =
                scan_nodes(&image, max_total);
            for file in vol_files {
                files.push(UbifsFile {
                    path: format!("vol{vol_id}/{}", file.path),
                    ..file
                });
            }
            notes.extend(vol_notes);
        }
        volumes.push(UbiVolume {
            vol_id: *vol_id,
            used_ebs,
            leb_count: lebs.len(),
            data_pad,
            vol_type,
        });
        leb_images.insert(*vol_id, image);
    }

    if saw_ubifs {
        notes.push(
            "UBI volume layer un-nested: each volume's logical erase blocks were reassembled in LEB order (byte-exact), and per-file payloads were recovered from the inner ubifs by node scan (zlib/lzo/zstd). The per-volume LEB image is also emitted for callers that need the raw filesystem".to_owned(),
        );
    } else {
        notes.push(
            "UBI volume layer un-nested into per-volume LEB images (byte-exact); inner content is not a recognized ubifs superblock".to_owned(),
        );
    }

    Ok(UbifsWalk {
        volumes,
        files,
        leb_images,
        notes,
    })
}

const _: i32 = UBIFS_SB_NODE;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const PEB: usize = 64 * 1024;
    const VID_OFFSET: usize = 64;
    const DATA_OFFSET: usize = 128;

    struct UbiBuilder {
        peb_size: usize,
        pebs: Vec<Vec<u8>>,
    }

    impl UbiBuilder {
        fn new(peb_size: usize) -> Self {
            Self {
                peb_size,
                pebs: Vec::new(),
            }
        }

        fn add_leb(&mut self, vol_id: u32, lnum: u32, vol_type: u8, data: &[u8]) {
            let mut peb: Vec<u8> = vec![0xFFu8; self.peb_size];
            peb[0..4].copy_from_slice(UBI_EC_HDR_MAGIC);
            peb[16..20].copy_from_slice(&(VID_OFFSET as u32).to_be_bytes());
            peb[20..24].copy_from_slice(&(DATA_OFFSET as u32).to_be_bytes());

            peb[VID_OFFSET..VID_OFFSET + 4].copy_from_slice(UBI_VID_HDR_MAGIC);
            peb[VID_OFFSET + 4] = vol_type;
            peb[VID_OFFSET + 8..VID_OFFSET + 12].copy_from_slice(&vol_id.to_be_bytes());
            peb[VID_OFFSET + 12..VID_OFFSET + 16].copy_from_slice(&lnum.to_be_bytes());
            if vol_type == UBI_VID_STATIC {
                peb[VID_OFFSET + 20..VID_OFFSET + 24]
                    .copy_from_slice(&(data.len() as u32).to_be_bytes());
            }
            peb[DATA_OFFSET..DATA_OFFSET + data.len()].copy_from_slice(data);
            self.pebs.push(peb);
        }

        fn finish(self) -> Vec<u8> {
            self.pebs.concat()
        }
    }

    #[test]
    fn detects_ubi_magic() {
        let mut img: Vec<u8> = vec![0u8; PEB * 2];
        img[0..4].copy_from_slice(UBI_EC_HDR_MAGIC);
        img[PEB..PEB + 4].copy_from_slice(UBI_EC_HDR_MAGIC);
        assert!(detect_ubi(&img));
        assert_eq!(detect_peb_size(&img), Some(PEB));
    }

    #[test]
    fn rejects_non_ubi() {
        assert!(!detect_ubi(&[0u8; 64]));
        assert!(detect_ubifs(&[0u8; 64]).is_none());
    }

    #[test]
    fn un_nests_ubi_volume_leb_order_byte_exact() {
        let leb0: Vec<u8> = {
            let mut v: Vec<u8> = UBIFS_NODE_MAGIC.to_le_bytes().to_vec();
            v.extend_from_slice(b" ubifs superblock leb zero payload");
            v
        };
        let leb1: Vec<u8> = b"second logical erase block content here".to_vec();
        let mut b: UbiBuilder = UbiBuilder::new(PEB);
        b.add_leb(0, 1, UBI_VID_DYNAMIC, &leb1);
        b.add_leb(0, 0, UBI_VID_DYNAMIC, &leb0);
        let img: Vec<u8> = b.finish();

        let leb_payload: usize = PEB - DATA_OFFSET;
        let walk: UbifsWalk = walk_ubifs(&img, 64 * 1024 * 1024).expect("walk ubi");
        assert_eq!(walk.volumes.len(), 1);
        assert_eq!(walk.volumes[0].vol_id, 0);
        let image: &Vec<u8> = walk.leb_images.get(&0).expect("leb image");
        assert!(image.starts_with(&UBIFS_NODE_MAGIC.to_le_bytes()));
        assert_eq!(&image[..leb0.len()], leb0.as_slice(), "leb 0 head bytes");
        assert_eq!(
            &image[leb_payload..leb_payload + leb1.len()],
            leb1.as_slice(),
            "leb 1 starts at fixed leb-payload boundary"
        );
        assert!(walk.notes.iter().any(|n| n.contains("un-nested")));
    }

    #[test]
    fn static_volume_truncates_to_data_size() {
        let payload: Vec<u8> = b"exact static volume bytes".to_vec();
        let mut b: UbiBuilder = UbiBuilder::new(PEB);
        b.add_leb(0, 0, UBI_VID_STATIC, &payload);
        let img: Vec<u8> = b.finish();
        let walk: UbifsWalk = walk_ubifs(&img, 1024 * 1024).expect("walk");
        let image: &Vec<u8> = walk.leb_images.get(&0).expect("img");
        assert_eq!(image.as_slice(), payload.as_slice());
    }

    #[test]
    fn extract_to_writes_ubi_leb_image() {
        let leb0: Vec<u8> = {
            let mut v: Vec<u8> = UBIFS_NODE_MAGIC.to_le_bytes().to_vec();
            v.extend_from_slice(b" payload");
            v
        };
        let mut b: UbiBuilder = UbiBuilder::new(PEB);
        b.add_leb(0, 0, UBI_VID_DYNAMIC, &leb0);
        let img: Vec<u8> = b.finish();
        let dir: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("binfmt-ubifs-e2e")
                .expect("create scratch dir");
        let result: crate::extract::ExtractionResult =
            crate::extract::extract_to(crate::container::ContainerKind::Ubifs, &img, dir.path())
                .expect("ubi extract");
        assert_eq!(result.kind, crate::container::ContainerKind::Ubifs);
    }

    fn ch(node_type: u8, body_len: usize) -> Vec<u8> {
        let mut header: Vec<u8> = Vec::new();
        header.extend_from_slice(&UBIFS_NODE_MAGIC.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&0u64.to_le_bytes());
        header.extend_from_slice(&((UBIFS_CH_LEN + body_len) as u32).to_le_bytes());
        header.push(node_type);
        header.push(0);
        header.extend_from_slice(&[0u8; 2]);
        header
    }

    const UBIFS_INO_NODE: u8 = 0;

    fn ino_node(inode: u32) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&inode.to_le_bytes());
        body.extend(std::iter::repeat_n(0u8, 12));
        body.extend(std::iter::repeat_n(0u8, 100));
        let mut out: Vec<u8> = ch(UBIFS_INO_NODE, body.len());
        out.extend_from_slice(&body);
        out
    }

    fn dent_node(parent: u32, target: u32, name: &str) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&parent.to_le_bytes());
        body.extend(std::iter::repeat_n(0u8, 12));
        body.extend_from_slice(&u64::from(target).to_le_bytes());
        body.push(0);
        body.push(1);
        body.extend_from_slice(&(name.len() as u16).to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(name.as_bytes());
        let mut out: Vec<u8> = ch(UBIFS_DENT_NODE, body.len());
        out.extend_from_slice(&body);
        out
    }

    fn data_node(inode: u32, block: u32, compr: u16, raw: &[u8], comp: &[u8]) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&inode.to_le_bytes());
        body.extend_from_slice(&block.to_le_bytes());
        body.extend(std::iter::repeat_n(0u8, 8));
        body.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        body.extend_from_slice(&compr.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(comp);
        let mut out: Vec<u8> = ch(UBIFS_DATA_NODE, body.len());
        out.extend_from_slice(&body);
        out
    }

    fn deflate_raw(input: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut encoder: flate2::write::DeflateEncoder<Vec<u8>> =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(input).expect("deflate write");
        encoder.finish().expect("deflate finish")
    }

    fn align8(buf: &mut Vec<u8>) {
        while !buf.len().is_multiple_of(8) {
            buf.push(0xFF);
        }
    }

    #[test]
    fn bare_ubifs_node_scan_recovers_zlib_and_stored_files() {
        let stored_payload: &[u8] = b"ubifs stored data node payload bytes, uncompressed";
        let zlib_payload: Vec<u8> = b"ubifs zlib data node payload repeated. "
            .iter()
            .copied()
            .cycle()
            .take(300)
            .collect();
        let zlib_comp: Vec<u8> = deflate_raw(&zlib_payload);

        let mut img: Vec<u8> = Vec::new();
        img.extend_from_slice(&ino_node(2));
        align8(&mut img);
        img.extend_from_slice(&ino_node(3));
        align8(&mut img);
        img.extend_from_slice(&dent_node(1, 2, "stored.bin"));
        align8(&mut img);
        img.extend_from_slice(&dent_node(1, 3, "compressed.bin"));
        align8(&mut img);
        img.extend_from_slice(&data_node(
            2,
            0,
            UBIFS_COMPR_NONE,
            stored_payload,
            stored_payload,
        ));
        align8(&mut img);
        img.extend_from_slice(&data_node(
            3,
            0,
            UBIFS_COMPR_ZLIB,
            &zlib_payload,
            &zlib_comp,
        ));
        align8(&mut img);

        let walk: UbifsWalk = walk_ubifs(&img, 16 * 1024 * 1024).expect("walk bare ubifs");
        let stored: &UbifsFile = walk
            .files
            .iter()
            .find(|f| f.path == "stored.bin")
            .expect("stored file");
        assert_eq!(stored.data, stored_payload, "stored data node");
        let compressed: &UbifsFile = walk
            .files
            .iter()
            .find(|f| f.path == "compressed.bin")
            .expect("compressed file");
        assert_eq!(compressed.data, zlib_payload, "zlib data node");
    }

    fn data_node_forged_size(
        inode: u32,
        block: u32,
        compr: u16,
        size: u32,
        comp: &[u8],
    ) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&inode.to_le_bytes());
        body.extend_from_slice(&block.to_le_bytes());
        body.extend(std::iter::repeat_n(0u8, 8));
        body.extend_from_slice(&size.to_le_bytes());
        body.extend_from_slice(&compr.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(comp);
        let mut out: Vec<u8> = ch(UBIFS_DATA_NODE, body.len());
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn oversized_node_size_field_does_not_overallocate() {
        let mut img: Vec<u8> = Vec::new();
        img.extend_from_slice(&ino_node(2));
        align8(&mut img);
        img.extend_from_slice(&dent_node(1, 2, "bomb.bin"));
        align8(&mut img);
        img.extend_from_slice(&data_node_forged_size(
            2,
            0,
            UBIFS_COMPR_NONE,
            u32::MAX,
            b"abc",
        ));
        align8(&mut img);

        let walk: UbifsWalk = walk_ubifs(&img, 16 * 1024 * 1024).expect("walk forged ubifs");
        for file in &walk.files {
            assert!(
                file.data.len() <= UBIFS_BLOCK_SIZE,
                "decoded node exceeded one logical block"
            );
        }
    }

    #[test]
    fn oversized_block_index_does_not_overallocate() {
        let payload: &[u8] = b"sparse-block payload";
        let mut img: Vec<u8> = Vec::new();
        img.extend_from_slice(&ino_node(2));
        align8(&mut img);
        img.extend_from_slice(&dent_node(1, 2, "sparse.bin"));
        align8(&mut img);
        img.extend_from_slice(&data_node(
            2,
            0x1FFF_FFFF,
            UBIFS_COMPR_NONE,
            payload,
            payload,
        ));
        align8(&mut img);

        let walk: UbifsWalk = walk_ubifs(&img, 64 * 1024).expect("walk sparse ubifs");
        for file in &walk.files {
            assert!(
                file.data.len() <= 64 * 1024,
                "sparse block reconstruction exceeded the total cap"
            );
        }
    }
}
