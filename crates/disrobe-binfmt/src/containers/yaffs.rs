use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const YAFFS_OBJECT_TYPE_FILE: u32 = 1;
const YAFFS_OBJECT_TYPE_SYMLINK: u32 = 2;
const YAFFS_OBJECT_TYPE_DIRECTORY: u32 = 3;
const YAFFS_OBJECT_TYPE_HARDLINK: u32 = 4;
const YAFFS_OBJECT_TYPE_SPECIAL: u32 = 5;

const YAFFS_OBJECTID_ROOT: u32 = 1;
const YAFFS_MAX_NAME_LENGTH: usize = 255;
const MAX_FILES: usize = 500_000;

const SPARE_SIZE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Yaffs2Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Geometry {
    chunk_size: usize,
    spare_size: usize,
    endian: Yaffs2Endian,
}

#[derive(Debug, Clone)]
pub struct Yaffs2File {
    pub path: String,
    pub data: Vec<u8>,
    pub is_executable: bool,
    pub is_symlink: bool,
}

#[derive(Debug, Clone)]
pub struct Yaffs2Walk {
    pub endian: Yaffs2Endian,
    pub chunk_size: usize,
    pub files: Vec<Yaffs2File>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
struct ObjectHeader {
    object_type: u32,
    parent_object_id: u32,
    name: String,
    file_size: u64,
    mode: u32,
    equiv_id: u32,
    alias: String,
}

#[derive(Debug, Clone, Copy)]
struct Tags {
    object_id: u32,
    chunk_id: u32,
    byte_count: u32,
}

struct Reader {
    endian: Yaffs2Endian,
}

impl Reader {
    fn u32(&self, b: &[u8], at: usize) -> u32 {
        let raw: [u8; 4] = [b[at], b[at + 1], b[at + 2], b[at + 3]];
        match self.endian {
            Yaffs2Endian::Little => u32::from_le_bytes(raw),
            Yaffs2Endian::Big => u32::from_be_bytes(raw),
        }
    }
}

#[must_use]
pub fn detect_yaffs2(bytes: &[u8]) -> Option<Yaffs2Endian> {
    detect_geometry(bytes).map(|g| g.endian)
}

fn detect_geometry(bytes: &[u8]) -> Option<Geometry> {
    const CHUNK_SIZES: [usize; 3] = [2048, 1024, 512];
    for chunk_size in CHUNK_SIZES {
        let total: usize = chunk_size + SPARE_SIZE;
        if bytes.len() < total {
            continue;
        }
        for endian in [Yaffs2Endian::Little, Yaffs2Endian::Big] {
            let geom: Geometry = Geometry {
                chunk_size,
                spare_size: SPARE_SIZE,
                endian,
            };
            if first_chunk_is_root_dir(bytes, geom) {
                return Some(geom);
            }
        }
    }
    None
}

fn first_chunk_is_root_dir(bytes: &[u8], geom: Geometry) -> bool {
    let reader: Reader = Reader {
        endian: geom.endian,
    };
    let Some(tags) = read_tags(&reader, bytes, geom, 0) else {
        return false;
    };
    if tags.chunk_id != 0 || tags.object_id != YAFFS_OBJECTID_ROOT {
        return false;
    }
    let header_region: &[u8] = &bytes[..geom.chunk_size];
    let object_type: u32 = reader.u32(header_region, 0);
    object_type == YAFFS_OBJECT_TYPE_DIRECTORY
}

fn read_tags(reader: &Reader, bytes: &[u8], geom: Geometry, chunk_index: usize) -> Option<Tags> {
    let chunk_start: usize = chunk_index * (geom.chunk_size + geom.spare_size);
    let spare_start: usize = chunk_start + geom.chunk_size;
    let spare: &[u8] = bytes.get(spare_start..spare_start + geom.spare_size)?;
    let seq: u32 = reader.u32(spare, 0);
    let object_id: u32 = reader.u32(spare, 4);
    let chunk_id: u32 = reader.u32(spare, 8);
    let byte_count: u32 = reader.u32(spare, 12);
    let _ = seq;
    Some(Tags {
        object_id,
        chunk_id: chunk_id & 0x3FFF_FFFF,
        byte_count,
    })
}

fn read_object_header(reader: &Reader, region: &[u8]) -> ObjectHeader {
    let object_type: u32 = reader.u32(region, 0);
    let parent_object_id: u32 = reader.u32(region, 4);
    let name_start: usize = 10;
    let name: String = read_c_string(&region[name_start..], YAFFS_MAX_NAME_LENGTH);
    let mode: u32 = reader.u32(region, 0x10c);
    let file_size_low: u32 = reader.u32(region, 0x118);
    let equiv_id: u32 = reader.u32(region, 0x11c);
    let alias_start: usize = 0x120;
    let alias: String = read_c_string(&region[alias_start..], YAFFS_MAX_NAME_LENGTH);
    let file_size_high: u32 = reader.u32(region, 0x164);
    let file_size: u64 = u64::from(file_size_low) | (u64::from(file_size_high) << 32);
    ObjectHeader {
        object_type,
        parent_object_id,
        name,
        file_size,
        mode,
        equiv_id,
        alias,
    }
}

fn read_c_string(region: &[u8], max: usize) -> String {
    let end: usize = region
        .iter()
        .take(max)
        .position(|&b| b == 0)
        .unwrap_or_else(|| region.len().min(max));
    String::from_utf8_lossy(&region[..end]).into_owned()
}

pub fn walk_yaffs2(bytes: &[u8], max_total: u64) -> Result<Yaffs2Walk> {
    let geom: Geometry = detect_geometry(bytes).ok_or_else(|| {
        Error::Yaffs("no yaffs2 root-directory object header at chunk 0".to_owned())
    })?;
    let reader: Reader = Reader {
        endian: geom.endian,
    };
    let total_chunk: usize = geom.chunk_size + geom.spare_size;
    let chunk_count: usize = bytes.len() / total_chunk;

    let mut headers: BTreeMap<u32, ObjectHeader> = BTreeMap::new();
    let mut file_chunks: BTreeMap<u32, BTreeMap<u32, (usize, usize)>> = BTreeMap::new();
    let mut notes: Vec<String> = Vec::new();

    for chunk_index in 0..chunk_count {
        if chunk_index > MAX_FILES * 4 {
            notes.push("yaffs2 chunk scan truncated at cap".to_owned());
            break;
        }
        let Some(tags) = read_tags(&reader, bytes, geom, chunk_index) else {
            continue;
        };
        if tags.object_id == 0 || tags.object_id == 0xFFFF_FFFF {
            continue;
        }
        let chunk_start: usize = chunk_index * total_chunk;
        if tags.chunk_id == 0 {
            let region: &[u8] = &bytes[chunk_start..chunk_start + geom.chunk_size];
            let header: ObjectHeader = read_object_header(&reader, region);
            headers.insert(tags.object_id, header);
        } else {
            let data_index: u32 = tags.chunk_id - 1;
            file_chunks
                .entry(tags.object_id)
                .or_default()
                .insert(data_index, (chunk_start, tags.byte_count as usize));
        }
    }

    let names: BTreeMap<u32, (String, u32)> = headers
        .iter()
        .map(|(id, h)| (*id, (h.name.clone(), h.parent_object_id)))
        .collect();

    let mut files: Vec<Yaffs2File> = Vec::new();
    let mut total: u64 = 0;
    for (object_id, header) in &headers {
        if *object_id == YAFFS_OBJECTID_ROOT {
            continue;
        }
        let Some(path) = resolve_path(*object_id, &names) else {
            notes.push(format!("yaffs2 object {object_id} has no resolvable path"));
            continue;
        };
        match header.object_type {
            YAFFS_OBJECT_TYPE_FILE => {
                let data: Vec<u8> =
                    assemble_file(bytes, geom, &file_chunks, *object_id, header.file_size);
                total = total.saturating_add(data.len() as u64);
                if total > max_total {
                    return Err(Error::Yaffs(format!("walk exceeds total cap {max_total}")));
                }
                files.push(Yaffs2File {
                    path,
                    is_executable: header.mode & 0o111 != 0,
                    data,
                    is_symlink: false,
                });
            }
            YAFFS_OBJECT_TYPE_SYMLINK => files.push(Yaffs2File {
                path,
                data: header.alias.clone().into_bytes(),
                is_executable: false,
                is_symlink: true,
            }),
            YAFFS_OBJECT_TYPE_HARDLINK => {
                if let Some(target) = headers.get(&header.equiv_id)
                    && target.object_type == YAFFS_OBJECT_TYPE_FILE
                {
                    let data: Vec<u8> =
                        assemble_file(bytes, geom, &file_chunks, header.equiv_id, target.file_size);
                    files.push(Yaffs2File {
                        path,
                        is_executable: target.mode & 0o111 != 0,
                        data,
                        is_symlink: false,
                    });
                }
            }
            YAFFS_OBJECT_TYPE_DIRECTORY | YAFFS_OBJECT_TYPE_SPECIAL => {}
            other => notes.push(format!("yaffs2 object {object_id} unknown type {other}")),
        }
    }

    Ok(Yaffs2Walk {
        endian: geom.endian,
        chunk_size: geom.chunk_size,
        files,
        notes,
    })
}

fn resolve_path(object_id: u32, names: &BTreeMap<u32, (String, u32)>) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut current: u32 = object_id;
    let mut guard: usize = 0;
    while current != YAFFS_OBJECTID_ROOT && guard < 256 {
        let (name, parent): &(String, u32) = names.get(&current)?;
        if name.is_empty() {
            return None;
        }
        parts.push(name.clone());
        current = *parent;
        guard += 1;
    }
    if current != YAFFS_OBJECTID_ROOT {
        return None;
    }
    parts.reverse();
    Some(parts.join("/"))
}

fn assemble_file(
    bytes: &[u8],
    geom: Geometry,
    file_chunks: &BTreeMap<u32, BTreeMap<u32, (usize, usize)>>,
    object_id: u32,
    file_size: u64,
) -> Vec<u8> {
    let Some(chunks) = file_chunks.get(&object_id) else {
        return Vec::new();
    };
    let capacity_hint: usize = file_size.min(bytes.len() as u64) as usize;
    let mut out: Vec<u8> = Vec::with_capacity(capacity_hint);
    for (chunk_start, byte_count) in chunks.values() {
        let len: usize = (*byte_count).min(geom.chunk_size);
        if let Some(slice) = bytes.get(*chunk_start..*chunk_start + len) {
            out.extend_from_slice(slice);
        }
    }
    if file_size > 0 {
        out.truncate(file_size as usize);
    }
    out
}

#[cfg(test)]
pub(crate) fn hostile_named_image(name: &str, body: &[u8]) -> Option<Vec<u8>> {
    let object_header_name_is_a_c_string: bool = name.contains('\u{0}');
    if name.is_empty() || name.len() > YAFFS_MAX_NAME_LENGTH || object_header_name_is_a_c_string {
        return None;
    }
    Some(tests::build_single_file_yaffs2(name, body))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const CHUNK: usize = 2048;

    pub(super) fn build_single_file_yaffs2(name: &str, body: &[u8]) -> Vec<u8> {
        let mut builder: Yaffs2Builder = Yaffs2Builder::new(Yaffs2Endian::Little);
        builder.object_header(
            YAFFS_OBJECTID_ROOT,
            YAFFS_OBJECT_TYPE_DIRECTORY,
            1,
            "",
            0,
            0o755,
            "",
        );
        builder.object_header(
            2,
            YAFFS_OBJECT_TYPE_FILE,
            YAFFS_OBJECTID_ROOT,
            name,
            body.len() as u64,
            0o755,
            "",
        );
        builder.file_data(2, body);
        builder.finish()
    }

    struct Yaffs2Builder {
        endian: Yaffs2Endian,
        out: Vec<u8>,
    }

    fn w32(endian: Yaffs2Endian, v: u32) -> [u8; 4] {
        match endian {
            Yaffs2Endian::Little => v.to_le_bytes(),
            Yaffs2Endian::Big => v.to_be_bytes(),
        }
    }

    impl Yaffs2Builder {
        fn new(endian: Yaffs2Endian) -> Self {
            Self {
                endian,
                out: Vec::new(),
            }
        }

        fn push_chunk(&mut self, data: &[u8], object_id: u32, chunk_id: u32, byte_count: u32) {
            let mut chunk: Vec<u8> = vec![0u8; CHUNK];
            chunk[..data.len()].copy_from_slice(data);
            self.out.extend_from_slice(&chunk);
            let mut spare: Vec<u8> = vec![0xFFu8; SPARE_SIZE];
            spare[0..4].copy_from_slice(&w32(self.endian, 1));
            spare[4..8].copy_from_slice(&w32(self.endian, object_id));
            spare[8..12].copy_from_slice(&w32(self.endian, chunk_id));
            spare[12..16].copy_from_slice(&w32(self.endian, byte_count));
            self.out.extend_from_slice(&spare);
        }

        fn object_header(
            &mut self,
            object_id: u32,
            object_type: u32,
            parent: u32,
            name: &str,
            file_size: u64,
            mode: u32,
            alias: &str,
        ) {
            let mut region: Vec<u8> = vec![0u8; CHUNK];
            region[0..4].copy_from_slice(&w32(self.endian, object_type));
            region[4..8].copy_from_slice(&w32(self.endian, parent));
            let name_bytes: &[u8] = name.as_bytes();
            region[10..10 + name_bytes.len()].copy_from_slice(name_bytes);
            region[0x10c..0x110].copy_from_slice(&w32(self.endian, mode));
            region[0x118..0x11c].copy_from_slice(&w32(self.endian, file_size as u32));
            if !alias.is_empty() {
                let a: &[u8] = alias.as_bytes();
                region[0x120..0x120 + a.len()].copy_from_slice(a);
            }
            region[0x164..0x168].copy_from_slice(&w32(self.endian, (file_size >> 32) as u32));
            self.push_chunk(&region, object_id, 0, 0xFFFF);
        }

        fn file_data(&mut self, object_id: u32, body: &[u8]) {
            let mut chunk_id: u32 = 1;
            let mut offset: usize = 0;
            while offset < body.len() {
                let end: usize = (offset + CHUNK).min(body.len());
                let slice: &[u8] = &body[offset..end];
                self.push_chunk(slice, object_id, chunk_id, slice.len() as u32);
                chunk_id += 1;
                offset = end;
            }
        }

        fn finish(self) -> Vec<u8> {
            self.out
        }
    }

    fn build_image(endian: Yaffs2Endian) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let body_a: Vec<u8> = b"yaffs2 single chunk file byte exact 0123456789".to_vec();
        let body_b: Vec<u8> = (0..3000u32).map(|i| (i % 256) as u8).collect();
        let mut b: Yaffs2Builder = Yaffs2Builder::new(endian);
        b.object_header(
            YAFFS_OBJECTID_ROOT,
            YAFFS_OBJECT_TYPE_DIRECTORY,
            1,
            "",
            0,
            0o755,
            "",
        );
        b.object_header(
            2,
            YAFFS_OBJECT_TYPE_FILE,
            YAFFS_OBJECTID_ROOT,
            "small.txt",
            body_a.len() as u64,
            0o755,
            "",
        );
        b.file_data(2, &body_a);
        b.object_header(
            3,
            YAFFS_OBJECT_TYPE_DIRECTORY,
            YAFFS_OBJECTID_ROOT,
            "dir",
            0,
            0o755,
            "",
        );
        b.object_header(
            4,
            YAFFS_OBJECT_TYPE_FILE,
            3,
            "big.bin",
            body_b.len() as u64,
            0o644,
            "",
        );
        b.file_data(4, &body_b);
        b.object_header(
            5,
            YAFFS_OBJECT_TYPE_SYMLINK,
            YAFFS_OBJECTID_ROOT,
            "link",
            0,
            0o777,
            "small.txt",
        );
        (b.finish(), body_a, body_b)
    }

    fn roundtrip(endian: Yaffs2Endian) {
        let (image, body_a, body_b): (Vec<u8>, Vec<u8>, Vec<u8>) = build_image(endian);
        assert_eq!(detect_yaffs2(&image), Some(endian));
        let walk: Yaffs2Walk = walk_yaffs2(&image, 64 * 1024 * 1024).expect("walk yaffs2");
        let small: &Yaffs2File = walk
            .files
            .iter()
            .find(|f| f.path == "small.txt")
            .expect("small");
        assert_eq!(small.data, body_a, "{endian:?} small");
        assert!(small.is_executable);
        let big: &Yaffs2File = walk
            .files
            .iter()
            .find(|f| f.path == "dir/big.bin")
            .expect("big");
        assert_eq!(big.data, body_b, "{endian:?} multi-chunk");
        let link: &Yaffs2File = walk.files.iter().find(|f| f.path == "link").expect("link");
        assert!(link.is_symlink);
        assert_eq!(link.data, b"small.txt");
    }

    #[test]
    fn roundtrip_little_endian() {
        roundtrip(Yaffs2Endian::Little);
    }

    #[test]
    fn roundtrip_big_endian() {
        roundtrip(Yaffs2Endian::Big);
    }

    #[test]
    fn rejects_non_yaffs() {
        assert!(detect_yaffs2(&[0u8; 4096]).is_none());
        assert!(detect_yaffs2(&[0xFFu8; CHUNK + SPARE_SIZE]).is_none());
    }

    #[test]
    fn extract_to_writes_yaffs2_files() {
        let (image, body_a, _): (Vec<u8>, Vec<u8>, Vec<u8>) = build_image(Yaffs2Endian::Little);
        let dir: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("binfmt-yaffs2-e2e")
                .expect("create scratch dir");
        let result: crate::extract::ExtractionResult =
            crate::extract::extract_to(crate::container::ContainerKind::Yaffs2, &image, dir.path())
                .expect("yaffs2 extract");
        assert_eq!(result.kind, crate::container::ContainerKind::Yaffs2);
        assert_eq!(
            std::fs::read(dir.path().join("small.txt")).expect("small"),
            body_a
        );
    }
}
