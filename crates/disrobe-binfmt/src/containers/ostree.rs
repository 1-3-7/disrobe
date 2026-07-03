use std::fs;
use std::io::Read as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OstreeExternalHint {
    pub tool_binary: &'static str,
    pub install_hint: &'static str,
}

#[must_use]
pub const fn ostree_external_hint() -> OstreeExternalHint {
    OstreeExternalHint {
        tool_binary: "ostree",
        install_hint: "OSTree archives use deduplicated content-addressed object storage; the in-tree walker decodes archive-mode (.commit/.dirtree/.dirmeta/.filez) repos directly, falling back to `ostree --repo=<repo> checkout <ref> <dest>` for bare/bare-user repos",
    }
}

const OSTREE_OBJECT_NAME_LEN: usize = 64;
const SHA256_BYTES: usize = 32;
const MAX_OSTREE_DEPTH: u32 = 64;
const MAX_OSTREE_FILES: usize = 200_000;
const FILEZ_HEADER_ALIGN_PAD: usize = 4;
pub(crate) const MAX_OSTREE_OBJECT_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const MAX_OSTREE_TEXT_BYTES: u64 = 1024 * 1024;
pub(crate) const MAX_OSTREE_DIR_ENTRIES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OstreeFile {
    pub path: String,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub symlink_target: Option<String>,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OstreeRef {
    pub name: String,
    pub commit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OstreeRepoLayout {
    pub mode: String,
    pub refs: Vec<OstreeRef>,
    pub commit_count: usize,
}

/// Abstraction over a source of raw `OSTree` objects keyed by `(checksum, extension)`.
pub trait ObjectSource {
    fn read_object(&self, checksum: &str, extension: &str) -> Result<Vec<u8>>;
}

#[derive(Debug, Clone)]
pub struct DiskStore<'a> {
    root: &'a std::path::Path,
}

impl<'a> DiskStore<'a> {
    #[must_use]
    pub const fn new(root: &'a std::path::Path) -> Self {
        Self { root }
    }

    fn object_path(&self, checksum: &str, extension: &str) -> Option<std::path::PathBuf> {
        object_shard_path(self.root, checksum, extension)
    }
}

impl ObjectSource for DiskStore<'_> {
    fn read_object(&self, checksum: &str, extension: &str) -> Result<Vec<u8>> {
        let path: std::path::PathBuf = self
            .object_path(checksum, extension)
            .ok_or_else(|| ostree_err(format!("invalid object checksum `{checksum}`")))?;
        read_file_bounded(&path, MAX_OSTREE_OBJECT_BYTES).map_err(|e: Error| {
            ostree_err(format!(
                "{extension} object {checksum} ({}): {e}",
                path.display()
            ))
        })
    }
}

#[derive(Debug, Default)]
pub struct MemoryStore {
    objects: std::collections::BTreeMap<(String, String), Vec<u8>>,
}

impl MemoryStore {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            objects: std::collections::BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, checksum: String, extension: &str, bytes: Vec<u8>) {
        self.objects.insert((checksum, extension.to_owned()), bytes);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}

impl ObjectSource for MemoryStore {
    fn read_object(&self, checksum: &str, extension: &str) -> Result<Vec<u8>> {
        self.objects
            .get(&(checksum.to_owned(), extension.to_owned()))
            .cloned()
            .ok_or_else(|| ostree_err(format!("missing {extension} object {checksum} in bundle")))
    }
}

#[must_use]
pub fn object_shard_path(
    root: &std::path::Path,
    checksum: &str,
    extension: &str,
) -> Option<std::path::PathBuf> {
    if checksum.len() != OSTREE_OBJECT_NAME_LEN
        || !checksum.bytes().all(|b: u8| b.is_ascii_hexdigit())
    {
        return None;
    }
    let (prefix, rest): (&str, &str) = checksum.split_at(2);
    Some(
        root.join("objects")
            .join(prefix)
            .join(format!("{rest}.{extension}")),
    )
}

#[must_use]
pub fn detect_ostree_repo(root: &std::path::Path) -> bool {
    root.join("config").is_file() && root.join("objects").is_dir()
}

pub fn parse_repo_config(root: &std::path::Path) -> Result<OstreeRepoLayout> {
    let config: String = read_text_bounded(&root.join("config"), MAX_OSTREE_TEXT_BYTES)
        .map_err(|e: Error| ostree_err(format!("reading repo config: {e}")))?;
    let mode: String = config
        .lines()
        .map(str::trim)
        .find_map(|line: &str| line.strip_prefix("mode="))
        .map_or_else(|| "bare".to_owned(), |m: &str| m.trim().to_owned());
    let refs: Vec<OstreeRef> = collect_refs(root)?;
    let commit_count: usize = count_objects(root, "commit");
    Ok(OstreeRepoLayout {
        mode,
        refs,
        commit_count,
    })
}

fn collect_refs(root: &std::path::Path) -> Result<Vec<OstreeRef>> {
    let heads: std::path::PathBuf = root.join("refs").join("heads");
    let mut out: Vec<OstreeRef> = Vec::new();
    collect_refs_recursive(&heads, &heads, &mut out)?;
    out.sort_by(|a: &OstreeRef, b: &OstreeRef| a.name.cmp(&b.name));
    Ok(out)
}

fn collect_refs_recursive(
    base: &std::path::Path,
    dir: &std::path::Path,
    out: &mut Vec<OstreeRef>,
) -> Result<()> {
    let Ok(entries): std::io::Result<std::fs::ReadDir> = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for entry_result in entries.take(MAX_OSTREE_DIR_ENTRIES) {
        let Ok(entry): std::io::Result<std::fs::DirEntry> = entry_result else {
            continue;
        };
        let path: std::path::PathBuf = entry.path();
        if path.is_dir() {
            collect_refs_recursive(base, &path, out)?;
        } else if path.is_file() {
            let commit: String = read_text_bounded(&path, MAX_OSTREE_TEXT_BYTES)
                .map_err(|e: Error| ostree_err(format!("reading ref: {e}")))?
                .trim()
                .to_owned();
            let name: String = path.strip_prefix(base).map_or_else(
                |_e: std::path::StripPrefixError| path.to_string_lossy().into_owned(),
                |p: &std::path::Path| p.to_string_lossy().replace('\\', "/"),
            );
            if !commit.is_empty() {
                out.push(OstreeRef { name, commit });
            }
        }
    }
    Ok(())
}

fn count_objects(root: &std::path::Path, extension: &str) -> usize {
    let objects: std::path::PathBuf = root.join("objects");
    let Ok(shards): std::io::Result<std::fs::ReadDir> = std::fs::read_dir(&objects) else {
        return 0;
    };
    let suffix: String = format!(".{extension}");
    let mut count: usize = 0;
    for shard_result in shards.take(MAX_OSTREE_DIR_ENTRIES) {
        let Ok(shard): std::io::Result<std::fs::DirEntry> = shard_result else {
            continue;
        };
        let Ok(files): std::io::Result<std::fs::ReadDir> = std::fs::read_dir(shard.path()) else {
            continue;
        };
        for file_result in files.take(MAX_OSTREE_DIR_ENTRIES) {
            let Ok(file): std::io::Result<std::fs::DirEntry> = file_result else {
                continue;
            };
            if file
                .file_name()
                .to_string_lossy()
                .ends_with(suffix.as_str())
            {
                count += 1;
            }
        }
    }
    count
}

pub(crate) fn read_file_bounded(path: &std::path::Path, max_bytes: u64) -> Result<Vec<u8>> {
    let metadata: fs::Metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(ostree_err(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > max_bytes {
        return Err(ostree_err(format!(
            "{} is {} bytes; cap is {} bytes",
            path.display(),
            metadata.len(),
            max_bytes
        )));
    }
    let file: fs::File = fs::File::open(path)?;
    let mut reader: std::io::Take<fs::File> = file.take(max_bytes.saturating_add(1));
    let capacity: usize = usize::try_from(metadata.len())
        .map_err(|_e: std::num::TryFromIntError| ostree_err("file length overflows usize"))?;
    let mut bytes: Vec<u8> = Vec::with_capacity(capacity);
    reader.read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_or(true, |len: u64| len > max_bytes) {
        return Err(ostree_err(format!(
            "{} grew past {} bytes while reading",
            path.display(),
            max_bytes
        )));
    }
    Ok(bytes)
}

pub(crate) fn read_text_bounded(path: &std::path::Path, max_bytes: u64) -> Result<String> {
    let bytes: Vec<u8> = read_file_bounded(path, max_bytes)?;
    String::from_utf8(bytes)
        .map_err(|_e: std::string::FromUtf8Error| ostree_err("text file is not utf-8"))
}

pub fn extract_commit(store: &dyn ObjectSource, commit_checksum: &str) -> Result<Vec<OstreeFile>> {
    let commit_bytes: Vec<u8> = store.read_object(commit_checksum, "commit")?;
    verify_metadata_checksum(&commit_bytes, commit_checksum, "commit")?;
    let commit: OstreeCommit = parse_commit(&commit_bytes)?;
    extract_dirtree(store, &commit.root_dirtree)
}

#[must_use]
pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher: Sha256 = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn verify_metadata_checksum(bytes: &[u8], expected_hex: &str, kind: &str) -> Result<()> {
    let actual: String = bytes_to_hex(&sha256(bytes))?;
    if actual != expected_hex {
        return Err(ostree_err(format!(
            "{kind} object content sha256 {actual} does not match its name {expected_hex} (corrupt or non-canonical object)"
        )));
    }
    Ok(())
}

pub fn extract_dirtree(
    store: &dyn ObjectSource,
    dirtree_checksum: &str,
) -> Result<Vec<OstreeFile>> {
    let mut files: Vec<OstreeFile> = Vec::new();
    walk_dirtree(store, dirtree_checksum, String::new(), 0, &mut files)?;
    Ok(files)
}

fn walk_dirtree(
    store: &dyn ObjectSource,
    dirtree_checksum: &str,
    prefix: String,
    depth: u32,
    out: &mut Vec<OstreeFile>,
) -> Result<()> {
    if depth >= MAX_OSTREE_DEPTH {
        return Err(ostree_err(format!(
            "dirtree nesting exceeds {MAX_OSTREE_DEPTH}"
        )));
    }
    if out.len() >= MAX_OSTREE_FILES {
        return Err(ostree_err(format!(
            "object count exceeds {MAX_OSTREE_FILES}"
        )));
    }
    let dirtree_bytes: Vec<u8> = store.read_object(dirtree_checksum, "dirtree")?;
    verify_metadata_checksum(&dirtree_bytes, dirtree_checksum, "dirtree")?;
    let dirtree: OstreeDirtree = parse_dirtree(&dirtree_bytes)?;
    for file_entry in &dirtree.files {
        let path: String = join_path(&prefix, &file_entry.name);
        let file_obj: OstreeFile = read_filez(store, &file_entry.checksum, path)?;
        out.push(file_obj);
        if out.len() >= MAX_OSTREE_FILES {
            return Err(ostree_err(format!(
                "object count exceeds {MAX_OSTREE_FILES}"
            )));
        }
    }
    for dir_entry in &dirtree.dirs {
        let child_prefix: String = join_path(&prefix, &dir_entry.name);
        walk_dirtree(
            store,
            &dir_entry.tree_checksum,
            child_prefix,
            depth + 1,
            out,
        )?;
    }
    Ok(())
}

fn join_path(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}/{name}")
    }
}

fn read_filez(store: &dyn ObjectSource, checksum: &str, path: String) -> Result<OstreeFile> {
    let raw: Vec<u8> = store.read_object(checksum, "filez")?;
    let parsed: FilezObject = parse_filez(&raw)?;
    Ok(OstreeFile {
        path,
        uid: parsed.uid,
        gid: parsed.gid,
        mode: parsed.mode,
        symlink_target: parsed.symlink_target,
        content: parsed.content,
    })
}

#[derive(Debug)]
struct OstreeCommit {
    root_dirtree: String,
}

fn parse_commit(bytes: &[u8]) -> Result<OstreeCommit> {
    let root: GVariant = parse_gvariant_tuple(bytes, &commit_member_types())
        .map_err(|e: GVariantError| ostree_err(format!("commit gvariant: {e}")))?;
    let members: &[GVariant] = root.as_tuple()?;
    let root_dirtree_bytes: &[u8] = members
        .get(6)
        .ok_or_else(|| ostree_err("commit missing root tree checksum".to_owned()))?
        .as_byte_array()?;
    Ok(OstreeCommit {
        root_dirtree: bytes_to_hex(root_dirtree_bytes)?,
    })
}

#[derive(Debug)]
struct DirtreeFileEntry {
    name: String,
    checksum: String,
}

#[derive(Debug)]
struct DirtreeDirEntry {
    name: String,
    tree_checksum: String,
}

#[derive(Debug)]
struct OstreeDirtree {
    files: Vec<DirtreeFileEntry>,
    dirs: Vec<DirtreeDirEntry>,
}

fn parse_dirtree(bytes: &[u8]) -> Result<OstreeDirtree> {
    let root: GVariant = parse_gvariant_tuple(bytes, &dirtree_member_types())
        .map_err(|e: GVariantError| ostree_err(format!("dirtree gvariant: {e}")))?;
    let members: &[GVariant] = root.as_tuple()?;
    let files_array: &[GVariant] = members
        .first()
        .ok_or_else(|| ostree_err("dirtree missing files array".to_owned()))?
        .as_array()?;
    let dirs_array: &[GVariant] = members
        .get(1)
        .ok_or_else(|| ostree_err("dirtree missing dirs array".to_owned()))?
        .as_array()?;
    let mut files: Vec<DirtreeFileEntry> = Vec::with_capacity(files_array.len());
    for file in files_array {
        let pair: &[GVariant] = file.as_tuple()?;
        let name: String = pair
            .first()
            .ok_or_else(|| ostree_err("dirtree file entry missing name".to_owned()))?
            .as_string()?
            .to_owned();
        let checksum: &[u8] = pair
            .get(1)
            .ok_or_else(|| ostree_err("dirtree file entry missing checksum".to_owned()))?
            .as_byte_array()?;
        files.push(DirtreeFileEntry {
            name,
            checksum: bytes_to_hex(checksum)?,
        });
    }
    let mut dirs: Vec<DirtreeDirEntry> = Vec::with_capacity(dirs_array.len());
    for dir in dirs_array {
        let triple: &[GVariant] = dir.as_tuple()?;
        let name: String = triple
            .first()
            .ok_or_else(|| ostree_err("dirtree dir entry missing name".to_owned()))?
            .as_string()?
            .to_owned();
        let tree_checksum: &[u8] = triple
            .get(1)
            .ok_or_else(|| ostree_err("dirtree dir entry missing tree checksum".to_owned()))?
            .as_byte_array()?;
        dirs.push(DirtreeDirEntry {
            name,
            tree_checksum: bytes_to_hex(tree_checksum)?,
        });
    }
    Ok(OstreeDirtree { files, dirs })
}

#[derive(Debug)]
struct FilezObject {
    uid: u32,
    gid: u32,
    mode: u32,
    symlink_target: Option<String>,
    content: Vec<u8>,
}

fn parse_filez(raw: &[u8]) -> Result<FilezObject> {
    if raw.len() < 4 + FILEZ_HEADER_ALIGN_PAD {
        return Err(ostree_err(
            "filez object truncated header prefix".to_owned(),
        ));
    }
    let header_len: usize = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    let header_start: usize = 4 + FILEZ_HEADER_ALIGN_PAD;
    let header_end: usize = header_start
        .checked_add(header_len)
        .ok_or_else(|| ostree_err("filez header length overflow".to_owned()))?;
    let header_bytes: &[u8] = raw
        .get(header_start..header_end)
        .ok_or_else(|| ostree_err("filez header out of bounds".to_owned()))?;
    let header: GVariant = parse_gvariant_tuple(header_bytes, &filez_header_member_types())
        .map_err(|e: GVariantError| ostree_err(format!("filez header gvariant: {e}")))?;
    let members: &[GVariant] = header.as_tuple()?;
    let uid: u32 = read_be_u32_member(members, 1, "uid")?;
    let gid: u32 = read_be_u32_member(members, 2, "gid")?;
    let mode: u32 = read_be_u32_member(members, 3, "mode")?;
    let symlink: &str = members
        .get(5)
        .ok_or_else(|| ostree_err("filez header missing symlink field".to_owned()))?
        .as_string()?;
    let is_symlink: bool = mode & 0o170_000 == 0o120_000;
    let symlink_target: Option<String> = if is_symlink && !symlink.is_empty() {
        Some(symlink.to_owned())
    } else {
        None
    };
    let compressed: &[u8] = &raw[header_end..];
    let content: Vec<u8> = if symlink_target.is_some() {
        Vec::new()
    } else {
        inflate_raw_deflate(compressed)?
    };
    Ok(FilezObject {
        uid,
        gid,
        mode,
        symlink_target,
        content,
    })
}

fn read_be_u32_member(members: &[GVariant], index: usize, field: &str) -> Result<u32> {
    let value: u32 = members
        .get(index)
        .ok_or_else(|| ostree_err(format!("filez header missing {field}")))?
        .as_u32_raw()?;
    Ok(value.swap_bytes())
}

const MAX_FILEZ_CONTENT: u64 = 2 * 1024 * 1024 * 1024;

fn inflate_raw_deflate(input: &[u8]) -> Result<Vec<u8>> {
    let mut decoder: flate2::read::DeflateDecoder<&[u8]> = flate2::read::DeflateDecoder::new(input);
    let mut out: Vec<u8> = Vec::new();
    decoder
        .by_ref()
        .take(MAX_FILEZ_CONTENT + 1)
        .read_to_end(&mut out)
        .map_err(|e: std::io::Error| ostree_err(format!("filez raw-deflate inflate: {e}")))?;
    Ok(out)
}

fn bytes_to_hex(bytes: &[u8]) -> Result<String> {
    if bytes.len() != SHA256_BYTES {
        return Err(ostree_err(format!(
            "object checksum is {} bytes, expected {SHA256_BYTES}",
            bytes.len()
        )));
    }
    let mut s: String = String::with_capacity(SHA256_BYTES * 2);
    for byte in bytes {
        s.push(char::from_digit((byte >> 4) as u32, 16).map_or('0', |value: char| value));
        s.push(char::from_digit((byte & 0x0f) as u32, 16).map_or('0', |value: char| value));
    }
    Ok(s)
}

#[inline]
fn ostree_err(msg: impl Into<String>) -> Error {
    Error::Flatpak(msg.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GType {
    Byte,
    U32,
    U64,
    String,
    ByteArray,
    Tuple(&'static [Self]),
    Array(&'static Self),
    DictArray,
}

impl GType {
    const fn alignment(self) -> usize {
        match self {
            Self::Byte | Self::String | Self::ByteArray => 1,
            Self::U32 => 4,
            Self::U64 | Self::DictArray => 8,
            Self::Array(inner) => inner.alignment(),
            Self::Tuple(members) => {
                let mut max: usize = 1;
                let mut i: usize = 0;
                while i < members.len() {
                    let a: usize = members[i].alignment();
                    if a > max {
                        max = a;
                    }
                    i += 1;
                }
                max
            }
        }
    }

    const fn fixed_size(self) -> Option<usize> {
        match self {
            Self::Byte => Some(1),
            Self::U32 => Some(4),
            Self::U64 => Some(8),
            Self::Tuple(members) => tuple_fixed_size(members),
            _ => None,
        }
    }
}

const fn tuple_fixed_size(members: &[GType]) -> Option<usize> {
    if members.is_empty() {
        return Some(0);
    }
    let mut total: usize = 0;
    let mut max_align: usize = 1;
    let mut i: usize = 0;
    while i < members.len() {
        let size: usize = match members[i].fixed_size() {
            Some(s) => s,
            None => return None,
        };
        let align: usize = members[i].alignment();
        total = align_up(total, align);
        total += size;
        if align > max_align {
            max_align = align;
        }
        i += 1;
    }
    Some(align_up(total, max_align))
}

const fn commit_member_types() -> [GType; 8] {
    [
        GType::DictArray,
        GType::ByteArray,
        GType::Array(&GType::Tuple(&[GType::String, GType::ByteArray])),
        GType::String,
        GType::String,
        GType::U64,
        GType::ByteArray,
        GType::ByteArray,
    ]
}

const fn dirtree_member_types() -> [GType; 2] {
    [
        GType::Array(&GType::Tuple(&[GType::String, GType::ByteArray])),
        GType::Array(&GType::Tuple(&[
            GType::String,
            GType::ByteArray,
            GType::ByteArray,
        ])),
    ]
}

const fn filez_header_member_types() -> [GType; 7] {
    [
        GType::U64,
        GType::U32,
        GType::U32,
        GType::U32,
        GType::U32,
        GType::String,
        GType::Array(&GType::Tuple(&[GType::ByteArray, GType::ByteArray])),
    ]
}

#[derive(Debug, Clone)]
pub(crate) enum GVariant {
    Byte(u8),
    U32(u32),
    U64(u64),
    Str(String),
    Bytes(Vec<u8>),
    Tuple(Vec<Self>),
    Array(Vec<Self>),
    Dict(Vec<(String, Self)>),
    Skipped,
}

impl GVariant {
    pub(crate) fn as_tuple(&self) -> Result<&[Self]> {
        match self {
            Self::Tuple(members) => Ok(members),
            _ => Err(ostree_err("gvariant value is not a tuple".to_owned())),
        }
    }

    pub(crate) fn as_array(&self) -> Result<&[Self]> {
        match self {
            Self::Array(items) => Ok(items),
            _ => Err(ostree_err("gvariant value is not an array".to_owned())),
        }
    }

    pub(crate) fn as_string(&self) -> Result<&str> {
        match self {
            Self::Str(s) => Ok(s),
            _ => Err(ostree_err("gvariant value is not a string".to_owned())),
        }
    }

    pub(crate) fn as_byte_array(&self) -> Result<&[u8]> {
        match self {
            Self::Bytes(b) => Ok(b),
            _ => Err(ostree_err("gvariant value is not a byte array".to_owned())),
        }
    }

    fn as_u32_raw(&self) -> Result<u32> {
        match self {
            Self::U32(v) => Ok(*v),
            _ => Err(ostree_err("gvariant value is not a u32".to_owned())),
        }
    }

    pub(crate) fn as_u64(&self) -> Result<u64> {
        match self {
            Self::U64(v) => Ok(*v),
            _ => Err(ostree_err("gvariant value is not a u64".to_owned())),
        }
    }

    pub(crate) fn as_byte(&self) -> Result<u8> {
        match self {
            Self::Byte(v) => Ok(*v),
            _ => Err(ostree_err("gvariant value is not a byte".to_owned())),
        }
    }
}

#[derive(Debug)]
pub(crate) enum GVariantError {
    Truncated,
    OffsetOutOfRange,
    BadOffsetFraming,
    NonUtf8String,
}

impl std::fmt::Display for GVariantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg: &str = match self {
            Self::Truncated => "buffer truncated",
            Self::OffsetOutOfRange => "framing offset out of range",
            Self::BadOffsetFraming => "inconsistent framing offsets",
            Self::NonUtf8String => "non-utf8 string element",
        };
        f.write_str(msg)
    }
}

pub(crate) type GResult<T> = std::result::Result<T, GVariantError>;

fn parse_gvariant_tuple(bytes: &[u8], members: &[GType]) -> GResult<GVariant> {
    decode_tuple(bytes, members)
}

pub(crate) fn decode_gvariant(bytes: &[u8], ty: &GType) -> GResult<GVariant> {
    decode_value(ty, bytes)
}

const fn offset_size_for(total: usize) -> usize {
    if total <= 0xff {
        1
    } else if total <= 0xffff {
        2
    } else if total <= 0xffff_ffff {
        4
    } else {
        8
    }
}

fn read_offset(bytes: &[u8], at: usize, size: usize) -> GResult<usize> {
    let slice: &[u8] = bytes.get(at..at + size).ok_or(GVariantError::Truncated)?;
    let mut value: u64 = 0;
    for (i, &b) in slice.iter().enumerate() {
        value |= u64::from(b) << (8 * i);
    }
    usize::try_from(value).map_err(|_e: std::num::TryFromIntError| GVariantError::OffsetOutOfRange)
}

const fn align_up(value: usize, alignment: usize) -> usize {
    value.next_multiple_of(alignment)
}

fn decode_tuple(bytes: &[u8], members: &[GType]) -> GResult<GVariant> {
    if let Some(fixed_total) = tuple_fixed_size(members) {
        return decode_fixed_tuple(bytes, members, fixed_total);
    }
    let total: usize = bytes.len();
    let offset_size: usize = offset_size_for(total);
    let variable_members: usize = members
        .iter()
        .filter(|m: &&GType| m.fixed_size().is_none())
        .count();
    let framing_count: usize = variable_members.saturating_sub(usize::from(
        members
            .last()
            .is_some_and(|m: &GType| m.fixed_size().is_none()),
    ));
    let offsets_region: usize = framing_count
        .checked_mul(offset_size)
        .ok_or(GVariantError::BadOffsetFraming)?;
    if offsets_region > total {
        return Err(GVariantError::BadOffsetFraming);
    }
    let mut values: Vec<GVariant> = Vec::with_capacity(members.len());
    let mut cursor: usize = 0;
    let mut frame_index: usize = 0;
    for (i, member) in members.iter().enumerate() {
        let align: usize = member.alignment();
        let is_last: bool = i + 1 == members.len();
        if let Some(size) = member.fixed_size() {
            cursor = align_up(cursor, align);
            let end: usize = cursor.checked_add(size).ok_or(GVariantError::Truncated)?;
            let slice: &[u8] = bytes.get(cursor..end).ok_or(GVariantError::Truncated)?;
            values.push(decode_fixed(member, slice)?);
            cursor = end;
        } else {
            let end: usize = if is_last {
                total - offsets_region
            } else {
                let frame_pos: usize = total - (frame_index + 1) * offset_size;
                let value_end: usize = read_offset(bytes, frame_pos, offset_size)?;
                frame_index += 1;
                value_end
            };
            if end > total {
                return Err(GVariantError::OffsetOutOfRange);
            }
            let aligned_start: usize = align_up(cursor, align);
            let slice: &[u8] = if aligned_start >= end {
                &[]
            } else {
                bytes
                    .get(aligned_start..end)
                    .ok_or(GVariantError::Truncated)?
            };
            values.push(decode_value(member, slice)?);
            cursor = end;
        }
    }
    Ok(GVariant::Tuple(values))
}

fn decode_fixed_tuple(bytes: &[u8], members: &[GType], fixed_total: usize) -> GResult<GVariant> {
    if bytes.len() < fixed_total {
        return Err(GVariantError::Truncated);
    }
    let mut values: Vec<GVariant> = Vec::with_capacity(members.len());
    let mut cursor: usize = 0;
    for member in members {
        let align: usize = member.alignment();
        cursor = align_up(cursor, align);
        let size: usize = member.fixed_size().ok_or(GVariantError::BadOffsetFraming)?;
        let end: usize = cursor + size;
        let slice: &[u8] = bytes.get(cursor..end).ok_or(GVariantError::Truncated)?;
        values.push(decode_fixed(member, slice)?);
        cursor = end;
    }
    Ok(GVariant::Tuple(values))
}

fn decode_fixed(member: &GType, slice: &[u8]) -> GResult<GVariant> {
    match member {
        GType::Byte => Ok(GVariant::Byte(
            *slice.first().ok_or(GVariantError::Truncated)?,
        )),
        GType::U32 => {
            let arr: [u8; 4] = slice
                .get(..4)
                .and_then(|s: &[u8]| s.try_into().ok())
                .ok_or(GVariantError::Truncated)?;
            Ok(GVariant::U32(u32::from_le_bytes(arr)))
        }
        GType::U64 => {
            let arr: [u8; 8] = slice
                .get(..8)
                .and_then(|s: &[u8]| s.try_into().ok())
                .ok_or(GVariantError::Truncated)?;
            Ok(GVariant::U64(u64::from_le_bytes(arr)))
        }
        GType::Tuple(inner) => decode_tuple(slice, inner),
        _ => Err(GVariantError::BadOffsetFraming),
    }
}

fn decode_value(member: &GType, slice: &[u8]) -> GResult<GVariant> {
    match member {
        GType::Byte | GType::U32 | GType::U64 => decode_fixed(member, slice),
        GType::String => decode_string(slice),
        GType::ByteArray => Ok(GVariant::Bytes(slice.to_vec())),
        GType::Tuple(inner) => decode_tuple(slice, inner),
        GType::Array(inner) => decode_array(slice, inner),
        GType::DictArray => decode_dict_array(slice),
    }
}

fn decode_string(slice: &[u8]) -> GResult<GVariant> {
    let without_nul: &[u8] = slice.strip_suffix(&[0]).map_or(slice, |value: &[u8]| value);
    let s: String = std::str::from_utf8(without_nul)
        .map_err(|_e: std::str::Utf8Error| GVariantError::NonUtf8String)?
        .to_owned();
    Ok(GVariant::Str(s))
}

fn decode_array(slice: &[u8], element: &GType) -> GResult<GVariant> {
    if slice.is_empty() {
        return Ok(GVariant::Array(Vec::new()));
    }
    match element.fixed_size() {
        Some(size) => {
            if size == 0 || !slice.len().is_multiple_of(size) {
                return Err(GVariantError::BadOffsetFraming);
            }
            let mut items: Vec<GVariant> = Vec::with_capacity(slice.len() / size);
            let mut at: usize = 0;
            while at < slice.len() {
                items.push(decode_fixed(element, &slice[at..at + size])?);
                at += size;
            }
            Ok(GVariant::Array(items))
        }
        None => decode_variable_array(slice, element),
    }
}

fn decode_variable_array(slice: &[u8], element: &GType) -> GResult<GVariant> {
    let total: usize = slice.len();
    let offset_size: usize = offset_size_for(total);
    let last_offset: usize = read_offset(slice, total - offset_size, offset_size)?;
    if last_offset > total {
        return Err(GVariantError::OffsetOutOfRange);
    }
    let offsets_region: usize = total - last_offset;
    if !offsets_region.is_multiple_of(offset_size) {
        return Err(GVariantError::BadOffsetFraming);
    }
    let count: usize = offsets_region / offset_size;
    let mut items: Vec<GVariant> = Vec::with_capacity(count);
    let mut element_start: usize = 0;
    let element_align: usize = element.alignment();
    for i in 0..count {
        let frame_pos: usize = last_offset + i * offset_size;
        let element_end: usize = read_offset(slice, frame_pos, offset_size)?;
        let aligned_start: usize = align_up(element_start, element_align);
        if element_end < aligned_start || element_end > last_offset {
            return Err(GVariantError::OffsetOutOfRange);
        }
        let element_bytes: &[u8] = slice
            .get(aligned_start..element_end)
            .ok_or(GVariantError::Truncated)?;
        items.push(decode_value(element, element_bytes)?);
        element_start = element_end;
    }
    Ok(GVariant::Array(items))
}

fn decode_dict_array(slice: &[u8]) -> GResult<GVariant> {
    if slice.is_empty() {
        return Ok(GVariant::Dict(Vec::new()));
    }
    let total: usize = slice.len();
    let offset_size: usize = offset_size_for(total);
    let last_offset: usize = read_offset(slice, total - offset_size, offset_size)?;
    if last_offset > total {
        return Err(GVariantError::OffsetOutOfRange);
    }
    let offsets_region: usize = total - last_offset;
    if !offsets_region.is_multiple_of(offset_size) {
        return Err(GVariantError::BadOffsetFraming);
    }
    let count: usize = offsets_region / offset_size;
    let mut entries: Vec<(String, GVariant)> = Vec::with_capacity(count);
    let mut element_start: usize = 0;
    for i in 0..count {
        let frame_pos: usize = last_offset + i * offset_size;
        let element_end: usize = read_offset(slice, frame_pos, offset_size)?;
        let aligned_start: usize = align_up(element_start, 8);
        if element_end < aligned_start || element_end > last_offset {
            return Err(GVariantError::OffsetOutOfRange);
        }
        let entry_bytes: &[u8] = slice
            .get(aligned_start..element_end)
            .ok_or(GVariantError::Truncated)?;
        entries.push(decode_dict_entry(entry_bytes)?);
        element_start = element_end;
    }
    Ok(GVariant::Dict(entries))
}

fn decode_dict_entry(bytes: &[u8]) -> GResult<(String, GVariant)> {
    let total: usize = bytes.len();
    let offset_size: usize = offset_size_for(total);
    if offset_size > total {
        return Err(GVariantError::BadOffsetFraming);
    }
    let key_end: usize = read_offset(bytes, total - offset_size, offset_size)?;
    if key_end > total - offset_size {
        return Err(GVariantError::OffsetOutOfRange);
    }
    let key_bytes: &[u8] = bytes.get(..key_end).ok_or(GVariantError::Truncated)?;
    let key: String = match decode_string(key_bytes)? {
        GVariant::Str(s) => s,
        _ => return Err(GVariantError::NonUtf8String),
    };
    let value_start: usize = align_up(key_end, 8);
    let value_bytes: &[u8] = bytes
        .get(value_start..total - offset_size)
        .ok_or(GVariantError::Truncated)?;
    let value: GVariant = decode_variant(value_bytes)?;
    Ok((key, value))
}

fn decode_variant(bytes: &[u8]) -> GResult<GVariant> {
    let sep: usize = bytes
        .iter()
        .rposition(|&b: &u8| b == 0)
        .ok_or(GVariantError::BadOffsetFraming)?;
    let child_bytes: &[u8] = &bytes[..sep];
    let signature: &[u8] = &bytes[sep + 1..];
    match signature {
        b"s" | b"o" | b"g" => decode_string(child_bytes),
        b"ay" => Ok(GVariant::Bytes(child_bytes.to_vec())),
        b"t" => decode_fixed(&GType::U64, child_bytes),
        b"u" => decode_fixed(&GType::U32, child_bytes),
        b"y" => decode_fixed(&GType::Byte, child_bytes),
        _ => Ok(GVariant::Skipped),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn ostree_hint_present() {
        assert_eq!(ostree_external_hint().tool_binary, "ostree");
    }

    fn offset_bytes(value: usize, size: usize) -> Vec<u8> {
        value.to_le_bytes()[..size].to_vec()
    }

    fn enc_string(s: &str) -> Vec<u8> {
        let mut out: Vec<u8> = s.as_bytes().to_vec();
        out.push(0);
        out
    }

    struct Member {
        bytes: Vec<u8>,
        fixed: bool,
        align: usize,
    }

    fn member_fixed(bytes: Vec<u8>, align: usize) -> Member {
        Member {
            bytes,
            fixed: true,
            align,
        }
    }

    fn member_var(bytes: Vec<u8>, align: usize) -> Member {
        Member {
            bytes,
            fixed: false,
            align,
        }
    }

    fn pick_offset_size(body_len: usize, count: usize) -> usize {
        let mut size: usize = 1;
        loop {
            let total: usize = body_len + count * size;
            let needed: usize = offset_size_for(total);
            if needed <= size {
                return size;
            }
            size = needed;
        }
    }

    fn build_tuple(members: &[Member]) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        let mut frames: Vec<usize> = Vec::new();
        for (i, member) in members.iter().enumerate() {
            while !body.len().is_multiple_of(member.align) {
                body.push(0);
            }
            body.extend_from_slice(&member.bytes);
            let is_last: bool = i + 1 == members.len();
            if !member.fixed && !is_last {
                frames.push(body.len());
            }
        }
        if frames.is_empty() {
            return body;
        }
        let offset_size: usize = pick_offset_size(body.len(), frames.len());
        for frame in frames.iter().rev() {
            body.extend_from_slice(&offset_bytes(*frame, offset_size));
        }
        body
    }

    fn build_variable_array(elements: &[Vec<u8>], element_align: usize) -> Vec<u8> {
        if elements.is_empty() {
            return Vec::new();
        }
        let mut body: Vec<u8> = Vec::new();
        let mut ends: Vec<usize> = Vec::new();
        for element in elements {
            while !body.len().is_multiple_of(element_align) {
                body.push(0);
            }
            body.extend_from_slice(element);
            ends.push(body.len());
        }
        let offset_size: usize = pick_offset_size(body.len(), ends.len());
        for end in &ends {
            body.extend_from_slice(&offset_bytes(*end, offset_size));
        }
        body
    }

    fn build_dirtree(files: &[(&str, [u8; 32])], dirs: &[(&str, [u8; 32], [u8; 32])]) -> Vec<u8> {
        let file_entries: Vec<Vec<u8>> = files
            .iter()
            .map(|(name, csum): &(&str, [u8; 32])| {
                build_tuple(&[
                    member_var(enc_string(name), 1),
                    member_var(csum.to_vec(), 1),
                ])
            })
            .collect();
        let dir_entries: Vec<Vec<u8>> = dirs
            .iter()
            .map(|(name, tree, meta): &(&str, [u8; 32], [u8; 32])| {
                build_tuple(&[
                    member_var(enc_string(name), 1),
                    member_var(tree.to_vec(), 1),
                    member_var(meta.to_vec(), 1),
                ])
            })
            .collect();
        build_tuple(&[
            member_var(build_variable_array(&file_entries, 1), 1),
            member_var(build_variable_array(&dir_entries, 1), 1),
        ])
    }

    #[test]
    fn dirtree_round_trips_files_and_dirs() {
        let csum_a: [u8; 32] = [0xaa; 32];
        let csum_b: [u8; 32] = [0xbb; 32];
        let tree_c: [u8; 32] = [0xcc; 32];
        let meta_c: [u8; 32] = [0xdd; 32];
        let encoded: Vec<u8> = build_dirtree(
            &[("alpha.txt", csum_a), ("beta.bin", csum_b)],
            &[("subdir", tree_c, meta_c)],
        );
        let parsed: OstreeDirtree = parse_dirtree(&encoded).expect("parse dirtree");
        assert_eq!(parsed.files.len(), 2);
        assert_eq!(parsed.files[0].name, "alpha.txt");
        assert_eq!(parsed.files[0].checksum, bytes_to_hex(&csum_a).unwrap());
        assert_eq!(parsed.files[1].name, "beta.bin");
        assert_eq!(parsed.files[1].checksum, bytes_to_hex(&csum_b).unwrap());
        assert_eq!(parsed.dirs.len(), 1);
        assert_eq!(parsed.dirs[0].name, "subdir");
        assert_eq!(parsed.dirs[0].tree_checksum, bytes_to_hex(&tree_c).unwrap());
    }

    #[test]
    fn empty_dirtree_parses_to_no_entries() {
        let encoded: Vec<u8> = build_dirtree(&[], &[]);
        let parsed: OstreeDirtree = parse_dirtree(&encoded).expect("parse empty dirtree");
        assert!(parsed.files.is_empty());
        assert!(parsed.dirs.is_empty());
    }

    fn build_filez(uid: u32, gid: u32, mode: u32, content: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let header: Vec<u8> = build_filez_header(content.len() as u64, uid, gid, mode, "");
        let mut encoder: flate2::write::DeflateEncoder<Vec<u8>> =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(content).expect("deflate write");
        let compressed: Vec<u8> = encoder.finish().expect("deflate finish");
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&(header.len() as u32).to_be_bytes());
        out.extend_from_slice(&[0u8; FILEZ_HEADER_ALIGN_PAD]);
        out.extend_from_slice(&header);
        out.extend_from_slice(&compressed);
        out
    }

    fn build_filez_header(size: u64, uid: u32, gid: u32, mode: u32, symlink: &str) -> Vec<u8> {
        build_tuple(&[
            member_fixed(size.swap_bytes().to_le_bytes().to_vec(), 8),
            member_fixed(uid.swap_bytes().to_le_bytes().to_vec(), 4),
            member_fixed(gid.swap_bytes().to_le_bytes().to_vec(), 4),
            member_fixed(mode.swap_bytes().to_le_bytes().to_vec(), 4),
            member_fixed(0u32.to_le_bytes().to_vec(), 4),
            member_var(enc_string(symlink), 1),
            member_var(Vec::new(), 1),
        ])
    }

    #[test]
    fn filez_round_trips_content_and_metadata() {
        let content: &[u8] = b"the quick brown fox over the lazy ostree object 0123456789";
        let encoded: Vec<u8> = build_filez(1000, 1000, 0o100_644, content);
        let parsed: FilezObject = parse_filez(&encoded).expect("parse filez");
        assert_eq!(parsed.uid, 1000);
        assert_eq!(parsed.gid, 1000);
        assert_eq!(parsed.mode, 0o100_644);
        assert_eq!(parsed.content, content);
        assert!(parsed.symlink_target.is_none());
    }

    #[test]
    fn filez_empty_content_round_trips() {
        let encoded: Vec<u8> = build_filez(0, 0, 0o100_600, b"");
        let parsed: FilezObject = parse_filez(&encoded).expect("parse empty filez");
        assert!(parsed.content.is_empty());
        assert_eq!(parsed.mode, 0o100_600);
    }

    #[test]
    fn object_path_shards_on_first_two_hex() {
        let root: std::path::PathBuf = std::path::PathBuf::from("/repo");
        let store: DiskStore<'_> = DiskStore::new(&root);
        let checksum: String = "ab".to_owned() + &"cd".repeat(31);
        let path: std::path::PathBuf = store
            .object_path(&checksum, "filez")
            .expect("valid checksum path");
        assert!(path.ends_with(format!("ab/{}.filez", "cd".repeat(31))));
    }

    #[test]
    fn object_path_rejects_bad_checksum() {
        let root: std::path::PathBuf = std::path::PathBuf::from("/repo");
        let store: DiskStore<'_> = DiskStore::new(&root);
        assert!(store.object_path("tooshort", "filez").is_none());
        assert!(store.object_path(&"zz".repeat(32), "filez").is_none());
    }

    fn build_commit(root_dirtree: &[u8; 32], root_dirmeta: &[u8; 32]) -> Vec<u8> {
        let timestamp: u64 = 1_700_000_000;
        build_tuple(&[
            member_var(Vec::new(), 8),
            member_var(Vec::new(), 1),
            member_var(Vec::new(), 1),
            member_var(enc_string("commit subject"), 1),
            member_var(enc_string("commit body"), 1),
            member_fixed(timestamp.swap_bytes().to_le_bytes().to_vec(), 8),
            member_var(root_dirtree.to_vec(), 1),
            member_var(root_dirmeta.to_vec(), 1),
        ])
    }

    fn build_dirmeta(uid: u32, gid: u32, mode: u32) -> Vec<u8> {
        build_tuple(&[
            member_fixed(uid.swap_bytes().to_le_bytes().to_vec(), 4),
            member_fixed(gid.swap_bytes().to_le_bytes().to_vec(), 4),
            member_fixed(mode.swap_bytes().to_le_bytes().to_vec(), 4),
            member_var(Vec::new(), 1),
        ])
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        bytes_to_hex(&sha256(bytes)).unwrap()
    }

    fn write_object(root: &std::path::Path, checksum: &str, ext: &str, bytes: &[u8]) {
        let path: std::path::PathBuf =
            object_shard_path(root, checksum, ext).expect("valid checksum");
        std::fs::create_dir_all(path.parent().unwrap()).expect("mkdir");
        std::fs::write(&path, bytes).expect("write object");
    }

    #[test]
    fn bounded_file_read_rejects_over_cap() {
        let path: std::path::PathBuf = std::env::temp_dir().join(format!(
            "disrobe-ostree-bound-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::write(&path, b"abcdef").expect("write bounded file");
        let err: Error = read_file_bounded(&path, 5).expect_err("reject over cap");
        assert!(matches!(err, Error::Flatpak(_)));
        std::fs::remove_file(&path).expect("remove bounded file");
    }

    #[test]
    fn full_repo_directory_walk_recovers_files() {
        let dir: std::path::PathBuf = std::env::temp_dir().join(format!(
            "disrobe-ostree-walk-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir repo");

        let dirmeta_bytes: Vec<u8> = build_dirmeta(0, 0, 0o040_755);
        let dirmeta_csum: String = sha256_hex(&dirmeta_bytes);

        let hello_body: &[u8] = b"hello from inside an ostree archive repo";
        let hello_filez: Vec<u8> = build_filez(0, 0, 0o100_644, hello_body);
        let hello_csum: String = sha256_hex(&hello_filez);

        let nested_body: &[u8] = b"nested file content 0xC0FFEE that round-trips";
        let nested_filez: Vec<u8> = build_filez(1000, 1000, 0o100_600, nested_body);
        let nested_csum: String = sha256_hex(&nested_filez);

        let sub_dirtree: Vec<u8> =
            build_dirtree(&[("nested.txt", hex_to_array(&nested_csum))], &[]);
        let sub_dirtree_csum: String = sha256_hex(&sub_dirtree);

        let root_dirtree: Vec<u8> = build_dirtree(
            &[("hello.txt", hex_to_array(&hello_csum))],
            &[(
                "subdir",
                hex_to_array(&sub_dirtree_csum),
                hex_to_array(&dirmeta_csum),
            )],
        );
        let root_dirtree_csum: String = sha256_hex(&root_dirtree);

        let commit: Vec<u8> = build_commit(
            &hex_to_array(&root_dirtree_csum),
            &hex_to_array(&dirmeta_csum),
        );
        let commit_csum: String = sha256_hex(&commit);

        write_object(&dir, &commit_csum, "commit", &commit);
        write_object(&dir, &root_dirtree_csum, "dirtree", &root_dirtree);
        write_object(&dir, &sub_dirtree_csum, "dirtree", &sub_dirtree);
        write_object(&dir, &dirmeta_csum, "dirmeta", &dirmeta_bytes);
        write_object(&dir, &hello_csum, "filez", &hello_filez);
        write_object(&dir, &nested_csum, "filez", &nested_filez);

        let store: DiskStore<'_> = DiskStore::new(&dir);
        let files: Vec<OstreeFile> = extract_commit(&store, &commit_csum).expect("walk commit");
        assert_eq!(files.len(), 2, "two regular files");

        let hello: &OstreeFile = files
            .iter()
            .find(|f: &&OstreeFile| f.path == "hello.txt")
            .expect("hello.txt");
        assert_eq!(hello.content, hello_body);
        assert_eq!(hello.mode, 0o100_644);

        let nested: &OstreeFile = files
            .iter()
            .find(|f: &&OstreeFile| f.path == "subdir/nested.txt")
            .expect("subdir/nested.txt");
        assert_eq!(nested.content, nested_body);
        assert_eq!(nested.uid, 1000);

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn hex_to_array(hex: &str) -> [u8; 32] {
        let mut out: [u8; 32] = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex");
        }
        out
    }
}
