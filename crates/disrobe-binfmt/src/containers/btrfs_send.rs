use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const BTRFS_SEND_MAGIC: &[u8; 13] = b"btrfs-stream\0";
const SEND_HEADER_LEN: usize = 17;
const CMD_HEADER_LEN: usize = 10;
const MAX_REPLAY_FILES: usize = 500_000;

const BTRFS_SEND_C_SUBVOL: u16 = 1;
const BTRFS_SEND_C_SNAPSHOT: u16 = 2;
const BTRFS_SEND_C_MKFILE: u16 = 3;
const BTRFS_SEND_C_MKDIR: u16 = 4;
const BTRFS_SEND_C_MKNOD: u16 = 5;
const BTRFS_SEND_C_MKFIFO: u16 = 6;
const BTRFS_SEND_C_MKSOCK: u16 = 7;
const BTRFS_SEND_C_SYMLINK: u16 = 8;
const BTRFS_SEND_C_RENAME: u16 = 9;
const BTRFS_SEND_C_LINK: u16 = 10;
const BTRFS_SEND_C_UNLINK: u16 = 11;
const BTRFS_SEND_C_RMDIR: u16 = 12;
const BTRFS_SEND_C_WRITE: u16 = 15;
const BTRFS_SEND_C_TRUNCATE: u16 = 19;
const BTRFS_SEND_C_END: u16 = 21;
const BTRFS_SEND_C_UPDATE_EXTENT: u16 = 22;
const BTRFS_SEND_C_ENCODED_WRITE: u16 = 25;

const BTRFS_SEND_A_PATH: u16 = 15;
const BTRFS_SEND_A_PATH_TO: u16 = 17;
const BTRFS_SEND_A_PATH_LINK: u16 = 18;
const BTRFS_SEND_A_FILE_OFFSET: u16 = 19;
const BTRFS_SEND_A_DATA: u16 = 20;
const BTRFS_SEND_A_SIZE: u16 = 22;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsSendHeader {
    pub version: u32,
}

#[derive(Debug, Clone)]
pub struct BtrfsSendFile {
    pub path: String,
    pub data: Vec<u8>,
    pub is_symlink: bool,
    pub symlink_target: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BtrfsSendReplay {
    pub header: BtrfsSendHeader,
    pub subvolume_name: Option<String>,
    pub files: Vec<BtrfsSendFile>,
    pub directories: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
enum Node {
    File {
        data: Vec<u8>,
        truncate: Option<u64>,
    },
    Dir,
    Symlink {
        target: String,
    },
}

fn rd_u16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn rd_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn rd_u64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        b[at],
        b[at + 1],
        b[at + 2],
        b[at + 3],
        b[at + 4],
        b[at + 5],
        b[at + 6],
        b[at + 7],
    ])
}

#[must_use]
pub fn detect_btrfs_send(bytes: &[u8]) -> Option<BtrfsSendHeader> {
    if bytes.len() < SEND_HEADER_LEN || !bytes.starts_with(BTRFS_SEND_MAGIC) {
        return None;
    }
    let version: u32 = rd_u32(bytes, 13);
    if version == 0 || version > 8 {
        return None;
    }
    Some(BtrfsSendHeader { version })
}

struct Attributes<'a> {
    map: BTreeMap<u16, &'a [u8]>,
}

impl<'a> Attributes<'a> {
    fn parse(body: &'a [u8]) -> Result<Self> {
        let mut map: BTreeMap<u16, &'a [u8]> = BTreeMap::new();
        let mut pos: usize = 0;
        while pos + 4 <= body.len() {
            let attr_type: u16 = rd_u16(body, pos);
            let attr_len: usize = rd_u16(body, pos + 2) as usize;
            pos += 4;
            let value: &[u8] = body
                .get(pos..pos + attr_len)
                .ok_or_else(|| Error::BtrfsSend("attribute value out of bounds".to_owned()))?;
            map.insert(attr_type, value);
            pos += attr_len;
        }
        Ok(Self { map })
    }

    fn string(&self, attr: u16) -> Option<String> {
        self.map
            .get(&attr)
            .map(|v| String::from_utf8_lossy(v).into_owned())
    }

    fn u64(&self, attr: u16) -> Option<u64> {
        self.map.get(&attr).and_then(|v| {
            if v.len() >= 8 {
                Some(rd_u64(v, 0))
            } else {
                None
            }
        })
    }

    fn data(&self, attr: u16) -> Option<&'a [u8]> {
        self.map.get(&attr).copied()
    }
}

pub fn replay_btrfs_send(bytes: &[u8], max_total: u64) -> Result<BtrfsSendReplay> {
    let header: BtrfsSendHeader = detect_btrfs_send(bytes)
        .ok_or_else(|| Error::BtrfsSend("btrfs-stream magic not found".to_owned()))?;
    let mut nodes: BTreeMap<String, Node> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut subvolume_name: Option<String> = None;
    let mut notes: Vec<String> = Vec::new();
    let mut total: u64 = 0;

    let mut pos: usize = SEND_HEADER_LEN;
    loop {
        if pos == bytes.len() {
            break;
        }
        let hdr: &[u8] = bytes
            .get(pos..pos + CMD_HEADER_LEN)
            .ok_or_else(|| Error::BtrfsSend(format!("command header at {pos} out of bounds")))?;
        let cmd_len: usize = rd_u32(hdr, 0) as usize;
        let cmd_type: u16 = rd_u16(hdr, 4);
        let body_start: usize = pos + CMD_HEADER_LEN;
        let body: &[u8] = bytes.get(body_start..body_start + cmd_len).ok_or_else(|| {
            Error::BtrfsSend(format!("command body for type {cmd_type} out of bounds"))
        })?;
        pos = body_start + cmd_len;

        if cmd_type == BTRFS_SEND_C_END {
            break;
        }
        if nodes.len() > MAX_REPLAY_FILES {
            notes.push("replay truncated at file cap".to_owned());
            break;
        }
        let attrs: Attributes = Attributes::parse(body)?;
        apply_command(
            cmd_type,
            &attrs,
            &mut nodes,
            &mut order,
            &mut subvolume_name,
            &mut notes,
            &mut total,
            max_total,
        )?;
    }

    let mut files: Vec<BtrfsSendFile> = Vec::new();
    let mut directories: Vec<String> = Vec::new();
    for path in &order {
        match nodes.get(path) {
            Some(Node::File { data, truncate }) => {
                let mut body: Vec<u8> = data.clone();
                if let Some(t) = truncate {
                    let t: usize = (*t as usize).min(body.len());
                    body.truncate(t);
                }
                files.push(BtrfsSendFile {
                    path: path.clone(),
                    data: body,
                    is_symlink: false,
                    symlink_target: None,
                });
            }
            Some(Node::Symlink { target }) => files.push(BtrfsSendFile {
                path: path.clone(),
                data: target.clone().into_bytes(),
                is_symlink: true,
                symlink_target: Some(target.clone()),
            }),
            Some(Node::Dir) => directories.push(path.clone()),
            None => {}
        }
    }

    Ok(BtrfsSendReplay {
        header,
        subvolume_name,
        files,
        directories,
        notes,
    })
}

#[allow(clippy::too_many_arguments)]
fn apply_command(
    cmd_type: u16,
    attrs: &Attributes,
    nodes: &mut BTreeMap<String, Node>,
    order: &mut Vec<String>,
    subvolume_name: &mut Option<String>,
    notes: &mut Vec<String>,
    total: &mut u64,
    max_total: u64,
) -> Result<()> {
    match cmd_type {
        BTRFS_SEND_C_SUBVOL | BTRFS_SEND_C_SNAPSHOT => {
            if let Some(name) = attrs.string(BTRFS_SEND_A_PATH) {
                *subvolume_name = Some(name);
            }
        }
        BTRFS_SEND_C_MKFILE | BTRFS_SEND_C_MKNOD | BTRFS_SEND_C_MKFIFO | BTRFS_SEND_C_MKSOCK => {
            if let Some(path) = attrs.string(BTRFS_SEND_A_PATH) {
                insert_node(
                    nodes,
                    order,
                    path,
                    Node::File {
                        data: Vec::new(),
                        truncate: None,
                    },
                );
            }
        }
        BTRFS_SEND_C_MKDIR => {
            if let Some(path) = attrs.string(BTRFS_SEND_A_PATH) {
                insert_node(nodes, order, path, Node::Dir);
            }
        }
        BTRFS_SEND_C_SYMLINK => {
            if let (Some(path), Some(target)) = (
                attrs.string(BTRFS_SEND_A_PATH),
                attrs.string(BTRFS_SEND_A_PATH_LINK),
            ) {
                insert_node(nodes, order, path, Node::Symlink { target });
            }
        }
        BTRFS_SEND_C_RENAME => {
            if let (Some(from), Some(to)) = (
                attrs.string(BTRFS_SEND_A_PATH),
                attrs.string(BTRFS_SEND_A_PATH_TO),
            ) {
                rename_node(nodes, order, &from, &to);
            }
        }
        BTRFS_SEND_C_LINK => {
            if let (Some(path), Some(target)) = (
                attrs.string(BTRFS_SEND_A_PATH),
                attrs.string(BTRFS_SEND_A_PATH_LINK),
            ) && let Some(Node::File { data, truncate }) = nodes.get(&target).cloned()
            {
                insert_node(nodes, order, path, Node::File { data, truncate });
            }
        }
        BTRFS_SEND_C_UNLINK | BTRFS_SEND_C_RMDIR => {
            if let Some(path) = attrs.string(BTRFS_SEND_A_PATH) {
                nodes.remove(&path);
                order.retain(|p| p != &path);
            }
        }
        BTRFS_SEND_C_WRITE => {
            apply_write(attrs, nodes, order, total, max_total)?;
        }
        BTRFS_SEND_C_TRUNCATE => {
            if let (Some(path), Some(size)) = (
                attrs.string(BTRFS_SEND_A_PATH),
                attrs.u64(BTRFS_SEND_A_SIZE),
            ) && let Some(Node::File { truncate, .. }) = nodes.get_mut(&path)
            {
                *truncate = Some(size);
            }
        }
        BTRFS_SEND_C_UPDATE_EXTENT => {
            notes.push(
                "btrfs send stream carries UPDATE_EXTENT (no-data / -no-data send); file content not present in this stream".to_owned(),
            );
        }
        BTRFS_SEND_C_ENCODED_WRITE => {
            if let Some(path) = attrs.string(BTRFS_SEND_A_PATH) {
                notes.push(format!(
                    "btrfs encoded (compressed) extent for `{path}` not replayed in-tree; re-send without --compressed-data for byte-exact content"
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

fn apply_write(
    attrs: &Attributes,
    nodes: &mut BTreeMap<String, Node>,
    order: &mut Vec<String>,
    total: &mut u64,
    max_total: u64,
) -> Result<()> {
    let Some(path) = attrs.string(BTRFS_SEND_A_PATH) else {
        return Ok(());
    };
    let offset: u64 = attrs
        .u64(BTRFS_SEND_A_FILE_OFFSET)
        .map_or(0, |value: u64| value);
    let Some(data) = attrs.data(BTRFS_SEND_A_DATA) else {
        return Ok(());
    };
    let data_len: u64 = u64::try_from(data.len())
        .map_err(|_| Error::BtrfsSend(format!("replay exceeds total cap {max_total}")))?;
    let logical_end: u64 = offset
        .checked_add(data_len)
        .ok_or_else(|| Error::BtrfsSend(format!("replay exceeds total cap {max_total}")))?;
    if !nodes.contains_key(&path) {
        insert_node(
            nodes,
            order,
            path.clone(),
            Node::File {
                data: Vec::new(),
                truncate: None,
            },
        );
    }
    if let Some(Node::File { data: buf, .. }) = nodes.get_mut(&path) {
        let old_len: u64 = u64::try_from(buf.len())
            .map_err(|_| Error::BtrfsSend(format!("replay exceeds total cap {max_total}")))?;
        let delta: u64 = logical_end.saturating_sub(old_len);
        let new_total: u64 = total
            .checked_add(delta)
            .ok_or_else(|| Error::BtrfsSend(format!("replay exceeds total cap {max_total}")))?;
        if logical_end > max_total || new_total > max_total {
            return Err(Error::BtrfsSend(format!(
                "replay exceeds total cap {max_total}"
            )));
        }
        *total = new_total;
        let start: usize = usize::try_from(offset)
            .map_err(|_| Error::BtrfsSend(format!("replay exceeds total cap {max_total}")))?;
        let end: usize = usize::try_from(logical_end)
            .map_err(|_| Error::BtrfsSend(format!("replay exceeds total cap {max_total}")))?;
        if buf.len() < end {
            buf.resize(end, 0);
        }
        buf[start..end].copy_from_slice(data);
    }
    Ok(())
}

fn insert_node(
    nodes: &mut BTreeMap<String, Node>,
    order: &mut Vec<String>,
    path: String,
    node: Node,
) {
    if !nodes.contains_key(&path) {
        order.push(path.clone());
    }
    nodes.insert(path, node);
}

fn rename_node(nodes: &mut BTreeMap<String, Node>, order: &mut [String], from: &str, to: &str) {
    if let Some(node) = nodes.remove(from) {
        if let Some(p) = order.iter_mut().find(|p| *p == from) {
            to.clone_into(p);
        }
        nodes.insert(to.to_owned(), node);
    }
}

#[cfg(test)]
pub(crate) fn hostile_named_image(name: &str, body: &[u8]) -> Option<Vec<u8>> {
    let path_attribute_length_field_is_two_bytes: bool = name.len() > u16::MAX as usize;
    if name.is_empty() || path_attribute_length_field_is_two_bytes {
        return None;
    }
    Some(tests::build_single_file_send_stream(name, body))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    pub(super) fn build_single_file_send_stream(name: &str, body: &[u8]) -> Vec<u8> {
        let mut builder: StreamBuilder = StreamBuilder::new();
        builder.command(BTRFS_SEND_C_SUBVOL, &[(BTRFS_SEND_A_PATH, b"myvol")]);
        builder.command(BTRFS_SEND_C_MKFILE, &[(BTRFS_SEND_A_PATH, name.as_bytes())]);
        builder.command(
            BTRFS_SEND_C_WRITE,
            &[
                (BTRFS_SEND_A_PATH, name.as_bytes()),
                (BTRFS_SEND_A_FILE_OFFSET, &0u64.to_le_bytes()),
                (BTRFS_SEND_A_DATA, body),
            ],
        );
        builder.finish()
    }

    struct StreamBuilder {
        out: Vec<u8>,
    }

    impl StreamBuilder {
        fn new() -> Self {
            let mut out: Vec<u8> = Vec::new();
            out.extend_from_slice(BTRFS_SEND_MAGIC);
            out.extend_from_slice(&1u32.to_le_bytes());
            Self { out }
        }

        fn command(&mut self, cmd_type: u16, attrs: &[(u16, &[u8])]) {
            let mut body: Vec<u8> = Vec::new();
            for (attr_type, value) in attrs {
                body.extend_from_slice(&attr_type.to_le_bytes());
                body.extend_from_slice(&(value.len() as u16).to_le_bytes());
                body.extend_from_slice(value);
            }
            self.out
                .extend_from_slice(&(body.len() as u32).to_le_bytes());
            self.out.extend_from_slice(&cmd_type.to_le_bytes());
            self.out.extend_from_slice(&0u32.to_le_bytes());
            self.out.extend_from_slice(&body);
        }

        fn finish(mut self) -> Vec<u8> {
            self.command(BTRFS_SEND_C_END, &[]);
            self.out
        }
    }

    fn build_reference_stream() -> Vec<u8> {
        let mut b: StreamBuilder = StreamBuilder::new();
        b.command(BTRFS_SEND_C_SUBVOL, &[(BTRFS_SEND_A_PATH, b"myvol")]);
        b.command(BTRFS_SEND_C_MKDIR, &[(BTRFS_SEND_A_PATH, b"dir")]);
        b.command(
            BTRFS_SEND_C_MKFILE,
            &[(BTRFS_SEND_A_PATH, b"dir/hello.txt")],
        );
        let body: &[u8] = b"btrfs send replay byte-exact content 01234567";
        b.command(
            BTRFS_SEND_C_WRITE,
            &[
                (BTRFS_SEND_A_PATH, b"dir/hello.txt"),
                (BTRFS_SEND_A_FILE_OFFSET, &0u64.to_le_bytes()),
                (BTRFS_SEND_A_DATA, body),
            ],
        );
        b.command(
            BTRFS_SEND_C_SYMLINK,
            &[
                (BTRFS_SEND_A_PATH, b"link"),
                (BTRFS_SEND_A_PATH_LINK, b"dir/hello.txt"),
            ],
        );
        b.finish()
    }

    #[test]
    fn detects_btrfs_send_magic() {
        let stream: Vec<u8> = build_reference_stream();
        let header: BtrfsSendHeader = detect_btrfs_send(&stream).expect("send header");
        assert_eq!(header.version, 1);
    }

    #[test]
    fn rejects_non_send() {
        assert!(detect_btrfs_send(&[0u8; 32]).is_none());
        assert!(detect_btrfs_send(b"btrfs-stream\0").is_none());
    }

    #[test]
    fn replays_write_byte_exact() {
        let stream: Vec<u8> = build_reference_stream();
        let replay: BtrfsSendReplay = replay_btrfs_send(&stream, 64 * 1024 * 1024).expect("replay");
        assert_eq!(replay.subvolume_name.as_deref(), Some("myvol"));
        let hello: &BtrfsSendFile = replay
            .files
            .iter()
            .find(|f| f.path == "dir/hello.txt")
            .expect("hello");
        assert_eq!(hello.data, b"btrfs send replay byte-exact content 01234567");
        let link: &BtrfsSendFile = replay
            .files
            .iter()
            .find(|f| f.path == "link")
            .expect("link");
        assert!(link.is_symlink);
        assert_eq!(link.symlink_target.as_deref(), Some("dir/hello.txt"));
    }

    #[test]
    fn replays_multi_write_with_offsets() {
        let mut b: StreamBuilder = StreamBuilder::new();
        b.command(BTRFS_SEND_C_MKFILE, &[(BTRFS_SEND_A_PATH, b"f")]);
        b.command(
            BTRFS_SEND_C_WRITE,
            &[
                (BTRFS_SEND_A_PATH, b"f"),
                (BTRFS_SEND_A_FILE_OFFSET, &0u64.to_le_bytes()),
                (BTRFS_SEND_A_DATA, b"AAAA"),
            ],
        );
        b.command(
            BTRFS_SEND_C_WRITE,
            &[
                (BTRFS_SEND_A_PATH, b"f"),
                (BTRFS_SEND_A_FILE_OFFSET, &4u64.to_le_bytes()),
                (BTRFS_SEND_A_DATA, b"BBBB"),
            ],
        );
        let stream: Vec<u8> = b.finish();
        let replay: BtrfsSendReplay = replay_btrfs_send(&stream, 1024).expect("replay");
        assert_eq!(replay.files[0].data, b"AAAABBBB");
    }

    #[test]
    fn sparse_write_end_counts_against_total_cap() {
        let mut b: StreamBuilder = StreamBuilder::new();
        b.command(BTRFS_SEND_C_MKFILE, &[(BTRFS_SEND_A_PATH, b"f")]);
        b.command(
            BTRFS_SEND_C_WRITE,
            &[
                (BTRFS_SEND_A_PATH, b"f"),
                (BTRFS_SEND_A_FILE_OFFSET, &1024u64.to_le_bytes()),
                (BTRFS_SEND_A_DATA, b"x"),
            ],
        );
        let stream: Vec<u8> = b.finish();
        let err: Error = replay_btrfs_send(&stream, 1024).expect_err("sparse end exceeds cap");
        assert!(matches!(err, Error::BtrfsSend(msg) if msg.contains("total cap")));
    }

    #[test]
    fn rename_moves_file_content() {
        let mut b: StreamBuilder = StreamBuilder::new();
        b.command(BTRFS_SEND_C_MKFILE, &[(BTRFS_SEND_A_PATH, b"old")]);
        b.command(
            BTRFS_SEND_C_WRITE,
            &[
                (BTRFS_SEND_A_PATH, b"old"),
                (BTRFS_SEND_A_FILE_OFFSET, &0u64.to_le_bytes()),
                (BTRFS_SEND_A_DATA, b"keepme"),
            ],
        );
        b.command(
            BTRFS_SEND_C_RENAME,
            &[(BTRFS_SEND_A_PATH, b"old"), (BTRFS_SEND_A_PATH_TO, b"new")],
        );
        let stream: Vec<u8> = b.finish();
        let replay: BtrfsSendReplay = replay_btrfs_send(&stream, 1024).expect("replay");
        assert_eq!(replay.files.len(), 1);
        assert_eq!(replay.files[0].path, "new");
        assert_eq!(replay.files[0].data, b"keepme");
    }

    #[test]
    fn extract_to_writes_replayed_files() {
        let stream: Vec<u8> = build_reference_stream();
        let dir: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("binfmt-btrfs-send-e2e")
                .expect("create scratch dir");
        let result: crate::extract::ExtractionResult = crate::extract::extract_to(
            crate::container::ContainerKind::BtrfsSend,
            &stream,
            dir.path(),
        )
        .expect("btrfs send extract");
        assert_eq!(result.kind, crate::container::ContainerKind::BtrfsSend);
        assert_eq!(
            std::fs::read(dir.path().join("dir/hello.txt")).expect("hello"),
            b"btrfs send replay byte-exact content 01234567"
        );
    }
}
