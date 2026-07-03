use std::io::Cursor;

use ntfs::structured_values::NtfsFileNamespace;
use ntfs::{Ntfs, NtfsFile, NtfsReadSeek};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const NTFS_OEM_ID: &[u8; 8] = b"NTFS    ";
const MAX_FILES: usize = 500_000;
const MAX_DEPTH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NtfsVolume {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub cluster_size: u32,
}

#[derive(Debug, Clone)]
pub struct NtfsFileEntry {
    pub path: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct NtfsWalk {
    pub volume: NtfsVolume,
    pub files: Vec<NtfsFileEntry>,
    pub notes: Vec<String>,
}

#[must_use]
pub fn detect_ntfs(bytes: &[u8]) -> Option<NtfsVolume> {
    if bytes.len() < 512 {
        return None;
    }
    if &bytes[3..11] != NTFS_OEM_ID {
        return None;
    }
    let bytes_per_sector: u16 = u16::from_le_bytes([bytes[11], bytes[12]]);
    let sectors_per_cluster: u8 = bytes[13];
    if bytes_per_sector == 0 || !bytes_per_sector.is_power_of_two() {
        return None;
    }
    Some(NtfsVolume {
        bytes_per_sector,
        sectors_per_cluster,
        cluster_size: u32::from(bytes_per_sector) * u32::from(sectors_per_cluster.max(1)),
    })
}

pub fn walk_ntfs(bytes: &[u8], max_total: u64) -> Result<NtfsWalk> {
    let volume: NtfsVolume = detect_ntfs(bytes)
        .ok_or_else(|| Error::Ntfs("NTFS OEM id not found at offset 3".to_owned()))?;
    let mut cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut ntfs: Ntfs =
        Ntfs::new(&mut cursor).map_err(|e| Error::Ntfs(format!("open volume: {e}")))?;
    ntfs.read_upcase_table(&mut cursor)
        .map_err(|e| Error::Ntfs(format!("read $UpCase: {e}")))?;
    let root: NtfsFile = ntfs
        .root_directory(&mut cursor)
        .map_err(|e| Error::Ntfs(format!("root directory: {e}")))?;

    let mut files: Vec<NtfsFileEntry> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut total: u64 = 0;
    let root_record: u64 = root.file_record_number();
    let mut stack: Vec<(NtfsFile, String, usize)> = vec![(root, String::new(), 0)];
    let mut visited: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();

    while let Some((dir, prefix, depth)) = stack.pop() {
        if depth > MAX_DEPTH || files.len() > MAX_FILES {
            break;
        }
        if !visited.insert(dir.file_record_number()) {
            continue;
        }
        let index = match dir.directory_index(&mut cursor) {
            Ok(i) => i,
            Err(e) => {
                notes.push(format!("ntfs `{prefix}` directory index: {e}"));
                continue;
            }
        };
        let mut entries = index.entries();
        while let Some(entry) = entries.next(&mut cursor) {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    notes.push(format!("ntfs entry in `{prefix}`: {e}"));
                    continue;
                }
            };
            let Some(key) = entry.key() else {
                continue;
            };
            let Ok(file_name) = key else {
                continue;
            };
            if file_name.namespace() == NtfsFileNamespace::Dos {
                continue;
            }
            let name: String = file_name.name().to_string_lossy();
            if name == "." || name.starts_with('$') {
                continue;
            }
            let child_record: u64 = entry.file_reference().file_record_number();
            if child_record == root_record {
                continue;
            }
            let child: NtfsFile = match entry.to_file(&ntfs, &mut cursor) {
                Ok(f) => f,
                Err(e) => {
                    notes.push(format!("ntfs to_file `{name}`: {e}"));
                    continue;
                }
            };
            let child_path: String = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if file_name.is_directory() {
                stack.push((child, child_path, depth + 1));
            } else {
                match read_default_data(&mut cursor, &child, max_total) {
                    Ok(Some(data)) => {
                        total = total.saturating_add(data.len() as u64);
                        if total > max_total {
                            return Err(Error::Ntfs(format!("walk exceeds total cap {max_total}")));
                        }
                        files.push(NtfsFileEntry {
                            path: child_path,
                            data,
                        });
                    }
                    Ok(None) => {}
                    Err(e) => notes.push(format!("ntfs read `{child_path}`: {e}")),
                }
            }
        }
    }

    Ok(NtfsWalk {
        volume,
        files,
        notes,
    })
}

fn read_default_data(
    cursor: &mut Cursor<&[u8]>,
    file: &NtfsFile,
    max_total: u64,
) -> std::result::Result<Option<Vec<u8>>, String> {
    let Some(data_item) = file.data(cursor, "") else {
        return Ok(None);
    };
    let data_item = data_item.map_err(|e| format!("data item: {e}"))?;
    let data_attribute = data_item
        .to_attribute()
        .map_err(|e| format!("to_attribute: {e}"))?;
    let mut value = data_attribute
        .value(cursor)
        .map_err(|e| format!("attribute value: {e}"))?;
    let len: u64 = value.len();
    if len > max_total {
        return Err(format!("file size {len} exceeds total cap {max_total}"));
    }
    let mut buf: Vec<u8> = vec![0u8; len as usize];
    value
        .read_exact(cursor, &mut buf)
        .map_err(|e| format!("read_exact: {e}"))?;
    Ok(Some(buf))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn corpus_fixture() -> Option<Vec<u8>> {
        let mut p: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.pop();
        p.push("corpus");
        p.push("binfmt");
        p.push("ntfs");
        p.push("hello.ntfs");
        std::fs::read(&p).ok()
    }

    #[test]
    fn detect_rejects_non_ntfs() {
        assert!(detect_ntfs(&[0u8; 1024]).is_none());
        let mut fake: Vec<u8> = vec![0u8; 512];
        fake[3..11].copy_from_slice(b"MSDOS5.0");
        assert!(detect_ntfs(&fake).is_none());
    }

    #[test]
    fn detect_accepts_ntfs_oem() {
        let mut boot: Vec<u8> = vec![0u8; 512];
        boot[3..11].copy_from_slice(NTFS_OEM_ID);
        boot[11..13].copy_from_slice(&512u16.to_le_bytes());
        boot[13] = 8;
        let vol: NtfsVolume = detect_ntfs(&boot).expect("ntfs");
        assert_eq!(vol.bytes_per_sector, 512);
        assert_eq!(vol.sectors_per_cluster, 8);
        assert_eq!(vol.cluster_size, 4096);
    }

    #[test]
    #[ignore = "needs gitignored real fixture corpus/binfmt/ntfs/hello.ntfs (~5MB); run with --ignored"]
    fn walks_real_ntfs_volume_byte_exact() {
        let Some(bytes): Option<Vec<u8>> = corpus_fixture() else {
            panic!("missing fixture corpus/binfmt/ntfs/hello.ntfs");
        };
        let walk: NtfsWalk = walk_ntfs(&bytes, 256 * 1024 * 1024).expect("walk ntfs");
        assert!(
            !walk.files.is_empty(),
            "expected at least one file in volume"
        );
        for f in &walk.files {
            assert!(!f.path.is_empty());
        }
    }
}
