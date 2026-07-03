use crate::error::{Error, Result};

const SIT_SIGNATURE: &[u8; 4] = b"SIT!";
const SIT_SIGNATURE2: &[u8; 4] = b"rLau";
const ARCHIVE_HEADER_LEN: usize = 22;
const FILE_HEADER_LEN: usize = 112;

const METHOD_STORED: u8 = 0;
const FLAG_FOLDER_START: u8 = 32;
const FLAG_FOLDER_END: u8 = 33;

#[derive(Debug, Clone)]
pub struct SitFork {
    pub method: u8,
    pub uncompressed_len: u32,
    pub compressed_len: u32,
    pub data_offset: usize,
}

#[derive(Debug, Clone)]
pub struct SitEntry {
    pub name: String,
    pub is_folder: bool,
    pub resource: SitFork,
    pub data: SitFork,
}

#[derive(Debug, Clone)]
pub struct SitArchive {
    pub entries: Vec<SitEntry>,
}

fn rd_u32_be(b: &[u8], at: usize) -> Result<u32> {
    let s: &[u8] = b
        .get(at..at + 4)
        .ok_or_else(|| Error::StuffIt("stuffit: truncated u32".to_owned()))?;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

pub fn parse_classic(bytes: &[u8]) -> Result<SitArchive> {
    if !bytes.starts_with(SIT_SIGNATURE) {
        return Err(Error::StuffIt("stuffit: missing SIT! signature".to_owned()));
    }
    if bytes.get(10..14) != Some(SIT_SIGNATURE2.as_slice()) {
        return Err(Error::StuffIt(
            "stuffit: missing rLau secondary signature".to_owned(),
        ));
    }
    let total_len: usize = rd_u32_be(bytes, 6)? as usize;
    let limit: usize = total_len.min(bytes.len());
    let mut cursor: usize = ARCHIVE_HEADER_LEN;
    let mut entries: Vec<SitEntry> = Vec::new();
    while cursor + FILE_HEADER_LEN <= limit {
        let header: &[u8] = &bytes[cursor..cursor + FILE_HEADER_LEN];
        let rsrc_method: u8 = header[0];
        let data_method: u8 = header[1];
        let name_len: usize = (header[2] as usize).min(63);
        let name: String = String::from_utf8_lossy(&header[3..3 + name_len]).into_owned();

        let rsrc_uncompressed: u32 = rd_u32_be(header, 84)?;
        let data_uncompressed: u32 = rd_u32_be(header, 88)?;
        let rsrc_compressed: u32 = rd_u32_be(header, 92)?;
        let data_compressed: u32 = rd_u32_be(header, 96)?;

        let is_folder: bool = rsrc_method == FLAG_FOLDER_START || rsrc_method == FLAG_FOLDER_END;
        if is_folder {
            entries.push(SitEntry {
                name,
                is_folder: true,
                resource: SitFork {
                    method: rsrc_method,
                    uncompressed_len: 0,
                    compressed_len: 0,
                    data_offset: 0,
                },
                data: SitFork {
                    method: data_method,
                    uncompressed_len: 0,
                    compressed_len: 0,
                    data_offset: 0,
                },
            });
            cursor += FILE_HEADER_LEN;
            continue;
        }

        let rsrc_offset: usize = cursor + FILE_HEADER_LEN;
        let data_offset: usize = rsrc_offset + rsrc_compressed as usize;
        let next: usize = data_offset + data_compressed as usize;
        if next > bytes.len() {
            break;
        }
        entries.push(SitEntry {
            name,
            is_folder: false,
            resource: SitFork {
                method: rsrc_method,
                uncompressed_len: rsrc_uncompressed,
                compressed_len: rsrc_compressed,
                data_offset: rsrc_offset,
            },
            data: SitFork {
                method: data_method,
                uncompressed_len: data_uncompressed,
                compressed_len: data_compressed,
                data_offset,
            },
        });
        cursor = next;
    }
    if entries.is_empty() {
        return Err(Error::StuffIt("stuffit: no file entries parsed".to_owned()));
    }
    Ok(SitArchive { entries })
}

pub fn fork_bytes(bytes: &[u8], fork: &SitFork) -> Result<Vec<u8>> {
    let raw: &[u8] = bytes
        .get(fork.data_offset..fork.data_offset + fork.compressed_len as usize)
        .ok_or_else(|| Error::StuffIt("stuffit: fork data out of bounds".to_owned()))?;
    match fork.method {
        METHOD_STORED => Ok(raw.to_vec()),
        other => Err(Error::StuffIt(format!(
            "stuffit: fork uses compression method {other}; the structure is parsed but this proprietary entropy codec is not decoded in tree"
        ))),
    }
}

#[must_use]
pub const fn fork_is_stored(fork: &SitFork) -> bool {
    fork.method == METHOD_STORED
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn build_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        for (name, data) in entries {
            let mut hdr: Vec<u8> = vec![0u8; FILE_HEADER_LEN];
            hdr[0] = METHOD_STORED;
            hdr[1] = METHOD_STORED;
            let nb: &[u8] = name.as_bytes();
            hdr[2] = nb.len() as u8;
            hdr[3..3 + nb.len()].copy_from_slice(nb);
            hdr[88..92].copy_from_slice(&(data.len() as u32).to_be_bytes());
            hdr[96..100].copy_from_slice(&(data.len() as u32).to_be_bytes());
            body.extend_from_slice(&hdr);
            body.extend_from_slice(data);
        }
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(SIT_SIGNATURE);
        out.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        let total: u32 = (ARCHIVE_HEADER_LEN + body.len()) as u32;
        out.extend_from_slice(&total.to_be_bytes());
        out.extend_from_slice(SIT_SIGNATURE2);
        out.extend_from_slice(&[0u8; 8]);
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn parses_stored_forks_byte_exact() {
        let payload_a: &[u8] = b"first stuffit member data fork stored verbatim";
        let payload_b: &[u8] = b"second member, also stored, different bytes here";
        let archive: Vec<u8> = build_archive(&[("alpha.txt", payload_a), ("beta.txt", payload_b)]);
        let parsed: SitArchive = parse_classic(&archive).expect("parse");
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].name, "alpha.txt");
        assert!(fork_is_stored(&parsed.entries[0].data));
        assert_eq!(
            fork_bytes(&archive, &parsed.entries[0].data).expect("fork a"),
            payload_a
        );
        assert_eq!(
            fork_bytes(&archive, &parsed.entries[1].data).expect("fork b"),
            payload_b
        );
    }

    #[test]
    fn compressed_fork_is_reported_not_decoded() {
        let mut hdr: Vec<u8> = vec![0u8; FILE_HEADER_LEN];
        hdr[0] = METHOD_STORED;
        hdr[1] = 13;
        let nb: &[u8] = b"lz.bin";
        hdr[2] = nb.len() as u8;
        hdr[3..3 + nb.len()].copy_from_slice(nb);
        hdr[88..92].copy_from_slice(&64u32.to_be_bytes());
        hdr[96..100].copy_from_slice(&8u32.to_be_bytes());
        let mut archive: Vec<u8> = Vec::new();
        archive.extend_from_slice(SIT_SIGNATURE);
        archive.extend_from_slice(&1u16.to_be_bytes());
        let total: u32 = (ARCHIVE_HEADER_LEN + FILE_HEADER_LEN + 8) as u32;
        archive.extend_from_slice(&total.to_be_bytes());
        archive.extend_from_slice(SIT_SIGNATURE2);
        archive.extend_from_slice(&[0u8; 8]);
        archive.extend_from_slice(&hdr);
        archive.extend_from_slice(&[0u8; 8]);

        let parsed: SitArchive = parse_classic(&archive).expect("parse");
        assert!(!fork_is_stored(&parsed.entries[0].data));
        assert!(fork_bytes(&archive, &parsed.entries[0].data).is_err());
    }

    #[test]
    fn extract_to_writes_stored_data_forks() {
        let payload: &[u8] = b"stuffit classic stored data fork written to disk by extract_to";
        let archive: Vec<u8> = build_archive(&[("doc.txt", payload)]);
        let dir: std::path::PathBuf =
            std::env::temp_dir().join(format!("disrobe-sit-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let result: crate::extract::ExtractionResult =
            crate::extract::extract_to(crate::container::ContainerKind::StuffIt, &archive, &dir)
                .expect("sit extract");
        assert_eq!(result.kind, crate::container::ContainerKind::StuffIt);
        assert_eq!(std::fs::read(dir.join("doc.txt")).expect("doc"), payload);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_non_sit() {
        assert!(parse_classic(b"PK\x03\x04 not a sit archive at all").is_err());
    }
}
