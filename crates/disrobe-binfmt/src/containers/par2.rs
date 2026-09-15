use crate::error::{Error, Result};

pub const PAR2_MAGIC: &[u8; 8] = b"PAR2\x00PKT";

const PACKET_HEADER_LEN: usize = 64;
const TYPE_FILE_DESC: &[u8; 16] = b"PAR 2.0\0FileDesc";
const TYPE_MAIN: &[u8; 16] = b"PAR 2.0\0Main\0\0\0\0";
const TYPE_CREATOR: &[u8; 16] = b"PAR 2.0\0Creator\0";
const TYPE_RECOVERY: &[u8; 16] = b"PAR 2.0\0RecvSlic";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Par2Packet {
    pub packet_type: String,
    pub offset: usize,
    pub length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Par2ProtectedFile {
    pub name: String,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Par2RecoverySet {
    pub packets: Vec<Par2Packet>,
    pub protected_files: Vec<Par2ProtectedFile>,
    pub recovery_slice_count: usize,
    pub creator: Option<String>,
}

#[must_use]
pub fn detect_par2(bytes: &[u8]) -> bool {
    bytes.starts_with(PAR2_MAGIC)
}

pub fn parse_par2(bytes: &[u8]) -> Result<Par2RecoverySet> {
    if !detect_par2(bytes) {
        return Err(Error::Par2("par2: missing PAR2\\0PKT magic".to_owned()));
    }
    let mut offset: usize = 0;
    let mut packets: Vec<Par2Packet> = Vec::new();
    let mut protected_files: Vec<Par2ProtectedFile> = Vec::new();
    let mut recovery_slice_count: usize = 0;
    let mut creator: Option<String> = None;

    while offset + PACKET_HEADER_LEN <= bytes.len() {
        if &bytes[offset..offset + 8] != PAR2_MAGIC {
            let Some(next) = find_magic(&bytes[offset + 1..]) else {
                break;
            };
            offset += 1 + next;
            continue;
        }
        let length: u64 = u64::from_le_bytes(
            bytes[offset + 8..offset + 16]
                .try_into()
                .map_err(|_| Error::Par2("par2: bad length field".to_owned()))?,
        );
        let length_us: usize =
            usize::try_from(length).map_err(|_| Error::Par2("par2: length overflow".to_owned()))?;
        if length_us < PACKET_HEADER_LEN || !length_us.is_multiple_of(4) {
            return Err(Error::Par2(format!(
                "par2: implausible packet length {length_us} at offset {offset}"
            )));
        }
        let packet_end: usize = offset
            .checked_add(length_us)
            .ok_or_else(|| Error::Par2("par2: packet end overflow".to_owned()))?;
        if packet_end > bytes.len() {
            break;
        }
        let type_field: &[u8] = &bytes[offset + 48..offset + 64];
        let body: &[u8] = &bytes[offset + 64..packet_end];
        let type_label: String = render_type(type_field);
        if type_field == TYPE_FILE_DESC {
            if let Some(file) = parse_file_desc(body) {
                protected_files.push(file);
            }
        } else if type_field == TYPE_RECOVERY {
            recovery_slice_count += 1;
        } else if type_field == TYPE_CREATOR {
            creator = Some(
                String::from_utf8_lossy(body)
                    .trim_end_matches('\0')
                    .trim()
                    .to_owned(),
            );
        } else if type_field == TYPE_MAIN {
        }
        packets.push(Par2Packet {
            packet_type: type_label,
            offset,
            length: length_us,
        });
        offset = packet_end;
    }

    if packets.is_empty() {
        return Err(Error::Par2(
            "par2: no valid packets found after magic".to_owned(),
        ));
    }
    protected_files.sort_by(|a: &Par2ProtectedFile, b: &Par2ProtectedFile| a.name.cmp(&b.name));
    protected_files.dedup();
    Ok(Par2RecoverySet {
        packets,
        protected_files,
        recovery_slice_count,
        creator,
    })
}

fn find_magic(bytes: &[u8]) -> Option<usize> {
    disrobe_core::byte_search::find(bytes, PAR2_MAGIC)
}

fn render_type(field: &[u8]) -> String {
    String::from_utf8_lossy(field)
        .replace('\0', " ")
        .trim()
        .to_owned()
}

fn parse_file_desc(body: &[u8]) -> Option<Par2ProtectedFile> {
    if body.len() < 56 {
        return None;
    }
    let length: u64 = u64::from_le_bytes(body[48..56].try_into().ok()?);
    let name_bytes: &[u8] = &body[56..];
    let trimmed: &[u8] = name_bytes
        .iter()
        .position(|&b: &u8| b == 0)
        .map_or(name_bytes, |pos: usize| &name_bytes[..pos]);
    let name: String = String::from_utf8_lossy(trimmed).into_owned();
    if name.is_empty() {
        return None;
    }
    Some(Par2ProtectedFile { name, length })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn packet(type_field: &[u8; 16], body: &[u8]) -> Vec<u8> {
        let mut p: Vec<u8> = Vec::new();
        let length: u64 = (PACKET_HEADER_LEN + body.len()) as u64;
        p.extend_from_slice(PAR2_MAGIC);
        p.extend_from_slice(&length.to_le_bytes());
        p.extend_from_slice(&[0u8; 16]);
        p.extend_from_slice(&[0xAB; 16]);
        p.extend_from_slice(type_field);
        p.extend_from_slice(body);
        p
    }

    fn file_desc_body(name: &str, file_len: u64) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&[0u8; 16]);
        body.extend_from_slice(&[0u8; 16]);
        body.extend_from_slice(&[0u8; 16]);
        body.extend_from_slice(&file_len.to_le_bytes());
        body.extend_from_slice(name.as_bytes());
        while !body.len().is_multiple_of(4) {
            body.push(0);
        }
        body
    }

    #[test]
    fn detect_matches_magic() {
        let mut bytes: Vec<u8> = PAR2_MAGIC.to_vec();
        bytes.extend([0u8; 64]);
        assert!(detect_par2(&bytes));
        assert!(!detect_par2(b"NOTPAR2!"));
    }

    #[test]
    fn parses_file_desc_and_recovery_packets() {
        let mut blob: Vec<u8> = Vec::new();
        blob.extend(packet(TYPE_MAIN, &[0u8; 32]));
        blob.extend(packet(TYPE_FILE_DESC, &file_desc_body("payload.bin", 4096)));
        blob.extend(packet(TYPE_RECOVERY, &[0u8; 64]));
        blob.extend(packet(TYPE_CREATOR, b"disrobe test\0\0\0\0"));
        let set: Par2RecoverySet = parse_par2(&blob).expect("parse par2");
        assert_eq!(set.protected_files.len(), 1);
        assert_eq!(set.protected_files[0].name, "payload.bin");
        assert_eq!(set.protected_files[0].length, 4096);
        assert_eq!(set.recovery_slice_count, 1);
        assert_eq!(set.creator.as_deref(), Some("disrobe test"));
        assert_eq!(set.packets.len(), 4);
    }
}
