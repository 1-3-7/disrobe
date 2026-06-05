use serde::{Deserialize, Serialize};

pub const NEXE_FOOTER_MAGIC: &[u8] = b"<nexe~~sentinel>";
pub const NEXE_FOOTER_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NexeLocation {
    pub payload_offset: u64,
    pub payload_size: u64,
    pub footer_offset: u64,
}

#[must_use]
pub fn detect_nexe_suffix(bytes: &[u8]) -> Option<NexeLocation> {
    if bytes.len() < NEXE_FOOTER_LEN + NEXE_FOOTER_MAGIC.len() {
        return None;
    }
    let footer_off: usize = bytes.len() - NEXE_FOOTER_LEN;
    let sentinel_off: usize = footer_off + 16;
    if sentinel_off + NEXE_FOOTER_MAGIC.len() > bytes.len() {
        return None;
    }
    if &bytes[sentinel_off..sentinel_off + NEXE_FOOTER_MAGIC.len()] != NEXE_FOOTER_MAGIC {
        return None;
    }
    let payload_size: u64 = u64::from_le_bytes([
        bytes[footer_off],
        bytes[footer_off + 1],
        bytes[footer_off + 2],
        bytes[footer_off + 3],
        bytes[footer_off + 4],
        bytes[footer_off + 5],
        bytes[footer_off + 6],
        bytes[footer_off + 7],
    ]);
    let resource_size: u64 = u64::from_le_bytes([
        bytes[footer_off + 8],
        bytes[footer_off + 9],
        bytes[footer_off + 10],
        bytes[footer_off + 11],
        bytes[footer_off + 12],
        bytes[footer_off + 13],
        bytes[footer_off + 14],
        bytes[footer_off + 15],
    ]);
    let total_payload: u64 = payload_size.saturating_add(resource_size);
    let payload_offset: u64 = (footer_off as u64).saturating_sub(total_payload);
    Some(NexeLocation {
        payload_offset,
        payload_size: total_payload,
        footer_offset: footer_off as u64,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn synth_nexe_binary(code: &[u8], resources: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = vec![0u8; 256];
        out.extend_from_slice(code);
        out.extend_from_slice(resources);
        out.extend_from_slice(&(code.len() as u64).to_le_bytes());
        out.extend_from_slice(&(resources.len() as u64).to_le_bytes());
        out.extend_from_slice(NEXE_FOOTER_MAGIC);
        out
    }

    #[test]
    fn detects_nexe_footer_and_sizes() {
        let code: &[u8] = b"// bundled code\n";
        let resources: &[u8] = b"resource-blob";
        let bytes: Vec<u8> = synth_nexe_binary(code, resources);
        let loc: NexeLocation = detect_nexe_suffix(&bytes).expect("nexe footer");
        assert_eq!(loc.payload_size, (code.len() + resources.len()) as u64);
        assert!(loc.footer_offset > 0);
    }

    #[test]
    fn returns_none_when_no_footer() {
        assert!(detect_nexe_suffix(&[0u8; 256]).is_none());
    }

    #[test]
    fn returns_none_when_too_short() {
        assert!(detect_nexe_suffix(&[0u8; 16]).is_none());
    }
}
