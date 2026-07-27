use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use memmap2::Mmap;

use crate::envelope::{
    Envelope, HEADER_SIZE, MAX_DECODED_ENVELOPE_BYTES, PayloadRanges, capped_declared_envelope_len,
    compute_root_hash, payload_ranges,
};
use crate::error::{EnvelopeError, Result};
use crate::{ENVELOPE_FORMAT_VERSION, ENVELOPE_MAGIC, Rung};

const READ_PREALLOC_CAP: usize = 1 << 20;

impl Envelope {
    pub fn read_from_path(path: impl AsRef<Path>) -> Result<Self> {
        let mut file: File = File::open(path).map_err(io_to_envelope)?;
        let header: [u8; HEADER_SIZE] = read_header(&mut file)?;
        let total: usize = envelope_len_from_header(&header)?;
        let remaining: usize = total - HEADER_SIZE;
        let capacity: usize = HEADER_SIZE + remaining.min(READ_PREALLOC_CAP);
        let mut buf: Vec<u8> = Vec::with_capacity(capacity);
        buf.extend_from_slice(&header);
        if remaining > 0 {
            let mut limited: std::io::Take<File> = file.take(remaining as u64);
            limited.read_to_end(&mut buf).map_err(io_to_envelope)?;
        }
        if buf.len() < total {
            return Err(EnvelopeError::Truncated {
                expected: total,
                got: buf.len(),
            });
        }
        Self::decode(&buf)
    }

    pub fn write_to_path(&self, path: impl AsRef<Path>) -> Result<()> {
        self.write_to_path_with(path, true)
    }

    pub fn write_to_path_with(&self, path: impl AsRef<Path>, create_new: bool) -> Result<()> {
        let bytes: Vec<u8> = self.encode()?;
        let mut opts: OpenOptions = OpenOptions::new();
        opts.write(true);
        if create_new {
            opts.create_new(true);
        } else {
            opts.create(true).truncate(true);
        }
        let mut file: File = opts.open(path).map_err(io_to_envelope)?;
        file.write_all(&bytes).map_err(io_to_envelope)?;
        file.sync_all().map_err(io_to_envelope)?;
        Ok(())
    }
}

fn read_header(file: &mut File) -> Result<[u8; HEADER_SIZE]> {
    let mut header: [u8; HEADER_SIZE] = [0u8; HEADER_SIZE];
    let mut got: usize = 0;
    while got < HEADER_SIZE {
        let n: usize = file.read(&mut header[got..]).map_err(io_to_envelope)?;
        if n == 0 {
            return Err(EnvelopeError::Truncated {
                expected: HEADER_SIZE,
                got,
            });
        }
        got += n;
    }
    Ok(header)
}

fn envelope_len_from_header(header: &[u8; HEADER_SIZE]) -> Result<usize> {
    let mut magic: [u8; 8] = [0u8; 8];
    magic.copy_from_slice(&header[0..8]);
    if &magic != ENVELOPE_MAGIC {
        return Err(EnvelopeError::BadMagic {
            expected: *ENVELOPE_MAGIC,
            got: magic,
        });
    }
    let version: u16 = u16::from_le_bytes([header[8], header[9]]);
    if version != ENVELOPE_FORMAT_VERSION {
        return Err(EnvelopeError::BadVersion(version));
    }
    if Rung::from_u8(header[10]).is_none() {
        return Err(EnvelopeError::BadRung(header[10]));
    }
    let hot_len: usize =
        u32::from_le_bytes([header[12], header[13], header[14], header[15]]) as usize;
    let cold_len: usize =
        u32::from_le_bytes([header[16], header[17], header[18], header[19]]) as usize;
    capped_declared_envelope_len(hot_len, cold_len)
}

#[derive(Debug)]
pub struct MmapView {
    mmap: Mmap,
    hot_range: (usize, usize),
    cold_range: (usize, usize),
    pub version: u16,
    pub rung: Rung,
    pub flags: u8,
    pub root_hash: [u8; 32],
}

impl MmapView {
    #[inline]
    #[must_use]
    pub fn hot(&self) -> &[u8] {
        &self.mmap[self.hot_range.0..self.hot_range.1]
    }

    #[inline]
    #[must_use]
    pub fn cold(&self) -> &[u8] {
        &self.mmap[self.cold_range.0..self.cold_range.1]
    }

    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.mmap[..]
    }
}

pub fn mmap_envelope_view(path: impl AsRef<Path>) -> Result<MmapView> {
    let file: File = File::open(path).map_err(io_to_envelope)?;
    reject_oversized_mmap(&file)?;
    let mmap: Mmap = unsafe_mmap(&file)?;
    let bytes: &[u8] = &mmap[..];

    if bytes.len() < HEADER_SIZE {
        return Err(EnvelopeError::Truncated {
            expected: HEADER_SIZE,
            got: bytes.len(),
        });
    }
    let mut magic: [u8; 8] = [0u8; 8];
    magic.copy_from_slice(&bytes[0..8]);
    if &magic != ENVELOPE_MAGIC {
        return Err(EnvelopeError::BadMagic {
            expected: *ENVELOPE_MAGIC,
            got: magic,
        });
    }
    let version: u16 = u16::from_le_bytes([bytes[8], bytes[9]]);
    if version != ENVELOPE_FORMAT_VERSION {
        return Err(EnvelopeError::BadVersion(version));
    }
    let Some(rung): Option<Rung> = Rung::from_u8(bytes[10]) else {
        return Err(EnvelopeError::BadRung(bytes[10]));
    };
    let flags: u8 = bytes[11];
    let hot_len: usize = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
    let cold_len: usize = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]) as usize;
    let mut root_hash: [u8; 32] = [0u8; 32];
    root_hash.copy_from_slice(&bytes[20..52]);

    let ranges: PayloadRanges = payload_ranges(bytes.len(), hot_len, cold_len)?;

    let computed: [u8; 32] = compute_root_hash(
        &bytes[ranges.hot.0..ranges.hot.1],
        &bytes[ranges.cold.0..ranges.cold.1],
    );
    if computed != root_hash {
        return Err(EnvelopeError::RootHashMismatch {
            header: root_hash,
            computed,
        });
    }

    Ok(MmapView {
        mmap,
        hot_range: ranges.hot,
        cold_range: ranges.cold,
        version,
        rung,
        flags,
        root_hash,
    })
}

fn reject_oversized_mmap(file: &File) -> Result<()> {
    let file_len: u64 = file.metadata().map_err(io_to_envelope)?.len();
    let max_file_len: u64 =
        u64::try_from(MAX_DECODED_ENVELOPE_BYTES).map_or(u64::MAX, |value: u64| value);
    if file_len > max_file_len {
        return Err(EnvelopeError::EnvelopeTooLarge {
            actual: usize::try_from(file_len).map_or(usize::MAX, |value: usize| value),
            max: MAX_DECODED_ENVELOPE_BYTES,
        });
    }
    Ok(())
}

#[allow(unsafe_code)]
fn unsafe_mmap(file: &File) -> Result<Mmap> {
    unsafe { Mmap::map(file) }.map_err(io_to_envelope)
}

const fn io_to_envelope(e: std::io::Error) -> EnvelopeError {
    EnvelopeError::Io(e)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::envelope::MAX_DECODED_ENVELOPE_BYTES;
    use crate::payload::{RawPayload, encode_raw};
    use crate::sidecar::Sidecar;
    use disrobe_core::Capability;
    use disrobe_core::scratch::ScratchDir;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn temp_path(stem: &str) -> (ScratchDir, PathBuf) {
        let purpose: String = format!("disrobe-ir-{stem}");
        let scratch: ScratchDir = ScratchDir::create(&purpose).expect("create scratch directory");
        let path: PathBuf = scratch.path().join("payload.dr");
        (scratch, path)
    }

    fn sample_envelope() -> Envelope {
        let hot: Vec<u8> = encode_raw(&RawPayload {
            source_path: "x.wasm".to_owned(),
            source_bytes: vec![1, 2, 3, 4, 5],
            source_hash: [0xAB; 32],
            detected_format: Some("wasm".to_owned()),
        })
        .expect("encode raw");
        let cold: Vec<u8> = Sidecar {
            produced_by: "io-test".to_owned(),
            produced_by_version: "0.1.0".to_owned(),
            capabilities: vec![Capability::produces("raw", 1)],
            provenance: BTreeMap::default(),
        }
        .encode()
        .expect("encode cold");
        Envelope::new(Rung::Raw, hot, cold)
    }

    #[test]
    fn write_then_read_round_trip() {
        let env: Envelope = sample_envelope();
        let (_scratch, path): (ScratchDir, PathBuf) = temp_path("write-read");
        env.write_to_path(&path).expect("write");
        let decoded: Envelope = Envelope::read_from_path(&path).expect("read");
        assert_eq!(env, decoded);
    }

    #[test]
    fn write_create_new_fails_if_exists() {
        let env: Envelope = sample_envelope();
        let (_scratch, path): (ScratchDir, PathBuf) = temp_path("collision");
        env.write_to_path(&path).expect("first write");
        let err: EnvelopeError = env
            .write_to_path(&path)
            .expect_err("should refuse overwrite");
        assert!(
            matches!(err, EnvelopeError::Io(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists)
        );
    }

    #[test]
    fn write_overwrite_with_truncate_succeeds() {
        let env: Envelope = sample_envelope();
        let (_scratch, path): (ScratchDir, PathBuf) = temp_path("overwrite");
        env.write_to_path_with(&path, false).expect("first");
        env.write_to_path_with(&path, false).expect("second");
    }

    #[test]
    fn mmap_view_round_trips() {
        let env: Envelope = sample_envelope();
        let (_scratch, path): (ScratchDir, PathBuf) = temp_path("mmap");
        env.write_to_path(&path).expect("write");
        let view: MmapView = mmap_envelope_view(&path).expect("mmap");
        assert_eq!(view.version, ENVELOPE_FORMAT_VERSION);
        assert_eq!(view.rung, Rung::Raw);
        assert_eq!(view.root_hash, env.root_hash);
        assert_eq!(view.hot(), env.hot.as_slice());
        assert_eq!(view.cold(), env.cold.as_slice());
        drop(view);
    }

    #[test]
    fn mmap_view_caches_archived_raw_payload() {
        use crate::payload::ArchivedRawPayload;
        use rkyv::rancor::Error as RkyvError;

        let env: Envelope = sample_envelope();
        let (_scratch, path): (ScratchDir, PathBuf) = temp_path("mmap-rkyv");
        env.write_to_path(&path).expect("write");
        let view: MmapView = mmap_envelope_view(&path).expect("mmap");
        let archived: &ArchivedRawPayload =
            rkyv::access::<ArchivedRawPayload, RkyvError>(view.hot())
                .expect("zero-copy rkyv access");
        assert_eq!(archived.source_path.as_str(), "x.wasm");
        assert_eq!(archived.source_bytes.as_slice(), &[1u8, 2, 3, 4, 5]);
        drop(view);
    }

    #[test]
    fn read_from_path_rejects_missing_file() {
        let (_scratch, path): (ScratchDir, PathBuf) = temp_path("missing-nonexistent");
        let _ = std::fs::remove_file(&path);
        let err: EnvelopeError = Envelope::read_from_path(&path).expect_err("should fail");
        assert!(
            matches!(err, EnvelopeError::Io(ref e) if e.kind() == std::io::ErrorKind::NotFound)
        );
    }

    #[test]
    fn read_from_path_rejects_truncated_declared_payload() {
        let env: Envelope = Envelope::new(Rung::Raw, vec![], vec![]);
        let mut bytes: Vec<u8> = env.encode().expect("encode");
        bytes[12..16].copy_from_slice(&1024u32.to_le_bytes());
        let (_scratch, path): (ScratchDir, PathBuf) = temp_path("read-truncated-payload");
        std::fs::write(&path, bytes).expect("write");
        let err: EnvelopeError = Envelope::read_from_path(&path).expect_err("should fail");
        assert!(matches!(
            err,
            EnvelopeError::Truncated {
                expected,
                got: HEADER_SIZE
            } if expected == HEADER_SIZE + 1024
        ));
    }

    #[test]
    fn read_from_path_rejects_declared_payload_over_cap() {
        let env: Envelope = Envelope::new(Rung::Raw, vec![], vec![]);
        let mut bytes: Vec<u8> = env.encode().expect("encode");
        let declared: usize = MAX_DECODED_ENVELOPE_BYTES - HEADER_SIZE + 1;
        let hot_len: u32 = u32::try_from(declared).expect("cap fits u32");
        bytes[12..16].copy_from_slice(&hot_len.to_le_bytes());
        let (_scratch, path): (ScratchDir, PathBuf) = temp_path("read-over-cap");
        std::fs::write(&path, bytes).expect("write");
        let err: EnvelopeError = Envelope::read_from_path(&path).expect_err("should fail");
        assert!(matches!(
            err,
            EnvelopeError::EnvelopeTooLarge {
                actual,
                max: MAX_DECODED_ENVELOPE_BYTES
            } if actual == MAX_DECODED_ENVELOPE_BYTES + 1
        ));
    }

    #[test]
    fn read_from_path_ignores_trailing_bytes() {
        let env: Envelope = sample_envelope();
        let mut bytes: Vec<u8> = env.encode().expect("encode");
        bytes.extend(std::iter::repeat_n(0xA5u8, READ_PREALLOC_CAP));
        let (_scratch, path): (ScratchDir, PathBuf) = temp_path("read-trailing");
        std::fs::write(&path, bytes).expect("write");
        let decoded: Envelope = Envelope::read_from_path(&path).expect("read");
        assert_eq!(decoded, env);
    }

    #[test]
    fn mmap_view_rejects_declared_payload_length_overflow() {
        let env: Envelope = Envelope::new(Rung::Raw, vec![], vec![]);
        let mut bytes: Vec<u8> = env.encode().expect("encode");
        bytes[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes[16..20].copy_from_slice(&u32::MAX.to_le_bytes());

        let (_scratch, path): (ScratchDir, PathBuf) = temp_path("mmap-overflow");
        std::fs::write(&path, bytes).expect("write");
        let err: EnvelopeError = mmap_envelope_view(&path).expect_err("should fail");
        assert!(matches!(err, EnvelopeError::Truncated { .. }));
    }

    #[test]
    fn mmap_view_rejects_file_over_cap_before_mapping() {
        let (_scratch, path): (ScratchDir, PathBuf) = temp_path("mmap-file-over-cap");
        let file: std::fs::File = std::fs::File::create(&path).expect("create");
        let oversized_len: u64 =
            u64::try_from(MAX_DECODED_ENVELOPE_BYTES).expect("cap fits u64") + 1;
        file.set_len(oversized_len).expect("set len");
        drop(file);

        let err: EnvelopeError = mmap_envelope_view(&path).expect_err("should fail");
        assert!(matches!(
            err,
            EnvelopeError::EnvelopeTooLarge {
                actual,
                max: MAX_DECODED_ENVELOPE_BYTES
            } if actual == MAX_DECODED_ENVELOPE_BYTES + 1
        ));
    }
}
