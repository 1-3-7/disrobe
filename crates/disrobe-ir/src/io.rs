use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use memmap2::Mmap;

use crate::envelope::{Envelope, HEADER_SIZE, compute_root_hash};
use crate::error::{EnvelopeError, Result};
use crate::{ENVELOPE_FORMAT_VERSION, ENVELOPE_MAGIC, Rung};

impl Envelope {
    pub fn read_from_path(path: impl AsRef<Path>) -> Result<Self> {
        let mut file: File = File::open(path).map_err(|e| io_to_envelope(&e))?;
        let mut buf: Vec<u8> = Vec::new();
        file.read_to_end(&mut buf).map_err(|e| io_to_envelope(&e))?;
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
        let mut file: File = opts.open(path).map_err(|e| io_to_envelope(&e))?;
        file.write_all(&bytes).map_err(|e| io_to_envelope(&e))?;
        file.sync_all().map_err(|e| io_to_envelope(&e))?;
        Ok(())
    }
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
    let file: File = File::open(path).map_err(|e| io_to_envelope(&e))?;
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
    let rung: Rung = match bytes[10] {
        0 => Rung::Raw,
        1 => Rung::Disasm,
        2 => Rung::Mir,
        3 => Rung::Hir,
        4 => Rung::Surface,
        other => return Err(EnvelopeError::BadRung(other)),
    };
    let flags: u8 = bytes[11];
    let hot_len: usize = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
    let cold_len: usize = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]) as usize;
    let mut root_hash: [u8; 32] = [0u8; 32];
    root_hash.copy_from_slice(&bytes[20..52]);

    let expected_total: usize = HEADER_SIZE + hot_len + cold_len;
    if bytes.len() < expected_total {
        return Err(EnvelopeError::Truncated {
            expected: expected_total,
            got: bytes.len(),
        });
    }
    let hot_start: usize = HEADER_SIZE;
    let hot_end: usize = hot_start + hot_len;
    let cold_start: usize = hot_end;
    let cold_end: usize = cold_start + cold_len;

    let computed: [u8; 32] =
        compute_root_hash(&bytes[hot_start..hot_end], &bytes[cold_start..cold_end]);
    if computed != root_hash {
        return Err(EnvelopeError::RootHashMismatch {
            header: root_hash,
            computed,
        });
    }

    Ok(MmapView {
        mmap,
        hot_range: (hot_start, hot_end),
        cold_range: (cold_start, cold_end),
        version,
        rung,
        flags,
        root_hash,
    })
}

#[allow(unsafe_code)]
fn unsafe_mmap(file: &File) -> Result<Mmap> {
    unsafe { Mmap::map(file) }.map_err(|e| io_to_envelope(&e))
}

fn io_to_envelope(e: &std::io::Error) -> EnvelopeError {
    EnvelopeError::RkyvAccess(format!("io: {e}"))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::payload::{RawPayload, encode_raw};
    use crate::sidecar::Sidecar;
    use disrobe_core::Capability;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_path(stem: &str) -> PathBuf {
        let id: u64 = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid: u32 = std::process::id();
        std::env::temp_dir().join(format!("disrobe-ir-{stem}-{pid}-{id}.dr"))
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
        let path: PathBuf = temp_path("write-read");
        env.write_to_path(&path).expect("write");
        let decoded: Envelope = Envelope::read_from_path(&path).expect("read");
        assert_eq!(env, decoded);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_create_new_fails_if_exists() {
        let env: Envelope = sample_envelope();
        let path: PathBuf = temp_path("collision");
        env.write_to_path(&path).expect("first write");
        let err: EnvelopeError = env
            .write_to_path(&path)
            .expect_err("should refuse overwrite");
        assert!(matches!(err, EnvelopeError::RkyvAccess(_)));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_overwrite_with_truncate_succeeds() {
        let env: Envelope = sample_envelope();
        let path: PathBuf = temp_path("overwrite");
        env.write_to_path_with(&path, false).expect("first");
        env.write_to_path_with(&path, false).expect("second");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn mmap_view_round_trips() {
        let env: Envelope = sample_envelope();
        let path: PathBuf = temp_path("mmap");
        env.write_to_path(&path).expect("write");
        let view: MmapView = mmap_envelope_view(&path).expect("mmap");
        assert_eq!(view.version, ENVELOPE_FORMAT_VERSION);
        assert_eq!(view.rung, Rung::Raw);
        assert_eq!(view.root_hash, env.root_hash);
        assert_eq!(view.hot(), env.hot.as_slice());
        assert_eq!(view.cold(), env.cold.as_slice());
        drop(view);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn mmap_view_caches_archived_raw_payload() {
        use crate::payload::ArchivedRawPayload;
        use rkyv::rancor::Error as RkyvError;

        let env: Envelope = sample_envelope();
        let path: PathBuf = temp_path("mmap-rkyv");
        env.write_to_path(&path).expect("write");
        let view: MmapView = mmap_envelope_view(&path).expect("mmap");
        let archived: &ArchivedRawPayload =
            rkyv::access::<ArchivedRawPayload, RkyvError>(view.hot())
                .expect("zero-copy rkyv access");
        assert_eq!(archived.source_path.as_str(), "x.wasm");
        assert_eq!(archived.source_bytes.as_slice(), &[1u8, 2, 3, 4, 5]);
        drop(view);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_from_path_rejects_missing_file() {
        let path: PathBuf = temp_path("missing-nonexistent");
        let _ = std::fs::remove_file(&path);
        let err: EnvelopeError = Envelope::read_from_path(&path).expect_err("should fail");
        assert!(matches!(err, EnvelopeError::RkyvAccess(_)));
    }
}
