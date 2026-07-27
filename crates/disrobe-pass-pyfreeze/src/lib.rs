#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
#![allow(clippy::redundant_pub_crate)]
use std::fs;
use std::io::Read as _;
use std::path::Path;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

const MAX_FREEZE_INPUT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_LIBRARY_ZIP_BYTES: u64 = 512 * 1024 * 1024;
const MAX_RECOVERY_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_FREEZE_DIR_ENTRIES: usize = 4096;

fn read_file_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let metadata: fs::Metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        )
        .into());
    }
    if metadata.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} is {} bytes; cap is {} bytes",
                path.display(),
                metadata.len(),
                max_bytes
            ),
        )
        .into());
    }
    let file: fs::File = fs::File::open(path)?;
    let mut reader: std::io::Take<fs::File> = file.take(max_bytes.saturating_add(1));
    let capacity: usize = usize::try_from(metadata.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} length does not fit usize", path.display()),
        )
    })?;
    let mut bytes: Vec<u8> = Vec::with_capacity(capacity);
    reader.read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_or(true, |len: u64| len > max_bytes) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} grew past {} bytes while reading",
                path.display(),
                max_bytes
            ),
        )
        .into());
    }
    Ok(bytes)
}

pub mod bbfreeze;
pub mod briefcase;
#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod common;
pub mod cxfreeze;
pub(crate) mod debug;
pub mod detect;
pub mod error;
pub mod pass;
pub mod pex;
pub mod provenance_header;
pub mod py2exe;
pub mod pyoxidizer;
pub mod recover;
pub mod shiv;
pub mod zipapp;

pub use common::manifest::{
    EntryKind, EntryOrigin, EntryRecord, FreezerKind, FreezerManifest, ModuleInventoryEntry,
};
pub use common::quota::{ExtractionQuota, QuotaGuard, QuotaReport};
pub use detect::{Detection, detect_bytes};
pub use error::{Error, Result};
pub use pass::{PyfreezeOutput, PyfreezeRecovery, detect, extract};
pub use provenance_header::{
    python_extracted_header, python_unpacked_header, render_extracted_with_header,
};
pub use recover::{
    RecoveredModule, RoundtripGrade, SurfacedNative, recover_bytecode, recover_bytecode_file,
    recover_raw_marshal, surface_native, surface_native_file,
};

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_file(name: &str) -> disrobe_core::scratch::ScratchFile {
        let seq: u64 = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let purpose: String = format!("disrobe_pyfreeze_{name}_{}_{}", std::process::id(), seq);
        let (scratch, _file): (disrobe_core::scratch::ScratchFile, std::fs::File) =
            disrobe_core::scratch::ScratchFile::create(&purpose, "").expect("create scratch file");
        scratch
    }

    #[test]
    fn bounded_file_read_accepts_under_cap() {
        let scratch: disrobe_core::scratch::ScratchFile = temp_file("under");
        let path: std::path::PathBuf = scratch.path().to_path_buf();
        std::fs::write(&path, b"abc").expect("write temp file");
        let bytes: Vec<u8> = read_file_bounded(&path, 3).expect("read under cap");
        assert_eq!(bytes, b"abc");
    }

    #[test]
    fn bounded_file_read_rejects_over_cap() {
        let scratch: disrobe_core::scratch::ScratchFile = temp_file("over");
        let path: std::path::PathBuf = scratch.path().to_path_buf();
        std::fs::write(&path, b"abcd").expect("write temp file");
        let err: Error = read_file_bounded(&path, 3).unwrap_err();
        assert!(matches!(err, Error::Io(_)));
    }
}
