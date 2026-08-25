use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::flutter::engine_symbols::normalize_flutter_engine_symbol_summary;
use crate::flutter::{FlutterEngineIdentity, FlutterEngineSymbol, ValidatedFlutterEngineSymbolMap};

pub const FLUTTER_ENGINE_SYMBOL_CACHE_FORMAT: &str = "disrobe.flutter.engine-symbol-cache";
pub const FLUTTER_ENGINE_SYMBOL_CACHE_VERSION: u32 = 1;
pub const FLUTTER_ENGINE_SYMBOL_CACHE_MAX_BYTES: usize = 1_048_576;

static NEXT_TEMPORARY_FILE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct FlutterEngineSymbolCache {
    directory: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CacheRecord {
    format: String,
    version: u32,
    identity: FlutterEngineIdentity,
    symbols: Vec<FlutterEngineSymbol>,
}

impl FlutterEngineSymbolCache {
    #[must_use]
    pub fn new(directory: impl AsRef<Path>) -> Self {
        Self {
            directory: directory.as_ref().to_path_buf(),
        }
    }

    pub fn load(
        &self,
        identity: &FlutterEngineIdentity,
    ) -> Result<Option<Vec<FlutterEngineSymbol>>> {
        let normalized_identity: FlutterEngineIdentity =
            normalize_flutter_engine_symbol_summary(identity, &[])?.0;
        let path: PathBuf = self.entry_path(&normalized_identity)?;
        let bytes: Vec<u8> = match read_bounded(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) if error.kind() == std::io::ErrorKind::InvalidData => return Ok(None),
            Err(error) => return Err(Error::Io(error)),
        };
        let record: CacheRecord = match serde_json::from_slice(&bytes) {
            Ok(record) => record,
            Err(_error) => return Ok(None),
        };
        if record.format != FLUTTER_ENGINE_SYMBOL_CACHE_FORMAT
            || record.version != FLUTTER_ENGINE_SYMBOL_CACHE_VERSION
        {
            return Ok(None);
        }
        let (stored_identity, symbols): (FlutterEngineIdentity, Vec<FlutterEngineSymbol>) =
            match normalize_flutter_engine_symbol_summary(&record.identity, &record.symbols) {
                Ok(summary) => summary,
                Err(_error) => return Ok(None),
            };
        if stored_identity != normalized_identity {
            return Ok(None);
        }
        Ok(Some(symbols))
    }

    pub fn store(
        &self,
        identity: &FlutterEngineIdentity,
        symbols: &[FlutterEngineSymbol],
    ) -> Result<()> {
        let (identity, symbols): (FlutterEngineIdentity, Vec<FlutterEngineSymbol>) =
            normalize_flutter_engine_symbol_summary(identity, symbols)?;
        let record: CacheRecord = CacheRecord {
            format: FLUTTER_ENGINE_SYMBOL_CACHE_FORMAT.to_owned(),
            version: FLUTTER_ENGINE_SYMBOL_CACHE_VERSION,
            identity,
            symbols,
        };
        let encoded: Vec<u8> =
            serde_json::to_vec(&record).map_err(|error: serde_json::Error| {
                Error::FlutterEngineSymbolMapMalformed(error.to_string())
            })?;
        if encoded.len() > FLUTTER_ENGINE_SYMBOL_CACHE_MAX_BYTES {
            return Err(Error::FlutterEngineSymbolMapTooLarge {
                actual: encoded.len(),
                limit: FLUTTER_ENGINE_SYMBOL_CACHE_MAX_BYTES,
            });
        }
        fs::create_dir_all(&self.directory).map_err(Error::Io)?;
        let destination: PathBuf = self.entry_path(&record.identity)?;
        let temporary: PathBuf = Self::temporary_path(&destination);
        let write_result: std::io::Result<()> = (|| {
            let mut file: File = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            file.write_all(&encoded)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, &destination)
        })();
        if let Err(error) = write_result {
            let _removed: bool = fs::remove_file(&temporary).is_ok();
            return Err(Error::Io(error));
        }
        Ok(())
    }

    pub fn store_validated(&self, summary: &ValidatedFlutterEngineSymbolMap) -> Result<()> {
        self.store(summary.identity(), summary.symbols())
    }

    fn entry_path(&self, identity: &FlutterEngineIdentity) -> Result<PathBuf> {
        let (identity, _symbols): (FlutterEngineIdentity, Vec<FlutterEngineSymbol>) =
            normalize_flutter_engine_symbol_summary(identity, &[])?;
        let key: String =
            blake3::hash(format!("{:?}:{}", identity.kind, identity.value).as_bytes())
                .to_hex()
                .to_string();
        Ok(self.directory.join(format!("{key}.json")))
    }

    fn temporary_path(destination: &Path) -> PathBuf {
        let sequence: u64 = NEXT_TEMPORARY_FILE.fetch_add(1, Ordering::Relaxed);
        destination.with_extension(format!("json.{}.{}.tmp", std::process::id(), sequence))
    }
}

fn read_bounded(path: &Path) -> std::io::Result<Vec<u8>> {
    let file: File = File::open(path)?;
    let limit: u64 = (FLUTTER_ENGINE_SYMBOL_CACHE_MAX_BYTES as u64) + 1;
    let mut bytes: Vec<u8> = Vec::with_capacity(8192);
    file.take(limit).read_to_end(&mut bytes)?;
    if bytes.len() > FLUTTER_ENGINE_SYMBOL_CACHE_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Flutter engine symbol cache entry exceeds byte cap",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::fs;

    use super::*;
    use crate::flutter::{
        FlutterEngineIdentity, FlutterEngineSymbol, FlutterEngineSymbolMapIdentityKind,
    };

    fn identity() -> FlutterEngineIdentity {
        FlutterEngineIdentity {
            kind: FlutterEngineSymbolMapIdentityKind::ElfBuildId,
            value: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        }
    }

    fn symbols() -> Vec<FlutterEngineSymbol> {
        vec![FlutterEngineSymbol {
            address: 0x1000,
            name: "Dart_Invoke".to_owned(),
        }]
    }

    fn cache_dir(test: &str) -> std::path::PathBuf {
        let sequence: u64 = NEXT_TEMPORARY_FILE.fetch_add(1, Ordering::Relaxed);
        let directory: std::path::PathBuf = std::env::temp_dir().join(format!(
            "disrobe-flutter-engine-cache-{test}-{}-{sequence}",
            std::process::id(),
        ));
        fs::create_dir_all(&directory).expect("create test cache directory");
        directory
    }

    #[test]
    fn stores_and_loads_a_validated_elf_summary_by_identity() {
        let directory: std::path::PathBuf = cache_dir("round-trip");
        let cache: FlutterEngineSymbolCache = FlutterEngineSymbolCache::new(&directory);
        let identity: FlutterEngineIdentity = identity();

        cache.store(&identity, &symbols()).expect("store summary");
        let loaded: Option<Vec<FlutterEngineSymbol>> = cache.load(&identity).expect("load summary");

        assert_eq!(loaded, Some(symbols()));
        fs::remove_dir_all(directory).expect("remove test cache directory");
    }

    #[test]
    fn treats_corrupt_and_old_entries_as_cache_misses() {
        let directory: std::path::PathBuf = cache_dir("invalid");
        let cache: FlutterEngineSymbolCache = FlutterEngineSymbolCache::new(&directory);
        let identity: FlutterEngineIdentity = identity();
        let path: std::path::PathBuf = cache.entry_path(&identity).expect("entry path");

        fs::write(&path, b"not json").expect("write corrupt entry");
        assert_eq!(cache.load(&identity).expect("corrupt miss"), None);
        fs::write(
            &path,
            br#"{"format":"disrobe.flutter.engine-symbol-cache","version":0,"identity":{"kind":"elf-build-id","value":"0123456789abcdef0123456789abcdef01234567"},"symbols":[]}"#,
        )
        .expect("write old entry");
        assert_eq!(cache.load(&identity).expect("old miss"), None);
        fs::remove_dir_all(directory).expect("remove test cache directory");
    }

    #[test]
    fn treats_an_oversized_entry_as_a_cache_miss() {
        let directory: std::path::PathBuf = cache_dir("oversized");
        let cache: FlutterEngineSymbolCache = FlutterEngineSymbolCache::new(&directory);
        let identity: FlutterEngineIdentity = identity();
        let path: std::path::PathBuf = cache.entry_path(&identity).expect("entry path");

        fs::write(&path, vec![b'x'; FLUTTER_ENGINE_SYMBOL_CACHE_MAX_BYTES + 1])
            .expect("write oversized entry");
        assert_eq!(cache.load(&identity).expect("oversized miss"), None);
        fs::remove_dir_all(directory).expect("remove test cache directory");
    }

    #[test]
    fn concurrent_writers_leave_a_complete_valid_entry() {
        let directory: std::path::PathBuf = cache_dir("concurrent");
        let identity: FlutterEngineIdentity = identity();
        let mut writers: Vec<std::thread::JoinHandle<()>> = Vec::new();
        for _ in 0..4 {
            let directory: std::path::PathBuf = directory.clone();
            let identity: FlutterEngineIdentity = identity.clone();
            writers.push(std::thread::spawn(move || {
                let cache: FlutterEngineSymbolCache = FlutterEngineSymbolCache::new(directory);
                for _ in 0..16 {
                    cache
                        .store(&identity, &symbols())
                        .expect("concurrent store");
                }
            }));
        }
        for writer in writers {
            writer.join().expect("writer thread");
        }

        let cache: FlutterEngineSymbolCache = FlutterEngineSymbolCache::new(&directory);
        assert_eq!(
            cache.load(&identity).expect("load final entry"),
            Some(symbols())
        );
        fs::remove_dir_all(directory).expect("remove test cache directory");
    }
}
