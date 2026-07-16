#![forbid(unsafe_code)]
#![allow(clippy::redundant_pub_crate)]

mod decompress;
mod detect;
mod electron;
mod embedded;
mod error;
mod model;
mod resolve;

pub use detect::detect_family;
pub use disrobe_binfmt::ExtractionQuota;
pub use error::{Error, Result};
pub use model::{
    CarveReport, Compression, IntegrityStatus, RecoveredAsset, SymlinkEntry, WebviewFamily,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

const GIBIBYTE: u64 = 1024 * 1024 * 1024;
const DEFAULT_MAX_ASSETS: usize = 100_000;
const DEFAULT_MAX_SCAN_CANDIDATES: usize = 256;
const DEFAULT_MAX_DEPTH: usize = 64;
const DEFAULT_MAX_TABLE_PROBES: u64 = 32_000_000;

#[derive(Debug, Clone, Copy)]
pub struct CarveConfig {
    pub quota: ExtractionQuota,
    pub max_scan_candidates: usize,
    pub max_depth: usize,
    pub max_table_probes: u64,
}

impl Default for CarveConfig {
    fn default() -> Self {
        Self {
            quota: ExtractionQuota {
                max_entries: DEFAULT_MAX_ASSETS,
                max_total_uncompressed: 4 * GIBIBYTE,
                max_per_entry_uncompressed: 512 * 1024 * 1024,
                max_per_entry_ratio: 100,
                max_aggregate_ratio: 10,
            },
            max_scan_candidates: DEFAULT_MAX_SCAN_CANDIDATES,
            max_depth: DEFAULT_MAX_DEPTH,
            max_table_probes: DEFAULT_MAX_TABLE_PROBES,
        }
    }
}

pub fn carve(bytes: &[u8]) -> Result<Vec<RecoveredAsset>> {
    carve_with_config(bytes, &CarveConfig::default()).map(|report: CarveReport| report.assets)
}

pub fn carve_report(bytes: &[u8]) -> Result<CarveReport> {
    carve_with_config(bytes, &CarveConfig::default())
}

pub fn carve_with_config(bytes: &[u8], cfg: &CarveConfig) -> Result<CarveReport> {
    if electron::locate_header(bytes, cfg.max_scan_candidates).is_some() {
        return electron::extract(bytes, cfg);
    }
    match embedded::scan(bytes, cfg) {
        Ok(assembled) => Ok(CarveReport {
            family: detect::family_guess(bytes),
            assets: assembled.assets,
            external_unpacked: Vec::new(),
            symlinks: Vec::new(),
            directories: assembled.directories,
            declared: assembled.declared,
            recovered: assembled.recovered,
        }),
        Err(Error::NativeParse(_) | Error::NoEmbeddedTable(_)) => match detect_family(bytes) {
            Some(family @ (WebviewFamily::Tauri | WebviewFamily::Wails)) => {
                Err(Error::FamilyNotExtractable { family })
            }
            _ => Err(Error::NotDetected),
        },
        Err(other) => Err(other),
    }
}
