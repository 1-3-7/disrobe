#![forbid(unsafe_code)]
#![allow(clippy::redundant_pub_crate)]

pub mod chain_detector;
mod decompress;
mod detect;
mod electron;
mod embedded;
mod error;
mod model;
mod resolve;

use disrobe_binfmt::{ContainerKind, detect_container};

pub use detect::{FamilyEvidence, classify, classify_all, detect_family};
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
const DEFAULT_MAX_EXPANSION_RATIO: u64 = 100;

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
                max_per_entry_ratio: DEFAULT_MAX_EXPANSION_RATIO,
                max_aggregate_ratio: DEFAULT_MAX_EXPANSION_RATIO,
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
            family: detect::embedded_family(bytes),
            assets: assembled.assets,
            external_unpacked: Vec::new(),
            symlinks: Vec::new(),
            directories: assembled.directories,
            declared: assembled.declared,
            recovered: assembled.recovered,
        }),
        Err(reason @ (Error::NativeParse(_) | Error::NoEmbeddedTable(_))) => {
            if let Some(container) = packaged_container(bytes) {
                return Err(Error::PackagedContainer { container });
            }
            match detect::embedded_family(bytes) {
                WebviewFamily::Unknown => Err(Error::NotDetected),
                family => Err(Error::FamilyNotExtractable {
                    family,
                    detail: reason.to_string(),
                }),
            }
        }
        Err(other) => Err(other),
    }
}

fn packaged_container(bytes: &[u8]) -> Option<&'static str> {
    detect_container(bytes)
        .filter(|kind: &ContainerKind| !matches!(*kind, ContainerKind::None))
        .map(ContainerKind::label)
}
