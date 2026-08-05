use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Compression {
    None,
    Zstd,
    Gzip,
    Brotli,
}

impl Compression {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Zstd => "zstd",
            Self::Gzip => "gzip",
            Self::Brotli => "brotli",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WebviewFamily {
    Electron,
    Tauri,
    Wails,
    Unknown,
}

impl WebviewFamily {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Electron => "electron",
            Self::Tauri => "tauri",
            Self::Wails => "wails",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for WebviewFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntegrityStatus {
    Absent,
    Verified,
    Mismatch,
}

impl IntegrityStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Verified => "verified",
            Self::Mismatch => "mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredAsset {
    pub path: String,
    pub bytes: Vec<u8>,
    pub compression: Compression,
    pub executable: bool,
    pub integrity: IntegrityStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymlinkEntry {
    pub path: String,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarveReport {
    pub family: WebviewFamily,
    pub assets: Vec<RecoveredAsset>,
    pub external_unpacked: Vec<String>,
    pub symlinks: Vec<SymlinkEntry>,
    pub directories: Vec<String>,
    pub declared: usize,
    pub recovered: usize,
}

impl CarveReport {
    #[must_use]
    pub fn coverage(&self) -> f64 {
        if self.declared == 0 {
            return 1.0;
        }
        self.recovered as f64 / self.declared as f64
    }
}
