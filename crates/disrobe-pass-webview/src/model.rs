use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Compression {
    None,
    Zstd,
    Gzip,
}

impl Compression {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Zstd => "zstd",
            Self::Gzip => "gzip",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WebviewFamily {
    Electron,
    Tauri,
    Wails,
}

impl WebviewFamily {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Electron => "electron",
            Self::Tauri => "tauri",
            Self::Wails => "wails",
        }
    }
}

impl fmt::Display for WebviewFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredAsset {
    pub path: String,
    pub bytes: Vec<u8>,
    pub compression: Compression,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarveReport {
    pub family: WebviewFamily,
    pub assets: Vec<RecoveredAsset>,
    pub external_unpacked: Vec<String>,
}
