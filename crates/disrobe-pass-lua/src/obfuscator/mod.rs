pub mod aztup_brew;
pub mod boronide;
pub mod darksec;
pub mod ironbrew2;
pub mod luaobfuscator_com;
pub mod moonsec_v1;
pub mod moonsec_v2;
pub mod moonsec_v3;
pub mod prometheus;
pub mod psu;
pub mod string_decode;
pub mod wearedevs;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LuaObfuscatorKind {
    Prometheus,
    MoonSecV1,
    MoonSecV2,
    MoonSecV3,
    Ironbrew2,
    AztupBrew,
    DarkSec,
    Boronide,
    Psu,
    WeAreDevs,
    LuaObfuscatorCom,
}

impl LuaObfuscatorKind {
    #[inline]
    #[must_use]
    pub const fn requires_authorization(self) -> bool {
        matches!(self, Self::MoonSecV3 | Self::Ironbrew2)
    }

    #[inline]
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Prometheus => "Prometheus",
            Self::MoonSecV1 => "MoonSec V1",
            Self::MoonSecV2 => "MoonSec V2",
            Self::MoonSecV3 => "MoonSec V3",
            Self::Ironbrew2 => "Ironbrew2",
            Self::AztupBrew => "AztupBrew",
            Self::DarkSec => "DarkSec",
            Self::Boronide => "Boronide",
            Self::Psu => "PSU",
            Self::WeAreDevs => "WeAreDevs LuaU",
            Self::LuaObfuscatorCom => "luaobfuscator.com",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObfuscatorDetection {
    pub kind: LuaObfuscatorKind,
    pub variant: Option<String>,
    pub confidence: u8,
    pub markers: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DeobfOptions {
    pub i_have_authorization: bool,
    pub strict: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeelResult {
    pub deobfuscated: Vec<u8>,
    pub passes_run: Vec<String>,
    pub residual_markers: Vec<String>,
    #[serde(default)]
    pub recovered_strings: Vec<String>,
    #[serde(default)]
    pub fully_recovered: bool,
}

impl PeelResult {
    #[must_use]
    pub fn passthrough(src: &[u8], residual_markers: Vec<String>) -> Self {
        Self {
            deobfuscated: src.to_vec(),
            passes_run: Vec::new(),
            residual_markers,
            recovered_strings: Vec::new(),
            fully_recovered: false,
        }
    }
}
