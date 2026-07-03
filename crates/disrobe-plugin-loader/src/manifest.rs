use std::collections::BTreeSet;

use serde::Deserialize;
use thiserror::Error;

const MAX_MANIFEST_NAME_BYTES: usize = 128;
const MAX_MANIFEST_TOML_BYTES: usize = 64 * 1024;
const MAX_CAPABILITIES: usize = 128;
const MAX_CAPABILITY_BYTES: usize = 256;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub name: String,

    #[serde(default)]
    capabilities: BTreeSet<String>,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ManifestError {
    #[error("invalid plugin manifest: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("plugin manifest name is empty")]
    EmptyName,
    #[error("plugin manifest name has leading or trailing whitespace")]
    NameWhitespace,
    #[error("plugin manifest name is too large: {len} bytes exceeds {limit}")]
    NameTooLarge { len: usize, limit: usize },
    #[error("plugin manifest name contains a control character: {name}")]
    NameControl { name: String },
    #[error("plugin manifest is too large: {len} bytes exceeds {limit}")]
    ManifestTooLarge { len: usize, limit: usize },
    #[error("plugin manifest grants too many capabilities: {len} exceeds {limit}")]
    TooManyCapabilities { len: usize, limit: usize },
    #[error("plugin manifest capability is empty")]
    EmptyCapability,
    #[error("plugin manifest capability has leading or trailing whitespace: {capability}")]
    CapabilityWhitespace { capability: String },
    #[error("plugin manifest capability is too large: {len} bytes exceeds {limit}")]
    CapabilityTooLarge { len: usize, limit: usize },
    #[error("plugin manifest capability contains a control character: {capability}")]
    CapabilityControl { capability: String },
}

impl Manifest {
    pub fn new(
        name: impl Into<String>,
        capabilities: BTreeSet<String>,
    ) -> Result<Self, ManifestError> {
        let manifest: Self = Self {
            name: name.into(),
            capabilities,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn from_toml(source: &str) -> Result<Self, ManifestError> {
        if source.len() > MAX_MANIFEST_TOML_BYTES {
            return Err(ManifestError::ManifestTooLarge {
                len: source.len(),
                limit: MAX_MANIFEST_TOML_BYTES,
            });
        }
        let manifest: Self = toml::from_str(source)?;
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<(), ManifestError> {
        if self.name.is_empty() {
            return Err(ManifestError::EmptyName);
        }
        if self.name.trim() != self.name {
            return Err(ManifestError::NameWhitespace);
        }
        if self.name.len() > MAX_MANIFEST_NAME_BYTES {
            return Err(ManifestError::NameTooLarge {
                len: self.name.len(),
                limit: MAX_MANIFEST_NAME_BYTES,
            });
        }
        if self.name.chars().any(char::is_control) {
            return Err(ManifestError::NameControl {
                name: self.name.clone(),
            });
        }
        if self.capabilities.len() > MAX_CAPABILITIES {
            return Err(ManifestError::TooManyCapabilities {
                len: self.capabilities.len(),
                limit: MAX_CAPABILITIES,
            });
        }
        for capability in &self.capabilities {
            if capability.is_empty() {
                return Err(ManifestError::EmptyCapability);
            }
            if capability.trim() != capability {
                return Err(ManifestError::CapabilityWhitespace {
                    capability: capability.clone(),
                });
            }
            if capability.len() > MAX_CAPABILITY_BYTES {
                return Err(ManifestError::CapabilityTooLarge {
                    len: capability.len(),
                    limit: MAX_CAPABILITY_BYTES,
                });
            }
            if capability.chars().any(char::is_control) {
                return Err(ManifestError::CapabilityControl {
                    capability: capability.clone(),
                });
            }
        }
        Ok(())
    }

    #[inline]
    #[must_use]
    pub fn grants(&self, capability: &str) -> bool {
        self.capabilities.contains(capability)
    }

    #[inline]
    pub const fn capabilities(&self) -> &BTreeSet<String> {
        &self.capabilities
    }
}
