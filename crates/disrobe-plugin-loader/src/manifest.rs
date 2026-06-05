//! Plugin manifest: the allow-list of WIT capabilities a component may import.

use std::collections::BTreeSet;

use serde::Deserialize;
use thiserror::Error;

/// Declarative capability grant for a plugin.
///
/// Parsed from TOML of the form:
///
/// ```toml
/// name = "example-plugin"
/// capabilities = ["wasi:cli/environment", "host:log/info"]
/// ```
///
/// Each entry in `capabilities` is a WIT import name the component is permitted
/// to import. Anything the component imports that is not listed is denied.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Human-readable plugin identity.
    pub name: String,
    /// Set of granted WIT import names.
    #[serde(default)]
    capabilities: BTreeSet<String>,
}

/// Failure parsing a [`Manifest`] from TOML.
#[derive(Debug, Error)]
#[error("invalid plugin manifest: {0}")]
pub struct ManifestError(#[from] toml::de::Error);

impl Manifest {
    /// Construct a manifest directly from a granted-capability set.
    pub fn new(name: impl Into<String>, capabilities: BTreeSet<String>) -> Self {
        Self {
            name: name.into(),
            capabilities,
        }
    }

    /// Parse a manifest from its TOML source.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] when the TOML is malformed or has unknown fields.
    pub fn from_toml(source: &str) -> Result<Self, ManifestError> {
        let manifest: Self = toml::from_str(source)?;
        Ok(manifest)
    }

    /// Whether `capability` is granted by this manifest.
    #[inline]
    pub fn grants(&self, capability: &str) -> bool {
        self.capabilities.contains(capability)
    }

    /// The granted capabilities.
    #[inline]
    pub const fn capabilities(&self) -> &BTreeSet<String> {
        &self.capabilities
    }
}
