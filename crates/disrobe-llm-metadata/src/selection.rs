use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::category::Category;
use crate::error::LlmMetadataError;
use crate::pack::Pack;

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum MetadataFormat {
    #[default]
    Json,
    Jsonl,
    Cbor,
    Msgpack,
}

impl MetadataFormat {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Jsonl => "jsonl",
            Self::Cbor => "cbor",
            Self::Msgpack => "msgpack",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataSelection {
    pub pack: Option<Pack>,
    pub categories: BTreeSet<Category>,
    pub excluded: BTreeSet<Category>,
    pub format: MetadataFormat,
    #[serde(default)]
    pub authorized_decryption_keys: bool,
}

impl Default for MetadataSelection {
    fn default() -> Self {
        Self::empty()
    }
}

impl MetadataSelection {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            pack: None,
            categories: BTreeSet::new(),
            excluded: BTreeSet::new(),
            format: MetadataFormat::Json,
            authorized_decryption_keys: false,
        }
    }

    #[must_use]
    pub const fn builder() -> SelectionBuilder {
        SelectionBuilder::new()
    }

    /// Resolve to the final deterministic set of categories.
    ///
    /// Algorithm (matches spec §4.2):
    /// 1. start with `categories`
    /// 2. union with `pack.expand()` if a pack is set
    /// 3. subtract `excluded`
    /// 4. strip `DecryptionKeys` unless `authorized_decryption_keys` is true
    #[must_use]
    pub fn resolved(&self) -> BTreeSet<Category> {
        let mut out: BTreeSet<Category> = self.categories.clone();
        if let Some(pack) = self.pack {
            out.extend(pack.expand());
        }
        for c in &self.excluded {
            out.remove(c);
        }
        if !self.authorized_decryption_keys {
            out.remove(&Category::DecryptionKeys);
        }
        out
    }

    #[inline]
    #[must_use]
    pub fn contains(&self, c: Category) -> bool {
        self.resolved().contains(&c)
    }

    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.resolved().is_empty()
    }

    /// Validate auth invariants without resolving.
    ///
    /// Returns `Err(UnauthorizedDecryptionKeys)` iff `DecryptionKeys` is in
    /// `categories` (explicitly requested by name, not via pack) and
    /// `authorized_decryption_keys` is `false`. Pack-only requests are silently
    /// stripped per spec §4.2 step 7 only when they came from a pack - but the
    /// CLI grammar wants an *error* when the user explicitly asked for the
    /// category without `--i-have-authorization`. Use this for that check.
    pub fn validate_auth(&self) -> Result<(), LlmMetadataError> {
        if self.categories.contains(&Category::DecryptionKeys) && !self.authorized_decryption_keys {
            return Err(LlmMetadataError::UnauthorizedDecryptionKeys);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct SelectionBuilder {
    inner: MetadataSelection,
}

impl SelectionBuilder {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: MetadataSelection::empty(),
        }
    }

    #[must_use]
    pub const fn pack(mut self, pack: Pack) -> Self {
        self.inner.pack = Some(pack);
        self
    }

    #[must_use]
    pub fn category(mut self, c: Category) -> Self {
        self.inner.categories.insert(c);
        self
    }

    #[must_use]
    pub fn categories<I: IntoIterator<Item = Category>>(mut self, iter: I) -> Self {
        self.inner.categories.extend(iter);
        self
    }

    #[must_use]
    pub fn exclude(mut self, c: Category) -> Self {
        self.inner.excluded.insert(c);
        self
    }

    #[must_use]
    pub fn excludes<I: IntoIterator<Item = Category>>(mut self, iter: I) -> Self {
        self.inner.excluded.extend(iter);
        self
    }

    #[must_use]
    pub const fn format(mut self, fmt: MetadataFormat) -> Self {
        self.inner.format = fmt;
        self
    }

    #[must_use]
    pub const fn authorize_decryption_keys(mut self) -> Self {
        self.inner.authorized_decryption_keys = true;
        self
    }

    #[must_use]
    pub fn build(self) -> MetadataSelection {
        self.inner
    }
}
