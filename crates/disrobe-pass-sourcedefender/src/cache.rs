use std::collections::BTreeMap;

use crate::codec::{basename_of, strip_extension};
use crate::envelope::{DecryptedPye, decrypt_pye_with_key};
use crate::error::Result;
use crate::kdf::{DerivedKey, derive_aes_key};

#[derive(Debug, Default)]
pub struct KeyCache {
    inner: BTreeMap<String, DerivedKey>,
    hits: u64,
    misses: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyCacheStats {
    pub entries: usize,
    pub hits: u64,
    pub misses: u64,
}

impl KeyCache {
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn get_or_derive(&mut self, filename: &str) -> Result<DerivedKey> {
        let basename: String = strip_extension(basename_of(filename)).to_owned();
        if let Some(key) = self.inner.get(&basename) {
            self.hits += 1;
            return Ok(*key);
        }
        self.misses += 1;
        let key: DerivedKey = derive_aes_key(&basename)?;
        self.inner.insert(basename, key);
        Ok(key)
    }

    #[inline]
    pub fn decrypt(&mut self, input: &[u8], filename: &str) -> Result<DecryptedPye> {
        let key: DerivedKey = self.get_or_derive(filename)?;
        decrypt_pye_with_key(input, filename, &key)
    }

    #[inline]
    #[must_use]
    pub fn stats(&self) -> KeyCacheStats {
        KeyCacheStats {
            entries: self.inner.len(),
            hits: self.hits,
            misses: self.misses,
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
        self.hits = 0;
        self.misses = 0;
    }

    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[inline]
    #[must_use]
    pub fn contains(&self, filename: &str) -> bool {
        let basename: &str = strip_extension(basename_of(filename));
        self.inner.contains_key(basename)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_starts_empty() {
        let cache: KeyCache = KeyCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        let stats: KeyCacheStats = cache.stats();
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
    }

    #[test]
    fn first_access_is_a_miss() {
        let mut cache: KeyCache = KeyCache::new();
        let _: Result<DerivedKey> = cache.get_or_derive("module.pye");
        let stats: KeyCacheStats = cache.stats();
        assert_eq!(stats.entries, 1);
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn second_access_is_a_hit() {
        let mut cache: KeyCache = KeyCache::new();
        let Ok(a): Result<DerivedKey> = cache.get_or_derive("module.pye") else {
            unreachable!("first derive failed")
        };
        let Ok(b): Result<DerivedKey> = cache.get_or_derive("module.pye") else {
            unreachable!("second derive failed")
        };
        assert_eq!(a, b);
        let stats: KeyCacheStats = cache.stats();
        assert_eq!(stats.entries, 1);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn distinct_basenames_create_distinct_entries() {
        let mut cache: KeyCache = KeyCache::new();
        let _: Result<DerivedKey> = cache.get_or_derive("a.pye");
        let _: Result<DerivedKey> = cache.get_or_derive("b.pye");
        assert_eq!(cache.len(), 2);
        assert!(cache.contains("a.pye"));
        assert!(cache.contains("b.pye"));
        assert!(!cache.contains("c.pye"));
    }

    #[test]
    fn path_components_are_stripped() {
        let mut cache: KeyCache = KeyCache::new();
        let _: Result<DerivedKey> = cache.get_or_derive("a/b/c.pye");
        let _: Result<DerivedKey> = cache.get_or_derive("c.pye");
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.stats().hits, 1);
    }

    #[test]
    fn clear_resets_state() {
        let mut cache: KeyCache = KeyCache::new();
        let _: Result<DerivedKey> = cache.get_or_derive("x.pye");
        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(
            cache.stats(),
            KeyCacheStats {
                entries: 0,
                hits: 0,
                misses: 0
            }
        );
    }
}
