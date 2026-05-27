use std::collections::BTreeMap;

use blake3::Hasher;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CacheKey(pub [u8; 32]);

impl CacheKey {
    pub fn from_trailer_and_prefix(trailer: &[u8], code_prefix: &[u8], nonce: &[u8; 12]) -> Self {
        let mut hasher: Hasher = Hasher::new();
        hasher.update(b"disrobe.pyarmor.descriptor.v1");
        hasher.update(&(trailer.len() as u64).to_le_bytes());
        hasher.update(trailer);
        hasher.update(&(code_prefix.len() as u64).to_le_bytes());
        hasher.update(code_prefix);
        hasher.update(nonce);
        Self(hasher.finalize().into())
    }
}

#[derive(Debug, Clone)]
pub struct CachedDescriptor {
    pub keystream: Vec<u8>,
    pub begin: usize,
    pub length: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct DescriptorCacheConfig {
    pub max_entries: usize,
    pub max_keystream_bytes: usize,
}

impl Default for DescriptorCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 512,
            max_keystream_bytes: 8 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DescriptorCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub inserted: u64,
    pub rejected_oversized: u64,
}

#[derive(Debug)]
pub struct DescriptorCache {
    config: DescriptorCacheConfig,
    entries: BTreeMap<CacheKey, (u64, CachedDescriptor)>,
    age_counter: u64,
    bytes_in_cache: usize,
    stats: DescriptorCacheStats,
}

impl DescriptorCache {
    pub fn new(config: DescriptorCacheConfig) -> Self {
        Self {
            config,
            entries: BTreeMap::new(),
            age_counter: 0,
            bytes_in_cache: 0,
            stats: DescriptorCacheStats::default(),
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(DescriptorCacheConfig::default())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub const fn stats(&self) -> &DescriptorCacheStats {
        &self.stats
    }

    pub fn get(&mut self, key: &CacheKey) -> Option<CachedDescriptor> {
        let Some((age, descriptor)): Option<&mut (u64, CachedDescriptor)> =
            self.entries.get_mut(key)
        else {
            self.stats.misses += 1;
            return None;
        };
        self.age_counter += 1;
        *age = self.age_counter;
        self.stats.hits += 1;
        Some(descriptor.clone())
    }

    pub fn insert(&mut self, key: CacheKey, descriptor: CachedDescriptor) {
        if descriptor.keystream.len() > self.config.max_keystream_bytes {
            self.stats.rejected_oversized += 1;
            return;
        }
        if let Some((_, old)) = self.entries.remove(&key) {
            self.bytes_in_cache = self.bytes_in_cache.saturating_sub(old.keystream.len());
        }
        self.evict_until_room_for(descriptor.keystream.len());
        self.age_counter += 1;
        self.bytes_in_cache = self
            .bytes_in_cache
            .saturating_add(descriptor.keystream.len());
        self.entries.insert(key, (self.age_counter, descriptor));
        self.stats.inserted += 1;
    }

    fn evict_until_room_for(&mut self, incoming_size: usize) {
        while self.entries.len() >= self.config.max_entries
            || self.bytes_in_cache.saturating_add(incoming_size) > self.config.max_keystream_bytes
        {
            if self.entries.is_empty() {
                break;
            }
            let Some(victim_key): Option<CacheKey> = self.find_lru_key() else {
                break;
            };
            if let Some((_, victim)) = self.entries.remove(&victim_key) {
                self.bytes_in_cache = self.bytes_in_cache.saturating_sub(victim.keystream.len());
                self.stats.evictions += 1;
            }
        }
    }

    fn find_lru_key(&self) -> Option<CacheKey> {
        let mut best: Option<(u64, CacheKey)> = None;
        for (k, (age, _)) in &self.entries {
            if !matches!(best, Some((best_age, _)) if best_age <= *age) {
                best = Some((*age, *k));
            }
        }
        best.map(|(_, k)| k)
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.bytes_in_cache = 0;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn descriptor(size: usize) -> CachedDescriptor {
        CachedDescriptor {
            keystream: vec![0xAB; size],
            begin: 0,
            length: size,
        }
    }

    #[test]
    fn cache_key_differs_when_nonce_differs() {
        let a: CacheKey = CacheKey::from_trailer_and_prefix(&[1, 2, 3], &[9, 8], &[0u8; 12]);
        let b: CacheKey = CacheKey::from_trailer_and_prefix(&[1, 2, 3], &[9, 8], &[1u8; 12]);
        assert_ne!(a, b);
    }

    #[test]
    fn cache_key_stable_for_same_inputs() {
        let a: CacheKey = CacheKey::from_trailer_and_prefix(&[1, 2], &[3], &[7u8; 12]);
        let b: CacheKey = CacheKey::from_trailer_and_prefix(&[1, 2], &[3], &[7u8; 12]);
        assert_eq!(a, b);
    }

    #[test]
    fn hit_miss_counters_increment() {
        let mut cache: DescriptorCache = DescriptorCache::with_default_config();
        let key: CacheKey = CacheKey([0u8; 32]);
        assert!(cache.get(&key).is_none());
        assert_eq!(cache.stats().misses, 1);
        cache.insert(key, descriptor(32));
        assert!(cache.get(&key).is_some());
        assert_eq!(cache.stats().hits, 1);
    }

    #[test]
    fn lru_evicts_oldest_when_capacity_hit() {
        let mut cache: DescriptorCache = DescriptorCache::new(DescriptorCacheConfig {
            max_entries: 2,
            max_keystream_bytes: 1024,
        });
        let k1: CacheKey = CacheKey([1u8; 32]);
        let k2: CacheKey = CacheKey([2u8; 32]);
        let k3: CacheKey = CacheKey([3u8; 32]);
        cache.insert(k1, descriptor(8));
        cache.insert(k2, descriptor(8));
        let _ = cache.get(&k1);
        cache.insert(k3, descriptor(8));
        assert!(cache.get(&k2).is_none());
        assert!(cache.get(&k1).is_some());
        assert!(cache.get(&k3).is_some());
        assert!(cache.stats().evictions >= 1);
    }

    #[test]
    fn oversized_keystream_is_rejected_not_panic() {
        let mut cache: DescriptorCache = DescriptorCache::new(DescriptorCacheConfig {
            max_entries: 16,
            max_keystream_bytes: 64,
        });
        cache.insert(CacheKey([7u8; 32]), descriptor(128));
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.stats().rejected_oversized, 1);
    }
}
