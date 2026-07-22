use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const CACHE_FORMAT_VERSION: u32 = 1;

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

const ENTRY_MAGIC: &[u8; 8] = b"DRCACHE\0";
const ENTRY_HEADER_SIZE: usize = 8 + 32;
const MAX_CACHE_ENTRY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CACHE_ENTRY_PREALLOC: usize = 8 * 1024 * 1024;
use crate::codec::hex::push_byte as push_lower_hex_byte;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheKey {
    digest: [u8; 32],
}

impl CacheKey {
    #[must_use]
    pub fn hex(&self) -> String {
        let mut out: String = String::with_capacity(64);
        for &byte in &self.digest {
            push_lower_hex_byte(&mut out, byte);
        }
        out
    }

    #[inline]
    #[must_use]
    pub const fn bytes(&self) -> &[u8; 32] {
        &self.digest
    }
}

#[derive(Debug, Default)]
pub struct CacheKeyBuilder {
    hasher: blake3::Hasher,
}

impl CacheKeyBuilder {
    #[must_use]
    pub fn new(operation: &str) -> Self {
        let mut hasher: blake3::Hasher = blake3::Hasher::new();
        write_field(&mut hasher, b"disrobe-cache-key");
        write_u32(&mut hasher, CACHE_FORMAT_VERSION);
        write_field(&mut hasher, crate::VERSION.as_bytes());
        write_field(&mut hasher, operation.as_bytes());
        Self { hasher }
    }

    pub fn field(&mut self, label: &str, value: &[u8]) -> &mut Self {
        write_field(&mut self.hasher, label.as_bytes());
        write_field(&mut self.hasher, value);
        self
    }

    #[must_use]
    pub fn input(mut self, bytes: &[u8]) -> CacheKey {
        write_field(&mut self.hasher, b"input");
        write_field(&mut self.hasher, bytes);
        CacheKey {
            digest: *self.hasher.finalize().as_bytes(),
        }
    }
}

#[inline]
fn write_u32(hasher: &mut blake3::Hasher, value: u32) {
    hasher.update(&value.to_le_bytes());
}

#[inline]
fn write_field(hasher: &mut blake3::Hasher, value: &[u8]) {
    let len: u64 = value.len() as u64;
    hasher.update(&len.to_le_bytes());
    hasher.update(value);
}

#[derive(Debug, Clone)]
pub struct Cache {
    root: PathBuf,
}

impl Cache {
    #[must_use]
    pub const fn new(root: PathBuf) -> Self {
        Self { root }
    }

    #[must_use]
    pub fn at_default_dir() -> Option<Self> {
        default_cache_dir().map(Self::new)
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn entry_path(&self, key: &CacheKey) -> PathBuf {
        let hex: String = key.hex();
        let shard: &str = &hex[..2];
        self.root
            .join(format!("dr-cache-v{CACHE_FORMAT_VERSION}"))
            .join(shard)
            .join(format!("{hex}.drc"))
    }

    #[must_use]
    pub fn get(&self, key: &CacheKey) -> Option<Vec<u8>> {
        let path: PathBuf = self.entry_path(key);
        let raw: Vec<u8> = read_entry_file(&path)?;
        decode_entry(&raw)
    }

    pub fn put(&self, key: &CacheKey, payload: &[u8]) -> std::io::Result<()> {
        let path: PathBuf = self.entry_path(key);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let encoded: Vec<u8> = encode_entry(payload);
        let tmp: PathBuf = temp_sibling(&path);
        std::fs::write(&tmp, &encoded)?;
        match std::fs::rename(&tmp, &path) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _: std::io::Result<()> = std::fs::remove_file(&tmp);
                Err(e)
            }
        }
    }
}

fn temp_sibling(path: &Path) -> PathBuf {
    let pid: u32 = std::process::id();
    let seq: u64 = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let stem: &str = path
        .file_name()
        .and_then(|s: &std::ffi::OsStr| s.to_str())
        .map_or("entry", std::convert::identity);
    let name: String = format!(".{stem}.{pid}.{seq}.tmp");
    match path.parent() {
        Some(dir) => dir.join(name),
        None => PathBuf::from(name),
    }
}

fn read_entry_file(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read as _;

    let file: std::fs::File = std::fs::File::open(path).ok()?;
    let file_len: u64 = file.metadata().ok()?.len();
    if file_len > MAX_CACHE_ENTRY_BYTES {
        return None;
    }
    let prealloc: usize = usize::try_from(file_len)
        .map_or(MAX_CACHE_ENTRY_PREALLOC, |len: usize| {
            len.min(MAX_CACHE_ENTRY_PREALLOC)
        });
    let mut raw: Vec<u8> = Vec::with_capacity(prealloc);
    let mut limited: std::io::Take<std::fs::File> = file.take(MAX_CACHE_ENTRY_BYTES + 1);
    let _: usize = limited.read_to_end(&mut raw).ok()?;
    let observed: u64 = u64::try_from(raw.len()).ok()?;
    if observed > MAX_CACHE_ENTRY_BYTES {
        return None;
    }
    Some(raw)
}

fn encode_entry(payload: &[u8]) -> Vec<u8> {
    let digest: [u8; 32] = *blake3::hash(payload).as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(ENTRY_HEADER_SIZE + payload.len());
    out.extend_from_slice(ENTRY_MAGIC);
    out.extend_from_slice(&digest);
    out.extend_from_slice(payload);
    out
}

fn decode_entry(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() < ENTRY_HEADER_SIZE {
        return None;
    }
    let magic: &[u8] = raw.get(0..8)?;
    if magic != ENTRY_MAGIC {
        return None;
    }
    let stored_digest: &[u8] = raw.get(8..ENTRY_HEADER_SIZE)?;
    let payload: &[u8] = raw.get(ENTRY_HEADER_SIZE..)?;
    let computed: [u8; 32] = *blake3::hash(payload).as_bytes();
    if computed.as_slice() != stored_digest {
        return None;
    }
    Some(payload.to_vec())
}

#[must_use]
pub fn default_cache_dir() -> Option<PathBuf> {
    if let Some(explicit) = non_empty_env("DISROBE_CACHE_DIR") {
        return Some(PathBuf::from(explicit).join("disrobe"));
    }
    base_cache_dir().map(|base: PathBuf| base.join("disrobe"))
}

#[cfg(target_os = "windows")]
fn base_cache_dir() -> Option<PathBuf> {
    non_empty_env("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| non_empty_env("APPDATA").map(PathBuf::from))
        .or_else(|| {
            non_empty_env("USERPROFILE")
                .map(|p: String| PathBuf::from(p).join("AppData").join("Local"))
        })
}

#[cfg(target_os = "macos")]
fn base_cache_dir() -> Option<PathBuf> {
    non_empty_env("HOME").map(|home: String| PathBuf::from(home).join("Library").join("Caches"))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn base_cache_dir() -> Option<PathBuf> {
    if let Some(xdg) = non_empty_env("XDG_CACHE_HOME") {
        return Some(PathBuf::from(xdg));
    }
    non_empty_env("HOME").map(|home: String| PathBuf::from(home).join(".cache"))
}

#[inline]
fn non_empty_env(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => Some(value),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn scratch_dir(stem: &str) -> PathBuf {
        let pid: u32 = std::process::id();
        let n: u64 = SEQ.fetch_add(1, Ordering::Relaxed);
        let p: PathBuf = std::env::temp_dir().join(format!("disrobe-cache-test-{stem}-{pid}-{n}"));
        let _: std::io::Result<()> = std::fs::remove_dir_all(&p);
        p
    }

    fn key_for(op: &str, config: &str, input: &[u8]) -> CacheKey {
        let mut b: CacheKeyBuilder = CacheKeyBuilder::new(op);
        b.field("config", config.as_bytes());
        b.input(input)
    }

    #[test]
    fn miss_then_hit_returns_identical_payload() {
        let cache: Cache = Cache::new(scratch_dir("hit"));
        let key: CacheKey = key_for("envelope.create", "rung=raw", b"hello world");
        assert!(cache.get(&key).is_none(), "cold lookup must miss");
        let payload: &[u8] = b"\x00\x01\x02 produced .dr bytes";
        cache.put(&key, payload).expect("store");
        let got: Vec<u8> = cache.get(&key).expect("warm lookup must hit");
        assert_eq!(got.as_slice(), payload);
        let _ = std::fs::remove_dir_all(cache.root());
    }

    #[test]
    fn different_input_misses() {
        let cache: Cache = Cache::new(scratch_dir("input"));
        let k1: CacheKey = key_for("op", "cfg", b"aaaa");
        let k2: CacheKey = key_for("op", "cfg", b"bbbb");
        cache.put(&k1, b"one").expect("store");
        assert!(cache.get(&k2).is_none(), "distinct input must not hit");
        let _ = std::fs::remove_dir_all(cache.root());
    }

    #[test]
    fn different_config_misses() {
        let cache: Cache = Cache::new(scratch_dir("config"));
        let k1: CacheKey = key_for("op", "rung=raw", b"same");
        let k2: CacheKey = key_for("op", "rung=disasm", b"same");
        cache.put(&k1, b"one").expect("store");
        assert!(cache.get(&k2).is_none(), "distinct config must not hit");
        let _ = std::fs::remove_dir_all(cache.root());
    }

    #[test]
    fn different_operation_misses() {
        let cache: Cache = Cache::new(scratch_dir("op"));
        let k1: CacheKey = key_for("op.a", "cfg", b"same");
        let k2: CacheKey = key_for("op.b", "cfg", b"same");
        cache.put(&k1, b"one").expect("store");
        assert!(cache.get(&k2).is_none(), "distinct operation must not hit");
        let _ = std::fs::remove_dir_all(cache.root());
    }

    #[test]
    fn field_boundary_is_unambiguous() {
        let a: CacheKey = key_for("op", "ab", b"c");
        let b: CacheKey = key_for("op", "a", b"bc");
        assert_ne!(
            a.hex(),
            b.hex(),
            "length-prefixed fields must not collide on shifted boundaries"
        );
    }

    #[test]
    fn corrupt_entry_is_a_miss() {
        let cache: Cache = Cache::new(scratch_dir("corrupt"));
        let key: CacheKey = key_for("op", "cfg", b"payload");
        cache.put(&key, b"the original payload").expect("store");
        let path: PathBuf = cache.entry_path(&key);
        let mut raw: Vec<u8> = std::fs::read(&path).expect("read back");
        let last: usize = raw.len() - 1;
        raw[last] ^= 0xFF;
        std::fs::write(&path, &raw).expect("corrupt write");
        assert!(
            cache.get(&key).is_none(),
            "a tampered payload must be treated as a miss"
        );
        let _ = std::fs::remove_dir_all(cache.root());
    }

    #[test]
    fn truncated_entry_is_a_miss() {
        let cache: Cache = Cache::new(scratch_dir("trunc"));
        let key: CacheKey = key_for("op", "cfg", b"payload");
        cache.put(&key, b"some bytes here").expect("store");
        let path: PathBuf = cache.entry_path(&key);
        std::fs::write(&path, b"DRC").expect("truncate");
        assert!(cache.get(&key).is_none(), "short entry must miss");
        let _ = std::fs::remove_dir_all(cache.root());
    }

    #[test]
    fn bad_magic_entry_is_a_miss() {
        let cache: Cache = Cache::new(scratch_dir("magic"));
        let key: CacheKey = key_for("op", "cfg", b"payload");
        let mut bogus: Vec<u8> = vec![0u8; ENTRY_HEADER_SIZE + 4];
        bogus[0] = b'X';
        let path: PathBuf = cache.entry_path(&key);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, &bogus).expect("write bogus");
        assert!(cache.get(&key).is_none(), "wrong magic must miss");
        let _ = std::fs::remove_dir_all(cache.root());
    }

    #[test]
    fn oversized_entry_file_is_a_miss() {
        let cache: Cache = Cache::new(scratch_dir("oversized"));
        let key: CacheKey = key_for("op", "cfg", b"payload");
        let path: PathBuf = cache.entry_path(&key);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        let file: std::fs::File = std::fs::File::create(&path).expect("create");
        file.set_len(MAX_CACHE_ENTRY_BYTES + 1).expect("set len");
        assert!(
            cache.get(&key).is_none(),
            "oversized cache entries must miss before payload allocation"
        );
        let _ = std::fs::remove_dir_all(cache.root());
    }

    #[test]
    fn put_is_idempotent_and_overwrites() {
        let cache: Cache = Cache::new(scratch_dir("idem"));
        let key: CacheKey = key_for("op", "cfg", b"x");
        cache.put(&key, b"first").expect("first");
        cache.put(&key, b"first").expect("second identical");
        let got: Vec<u8> = cache.get(&key).expect("hit");
        assert_eq!(got.as_slice(), b"first");
        let _ = std::fs::remove_dir_all(cache.root());
    }

    #[test]
    fn entry_path_is_sharded_and_versioned() {
        let cache: Cache = Cache::new(PathBuf::from("/tmp/root"));
        let key: CacheKey = key_for("op", "cfg", b"abc");
        let path: PathBuf = cache.entry_path(&key);
        let hex: String = key.hex();
        let shard: &str = &hex[0..2];
        let as_str: String = path.display().to_string();
        assert!(
            as_str.contains(&format!("dr-cache-v{CACHE_FORMAT_VERSION}")),
            "path must be format-version namespaced: {as_str}"
        );
        assert!(
            path.ends_with(format!("{shard}/{hex}.drc"))
                || path.ends_with(format!("{shard}\\{hex}.drc")),
            "path must shard by the first hex byte: {as_str}"
        );
    }
}
