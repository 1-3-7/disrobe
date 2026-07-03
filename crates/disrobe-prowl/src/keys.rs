use std::collections::BTreeMap;
use std::fmt;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use crate::model::Source;

const MAX_CONFIG_BYTES: u64 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOrigin {
    Flag,
    Env,
    Keyring,
    ConfigFile,
}

impl KeyOrigin {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Flag => "flag",
            Self::Env => "env",
            Self::Keyring => "keyring",
            Self::ConfigFile => "config-file",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ApiKey {
    value: String,
    origin: KeyOrigin,
}

impl ApiKey {
    #[must_use]
    pub const fn new(value: String, origin: KeyOrigin) -> Self {
        Self { value, origin }
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.value
    }

    #[inline]
    #[must_use]
    pub const fn origin(&self) -> KeyOrigin {
        self.origin
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKey")
            .field("value", &redact(&self.value))
            .field("origin", &self.origin.label())
            .finish()
    }
}

impl fmt::Display for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&redact(&self.value))
    }
}

/// Masks a key to `head...<redacted N chars>`, reusing the disrobe-core secret-shaped guard
/// so every prowl key prints identically to the rest of the suite's debug output.
#[must_use]
pub fn redact(value: &str) -> String {
    let trimmed: &str = value.trim();
    if trimmed.is_empty() {
        return "<empty>".to_owned();
    }
    let len: usize = trimmed.chars().count();
    if len <= 8 {
        return format!("<redacted {len} chars>");
    }
    let head: String = trimmed.chars().take(4).collect();
    let guarded: String = disrobe_core::debug::guard_secret_shaped(trimmed);
    if guarded == trimmed {
        format!("{head}\u{2026}<redacted {len} chars>")
    } else {
        guarded
    }
}

#[must_use]
pub fn keyring_service(source: Source) -> String {
    format!("disrobe-prowl:{}", source.label())
}

/// Whether the source can authenticate with an API key, and whether that key is mandatory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPolicy {
    None,
    Optional,
    Required,
}

#[must_use]
pub const fn auth_policy(source: Source) -> AuthPolicy {
    match source {
        Source::Wayback | Source::CommonCrawl | Source::Crtsh => AuthPolicy::None,
        Source::Otx | Source::Urlscan => AuthPolicy::Optional,
        Source::Urlhaus | Source::Threatfox | Source::Virustotal => AuthPolicy::Required,
    }
}

/// The conventional environment-variable name each service publishes, accepted in addition to
/// the uniform `PROWL_<PROVIDER>_API_KEY`.
#[must_use]
pub const fn conventional_env(source: Source) -> Option<&'static str> {
    match source {
        Source::Virustotal => Some("VT_API_KEY"),
        Source::Urlscan => Some("URLSCAN_API_KEY"),
        Source::Otx => Some("OTX_API_KEY"),
        Source::Urlhaus => Some("URLHAUS_AUTH_KEY"),
        Source::Threatfox => Some("THREATFOX_AUTH_KEY"),
        _ => None,
    }
}

#[must_use]
pub fn prowl_env(source: Source) -> String {
    format!("PROWL_{}_API_KEY", source.label().to_ascii_uppercase())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    ConfigPermissions { path: PathBuf, mode: u32 },
    ConfigTooLarge { path: PathBuf, bytes: u64, max: u64 },
    ConfigParse { path: PathBuf, detail: String },
    Keyring(String),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigPermissions { path, mode } => write!(
                f,
                "config file {} is group/world-readable (mode {mode:o}); chmod 600 it or remove the key",
                path.display()
            ),
            Self::ConfigTooLarge { path, bytes, max } => write!(
                f,
                "config file {} is {bytes} bytes, above the {max} byte cap",
                path.display()
            ),
            Self::ConfigParse { path, detail } => {
                write!(f, "config file {}: {detail}", path.display())
            }
            Self::Keyring(detail) => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for KeyError {}

#[derive(Debug, Clone, Default)]
pub struct FlagKeys {
    map: BTreeMap<Source, String>,
}

impl FlagKeys {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, source: Source, value: String) {
        self.map.insert(source, value);
    }

    #[must_use]
    pub fn get(&self, source: Source) -> Option<&str> {
        self.map.get(&source).map(String::as_str)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

pub trait KeyringBackend: Send + Sync + std::fmt::Debug {
    fn get(&self, service: &str, account: &str) -> Result<Option<String>, KeyError>;
    fn set(&self, service: &str, account: &str, secret: &str) -> Result<(), KeyError>;
    fn delete(&self, service: &str, account: &str) -> Result<(), KeyError>;
}

#[must_use]
pub fn default_config_path() -> Option<PathBuf> {
    config_dir().map(|dir: PathBuf| dir.join("disrobe").join("prowl.toml"))
}

#[cfg(target_os = "windows")]
#[must_use]
fn config_dir() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(PathBuf::from)
}

#[cfg(target_os = "macos")]
#[must_use]
fn config_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home: std::ffi::OsString| {
        PathBuf::from(home)
            .join("Library")
            .join("Application Support")
    })
}

#[cfg(all(unix, not(target_os = "macos")))]
#[must_use]
fn config_dir() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(xdg));
    }
    std::env::var_os("HOME").map(|home: std::ffi::OsString| PathBuf::from(home).join(".config"))
}

/// Parses a `prowl.toml` whose `[keys]` table maps a source label to its key. On unix the file
/// is refused if any group/other bit is set, so a leaked key never silently loads.
pub fn config_keys_at(path: &PathBuf) -> Result<BTreeMap<Source, String>, KeyError> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let meta: std::fs::Metadata = std::fs::metadata(path).map_err(|e| KeyError::ConfigParse {
        path: path.clone(),
        detail: e.to_string(),
    })?;
    let bytes: u64 = meta.len();
    if bytes > MAX_CONFIG_BYTES {
        return Err(KeyError::ConfigTooLarge {
            path: path.clone(),
            bytes,
            max: MAX_CONFIG_BYTES,
        });
    }
    check_config_perms(path, &meta)?;
    let text: String = read_config_text(path, MAX_CONFIG_BYTES)?;
    let parsed: toml::Value = toml::from_str(&text).map_err(|e| KeyError::ConfigParse {
        path: path.clone(),
        detail: e.to_string(),
    })?;
    let mut out: BTreeMap<Source, String> = BTreeMap::new();
    if let Some(table) = parsed.get("keys").and_then(toml::Value::as_table) {
        for (label, value) in table {
            if let (Some(source), Some(key)) = (Source::from_label(label), value.as_str())
                && !key.trim().is_empty()
            {
                out.insert(source, key.trim().to_owned());
            }
        }
    }
    Ok(out)
}

fn read_config_text(path: &Path, max: u64) -> Result<String, KeyError> {
    let file: std::fs::File = std::fs::File::open(path).map_err(|e| KeyError::ConfigParse {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;
    let mut limited: std::io::Take<std::fs::File> = file.take(max.saturating_add(1));
    let mut bytes: Vec<u8> = Vec::new();
    let read_len: usize = limited
        .read_to_end(&mut bytes)
        .map_err(|e| KeyError::ConfigParse {
            path: path.to_path_buf(),
            detail: e.to_string(),
        })?;
    let read_len_u64: u64 = u64::try_from(read_len).unwrap_or(u64::MAX);
    if read_len_u64 > max {
        return Err(KeyError::ConfigTooLarge {
            path: path.to_path_buf(),
            bytes: read_len_u64,
            max,
        });
    }
    String::from_utf8(bytes).map_err(|e| KeyError::ConfigParse {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })
}

#[cfg(unix)]
fn check_config_perms(path: &std::path::Path, meta: &std::fs::Metadata) -> Result<(), KeyError> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode: u32 = meta.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(KeyError::ConfigPermissions {
            path: path.to_path_buf(),
            mode: mode & 0o7777,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
const fn check_config_perms(
    _path: &std::path::Path,
    _meta: &std::fs::Metadata,
) -> Result<(), KeyError> {
    Ok(())
}

type EnvLookup<'a> = Box<dyn Fn(&str) -> Option<String> + 'a>;

pub struct KeyResolver<'a> {
    flags: &'a FlagKeys,
    config: BTreeMap<Source, String>,
    keyring: Option<&'a dyn KeyringBackend>,
    env_lookup: EnvLookup<'a>,
}

impl fmt::Debug for KeyResolver<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyResolver")
            .field("flags", &self.flags)
            .field("config_sources", &self.config.keys().collect::<Vec<_>>())
            .field("keyring", &self.keyring.map(|_| "<backend>"))
            .finish_non_exhaustive()
    }
}

impl<'a> KeyResolver<'a> {
    #[must_use]
    pub fn new(
        flags: &'a FlagKeys,
        config: BTreeMap<Source, String>,
        keyring: Option<&'a dyn KeyringBackend>,
    ) -> Self {
        Self {
            flags,
            config,
            keyring,
            env_lookup: Box::new(|name: &str| std::env::var(name).ok()),
        }
    }

    #[must_use]
    pub fn with_env_lookup(mut self, lookup: impl Fn(&str) -> Option<String> + 'a) -> Self {
        self.env_lookup = Box::new(lookup);
        self
    }

    fn env_for(&self, source: Source) -> Option<String> {
        if let Some(v) =
            (self.env_lookup)(&prowl_env(source)).filter(|v: &String| !v.trim().is_empty())
        {
            return Some(v.trim().to_owned());
        }
        conventional_env(source)
            .and_then(|name: &str| (self.env_lookup)(name))
            .filter(|v: &String| !v.trim().is_empty())
            .map(|v: String| v.trim().to_owned())
    }

    /// Resolves a source's key by priority: flag > env > OS keyring > config file. Returns the
    /// resolved key (never logged in the clear) or a [`KeyError`] only when the keyring backend
    /// itself fails; a missing key is `Ok(None)`.
    pub fn resolve(&self, source: Source) -> Result<Option<ApiKey>, KeyError> {
        if let Some(v) = self
            .flags
            .get(source)
            .filter(|v: &&str| !v.trim().is_empty())
        {
            return Ok(Some(ApiKey::new(v.trim().to_owned(), KeyOrigin::Flag)));
        }
        if let Some(v) = self.env_for(source) {
            return Ok(Some(ApiKey::new(v, KeyOrigin::Env)));
        }
        if let Some(backend) = self.keyring
            && let Some(v) = backend
                .get(&keyring_service(source), source.label())?
                .filter(|v: &String| !v.trim().is_empty())
        {
            return Ok(Some(ApiKey::new(v.trim().to_owned(), KeyOrigin::Keyring)));
        }
        if let Some(v) = self
            .config
            .get(&source)
            .filter(|v: &&String| !v.trim().is_empty())
        {
            return Ok(Some(ApiKey::new(
                v.trim().to_owned(),
                KeyOrigin::ConfigFile,
            )));
        }
        Ok(None)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct MemoryKeyring {
        store: Mutex<BTreeMap<(String, String), String>>,
    }

    impl KeyringBackend for MemoryKeyring {
        fn get(&self, service: &str, account: &str) -> Result<Option<String>, KeyError> {
            Ok(self
                .store
                .lock()
                .unwrap()
                .get(&(service.to_owned(), account.to_owned()))
                .cloned())
        }

        fn set(&self, service: &str, account: &str, secret: &str) -> Result<(), KeyError> {
            self.store
                .lock()
                .unwrap()
                .insert((service.to_owned(), account.to_owned()), secret.to_owned());
            Ok(())
        }

        fn delete(&self, service: &str, account: &str) -> Result<(), KeyError> {
            self.store
                .lock()
                .unwrap()
                .remove(&(service.to_owned(), account.to_owned()));
            Ok(())
        }
    }

    fn empty_env(_name: &str) -> Option<String> {
        None
    }

    #[test]
    fn redaction_masks_long_keys_and_never_leaks() {
        let key: &str = "aB3xK9mQ7zP1wL5tN2vR8sD4fG6hJ0cY";
        let masked: String = redact(key);
        assert!(masked.starts_with("aB3x") || masked.contains("redacted"));
        assert!(masked.contains("redacted"));
        assert!(!masked.contains("zP1wL5tN2vR8sD4fG6hJ0cY"));
        let api: ApiKey = ApiKey::new(key.to_owned(), KeyOrigin::Env);
        let debug: String = format!("{api:?}");
        assert!(!debug.contains("zP1wL5tN2vR8sD4fG6hJ0cY"), "{debug}");
        let display: String = format!("{api}");
        assert!(!display.contains("zP1wL5tN2vR8sD4fG6hJ0cY"), "{display}");
    }

    #[test]
    fn resolution_priority_flag_over_env_over_keyring_over_config() {
        let mut flags: FlagKeys = FlagKeys::new();
        flags.set(Source::Virustotal, "flagkey-aaaaaaaaaaaaaaaa".to_owned());
        let keyring: MemoryKeyring = MemoryKeyring::default();
        keyring
            .set(
                &keyring_service(Source::Virustotal),
                Source::Virustotal.label(),
                "ringkey-bbbbbbbbbbbbbbbb",
            )
            .unwrap();
        let mut config: BTreeMap<Source, String> = BTreeMap::new();
        config.insert(Source::Virustotal, "configkey-cccccccccccc".to_owned());

        let resolver: KeyResolver<'_> = KeyResolver::new(&flags, config.clone(), Some(&keyring))
            .with_env_lookup(|name: &str| {
                if name == prowl_env(Source::Virustotal) {
                    Some("envkey-dddddddddddddddd".to_owned())
                } else {
                    None
                }
            });
        let resolved: ApiKey = resolver.resolve(Source::Virustotal).unwrap().unwrap();
        assert_eq!(resolved.origin(), KeyOrigin::Flag);
        assert_eq!(resolved.expose(), "flagkey-aaaaaaaaaaaaaaaa");

        let no_flag: FlagKeys = FlagKeys::new();
        let env_resolver: KeyResolver<'_> =
            KeyResolver::new(&no_flag, config.clone(), Some(&keyring)).with_env_lookup(
                |name: &str| {
                    if name == prowl_env(Source::Virustotal) {
                        Some("envkey-dddddddddddddddd".to_owned())
                    } else {
                        None
                    }
                },
            );
        let env_key: ApiKey = env_resolver.resolve(Source::Virustotal).unwrap().unwrap();
        assert_eq!(env_key.origin(), KeyOrigin::Env);

        let ring_resolver: KeyResolver<'_> =
            KeyResolver::new(&no_flag, config.clone(), Some(&keyring)).with_env_lookup(empty_env);
        let ring_key: ApiKey = ring_resolver.resolve(Source::Virustotal).unwrap().unwrap();
        assert_eq!(ring_key.origin(), KeyOrigin::Keyring);

        let cfg_resolver: KeyResolver<'_> =
            KeyResolver::new(&no_flag, config, None).with_env_lookup(empty_env);
        let cfg_key: ApiKey = cfg_resolver.resolve(Source::Virustotal).unwrap().unwrap();
        assert_eq!(cfg_key.origin(), KeyOrigin::ConfigFile);
    }

    #[test]
    fn conventional_env_name_accepted() {
        let flags: FlagKeys = FlagKeys::new();
        let resolver: KeyResolver<'_> = KeyResolver::new(&flags, BTreeMap::new(), None)
            .with_env_lookup(|name: &str| {
                if name == "VT_API_KEY" {
                    Some("conventional-key-xxxxxxxxxx".to_owned())
                } else {
                    None
                }
            });
        let key: ApiKey = resolver.resolve(Source::Virustotal).unwrap().unwrap();
        assert_eq!(key.origin(), KeyOrigin::Env);
        assert_eq!(key.expose(), "conventional-key-xxxxxxxxxx");
    }

    #[test]
    fn missing_key_is_none_not_error() {
        let flags: FlagKeys = FlagKeys::new();
        let resolver: KeyResolver<'_> =
            KeyResolver::new(&flags, BTreeMap::new(), None).with_env_lookup(empty_env);
        assert!(resolver.resolve(Source::Virustotal).unwrap().is_none());
    }

    #[test]
    fn auth_policy_matches_service_contract() {
        assert_eq!(auth_policy(Source::Wayback), AuthPolicy::None);
        assert_eq!(auth_policy(Source::Urlscan), AuthPolicy::Optional);
        assert_eq!(auth_policy(Source::Virustotal), AuthPolicy::Required);
        assert_eq!(auth_policy(Source::Urlhaus), AuthPolicy::Required);
        assert_eq!(auth_policy(Source::Threatfox), AuthPolicy::Required);
    }

    #[test]
    fn config_file_parses_keys_table() {
        let dir: PathBuf = std::env::temp_dir().join(format!("prowl-keys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path: PathBuf = dir.join("prowl.toml");
        std::fs::write(
            &path,
            "[keys]\nvirustotal = \"cfg-vt-key-zzzzzzzzzz\"\nurlscan = \"cfg-us-key-yyyyyyyyy\"\n",
        )
        .unwrap();
        harden_perms(&path);
        let keys: BTreeMap<Source, String> = config_keys_at(&path).unwrap();
        assert_eq!(
            keys.get(&Source::Virustotal).map(String::as_str),
            Some("cfg-vt-key-zzzzzzzzzz")
        );
        assert_eq!(
            keys.get(&Source::Urlscan).map(String::as_str),
            Some("cfg-us-key-yyyyyyyyy")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oversized_config_file_is_refused() {
        let dir: PathBuf =
            std::env::temp_dir().join(format!("prowl-keys-big-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path: PathBuf = dir.join("prowl.toml");
        let text: String = "x".repeat((MAX_CONFIG_BYTES + 1) as usize);
        std::fs::write(&path, text).unwrap();
        harden_perms(&path);
        let err: KeyError = config_keys_at(&path).unwrap_err();
        assert!(matches!(
            err,
            KeyError::ConfigTooLarge {
                bytes,
                max: MAX_CONFIG_BYTES,
                ..
            } if bytes == MAX_CONFIG_BYTES + 1
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn config_reader_enforces_actual_read_cap() {
        let dir: PathBuf =
            std::env::temp_dir().join(format!("prowl-keys-read-cap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path: PathBuf = dir.join("prowl.toml");
        std::fs::write(&path, "abcdef").unwrap();
        let err: KeyError = read_config_text(&path, 5).unwrap_err();
        assert!(matches!(
            err,
            KeyError::ConfigTooLarge {
                bytes,
                max: 5,
                ..
            } if bytes == 6
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    fn harden_perms(path: &PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(not(unix))]
    fn harden_perms(_path: &PathBuf) {}

    #[cfg(unix)]
    #[test]
    fn world_readable_config_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir: PathBuf = std::env::temp_dir().join(format!("prowl-perms-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path: PathBuf = dir.join("prowl.toml");
        std::fs::write(&path, "[keys]\nvirustotal = \"leaky-key-wwwwwwwwww\"\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err: KeyError = config_keys_at(&path).unwrap_err();
        assert!(matches!(err, KeyError::ConfigPermissions { .. }));
        std::fs::remove_dir_all(&dir).ok();
    }
}
