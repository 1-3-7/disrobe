#![forbid(unsafe_code)]

pub mod engine;
pub mod extract;
pub mod filter;
pub mod http;
pub mod input;
#[cfg(feature = "keyring")]
pub mod keyring_store;
pub mod keys;
pub mod model;
pub mod provider;
pub mod providers;
pub mod ratelimit;

pub use engine::{EngineConfig, KeySet, backoff_for, harvest, harvest_with_keys};
pub use extract::extract_iocs;
pub use filter::{Filter, apply_ioc_filters, apply_url_filters, host_of};
pub use http::{FetchError, FetchResponse, Fetcher, HttpConfig, ReqwestFetcher};
pub use input::{normalize_target, parse_target_lines, targets_from_disrobe_report};
#[cfg(feature = "keyring")]
pub use keyring_store::OsKeyring;
pub use keys::{
    ApiKey, AuthPolicy, FlagKeys, KeyError, KeyOrigin, KeyResolver, KeyringBackend, auth_policy,
    config_keys_at, conventional_env, default_config_path, keyring_service, prowl_env, redact,
};
pub use model::{
    HarvestedUrl, Ioc, IocKind, PROWL_SCHEMA, ProviderOutcome, ProviderStatus, ProwlReport, Source,
};
pub use provider::{Method, Provider, Request, Yield};
pub use ratelimit::{HostRateLimiter, RateConfig};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
