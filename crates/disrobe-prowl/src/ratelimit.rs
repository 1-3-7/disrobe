use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time::Instant;

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

#[derive(Debug, Clone, Copy)]
pub struct RateConfig {
    pub per_host_rps: f64,
    pub burst: f64,
}

impl Default for RateConfig {
    fn default() -> Self {
        Self {
            per_host_rps: 4.0,
            burst: 4.0,
        }
    }
}

/// Per-host token-bucket limiter. Independent hosts never block one another, so a wide fan-out
/// across distinct services runs fully concurrent while each individual host stays polite.
#[derive(Debug, Clone)]
pub struct HostRateLimiter {
    config: RateConfig,
    buckets: Arc<Mutex<BTreeMap<String, Bucket>>>,
}

impl HostRateLimiter {
    #[must_use]
    pub fn new(config: RateConfig) -> Self {
        Self {
            config,
            buckets: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    #[must_use]
    pub fn host_of(url: &str) -> String {
        let after: &str = url
            .split_once("://")
            .map_or(url, |(_, rest): (&str, &str)| rest);
        let authority: &str = after
            .split(['/', '?', '#'])
            .next()
            .map_or(after, |value: &str| value);
        authority
            .rsplit('@')
            .next()
            .map_or(authority, |value: &str| value)
            .to_ascii_lowercase()
    }

    /// Blocks until a token is available for `host`, refilling at the configured per-host rate.
    /// A `per_host_rps <= 0` disables limiting (returns immediately).
    pub async fn acquire(&self, host: &str) {
        if self.config.per_host_rps <= 0.0 {
            return;
        }
        loop {
            let wait: Option<Duration> = {
                let mut guard: tokio::sync::MutexGuard<'_, BTreeMap<String, Bucket>> =
                    self.buckets.lock().await;
                self.take_locked(&mut guard, host)
            };
            match wait {
                None => return,
                Some(delay) => tokio::time::sleep(delay).await,
            }
        }
    }

    fn take_locked(&self, guard: &mut BTreeMap<String, Bucket>, host: &str) -> Option<Duration> {
        let now: Instant = Instant::now();
        let bucket: &mut Bucket = guard.entry(host.to_owned()).or_insert(Bucket {
            tokens: self.config.burst,
            last: now,
        });
        let elapsed: f64 = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = elapsed
            .mul_add(self.config.per_host_rps, bucket.tokens)
            .min(self.config.burst);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            None
        } else {
            let deficit: f64 = 1.0 - bucket.tokens;
            Some(Duration::from_secs_f64(deficit / self.config.per_host_rps))
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn host_extraction() {
        assert_eq!(
            HostRateLimiter::host_of("https://web.archive.org/cdx?url=x"),
            "web.archive.org"
        );
        assert_eq!(
            HostRateLimiter::host_of("https://user@otx.alienvault.com/api"),
            "otx.alienvault.com"
        );
    }

    #[tokio::test]
    async fn first_token_per_distinct_host_is_immediate() {
        let limiter: HostRateLimiter = HostRateLimiter::new(RateConfig {
            per_host_rps: 5.0,
            burst: 1.0,
        });
        let start: Instant = Instant::now();
        for host in ["a.example", "b.example", "c.example", "d.example"] {
            limiter.acquire(host).await;
        }
        assert!(
            start.elapsed() < Duration::from_millis(50),
            "distinct hosts never block each other: {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn same_host_second_token_waits_for_refill() {
        let limiter: HostRateLimiter = HostRateLimiter::new(RateConfig {
            per_host_rps: 20.0,
            burst: 1.0,
        });
        limiter.acquire("a.example").await;
        let start: Instant = Instant::now();
        limiter.acquire("a.example").await;
        assert!(
            start.elapsed() >= Duration::from_millis(30),
            "second hit on the same host paces at ~1/rps: {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn zero_rps_disables_limiting() {
        let limiter: HostRateLimiter = HostRateLimiter::new(RateConfig {
            per_host_rps: 0.0,
            burst: 1.0,
        });
        let start: Instant = Instant::now();
        for _ in 0..100 {
            limiter.acquire("a.example").await;
        }
        assert!(start.elapsed() < Duration::from_millis(50));
    }
}
