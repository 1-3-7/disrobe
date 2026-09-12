use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[must_use]
pub fn now() -> SystemTime {
    now_from_env(std::env::var("SOURCE_DATE_EPOCH").ok().as_deref())
}

#[must_use]
pub fn now_secs() -> u64 {
    now_secs_from_env(std::env::var("SOURCE_DATE_EPOCH").ok().as_deref())
}

fn now_from_env(epoch_raw: Option<&str>) -> SystemTime {
    if let Some(secs) = parse_epoch(epoch_raw) {
        return UNIX_EPOCH + Duration::from_secs(secs);
    }
    UNIX_EPOCH + Duration::from_secs(wall_clock_secs())
}

fn now_secs_from_env(epoch_raw: Option<&str>) -> u64 {
    if let Some(secs) = parse_epoch(epoch_raw) {
        return secs;
    }
    wall_clock_secs()
}

#[cfg(not(target_arch = "wasm32"))]
fn wall_clock_secs() -> u64 {
    #[allow(clippy::disallowed_methods)]
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d: Duration| d.as_secs())
}

#[cfg(target_arch = "wasm32")]
const fn wall_clock_secs() -> u64 {
    0
}

fn parse_epoch(raw: Option<&str>) -> Option<u64> {
    raw.and_then(|v: &str| v.parse::<u64>().ok())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn now_secs_honors_source_date_epoch() {
        assert_eq!(now_secs_from_env(Some("1700000000")), 1_700_000_000);
        let st: SystemTime = now_from_env(Some("1700000000"));
        let d: Duration = st.duration_since(UNIX_EPOCH).expect("after epoch");
        assert_eq!(d.as_secs(), 1_700_000_000);
    }

    #[test]
    fn now_secs_falls_back_when_unset() {
        let s: u64 = now_secs_from_env(None);
        assert!(s > 1_600_000_000);
    }

    #[test]
    fn now_secs_falls_back_when_unparseable() {
        let s: u64 = now_secs_from_env(Some("not-a-number"));
        assert!(s > 1_600_000_000);
    }
}
