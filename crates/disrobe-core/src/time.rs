use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SOURCE_DATE_EPOCH: &str = "SOURCE_DATE_EPOCH";
const LAST_REPRESENTABLE_SECOND: i64 = 253_402_300_799;
const SECONDS_PER_DAY: i64 = 86_400;

pub fn now_secs() -> Result<u64, SourceDateError> {
    now_secs_from(std::env::var(SOURCE_DATE_EPOCH))
}

fn now_secs_from(value: Result<String, std::env::VarError>) -> Result<u64, SourceDateError> {
    Ok(source_date_from(value)?.map_or_else(wall_clock_secs, SourceDate::seconds))
}

fn wall_clock_secs() -> u64 {
    since_unix_epoch().as_secs()
}

#[cfg(not(target_arch = "wasm32"))]
fn since_unix_epoch() -> Duration {
    #[allow(clippy::disallowed_methods)]
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
}

#[cfg(target_arch = "wasm32")]
const fn since_unix_epoch() -> Duration {
    Duration::ZERO
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourceDate(i64);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SourceDateError {
    #[error("SOURCE_DATE_EPOCH is not valid unicode")]
    NotUnicode,
    #[error("SOURCE_DATE_EPOCH must be a whole number of seconds since 1970, got `{0}`")]
    NotSeconds(String),
    #[error(
        "SOURCE_DATE_EPOCH {0} is later than 9999-12-31T23:59:59Z, the last date an RFC 3339 timestamp can hold"
    )]
    OutOfRange(u64),
}

impl SourceDate {
    pub fn from_seconds(seconds: u64) -> Result<Self, SourceDateError> {
        match i64::try_from(seconds) {
            Ok(value) if value <= LAST_REPRESENTABLE_SECOND => Ok(Self(value)),
            _ => Err(SourceDateError::OutOfRange(seconds)),
        }
    }

    #[must_use]
    pub const fn seconds(self) -> u64 {
        self.0.unsigned_abs()
    }

    #[must_use]
    pub fn rfc3339(self) -> String {
        rfc3339(self.0, Fraction::Millis(0))
    }
}

pub fn source_date() -> Result<Option<SourceDate>, SourceDateError> {
    source_date_from(std::env::var(SOURCE_DATE_EPOCH))
}

fn source_date_from(
    value: Result<String, std::env::VarError>,
) -> Result<Option<SourceDate>, SourceDateError> {
    let raw: String = match value {
        Ok(raw) => raw,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => return Err(SourceDateError::NotUnicode),
    };
    let seconds: u64 = raw
        .trim()
        .parse::<u64>()
        .map_err(|_| SourceDateError::NotSeconds(raw.clone()))?;
    SourceDate::from_seconds(seconds).map(Some)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WallClock(Duration);

impl WallClock {
    #[must_use]
    pub fn now() -> Self {
        Self(since_unix_epoch())
    }

    #[must_use]
    pub fn system_time(self) -> SystemTime {
        UNIX_EPOCH + self.0
    }

    #[must_use]
    pub fn rfc3339_millis(self) -> String {
        rfc3339(
            self.whole_seconds(),
            Fraction::Millis(self.0.subsec_millis()),
        )
    }

    #[must_use]
    pub fn rfc3339_nanos(self) -> String {
        rfc3339(self.whole_seconds(), Fraction::Nanos(self.0.subsec_nanos()))
    }

    fn whole_seconds(self) -> i64 {
        i64::try_from(self.0.as_secs()).unwrap_or(i64::MAX)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fraction {
    Omitted,
    Millis(u32),
    Nanos(u32),
}

#[must_use]
pub fn rfc3339(seconds: i64, fraction: Fraction) -> String {
    let within: i64 = seconds.rem_euclid(SECONDS_PER_DAY);
    let (year, month, day): (i64, i64, i64) = civil_from_days(seconds.div_euclid(SECONDS_PER_DAY));
    let clock: String = format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
        within / 3_600,
        within % 3_600 / 60,
        within % 60
    );
    match fraction {
        Fraction::Omitted => format!("{clock}Z"),
        Fraction::Millis(millis) => format!("{clock}.{:03}Z", millis.min(999)),
        Fraction::Nanos(nanos) => format!("{clock}.{:09}Z", nanos.min(999_999_999)),
    }
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted: i64 = days + 719_468;
    let era: i64 = shifted.div_euclid(146_097);
    let day_of_era: i64 = shifted.rem_euclid(146_097);
    let year_of_era: i64 =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year: i64 = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index: i64 = (5 * day_of_year + 2) / 153;
    let day: i64 = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month: i64 = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year: i64 = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn now_secs_is_the_source_date_when_one_is_set() {
        assert_eq!(
            now_secs_from(Ok("1700000000".to_string())),
            Ok(1_700_000_000)
        );
    }

    #[test]
    fn now_secs_reads_the_wall_clock_only_without_a_source_date() {
        let seconds: u64 =
            now_secs_from(Err(std::env::VarError::NotPresent)).expect("an unset variable");
        assert!(seconds > 1_600_000_000);
    }

    #[test]
    fn now_secs_refuses_a_malformed_source_date_instead_of_reading_the_clock() {
        assert_eq!(
            now_secs_from(Ok("not-a-number".to_string())),
            Err(SourceDateError::NotSeconds("not-a-number".to_string()))
        );
        assert_eq!(
            now_secs_from(Ok("253402300800".to_string())),
            Err(SourceDateError::OutOfRange(253_402_300_800))
        );
    }

    #[test]
    fn a_source_date_is_present_only_when_the_variable_holds_whole_seconds() {
        assert_eq!(
            source_date_from(Err(std::env::VarError::NotPresent)),
            Ok(None)
        );
        assert_eq!(
            source_date_from(Ok(" 1700000000 ".to_string()))
                .map(|date: Option<SourceDate>| date.map(SourceDate::seconds)),
            Ok(Some(1_700_000_000))
        );
        assert_eq!(
            source_date_from(Ok("yesterday".to_string())),
            Err(SourceDateError::NotSeconds("yesterday".to_string()))
        );
        assert_eq!(
            source_date_from(Ok("253402300800".to_string())),
            Err(SourceDateError::OutOfRange(253_402_300_800))
        );
        assert_eq!(
            SourceDate::from_seconds(u64::MAX),
            Err(SourceDateError::OutOfRange(u64::MAX))
        );
    }

    #[test]
    fn rfc3339_renders_civil_dates_at_the_requested_precision() {
        assert_eq!(rfc3339(0, Fraction::Millis(0)), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(0, Fraction::Omitted), "1970-01-01T00:00:00Z");
        assert_eq!(
            rfc3339(1_700_000_000, Fraction::Millis(7)),
            "2023-11-14T22:13:20.007Z"
        );
        assert_eq!(
            rfc3339(951_782_400, Fraction::Nanos(5)),
            "2000-02-29T00:00:00.000000005Z"
        );
        assert_eq!(
            rfc3339(LAST_REPRESENTABLE_SECOND, Fraction::Millis(999)),
            "9999-12-31T23:59:59.999Z"
        );
        assert_eq!(
            SourceDate::from_seconds(1_700_000_000)
                .expect("in range")
                .rfc3339(),
            "2023-11-14T22:13:20.000Z"
        );
    }

    #[test]
    fn rfc3339_renders_instants_before_1970() {
        assert_eq!(rfc3339(-1, Fraction::Omitted), "1969-12-31T23:59:59Z");
        assert_eq!(
            rfc3339(-631_152_000, Fraction::Omitted),
            "1950-01-01T00:00:00Z"
        );
        assert_eq!(
            rfc3339(-2_203_891_200, Fraction::Omitted),
            "1900-03-01T00:00:00Z"
        );
        assert_eq!(
            rfc3339(-62_167_219_200, Fraction::Omitted),
            "0000-01-01T00:00:00Z"
        );
    }
}
