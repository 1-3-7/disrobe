use std::ffi::OsString;
use std::time::Duration;

use crate::error::StressError;
use crate::rng::splitmix64;

pub const SEED_ENV: &str = "DISROBE_STRESS_SEED";
pub const DEFAULT_MASTER_SEED: u64 = 0xD157_0BE5_7E57_C0DE;
pub const DEFAULT_CASES_PER_INPUT: usize = 64;
pub const DEFAULT_BATCH_SIZE: usize = 16;
pub const DEFAULT_CASE_BUDGET: Duration = Duration::from_millis(750);
pub const DEFAULT_SUITE_BUDGET: Duration = Duration::from_mins(5);
pub const BATCH_STARTUP_OVERHEAD: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StressConfig {
    pub cases_per_input: usize,
    pub master_seed: u64,
    pub batch_size: usize,
    pub case_budget: Duration,
    pub suite_budget: Duration,
}

impl Default for StressConfig {
    fn default() -> Self {
        Self {
            cases_per_input: DEFAULT_CASES_PER_INPUT,
            master_seed: DEFAULT_MASTER_SEED,
            batch_size: DEFAULT_BATCH_SIZE,
            case_budget: DEFAULT_CASE_BUDGET,
            suite_budget: DEFAULT_SUITE_BUDGET,
        }
    }
}

impl StressConfig {
    #[must_use]
    pub fn scaled_batch_timeout(case_budget: Duration, batch_size: usize) -> Duration {
        let factor: u32 = u32::try_from(batch_size).unwrap_or(u32::MAX);
        case_budget
            .saturating_mul(factor)
            .saturating_add(BATCH_STARTUP_OVERHEAD)
    }

    #[must_use]
    pub fn batch_timeout(&self) -> Duration {
        Self::scaled_batch_timeout(self.case_budget, self.batch_size)
    }

    #[must_use]
    pub const fn with_case_budget(self, case_budget: Duration) -> Self {
        Self {
            case_budget,
            ..self
        }
    }

    #[must_use]
    pub const fn with_suite_budget(self, suite_budget: Duration) -> Self {
        Self {
            suite_budget,
            ..self
        }
    }

    #[must_use]
    pub const fn case_seed(&self, case_index: usize) -> u64 {
        splitmix64(self.master_seed ^ splitmix64(case_index as u64))
    }

    #[must_use]
    pub const fn total_cases(&self, corpus_entries: usize) -> usize {
        corpus_entries.saturating_mul(self.cases_per_input)
    }

    pub fn with_seed_from_env(self) -> Result<Self, StressError> {
        let Some(raw): Option<OsString> = std::env::var_os(SEED_ENV) else {
            return Ok(self);
        };
        let Some(text): Option<&str> = raw.to_str() else {
            return Err(StressError::SeedEnv {
                variable: SEED_ENV,
                value: raw.to_string_lossy().into_owned(),
            });
        };
        let trimmed: &str = text.trim();
        if trimmed.is_empty() {
            return Ok(self);
        }
        let master_seed: u64 = parse_seed(trimmed).ok_or_else(|| StressError::SeedEnv {
            variable: SEED_ENV,
            value: trimmed.to_owned(),
        })?;
        Ok(Self {
            master_seed,
            ..self
        })
    }
}

fn parse_seed(text: &str) -> Option<u64> {
    let digits: &str = text.trim_start_matches('+');
    digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
        .map_or_else(
            || digits.parse::<u64>().ok(),
            |hexadecimal: &str| u64::from_str_radix(hexadecimal, 16).ok(),
        )
}

pub(crate) fn print_banner(
    config: &StressConfig,
    corpus_entries: usize,
    total_cases: usize,
    worker: Option<&str>,
) {
    let mode: &str = match worker {
        Some(_) => "child-process isolation",
        None => "in-process",
    };
    println!(
        "disrobe-testkit: {mode} run over {corpus_entries} corpus entr(ies), {} case(s) each, {total_cases} total; master seed {:#018x} (override with {SEED_ENV}); batch size {}, batch timeout {:?}, suite budget {:?}",
        config.cases_per_input,
        config.master_seed,
        config.batch_size,
        config.batch_timeout(),
        config.suite_budget
    );
    if let Some(filter) = worker {
        println!("disrobe-testkit: worker test filter `{filter}`");
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BATCH_STARTUP_OVERHEAD, DEFAULT_BATCH_SIZE, DEFAULT_CASE_BUDGET, DEFAULT_MASTER_SEED,
        DEFAULT_SUITE_BUDGET, StressConfig, parse_seed,
    };
    use std::time::Duration;

    #[test]
    fn the_default_master_seed_is_a_fixed_constant() {
        let config: StressConfig = StressConfig::default();
        assert_eq!(config.master_seed, DEFAULT_MASTER_SEED);
        assert_eq!(config.suite_budget, DEFAULT_SUITE_BUDGET);
        assert_eq!(
            config.batch_timeout(),
            DEFAULT_CASE_BUDGET
                .saturating_mul(u32::try_from(DEFAULT_BATCH_SIZE).unwrap_or(u32::MAX))
                .saturating_add(BATCH_STARTUP_OVERHEAD)
        );
    }

    #[test]
    fn overriding_the_batch_size_with_struct_update_rescales_the_batch_timeout() {
        let base: StressConfig = StressConfig::default();
        let widened: StressConfig = StressConfig {
            batch_size: base.batch_size.saturating_mul(4),
            ..base
        };
        assert_eq!(
            widened.batch_timeout(),
            StressConfig::scaled_batch_timeout(base.case_budget, base.batch_size * 4)
        );
        assert!(widened.batch_timeout() > base.batch_timeout());
    }

    #[test]
    fn the_suite_budget_survives_a_case_budget_override() {
        let tightened: StressConfig = StressConfig::default()
            .with_case_budget(Duration::from_millis(5))
            .with_suite_budget(Duration::from_secs(11));
        assert_eq!(tightened.case_budget, Duration::from_millis(5));
        assert_eq!(tightened.suite_budget, Duration::from_secs(11));
        assert_eq!(
            tightened.batch_timeout(),
            StressConfig::scaled_batch_timeout(Duration::from_millis(5), DEFAULT_BATCH_SIZE)
        );
    }

    #[test]
    fn the_batch_timeout_scales_with_the_batch_size() {
        let small: Duration = StressConfig::scaled_batch_timeout(Duration::from_millis(100), 4);
        let large: Duration = StressConfig::scaled_batch_timeout(Duration::from_millis(100), 64);
        assert_eq!(small, Duration::from_millis(400) + BATCH_STARTUP_OVERHEAD);
        assert!(large > small);
    }

    #[test]
    fn case_seeds_are_stable_and_distinct() {
        let config: StressConfig = StressConfig::default();
        let mut seen: Vec<u64> = Vec::new();
        for index in 0..1024usize {
            let seed: u64 = config.case_seed(index);
            assert_eq!(seed, config.case_seed(index));
            assert!(!seen.contains(&seed), "case seed {seed:#x} repeated");
            seen.push(seed);
        }
    }

    #[test]
    fn a_different_master_seed_moves_every_case_seed() {
        let base: StressConfig = StressConfig::default();
        let shifted: StressConfig = StressConfig {
            master_seed: DEFAULT_MASTER_SEED ^ 1,
            ..base
        };
        for index in 0..256usize {
            assert_ne!(base.case_seed(index), shifted.case_seed(index));
        }
    }

    #[test]
    fn seed_text_accepts_decimal_and_hexadecimal() {
        assert_eq!(parse_seed("42"), Some(42));
        assert_eq!(parse_seed("0x2a"), Some(42));
        assert_eq!(parse_seed("0X2A"), Some(42));
        assert_eq!(parse_seed("+7"), Some(7));
        assert_eq!(parse_seed("18446744073709551615"), Some(u64::MAX));
        assert_eq!(parse_seed("-1"), None);
        assert_eq!(parse_seed("banana"), None);
        assert_eq!(parse_seed("0x"), None);
    }

    #[test]
    fn total_cases_saturates_instead_of_overflowing() {
        let config: StressConfig = StressConfig {
            cases_per_input: usize::MAX,
            ..StressConfig::default()
        };
        assert_eq!(config.total_cases(4), usize::MAX);
        assert_eq!(config.total_cases(0), 0);
    }
}
