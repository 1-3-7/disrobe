#![allow(dead_code)]
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProgressMode {
    Auto,
    Always,
    Never,
}

impl ProgressMode {
    pub(crate) fn enabled(self) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::Auto => is_tty_stderr(),
        }
    }
}

impl core::str::FromStr for ProgressMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "always" => Ok(Self::Always),
            "never" => Ok(Self::Never),
            other => Err(format!(
                "invalid --progress value `{other}`; expected auto|always|never"
            )),
        }
    }
}

impl core::fmt::Display for ProgressMode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s: &'static str = match self {
            Self::Auto => "auto",
            Self::Always => "always",
            Self::Never => "never",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Globals {
    pub(crate) in_place: bool,
    pub(crate) force: bool,
    pub(crate) threads: u32,
    pub(crate) no_cache: bool,
    pub(crate) dry_run: bool,
    pub(crate) progress: ProgressMode,
}

impl Globals {
    #[allow(clippy::fn_params_excessive_bools)]
    pub(crate) fn new(
        in_place: bool,
        force: bool,
        threads: Option<u32>,
        no_cache: bool,
        dry_run: bool,
        progress: ProgressMode,
    ) -> Self {
        let resolved_threads: u32 = threads.unwrap_or_else(detect_num_cpus);
        Self {
            in_place,
            force,
            threads: resolved_threads,
            no_cache,
            dry_run,
            progress,
        }
    }

    #[inline]
    pub(crate) fn progress_enabled(self) -> bool {
        self.progress.enabled()
    }

    #[inline]
    pub(crate) const fn progress_forced(self) -> bool {
        matches!(self.progress, ProgressMode::Always)
    }
}

static GLOBALS: OnceLock<Globals> = OnceLock::new();

pub(crate) fn install(globals: Globals) -> Globals {
    let _: Result<_, _> = GLOBALS.set(globals);
    GLOBALS.get().copied().unwrap_or(globals)
}

pub(crate) fn current() -> Globals {
    GLOBALS
        .get()
        .copied()
        .unwrap_or_else(|| Globals::new(false, false, None, false, false, ProgressMode::Auto))
}

#[inline]
fn detect_num_cpus() -> u32 {
    let n: usize = num_cpus::get();
    u32::try_from(n).unwrap_or(u32::MAX).max(1)
}

#[cfg(not(target_os = "wasi"))]
pub(crate) fn is_tty_stderr() -> bool {
    use std::io::IsTerminal as _;
    std::io::stderr().is_terminal()
}

#[cfg(target_os = "wasi")]
pub(crate) fn is_tty_stderr() -> bool {
    false
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn progress_mode_parse_round_trip() {
        let a: ProgressMode = "auto".parse().expect("auto");
        let b: ProgressMode = "always".parse().expect("always");
        let c: ProgressMode = "never".parse().expect("never");
        assert_eq!(a.to_string(), "auto");
        assert_eq!(b.to_string(), "always");
        assert_eq!(c.to_string(), "never");
    }

    #[test]
    fn progress_mode_rejects_garbage() {
        let r: Result<ProgressMode, String> = "sometimes".parse();
        assert!(r.is_err());
    }

    #[test]
    fn never_is_disabled_always_is_enabled() {
        assert!(!ProgressMode::Never.enabled());
        assert!(ProgressMode::Always.enabled());
    }

    #[test]
    fn globals_defaults_thread_count_to_at_least_one() {
        let g: Globals = Globals::new(false, false, None, false, false, ProgressMode::Never);
        assert!(g.threads >= 1);
    }

    #[test]
    fn globals_honors_explicit_thread_override() {
        let g: Globals = Globals::new(false, false, Some(4), false, false, ProgressMode::Always);
        assert_eq!(g.threads, 4);
        assert!(g.progress_enabled());
    }
}
