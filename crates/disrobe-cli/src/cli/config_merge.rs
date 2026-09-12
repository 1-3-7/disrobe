use clap::ArgMatches;
use clap::parser::ValueSource;

use super::config::{ConfigColor, ConfigProgress, DisrobeConfig};

#[inline]
fn was_supplied(matches: &ArgMatches, name: &str) -> bool {
    matches!(matches.value_source(name), Some(ValueSource::CommandLine))
}

#[inline]
fn merge_bool(matches: &ArgMatches, name: &str, cli: bool, cfg: Option<bool>) -> bool {
    if was_supplied(matches, name) {
        cli
    } else {
        cfg.unwrap_or(cli)
    }
}

#[inline]
fn merge_opt<T>(matches: &ArgMatches, name: &str, cli: Option<T>, cfg: Option<T>) -> Option<T> {
    if was_supplied(matches, name) {
        cli
    } else {
        cfg.or(cli)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EffectiveGlobals {
    pub(crate) verbose: u8,
    pub(crate) quiet: bool,
    pub(crate) json: bool,
    pub(crate) ndjson: bool,
    pub(crate) sarif: bool,
    pub(crate) in_place: bool,
    pub(crate) force: bool,
    pub(crate) threads: Option<u32>,
    pub(crate) no_cache: bool,
    pub(crate) dry_run: bool,
    pub(crate) color_always: bool,
    pub(crate) color_never: bool,
    pub(crate) progress_always: bool,
    pub(crate) progress_never: bool,
    pub(crate) redact: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CliGlobalsSnapshot {
    pub(crate) verbose: u8,
    pub(crate) quiet: bool,
    pub(crate) json: bool,
    pub(crate) ndjson: bool,
    pub(crate) sarif: bool,
    pub(crate) in_place: bool,
    pub(crate) force: bool,
    pub(crate) threads: Option<u32>,
    pub(crate) no_cache: bool,
    pub(crate) dry_run: bool,
}

pub(crate) fn merge_globals(
    matches: &ArgMatches,
    cli: CliGlobalsSnapshot,
    cfg: &DisrobeConfig,
) -> EffectiveGlobals {
    let verbose: u8 = if was_supplied(matches, "verbose") {
        cli.verbose
    } else {
        cfg.output
            .verbosity
            .map_or(cli.verbose, super::config::ConfigVerbosity::as_count)
    };
    let (color_always, color_never): (bool, bool) = match cfg.output.color {
        Some(ConfigColor::Always) => (true, false),
        Some(ConfigColor::Never) => (false, true),
        Some(ConfigColor::Auto) | None => (false, false),
    };
    let progress_supplied: bool = was_supplied(matches, "progress");
    let (progress_always, progress_never): (bool, bool) = if progress_supplied {
        (false, false)
    } else {
        match cfg.output.progress {
            Some(ConfigProgress::Always) => (true, false),
            Some(ConfigProgress::Never) => (false, true),
            Some(ConfigProgress::Auto) | None => (false, false),
        }
    };
    EffectiveGlobals {
        verbose,
        quiet: merge_bool(matches, "quiet", cli.quiet, cfg.output.quiet),
        json: merge_bool(matches, "json", cli.json, cfg.output.json),
        ndjson: merge_bool(matches, "ndjson", cli.ndjson, cfg.output.ndjson),
        sarif: merge_bool(matches, "sarif", cli.sarif, cfg.output.sarif),
        in_place: merge_bool(matches, "in_place", cli.in_place, cfg.execution.in_place),
        force: merge_bool(matches, "force", cli.force, cfg.execution.force),
        threads: merge_opt(matches, "threads", cli.threads, cfg.execution.threads),
        no_cache: merge_bool(matches, "no_cache", cli.no_cache, cfg.execution.no_cache),
        dry_run: merge_bool(matches, "dry_run", cli.dry_run, cfg.execution.dry_run),
        color_always,
        color_never,
        progress_always,
        progress_never,
        redact: cfg.output.redact.unwrap_or(false),
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::bool_assert_comparison
)]
mod tests {
    use super::*;
    use crate::cli::config::{ConfigVerbosity, ExecutionConfig, OutputConfig};
    use clap::{Arg, ArgAction, Command};

    fn test_command() -> Command {
        Command::new("t")
            .arg(Arg::new("verbose").short('v').action(ArgAction::Count))
            .arg(Arg::new("quiet").long("quiet").action(ArgAction::SetTrue))
            .arg(Arg::new("json").long("json").action(ArgAction::SetTrue))
            .arg(Arg::new("ndjson").long("ndjson").action(ArgAction::SetTrue))
            .arg(Arg::new("sarif").long("sarif").action(ArgAction::SetTrue))
            .arg(
                Arg::new("in_place")
                    .long("in-place")
                    .action(ArgAction::SetTrue),
            )
            .arg(Arg::new("force").long("force").action(ArgAction::SetTrue))
            .arg(
                Arg::new("threads")
                    .long("threads")
                    .value_parser(clap::value_parser!(u32)),
            )
            .arg(
                Arg::new("no_cache")
                    .long("no-cache")
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("dry_run")
                    .long("dry-run")
                    .action(ArgAction::SetTrue),
            )
            .arg(Arg::new("progress").long("progress"))
    }

    fn snapshot_from(matches: &ArgMatches) -> CliGlobalsSnapshot {
        CliGlobalsSnapshot {
            verbose: matches.get_count("verbose"),
            quiet: matches.get_flag("quiet"),
            json: matches.get_flag("json"),
            ndjson: matches.get_flag("ndjson"),
            sarif: matches.get_flag("sarif"),
            in_place: matches.get_flag("in_place"),
            force: matches.get_flag("force"),
            threads: matches.get_one::<u32>("threads").copied(),
            no_cache: matches.get_flag("no_cache"),
            dry_run: matches.get_flag("dry_run"),
        }
    }

    fn parse(args: &[&str]) -> ArgMatches {
        test_command().get_matches_from(args)
    }

    #[test]
    fn config_fills_when_flag_absent() {
        let matches: ArgMatches = parse(&["t"]);
        let snap: CliGlobalsSnapshot = snapshot_from(&matches);
        let cfg: DisrobeConfig = DisrobeConfig {
            output: OutputConfig {
                json: Some(true),
                verbosity: Some(ConfigVerbosity::Debug),
                ..OutputConfig::default()
            },
            execution: ExecutionConfig {
                threads: Some(7),
                force: Some(true),
                ..ExecutionConfig::default()
            },
            ..DisrobeConfig::default()
        };
        let eff: EffectiveGlobals = merge_globals(&matches, snap, &cfg);
        assert_eq!(eff.json, true);
        assert_eq!(eff.verbose, 2);
        assert_eq!(eff.threads, Some(7));
        assert_eq!(eff.force, true);
    }

    #[test]
    fn cli_flag_overrides_config() {
        let matches: ArgMatches = parse(&["t", "--threads", "3", "-vv"]);
        let snap: CliGlobalsSnapshot = snapshot_from(&matches);
        let cfg: DisrobeConfig = DisrobeConfig {
            output: OutputConfig {
                verbosity: Some(ConfigVerbosity::Trace),
                ..OutputConfig::default()
            },
            execution: ExecutionConfig {
                threads: Some(99),
                ..ExecutionConfig::default()
            },
            ..DisrobeConfig::default()
        };
        let eff: EffectiveGlobals = merge_globals(&matches, snap, &cfg);
        assert_eq!(eff.threads, Some(3), "CLI --threads must beat config");
        assert_eq!(eff.verbose, 2, "CLI -vv must beat config trace(3)");
    }

    #[test]
    fn defaults_when_neither_present() {
        let matches: ArgMatches = parse(&["t"]);
        let snap: CliGlobalsSnapshot = snapshot_from(&matches);
        let cfg: DisrobeConfig = DisrobeConfig::default();
        let eff: EffectiveGlobals = merge_globals(&matches, snap, &cfg);
        assert_eq!(eff.json, false);
        assert_eq!(eff.verbose, 0);
        assert_eq!(eff.threads, None);
        assert_eq!(eff.force, false);
        assert_eq!(eff.color_always, false);
        assert_eq!(eff.color_never, false);
    }

    #[test]
    fn config_color_never_maps_to_flag_pair() {
        let matches: ArgMatches = parse(&["t"]);
        let snap: CliGlobalsSnapshot = snapshot_from(&matches);
        let cfg: DisrobeConfig = DisrobeConfig {
            output: OutputConfig {
                color: Some(ConfigColor::Never),
                ..OutputConfig::default()
            },
            ..DisrobeConfig::default()
        };
        let eff: EffectiveGlobals = merge_globals(&matches, snap, &cfg);
        assert_eq!(eff.color_never, true);
        assert_eq!(eff.color_always, false);
    }
}
