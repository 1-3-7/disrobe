use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use disrobe_prowl::{
    AuthPolicy, EngineConfig, Fetcher, Filter, FlagKeys, HttpConfig, IocKind, KeyError,
    KeyResolver, KeySet, KeyringBackend, OsKeyring, ProviderOutcome, ProwlReport, ReqwestFetcher,
    Source, auth_policy, config_keys_at, conventional_env, default_config_path, keyring_service,
    prowl_env, redact, targets_from_disrobe_report,
};

use super::ProwlFormat;
use crate::cli::output::OutputFormat;

#[allow(clippy::struct_excessive_bools)]
pub(crate) struct ProwlArgs {
    pub targets: Vec<String>,
    pub targets_file: Option<PathBuf>,
    pub recon_input: Option<PathBuf>,
    pub stdin: bool,
    pub sources: Vec<String>,
    pub subs: bool,
    pub blacklist: Vec<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub match_status: Vec<u16>,
    pub filter_status: Vec<u16>,
    pub match_mime: Vec<String>,
    pub filter_mime: Vec<String>,
    pub ioc_kinds: Vec<String>,
    pub collapse_params: bool,
    pub no_iocs: bool,
    pub proxy: Option<String>,
    pub timeout_secs: u64,
    pub concurrency: usize,
    pub per_host_rps: f64,
    pub max_pages: u32,
    pub max_urls: usize,
    pub max_iocs: usize,
    pub retries: u32,
    pub format: ProwlFormat,
    pub api_keys: Vec<String>,
}

const MAX_TARGET_INPUT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TARGETS: usize = 65_536;

#[derive(Debug, clap::Parser)]
#[command(name = "prowl keyring", no_binary_name = true)]
struct ProwlKeyringCli {
    #[command(subcommand)]
    cmd: ProwlKeyringCmd,
}

#[derive(Clone, Debug, clap::Subcommand)]
pub(crate) enum ProwlKeyringCmd {
    #[command(about = "store a provider API key in the OS credential store")]
    Set {
        #[arg(value_name = "PROVIDER")]
        provider: String,
        #[arg(
            value_name = "KEY",
            help = "the key; omit to read from PROWL_<PROVIDER>_API_KEY"
        )]
        key: Option<String>,
    },
    #[command(
        about = "show whether a provider key is present in the OS credential store (redacted)"
    )]
    Get {
        #[arg(value_name = "PROVIDER")]
        provider: String,
    },
    #[command(about = "remove a provider API key from the OS credential store")]
    Rm {
        #[arg(value_name = "PROVIDER")]
        provider: String,
    },
    #[command(about = "list which providers have a key in the OS credential store (redacted)")]
    List,
}

fn selected_sources(requested: &[String]) -> miette::Result<Vec<Source>> {
    if requested.is_empty() {
        return Ok(Source::all().to_vec());
    }
    let mut out: Vec<Source> = Vec::with_capacity(requested.len());
    for label in requested {
        let source: Source = Source::from_label(label.trim()).ok_or_else(|| {
            miette::miette!(
                "DR-PROWL-0040: unknown source '{label}' (use wayback, commoncrawl, otx, urlscan, crtsh, urlhaus, threatfox, virustotal)"
            )
        })?;
        if !out.contains(&source) {
            out.push(source);
        }
    }
    Ok(out)
}

fn selected_ioc_kinds(requested: &[String]) -> miette::Result<Vec<IocKind>> {
    let mut out: Vec<IocKind> = Vec::with_capacity(requested.len());
    for label in requested {
        let kind: IocKind = IocKind::from_label(label.trim()).ok_or_else(|| {
            miette::miette!(
                "DR-PROWL-0043: unknown ioc kind '{label}' (use subdomain, domain, ipv4, ipv6, email, md5, sha1, sha256, asn)"
            )
        })?;
        if !out.contains(&kind) {
            out.push(kind);
        }
    }
    Ok(out)
}

fn read_target_text_with_limit<R: std::io::Read>(
    reader: R,
    label: &str,
    limit: u64,
) -> miette::Result<String> {
    let mut limited: std::io::Take<R> = reader.take(limit.saturating_add(1));
    let mut bytes: Vec<u8> = Vec::new();
    limited
        .read_to_end(&mut bytes)
        .map_err(|e| miette::miette!("DR-PROWL-0059: {label} read: {e}"))?;
    let len: u64 = u64::try_from(bytes.len())
        .map_err(|_| miette::miette!("DR-PROWL-0060: {label} exceeds {limit} bytes"))?;
    if len > limit {
        return Err(miette::miette!(
            "DR-PROWL-0060: {label} exceeds {limit} bytes"
        ));
    }
    String::from_utf8(bytes)
        .map_err(|e| miette::miette!("DR-PROWL-0061: {label} is not utf-8: {e}"))
}

fn read_target_text<R: std::io::Read>(reader: R, label: &str) -> miette::Result<String> {
    read_target_text_with_limit(reader, label, MAX_TARGET_INPUT_BYTES)
}

fn read_stdin() -> miette::Result<String> {
    let stdin: std::io::Stdin = std::io::stdin();
    let lock: std::io::StdinLock<'_> = stdin.lock();
    read_target_text(lock, "stdin").map_err(|e| miette::miette!("DR-PROWL-0044: {e}"))
}

fn read_target_file(path: &std::path::Path, label: &str, code: &str) -> miette::Result<String> {
    let file: std::fs::File = std::fs::File::open(path)
        .map_err(|e| miette::miette!("{code}: {label} `{}`: {e}", path.display()))?;
    let display: String = format!("{label} `{}`", path.display());
    read_target_text(file, &display).map_err(|e| miette::miette!("{code}: {e}"))
}

fn push_target_with_limit(
    out: &mut Vec<String>,
    seen: &mut BTreeSet<String>,
    target: String,
    limit: usize,
) -> miette::Result<()> {
    if target.is_empty() || seen.contains(&target) {
        return Ok(());
    }
    if out.len() >= limit {
        return Err(miette::miette!(
            "DR-PROWL-0062: too many targets: exceeds {limit}"
        ));
    }
    seen.insert(target.clone());
    out.push(target);
    Ok(())
}

fn push_target(
    out: &mut Vec<String>,
    seen: &mut BTreeSet<String>,
    target: String,
) -> miette::Result<()> {
    push_target_with_limit(out, seen, target, MAX_TARGETS)
}

fn push_arg_target(
    out: &mut Vec<String>,
    seen: &mut BTreeSet<String>,
    raw: &str,
) -> miette::Result<()> {
    let normalized: String =
        disrobe_prowl::normalize_target(raw).unwrap_or_else(|| raw.trim().to_ascii_lowercase());
    push_target(out, seen, normalized)
}

fn push_target_lines(
    out: &mut Vec<String>,
    seen: &mut BTreeSet<String>,
    text: &str,
) -> miette::Result<()> {
    for line in text.lines() {
        if let Some(target) = disrobe_prowl::normalize_target(line) {
            push_target(out, seen, target)?;
        }
    }
    Ok(())
}

fn push_report_targets(
    out: &mut Vec<String>,
    seen: &mut BTreeSet<String>,
    text: &str,
) -> miette::Result<()> {
    for target in targets_from_disrobe_report(text) {
        push_target(out, seen, target)?;
    }
    Ok(())
}

fn collect_targets(args: &ProwlArgs) -> miette::Result<Vec<String>> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out: Vec<String> = Vec::new();
    for t in &args.targets {
        push_arg_target(&mut out, &mut seen, t)?;
    }
    if let Some(path) = &args.targets_file {
        let text: String = read_target_file(path, "targets file", "DR-PROWL-0045")?;
        push_target_lines(&mut out, &mut seen, &text)?;
    }
    if let Some(path) = &args.recon_input {
        let text: String = read_target_file(path, "recon input", "DR-PROWL-0046")?;
        push_report_targets(&mut out, &mut seen, &text)?;
    }
    if args.stdin {
        let text: String = read_stdin()?;
        if text.trim_start().starts_with('{') {
            push_report_targets(&mut out, &mut seen, &text)?;
        } else {
            push_target_lines(&mut out, &mut seen, &text)?;
        }
    }
    if out.is_empty() {
        return Err(miette::miette!(
            "DR-PROWL-0047: no targets (pass a domain, --targets-file, --recon-input, or --stdin)"
        ));
    }
    Ok(out)
}

fn render_text(report: &ProwlReport) {
    for u in &report.urls {
        println!("{}", u.url);
    }
    for ioc in &report.iocs {
        eprintln!("ioc {}: {}", ioc.kind.label(), ioc.value);
    }
    for status in &report.providers {
        if status.outcome != ProviderOutcome::Ok {
            let note: &str = status.note.as_deref().unwrap_or("");
            eprintln!(
                "provider {}: {} {note}",
                status.source.label(),
                status.outcome.label()
            );
        }
    }
    eprintln!(
        "{} url(s), {} ioc(s) from {} source(s) over {} target(s)",
        report.url_total,
        report.ioc_total,
        report.sources.len(),
        report.targets.len()
    );
}

fn parse_api_key_flag(raw: &str) -> miette::Result<(String, String)> {
    let (label, key): (&str, &str) = raw.split_once('=').ok_or_else(|| {
        miette::miette!("DR-PROWL-0050: --api-key expects provider=KEY (got `{raw}`)")
    })?;
    let source: Source = Source::from_label(label.trim())
        .ok_or_else(|| miette::miette!("DR-PROWL-0051: unknown provider `{label}` in --api-key"))?;
    Ok((source.label().to_owned(), key.to_owned()))
}

fn config_keys() -> BTreeMap<Source, String> {
    default_config_path()
        .and_then(|path: PathBuf| config_keys_at(&path).ok())
        .unwrap_or_default()
}

fn resolve_keys(flags: &FlagKeys, sources: &[Source]) -> (KeySet, Vec<String>) {
    let keyring: OsKeyring = OsKeyring::new();
    let config: BTreeMap<Source, String> = config_keys();
    let resolver: KeyResolver<'_> =
        KeyResolver::new(flags, config, Some(&keyring as &dyn KeyringBackend));
    let mut keyset: KeySet = KeySet::new();
    let mut notes: Vec<String> = Vec::new();
    for source in sources {
        match resolver.resolve(*source) {
            Ok(Some(key)) => keyset.insert(*source, key.expose().to_owned()),
            Ok(None) => {
                if matches!(auth_policy(*source), AuthPolicy::Required) {
                    notes.push(format!(
                        "{}: no API key configured - set {} (provider will be skipped)",
                        source.label(),
                        prowl_env(*source)
                    ));
                }
            }
            Err(err) => notes.push(format!("{}: {err}", source.label())),
        }
    }
    (keyset, notes)
}

fn keyring_provider(raw: &str) -> miette::Result<Source> {
    Source::from_label(raw.trim()).ok_or_else(|| {
        miette::miette!(
            "DR-PROWL-0052: unknown provider `{raw}` (use a source label, e.g. virustotal)"
        )
    })
}

pub(crate) fn run_keyring_argv(targets: &[String]) -> miette::Result<()> {
    use clap::Parser as _;
    let rest: &[String] = targets.get(1..).unwrap_or(&[]);
    let parsed: ProwlKeyringCli = ProwlKeyringCli::try_parse_from(rest)
        .map_err(|e: clap::Error| miette::miette!("DR-PROWL-0058: {e}"))?;
    run_keyring(parsed.cmd)
}

pub(crate) fn run_keyring(cmd: ProwlKeyringCmd) -> miette::Result<()> {
    let keyring: OsKeyring = OsKeyring::new();
    match cmd {
        ProwlKeyringCmd::Set { provider, key } => {
            let source: Source = keyring_provider(&provider)?;
            let value: String = match key {
                Some(k) => k,
                None => std::env::var(prowl_env(source)).map_err(|_| {
                    miette::miette!(
                        "DR-PROWL-0053: no key argument and {} is unset",
                        prowl_env(source)
                    )
                })?,
            };
            if value.trim().is_empty() {
                return Err(miette::miette!(
                    "DR-PROWL-0054: refusing to store an empty key"
                ));
            }
            keyring
                .set(&keyring_service(source), source.label(), value.trim())
                .map_err(|e: KeyError| miette::miette!("DR-PROWL-0055: keyring set: {e}"))?;
            eprintln!(
                "stored {} key (redacted {})",
                source.label(),
                redact(&value)
            );
            Ok(())
        }
        ProwlKeyringCmd::Get { provider } => {
            let source: Source = keyring_provider(&provider)?;
            let found: Option<String> = keyring
                .get(&keyring_service(source), source.label())
                .map_err(|e: KeyError| miette::miette!("DR-PROWL-0056: keyring get: {e}"))?;
            match found {
                Some(v) => println!("{}: {}", source.label(), redact(&v)),
                None => println!("{}: <none>", source.label()),
            }
            Ok(())
        }
        ProwlKeyringCmd::Rm { provider } => {
            let source: Source = keyring_provider(&provider)?;
            keyring
                .delete(&keyring_service(source), source.label())
                .map_err(|e: KeyError| miette::miette!("DR-PROWL-0057: keyring rm: {e}"))?;
            eprintln!("removed {} key", source.label());
            Ok(())
        }
        ProwlKeyringCmd::List => {
            for source in Source::all() {
                if matches!(auth_policy(source), AuthPolicy::None) {
                    continue;
                }
                let present: bool = keyring
                    .get(&keyring_service(source), source.label())
                    .ok()
                    .flatten()
                    .is_some();
                let conv: &str = conventional_env(source).unwrap_or("-");
                println!(
                    "{:<12} keyring={} env={} ({})",
                    source.label(),
                    if present { "yes" } else { "no" },
                    prowl_env(source),
                    conv
                );
            }
            Ok(())
        }
    }
}

pub(crate) fn run(args: ProwlArgs, fmt: OutputFormat) -> miette::Result<()> {
    let sources: Vec<Source> = selected_sources(&args.sources)?;
    let ioc_kinds: Vec<IocKind> = selected_ioc_kinds(&args.ioc_kinds)?;
    let targets: Vec<String> = collect_targets(&args)?;

    let mut flag_keys: FlagKeys = FlagKeys::new();
    for raw in &args.api_keys {
        let (label, key): (String, String) = parse_api_key_flag(raw)?;
        if let Some(source) = Source::from_label(&label) {
            flag_keys.set(source, key);
        }
    }
    let (keyset, key_notes): (KeySet, Vec<String>) = resolve_keys(&flag_keys, &sources);
    for note in &key_notes {
        eprintln!("prowl: {note}");
    }

    let filter: Filter = Filter {
        blacklist_extensions: args.blacklist.clone(),
        subs: args.subs,
        from: args.from.clone(),
        to: args.to.clone(),
        match_status: args.match_status.clone(),
        exclude_status: args.filter_status.clone(),
        match_mime: args.match_mime.clone(),
        exclude_mime: args.filter_mime.clone(),
        collapse_params: args.collapse_params,
        ioc_kinds,
    };

    let http_config: HttpConfig = HttpConfig {
        timeout: Duration::from_secs(args.timeout_secs),
        proxy: args.proxy.clone(),
        ..HttpConfig::default()
    };
    let fetcher: Arc<dyn Fetcher> = Arc::new(
        ReqwestFetcher::new(&http_config)
            .map_err(|e| miette::miette!("DR-PROWL-0041: http client: {e}"))?,
    );

    let engine_config: EngineConfig = EngineConfig {
        provider_concurrency: args.concurrency.max(1),
        max_pages_per_provider: args.max_pages.max(1),
        max_urls: args.max_urls,
        max_iocs: args.max_iocs,
        max_retries: args.retries,
        per_host_rps: args.per_host_rps.max(0.0),
        extract_iocs: !args.no_iocs,
        ..EngineConfig::default()
    };

    let runtime: tokio::runtime::Runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| miette::miette!("DR-PROWL-0042: tokio runtime build failed: {e}"))?;

    let report: ProwlReport = runtime.block_on(disrobe_prowl::harvest_with_keys(
        fetcher,
        &targets,
        &sources,
        &filter,
        &engine_config,
        &keyset,
    ));

    let effective: ProwlFormat = if fmt.is_machine() {
        ProwlFormat::Json
    } else {
        args.format
    };
    match effective {
        ProwlFormat::Text => {
            render_text(&report);
            Ok(())
        }
        ProwlFormat::Json => {
            let s: String = serde_json::to_string_pretty(&report)
                .map_err(|e| miette::miette!("DR-PROWL-0048: json serialize: {e}"))?;
            println!("{s}");
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_sources_selects_all() {
        let all: Vec<Source> = selected_sources(&[]).expect("all");
        assert_eq!(all, Source::all().to_vec());
    }

    #[test]
    fn named_sources_dedup_and_validate() {
        let picked: Vec<Source> = selected_sources(&[
            "wayback".to_owned(),
            "crtsh".to_owned(),
            "wayback".to_owned(),
        ])
        .expect("valid");
        assert_eq!(picked, vec![Source::Wayback, Source::Crtsh]);
        assert!(selected_sources(&["bogus".to_owned()]).is_err());
    }

    #[test]
    fn unknown_source_guidance_lists_virustotal() {
        let error: String = selected_sources(&["bogus".to_owned()])
            .expect_err("unknown source must fail")
            .to_string();
        assert!(error.contains("virustotal"), "{error}");
    }

    #[test]
    fn ioc_kinds_validate() {
        let picked: Vec<IocKind> =
            selected_ioc_kinds(&["ipv4".to_owned(), "sha256".to_owned()]).expect("valid");
        assert_eq!(picked, vec![IocKind::Ipv4, IocKind::Sha256]);
        assert!(selected_ioc_kinds(&["nope".to_owned()]).is_err());
    }

    #[test]
    fn api_key_flag_parses_provider_and_value() {
        let (label, key): (String, String) =
            parse_api_key_flag("virustotal=vt-secret-9999999999").expect("valid flag");
        assert_eq!(label, "virustotal");
        assert_eq!(key, "vt-secret-9999999999");
        let (vt_alias, _): (String, String) =
            parse_api_key_flag("vt=alias-key-1234567890").expect("alias accepted");
        assert_eq!(vt_alias, "virustotal");
        assert!(parse_api_key_flag("no-equals").is_err());
        assert!(parse_api_key_flag("bogus=key").is_err());
    }

    #[test]
    fn flag_keys_resolve_into_keyset_and_redact() {
        let mut flags: FlagKeys = FlagKeys::new();
        flags.set(Source::Virustotal, "vt-flag-key-aaaaaaaaaa".to_owned());
        let (keyset, _notes): (KeySet, Vec<String>) =
            resolve_keys(&flags, &[Source::Virustotal, Source::Wayback]);
        assert_eq!(
            keyset.get(Source::Virustotal),
            Some("vt-flag-key-aaaaaaaaaa")
        );
        assert_eq!(keyset.get(Source::Wayback), None);
        let masked: String = redact("vt-flag-key-aaaaaaaaaa");
        assert!(!masked.contains("aaaaaaaaaa"), "{masked}");
    }

    #[test]
    fn target_reader_rejects_limit_overrun() {
        let input: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(b"abcd".to_vec());
        let err: String = read_target_text_with_limit(input, "targets", 3)
            .expect_err("overrun must fail")
            .to_string();
        assert!(err.contains("exceeds 3 bytes"), "{err}");
    }

    #[test]
    fn target_collector_rejects_unique_target_overflow() {
        let mut out: Vec<String> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        push_target_with_limit(&mut out, &mut seen, "a.example".to_owned(), 2).unwrap();
        push_target_with_limit(&mut out, &mut seen, "b.example".to_owned(), 2).unwrap();
        push_target_with_limit(&mut out, &mut seen, "a.example".to_owned(), 2).unwrap();
        let err: String = push_target_with_limit(&mut out, &mut seen, "c.example".to_owned(), 2)
            .expect_err("third unique target must fail")
            .to_string();
        assert!(err.contains("too many targets"), "{err}");
        assert_eq!(out, vec!["a.example", "b.example"]);
    }
}
