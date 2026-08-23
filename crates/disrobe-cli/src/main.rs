#![recursion_limit = "256"]
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::redundant_pub_crate,
    clippy::unnecessary_wraps,
    clippy::too_many_lines
)]

mod cli;

use std::path::PathBuf;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};

use cli::annot::{self, AnnotCmd};
#[cfg(feature = "jvm")]
use cli::apk;
#[cfg(feature = "as3")]
use cli::as3::{self, As3Cmd};
#[cfg(feature = "chain")]
use cli::auto;
#[cfg(feature = "beam")]
use cli::beam::{self, BeamCmd};
use cli::behavior;
use cli::bug_report;
use cli::capabilities;
#[cfg(feature = "chain")]
use cli::catalog;
#[cfg(feature = "chain")]
use cli::chain_compare;
#[cfg(feature = "chain")]
use cli::chain_v1;
use cli::completions as completions_cmd;
use cli::config::{self, ConfigCmd};
use cli::config_merge::{self, CliGlobalsSnapshot, EffectiveGlobals};
use cli::context;
#[cfg(feature = "chain")]
use cli::detect;
use cli::doctor;
#[cfg(feature = "dotnet")]
use cli::dotnet::{self, DotnetCmd};
use cli::envelope::{self, CacheSettings, EnvelopeCmd};
use cli::explain;
use cli::extract;
#[cfg(feature = "flutter")]
use cli::flutter::{self, FlutterCmd};
use cli::frisk::{self, FriskFormat};
use cli::globals::{self, Globals, ProgressMode};
#[cfg(feature = "go")]
use cli::go::{self, GoCmd};
#[cfg(feature = "chain")]
use cli::guard;
#[cfg(feature = "mobile")]
use cli::hermes::{self, HermesCmd};
use cli::identify;
use cli::indicators::{self, IndicatorsFormat};
use cli::init::{self as init_cmd, IdeFlavor};
use cli::install as install_cmd;
use cli::install_deps::{self, InstallDepsCmd};
use cli::ioc::{self, IocFormat};
#[cfg(feature = "js")]
use cli::js::{self, JsCmd};
#[cfg(feature = "jvm")]
use cli::jvm::{self, JvmCmd};
use cli::llm::LlmFlags;
#[cfg(feature = "lua")]
use cli::lua::{self, LuaCmd};
#[cfg(feature = "swift")]
use cli::macho::{self, MachoCmd};
use cli::man;
#[cfg(feature = "mobile")]
use cli::mobile::{self, MobileCmd};
use cli::native;
use cli::native_match;
use cli::nuitka::{self, NuitkaCmd};
use cli::output::OutputFormat;
#[cfg(feature = "php")]
use cli::php::{self, PhpCmd};
#[cfg(feature = "pickle")]
use cli::pickle::{self, PickleCmd};
#[cfg(feature = "plugin")]
use cli::plugin::{self, PluginCmd};
use cli::progress_ui;
use cli::prowl::ProwlFormat;
#[cfg(feature = "prowl")]
use cli::prowl::{self, ProwlArgs};
use cli::py::{self, PyCmd};
use cli::pyarmor::{self, PyarmorCmd};
use cli::pyfreeze::{self, PyfreezeCmd};
use cli::pyinstaller::{self, PyinstallerCmd};
use cli::query;
use cli::rename;
#[cfg(feature = "chain")]
use cli::report::{self, ReportFormat};
#[cfg(feature = "ruby")]
use cli::ruby::{self, RubyCmd};
use cli::scan;
use cli::self_update as self_update_cmd;
use cli::semdiff;
#[cfg(feature = "server")]
use cli::serve;
#[cfg(feature = "shell")]
use cli::shell::{self, ShellCmd};
use cli::status as status_cmd;
use cli::strings as strings_cmd;
#[cfg(feature = "swift")]
use cli::swift::{self, SwiftCmd};
use cli::taint;
use cli::util::init_tracing;
use cli::vulnmatch;
use cli::wasm_cmd::WasmCmd;
use cli::webview;
use cli::yara::{self, YaraCmd};

const ABOUT: &str = "strip the obfuscation, read the source";
const LONG_ABOUT: &str = "disrobe is a deterministic deobfuscator & decompiler suite. it covers Python bytecode, JavaScript / TypeScript, WebAssembly, JVM / Android, .NET, native PE / ELF / Mach-O, native packers (UPX, MPRESS, NSPack, FSG, kkrunchy, mew, ...), Go, Lua, PHP, Ruby, BEAM, Swift / Objective-C, AS3, Hermes, Flutter, & the freezer / protector chains stacked on top.\n\nrun `disrobe doctor` to probe external tools, `disrobe install <tool>` to install one, or `disrobe install --list` to list every known tool.";

#[derive(Parser, Debug)]
#[command(name = "disrobe", version, about = ABOUT, long_about = LONG_ABOUT, propagate_version = true, infer_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,

    #[arg(short, long, action = clap::ArgAction::Count, global = true, help = "increase log verbosity (-v, -vv, -vvv)")]
    verbose: u8,

    #[arg(short, long, global = true, help = "suppress non-error output")]
    quiet: bool,

    #[arg(
        long,
        global = true,
        help = "emit structured JSON instead of human text"
    )]
    json: bool,

    #[arg(long, global = true, help = "emit newline-delimited JSON (streaming)")]
    ndjson: bool,

    #[arg(
        long,
        global = true,
        help = "emit SARIF 2.1.0 (for GitHub code scanning, etc.)"
    )]
    sarif: bool,

    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help = "TOML config file path"
    )]
    config: Option<PathBuf>,

    #[arg(long, global = true, help = "rewrite the input file in place")]
    in_place: bool,

    #[arg(
        long,
        global = true,
        help = "overwrite existing outputs without prompting"
    )]
    force: bool,

    #[arg(
        long,
        short = 'j',
        global = true,
        value_name = "N",
        help = "worker thread pool size"
    )]
    threads: Option<u32>,

    #[arg(long, global = true, help = "bypass the .dr envelope cache")]
    no_cache: bool,

    #[arg(
        long,
        global = true,
        help = "report what would happen without writing any output"
    )]
    dry_run: bool,

    #[arg(long, global = true, value_name = "MODE", default_value_t = ProgressMode::Auto, help = "progress bar rendering: auto, always, never")]
    progress: ProgressMode,

    #[command(flatten)]
    llm: LlmFlags,
}

#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
enum Cmd {
    #[command(about = "unpack a PyArmor-protected wrapper (v6 / v7 / v8 / v9-pro)")]
    Pyarmor {
        #[command(subcommand)]
        action: PyarmorCmd,
    },
    #[command(about = "detect & extract PyInstaller onefile / onedir executables")]
    Pyinstaller {
        #[command(subcommand)]
        action: PyinstallerCmd,
    },
    #[command(
        about = "detect & extract cx_Freeze / py2exe / shiv / pex / PyOxidizer (experimental, unvalidated) / Briefcase containers"
    )]
    Pyfreeze {
        #[command(subcommand)]
        action: PyfreezeCmd,
    },
    #[command(about = "detect, extract, & symbol-dump Nuitka --onefile / --standalone builds")]
    Nuitka {
        #[command(subcommand)]
        action: NuitkaCmd,
    },
    #[command(
        about = "Python source / .pyc deobfuscate, disassemble, decompile, extract, sourcedefender decrypt"
    )]
    Py {
        #[command(subcommand)]
        action: PyCmd,
    },
    #[command(
        about = "scan a target's raw bytes for leaked credentials (cloud keys, VCS tokens, JWTs, PEM/SSH keys)"
    )]
    Scan {
        #[arg(value_name = "PATH")]
        path: PathBuf,
        #[arg(
            long,
            help = "replace every detected secret with a stable truncated SHA-256 token"
        )]
        redact: bool,
    },
    #[command(
        about = "extract indicators of compromise (URLs, IPs, domains, emails, paths, registry keys, wallets, crypto constants) from raw bytes & recovered strings, decoding one base64/hex layer"
    )]
    Ioc {
        #[arg(value_name = "PATH")]
        path: PathBuf,
        #[arg(
            long,
            value_enum,
            default_value_t = IocFormat::Text,
            help = "output format: text, json, or sarif"
        )]
        format: IocFormat,
        #[arg(
            long,
            help = "neutralize indicators for safe reporting (hxxp://, 1[.]2[.]3[.]4)"
        )]
        defang: bool,
    },
    #[command(
        about = "aggregate disrobe recon/ioc/prowl JSON artifacts into one versioned indicator bundle (disrobe.indicators/v0) with per-indicator source provenance; --targets-only re-seeds a prowl harvest"
    )]
    Indicators {
        #[arg(
            value_name = "JSON",
            help = "one or more disrobe recon/ioc/prowl JSON report files"
        )]
        inputs: Vec<PathBuf>,
        #[arg(
            long,
            help = "print only the network indicators as bare targets (host/ip), one per line, ready to feed `prowl --targets-file`"
        )]
        targets_only: bool,
        #[arg(
            long,
            value_enum,
            default_value_t = IndicatorsFormat::Text,
            help = "output format: text or json"
        )]
        format: IndicatorsFormat,
    },
    #[command(
        about = "recon a file or recovered source tree for secrets, API endpoints, cloud storage, and IOCs with per-finding file:line (encoding-safe)"
    )]
    Frisk {
        #[arg(value_name = "PATH")]
        path: PathBuf,
        #[arg(
            long,
            value_enum,
            default_value_t = FriskFormat::Text,
            help = "output format: text, json, or sarif"
        )]
        format: FriskFormat,
        #[arg(
            long,
            value_name = "FILE",
            help = "custom rule pack: `name=regex` per line, # comments allowed"
        )]
        pattern: Option<PathBuf>,
        #[arg(
            long,
            value_name = "SUBSTR",
            help = "suppress findings whose value contains this substring (repeatable)"
        )]
        suppress: Vec<String>,
        #[arg(
            long,
            value_name = "FILE",
            help = "baseline JSON array of finding fingerprints to ignore"
        )]
        baseline: Option<PathBuf>,
        #[arg(
            long,
            help = "print the current findings as a baseline JSON array (snapshot to suppress later)"
        )]
        emit_baseline: bool,
        #[arg(long, help = "include high-entropy generic-secret findings")]
        entropy: bool,
        #[arg(
            long,
            help = "scan the full git commit history at PATH (finds secrets in deleted/rewritten blobs a working-tree walk misses)"
        )]
        git: bool,
        #[arg(
            long,
            help = "replace every detected secret with a stable truncated SHA-256 token in every output format"
        )]
        redact: bool,
    },
    #[command(
        about = "harvest URLs and IoCs for a target from public web archives and threat-intel feeds (Wayback, Common Crawl, OTX, urlscan, crt.sh, URLhaus, ThreatFox, VirusTotal) with async fan-out, per-host rate limiting, backoff, API-key auth, filtering & dedup; `prowl keyring set|get|rm|list <provider>` manages stored keys"
    )]
    Prowl {
        #[arg(
            value_name = "TARGET",
            help = "targets, or `keyring set|get|rm|list <provider>` to manage stored API keys"
        )]
        targets: Vec<String>,
        #[arg(
            long,
            value_name = "FILE",
            help = "read targets (one domain/url per line) from a file"
        )]
        targets_file: Option<PathBuf>,
        #[arg(
            long,
            value_name = "FILE",
            help = "seed targets from a disrobe recon/IoC report (its urls/domains/ips)"
        )]
        recon_input: Option<PathBuf>,
        #[arg(long, help = "read targets (lines or a recon/IoC report) from stdin")]
        stdin: bool,
        #[arg(
            long,
            value_name = "LIST",
            value_delimiter = ',',
            help = "sources to query (default all): wayback,commoncrawl,otx,urlscan,crtsh,urlhaus,threatfox,virustotal"
        )]
        sources: Vec<String>,
        #[arg(long, help = "include subdomains of the target")]
        subs: bool,
        #[arg(
            long,
            value_name = "EXT",
            value_delimiter = ',',
            help = "drop URLs with these file extensions (e.g. png,jpg,css)"
        )]
        blacklist: Vec<String>,
        #[arg(
            long,
            value_name = "YYYYMMDD",
            help = "earliest capture date (Wayback)"
        )]
        from: Option<String>,
        #[arg(long, value_name = "YYYYMMDD", help = "latest capture date (Wayback)")]
        to: Option<String>,
        #[arg(
            long,
            value_name = "CODE",
            value_delimiter = ',',
            help = "keep only these HTTP status codes"
        )]
        mc: Vec<u16>,
        #[arg(
            long,
            value_name = "CODE",
            value_delimiter = ',',
            help = "drop these HTTP status codes"
        )]
        fc: Vec<u16>,
        #[arg(
            long,
            value_name = "MIME",
            value_delimiter = ',',
            help = "keep only URLs whose MIME contains one of these"
        )]
        mt: Vec<String>,
        #[arg(
            long,
            value_name = "MIME",
            value_delimiter = ',',
            help = "drop URLs whose MIME contains one of these"
        )]
        ft: Vec<String>,
        #[arg(
            long,
            value_name = "KIND",
            value_delimiter = ',',
            help = "keep only these IoC kinds: subdomain,domain,ipv4,ipv6,email,md5,sha1,sha256,asn"
        )]
        ioc: Vec<String>,
        #[arg(
            long,
            help = "collapse URLs that differ only in query-parameter values"
        )]
        fp: bool,
        #[arg(long, help = "do not derive structured IoCs from harvested URLs")]
        no_iocs: bool,
        #[arg(
            long,
            value_name = "URL",
            help = "route requests through an HTTP(S)/SOCKS proxy (else HTTP(S)_PROXY env)"
        )]
        proxy: Option<String>,
        #[arg(
            long,
            default_value_t = 45,
            value_name = "SECS",
            help = "per-request HTTP timeout"
        )]
        timeout: u64,
        #[arg(
            long,
            default_value_t = 12,
            value_name = "N",
            help = "concurrent in-flight source/target requests"
        )]
        concurrency: usize,
        #[arg(
            long,
            default_value_t = 4.0,
            value_name = "RPS",
            help = "per-host request rate (independent hosts run concurrent); 0 disables"
        )]
        per_host_rps: f64,
        #[arg(
            long = "api-key",
            value_name = "PROVIDER=KEY",
            help = "provider API key (discouraged; prefer PROWL_<PROVIDER>_API_KEY or `prowl keyring set`)"
        )]
        api_key: Vec<String>,
        #[arg(
            long,
            default_value_t = 50,
            value_name = "N",
            help = "max paginated requests per source"
        )]
        max_pages: u32,
        #[arg(
            long,
            default_value_t = 1_000_000,
            value_name = "N",
            help = "max URLs to keep"
        )]
        max_urls: usize,
        #[arg(
            long,
            default_value_t = 1_000_000,
            value_name = "N",
            help = "max IOCs to keep"
        )]
        max_iocs: usize,
        #[arg(
            long,
            default_value_t = 3,
            value_name = "N",
            help = "retries on 429/5xx with exponential backoff"
        )]
        retries: u32,
        #[arg(
            long,
            value_enum,
            default_value_t = ProwlFormat::Text,
            help = "output format: text or json"
        )]
        format: ProwlFormat,
    },
    #[command(
        about = "extract ASCII + UTF-16LE strings & deobfuscate (single-byte XOR brute, base64, ROT-n, stack-string reconstruction)"
    )]
    Strings {
        #[arg(value_name = "PATH")]
        path: PathBuf,
        #[arg(
            long,
            default_value_t = disrobe_core::strings::DEFAULT_MIN_LEN,
            value_name = "N",
            help = "minimum printable run length to report"
        )]
        min_len: usize,
        #[arg(
            long,
            help = "disable deobfuscation passes; report only plain ASCII / UTF-16 strings"
        )]
        no_decode: bool,
    },
    #[command(
        about = "summarize what a binary DOES (network, filesystem, process/exec, registry/persistence, crypto, anti-analysis, dynamic-code) with MITRE ATT&CK technique ids"
    )]
    Behavior {
        #[arg(value_name = "PATH")]
        path: PathBuf,
        #[arg(
            long,
            help = "also lift the input to the intermediate representation and report, per hard effect, how many instructions carry it and what evidence assigned it"
        )]
        effects: bool,
    },
    #[command(
        alias = "die",
        about = "identify what built or packed a PE / ELF / Mach-O: compiler, linker, packer, protector, installer, with structural evidence and version, and the disrobe pass that handles each"
    )]
    Identify {
        #[arg(value_name = "PATH")]
        path: PathBuf,
        #[arg(
            long,
            help = "also account for every byte of the file against the structures its format declares, reporting unclaimed, slack, overlapping, unbacked and missing bytes"
        )]
        coverage: bool,
    },
    #[cfg(feature = "chain")]
    #[command(
        about = "detect parsed New Executable structure and run every obfuscator/packer catalog detector against a file"
    )]
    Detect {
        #[arg(value_name = "PATH", help = "input file to fingerprint")]
        input: PathBuf,
    },
    #[cfg(feature = "chain")]
    #[command(
        about = "list every obfuscator/packer/protector family disrobe supports, grouped by ecosystem with each one's recovery level; pass an ecosystem (python, js, jvm, dotnet, native, go, wasm, ruby, lua, php, beam, as3, mobile, swift, shell) to filter"
    )]
    Catalog {
        #[arg(
            value_name = "ECOSYSTEM",
            help = "filter to one ecosystem (python, js, jvm, dotnet, native, go, wasm, ruby, lua, php, beam, as3, mobile, swift, shell); omit for all"
        )]
        ecosystem: Option<String>,
    },
    #[command(
        about = "carve & extract a container or firmware image: detect every known format at any offset, recurse into nested archives, split unknown / padding regions, report per-chunk entropy"
    )]
    Extract {
        #[arg(value_name = "PATH")]
        input: PathBuf,
        #[arg(long, value_name = "DIR", help = "output directory for carved members")]
        out: Option<PathBuf>,
        #[arg(
            long,
            help = "carve recursively: re-scan every extracted file for further nested formats"
        )]
        recursive: bool,
        #[arg(
            long,
            default_value_t = disrobe_binfmt::DEFAULT_MAX_DEPTH,
            value_name = "N",
            help = "maximum recursion depth when --recursive is set"
        )]
        max_depth: u32,
    },
    #[command(
        about = "static-carve the shipped web frontend (HTML/JS/CSS/assets) from a compiled webview-desktop binary (Electron ASAR byte-exact; Tauri/Wails byte-exact against a compressed embedded asset map)"
    )]
    Webview {
        #[arg(value_name = "PATH", help = "input webview-desktop binary")]
        input: PathBuf,
        #[arg(
            long,
            value_name = "DIR",
            help = "output directory for the recovered asset tree (default: ./out/<stem>-webview)"
        )]
        out: Option<PathBuf>,
    },
    #[command(
        about = "YARA tooling: parse a ruleset into a typed AST (read-only), or generate a candidate rule from an artifact"
    )]
    Yara {
        #[command(subcommand)]
        action: YaraCmd,
    },
    #[cfg(feature = "js")]
    #[command(about = "JavaScript / TypeScript deobfuscate & bundle splitter")]
    Js {
        #[command(subcommand)]
        action: JsCmd,
    },
    #[command(
        about = "WebAssembly analyze, decompile (Rust / TypeScript / WAT / C), deobfuscate, component / GC types"
    )]
    Wasm {
        #[command(subcommand)]
        action: WasmCmd,
    },
    #[command(
        about = "native PE / ELF / Mach-O: in-tree x86-64 -> C decompile, symbol dump, unpack, disassemble, Ghidra-headless"
    )]
    Native {
        #[command(subcommand)]
        action: NativeCmd,
    },
    #[cfg(feature = "jvm")]
    #[command(
        about = "JVM / Android decompile: classfile, .jar, .dex, .apk through CFR / Vineflower / Procyon / JADX"
    )]
    Jvm {
        #[command(subcommand)]
        action: JvmCmd,
    },
    #[cfg(feature = "jvm")]
    #[command(
        about = "analyze an .apk: decode the binary AndroidManifest.xml, map resource ids to names, and dump each signer certificate's SHA-256"
    )]
    Apk {
        #[arg(value_name = "PATH", help = "input .apk file")]
        path: PathBuf,
        #[arg(
            short,
            long,
            help = "write the decoded AndroidManifest.xml and the resource id->name table to this directory"
        )]
        out: Option<PathBuf>,
    },
    #[cfg(feature = "dotnet")]
    #[command(
        about = ".NET decompile & static analysis: PE/CLR, ILSpy / dnSpyEx / de4dot, protector detection"
    )]
    Dotnet {
        #[command(subcommand)]
        action: DotnetCmd,
    },
    #[cfg(feature = "mobile")]
    #[command(about = "React Native Hermes bundle: lift to JS surface, disassemble, header info")]
    Hermes {
        #[command(subcommand)]
        action: HermesCmd,
    },
    #[cfg(feature = "swift")]
    #[command(
        about = "Mach-O / Fat-Mach-O / .ipa dump, raw-Mach-O ObjC + Swift class-dump, fat slice walker"
    )]
    Macho {
        #[command(subcommand)]
        action: MachoCmd,
    },
    #[cfg(feature = "lua")]
    #[command(
        about = "Lua 5.1 / 5.2 / 5.3 / 5.4 / LuaJIT / Luau / GLua decompile & obfuscator peel (Prometheus, MoonSec, Ironbrew2, ...)"
    )]
    Lua {
        #[command(subcommand)]
        action: LuaCmd,
    },
    #[cfg(feature = "php")]
    #[command(
        about = "PHP phar decode, commercial encoder envelope report (ionCube, SourceGuardian, ZendGuard), & eval-chain deobfuscation"
    )]
    Php {
        #[command(subcommand)]
        action: PhpCmd,
    },
    #[cfg(feature = "shell")]
    #[command(
        about = "shell / batch / VBA deobfuscate: PowerShell (Invoke-Obfuscation, Invoke-Stealth, PowerHell, Chameleon, psobf), Bashfuscator, batch, VBA macros"
    )]
    Shell {
        #[command(subcommand)]
        action: ShellCmd,
    },
    #[cfg(feature = "ruby")]
    #[command(
        about = "Ruby flavor analysis: MRI source, YARV binary, mruby RITE, JRuby class, TruffleRuby AOT, Ruby2Exe, Ocra"
    )]
    Ruby {
        #[command(subcommand)]
        action: RubyCmd,
    },
    #[cfg(feature = "beam")]
    #[command(
        about = "BEAM (Erlang / Elixir) IFF chunk parse, Core Erlang lift, Code chunk disassemble"
    )]
    Beam {
        #[command(subcommand)]
        action: BeamCmd,
    },
    #[cfg(feature = "pickle")]
    #[command(
        about = "Python pickle: disasm, decompile, safety analysis, symbolic trace, polyglot & ML model-file detection"
    )]
    Pickle {
        #[command(subcommand)]
        action: PickleCmd,
    },
    #[cfg(feature = "plugin")]
    #[command(
        about = "signed WebAssembly component plugin sandbox: run, verify, list (fuel/wall-deadline/memory-capped, deny-all-imports)"
    )]
    Plugin {
        #[command(subcommand)]
        action: PluginCmd,
    },
    #[cfg(feature = "go")]
    #[command(
        about = "Go binary recovery: pclntab, moduledata, garble report, embed.FS extraction (PE / ELF / Mach-O)"
    )]
    Go {
        #[command(subcommand)]
        action: GoCmd,
    },
    #[cfg(feature = "swift")]
    #[command(
        about = "Swift / Objective-C class-dump, SwiftShield mapping parser, explicit-key XOR blob decoding"
    )]
    Swift {
        #[command(subcommand)]
        action: SwiftCmd,
    },
    #[cfg(feature = "as3")]
    #[command(about = "ActionScript 3 disassembly: SWF parse + DoABC tag disasm")]
    As3 {
        #[command(subcommand)]
        action: As3Cmd,
    },
    #[cfg(feature = "flutter")]
    #[command(
        about = "Flutter / Dart AOT: libapp.so symbol layout, Dart snapshot decompile, obfuscation_map parser"
    )]
    Flutter {
        #[command(subcommand)]
        action: FlutterCmd,
    },
    #[cfg(feature = "mobile")]
    #[command(
        about = "mobile app pipeline: detect runtime, extract React Native bundles, Hermes disasm + JS lift, Flutter libapp dump"
    )]
    Mobile {
        #[command(subcommand)]
        action: MobileCmd,
    },
    #[command(
        about = ".dr envelope create / inspect / verify (rkyv hot payload + postcard cold sidecar + BLAKE3 root hash)"
    )]
    Envelope {
        #[command(subcommand)]
        action: EnvelopeCmd,
    },
    #[command(
        about = "query a native binary or a Disasm- or Mir-rung .dr envelope's IR: functions, calls-to <sym>, xrefs-to <sym>, string-decoders, complexity-over <N>, capability <network|crypto|filesystem|process>"
    )]
    Query {
        #[arg(
            value_name = "INPUT",
            help = "native binary (PE/ELF/Mach-O/COFF) or a Disasm- or Mir-rung .dr envelope to query"
        )]
        input: PathBuf,
        #[arg(
            value_name = "QUERY",
            num_args = 1..,
            required = true,
            help = "query expression, e.g. `calls-to read_byte` or `complexity-over 10`"
        )]
        query: Vec<String>,
    },
    #[command(
        about = "match a native binary against a built-in capability rule set (create/write/read file, network connect, http, registry persistence, anti-debug, xor-decrypt, resolve-api-by-hash, ...) and report each capability with its evidence address and MITRE ATT&CK / MBC tags"
    )]
    Capabilities {
        #[arg(
            value_name = "INPUT",
            help = "native binary (PE/ELF/Mach-O/COFF) or a Disasm- or Mir-rung .dr envelope to scan"
        )]
        input: PathBuf,
    },
    #[command(
        about = "track a value from a declared source call to a declared sink call across the normalized IR: lifts a native binary, a wasm module, a JVM/Dalvik class/dex, or a Disasm/Mir-rung .dr envelope, then reports every source-to-sink flow (input/recv/read sources reaching exec/system/write/connect sinks by default)"
    )]
    Taint {
        #[arg(
            value_name = "INPUT",
            help = "native binary (PE/ELF/Mach-O/COFF), wasm module, JVM .class, Android .dex, or a Disasm/Mir-rung .dr envelope"
        )]
        input: PathBuf,
        #[arg(
            long = "source",
            value_name = "SYMBOL",
            help = "treat calls to SYMBOL as a taint source; repeatable; replaces the built-in source set when supplied"
        )]
        source: Vec<String>,
        #[arg(
            long = "sink",
            value_name = "SYMBOL",
            help = "treat calls to SYMBOL as a taint sink; repeatable; replaces the built-in sink set when supplied"
        )]
        sink: Vec<String>,
    },
    #[command(
        about = "pair the functions of two builds by what they compute, not by name: lifts both inputs to the normalized IR, matches leaf functions on an exact structural signature, then on a symbolic summary, then propagates along the call graph, and reports every refusal with its typed reason. Works on any input the lifters accept (native, wasm, JVM/Dalvik, .NET, Python, Lua, Ruby, BEAM, ABC), unlike `native diff` and `native match`, which read native images only"
    )]
    Semdiff {
        #[arg(
            value_name = "BASE",
            help = "the reference build: native binary, wasm module, JVM .class, Android .dex, managed PE, .pyc, or a Disasm/Mir-rung .dr envelope"
        )]
        base: PathBuf,
        #[arg(
            value_name = "OTHER",
            num_args = 1..,
            required = true,
            help = "the build to pair against BASE; must lift to the same source language. Pass more than one only with --lineage"
        )]
        others: Vec<PathBuf>,
        #[arg(
            long = "lineage",
            help = "track each BASE function across every OTHER build at once and group the correspondences into families, instead of reporting one pair"
        )]
        lineage: bool,
        #[arg(
            long = "limit",
            value_name = "N",
            help = "list at most N rows per section; totals are always exact"
        )]
        limit: Option<usize>,
    },
    #[command(
        about = "match reachability-aware vulnerability rules against a native binary or a Disasm- or Mir-rung .dr envelope, preserving reachable, reachability-unknown, present, and confirmed findings"
    )]
    Vulnmatch {
        #[arg(
            value_name = "INPUT",
            help = "native binary (PE/ELF/Mach-O/COFF) or a Disasm- or Mir-rung .dr envelope"
        )]
        input: PathBuf,
        #[arg(
            long = "osv-db",
            value_name = "FILE",
            help = "match installed Debian packages in an extracted root filesystem against one local OSV v1 vulnerability document"
        )]
        osv_db: Option<PathBuf>,
        #[arg(long, help = "emit OpenVEX 0.2.0 JSON instead of the normal report")]
        openvex: bool,
        #[arg(
            long,
            value_name = "IDENTITY",
            requires = "openvex",
            help = "OpenVEX document author identity"
        )]
        author: Option<String>,
        #[arg(
            long,
            value_name = "UTC",
            requires = "openvex",
            help = "OpenVEX issue time in canonical UTC form YYYY-MM-DDTHH:MM:SSZ"
        )]
        timestamp: Option<String>,
    },
    #[cfg(feature = "chain")]
    #[command(
        about = "auto-detect the input format & chain the right pass pipeline end-to-end; pass a directory to batch-process it recursively"
    )]
    Auto {
        #[arg(help = "input file, or a directory to walk and batch-process recursively")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output directory (file: ./out/<stem>-auto; directory: ./out/<dir>-batch)"
        )]
        out: Option<PathBuf>,
        #[arg(
            long,
            default_value_t = 8,
            help = "maximum chain depth before stopping"
        )]
        max_depth: u8,
        #[arg(
            long,
            value_delimiter = ',',
            help = "comma-separated emit kinds; for `auto` only `recovery` (echo recovery.json to stdout) is accepted"
        )]
        emit: Vec<String>,
        #[arg(long, help = "report what would happen without writing any output")]
        dry_run: bool,
        #[arg(
            long,
            help = "replace detected secret values in reports with stable redaction tokens"
        )]
        redact: bool,
        #[arg(
            long,
            help = "mirror each executed pass's byte-exact output under <out>/NN-<pass>/ (1-based) and link terminal stage(s) (symlink->junction->copy) under <out>/final/NN-<pass>/"
        )]
        capture_stages: bool,
        #[arg(
            long,
            value_name = "N",
            help = "batch only: maximum directory recursion depth (default: unlimited)"
        )]
        batch_max_depth: Option<usize>,
        #[arg(
            long = "include",
            value_name = "GLOB",
            help = "batch only: only process files matching this glob (repeatable; e.g. '**/*.pyc')"
        )]
        include: Vec<String>,
        #[arg(
            long = "exclude",
            value_name = "GLOB",
            help = "batch only: skip files matching this glob (repeatable)"
        )]
        exclude: Vec<String>,
        #[arg(
            long,
            value_name = "N",
            help = "batch only: bounded worker concurrency (default: 1, conservative for memory-heavy chains)"
        )]
        jobs: Option<usize>,
    },
    #[cfg(feature = "chain")]
    #[command(
        about = "explicit pass pipeline orchestrator backed by the registry-driven chain engine"
    )]
    Chain {
        #[arg(help = "input file")]
        input: PathBuf,
        #[arg(short, long, help = "output directory (default: ./out/<stem>-chain)")]
        out: Option<PathBuf>,
        #[arg(
            long,
            default_value = "auto:8",
            help = "chain specifier, e.g. 'auto:8' or 'pyarmor+py-decompile'"
        )]
        chain: String,
        #[arg(long = "chain-pin", help = "pin every pass to a specific version")]
        chain_pin: Option<String>,
        #[arg(
            long,
            help = "mirror each executed pass's byte-exact output under <out>/NN-<pass>/ (1-based) and link terminal stage(s) (symlink->junction->copy) under <out>/final/NN-<pass>/"
        )]
        capture_stages: bool,
    },
    #[cfg(feature = "chain")]
    #[command(
        about = "structurally diff two chain.json documents (passes, stage blake3 hashes, sizes, verdicts)"
    )]
    Diff {
        #[arg(help = "left chain.json")]
        left: PathBuf,
        #[arg(help = "right chain.json")]
        right: PathBuf,
    },
    #[cfg(feature = "chain")]
    #[command(
        about = "ground-truth guards: verify chain.json hashes, or deny edits to stage outputs"
    )]
    Guard {
        #[command(subcommand)]
        action: GuardCmd,
    },
    #[command(about = "run disrobe as an HTTP daemon, gRPC server, or LSP-over-stdio")]
    Serve {
        #[arg(long, default_value = "127.0.0.1:7373", help = "HTTP bind address")]
        bind: String,
        #[arg(long, help = "serve LSP over stdio instead of HTTP")]
        stdio: bool,
        #[arg(
            long,
            help = "serve the MCP companion over stdio (rmcp) instead of HTTP/LSP"
        )]
        mcp: bool,
        #[arg(long, help = "expose the gRPC surface alongside HTTP")]
        grpc: bool,
        #[arg(
            long,
            value_name = "ORIGIN",
            help = "additional CORS origin to allow (repeatable)"
        )]
        cors_origin: Vec<String>,
        #[arg(long, default_value_t = 50 * 1024 * 1024, help = "maximum request body size in bytes")]
        max_body_size: usize,
    },
    #[command(
        about = "install heavyweight optional dependencies (Ghidra, etc.) from upstream releases"
    )]
    InstallDeps {
        #[command(subcommand)]
        action: Option<InstallDepsCmd>,
        #[arg(long, help = "install every supported heavyweight dependency")]
        all: bool,
        #[arg(long, help = "report what would happen without downloading")]
        dry_run: bool,
    },
    #[command(
        about = "summarize the current ./out/ directory: per-stage artifact counts, sizes, manifests"
    )]
    Status,
    #[command(about = "verify a .dr envelope (alias for `disrobe envelope verify <PATH>`)")]
    Verify {
        #[arg(help = "path to the .dr envelope to verify")]
        path: PathBuf,
    },
    #[command(
        about = "look up a DR-* error code & print its description, common causes, & common fixes"
    )]
    Explain {
        #[arg(help = "DR error code, e.g. DR-CLI-0001 or just CLI-1")]
        code: String,
    },
    #[command(about = "list every registered pass with a one-line capability summary")]
    Passes,
    #[cfg(feature = "chain")]
    #[command(hide = true, about = "print every clap subcommand path, one per line")]
    SubcommandTree,
    #[command(
        about = "probe ~50 optional external tools & report what is installed, missing, or stale"
    )]
    Doctor {
        #[arg(
            long,
            help = "install every missing tool that has a known install action"
        )]
        auto_install: bool,
        #[arg(
            long,
            short = 'y',
            help = "skip the interactive confirmation prompt for installs"
        )]
        yes: bool,
    },
    #[command(
        about = "install a single optional tool (e.g. `disrobe install ghidra`, `disrobe install upx`); pass `--list` to see every known tool"
    )]
    Install {
        #[arg(
            default_value = "",
            help = "tool name (e.g. ghidra, upx, rizin, java, dotnet, lua); omit when using --list"
        )]
        tool: String,
        #[arg(
            long,
            help = "list every known tool with its per-platform package mapping & exit"
        )]
        list: bool,
        #[arg(long, help = "report what would happen without installing")]
        dry_run: bool,
        #[arg(long, short = 'y', help = "skip the interactive confirmation prompt")]
        yes: bool,
    },
    #[command(about = "scaffold a `.disrobe/` workspace in the current directory")]
    Init {
        #[arg(
            long,
            value_enum,
            help = "also generate IDE-specific settings (claude, cursor, windsurf, aider)"
        )]
        ide: Option<IdeFlavor>,
        #[arg(long, help = "overwrite an existing scaffold")]
        force: bool,
    },
    #[command(
        about = "collect environment, manifests, & tooling versions into a markdown bug report"
    )]
    BugReport {
        #[arg(short, long, help = "output path; pass `-` to write to stdout")]
        out: Option<PathBuf>,
    },
    #[command(
        about = "print self-update guidance (disrobe ships as source only; rebuild from git)"
    )]
    SelfUpdate {
        #[arg(long, help = "report source-only posture & exit (no network)")]
        check_only: bool,
        #[arg(
            long,
            help = "no-op kept for flag compatibility; source-only distribution"
        )]
        download: bool,
        #[arg(long, help = "report what would happen without touching disk")]
        dry_run: bool,
    },
    #[command(about = "generate shell completions for bash, zsh, fish, PowerShell, or elvish")]
    Completions {
        #[arg(help = "target shell")]
        shell: clap_complete::Shell,
        #[arg(long, help = "install the completion script into the shell's rc file")]
        install: bool,
        #[arg(
            long,
            value_name = "PATH",
            help = "override the rc file path for --install"
        )]
        rc_file: Option<PathBuf>,
    },
    #[command(about = "generate man pages (one per subcommand) into the given output directory")]
    Man {
        #[arg(
            short,
            long,
            help = "output directory for the .1 pages (default: ./man)"
        )]
        out: Option<PathBuf>,
    },
    #[command(
        about = "summarize a chain recovery report: per-pass status, confidence tiers, verdict, provenance"
    )]
    Context {
        #[arg(
            long,
            value_name = "DIR",
            help = "directory containing recovery.json (the chain/auto out dir, e.g. ./out/<stem>-chain)"
        )]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_name = "THRESHOLD",
            help = "exit non-zero when the worst chain verdict under --out grades at or above never|incomplete|failed|any, instead of printing the summary"
        )]
        fail_on: Option<String>,
    },
    #[command(
        about = "show the resolved `.disrobe.toml` config or write a documented template (`disrobe config init`)"
    )]
    Config {
        #[command(subcommand)]
        action: Option<ConfigCmd>,
    },
    #[cfg(feature = "chain")]
    #[command(
        about = "consolidate a completed run (out dir or batch manifest) into a forensic summary; runs `auto` first if given a raw input"
    )]
    Report {
        #[arg(
            help = "a completed run's out directory, a batch out directory, or a raw input to analyze first"
        )]
        target: PathBuf,
        #[arg(
            long,
            value_enum,
            default_value_t = ReportFormat::Text,
            help = "output format: text, json, markdown, or html (self-contained, offline; redirect to a .html file)"
        )]
        format: ReportFormat,
        #[arg(
            long,
            help = "directory to hold the run this report derives from; defaults to ./out under the working directory"
        )]
        out: Option<PathBuf>,
        #[arg(
            long,
            help = "replace every detected secret with a stable truncated SHA-256 token"
        )]
        redact: bool,
    },
    #[command(about = "rebuild a `.disrobe/annotations/<stem>.annot.json` symbol annotation file")]
    Annot {
        #[command(subcommand)]
        action: AnnotCmd,
    },
    #[command(about = "record a symbol/file rename in `.disrobe/notes/renames.json` (append-only)")]
    Rename {
        #[arg(help = "current symbol or file name")]
        old: String,
        #[arg(help = "proposed new name")]
        new: String,
        #[arg(long, help = "optional rationale captured alongside the rename")]
        note: Option<String>,
    },
}

#[cfg(feature = "chain")]
#[derive(Subcommand, Debug)]
enum GuardCmd {
    #[command(about = "verify a chain.json's per-stage output hashes match a committed reference")]
    Verify {
        #[arg(help = "subject chain.json to verify")]
        subject: PathBuf,
        #[arg(
            long,
            help = "reference chain.json holding ground-truth per-stage output hashes"
        )]
        reference: PathBuf,
    },
    #[command(
        about = "deny a write/edit to a ground-truth stage path (out/**/stages|final or .disrobe-stage-lock), allow elsewhere"
    )]
    Check {
        #[arg(help = "candidate path about to be written/edited (need not exist yet)")]
        path: PathBuf,
        #[arg(
            long,
            value_delimiter = ',',
            help = "extra protected root subtree(s); repeatable / comma-separated"
        )]
        root: Vec<PathBuf>,
    },
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum SbomFormat {
    #[default]
    Cyclonedx,
    Spdx,
}

#[derive(Subcommand, Debug)]
enum NativeCmd {
    #[command(
        about = "decompile a PE / ELF / Mach-O binary to C (in-tree x86-64 engine by default; --backend ghidra for external ghidra-headless)"
    )]
    Decompile {
        #[arg(help = "input native binary")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output directory (default: ./out/<stem>-native-decompiled)"
        )]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            default_value_t,
            help = "decompiler backend: native (in-tree x86-64 -> C, no external dependency) or ghidra (external ghidra-headless)"
        )]
        backend: native::DecompileBackend,
        #[arg(
            long,
            value_enum,
            default_value_t,
            help = "native backend output language: c (default) or rust (behavior-preserving pseudo-Rust for the pure-safe integer leaf class)"
        )]
        format: native::DecompileLang,
        #[arg(
            long,
            value_delimiter = ',',
            help = "ghidra backend only: comma-separated emit kinds: source, disasm, ast, cfg, ir, manifest, sourcemap, symbols, strings, imports, signatures, report"
        )]
        emit: Vec<String>,
        #[arg(
            long = "no-devirt",
            default_value_t = false,
            help = "disable the symbolic devirtualizer (on by default in a full build): folds proven-dead conditional arms in the aarch64 nir decompile path before structuring"
        )]
        no_devirt: bool,
    },
    #[command(
        about = "dump symbols, sections, segments, imports, & debug info from a native binary"
    )]
    Symbols {
        #[arg(help = "input native binary")]
        input: PathBuf,
        #[arg(short, long, help = "output path for the symbols JSON")]
        out: Option<PathBuf>,
    },
    #[command(
        about = "fingerprint the compiler, packer, protector, and installer of a binary and route each to its disrobe support pass"
    )]
    Identify {
        #[arg(help = "input native binary")]
        input: PathBuf,
        #[arg(short, long, help = "output path for the identity JSON")]
        out: Option<PathBuf>,
    },
    #[command(
        about = "detect the runtime packer and unpack it (UPX/Petite/NSPack/MEW/FSG/MPRESS) to recovered bytes"
    )]
    Unpack {
        #[arg(help = "input packed native binary")]
        input: Option<PathBuf>,
        #[arg(
            short,
            long,
            help = "output path for the recovered image (default: ./out/<stem>.unpacked.bin)"
        )]
        out: Option<PathBuf>,
        #[arg(
            long,
            help = "list the native packers / protectors disrobe can detect and unpack, then exit"
        )]
        list: bool,
    },
    #[command(
        about = "devirtualize a bytecode-VM-protected binary: recover the handler table, fingerprint each handler's micro-op by behavioral probing, lift the bytecode to a re-executable IR, and emit recovered pseudo-code"
    )]
    Devirt {
        #[arg(help = "input VM-protected native binary")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output directory for the recovered listing + pseudo-code (default: ./out/<stem>-devirt)"
        )]
        out: Option<PathBuf>,
    },
    #[command(
        about = "unpack, recover symbols, and export a backend-ready bundle: a rebuilt loadable PE (OEP restored, sections overlaid) plus a Ghidra post-script, IDAPython, or JSON symbol map that feeds Ghidra/IDA/Binary Ninja cleaner input"
    )]
    Export {
        #[arg(help = "input packed native binary")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output directory for the rebuilt image + sidecar (default: ./out/<stem>-export)"
        )]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            default_value_t = native::ExportTarget::Ghidra,
            help = "symbol sidecar format: ghidra (.java post-script), ida (IDAPython .py), or json (tool-neutral symbol map)"
        )]
        format: native::ExportTarget,
    },
    #[command(
        about = "slide a 4KB window computing Shannon entropy (bits/byte) to map packed/encrypted regions; renders an ASCII heat-strip + byte histogram, or a dark-theme SVG entropy map with section overlays"
    )]
    Entropy {
        #[arg(help = "input native binary")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the entropy JSON (also written in text mode)"
        )]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            default_value_t = native::EntropyFormat::Text,
            help = "output format: text (sparkline + histogram), json, or svg (entropy map)"
        )]
        format: native::EntropyFormat,
        #[arg(
            long,
            help = "write a self-contained SVG entropy map to this path (implies svg rendering)"
        )]
        svg: Option<PathBuf>,
    },
    #[command(
        about = "fingerprint embedded crypto primitives (AES T-tables, SHA/MD5 IV+K, ChaCha20 sigma)"
    )]
    Signatures {
        #[arg(help = "input native binary")]
        input: PathBuf,
        #[arg(short, long, help = "output path for the signatures JSON")]
        out: Option<PathBuf>,
        #[arg(
            long,
            help = "optional IDA FLIRT .sig database to match against the input"
        )]
        flirt: Option<PathBuf>,
    },
    #[command(
        about = "aggregate crypto-constant + FLIRT + ASCII string-xref fingerprints into a typed sidecar at .disrobe/fingerprints/<stem>.json"
    )]
    Fingerprint {
        #[arg(help = "input native binary")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output directory (default: .disrobe/fingerprints); file is <stem>.json"
        )]
        out: Option<PathBuf>,
        #[arg(
            long,
            help = "optional IDA FLIRT .sig database to match against the input"
        )]
        flirt: Option<PathBuf>,
    },
    #[command(
        about = "emit a CycloneDX 1.5 or SPDX 2.3 SBOM from an extracted artifact's embedded cargo-auditable dependency metadata"
    )]
    Sbom {
        #[arg(help = "input native binary with an embedded cargo-auditable section")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the SBOM JSON (default: ./out/<stem>.<format>.json)"
        )]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            default_value_t,
            help = "SBOM document format: cyclonedx or spdx"
        )]
        format: SbomFormat,
        #[arg(
            long,
            value_name = "UTC",
            help = "SPDX creation time in canonical UTC form YYYY-MM-DDTHH:MM:SSZ"
        )]
        timestamp: Option<String>,
    },
    #[command(
        about = "recover build provenance from a Windows PDB: DBI version, per-module compiler and linker records, and recorded tool, source and environment strings"
    )]
    Pdb {
        #[arg(help = "input Windows PDB (.pdb)")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output directory for the provenance report (default: ./out/<stem>-pdb)"
        )]
        out: Option<PathBuf>,
    },
    #[command(
        about = "reconstruct compilable C++ headers from a Windows PDB's TPI/IPI type streams (UDTs, enums, typedefs, globals, functions)"
    )]
    PdbCxx {
        #[arg(help = "input Windows PDB (.pdb)")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output directory for the reconstructed header + report (default: ./out/<stem>-pdb-cxx)"
        )]
        out: Option<PathBuf>,
    },
    #[command(
        about = "render the import/export table as a Graphviz DOT digraph (modules -> imported symbols, plus exports)"
    )]
    Graph {
        #[arg(help = "input native binary")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the DOT file (default: ./out/<stem>.imports.dot)"
        )]
        out: Option<PathBuf>,
    },
    #[command(
        about = "recursive-descent disassemble a native binary (symbol-independent function discovery on stripped input); emit linear asm, per-function CFG DOT, or structured JSON"
    )]
    Disasm {
        #[arg(help = "input native binary or a Disasm- or Mir-rung .dr envelope")]
        input: PathBuf,
        #[arg(short, long, help = "output path (default: ./out/<stem>.<emit>)")]
        out: Option<PathBuf>,
        #[arg(
            long,
            help = "treat the input as a flat code blob (no object headers) and sweep from --base"
        )]
        raw: bool,
        #[arg(
            long,
            default_value_t = 0,
            value_parser = parse_u64_auto,
            help = "load/base address for --raw mode (accepts 0x-prefixed hex)"
        )]
        base: u64,
        #[arg(
            long,
            value_enum,
            default_value_t = native::DisasmBits::Bits64,
            help = "instruction width for --raw mode"
        )]
        bits: native::DisasmBits,
        #[arg(
            long,
            value_enum,
            default_value_t = native::DisasmEmit::Asm,
            help = "output kind: asm, cfg-dot, or json"
        )]
        emit: native::DisasmEmit,
        #[arg(
            long,
            value_enum,
            default_value_t = native::DisasmSyntax::Nasm,
            help = "x86 assembly dialect for --raw asm output: nasm, intel, att, or masm"
        )]
        syntax: native::DisasmSyntax,
    },
    #[command(
        about = "build the whole-program call graph (every edge backed by a real call instruction in the caller) and emit Graphviz DOT or JSON"
    )]
    Callgraph {
        #[arg(help = "input native binary or a Disasm- or Mir-rung .dr envelope")]
        input: PathBuf,
        #[arg(short, long, help = "output path (default: ./out/<stem>.<emit>)")]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            default_value_t = native::CallgraphEmit::Dot,
            help = "output kind: dot or json"
        )]
        emit: native::CallgraphEmit,
    },
    #[command(
        about = "rewrite PE / ELF bytes at a virtual address and reparse to validate: --bytes XX,XX overwrites in place, --nop-range A:B lays 0x90 fill across a span; the patched image is re-validated as a loadable object"
    )]
    Patch {
        #[arg(help = "input native binary (PE/ELF/Mach-O)")]
        input: PathBuf,
        #[arg(
            long,
            value_parser = parse_u64_auto,
            help = "virtual address to patch (accepts 0x-prefixed hex)"
        )]
        at: u64,
        #[arg(
            long,
            default_value = "",
            help = "comma-separated replacement bytes, e.g. 90,90 or 0x90,0xC3"
        )]
        bytes: String,
        #[arg(
            long,
            help = "fill a START:END virtual-address span with 0x90 (hex or decimal bounds)"
        )]
        nop_range: Option<String>,
        #[arg(
            short,
            long,
            help = "output path for the patched image (default: ./out/<stem>.patched.bin)"
        )]
        out: Option<PathBuf>,
    },
    #[command(
        about = "generate a wildcarded byte signature from the function at a virtual address (IDA xx ? xx plus a byte+mask form): immediate and relocated operand bytes are wildcarded via instruction operand info, then the pattern is uniqueness-tested across the image"
    )]
    Sigmaker {
        #[arg(help = "input native binary (x86 / x86-64)")]
        input: PathBuf,
        #[arg(
            long,
            value_parser = parse_u64_auto,
            help = "virtual address of the function to fingerprint (accepts 0x-prefixed hex)"
        )]
        at: u64,
        #[arg(
            long,
            value_enum,
            default_value_t = native::SigEmit::CArray,
            help = "byte emitter for the pattern: c-array or python-bytes"
        )]
        emit: native::SigEmit,
    },
    #[command(
        about = "recover Delphi / C++Builder structure from a compiled image: virtual method tables to class names, parents, units, published properties, methods, fields, interfaces, plus RTTI type records, decoded DFM form resources, and the release identified from its version signals"
    )]
    Delphi {
        #[arg(help = "input native binary (Delphi / C++Builder PE)")]
        input: PathBuf,
        #[arg(short, long, help = "output path for the Delphi report JSON")]
        out: Option<PathBuf>,
        #[arg(long, help = "emit the full Delphi report as JSON")]
        json: bool,
    },
    #[command(
        about = "function-level diff of two binaries: match functions by content hash, name, and CFG fingerprint, then report added / removed / changed functions with the kind of change"
    )]
    Diff {
        #[arg(help = "binary A (PE/ELF/Mach-O)")]
        a: PathBuf,
        #[arg(help = "binary B (PE/ELF/Mach-O)")]
        b: PathBuf,
        #[arg(long, help = "emit the full diff report as JSON")]
        json: bool,
        #[arg(long, value_name = "N", help = native::DIFF_LIMIT_HELP)]
        limit: Option<usize>,
    },
    #[command(
        about = "name the counterpart of every function across two stripped binaries: anchor on shared data references, then on a control-flow fingerprint, then propagate along the call graph; each pair carries the stage and the evidence that produced it, and a refusal is reported with its candidates"
    )]
    Match {
        #[arg(help = "binary A (PE/ELF/Mach-O)")]
        a: PathBuf,
        #[arg(help = "binary B (PE/ELF/Mach-O)")]
        b: PathBuf,
        #[arg(short, long, help = "output path for the match report JSON")]
        out: Option<PathBuf>,
        #[arg(long, value_name = "N", help = native_match::LIMIT_HELP)]
        limit: Option<usize>,
        #[arg(
            long,
            value_name = "ADDRESS",
            value_parser = parse_u64_auto,
            conflicts_with = "stage",
            help = native_match::FUNCTION_HELP
        )]
        function: Option<u64>,
        #[arg(long, value_enum, help = native_match::STAGE_HELP)]
        stage: Option<native_match::ListingStage>,
    },
}

fn parse_u64_auto(s: &str) -> Result<u64, String> {
    let trimmed: &str = s.trim();
    trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .map_or_else(
            || {
                trimmed
                    .parse::<u64>()
                    .map_err(|e: std::num::ParseIntError| e.to_string())
            },
            |hex: &str| {
                u64::from_str_radix(hex, 16).map_err(|e: std::num::ParseIntError| e.to_string())
            },
        )
}

#[cfg(feature = "swift")]
fn parse_u8_auto(s: &str) -> Result<u8, String> {
    let value: u64 = parse_u64_auto(s)?;
    u8::try_from(value).map_err(|e: std::num::TryFromIntError| e.to_string())
}

#[cfg(feature = "chain")]
pub(crate) fn subcommand_names() -> std::collections::BTreeSet<String> {
    <Cli as clap::CommandFactory>::command()
        .get_subcommands()
        .map(|sub: &clap::Command| sub.get_name().to_owned())
        .collect()
}

#[cfg(feature = "chain")]
pub(crate) fn subcommand_paths() -> std::collections::BTreeSet<String> {
    let mut paths: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for top in <Cli as clap::CommandFactory>::command().get_subcommands() {
        paths.insert(top.get_name().to_owned());
        for child in top.get_subcommands() {
            paths.insert(format!("{} {}", top.get_name(), child.get_name()));
        }
    }
    paths
}

fn install_crash_reporter() {
    if cfg!(debug_assertions) || std::env::var_os("RUST_BACKTRACE").is_some() {
        return;
    }
    let previous: Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send> =
        std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info: &std::panic::PanicHookInfo<'_>| {
        previous(info);
        eprintln!();
        eprintln!(
            "{} {} crashed. Nothing was written outside the directory you chose.",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        );
        eprintln!(
            "Run `{} bug-report --out <PATH>` to collect the environment and tooling versions,",
            env!("CARGO_PKG_NAME")
        );
        eprintln!("then attach that file to a report. No diagnostics are sent automatically.");
    }));
}

fn main() -> miette::Result<()> {
    install_crash_reporter();
    color_eyre::install().map_err(|e| miette::miette!("color-eyre install failed: {e}"))?;

    let matches: clap::ArgMatches = Cli::command().get_matches();
    let cli: Cli = Cli::from_arg_matches(&matches)
        .map_err(|e: clap::Error| miette::miette!("DR-CLI-0337: argument parse error: {e}"))?;
    let resolved: config::ResolvedConfig = config::resolve(cli.config.as_deref())?;
    let snapshot: CliGlobalsSnapshot = CliGlobalsSnapshot {
        verbose: cli.verbose,
        quiet: cli.quiet,
        json: cli.json,
        ndjson: cli.ndjson,
        sarif: cli.sarif,
        in_place: cli.in_place,
        force: cli.force,
        threads: cli.threads,
        no_cache: cli.no_cache,
        dry_run: cli.dry_run,
    };
    let eff: EffectiveGlobals = config_merge::merge_globals(&matches, snapshot, &resolved.config);

    init_tracing(eff.verbose, eff.quiet);
    let fmt: OutputFormat = OutputFormat::from_flags(eff.json, eff.ndjson, eff.sarif);
    let progress: ProgressMode = if eff.quiet || fmt.is_machine() || eff.progress_never {
        ProgressMode::Never
    } else if eff.progress_always {
        ProgressMode::Always
    } else {
        cli.progress
    };
    let _: Globals = globals::install(Globals::new(
        eff.in_place,
        eff.force,
        eff.threads,
        eff.no_cache,
        eff.dry_run,
        progress,
    ));
    progress_ui::install_rayon_pool(eff.threads);
    let global_dry_run: bool = eff.dry_run;
    let config_explicit: Option<PathBuf> = cli.config.clone();
    #[cfg(feature = "chain")]
    let auto_default_out: Option<PathBuf> = resolved.config.output.dir;
    #[cfg(feature = "chain")]
    let auto_default_depth: Option<u8> = resolved.config.execution.max_depth;
    #[cfg(feature = "chain")]
    let auto_default_emit: Option<Vec<String>> = resolved.config.output.emit;
    let llm_flags: LlmFlags = cli.llm.clone();

    match cli.command {
        Cmd::Pyarmor { action } => pyarmor::run(action),
        Cmd::Pyinstaller { action } => pyinstaller::run(action),
        Cmd::Pyfreeze { action } => pyfreeze::run(action),
        Cmd::Nuitka { action } => nuitka::run(action),
        Cmd::Py { action } => py::run(action, &llm_flags),
        Cmd::Scan { path, redact } => scan::run(path, fmt, redact || eff.redact),
        Cmd::Ioc {
            path,
            format,
            defang,
        } => ioc::run(path, format, defang, fmt),
        Cmd::Indicators {
            inputs,
            targets_only,
            format,
        } => indicators::run(inputs, targets_only, format, fmt),
        Cmd::Frisk {
            path,
            format,
            pattern,
            suppress,
            baseline,
            emit_baseline,
            entropy,
            git,
            redact,
        } => frisk::run(
            path,
            format,
            pattern,
            suppress,
            baseline,
            emit_baseline,
            entropy,
            git,
            redact || eff.redact,
            fmt,
        ),
        #[cfg(feature = "prowl")]
        Cmd::Prowl {
            targets,
            targets_file,
            recon_input,
            stdin,
            sources,
            subs,
            blacklist,
            from,
            to,
            mc,
            fc,
            mt,
            ft,
            ioc,
            fp,
            no_iocs,
            proxy,
            timeout,
            concurrency,
            per_host_rps,
            api_key,
            max_pages,
            max_urls,
            max_iocs,
            retries,
            format,
        } => {
            if targets.first().is_some_and(|t: &String| t == "keyring") {
                prowl::run_keyring_argv(&targets)
            } else {
                prowl::run(
                    ProwlArgs {
                        targets,
                        targets_file,
                        recon_input,
                        stdin,
                        sources,
                        subs,
                        blacklist,
                        from,
                        to,
                        match_status: mc,
                        filter_status: fc,
                        match_mime: mt,
                        filter_mime: ft,
                        ioc_kinds: ioc,
                        collapse_params: fp,
                        no_iocs,
                        proxy,
                        timeout_secs: timeout,
                        concurrency,
                        per_host_rps,
                        api_keys: api_key,
                        max_pages,
                        max_urls,
                        max_iocs,
                        retries,
                        format,
                    },
                    fmt,
                )
            }
        }
        #[cfg(not(feature = "prowl"))]
        Cmd::Prowl { .. } => Err(miette::miette!(
            "DR-CLI-0327: this binary was built without the `prowl` feature, so it carries no \
             archive and threat-intel harvester and no keyring for provider credentials. \
             rebuild with `--features prowl`, or use the default build which enables it"
        )),
        Cmd::Strings {
            path,
            min_len,
            no_decode,
        } => strings_cmd::run(path, min_len, no_decode, fmt),
        Cmd::Behavior { path, effects } => behavior::run(path, fmt, effects),
        Cmd::Identify { path, coverage } => identify::run(path, fmt, coverage),
        #[cfg(feature = "chain")]
        Cmd::Detect { input } => detect::run(input),
        #[cfg(feature = "chain")]
        Cmd::Catalog { ecosystem } => catalog::run(ecosystem, fmt),
        Cmd::Extract {
            input,
            out,
            recursive,
            max_depth,
        } => extract::run(input, out, recursive, max_depth, fmt),
        Cmd::Webview { input, out } => webview::run(input, out, fmt),
        Cmd::Yara { action } => yara::run(action, fmt),
        #[cfg(feature = "js")]
        Cmd::Js { action } => js::run(action),
        Cmd::Wasm { action } => crate::cli::pass_registry::WASM_RUN.map_or_else(
            || Err(crate::cli::pass_registry::not_compiled("wasm", "wasm")),
            |run| run(action),
        ),
        Cmd::Native { action } => match action {
            NativeCmd::Decompile {
                input,
                out,
                backend,
                format,
                emit,
                no_devirt,
            } => native::decompile(input, out, emit, backend, format, !no_devirt),
            NativeCmd::Symbols { input, out } => native::symbols(input, out),
            NativeCmd::Identify { input, out } => native::identify(input, out),
            NativeCmd::Unpack { input, out, list } => native::unpack(input, out, list),
            NativeCmd::Devirt { input, out } => native::devirt(input, out),
            NativeCmd::Export { input, out, format } => native::export(input, out, format),
            NativeCmd::Entropy {
                input,
                out,
                format,
                svg,
            } => native::entropy(input, out, format, svg),
            NativeCmd::Signatures { input, out, flirt } => native::signatures(input, out, flirt),
            NativeCmd::Fingerprint { input, out, flirt } => native::fingerprint(input, out, flirt),
            NativeCmd::Sbom {
                input,
                out,
                format,
                timestamp,
            } => native::sbom(input, out, format, timestamp),
            NativeCmd::Pdb { input, out } => native::pdb(input, out, fmt),
            NativeCmd::PdbCxx { input, out } => native::pdb_cxx(input, out, fmt),
            NativeCmd::Graph { input, out } => native::graph(input, out),
            NativeCmd::Disasm {
                input,
                out,
                raw,
                base,
                bits,
                emit,
                syntax,
            } => native::disasm(input, out, raw, base, bits, emit, syntax),
            NativeCmd::Callgraph { input, out, emit } => native::callgraph(input, out, emit),
            NativeCmd::Patch {
                input,
                at,
                bytes,
                nop_range,
                out,
            } => native::patch(input, at, bytes, nop_range, out),
            NativeCmd::Sigmaker { input, at, emit } => native::sigmaker(input, at, emit),
            NativeCmd::Delphi { input, out, json } => native::delphi(input, out, json),
            NativeCmd::Diff { a, b, json, limit } => {
                let diff_fmt: OutputFormat = if json { OutputFormat::Json } else { fmt };
                native::diff(a, b, diff_fmt, limit)
            }
            NativeCmd::Match {
                a,
                b,
                out,
                limit,
                function,
                stage,
            } => native_match::run(
                a,
                b,
                out,
                fmt,
                native_match::ListingOptions {
                    limit,
                    function,
                    stage,
                },
            ),
        },
        #[cfg(feature = "jvm")]
        Cmd::Jvm { action } => jvm::run(action),
        #[cfg(feature = "jvm")]
        Cmd::Apk { path, out } => apk::run(path, out, fmt),
        #[cfg(feature = "dotnet")]
        Cmd::Dotnet { action } => dotnet::run(action),
        #[cfg(feature = "mobile")]
        Cmd::Hermes { action } => hermes::run(action, fmt),
        #[cfg(feature = "swift")]
        Cmd::Macho { action } => macho::run(action),
        #[cfg(feature = "lua")]
        Cmd::Lua { action } => lua::run(action),
        #[cfg(feature = "php")]
        Cmd::Php { action } => php::run(action),
        #[cfg(feature = "shell")]
        Cmd::Shell { action } => shell::run(action),
        #[cfg(feature = "ruby")]
        Cmd::Ruby { action } => ruby::run(action),
        #[cfg(feature = "beam")]
        Cmd::Beam { action } => beam::run(action),
        #[cfg(feature = "pickle")]
        Cmd::Pickle { action } => pickle::run(action, fmt),
        #[cfg(feature = "plugin")]
        Cmd::Plugin { action } => plugin::run(action),
        #[cfg(feature = "go")]
        Cmd::Go { action } => go::run(action),
        #[cfg(feature = "swift")]
        Cmd::Swift { action } => swift::run(action),
        #[cfg(feature = "as3")]
        Cmd::As3 { action } => as3::run(action),
        #[cfg(feature = "flutter")]
        Cmd::Flutter { action } => flutter::run(action),
        #[cfg(feature = "mobile")]
        Cmd::Mobile { action } => mobile::run(action),
        Cmd::Envelope { action } => {
            let cache_settings: CacheSettings = CacheSettings {
                enabled: !eff.no_cache,
                dir: resolved.config.execution.cache_dir,
            };
            envelope::run(action, fmt, &cache_settings)
        }
        Cmd::Query { input, query } => {
            let expr: String = query.join(" ");
            query::run(input, expr, fmt)
        }
        Cmd::Capabilities { input } => capabilities::run(input, fmt),
        Cmd::Taint {
            input,
            source,
            sink,
        } => taint::run(input, source, sink, fmt, &llm_flags),
        Cmd::Semdiff {
            base,
            others,
            lineage,
            limit,
        } => semdiff::run(base, others, lineage, limit, fmt),
        Cmd::Vulnmatch {
            input,
            osv_db,
            openvex,
            author,
            timestamp,
        } => vulnmatch::run(input, osv_db, fmt, openvex, author, timestamp),
        #[cfg(feature = "chain")]
        Cmd::Auto {
            input,
            out,
            max_depth,
            emit,
            dry_run,
            redact,
            capture_stages,
            batch_max_depth,
            include,
            exclude,
            jobs,
        } => {
            if llm_flags.is_active() {
                return Err(miette::miette!(
                    "DR-CLI-0843: `auto --llm` / `--metadata-pack-N` is not supported; the chain engine writes a single chain.json. Run the matching per-language subcommand (e.g. `disrobe py decompile <input> --llm`) to emit the llm metadata bundle."
                ));
            }
            let auto_matches: Option<&clap::ArgMatches> = matches.subcommand_matches("auto");
            let supplied = |name: &str| -> bool {
                auto_matches.is_some_and(|m: &clap::ArgMatches| {
                    matches!(
                        m.value_source(name),
                        Some(clap::parser::ValueSource::CommandLine)
                    )
                })
            };
            let eff_out: Option<PathBuf> = if supplied("out") {
                out
            } else {
                out.or(auto_default_out)
            };
            let eff_depth: u8 = if supplied("max_depth") {
                max_depth
            } else {
                auto_default_depth.unwrap_or(max_depth)
            };
            let eff_emit: Vec<String> = if supplied("emit") || !emit.is_empty() {
                emit
            } else {
                auto_default_emit.unwrap_or_default()
            };
            auto::run(
                input,
                eff_out,
                Some(eff_depth),
                eff_emit,
                fmt,
                auto::AutoOptions {
                    dry_run: dry_run || global_dry_run,
                    redact: redact || eff.redact,
                    capture_stages,
                    i_have_authorization: llm_flags.i_have_authorization,
                },
                auto::BatchArgs {
                    max_depth: batch_max_depth,
                    include,
                    exclude,
                    jobs: jobs.unwrap_or(1).max(1),
                },
            )
        }
        #[cfg(feature = "chain")]
        Cmd::Chain {
            input,
            out,
            chain,
            chain_pin,
            capture_stages,
        } => chain_v1::run_with_disk(
            input,
            out,
            chain,
            chain_pin,
            fmt,
            chain_v1::ChainRunOptions {
                write_to_disk: true,
                redact: false,
                capture_stages,
                emit_recovery: false,
                i_have_authorization: llm_flags.i_have_authorization,
            },
        ),
        #[cfg(feature = "chain")]
        Cmd::Diff { left, right } => chain_compare::run_diff(left, right, fmt),
        #[cfg(feature = "chain")]
        Cmd::Guard { action } => match action {
            GuardCmd::Verify { subject, reference } => {
                chain_compare::run_guard(subject, reference, fmt)
            }
            GuardCmd::Check { path, root } => guard::run_check(path, root, fmt),
        },
        #[cfg(feature = "server")]
        Cmd::Serve {
            bind,
            stdio,
            mcp,
            grpc,
            cors_origin,
            max_body_size,
        } => serve::run(bind, stdio, mcp, grpc, cors_origin, max_body_size),
        #[cfg(not(feature = "server"))]
        Cmd::Serve { .. } => Err(miette::miette!(
            "DR-CLI-0326: this binary was built without the `server` feature, so it carries no HTTP \
             daemon, no gRPC surface and no LSP-over-stdio. rebuild with `--features server`, or \
             use the default build which enables it"
        )),
        Cmd::InstallDeps {
            action,
            all,
            dry_run,
        } => {
            let effective_dry: bool = dry_run || global_dry_run;
            action.map_or_else(
                || {
                    if all {
                        install_deps::run_all(effective_dry, fmt)
                    } else {
                        Err(miette::miette!(
                            "DR-CLI-0290: `disrobe install-deps` requires a subcommand or `--all`; try `disrobe install-deps ghidra`"
                        ))
                    }
                },
                |act| install_deps::run(act, fmt),
            )
        }
        Cmd::Status => status_cmd::run(fmt),
        Cmd::Verify { path } => envelope::run(
            EnvelopeCmd::Verify { input: path },
            fmt,
            &CacheSettings {
                enabled: false,
                dir: None,
            },
        ),
        Cmd::Explain { code } => explain::run(code, fmt),
        Cmd::Passes => print_passes(),
        #[cfg(feature = "chain")]
        Cmd::SubcommandTree => {
            for path in subcommand_paths() {
                println!("{path}");
            }
            Ok(())
        }
        Cmd::Doctor { auto_install, yes } => doctor::run_with_options(fmt, auto_install, yes),
        Cmd::Install {
            tool,
            list,
            dry_run,
            yes,
        } => {
            if list {
                install_cmd::run_list(fmt)
            } else if tool.is_empty() {
                Err(miette::miette!(
                    "DR-CLI-0271: `disrobe install` requires a tool name or `--list`; try `disrobe install ghidra` or `disrobe install --list`"
                ))
            } else {
                install_cmd::run(&tool, dry_run || global_dry_run, yes, fmt)
            }
        }
        Cmd::Init { ide, force } => init_cmd::run(ide, force, fmt),
        Cmd::Context { out, fail_on } => context::run(out, fail_on, fmt),
        Cmd::Config { action } => config::run(action, config_explicit.as_deref(), fmt),
        #[cfg(feature = "chain")]
        Cmd::Report {
            target,
            format,
            out,
            redact,
        } => report::run(target, format, fmt, out, redact || eff.redact),
        Cmd::Annot { action } => annot::run(action, fmt),
        Cmd::Rename { old, new, note } => rename::run(old, new, note, fmt),
        Cmd::BugReport { out } => bug_report::run(out),
        Cmd::SelfUpdate {
            check_only,
            download,
            dry_run,
        } => self_update_cmd::run(check_only, download, dry_run || global_dry_run, fmt),
        Cmd::Completions {
            shell,
            install,
            rc_file,
        } => completions_cmd::run::<Cli>(shell, install, rc_file),
        Cmd::Man { out } => man::run::<Cli>(out),
    }
}

fn print_passes() -> miette::Result<()> {
    println!("registered passes:");
    println!("  pyarmor       v6 / v7 (dynamic-hook) + v8 / v9-pro static unpack");
    println!("  pyinstaller   PyInstaller 2.1 .. 6.x extract + AES-CTR / CFB decrypt");
    println!(
        "  pyfreeze      cx_Freeze / py2exe / shiv / pex / PyOxidizer (experimental, unvalidated) / Briefcase detect + extract"
    );
    println!("  nuitka        --onefile payload extract (kax / kay + zstd) + symbol scan");
    println!(
        "  py            deobfuscate (peel + cleanup) / disassemble / decompile / extract / sourcedefender decrypt"
    );
    println!(
        "  js            deobfuscate (string-array + unminify + scope-aware rename) / unbundle"
    );
    println!(
        "  wasm          analyze / decompile (JSON | Rust | TypeScript | WAT | C) / deobfuscate (3 transform families; Tigress classify-only; wasm-name-obfuscator classify-only)"
    );
    println!("  envelope      .dr create / inspect / verify");
    println!(
        "  query         query Disasm .dr IR: functions / calls-to / xrefs-to / string-decoders / complexity-over / capability"
    );
    println!(
        "  capabilities  match a binary against built-in capability rules (and / or / not / N-of, scoped) with evidence addresses + ATT&CK / MBC tags"
    );
    println!("  native        in-tree x86-64 -> C decompile, symbol dump, unpack, Ghidra-headless");
    println!(
        "  jvm           classfile / .jar / .dex / .apk decompile via CFR / Vineflower / Procyon / JADX"
    );
    println!(
        "  apk           AndroidManifest.xml decode + resource id->name map + signer cert sha256"
    );
    println!(
        "  dotnet        .NET PE decompile via ILSpy / dnSpyEx / de4dot + protector detection"
    );
    println!("  hermes        React Native Hermes bundle disasm + JS surface lift");
    println!("  macho         Mach-O / fat / .ipa dump + raw Mach-O ObjC + Swift class-dump");
    println!(
        "  lua           Lua 5.1 / 5.2 / 5.3 / 5.4 / LuaJIT / Luau / GLua decompile + obfuscator peel"
    );
    println!(
        "  php           phar decode, encoder envelope report (ionCube / SourceGuardian / ZendGuard) + eval-chain peel"
    );
    println!("  ruby          MRI / YARV / mruby / JRuby / TruffleRuby / Ruby2Exe / Ocra analysis");
    println!("  beam          .beam IFF parse + Core Erlang lift + Code chunk disasm");
    println!(
        "  pickle        Python pickle disasm + decompile + safety + trace + polyglot + ML detect"
    );
    println!("  go            Go binary recovery: pclntab + moduledata + garble + embed.FS");
    println!(
        "  swift         Swift / ObjC class-dump + SwiftShield mapping parser + explicit-key XOR blob decoding"
    );
    println!("  as3           ActionScript 3 .swf DoABC tag disasm");
    println!("  flutter       Dart AOT / libapp.so dump + obfuscation_map parse");
    println!("  chain         explicit pass pipeline orchestrator");
    println!("  serve         HTTP daemon + WebSocket stream + LSP-stdio + gRPC");
    print_chain_registry();
    Ok(())
}

#[cfg(not(feature = "chain"))]
fn print_chain_registry() {
    println!();
    println!(
        "chain passes reachable from `disrobe auto` in this build: none, because this binary was \
         built without the chain feature"
    );
}

#[cfg(feature = "chain")]
fn print_chain_registry() {
    let registry: disrobe_core::chain::PassRegistry = disrobe_passes::build_registry();
    println!();
    println!("chain passes reachable from `disrobe auto` in this build:");
    for pass in registry.iter_passes() {
        let meta: disrobe_core::chain::PassMeta = pass.meta();
        println!(
            "  {id:<24} {ecosystem:<12} {support}",
            id = pass.id(),
            ecosystem = meta.ecosystem.label(),
            support = meta.support.label()
        );
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "swift")]
    fn parse_u8_auto_accepts_decimal_and_hexadecimal_values() {
        assert_eq!(parse_u8_auto("85"), Ok(85));
        assert_eq!(parse_u8_auto("0x55"), Ok(85));
        assert_eq!(parse_u8_auto("0X55"), Ok(85));
        assert!(parse_u8_auto("256").is_err());
        assert!(parse_u8_auto("0x100").is_err());
    }

    #[test]
    fn prowl_help_lists_virustotal_source() {
        let mut command: clap::Command = <Cli as clap::CommandFactory>::command();
        let prowl: &mut clap::Command = command
            .find_subcommand_mut("prowl")
            .expect("prowl subcommand");
        let mut buffer: Vec<u8> = Vec::new();
        prowl.write_long_help(&mut buffer).expect("help renders");
        let help: String = String::from_utf8(buffer).expect("utf8 help");
        assert!(
            help.contains("wayback,commoncrawl,otx,urlscan,crtsh,urlhaus,threatfox,virustotal"),
            "{help}"
        );
    }
}
