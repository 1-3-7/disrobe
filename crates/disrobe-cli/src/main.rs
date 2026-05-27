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

use clap::{Parser, Subcommand};

use cli::as3::{self, As3Cmd};
#[cfg(feature = "chain")]
use cli::auto;
use cli::beam::{self, BeamCmd};
use cli::bug_report;
#[cfg(feature = "chain")]
use cli::chain_v1;
use cli::completions as completions_cmd;
use cli::doctor;
use cli::dotnet::{self, DotnetCmd};
use cli::envelope::{self, EnvelopeCmd};
use cli::explain;
use cli::flutter::{self, FlutterCmd};
use cli::globals::{self, Globals, ProgressMode};
use cli::go::{self, GoCmd};
use cli::hermes::{self, HermesCmd};
use cli::init::{self as init_cmd, IdeFlavor};
use cli::install as install_cmd;
use cli::install_deps::{self, InstallDepsCmd};
use cli::js::{self, JsCmd};
use cli::jvm::{self, JvmCmd};
use cli::llm::LlmFlags;
use cli::lua::{self, LuaCmd};
use cli::macho::{self, MachoCmd};
use cli::man;
use cli::native;
use cli::nuitka::{self, NuitkaCmd};
use cli::output::OutputFormat;
use cli::php::{self, PhpCmd};
use cli::progress_ui;
use cli::py::{self, PyCmd};
use cli::pyarmor::{self, PyarmorCmd};
use cli::pyfreeze::{self, PyfreezeCmd};
use cli::pyinstaller::{self, PyinstallerCmd};
use cli::ruby::{self, RubyCmd};
use cli::self_update as self_update_cmd;
use cli::serve;
use cli::status as status_cmd;
use cli::swift::{self, SwiftCmd};
use cli::util::init_tracing;
use cli::wasm::{self, WasmCmd};

const ABOUT: &str = "strip the obfuscation, read the source";
const LONG_ABOUT: &str = "disrobe is a deterministic deobfuscator and decompiler suite. it covers Python bytecode, JavaScript / TypeScript, WebAssembly, JVM / Android, .NET, native PE / ELF / Mach-O, native packers (UPX, MPRESS, NSPack, FSG, kkrunchy, mew, ...), Go, Lua, PHP, Ruby, BEAM, Swift / Objective-C, AS3, Hermes, Flutter, and the freezer / protector chains stacked on top.\n\nrun `disrobe doctor` to probe external tools, `disrobe install <tool>` to install one, or `disrobe install --list` to list every known tool.";

#[derive(Parser, Debug)]
#[command(name = "disrobe", version, about = ABOUT, long_about = LONG_ABOUT, propagate_version = true, infer_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,

    #[arg(short, long, action = clap::ArgAction::Count, global = true, help = "increase log verbosity (-v, -vv, -vvv)")]
    verbose: u8,

    #[arg(short, long, global = true, help = "suppress non-error output")]
    quiet: bool,

    #[arg(long, value_enum, default_value_t = ColorChoice::Auto, global = true, help = "control ANSI color in terminal output")]
    color: ColorChoice,

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
        value_name = "N",
        help = "RNG seed for non-deterministic backends"
    )]
    seed: Option<u64>,

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

impl Cli {
    const fn output_mode(&self) -> OutputFormat {
        OutputFormat::from_flags(self.json, self.ndjson, self.sarif)
    }
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum ColorChoice {
    Auto,
    Always,
    Never,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    #[command(about = "unpack a PyArmor-protected wrapper (v6 / v7 / v8 / v9-pro)")]
    Pyarmor {
        #[command(subcommand)]
        action: PyarmorCmd,
    },
    #[command(about = "detect and extract PyInstaller onefile / onedir executables")]
    Pyinstaller {
        #[command(subcommand)]
        action: PyinstallerCmd,
    },
    #[command(
        about = "detect and extract cx_Freeze / py2exe / shiv / pex / PyOxidizer / Briefcase containers"
    )]
    Pyfreeze {
        #[command(subcommand)]
        action: PyfreezeCmd,
    },
    #[command(about = "detect, extract, and symbol-dump Nuitka --onefile / --standalone builds")]
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
    #[command(about = "JavaScript / TypeScript deobfuscate and bundle splitter")]
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
    #[command(about = "native PE / ELF / Mach-O symbol dump and Ghidra-headless decompile")]
    Native {
        #[command(subcommand)]
        action: NativeCmd,
    },
    #[command(
        about = "JVM / Android decompile: classfile, .jar, .dex, .apk through CFR / Vineflower / Procyon / JADX"
    )]
    Jvm {
        #[command(subcommand)]
        action: JvmCmd,
    },
    #[command(
        about = ".NET decompile and static analysis: PE/CLR, ILSpy / dnSpyEx / de4dot, protector detection"
    )]
    Dotnet {
        #[command(subcommand)]
        action: DotnetCmd,
    },
    #[command(about = "React Native Hermes bundle: lift to JS surface, disassemble, header info")]
    Hermes {
        #[command(subcommand)]
        action: HermesCmd,
    },
    #[command(about = "Mach-O / Fat-Mach-O / .ipa dump, ObjC + Swift class-dump, fat slice walker")]
    Macho {
        #[command(subcommand)]
        action: MachoCmd,
    },
    #[command(
        about = "Lua 5.1 / 5.2 / 5.3 / 5.4 / LuaJIT / Luau / GLua decompile and obfuscator peel (Prometheus, MoonSec, Ironbrew2, ...)"
    )]
    Lua {
        #[command(subcommand)]
        action: LuaCmd,
    },
    #[command(
        about = "PHP encoder decode (phar, ionCube, SourceGuardian, ZendGuard) and eval-chain deobfuscation"
    )]
    Php {
        #[command(subcommand)]
        action: PhpCmd,
    },
    #[command(
        about = "Ruby flavor analysis: MRI source, YARV binary, mruby RITE, JRuby class, TruffleRuby AOT, Ruby2Exe, Ocra"
    )]
    Ruby {
        #[command(subcommand)]
        action: RubyCmd,
    },
    #[command(
        about = "BEAM (Erlang / Elixir) IFF chunk parse, Core Erlang lift, Code chunk disassemble"
    )]
    Beam {
        #[command(subcommand)]
        action: BeamCmd,
    },
    #[command(
        about = "Go binary recovery: pclntab, moduledata, garble report, embed.FS extraction (PE / ELF / Mach-O)"
    )]
    Go {
        #[command(subcommand)]
        action: GoCmd,
    },
    #[command(
        about = "Swift / Objective-C class-dump, SwiftShield undo, SwiftConfidential XOR-decrypt"
    )]
    Swift {
        #[command(subcommand)]
        action: SwiftCmd,
    },
    #[command(about = "ActionScript 3 disassembly: SWF parse + DoABC tag disasm")]
    As3 {
        #[command(subcommand)]
        action: As3Cmd,
    },
    #[command(
        about = "Flutter / Dart AOT: libapp.so symbol layout, Dart snapshot decompile, obfuscation_map parser"
    )]
    Flutter {
        #[command(subcommand)]
        action: FlutterCmd,
    },
    #[command(
        about = ".dr envelope create / inspect / verify (rkyv hot payload + postcard cold sidecar + BLAKE3 root hash)"
    )]
    Envelope {
        #[command(subcommand)]
        action: EnvelopeCmd,
    },
    #[cfg(feature = "chain")]
    #[command(about = "auto-detect the input format and chain the right pass pipeline end-to-end")]
    Auto {
        #[arg(help = "input file to inspect and chain through the right passes")]
        input: PathBuf,
        #[arg(short, long, help = "output directory (default: ./out/<stem>-auto)")]
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
            help = "comma-separated emit kinds: source,disasm,ast,cfg,ir,manifest,sourcemap,symbols,strings,imports,signatures,report"
        )]
        emit: Vec<String>,
        #[arg(long, help = "report what would happen without writing any output")]
        dry_run: bool,
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
    },
    #[command(about = "run disrobe as an HTTP daemon, gRPC server, or LSP-over-stdio")]
    Serve {
        #[arg(long, default_value = "127.0.0.1:7373", help = "HTTP bind address")]
        bind: String,
        #[arg(long, help = "serve over stdio for LSP / MCP clients instead of HTTP")]
        stdio: bool,
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
        about = "look up a DR-* error code and print its description, common causes, and common fixes"
    )]
    Explain {
        #[arg(help = "DR error code, e.g. DR-CLI-0001 or just CLI-1")]
        code: String,
    },
    #[command(about = "list every registered pass with a one-line capability summary")]
    Passes,
    #[command(
        about = "probe ~50 optional external tools and report what is installed, missing, or stale"
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
            help = "list every known tool with its per-platform package mapping and exit"
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
            help = "also generate IDE-specific settings (vscode, jetbrains, zed)"
        )]
        ide: Option<IdeFlavor>,
        #[arg(long, help = "overwrite an existing scaffold")]
        force: bool,
    },
    #[command(
        about = "collect environment, manifests, and tooling versions into a markdown bug report"
    )]
    BugReport {
        #[arg(short, long, help = "output path; pass `-` to write to stdout")]
        out: Option<PathBuf>,
    },
    #[command(
        about = "print self-update guidance (disrobe ships as source only; rebuild from git)"
    )]
    SelfUpdate {
        #[arg(long, help = "report source-only posture and exit (no network)")]
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
}

#[derive(Subcommand, Debug)]
enum NativeCmd {
    #[command(about = "decompile a PE / ELF / Mach-O binary via Ghidra-headless")]
    Decompile {
        #[arg(help = "input native binary")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output directory (default: ./out/<stem>-native-decompiled)"
        )]
        out: Option<PathBuf>,
    },
    #[command(
        about = "dump symbols, sections, segments, imports, and debug info from a native binary"
    )]
    Symbols {
        #[arg(help = "input native binary")]
        input: PathBuf,
        #[arg(short, long, help = "output path for the symbols JSON")]
        out: Option<PathBuf>,
    },
}

fn main() -> miette::Result<()> {
    human_panic::setup_panic!();
    color_eyre::install().map_err(|e| miette::miette!("color-eyre install failed: {e}"))?;

    let cli: Cli = Cli::parse();
    init_tracing(cli.verbose, cli.quiet);
    let fmt: OutputFormat = cli.output_mode();
    let _: Globals = globals::install(Globals::new(
        cli.in_place,
        cli.force,
        cli.threads,
        cli.no_cache,
        cli.dry_run,
        cli.progress,
    ));
    progress_ui::install_rayon_pool(cli.threads);
    let global_dry_run: bool = cli.dry_run;
    let llm_flags: LlmFlags = cli.llm.clone();

    match cli.command {
        Cmd::Pyarmor { action } => pyarmor::run(action),
        Cmd::Pyinstaller { action } => pyinstaller::run(action),
        Cmd::Pyfreeze { action } => pyfreeze::run(action),
        Cmd::Nuitka { action } => nuitka::run(action),
        Cmd::Py { action } => py::run(action, &llm_flags),
        Cmd::Js { action } => js::run(action),
        Cmd::Wasm { action } => wasm::run(action),
        Cmd::Native { action } => match action {
            NativeCmd::Decompile { input, out } => native::decompile(input, out),
            NativeCmd::Symbols { input, out } => native::symbols(input, out),
        },
        Cmd::Jvm { action } => jvm::run(action),
        Cmd::Dotnet { action } => dotnet::run(action),
        Cmd::Hermes { action } => hermes::run(action),
        Cmd::Macho { action } => macho::run(action),
        Cmd::Lua { action } => lua::run(action),
        Cmd::Php { action } => php::run(action),
        Cmd::Ruby { action } => ruby::run(action),
        Cmd::Beam { action } => beam::run(action),
        Cmd::Go { action } => go::run(action),
        Cmd::Swift { action } => swift::run(action),
        Cmd::As3 { action } => as3::run(action),
        Cmd::Flutter { action } => flutter::run(action),
        Cmd::Envelope { action } => envelope::run(action),
        #[cfg(feature = "chain")]
        Cmd::Auto {
            input,
            out,
            max_depth,
            emit,
            dry_run,
        } => auto::run(
            input,
            out,
            Some(max_depth),
            emit,
            dry_run || global_dry_run,
            fmt,
        ),
        #[cfg(feature = "chain")]
        Cmd::Chain {
            input,
            out,
            chain,
            chain_pin,
        } => chain_v1::run(input, out, chain, chain_pin, fmt),
        Cmd::Serve {
            bind,
            stdio,
            grpc,
            cors_origin,
            max_body_size,
        } => serve::run(bind, stdio, grpc, cors_origin, max_body_size),
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
        Cmd::Verify { path } => envelope::run(EnvelopeCmd::Verify { input: path }),
        Cmd::Explain { code } => explain::run(code, fmt),
        Cmd::Passes => print_passes(),
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
        "  pyfreeze      cx_Freeze / py2exe / shiv / pex / PyOxidizer / Briefcase detect + extract"
    );
    println!("  nuitka        --onefile payload extract (kax / kay + zstd) + symbol scan");
    println!(
        "  py            deobfuscate (peel + cleanup) / disassemble / decompile / extract / sourcedefender decrypt"
    );
    println!(
        "  js            deobfuscate (string-array + unminify + scope-aware rename) / unbundle"
    );
    println!(
        "  wasm          analyze / decompile (JSON | Rust | TypeScript | WAT | C) / deobfuscate (5 families)"
    );
    println!("  envelope      .dr create / inspect / verify");
    println!("  native        Ghidra-headless decompile / object-crate symbol dump");
    println!(
        "  jvm           classfile / .jar / .dex / .apk decompile via CFR / Vineflower / Procyon / JADX"
    );
    println!(
        "  dotnet        .NET PE decompile via ILSpy / dnSpyEx / de4dot + protector detection"
    );
    println!("  hermes        React Native Hermes bundle disasm + JS surface lift");
    println!("  macho         Mach-O / fat / .ipa dump + ObjC + Swift class-dump");
    println!(
        "  lua           Lua 5.1 / 5.2 / 5.3 / 5.4 / LuaJIT / Luau / GLua decompile + obfuscator peel"
    );
    println!(
        "  php           encoder decode (phar / ionCube / SourceGuardian / ZendGuard) + eval-chain peel"
    );
    println!("  ruby          MRI / YARV / mruby / JRuby / TruffleRuby / Ruby2Exe / Ocra analysis");
    println!("  beam          .beam IFF parse + Core Erlang lift + Code chunk disasm");
    println!("  go            Go binary recovery: pclntab + moduledata + garble + embed.FS");
    println!(
        "  swift         Swift / ObjC class-dump + SwiftShield undo + Confidential XOR-decrypt"
    );
    println!("  as3           ActionScript 3 .swf DoABC tag disasm");
    println!("  flutter       Dart AOT / libapp.so dump + obfuscation_map parse");
    println!("  chain         explicit pass pipeline orchestrator");
    println!("  serve         HTTP daemon + WebSocket stream + LSP-stdio + gRPC");
    Ok(())
}
