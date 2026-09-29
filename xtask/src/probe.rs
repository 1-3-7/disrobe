use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_tool_process::{CaptureOutcome, CommandSpec, Completion, Execution};
use eyre::{Result, WrapErr, bail};

const STEP_TIMEOUT: Duration = Duration::from_mins(2);
const CAPTURE_LIMIT: usize = 16 << 20;
const RUBY_COMPILE: &str =
    "File.binwrite(ARGV[1], RubyVM::InstructionSequence.compile_file(ARGV[0]).to_binary)";
const PYTHON_COMPILE: &str =
    "import py_compile, sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True)";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Language {
    Lua { version: &'static str },
    Python { version: String },
    Ruby,
    Erlang,
    Java,
}

impl Language {
    pub(crate) fn parse(name: &str) -> Result<Self> {
        let lua: Option<&'static str> = ["5.1", "5.2", "5.3", "5.4"]
            .into_iter()
            .find(|version: &&str| name.strip_prefix("lua") == Some(*version));
        if let Some(version) = lua {
            return Ok(Self::Lua { version });
        }
        if let Some(version) = name.strip_prefix("python")
            && let Some(minor) = version.strip_prefix("3.")
            && minor.parse::<u8>().is_ok_and(|m: u8| (8..=15).contains(&m))
        {
            return Ok(Self::Python {
                version: version.to_owned(),
            });
        }
        if name == "ruby" {
            return Ok(Self::Ruby);
        }
        if name == "erlang" {
            return Ok(Self::Erlang);
        }
        if name == "java" {
            return Ok(Self::Java);
        }
        bail!(
            "unknown probe language `{name}`; expected lua5.1..lua5.4, python3.8..python3.15, ruby, erlang or java"
        )
    }
}

struct Toolchain {
    compiler: PathBuf,
    runtime: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
struct RunOutcome {
    succeeded: bool,
    stdout: String,
    stderr: String,
}

pub(crate) fn run(
    language: &str,
    source: &Path,
    disrobe: Option<PathBuf>,
    keep: Option<PathBuf>,
) -> Result<()> {
    let language: Language = Language::parse(language)?;
    let disrobe: PathBuf = disrobe
        .or_else(|| std::env::var_os("DISROBE_BIN").map(PathBuf::from))
        .ok_or_else(|| {
            eyre::eyre!(
                "no disrobe binary: build it with `cargo build -p disrobe-cli --bin disrobe` and pass --bin or set DISROBE_BIN"
            )
        })?;
    if !disrobe.is_file() {
        bail!("the disrobe binary {} does not exist", disrobe.display());
    }
    let toolchain: Toolchain = resolve_toolchain(&language)?;
    let mut scratch: Option<ScratchDir> = None;
    let work: PathBuf = if let Some(dir) = keep {
        std::fs::create_dir_all(&dir).wrap_err_with(|| format!("creating {}", dir.display()))?;
        dir
    } else {
        let created: ScratchDir =
            ScratchDir::create("xtask-probe").wrap_err("creating the probe scratch directory")?;
        let path: PathBuf = created.path().to_path_buf();
        scratch = Some(created);
        path
    };
    let stem: String = source
        .file_stem()
        .and_then(|s: &std::ffi::OsStr| s.to_str())
        .filter(|s: &&str| !s.is_empty())
        .ok_or_else(|| eyre::eyre!("{} has no usable file stem", source.display()))?
        .to_owned();
    let program: PathBuf = work.join(source.file_name().unwrap_or_default());
    std::fs::copy(source, &program)
        .wrap_err_with(|| format!("copying {} into {}", source.display(), work.display()))?;

    let compiled: PathBuf = compile(&language, &toolchain, &program, &work, &stem)?;
    let original_input: &Path = if matches!(language, Language::Erlang | Language::Java) {
        &compiled
    } else {
        &program
    };
    let original: RunOutcome = run_program(&language, &toolchain, original_input, &stem)?;
    let recovered_path: PathBuf = decompile(&language, &disrobe, &compiled, &work, &stem)?;
    let recovered_source: String = std::fs::read_to_string(&recovered_path)
        .wrap_err_with(|| format!("reading the recovered source {}", recovered_path.display()))?;
    let recovered: RunOutcome = run_program(&language, &toolchain, &recovered_path, &stem)?;
    drop(scratch);

    if original.succeeded == recovered.succeeded && original.stdout == recovered.stdout {
        println!(
            "probe {}: equal ({} stdout bytes)",
            source.display(),
            original.stdout.len()
        );
        return Ok(());
    }
    println!("probe {}: DIVERGED", source.display());
    println!(
        "--- original (succeeded: {}) ---\n{}{}",
        original.succeeded, original.stdout, original.stderr
    );
    println!(
        "--- recovered (succeeded: {}) ---\n{}{}",
        recovered.succeeded, recovered.stdout, recovered.stderr
    );
    println!(
        "--- recovered source {} ---\n{recovered_source}",
        recovered_path.display()
    );
    bail!(
        "the recovered program behaves differently from {}",
        source.display()
    )
}

fn resolve_toolchain(language: &Language) -> Result<Toolchain> {
    match language {
        Language::Lua { version } => {
            let compact: String = version.replace('.', "");
            let compiler: PathBuf =
                find_on_path(&[&format!("luac{version}"), &format!("luac{compact}")])?;
            let runtime: PathBuf =
                find_on_path(&[&format!("lua{version}"), &format!("lua{compact}")])?;
            Ok(Toolchain { compiler, runtime })
        }
        Language::Python { version } => {
            let python: PathBuf = find_python(version)?;
            Ok(Toolchain {
                compiler: python.clone(),
                runtime: python,
            })
        }
        Language::Ruby => {
            let ruby: PathBuf = find_on_path(&["ruby"])?;
            Ok(Toolchain {
                compiler: ruby.clone(),
                runtime: ruby,
            })
        }
        Language::Erlang => Ok(Toolchain {
            compiler: find_on_path(&["erlc"])?,
            runtime: find_on_path(&["erl"])?,
        }),
        Language::Java => Ok(Toolchain {
            compiler: find_on_path(&["javac"])?,
            runtime: find_on_path(&["java"])?,
        }),
    }
}

fn run_program(
    language: &Language,
    toolchain: &Toolchain,
    file: &Path,
    stem: &str,
) -> Result<RunOutcome> {
    let dir: &Path = file.parent().unwrap_or_else(|| Path::new("."));
    match language {
        Language::Erlang => {}
        Language::Java => return run_java(toolchain, file, dir, stem),
        Language::Lua { .. } | Language::Python { .. } | Language::Ruby => {
            return execute(&toolchain.runtime, &[file.as_os_str().to_owned()], dir);
        }
    }
    if file
        .extension()
        .is_some_and(|ext: &std::ffi::OsStr| ext == "erl")
    {
        let args: Vec<OsString> = vec!["-o".into(), dir.into(), file.into()];
        let compiled: RunOutcome = execute(&toolchain.compiler, &args, dir)?;
        if !compiled.succeeded {
            return Ok(compiled);
        }
    }
    let args: Vec<OsString> = vec![
        "-noshell".into(),
        "-pa".into(),
        dir.into(),
        "-s".into(),
        stem.into(),
        "main".into(),
        "-s".into(),
        "init".into(),
        "stop".into(),
    ];
    execute(&toolchain.runtime, &args, dir)
}

fn run_java(toolchain: &Toolchain, file: &Path, dir: &Path, stem: &str) -> Result<RunOutcome> {
    let classes: PathBuf = if file
        .extension()
        .is_some_and(|ext: &std::ffi::OsStr| ext == "java")
    {
        let classes: PathBuf = dir.join("classes");
        let args: Vec<OsString> = vec!["-d".into(), classes.clone().into(), file.into()];
        let compiled: RunOutcome = execute(&toolchain.compiler, &args, dir)?;
        if !compiled.succeeded {
            return Ok(compiled);
        }
        classes
    } else {
        dir.to_path_buf()
    };
    let args: Vec<OsString> = vec!["-cp".into(), classes.into(), stem.into()];
    execute(&toolchain.runtime, &args, dir)
}

fn compile(
    language: &Language,
    toolchain: &Toolchain,
    program: &Path,
    work: &Path,
    stem: &str,
) -> Result<PathBuf> {
    let (compiled, args): (PathBuf, Vec<OsString>) = match language {
        Language::Lua { .. } => {
            let out: PathBuf = work.join(format!("{stem}.luac"));
            let args: Vec<OsString> =
                vec!["-s".into(), "-o".into(), out.clone().into(), program.into()];
            (out, args)
        }
        Language::Python { .. } => {
            let out: PathBuf = work.join(format!("{stem}.pyc"));
            let args: Vec<OsString> = vec![
                "-c".into(),
                PYTHON_COMPILE.into(),
                program.into(),
                out.clone().into(),
            ];
            (out, args)
        }
        Language::Erlang => {
            let out: PathBuf = work.join(format!("{stem}.beam"));
            let args: Vec<OsString> = vec![
                "+no_debug_info".into(),
                "-o".into(),
                work.into(),
                program.into(),
            ];
            (out, args)
        }
        Language::Java => {
            let classes: PathBuf = work.join("classes");
            let out: PathBuf = classes.join(format!("{stem}.class"));
            let args: Vec<OsString> = vec!["-d".into(), classes.into(), program.into()];
            (out, args)
        }
        Language::Ruby => {
            let out: PathBuf = work.join(format!("{stem}.yarb"));
            let args: Vec<OsString> = vec![
                "-e".into(),
                RUBY_COMPILE.into(),
                program.into(),
                out.clone().into(),
            ];
            (out, args)
        }
    };
    let outcome: RunOutcome = execute(&toolchain.compiler, &args, work)?;
    if !outcome.succeeded || !compiled.is_file() {
        bail!(
            "{} did not compile {}:\n{}{}",
            toolchain.compiler.display(),
            program.display(),
            outcome.stdout,
            outcome.stderr
        );
    }
    Ok(compiled)
}

fn decompile(
    language: &Language,
    disrobe: &Path,
    compiled: &Path,
    work: &Path,
    stem: &str,
) -> Result<PathBuf> {
    let recovered_dir: PathBuf = work.join("recovered");
    std::fs::create_dir_all(&recovered_dir)
        .wrap_err_with(|| format!("creating {}", recovered_dir.display()))?;
    let (recovered, args): (PathBuf, Vec<OsString>) = match language {
        Language::Lua { .. } => {
            let out: PathBuf = recovered_dir.join(format!("{stem}.lua"));
            let args: Vec<OsString> = vec![
                "lua".into(),
                "decompile".into(),
                compiled.into(),
                "--out".into(),
                out.clone().into(),
            ];
            (out, args)
        }
        Language::Python { .. } => {
            let out: PathBuf = recovered_dir.join(format!("{stem}.py"));
            let args: Vec<OsString> = vec![
                "py".into(),
                "decompile".into(),
                compiled.into(),
                "--out".into(),
                recovered_dir.into(),
            ];
            (out, args)
        }
        Language::Erlang => {
            let out: PathBuf = recovered_dir.join(format!("{stem}.erl"));
            let args: Vec<OsString> = vec![
                "beam".into(),
                "lift".into(),
                compiled.into(),
                "--out".into(),
                recovered_dir.into(),
            ];
            (out, args)
        }
        Language::Java => {
            let out: PathBuf = recovered_dir.join(format!("{stem}.java"));
            let args: Vec<OsString> = vec![
                "jvm".into(),
                "decompile".into(),
                compiled.into(),
                "--out".into(),
                recovered_dir.into(),
            ];
            (out, args)
        }
        Language::Ruby => {
            let analysis: PathBuf = recovered_dir.join(format!("{stem}-ruby.json"));
            let args: Vec<OsString> = vec![
                "ruby".into(),
                "decompile".into(),
                compiled.into(),
                "--out".into(),
                analysis.clone().into(),
            ];
            (analysis.with_extension("rb"), args)
        }
    };
    let outcome: RunOutcome = execute(disrobe, &args, work)?;
    if !outcome.succeeded || !recovered.is_file() {
        bail!(
            "disrobe did not recover {} (expected {}):\n{}{}",
            compiled.display(),
            recovered.display(),
            outcome.stdout,
            outcome.stderr
        );
    }
    Ok(recovered)
}

fn execute(program: &Path, args: &[OsString], cwd: &Path) -> Result<RunOutcome> {
    let execution: Execution = CommandSpec::new(program, STEP_TIMEOUT)
        .args(args.iter().cloned())
        .current_dir(cwd.to_path_buf())
        .capture_limits(CAPTURE_LIMIT, CAPTURE_LIMIT)
        .run()
        .wrap_err_with(|| format!("starting {}", program.display()))?;
    let status: ExitStatus = match execution.completion {
        Completion::Exited(status) => status,
        Completion::TimedOut(_) => bail!(
            "{} ran longer than {} seconds",
            program.display(),
            STEP_TIMEOUT.as_secs()
        ),
    };
    Ok(RunOutcome {
        succeeded: status.success(),
        stdout: captured_text(&execution.stdout, program, "stdout")?,
        stderr: captured_text(&execution.stderr, program, "stderr")?,
    })
}

fn captured_text(capture: &CaptureOutcome, program: &Path, stream: &str) -> Result<String> {
    match capture {
        CaptureOutcome::Complete(captured) if !captured.truncated => {
            Ok(String::from_utf8_lossy(&captured.bytes).replace("\r\n", "\n"))
        }
        CaptureOutcome::Complete(_) => bail!(
            "{} wrote more than {CAPTURE_LIMIT} bytes to {stream}",
            program.display()
        ),
        CaptureOutcome::Failed { source, .. } => {
            bail!("reading {stream} of {} failed: {source}", program.display())
        }
        CaptureOutcome::NotStarted
        | CaptureOutcome::WorkerPanicked
        | CaptureOutcome::WorkerUnresponsive => {
            bail!("{stream} of {} was not captured", program.display())
        }
    }
}

fn find_on_path(names: &[&str]) -> Result<PathBuf> {
    let path: OsString = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        for name in names {
            for candidate in [dir.join(name), dir.join(format!("{name}.exe"))] {
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
    }
    bail!("none of {names:?} is on PATH; install it or add its directory to PATH")
}

fn find_python(version: &str) -> Result<PathBuf> {
    let tag: String = version.replace('.', "");
    let mut candidates: Vec<PathBuf> = Vec::with_capacity(4);
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        candidates.push(
            PathBuf::from(local)
                .join("Programs")
                .join("Python")
                .join(format!("Python{tag}"))
                .join("python.exe"),
        );
    }
    candidates.push(PathBuf::from(format!("/usr/bin/python{version}")));
    candidates.push(PathBuf::from(format!("/usr/local/bin/python{version}")));
    if let Some(found) = candidates.into_iter().find(|p: &PathBuf| p.is_file()) {
        return Ok(found);
    }
    find_on_path(&[&format!("python{version}")])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn languages_parse_to_their_toolchain_family() {
        assert_eq!(
            Language::parse("lua5.3").ok(),
            Some(Language::Lua { version: "5.3" })
        );
        assert_eq!(
            Language::parse("python3.12").ok(),
            Some(Language::Python {
                version: "3.12".to_owned()
            })
        );
        assert_eq!(Language::parse("ruby").ok(), Some(Language::Ruby));
        assert_eq!(Language::parse("erlang").ok(), Some(Language::Erlang));
        assert_eq!(Language::parse("java").ok(), Some(Language::Java));
        assert!(Language::parse("lua5.5").is_err());
        assert!(Language::parse("python3.7").is_err());
        assert!(Language::parse("python2.7").is_err());
        assert!(Language::parse("perl").is_err());
    }
}
