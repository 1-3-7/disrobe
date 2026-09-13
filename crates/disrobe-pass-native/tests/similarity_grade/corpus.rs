use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;

const FIXTURE_DIRECTORY: &str = "similarity_corpus";

const HOSTED_HARNESS: &str = "harness_hosted.c";

const FREESTANDING_HARNESS: &str = "harness_free.c";

const VARIANT_SUFFIX: &str = ".v2";

#[cfg(target_os = "windows")]
const FORCED_IMPORT_THUNK_SOURCE: &str =
    "typedef unsigned long long u64;\nu64 corpus_main(u64 seed) { return seed + 7; }\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Compiler {
    Gcc,
    Clang,
}

impl Compiler {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Gcc => "gcc",
            Self::Clang => "clang",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Flavor {
    Hosted,
    FreestandingElf64,
    FreestandingAarch64,
}

impl Flavor {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Hosted => "hosted",
            Self::FreestandingElf64 => "freestanding-x86-64",
            Self::FreestandingAarch64 => "freestanding-aarch64",
        }
    }

    const fn harness(self) -> &'static str {
        match self {
            Self::Hosted => HOSTED_HARNESS,
            Self::FreestandingElf64 | Self::FreestandingAarch64 => FREESTANDING_HARNESS,
        }
    }

    fn flags(self, compiler: Compiler) -> Vec<&'static str> {
        match (self, compiler) {
            (Self::Hosted, Compiler::Gcc) => Vec::new(),
            (Self::Hosted, Compiler::Clang) if cfg!(target_os = "macos") => {
                vec!["--target=x86_64-w64-windows-gnu", "-fuse-ld=lld"]
            }
            (Self::Hosted, Compiler::Clang) => vec!["--target=x86_64-w64-windows-gnu"],
            (Self::FreestandingElf64, _) => vec![
                "--target=x86_64-unknown-linux-gnu",
                "-nostdlib",
                "-ffreestanding",
                "-fuse-ld=lld",
            ],
            (Self::FreestandingAarch64, _) => vec![
                "--target=aarch64-unknown-linux-gnu",
                "-nostdlib",
                "-ffreestanding",
                "-fuse-ld=lld",
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BuildKey {
    pub(crate) program: String,
    pub(crate) compiler: Compiler,
    pub(crate) flavor: Flavor,
    pub(crate) level: &'static str,
}

impl BuildKey {
    pub(crate) fn describe(&self) -> String {
        format!(
            "{} {} {} -{}",
            self.program,
            self.compiler.label(),
            self.flavor.label(),
            self.level
        )
    }
}

#[derive(Debug)]
pub(crate) struct Artifact {
    pub(crate) symbols: Vec<u8>,
    pub(crate) stripped: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct Toolchain {
    root: PathBuf,
    scratch: ScratchDir,
    gcc: Option<PathBuf>,
    clang: Option<PathBuf>,
    strippers: Vec<PathBuf>,
    versions: BTreeMap<&'static str, String>,
}

impl Toolchain {
    pub(crate) fn discover() -> Option<Self> {
        let root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(FIXTURE_DIRECTORY);
        if !root.is_dir() {
            return None;
        }
        let scratch: ScratchDir = ScratchDir::create("similarity-grade").ok()?;
        let gcc: Option<PathBuf> = locate_gnu_gcc();
        let clang: Option<PathBuf> = locate("clang");
        let strippers: Vec<PathBuf> = ["llvm-strip", "strip"]
            .into_iter()
            .filter_map(locate)
            .collect();
        let mut versions: BTreeMap<&'static str, String> = BTreeMap::new();
        if let Some(gcc) = &gcc {
            versions.insert("gcc", first_line(gcc));
        }
        if let Some(clang) = &clang {
            versions.insert("clang", first_line(clang));
        }
        Some(Self {
            root,
            scratch,
            gcc,
            clang,
            strippers,
            versions,
        })
    }

    pub(crate) const fn has_gcc(&self) -> bool {
        self.gcc.is_some()
    }

    pub(crate) const fn has_clang(&self) -> bool {
        self.clang.is_some()
    }

    pub(crate) const fn can_strip(&self) -> bool {
        !self.strippers.is_empty()
    }

    pub(crate) const fn versions(&self) -> &BTreeMap<&'static str, String> {
        &self.versions
    }

    pub(crate) fn programs(&self) -> Vec<String> {
        let Ok(entries): std::io::Result<std::fs::ReadDir> = std::fs::read_dir(&self.root) else {
            return Vec::new();
        };
        let mut out: Vec<String> = Vec::new();
        for entry in entries.flatten() {
            let name: String = entry.file_name().to_string_lossy().into_owned();
            let Some(stem): Option<&str> = name.strip_suffix(".c") else {
                continue;
            };
            if stem.starts_with("harness_") || stem.ends_with(VARIANT_SUFFIX) {
                continue;
            }
            out.push(stem.to_owned());
        }
        out.sort_unstable();
        out
    }

    pub(crate) fn variant_of(&self, program: &str) -> Option<String> {
        let candidate: String = format!("{program}{VARIANT_SUFFIX}");
        self.root
            .join(format!("{candidate}.c"))
            .is_file()
            .then_some(candidate)
    }

    pub(crate) fn build(&self, key: &BuildKey) -> Option<Artifact> {
        let source: PathBuf = self.root.join(format!("{}.c", key.program));
        if !source.is_file() {
            return None;
        }
        let stem: String = format!(
            "{}-{}-{}-{}",
            key.program.replace('.', "_"),
            key.compiler.label(),
            key.flavor.label(),
            key.level
        );
        self.build_source(&stem, &source, key.compiler, key.flavor, key.level, &[])
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn build_forced_import_thunk(&self) -> Option<Artifact> {
        let source: PathBuf = self.scratch.path().join("forced-import-thunk.c");
        std::fs::write(&source, FORCED_IMPORT_THUNK_SOURCE).ok()?;
        self.build_source(
            "forced-import-thunk-gcc-hosted-O2",
            &source,
            Compiler::Gcc,
            Flavor::Hosted,
            "O2",
            &["-Wl,--undefined=Sleep", "-lkernel32"],
        )
    }

    fn build_source(
        &self,
        stem: &str,
        source: &Path,
        compiler_kind: Compiler,
        flavor: Flavor,
        level: &str,
        extra_linker_args: &[&str],
    ) -> Option<Artifact> {
        let compiler: &PathBuf = match compiler_kind {
            Compiler::Gcc => self.gcc.as_ref()?,
            Compiler::Clang => self.clang.as_ref()?,
        };
        let output: PathBuf = self.scratch.path().join(format!("{stem}.image"));
        let mut command: Command = Command::new(compiler);
        command
            .arg(format!("-I{}", self.root.display()))
            .args(flavor.flags(compiler_kind))
            .arg(format!("-{level}"))
            .arg("-o")
            .arg(&output)
            .arg(source)
            .arg(self.root.join(flavor.harness()))
            .args(extra_linker_args);
        if !succeeded(&mut command) {
            return None;
        }
        let symbols: Vec<u8> = std::fs::read(&output).ok()?;
        let stripped_path: PathBuf = self.scratch.path().join(format!("{stem}.stripped"));
        let stripped: Vec<u8> = self.strip(&output, &stripped_path)?;
        Some(Artifact { symbols, stripped })
    }

    fn strip(&self, source: &Path, destination: &Path) -> Option<Vec<u8>> {
        for stripper in &self.strippers {
            if std::fs::copy(source, destination).is_err() {
                continue;
            }
            let mut command: Command = Command::new(stripper);
            command.arg("-s").arg(destination);
            if !succeeded(&mut command) {
                continue;
            }
            if let Ok(bytes) = std::fs::read(destination) {
                return Some(bytes);
            }
        }
        None
    }
}

fn locate(name: &str) -> Option<PathBuf> {
    Command::new(name)
        .arg("--version")
        .output()
        .ok()
        .filter(|out: &Output| out.status.success())
        .map(|_| PathBuf::from(name))
}

fn locate_gnu_gcc() -> Option<PathBuf> {
    let configured: Option<std::ffi::OsString> = std::env::var_os("DISROBE_SIMILARITY_GCC");
    let candidates: Vec<PathBuf> = configured
        .map(PathBuf::from)
        .into_iter()
        .chain(if cfg!(target_os = "macos") {
            vec![PathBuf::from("x86_64-w64-mingw32-gcc")]
        } else {
            vec![PathBuf::from("gcc")]
        })
        .collect();
    candidates.into_iter().find_map(|candidate: PathBuf| {
        let output: Output = Command::new(&candidate).arg("--version").output().ok()?;
        let version: String = String::from_utf8(output.stdout).ok()?;
        (output.status.success()
            && version.to_ascii_lowercase().contains("gcc")
            && !version.to_ascii_lowercase().contains("clang"))
        .then_some(candidate)
    })
}

fn first_line(path: &Path) -> String {
    Command::new(path)
        .arg("--version")
        .output()
        .ok()
        .and_then(|out: Output| String::from_utf8(out.stdout).ok())
        .and_then(|text: String| text.lines().next().map(str::trim).map(str::to_owned))
        .unwrap_or_else(|| format!("{} version unavailable", path.display()))
}

fn succeeded(command: &mut Command) -> bool {
    command
        .output()
        .is_ok_and(|out: Output| out.status.success())
}
