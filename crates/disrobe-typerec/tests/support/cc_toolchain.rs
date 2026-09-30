use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_testkit::{Available, CommandSpec, ToolError, ToolOutput, tool_output};
use object::{Architecture, BinaryFormat, Object, ObjectKind};

pub(crate) const PREREQUISITE: &str = "disrobe-typerec::gnu-cc";
pub(crate) const GCC_BIN_VAR: &str = "DISROBE_GCC_BIN";
pub(crate) const OBJCOPY_BIN_VAR: &str = "DISROBE_OBJCOPY_BIN";

pub(crate) const CALL_TIMEOUT: Duration = Duration::from_mins(2);
const CAPTURE_CAP: usize = 1 << 20;
const NEUTRAL_BUILD_DIRECTORY: &str = "/disrobe/typerec";
const GCC_NAMES: [&str; 3] = ["gcc", "cc", "gcc-14"];
const OBJCOPY_NAMES: [&str; 2] = ["objcopy", "llvm-objcopy"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CcTarget {
    X86_64Elf,
    X86_64Pe,
}

impl CcTarget {
    fn from_triple(triple: &str) -> Option<Self> {
        let (architecture, platform): (&str, &str) = triple.split_once('-')?;
        if architecture != "x86_64" {
            return None;
        }
        if platform.split('-').any(|part: &str| part == "mingw32") {
            Some(Self::X86_64Pe)
        } else if platform
            .split('-')
            .any(|part: &str| matches!(part, "linux" | "elf"))
        {
            Some(Self::X86_64Elf)
        } else {
            None
        }
    }

    const fn format(self) -> BinaryFormat {
        match self {
            Self::X86_64Elf => BinaryFormat::Elf,
            Self::X86_64Pe => BinaryFormat::Pe,
        }
    }

    fn verify_image(self, bytes: &[u8]) -> Result<(), String> {
        let file: object::File<'_> = object::File::parse(bytes)
            .map_err(|error: object::Error| format!("parse compiled image: {error}"))?;
        if file.architecture() != Architecture::X86_64
            || file.format() != self.format()
            || !matches!(file.kind(), ObjectKind::Executable | ObjectKind::Dynamic)
        {
            return Err(format!(
                "expected a linked {self:?} image, found {:?} {:?} {:?}",
                file.architecture(),
                file.format(),
                file.kind()
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CcToolchain {
    pub(crate) gcc: PathBuf,
    pub(crate) objcopy: PathBuf,
    pub(crate) identity: String,
    target: CcTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Probe {
    Usable(Box<CcToolchain>),
    NotGnu { identity: String },
    Missing { defect: String },
    InvalidTarget { defect: String },
}

const fn executable_suffixes() -> &'static [&'static str] {
    if cfg!(windows) {
        &["", ".exe", ".bat", ".cmd"]
    } else {
        &[""]
    }
}

pub(crate) fn find_on_path(names: &[&str], binary_var: &str) -> Option<PathBuf> {
    if let Some(raw) = std::env::var_os(binary_var) {
        let candidate: PathBuf = PathBuf::from(raw);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    let path_var: OsString = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path_var) {
        for name in names {
            for suffix in executable_suffixes() {
                let candidate: PathBuf = directory.join(format!("{name}{suffix}"));
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

fn command_line(program: &Path, arguments: &[OsString]) -> String {
    let mut printed: String = program.display().to_string();
    for argument in arguments {
        printed.push(' ');
        printed.push_str(&argument.to_string_lossy());
    }
    printed
}

fn run_bounded(
    program: &Path,
    arguments: &[OsString],
    work: Option<&Path>,
) -> Result<ToolOutput, String> {
    let mut spec: CommandSpec = CommandSpec::new(program, CALL_TIMEOUT)
        .args(arguments)
        .capture_limits(CAPTURE_CAP, CAPTURE_CAP);
    if let Some(work) = work {
        spec = spec.current_dir(work.to_path_buf());
    }
    let output: ToolOutput = tool_output(spec).map_err(|error: ToolError| {
        format!(
            "`{}` could not run: {error}",
            command_line(program, arguments)
        )
    })?;
    if output.timed_out {
        return Err(format!(
            "`{}` did not exit within {CALL_TIMEOUT:?}",
            command_line(program, arguments)
        ));
    }
    Ok(output)
}

fn first_line(output: &ToolOutput) -> String {
    let mut printed: String = String::from_utf8_lossy(&output.stdout).into_owned();
    if printed.trim().is_empty() {
        printed = String::from_utf8_lossy(&output.stderr).into_owned();
    }
    printed.lines().next().unwrap_or_default().trim().to_owned()
}

fn identity_of(program: &Path) -> Result<String, String> {
    let output: ToolOutput = run_bounded(program, &[OsString::from("--version")], None)?;
    if output.exit_code != Some(0) {
        return Err(format!(
            "`{} --version` exited with {:?}",
            program.display(),
            output.exit_code
        ));
    }
    let line: String = first_line(&output);
    if line.is_empty() {
        return Err(format!(
            "`{} --version` printed nothing, so it cannot be identified",
            program.display()
        ));
    }
    Ok(line)
}

fn announces_gnu(identity: &str) -> bool {
    let lowered: String = identity.to_ascii_lowercase();
    if lowered.contains("clang") {
        return false;
    }
    lowered.contains("gcc") || lowered.contains("free software foundation")
}

fn target_of(program: &Path) -> Result<(CcTarget, String), String> {
    let arguments: [OsString; 1] = [OsString::from("-dumpmachine")];
    let output: ToolOutput = run_bounded(program, &arguments, None)?;
    if output.exit_code != Some(0) {
        return Err(describe(program, &arguments, &output));
    }
    let triple: &str = std::str::from_utf8(&output.stdout)
        .map_err(|error: std::str::Utf8Error| format!("invalid compiler target: {error}"))?
        .trim();
    let target: CcTarget = CcTarget::from_triple(triple).ok_or_else(|| {
        format!(
            "`{} -dumpmachine` reported {triple:?}; these grades require linked x86-64 ELF or \
             PE images. Set {GCC_BIN_VAR} and {OBJCOPY_BIN_VAR} to matching x86_64-elf GNU \
             cross tools, or use an x86-64 Linux or MinGW GNU toolchain",
            program.display()
        )
    })?;
    Ok((target, triple.to_owned()))
}

pub(crate) fn probe() -> Probe {
    let Some(gcc): Option<PathBuf> = find_on_path(&GCC_NAMES, GCC_BIN_VAR) else {
        return Probe::Missing {
            defect: format!(
                "none of {} is on PATH and {GCC_BIN_VAR} does not name a file",
                GCC_NAMES.join(", ")
            ),
        };
    };
    let identity: String = match identity_of(&gcc) {
        Ok(identity) => identity,
        Err(defect) => return Probe::Missing { defect },
    };
    if !announces_gnu(&identity) {
        return Probe::NotGnu { identity };
    }
    let (target, triple): (CcTarget, String) = match target_of(&gcc) {
        Ok(target) => target,
        Err(defect) => return Probe::InvalidTarget { defect },
    };
    let Some(objcopy): Option<PathBuf> = find_on_path(&OBJCOPY_NAMES, OBJCOPY_BIN_VAR) else {
        return Probe::Missing {
            defect: format!(
                "{} names a usable gcc but none of {} is on PATH, so a stripped input cannot be \
                 produced",
                gcc.display(),
                OBJCOPY_NAMES.join(", ")
            ),
        };
    };
    if let Err(defect) = identity_of(&objcopy) {
        return Probe::Missing { defect };
    }
    Probe::Usable(Box::new(CcToolchain {
        gcc,
        objcopy,
        identity: format!("{identity}; target={triple}"),
        target,
    }))
}

pub(crate) fn require(graded: &str) -> CcToolchain {
    resolve(graded, probe())
}

#[allow(clippy::panic)]
pub(crate) fn resolve(graded: &str, probe: Probe) -> CcToolchain {
    let (found, what): (Option<CcToolchain>, String) = match probe {
        Probe::Usable(toolchain) => (Some(*toolchain), String::new()),
        Probe::InvalidTarget { defect } => {
            panic!("{graded} cannot use the selected GNU compiler: {defect}");
        }
        Probe::NotGnu { identity } => (
            None,
            format!(
                "a GNU C compiler, because {graded} reads the debug information GNU cc emits and \
                 the C compiler here announces itself as {identity:?}; install gcc, or point \
                 {GCC_BIN_VAR} at one"
            ),
        ),
        Probe::Missing { defect } => (
            None,
            format!(
                "a GNU C compiler and binutils ({defect}); install them, or point {GCC_BIN_VAR} \
                 and {OBJCOPY_BIN_VAR} at them"
            ),
        ),
    };
    match disrobe_testkit::require(PREREQUISITE, &what, found) {
        Ok(Available::Present(toolchain)) => toolchain,
        Ok(Available::NotMeasured { record }) => panic!(
            "tests/optional.toml lists {PREREQUISITE}, but {graded} has no result without a GNU \
             C compiler, so that entry only hides the gap recorded in {}; remove it",
            record.display()
        ),
        Err(error) => {
            panic!("{graded} was measured against nothing and must not report success: {error}")
        }
    }
}

fn describe(program: &Path, arguments: &[OsString], output: &ToolOutput) -> String {
    format!(
        "`{}` exited with {:?} and printed stdout {:?} and stderr {:?}",
        command_line(program, arguments),
        output.exit_code,
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

fn call(program: &Path, arguments: &[OsString], work: &Path) -> Result<(), String> {
    let output: ToolOutput = run_bounded(program, arguments, Some(work))?;
    if output.exit_code == Some(0) {
        return Ok(());
    }
    Err(describe(program, arguments, &output))
}

pub(crate) fn compile(
    toolchain: &CcToolchain,
    work: &Path,
    source: &OsStr,
    output: &OsStr,
    flags: &[&str],
) -> Result<(), String> {
    let mut arguments: Vec<OsString> = vec![OsString::from(format!(
        "-fdebug-prefix-map={}={NEUTRAL_BUILD_DIRECTORY}",
        work.display()
    ))];
    arguments.extend(flags.iter().map(OsString::from));
    arguments.push(OsString::from("-Wl,-e,_start"));
    arguments.push(OsString::from("-o"));
    arguments.push(output.to_owned());
    arguments.push(source.to_owned());
    call(&toolchain.gcc, &arguments, work)?;
    let path: PathBuf = work.join(output);
    let bytes: Vec<u8> = std::fs::read(&path)
        .map_err(|error: std::io::Error| format!("read {}: {error}", path.display()))?;
    toolchain.target.verify_image(&bytes)
}

pub(crate) fn strip_debug(
    toolchain: &CcToolchain,
    work: &Path,
    input: &OsStr,
    output: &OsStr,
) -> Result<(), String> {
    let arguments: Vec<OsString> = vec![
        OsString::from("--strip-debug"),
        input.to_owned(),
        output.to_owned(),
    ];
    call(&toolchain.objcopy, &arguments, work)
}

pub(crate) fn accepts_flag(toolchain: &CcToolchain, work: &Path, flag: &str) -> bool {
    let probe_source: PathBuf = work.join("disrobe_flag_probe.c");
    if std::fs::write(
        &probe_source,
        b"int disrobe_flag_probe(void) { return 0; }\n",
    )
    .is_err()
    {
        return false;
    }
    let arguments: Vec<OsString> = vec![
        OsString::from(flag),
        OsString::from("-c"),
        OsString::from("-o"),
        OsString::from("disrobe_flag_probe.o"),
        OsString::from("disrobe_flag_probe.c"),
    ];
    call(&toolchain.gcc, &arguments, work).is_ok()
}

pub(crate) fn stage_source(work: &Path, source: &Path) -> Result<OsString, String> {
    let Some(name): Option<&OsStr> = source.file_name() else {
        return Err(format!("{} has no file name", source.display()));
    };
    let staged: PathBuf = work.join(name);
    std::fs::copy(source, &staged).map_err(|error: std::io::Error| {
        format!("copy {} to {}: {error}", source.display(), staged.display())
    })?;
    Ok(name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::CcTarget;

    #[test]
    fn compiler_targets_preserve_the_x86_64_image_contract() {
        for triple in ["x86_64-elf", "x86_64-unknown-linux-gnu", "x86_64-linux-gnu"] {
            assert_eq!(CcTarget::from_triple(triple), Some(CcTarget::X86_64Elf));
        }
        assert_eq!(
            CcTarget::from_triple("x86_64-w64-mingw32"),
            Some(CcTarget::X86_64Pe)
        );
        for triple in [
            "aarch64-apple-darwin24",
            "x86_64-apple-darwin24",
            "aarch64-linux-gnu",
            "i686-w64-mingw32",
            "x86_64-unknown-unknown",
            "",
        ] {
            assert_eq!(CcTarget::from_triple(triple), None, "{triple}");
        }
    }

    #[test]
    fn compiled_images_must_match_the_compiler_target() {
        let elf: &[u8] = include_bytes!("../fixtures/region_corpus.unstripped.elf");
        let pe: &[u8] = include_bytes!("../fixtures/types_corpus.unstripped.exe");
        assert!(CcTarget::X86_64Elf.verify_image(elf).is_ok());
        assert!(CcTarget::X86_64Pe.verify_image(pe).is_ok());
        assert!(CcTarget::X86_64Elf.verify_image(pe).is_err());
        assert!(CcTarget::X86_64Pe.verify_image(elf).is_err());
        assert!(CcTarget::X86_64Elf.verify_image(b"not an image").is_err());

        let mut wrong_architecture: Vec<u8> = elf.to_vec();
        wrong_architecture[18..20].copy_from_slice(&183u16.to_le_bytes());
        assert!(
            CcTarget::X86_64Elf
                .verify_image(&wrong_architecture)
                .is_err()
        );

        let mut unlinked: Vec<u8> = elf.to_vec();
        unlinked[16..18].copy_from_slice(&1u16.to_le_bytes());
        assert!(CcTarget::X86_64Elf.verify_image(&unlinked).is_err());
    }
}
