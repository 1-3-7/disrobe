#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_ir::payload::DisasmPayload;
use disrobe_nir::{NirModule, NirOp, NirSymbol};
use disrobe_taint::{TaintConfig, TaintFinding, TaintReport};

pub(crate) const CORPUS_URL: &str = "https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip";
pub(crate) const CORPUS_SHA256: &str =
    "ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb";
pub(crate) const CORPUS_SIZE_BYTES: u64 = 152_957_342;
pub(crate) const REQUIRE_CORPUS_VAR: &str = "DISROBE_REQUIRE_JULIET_CORPUS";

const MANIFEST_PATH: &str = "C/manifest.xml";
const TESTCASESUPPORT_FILES: [&str; 3] = [
    "C/testcasesupport/io.c",
    "C/testcasesupport/std_testcase.h",
    "C/testcasesupport/std_testcase_io.h",
];
const CWE78_ZIP_PREFIX: &str = "C/testcases/CWE78_OS_Command_Injection/";

const COMPILE_TIMEOUT: Duration = Duration::from_secs(30);
const ANALYZE_TIMEOUT: Duration = Duration::from_secs(20);
const CAPTURE_CAP_BYTES: usize = 1 << 20;
const CASE_WORKERS: usize = 8;

const C_COMPILER_CANDIDATES: [&str; 3] = ["cc", "gcc", "clang"];

static HOST_C_COMPILER: OnceLock<Option<PathBuf>> = OnceLock::new();

fn tool_runs(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|probe: std::process::Output| probe.status.success())
}

pub(crate) fn host_c_compiler() -> Option<&'static Path> {
    HOST_C_COMPILER
        .get_or_init(|| {
            C_COMPILER_CANDIDATES
                .into_iter()
                .find(|candidate: &&'static str| tool_runs(candidate))
                .map(PathBuf::from)
        })
        .as_deref()
}

pub(crate) const DEFAULT_SOURCES: &[&str] = &[
    "recv",
    "recvfrom",
    "read",
    "fread",
    "fgets",
    "gets",
    "accept",
    "socket",
    "input",
    "getenv",
    "ReadFile",
    "InternetReadFile",
    "os.read",
    "sys.stdin.read",
    "socket.socket",
    "socket.recv",
    "sock.recv",
    "request.args.get",
    "request.form.get",
    "request.get_data",
];

pub(crate) const DEFAULT_SINKS: &[&str] = &[
    "system",
    "popen",
    "exec",
    "execl",
    "execv",
    "execve",
    "execvp",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "CreateProcessA",
    "CreateProcessW",
    "eval",
    "write",
    "fwrite",
    "send",
    "sendto",
    "connect",
    "WriteFile",
    "os.system",
    "os.popen",
    "os.exec",
    "os.execv",
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_output",
];

pub(crate) fn default_taint_config() -> TaintConfig {
    TaintConfig::from_lists(
        DEFAULT_SOURCES.iter().copied(),
        DEFAULT_SINKS.iter().copied(),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CorpusRequirement {
    Optional,
    Mandatory,
}

pub(crate) fn corpus_requirement() -> CorpusRequirement {
    let raw: Option<std::ffi::OsString> = std::env::var_os(REQUIRE_CORPUS_VAR);
    let Some(raw): Option<std::ffi::OsString> = raw else {
        return CorpusRequirement::Optional;
    };
    let text: String = raw.to_string_lossy().trim().to_ascii_lowercase();
    match text.as_str() {
        "" | "0" | "false" | "no" | "off" => CorpusRequirement::Optional,
        _ => CorpusRequirement::Mandatory,
    }
}

pub(crate) fn cache_root() -> PathBuf {
    disrobe_core::scratch::scratch_root().join("juliet-corpus-cache")
}

pub(crate) fn cached_zip_path() -> PathBuf {
    cache_root().join("juliet_1_3.zip")
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let mut hasher: Sha256 = Sha256::new();
    hasher.update(bytes);
    let digest: sha2::digest::Output<Sha256> = hasher.finalize();
    let mut out: String = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _: std::fmt::Result = write!(out, "{byte:02x}");
    }
    out
}

fn declared_zip_defect(bytes: &[u8]) -> Option<String> {
    if bytes.len() as u64 != CORPUS_SIZE_BYTES {
        return Some(format!(
            "cached juliet_1_3.zip is {} bytes, expected {CORPUS_SIZE_BYTES}",
            bytes.len()
        ));
    }
    let digest: String = sha256_hex(bytes);
    (digest != CORPUS_SHA256)
        .then(|| format!("cached juliet_1_3.zip has sha256 {digest}, expected {CORPUS_SHA256}"))
}

fn fetch_command() -> String {
    format!(
        "mkdir -p \"{cache}\" && curl -sS -o \"{zip}\" \"{url}\"",
        cache = cache_root().display(),
        zip = cached_zip_path().display(),
        url = CORPUS_URL,
    )
}

fn announce_ungraded(case: &str) {
    println!(
        "\nUNGRADED {case}: the NIST SARD Juliet Test Suite for C/C++ v1.3 is absent from the \
         local cache at {zip}. It is {CORPUS_SIZE_BYTES} bytes, pinned by sha256 {CORPUS_SHA256}, \
         and is never fetched automatically or tracked in this repository. Populate the cache \
         reproducibly with:\n  {cmd}\nthen re-run this test. Set {REQUIRE_CORPUS_VAR}=1 to fail \
         instead of skipping when the corpus is absent.\n",
        zip = cached_zip_path().display(),
        cmd = fetch_command(),
    );
}

fn enforce_requirement(case: &str, requirement: CorpusRequirement) {
    assert!(
        requirement == CorpusRequirement::Optional,
        "{REQUIRE_CORPUS_VAR} makes the Juliet corpus mandatory for {case}, so it cannot be \
         graded and must not report success. Populate the cache with:\n  {}\nor clear \
         {REQUIRE_CORPUS_VAR} to permit a run that grades nothing here.",
        fetch_command(),
    );
    announce_ungraded(case);
}

pub(crate) fn ensure_corpus_zip(case: &str) -> Option<Vec<u8>> {
    let zip_path: PathBuf = cached_zip_path();
    match std::fs::read(&zip_path) {
        Ok(bytes) => {
            if let Some(defect) = declared_zip_defect(&bytes) {
                let _: std::io::Result<()> = std::fs::remove_file(&zip_path);
                panic!(
                    "{case}: {zip_path} did not match the pinned Juliet corpus and was removed: \
                     {defect}. Re-populate with:\n  {cmd}",
                    zip_path = zip_path.display(),
                    cmd = fetch_command(),
                );
            }
            Some(bytes)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            enforce_requirement(case, corpus_requirement());
            None
        }
        Err(err) => panic!(
            "{case}: {} exists but could not be read ({err}); an unreadable cache entry is never \
             a skip",
            zip_path.display()
        ),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ManifestFlaw {
    pub(crate) line: u32,
    pub(crate) name: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ManifestFile {
    pub(crate) path: String,
    pub(crate) flaws: Vec<ManifestFlaw>,
}

#[derive(Debug, Clone)]
pub(crate) struct ManifestTestcase {
    pub(crate) files: Vec<ManifestFile>,
}

fn xml_unescape(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn xml_attr(line: &str, attr: &str) -> Option<String> {
    let needle: String = format!("{attr}=\"");
    let start: usize = line.find(&needle)? + needle.len();
    let rest: &str = &line[start..];
    let end: usize = rest.find('"')?;
    Some(xml_unescape(&rest[..end]))
}

pub(crate) fn parse_manifest(xml: &str) -> Vec<ManifestTestcase> {
    let mut testcases: Vec<ManifestTestcase> = Vec::new();
    let mut current: Option<Vec<ManifestFile>> = None;
    let mut pending_file: Option<ManifestFile> = None;
    for (idx, raw_line) in xml.lines().enumerate() {
        let line_no: usize = idx + 1;
        let line: &str = raw_line.trim();
        if line.is_empty() || line.starts_with("<?xml") {
            continue;
        }
        if line == "<container>" || line == "</container>" {
            continue;
        }
        if line == "<testcase>" {
            assert!(
                current.is_none(),
                "nested <testcase> at manifest.xml line {line_no}"
            );
            current = Some(Vec::new());
            continue;
        }
        if line == "</testcase>" {
            let files: Vec<ManifestFile> = current.take().unwrap_or_else(|| {
                panic!("</testcase> without an open <testcase> at line {line_no}")
            });
            assert!(
                pending_file.is_none(),
                "<file> left open across </testcase> at manifest.xml line {line_no}"
            );
            testcases.push(ManifestTestcase { files });
            continue;
        }
        let group: &mut Vec<ManifestFile> = current.as_mut().unwrap_or_else(|| {
            panic!("manifest.xml content outside <testcase> at line {line_no}: {line}")
        });
        if let Some(_rest) = line.strip_prefix("<file ") {
            assert!(
                pending_file.is_none(),
                "nested <file> at manifest.xml line {line_no}"
            );
            let path: String = xml_attr(line, "path").unwrap_or_else(|| {
                panic!("<file> without a path attribute at line {line_no}: {line}")
            });
            let file: ManifestFile = ManifestFile {
                path,
                flaws: Vec::new(),
            };
            if line.ends_with("/>") {
                group.push(file);
            } else if line.ends_with('>') {
                pending_file = Some(file);
            } else {
                panic!("malformed <file> tag at manifest.xml line {line_no}: {line}");
            }
            continue;
        }
        if line == "</file>" {
            let file: ManifestFile = pending_file
                .take()
                .unwrap_or_else(|| panic!("</file> without an open <file> at line {line_no}"));
            group.push(file);
            continue;
        }
        if line.starts_with("<flaw ") {
            let file: &mut ManifestFile = pending_file.as_mut().unwrap_or_else(|| {
                panic!("<flaw> outside an open <file> at line {line_no}: {line}")
            });
            let flaw_line: u32 = xml_attr(line, "line")
                .and_then(|v: String| v.parse().ok())
                .unwrap_or_else(|| {
                    panic!("<flaw> without a numeric line attribute at line {line_no}: {line}")
                });
            let name: String = xml_attr(line, "name").unwrap_or_else(|| {
                panic!("<flaw> without a name attribute at line {line_no}: {line}")
            });
            file.flaws.push(ManifestFlaw {
                line: flaw_line,
                name,
            });
            continue;
        }
        panic!("unrecognized manifest.xml line {line_no}: {line}");
    }
    assert!(
        current.is_none(),
        "manifest.xml ended with an open <testcase>"
    );
    testcases
}

fn has_extension(name: &str, extension: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|found: &OsStr| found.eq_ignore_ascii_case(extension))
}

fn is_selected_flaw_file(name: &str) -> bool {
    name.starts_with("CWE78_OS_Command_Injection__char_")
        && name.contains("_system_")
        && has_extension(name, "c")
}

#[derive(Debug, Clone)]
pub(crate) struct FunctionSpan {
    pub(crate) name: String,
    pub(crate) start_line: usize,
    pub(crate) end_line: usize,
}

fn starts_with_comment_or_directive(trimmed: &str) -> bool {
    trimmed.starts_with('#')
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
        || trimmed.starts_with("//")
}

fn function_signature_name(trimmed: &str) -> Option<String> {
    if trimmed.contains(';') || trimmed.contains('{') || trimmed.contains('}') {
        return None;
    }
    if !trimmed.ends_with(')') {
        return None;
    }
    let paren_pos: usize = trimmed.find('(')?;
    let before: &str = trimmed[..paren_pos].trim_end();
    let name: &str = before
        .rsplit(|c: char| !(c.is_alphanumeric() || c == '_'))
        .next()?;
    let first: char = name.chars().next()?;
    (!name.is_empty() && (first.is_alphabetic() || first == '_')).then(|| name.to_owned())
}

pub(crate) fn top_level_functions(source: &str) -> Vec<FunctionSpan> {
    let mut out: Vec<FunctionSpan> = Vec::new();
    let mut depth: i64 = 0;
    let mut pending: Option<(String, usize)> = None;
    for (idx, line) in source.lines().enumerate() {
        let line_no: usize = idx + 1;
        let trimmed: &str = line.trim();
        if depth == 0
            && !trimmed.is_empty()
            && !starts_with_comment_or_directive(trimmed)
            && let Some(name) = function_signature_name(trimmed)
        {
            pending = Some((name, line_no));
        }
        if depth == 0 && trimmed.ends_with('{') && pending.is_some() {
            depth = 1;
            continue;
        }
        if depth > 0 {
            let opens: i64 = line.matches('{').count() as i64;
            let closes: i64 = line.matches('}').count() as i64;
            depth += opens - closes;
            if depth <= 0 {
                if let Some((name, start_line)) = pending.take() {
                    out.push(FunctionSpan {
                        name,
                        start_line,
                        end_line: line_no,
                    });
                }
                depth = 0;
            }
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Category {
    DirectFlow,
    Field,
    ArrayElement,
    Container,
    Callback,
    VirtualCall,
    FunctionPointer,
    StringOperation,
    SanitizerSevers,
    ControlDependence,
    Loop,
    Recursion,
    InterproceduralDepthOne,
    InterproceduralDepthGtOne,
    LibraryBoundary,
}

impl Category {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::DirectFlow => "direct flow",
            Self::Field => "flow through a field",
            Self::ArrayElement => "flow through an array element",
            Self::Container => "flow through a container",
            Self::Callback => "flow through a callback",
            Self::VirtualCall => "flow across a virtual call",
            Self::FunctionPointer => "flow across a function pointer",
            Self::StringOperation => "flow through a string operation",
            Self::SanitizerSevers => "flow through a sanitiser that should sever it",
            Self::ControlDependence => "implicit flow through a control dependence",
            Self::Loop => "flow through a loop",
            Self::Recursion => "flow through recursion",
            Self::InterproceduralDepthOne => "inter-procedural flow at depth one",
            Self::InterproceduralDepthGtOne => "inter-procedural flow at depth greater than one",
            Self::LibraryBoundary => "flow across a library boundary",
        }
    }

    pub(crate) const fn all() -> [Self; 15] {
        [
            Self::DirectFlow,
            Self::Field,
            Self::ArrayElement,
            Self::Container,
            Self::Callback,
            Self::VirtualCall,
            Self::FunctionPointer,
            Self::StringOperation,
            Self::SanitizerSevers,
            Self::ControlDependence,
            Self::Loop,
            Self::Recursion,
            Self::InterproceduralDepthOne,
            Self::InterproceduralDepthGtOne,
            Self::LibraryBoundary,
        ]
    }
}

fn classify_variant(variant: &str) -> Option<Category> {
    match variant {
        "01" | "31" | "32" => Some(Category::DirectFlow),
        "34" | "67" => Some(Category::Field),
        "66" => Some(Category::ArrayElement),
        "44" | "65" => Some(Category::FunctionPointer),
        "16" | "17" => Some(Category::Loop),
        "02" | "03" | "04" | "05" | "06" | "07" | "08" | "09" | "10" | "11" | "12" | "13"
        | "14" | "15" | "18" | "21" | "22" => Some(Category::ControlDependence),
        "41" | "42" | "45" | "51" | "61" | "63" | "64" | "68" => {
            Some(Category::InterproceduralDepthOne)
        }
        "52" | "53" | "54" => Some(Category::InterproceduralDepthGtOne),
        _ => None,
    }
}

fn variant_number(flaw_source: &str) -> Option<String> {
    let marker: &str = "Flow Variant:";
    let start: usize = flaw_source.find(marker)? + marker.len();
    let rest: &str = flaw_source[start..].trim_start();
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    (!digits.is_empty()).then_some(digits)
}

#[derive(Debug, Clone)]
pub(crate) struct TestcaseGroup {
    pub(crate) flaw_file: String,
    pub(crate) flaw_line: u32,
    pub(crate) variant: String,
    pub(crate) category: Category,
    pub(crate) member_paths: Vec<String>,
    pub(crate) bad_entry: String,
    pub(crate) good_entry: String,
    pub(crate) bad_chain: BTreeSet<String>,
    pub(crate) good_chain: BTreeSet<String>,
}

pub(crate) struct JulietCorpusContent {
    pub(crate) files: BTreeMap<String, Vec<u8>>,
    pub(crate) testcasesupport_dir: ScratchDir,
    pub(crate) groups: Vec<TestcaseGroup>,
}

fn read_zip_entries(zip_bytes: &[u8], needed: &BTreeSet<String>) -> BTreeMap<String, Vec<u8>> {
    use std::io::Read as _;
    let cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(zip_bytes);
    let mut archive: zip::ZipArchive<std::io::Cursor<&[u8]>> =
        zip::ZipArchive::new(cursor).expect("open juliet_1_3.zip");
    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for idx in 0..archive.len() {
        let mut entry: zip::read::ZipFile<'_> = archive.by_index(idx).expect("zip entry by index");
        if !entry.is_file() {
            continue;
        }
        let full_path: String = entry.name().to_owned();
        if !full_path.starts_with(CWE78_ZIP_PREFIX) {
            continue;
        }
        let basename: String = full_path
            .rsplit('/')
            .next()
            .unwrap_or(&full_path)
            .to_owned();
        if !needed.contains(&basename) {
            continue;
        }
        assert!(
            !out.contains_key(&basename),
            "the Juliet corpus tree has more than one file named {basename} inside \
             {CWE78_ZIP_PREFIX}, and the grading harness needs it to be unique"
        );
        let mut bytes: Vec<u8> = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut bytes).expect("read zip entry");
        out.insert(basename, bytes);
    }
    for support_path in TESTCASESUPPORT_FILES {
        let mut entry: zip::read::ZipFile<'_> =
            archive
                .by_name(support_path)
                .unwrap_or_else(|e: zip::result::ZipError| {
                    panic!("{support_path} missing from juliet_1_3.zip: {e}")
                });
        let basename: String = support_path
            .rsplit('/')
            .next()
            .unwrap_or(support_path)
            .to_owned();
        let mut bytes: Vec<u8> = Vec::with_capacity(entry.size() as usize);
        entry
            .read_to_end(&mut bytes)
            .expect("read testcasesupport entry");
        out.insert(basename, bytes);
    }
    out
}

fn outer_entry(spans: &[FunctionSpan], suffix: &str) -> String {
    let matches: Vec<&FunctionSpan> = spans
        .iter()
        .filter(|s: &&FunctionSpan| s.name.ends_with(suffix))
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one function ending in {suffix}, found {}: {:?}",
        matches.len(),
        matches
            .iter()
            .map(|s: &&FunctionSpan| s.name.clone())
            .collect::<Vec<String>>()
    );
    matches[0].name.clone()
}

fn build_group(
    testcase: &ManifestTestcase,
    flaw_file: &str,
    flaw: &ManifestFlaw,
    files: &BTreeMap<String, Vec<u8>>,
) -> TestcaseGroup {
    assert!(
        flaw.name.contains("CWE-078"),
        "manifest.xml names the flaw in {flaw_file} as `{}`, which is not a CWE-078 flaw; the \
         selection predicate and the manifest disagree about what this group is",
        flaw.name
    );
    let flaw_text: String = {
        let source: &[u8] = files
            .get(flaw_file)
            .unwrap_or_else(|| panic!("corpus content missing for flaw file {flaw_file}"));
        String::from_utf8_lossy(source).into_owned()
    };
    let variant: String = variant_number(&flaw_text)
        .unwrap_or_else(|| panic!("{flaw_file} has no `Flow Variant: NN` header line"));
    let category: Category = classify_variant(&variant)
        .unwrap_or_else(|| panic!("flow variant {variant} in {flaw_file} has no category mapping"));

    let flaw_file_spans: Vec<FunctionSpan> = top_level_functions(&flaw_text);
    let enclosing: &FunctionSpan = flaw_file_spans
        .iter()
        .find(|span: &&FunctionSpan| {
            span.start_line <= flaw.line as usize && flaw.line as usize <= span.end_line
        })
        .unwrap_or_else(|| {
            panic!(
                "manifest.xml flaw line {} in {flaw_file} falls inside no function span this parser found",
                flaw.line
            )
        });
    let enclosing_lower: String = enclosing.name.to_ascii_lowercase();
    assert!(
        enclosing_lower.contains("bad"),
        "the function enclosing the manifest flaw line in {flaw_file} is `{}`, which does not read \
         as a bad-labeled function; the bad/good chain derived from name substrings would not agree \
         with the manifest's own flaw line",
        enclosing.name
    );

    let member_paths: Vec<String> = testcase
        .files
        .iter()
        .map(|f: &ManifestFile| f.path.clone())
        .collect();
    let mut all_spans: Vec<FunctionSpan> = Vec::new();
    for path in &member_paths {
        if !(has_extension(path, "c") || has_extension(path, "h")) {
            continue;
        }
        let bytes: &[u8] = files
            .get(path)
            .unwrap_or_else(|| panic!("corpus content missing for member file {path}"));
        let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(bytes);
        all_spans.extend(top_level_functions(&text));
    }

    let bad_entry: String = outer_entry(&all_spans, "_bad");
    let good_entry: String = outer_entry(&all_spans, "_good");
    let mut bad_chain: BTreeSet<String> = BTreeSet::new();
    let mut good_chain: BTreeSet<String> = BTreeSet::new();
    for span in &all_spans {
        let lower: String = span.name.to_ascii_lowercase();
        if lower.contains("bad") {
            bad_chain.insert(span.name.clone());
        } else if lower.contains("good") {
            good_chain.insert(span.name.clone());
        }
    }

    TestcaseGroup {
        flaw_file: flaw_file.to_owned(),
        flaw_line: flaw.line,
        variant,
        category,
        member_paths,
        bad_entry,
        good_entry,
        bad_chain,
        good_chain,
    }
}

fn read_manifest_bytes(zip_bytes: &[u8]) -> Vec<u8> {
    use std::io::Read as _;
    let cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(zip_bytes);
    let mut archive: zip::ZipArchive<std::io::Cursor<&[u8]>> =
        zip::ZipArchive::new(cursor).expect("open juliet_1_3.zip for manifest");
    let mut entry: zip::read::ZipFile<'_> = archive
        .by_name(MANIFEST_PATH)
        .expect("C/manifest.xml present");
    let mut bytes: Vec<u8> = Vec::with_capacity(entry.size() as usize);
    entry.read_to_end(&mut bytes).expect("read manifest.xml");
    bytes
}

pub(crate) fn load_corpus_content(case: &str) -> Option<JulietCorpusContent> {
    let zip_bytes: Vec<u8> = ensure_corpus_zip(case)?;
    let manifest_bytes: Vec<u8> = read_manifest_bytes(&zip_bytes);
    let manifest_text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&manifest_bytes);
    let testcases: Vec<ManifestTestcase> = parse_manifest(&manifest_text);

    let mut relevant: Vec<(ManifestTestcase, String, ManifestFlaw)> = Vec::new();
    for testcase in testcases {
        let flaw_entry: Option<(String, ManifestFlaw)> =
            testcase.files.iter().find_map(|f: &ManifestFile| {
                if !is_selected_flaw_file(&f.path) || f.flaws.is_empty() {
                    return None;
                }
                assert_eq!(
                    f.flaws.len(),
                    1,
                    "{} carries {} manifest flaw entries; the selected char/system CWE-78 slice is \
                     expected to label exactly one flaw per file, and this changes what a labeled \
                     flow means for this group",
                    f.path,
                    f.flaws.len()
                );
                Some((f.path.clone(), f.flaws[0].clone()))
            });
        if let Some((flaw_file, flaw)) = flaw_entry {
            relevant.push((testcase, flaw_file, flaw));
        }
    }

    let mut needed_basenames: BTreeSet<String> = BTreeSet::new();
    for (testcase, _, _) in &relevant {
        for file in &testcase.files {
            needed_basenames.insert(file.path.clone());
        }
    }

    let mut content: BTreeMap<String, Vec<u8>> = read_zip_entries(&zip_bytes, &needed_basenames);

    let testcasesupport_dir: ScratchDir =
        ScratchDir::create("juliet-testcasesupport").expect("create testcasesupport scratch dir");
    for name in ["io.c", "std_testcase.h", "std_testcase_io.h"] {
        let bytes: &Vec<u8> = content
            .get(name)
            .unwrap_or_else(|| panic!("testcasesupport file {name} missing from corpus zip"));
        std::fs::write(testcasesupport_dir.path().join(name), bytes)
            .unwrap_or_else(|e: std::io::Error| panic!("write testcasesupport/{name}: {e}"));
    }

    let groups: Vec<TestcaseGroup> = relevant
        .iter()
        .map(
            |(testcase, flaw_file, flaw): &(ManifestTestcase, String, ManifestFlaw)| {
                build_group(testcase, flaw_file, flaw, &content)
            },
        )
        .collect();

    content.retain(|name: &String, _: &mut Vec<u8>| {
        !matches!(
            name.as_str(),
            "io.c" | "std_testcase.h" | "std_testcase_io.h"
        )
    });

    Some(JulietCorpusContent {
        files: content,
        testcasesupport_dir,
        groups,
    })
}

fn driver_source(good_entry: &str, bad_entry: &str) -> String {
    format!(
        "extern void {good_entry}(void);\nextern void {bad_entry}(void);\n\nint main(void)\n{{\n    {good_entry}();\n    {bad_entry}();\n    return 0;\n}}\n"
    )
}

fn host_executable_name(stem: &str) -> String {
    if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem.to_owned()
    }
}

pub(crate) enum CompileOutcome {
    Compiled {
        scratch: ScratchDir,
        exe_path: PathBuf,
    },
    TimedOut,
    Failed(String),
}

pub(crate) fn compile_group(
    compiler: &Path,
    opt_flag: &str,
    group: &TestcaseGroup,
    files: &BTreeMap<String, Vec<u8>>,
    testcasesupport_dir: &Path,
) -> CompileOutcome {
    let scratch: ScratchDir = match ScratchDir::create("juliet-taint-case") {
        Ok(dir) => dir,
        Err(err) => return CompileOutcome::Failed(format!("scratch dir: {err}")),
    };
    let dir: &Path = scratch.path();
    let mut source_paths: Vec<PathBuf> = Vec::new();
    for name in &group.member_paths {
        let bytes: &Vec<u8> = files
            .get(name)
            .unwrap_or_else(|| panic!("corpus content missing for {name} ({})", group.flaw_file));
        let path: PathBuf = dir.join(name);
        if let Err(err) = std::fs::write(&path, bytes) {
            return CompileOutcome::Failed(format!("write {name}: {err}"));
        }
        if has_extension(name, "c") {
            source_paths.push(path);
        }
    }
    let driver_path: PathBuf = dir.join("driver.c");
    if let Err(err) = std::fs::write(
        &driver_path,
        driver_source(&group.good_entry, &group.bad_entry),
    ) {
        return CompileOutcome::Failed(format!("write driver.c: {err}"));
    }
    source_paths.push(driver_path);
    source_paths.push(testcasesupport_dir.join("io.c"));

    let exe_path: PathBuf = dir.join(host_executable_name("case"));
    let mut args: Vec<OsString> = vec![
        OsString::from(opt_flag),
        OsString::from("-fno-builtin"),
        OsString::from("-I"),
        testcasesupport_dir.as_os_str().to_owned(),
        OsString::from("-I"),
        dir.as_os_str().to_owned(),
        OsString::from("-o"),
        exe_path.as_os_str().to_owned(),
    ];
    for path in &source_paths {
        args.push(path.as_os_str().to_owned());
    }
    if cfg!(windows) {
        args.push(OsString::from("-lws2_32"));
    }

    let captured: Option<CapturedOutput> =
        match run_captured(compiler, &args, COMPILE_TIMEOUT, CAPTURE_CAP_BYTES) {
            Ok(captured) => captured,
            Err(err) => return CompileOutcome::Failed(format!("spawn compiler: {err}")),
        };
    let Some(captured): Option<CapturedOutput> = captured else {
        return CompileOutcome::TimedOut;
    };
    if captured.exit_code != Some(0) {
        return CompileOutcome::Failed(format!(
            "compiler exited {:?}: {}",
            captured.exit_code,
            String::from_utf8_lossy(&captured.stderr)
        ));
    }
    CompileOutcome::Compiled { scratch, exe_path }
}

pub(crate) fn lift_native_module(bytes: &[u8]) -> NirModule {
    let payload: DisasmPayload = disrobe_pass_native::build_disasm_payload(bytes).unwrap_or_else(
        |err: disrobe_pass_native::error::Error| panic!("lift native binary: {err}"),
    );
    disrobe_query::disasm_to_nir(&payload)
}

pub(crate) enum AnalyzeOutcome {
    Analyzed {
        module: NirModule,
        report: TaintReport,
    },
    TimedOut,
}

type AnalyzedPair = (NirModule, TaintReport);

pub(crate) fn analyze_with_timeout(bytes: Vec<u8>, config: TaintConfig) -> AnalyzeOutcome {
    let (tx, rx): (
        std::sync::mpsc::Sender<AnalyzedPair>,
        std::sync::mpsc::Receiver<AnalyzedPair>,
    ) = std::sync::mpsc::channel();
    let handle: std::thread::JoinHandle<()> = std::thread::spawn(move || {
        let module: NirModule = lift_native_module(&bytes);
        let report: TaintReport = disrobe_taint::analyze(&module, &config);
        let _: Result<(), _> = tx.send((module, report));
    });
    match rx.recv_timeout(ANALYZE_TIMEOUT) {
        Ok((module, report)) => {
            let _: std::thread::Result<()> = handle.join();
            AnalyzeOutcome::Analyzed { module, report }
        }
        Err(_) => AnalyzeOutcome::TimedOut,
    }
}

fn symbol_matches(name: &str, candidates: &[&str]) -> bool {
    let normalized: String = name.trim_start_matches('_').to_ascii_lowercase();
    candidates
        .iter()
        .any(|candidate: &&str| candidate.to_ascii_lowercase() == normalized)
}

pub(crate) fn any_call_resolves_to(module: &NirModule, candidates: &[&str]) -> bool {
    let symbol_by_addr: BTreeMap<u64, &str> = module
        .symbols
        .iter()
        .map(|s: &NirSymbol| (s.address, s.name.as_str()))
        .collect();
    for function in &module.functions {
        for instr in &function.instructions {
            if let NirOp::ExternCall { symbol } = &instr.op
                && symbol_matches(symbol, candidates)
            {
                return true;
            }
            if let Some(target) = instr.op.direct_target()
                && let Some(name) = symbol_by_addr.get(&target)
                && symbol_matches(name, candidates)
            {
                return true;
            }
        }
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CaseVerdict {
    TruePositive,
    FalseNegative,
    TrueNegative,
    FalsePositive,
    Timeout,
    Unanalysable,
}

pub(crate) struct GroupGrade {
    pub(crate) category: Category,
    pub(crate) bad_verdict: CaseVerdict,
    pub(crate) good_verdict: CaseVerdict,
    pub(crate) reported_flows: usize,
    pub(crate) source_resolved: bool,
    pub(crate) sink_resolved: bool,
}

pub(crate) fn grade_findings(
    findings: &[TaintFinding],
    bad_chain: &BTreeSet<String>,
    good_chain: &BTreeSet<String>,
    case_label: &str,
) -> (CaseVerdict, CaseVerdict) {
    let mut bad_matches: usize = 0;
    let mut unexpected: usize = 0;
    for finding in findings {
        if bad_chain.contains(&finding.function) {
            bad_matches += 1;
        } else {
            unexpected += 1;
            if !good_chain.contains(&finding.function) {
                eprintln!(
                    "juliet corpus {case_label}: finding attributed to `{}`, which matches neither \
                     the bad chain nor the good chain the corpus itself names",
                    finding.function
                );
            }
        }
    }
    let bad_verdict: CaseVerdict = if bad_matches > 0 {
        CaseVerdict::TruePositive
    } else {
        CaseVerdict::FalseNegative
    };
    let good_verdict: CaseVerdict = if unexpected > 0 {
        CaseVerdict::FalsePositive
    } else {
        CaseVerdict::TrueNegative
    };
    (bad_verdict, good_verdict)
}

fn case_label(group: &TestcaseGroup) -> String {
    format!(
        "{} (variant {}, flaw line {})",
        group.flaw_file, group.variant, group.flaw_line
    )
}

pub(crate) fn grade_group(
    compiler: &Path,
    opt_flag: &str,
    group: &TestcaseGroup,
    files: &BTreeMap<String, Vec<u8>>,
    testcasesupport_dir: &Path,
    config: &TaintConfig,
) -> GroupGrade {
    assert!(
        group.bad_chain.is_disjoint(&group.good_chain),
        "{}: bad_chain and good_chain share a function name, which the corpus's own naming \
         convention never does",
        case_label(group)
    );
    match compile_group(compiler, opt_flag, group, files, testcasesupport_dir) {
        CompileOutcome::TimedOut => {
            eprintln!("juliet corpus {}: compile timed out", case_label(group));
            GroupGrade {
                category: group.category,
                bad_verdict: CaseVerdict::Timeout,
                good_verdict: CaseVerdict::Timeout,
                reported_flows: 0,
                source_resolved: false,
                sink_resolved: false,
            }
        }
        CompileOutcome::Failed(reason) => {
            eprintln!(
                "juliet corpus {}: compile failed: {reason}",
                case_label(group)
            );
            GroupGrade {
                category: group.category,
                bad_verdict: CaseVerdict::Unanalysable,
                good_verdict: CaseVerdict::Unanalysable,
                reported_flows: 0,
                source_resolved: false,
                sink_resolved: false,
            }
        }
        CompileOutcome::Compiled {
            exe_path,
            scratch: _scratch_guard,
        } => {
            let exe_bytes: Vec<u8> = match std::fs::read(&exe_path) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return GroupGrade {
                        category: group.category,
                        bad_verdict: CaseVerdict::Unanalysable,
                        good_verdict: CaseVerdict::Unanalysable,
                        reported_flows: 0,
                        source_resolved: false,
                        sink_resolved: false,
                    };
                }
            };
            match analyze_with_timeout(exe_bytes, config.clone()) {
                AnalyzeOutcome::TimedOut => {
                    eprintln!("juliet corpus {}: analyze timed out", case_label(group));
                    GroupGrade {
                        category: group.category,
                        bad_verdict: CaseVerdict::Timeout,
                        good_verdict: CaseVerdict::Timeout,
                        reported_flows: 0,
                        source_resolved: false,
                        sink_resolved: false,
                    }
                }
                AnalyzeOutcome::Analyzed { module, report } => {
                    let (bad_verdict, good_verdict): (CaseVerdict, CaseVerdict) = grade_findings(
                        report.findings(),
                        &group.bad_chain,
                        &group.good_chain,
                        &case_label(group),
                    );
                    GroupGrade {
                        category: group.category,
                        bad_verdict,
                        good_verdict,
                        reported_flows: report.findings().len(),
                        source_resolved: any_call_resolves_to(&module, DEFAULT_SOURCES),
                        sink_resolved: any_call_resolves_to(&module, DEFAULT_SINKS),
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ratio {
    Defined(u64, u64),
    Undefined,
}

impl std::fmt::Display for Ratio {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Defined(num, den) => {
                let pct: f64 = 100.0 * (*num as f64) / (*den as f64);
                write!(f, "{num}/{den} ({pct:.1}%)")
            }
            Self::Undefined => write!(f, "undefined"),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct CategoryTally {
    pub(crate) labeled_flows: usize,
    pub(crate) reported_flows: usize,
    pub(crate) true_positives: usize,
    pub(crate) false_positives: usize,
    pub(crate) false_negatives: usize,
    pub(crate) true_negatives: usize,
    pub(crate) timeouts: usize,
    pub(crate) unanalysable: usize,
    pub(crate) source_resolved_count: usize,
    pub(crate) sink_resolved_count: usize,
    pub(crate) groups: usize,
}

impl CategoryTally {
    pub(crate) const fn precision(&self) -> Ratio {
        let denom: usize = self.true_positives + self.false_positives;
        if denom == 0 {
            Ratio::Undefined
        } else {
            Ratio::Defined(self.true_positives as u64, denom as u64)
        }
    }

    pub(crate) const fn recall(&self) -> Ratio {
        let denom: usize = self.true_positives + self.false_negatives;
        if denom == 0 {
            Ratio::Undefined
        } else {
            Ratio::Defined(self.true_positives as u64, denom as u64)
        }
    }

    fn absorb(&mut self, grade: &GroupGrade) {
        self.groups += 1;
        self.labeled_flows += 1;
        self.reported_flows += grade.reported_flows;
        if grade.source_resolved {
            self.source_resolved_count += 1;
        }
        if grade.sink_resolved {
            self.sink_resolved_count += 1;
        }
        for verdict in [grade.bad_verdict, grade.good_verdict] {
            match verdict {
                CaseVerdict::TruePositive => self.true_positives += 1,
                CaseVerdict::FalseNegative => self.false_negatives += 1,
                CaseVerdict::TrueNegative => self.true_negatives += 1,
                CaseVerdict::FalsePositive => self.false_positives += 1,
                CaseVerdict::Timeout => self.timeouts += 1,
                CaseVerdict::Unanalysable => self.unanalysable += 1,
            }
        }
    }
}

pub(crate) struct GradedReport {
    pub(crate) opt_flag: &'static str,
    pub(crate) tallies: BTreeMap<Category, CategoryTally>,
}

impl GradedReport {
    pub(crate) fn render(&self) -> String {
        let mut out: String = format!(
            "juliet cwe-78 char/system corpus grade at {}\n{:<48} {:>6} {:>6} {:>4} {:>4} {:>4} {:>4} {:>4} {:>7} {:>7} {:>7}\n",
            self.opt_flag,
            "category",
            "groups",
            "labld",
            "tp",
            "fp",
            "fn",
            "tn",
            "to",
            "unanl",
            "prec",
            "recall",
        );
        for category in Category::all() {
            use std::fmt::Write as _;
            let tally: CategoryTally = self.tallies.get(&category).copied().unwrap_or_default();
            let _: std::fmt::Result = writeln!(
                out,
                "{:<48} {:>6} {:>6} {:>4} {:>4} {:>4} {:>4} {:>4} {:>7} {:>7} {:>7}",
                category.label(),
                tally.groups,
                tally.labeled_flows,
                tally.true_positives,
                tally.false_positives,
                tally.false_negatives,
                tally.true_negatives,
                tally.timeouts,
                tally.unanalysable,
                tally.precision(),
                tally.recall(),
            );
        }
        out
    }
}

pub(crate) fn grade_corpus(
    content: &JulietCorpusContent,
    opt_flag: &'static str,
    config: &TaintConfig,
) -> GradedReport {
    let compiler: &Path =
        host_c_compiler().expect("host c compiler must be resolved before grading");
    let pool: rayon::ThreadPool = rayon::ThreadPoolBuilder::new()
        .num_threads(CASE_WORKERS)
        .build()
        .expect("build bounded rayon pool");
    let grades: Vec<GroupGrade> = pool.install(|| {
        use rayon::prelude::*;
        content
            .groups
            .par_iter()
            .map(|group: &TestcaseGroup| {
                grade_group(
                    compiler,
                    opt_flag,
                    group,
                    &content.files,
                    content.testcasesupport_dir.path(),
                    config,
                )
            })
            .collect()
    });
    let mut tallies: BTreeMap<Category, CategoryTally> = BTreeMap::new();
    for grade in &grades {
        tallies.entry(grade.category).or_default().absorb(grade);
    }
    GradedReport { opt_flag, tallies }
}

pub(crate) fn require_host_compiler(case: &str) -> &'static Path {
    host_c_compiler().unwrap_or_else(|| {
        panic!(
            "{case}: no host c compiler is callable: tried {}",
            C_COMPILER_CANDIDATES.join(", ")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_predicate_accepts_only_char_system_dot_c_cwe78_files() {
        assert!(is_selected_flaw_file(
            "CWE78_OS_Command_Injection__char_console_system_01.c"
        ));
        assert!(!is_selected_flaw_file(
            "CWE78_OS_Command_Injection__char_console_system_33.cpp"
        ));
        assert!(!is_selected_flaw_file(
            "CWE78_OS_Command_Injection__wchar_t_console_system_01.c"
        ));
        assert!(!is_selected_flaw_file(
            "CWE78_OS_Command_Injection__char_console_popen_01.c"
        ));
        assert!(!is_selected_flaw_file(
            "CWE789_Uncontrolled_Mem_Alloc__malloc_char_rand_32.c"
        ));
    }

    #[test]
    fn variant_number_reads_the_corpus_own_header_line() {
        let source: &str = "/*\n * Flow Variant: 67 Data flow: data passed in a struct\n */\n";
        assert_eq!(variant_number(source).as_deref(), Some("67"));
        assert_eq!(variant_number("no header here").as_deref(), None);
    }

    #[test]
    fn every_declared_variant_maps_to_exactly_one_category() {
        let all_variants: Vec<&str> = vec![
            "01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12", "13", "14",
            "15", "16", "17", "18", "21", "22", "31", "32", "34", "41", "42", "44", "45", "51",
            "52", "53", "54", "61", "63", "64", "65", "66", "67", "68",
        ];
        for variant in all_variants {
            assert!(
                classify_variant(variant).is_some(),
                "variant {variant} has no category mapping"
            );
        }
        assert!(classify_variant("99").is_none());
    }

    #[test]
    fn top_level_functions_finds_a_definition_but_not_a_prototype() {
        let source: &str = concat!(
            "void CWE78_x__char_console_system_51b_badSink(char * data);\n",
            "\n",
            "void CWE78_x__char_console_system_51_bad()\n",
            "{\n",
            "    int x = 1;\n",
            "    if (x) {\n",
            "        x += 1;\n",
            "    }\n",
            "}\n",
            "\n",
            "static void goodG2B()\n",
            "{\n",
            "    return;\n",
            "}\n",
        );
        let spans: Vec<FunctionSpan> = top_level_functions(source);
        let names: Vec<&str> = spans
            .iter()
            .map(|s: &FunctionSpan| s.name.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["CWE78_x__char_console_system_51_bad", "goodG2B"]
        );
    }

    #[test]
    fn side_classification_never_matches_both_bad_and_good() {
        for name in [
            "taint_entry_bad",
            "goodG2BSink",
            "main",
            "staticReturnsTrue",
        ] {
            let lower: String = name.to_ascii_lowercase();
            assert!(!(lower.contains("bad") && lower.contains("good")), "{name}");
        }
    }

    #[test]
    fn manifest_parses_a_combined_and_a_split_testcase() {
        let xml: &str = concat!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
            "<container>\n",
            "  <testcase>\n",
            "    <file path=\"CWE78_x_01.c\">\n",
            "      <flaw line=\"67\" name=\"CWE-078: OS Command Injection\"/>\n",
            "    </file>\n",
            "  </testcase>\n",
            "  <testcase>\n",
            "    <file path=\"CWE78_x_51a.c\"/>\n",
            "    <file path=\"CWE78_x_51b.c\">\n",
            "      <flaw line=\"41\" name=\"CWE-078: OS Command Injection\"/>\n",
            "    </file>\n",
            "  </testcase>\n",
            "</container>\n",
        );
        let testcases: Vec<ManifestTestcase> = parse_manifest(xml);
        assert_eq!(testcases.len(), 2);
        assert_eq!(testcases[0].files.len(), 1);
        assert_eq!(testcases[0].files[0].flaws[0].line, 67);
        assert_eq!(testcases[1].files.len(), 2);
        assert!(testcases[1].files[0].flaws.is_empty());
        assert_eq!(testcases[1].files[1].flaws[0].line, 41);
    }

    #[test]
    fn manifest_accepts_more_than_one_flaw_on_a_single_file() {
        let xml: &str = concat!(
            "<container>\n",
            "  <testcase>\n",
            "    <file path=\"CWE121_x_01.c\">\n",
            "      <flaw line=\"35\" name=\"CWE-135: Incorrect Calculation\"/>\n",
            "      <flaw line=\"37\" name=\"CWE-121: Stack-based Buffer Overflow\"/>\n",
            "    </file>\n",
            "  </testcase>\n",
            "</container>\n",
        );
        let testcases: Vec<ManifestTestcase> = parse_manifest(xml);
        assert_eq!(testcases[0].files[0].flaws.len(), 2);
        assert_eq!(testcases[0].files[0].flaws[0].line, 35);
        assert_eq!(testcases[0].files[0].flaws[1].line, 37);
    }

    #[test]
    #[should_panic(expected = "unrecognized manifest.xml line")]
    fn manifest_rejects_an_unrecognized_line_rather_than_defaulting() {
        let xml: &str =
            "<container>\n  <testcase>\n    <weird attr=\"1\"/>\n  </testcase>\n</container>\n";
        let _: Vec<ManifestTestcase> = parse_manifest(xml);
    }

    #[test]
    fn precision_and_recall_are_undefined_at_zero_denominator() {
        let tally: CategoryTally = CategoryTally::default();
        assert_eq!(tally.precision(), Ratio::Undefined);
        assert_eq!(tally.recall(), Ratio::Undefined);
    }

    #[test]
    fn precision_and_recall_compute_over_true_and_false_calls() {
        let tally: CategoryTally = CategoryTally {
            true_positives: 3,
            false_positives: 1,
            false_negatives: 2,
            ..CategoryTally::default()
        };
        assert_eq!(tally.precision(), Ratio::Defined(3, 4));
        assert_eq!(tally.recall(), Ratio::Defined(3, 5));
    }

    #[test]
    fn grade_findings_matches_a_finding_by_function_name_against_the_bad_chain() {
        let bad_chain: BTreeSet<String> = BTreeSet::from(["taint_entry_bad".to_owned()]);
        let good_chain: BTreeSet<String> = BTreeSet::from(["taint_entry_good".to_owned()]);
        let matching: Vec<TaintFinding> = vec![sample_finding("taint_entry_bad")];
        let (bad, good): (CaseVerdict, CaseVerdict) =
            grade_findings(&matching, &bad_chain, &good_chain, "unit-test-case");
        assert_eq!(bad, CaseVerdict::TruePositive);
        assert_eq!(good, CaseVerdict::TrueNegative);

        let unmatched: Vec<TaintFinding> = vec![sample_finding("taint_entry_good")];
        let (bad, good): (CaseVerdict, CaseVerdict) =
            grade_findings(&unmatched, &bad_chain, &good_chain, "unit-test-case");
        assert_eq!(bad, CaseVerdict::FalseNegative);
        assert_eq!(good, CaseVerdict::FalsePositive);

        let none: Vec<TaintFinding> = Vec::new();
        let (bad, good): (CaseVerdict, CaseVerdict) =
            grade_findings(&none, &bad_chain, &good_chain, "unit-test-case");
        assert_eq!(bad, CaseVerdict::FalseNegative);
        assert_eq!(good, CaseVerdict::TrueNegative);
    }

    fn sample_finding(function: &str) -> TaintFinding {
        TaintFinding {
            function: function.to_owned(),
            function_address: 0,
            source_site: 0,
            source_symbol: "fgets".to_owned(),
            sink_site: 0,
            sink_symbol: "system".to_owned(),
            path: Vec::new(),
        }
    }
}
