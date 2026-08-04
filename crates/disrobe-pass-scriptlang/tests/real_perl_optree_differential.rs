#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_scriptlang::lang::perl::{PerlOpTree, PerlSub, read_concise};
use disrobe_pass_scriptlang::lang::perl_decompile::{DecompileWalker, PerlSource};

const PERL_TIMEOUT: Duration = Duration::from_mins(1);
const PERL_CAPTURE_LIMIT: usize = 4 * 1024 * 1024;
const CONCISE_OK_SUFFIX: &str = "syntax OK";
const MAIN_PROGRAM_HEADER: &str = "main program:";
const SEQ_FIELD_WIDTH: usize = 3;
const INDENT_PER_DEPTH: usize = 3;
const MAX_SEQ_TOKEN_LEN: usize = 2;
const MAX_REPORTED_DIFF_LINES: usize = 60;

#[derive(Debug, Clone, Copy)]
struct Fixture {
    name: &'static str,
    source: &'static str,
    committed_concise: &'static [u8],
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        name: "hello",
        source: include_str!("fixtures/hello.pl"),
        committed_concise: include_bytes!("fixtures/hello.concise.txt"),
    },
    Fixture {
        name: "rich",
        source: include_str!("fixtures/rich.pl"),
        committed_concise: include_bytes!("fixtures/rich.concise.txt"),
    },
    Fixture {
        name: "ops",
        source: include_str!("fixtures/ops.pl"),
        committed_concise: include_bytes!("fixtures/ops.concise.txt"),
    },
    Fixture {
        name: "ctl",
        source: include_str!("fixtures/ctl.pl"),
        committed_concise: include_bytes!("fixtures/ctl.concise.txt"),
    },
    Fixture {
        name: "nested_call",
        source: include_str!("fixtures/nested_call.pl"),
        committed_concise: include_bytes!("fixtures/nested_call.concise.txt"),
    },
    Fixture {
        name: "nested_bare_call",
        source: include_str!("fixtures/nested_bare_call.pl"),
        committed_concise: include_bytes!("fixtures/nested_bare_call.concise.txt"),
    },
    Fixture {
        name: "nested_call_arguments",
        source: include_str!("fixtures/nested_call_arguments.pl"),
        committed_concise: include_bytes!("fixtures/nested_call_arguments.concise.txt"),
    },
    Fixture {
        name: "sample1",
        source: include_str!("fixtures/sample1.pl"),
        committed_concise: include_bytes!("fixtures/sample1.concise.txt"),
    },
];

#[derive(Debug, Clone, Copy)]
struct Expectation {
    fixture: &'static str,
    subs: &'static [&'static str],
    committed_subs: &'static [&'static str],
    min_reference_lines: usize,
}

const EXPECTED: &[Expectation] = &[
    Expectation {
        fixture: "hello",
        subs: &["main::greet", "main::add", "main program"],
        committed_subs: &["main::greet", "main::add", "main program"],
        min_reference_lines: 64,
    },
    Expectation {
        fixture: "rich",
        subs: &[
            "main::classify",
            "main::total",
            "main::loop_sum",
            "main program",
        ],
        committed_subs: &[
            "main::classify",
            "main::total",
            "main::loop_sum",
            "main program",
        ],
        min_reference_lines: 130,
    },
    Expectation {
        fixture: "ops",
        subs: &["main::cmps", "main::assigns", "main program"],
        committed_subs: &["main::cmps", "main::assigns", "main program"],
        min_reference_lines: 90,
    },
    Expectation {
        fixture: "ctl",
        subs: &["main::bare_if", "main::use_unless", "main program"],
        committed_subs: &["main::bare_if", "main::use_unless"],
        min_reference_lines: 66,
    },
    Expectation {
        fixture: "nested_call",
        subs: &["main::inner", "main::outer", "main program"],
        committed_subs: &["main::inner", "main::outer", "main program"],
        min_reference_lines: 50,
    },
    Expectation {
        fixture: "nested_bare_call",
        subs: &["main::inner", "main::outer", "main program"],
        committed_subs: &["main::inner", "main::outer", "main program"],
        min_reference_lines: 44,
    },
    Expectation {
        fixture: "nested_call_arguments",
        subs: &["main::inner", "main::outer", "main program"],
        committed_subs: &["main::inner", "main::outer", "main program"],
        min_reference_lines: 54,
    },
    Expectation {
        fixture: "sample1",
        subs: &["main::greet", "main::add", "main::area", "main program"],
        committed_subs: &["main::greet", "main::add", "main::area", "main program"],
        min_reference_lines: 83,
    },
];

const TOTAL_REFERENCE_LINE_FLOOR: usize = 581;
const COMMITTED_SUB_DUMP_FLOOR: usize = 25;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Identical,
    Divergent,
    MissingFromRecovered,
    AbsentFromReference,
}

impl Verdict {
    const fn label(self) -> &'static str {
        match self {
            Self::Identical => "identical",
            Self::Divergent => "divergent",
            Self::MissingFromRecovered => "missing-from-recovered",
            Self::AbsentFromReference => "absent-from-reference",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedSub {
    name: String,
    lines: Vec<String>,
}

#[derive(Debug)]
struct ConciseDump {
    header: String,
    tree_text: String,
}

#[derive(Debug)]
struct SubOutcome {
    sub: String,
    verdict: Verdict,
    reference_lines: usize,
    recovered_lines: usize,
    matched_lines: usize,
    diff: String,
}

#[derive(Debug)]
struct FixtureOutcome {
    fixture: String,
    compiles: bool,
    compile_error: String,
    subs: Vec<SubOutcome>,
    recovered_source: String,
}

impl FixtureOutcome {
    fn identical_subs(&self) -> usize {
        self.subs
            .iter()
            .filter(|s: &&SubOutcome| s.verdict == Verdict::Identical)
            .count()
    }

    fn reference_lines(&self) -> usize {
        self.subs
            .iter()
            .map(|s: &SubOutcome| s.reference_lines)
            .sum()
    }

    fn matched_lines(&self) -> usize {
        self.subs.iter().map(|s: &SubOutcome| s.matched_lines).sum()
    }

    fn agreement(&self) -> f64 {
        let total: usize = self.reference_lines();
        if total == 0 {
            return 0.0;
        }
        self.matched_lines() as f64 / total as f64
    }
}

fn perl_binary() -> Option<PathBuf> {
    let candidate: PathBuf = PathBuf::from("perl");
    let args: [OsString; 3] = [
        OsString::from("-MB::Concise"),
        OsString::from("-e"),
        OsString::from("exit 0"),
    ];
    match run_captured(&candidate, &args, PERL_TIMEOUT, PERL_CAPTURE_LIMIT) {
        Ok(Some(out)) if out.exit_code == Some(0) => Some(candidate),
        _ => None,
    }
}

fn require_perl(test_name: &str) -> PathBuf {
    let Some(perl): Option<PathBuf> = perl_binary() else {
        panic!("{test_name} requires a callable Perl with B::Concise on PATH");
    };
    perl
}

fn run_concise(perl: &Path, script: &Path, subs: &[String]) -> Result<ConciseDump, String> {
    let mut spec: String = String::from("-MO=Concise,-main");
    for name in subs {
        spec.push(',');
        spec.push_str(name);
    }
    let args: [OsString; 2] = [OsString::from(spec), script.as_os_str().to_owned()];
    let captured: CapturedOutput = run_captured(perl, &args, PERL_TIMEOUT, PERL_CAPTURE_LIMIT)
        .map_err(|error: std::io::Error| format!("spawning perl failed: {error}"))?
        .ok_or_else(|| String::from("perl -MO=Concise exceeded its timeout"))?;
    let stderr: String = String::from_utf8_lossy(&captured.stderr).into_owned();
    if captured.exit_code != Some(0) {
        return Err(format!(
            "perl -MO=Concise exited {:?}:\n{stderr}",
            captured.exit_code
        ));
    }
    let header: String = stderr
        .lines()
        .find(|line: &&str| line.trim_end().ends_with(CONCISE_OK_SUFFIX))
        .map(str::to_owned)
        .ok_or_else(|| format!("perl never reported `syntax OK`:\n{stderr}"))?;
    Ok(ConciseDump {
        header,
        tree_text: String::from_utf8_lossy(&captured.stdout).into_owned(),
    })
}

fn compile_check(perl: &Path, script: &Path) -> Result<(), String> {
    let args: [OsString; 2] = [OsString::from("-c"), script.as_os_str().to_owned()];
    let captured: CapturedOutput = run_captured(perl, &args, PERL_TIMEOUT, PERL_CAPTURE_LIMIT)
        .map_err(|error: std::io::Error| format!("spawning perl failed: {error}"))?
        .ok_or_else(|| String::from("perl -c exceeded its timeout"))?;
    if captured.exit_code == Some(0) {
        return Ok(());
    }
    Err(String::from_utf8_lossy(&captured.stderr).into_owned())
}

fn sub_names(tree: &PerlOpTree) -> Vec<String> {
    tree.subs
        .iter()
        .filter(|s: &&PerlSub| !s.is_main_program)
        .map(|s: &PerlSub| {
            s.name
                .strip_prefix("main::")
                .map_or_else(|| s.name.clone(), str::to_owned)
        })
        .collect()
}

fn declared_sub_names(source: &str) -> Vec<String> {
    source
        .lines()
        .filter_map(|line: &str| {
            let rest: &str = line.trim_start().strip_prefix("sub ")?;
            let name: &str = rest
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .next()?;
            if name.is_empty() {
                None
            } else {
                Some(name.to_owned())
            }
        })
        .collect()
}

fn is_sub_header(line: &str) -> Option<String> {
    if line == MAIN_PROGRAM_HEADER {
        return Some(String::from("main program"));
    }
    let stripped: &str = line.strip_suffix(':')?;
    if stripped.is_empty() || stripped.contains(' ') || stripped.contains('<') {
        return None;
    }
    if stripped.contains("::") {
        return Some(stripped.to_owned());
    }
    None
}

fn normalize_dump(tree_text: &str) -> Vec<NormalizedSub> {
    let mut subs: Vec<NormalizedSub> = Vec::new();
    let mut current: Option<NormalizedSub> = None;
    for raw in tree_text.lines() {
        let line: &str = raw.trim_end();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = is_sub_header(line) {
            if let Some(done) = current.take() {
                subs.push(done);
            }
            current = Some(NormalizedSub {
                name,
                lines: Vec::new(),
            });
            continue;
        }
        if !looks_like_op_line(line) {
            continue;
        }
        let Some(target): Option<&mut NormalizedSub> = current.as_mut() else {
            continue;
        };
        if let Some(normalized) = normalize_op_line(line) {
            target.lines.push(normalized);
        }
    }
    if let Some(done) = current.take() {
        subs.push(done);
    }
    subs
}

fn looks_like_op_line(line: &str) -> bool {
    let Some(open): Option<usize> = line.find('<') else {
        return false;
    };
    let head: &str = line[..open].trim_end();
    !head.is_empty() && !head.contains(' ')
}

fn normalize_op_line(line: &str) -> Option<String> {
    let seq_end: usize = line.find(' ')?;
    let seq: &str = &line[..seq_end];
    assert!(
        !seq.is_empty() && seq.len() <= MAX_SEQ_TOKEN_LEN,
        "the depth model assumes a sequence field of at most {MAX_SEQ_TOKEN_LEN} characters; saw {seq:?} in line {line:?}"
    );
    let open: usize = line.find('<')?;
    assert!(
        open >= SEQ_FIELD_WIDTH && (open - SEQ_FIELD_WIDTH).is_multiple_of(INDENT_PER_DEPTH),
        "B::Concise indents {INDENT_PER_DEPTH} spaces per level past a {SEQ_FIELD_WIDTH}-wide sequence field; line {line:?} breaks that model"
    );
    let depth: usize = (open - SEQ_FIELD_WIDTH) / INDENT_PER_DEPTH;
    let class_end: usize = line[open..].find('>')? + open;
    let class: &str = &line[open..=class_end];
    let rest: &str = line[class_end + 1..].trim();
    let (body, target): (&str, &str) = rest
        .rsplit_once(" ->")
        .map_or((rest, ""), |(left, right): (&str, &str)| (left, right));
    let boundary: usize = token_boundary(body);
    let token: String = normalize_token(&body[..boundary]);
    let flags: String = normalize_seq_arrows(body[boundary..].trim());
    let executed: char = if seq == "-" { '-' } else { '#' };
    let next: &str = match target {
        "" => "",
        "(end)" => "(end)",
        "-" => "-",
        _ => "#",
    };
    Some(format!(
        "{depth:>3} {executed} {class} {token} {flags} ->{next}"
    ))
}

fn token_boundary(body: &str) -> usize {
    let mut depth: i32 = 0i32;
    let mut quoted: bool = false;
    for (idx, ch) in body.char_indices() {
        match ch {
            '"' => quoted = !quoted,
            '[' | '(' if !quoted => depth += 1,
            ']' | ')' if !quoted => depth -= 1,
            ' ' if !quoted && depth <= 0 => return idx,
            _ => {}
        }
    }
    body.len()
}

fn normalize_token(token: &str) -> String {
    if let Some(head) = token.strip_suffix(')')
        && let Some(idx) = head.find('(')
        && is_cop(&head[..idx])
    {
        return format!("{}(COP)", &head[..idx]);
    }
    normalize_seq_arrows(&normalize_trailing_bracket(token))
}

fn is_cop(name: &str) -> bool {
    matches!(
        name.trim_start_matches("ex-"),
        "nextstate" | "dbstate" | "setstate"
    )
}

fn normalize_trailing_bracket(token: &str) -> String {
    let Some(head): Option<&str> = token.strip_suffix(']') else {
        return token.to_owned();
    };
    let Some(open): Option<usize> = head.rfind('[') else {
        return token.to_owned();
    };
    let Some(inner): Option<String> = normalize_pad_group(&head[open + 1..]) else {
        return token.to_owned();
    };
    format!("{}[{inner}]", &head[..open])
}

fn normalize_pad_group(inner: &str) -> Option<String> {
    if inner.is_empty() || inner.contains('"') {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    for entry in inner.split(';') {
        parts.push(normalize_pad_entry(entry.trim())?);
    }
    Some(parts.join("; "))
}

fn normalize_pad_entry(entry: &str) -> Option<String> {
    if let Some(rest) = entry.strip_prefix('t')
        && !rest.is_empty()
        && rest.bytes().all(|b: u8| b.is_ascii_digit())
    {
        return Some(String::from("t"));
    }
    let first: char = entry.chars().next()?;
    if !matches!(first, '$' | '@' | '%') {
        return None;
    }
    match entry.split_once(':') {
        None => Some(entry.to_owned()),
        Some((name, range)) if is_pad_scope_range(range) => Some(name.to_owned()),
        Some(_) => None,
    }
}

fn is_pad_scope_range(range: &str) -> bool {
    !range.is_empty()
        && range
            .split(',')
            .all(|part: &str| !part.is_empty() && part.bytes().all(|b: u8| b.is_ascii_digit()))
}

fn normalize_seq_arrows(text: &str) -> String {
    let bytes: &[u8] = text.as_bytes();
    let mut out: String = String::with_capacity(text.len());
    let mut idx: usize = 0usize;
    let mut quoted: bool = false;
    while idx < bytes.len() {
        let ch: u8 = bytes[idx];
        if ch == b'"' {
            quoted = !quoted;
            out.push('"');
            idx += 1;
            continue;
        }
        if !quoted && ch == b'-' && bytes.get(idx + 1) == Some(&b'>') {
            let mut end: usize = idx + 2;
            while end < bytes.len() && bytes[end].is_ascii_alphanumeric() {
                end += 1;
            }
            if end > idx + 2 {
                out.push_str("->#");
                idx = end;
                continue;
            }
        }
        out.push(char::from(ch));
        idx += 1;
    }
    out
}

fn lcs_matrix(left: &[String], right: &[String]) -> Vec<Vec<usize>> {
    let mut table: Vec<Vec<usize>> = vec![vec![0usize; right.len() + 1]; left.len() + 1];
    for i in (0..left.len()).rev() {
        for j in (0..right.len()).rev() {
            table[i][j] = if left[i] == right[j] {
                table[i + 1][j + 1] + 1
            } else {
                table[i + 1][j].max(table[i][j + 1])
            };
        }
    }
    table
}

fn diff_lines(left: &[String], right: &[String]) -> (usize, String) {
    let table: Vec<Vec<usize>> = lcs_matrix(left, right);
    let matched: usize = table[0][0];
    let mut report: String = String::new();
    let mut emitted: usize = 0usize;
    let mut i: usize = 0usize;
    let mut j: usize = 0usize;
    while i < left.len() || j < right.len() {
        if emitted >= MAX_REPORTED_DIFF_LINES {
            let _: Result<(), std::fmt::Error> = writeln!(report, "        ... diff truncated");
            break;
        }
        if i < left.len() && j < right.len() && left[i] == right[j] {
            i += 1;
            j += 1;
            continue;
        }
        if j < right.len() && (i == left.len() || table[i][j + 1] >= table[i + 1][j]) {
            let _: Result<(), std::fmt::Error> =
                writeln!(report, "        +recovered {}", right[j]);
            j += 1;
        } else {
            let _: Result<(), std::fmt::Error> = writeln!(report, "        -reference {}", left[i]);
            i += 1;
        }
        emitted += 1;
    }
    (matched, report)
}

fn compare_subs(reference: &[NormalizedSub], recovered: &[NormalizedSub]) -> Vec<SubOutcome> {
    let mut outcomes: Vec<SubOutcome> = Vec::new();
    for sub in reference {
        let found: Option<&NormalizedSub> = recovered
            .iter()
            .find(|s: &&NormalizedSub| s.name == sub.name);
        let Some(other): Option<&NormalizedSub> = found else {
            outcomes.push(SubOutcome {
                sub: sub.name.clone(),
                verdict: Verdict::MissingFromRecovered,
                reference_lines: sub.lines.len(),
                recovered_lines: 0,
                matched_lines: 0,
                diff: String::new(),
            });
            continue;
        };
        let (matched, diff): (usize, String) = diff_lines(&sub.lines, &other.lines);
        let verdict: Verdict = if sub.lines == other.lines {
            Verdict::Identical
        } else {
            Verdict::Divergent
        };
        outcomes.push(SubOutcome {
            sub: sub.name.clone(),
            verdict,
            reference_lines: sub.lines.len(),
            recovered_lines: other.lines.len(),
            matched_lines: matched,
            diff,
        });
    }
    for sub in recovered {
        if reference.iter().any(|s: &NormalizedSub| s.name == sub.name) {
            continue;
        }
        outcomes.push(SubOutcome {
            sub: sub.name.clone(),
            verdict: Verdict::AbsentFromReference,
            reference_lines: 0,
            recovered_lines: sub.lines.len(),
            matched_lines: 0,
            diff: String::new(),
        });
    }
    outcomes
}

fn measure(perl: &Path, scratch: &Path, fixture: Fixture) -> FixtureOutcome {
    let original_path: PathBuf = scratch.join(format!("{}_original.pl", fixture.name));
    std::fs::write(&original_path, fixture.source).expect("write original fixture to scratch");

    let declared: Vec<String> = declared_sub_names(fixture.source);
    let reference: ConciseDump =
        run_concise(perl, &original_path, &declared).expect("perl must dump the original op tree");
    let reference_text: String = format!("{}\n{}", reference.header, reference.tree_text);
    let tree: PerlOpTree =
        read_concise(reference_text.as_bytes()).expect("parse the original op tree");
    assert_eq!(
        sub_names(&tree),
        declared,
        "the sub list parsed out of the reference dump must match the sub list requested from perl"
    );

    let recovered: PerlSource = DecompileWalker::new(&tree).decompile();
    let recovered_path: PathBuf = scratch.join(format!("{}_recovered.pl", fixture.name));
    std::fs::write(&recovered_path, &recovered.rendered).expect("write recovered source");

    if let Err(error) = compile_check(perl, &recovered_path) {
        return FixtureOutcome {
            fixture: fixture.name.to_owned(),
            compiles: false,
            compile_error: error,
            subs: Vec::new(),
            recovered_source: recovered.rendered,
        };
    }

    let candidate: ConciseDump = run_concise(perl, &recovered_path, &declared)
        .expect("perl must dump the recovered op tree");
    let subs: Vec<SubOutcome> = compare_subs(
        &normalize_dump(&reference.tree_text),
        &normalize_dump(&candidate.tree_text),
    );
    FixtureOutcome {
        fixture: fixture.name.to_owned(),
        compiles: true,
        compile_error: String::new(),
        subs,
        recovered_source: recovered.rendered,
    }
}

fn measure_all(perl: &Path) -> Vec<FixtureOutcome> {
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-perl-optree").expect("create scratch directory");
    let outcomes: Vec<FixtureOutcome> = FIXTURES
        .iter()
        .map(|fixture: &Fixture| measure(perl, scratch.path(), *fixture))
        .collect();
    scratch.close().expect("remove scratch directory");
    outcomes
}

fn report(outcomes: &[FixtureOutcome]) {
    for outcome in outcomes {
        if !outcome.compiles {
            eprintln!(
                "[perl-optree] {} DOES NOT COMPILE under perl -c",
                outcome.fixture
            );
            for line in outcome.compile_error.lines() {
                eprintln!("    {line}");
            }
            for line in outcome.recovered_source.lines() {
                eprintln!("    | {line}");
            }
            continue;
        }
        eprintln!(
            "[perl-optree] {}: subs {}/{} identical, op lines {}/{} = {:.4}",
            outcome.fixture,
            outcome.identical_subs(),
            outcome.subs.len(),
            outcome.matched_lines(),
            outcome.reference_lines(),
            outcome.agreement()
        );
        for sub in &outcome.subs {
            if sub.verdict == Verdict::Identical {
                continue;
            }
            eprintln!(
                "    [{}] {} reference={} recovered={} matched={}",
                sub.verdict.label(),
                sub.sub,
                sub.reference_lines,
                sub.recovered_lines,
                sub.matched_lines
            );
            eprint!("{}", sub.diff);
            for line in outcome.recovered_source.lines() {
                eprintln!("    | {line}");
            }
        }
    }
}

#[test]
fn recovered_perl_recompiles_to_the_original_op_tree() {
    let perl: PathBuf = require_perl("recovered_perl_recompiles_to_the_original_op_tree");
    let outcomes: Vec<FixtureOutcome> = measure_all(&perl);
    report(&outcomes);

    assert_eq!(
        outcomes.len(),
        EXPECTED.len(),
        "every fixture must be measured"
    );
    let mut total_reference: usize = 0usize;
    for (outcome, expected) in outcomes.iter().zip(EXPECTED) {
        assert_eq!(outcome.fixture, expected.fixture);
        assert!(
            outcome.compiles,
            "{}: the recovered source must compile under `perl -c`; perl said:\n{}",
            outcome.fixture, outcome.compile_error
        );
        let observed: Vec<&str> = outcome
            .subs
            .iter()
            .map(|s: &SubOutcome| s.sub.as_str())
            .collect();
        assert_eq!(
            observed, expected.subs,
            "{}: the compared sub set drifted",
            outcome.fixture
        );
        assert!(
            outcome.reference_lines() >= expected.min_reference_lines,
            "{}: the reference op tree shrank to {} lines, below the measured floor of {}; a comparison over fewer lines than were really emitted is not a comparison",
            outcome.fixture,
            outcome.reference_lines(),
            expected.min_reference_lines
        );
        for sub in &outcome.subs {
            assert!(
                sub.reference_lines > 0,
                "{}: sub {} contributed no op lines, so its verdict is vacuous",
                outcome.fixture,
                sub.sub
            );
            assert_eq!(
                sub.verdict,
                Verdict::Identical,
                "{}: sub {} does not recompile to the original op tree ({} of {} reference lines matched)\n{}",
                outcome.fixture,
                sub.sub,
                sub.matched_lines,
                sub.reference_lines,
                sub.diff
            );
        }
        assert_eq!(
            outcome.matched_lines(),
            outcome.reference_lines(),
            "{}: op-line agreement must stay at 1.0",
            outcome.fixture
        );
        total_reference += outcome.reference_lines();
    }
    assert!(
        total_reference >= TOTAL_REFERENCE_LINE_FLOOR,
        "the differential covered {total_reference} op lines, below the measured floor of {TOTAL_REFERENCE_LINE_FLOOR}"
    );
}

#[test]
fn committed_concise_fixtures_still_match_the_installed_perl() {
    let perl: PathBuf = require_perl("committed_concise_fixtures_still_match_the_installed_perl");
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-perl-fixture").expect("create scratch directory");
    let mut checked: usize = 0usize;
    assert_eq!(
        FIXTURES.len(),
        EXPECTED.len(),
        "every fixture must declare its expected live and committed subroutine sets"
    );
    for (fixture, expected) in FIXTURES.iter().zip(EXPECTED) {
        assert_eq!(fixture.name, expected.fixture);
        let path: PathBuf = scratch.path().join(format!("{}.pl", fixture.name));
        std::fs::write(&path, fixture.source).expect("write fixture source");
        let declared: Vec<String> = declared_sub_names(fixture.source);
        let live: ConciseDump =
            run_concise(&perl, &path, &declared).expect("perl must dump the fixture op tree");
        let live_subs: Vec<NormalizedSub> = normalize_dump(&live.tree_text);
        let committed_text: String =
            String::from_utf8_lossy(fixture.committed_concise).into_owned();
        let committed_subs: Vec<NormalizedSub> = normalize_dump(&committed_text);
        let committed_names: Vec<&str> = committed_subs
            .iter()
            .map(|sub: &NormalizedSub| sub.name.as_str())
            .collect();
        assert_eq!(
            committed_names, expected.committed_subs,
            "{}: committed subroutine set drifted",
            fixture.name
        );
        assert!(
            !committed_subs.is_empty(),
            "{}: the committed dump parsed to nothing",
            fixture.name
        );
        for sub in &committed_subs {
            let live_sub: &NormalizedSub = live_subs
                .iter()
                .find(|s: &&NormalizedSub| s.name == sub.name)
                .unwrap_or_else(|| {
                    panic!(
                        "{}: installed perl no longer emits {}",
                        fixture.name, sub.name
                    )
                });
            assert!(!sub.lines.is_empty());
            let (_, diff): (usize, String) = diff_lines(&sub.lines, &live_sub.lines);
            assert_eq!(
                sub.lines, live_sub.lines,
                "{}: committed fixture for {} is stale against the installed perl\n{diff}",
                fixture.name, sub.name
            );
            checked += 1;
        }
    }
    scratch.close().expect("remove scratch directory");
    eprintln!("[perl-optree] {checked} committed sub dumps re-derived from the installed perl");
    assert!(
        checked >= COMMITTED_SUB_DUMP_FLOOR,
        "checked {checked} committed sub dumps, below the measured floor of {COMMITTED_SUB_DUMP_FLOOR}"
    );
}

#[test]
fn the_normalized_comparison_rejects_real_op_tree_changes() {
    let perl: PathBuf = require_perl("the_normalized_comparison_rejects_real_op_tree_changes");
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-perl-mutate").expect("create scratch directory");
    let mut checked: usize = 0usize;
    for fixture in FIXTURES {
        let path: PathBuf = scratch.path().join(format!("{}.pl", fixture.name));
        std::fs::write(&path, fixture.source).expect("write fixture source");
        let dump: ConciseDump = run_concise(&perl, &path, &declared_sub_names(fixture.source))
            .expect("perl must dump the fixture op tree");
        let base: Vec<NormalizedSub> = normalize_dump(&dump.tree_text);
        assert!(!base.is_empty());

        for (label, mutated) in significant_mutations(&dump.tree_text) {
            assert_ne!(
                mutated, dump.tree_text,
                "{}: mutation `{label}` did not change the dump, so it proves nothing",
                fixture.name
            );
            assert_ne!(
                normalize_dump(&mutated),
                base,
                "{}: mutation `{label}` survived normalization, so the comparison would not catch it",
                fixture.name
            );
            checked += 1;
        }
        for (label, rewritten) in incidental_rewrites(&dump.tree_text) {
            assert_ne!(
                rewritten, dump.tree_text,
                "{}: rewrite `{label}` did not change the dump, so it proves nothing",
                fixture.name
            );
            assert_eq!(
                normalize_dump(&rewritten),
                base,
                "{}: rewrite `{label}` touches only compilation-incidental detail and must normalize away",
                fixture.name
            );
            checked += 1;
        }
    }
    scratch.close().expect("remove scratch directory");
    eprintln!("[perl-optree] {checked} mutation and rewrite probes exercised");
    assert!(checked >= 60);
}

fn significant_mutations(dump: &str) -> Vec<(&'static str, String)> {
    vec![
        ("drop an op line", drop_nth_op(dump, 2)),
        ("reorder two sibling ops", swap_first_sibling_pair(dump)),
        ("rename an op", rename_first_op(dump)),
        (
            "change a constant",
            dump.replacen("const[IV ", "const[IV 9", 1),
        ),
        ("drop a private flag", dump.replacen("/REFC", "", 1)),
        ("change an op class", dump.replacen("<1>", "<9>", 1)),
        ("reindent a subtree", reindent_nth_op(dump, 1)),
        ("elide an executed op", elide_first_sequence(dump)),
    ]
}

fn incidental_rewrites(dump: &str) -> Vec<(&'static str, String)> {
    let mut rewrites: Vec<(&'static str, String)> = vec![
        ("renumber a pad scope range", bump_pad_ranges(dump)),
        ("renumber a temporary slot", dump.replace("[t", "[t9")),
        (
            "renumber a statement line",
            dump.replace("nextstate(main ", "nextstate(main 900"),
        ),
        (
            "rename the source file",
            dump.replace(".pl:", ".elsewhere:"),
        ),
        ("renumber the next-op arrows", bump_next_arrows(dump)),
        ("renumber a sequence number", renumber_first_sequence(dump)),
    ];
    if dump.contains("other->") {
        rewrites.push((
            "renumber a branch target",
            dump.replace("other->", "other->9"),
        ));
    }
    rewrites
}

fn dump_lines(dump: &str) -> Vec<String> {
    dump.lines().map(str::to_owned).collect()
}

fn op_line_indices(lines: &[String]) -> Vec<usize> {
    lines
        .iter()
        .enumerate()
        .filter(|(_, line): &(usize, &String)| {
            let text: &str = line.trim_end();
            !text.trim().is_empty() && is_sub_header(text).is_none() && looks_like_op_line(text)
        })
        .map(|(idx, _): (usize, &String)| idx)
        .collect()
}

fn drop_nth_op(dump: &str, nth: usize) -> String {
    let lines: Vec<String> = dump_lines(dump);
    let indices: Vec<usize> = op_line_indices(&lines);
    let Some(target): Option<&usize> = indices.get(nth) else {
        return dump.to_owned();
    };
    lines
        .iter()
        .enumerate()
        .filter(|(idx, _): &(usize, &String)| idx != target)
        .map(|(_, line): (usize, &String)| line.clone())
        .collect::<Vec<String>>()
        .join("\n")
}

fn swap_first_sibling_pair(dump: &str) -> String {
    let mut lines: Vec<String> = dump_lines(dump);
    let indices: Vec<usize> = op_line_indices(&lines);
    for pair in indices.windows(2) {
        let (first, second): (usize, usize) = (pair[0], pair[1]);
        if lines[first].find('<') == lines[second].find('<')
            && normalize_op_line(&lines[first]) != normalize_op_line(&lines[second])
        {
            lines.swap(first, second);
            return lines.join("\n");
        }
    }
    dump.to_owned()
}

fn rename_first_op(dump: &str) -> String {
    let mut lines: Vec<String> = dump_lines(dump);
    let indices: Vec<usize> = op_line_indices(&lines);
    let Some(&target): Option<&usize> = indices.first() else {
        return dump.to_owned();
    };
    let line: &str = &lines[target];
    let Some(class_end): Option<usize> = line.find('>') else {
        return dump.to_owned();
    };
    let head: &str = &line[..=class_end];
    let tail: &str = &line[class_end + 1..];
    let name_end: usize = tail
        .char_indices()
        .find(|(_, ch): &(usize, char)| !ch.is_ascii_alphanumeric() && *ch != '_' && *ch != ' ')
        .map_or(tail.len(), |(idx, _): (usize, char)| idx);
    let renamed: String = format!("{head} zzzop{}", &tail[name_end..]);
    lines[target] = renamed;
    lines.join("\n")
}

fn reindent_nth_op(dump: &str, nth: usize) -> String {
    let mut lines: Vec<String> = dump_lines(dump);
    let indices: Vec<usize> = op_line_indices(&lines);
    let Some(&target): Option<&usize> = indices.get(nth) else {
        return dump.to_owned();
    };
    let line: &str = &lines[target];
    let Some(open): Option<usize> = line.find('<') else {
        return dump.to_owned();
    };
    lines[target] = format!("{}   {}", &line[..open], &line[open..]);
    lines.join("\n")
}

fn elide_first_sequence(dump: &str) -> String {
    rewrite_first_sequence(dump, |seq: &str| {
        "-".to_owned() + &" ".repeat(seq.len() - 1)
    })
}

fn renumber_first_sequence(dump: &str) -> String {
    rewrite_first_sequence(dump, |seq: &str| "z".repeat(seq.len()))
}

fn rewrite_first_sequence(dump: &str, rewrite: impl Fn(&str) -> String) -> String {
    let mut lines: Vec<String> = dump_lines(dump);
    let indices: Vec<usize> = op_line_indices(&lines);
    for index in indices {
        let line: &str = &lines[index];
        let Some(seq_end): Option<usize> = line.find(' ') else {
            continue;
        };
        let seq: &str = &line[..seq_end];
        if seq == "-" {
            continue;
        }
        lines[index] = format!("{}{}", rewrite(seq), &line[seq_end..]);
        return lines.join("\n");
    }
    dump.to_owned()
}

fn bump_pad_ranges(dump: &str) -> String {
    dump.lines()
        .map(rewrite_pad_ranges_in_line)
        .collect::<Vec<String>>()
        .join("\n")
}

fn rewrite_pad_ranges_in_line(line: &str) -> String {
    let Some(open): Option<usize> = line.find('[') else {
        return line.to_owned();
    };
    let Some(close): Option<usize> = line[open..].find(']').map(|idx: usize| idx + open) else {
        return line.to_owned();
    };
    let inner: &str = &line[open + 1..close];
    if inner.contains('"') {
        return line.to_owned();
    }
    let rewritten: String = inner
        .split(';')
        .map(|entry: &str| {
            let entry: &str = entry.trim();
            match entry.split_once(':') {
                Some((name, range))
                    if name.starts_with(['$', '@', '%']) && is_pad_scope_range(range) =>
                {
                    format!("{name}:1000,2000")
                }
                _ => entry.to_owned(),
            }
        })
        .collect::<Vec<String>>()
        .join("; ");
    format!("{}[{rewritten}]{}", &line[..open], &line[close + 1..])
}

fn bump_next_arrows(dump: &str) -> String {
    dump.lines()
        .map(|line: &str| match line.rsplit_once("->") {
            Some((head, tail))
                if !tail.is_empty() && tail.bytes().all(|b: u8| b.is_ascii_alphanumeric()) =>
            {
                format!("{head}->9{tail}")
            }
            _ => line.to_owned(),
        })
        .collect::<Vec<String>>()
        .join("\n")
}
