#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

#[path = "support/vba_source_grade.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod vba_source_grade;

#[path = "support/vba_stomp_harness.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod vba_stomp_harness;

use disrobe_pass_shell::{
    Error, ModuleStompReport, StompReport, StompVerdict, analyze_stomp, extract_from_bytes,
};

use vba_source_grade::{
    Grade, code_lines, grade, grade_lines, join_continuations, read_authored, read_corpus,
    strip_trailing_comment,
};
use vba_stomp_harness::{
    module_text_offset, repack_ooxml_with_vba_project, stomp_with_junk_source, vba_project_of,
};

struct Subject {
    container: &'static str,
    module: &'static str,
    authored: &'static str,
}

const SUBJECTS: [Subject; 3] = [
    Subject {
        container: "vba/megafile.docm",
        module: "EdgeCases",
        authored: "vba/megafile/EdgeCases.bas",
    },
    Subject {
        container: "vba/megafile.docm",
        module: "GreetingTemplate",
        authored: "vba/megafile/GreetingTemplate.cls",
    },
    Subject {
        container: "vba/sourceprobe.xlsm",
        module: "SourceProbe",
        authored: "vba/sourceprobe/SourceProbe.bas",
    },
];

const GRADED_MODULES: usize = 3;
const CODE_LINES_MATCHED: usize = 684;
const CODE_LINES_TOTAL: usize = 686;
const COMMENT_LINES_MATCHED: usize = 50;
const COMMENT_LINES_TOTAL: usize = 50;
const TRAILING_COMMENTS_MATCHED: usize = 2;
const TRAILING_COMMENTS_TOTAL: usize = 2;
const PCODE_ONLY_CEILING_MATCHED: usize = 736;
const PCODE_ONLY_CEILING_TOTAL: usize = 738;

fn is_comment_only(line: &str) -> bool {
    let trimmed: &str = line.trim_start();
    if trimmed.starts_with('\'') {
        return true;
    }
    let mut words = trimmed.split_whitespace();
    words
        .next()
        .is_some_and(|head: &str| head.eq_ignore_ascii_case("Rem"))
}

fn comment_body(line: &str) -> String {
    let trimmed: &str = line.trim();
    let body: &str = trimmed
        .strip_prefix('\'')
        .unwrap_or_else(|| trimmed.get(3..).unwrap_or_default());
    body.split_whitespace().collect::<Vec<&str>>().join(" ")
}

fn whole_line_comments(text: &str) -> Vec<String> {
    join_continuations(text)
        .iter()
        .filter(|line: &&String| is_comment_only(line))
        .map(|line: &String| comment_body(line))
        .filter(|body: &String| !body.is_empty())
        .collect()
}

fn trailing_comments(text: &str) -> Vec<String> {
    join_continuations(text)
        .iter()
        .filter(|line: &&String| !is_comment_only(line))
        .filter_map(|line: &String| {
            let code: &str = strip_trailing_comment(line);
            if code.len() == line.len() || code.trim().is_empty() {
                return None;
            }
            let body: String = comment_body(&line[code.len()..]);
            (!body.is_empty()).then_some(body)
        })
        .collect()
}

fn stomped_recovery(subject: &Subject) -> String {
    let container: Vec<u8> = read_corpus(subject.container);
    let offset: usize = module_text_offset(&container, subject.module);
    let project: Vec<u8> = vba_project_of(&container);
    let stomped_project: Vec<u8> = stomp_with_junk_source(&project, subject.module, offset);
    let stomped: Vec<u8> = repack_ooxml_with_vba_project(&container, &stomped_project);
    assert!(
        extract_from_bytes(&stomped)
            .expect("extract the stomped container")
            .modules
            .iter()
            .find(|m: &&disrobe_pass_shell::ExtractedModule| {
                m.name.eq_ignore_ascii_case(subject.module)
            })
            .is_some_and(|m: &disrobe_pass_shell::ExtractedModule| {
                m.source_error.is_some() && m.recovered_source.is_empty()
            }),
        "{}: the stomp must leave the source stream worthless, otherwise the figure below is not \
         a p-code-only figure",
        subject.module
    );
    let report: StompReport = analyze_stomp(&stomped)
        .unwrap_or_else(|e: Error| panic!("{}: analyze_stomp refused: {e}", subject.module));
    let module: &ModuleStompReport = report
        .modules
        .iter()
        .find(|m: &&ModuleStompReport| m.module.eq_ignore_ascii_case(subject.module))
        .unwrap_or_else(|| panic!("{} missing from the stomp report", subject.module));
    assert_eq!(
        module.verdict,
        StompVerdict::Stomped,
        "{}: the subject must be classified as stomped before its recovery is counted",
        subject.module
    );
    module.recovered_source.clone()
}

#[derive(Default)]
struct Ceiling {
    graded_modules: usize,
    code_matched: usize,
    code_total: usize,
    comment_matched: usize,
    comment_total: usize,
    trailing_matched: usize,
    trailing_total: usize,
}

impl Ceiling {
    const fn matched(&self) -> usize {
        self.code_matched + self.comment_matched + self.trailing_matched
    }

    const fn total(&self) -> usize {
        self.code_total + self.comment_total + self.trailing_total
    }

    fn pct(&self) -> f64 {
        100.0 * self.matched() as f64 / self.total() as f64
    }
}

fn measure() -> Ceiling {
    let mut out: Ceiling = Ceiling::default();
    for subject in &SUBJECTS {
        let authored: String = read_authored(subject.authored);
        let recovered: String = stomped_recovery(subject);
        let code: Grade = grade(&recovered, &authored);
        let comments: Grade = grade_lines(
            &whole_line_comments(&authored),
            &whole_line_comments(&recovered),
        );
        let trailing: Grade = grade_lines(
            &trailing_comments(&authored),
            &trailing_comments(&recovered),
        );
        println!(
            "{}: code {}/{}, whole-line comments {}/{}, trailing comments {}/{}{}",
            subject.module,
            code.matched,
            code.total,
            comments.matched,
            comments.total,
            trailing.matched,
            trailing.total,
            code.first_mismatch.as_ref().map_or_else(String::new, |m| {
                format!(
                    "\n  first unmatched authored code line {}\n    authored:  {}\n    \
                     recovered: {}",
                    m.authored_ordinal, m.authored, m.recovered
                )
            })
        );
        out.graded_modules += 1;
        out.code_matched += code.matched;
        out.code_total += code.total;
        out.comment_matched += comments.matched;
        out.comment_total += comments.total;
        out.trailing_matched += trailing.matched;
        out.trailing_total += trailing.total;
    }
    out
}

#[test]
fn the_published_pcode_only_ceiling_is_measured_and_pinned() {
    let c: Ceiling = measure();
    println!(
        "p-code-only ceiling over {} stomped modules: {}/{} authored lines ({:.2}%), made of \
         code {}/{}, whole-line comments {}/{} and trailing comments {}/{}",
        c.graded_modules,
        c.matched(),
        c.total(),
        c.pct(),
        c.code_matched,
        c.code_total,
        c.comment_matched,
        c.comment_total,
        c.trailing_matched,
        c.trailing_total
    );
    assert_eq!(
        c.graded_modules, GRADED_MODULES,
        "the graded-module count is pinned by equality so the ceiling denominator cannot shrink"
    );
    assert_eq!(
        c.code_total, CODE_LINES_TOTAL,
        "the authored code-line denominator is pinned so a shrinking fixture cannot raise the rate"
    );
    assert_eq!(
        c.comment_total, COMMENT_LINES_TOTAL,
        "the authored whole-line-comment denominator is pinned"
    );
    assert_eq!(
        c.trailing_total, TRAILING_COMMENTS_TOTAL,
        "the authored trailing-comment denominator is pinned"
    );
    assert_eq!(
        c.total(),
        PCODE_ONLY_CEILING_TOTAL,
        "the published ceiling denominator is pinned"
    );
    assert!(
        c.code_matched >= CODE_LINES_MATCHED,
        "p-code-only code-line recovery fell to {}/{}, below the published floor of {}",
        c.code_matched,
        c.code_total,
        CODE_LINES_MATCHED
    );
    assert!(
        c.comment_matched >= COMMENT_LINES_MATCHED,
        "p-code-only whole-line-comment recovery fell to {}/{}, below the published floor of {}",
        c.comment_matched,
        c.comment_total,
        COMMENT_LINES_MATCHED
    );
    assert!(
        c.trailing_matched >= TRAILING_COMMENTS_MATCHED,
        "p-code-only trailing-comment recovery fell to {}/{}, below the published floor of {}",
        c.trailing_matched,
        c.trailing_total,
        TRAILING_COMMENTS_MATCHED
    );
    assert!(
        c.matched() >= PCODE_ONLY_CEILING_MATCHED,
        "the published p-code-only ceiling fell to {}/{} ({:.2}%), below the floor of {}",
        c.matched(),
        c.total(),
        c.pct(),
        PCODE_ONLY_CEILING_MATCHED
    );
}

const CLASS_HANDLERS: [&str; 2] = ["Class_Initialize", "Class_Terminate"];

#[test]
fn the_lines_the_ceiling_misses_are_named_and_the_reference_misses_them_too() {
    let recovered: String = stomped_recovery(&SUBJECTS[1]);
    let authored: String = read_authored(SUBJECTS[1].authored);
    let golden: String = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("golden")
            .join("megafile.pcodedmp.txt"),
    )
    .expect("read the pcodedmp golden");
    for handler in CLASS_HANDLERS {
        assert!(
            authored.contains(&format!("Private Sub {handler}()")),
            "{handler} must be authored as Private for this shortfall to be the one described"
        );
        assert!(
            recovered.contains(&format!("Sub {handler}()")),
            "{handler} must still be recovered as a procedure; got:\n{recovered}"
        );
        assert!(
            !recovered.contains(&format!("Private Sub {handler}()")),
            "{handler} must not gain a Private keyword the compiled record does not carry"
        );
    }
    assert_eq!(
        authored.matches("Private Sub ").count(),
        CLASS_HANDLERS.len(),
        "the authored class declares exactly the two Private procedures this shortfall names"
    );
    assert!(
        golden.contains("FuncDefn (Public Sub "),
        "the reference dump must render a scope keyword somewhere, otherwise it never renders \
         scope and the absence below would prove nothing"
    );
    assert_eq!(
        golden.matches("FuncDefn (Private ").count(),
        0,
        "pcodedmp 1.2.6 reads the same records and renders Private on no procedure in this \
         project, so the two missing keywords are what the VBA compiler stored for a class event \
         handler, not what disrobe dropped"
    );
    assert_eq!(
        golden.matches("FuncDefn (Sub ").count(),
        CLASS_HANDLERS.len(),
        "the reference dump must show exactly two procedures with no scope keyword, matching the \
         two the authored source declares Private"
    );
}

#[test]
fn the_ceiling_splits_the_three_line_kinds_it_counts() {
    let authored: &str =
        "' a whole-line comment\nRem another one\nx = 1 ' trailing note\n\ny = 2\n";
    assert_eq!(
        whole_line_comments(authored),
        vec!["a whole-line comment".to_owned(), "another one".to_owned()]
    );
    assert_eq!(
        trailing_comments(authored),
        vec!["trailing note".to_owned()]
    );
    assert_eq!(
        code_lines(authored),
        vec![
            "rem another one".to_owned(),
            "x = 1".to_owned(),
            "y = 2".to_owned()
        ],
        "the code-line projection keeps a Rem line, so the comment projection must not be added \
         to it blindly"
    );
    let perfect: Grade = grade("x = 1\ny = 2\n", authored);
    assert_eq!(
        (perfect.matched, perfect.total),
        (2, 3),
        "the code-line grader drops apostrophe comments, which is why the ceiling counts them \
         through their own projection"
    );
}

const CONSTRUCTS: [(&str, &str); 23] = [
    ("Sub declaration", "Public Sub "),
    ("Function declaration", "Public Function "),
    ("ByVal argument", "ByVal "),
    ("ByRef argument", "ByRef "),
    ("ParamArray argument", "ParamArray "),
    ("Dim with an explicit type", "Dim "),
    ("fixed-bound array", "Erase "),
    ("dynamic array", "ReDim "),
    ("For loop", "For "),
    ("For Each loop", "For Each "),
    ("pre-test Do While loop", "Do While "),
    ("pre-test Do Until loop", "Do Until "),
    ("Select Case", "Select Case "),
    ("On Error GoTo", "On Error GoTo "),
    ("On Error Resume Next", "On Error Resume Next"),
    ("GoTo and a label", "GoTo "),
    ("user-defined type", "Type "),
    ("enum", "Enum "),
    ("Property Get", "Property Get "),
    ("Property Let", "Property Let "),
    ("Property Set", "Property Set "),
    ("late-bound CreateObject", "CreateObject("),
    ("Const declaration", "Const "),
];

const UNCLAIMED_CONSTRUCTS: [(&str, &str); 9] = [
    (
        "Declare for an external call",
        "no committed document declares one",
    ),
    ("Optional argument", "no committed document declares one"),
    ("With block", "no committed document contains one"),
    (
        "post-test Do ... Loop While",
        "no committed document contains one",
    ),
    (
        "post-test Do ... Loop Until",
        "no committed document contains one",
    ),
    ("GoSub and Return", "no committed document contains one"),
    ("Static local", "no committed document declares one"),
    ("Friend procedure", "no committed document declares one"),
    ("Implements", "no committed document declares one"),
];

#[test]
fn every_claimed_language_construct_is_recovered_from_pcode_alone() {
    let mut authored_all: String = String::new();
    let mut recovered_all: String = String::new();
    for subject in &SUBJECTS {
        authored_all.push_str(&read_authored(subject.authored));
        authored_all.push('\n');
        recovered_all.push_str(&stomped_recovery(subject));
        recovered_all.push('\n');
    }
    let authored_lower: String = authored_all.to_ascii_lowercase();
    let recovered_lower: String = recovered_all.to_ascii_lowercase();
    for (name, needle) in CONSTRUCTS {
        let lowered: String = needle.to_ascii_lowercase();
        assert!(
            authored_lower.contains(&lowered),
            "{name}: the claim list names a construct the authored corpus does not contain, so \
             the check below would be vacuous"
        );
        assert!(
            recovered_lower.contains(&lowered),
            "{name}: present in the authored source but absent from what p-code alone recovered"
        );
    }
    for (name, reason) in UNCLAIMED_CONSTRUCTS {
        println!("unclaimed construct {name}: {reason}");
    }
    assert_eq!(
        CONSTRUCTS.len() + UNCLAIMED_CONSTRUCTS.len(),
        32,
        "the construct roster length is pinned so a construct cannot silently leave either list"
    );
}

#[test]
fn the_unclaimed_constructs_really_are_absent_from_the_corpus() {
    let mut authored_all: String = String::new();
    for subject in &SUBJECTS {
        authored_all.push_str(&read_authored(subject.authored));
        authored_all.push('\n');
    }
    let lowered: String = authored_all.to_ascii_lowercase();
    for needle in [
        "declare ",
        "optional ",
        "\nwith ",
        "loop while",
        "loop until",
        "gosub",
        "\nstatic ",
        "friend ",
        "implements ",
    ] {
        assert!(
            !lowered.contains(needle),
            "{needle:?} is listed as unclaimed but the authored corpus does contain it; either \
             grade it or correct the roster"
        );
    }
}
