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

#[path = "support/vba_pcode_only_measure.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod vba_pcode_only_measure;

use vba_pcode_only_measure::{
    BarDefect, Ceiling, SUBJECTS, check_published_bar, describe_bar_defect, measure,
    stomped_recovery, trailing_comments, whole_line_comments,
};
use vba_source_grade::{Grade, code_lines, grade, read_authored};

const GRADED_MODULES: usize = 3;
const CODE_LINES_MATCHED: usize = 684;
const CODE_LINES_TOTAL: usize = 686;
const COMMENT_LINES_MATCHED: usize = 50;
const COMMENT_LINES_TOTAL: usize = 50;
const TRAILING_COMMENTS_MATCHED: usize = 2;
const TRAILING_COMMENTS_TOTAL: usize = 2;
const PCODE_ONLY_CEILING_MATCHED: usize = 736;
const PCODE_ONLY_CEILING_TOTAL: usize = 738;

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

#[test]
fn the_bar_check_refuses_a_shrunken_denominator_and_an_inflated_numerator() {
    let c: Ceiling = measure();
    let num: usize = c.matched();
    let den: usize = c.total();
    let pct: f64 = c.pct();
    assert_eq!(
        check_published_bar(num, den, pct, &c),
        Ok(()),
        "the live measurement must satisfy its own comparison, otherwise the refutations below \
         prove nothing"
    );
    for (bad_num, bad_den, expected, label) in [
        (num + 1, den, BarDefect::Numerator, "inflated numerator"),
        (num - 1, den, BarDefect::Numerator, "deflated numerator"),
        (num, den - 1, BarDefect::Denominator, "shrunken denominator"),
        (num, den + 1, BarDefect::Denominator, "padded denominator"),
    ] {
        let verdict: Result<(), BarDefect> = check_published_bar(
            bad_num,
            bad_den,
            100.0 * bad_num as f64 / bad_den as f64,
            &c,
        );
        assert_eq!(
            verdict,
            Err(expected),
            "{label}: a bar carrying {bad_num} / {bad_den} must be refused by the {expected:?} \
             check against a measured {num} / {den}; a refusal from a later check would mean the \
             named guard is doing nothing"
        );
    }
    assert_eq!(
        check_published_bar(num, den, pct + 1.0, &c),
        Err(BarDefect::Percentage),
        "a percentage that disagrees with its own numerator and denominator must be refused by \
         the percentage check"
    );
    assert!(
        !describe_bar_defect(BarDefect::Denominator, &c).is_empty(),
        "every defect must render a reason a reader can act on"
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
