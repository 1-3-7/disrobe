use disrobe_pass_shell::{
    Error, ExtractedModule, ModuleStompReport, StompReport, StompVerdict, analyze_stomp,
    extract_from_bytes,
};

use crate::vba_source_grade::{
    Grade, grade, grade_lines, join_continuations, read_authored, read_corpus,
    strip_trailing_comment,
};
use crate::vba_stomp_harness::{
    module_text_offset, repack_ooxml_with_vba_project, stomp_with_junk_source, vba_project_of,
};

pub(crate) struct Subject {
    pub(crate) container: &'static str,
    pub(crate) module: &'static str,
    pub(crate) authored: &'static str,
}

pub(crate) const SUBJECTS: [Subject; 3] = [
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

pub(crate) fn is_comment_only(line: &str) -> bool {
    let trimmed: &str = line.trim_start();
    if trimmed.starts_with('\'') {
        return true;
    }
    trimmed
        .split_whitespace()
        .next()
        .is_some_and(|head: &str| head.eq_ignore_ascii_case("Rem"))
}

pub(crate) fn comment_body(line: &str) -> String {
    let trimmed: &str = line.trim();
    let body: &str = trimmed
        .strip_prefix('\'')
        .unwrap_or_else(|| trimmed.get(3..).unwrap_or_default());
    body.split_whitespace().collect::<Vec<&str>>().join(" ")
}

pub(crate) fn whole_line_comments(text: &str) -> Vec<String> {
    join_continuations(text)
        .iter()
        .filter(|line: &&String| is_comment_only(line))
        .map(|line: &String| comment_body(line))
        .filter(|body: &String| !body.is_empty())
        .collect()
}

pub(crate) fn trailing_comments(text: &str) -> Vec<String> {
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

pub(crate) fn stomped_recovery(subject: &Subject) -> String {
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
            .find(|m: &&ExtractedModule| m.name.eq_ignore_ascii_case(subject.module))
            .is_some_and(|m: &ExtractedModule| {
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
pub(crate) struct Ceiling {
    pub(crate) graded_modules: usize,
    pub(crate) code_matched: usize,
    pub(crate) code_total: usize,
    pub(crate) comment_matched: usize,
    pub(crate) comment_total: usize,
    pub(crate) trailing_matched: usize,
    pub(crate) trailing_total: usize,
}

impl Ceiling {
    pub(crate) const fn matched(&self) -> usize {
        self.code_matched + self.comment_matched + self.trailing_matched
    }

    pub(crate) const fn total(&self) -> usize {
        self.code_total + self.comment_total + self.trailing_total
    }

    pub(crate) fn pct(&self) -> f64 {
        100.0 * self.matched() as f64 / self.total() as f64
    }
}

pub(crate) const PUBLISHED_PCT_TOLERANCE: f64 = 0.005;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BarDefect {
    Numerator,
    Denominator,
    Percentage,
}

pub(crate) fn describe_bar_defect(defect: BarDefect, measured: &Ceiling) -> String {
    match defect {
        BarDefect::Numerator => format!(
            "the published numerator disagrees with the {} authored lines this run recovered \
             from p-code alone",
            measured.matched()
        ),
        BarDefect::Denominator => format!(
            "the published denominator disagrees with the {} content lines the authored corpus \
             carries ({} code, {} whole-line comments, {} trailing comments), so a shrinking \
             fixture could otherwise raise the published rate",
            measured.total(),
            measured.code_total,
            measured.comment_total,
            measured.trailing_total
        ),
        BarDefect::Percentage => format!(
            "the published percentage disagrees with the {:.2} this run measures",
            measured.pct()
        ),
    }
}

pub(crate) fn check_published_bar(
    num: usize,
    den: usize,
    value: f64,
    measured: &Ceiling,
) -> Result<(), BarDefect> {
    if num != measured.matched() {
        return Err(BarDefect::Numerator);
    }
    if den != measured.total() {
        return Err(BarDefect::Denominator);
    }
    if (value - measured.pct()).abs() >= PUBLISHED_PCT_TOLERANCE {
        return Err(BarDefect::Percentage);
    }
    Ok(())
}

pub(crate) fn measure() -> Ceiling {
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
