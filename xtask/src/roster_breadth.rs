use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail, eyre};

use crate::doc_region::{self, Mode, Region, RegionSyntax};
use crate::fileio::read_text_bounded;

const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;

const CONTAINER_SOURCE: &str = "crates/disrobe-binfmt/src/container.rs";
const CONTAINER_EVIDENCE: &str = "crates/disrobe-cli/tests/golden/container_breadth.txt";
const CONTAINER_ARRAY: &str = "pub const ALL: [Self;";

const STATUS_EXTRACT: &str = "extract";

const MIN_DECLARED: usize = 50;
const MIN_EVIDENCE_ROWS: usize = 10;

const SYNTAX: RegionSyntax = RegionSyntax {
    open_prefix: "<!-- roster-breadth:",
    close: "<!-- /roster-breadth -->",
};

const CONTAINERS_DECLARED: &str = "containers-declared";
const CONTAINERS_EXERCISED: &str = "containers-exercised";

#[derive(Debug)]
struct Breadth {
    declared: usize,
    exercised: usize,
    reached: usize,
}

fn read_repo_text(root: &Path, relative: &str) -> Result<String> {
    let path: PathBuf = root.join(relative);
    read_text_bounded(&path, MAX_SOURCE_BYTES).wrap_err_with(|| format!("reading {relative}"))
}

fn declared_containers(source: &str) -> Result<usize> {
    let head: usize = source.find(CONTAINER_ARRAY).ok_or_else(|| {
        eyre!(
            "{CONTAINER_SOURCE} no longer declares `{CONTAINER_ARRAY}`, so the container roster \
             every page publishes is derived from nothing"
        )
    })?;
    let after: &str = source
        .get(head + CONTAINER_ARRAY.len()..)
        .unwrap_or_default();
    let digits: String = after
        .chars()
        .skip_while(|c: &char| c.is_whitespace())
        .take_while(char::is_ascii_digit)
        .collect();
    let declared: usize = digits.parse::<usize>().map_err(|_| {
        eyre!(
            "the `ContainerKind::ALL` declaration in {CONTAINER_SOURCE} no longer states a fixed \
             length this check can read, so the declared roster size is derived from nothing"
        )
    })?;
    if declared < MIN_DECLARED {
        bail!(
            "{CONTAINER_SOURCE} declares {declared} container format(s), fewer than the \
             {MIN_DECLARED} this check requires; the declaration shape moved and the published \
             breadth would be compared against a truncated roster"
        );
    }
    Ok(declared)
}

fn evidence_rows(root: &Path) -> Result<Vec<(String, String)>> {
    let text: String = read_repo_text(root, CONTAINER_EVIDENCE)?;
    let mut rows: Vec<(String, String)> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for line in text.lines() {
        let trimmed: &str = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts: std::str::Split<'_, char> = trimmed.split('\t');
        let (Some(kind), Some(status), Some(input)) = (parts.next(), parts.next(), parts.next())
        else {
            bail!(
                "{CONTAINER_EVIDENCE} row `{trimmed}` is not a format, a status and a committed \
                 input separated by tabs, so this check cannot tell what it claims and the \
                 exercised figure would rest on an unread file"
            );
        };
        if kind.is_empty() || status.is_empty() || input.is_empty() {
            bail!("{CONTAINER_EVIDENCE} row `{trimmed}` leaves a column empty");
        }
        if !seen.insert(kind.to_owned()) {
            bail!(
                "{CONTAINER_EVIDENCE} records `{kind}` twice, so one format would be counted twice \
                 in the published figure"
            );
        }
        rows.push((kind.to_owned(), status.to_owned()));
    }
    if rows.len() < MIN_EVIDENCE_ROWS {
        bail!(
            "{CONTAINER_EVIDENCE} holds {} row(s), fewer than the {MIN_EVIDENCE_ROWS} this check \
             requires; an evidence file that shrank to nothing would otherwise publish an \
             exercised figure of zero as though it were measured",
            rows.len()
        );
    }
    Ok(rows)
}

fn breadth(root: &Path) -> Result<Breadth> {
    let source: String = read_repo_text(root, CONTAINER_SOURCE)?;
    let declared: usize = declared_containers(&source)?;
    let rows: Vec<(String, String)> = evidence_rows(root)?;
    let exercised: usize = rows
        .iter()
        .filter(|(_, status): &&(String, String)| status == STATUS_EXTRACT)
        .count();
    if exercised == 0 {
        bail!(
            "{CONTAINER_EVIDENCE} credits no format with extracting member bytes from a committed \
             input, so the published breadth would rest on nothing"
        );
    }
    if exercised > declared {
        bail!(
            "{CONTAINER_EVIDENCE} credits {exercised} exercised format(s) against the {declared} \
             {CONTAINER_SOURCE} declares, so the evidence names a format the roster does not carry"
        );
    }
    Ok(Breadth {
        declared,
        exercised,
        reached: rows.len(),
    })
}

fn render(breadth: &Breadth, slug: &str) -> Result<String> {
    match slug {
        CONTAINERS_DECLARED => Ok(breadth.declared.to_string()),
        CONTAINERS_EXERCISED => Ok(breadth.exercised.to_string()),
        other => bail!(
            "`{other}` is not a roster breadth figure this check derives; the figures on record \
             are `{CONTAINERS_DECLARED}` and `{CONTAINERS_EXERCISED}`"
        ),
    }
}

pub(crate) fn run(root: &Path, mode: Mode) -> Result<()> {
    let breadth: Breadth = breadth(root)?;
    let files: Vec<PathBuf> = doc_region::manifest(root)?;

    match mode {
        Mode::Write => {
            let mut rewritten: usize = 0;
            for path in &files {
                let text: String = doc_region::read_doc(path)?;
                let updated: String =
                    doc_region::rewrite(SYNTAX, &text, &|slug: &str| render(&breadth, slug))
                        .wrap_err_with(|| {
                            format!("rewriting roster breadth in {}", path.display())
                        })?;
                if updated != text {
                    std::fs::write(path, &updated)
                        .wrap_err_with(|| format!("writing {}", path.display()))?;
                    rewritten += 1;
                }
            }
            println!(
                "xtask roster-breadth: {rewritten} file(s) rewritten from {} declared container \
                 formats, {} of which a committed input drives to member bytes",
                breadth.declared, breadth.exercised
            );
            Ok(())
        }
        Mode::Check => {
            let mut issues: Vec<String> = Vec::new();
            let mut seen: BTreeSet<String> = BTreeSet::new();
            for path in &files {
                let text: String = doc_region::read_doc(path)?;
                let label: String = doc_region::label(root, path);
                let regions: Vec<Region> = doc_region::parse(SYNTAX, &text)
                    .wrap_err_with(|| format!("parsing roster breadth regions in {label}"))?;
                for region in &regions {
                    seen.insert(region.slug.clone());
                    match render(&breadth, &region.slug) {
                        Ok(expected) if expected == region.content => {}
                        Ok(expected) => issues.push(format!(
                            "{label}:{}: `{}` publishes {} where the code and the committed \
                             evidence carry {expected}",
                            region.line, region.slug, region.content
                        )),
                        Err(error) => {
                            issues.push(format!("{label}:{}: {error}", region.line));
                        }
                    }
                }
            }
            for required in [CONTAINERS_DECLARED, CONTAINERS_EXERCISED] {
                if !seen.contains(required) {
                    issues.push(format!(
                        "no page publishes a `{required}` figure, so that half of the container \
                         breadth claim is stated by nothing a check can read"
                    ));
                }
            }
            if breadth.exercised == breadth.declared {
                issues.push(format!(
                    "the evidence credits every one of the {} declared container formats, which \
                     would make the exercised figure a second name for the roster length rather \
                     than a measurement; confirm {CONTAINER_EVIDENCE} was regenerated from a real \
                     run",
                    breadth.declared
                ));
            }

            if issues.is_empty() {
                println!(
                    "xtask roster-breadth: the container roster publishes {} declared formats and \
                     {} exercised, matching {CONTAINER_SOURCE} and the {} format(s) \
                     {CONTAINER_EVIDENCE} records a committed input reaching",
                    breadth.declared, breadth.exercised, breadth.reached
                );
                Ok(())
            } else {
                bail!(
                    "{} published roster breadth claim(s) disagree with the code and the committed \
                     evidence; run `cargo run -p xtask -- regen` to rewrite them:\n  {}",
                    issues.len(),
                    issues.join("\n  ")
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE_FIXTURE: &str =
        "impl ContainerKind {\n    pub const ALL: [Self; 100] = [\n        Self::Zip,\n    ];\n}\n";

    fn fixture() -> Breadth {
        Breadth {
            declared: 100,
            exercised: 33,
            reached: 35,
        }
    }

    #[test]
    fn the_declared_length_reads_from_the_array_header() -> Result<()> {
        assert_eq!(declared_containers(SOURCE_FIXTURE)?, 100);
        Ok(())
    }

    #[test]
    fn a_roster_shrunk_below_the_floor_is_refused() {
        let shrunk: &str = "pub const ALL: [Self; 3] = [];\n";
        assert!(declared_containers(shrunk).is_err());
    }

    #[test]
    fn a_declaration_this_check_cannot_read_is_refused() {
        assert!(declared_containers("pub const ALL: &[Self] = &[];\n").is_err());
    }

    #[test]
    fn the_two_figures_render_from_the_measurement() -> Result<()> {
        let breadth: Breadth = fixture();
        assert_eq!(render(&breadth, CONTAINERS_DECLARED)?, "100");
        assert_eq!(render(&breadth, CONTAINERS_EXERCISED)?, "33");
        assert!(render(&breadth, "containers-imagined").is_err());
        Ok(())
    }

    #[test]
    fn a_rewrite_is_a_fixpoint() -> Result<()> {
        let breadth: Breadth = fixture();
        let source: &str = "of <!-- roster-breadth:containers-declared -->0<!-- /roster-breadth --> \
                            formats, <!-- roster-breadth:containers-exercised -->0<!-- /roster-breadth --> run.\n";
        let render_one = |slug: &str| -> Result<String> { render(&breadth, slug) };
        let once: String = doc_region::rewrite(SYNTAX, source, &render_one)?;
        let twice: String = doc_region::rewrite(SYNTAX, &once, &render_one)?;
        assert!(
            once.contains("-->100<!-- /roster-breadth --> formats"),
            "{once}"
        );
        assert!(once.contains("-->33<!-- /roster-breadth --> run"), "{once}");
        assert_eq!(once, twice);
        Ok(())
    }
}
