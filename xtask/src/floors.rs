use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::path::{Path, PathBuf};

use eyre::{Result, bail};

use crate::fileio::read_text_bounded;

const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_DOC_BYTES: u64 = 4 * 1024 * 1024;
const MARKER_OPEN: &str = "<!-- m:";
const MARKER_CLOSE: &str = "<!-- /m -->";
const COMMENT_END: &str = "-->";

fn without_marker_delimiters(text: &str) -> String {
    let mut out: String = String::with_capacity(text.len());
    let mut rest: &str = text;
    loop {
        let Some(at): Option<usize> = rest.find(MARKER_OPEN) else {
            out.push_str(rest);
            return out;
        };
        out.push_str(&rest[..at]);
        let tail: &str = &rest[at..];
        let Some(end): Option<usize> = tail.find(COMMENT_END) else {
            out.push_str(tail);
            return out;
        };
        rest = &tail[end + COMMENT_END.len()..];
        if let Some(close) = rest.find(MARKER_CLOSE) {
            out.push_str(&rest[..close]);
            rest = &rest[close + MARKER_CLOSE.len()..];
        }
    }
}

struct FloorClaim {
    constant: &'static str,
    source: &'static str,
    sites: &'static [(&'static str, &'static str)],
}

struct FigureClaim {
    constant: &'static str,
    source: &'static str,
    span: &'static str,
    sites: &'static [(&'static str, &'static str)],
}

const DALVIK_VERIFIER_GATE: &str = "crates/disrobe-pass-jvm/tests/dalvik_verifier_gate.rs";
const PICKLE_ROUNDTRIP_GATE: &str = "crates/disrobe-pass-pickle/tests/roundtrip.rs";
const JVM_RECOMPILE_GATE: &str = "crates/disrobe-pass-jvm/tests/decompile_recompile_rate.rs";
const PYTHON_BINDINGS_DOC: &str = "docs/src/python-bindings.md";
const PACKER_BYTE_GATE: &str = "crates/disrobe-pass-native/tests/committed_packer_byte_recovery.rs";
const EAZVM_GATE: &str = "crates/disrobe-pass-dotnet/tests/real_eazvm.rs";
const PY_ARBITRARY_GATE: &str =
    "crates/disrobe-pass-py-decompile/tests/arbitrary_recompile_gate.rs";
const PY_ROUNDTRIP_METRIC_GATE: &str = "crates/disrobe-pass-py-decompile/tests/roundtrip_metric.rs";
const VBA_SOURCE_ORACLE_GATE: &str =
    "crates/disrobe-pass-shell/tests/vba_semantic_source_oracle.rs";
const YARV_RECOMPILE_GATE: &str = "crates/disrobe-pass-ruby/tests/yarv_recompile_oracle.rs";
const UPX_UNPACK_GATE: &str = "crates/disrobe-pass-native/tests/upx_unpack_all.rs";
const README_DOC: &str = "README.md";
const CATALOG_DOC: &str = "docs/src/catalog.md";
const NATIVE_DOC: &str = "docs/src/languages/native.md";
const DOTNET_DOC: &str = "docs/src/languages/dotnet.md";
const SHELL_DOC: &str = "docs/src/languages/shell.md";
const RUBY_DOC: &str = "docs/src/languages/ruby.md";
const WHITEPAPER_DOC: &str = "docs/src/architecture/whitepaper.md";

const CONTENT_SPAN: &str = "the content span that counts `.rsrc`, not the older whole-image span \
                            measured over `.text`, `.rdata` and `.data` only";

const CLAIMS: [FloorClaim; 19] = [
    FloorClaim {
        constant: "FLOOR_PERCENT",
        source: PICKLE_ROUNDTRIP_GATE,
        sites: &[(README_DOC, "re-execute equal, floor {}% `[CI]`")],
    },
    FloorClaim {
        constant: "CLEAN_BASELINE_INSTRUCTIONS",
        source: EAZVM_GATE,
        sites: &[
            (WHITEPAPER_DOC, "The result is 67 of {} instructions"),
            (WHITEPAPER_DOC, "The EazVM ordered-CIL grade, 67 of {}"),
            (WHITEPAPER_DOC, "at 67 of {} instructions in order"),
            (DOTNET_DOC, "67 of {} instructions match in sequence"),
            (README_DOC, "67 / {} instructions lifted, ordered-CIL match"),
        ],
    },
    FloorClaim {
        constant: "MODULES_EXACT_FLOOR",
        source: PY_ARBITRARY_GATE,
        sites: &[
            (README_DOC, "{} of 200 modules whole"),
            (
                README_DOC,
                "whole-module figure of {} of 200 modules (61.0%)",
            ),
            (
                README_DOC,
                "{} of 200 modules recompile whole, floor {} `[CI]`",
            ),
            (
                WHITEPAPER_DOC,
                "equivalent, is {} of the 200 modules in the pinned corpus, 61.0%",
            ),
        ],
    },
    FloorClaim {
        constant: "MODULES_EXACT_PCT_FLOOR",
        source: PY_ARBITRARY_GATE,
        sites: &[
            (README_DOC, "of 200 modules ({}%)"),
            (
                WHITEPAPER_DOC,
                "is 122 of the 200 modules in the pinned corpus, {}%",
            ),
            (WHITEPAPER_DOC, "rate and the {}% per-module rate"),
            (WHITEPAPER_DOC, "96.51% and the {}% figures"),
        ],
    },
    FloorClaim {
        constant: "PINNED_MODULE_COUNT",
        source: PY_ARBITRARY_GATE,
        sites: &[
            (README_DOC, "122 of {} modules whole"),
            (
                WHITEPAPER_DOC,
                "is 122 of the {} modules in the pinned corpus",
            ),
            (WHITEPAPER_DOC, "over the {}-module pinned corpus"),
        ],
    },
    FloorClaim {
        constant: "PINNED_REEXECUTED",
        source: PICKLE_ROUNDTRIP_GATE,
        sites: &[
            (
                README_DOC,
                "{} / 470 reconstructed fixtures re-execute equal",
            ),
            (README_DOC, "{} / 470 re-execute equal, floor 100%"),
        ],
    },
    FloorClaim {
        constant: "PINNED_FIXTURES",
        source: PICKLE_ROUNDTRIP_GATE,
        sites: &[
            (
                README_DOC,
                "470 / {} reconstructed fixtures re-execute equal",
            ),
            (README_DOC, "470 / {} re-execute equal, floor 100%"),
        ],
    },
    FloorClaim {
        constant: "OBJECT_PCT_FLOOR",
        source: "crates/disrobe-pass-py-decompile/tests/arbitrary_recompile_gate.rs",
        sites: &[
            ("README.md", "floor {}% `[CI]`"),
            (
                "docs/src/languages/python.md",
                "above a {}% floor a committed CI gate enforces",
            ),
            ("docs/src/python-bindings.md", "CI floor {}%"),
            (
                "docs/src/architecture/whitepaper.md",
                "holds the per-object rate above a floor of {}%",
            ),
        ],
    },
    FloorClaim {
        constant: "PER_METHOD_JAVAC_OK_FLOOR",
        source: JVM_RECOMPILE_GATE,
        sites: &[
            (
                "docs/src/architecture/whitepaper.md",
                "sets `PER_METHOD_JAVAC_OK_FLOOR = {}`",
            ),
            (README_DOC, "methods recompile error-free, floor {} `[CI]`"),
            (
                PYTHON_BINDINGS_DOC,
                "recompile error-free under javac (CI floor {} of",
            ),
        ],
    },
    FloorClaim {
        constant: "IL_EQUIVALENCE_FLOOR",
        source: "crates/disrobe-pass-dotnet/tests/whole_type_il_equivalence_oracle.rs",
        sites: &[(
            "docs/src/architecture/whitepaper.md",
            "sets `IL_EQUIVALENCE_FLOOR = {}`",
        )],
    },
    FloorClaim {
        constant: "REEXEC_FLOOR_NUM",
        source: "crates/disrobe-pass-lua/tests/reexec_diff_oracle.rs",
        sites: &[(
            "docs/src/architecture/whitepaper.md",
            "sets `REEXEC_FLOOR_NUM = {}`",
        )],
    },
    FloorClaim {
        constant: "COMMITTED_VERIFY_CLEAN_CLASSES",
        source: DALVIK_VERIFIER_GATE,
        sites: &[("README.md", "{} / {} verifier-presented classes clean")],
    },
    FloorClaim {
        constant: "COMMITTED_BODY_VERIFY_CLEAN",
        source: DALVIK_VERIFIER_GATE,
        sites: &[
            ("README.md", "{} re-hosted bodies clean"),
            (
                "docs/src/languages/jvm-android.md",
                "{} re-hosted bodies verify clean",
            ),
        ],
    },
    FloorClaim {
        constant: "SOURCEPROBE_AUTHORED_LINES",
        source: VBA_SOURCE_ORACLE_GATE,
        sites: &[(SHELL_DOC, "71 of {} on SourceProbe")],
    },
    FloorClaim {
        constant: "EDGECASES_AUTHORED_LINES",
        source: VBA_SOURCE_ORACLE_GATE,
        sites: &[(SHELL_DOC, "552 of {} on the wider EdgeCases")],
    },
    FloorClaim {
        constant: "MEGAFILE_EXPECTED_PCT",
        source: YARV_RECOMPILE_GATE,
        sites: &[(RUBY_DOC, "at least {}% on the megafile fixture")],
    },
    FloorClaim {
        constant: "WHOLE_MODULE_FLOOR_PCT",
        source: PY_ROUNDTRIP_METRIC_GATE,
        sites: &[(
            WHITEPAPER_DOC,
            "whole module on a different corpus: {}% of 42 graded fixtures",
        )],
    },
    FloorClaim {
        constant: "GRADED_FIXTURE_COUNT",
        source: PY_ROUNDTRIP_METRIC_GATE,
        sites: &[(WHITEPAPER_DOC, "57.1% of {} graded fixtures")],
    },
    FloorClaim {
        constant: "FLOOR_PCT",
        source: UPX_UNPACK_GATE,
        sites: &[
            (
                WHITEPAPER_DOC,
                "The nrv2b whole-image content floor is {}% `[CI]` (`FLOOR_PCT` in \
                 `crates/disrobe-pass-native/tests/upx_unpack_all.rs`)",
            ),
            (
                README_DOC,
                "`.text` and `.pdata` byte-identical, floor {}% `[CI]`",
            ),
        ],
    },
];

const FIGURE_CLAIMS: [FigureClaim; 6] = [
    FigureClaim {
        constant: "FSG_HASH_CONTENT",
        source: PACKER_BYTE_GATE,
        span: CONTENT_SPAN,
        sites: &[
            (README_DOC, "fsg {matching} / {compared}"),
            (CATALOG_DOC, "FSG {matching} of {compared}"),
            (NATIVE_DOC, "| {matching} / {compared} |"),
        ],
    },
    FigureClaim {
        constant: "NSPACK_HASH_CONTENT",
        source: PACKER_BYTE_GATE,
        span: CONTENT_SPAN,
        sites: &[
            (README_DOC, "nspack {matching} / {compared}"),
            (CATALOG_DOC, "NSPack {matching} of {compared} bytes"),
            (NATIVE_DOC, "| {matching} / {compared} |"),
        ],
    },
    FigureClaim {
        constant: "PETITE_HELLO_CONTENT",
        source: PACKER_BYTE_GATE,
        span: CONTENT_SPAN,
        sites: &[
            (README_DOC, "petite {matching} / {compared}"),
            (CATALOG_DOC, "Petite {matching} of {compared}"),
            (NATIVE_DOC, "| {matching} / {compared} |"),
        ],
    },
    FigureClaim {
        constant: "FSG_HASH_SECTIONS",
        source: PACKER_BYTE_GATE,
        span: "the per-section comparison over `.text`, `.rdata`, `.data` and `.rsrc`",
        sites: &[
            (
                NATIVE_DOC,
                "| FSG (`Hash.exe`) | {.text.matching} / {.text.compared} | {.rdata.matching} / \
                 {.rdata.compared} | {.data.matching} / {.data.compared} | {.rsrc.matching} / \
                 {.rsrc.compared} |",
            ),
            (NATIVE_DOC, "at {.rsrc.matching} / {.rsrc.compared} for FSG"),
        ],
    },
    FigureClaim {
        constant: "NSPACK_HASH_SECTIONS",
        source: PACKER_BYTE_GATE,
        span: "the per-section comparison over `.text`, `.rdata`, `.data` and `.rsrc`",
        sites: &[
            (
                NATIVE_DOC,
                "| NSPack (`hash.exe`) | {.text.matching} / {.text.compared} | {.rdata.matching} / \
                 {.rdata.compared} | {.data.matching} / {.data.compared} | {.rsrc.matching} / \
                 {.rsrc.compared} |",
            ),
            (NATIVE_DOC, "{.rsrc.matching} / {.rsrc.compared} for NSPack"),
        ],
    },
    FigureClaim {
        constant: "PETITE_HELLO_SECTIONS",
        source: PACKER_BYTE_GATE,
        span: "the per-section comparison over `.text`, `.rdata` and `.data`, the three sections \
               this fixture carries",
        sites: &[(
            NATIVE_DOC,
            "| Petite (`hello.exe`) | {.text.matching} / {.text.compared} | {.rdata.matching} / \
             {.rdata.compared} | {.data.matching} / {.data.compared} |",
        )],
    },
];

fn literal_after_equals(line: &str) -> Option<&str> {
    let after: &str = line.split_once('=')?.1;
    let trimmed: &str = after.trim();
    let end: usize = trimmed
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(trimmed.len());
    let literal: &str = trimmed.get(..end)?;
    if literal.is_empty() {
        None
    } else {
        Some(literal)
    }
}

fn declared_value(text: &str, constant: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed: &str = line.trim();
        if !trimmed.starts_with("const ") {
            continue;
        }
        if !trimmed.contains(constant) {
            continue;
        }
        if let Some(literal) = literal_after_equals(trimmed) {
            return Some(literal.trim_end_matches('.').to_owned());
        }
    }
    None
}

fn first_number(text: &str) -> Option<String> {
    let digits: String = text
        .chars()
        .skip_while(|c: &char| !c.is_ascii_digit())
        .take_while(char::is_ascii_digit)
        .collect();
    if digits.is_empty() {
        None
    } else {
        Some(digits)
    }
}

fn quoted(text: &str) -> Option<String> {
    let opened: &str = text.split_once('"')?.1;
    Some(opened.split_once('"')?.0.to_owned())
}

fn constant_block<'src>(text: &'src str, constant: &str) -> Option<&'src str> {
    let needle: String = format!("const {constant}:");
    let at: usize = text.find(&needle)?;
    let after: &str = text.get(at..)?;
    if after.get(needle.len()..)?.contains(&needle) {
        return None;
    }
    let list_end: Option<usize> = after.find("\n];");
    let struct_end: Option<usize> = after.find("\n};");
    let end: usize = match (list_end, struct_end) {
        (Some(list), Some(item)) => list.min(item),
        (Some(only), None) | (None, Some(only)) => only,
        (None, None) => return None,
    };
    after.get(..end)
}

fn declared_figures(text: &str, constant: &str) -> Option<Vec<(String, String)>> {
    let body: &str = constant_block(text, constant)?;
    let mut figures: Vec<(String, String)> = Vec::new();
    let mut section: Option<String> = None;
    for line in body.lines() {
        let trimmed: &str = line.trim();
        if let Some(rest) = trimmed.strip_prefix("name:") {
            section = quoted(rest);
            continue;
        }
        for field in ["matching", "compared"] {
            let Some(rest) = trimmed
                .strip_prefix(field)
                .and_then(|tail: &str| tail.strip_prefix(':'))
            else {
                continue;
            };
            let value: String = first_number(rest)?;
            let key: String = section
                .as_deref()
                .map_or_else(|| field.to_owned(), |name: &str| format!("{name}.{field}"));
            figures.push((key, value));
        }
    }
    if figures.is_empty() {
        None
    } else {
        Some(figures)
    }
}

fn render(template: &str, figures: &[(String, String)]) -> String {
    let mut rendered: String = template.to_owned();
    for (key, value) in figures {
        rendered = rendered.replace(&format!("{{{key}}}"), value);
    }
    rendered
}

fn check_figure_claims(root: &Path, issues: &mut Vec<String>, checked: &mut usize) {
    let mut docs: BTreeMap<&'static str, Option<String>> = BTreeMap::new();

    for claim in &FIGURE_CLAIMS {
        let source_path: PathBuf = root.join(claim.source);
        let source_text: String = match read_text_bounded(&source_path, MAX_SOURCE_BYTES) {
            Ok(text) => text,
            Err(error) => {
                issues.push(format!(
                    "the gate that owns `{}` is missing at `{}`: {error}",
                    claim.constant, claim.source
                ));
                continue;
            }
        };

        let Some(figures): Option<Vec<(String, String)>> =
            declared_figures(&source_text, claim.constant)
        else {
            issues.push(format!(
                "`{}` is no longer declared in `{}` in a shape this check can read, so every \
                 document that publishes its figures is unchecked",
                claim.constant, claim.source
            ));
            continue;
        };

        for (key, value) in &figures {
            let placeholder: String = format!("{{{key}}}");
            let stated: bool = claim
                .sites
                .iter()
                .any(|(_, template): &(&str, &str)| template.contains(&placeholder));
            *checked += 1;
            if !stated {
                issues.push(format!(
                    "`{}` in {} now declares `{key}` as {value}, which no document site states, so \
                     that figure is published nowhere and pinned by nothing",
                    claim.constant, claim.source
                ));
            }
        }

        for (doc, template) in claim.sites {
            let cached: &Option<String> = match docs.entry(doc) {
                Entry::Occupied(slot) => slot.into_mut(),
                Entry::Vacant(slot) => {
                    slot.insert(read_text_bounded(&root.join(doc), MAX_DOC_BYTES).ok())
                }
            };
            let Some(doc_text) = cached.as_deref() else {
                issues.push(format!("{doc} could not be read"));
                continue;
            };
            let expected: String = render(template, &figures);
            *checked += 1;
            if expected.contains('{') {
                issues.push(format!(
                    "the {doc} site for `{}` names a figure `{}` that constant does not declare, so \
                     the site is checked against nothing",
                    claim.constant, expected
                ));
                continue;
            }
            if !without_marker_delimiters(doc_text).contains(&expected) {
                issues.push(format!(
                    "{doc} does not state `{expected}`; `{}` in {} measures {}, so the page \
                     publishes a figure the gate does not enforce",
                    claim.constant, claim.source, claim.span
                ));
            }
        }
    }
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let mut issues: Vec<String> = Vec::new();
    let mut checked: usize = 0;

    for claim in &CLAIMS {
        let source_path: PathBuf = root.join(claim.source);
        let source_text: String = match read_text_bounded(&source_path, MAX_SOURCE_BYTES) {
            Ok(text) => text,
            Err(error) => {
                issues.push(format!(
                    "the gate that owns `{}` is missing at `{}`: {error}",
                    claim.constant, claim.source
                ));
                continue;
            }
        };

        let Some(value): Option<String> = declared_value(&source_text, claim.constant) else {
            issues.push(format!(
                "`{}` is no longer declared in `{}`, so every document that publishes it is \
                 unchecked",
                claim.constant, claim.source
            ));
            continue;
        };

        for (doc, template) in claim.sites {
            let doc_path: PathBuf = root.join(doc);
            let doc_text: String = match read_text_bounded(&doc_path, MAX_DOC_BYTES) {
                Ok(text) => text,
                Err(error) => {
                    issues.push(format!("{doc} could not be read: {error}"));
                    continue;
                }
            };
            checked += 1;
            if !template.contains("{}") {
                issues.push(format!(
                    "the {doc} site for `{}` carries no placeholder, so it is compared against a \
                     fixed string and stays green whatever that constant becomes",
                    claim.constant
                ));
                continue;
            }
            let expected: String = template.replace("{}", &value);
            if !without_marker_delimiters(&doc_text).contains(&expected) {
                issues.push(format!(
                    "{doc} does not state the floor as `{expected}`, but `{}` in {} is {value}; a \
                     document publishing a floor other than the one the gate enforces understates \
                     or overstates what is actually guaranteed",
                    claim.constant, claim.source
                ));
            }
        }
    }

    check_figure_claims(root, &mut issues, &mut checked);

    if issues.is_empty() {
        println!(
            "xtask regen: published-floor cross-check ok ({checked} document site(s) and declared \
             figure(s) state the same numbers their gate enforces)"
        );
        Ok(())
    } else {
        bail!(
            "xtask regen: {} published floor(s) disagree with the constant the gate enforces:\n  {}",
            issues.len(),
            issues.join("\n  ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTENT_THEN_SECTIONS: &str = "const FSG_HASH_CONTENT: ContentFloor = ContentFloor {\n    matching: 55080,\n    compared: 60060,\n};\n\nconst FSG_HASH_SECTIONS: &[SectionFloor] = &[\n    SectionFloor {\n        name: \".text\",\n        matching: 18188,\n        compared: 18188,\n    },\n    SectionFloor {\n        name: \".rsrc\",\n        matching: 1369,\n        compared: 4672,\n    },\n];\n";

    #[test]
    fn a_pair_reads_out_of_a_struct_literal_constant() {
        assert_eq!(
            declared_figures(CONTENT_THEN_SECTIONS, "FSG_HASH_CONTENT"),
            Some(vec![
                ("matching".to_owned(), "55080".to_owned()),
                ("compared".to_owned(), "60060".to_owned()),
            ])
        );
    }

    #[test]
    fn a_list_reads_one_pair_per_named_section() {
        assert_eq!(
            declared_figures(CONTENT_THEN_SECTIONS, "FSG_HASH_SECTIONS"),
            Some(vec![
                (".text.matching".to_owned(), "18188".to_owned()),
                (".text.compared".to_owned(), "18188".to_owned()),
                (".rsrc.matching".to_owned(), "1369".to_owned()),
                (".rsrc.compared".to_owned(), "4672".to_owned()),
            ])
        );
    }

    #[test]
    fn a_duplicated_constant_reads_as_unresolvable() {
        let source: &str = "const A: ContentFloor = ContentFloor {\n    matching: 1,\n    compared: 2,\n};\nconst A: ContentFloor = ContentFloor {\n    matching: 3,\n    compared: 4,\n};\n";
        assert_eq!(declared_figures(source, "A"), None);
        assert_eq!(declared_figures(source, "B"), None);
    }

    #[test]
    fn a_template_that_names_an_absent_figure_keeps_its_placeholder() {
        let figures: Vec<(String, String)> = vec![
            ("matching".to_owned(), "55080".to_owned()),
            ("compared".to_owned(), "60060".to_owned()),
        ];
        assert_eq!(
            render("fsg {matching} / {compared}", &figures),
            "fsg 55080 / 60060"
        );
        assert!(render("fsg {recovered} / {compared}", &figures).contains('{'));
    }

    #[test]
    fn a_section_key_is_not_clobbered_by_the_bare_field_name() {
        let figures: Vec<(String, String)> = vec![
            (".rsrc.matching".to_owned(), "1369".to_owned()),
            (".rsrc.compared".to_owned(), "4672".to_owned()),
        ];
        assert_eq!(
            render("at {.rsrc.matching} / {.rsrc.compared} for FSG", &figures),
            "at 1369 / 4672 for FSG"
        );
    }

    #[test]
    fn every_declared_figure_is_named_by_a_site_of_its_own_claim() {
        for claim in &FIGURE_CLAIMS {
            for key in [".text.matching", "matching"] {
                let placeholder: String = format!("{{{key}}}");
                let named: bool = claim
                    .sites
                    .iter()
                    .any(|(_, template): &(&str, &str)| template.contains(&placeholder));
                let shaped_for_sections: bool = claim.constant.ends_with("SECTIONS");
                if key == "matching" && !shaped_for_sections {
                    assert!(named, "{} states no content pair", claim.constant);
                }
                if key == ".text.matching" && shaped_for_sections {
                    assert!(named, "{} states no `.text` pair", claim.constant);
                }
            }
        }
    }
}
