#![allow(clippy::expect_used, clippy::panic, clippy::too_many_lines)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_py_decompile::emit::{authentic_literal_markers, find_leaked_marker};
use disrobe_pass_py_decompile::{DecompileError, NativeDecompile, decompile_pyc};
use disrobe_py_marshal::{CodeEra, CodeObject, Object};

const MARKER_PREFIX: &str = "__DR_";
const BYTE_MARKER_SCAN_CAP: usize = 1 << 20;
const REFUSAL_SENTINEL: &str = "reconstruction placeholder";
const MIN_GRADED_FILES: usize = 270;
const MAX_FIXTURE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_WALK_DEPTH: usize = 12;

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("python")
}

fn collect_pyc(dir: &Path, depth: usize, into: &mut Vec<PathBuf>) {
    if depth > MAX_WALK_DEPTH {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut sorted: Vec<PathBuf> = entries
        .filter_map(std::result::Result::ok)
        .map(|entry: fs::DirEntry| entry.path())
        .collect();
    sorted.sort();
    for path in sorted {
        if path.is_dir() {
            collect_pyc(&path, depth.saturating_add(1), into);
        } else if path
            .extension()
            .is_some_and(|ext: &std::ffi::OsStr| ext == "pyc")
        {
            into.push(path);
        }
    }
}

fn relative(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

struct Graded {
    recovered: BTreeSet<String>,
    refused: BTreeSet<String>,
    placeholder_refusals: BTreeMap<String, String>,
    leaks: BTreeMap<String, String>,
}

fn grade_tracked_corpus() -> Graded {
    let root: PathBuf = corpus_root();
    let mut files: Vec<PathBuf> = Vec::new();
    collect_pyc(&root, 0, &mut files);

    assert!(
        files.len() >= MIN_GRADED_FILES,
        "the tracked python corpus under {} yielded only {} .pyc file(s), below the floor of {}. \
         Either the walk is broken or the corpus moved; a grade that reads a fraction of the \
         population reports a clean sheet for every file it never opened",
        root.display(),
        files.len(),
        MIN_GRADED_FILES
    );

    let mut graded: Graded = Graded {
        recovered: BTreeSet::new(),
        refused: BTreeSet::new(),
        placeholder_refusals: BTreeMap::new(),
        leaks: BTreeMap::new(),
    };

    for path in &files {
        let name: String = relative(path, &root);
        let Ok(meta) = fs::metadata(path) else {
            continue;
        };
        if meta.len() > MAX_FIXTURE_BYTES {
            continue;
        }
        let Ok(bytes) = fs::read(path) else {
            continue;
        };
        let Ok(decompiled): Result<NativeDecompile, DecompileError> = decompile_pyc(&bytes) else {
            graded.refused.insert(name);
            continue;
        };
        if !decompiled.recovered_directly {
            let reason: String = decompiled.fallback_reason.unwrap_or_default();
            if reason.contains(REFUSAL_SENTINEL) {
                graded.placeholder_refusals.insert(name.clone(), reason);
            }
            graded.refused.insert(name);
            continue;
        }
        if let Some(at) = decompiled
            .source
            .lines()
            .enumerate()
            .find(|(_, line): &(usize, &str)| line.contains(MARKER_PREFIX))
        {
            graded.leaks.insert(
                name.clone(),
                format!("line {}: {}", at.0.saturating_add(1), at.1.trim()),
            );
        }
        graded.recovered.insert(name);
    }

    graded
}

#[test]
fn no_recovered_python_carries_a_reconstruction_placeholder() {
    let graded: Graded = grade_tracked_corpus();
    let population: usize = graded.recovered.len().saturating_add(graded.refused.len());

    assert!(
        population >= MIN_GRADED_FILES,
        "only {population} tracked .pyc fixture(s) were graded, below the floor of \
         {MIN_GRADED_FILES}"
    );
    assert!(
        !graded.recovered.is_empty(),
        "every one of the {population} tracked .pyc fixture(s) refused, so this grade proves \
         nothing about emitted source"
    );

    assert!(
        graded.leaks.is_empty(),
        "{} of {} directly-recovered fixture(s) emitted an internal reconstruction placeholder \
         into python a caller may read, save or feed to a tool:\n  {}",
        graded.leaks.len(),
        graded.recovered.len(),
        graded
            .leaks
            .iter()
            .map(|(file, at): (&String, &String)| format!("{file} -> {at}"))
            .collect::<Vec<String>>()
            .join("\n  ")
    );
}

#[test]
fn the_refusal_this_grade_matches_on_is_the_one_the_engine_emits() {
    let rendered: String = DecompileError::UnresolvedMarker {
        stem: "CHAIN_VALUE".to_owned(),
        line: 3,
    }
    .to_string();

    assert!(
        rendered.contains(REFUSAL_SENTINEL),
        "the placeholder refusal reads `{rendered}`, which no longer carries the sentinel \
         `{REFUSAL_SENTINEL}` that the membership pin matches on. Reword either and the pin \
         silently observes an empty set and passes forever"
    );
    assert!(
        !rendered.contains(MARKER_PREFIX),
        "the refusal text reads `{rendered}`, which reintroduces the placeholder token into \
         output a caller reads; name the placeholder by its stem instead"
    );
    assert!(
        rendered.contains("CHAIN_VALUE") && rendered.contains('3'),
        "the refusal must name what could not be resolved and where, but reads `{rendered}`"
    );
}

#[test]
fn the_fixtures_refused_for_an_unresolved_placeholder_are_pinned_by_name() {
    const PINNED: &[&str] = &[];

    let graded: Graded = grade_tracked_corpus();
    let observed: BTreeSet<&str> = graded
        .placeholder_refusals
        .keys()
        .map(String::as_str)
        .collect();
    let pinned: BTreeSet<&str> = PINNED.iter().copied().collect();

    let appeared: Vec<&&str> = observed.difference(&pinned).collect();
    let departed: Vec<&&str> = pinned.difference(&observed).collect();

    assert!(
        appeared.is_empty(),
        "{} fixture(s) newly refuse because reconstruction left a placeholder, and they are not in \
         the pinned set. A count would have read as noise; these are the names:\n  {}\nreasons:\n  \
         {}",
        appeared.len(),
        appeared
            .iter()
            .map(|name: &&&str| (**name).to_owned())
            .collect::<Vec<String>>()
            .join("\n  "),
        graded
            .placeholder_refusals
            .values()
            .map(String::as_str)
            .collect::<Vec<&str>>()
            .join("\n  ")
    );
    assert!(
        departed.is_empty(),
        "{} pinned fixture(s) no longer refuse for an unresolved placeholder. That is an \
         improvement, and the pin must be lowered in the same change so the declared set cannot \
         drift away from the real one:\n  {}",
        departed.len(),
        departed
            .iter()
            .map(|name: &&&str| (**name).to_owned())
            .collect::<Vec<String>>()
            .join("\n  ")
    );
}

#[test]
fn a_placeholder_in_emitted_text_is_reported_with_its_name_and_line() {
    let source: String =
        format!("def f(a):\n    b = a + 1\n    return {MARKER_PREFIX}CHAIN_VALUE__ + b\n");
    let empty: BTreeSet<String> = BTreeSet::new();
    let found = find_leaked_marker(&source, &empty)
        .expect("a placeholder in emitted text must be reported, not passed through");

    assert_eq!(found.stem, "CHAIN_VALUE");
    assert_eq!(found.line, 3);

    let clean: &str = "def f(a):\n    b = a + 1\n    return b\n";
    assert!(
        find_leaked_marker(clean, &empty).is_none(),
        "python that carries no placeholder must not be refused"
    );
}

#[test]
fn an_authored_marker_spelling_inside_a_literal_is_not_treated_as_a_leak() {
    let authored: String = format!("{MARKER_PREFIX}CHAIN_VALUE__");
    let authentic: BTreeSet<String> = BTreeSet::from([authored.clone()]);
    let source: String = format!("note = '{authored}'\nprint(note)\n");

    assert!(
        find_leaked_marker(&source, &authentic).is_none(),
        "literal content from the original program must not be treated as an internal placeholder"
    );
}

#[test]
fn an_authored_marker_literal_does_not_whitelist_a_reconstructed_identifier() {
    let authored: String = format!("{MARKER_PREFIX}CHAIN_VALUE__");
    let authentic: BTreeSet<String> = BTreeSet::from([authored.clone()]);
    let source: String = format!("note = '{authored}'\nresult = {authored}\n");
    let found = find_leaked_marker(&source, &authentic).expect(
        "an authentic literal must not let the same spelling pass as an emitted identifier",
    );
    assert_eq!(found.stem, "CHAIN_VALUE");
    assert_eq!(found.line, 2);
}

#[test]
fn a_marker_in_a_comment_is_never_authenticated() {
    let authored: String = format!("{MARKER_PREFIX}CHAIN_VALUE__");
    let authentic: BTreeSet<String> = BTreeSet::from([authored.clone()]);
    let source: String = format!("# {authored}\nvalue = 1\n");
    let found = find_leaked_marker(&source, &authentic)
        .expect("comments have no bytecode provenance and must not carry an internal marker");

    assert_eq!(found.stem, "CHAIN_VALUE");
    assert_eq!(found.line, 1);
}

#[test]
fn an_authored_byte_literal_does_not_whitelist_a_reconstructed_identifier() {
    let authored: String = format!("{MARKER_PREFIX}CHAIN_VALUE__");
    let mut code: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    code.consts
        .push(Object::Bytes(authored.as_bytes().to_vec()));
    let authentic: BTreeSet<String> = authentic_literal_markers(&code);
    let literal: String = format!("value = b'{authored}'\n");

    assert!(
        find_leaked_marker(&literal, &authentic).is_none(),
        "marker text from an authored byte literal must survive emitted byte-literal syntax"
    );

    let collision: String = format!("value = b'{authored}'\nresult = {authored}\n");
    let found = find_leaked_marker(&collision, &authentic).expect(
        "an authored byte literal must not authorize the same spelling as an emitted identifier",
    );
    assert_eq!(found.stem, "CHAIN_VALUE");
    assert_eq!(found.line, 2);
}

#[test]
fn a_byte_marker_ending_at_the_budget_cap_is_authenticated_before_a_delimiter() {
    let authored: String = format!("{MARKER_PREFIX}CHAIN_VALUE__");
    let padding: String = "x".repeat(BYTE_MARKER_SCAN_CAP.saturating_sub(authored.len()));
    let mut value: Vec<u8> = padding.into_bytes();
    value.extend_from_slice(authored.as_bytes());
    value.push(b'!');
    let mut code: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    code.consts.push(Object::Bytes(value));
    let authentic: BTreeSet<String> = authentic_literal_markers(&code);
    let literal: String = format!("value = b'{authored}!'\n");

    assert!(
        find_leaked_marker(&literal, &authentic).is_none(),
        "a delimiter immediately after the scan cap completes the authored byte marker"
    );

    let collision: String = format!("value = b'{authored}!'\nresult = {authored}\n");
    let found = find_leaked_marker(&collision, &authentic)
        .expect("a byte marker ending at the scan cap must not authorize an emitted identifier");
    assert_eq!(found.stem, "CHAIN_VALUE");
    assert_eq!(found.line, 2);
}

#[test]
fn a_byte_marker_split_across_the_budget_cap_remains_unauthenticated() {
    let authored: String = format!("{MARKER_PREFIX}CHAIN_VALUE__");
    let padding: String = "x".repeat(BYTE_MARKER_SCAN_CAP.saturating_sub(authored.len()));
    let mut value: Vec<u8> = padding.into_bytes();
    value.extend_from_slice(authored.as_bytes());
    value.push(b'A');
    let mut code: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    code.consts.push(Object::Bytes(value));
    let authentic: BTreeSet<String> = authentic_literal_markers(&code);
    let emitted: String = format!("{authored}A");
    let literal: String = format!("value = b'{emitted}'\n");
    let found = find_leaked_marker(&literal, &authentic)
        .expect("a marker token split by the scan cap must remain a refusal");

    assert_eq!(found.stem, "CHAIN_VALUE__A");
    assert_eq!(found.line, 1);
}

#[test]
fn formatted_literal_segments_do_not_authorize_interpolations_or_format_specs() {
    let authored: String = format!("{MARKER_PREFIX}CHAIN_VALUE__");
    let authentic: BTreeSet<String> = BTreeSet::from([authored.clone()]);
    let cases: Vec<(&str, String, bool)> = vec![
        ("f-literal", format!("value = f'{authored}'\n"), false),
        ("t-literal", format!("value = t'{authored}'\n"), false),
        (
            "f-interpolation",
            format!("value = f'{{{authored}}}'\n"),
            true,
        ),
        (
            "t-interpolation",
            format!("value = t'{{{authored}}}'\n"),
            true,
        ),
        (
            "f-format-spec",
            format!("value = f'{{1:{{{authored}}}}}'\n"),
            true,
        ),
        (
            "t-format-spec",
            format!("value = t'{{1:{{{authored}}}}}'\n"),
            true,
        ),
        (
            "nested-f-literal",
            format!("value = f\"{{f'{authored}'}}\"\n"),
            false,
        ),
        (
            "nested-t-literal",
            format!("value = t\"{{t'{authored}'}}\"\n"),
            false,
        ),
        (
            "nested-f-interpolation",
            format!("value = f\"{{f'{{{authored}}}'}}\"\n"),
            true,
        ),
        (
            "nested-t-interpolation",
            format!("value = t\"{{t'{{{authored}}}'}}\"\n"),
            true,
        ),
        (
            "nested-f-format-spec",
            format!("value = f\"{{f'{{1:{{{authored}}}}}'}}\"\n"),
            true,
        ),
        (
            "nested-t-format-spec",
            format!("value = t\"{{t'{{1:{{{authored}}}}}'}}\"\n"),
            true,
        ),
    ];

    for (label, source, should_leak) in cases {
        let found = find_leaked_marker(&source, &authentic);
        assert_eq!(
            found.is_some(),
            should_leak,
            "{label} classified marker spelling by text instead of its formatted-string role:\n{source}"
        );
    }
}

#[test]
fn no_tracked_fixture_contains_an_authentic_marker_literal() {
    let root: PathBuf = corpus_root();
    let mut files: Vec<PathBuf> = Vec::new();
    collect_pyc(&root, 0, &mut files);

    let mut read: usize = 0;
    let mut declaring: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for path in &files {
        let Ok(bytes) = fs::read(path) else {
            continue;
        };
        let Ok(decompiled) = decompile_pyc(&bytes) else {
            continue;
        };
        read = read.saturating_add(1);
        let declared: BTreeSet<String> = authentic_literal_markers(&decompiled.code);
        if !declared.is_empty() {
            declaring.insert(relative(path, &root), declared);
        }
    }

    assert!(
        read >= MIN_GRADED_FILES,
        "only {read} of {} tracked .pyc fixture(s) parsed, below the floor of {MIN_GRADED_FILES}; \
         a scan that reads a fraction of the population establishes nothing about the rest",
        files.len()
    );
    assert!(
        declaring.is_empty(),
        "{} tracked fixture(s) contain a literal shaped like a reconstruction placeholder, so the \
         marker guard must classify it by emitted role rather than spelling alone:\n  {}",
        declaring.len(),
        declaring
            .iter()
            .map(|(file, names): (&String, &BTreeSet<String>)| format!("{file} -> {names:?}"))
            .collect::<Vec<String>>()
            .join("\n  ")
    );
}
