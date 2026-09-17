#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::missing_panics_doc
)]

#[path = "support/xlm_reference.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod xlm_reference;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_shell::{XlmCell, XlmRecovery, XlmSheet, recover_xlm};

use xlm_reference::{
    CellAnswer, CellJob, FORMULA_REFERENCE, FunctionTables, Manifest, TABLE_REFERENCE, manifest,
    normalize, parse_id, pinned_fixture_bytes, read_cells, read_function_tables,
    require_interpreter,
};

const BASE_FIXTURE: &str = "real_xlm_excel16.xls";
const CETAB_FLAG: u16 = 0x8000;
const PROBE_ID: u16 = 0x0016;
const GRADED_FTAB: usize = 359;
const GRADED_CETAB: usize = 396;
const UNCARRIED_FTAB: usize = 117;
const UNCARRIED_CETAB: usize = 0;
const USER_DEFINED_FUNCTION: u16 = 0x00FF;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Class {
    Ftab,
    Cetab,
}

impl Class {
    const fn label(self) -> &'static str {
        match self {
            Self::Ftab => "ftab",
            Self::Cetab => "cetab",
        }
    }

    const fn field(self, id: u16) -> u16 {
        match self {
            Self::Ftab => id,
            Self::Cetab => id | CETAB_FLAG,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct IndexSite {
    label: &'static str,
    sheet: &'static str,
    cell: &'static str,
    window: &'static [u8],
    id_offset: usize,
}

const EXEC_CALL: [u8; 15] = [
    0x17, 0x08, 0x00, b'c', b'a', b'l', b'c', b'.', b'e', b'x', b'e', 0x42, 0x01, 0x6E, 0x00,
];
const RETURN_CALL: [u8; 4] = [0x42, 0x00, 0x37, 0x00];
const SUM_CALL: [u8; 10] = [0x1E, 0x01, 0x00, 0x1E, 0x02, 0x00, 0x42, 0x02, 0x04, 0x00];
const KERNEL32_CALL: [u8; 4] = [0x42, 0x03, 0x96, 0x00];

const INDEX_SITES: [IndexSite; 4] = [
    IndexSite {
        label: "one-argument",
        sheet: "Macro1",
        cell: "C1",
        window: &EXEC_CALL,
        id_offset: 13,
    },
    IndexSite {
        label: "no-argument",
        sheet: "Macro1",
        cell: "A3",
        window: &RETURN_CALL,
        id_offset: 2,
    },
    IndexSite {
        label: "two-argument",
        sheet: "Macro1",
        cell: "A2",
        window: &SUM_CALL,
        id_offset: 8,
    },
    IndexSite {
        label: "three-argument",
        sheet: "Macro1",
        cell: "C2",
        window: &KERNEL32_CALL,
        id_offset: 2,
    },
];

const SHAPED_RGCE: [u8; 34] = [
    0x17, 0x08, 0x00, b'K', b'e', b'r', b'n', b'e', b'l', b'3', b'2', 0x17, 0x0C, 0x00, b'G', b'e',
    b't', b'T', b'i', b'c', b'k', b'C', b'o', b'u', b'n', b't', 0x17, 0x01, 0x00, b'J', 0x42, 0x03,
    0x96, 0x00,
];
const SHAPED_FILLER: u8 = b'P';

#[derive(Debug, Clone, Copy)]
struct ShapedSite {
    label: &'static str,
    sheet: &'static str,
    cell: &'static str,
    argc: u8,
}

const SHAPED_SITES: [ShapedSite; 2] = [
    ShapedSite {
        label: "four-argument",
        sheet: "Macro1",
        cell: "C2",
        argc: 4,
    },
    ShapedSite {
        label: "five-argument",
        sheet: "Macro1",
        cell: "C2",
        argc: 5,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReferenceDivergence {
    class: Class,
    id: u16,
    ours: &'static str,
    theirs: &'static str,
    reason: &'static str,
}

const DECLARED_REFERENCE_DIVERGENCES: [ReferenceDivergence; 1] = [ReferenceDivergence {
    class: Class::Ftab,
    id: 0x005C,
    ours: "SERIES",
    theirs: "SERIESSUM",
    reason: "0x005C is SERIES and 0x019E is SERIESSUM. The formula reference names both SERIESSUM, \
             so it folds two distinct entries onto one name; the function-name table reference \
             names 0x005C SERIES and agrees with the recovery",
}];

fn divergence(class: Class, id: u16) -> Option<&'static ReferenceDivergence> {
    DECLARED_REFERENCE_DIVERGENCES
        .iter()
        .find(|entry: &&ReferenceDivergence| entry.class == class && entry.id == id)
}

fn recovered_cells(report: &XlmRecovery) -> BTreeMap<(String, String), String> {
    let mut out: BTreeMap<(String, String), String> = BTreeMap::new();
    for sheet in &report.sheets {
        for cell in &sheet.cells {
            out.insert(
                (sheet.name.clone(), cell.cell.clone()),
                cell.formula.clone(),
            );
        }
    }
    out
}

fn recovery_of(data: &[u8]) -> BTreeMap<(String, String), String> {
    let report: XlmRecovery =
        recover_xlm(data).unwrap_or_else(|| panic!("the perturbed workbook must still recover"));
    recovered_cells(&report)
}

fn changed_cells(
    control: &BTreeMap<(String, String), String>,
    probe: &BTreeMap<(String, String), String>,
) -> BTreeSet<(String, String)> {
    let mut out: BTreeSet<(String, String)> = BTreeSet::new();
    for (key, value) in control {
        if probe.get(key) != Some(value) {
            out.insert(key.clone());
        }
    }
    for key in probe.keys() {
        if !control.contains_key(key) {
            out.insert(key.clone());
        }
    }
    out
}

fn names_a_function(formula: &str) -> bool {
    let Some(body): Option<&str> = formula.strip_prefix('=') else {
        return false;
    };
    let head: &str = body
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '_'))
        .next()
        .unwrap_or_default();
    head.starts_with(|c: char| c.is_ascii_alphabetic()) && body.starts_with(head)
}

fn occurrences(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(|(at, window): (usize, &[u8])| (window == needle).then_some(at))
        .collect()
}

fn with_index(base: &[u8], at: usize, field: u16) -> Vec<u8> {
    let mut out: Vec<u8> = base.to_vec();
    out[at] = (field & 0x00FF) as u8;
    out[at + 1] = (field >> 8) as u8;
    out
}

fn shaped_rgce(field: u16, argc: u8) -> Vec<u8> {
    let filler: usize = SHAPED_RGCE.len() - 4 - 3 - 3 * (usize::from(argc) - 1);
    let mut out: Vec<u8> = Vec::with_capacity(SHAPED_RGCE.len());
    out.push(0x17);
    out.push(u8::try_from(filler).expect("the filler string fits one byte of length"));
    out.push(0x00);
    out.extend(std::iter::repeat_n(SHAPED_FILLER, filler));
    for operand in 1..u16::from(argc) {
        out.push(0x1E);
        out.extend_from_slice(&operand.to_le_bytes());
    }
    out.push(0x42);
    out.push(argc);
    out.extend_from_slice(&field.to_le_bytes());
    assert_eq!(
        out.len(),
        SHAPED_RGCE.len(),
        "a shaped call must keep the record length of the workbook it replaces"
    );
    out
}

fn with_rgce(base: &[u8], at: usize, rgce: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = base.to_vec();
    out[at..at + rgce.len()].copy_from_slice(rgce);
    out
}

fn resolve_index_site(base: &[u8], control: &BTreeMap<(String, String), String>) -> Vec<usize> {
    INDEX_SITES
        .iter()
        .map(|site: &IndexSite| {
            let found: Vec<usize> = occurrences(base, site.window);
            assert!(
                !found.is_empty(),
                "{} call site is absent from {BASE_FIXTURE}",
                site.label
            );
            let target: BTreeSet<(String, String)> =
                BTreeSet::from([(site.sheet.to_owned(), site.cell.to_owned())]);
            let hits: Vec<usize> = found
                .iter()
                .map(|at: &usize| at + site.id_offset)
                .filter(|at: &usize| {
                    changed_cells(control, &recovery_of(&with_index(base, *at, PROBE_ID))) == target
                })
                .collect();
            assert_eq!(
                hits.len(),
                1,
                "{} call site must resolve to exactly one index that moves only {}!{}, got {hits:?} \
                 among {} candidate windows",
                site.label,
                site.sheet,
                site.cell,
                found.len()
            );
            hits[0]
        })
        .collect()
}

fn resolve_shaped_site(base: &[u8], control: &BTreeMap<(String, String), String>) -> usize {
    let found: Vec<usize> = occurrences(base, &SHAPED_RGCE);
    assert_eq!(
        found.len(),
        1,
        "the replaceable call record must appear exactly once in {BASE_FIXTURE}"
    );
    let at: usize = found[0];
    for site in SHAPED_SITES {
        let probe: Vec<u8> = with_rgce(base, at, &shaped_rgce(PROBE_ID, site.argc));
        let target: BTreeSet<(String, String)> =
            BTreeSet::from([(site.sheet.to_owned(), site.cell.to_owned())]);
        assert_eq!(
            changed_cells(control, &recovery_of(&probe)),
            target,
            "a {} shaped call must move only {}!{}",
            site.label,
            site.sheet,
            site.cell
        );
    }
    at
}

#[derive(Debug, Clone)]
struct Graded {
    site: &'static str,
    ours: String,
    theirs: String,
}

struct Sweep<'a> {
    python: &'a Path,
    scratch: &'a Path,
    base: Vec<u8>,
    index_at: Vec<usize>,
    shaped_at: usize,
    round: usize,
}

impl Sweep<'_> {
    fn phase(
        &mut self,
        class: Class,
        label: &'static str,
        sheet: &'static str,
        cell: &'static str,
        remaining: &mut BTreeSet<u16>,
        build: &dyn Fn(u16) -> Vec<u8>,
        graded: &mut BTreeMap<u16, Graded>,
    ) {
        if remaining.is_empty() {
            return;
        }
        let mut jobs: Vec<CellJob> = Vec::with_capacity(remaining.len());
        let mut ours: BTreeMap<u16, String> = BTreeMap::new();
        let mut staged: Vec<PathBuf> = Vec::with_capacity(remaining.len());
        for id in remaining.iter().copied() {
            let data: Vec<u8> = build(id);
            let key: String = format!("0x{id:04X}");
            let path: PathBuf = self
                .scratch
                .join(format!("{}_{label}_{key}.xls", class.label()));
            std::fs::write(&path, &data)
                .unwrap_or_else(|err| panic!("cannot stage {}: {err}", path.display()));
            let recovered: BTreeMap<(String, String), String> = recovery_of(&data);
            let Some(formula): Option<&String> =
                recovered.get(&(sheet.to_owned(), cell.to_owned()))
            else {
                panic!(
                    "the recovery lost {sheet}!{cell} after setting {} {key}",
                    class.label()
                );
            };
            ours.insert(id, formula.clone());
            jobs.push(CellJob {
                key,
                file: path.to_string_lossy().into_owned(),
                sheet: sheet.to_owned(),
                cell: cell.to_owned(),
            });
            staged.push(path);
        }
        self.round += 1;
        let answers: BTreeMap<String, CellAnswer> =
            read_cells(self.python, self.scratch, self.round, &jobs);
        for path in &staged {
            let _ = std::fs::remove_file(path);
        }
        let mut taken: usize = 0;
        for (key, answer) in &answers {
            if answer.status != "named" || !names_a_function(&answer.formula) {
                continue;
            }
            let id: u16 = parse_id(key);
            let Some(our_formula): Option<&String> = ours.get(&id) else {
                panic!("the driver answered for {key}, which this phase never staged");
            };
            graded.insert(
                id,
                Graded {
                    site: label,
                    ours: our_formula.clone(),
                    theirs: answer.formula.clone(),
                },
            );
            remaining.remove(&id);
            taken += 1;
        }
        println!(
            "  {} {label}: {taken} newly graded, {} still unread by {FORMULA_REFERENCE}",
            class.label(),
            remaining.len()
        );
    }

    fn run(&mut self, class: Class, ids: &BTreeSet<u16>) -> SweepResult {
        let mut remaining: BTreeSet<u16> = ids.clone();
        let mut graded: BTreeMap<u16, Graded> = BTreeMap::new();
        for (index, site) in INDEX_SITES.iter().enumerate() {
            let at: usize = self.index_at[index];
            let base: Vec<u8> = self.base.clone();
            let build = move |id: u16| -> Vec<u8> { with_index(&base, at, class.field(id)) };
            self.phase(
                class,
                site.label,
                site.sheet,
                site.cell,
                &mut remaining,
                &build,
                &mut graded,
            );
        }
        for site in SHAPED_SITES {
            let at: usize = self.shaped_at;
            let base: Vec<u8> = self.base.clone();
            let argc: u8 = site.argc;
            let build = move |id: u16| -> Vec<u8> {
                with_rgce(&base, at, &shaped_rgce(class.field(id), argc))
            };
            self.phase(
                class,
                site.label,
                site.sheet,
                site.cell,
                &mut remaining,
                &build,
                &mut graded,
            );
        }
        SweepResult {
            graded,
            unnamed: remaining,
        }
    }
}

#[derive(Debug)]
struct SweepResult {
    graded: BTreeMap<u16, Graded>,
    unnamed: BTreeSet<u16>,
}

fn expected_from_reference(class: Class, id: u16, theirs: &str) -> String {
    divergence(class, id).map_or_else(
        || theirs.to_owned(),
        |entry: &ReferenceDivergence| theirs.replacen(entry.theirs, entry.ours, 1),
    )
}

fn faults(class: Class, graded: &BTreeMap<u16, Graded>) -> Vec<String> {
    graded
        .iter()
        .filter_map(|(id, entry): (&u16, &Graded)| {
            let expected: String = expected_from_reference(class, *id, &entry.theirs);
            (normalize(&expected) != normalize(&entry.ours)).then(|| {
                format!(
                    "{} 0x{id:04X} at the {} call site: {FORMULA_REFERENCE} reads {:?}, the \
                     recovery reads {:?}",
                    class.label(),
                    entry.site,
                    entry.theirs,
                    entry.ours
                )
            })
        })
        .collect()
}

fn table_ids(table: &BTreeMap<String, String>) -> BTreeSet<u16> {
    table.keys().map(|raw: &String| parse_id(raw)).collect()
}

#[test]
fn every_function_index_is_graded_from_a_real_sheet_against_an_independent_reader() {
    let python: PathBuf = require_interpreter();
    let guard: ScratchDir =
        ScratchDir::create("xlm-ftab-real-sheet").expect("create scratch directory");
    let tables: FunctionTables = read_function_tables(&python, guard.path());
    let catalog: Manifest = manifest();
    let base: Vec<u8> = pinned_fixture_bytes(&catalog, BASE_FIXTURE);
    let control: BTreeMap<(String, String), String> = recovery_of(&base);

    println!(
        "\nreference: {FORMULA_REFERENCE} {} over xlrd2 {}, and {TABLE_REFERENCE} {}, via {}",
        tables.xlmmacrodeobfuscator,
        tables.xlrd2,
        tables.pyxlsb2,
        python.display()
    );

    let mut sweep: Sweep<'_> = Sweep {
        python: &python,
        scratch: guard.path(),
        index_at: resolve_index_site(&base, &control),
        shaped_at: resolve_shaped_site(&base, &control),
        base,
        round: 0,
    };

    let ftab_ids: BTreeSet<u16> = table_ids(&tables.ftab);
    let cetab_ids: BTreeSet<u16> = table_ids(&tables.cetab);
    let ftab_sweep: SweepResult = sweep.run(Class::Ftab, &ftab_ids);
    let cetab_sweep: SweepResult = sweep.run(Class::Cetab, &cetab_ids);
    let ftab: BTreeMap<u16, Graded> = ftab_sweep.graded;
    let cetab: BTreeMap<u16, Graded> = cetab_sweep.graded;

    let mut reported: Vec<String> = faults(Class::Ftab, &ftab);
    reported.extend(faults(Class::Cetab, &cetab));
    assert!(
        reported.is_empty(),
        "{} formula disagreement(s) between the recovery and {FORMULA_REFERENCE} {}:\n{}",
        reported.len(),
        tables.xlmmacrodeobfuscator,
        reported.join("\n")
    );

    for entry in DECLARED_REFERENCE_DIVERGENCES {
        let source: &BTreeMap<u16, Graded> = match entry.class {
            Class::Ftab => &ftab,
            Class::Cetab => &cetab,
        };
        let Some(graded): Option<&Graded> = source.get(&entry.id) else {
            panic!(
                "recorded divergence {} 0x{:04X} is no longer graded, so the exemption is stale",
                entry.class.label(),
                entry.id
            );
        };
        assert!(
            graded.theirs.contains(entry.theirs) && graded.ours.contains(entry.ours),
            "recorded divergence {} 0x{:04X} is {} against {}, now {:?} against {:?}. {}",
            entry.class.label(),
            entry.id,
            entry.ours,
            entry.theirs,
            graded.ours,
            graded.theirs,
            entry.reason
        );
    }

    assert_eq!(
        ftab.len(),
        GRADED_FTAB,
        "docs/src/languages/shell.md publishes {GRADED_FTAB} real-sheet-graded ftab ids, so a \
         change to the sweep's coverage moves the figure in the same commit"
    );
    assert_eq!(
        cetab.len(),
        GRADED_CETAB,
        "docs/src/languages/shell.md publishes {GRADED_CETAB} real-sheet-graded cetab ids, so a \
         change to the sweep's coverage moves the figure in the same commit"
    );
    assert_eq!(
        ftab.len() + ftab_sweep.unnamed.len(),
        tables.ftab.len(),
        "every ftab id must be graded or recorded as one {FORMULA_REFERENCE} does not carry"
    );
    assert_eq!(
        cetab.len() + cetab_sweep.unnamed.len(),
        tables.cetab.len(),
        "every cetab id must be graded or recorded as one {FORMULA_REFERENCE} does not carry"
    );
    let parser_ids: BTreeSet<u16> = tables
        .parser_ids
        .iter()
        .map(|raw: &String| parse_id(raw))
        .collect();
    let mut absent_from_the_parser: BTreeSet<u16> =
        ftab_ids.difference(&parser_ids).copied().collect();
    absent_from_the_parser.insert(USER_DEFINED_FUNCTION);
    assert_eq!(
        ftab_sweep.unnamed, absent_from_the_parser,
        "the ftab ids {FORMULA_REFERENCE} renders without a name must be exactly the ids its \
         parser table omits, plus 0x{USER_DEFINED_FUNCTION:04X}, which it refuses as a record \
         rather than naming"
    );
    assert_eq!(
        ftab_sweep.unnamed.len(),
        UNCARRIED_FTAB,
        "docs/src/languages/shell.md publishes {UNCARRIED_FTAB} ftab ids {FORMULA_REFERENCE} \
         renders without a name, so a change to that count moves the figure in the same commit"
    );
    assert_eq!(
        cetab_sweep.unnamed.len(),
        UNCARRIED_CETAB,
        "docs/src/languages/shell.md publishes all 396 cetab ids as named, so {UNCARRIED_CETAB} \
         unnamed must hold or the figure moves in the same commit: {:?}",
        cetab_sweep
            .unnamed
            .iter()
            .map(|id: &u16| format!("0x{id:04X}"))
            .collect::<Vec<String>>()
    );
    println!(
        "\nGRADED: {} of {} ftab and {} of {} cetab function indexes, each set into a real Excel \
         workbook and read back by {FORMULA_REFERENCE} {}, with {} recorded divergence(s). \
         {} ftab and {} cetab ids carry no name in {FORMULA_REFERENCE} at any call site and stay \
         graded only against {TABLE_REFERENCE}.\n",
        ftab.len(),
        tables.ftab.len(),
        cetab.len(),
        tables.cetab.len(),
        tables.xlmmacrodeobfuscator,
        DECLARED_REFERENCE_DIVERGENCES.len(),
        ftab_sweep.unnamed.len(),
        cetab_sweep.unnamed.len()
    );
}

#[test]
fn shifting_one_function_index_is_reported_for_a_used_entry_and_for_a_table_only_entry() {
    let python: PathBuf = require_interpreter();
    let guard: ScratchDir =
        ScratchDir::create("xlm-ftab-index-shift").expect("create scratch directory");
    let tables: FunctionTables = read_function_tables(&python, guard.path());
    let catalog: Manifest = manifest();
    let base: Vec<u8> = pinned_fixture_bytes(&catalog, BASE_FIXTURE);
    let control: BTreeMap<(String, String), String> = recovery_of(&base);
    let index_at: Vec<usize> = resolve_index_site(&base, &control);
    let shaped_at: usize = resolve_shaped_site(&base, &control);

    let report: XlmRecovery = recover_xlm(&base).expect("the base workbook recovers");
    let macro_sheet: &XlmSheet = report
        .sheets
        .iter()
        .find(|sheet: &&XlmSheet| sheet.name == "Macro1")
        .expect("the base workbook carries Macro1");
    assert!(
        macro_sheet
            .cells
            .iter()
            .any(|cell: &XlmCell| cell.formula == "=EXEC(\"calc.exe\")"),
        "0x006E is the index the committed sheet already uses, so it must appear as authored"
    );

    let mut sweep: Sweep<'_> = Sweep {
        python: &python,
        scratch: guard.path(),
        index_at,
        shaped_at,
        base,
        round: 0,
    };

    let used_pair: [u16; 2] = [0x006E, 0x006F];
    let table_only_pair: [u16; 2] = [0x0125, 0x011E];
    for pair in [used_pair, table_only_pair] {
        let ids: BTreeSet<u16> = pair.into_iter().collect();
        let outcome: SweepResult = sweep.run(Class::Ftab, &ids);
        assert!(
            outcome.unnamed.is_empty(),
            "both ids in {pair:?} must carry a name in {FORMULA_REFERENCE}"
        );
        let graded: BTreeMap<u16, Graded> = outcome.graded;
        let held: &Graded = graded
            .get(&pair[0])
            .unwrap_or_else(|| panic!("0x{:04X} must grade", pair[0]));
        let neighbour: &Graded = graded
            .get(&pair[1])
            .unwrap_or_else(|| panic!("0x{:04X} must grade", pair[1]));
        assert_eq!(
            normalize(&expected_from_reference(Class::Ftab, pair[0], &held.theirs)),
            normalize(&held.ours),
            "0x{:04X} must agree with {FORMULA_REFERENCE} before a shift is simulated",
            pair[0]
        );
        let shifted: Graded = Graded {
            site: held.site,
            ours: held.ours.clone(),
            theirs: neighbour.theirs.clone(),
        };
        let reported: Vec<String> = faults(Class::Ftab, &BTreeMap::from([(pair[0], shifted)]));
        assert_eq!(
            reported.len(),
            1,
            "reading 0x{:04X} as 0x{:04X} must be reported, not folded away. \
             {FORMULA_REFERENCE} reads {:?} for the first and {:?} for the second",
            pair[0],
            pair[1],
            held.theirs,
            neighbour.theirs
        );
        println!(
            "  a shift from 0x{:04X} to 0x{:04X} is reported",
            pair[0], pair[1]
        );
    }
    assert_eq!(tables.symbol, "pyxlsb2.ptgs.function_names");
}
