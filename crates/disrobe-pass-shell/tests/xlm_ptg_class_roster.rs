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

use std::collections::BTreeSet;

use disrobe_pass_shell::xlm::biff::{iter_biff8, read_u16};
use disrobe_pass_shell::xlm::container::{XlmSource, open_source};
use disrobe_pass_shell::xlm::ptg::{BiffVersion, PtgContext, token_base_codes};
use disrobe_pass_shell::xlm::scope::XtiScope;
use xlm_reference::{Manifest, manifest, pinned_fixture_bytes};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Coverage {
    CommittedWorkbook,
    ConstructedWorkbook(&'static str),
    Uncovered(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Detector {
    Codes(&'static [u8]),
    AttrGrbits(&'static [u8]),
}

#[derive(Debug, Clone, Copy)]
struct PtgEntry {
    name: &'static str,
    detector: Detector,
    coverage: Coverage,
}

const PTG_SPACE: [PtgEntry; 24] = [
    PtgEntry {
        name: "tExp (shared-formula host)",
        detector: Detector::Codes(&[0x01]),
        coverage: Coverage::CommittedWorkbook,
    },
    PtgEntry {
        name: "tTbl (data-table host)",
        detector: Detector::Codes(&[0x02]),
        coverage: Coverage::ConstructedWorkbook(
            "xlm_fixtures.rs's ptg_tbl_alone_refuses_rather_than_inventing_a_data_table_formula \
             proves a lone tTbl host is refused rather than decoded as a value; no committed \
             workbook carries a TABLE record, matching the record-space roster's TABLE entry",
        ),
    },
    PtgEntry {
        name: "operand literals (ptgStr, ptgErr, ptgBool, ptgInt, ptgNum)",
        detector: Detector::Codes(&[0x17, 0x1C, 0x1D, 0x1E, 0x1F]),
        coverage: Coverage::CommittedWorkbook,
    },
    PtgEntry {
        name: "operators (a binary operator, both unary signs, percent, paren, ptgMissArg)",
        detector: Detector::Codes(&[0x03, 0x12, 0x13, 0x14, 0x15, 0x16]),
        coverage: Coverage::CommittedWorkbook,
    },
    PtgEntry {
        name: "ptgArray (inline array constant)",
        detector: Detector::Codes(&[0x20]),
        coverage: Coverage::CommittedWorkbook,
    },
    PtgEntry {
        name: "ptgFunc (fixed-arity function call)",
        detector: Detector::Codes(&[0x21]),
        coverage: Coverage::CommittedWorkbook,
    },
    PtgEntry {
        name: "ptgFuncVar (variable-argument-count function call)",
        detector: Detector::Codes(&[0x22]),
        coverage: Coverage::CommittedWorkbook,
    },
    PtgEntry {
        name: "ptgName (defined-name reference)",
        detector: Detector::Codes(&[0x23]),
        coverage: Coverage::CommittedWorkbook,
    },
    PtgEntry {
        name: "ptgRef and ptgArea (in-sheet cell and range reference)",
        detector: Detector::Codes(&[0x24, 0x25]),
        coverage: Coverage::CommittedWorkbook,
    },
    PtgEntry {
        name: "ptgMemArea (area-scope memoization)",
        detector: Detector::Codes(&[0x26]),
        coverage: Coverage::CommittedWorkbook,
    },
    PtgEntry {
        name: "ptgMemErr (area-scope memoization, error form)",
        detector: Detector::Codes(&[0x27]),
        coverage: Coverage::Uncovered(
            "the decoder skips this token's fixed-size body without interpreting it, the same as \
             ptgMemArea, but no committed workbook and no fixture constructs one",
        ),
    },
    PtgEntry {
        name: "ptgMemNoMem (area-scope memoization, no-memory form)",
        detector: Detector::Codes(&[0x28]),
        coverage: Coverage::Uncovered(
            "the decoder shares ptgMemArea's byte-skip for this opcode, but no committed workbook \
             and no fixture carries the distinct 0x28 byte",
        ),
    },
    PtgEntry {
        name: "ptgMemFunc (function-scope memoization)",
        detector: Detector::Codes(&[0x29]),
        coverage: Coverage::Uncovered(
            "no committed workbook's FORMULA or SHRFMLA record carries this opcode and no fixture \
             constructs one; Excel emits it around a function call over a memoized area argument, \
             a shape absent from the current corpus",
        ),
    },
    PtgEntry {
        name: "ptgRefErr and ptgAreaErr (broken in-sheet reference)",
        detector: Detector::Codes(&[0x2A, 0x2B]),
        coverage: Coverage::ConstructedWorkbook(
            "xlm_fixtures.rs's ptg_ref_err_and_area_err_always_render_as_ref_error decodes both to \
             #REF! from a hand-built token",
        ),
    },
    PtgEntry {
        name: "ptgRefN and ptgAreaN (shared-formula relative reference)",
        detector: Detector::Codes(&[0x2C, 0x2D]),
        coverage: Coverage::ConstructedWorkbook(
            "xlm_fixtures.rs's biff8_ptg_refn_negative_row_offset_resolves_absolute, \
             biff8_ptg_refn_negative_column_offset_resolves_absolute and \
             xls_shared_formula_relative_recovers_absolute_refs drive ptgRefN, and \
             biff8_ptg_arean_relative_offset_resolves_absolute_range drives ptgAreaN; the \
             committed corpus's one shared formula does not itself resolve through either",
        ),
    },
    PtgEntry {
        name: "ptgNameX (external or cross-workbook name reference)",
        detector: Detector::Codes(&[0x39]),
        coverage: Coverage::CommittedWorkbook,
    },
    PtgEntry {
        name: "ptgRef3d and ptgArea3d (cross-sheet 3D reference)",
        detector: Detector::Codes(&[0x3A, 0x3B]),
        coverage: Coverage::CommittedWorkbook,
    },
    PtgEntry {
        name: "ptgRefErr3d and ptgAreaErr3d (broken 3D reference)",
        detector: Detector::Codes(&[0x3C, 0x3D]),
        coverage: Coverage::ConstructedWorkbook(
            "xlm_fixtures.rs's ptg_ref_err3d_never_resolves_its_reserved_bytes_as_a_location and \
             ptg_area_err3d_never_resolves_its_reserved_bytes_as_a_range decode both to #REF!, \
             each proved in both BIFF8 and BIFF12 byte widths; these tokens carry no location, and \
             xlm/ptg.rs used to misdecode them as a live relative 3D reference, which it now \
             refuses to do",
        ),
    },
    PtgEntry {
        name: "ptgAttr, SUM subtype",
        detector: Detector::AttrGrbits(&[0x10]),
        coverage: Coverage::CommittedWorkbook,
    },
    PtgEntry {
        name: "ptgAttr, IF subtype",
        detector: Detector::AttrGrbits(&[0x02]),
        coverage: Coverage::CommittedWorkbook,
    },
    PtgEntry {
        name: "ptgAttr, GOTO subtype",
        detector: Detector::AttrGrbits(&[0x08]),
        coverage: Coverage::CommittedWorkbook,
    },
    PtgEntry {
        name: "ptgAttr, CHOOSE subtype",
        detector: Detector::AttrGrbits(&[0x04]),
        coverage: Coverage::ConstructedWorkbook(
            "xlm_fixtures.rs's ptg_attr_choose_skips_its_jump_table_without_corrupting_the_stack \
             proves the jump table is skipped without leaking into the decoded value",
        ),
    },
    PtgEntry {
        name: "ptgAttr, SPACE subtype",
        detector: Detector::AttrGrbits(&[0x40]),
        coverage: Coverage::ConstructedWorkbook(
            "xlm_fixtures.rs's \
             ptg_attr_space_is_skipped_as_a_formatting_marker_not_pushed_onto_the_stack proves the \
             formatting marker never turns a value unknown",
        ),
    },
    PtgEntry {
        name: "\"ptgSpread\"",
        detector: Detector::Codes(&[0xFF]),
        coverage: Coverage::Uncovered(
            "no token by this name exists in xlm/ptg.rs's dispatch, in pyxlsb2.ptgs's class list, \
             or in XLMMacroDeobfuscator's source; real_xlm_ptgspread.xls is named for the breadth \
             of forms it carries in one workbook, not for a single token, and each of those forms \
             (ptgArea, ptgNum, ptgErr, ptgArray, percent, unary plus, and the union and \
             intersection operators) is tracked under its own entry in this roster",
        ),
    },
];

const REC_FORMULA: u16 = 0x0006;
const REC_SHRFMLA: u16 = 0x04BC;
const FORMULA_CCE_AT: usize = 20;
const SHRFMLA_CCE_AT: usize = 8;
const ATTR_BYTE: u8 = 0x19;
const PTG_INT: u8 = 0x1E;
const PTG_MEM_FUNC: u8 = 0x29;

fn workbook_stream(data: &[u8]) -> Option<Vec<u8>> {
    match open_source(data)? {
        XlmSource::Biff8 { workbook } => Some(workbook),
        XlmSource::Biff12 { .. } => None,
    }
}

fn split_rgce(body: &[u8], cce_at: usize) -> Option<(Vec<u8>, Vec<u8>)> {
    let cce: usize = usize::from(read_u16(body, cce_at)?);
    let start: usize = cce_at.checked_add(2)?;
    let end: usize = start.checked_add(cce)?;
    let rgce: &[u8] = body.get(start..end)?;
    let rgcb: &[u8] = body.get(end..).unwrap_or_default();
    Some((rgce.to_vec(), rgcb.to_vec()))
}

fn ptg_context() -> (Vec<String>, XtiScope) {
    (Vec::new(), XtiScope::default())
}

struct Present {
    codes: BTreeSet<(u8, String)>,
    attr_grbits: BTreeSet<(u8, String)>,
}

fn scan_workbooks(catalog: &Manifest) -> Present {
    let (names, scope): (Vec<String>, XtiScope) = ptg_context();
    let ctx: PtgContext<'_> = PtgContext {
        version: BiffVersion::Biff8,
        base_row: 0,
        base_col: 0,
        names: &names,
        scope: &scope,
    };
    let mut codes: BTreeSet<(u8, String)> = BTreeSet::new();
    let mut attr_grbits: BTreeSet<(u8, String)> = BTreeSet::new();
    for fixture in &catalog.fixtures {
        let data: Vec<u8> = pinned_fixture_bytes(catalog, &fixture.file);
        let Some(stream): Option<Vec<u8>> = workbook_stream(&data) else {
            continue;
        };
        for rec in iter_biff8(&stream) {
            let cce_at: Option<usize> = match u16::try_from(rec.rt).unwrap_or_default() {
                REC_FORMULA => Some(FORMULA_CCE_AT),
                REC_SHRFMLA => Some(SHRFMLA_CCE_AT),
                _ => None,
            };
            let Some(cce_at): Option<usize> = cce_at else {
                continue;
            };
            let Some((rgce, rgcb)): Option<(Vec<u8>, Vec<u8>)> = split_rgce(&rec.data, cce_at)
            else {
                continue;
            };
            for (pos, code) in token_base_codes(&rgce, &rgcb, &ctx) {
                codes.insert((code, fixture.file.clone()));
                if code == ATTR_BYTE
                    && let Some(&grbit) = rgce.get(pos + 1)
                {
                    attr_grbits.insert((grbit, fixture.file.clone()));
                }
            }
        }
    }
    Present { codes, attr_grbits }
}

fn holder(present: &BTreeSet<(u8, String)>, code: u8) -> Option<String> {
    present
        .iter()
        .find(|(found, _file): &&(u8, String)| *found == code)
        .map(|(_found, file): &(u8, String)| file.clone())
}

fn missing_of(present: &BTreeSet<(u8, String)>, codes: &[u8]) -> Vec<u8> {
    codes
        .iter()
        .copied()
        .filter(|code: &u8| holder(present, *code).is_none())
        .collect()
}

fn any_present_of(present: &BTreeSet<(u8, String)>, codes: &[u8]) -> Option<(u8, String)> {
    codes
        .iter()
        .find_map(|&code: &u8| holder(present, code).map(|file: String| (code, file)))
}

#[test]
fn every_declared_ptg_class_is_covered_by_a_workbook_or_states_why_it_is_not() {
    let catalog: Manifest = manifest();
    let present: Present = scan_workbooks(&catalog);

    let mut faults: Vec<String> = Vec::new();
    let mut covered: usize = 0;
    for entry in PTG_SPACE {
        let set: &BTreeSet<(u8, String)> = match entry.detector {
            Detector::Codes(_) => &present.codes,
            Detector::AttrGrbits(_) => &present.attr_grbits,
        };
        let codes: &[u8] = match entry.detector {
            Detector::Codes(codes) | Detector::AttrGrbits(codes) => codes,
        };
        match entry.coverage {
            Coverage::CommittedWorkbook => {
                let missing: Vec<u8> = missing_of(set, codes);
                if missing.is_empty() {
                    covered += 1;
                    println!("  {} is fully carried across {:02X?}", entry.name, codes);
                } else {
                    faults.push(format!(
                        "{} is recorded as carried by a committed workbook and {:02X?} carries \
                         no such token",
                        entry.name, missing
                    ));
                }
            }
            Coverage::ConstructedWorkbook(reason) | Coverage::Uncovered(reason) => {
                if let Some((code, file)) = any_present_of(set, codes) {
                    faults.push(format!(
                        "{} is recorded as absent from the committed workbooks because {reason}, \
                         and {file} now carries 0x{code:02X}, so promote the roster entry",
                        entry.name
                    ));
                }
            }
        }
    }
    assert!(
        faults.is_empty(),
        "{} ptg-class roster disagreement(s):\n{}",
        faults.len(),
        faults.join("\n")
    );
    assert_eq!(
        covered,
        PTG_SPACE
            .iter()
            .filter(|entry: &&PtgEntry| entry.coverage == Coverage::CommittedWorkbook)
            .count()
    );
    println!(
        "\nPTG CLASS SPACE: {covered} of {} declared classes are carried by a committed workbook, \
         and each of the remaining {} states why it is not\n",
        PTG_SPACE.len(),
        PTG_SPACE.len() - covered
    );
}

struct FormulaSite {
    rgce_start: usize,
    rgce: Vec<u8>,
    rgcb: Vec<u8>,
}

fn formula_sites(stream: &[u8]) -> Vec<FormulaSite> {
    let mut out: Vec<FormulaSite> = Vec::new();
    let mut offset: usize = 0;
    while let (Some(rt), Some(cb)) = (read_u16(stream, offset), read_u16(stream, offset + 2)) {
        let body_start: usize = offset + 4;
        let Some(body_end): Option<usize> = body_start.checked_add(usize::from(cb)) else {
            break;
        };
        if body_end > stream.len() {
            break;
        }
        let cce_at: Option<usize> = match rt {
            REC_FORMULA => Some(FORMULA_CCE_AT),
            REC_SHRFMLA => Some(SHRFMLA_CCE_AT),
            _ => None,
        };
        if let Some(cce_at) = cce_at
            && let Some(cce) = read_u16(stream, body_start + cce_at)
        {
            let rgce_start: usize = body_start + cce_at + 2;
            let rgce_end: usize = rgce_start + usize::from(cce);
            if rgce_end <= body_end {
                out.push(FormulaSite {
                    rgce_start,
                    rgce: stream[rgce_start..rgce_end].to_vec(),
                    rgcb: stream[rgce_end..body_end].to_vec(),
                });
            }
        }
        offset = body_end;
    }
    out
}

fn codes_in(stream: &[u8]) -> BTreeSet<u8> {
    let (names, scope): (Vec<String>, XtiScope) = ptg_context();
    let ctx: PtgContext<'_> = PtgContext {
        version: BiffVersion::Biff8,
        base_row: 0,
        base_col: 0,
        names: &names,
        scope: &scope,
    };
    formula_sites(stream)
        .iter()
        .flat_map(|site: &FormulaSite| token_base_codes(&site.rgce, &site.rgcb, &ctx))
        .map(|(_pos, code): (usize, u8)| code)
        .collect()
}

#[test]
fn the_ptg_walk_reports_a_class_the_roster_calls_absent_once_one_is_planted() {
    let catalog: Manifest = manifest();
    let data: Vec<u8> = pinned_fixture_bytes(&catalog, "real_xlm_excel16.xls");
    let mut stream: Vec<u8> =
        workbook_stream(&data).expect("the committed workbook opens as BIFF8");
    assert!(
        !codes_in(&stream).contains(&PTG_MEM_FUNC),
        "the control must start without a ptgMemFunc token"
    );

    let sites: Vec<FormulaSite> = formula_sites(&stream);
    let mut planted: bool = false;
    for site in &sites {
        if let Some(offset) = site.rgce.iter().position(|byte: &u8| *byte == PTG_INT) {
            stream[site.rgce_start + offset] = PTG_MEM_FUNC;
            planted = true;
            break;
        }
    }
    assert!(planted, "the control must carry a ptgInt token to relabel");

    assert!(
        codes_in(&stream).contains(&PTG_MEM_FUNC),
        "a planted class must reach the ptg walk, or the walk grades nothing"
    );
}
