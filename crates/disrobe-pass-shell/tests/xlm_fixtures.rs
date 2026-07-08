#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::io::{Cursor, Write};

use disrobe_pass_shell::detect::{Dialect, detect};
use disrobe_pass_shell::xlm::ptg::{BiffVersion, PtgContext, decode_rgce};
use disrobe_pass_shell::{XlmRecovery, recover_xlm};

fn record(rt: u16, data: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&rt.to_le_bytes());
    out.extend_from_slice(&(data.len() as u16).to_le_bytes());
    out.extend_from_slice(data);
    out
}

fn bof(dt: u16) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&0x0600u16.to_le_bytes());
    data.extend_from_slice(&dt.to_le_bytes());
    data.extend_from_slice(&0x0DBBu16.to_le_bytes());
    data.extend_from_slice(&0x07CCu16.to_le_bytes());
    data.extend_from_slice(&0x0000_00C1u32.to_le_bytes());
    data.extend_from_slice(&0x0000_0006u32.to_le_bytes());
    record(0x0809, &data)
}

fn eof() -> Vec<u8> {
    record(0x000A, &[])
}

fn boundsheet(lb_ply_pos: u32, name: &str) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&lb_ply_pos.to_le_bytes());
    data.push(0x00);
    data.push(0x01);
    data.push(name.len() as u8);
    data.push(0x00);
    data.extend_from_slice(name.as_bytes());
    record(0x0085, &data)
}

fn formula(row: u16, col: u16, rgce: &[u8]) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&row.to_le_bytes());
    data.extend_from_slice(&col.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&(rgce.len() as u16).to_le_bytes());
    data.extend_from_slice(rgce);
    record(0x0006, &data)
}

fn dimensions() -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&16u32.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    record(0x0200, &data)
}

fn p_int(value: u16) -> Vec<u8> {
    let mut b: Vec<u8> = vec![0x1E];
    b.extend_from_slice(&value.to_le_bytes());
    b
}

fn p_str(text: &str) -> Vec<u8> {
    let mut b: Vec<u8> = vec![0x17, text.chars().count() as u8, 0x00];
    b.extend_from_slice(text.as_bytes());
    b
}

fn p_ref(row: u16, col: u16) -> Vec<u8> {
    let mut b: Vec<u8> = vec![0x24];
    b.extend_from_slice(&row.to_le_bytes());
    let colfield: u16 = (col & 0x3FFF) | 0x4000 | 0x8000;
    b.extend_from_slice(&colfield.to_le_bytes());
    b
}

fn p_func(iftab: u16) -> Vec<u8> {
    let mut b: Vec<u8> = vec![0x21];
    b.extend_from_slice(&iftab.to_le_bytes());
    b
}

fn p_funcvar(cparams: u8, tab: u16, command: bool) -> Vec<u8> {
    let mut b: Vec<u8> = vec![0x22, cparams];
    let field: u16 = (tab & 0x7FFF) | if command { 0x8000 } else { 0 };
    b.extend_from_slice(&field.to_le_bytes());
    b
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    parts
        .iter()
        .flat_map(|p: &&[u8]| p.iter().copied())
        .collect()
}

fn build_workbook_stream() -> Vec<u8> {
    let mut globals: Vec<u8> = Vec::new();
    globals.extend_from_slice(&bof(0x0005));
    globals.extend_from_slice(&record(0x0042, &0x04B0u16.to_le_bytes()));
    let macro_offset: u32 = 0;
    let placeholder: Vec<u8> = boundsheet(macro_offset, "Macro1");
    globals.extend_from_slice(&placeholder);
    globals.extend_from_slice(&eof());

    let boundsheet_pos: usize = bof(0x0005).len() + record(0x0042, &0x04B0u16.to_le_bytes()).len();
    let lb_ply_pos: u32 = globals.len() as u32;
    let fixed: Vec<u8> = boundsheet(lb_ply_pos, "Macro1");
    globals.splice(boundsheet_pos..boundsheet_pos + placeholder.len(), fixed);

    let formulas: [(u16, Vec<u8>); 11] = [
        (
            0,
            concat(&[&p_str("calc.exe"), &p_funcvar(1, 0x006E, false)]),
        ),
        (1, p_funcvar(0, 0x0036, false)),
        (
            2,
            concat(&[&p_int(1), &p_int(2), &p_int(3), &[0x05], &[0x03]]),
        ),
        (3, concat(&[&p_ref(0, 0), &p_str("x"), &[0x08]])),
        (4, concat(&[&p_ref(0, 0), &p_funcvar(1, 0x0011, true)])),
        (
            5,
            concat(&[&p_str("=1+1"), &p_ref(6, 0), &p_funcvar(2, 0x0060, true)]),
        ),
        (6, concat(&[&p_int(1), &p_funcvar(1, 0x00BA, false)])),
        (
            7,
            concat(&[
                &p_str("Kernel32"),
                &p_str("Sleep"),
                &p_str("JJ"),
                &p_int(1000),
                &p_funcvar(4, 0x0096, false),
            ]),
        ),
        (8, concat(&[&p_ref(2, 0), &p_func(0x0014)])),
        (9, concat(&[&p_ref(2, 0), &[0x13]])),
        (
            10,
            concat(&[&p_int(1), &p_int(2), &[0x03], &[0x15], &p_int(3), &[0x05]]),
        ),
    ];

    let mut sheet: Vec<u8> = Vec::new();
    sheet.extend_from_slice(&bof(0x0040));
    sheet.extend_from_slice(&dimensions());
    for (row, rgce) in &formulas {
        sheet.extend_from_slice(&formula(*row, 0, rgce));
    }
    sheet.extend_from_slice(&eof());

    let mut stream: Vec<u8> = globals;
    stream.extend_from_slice(&sheet);
    stream
}

fn build_xls() -> Vec<u8> {
    let workbook: Vec<u8> = build_workbook_stream();
    let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    let mut comp: cfb::CompoundFile<Cursor<Vec<u8>>> =
        cfb::CompoundFile::create_with_version(cfb::Version::V3, cursor).expect("create cfb");
    {
        let mut stream: cfb::Stream<Cursor<Vec<u8>>> = comp
            .create_stream("Workbook")
            .expect("create workbook stream");
        stream.write_all(&workbook).expect("write workbook");
        stream.flush().expect("flush stream");
    }
    comp.into_inner().into_inner()
}

const EXPECTED: [(&str, &str); 11] = [
    ("A1", "=EXEC(\"calc.exe\")"),
    ("A2", "=HALT()"),
    ("A3", "=1+2*3"),
    ("A4", "=A1&\"x\""),
    ("A5", "=RUN(A1)"),
    ("A6", "=FORMULA(\"=1+1\",A7)"),
    ("A7", "=GET.WORKSPACE(1)"),
    ("A8", "=CALL(\"Kernel32\",\"Sleep\",\"JJ\",1000)"),
    ("A9", "=SQRT(A3)"),
    ("A10", "=-A3"),
    ("A11", "=(1+2)*3"),
];

#[test]
fn xls_macro_sheet_detects_as_xlm() {
    let xls: Vec<u8> = build_xls();
    assert_eq!(detect(&xls).dialect, Dialect::Xlm);
}

#[test]
fn xls_macro_sheet_recovers_expected_formulas() {
    let xls: Vec<u8> = build_xls();
    let report: XlmRecovery = recover_xlm(&xls).expect("recover xlm");
    assert!(report.has_macro_sheet(), "must flag a macro sheet");
    let sheet: &disrobe_pass_shell::XlmSheet = report
        .sheets
        .iter()
        .find(|s: &&disrobe_pass_shell::XlmSheet| s.kind == "macro")
        .expect("macro sheet present");
    assert_eq!(sheet.name, "Macro1");
    assert_eq!(sheet.cells.len(), EXPECTED.len());
    for ((cell, formula), actual) in EXPECTED.iter().zip(&sheet.cells) {
        assert_eq!(&actual.cell, cell, "cell address mismatch");
        assert_eq!(&actual.formula, formula, "formula text mismatch at {cell}");
        assert!(
            !actual.unknown,
            "cell {cell} flagged unknown: {}",
            actual.formula
        );
    }
}

#[test]
fn unrecognized_ptg_yields_marker_not_a_guess() {
    let ctx: PtgContext<'_> = PtgContext {
        version: BiffVersion::Biff8,
        base_row: 0,
        base_col: 0,
        names: &[],
    };
    let rgce: [u8; 4] = [0x1E, 0x05, 0x00, 0x7F];
    let decoded: disrobe_pass_shell::xlm::ptg::DecodedFormula = decode_rgce(&rgce, &ctx);
    assert!(
        decoded.unknown,
        "must not fabricate a formula for an unknown token"
    );
    assert!(decoded.text.contains("[[xlm-unknown-token]]"));
}

#[test]
fn biff12_ref_uses_four_byte_row() {
    let ctx: PtgContext<'_> = PtgContext {
        version: BiffVersion::Biff12,
        base_row: 0,
        base_col: 0,
        names: &[],
    };
    let mut rgce: Vec<u8> = vec![0x44];
    rgce.extend_from_slice(&4u32.to_le_bytes());
    rgce.extend_from_slice(&0xC001u16.to_le_bytes());
    rgce.extend_from_slice(&[0x1E, 0x02, 0x00]);
    rgce.push(0x05);
    rgce.extend_from_slice(&[0x21, 0x14, 0x00]);
    let decoded: disrobe_pass_shell::xlm::ptg::DecodedFormula = decode_rgce(&rgce, &ctx);
    assert!(
        !decoded.unknown,
        "biff12 decode should not be unknown: {}",
        decoded.text
    );
    assert_eq!(decoded.text, "SQRT(B5*2)");
}

#[test]
fn mutated_xls_never_panics() {
    use std::panic::{self, AssertUnwindSafe};

    panic::set_hook(Box::new(|_info: &panic::PanicHookInfo<'_>| {}));
    let base: Vec<u8> = build_xls();
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = |bound: usize| -> usize {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        if bound == 0 {
            0
        } else {
            (state % bound as u64) as usize
        }
    };
    for _ in 0..20_000 {
        let mut buf: Vec<u8> = base.clone();
        let flips: usize = next(24) + 1;
        for _ in 0..flips {
            if buf.is_empty() {
                break;
            }
            let idx: usize = next(buf.len());
            buf[idx] = (next(256)) as u8;
        }
        if next(3) == 0 {
            buf.truncate(next(buf.len() + 1));
        }
        let result: Result<(), Box<dyn std::any::Any + Send>> =
            panic::catch_unwind(AssertUnwindSafe(|| {
                let _ = recover_xlm(&buf);
                let _ = detect(&buf);
            }));
        assert!(result.is_ok(), "recover_xlm panicked on a mutated workbook");
    }
}

#[test]
fn dump_fixture_when_requested() {
    if let Ok(path) = std::env::var("XLM_FIXTURE_OUT") {
        std::fs::write(&path, build_xls()).expect("write fixture");
    }
}
