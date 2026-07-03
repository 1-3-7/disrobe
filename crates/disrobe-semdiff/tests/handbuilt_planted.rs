use disrobe_nir::{BinaryOp, NirFunction, NirInstr, NirModule, NirOp, SourceLang, SourceRef};
use disrobe_semdiff::{ChangeKind, FunctionChange, SemanticDiff, diff};

const fn instr(address: u64, op: NirOp) -> NirInstr {
    NirInstr {
        address,
        op,
        mnemonic: String::new(),
        operands: Vec::new(),
        reads_memory: false,
        writes_memory: false,
        byte_width: false,
        source: SourceRef::new(SourceLang::NativeX86, address),
    }
}

fn function(name: &str, address: u64, ops: Vec<NirOp>) -> NirFunction {
    let instructions: Vec<NirInstr> = ops
        .into_iter()
        .enumerate()
        .map(|(i, op): (usize, NirOp)| instr(address + i as u64, op))
        .collect();
    let end: u64 = address + instructions.len() as u64;
    NirFunction {
        name: name.to_owned(),
        address,
        end,
        is_export: true,
        instructions,
        source: SourceRef::new(SourceLang::NativeX86, address),
    }
}

fn three_function_module(middle_op: BinaryOp, base: u64) -> NirModule {
    NirModule {
        source_hash: [0u8; 32],
        lang: SourceLang::NativeX86,
        functions: vec![
            function(
                "alpha",
                base,
                vec![NirOp::Load, NirOp::Store, NirOp::Return],
            ),
            function(
                "beta",
                base + 0x100,
                vec![NirOp::BinOp { op: middle_op }, NirOp::Return],
            ),
            function("gamma", base + 0x200, vec![NirOp::Const, NirOp::Return]),
        ],
        symbols: Vec::new(),
    }
}

fn duplicate_named_module(name: &str, first: Vec<NirOp>, second: Vec<NirOp>) -> NirModule {
    NirModule {
        source_hash: [0u8; 32],
        lang: SourceLang::NativeX86,
        functions: vec![
            function(name, 0x1000, first),
            function(name, 0x2000, second),
        ],
        symbols: Vec::new(),
    }
}

fn internal_call_module(target: u64) -> NirModule {
    NirModule {
        source_hash: [0u8; 32],
        lang: SourceLang::NativeX86,
        functions: vec![
            function(
                "caller",
                0x1000,
                vec![
                    NirOp::Call {
                        target: Some(target),
                    },
                    NirOp::Return,
                ],
            ),
            function("alpha", 0x2000, vec![NirOp::Return]),
            function("beta", 0x3000, vec![NirOp::Return]),
        ],
        symbols: Vec::new(),
    }
}

#[test]
fn identical_modules_diff_to_nothing() {
    let base: NirModule = three_function_module(BinaryOp::Xor, 0x1000);
    let other: NirModule = three_function_module(BinaryOp::Xor, 0x1000);
    let report: SemanticDiff = diff(&base, &other);
    assert!(report.is_empty());
}

#[test]
fn rebased_addresses_alone_diff_to_nothing() {
    let base: NirModule = three_function_module(BinaryOp::Xor, 0x1000);
    let rebased: NirModule = three_function_module(BinaryOp::Xor, 0x40000);
    let report: SemanticDiff = diff(&base, &rebased);
    assert!(
        report.is_empty(),
        "the fingerprint is relocation-invariant: {report:?}"
    );
}

#[test]
fn duplicate_empty_function_names_report_the_changed_occurrence() {
    let base: NirModule = duplicate_named_module(
        "",
        vec![NirOp::Load, NirOp::Return],
        vec![NirOp::Const, NirOp::Return],
    );
    let other: NirModule = duplicate_named_module(
        "",
        vec![NirOp::BinOp { op: BinaryOp::Xor }, NirOp::Return],
        vec![NirOp::Const, NirOp::Return],
    );
    let report: SemanticDiff = diff(&base, &other);
    assert_eq!(report.count(), 1);
    let change: &FunctionChange = &report.changes()[0];
    assert_eq!(change.function, "<unnamed>#1");
    assert_eq!(change.kind, ChangeKind::Changed);
}

#[test]
fn single_empty_function_name_reports_as_unnamed() {
    let base: NirModule = NirModule {
        source_hash: [0u8; 32],
        lang: SourceLang::NativeX86,
        functions: vec![function("", 0x1000, vec![NirOp::Load, NirOp::Return])],
        symbols: Vec::new(),
    };
    let other: NirModule = NirModule {
        source_hash: [0u8; 32],
        lang: SourceLang::NativeX86,
        functions: vec![function(
            "",
            0x1000,
            vec![NirOp::BinOp { op: BinaryOp::Xor }, NirOp::Return],
        )],
        symbols: Vec::new(),
    };
    let report: SemanticDiff = diff(&base, &other);
    assert_eq!(report.count(), 1);
    let change: &FunctionChange = &report.changes()[0];
    assert_eq!(change.function, "<unnamed>");
    assert_eq!(change.kind, ChangeKind::Changed);
}

#[test]
fn duplicate_nonempty_function_names_report_the_changed_occurrence() {
    let base: NirModule = duplicate_named_module(
        "dup",
        vec![NirOp::Load, NirOp::Return],
        vec![NirOp::Const, NirOp::Return],
    );
    let other: NirModule = duplicate_named_module(
        "dup",
        vec![NirOp::Load, NirOp::Return],
        vec![NirOp::BinOp { op: BinaryOp::Xor }, NirOp::Return],
    );
    let report: SemanticDiff = diff(&base, &other);
    assert_eq!(report.count(), 1);
    let change: &FunctionChange = &report.changes()[0];
    assert_eq!(change.function, "dup#2");
    assert_eq!(change.kind, ChangeKind::Changed);
}

#[test]
fn changing_one_functions_operator_flags_only_that_function() {
    let base: NirModule = three_function_module(BinaryOp::Xor, 0x1000);
    let other: NirModule = three_function_module(BinaryOp::Add, 0x1000);
    let report: SemanticDiff = diff(&base, &other);
    let changed: Vec<&str> = report.changed().collect();
    assert_eq!(changed, vec!["beta"], "only beta's operator changed");
    assert!(!report.affects("alpha"));
    assert!(!report.affects("gamma"));
}

#[test]
fn internal_call_target_changes_without_symbols_are_reported() {
    let base: NirModule = internal_call_module(0x2000);
    let other: NirModule = internal_call_module(0x3000);
    let report: SemanticDiff = diff(&base, &other);
    let changed: Vec<&str> = report.changed().collect();
    assert_eq!(changed, vec!["caller"]);
    assert!(!report.affects("alpha"));
    assert!(!report.affects("beta"));
}

#[test]
fn a_removed_function_is_reported_as_removed() {
    let mut base: NirModule = three_function_module(BinaryOp::Xor, 0x1000);
    let other: NirModule = three_function_module(BinaryOp::Xor, 0x1000);
    base.functions
        .push(function("delta", 0x1300, vec![NirOp::Return]));
    let report: SemanticDiff = diff(&base, &other);
    assert_eq!(report.count(), 1);
    let change: &FunctionChange = &report.changes()[0];
    assert_eq!(change.function, "delta");
    assert_eq!(change.kind, ChangeKind::Removed);
}

#[test]
fn an_added_function_is_reported_as_added() {
    let base: NirModule = three_function_module(BinaryOp::Xor, 0x1000);
    let mut other: NirModule = three_function_module(BinaryOp::Xor, 0x1000);
    other
        .functions
        .push(function("epsilon", 0x1300, vec![NirOp::Return]));
    let report: SemanticDiff = diff(&base, &other);
    assert_eq!(report.count(), 1);
    let change: &FunctionChange = &report.changes()[0];
    assert_eq!(change.function, "epsilon");
    assert_eq!(change.kind, ChangeKind::Added);
}
