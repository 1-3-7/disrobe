#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::uninlined_format_args,
    clippy::case_sensitive_file_extension_comparisons
)]

use std::path::{Path, PathBuf};

use disrobe_pass_mobile::{
    Arm64Disassembly, Arm64FlowKind, Arm64Function, DartKernel, DartKernelDecompile, KernelClass,
    KernelProcedure, decompile_dart_kernel, disassemble_libapp_so, parse_dart_kernel,
    parse_libapp_so,
};

fn sample_dir() -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("flutter")
        .join("disrobe_sample")
}

fn read_sample(name: &str) -> Vec<u8> {
    let path: PathBuf = sample_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "self-authored sample {} must be committed: {e}",
            path.display()
        )
    })
}

fn original_source() -> String {
    String::from_utf8(read_sample("disrobe_aot_sample.dart")).expect("source is utf-8")
}

fn find_class<'a>(kernel: &'a DartKernel, name: &str) -> &'a KernelClass {
    kernel
        .libraries
        .iter()
        .flat_map(|l| l.classes.iter())
        .find(|c: &&KernelClass| c.name == name)
        .unwrap_or_else(|| panic!("kernel must recover class {name}"))
}

fn top_level<'a>(kernel: &'a DartKernel, name: &str) -> &'a KernelProcedure {
    kernel
        .libraries
        .iter()
        .flat_map(|l| l.procedures.iter())
        .find(|p: &&KernelProcedure| p.name == name)
        .unwrap_or_else(|| panic!("kernel must recover top-level function {name}"))
}

#[test]
fn kernel_recovers_known_class_and_method_names() {
    let bytes: Vec<u8> = read_sample("disrobe_aot_sample.app.dill");
    let kernel: DartKernel = parse_dart_kernel(&bytes).expect("parse real app kernel");

    assert_eq!(kernel.format_version, 130, "app kernel formatVersion");
    assert!(kernel.string_count >= 80, "string table fully recovered");

    let inventory: &KernelClass = find_class(&kernel, "InventoryItem");
    let warehouse: &KernelClass = find_class(&kernel, "WarehouseLedger");

    let inv_methods: Vec<&str> = inventory
        .procedures
        .iter()
        .map(|p: &KernelProcedure| p.name.as_str())
        .collect::<Vec<&str>>();
    for expected in ["extendedValue", "isBackordered", "withRestock"] {
        assert!(
            inv_methods.contains(&expected),
            "InventoryItem must recover method {expected}, got {inv_methods:?}"
        );
    }

    let wh_methods: Vec<&str> = warehouse
        .procedures
        .iter()
        .map(|p: &KernelProcedure| p.name.as_str())
        .collect::<Vec<&str>>();
    for expected in ["totalCarryingValue", "countBackordered", "mostValuable"] {
        assert!(
            wh_methods.contains(&expected),
            "WarehouseLedger must recover method {expected}, got {wh_methods:?}"
        );
    }

    assert!(
        inventory.fields.contains(&"skuLabel".to_owned())
            && inventory.fields.contains(&"quantityOnHand".to_owned())
            && inventory.fields.contains(&"unitPriceUsd".to_owned()),
        "InventoryItem must recover its three fields, got {:?}",
        inventory.fields
    );

    for fname in ["fibonacciStep", "classifyMagnitude", "main"] {
        let _ = top_level(&kernel, fname);
    }

    eprintln!(
        "disrobe_sample kernel recovery: format_version={} strings={} classes={} procedures={} fields={} bodies_recovered={}",
        kernel.format_version,
        kernel.string_count,
        kernel.class_count,
        kernel.procedure_count,
        kernel.field_count,
        kernel.bodies_recovered
    );
}

#[test]
fn kernel_recovers_byte_exact_function_bodies() {
    let bytes: Vec<u8> = read_sample("disrobe_aot_sample.app.dill");
    let kernel: DartKernel = parse_dart_kernel(&bytes).expect("parse kernel");
    let original: String = original_source();

    let fib: &KernelProcedure = top_level(&kernel, "fibonacciStep");
    let fib_src: &str = fib
        .recovered_source
        .as_deref()
        .expect("fibonacciStep body must be recovered from the kernel source table");
    assert!(
        original.contains(fib_src),
        "recovered fibonacciStep body must be a verbatim substring of the original source, got:\n{fib_src}"
    );
    assert!(
        fib_src.contains("int fibonacciStep(int depth)")
            && fib_src.contains("return fibonacciStep(depth - 1) + fibonacciStep(depth - 2)"),
        "fibonacciStep body must contain its real signature and recursive return, got:\n{fib_src}"
    );

    let classify: &KernelProcedure = top_level(&kernel, "classifyMagnitude");
    let classify_src: &str = classify
        .recovered_source
        .as_deref()
        .expect("classifyMagnitude body recovered");
    assert!(original.contains(classify_src));
    for literal in ["enterprise-tier", "mid-market-tier", "starter-tier"] {
        assert!(
            classify_src.contains(literal),
            "classifyMagnitude must recover literal {literal}, got:\n{classify_src}"
        );
    }

    let bodies: usize = kernel.bodies_recovered;
    assert!(
        bodies >= 3,
        "at least the three top-level functions must have recovered bodies, got {bodies}"
    );

    let decompile: DartKernelDecompile = decompile_dart_kernel(&bytes).expect("decompile kernel");
    assert!(
        decompile.recovered_source.contains("class InventoryItem"),
        "whole-program source recovery must include the InventoryItem class declaration"
    );
    assert!(
        decompile
            .recovered_source
            .contains("double totalCarryingValue()"),
        "whole-program source recovery must include WarehouseLedger.totalCarryingValue signature"
    );
}

#[test]
fn arm64_aot_disassembles_to_real_instructions() {
    let bytes: Vec<u8> = read_sample("libapp_arm64.so");

    assert_eq!(&bytes[..4], &[0x7f, b'E', b'L', b'F'], "must be ELF");
    let e_machine: u16 = u16::from_le_bytes([bytes[18], bytes[19]]);
    assert_eq!(e_machine, 0xb7, "must be AArch64 (e_machine 0xB7)");

    let layout = parse_libapp_so(&bytes).expect("parse arm64 libapp.so");
    assert!(
        layout.isolate_snapshot_instructions.is_some(),
        "real ARM64 AOT must expose _kDartIsolateSnapshotInstructions"
    );

    let disasm: Arm64Disassembly = disassemble_libapp_so(&bytes).expect("disassemble arm64 aot");
    assert!(
        disasm.function_count > 100,
        "a real Dart AOT image holds thousands of functions, got {}",
        disasm.function_count
    );
    assert!(
        disasm.total_instructions > 1000,
        "ARM64 disasm must decode thousands of real instructions, got {}",
        disasm.total_instructions
    );

    let mut saw_stp: bool = false;
    let mut saw_ret: bool = false;
    let mut saw_call: bool = false;
    let mut saw_branch: bool = false;
    let mut bad: usize = 0;
    let mut total: usize = 0;
    for func in &disasm.functions {
        for insn in &func.instructions {
            total += 1;
            if insn.flow == Arm64FlowKind::DecodeError {
                bad += 1;
                continue;
            }
            if insn.text.starts_with("stp") {
                saw_stp = true;
            }
            if insn.flow == Arm64FlowKind::Return {
                saw_ret = true;
            }
            if insn.flow == Arm64FlowKind::DirectCall && insn.branch_target.is_some() {
                saw_call = true;
            }
            if matches!(
                insn.flow,
                Arm64FlowKind::DirectBranch | Arm64FlowKind::ConditionalBranch
            ) && insn.branch_target.is_some()
            {
                saw_branch = true;
            }
        }
    }
    assert!(saw_stp, "must decode the stp fp,lr frame-setup mnemonic");
    assert!(saw_ret, "must decode ret terminators");
    assert!(saw_call, "must resolve at least one direct bl call target");
    assert!(
        saw_branch,
        "must resolve at least one direct/conditional branch target"
    );

    let bad_ratio: f64 = bad as f64 / total.max(1) as f64;
    assert!(
        bad_ratio < 0.25,
        "decode-error ratio {bad_ratio:.3} too high; the parser is misframing real ARM64 code"
    );

    let listed: &Arm64Function = disasm
        .functions
        .iter()
        .find(|f: &&Arm64Function| f.instructions.len() >= 4 && f.ends_in_return)
        .expect("at least one well-formed function with a return");
    let listing: String = listed.to_listing();
    assert!(
        listing.lines().count() >= 5,
        "function listing must render a header plus instruction lines"
    );

    eprintln!(
        "disrobe_sample ARM64 AOT disasm: functions={} instructions={} decode_errors={} ({:.2}%) saw[stp={} ret={} call={} branch={}]",
        disasm.function_count,
        disasm.total_instructions,
        bad,
        bad_ratio * 100.0,
        saw_stp,
        saw_ret,
        saw_call,
        saw_branch
    );
    eprintln!("--- sample recovered ARM64 listing ---\n{}", {
        let mut head: String = String::new();
        for line in listing.lines().take(12) {
            head.push_str(line);
            head.push('\n');
        }
        head
    });
}

#[test]
fn arm64_boundaries_resolve_exact_dart_code_symbol_names() {
    use disrobe_pass_mobile::{
        Arm64Function, DartNameSource, DartProgramSkeleton, DartRecoveredFunction,
        DartSnapshotStructure, LibAppLayout, build_dart_program_skeleton, decompile_libapp_so,
        decompile_libapp_so_structured,
    };

    let bytes: Vec<u8> = read_sample("libapp_arm64.so");
    let layout: LibAppLayout = parse_libapp_so(&bytes).expect("parse libapp layout");

    let recovery = decompile_libapp_so(&bytes).expect("decompile arm64 names");
    assert!(
        recovery
            .method_names
            .iter()
            .any(|m| m.scrubbed == "fibonacciStep"),
        "the string pool must carry the real method name fibonacciStep"
    );
    let fib_symbol = layout
        .function_symbols
        .iter()
        .find(|s| s.name == "fibonacciStep")
        .expect("the real AOT ELF symtab must carry fibonacciStep");
    assert!(
        layout
            .function_symbols
            .iter()
            .any(|s| s.name == "WarehouseLedger.mostValuable"),
        "the real AOT ELF symtab must carry WarehouseLedger.mostValuable"
    );

    let structure: DartSnapshotStructure =
        decompile_libapp_so_structured(&bytes).expect("structured recovery");
    let function_total: usize = structure.functions.len();
    assert!(
        function_total > 100,
        "the real AOT image yields thousands of prologue boundaries, got {function_total}"
    );
    assert!(structure.named_function_count > 0);
    assert!(
        structure.unresolved_function_count < function_total,
        "exact code-symbol matches must reduce unresolved functions"
    );
    assert!(
        structure.function_names_recoverable,
        "the structure must report that exact symtab-backed function names are recoverable"
    );
    let fib: &DartRecoveredFunction = structure
        .functions
        .iter()
        .find(|f: &&DartRecoveredFunction| f.offset == fib_symbol.offset)
        .expect("fibonacciStep boundary must exist");
    assert_eq!(fib.name.as_deref(), Some("fibonacciStep"));
    assert_eq!(fib.name_source, DartNameSource::CodeObjectCluster);
    let most_valuable: &DartRecoveredFunction = structure
        .functions
        .iter()
        .find(|f: &&DartRecoveredFunction| {
            f.name.as_deref() == Some("WarehouseLedger.mostValuable")
        })
        .expect("WarehouseLedger.mostValuable must be keyed by exact offset");
    assert_eq!(most_valuable.name_source, DartNameSource::CodeObjectCluster);
    assert!(
        structure
            .functions
            .iter()
            .any(|f: &DartRecoveredFunction| f.name.is_none()),
        "unmatched prologue boundaries must remain unresolved instead of guessed"
    );

    let static_recovery = recovery;
    let skeleton: DartProgramSkeleton = build_dart_program_skeleton(&static_recovery);
    assert_eq!(
        skeleton.named_function_count, 0,
        "skeleton must not claim any confidently named function"
    );
    for f in &skeleton.functions {
        assert!(
            !f.name_resolved && f.name.starts_with("sub_"),
            "skeleton functions keep an address label, never a zipped Dart name, got {}",
            f.name
        );
    }

    let disasm = disassemble_libapp_so(&bytes).expect("disassemble for naming check");
    let named_in_disasm: usize = disasm
        .functions
        .iter()
        .filter(|f: &&Arm64Function| f.name.is_some())
        .count();
    assert!(
        named_in_disasm > 0,
        "the ARM64 disassembly must attach exact symtab-backed method names"
    );
    assert!(
        disasm
            .functions
            .iter()
            .any(|f: &Arm64Function| f.name.as_deref() == Some("fibonacciStep")),
        "disassembly must carry fibonacciStep on its exact code offset"
    );

    eprintln!(
        "disrobe_sample ARM64 name-keying: boundaries={} confidently_named={} unresolved={} symtab_functions={} string_pool_method_names={}",
        function_total,
        structure.named_function_count,
        structure.unresolved_function_count,
        layout.function_symbols.len(),
        static_recovery.method_names.len(),
    );
}

#[test]
fn code_object_methods_attribute_to_owner_class_from_real_aot() {
    use disrobe_pass_mobile::{
        DartClassEntry, DartMethodEntry, DartSnapshotStructure, decompile_libapp_so_structured,
    };

    let bytes: Vec<u8> = read_sample("libapp_arm64.so");
    let structure: DartSnapshotStructure =
        decompile_libapp_so_structured(&bytes).expect("structured recovery");

    let ledger: &DartClassEntry = structure
        .classes
        .iter()
        .find(|c: &&DartClassEntry| c.name == "WarehouseLedger")
        .expect("WarehouseLedger recovered as a class");
    assert!(
        ledger.code_object_backed,
        "WarehouseLedger must be flagged as backed by real code-object identities"
    );

    let method_names: Vec<&str> = ledger
        .methods
        .iter()
        .map(|m: &DartMethodEntry| m.name.as_str())
        .collect::<Vec<&str>>();
    for expected in ["mostValuable", "countBackordered", "totalCarryingValue"] {
        assert!(
            method_names.contains(&expected),
            "WarehouseLedger.{expected} is a real code object; it must attribute to the class, got {method_names:?}"
        );
    }

    assert!(
        structure.code_object_attributed_class_count > 0
            && structure.code_object_attributed_method_count
                >= structure.code_object_attributed_class_count,
        "the real AOT image attributes hundreds of qualified code objects to their owner classes: classes={} methods={}",
        structure.code_object_attributed_class_count,
        structure.code_object_attributed_method_count
    );

    assert!(
        !structure.class_fields_recoverable && ledger.fields.is_empty(),
        "instance field names are tree-shaken out of the product AOT snapshot (Precompiler::DropFields); \
         recovery must never fabricate them, so fields stay empty and unrecoverable"
    );
    assert!(
        structure
            .recovery_notes
            .iter()
            .any(|n: &String| n.contains("owning class")),
        "the recovery notes must state that code objects carry their owner-class identity"
    );

    eprintln!(
        "disrobe_sample code-object method attribution: attributed_classes={} attributed_methods={} WarehouseLedger.methods={:?}",
        structure.code_object_attributed_class_count,
        structure.code_object_attributed_method_count,
        method_names
    );
}

#[test]
fn arm64_names_survive_in_isolate_data() {
    let bytes: Vec<u8> = read_sample("libapp_arm64.so");
    let recovery = disrobe_pass_mobile::decompile_libapp_so(&bytes).expect("decompile arm64");
    let class_hits: usize = recovery
        .class_names
        .iter()
        .filter(|c: &&String| c.as_str() == "InventoryItem" || c.as_str() == "WarehouseLedger")
        .count();
    assert!(
        class_hits >= 1,
        "at least one of my class names must survive in the ARM64 isolate data string table, got classes sample: {:?}",
        &recovery
            .class_names
            .iter()
            .take(20)
            .collect::<Vec<&String>>()
    );
    eprintln!(
        "disrobe_sample ARM64 name recovery: classes={} methods={} library_uris={} (bodies from machine code are not byte-recoverable; the kernel path recovers them)",
        recovery.class_names.len(),
        recovery.method_names.len(),
        recovery.library_uris.len()
    );
}
