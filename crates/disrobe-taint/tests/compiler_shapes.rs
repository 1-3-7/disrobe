#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_nir::{
    NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, SourceRef, SymbolKind,
};
use disrobe_taint::{
    ConstantPointers, TaintConfig, TaintReport, analyze, analyze_with_constant_pointers,
};

const CALLEE_ADDR: u64 = 0x100;
const CALLER_ADDR: u64 = 0x200;
const SINK_ADDR: u64 = 0x300;
const CONSTANT_ACTION_ADDR: u64 = 0x400;
const FGETS_THUNK: u64 = 0xA000;
const SYSTEM_THUNK: u64 = 0xB000;
const UNNAMED_TARGET: u64 = 0xC000;
const STRNCAT_THUNK: u64 = 0xD000;
const REFPTR_SLOT: u64 = 0x4370;
const VTABLE: u64 = 0x5000;

fn instr(address: u64, op: NirOp, mnemonic: &str, operands: &[&str]) -> NirInstr {
    NirInstr {
        address,
        op,
        mnemonic: mnemonic.to_owned(),
        operands: operands
            .iter()
            .map(|value: &&str| (*value).to_owned())
            .collect(),
        reads_memory: false,
        writes_memory: false,
        byte_width: false,
        source: SourceRef::new(SourceLang::NativeX86, address),
    }
}

fn load(address: u64, destination: &str, memory: &str) -> NirInstr {
    instr(address, NirOp::Load, "mov", &[destination, memory])
}

fn store(address: u64, memory: &str, value: &str) -> NirInstr {
    instr(address, NirOp::Store, "mov", &[memory, value])
}

fn lea(address: u64, destination: &str, memory: &str) -> NirInstr {
    instr(address, NirOp::Load, "lea", &[destination, memory])
}

fn copy(address: u64, destination: &str, value: &str) -> NirInstr {
    instr(address, NirOp::Nop, "mov", &[destination, value])
}

fn push(address: u64, register: &str) -> NirInstr {
    instr(address, NirOp::Nop, "push", &[register])
}

fn call_extern(address: u64, symbol: &str, operands: &[&str]) -> NirInstr {
    instr(
        address,
        NirOp::ExternCall {
            symbol: symbol.to_owned(),
        },
        "call",
        operands,
    )
}

fn call_address(address: u64, target: u64) -> NirInstr {
    instr(
        address,
        NirOp::Call {
            target: Some(target),
        },
        "call",
        &[],
    )
}

fn ret(address: u64) -> NirInstr {
    instr(address, NirOp::Return, "ret", &[])
}

fn function(name: &str, address: u64, instructions: Vec<NirInstr>) -> NirFunction {
    NirFunction {
        name: name.to_owned(),
        address,
        end: address + 0x80,
        is_export: address == CALLER_ADDR,
        instructions,
        source: SourceRef::new(SourceLang::NativeX86, address),
    }
}

fn module(functions: Vec<NirFunction>) -> NirModule {
    let mut symbols: Vec<NirSymbol> = functions
        .iter()
        .map(|function: &NirFunction| NirSymbol {
            address: function.address,
            name: function.name.clone(),
            kind: SymbolKind::Function,
        })
        .collect();
    for (address, name) in [
        (FGETS_THUNK, "fgets"),
        (SYSTEM_THUNK, "system"),
        (STRNCAT_THUNK, "strncat"),
    ] {
        symbols.push(NirSymbol {
            address,
            name: name.to_owned(),
            kind: SymbolKind::Import,
        });
    }
    NirModule {
        source_hash: [13u8; 32],
        lang: SourceLang::NativeX86,
        functions,
        symbols,
    }
}

fn console_config() -> TaintConfig {
    TaintConfig::from_lists(["fgets"], ["system"])
}

fn environment_config() -> TaintConfig {
    TaintConfig::from_lists(["getenv"], ["system"])
}

fn tail_call_module(jump_target: u64) -> NirModule {
    let wrapper: NirFunction = function(
        "run_through_tail_call",
        SINK_ADDR,
        vec![
            load(SINK_ADDR, "rcx", "[rcx]"),
            instr(
                0x303,
                NirOp::Branch {
                    target: Some(jump_target),
                },
                "jmp",
                &[&format!("{jump_target:016X}h")],
            ),
        ],
    );
    let caller: NirFunction = function(
        "call_tail_wrapper",
        CALLER_ADDR,
        vec![
            lea(CALLER_ADDR, "rcx", "[rsp+30h]"),
            store(0x205, "[rsp+28h]", "rcx"),
            call_extern(0x20a, "fgets", &[]),
            lea(0x20f, "rcx", "[rsp+28h]"),
            call_address(0x214, SINK_ADDR),
            ret(0x219),
        ],
    );
    module(vec![wrapper, caller])
}

#[test]
fn a_jump_out_of_the_function_into_an_import_thunk_is_a_call_to_that_import() {
    let report: TaintReport = analyze(&tail_call_module(SYSTEM_THUNK), &console_config());
    assert!(
        report.flow_in("call_tail_wrapper", "fgets", "run_through_tail_call"),
        "the wrapper loads the data pointer and tail-jumps into the system thunk, so its caller's \
         buffer reaches system: {report:?}"
    );

    let severed: TaintReport = analyze(&tail_call_module(UNNAMED_TARGET), &console_config());
    assert!(
        severed.is_empty(),
        "a jump to an address no import names is not a call to system: {severed:?}"
    );
}

fn frame_spill_module(spill: &str) -> NirModule {
    let sink: NirFunction = function(
        "run_through_pointer",
        SINK_ADDR,
        vec![
            load(SINK_ADDR, "rcx", "[rcx]"),
            call_extern(0x303, "system", &["rcx"]),
            ret(0x308),
        ],
    );
    let caller: NirFunction = function(
        "spill_in_large_frame",
        CALLER_ADDR,
        vec![
            push(CALLER_ADDR, "rbp"),
            lea(0x201, "rbp", "[rsp+80h]"),
            call_extern(0x209, "getenv", &[]),
            store(0x20e, spill, "rax"),
            lea(0x212, "rcx", "[rbp-8]"),
            call_address(0x216, SINK_ADDR),
            ret(0x21b),
        ],
    );
    module(vec![sink, caller])
}

#[test]
fn a_frame_pointer_set_from_the_stack_pointer_keeps_frame_cells_under_one_name() {
    let report: TaintReport = analyze(&frame_spill_module("[rbp-8]"), &environment_config());
    assert!(
        report.flow_in("spill_in_large_frame", "getenv", "run_through_pointer"),
        "a large frame addresses its locals from rbp after lea rbp,[rsp+80h]; the spilled getenv \
         result and the address handed to the sink name the same frame cell: {report:?}"
    );

    let severed: TaintReport = analyze(&frame_spill_module("[rbp-10h]"), &environment_config());
    assert!(
        severed.is_empty(),
        "spilling into a different frame cell leaves the passed cell clean: {severed:?}"
    );
}

fn compared_cell_module(compare: NirInstr) -> NirModule {
    let caller: NirFunction = function(
        "compare_spilled_value",
        CALLER_ADDR,
        vec![
            call_extern(CALLER_ADDR, "getenv", &[]),
            store(0x205, "[rsp+28h]", "rax"),
            compare,
            load(0x210, "rcx", "[rsp+28h]"),
            call_extern(0x215, "system", &["rcx"]),
            ret(0x21a),
        ],
    );
    module(vec![caller])
}

#[test]
fn comparing_a_memory_cell_reads_it_without_overwriting_it() {
    let report: TaintReport = analyze(
        &compared_cell_module(instr(0x20a, NirOp::Load, "cmp", &["qword [rsp+28h]", "0"])),
        &environment_config(),
    );
    assert!(
        report.flow_in("compare_spilled_value", "getenv", "system"),
        "cmp only sets flags, so the spilled environment pointer is still in the cell: {report:?}"
    );

    let severed: TaintReport = analyze(
        &compared_cell_module(store(0x20a, "qword [rsp+28h]", "0")),
        &environment_config(),
    );
    assert!(
        severed.is_empty(),
        "a real store of zero into the cell does replace the pointer: {severed:?}"
    );
}

fn spilled_function_pointer_module(target: &str) -> NirModule {
    let runner: NirFunction = function(
        "run_received",
        SINK_ADDR,
        vec![call_extern(SINK_ADDR, "system", &["rcx"]), ret(0x305)],
    );
    let constant: NirFunction = function(
        "run_constant",
        CONSTANT_ACTION_ADDR,
        vec![
            lea(CONSTANT_ACTION_ADDR, "rcx", "[rel 6000h]"),
            call_extern(0x407, "system", &["rcx"]),
            ret(0x40c),
        ],
    );
    let caller: NirFunction = function(
        "call_through_spilled_pointer",
        CALLER_ADDR,
        vec![
            lea(CALLER_ADDR, "rax", target),
            store(0x207, "[rsp+28h]", "rax"),
            lea(0x20c, "rcx", "[rsp+30h]"),
            call_extern(0x211, "fgets", &[]),
            lea(0x216, "rcx", "[rsp+30h]"),
            load(0x21b, "rdx", "[rsp+28h]"),
            instr(0x220, NirOp::IndirectCall, "call", &["rdx"]),
            ret(0x222),
        ],
    );
    module(vec![runner, constant, caller])
}

#[test]
fn a_call_through_a_function_pointer_kept_in_a_stack_cell_reaches_the_stored_function() {
    let report: TaintReport = analyze(
        &spilled_function_pointer_module("[rel 300h]"),
        &console_config(),
    );
    assert!(
        report.flow_in("call_through_spilled_pointer", "fgets", "run_received"),
        "unoptimized code spills the function pointer to the stack and calls through a reload of \
         it, so the call lands on the stored function with the tainted buffer: {report:?}"
    );

    let severed: TaintReport = analyze(
        &spilled_function_pointer_module("[rel 400h]"),
        &console_config(),
    );
    assert!(
        severed.is_empty(),
        "a stored function that ignores its argument must not report the buffer: {severed:?}"
    );
}

fn vtable_offset_module(adjust: &str) -> NirModule {
    let method: NirFunction = function(
        "overriding_action",
        SINK_ADDR,
        vec![
            copy(SINK_ADDR, "rcx", "rdx"),
            call_extern(0x303, "system", &["rcx"]),
            ret(0x308),
        ],
    );
    let caller: NirFunction = function(
        "dispatch_through_refptr",
        CALLER_ADDR,
        vec![
            lea(CALLER_ADDR, "rcx", "[rsp+30h]"),
            call_extern(0x205, "fgets", &[]),
            load(0x20a, "rax", "[rel 4370h]"),
            instr(
                0x211,
                NirOp::BinOp {
                    op: disrobe_nir::BinaryOp::Add,
                },
                "add",
                &["rax", adjust],
            ),
            store(0x215, "[rsp+40h]", "rax"),
            load(0x21a, "rax", "[rsp+40h]"),
            load(0x21f, "r8", "[rax]"),
            lea(0x222, "rdx", "[rsp+30h]"),
            lea(0x227, "rcx", "[rsp+40h]"),
            instr(0x22c, NirOp::IndirectCall, "call", &["r8"]),
            ret(0x22f),
        ],
    );
    module(vec![method, caller])
}

#[test]
fn adding_a_constant_to_a_vtable_pointer_selects_the_slot_at_that_offset() {
    let pointers: ConstantPointers = ConstantPointers::new()
        .with_slot(REFPTR_SLOT, VTABLE)
        .with_slot(VTABLE + 0x10, SINK_ADDR);
    let report: TaintReport = analyze_with_constant_pointers(
        &vtable_offset_module("10h"),
        &console_config(),
        &[],
        &pointers,
    );
    assert!(
        report.flow_in("dispatch_through_refptr", "fgets", "overriding_action"),
        "the inlined constructor stores the vtable address plus 16 into the object and the call \
         reads the first method slot through it: {report:?}"
    );

    let severed: TaintReport = analyze_with_constant_pointers(
        &vtable_offset_module("8"),
        &console_config(),
        &[],
        &pointers,
    );
    assert!(
        severed.is_empty(),
        "a vtable pointer advanced by 8 reads a slot that names no method: {severed:?}"
    );
}

fn heap_object_module(allocator: &str) -> NirModule {
    let constructor: NirFunction = function(
        "store_command",
        CALLEE_ADDR,
        vec![store(CALLEE_ADDR, "[rcx]", "rdx"), ret(0x103)],
    );
    let destructor: NirFunction = function(
        "run_stored_command",
        SINK_ADDR,
        vec![
            load(SINK_ADDR, "rcx", "[rcx]"),
            call_extern(0x303, "system", &["rcx"]),
            ret(0x308),
        ],
    );
    let caller: NirFunction = function(
        "construct_on_heap",
        CALLER_ADDR,
        vec![
            call_extern(CALLER_ADDR, allocator, &[]),
            copy(0x205, "rbx", "rax"),
            copy(0x208, "rcx", "rax"),
            lea(0x20b, "rdx", "[rsp+30h]"),
            call_address(0x210, CALLEE_ADDR),
            lea(0x215, "rcx", "[rsp+30h]"),
            call_extern(0x21a, "fgets", &[]),
            copy(0x21f, "rcx", "rbx"),
            call_address(0x222, SINK_ADDR),
            ret(0x227),
        ],
    );
    module(vec![constructor, destructor, caller])
}

#[test]
fn an_allocated_object_carries_the_pointer_its_constructor_stores() {
    let report: TaintReport = analyze(&heap_object_module("_Znwy"), &console_config());
    assert!(
        report.flow_in("construct_on_heap", "fgets", "run_stored_command"),
        "operator new returns a fresh object, the constructor stores the buffer pointer into it \
         and the destructor reads it back: {report:?}"
    );

    let severed: TaintReport = analyze(&heap_object_module("rand"), &console_config());
    assert!(
        severed.is_empty(),
        "a call that does not allocate returns no object for the constructor to fill: {severed:?}"
    );
}

fn callee_saved_buffer_module(prologue: Vec<NirInstr>) -> NirModule {
    let mut instructions: Vec<NirInstr> = prologue;
    instructions.extend([
        lea(0x204, "rsi", "[rsp+30h]"),
        call_extern(0x209, "strlen", &["rsi"]),
        copy(0x20e, "rcx", "rsi"),
        call_extern(0x211, "fgets", &[]),
        copy(0x216, "rcx", "rsi"),
        call_extern(0x219, "system", &["rcx"]),
        ret(0x21e),
    ]);
    module(vec![function(
        "keep_buffer_in_rsi",
        CALLER_ADDR,
        instructions,
    )])
}

fn constant_command_module(prologue: Vec<NirInstr>) -> NirModule {
    let mut instructions: Vec<NirInstr> = prologue;
    instructions.extend([
        lea(0x204, "rdi", "[rsp+30h]"),
        lea(0x209, "rcx", "[rsp+30h]"),
        call_address(0x20e, FGETS_THUNK),
        lea(0x213, "rcx", "[rel 6000h]"),
        call_address(0x21a, SYSTEM_THUNK),
        ret(0x21f),
    ]);
    module(vec![function(
        "run_constant_command",
        CALLER_ADDR,
        instructions,
    )])
}

#[test]
fn a_prologue_that_saves_rsi_keeps_rsi_across_calls_and_out_of_the_argument_list() {
    let report: TaintReport = analyze(
        &callee_saved_buffer_module(vec![push(CALLER_ADDR, "rsi")]),
        &console_config(),
    );
    assert!(
        report.flow_in("keep_buffer_in_rsi", "fgets", "system"),
        "a function that saves rsi is Win64 code, where rsi survives strlen and still addresses \
         the buffer fgets fills: {report:?}"
    );
    let unknown: TaintReport = analyze(
        &callee_saved_buffer_module(vec![push(CALLER_ADDR, "rbx")]),
        &console_config(),
    );
    assert!(
        unknown.is_empty(),
        "without that evidence rsi may be a System V argument register that strlen clobbers: \
         {unknown:?}"
    );

    let clean: TaintReport = analyze(
        &constant_command_module(vec![push(CALLER_ADDR, "rsi")]),
        &console_config(),
    );
    assert!(
        clean.is_empty(),
        "under Win64 system reads only rcx, which holds a constant command, so the buffer address \
         left in rdi is not an argument: {clean:?}"
    );
    let ambiguous: TaintReport = analyze(
        &constant_command_module(vec![push(CALLER_ADDR, "rbx")]),
        &console_config(),
    );
    assert!(
        ambiguous.flow_in("run_constant_command", "fgets", "system"),
        "without Win64 evidence rdi stays a possible System V argument of both calls: \
         {ambiguous:?}"
    );
}

fn caller_buffer_module(fill_through: NirInstr) -> NirModule {
    let reader: NirFunction = function(
        "read_into",
        CALLEE_ADDR,
        vec![
            copy(CALLEE_ADDR, "rbx", "rcx"),
            call_extern(0x103, "strlen", &["rcx"]),
            fill_through,
            call_extern(0x10b, "fgets", &[]),
            ret(0x110),
        ],
    );
    let caller: NirFunction = function(
        "fill_then_run",
        CALLER_ADDR,
        vec![
            lea(CALLER_ADDR, "rcx", "[rsp+30h]"),
            call_address(0x205, CALLEE_ADDR),
            lea(0x20a, "rcx", "[rsp+30h]"),
            call_extern(0x20f, "system", &["rcx"]),
            ret(0x214),
        ],
    );
    module(vec![reader, caller])
}

#[test]
fn a_callee_that_reads_into_its_pointer_argument_fills_the_callers_buffer() {
    let report: TaintReport = analyze(
        &caller_buffer_module(copy(0x108, "rcx", "rbx")),
        &console_config(),
    );
    assert!(
        report.flow_in("fill_then_run", "read_into", "system"),
        "the callee keeps its buffer argument in rbx across strlen and reads input through it, so \
         the caller's buffer holds the input afterwards: {report:?}"
    );

    let severed: TaintReport = analyze(
        &caller_buffer_module(lea(0x108, "rcx", "[rsp+8]")),
        &console_config(),
    );
    assert!(
        severed.is_empty(),
        "a callee that reads into its own stack buffer leaves the caller's buffer clean: \
         {severed:?}"
    );
}

fn copy_result_module(routine: &str) -> NirModule {
    let caller: NirFunction = function(
        "use_copy_result",
        CALLER_ADDR,
        vec![
            lea(CALLER_ADDR, "rcx", "[rsp+30h]"),
            lea(0x205, "rdx", "[rel 6000h]"),
            call_extern(0x20c, routine, &[]),
            copy(0x211, "rbx", "rax"),
            lea(0x214, "rcx", "[rsp+30h]"),
            call_extern(0x219, "fgets", &[]),
            copy(0x21e, "rcx", "rbx"),
            call_extern(0x221, "system", &["rcx"]),
            ret(0x226),
        ],
    );
    module(vec![caller])
}

#[test]
fn a_copy_routine_returns_its_destination_buffer() {
    let report: TaintReport = analyze(&copy_result_module("strcpy"), &console_config());
    assert!(
        report.flow_in("use_copy_result", "fgets", "system"),
        "strcpy returns the destination pointer, and that buffer is later filled from input: \
         {report:?}"
    );

    let severed: TaintReport = analyze(&copy_result_module("strlen"), &console_config());
    assert!(
        severed.is_empty(),
        "strlen returns a length, not the buffer: {severed:?}"
    );
}

fn binop(address: u64, op: disrobe_nir::BinaryOp, mnemonic: &str, operands: &[&str]) -> NirInstr {
    instr(address, NirOp::BinOp { op }, mnemonic, operands)
}

fn zeroed_register_module(clear: NirInstr) -> NirModule {
    let caller: NirFunction = function(
        "clear_buffer_register",
        CALLER_ADDR,
        vec![
            lea(CALLER_ADDR, "rcx", "[rsp+30h]"),
            call_extern(0x205, "fgets", &[]),
            lea(0x20a, "rcx", "[rsp+30h]"),
            clear,
            call_extern(0x211, "system", &["rcx"]),
            ret(0x216),
        ],
    );
    module(vec![caller])
}

#[test]
fn zeroing_a_register_drops_the_buffer_it_pointed_at() {
    let report: TaintReport = analyze(
        &zeroed_register_module(binop(
            0x20f,
            disrobe_nir::BinaryOp::Xor,
            "xor",
            &["ecx", "ecx"],
        )),
        &console_config(),
    );
    assert!(
        report.is_empty(),
        "xor ecx,ecx leaves a zero in rcx, not the buffer address: {report:?}"
    );

    let kept: TaintReport = analyze(
        &zeroed_register_module(binop(
            0x20f,
            disrobe_nir::BinaryOp::Add,
            "add",
            &["rcx", "0"],
        )),
        &console_config(),
    );
    assert!(
        kept.flow_in("clear_buffer_register", "fgets", "system"),
        "adding zero keeps the buffer address in rcx: {kept:?}"
    );
}

fn rsi_reader_module(prologue: &str) -> NirModule {
    let reader: NirFunction = function(
        "read_through_rsi",
        SINK_ADDR,
        vec![
            push(SINK_ADDR, prologue),
            load(0x301, "rcx", "[rsi]"),
            call_extern(0x304, "system", &["rcx"]),
            ret(0x309),
        ],
    );
    let caller: NirFunction = function(
        "leave_pointer_in_rsi",
        CALLER_ADDR,
        vec![
            lea(CALLER_ADDR, "rcx", "[rsp+30h]"),
            store(0x205, "[rsp+28h]", "rcx"),
            call_extern(0x20a, "fgets", &[]),
            lea(0x20f, "rsi", "[rsp+28h]"),
            call_address(0x214, SINK_ADDR),
            ret(0x219),
        ],
    );
    module(vec![reader, caller])
}

#[test]
fn a_win64_callee_never_reads_a_parameter_from_rsi() {
    let report: TaintReport = analyze(&rsi_reader_module("rsi"), &console_config());
    assert!(
        report.is_empty(),
        "Win64 passes no parameter in rsi, so the callee's read through rsi is not a read of \
         anything its caller handed over: {report:?}"
    );

    let ambiguous: TaintReport = analyze(&rsi_reader_module("rbx"), &console_config());
    assert!(
        ambiguous.flow_in("leave_pointer_in_rsi", "fgets", "read_through_rsi"),
        "without Win64 evidence rsi may carry the System V second argument: {ambiguous:?}"
    );
}

fn copy_from_parameter_module(before_copy: NirInstr) -> NirModule {
    let callee: NirFunction = function(
        "copy_parameter_and_run",
        SINK_ADDR,
        vec![
            before_copy,
            lea(0x303, "rcx", "[rsp+30h]"),
            call_extern(0x308, "strcpy", &[]),
            lea(0x30d, "rcx", "[rsp+30h]"),
            call_extern(0x312, "system", &["rcx"]),
            ret(0x317),
        ],
    );
    let caller: NirFunction = function(
        "pass_input_as_second_argument",
        CALLER_ADDR,
        vec![
            lea(CALLER_ADDR, "rcx", "[rsp+30h]"),
            call_extern(0x205, "fgets", &[]),
            lea(0x20a, "rdx", "[rsp+30h]"),
            binop(0x20f, disrobe_nir::BinaryOp::Xor, "xor", &["ecx", "ecx"]),
            call_address(0x211, SINK_ADDR),
            ret(0x216),
        ],
    );
    module(vec![callee, caller])
}

#[test]
fn a_copy_reads_a_parameter_the_callee_never_touched_before_the_call() {
    let report: TaintReport = analyze(
        &copy_from_parameter_module(instr(0x300, NirOp::Nop, "nop", &[])),
        &console_config(),
    );
    assert!(
        report.flow_in(
            "pass_input_as_second_argument",
            "fgets",
            "copy_parameter_and_run"
        ),
        "the callee copies its untouched second parameter into a local buffer and runs it: \
         {report:?}"
    );

    let severed: TaintReport = analyze(
        &copy_from_parameter_module(binop(
            0x300,
            disrobe_nir::BinaryOp::Xor,
            "xor",
            &["edx", "edx"],
        )),
        &console_config(),
    );
    assert!(
        severed.is_empty(),
        "a callee that zeroes rdx before the copy copies from no buffer: {severed:?}"
    );
}

fn tail_copy_module(last: NirInstr) -> NirModule {
    let appender: NirFunction = function(
        "append_by_tail_call",
        CALLEE_ADDR,
        vec![
            copy(CALLEE_ADDR, "rbx", "rcx"),
            call_extern(0x103, "getenv", &[]),
            copy(0x108, "rcx", "rbx"),
            copy(0x10b, "rdx", "rax"),
            last,
        ],
    );
    let caller: NirFunction = function(
        "run_after_tail_copy",
        CALLER_ADDR,
        vec![
            lea(CALLER_ADDR, "rcx", "[rsp+30h]"),
            call_address(0x205, CALLEE_ADDR),
            lea(0x20a, "rcx", "[rsp+30h]"),
            call_extern(0x20f, "system", &["rcx"]),
            ret(0x214),
        ],
    );
    module(vec![appender, caller])
}

#[test]
fn a_tail_call_into_a_copy_routine_exports_what_the_copy_writes() {
    let report: TaintReport = analyze(
        &tail_copy_module(instr(
            0x10e,
            NirOp::Branch {
                target: Some(STRNCAT_THUNK),
            },
            "jmp",
            &["000000000000D000h"],
        )),
        &environment_config(),
    );
    assert!(
        report.flow_in("run_after_tail_copy", "append_by_tail_call", "system"),
        "the callee ends by jumping into strncat with its buffer argument as the destination, so \
         its caller's buffer holds the environment string afterwards: {report:?}"
    );

    let severed: TaintReport = analyze(&tail_copy_module(ret(0x10e)), &environment_config());
    assert!(
        severed.is_empty(),
        "returning without the copy leaves the caller's buffer clean: {severed:?}"
    );
}
