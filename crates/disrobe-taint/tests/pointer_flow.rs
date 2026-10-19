#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_nir::{
    BinaryOp, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, SourceRef, SymbolKind,
};
use disrobe_taint::{
    ConstantPointers, TaintConfig, TaintReport, analyze, analyze_with_constant_pointers,
};

const CALLEE_ADDR: u64 = 0x100;
const CALLER_ADDR: u64 = 0x200;
const SINK_ADDR: u64 = 0x300;
const REFPTR_SLOT: u64 = 0x4370;
const GLOBAL_DATA: u64 = 0x7038;
const OTHER_GLOBAL: u64 = 0x7040;

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

fn call_internal(address: u64, target: u64) -> NirInstr {
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
    let symbols: Vec<NirSymbol> = functions
        .iter()
        .map(|function: &NirFunction| NirSymbol {
            address: function.address,
            name: function.name.clone(),
            kind: SymbolKind::Function,
        })
        .collect();
    NirModule {
        source_hash: [12u8; 32],
        lang: SourceLang::NativeX86,
        functions,
        symbols,
    }
}

fn environment_config() -> TaintConfig {
    TaintConfig::from_lists(["getenv"], ["system"])
}

fn console_config() -> TaintConfig {
    TaintConfig::from_lists(["fgets"], ["system"])
}

fn returning_caller() -> NirFunction {
    function(
        "run_returned_command",
        CALLER_ADDR,
        vec![
            lea(CALLER_ADDR, "rcx", "[rsp+20h]"),
            call_internal(0x208, CALLEE_ADDR),
            copy(0x210, "rcx", "rax"),
            call_extern(0x218, "system", &["rcx"]),
            ret(0x220),
        ],
    )
}

fn appended_in_place_module(copy_routine: &str) -> NirModule {
    let callee: NirFunction = function(
        "append_environment",
        CALLEE_ADDR,
        vec![
            copy(CALLEE_ADDR, "rbx", "rcx"),
            lea(0x104, "rcx", "[rel 5000h]"),
            call_extern(0x10c, "getenv", &[]),
            lea(0x114, "rcx", "[rbx+rsi]"),
            copy(0x118, "rdx", "rax"),
            call_extern(0x11c, copy_routine, &[]),
            copy(0x124, "rax", "rbx"),
            ret(0x128),
        ],
    );
    module(vec![callee, returning_caller()])
}

fn spilled_argument_module(reload: &str) -> NirModule {
    let callee: NirFunction = function(
        "append_to_spilled_argument",
        CALLEE_ADDR,
        vec![
            store(CALLEE_ADDR, "[rsp+30h]", "rcx"),
            lea(0x108, "rcx", "[rel 5000h]"),
            call_extern(0x110, "getenv", &[]),
            load(0x118, "r9", "[rsp+30h]"),
            lea(0x120, "rcx", "[r9+rbx]"),
            copy(0x124, "rdx", "rax"),
            call_extern(0x128, "strncat", &[]),
            load(0x130, "r9", reload),
            copy(0x138, "rax", "r9"),
            ret(0x13c),
        ],
    );
    module(vec![callee, returning_caller()])
}

fn pointer_to_pointer_module(passed_cell: &str) -> NirModule {
    let caller: NirFunction = function(
        "pass_pointer_to_pointer",
        CALLER_ADDR,
        vec![
            lea(CALLER_ADDR, "rcx", "[rsp+30h]"),
            store(0x205, "[rsp+28h]", "rcx"),
            call_extern(0x20a, "strlen", &["rcx"]),
            load(0x20f, "rcx", "[rsp+28h]"),
            instr(
                0x214,
                NirOp::BinOp { op: BinaryOp::Add },
                "add",
                &["rcx", "rbx"],
            ),
            call_extern(0x217, "fgets", &[]),
            lea(0x21c, "rcx", passed_cell),
            call_internal(0x221, SINK_ADDR),
            ret(0x226),
        ],
    );
    let sink: NirFunction = function(
        "sink_through_pointer",
        SINK_ADDR,
        vec![
            load(SINK_ADDR, "rcx", "[rcx]"),
            call_extern(0x303, "system", &["rcx"]),
            ret(0x308),
        ],
    );
    module(vec![caller, sink])
}

fn spilled_parameter_sink_module(reload: &str) -> NirModule {
    let caller: NirFunction = function(
        "pass_pointer_cell",
        CALLER_ADDR,
        vec![
            lea(CALLER_ADDR, "rax", "[rbp-80h]"),
            store(0x204, "[rbp-8]", "rax"),
            load(0x208, "rcx", "[rbp-8]"),
            call_extern(0x20c, "fgets", &[]),
            lea(0x211, "rax", "[rbp-8]"),
            copy(0x215, "rcx", "rax"),
            call_internal(0x218, SINK_ADDR),
            ret(0x21d),
        ],
    );
    let sink: NirFunction = function(
        "sink_through_spilled_parameter",
        SINK_ADDR,
        vec![
            store(SINK_ADDR, "[rbp+10h]", "rcx"),
            load(0x304, "rax", reload),
            load(0x308, "rax", "[rax]"),
            store(0x30b, "[rbp-8]", "rax"),
            load(0x30f, "rax", "[rbp-8]"),
            copy(0x313, "rcx", "rax"),
            call_extern(0x316, "system", &["rcx"]),
            ret(0x31b),
        ],
    );
    module(vec![caller, sink])
}

fn global_pointer_module() -> NirModule {
    let caller: NirFunction = function(
        "publish_through_global",
        CALLER_ADDR,
        vec![
            lea(CALLER_ADDR, "rbx", "[rsp+30h]"),
            copy(0x205, "rcx", "rbx"),
            call_extern(0x208, "fgets", &[]),
            store(0x20d, "[rel 7038h]", "rbx"),
            call_internal(0x214, SINK_ADDR),
            ret(0x219),
        ],
    );
    let sink: NirFunction = function(
        "sink_through_global",
        SINK_ADDR,
        vec![
            load(SINK_ADDR, "rax", "[rel 4370h]"),
            load(0x307, "rcx", "[rax]"),
            call_extern(0x30a, "system", &["rcx"]),
            ret(0x30f),
        ],
    );
    module(vec![caller, sink])
}

fn stale_return_alias_module(between: NirInstr) -> NirModule {
    let caller: NirFunction = function(
        "reuse_return_register",
        CALLER_ADDR,
        vec![
            lea(CALLER_ADDR, "rax", "[rsp+30h]"),
            copy(0x205, "rcx", "rax"),
            call_extern(0x208, "fgets", &[]),
            lea(0x20d, "rax", "[rsp+30h]"),
            between,
            copy(0x217, "rcx", "rax"),
            call_extern(0x21a, "system", &["rcx"]),
            ret(0x21f),
        ],
    );
    module(vec![caller])
}

#[test]
fn a_copy_into_the_argument_buffer_taints_the_pointer_the_callee_returns() {
    let report: TaintReport = analyze(&appended_in_place_module("strncat"), &environment_config());
    assert!(
        report.flow_in("run_returned_command", "append_environment", "system"),
        "strncat appends the environment string into the buffer the callee was handed and the \
         callee returns that same pointer, so the caller's sink must see the callee as a source: \
         {report:?}"
    );

    let severed: TaintReport = analyze(&appended_in_place_module("strlen"), &environment_config());
    assert!(
        severed.is_empty(),
        "a call that only reads the buffer never moves the environment string into it, so the \
         returned pointer must stay clean: {severed:?}"
    );
}

#[test]
fn a_spilled_argument_reloaded_after_the_copy_still_returns_the_tainted_buffer() {
    let report: TaintReport = analyze(&spilled_argument_module("[rsp+30h]"), &environment_config());
    assert!(
        report.flow_in(
            "run_returned_command",
            "append_to_spilled_argument",
            "system"
        ),
        "the callee spills its buffer argument, appends through a reload of that spill, then \
         returns a second reload of it; the returned pointer names the buffer the copy wrote: \
         {report:?}"
    );

    let severed: TaintReport =
        analyze(&spilled_argument_module("[rsp+38h]"), &environment_config());
    assert!(
        severed.is_empty(),
        "returning a value reloaded from a different stack cell returns a pointer that was never \
         shown to name the written buffer: {severed:?}"
    );
}

#[test]
fn a_sink_that_dereferences_a_pointer_to_the_data_pointer_reaches_the_buffer() {
    let report: TaintReport = analyze(&pointer_to_pointer_module("[rsp+28h]"), &console_config());
    assert!(
        report.flow_in("pass_pointer_to_pointer", "fgets", "sink_through_pointer"),
        "the caller keeps its data pointer in a stack cell across a call, reads into the buffer \
         through a reload of that cell, and hands the sink the cell's address; the sink loads the \
         data pointer back out of it, as both the char ** and the void * cast form compile: \
         {report:?}"
    );

    let severed: TaintReport = analyze(&pointer_to_pointer_module("[rsp+38h]"), &console_config());
    assert!(
        severed.is_empty(),
        "handing the sink a cell that never held the data pointer must not reach the buffer: \
         {severed:?}"
    );
}

#[test]
fn a_sink_that_loads_its_parameter_back_from_a_spill_slot_dereferences_the_callers_cell() {
    let report: TaintReport = analyze(
        &spilled_parameter_sink_module("[rbp+10h]"),
        &console_config(),
    );
    assert!(
        report.flow_in(
            "pass_pointer_cell",
            "fgets",
            "sink_through_spilled_parameter"
        ),
        "unoptimized code spills the char ** parameter, reloads it, and dereferences the reload; \
         the dereference must read the cell the caller passed: {report:?}"
    );

    let severed: TaintReport = analyze(
        &spilled_parameter_sink_module("[rbp+18h]"),
        &console_config(),
    );
    assert!(
        severed.is_empty(),
        "dereferencing a reload of a slot that never held the parameter must not reach the \
         caller's buffer: {severed:?}"
    );
}

#[test]
fn a_sink_that_reads_an_external_global_through_its_constant_pointer_slot_reaches_the_buffer() {
    let pointers: ConstantPointers = ConstantPointers::new().with_slot(REFPTR_SLOT, GLOBAL_DATA);
    let report: TaintReport =
        analyze_with_constant_pointers(&global_pointer_module(), &console_config(), &[], &pointers);
    assert!(
        report.flow_in("publish_through_global", "fgets", "sink_through_global"),
        "the caller stores its data pointer in a global, and the sink reaches that global through \
         the read-only slot holding its address, so the sink must read the caller's buffer: \
         {report:?}"
    );

    let unknown: TaintReport = analyze_with_constant_pointers(
        &global_pointer_module(),
        &console_config(),
        &[],
        &ConstantPointers::new(),
    );
    assert!(
        unknown.is_empty(),
        "without the slot's relocated value the load through it names no known global: \
         {unknown:?}"
    );

    let elsewhere: ConstantPointers = ConstantPointers::new().with_slot(REFPTR_SLOT, OTHER_GLOBAL);
    let severed: TaintReport = analyze_with_constant_pointers(
        &global_pointer_module(),
        &console_config(),
        &[],
        &elsewhere,
    );
    assert!(
        severed.is_empty(),
        "a slot that points at a different global must not inherit the caller's pointer: \
         {severed:?}"
    );
}

#[test]
fn a_call_replaces_the_return_register_so_its_earlier_buffer_alias_is_gone() {
    let report: TaintReport = analyze(
        &stale_return_alias_module(call_extern(0x212, "rand", &[])),
        &console_config(),
    );
    assert!(
        report.is_empty(),
        "after the call the return register holds the callee's result, not the address computed \
         before the call: {report:?}"
    );

    let kept: TaintReport = analyze(
        &stale_return_alias_module(instr(0x212, NirOp::Nop, "nop", &[])),
        &console_config(),
    );
    assert!(
        kept.flow_in("reuse_return_register", "fgets", "system"),
        "with no call in between, the register still holds the buffer address the source wrote \
         through: {kept:?}"
    );
}

fn reference_parameter_module(passed_cell: &str) -> NirModule {
    let callee: NirFunction = function(
        "append_through_reference",
        CALLEE_ADDR,
        vec![
            copy(CALLEE_ADDR, "rbx", "rcx"),
            load(0x103, "rcx", "[rcx]"),
            call_extern(0x106, "strlen", &["rcx"]),
            lea(0x10b, "rcx", "[rel 5000h]"),
            call_extern(0x112, "getenv", &[]),
            load(0x117, "rcx", "[rbx]"),
            copy(0x11a, "rdx", "rax"),
            call_extern(0x11d, "strncat", &[]),
            ret(0x122),
        ],
    );
    let caller: NirFunction = function(
        "fill_through_reference",
        CALLER_ADDR,
        vec![
            lea(CALLER_ADDR, "rax", "[rsp+30h]"),
            store(0x205, "[rsp+28h]", "rax"),
            lea(0x20a, "rcx", passed_cell),
            call_internal(0x20f, CALLEE_ADDR),
            load(0x214, "rcx", "[rsp+28h]"),
            call_extern(0x219, "system", &["rcx"]),
            ret(0x21e),
        ],
    );
    module(vec![callee, caller])
}

fn constructor_module(stored_field: &str) -> NirModule {
    let constructor: NirFunction = function(
        "store_command",
        CALLEE_ADDR,
        vec![store(CALLEE_ADDR, stored_field, "rdx"), ret(0x103)],
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
        "construct_and_destroy",
        CALLER_ADDR,
        vec![
            lea(CALLER_ADDR, "rcx", "[rsp+40h]"),
            lea(0x205, "rdx", "[rsp+30h]"),
            call_internal(0x20a, CALLEE_ADDR),
            lea(0x20f, "rcx", "[rsp+30h]"),
            call_extern(0x214, "fgets", &[]),
            lea(0x219, "rcx", "[rsp+40h]"),
            call_internal(0x21e, SINK_ADDR),
            ret(0x223),
        ],
    );
    module(vec![constructor, destructor, caller])
}

const VTABLE_SLOT: u64 = 0x5010;
const CONSTANT_ACTION_ADDR: u64 = 0x400;

fn virtual_dispatch_module() -> NirModule {
    let constructor: NirFunction = function(
        "construct_derived",
        CALLEE_ADDR,
        vec![
            lea(CALLEE_ADDR, "rax", "[rel 5010h]"),
            store(0x107, "[rcx]", "rax"),
            ret(0x10a),
        ],
    );
    let action: NirFunction = function(
        "derived_action",
        SINK_ADDR,
        vec![
            copy(SINK_ADDR, "rcx", "rdx"),
            call_extern(0x303, "system", &["rcx"]),
            ret(0x308),
        ],
    );
    let constant_action: NirFunction = function(
        "constant_action",
        CONSTANT_ACTION_ADDR,
        vec![
            lea(CONSTANT_ACTION_ADDR, "rcx", "[rel 6000h]"),
            call_extern(0x407, "system", &["rcx"]),
            ret(0x40c),
        ],
    );
    let caller: NirFunction = function(
        "dispatch_virtual",
        CALLER_ADDR,
        vec![
            lea(CALLER_ADDR, "rcx", "[rsp+30h]"),
            call_extern(0x205, "fgets", &[]),
            lea(0x20a, "rcx", "[rsp+40h]"),
            call_internal(0x20f, CALLEE_ADDR),
            load(0x214, "rax", "[rsp+40h]"),
            load(0x219, "rax", "[rax]"),
            lea(0x21c, "rdx", "[rsp+30h]"),
            lea(0x221, "rcx", "[rsp+40h]"),
            instr(0x226, NirOp::IndirectCall, "call", &["rax"]),
            ret(0x228),
        ],
    );
    module(vec![constructor, action, constant_action, caller])
}

#[test]
fn a_callee_that_appends_through_a_reference_to_the_data_pointer_fills_the_callers_buffer() {
    let report: TaintReport = analyze(
        &reference_parameter_module("[rsp+28h]"),
        &environment_config(),
    );
    assert!(
        report.flow_in(
            "fill_through_reference",
            "append_through_reference",
            "system"
        ),
        "the callee receives the address of the caller's data pointer, loads the pointer back out \
         of it and appends the environment string through it, so the buffer the caller later hands \
         the sink is the one the callee wrote: {report:?}"
    );

    let severed: TaintReport = analyze(
        &reference_parameter_module("[rsp+38h]"),
        &environment_config(),
    );
    assert!(
        severed.is_empty(),
        "handing the callee a cell that never held the data pointer must leave the caller's buffer \
         untouched: {severed:?}"
    );
}

#[test]
fn a_pointer_a_constructor_stores_into_the_object_is_the_one_its_destructor_reads() {
    let report: TaintReport = analyze(&constructor_module("[rcx]"), &console_config());
    assert!(
        report.flow_in("construct_and_destroy", "fgets", "run_stored_command"),
        "the constructor stores its buffer argument into the object's first field and the \
         destructor passes that field to the sink, so the buffer read into between them reaches \
         it: {report:?}"
    );

    let severed: TaintReport = analyze(&constructor_module("[rcx+8]"), &console_config());
    assert!(
        severed.is_empty(),
        "a constructor that stores the buffer into a different field leaves the field the \
         destructor reads unknown: {severed:?}"
    );
}

#[test]
fn a_virtual_call_through_a_constructor_installed_vtable_reaches_the_overriding_method() {
    let pointers: ConstantPointers = ConstantPointers::new().with_slot(VTABLE_SLOT, SINK_ADDR);
    let report: TaintReport = analyze_with_constant_pointers(
        &virtual_dispatch_module(),
        &console_config(),
        &[],
        &pointers,
    );
    assert!(
        report.flow_in("dispatch_virtual", "fgets", "derived_action"),
        "the constructor installs the vtable pointer, the caller loads the first slot through it \
         and calls it with the tainted buffer, and the relocated slot names the overriding \
         method: {report:?}"
    );

    let unknown: TaintReport = analyze_with_constant_pointers(
        &virtual_dispatch_module(),
        &console_config(),
        &[],
        &ConstantPointers::new(),
    );
    assert!(
        unknown.is_empty(),
        "without the slot's relocated value the call target is unknown: {unknown:?}"
    );

    let other: ConstantPointers =
        ConstantPointers::new().with_slot(VTABLE_SLOT, CONSTANT_ACTION_ADDR);
    let severed: TaintReport =
        analyze_with_constant_pointers(&virtual_dispatch_module(), &console_config(), &[], &other);
    assert!(
        severed.is_empty(),
        "a slot naming a method that ignores its argument must not report the buffer: {severed:?}"
    );
}
