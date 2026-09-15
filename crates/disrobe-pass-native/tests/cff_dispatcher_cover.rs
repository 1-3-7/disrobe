#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_native::stub_emu::cpu::{NoopHost, map_buffer};
use disrobe_pass_native::stub_emu::{Cpu, CpuMode, ExitReason, Perm, Reg};
use disrobe_pass_native::{
    BlockSpan, CffOutcome, CffRecovery, CffStateLoc, DeobfBits, DispatcherCover, StateRegion,
    defeat_cff,
};
use iced_x86::code_asm::{CodeAssembler, CodeLabel};
use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, Instruction, Register};

const BASE: u64 = 0x1000;
const RECOVERED_BASE: u64 = 0x40_0000;
const STACK_BASE: u64 = 0x20_0000;
const STACK_BYTES: u64 = 0x4000;
const RETURN_SENTINEL: u64 = 0x00DE_AD00;
const STEP_BUDGET: u32 = 200_000;

const DIFFERENTIAL_INPUTS: [i32; 15] = [-7, -1, 0, 1, 2, 3, 5, 9, 10, 11, 12, 15, 32, 64, 100];

struct Sample {
    file: &'static str,
    entry_point: &'static str,
    dispatcher_states: u32,
    source: fn(i32) -> i32,
}

const SAMPLES: [Sample; 2] = [
    Sample {
        file: "classify_fla.bin",
        entry_point: "classify",
        dispatcher_states: 4,
        source: classify_from_source,
    },
    Sample {
        file: "sumto_fla.bin",
        entry_point: "sum_to",
        dispatcher_states: 5,
        source: sum_to_from_source,
    },
];

const fn classify_from_source(n: i32) -> i32 {
    if n > 10 {
        n.wrapping_mul(2)
    } else {
        n.wrapping_add(1)
    }
}

const fn sum_to_from_source(n: i32) -> i32 {
    let mut total: i32 = 0;
    let mut i: i32 = 1;
    while i <= n {
        total = total.wrapping_add(i);
        i = i.wrapping_add(1);
    }
    total
}

fn corpus(name: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus");
    path.push("native");
    path.push("ollvm");
    path.push(name);
    path
}

fn read_sample(sample: &Sample) -> Vec<u8> {
    let path: PathBuf = corpus(sample.file);
    std::fs::read(&path).unwrap_or_else(|err: std::io::Error| {
        panic!(
            "git tracks {}, so its absence is a defect in this checkout rather than a fact \
             about this host, and skipping here would print a line nobody reads while the run \
             went green: {err}",
            path.display()
        )
    })
}

fn recover(bytes: &[u8]) -> CffRecovery {
    match defeat_cff(DeobfBits::Bits64, BASE, bytes, BASE) {
        CffOutcome::Recovered(recovery) => *recovery,
        other => panic!("the committed sample must reach a dispatcher recovery, got {other:?}"),
    }
}

fn check_cover(expected_states: u32, cover: &DispatcherCover) -> Result<(), String> {
    let mut faults: Vec<String> = Vec::new();
    if cover.dispatcher_states != expected_states {
        faults.push(format!(
            "the dispatcher exposes {} states, not the {expected_states} this gate is pinned to",
            cover.dispatcher_states
        ));
    }
    for uncovered in &cover.uncovered {
        faults.push(format!(
            "state {:#x} at block {:#x} is not covered: {:?}",
            uncovered.state, uncovered.case_target, uncovered.gap
        ));
    }
    for region in cover.unresolved_transitions() {
        faults.push(format!(
            "state {:#x} has an unresolved transition: {:?}",
            region.state, region.degrade
        ));
    }
    if let Some(violation) = cover.canary {
        faults.push(format!(
            "the recovered edge set fails its check: {violation:?}"
        ));
    }
    if cover.covered_states != cover.dispatcher_states {
        faults.push(format!(
            "cover is {} of {} dispatcher states",
            cover.covered_states, cover.dispatcher_states
        ));
    }
    if faults.is_empty() {
        Ok(())
    } else {
        Err(faults.join("; "))
    }
}

#[test]
fn dispatcher_cover_counts_every_state_the_flattened_dispatcher_can_select() {
    let mut graded: u32 = 0;
    let mut states: u32 = 0;
    for sample in &SAMPLES {
        let bytes: Vec<u8> = read_sample(sample);
        let recovery: CffRecovery = recover(&bytes);
        println!(
            "{}: dispatcher cover {} of {} states, {} blocks placed, state variable {}",
            sample.file,
            recovery.cover.covered_states,
            recovery.cover.dispatcher_states,
            recovery.recovered_block_count,
            recovery.state_loc.render()
        );
        if let Err(why) = check_cover(sample.dispatcher_states, &recovery.cover) {
            panic!(
                "{}: the dispatcher-cover gate is red. The denominator is enumerated from the \
                 flattened program's own compare tree or jump table, so a state the recovery never \
                 places stays in the denominator instead of shrinking it: {why}",
                sample.file
            );
        }
        graded += 1;
        states += recovery.cover.dispatcher_states;
    }
    assert_eq!(
        graded as usize,
        SAMPLES.len(),
        "every committed flattening sample must be graded"
    );
    println!(
        "dispatcher cover graded over {graded} committed functions carrying {states} dispatcher \
         states in total. That population is the whole claim: it says nothing about a function \
         this repository does not commit"
    );
    assert_eq!(states, 9, "the committed population is 9 dispatcher states");
}

fn states_compared_against_by_a_linear_scan(bytes: &[u8], loc: CffStateLoc) -> BTreeSet<u64> {
    let register: Register = state_register(loc);
    let mut decoder: Decoder<'_> = Decoder::with_ip(64, bytes, BASE, DecoderOptions::NONE);
    let mut found: BTreeSet<u64> = BTreeSet::new();
    let mut pending: Option<u64> = None;
    let mut insn: Instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        assert!(
            !insn.is_invalid(),
            "this scan reads the whole sample linearly, and a byte at {:#x} it cannot decode means \
             the scan is no longer an independent count",
            insn.ip()
        );
        let compared: Option<u64> = (insn.mnemonic() == iced_x86::Mnemonic::Cmp
            && insn.op0_kind() == iced_x86::OpKind::Register
            && insn.op0_register() == register)
            .then(|| insn.try_immediate(1).ok())
            .flatten();
        match insn.mnemonic() {
            iced_x86::Mnemonic::Je | iced_x86::Mnemonic::Jne => {
                if let Some(state) = pending.take() {
                    found.insert(state);
                }
            }
            _ => pending = compared,
        }
    }
    found
}

#[test]
fn the_denominator_is_not_the_tree_walk_counting_itself() {
    for sample in &SAMPLES {
        let bytes: Vec<u8> = read_sample(sample);
        let recovery: CffRecovery = recover(&bytes);
        let scanned: BTreeSet<u64> =
            states_compared_against_by_a_linear_scan(&bytes, recovery.state_loc);
        let modelled: BTreeSet<u64> = recovery
            .cover
            .regions
            .iter()
            .map(|region: &StateRegion| region.state)
            .collect();
        println!(
            "{}: a linear scan finds {} states the dispatcher tests for equality, the tree walk \
             models {}",
            sample.file,
            scanned.len(),
            modelled.len()
        );
        assert_eq!(
            modelled, scanned,
            "{}: the denominator comes from walking the dispatcher's compare tree, so a walk that \
             stops early would shrink its own denominator and score higher. This leg counts the \
             same states a second way, by reading every equality compare against the state \
             register out of a linear decode of the whole function, and the two must agree",
            sample.file
        );
        assert_eq!(
            u32::try_from(scanned.len()).expect("state count fits u32"),
            recovery.cover.dispatcher_states,
            "{}: the published denominator must be that same count",
            sample.file
        );
    }
}

#[test]
fn the_cover_reaches_the_chain_sidecar_the_auto_run_writes() {
    use object::write::{Object as WriteObject, StandardSection};
    use object::{Architecture, BinaryFormat, Endianness};

    let bytes: Vec<u8> = read_sample(&SAMPLES[0]);
    let mut object: WriteObject<'_> =
        WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text: object::write::SectionId = object.section_id(StandardSection::Text);
    let _: u64 = object.append_section_data(text, &bytes, 16);
    let image: Vec<u8> = object
        .write()
        .expect("write the elf carrying the flattened function");

    let report: disrobe_pass_native::DeobfReport =
        disrobe_pass_native::pass::analyze_deobf_report(&image)
            .expect("the native pass must produce a report for an image carrying a dispatcher");
    let recovery: &CffRecovery = report
        .cff
        .as_ref()
        .expect("the report must carry the recovery the chain sidecar publishes");
    assert_eq!(
        (
            recovery.cover.covered_states,
            recovery.cover.dispatcher_states
        ),
        (4, 4),
        "the pass that feeds deobf.json must report the same cover the dedicated call does"
    );
    assert!(
        report
            .notes
            .iter()
            .any(|note: &String| note == "dispatcher cover 4 of 4 states"),
        "the text surface must state the cover as a numerator over a denominator: {:?}",
        report.notes
    );

    let json: serde_json::Value =
        serde_json::to_value(&report).expect("the sidecar is written by serializing this report");
    let cover: &serde_json::Value = &json["cff"]["cover"];
    assert_eq!(cover["dispatcher_states"], serde_json::json!(4));
    assert_eq!(cover["covered_states"], serde_json::json!(4));
    assert!(
        cover["uncovered"].is_array() && cover["edges"].is_array() && cover["regions"].is_array(),
        "the JSON surface must carry the per-state detail, not only the two totals: {cover}"
    );
}

const PUBLISHED_BAR: &str = "OLLVM -fla dispatcher states";

fn published(field: &str) -> u64 {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("xtask");
    path.push("data");
    path.push("recovery.json");
    let raw: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()));
    let parsed: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|error: serde_json::Error| panic!("parse {}: {error}", path.display()));
    for group in parsed["groups"].as_array().expect("groups array") {
        for bar in group["bars"].as_array().unwrap_or(&Vec::new()) {
            if bar["label"].as_str() == Some(PUBLISHED_BAR) {
                return bar[field]
                    .as_u64()
                    .unwrap_or_else(|| panic!("the {PUBLISHED_BAR} bar must record {field}"));
            }
        }
    }
    panic!("recovery.json must carry a {PUBLISHED_BAR} bar")
}

#[test]
fn the_published_dispatcher_cover_matches_the_committed_corpus() {
    let mut declared: u64 = 0;
    let mut reached: u64 = 0;
    let mut graded: usize = 0;
    for sample in &SAMPLES {
        let bytes: Vec<u8> = read_sample(sample);
        let recovery: CffRecovery = recover(&bytes);
        declared += u64::from(recovery.cover.dispatcher_states);
        reached += u64::from(recovery.cover.covered_states);
        graded += 1;
    }
    assert_eq!(
        graded,
        SAMPLES.len(),
        "the published figure covers every committed sample, so a missing sample must fail rather \
         than quietly shrink the denominator"
    );
    assert_eq!(
        declared,
        published("detected"),
        "recovery.json publishes a denominator that no longer matches the states the committed \
         dispatchers declare"
    );
    assert_eq!(
        reached,
        published("delivered"),
        "recovery.json publishes a cover that no longer matches what the recovery reaches"
    );
}

#[test]
fn dropping_one_dispatcher_state_turns_the_cover_gate_red_and_names_it() {
    const CLASSIFY_FALLTHROUGH_STATE: u32 = 0x3257_B88B;
    let bytes: Vec<u8> = read_sample(&SAMPLES[0]);
    let clean: CffRecovery = recover(&bytes);
    assert!(
        check_cover(SAMPLES[0].dispatcher_states, &clean.cover).is_ok(),
        "the unmodified sample must be green before the mutant can mean anything"
    );

    let mutant: Vec<u8> = retarget_state_constant(&bytes, CLASSIFY_FALLTHROUGH_STATE, 0x0BAD_0BAD);
    let mutated: CffRecovery = recover(&mutant);
    let Err(why): Result<(), String> = check_cover(SAMPLES[0].dispatcher_states, &mutated.cover)
    else {
        panic!(
            "one dispatcher state is now unreachable, so the gate must go red. It stayed green at \
             {} of {} states, which means it grades nothing",
            mutated.cover.covered_states, mutated.cover.dispatcher_states
        );
    };
    println!("mutant cover gate says: {why}");
    assert!(
        why.contains(&format!("{CLASSIFY_FALLTHROUGH_STATE:#x}")),
        "the red gate must name the state that went missing, got: {why}"
    );
    assert_eq!(
        mutated.cover.covered_states,
        SAMPLES[0].dispatcher_states - 1,
        "exactly one state must drop out: {:?}",
        mutated.cover
    );
    assert!(
        !mutated.fully_recovered,
        "a recovery that reaches 3 of 4 dispatcher states is not full: {:?}",
        mutated.cover
    );
}

fn retarget_state_constant(bytes: &[u8], from: u32, to: u32) -> Vec<u8> {
    let needle: [u8; 4] = from.to_le_bytes();
    let mut out: Vec<u8> = bytes.to_vec();
    let mut patched: u32 = 0;
    let mut offset: usize = 0;
    while let Some(found) = out
        .get(offset..)
        .and_then(|tail: &[u8]| tail.windows(4).position(|w: &[u8]| w == needle))
    {
        let at: usize = offset + found;
        if is_immediate_of_a_state_store(bytes, at) {
            out[at..at + 4].copy_from_slice(&to.to_le_bytes());
            patched += 1;
            break;
        }
        offset = at + 1;
    }
    assert_eq!(
        patched, 1,
        "the mutant must retarget exactly one state store carrying {from:#x}"
    );
    out
}

fn is_immediate_of_a_state_store(bytes: &[u8], at: usize) -> bool {
    let mut decoder: Decoder<'_> = Decoder::with_ip(64, bytes, BASE, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        let start: usize = usize::try_from(insn.ip() - BASE).unwrap_or(usize::MAX);
        if insn.mnemonic() == iced_x86::Mnemonic::Mov && at > start && at + 4 == start + insn.len()
        {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RunOutcome {
    Returned(i32),
    BudgetExhausted,
    Fault(String),
}

fn run_function(bytes: &[u8], base: u64, argument: i32) -> RunOutcome {
    let mut cpu: Cpu = Cpu::new(CpuMode::Bits64);
    if let Err(err) = map_buffer(&mut cpu.mem, base, bytes, Perm::RX) {
        return RunOutcome::Fault(format!("cannot map the code at {base:#x}: {err}"));
    }
    if let Err(err) = cpu.mem.map(STACK_BASE, STACK_BYTES, Perm::RW) {
        return RunOutcome::Fault(format!("cannot map the stack: {err}"));
    }
    let stack_pointer: u64 = STACK_BASE + STACK_BYTES - 0x200;
    if let Err(err) = cpu.mem.write_u64(stack_pointer, RETURN_SENTINEL) {
        return RunOutcome::Fault(format!("cannot seed the return address: {err}"));
    }
    cpu.regs.set(Reg::Rsp, stack_pointer);
    cpu.regs.set(Reg::Rcx, u64::from(argument.cast_unsigned()));
    cpu.regs.rip = base;
    let mut host: NoopHost = NoopHost;
    for _ in 0..STEP_BUDGET {
        if cpu.regs.rip == RETURN_SENTINEL {
            return RunOutcome::Returned(returned_value(&cpu));
        }
        if !cpu.mem.is_mapped(cpu.regs.rip) {
            return RunOutcome::Fault(format!("fetch from unmapped {:#x}", cpu.regs.rip));
        }
        match cpu.run(&mut host, 1) {
            Ok(ExitReason::StepCap(_)) => {}
            Ok(ExitReason::JumpedOutOfRange { to, .. }) if to == RETURN_SENTINEL => {
                return RunOutcome::Returned(returned_value(&cpu));
            }
            Ok(reason) => return RunOutcome::Fault(format!("{reason:?}")),
            Err(err) => return RunOutcome::Fault(format!("{err}")),
        }
    }
    RunOutcome::BudgetExhausted
}

fn returned_value(cpu: &Cpu) -> i32 {
    (cpu.regs.get(Reg::Rax) as u32).cast_signed()
}

fn state_register(loc: CffStateLoc) -> Register {
    match loc {
        CffStateLoc::Reg(raw) => Register::values()
            .find(|register: &Register| *register as u16 == raw)
            .unwrap_or(Register::None),
        CffStateLoc::Mem { .. } => Register::None,
    }
}

fn instructions_in(bytes: &[u8], span: BlockSpan) -> Vec<Instruction> {
    let start: usize = usize::try_from(span.start.saturating_sub(BASE)).unwrap_or(usize::MAX);
    let end: usize = usize::try_from(span.end.saturating_sub(BASE))
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    let Some(window): Option<&[u8]> = bytes.get(start..end) else {
        return Vec::new();
    };
    let mut decoder: Decoder<'_> = Decoder::with_ip(64, window, span.start, DecoderOptions::NONE);
    let mut out: Vec<Instruction> = Vec::new();
    while decoder.can_decode() {
        let insn: Instruction = decoder.decode();
        if insn.is_invalid() {
            break;
        }
        out.push(insn);
    }
    out
}

fn body_of(bytes: &[u8], spans: &[BlockSpan], label: &str) -> Vec<Instruction> {
    let mut body: Vec<Instruction> = Vec::new();
    for span in spans {
        for insn in instructions_in(bytes, *span) {
            match insn.flow_control() {
                FlowControl::UnconditionalBranch | FlowControl::Return => {}
                FlowControl::Next => {
                    assert!(
                        !insn.is_ip_rel_memory_operand(),
                        "{label}: {insn} at {:#x} addresses memory through RIP, so moving it to a \
                         new address changes what it reads. This harness does not relocate that",
                        insn.ip()
                    );
                    body.push(insn);
                }
                other => panic!(
                    "{label}: this emitter only rebuilds straight-line regions, and {other:?} at \
                     {:#x} is not one. A region carrying its own branch needs the branch \
                     retargeted, which this harness does not do",
                    insn.ip()
                ),
            }
        }
    }
    body
}

struct Placer {
    next_ip: u64,
}

impl Placer {
    fn place(&mut self, asm: &mut CodeAssembler, mut insn: Instruction) {
        insn.set_ip(self.next_ip);
        self.next_ip += 16;
        asm.add_instruction(insn).expect("place instruction");
    }
}

fn returns_at_end(bytes: &[u8], spans: &[BlockSpan]) -> bool {
    spans.last().is_some_and(|span: &BlockSpan| {
        instructions_in(bytes, *span)
            .last()
            .is_some_and(|insn: &Instruction| insn.flow_control() == FlowControl::Return)
    })
}

fn emit_recovered(bytes: &[u8], recovery: &CffRecovery) -> Vec<u8> {
    let register: Register = state_register(recovery.state_loc);
    assert_eq!(
        register.size(),
        4,
        "this harness lowers a two-way state select as a 32-bit compare, and the state variable is \
         {register:?}"
    );
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let labels: std::collections::BTreeMap<u64, CodeLabel> = recovery
        .cover
        .covered
        .iter()
        .map(|state: &u64| (*state, asm.create_label()))
        .collect();
    let by_state: std::collections::BTreeMap<u64, &StateRegion> = recovery
        .cover
        .regions
        .iter()
        .map(|region: &StateRegion| (region.state, region))
        .collect();

    let mut placer: Placer = Placer { next_ip: 16 };
    for insn in body_of(bytes, &recovery.cover.prologue, "prologue") {
        placer.place(&mut asm, insn);
    }
    emit_transition(
        &mut asm,
        &mut placer,
        register,
        &recovery.cover.entry_states,
        &labels,
        false,
    );

    for state in &recovery.cover.covered {
        let mut label: CodeLabel = *labels.get(state).expect("label for a covered state");
        asm.set_label(&mut label).expect("set label");
        asm.zero_bytes().expect("anchor the label");
        let region: &&StateRegion = by_state.get(state).expect("region for a covered state");
        for insn in body_of(bytes, &region.blocks, "region") {
            placer.place(&mut asm, insn);
        }
        if returns_at_end(bytes, &region.blocks) {
            asm.ret().expect("region return");
            continue;
        }
        emit_transition(
            &mut asm,
            &mut placer,
            register,
            &region.successors,
            &labels,
            true,
        );
    }
    asm.assemble(RECOVERED_BASE).expect("assemble the recovery")
}

fn emit_transition(
    asm: &mut CodeAssembler,
    placer: &mut Placer,
    register: Register,
    successors: &[u64],
    labels: &std::collections::BTreeMap<u64, CodeLabel>,
    required: bool,
) {
    match successors {
        [] => assert!(
            !required,
            "a region with no successor must have ended in a return"
        ),
        [next] => {
            let target: CodeLabel = *labels.get(next).expect("label for the next state");
            asm.jmp(target).expect("direct edge");
        }
        [taken, fallthrough] => {
            let Ok(narrow): Result<u32, _> = u32::try_from(*taken) else {
                panic!(
                    "state {taken:#x} does not fit the 32-bit state register, so lowering the \
                     select as a 32-bit compare would test a truncated value"
                );
            };
            let selected: i32 = narrow.cast_signed();
            let compare: Instruction =
                Instruction::with2(Code::Cmp_rm32_imm32, register, selected).expect("compare");
            placer.place(asm, compare);
            let taken_label: CodeLabel = *labels.get(taken).expect("label for the taken state");
            let fall_label: CodeLabel = *labels
                .get(fallthrough)
                .expect("label for the fallthrough state");
            asm.je(taken_label).expect("taken edge");
            asm.jmp(fall_label).expect("fallthrough edge");
        }
        more => panic!(
            "this harness lowers at most a two-way state select, and the recovery names {} \
             successors",
            more.len()
        ),
    }
}

#[test]
fn a_bounded_differential_agrees_with_the_committed_source_on_every_input_it_runs() {
    let mut executions: u32 = 0;
    let mut samples_graded: u32 = 0;
    for sample in &SAMPLES {
        let bytes: Vec<u8> = read_sample(sample);
        let recovery: CffRecovery = recover(&bytes);
        let recovered: Vec<u8> = emit_recovered(&bytes, &recovery);
        println!(
            "{}: flattened {} bytes, recovered {} bytes at {RECOVERED_BASE:#x}",
            sample.file,
            bytes.len(),
            recovered.len()
        );
        for argument in DIFFERENTIAL_INPUTS {
            let expected: i32 = (sample.source)(argument);
            let flattened: RunOutcome = run_function(&bytes, BASE, argument);
            let deflattened: RunOutcome = run_function(&recovered, RECOVERED_BASE, argument);
            assert_eq!(
                flattened,
                RunOutcome::Returned(expected),
                "{}({argument}) is {expected} in corpus/native/ollvm/probe_src.c, which is the \
                 reference this differential grades against. The flattened bytes disagreeing means \
                 the emulator or the argument register is wrong, not that the recovery is right",
                sample.entry_point
            );
            assert_eq!(
                deflattened, flattened,
                "{}({argument}): the recovered program must observe the same return value as the \
                 flattened one",
                sample.entry_point
            );
            executions += 2;
        }
        samples_graded += 1;
    }
    assert_eq!(
        samples_graded as usize,
        SAMPLES.len(),
        "every committed flattening sample must run the differential"
    );
    assert_eq!(
        executions,
        2 * (SAMPLES.len() as u32) * (DIFFERENTIAL_INPUTS.len() as u32),
        "the differential population must be the full input set on both programs"
    );
    println!(
        "differential population: {} arguments per function over {samples_graded} functions, run \
         on the flattened bytes and on the recovered bytes, {executions} executions in total. \
         Budget per execution: {STEP_BUDGET} instruction steps and a {STACK_BYTES}-byte stack. \
         This establishes agreement on those {} arguments and on nothing else",
        DIFFERENTIAL_INPUTS.len(),
        DIFFERENTIAL_INPUTS.len()
    );
}

#[test]
fn a_seeded_wrong_edge_makes_the_bounded_differential_disagree() {
    const REAL_TAKEN_STATE: u64 = 0x5864_E5C6;
    const RETURN_STATE: u64 = 0x69B0_963D;
    let bytes: Vec<u8> = read_sample(&SAMPLES[0]);
    let mut recovery: CffRecovery = recover(&bytes);
    let retargeted: bool = recovery
        .cover
        .regions
        .iter_mut()
        .filter(|region: &&mut StateRegion| region.successors.len() == 2)
        .any(|region: &mut StateRegion| {
            let Some(slot): Option<&mut u64> = region
                .successors
                .iter_mut()
                .find(|state: &&mut u64| **state == REAL_TAKEN_STATE)
            else {
                return false;
            };
            *slot = RETURN_STATE;
            true
        });
    assert!(
        retargeted,
        "classify branches on n > 10 into state {REAL_TAKEN_STATE:#x}, so that edge must exist \
         before it can be retargeted"
    );
    let defective: Vec<u8> = emit_recovered(&bytes, &recovery);
    let disagreements: Vec<i32> = DIFFERENTIAL_INPUTS
        .into_iter()
        .filter(|argument: &i32| {
            run_function(&defective, RECOVERED_BASE, *argument)
                != RunOutcome::Returned(classify_from_source(*argument))
        })
        .collect();
    println!("seeded wrong edge disagrees on inputs {disagreements:?}");
    assert_eq!(
        disagreements,
        vec![11, 12, 15, 32, 64, 100],
        "the retargeted edge sends every argument above ten down the n + 1 arm instead of the \
         n * 2 arm, and only those arguments, so the differential must disagree on exactly them"
    );
}

#[test]
fn the_differential_does_not_grade_the_order_of_a_two_way_state_select() {
    let bytes: Vec<u8> = read_sample(&SAMPLES[0]);
    let mut recovery: CffRecovery = recover(&bytes);
    let swapped: bool = recovery
        .cover
        .regions
        .iter_mut()
        .filter(|region: &&mut StateRegion| region.successors.len() == 2)
        .any(|region: &mut StateRegion| {
            region.successors.swap(0, 1);
            true
        });
    assert!(swapped, "classify must carry one two-way state select");
    let reordered: Vec<u8> = emit_recovered(&bytes, &recovery);
    for argument in DIFFERENTIAL_INPUTS {
        assert_eq!(
            run_function(&reordered, RECOVERED_BASE, argument),
            RunOutcome::Returned(classify_from_source(argument)),
            "the recovered program tests the state variable against the named arm at run time, so \
             naming the two arms in the other order emits the same test the other way round"
        );
    }
    println!(
        "the two arms of a state select are interchangeable in the emitted program, so the \
         differential grades the successor set and the region contents, never which arm the \
         recovery calls taken"
    );
}

#[test]
fn a_flattened_loop_that_outruns_the_step_budget_is_reported_rather_than_hung() {
    let bytes: Vec<u8> = read_sample(&SAMPLES[1]);
    let outcome: RunOutcome = run_function(&bytes, BASE, i32::MAX);
    assert_eq!(
        outcome,
        RunOutcome::BudgetExhausted,
        "sum_to(i32::MAX) runs about two billion iterations, so the differential must stop at its \
         step budget and say so rather than pin the machine"
    );
}

#[test]
fn a_function_with_no_dispatcher_is_never_reported_as_recovered() {
    let path: PathBuf = corpus("classify_plain.bin");
    let plain: Vec<u8> = std::fs::read(&path).unwrap_or_else(|err: std::io::Error| {
        panic!(
            "git tracks {}, so its absence is a defect: {err}",
            path.display()
        )
    });
    let outcome: CffOutcome = defeat_cff(DeobfBits::Bits64, BASE, &plain, BASE);
    assert_eq!(
        outcome,
        CffOutcome::NotFlattened,
        "the unobfuscated sibling of classify carries no dispatcher, so nothing may be recovered \
         from it"
    );
}

#[test]
fn an_unresolvable_state_update_abstains_with_a_named_reason() {
    use iced_x86::code_asm::{dword_ptr, eax, ecx, r9d, rbp};

    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut dispatcher: CodeLabel = asm.create_label();
    let mut case_a: CodeLabel = asm.create_label();
    let mut case_b: CodeLabel = asm.create_label();
    let mut case_c: CodeLabel = asm.create_label();

    asm.mov(dword_ptr(rbp - 4), 10i32).unwrap();
    asm.jmp(dispatcher).unwrap();

    asm.set_label(&mut dispatcher).unwrap();
    asm.cmp(dword_ptr(rbp - 4), 10i32).unwrap();
    asm.je(case_a).unwrap();
    asm.cmp(dword_ptr(rbp - 4), 20i32).unwrap();
    asm.je(case_b).unwrap();
    asm.cmp(dword_ptr(rbp - 4), 30i32).unwrap();
    asm.je(case_c).unwrap();
    asm.ret().unwrap();

    asm.set_label(&mut case_a).unwrap();
    asm.mov(eax, ecx).unwrap();
    asm.imul_2(eax, ecx).unwrap();
    asm.and(eax, 1i32).unwrap();
    asm.add(eax, 20i32).unwrap();
    asm.mov(dword_ptr(rbp - 4), eax).unwrap();
    asm.jmp(dispatcher).unwrap();

    asm.set_label(&mut case_b).unwrap();
    asm.add(r9d, 1i32).unwrap();
    asm.mov(dword_ptr(rbp - 4), 30i32).unwrap();
    asm.jmp(dispatcher).unwrap();

    asm.set_label(&mut case_c).unwrap();
    asm.ret().unwrap();

    let bytes: Vec<u8> = asm.assemble(BASE).expect("assemble");
    let CffOutcome::Recovered(recovery): CffOutcome =
        defeat_cff(DeobfBits::Bits64, BASE, &bytes, BASE)
    else {
        panic!("the dispatcher itself is plain, so recovery must reach it");
    };
    println!("opaque state update cover: {:?}", recovery.cover);
    assert!(
        !recovery.fully_recovered,
        "state 10 updates the state variable through an always-even predicate, so the transition \
         out of it is not a constant and the recovery is not full: {:?}",
        recovery.cover
    );
    let unresolved: Vec<&StateRegion> = recovery.cover.unresolved_transitions();
    assert!(
        unresolved
            .iter()
            .any(|region: &&StateRegion| region.state == 10),
        "the abstention must name state 10 rather than drop it silently: {:?}",
        recovery.cover
    );
    assert!(
        recovery
            .cover
            .uncovered
            .iter()
            .any(|state: &disrobe_pass_native::UncoveredState| state.state == 20),
        "state 20 is reachable only through the unresolved update, so it must be reported \
         uncovered with a reason: {:?}",
        recovery.cover
    );
    assert_eq!(
        recovery.cover.dispatcher_states, 3,
        "the denominator stays at every state the dispatcher can select"
    );
}
