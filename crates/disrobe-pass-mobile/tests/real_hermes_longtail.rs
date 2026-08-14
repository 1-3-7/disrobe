#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::uninlined_format_args
)]

use std::collections::{BTreeMap, BTreeSet};

use boa_engine::{Context, Source};
use disrobe_pass_mobile::{
    DecompileReport, DecompiledFunction, HermesModule, SmallFunctionHeader, StructureDecline,
    decompile_hermes_module, hermes_disasm_function, parse_hermes_module,
};
use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;
use sha2::{Digest, Sha256};

const TOOLCHAIN: &str = "facebook/hermes v0.13.0 release hermes-cli-windows.tar.gz, rebuilt by \
                         crates/disrobe-pass-mobile/tests/fixtures/hermes/build.ps1";

const LONGTAIL_HBC: &[u8] = include_bytes!("fixtures/hermes/longtail.hbc");
const LONGTAIL_JS: &str = include_str!("fixtures/hermes/longtail.js");
const LONGTAIL_HBCDUMP: &str = include_str!("fixtures/hermes/longtail.hbcdump.txt");
const LONGTAIL_VM_STDOUT: &str = include_str!("fixtures/hermes/longtail.hermes-stdout.txt");
const LONGTAIL_SHA256: &str = "ec1442d7481836c205d6b9b2447e6eee102bf70a04835b658b6f5d52d0bd626d";

const SHAPES_HBC: &[u8] = include_bytes!("fixtures/hermes/shapes.hbc");
const SHAPES_JS: &str = include_str!("fixtures/hermes/shapes.js");
const SHAPES_HBCDUMP: &str = include_str!("fixtures/hermes/shapes.hbcdump.txt");
const SHAPES_VM_STDOUT: &str = include_str!("fixtures/hermes/shapes.hermes-stdout.txt");
const SHAPES_SHA256: &str = "7f0e2eab19c6a275e92a8e19b66de4c24e5c688acabc46450f666595c6852168";

struct Bundle {
    label: &'static str,
    bytecode: &'static [u8],
    source: &'static str,
    hbcdump: &'static str,
    vm_stdout: &'static str,
    sha256: &'static str,
}

const LONGTAIL: Bundle = Bundle {
    label: "longtail.hbc",
    bytecode: LONGTAIL_HBC,
    source: LONGTAIL_JS,
    hbcdump: LONGTAIL_HBCDUMP,
    vm_stdout: LONGTAIL_VM_STDOUT,
    sha256: LONGTAIL_SHA256,
};

const SHAPES: Bundle = Bundle {
    label: "shapes.hbc",
    bytecode: SHAPES_HBC,
    source: SHAPES_JS,
    hbcdump: SHAPES_HBCDUMP,
    vm_stdout: SHAPES_VM_STDOUT,
    sha256: SHAPES_SHA256,
};

const BUNDLES: [&Bundle; 2] = [&LONGTAIL, &SHAPES];

#[derive(Debug, Clone)]
struct ToolInstruction {
    absolute: u32,
    mnemonic: String,
    encoded: Vec<u8>,
}

#[derive(Debug, Clone)]
struct ToolFunction {
    start: u32,
    label: String,
    instructions: Vec<ToolInstruction>,
}

fn hex_u32(text: &str) -> Option<u32> {
    u32::from_str_radix(text, 16).ok()
}

fn parse_encoded(field: &str) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::with_capacity(field.len() / 3);
    for token in field.split_ascii_whitespace() {
        bytes.push(u8::from_str_radix(token, 16).ok()?);
    }
    if bytes.is_empty() { None } else { Some(bytes) }
}

fn tool_functions(bundle: &Bundle) -> Vec<ToolFunction> {
    let mut functions: Vec<ToolFunction> = Vec::new();
    let mut format_line_seen: bool = false;
    for line in bundle.hbcdump.lines() {
        let trimmed: &str = line.trim_end();
        if trimmed.contains("file format HBC-") {
            format_line_seen = true;
            continue;
        }
        if let Some(rest) = trimmed.strip_suffix(">:")
            && let Some((offset, label)) = rest.split_once(" <")
        {
            let Some(start): Option<u32> = hex_u32(offset.trim()) else {
                panic!(
                    "{}: the disassembly names a function at `{offset}`, which is not a hexadecimal \
                     offset, so this reference cannot be aligned to the decoder under test",
                    bundle.label
                )
            };
            functions.push(ToolFunction {
                start,
                label: label.to_owned(),
                instructions: Vec::new(),
            });
            continue;
        }
        let Some((offset, body)) = trimmed.split_once(":\t") else {
            continue;
        };
        let Some(absolute): Option<u32> = hex_u32(offset.trim()) else {
            continue;
        };
        let mut columns = body.split("  ").filter(|c: &&str| !c.trim().is_empty());
        let Some(encoded_field): Option<&str> = columns.next() else {
            panic!(
                "{}: the instruction at {offset} carries no encoded bytes, so nothing binds this \
                 reference line to the committed bytecode",
                bundle.label
            )
        };
        let Some(mnemonic_field): Option<&str> = columns.next() else {
            panic!(
                "{}: the instruction at {offset} carries no mnemonic, so the reference names no \
                 opcode for the decoder to be graded against",
                bundle.label
            )
        };
        let Some(encoded): Option<Vec<u8>> = parse_encoded(encoded_field) else {
            panic!(
                "{}: the instruction at {offset} has an unreadable byte column `{encoded_field}`",
                bundle.label
            )
        };
        let Some(current): Option<&mut ToolFunction> = functions.last_mut() else {
            panic!(
                "{}: the instruction at {offset} precedes every function header in the \
                 disassembly, so it belongs to no function",
                bundle.label
            )
        };
        current.instructions.push(ToolInstruction {
            absolute,
            mnemonic: mnemonic_field.trim().to_owned(),
            encoded,
        });
    }

    assert!(
        format_line_seen,
        "{}: the committed disassembly carries no `file format HBC-` line, so it is not the output \
         of the Hermes toolchain over this bundle and grading against it would compare the decoder \
         to arbitrary text",
        bundle.label
    );
    assert!(
        !functions.is_empty(),
        "{}: the committed disassembly names no function, so every comparison below would hold \
         over an empty reference",
        bundle.label
    );
    functions
}

fn module_of(bundle: &Bundle) -> HermesModule {
    let digest: String = format!("{:x}", Sha256::digest(bundle.bytecode));
    assert_eq!(
        digest, bundle.sha256,
        "{}: the committed bytecode no longer hashes to the digest this file records, so the \
         disassembly and the interpreter output beside it describe a different program",
        bundle.label
    );
    parse_hermes_module(bundle.bytecode).unwrap_or_else(|error| panic!("{}: {error}", bundle.label))
}

fn report_of(bundle: &Bundle) -> DecompileReport {
    let module: HermesModule = module_of(bundle);
    let report: DecompileReport = decompile_hermes_module(&module);
    assert_eq!(report.hermes_version, 96, "{}", bundle.label);
    assert!(
        report.lift_supported,
        "{}: this bundle declares a version the crate claims to lift, so a refusal here is a \
         failure and never a skip",
        bundle.label
    );
    report
}

fn decoded_mnemonic(line: &str) -> (u32, String) {
    let Some((offset, rest)) = line.split_once(": ") else {
        panic!("the decoder emitted `{line}`, which carries no offset")
    };
    let Some(hex): Option<&str> = offset.trim().strip_prefix("0x") else {
        panic!("the decoder emitted `{line}`, whose offset is not written in hexadecimal")
    };
    let Some(value): Option<u32> = hex_u32(hex) else {
        panic!("the decoder emitted `{line}`, whose offset does not parse")
    };
    let name: &str = rest.split('(').next().unwrap_or(rest);
    (value, name.to_owned())
}

fn parses_as_javascript(src: &str) -> bool {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("recovered.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, src, source_type).parse();
    parsed.errors.is_empty() && !parsed.panicked
}

fn eval_capture(program: &str) -> Option<String> {
    let mut context: Context = Context::default();
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
        runtime.set_loop_iteration_limit(2_000_000);
        runtime.set_recursion_limit(1_500);
        runtime.set_stack_size_limit(50_000);
    }
    let harness: String = format!(
        "var __out = []; var print = function(v){{ __out.push(String(v)); }};\n\
         globalThis.print = print;\n{program}\n__out.join('\\n');"
    );
    let value: boa_engine::JsValue = context.eval(Source::from_bytes(harness.as_bytes())).ok()?;
    value
        .as_string()
        .map(boa_engine::JsString::to_std_string_escaped)
}

fn vm_lines(bundle: &Bundle) -> Vec<&'static str> {
    let lines: Vec<&str> = bundle
        .vm_stdout
        .lines()
        .filter(|line: &&str| !line.is_empty())
        .collect();
    assert!(
        !lines.is_empty(),
        "{}: the committed interpreter output is empty, so the behavioural comparison would hold \
         over nothing",
        bundle.label
    );
    lines
}

#[test]
fn the_committed_disassembly_describes_the_committed_bytecode_byte_for_byte() {
    for bundle in BUNDLES {
        let module: HermesModule = module_of(bundle);
        let functions: Vec<ToolFunction> = tool_functions(bundle);

        assert_eq!(
            functions.len(),
            module.functions.len(),
            "{}: the Hermes disassembly names {} functions and the reader found {}, so one of the \
             two is reading a different container",
            bundle.label,
            functions.len(),
            module.functions.len()
        );

        let mut checked: usize = 0;
        for tool in &functions {
            for instruction in &tool.instructions {
                let start: usize = instruction.absolute as usize;
                let end: usize = start.saturating_add(instruction.encoded.len());
                let Some(actual): Option<&[u8]> = bundle.bytecode.get(start..end) else {
                    panic!(
                        "{}: the disassembly places {} at {:#x}, which is past the end of the \
                         committed bytecode",
                        bundle.label, instruction.mnemonic, instruction.absolute
                    )
                };
                assert_eq!(
                    actual,
                    instruction.encoded.as_slice(),
                    "{}: the disassembly records {} at {:#x} as {:02x?}, but the committed \
                     bytecode holds {:02x?} there. The two fixtures were produced from different \
                     inputs and neither can grade the decoder",
                    bundle.label,
                    instruction.mnemonic,
                    instruction.absolute,
                    instruction.encoded,
                    actual
                );
                checked += 1;
            }
        }
        assert!(
            checked > 100,
            "{}: only {checked} instructions bind the disassembly to the bytecode, which is too \
             few to be this program",
            bundle.label
        );
        eprintln!(
            "{}: {checked} reference instructions across {} functions match the committed \
             bytecode byte for byte",
            bundle.label,
            functions.len()
        );
    }
}

fn declared_function_names(source: &str) -> Vec<&str> {
    let mut names: Vec<&str> = Vec::new();
    for line in source.lines() {
        let trimmed: &str = line.trim_start();
        let rest: &str = match trimmed.strip_prefix("function* ") {
            Some(rest) => rest,
            None => match trimmed.strip_prefix("function ") {
                Some(rest) => rest,
                None => continue,
            },
        };
        if let Some((name, _)) = rest.split_once('(')
            && !name.is_empty()
        {
            names.push(name);
        }
    }
    names
}

#[test]
fn every_function_the_committed_source_declares_is_recovered_under_its_own_name() {
    for bundle in BUNDLES {
        let report: DecompileReport = report_of(bundle);
        let declared: Vec<&str> = declared_function_names(bundle.source);
        assert!(
            declared.len() >= 8,
            "{}: the committed source declares only {} named functions, which is too few to be \
             this program",
            bundle.label,
            declared.len()
        );
        for name in &declared {
            assert!(
                report
                    .functions
                    .iter()
                    .any(|f: &DecompiledFunction| f.name == *name),
                "{}: the committed source declares `function {name}` and the report names no such \
                 function, so the bytecode beside it was compiled from a different program or a \
                 name was lost. Recovered: {:?}",
                bundle.label,
                report
                    .functions
                    .iter()
                    .map(|f: &DecompiledFunction| f.name.as_str())
                    .collect::<Vec<&str>>()
            );
        }
        eprintln!(
            "{}: {} named declarations in the committed source are all recovered by name",
            bundle.label,
            declared.len()
        );
    }
}

#[test]
fn every_decoded_instruction_carries_the_mnemonic_the_hermes_toolchain_gives_it() {
    for bundle in BUNDLES {
        let module: HermesModule = module_of(bundle);
        let functions: Vec<ToolFunction> = tool_functions(bundle);
        let by_start: BTreeMap<u32, &ToolFunction> = functions
            .iter()
            .map(|f: &ToolFunction| (f.start, f))
            .collect();

        let mut compared: usize = 0;
        for (index, header) in module.functions.iter().enumerate() {
            let header: &SmallFunctionHeader = header;
            let Some(tool): Option<&&ToolFunction> = by_start.get(&header.offset) else {
                panic!(
                    "{}: the reader places function {index} at {:#x} and the Hermes disassembly \
                     names no function there, so the container layout the decoder walks disagrees \
                     with the toolchain that wrote it",
                    bundle.label, header.offset
                )
            };
            let decoded: Vec<String> = hermes_disasm_function(&module, index);
            assert_eq!(
                decoded.len(),
                tool.instructions.len(),
                "{} {}: the decoder produced {} instructions and the Hermes disassembly holds {}. \
                 A differing count means the decoder walked the wrong instruction lengths",
                bundle.label,
                tool.label,
                decoded.len(),
                tool.instructions.len()
            );
            for (line, expected) in decoded.iter().zip(tool.instructions.iter()) {
                let (relative, mnemonic): (u32, String) = decoded_mnemonic(line);
                let absolute: u32 = header.offset.saturating_add(relative);
                assert_eq!(
                    absolute, expected.absolute,
                    "{} {}: the decoder placed {mnemonic} at {absolute:#x} and the Hermes \
                     disassembly places {} at {:#x}; the streams have desynchronised",
                    bundle.label, tool.label, expected.mnemonic, expected.absolute
                );
                assert_eq!(
                    mnemonic, expected.mnemonic,
                    "{} {}: at {absolute:#x} the decoder names the opcode {mnemonic} and the \
                     Hermes toolchain names it {}. The opcode table for this bytecode version is \
                     wrong at this byte",
                    bundle.label, tool.label, expected.mnemonic
                );
                compared += 1;
            }
        }
        eprintln!(
            "{}: {compared} instructions agree with the Hermes disassembly at the same offset \
             under the same mnemonic",
            bundle.label
        );
    }
}

fn mnemonics_in_reference(bundle: &Bundle) -> BTreeSet<String> {
    tool_functions(bundle)
        .iter()
        .flat_map(|f: &ToolFunction| f.instructions.iter())
        .map(|i: &ToolInstruction| i.mnemonic.clone())
        .collect()
}

#[test]
fn every_declined_opcode_is_named_under_a_mnemonic_the_hermes_toolchain_uses() {
    for bundle in BUNDLES {
        let report: DecompileReport = report_of(bundle);
        let reference: BTreeSet<String> = mnemonics_in_reference(bundle);
        assert!(
            reference.len() > 20,
            "{}: the reference names only {} distinct opcodes, too few to be this program",
            bundle.label,
            reference.len()
        );

        let declined: Vec<String> = report
            .declined_opcodes
            .iter()
            .map(|c: &disrobe_pass_mobile::OpcodeCount| c.opcode.clone())
            .collect();
        for name in &declined {
            assert!(
                reference.contains(name),
                "{}: the report declines `{name}`, which the Hermes toolchain never names in this \
                 bundle. A declined opcode must be reported under the real mnemonic so a reader \
                 can look it up, and an invented name hides which instruction was refused",
                bundle.label
            );
        }
        eprintln!(
            "{}: declined opcodes {:?}, all named as the Hermes toolchain names them",
            bundle.label, declined
        );
    }
}

struct Pinned {
    functions: usize,
    bodies: usize,
    decoded_ops: usize,
    reconstructed_ops: usize,
    declined_ops: usize,
    unaccounted_ops: usize,
    structured_before: usize,
    structured_after: usize,
}

const LONGTAIL_PINNED: Pinned = Pinned {
    functions: 12,
    bodies: 12,
    decoded_ops: 277,
    reconstructed_ops: 277,
    declined_ops: 0,
    unaccounted_ops: 0,
    structured_before: 10,
    structured_after: 10,
};

const SHAPES_PINNED: Pinned = Pinned {
    functions: 15,
    bodies: 15,
    decoded_ops: 231,
    reconstructed_ops: 231,
    declined_ops: 0,
    unaccounted_ops: 0,
    structured_before: 15,
    structured_after: 15,
};

const SWITCH_IMM_ARMS_BEFORE: usize = 1;
const SWITCH_IMM_ARMS_AFTER: usize = 17;

struct Declined {
    bundle: &'static str,
    function: &'static str,
    reason: StructureDecline,
    note: &'static str,
}

const DECLINED: &[Declined] = &[
    Declined {
        bundle: "longtail.hbc",
        function: "firstPair",
        reason: StructureDecline::UnsupportedRegion,
        note: "a labelled break and a labelled continue leave the inner loop of a reducible nested \
               loop. The region structurer has no label on its break and continue sinks, so it \
               refuses the region by name rather than emitting a body that leaves the wrong loop",
    },
    Declined {
        bundle: "longtail.hbc",
        function: "global",
        reason: StructureDecline::IncompleteCover,
        note: "the top-level graph is one basic block and structures on its own. It is refused \
               only because the recovered text of firstPair is inlined into it and that text is \
               in goto form, so the whole body is held back rather than published as JavaScript \
               that does not parse",
    },
];

fn pinned_for(bundle: &Bundle) -> &'static Pinned {
    match bundle.label {
        "longtail.hbc" => &LONGTAIL_PINNED,
        _ => &SHAPES_PINNED,
    }
}

#[test]
fn the_recovery_table_over_both_bundles_is_pinned_by_equality() {
    for bundle in BUNDLES {
        let module: HermesModule = module_of(bundle);
        let report: DecompileReport = report_of(bundle);
        let pinned: &Pinned = pinned_for(bundle);
        let decoded: usize = report.total_reconstructed_ops
            + report.total_fallback_ops
            + report.total_unaccounted_ops;

        eprintln!(
            "=== {} ===\n  functions parsed        {}\n  functions with a body   {}\n  \
             functions structured    {} (was {} before this change)\n  \
             instructions decoded    {decoded}\n  opcodes reconstructed   {}\n  \
             opcodes declined        {}\n  opcodes unaccounted     {}\n  \
             structure declines      {:?}\n  declined opcodes        {:?}\n  \
             unaccounted opcodes     {:?}\n  utf16 string entries    {}\n  \
             bigint table entries    {}",
            bundle.label,
            report.function_count,
            report.functions_with_body,
            report.structured_functions,
            pinned.structured_before,
            report.total_reconstructed_ops,
            report.total_fallback_ops,
            report.total_unaccounted_ops,
            report.structure_declines,
            report.declined_opcodes,
            report.unaccounted_opcodes,
            module.utf16_strings,
            module.big_int_table.len()
        );
        for function in &report.functions {
            let function: &DecompiledFunction = function;
            eprintln!(
                "  fn {:<12} bytes={} blocks={} structured={} decline={:?} ops={}",
                function.name,
                function.bytecode_size,
                function.block_count,
                function.structured,
                function.structure_decline,
                function.reconstructed_ops + function.fallback_ops + function.unaccounted_ops
            );
        }

        assert_eq!(
            report.function_count, pinned.functions,
            "{}: the function denominator is pinned by equality, so a change that raises a rate \
             by parsing fewer functions fails here instead",
            bundle.label
        );
        assert_eq!(
            report.functions_with_body, pinned.bodies,
            "{}",
            bundle.label
        );
        assert_eq!(
            decoded, pinned.decoded_ops,
            "{}: the opcode denominator is pinned by equality, so decoding fewer instructions \
             must move this figure deliberately rather than raise the coverage ratio by dropping \
             them",
            bundle.label
        );
        assert_eq!(
            report.total_reconstructed_ops, pinned.reconstructed_ops,
            "{}",
            bundle.label
        );
        assert_eq!(
            report.total_fallback_ops, pinned.declined_ops,
            "{}: declined {:?}",
            bundle.label, report.declined_opcodes
        );
        assert_eq!(
            report.total_unaccounted_ops, pinned.unaccounted_ops,
            "{}: unaccounted {:?}",
            bundle.label, report.unaccounted_opcodes
        );
        assert_eq!(
            report.structured_functions, pinned.structured_after,
            "{}: the structured count is pinned by equality; declines {:?}",
            bundle.label, report.structure_declines
        );
    }
}

#[test]
fn the_functions_that_decline_are_exactly_the_ones_this_ledger_names() {
    for bundle in BUNDLES {
        let report: DecompileReport = report_of(bundle);
        let mut observed: Vec<(&str, StructureDecline)> = report
            .functions
            .iter()
            .filter_map(|f: &DecompiledFunction| {
                f.structure_decline
                    .map(|reason: StructureDecline| (f.name.as_str(), reason))
            })
            .collect();
        observed.sort_unstable_by_key(|(name, _): &(&str, StructureDecline)| *name);

        let mut expected: Vec<(&str, StructureDecline)> = DECLINED
            .iter()
            .filter(|row: &&Declined| row.bundle == bundle.label)
            .map(|row: &Declined| (row.function, row.reason))
            .collect();
        expected.sort_unstable_by_key(|(name, _): &(&str, StructureDecline)| *name);

        assert_eq!(
            observed, expected,
            "{}: the declined set is pinned by equality. A function that starts declining must \
             gain a row here with the reason, and a function that stops declining must lose its \
             row rather than leave this ledger claiming a refusal that no longer happens",
            bundle.label
        );

        for row in DECLINED
            .iter()
            .filter(|r: &&Declined| r.bundle == bundle.label)
        {
            assert!(
                row.note.len() > 60,
                "{}: {} declines, so this ledger must say why in words a reader can act on",
                bundle.label,
                row.function
            );
            let declining: &DecompiledFunction = report
                .functions
                .iter()
                .find(|f: &&DecompiledFunction| f.name == row.function)
                .unwrap_or_else(|| panic!("{}: no function {}", bundle.label, row.function));
            assert!(
                !declining.structured,
                "{}: {} is listed as declined but the report calls it structured",
                bundle.label, row.function
            );
            eprintln!(
                "declined[{} {}]: {:?} -- {}",
                bundle.label, row.function, row.reason, row.note
            );
        }
    }
}

#[test]
fn the_dense_switch_recovers_every_case_the_jump_table_holds() {
    let report: DecompileReport = report_of(&LONGTAIL);
    let pick: &DecompiledFunction = report
        .functions
        .iter()
        .find(|f: &&DecompiledFunction| f.name == "pick")
        .unwrap_or_else(|| panic!("longtail.hbc recovers no function named pick"));

    let switch_imm_count: usize = LONGTAIL
        .hbcdump
        .lines()
        .filter(|line: &&str| line.contains("SwitchImm"))
        .count();
    assert_eq!(
        switch_imm_count, 1,
        "the reference must hold exactly one SwitchImm for this measurement to name one function"
    );

    assert!(
        pick.structured && pick.structure_decline.is_none(),
        "pick must reach structured control flow before its arms are counted, because the goto \
         fallback rendering also prints one line per case target and the count below would then \
         be taken over a body that is not JavaScript; decline {:?}\nsrc:\n{}",
        pick.structure_decline,
        pick.source
    );
    assert!(
        !pick.source.contains("goto "),
        "pick must carry no goto edge\nsrc:\n{}",
        pick.source
    );

    let arms: usize =
        pick.source.matches("case ").count() + pick.source.matches("default:").count();
    assert_eq!(
        arms, SWITCH_IMM_ARMS_AFTER,
        "the jump table of this real bundle holds sixteen entries and one default. Before the \
         table was read at its aligned absolute position in the whole image it yielded \
         {SWITCH_IMM_ARMS_BEFORE} arm, so every case body was dropped while the report still \
         called the function structured at full opcode coverage.\nsrc:\n{}",
        pick.source
    );
    for value in 0..16u32 {
        assert!(
            pick.source.contains(&format!("case {value}:")),
            "case {value} is missing from the recovered switch\nsrc:\n{}",
            pick.source
        );
    }
    eprintln!(
        "hermes SwitchImm on a real bundle: {SWITCH_IMM_ARMS_BEFORE} arm before, {arms} arms now"
    );
}

struct Probe {
    function: &'static str,
    call: &'static str,
    vm_line: usize,
}

const LONGTAIL_PROBES: &[Probe] = &[
    Probe {
        function: "pick",
        call: "globalThis.pick(0)",
        vm_line: 0,
    },
    Probe {
        function: "pick",
        call: "globalThis.pick(15)",
        vm_line: 1,
    },
    Probe {
        function: "pick",
        call: "globalThis.pick(99)",
        vm_line: 2,
    },
    Probe {
        function: "classify",
        call: "globalThis.classify(1)",
        vm_line: 3,
    },
    Probe {
        function: "countDown",
        call: "globalThis.countDown(5)",
        vm_line: 5,
    },
    Probe {
        function: "guarded",
        call: "globalThis.guarded(9, 4)",
        vm_line: 6,
    },
    Probe {
        function: "guarded",
        call: "globalThis.guarded(1, 0)",
        vm_line: 7,
    },
    Probe {
        function: "grade",
        call: "globalThis.grade(95)",
        vm_line: 8,
    },
    Probe {
        function: "grade",
        call: "globalThis.grade(72)",
        vm_line: 9,
    },
    Probe {
        function: "bits",
        call: "globalThis.bits(1023)",
        vm_line: 10,
    },
    Probe {
        function: "total",
        call: "globalThis.total([1, 2, 3, 4, 5])",
        vm_line: 12,
    },
    Probe {
        function: "names",
        call: "globalThis.names({ a: 1, b: 2, c: 3 })",
        vm_line: 13,
    },
];

const PINNED_EXECUTION_PROBES: usize = 12;
const PINNED_EXECUTION_EQUIVALENT: usize = 12;
const PINNED_EXECUTION_GRADED_FUNCTIONS: usize = 8;
const PINNED_UNGRADED_FUNCTIONS: usize = 2;

const PARSE_GRADED_ONLY: &[(&str, &str)] = &[
    (
        "makeAdder",
        "the body writes its captured variable as a bare assignment rather than binding it in the \
         enclosing scope, so one call happens to read back the right value while two live closures \
         would share a single slot. Running one call would pass for the wrong reason, so this \
         function is graded on parse and its capture emission is recorded as unfinished",
    ),
    (
        "$func9",
        "the closure returned by makeAdder reads the same captured slot and carries the same \
         unfinished capture emission, and hermesc gave it no name of its own",
    ),
];

fn installed(report: &DecompileReport, name: &str) -> String {
    let recovered: &DecompiledFunction = report
        .functions
        .iter()
        .find(|f: &&DecompiledFunction| f.name == name)
        .unwrap_or_else(|| panic!("longtail.hbc recovers no function named {name}"));
    assert!(
        recovered.structured,
        "{name}: a function driven through the interpreter comparison must have structured; \
         decline {:?}",
        recovered.structure_decline
    );
    assert!(
        parses_as_javascript(&recovered.source),
        "{name}: the recovered body must parse before it can be run\n{}",
        recovered.source
    );
    format!("globalThis.{name} = {};", recovered.source)
}

#[test]
fn each_recovered_function_reproduces_the_line_the_hermes_interpreter_printed() {
    let report: DecompileReport = report_of(&LONGTAIL);
    let expected: Vec<&str> = vm_lines(&LONGTAIL);
    assert_eq!(
        expected.len(),
        14,
        "longtail.js prints fourteen lines, so a different count means the interpreter output \
         beside the bytecode is from another program"
    );
    assert_eq!(
        LONGTAIL_PROBES.len(),
        PINNED_EXECUTION_PROBES,
        "the probe population is pinned by equality, so dropping a probe that stopped matching \
         fails here instead of raising the rate over what is left"
    );

    let mut graded_names: BTreeSet<&str> = BTreeSet::new();
    for probe in LONGTAIL_PROBES {
        graded_names.insert(probe.function);
    }
    let mut preamble: String = String::new();
    for name in &graded_names {
        preamble.push_str(&installed(&report, name));
        preamble.push('\n');
    }

    let mut equivalent: usize = 0;
    for probe in LONGTAIL_PROBES {
        let Some(want): Option<&&str> = expected.get(probe.vm_line) else {
            panic!(
                "probe {} names interpreter line {} and the committed output has {} lines",
                probe.call,
                probe.vm_line,
                expected.len()
            )
        };
        let driver: String = format!("{preamble}print({});", probe.call);
        let got: String = eval_capture(&driver).unwrap_or_else(|| {
            panic!(
                "{}: the recovered body must run in a JavaScript engine, and a body that throws \
                 on entry is a failure and never a skip\n{driver}",
                probe.call
            )
        });
        assert_eq!(
            &got, *want,
            "{}: the recovered body printed {got:?} and the Hermes interpreter printed {want:?} \
             for the same call over the committed source. Reference produced by {TOOLCHAIN}",
            probe.call
        );
        let repeat: String = eval_capture(&driver)
            .unwrap_or_else(|| panic!("{}: the recovered body must run twice", probe.call));
        assert_eq!(
            repeat, got,
            "{}: two runs of the same recovered body must agree, or the single run this figure \
             rests on proves nothing",
            probe.call
        );
        equivalent += 1;
    }

    assert_eq!(
        equivalent, PINNED_EXECUTION_EQUIVALENT,
        "every probe reproduces the interpreter line for the same call"
    );
    assert_eq!(
        graded_names.len(),
        PINNED_EXECUTION_GRADED_FUNCTIONS,
        "the execution-graded function population is pinned by equality: {graded_names:?}"
    );
    eprintln!(
        "longtail.hbc execution-equivalent: {equivalent}/{PINNED_EXECUTION_PROBES} calls across \
         {}/{} functions, graded against the output of the Hermes interpreter",
        graded_names.len(),
        LONGTAIL_PINNED.functions
    );
}

#[test]
fn every_function_lands_in_exactly_one_grading_population() {
    let report: DecompileReport = report_of(&LONGTAIL);
    let executed: BTreeSet<&str> = LONGTAIL_PROBES.iter().map(|p: &Probe| p.function).collect();
    let declined: BTreeSet<&str> = DECLINED
        .iter()
        .filter(|row: &&Declined| row.bundle == LONGTAIL.label)
        .map(|row: &Declined| row.function)
        .collect();

    let parse_only: BTreeSet<&str> = PARSE_GRADED_ONLY
        .iter()
        .map(|(name, _): &(&str, &str)| *name)
        .collect();

    let mut execution_graded: Vec<&str> = Vec::new();
    let mut parse_graded: Vec<&str> = Vec::new();
    let mut ungraded: Vec<&str> = Vec::new();
    for function in &report.functions {
        let function: &DecompiledFunction = function;
        let name: &str = &function.name;
        if executed.contains(name) {
            execution_graded.push(name);
        } else if declined.contains(name) {
            ungraded.push(name);
        } else {
            assert!(
                parse_only.contains(name),
                "{name} is graded by no method and this file names no reason. A function must be \
                 executed against the interpreter output, listed as declined, or listed here with \
                 the reason execution would prove nothing about it"
            );
            assert!(
                function.structured && parses_as_javascript(&function.source),
                "{name}: a function listed as parse-graded must still parse, so a body that does \
                 not is a failure and not a skip\n{}",
                function.source
            );
            parse_graded.push(name);
        }
    }

    assert_eq!(
        execution_graded.len() + parse_graded.len() + ungraded.len(),
        report.function_count,
        "every function lands in exactly one population, so none can fall out of all three"
    );
    assert_eq!(
        execution_graded.len(),
        PINNED_EXECUTION_GRADED_FUNCTIONS,
        "execution-graded: {execution_graded:?}"
    );
    assert_eq!(
        parse_graded.len(),
        PARSE_GRADED_ONLY.len(),
        "parse-graded: {parse_graded:?}"
    );
    assert_eq!(
        ungraded.len(),
        PINNED_UNGRADED_FUNCTIONS,
        "declined and therefore graded by neither method: {ungraded:?}"
    );
    for (name, note) in PARSE_GRADED_ONLY {
        assert!(
            note.len() > 60,
            "{name} is graded on parse alone, so this file must say why in words a reader can act \
             on"
        );
        eprintln!("parse-graded[{name}]: {note}");
    }
    eprintln!(
        "longtail.hbc populations: {} execution-equivalent, {} parse-only, {} declined; the three \
         denominators sum to the pinned {} and are never added into one rate",
        execution_graded.len(),
        parse_graded.len(),
        ungraded.len(),
        report.function_count
    );
}

#[test]
fn a_body_that_drops_its_switch_cases_does_not_pass_the_interpreter_comparison() {
    let expected: Vec<&str> = vm_lines(&LONGTAIL);
    let emptied: &str = "globalThis.pick = function pick(arg0) { switch (arg0) { default: return \
                         \"zz\"; } };";
    let driver: String = format!("{emptied}\nprint(globalThis.pick(0));");
    let got: String = eval_capture(&driver).expect("the emptied body evaluates");
    assert_ne!(
        Some(got.as_str()),
        expected.first().copied(),
        "a switch whose case arms were all dropped must not reproduce the interpreter line, or \
         this comparison would have passed over the recovery it exists to catch"
    );
    assert!(
        parses_as_javascript(emptied),
        "the emptied body still parses, so parse validity alone is no evidence and the \
         interpreter comparison is what carries this measurement"
    );
}
