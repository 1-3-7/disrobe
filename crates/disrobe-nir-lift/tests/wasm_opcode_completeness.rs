#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use disrobe_nir::{NirFunction, NirInstr, NirModule, NirOp};
use disrobe_nir_lift::{LiftError, lift_wasm_module};
use wasmparser::{FunctionBody, Operator, Parser, Payload};

const OPERATOR_SPACE: usize = 627;
const REACHED_OPERATORS: usize = 98;
const MODELLED_OPERATORS: usize = 27;
const STRUCTURAL_OPERATORS: usize = 4;
const DECLINED_OPERATORS: usize = 67;

const STRUCTURAL: [&str; 5] = ["Block", "Else", "End", "Loop", "Nop"];

const CODELESS_FIXTURES: [&str; 2] = ["wat/custom_page_size.wat", "wat/js_string_builtins.wat"];

const FIXTURES: [(&str, &str); 40] = [
    (
        "wat/eh_numeric_roundtrip.wat",
        "ed91ed21de039facba8109a472a4d21b9ac0d1594ed7404d72483c412530a9f7",
    ),
    (
        "wat/eh_try_table_modern.wat",
        "aa3e64db84207ce66a2551aecc03cf55b58235fc2127f438d53795d5fdd784b1",
    ),
    (
        "wat/funcref_numeric.wat",
        "94af64d533c11b2ff44855a31263d3cfbc87a1579fcb6fb7c1b8addac9823744",
    ),
    (
        "wat/function_refs.wasm",
        "37bc216af5989f40fe93f5a988093b6b69989d5ecffaea668d59d4a68f6435d5",
    ),
    (
        "wat/function_refs.wat",
        "562cf9b9185a4b891137f3b4910c7526961ab061f57db228f2db0a3e2132e9aa",
    ),
    (
        "wat/gc_extern_convert.wat",
        "921393d6c33a6fe8d8139635302529df324060e656908588b2b5373df77893c9",
    ),
    (
        "wat/gc_numeric_roundtrip.wat",
        "152f132cd1ac2c7c26217d35fa47ff62aecb98d164e8ff5df7f143cfc9815e8e",
    ),
    (
        "wat/gc_selfref_field.wat",
        "3c134517de830375eeb8439dbecae24ee22dd863d49f586dfd09dc9f98c660ae",
    ),
    (
        "wat/gc_subtype_roundtrip.wat",
        "a0f0fe843d558e111ef6744ad787118cba2cc0b0cf89c13a623f757e60ddb944",
    ),
    (
        "wat/multi_memory.wat",
        "61db200e35b4303a0c0b53513f778dca37d2f387de469280b6dda205d97332fb",
    ),
    (
        "wat/stack_switching.wat",
        "7dcd233449234f69d6ed41f9d8438bca0c72bd04ab8a75b5385ad5150d049e9e",
    ),
    (
        "wat/stack_switching_bind_throw.wat",
        "02555fcab2f5ae0d1f5f9dcce30659bf1c6dab500825f7ef57fc52aae27d7d97",
    ),
    (
        "plugins/busyloop_timeout.wat",
        "f76ddaac48d6bd03bd6d6b8e106a05392f8d51c73dad30b896078d25f3f36663",
    ),
    (
        "plugins/compute_xor.wat",
        "28a986a735022c39c03c4016c023470a1bc39d09508673e38167559328f3c4c1",
    ),
    (
        "plugins/deny_fs_fd_write.wat",
        "d79f04e1899e208513a368074e644ca91279dd366a4e3c68fb8aafb4bbfe92fb",
    ),
    (
        "plugins/deny_net_sock_open.wat",
        "1a33a953e2491dcb9e6626ae1b738a0cd541626ea9f5790c06f07c910c62fce5",
    ),
    (
        "plugins/memgrow_bomb.wat",
        "dd50fab7fefcae5e65347a000e4aeda88f0ffc7bf7898ba90a403ffdf4a1168e",
    ),
    (
        "obf/real/callind_dispatch.clean.wat",
        "c84324c2289e86d311edaaff13b15952f5333ef640f78010c9ebe77303ba1210",
    ),
    (
        "obf/real/callind_dispatch.obf.wat",
        "06e3e91290d043b7ed837543ea4e42393b0758002795e9a4c5728e59f98caa4f",
    ),
    (
        "obf/real/cff_cond_diamond.clean.wat",
        "54f51553d8f32b7b7ade287456100e224077b3b8ce438fa49dfcc45c8a8a0dbb",
    ),
    (
        "obf/real/cff_cond_diamond.obf.wat",
        "ea91d428ba6730e3e3f8ab3464d3791cf4e7a0cef5076441b456fd9693e788de",
    ),
    (
        "obf/real/cff_cond_loop.clean.wat",
        "62f5e337a5af89851fd673a0399508325ce89a2da42c0192870ef49e5ce495d9",
    ),
    (
        "obf/real/cff_cond_loop.obf.wat",
        "8ccf3d52051c6641c54a396f23deff3b23dc11ddfafb4ac632cd6c92a318ef8b",
    ),
    (
        "obf/real/cff_loop.clean.wat",
        "9d032a5e592bbf93a3b55f153b41e73d3c0328cbd7f828d5b94d2aa562e375d9",
    ),
    (
        "obf/real/cff_loop.obf.wat",
        "4792490136df1051d9811952d38e98dc597a988a12d63df1929bf66cbf676853",
    ),
    (
        "obf/real/cff_pipeline.clean.wat",
        "452ca6c7b67e4a8874078cb7e3d295ece89736b15999f6e9d3a4d02757a3cc06",
    ),
    (
        "obf/real/cff_pipeline.obf.wat",
        "c1ad93a4e21c1182b87782cff475f34d92beac79d11336a171d6592ec430a49a",
    ),
    (
        "obf/real/decrypt_stub.obf.wat",
        "bbd6a1ea318b1aba22066470fefc471f973dce57b8603fb00096a2fe8165d143",
    ),
    (
        "obf/real/jscrambler_guard.clean.wat",
        "de993224726f90f8f1686e6dbcf7cf1e4b01487b7153c885d1ed51aeaeeb1b44",
    ),
    (
        "obf/real/jscrambler_guard.obf.wat",
        "352bc0afae9ab3f4eecaf3136f31de0278137f7f08eb5d70e3b53f9b45a93bf6",
    ),
    (
        "obf/real/mba_checksum.clean.wat",
        "91736e0084babd5d984e83ccb472c30a05a810b673a99d0c7c9224d147e1aaae",
    ),
    (
        "obf/real/mba_checksum.obf.wat",
        "ed29753f2f7c913e4efa8e95cbe0940876b6ec333bfe77ec47cefd2ffa1970cb",
    ),
    (
        "obf/real/opaque_select.clean.wat",
        "5cc752a06ff7f29f7e7162b40dd5f8602da0146b23a47fa8c3f3a9d1a2a9ac69",
    ),
    (
        "obf/real/opaque_select.obf.wat",
        "11098b9691ba9d5608532f148424fd000c4de266634470e47759c8093469aa5f",
    ),
    (
        "obf/real/trunc_sat.obf.wat",
        "6445b3f551b93ec43659a2aa2bf7fde00f7ac5efa7fe25c15eeb47d61c7e80f5",
    ),
    (
        "obf/real/wasmixer_inflate.clean.wat",
        "2084e58ad24ed7577ed5affe95a55e7f92724bc8f84e5d3aa4b67ec28a6bc60b",
    ),
    (
        "obf/real/wasmixer_inflate.obf.wat",
        "d89fa0fa41c91fe9cffa7f0b6d78a099098faad65e99a600c3f4690bf644e61d",
    ),
    (
        "obf/real/wasmixer_ondemand.obf.wat",
        "4b60c5165ee9a0df3b0a17104c380e5ab322f639eb18a1e8da06c70aa148b9ee",
    ),
    (
        "obf/real/wobfuscator_import.clean.wat",
        "efe68d923309b7b24a97f9e6a16987f0d798ce762c9452f198ad0e524f37368d",
    ),
    (
        "obf/real/wobfuscator_import.obf.wat",
        "add87c7c11f494c9f980ba35a86d3272a99d1f7044015640725082c4e6708602",
    ),
];

const PINNED_VERDICTS: [(&str, &str); REACHED_OPERATORS] = [
    ("AnyConvertExtern", "Nop"),
    ("ArrayFill", "Nop"),
    ("ArrayGet", "Nop"),
    ("ArrayLen", "Nop"),
    ("ArrayNew", "Nop"),
    ("ArrayNewDefault", "Nop"),
    ("ArrayNewFixed", "Nop"),
    ("ArraySet", "Nop"),
    ("Block", "Nop"),
    ("Br", "Branch"),
    ("BrIf", "CondBranch"),
    ("BrOnCast", "Nop"),
    ("BrTable", "CondBranch"),
    ("Call", "Call"),
    ("CallIndirect", "IndirectCall"),
    ("CallRef", "IndirectCall"),
    ("Catch", "Nop"),
    ("CatchAll", "Nop"),
    ("ContBind", "Nop"),
    ("ContNew", "Nop"),
    ("DataDrop", "Nop"),
    ("Delegate", "Nop"),
    ("Drop", "Nop"),
    ("Else", "Nop"),
    ("End", "Nop"),
    ("ExternConvertAny", "Nop"),
    ("F32Load", "Load"),
    ("F32Store", "Store"),
    ("F64Load", "Load"),
    ("F64Store", "Store"),
    ("GlobalGet", "Nop"),
    ("GlobalSet", "Nop"),
    ("I31GetS", "Nop"),
    ("I31GetU", "Nop"),
    ("I32Add", "BinOp"),
    ("I32And", "BinOp"),
    ("I32Const", "Const"),
    ("I32DivS", "BinOp"),
    ("I32Eq", "Nop"),
    ("I32Eqz", "Nop"),
    ("I32GeS", "Nop"),
    ("I32GeU", "Nop"),
    ("I32GtS", "Nop"),
    ("I32GtU", "Nop"),
    ("I32LeS", "Nop"),
    ("I32Load", "Load"),
    ("I32Load8U", "Load"),
    ("I32LtS", "Nop"),
    ("I32LtU", "Nop"),
    ("I32Mul", "BinOp"),
    ("I32Ne", "Nop"),
    ("I32Shl", "BinOp"),
    ("I32Store", "Store"),
    ("I32Store8", "Store"),
    ("I32Sub", "BinOp"),
    ("I32TruncSatF32S", "Nop"),
    ("I32TruncSatF32U", "Nop"),
    ("I32TruncSatF64S", "Nop"),
    ("I32TruncSatF64U", "Nop"),
    ("I32WrapI64", "Nop"),
    ("I32Xor", "BinOp"),
    ("I64Add", "BinOp"),
    ("I64Const", "Const"),
    ("I64LtS", "Nop"),
    ("I64TruncSatF32S", "Nop"),
    ("I64TruncSatF32U", "Nop"),
    ("I64TruncSatF64S", "Nop"),
    ("I64TruncSatF64U", "Nop"),
    ("If", "CondBranch"),
    ("LocalGet", "Nop"),
    ("LocalSet", "Nop"),
    ("LocalTee", "Nop"),
    ("Loop", "Nop"),
    ("MemoryCopy", "Nop"),
    ("MemoryFill", "Nop"),
    ("MemoryGrow", "Nop"),
    ("MemoryInit", "Nop"),
    ("MemorySize", "Nop"),
    ("RefAsNonNull", "Nop"),
    ("RefFunc", "Nop"),
    ("RefI31", "Nop"),
    ("RefIsNull", "Nop"),
    ("RefNull", "Nop"),
    ("RefTestNonNull", "Nop"),
    ("Resume", "Nop"),
    ("ResumeThrow", "Nop"),
    ("Rethrow", "Nop"),
    ("Return", "Return"),
    ("Select", "Nop"),
    ("StructGet", "Nop"),
    ("StructNew", "Nop"),
    ("StructSet", "Nop"),
    ("Suspend", "Nop"),
    ("Throw", "Nop"),
    ("ThrowRef", "Nop"),
    ("Try", "Nop"),
    ("TryTable", "Nop"),
    ("Unreachable", "Interrupt"),
];

fn corpus_path(relative: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates directory")
        .parent()
        .expect("workspace root")
        .join("corpus")
        .join("wasm");
    for segment in relative.split('/') {
        path.push(segment);
    }
    path
}

fn fixture_bytes(relative: &str, expected_hash: &str) -> Vec<u8> {
    let path: PathBuf = corpus_path(relative);
    let raw: Vec<u8> = std::fs::read(&path).expect("committed wasm corpus entry present");
    let observed: String = blake3::hash(&raw).to_hex().to_string();
    assert_eq!(
        observed, expected_hash,
        "{relative} changed; the graded corpus is hash-pinned so a rescored run cannot pass silently"
    );
    if corpus_path(relative)
        .extension()
        .is_some_and(|extension: &std::ffi::OsStr| extension.eq_ignore_ascii_case("wasm"))
    {
        return raw;
    }
    wat::parse_bytes(&raw)
        .expect("assemble the committed wat fixture")
        .into_owned()
}

const fn operator_variant(op: &Operator<'_>) -> &'static str {
    macro_rules! define_variant {
        ($( @$proposal:ident $name:ident $({ $($arg:ident: $argty:ty),* })? => $visit:ident ($($ann:tt)*))*) => {
            match op {
                $( Operator::$name $( { $($arg: _),* } )? => stringify!($name), )*
                _ => "Unrecognised",
            }
        };
    }
    wasmparser::for_each_operator!(define_variant)
}

fn operator_space() -> BTreeMap<&'static str, &'static str> {
    macro_rules! define_space {
        ($( @$proposal:ident $name:ident $({ $($arg:ident: $argty:ty),* })? => $visit:ident ($($ann:tt)*))*) => {
            {
                const SPACE: &[(&str, &str)] = &[$( (stringify!($name), stringify!($proposal)), )*];
                SPACE.iter().copied().collect()
            }
        };
    }
    wasmparser::for_each_operator!(define_space)
}

fn reference_functions(bytes: &[u8]) -> Vec<Vec<(&'static str, usize)>> {
    let mut functions: Vec<Vec<(&'static str, usize)>> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        let payload: Payload<'_> = payload.expect("the reference decoder must accept the fixture");
        let Payload::CodeSectionEntry(body) = payload else {
            continue;
        };
        let body: FunctionBody<'_> = body;
        let mut operators: Vec<(&'static str, usize)> = Vec::new();
        let reader: wasmparser::OperatorsReader<'_> = body
            .get_operators_reader()
            .expect("the reference decoder must read the code entry");
        for item in reader.into_iter_with_offsets() {
            let (op, offset): (Operator<'_>, usize) =
                item.expect("the reference decoder must decode every operator");
            operators.push((operator_variant(&op), offset));
        }
        functions.push(operators);
    }
    functions
}

const fn observed_category(op: &NirOp) -> &'static str {
    match op {
        NirOp::Nop => "Nop",
        NirOp::Const => "Const",
        NirOp::BinOp { .. } => "BinOp",
        NirOp::Load => "Load",
        NirOp::Store => "Store",
        NirOp::Call { .. } => "Call",
        NirOp::IndirectCall => "IndirectCall",
        NirOp::Branch { .. } => "Branch",
        NirOp::CondBranch { .. } => "CondBranch",
        NirOp::Return => "Return",
        NirOp::Interrupt => "Interrupt",
        NirOp::ExternCall { .. } => "ExternCall",
        NirOp::NoReturnCall { .. } => "NoReturnCall",
        NirOp::TailCall { .. } => "TailCall",
        NirOp::Unmodeled { .. } => "Unmodeled",
        _ => "Other",
    }
}

fn graded_verdicts() -> BTreeMap<&'static str, &'static str> {
    let mut verdicts: BTreeMap<&'static str, &'static str> = BTreeMap::new();
    for (relative, expected_hash) in FIXTURES {
        let bytes: Vec<u8> = fixture_bytes(relative, expected_hash);
        let reference: Vec<Vec<(&'static str, usize)>> = reference_functions(&bytes);
        let module: NirModule = lift_wasm_module(&bytes).expect("lift the fixture to NIR");
        assert_eq!(
            module.functions.len(),
            reference.len(),
            "{relative} must lift one NIR function per reference code entry"
        );
        for (function, operators) in module.functions.iter().zip(reference.iter()) {
            let function: &NirFunction = function;
            assert_eq!(
                function.instructions.len(),
                operators.len(),
                "{relative} {} must lift one instruction per reference operator",
                function.name
            );
            for (instruction, (variant, offset)) in
                function.instructions.iter().zip(operators.iter())
            {
                let instruction: &NirInstr = instruction;
                let category: &'static str = observed_category(&instruction.op);
                if let Some(previous) = verdicts.insert(variant, category) {
                    assert_eq!(
                        previous, category,
                        "{variant} lifts inconsistently: {previous} then {category} at code offset {offset} in {relative}"
                    );
                }
            }
        }
    }
    verdicts
}

#[test]
fn the_reference_operator_space_is_version_pinned() {
    let space: BTreeMap<&'static str, &'static str> = operator_space();
    assert_eq!(
        space.len(),
        OPERATOR_SPACE,
        "the reference decoder's operator space changed; re-grade the corpus before moving this pin"
    );
    let proposals: BTreeSet<&'static str> = space.values().copied().collect();
    assert!(
        proposals.contains("mvp") && proposals.contains("bulk_memory"),
        "the reference space must span more than one proposal: {proposals:?}"
    );
}

#[test]
fn every_lifted_operator_carries_its_pinned_verdict() {
    let observed: BTreeMap<&'static str, &'static str> = graded_verdicts();
    let pinned: BTreeMap<&'static str, &'static str> = PINNED_VERDICTS.into_iter().collect();
    assert_eq!(
        pinned.len(),
        PINNED_VERDICTS.len(),
        "the pinned verdict table must not repeat an operator"
    );
    assert_eq!(
        observed, pinned,
        "the lifted verdict for at least one reference operator changed"
    );
}

#[test]
fn coverage_is_counted_against_the_reference_space_and_declines_are_named() {
    let space: BTreeMap<&'static str, &'static str> = operator_space();
    let observed: BTreeMap<&'static str, &'static str> = graded_verdicts();
    let structural: BTreeSet<&str> = STRUCTURAL.into_iter().collect();

    let unknown_to_reference: Vec<&&str> = observed
        .keys()
        .filter(|variant: &&&str| !space.contains_key(*variant))
        .collect();
    assert!(
        unknown_to_reference.is_empty(),
        "every graded operator must exist in the reference space: {unknown_to_reference:?}"
    );

    let modelled: BTreeSet<&str> = observed
        .iter()
        .filter(|(_, category): &(&&str, &&str)| **category != "Nop")
        .map(|(variant, _): (&&str, &&str)| *variant)
        .collect();
    let structural_reached: BTreeSet<&str> = observed
        .keys()
        .copied()
        .filter(|variant: &&str| structural.contains(variant))
        .collect();
    let declined: BTreeSet<&str> = observed
        .iter()
        .filter(|(variant, category): &(&&str, &&str)| {
            **category == "Nop" && !structural.contains(*variant)
        })
        .map(|(variant, _): (&&str, &&str)| *variant)
        .collect();

    let absent: BTreeMap<&str, usize> = space.iter().fold(
        BTreeMap::new(),
        |mut acc: BTreeMap<&str, usize>, (variant, proposal)| {
            if !observed.contains_key(variant) {
                *acc.entry(proposal).or_insert(0) += 1;
            }
            acc
        },
    );

    println!(
        "wasm operator coverage: reference space {}, corpus reach {}, modelled {}, structural {}, declined {}",
        space.len(),
        observed.len(),
        modelled.len(),
        structural_reached.len(),
        declined.len()
    );
    println!("wasm spec-present corpus-absent by proposal: {absent:?}");
    println!("wasm declined operators: {declined:?}");

    assert_eq!(observed.len(), REACHED_OPERATORS);
    assert_eq!(modelled.len(), MODELLED_OPERATORS);
    assert_eq!(structural_reached.len(), STRUCTURAL_OPERATORS);
    assert_eq!(
        declined.len(),
        DECLINED_OPERATORS,
        "the declined operator set is pinned; growing it silently widens what the IR omits: {declined:?}"
    );
    assert_eq!(
        space.len().saturating_sub(observed.len()),
        OPERATOR_SPACE.saturating_sub(REACHED_OPERATORS),
        "spec-present but corpus-absent operators are reported, never counted as coverage"
    );
}

#[test]
fn a_single_changed_table_entry_fails_the_gate() {
    let observed: BTreeMap<&'static str, &'static str> = graded_verdicts();
    let pinned: BTreeMap<&'static str, &'static str> = PINNED_VERDICTS.into_iter().collect();
    let mut mutated: BTreeMap<&'static str, &'static str> = observed.clone();
    let previous: Option<&'static str> = mutated.insert("I32Xor", "Nop");
    assert_eq!(
        previous,
        Some("BinOp"),
        "the graded corpus must exercise a modelled binary operator"
    );
    assert_ne!(
        mutated, pinned,
        "dropping one operator from the lifter's table must fail the pinned comparison"
    );
    assert_eq!(observed, pinned);
}

#[test]
fn a_module_without_a_code_section_is_refused_rather_than_scored() {
    for relative in CODELESS_FIXTURES {
        let path: PathBuf = corpus_path(relative);
        let raw: Vec<u8> = std::fs::read(&path).expect("committed wasm corpus entry present");
        let bytes: Vec<u8> = wat::parse_bytes(&raw)
            .expect("assemble the committed wat fixture")
            .into_owned();
        let error: LiftError = lift_wasm_module(&bytes)
            .expect_err("a module with no code section must not lift to an empty module");
        assert!(
            matches!(error, LiftError::Empty),
            "{relative} must refuse with the empty-input error, got {error}"
        );
        assert!(
            reference_functions(&bytes).is_empty(),
            "{relative} must carry no reference code entry"
        );
    }
}
