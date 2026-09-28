#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;

use disrobe_nir::{NirBlock, NirFunction, NirInstr, NirModule, basic_blocks};

type SwitchEdges = Vec<(u64, Vec<u64>)>;

fn repo_path(relative: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push(relative);
    path
}

fn read_bytes(relative: &str) -> Vec<u8> {
    std::fs::read(repo_path(relative))
        .unwrap_or_else(|error| panic!("committed fixture {relative} must be present: {error}"))
}

fn read_text(relative: &str) -> String {
    String::from_utf8(read_bytes(relative)).expect("reference listing is UTF-8")
}

fn function_switch_edges(function: &NirFunction, mnemonics: &[&str]) -> SwitchEdges {
    let mut edges: SwitchEdges = Vec::new();
    for block in basic_blocks(function) {
        let block: NirBlock = block;
        let Some(last): Option<&NirInstr> = block.instructions.last() else {
            continue;
        };
        if !mnemonics.contains(&last.mnemonic.as_str()) {
            continue;
        }
        let successors: Vec<u64> = block
            .successors
            .iter()
            .map(|successor: &u64| successor - function.address)
            .collect();
        edges.push((last.address - function.address, successors));
    }
    edges
}

fn switch_edges(module: &NirModule, mnemonics: &[&str]) -> SwitchEdges {
    let mut edges: SwitchEdges = module
        .functions
        .iter()
        .flat_map(|function: &NirFunction| function_switch_edges(function, mnemonics))
        .collect();
    edges.sort();
    edges
}

fn normalized(mut edges: SwitchEdges) -> SwitchEdges {
    for (_, targets) in &mut edges {
        targets.sort_unstable();
        targets.dedup();
    }
    edges.sort();
    edges
}

fn target_sets(edges: &SwitchEdges) -> Vec<Vec<u64>> {
    let mut sets: Vec<Vec<u64>> = edges
        .iter()
        .map(|(_, targets): &(u64, Vec<u64>)| targets.clone())
        .collect();
    sets.sort();
    sets
}

fn hex(text: &str) -> u64 {
    u64::from_str_radix(text, 16).unwrap_or_else(|error| panic!("hex label {text}: {error}"))
}

fn decimal(text: &str) -> u64 {
    text.parse::<u64>()
        .unwrap_or_else(|error| panic!("decimal offset {text}: {error}"))
}

#[cfg(feature = "jvm")]
fn javap_switches(listing: &str) -> SwitchEdges {
    let mut edges: SwitchEdges = Vec::new();
    let mut current: Option<(u64, Vec<u64>)> = None;
    for line in listing.lines() {
        let trimmed: &str = line.trim();
        if let Some((offset, rest)) = trimmed.split_once(": ")
            && (rest.starts_with("tableswitch") || rest.starts_with("lookupswitch"))
        {
            current = Some((decimal(offset), Vec::new()));
            continue;
        }
        if trimmed == "}" {
            edges.push(current.take().expect("a closing brace ends an open switch"));
            continue;
        }
        if let Some((_, target)) = trimmed.split_once(": ")
            && let Some((_, targets)) = current.as_mut()
        {
            targets.push(decimal(target));
        }
    }
    assert!(current.is_none(), "every javap switch table is closed");
    normalized(edges)
}

#[cfg(feature = "jvm")]
#[test]
fn jvm_switch_successors_equal_javap_targets() {
    use disrobe_nir_lift::lift_classfile;

    let fixtures: [(&str, &str, usize); 2] = [
        (
            "corpus/jvm/evalshapes/SwitchDispatch.class",
            "crates/disrobe-nir-lift/tests/fixtures/switch/SwitchDispatch.javap-switch.txt",
            1,
        ),
        (
            "corpus/jvm/stringer/uh.class",
            "crates/disrobe-nir-lift/tests/fixtures/switch/uh.javap-switch.txt",
            4,
        ),
    ];
    for (class_path, listing_path, count) in fixtures {
        let module: NirModule = lift_classfile(&read_bytes(class_path)).expect("lift classfile");
        let lifted: SwitchEdges = switch_edges(&module, &["tableswitch", "lookupswitch"]);
        let expected: SwitchEdges = javap_switches(&read_text(listing_path));
        assert_eq!(expected.len(), count, "javap switch count for {class_path}");
        assert_eq!(
            lifted, expected,
            "every tableswitch and lookupswitch block in {class_path} must reach exactly the \
             case and default targets javap -c lists"
        );
    }
}

#[cfg(feature = "jvm")]
fn dexdump_switch_offsets(listing: &str) -> Vec<u64> {
    let mut offsets: Vec<u64> = listing
        .lines()
        .filter_map(|line: &str| {
            let (_, instruction) = line.split_once('|')?;
            let (offset, rest) = instruction.split_once(": ")?;
            let is_switch: bool = (rest.starts_with("packed-switch ")
                || rest.starts_with("sparse-switch "))
                && !rest.contains("-data");
            is_switch.then(|| hex(offset))
        })
        .collect();
    offsets.sort_unstable();
    offsets
}

#[cfg(feature = "jvm")]
fn jadx_switch_target_sets(listing: &str) -> Vec<Vec<u64>> {
    let mut sets: Vec<Vec<u64>> = Vec::new();
    let mut current: Option<Vec<u64>> = None;
    for line in listing.lines() {
        let trimmed: &str = line.trim();
        if trimmed.starts_with("switch(") {
            current = Some(Vec::new());
            continue;
        }
        if trimmed == "}" {
            let mut targets: Vec<u64> = current.take().expect("a closing brace ends a switch");
            targets.sort_unstable();
            targets.dedup();
            sets.push(targets);
            continue;
        }
        if let Some((_, label)) = trimmed.split_once("goto L")
            && let Some(targets) = current.as_mut()
        {
            targets.push(hex(label.trim_end_matches(';')));
        }
    }
    assert!(current.is_none(), "every jadx switch block is closed");
    sets.sort();
    sets
}

#[cfg(feature = "jvm")]
#[test]
fn dalvik_switch_successors_equal_dexdump_and_jadx() {
    use disrobe_nir_lift::lift_dex;

    let module: NirModule =
        lift_dex(&read_bytes("corpus/jvm/dex/EdgeCases.dex")).expect("lift dex");
    let lifted: SwitchEdges = switch_edges(&module, &["packed-switch", "sparse-switch"]);
    let offsets: Vec<u64> = dexdump_switch_offsets(&read_text(
        "crates/disrobe-nir-lift/tests/fixtures/switch/EdgeCases.dexdump-switch.txt",
    ));
    let sets: Vec<Vec<u64>> = jadx_switch_target_sets(&read_text(
        "crates/disrobe-nir-lift/tests/fixtures/switch/EdgeCases.jadx-switch.txt",
    ));
    assert_eq!(offsets.len(), 4, "dexdump lists four switches");
    assert_eq!(
        sets.len(),
        offsets.len(),
        "jadx and dexdump agree on the count"
    );
    let lifted_offsets: Vec<u64> = lifted
        .iter()
        .map(|(offset, _): &(u64, Vec<u64>)| *offset)
        .collect();
    assert_eq!(
        lifted_offsets, offsets,
        "lifted switch blocks end where dexdump -d places each switch"
    );
    assert_eq!(
        target_sets(&lifted),
        sets,
        "every packed-switch block must reach exactly the case and default targets jadx lists"
    );
}

#[cfg(feature = "dotnet")]
fn ilspy_switches(listing: &str) -> SwitchEdges {
    let edges: SwitchEdges = listing
        .lines()
        .filter_map(|line: &str| {
            let rest: &str = line.trim().strip_prefix("IL_")?;
            let (offset, operands) = rest.split_once(": switch (")?;
            let labels: Vec<u64> = operands
                .trim_end_matches(')')
                .split(", ")
                .map(|label: &str| hex(label.trim_start_matches("IL_")))
                .collect();
            let count: u64 = u64::try_from(labels.len()).expect("label count fits");
            let fallthrough: u64 = hex(offset) + 1 + 4 + 4 * count;
            let mut targets: Vec<u64> = labels;
            targets.push(fallthrough);
            Some((hex(offset), targets))
        })
        .collect();
    normalized(edges)
}

#[cfg(feature = "dotnet")]
#[test]
fn cil_switch_successors_equal_ilspy_targets() {
    use disrobe_nir_lift::lift_dotnet_pe;

    let module: NirModule =
        lift_dotnet_pe(&read_bytes("corpus/dotnet/megafile/EdgeCases.baseline.dll"))
            .expect("lift dotnet pe");
    let lifted: SwitchEdges = switch_edges(&module, &["switch"]);
    let expected: SwitchEdges = ilspy_switches(&read_text(
        "crates/disrobe-nir-lift/tests/fixtures/switch/EdgeCases.baseline.ilspy-switch.txt",
    ));
    assert_eq!(expected.len(), 6, "ilspycmd lists six switches");
    assert_eq!(
        lifted, expected,
        "every CIL switch block must reach its targets and the next instruction as ilspycmd -il \
         lists them"
    );
}

#[cfg(feature = "as3")]
fn jpexs_switches(listing: &str) -> Vec<(String, Vec<u64>)> {
    let mut switches: Vec<(String, Vec<u64>)> = Vec::new();
    let mut method: Option<String> = None;
    for line in listing.lines() {
        let trimmed: &str = line.trim();
        if let Some(rest) = trimmed.strip_prefix("trait method QName(") {
            let name: &str = rest
                .rsplit_once(",\"")
                .and_then(|(_, tail): (&str, &str)| tail.strip_suffix("\")"))
                .unwrap_or_else(|| panic!("trait method line {trimmed}"));
            method = Some(name.to_owned());
            continue;
        }
        let Some(operands) = trimmed.strip_prefix("lookupswitch ") else {
            continue;
        };
        let mut targets: Vec<u64> = operands
            .split([',', '[', ']', ' '])
            .filter(|token: &&str| !token.is_empty())
            .map(|token: &str| hex(token.trim_start_matches("ofs")))
            .collect();
        targets.sort_unstable();
        targets.dedup();
        let owner: String = method
            .clone()
            .expect("a lookupswitch sits inside a named trait method");
        switches.push((owner, targets));
    }
    switches.sort();
    switches
}

#[cfg(feature = "as3")]
#[test]
fn avm2_switch_successors_equal_jpexs_targets() {
    use disrobe_nir_lift::lift_swf_abc;

    let fixtures: [(&str, &str, &str); 2] = [
        (
            "corpus/flash/avm2_disasm_oracle/opcode_breadth.swf",
            "corpus/flash/avm2_disasm_oracle/opcode_breadth.pcode.txt",
            "selector",
        ),
        (
            "corpus/flash/avm2_disasm_oracle/control_shapes.swf",
            "corpus/flash/avm2_disasm_oracle/control_shapes.pcode.txt",
            "enums",
        ),
    ];
    for (program, listing, method) in fixtures {
        let module: NirModule = lift_swf_abc(&read_bytes(program)).expect("lift swf");
        let expected: Vec<(String, Vec<u64>)> = jpexs_switches(&read_text(listing));
        let expected_names: Vec<&str> = expected
            .iter()
            .map(|(name, _): &(String, Vec<u64>)| name.as_str())
            .collect();
        assert_eq!(
            expected_names,
            vec![method],
            "the JPEXS listing of {program} prints one lookupswitch, in {method}"
        );
        let mut lifted: Vec<(String, Vec<u64>)> = Vec::new();
        for function in &module.functions {
            if !expected_names.contains(&function.name.as_str()) {
                continue;
            }
            for (_, targets) in function_switch_edges(function, &["lookupswitch"]) {
                lifted.push((function.name.clone(), targets));
            }
        }
        lifted.sort();
        assert_eq!(
            lifted, expected,
            "the lookupswitch block of {method} in {program} must reach exactly the default and              case targets JPEXS lists"
        );
    }
}

#[cfg(feature = "ruby")]
fn ruby_case_dispatches(listing: &str) -> SwitchEdges {
    let edges: SwitchEdges = listing
        .lines()
        .map(|line: &str| {
            let (position, targets) = line
                .split_once(": ")
                .unwrap_or_else(|| panic!("reference row {line}"));
            (
                decimal(position),
                targets.split(' ').map(decimal).collect::<Vec<u64>>(),
            )
        })
        .collect();
    normalized(edges)
}

#[cfg(feature = "ruby")]
#[test]
fn yarv_case_dispatch_successors_equal_ruby_iseq_labels() {
    use std::collections::BTreeMap;

    use disrobe_nir_lift::lift_ruby_iseq;
    use disrobe_pass_ruby::{IbfImage, YarvIbfInstruction, YarvIseqBody, analyze_bytes};

    let bytes: Vec<u8> = read_bytes("corpus/ruby/mri/yarv/edge_cases.rb.yarvc");
    let module: NirModule = lift_ruby_iseq(&bytes).expect("lift yarv image");
    let image: IbfImage = analyze_bytes(&bytes, "edge_cases.rb.yarvc")
        .expect("analyze yarv image")
        .yarv
        .expect("yarv flavor")
        .ibf;
    assert_eq!(module.functions.len(), image.iseqs.len());
    let mut slot_of: BTreeMap<u64, u64> = BTreeMap::new();
    for (function, body) in module.functions.iter().zip(&image.iseqs) {
        let body: &YarvIseqBody = body;
        let mut slot: u64 = 0;
        for instruction in &body.instructions {
            let instruction: &YarvIbfInstruction = instruction;
            slot_of.insert(function.address + u64::from(instruction.pc), slot);
            slot += 1 + u64::try_from(instruction.operands.len()).expect("operand count fits");
        }
    }
    let slot = |address: u64| -> u64 {
        *slot_of
            .get(&address)
            .unwrap_or_else(|| panic!("lifted address {address:#x} is an instruction"))
    };
    let mut lifted: SwitchEdges = Vec::new();
    for function in &module.functions {
        for block in basic_blocks(function) {
            let Some(last): Option<&NirInstr> = block.instructions.last() else {
                continue;
            };
            if last.mnemonic != "opt_case_dispatch" {
                continue;
            }
            lifted.push((
                slot(last.address),
                block
                    .successors
                    .iter()
                    .map(|target: &u64| slot(*target))
                    .collect(),
            ));
        }
    }
    let lifted: SwitchEdges = normalized(lifted);
    let expected: SwitchEdges = ruby_case_dispatches(&read_text(
        "crates/disrobe-nir-lift/tests/fixtures/switch/edge_cases.case_dispatch.txt",
    ));
    assert_eq!(
        expected.len(),
        1,
        "the megafile has one optimized case dispatch"
    );
    assert_eq!(
        lifted, expected,
        "opt_case_dispatch must reach every case body, the else body and the fall-through that \
         RubyVM::InstructionSequence#to_a labels"
    );
}
