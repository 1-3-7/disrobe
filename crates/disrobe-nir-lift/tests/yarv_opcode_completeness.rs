#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_nir::{NirFunction, NirInstr, NirModule, NirOp};
use disrobe_nir_lift::lift_ruby_iseq;
use disrobe_pass_ruby::{IbfImage, YarvAnalysis, YarvIbfInstruction, YarvIseqBody, analyze_bytes};

const COMMITTED_FIXTURES: [&str; 5] = [
    "hello.rb.yarvc",
    "greeter.rb.yarvc",
    "literals.rb.yarvc",
    "edge_cases.rb.yarvc",
    "opassign.rb.yarvc",
];

fn fixture_bytes(name: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus");
    path.push("ruby");
    path.push("mri");
    path.push("yarv");
    path.push(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("committed YARV fixture {name} present: {e}"))
}

#[derive(Debug, Default)]
struct NirStats {
    total: usize,
    unmodeled: usize,
    nop: usize,
    opcodes: BTreeSet<u8>,
    mnemonics: BTreeSet<String>,
}

fn image_of(bytes: &[u8], label: &str) -> IbfImage {
    let analysis: YarvAnalysis = analyze_bytes(bytes, label)
        .expect("analyze YARV image")
        .yarv
        .expect("yarv flavor present");
    analysis.ibf
}

fn invariants(bytes: &[u8], label: &str) -> NirStats {
    let module: NirModule = lift_ruby_iseq(bytes).expect("lift YARV image to NIR");
    let image: IbfImage = image_of(bytes, label);
    assert_eq!(
        module.functions.len(),
        image.iseqs.len(),
        "one lifted function per decoded iseq for {label}"
    );

    let mut stats: NirStats = NirStats::default();
    for (function, body) in module.functions.iter().zip(&image.iseqs) {
        let function: &NirFunction = function;
        let body: &YarvIseqBody = body;
        assert_eq!(
            function.instructions.len(),
            body.instructions.len(),
            "one lifted instruction per decoded YARV instruction for {} in {label}",
            function.name
        );
        for (nir, ibf) in function.instructions.iter().zip(&body.instructions) {
            let nir: &NirInstr = nir;
            let ibf: &YarvIbfInstruction = ibf;
            assert_eq!(
                nir.mnemonic, ibf.mnemonic,
                "lifted mnemonic must track the decoded YARV instruction in {}",
                function.name
            );
            let opcode: u8 = u8::try_from(ibf.opcode).unwrap_or(u8::MAX);
            stats.total += 1;
            stats.opcodes.insert(opcode);
            stats.mnemonics.insert(ibf.mnemonic.clone());
            match &nir.op {
                NirOp::Nop => {
                    stats.nop += 1;
                    assert_eq!(
                        ibf.mnemonic, "nop",
                        "only a real nop lifts to Nop, saw {} at pc {} in {}",
                        ibf.mnemonic, ibf.pc, function.name
                    );
                }
                NirOp::Unmodeled {
                    opcode: carried,
                    offset,
                } => {
                    assert_eq!(
                        *carried, opcode,
                        "Unmodeled must carry the real opcode for {} in {}",
                        ibf.mnemonic, function.name
                    );
                    assert_eq!(
                        *offset, ibf.pc,
                        "Unmodeled must carry the real offset for {} in {}",
                        ibf.mnemonic, function.name
                    );
                    stats.unmodeled += 1;
                }
                _ => assert_ne!(
                    ibf.mnemonic, "nop",
                    "a real nop must never lift to a modeled op in {}",
                    function.name
                ),
            }
        }
    }
    stats
}

#[test]
fn committed_yarv_fixtures_surface_unmodeled_without_silent_nop() {
    let mut merged: NirStats = NirStats::default();
    for name in COMMITTED_FIXTURES {
        let stats: NirStats = invariants(&fixture_bytes(name), name);
        assert!(stats.total > 0, "{name} must lift to instructions");
        merged.total += stats.total;
        merged.unmodeled += stats.unmodeled;
        merged.nop += stats.nop;
        merged.opcodes.extend(stats.opcodes);
        merged.mnemonics.extend(stats.mnemonics);
    }
    assert!(
        merged.unmodeled >= 5,
        "unmodeled YARV instructions must be surfaced, not collapsed to Nop: {}",
        merged.unmodeled
    );
    assert!(
        merged.opcodes.len() >= 20,
        "the opcode range must be non-vacuous: {} distinct",
        merged.opcodes.len()
    );
    for mnemonic in ["putobject", "putself", "leave", "opt_plus"] {
        assert!(
            merged.mnemonics.contains(mnemonic),
            "the opcode range must include {mnemonic}: {:?}",
            merged.mnemonics
        );
    }
}

#[test]
fn stack_manipulation_opcodes_surface_as_unmodeled_not_nop() {
    let mut saw: BTreeSet<String> = BTreeSet::new();
    for name in COMMITTED_FIXTURES {
        let bytes: Vec<u8> = fixture_bytes(name);
        let module: NirModule = lift_ruby_iseq(&bytes).expect("lift YARV image to NIR");
        for function in &module.functions {
            for instr in &function.instructions {
                let instr: &NirInstr = instr;
                if matches!(
                    instr.mnemonic.as_str(),
                    "dup" | "pop" | "swap" | "putspecialobject" | "definemethod" | "defineclass"
                ) {
                    saw.insert(instr.mnemonic.clone());
                    assert!(
                        instr.op.is_unmodeled(),
                        "{} must never collapse to a silent Nop, saw {:?}",
                        instr.mnemonic,
                        instr.op
                    );
                }
            }
        }
    }
    assert!(
        !saw.is_empty(),
        "the committed fixtures exercise unmodeled stack and definition opcodes"
    );
}

fn ruby_version() -> Option<(u32, u32)> {
    let output: Output = Command::new("ruby").arg("--version").output().ok()?;
    let text: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let rest: &str = text.strip_prefix("ruby ")?;
    let mut parts: std::str::Split<'_, char> = rest.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    Some((major, minor))
}

const BROAD_SOURCES: [&str; 2] = [
    "GLOBAL = 7\n\
     class Greeter\n\
       def initialize(name)\n\
         @name = name\n\
         @count = 0\n\
       end\n\
       def greet(prefix)\n\
         @count += 1\n\
         msg = prefix + \" \" + @name\n\
         if @count > 3\n\
           puts msg\n\
         else\n\
           puts \"hi\"\n\
         end\n\
         arr = [1, 2, @count]\n\
         h = { a: 1, b: msg }\n\
         total = 0\n\
         arr.each { |x| total = total + x }\n\
         total < GLOBAL ? total : GLOBAL\n\
       end\n\
     end\n\
     g = Greeter.new(\"world\")\n\
     3.times { g.greet(\"hello\") }\n",
    "def classify(n)\n\
       case n\n\
       when 0 then :zero\n\
       when 1..9 then :small\n\
       else :big\n\
       end\n\
     end\n\
     values = [0, 5, 42]\n\
     acc = 0\n\
     values.each do |v|\n\
       acc = acc + v unless v.nil?\n\
       acc = acc * 2 if v > 3\n\
     end\n\
     $result = acc\n\
     while acc > 0\n\
       acc -= 1\n\
     end\n",
];

fn compile_with_ruby(scratch: &Path, source: &str, index: usize) -> Option<(Vec<u8>, String)> {
    let src_path: PathBuf = scratch.join(format!("broad_{index}.rb"));
    let bin_path: PathBuf = scratch.join(format!("broad_{index}.yarb"));
    std::fs::write(&src_path, source).expect("write ruby source");
    let script: &str = "src = File.read(ARGV[0]); \
         iseq = RubyVM::InstructionSequence.compile(src); \
         File.binwrite(ARGV[1], iseq.to_binary); \
         STDOUT.write(iseq.disasm)";
    let output: Output = Command::new("ruby")
        .arg("-e")
        .arg(script)
        .arg(&src_path)
        .arg(&bin_path)
        .output()
        .expect("run ruby compile+disasm");
    if !output.status.success() {
        eprintln!(
            "ruby compile failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return None;
    }
    let binary: Vec<u8> = std::fs::read(&bin_path).expect("read compiled YARV binary");
    let disasm: String = String::from_utf8_lossy(&output.stdout).into_owned();
    Some((binary, disasm))
}

fn is_mnemonic(token: &str) -> bool {
    let mut chars: std::str::Chars<'_> = token.chars();
    let Some(first): Option<char> = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    token
        .chars()
        .all(|c: char| c.is_ascii_alphanumeric() || c == '_')
}

fn disasm_streams(disasm: &str) -> Vec<Vec<String>> {
    let mut streams: Vec<Vec<String>> = Vec::new();
    let mut current: Option<Vec<String>> = None;
    for line in disasm.lines() {
        let trimmed: &str = line.trim_start();
        if trimmed.starts_with("== disasm:") {
            if let Some(done) = current.replace(Vec::new()) {
                streams.push(done);
            }
            continue;
        }
        let mut tokens: std::str::SplitWhitespace<'_> = trimmed.split_whitespace();
        let Some(pc_token): Option<&str> = tokens.next() else {
            continue;
        };
        if pc_token.len() < 4 || !pc_token.bytes().all(|b: u8| b.is_ascii_digit()) {
            continue;
        }
        let Some(mnemonic): Option<&str> = tokens.next() else {
            continue;
        };
        if !is_mnemonic(mnemonic) {
            continue;
        }
        if let Some(stream) = current.as_mut() {
            stream.push(mnemonic.to_owned());
        }
    }
    if let Some(done) = current.take() {
        streams.push(done);
    }
    streams.retain(|stream: &Vec<String>| !stream.is_empty());
    streams.sort();
    streams
}

fn lifted_streams(module: &NirModule) -> Vec<Vec<String>> {
    let mut streams: Vec<Vec<String>> = module
        .functions
        .iter()
        .map(|function: &NirFunction| {
            function
                .instructions
                .iter()
                .map(|instr: &NirInstr| instr.mnemonic.clone())
                .collect::<Vec<String>>()
        })
        .filter(|stream: &Vec<String>| !stream.is_empty())
        .collect();
    streams.sort();
    streams
}

#[test]
fn yarv_lift_agrees_with_ruby_disasm_and_surfaces_unmodeled() {
    let Some((major, minor)): Option<(u32, u32)> = ruby_version() else {
        eprintln!("skipping RubyVM#disasm agreement: ruby not on PATH");
        return;
    };

    let scratch: PathBuf =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("yarv_opcode_completeness");
    std::fs::create_dir_all(&scratch).expect("create scratch dir");

    let mut union: BTreeSet<String> = BTreeSet::new();
    let mut checked_sources: usize = 0;
    let mut total_unmodeled: usize = 0;

    for (index, source) in BROAD_SOURCES.iter().enumerate() {
        let Some((binary, disasm)): Option<(Vec<u8>, String)> =
            compile_with_ruby(&scratch, source, index)
        else {
            continue;
        };

        let expected: Vec<Vec<String>> = disasm_streams(&disasm);
        assert!(
            !expected.is_empty(),
            "RubyVM#disasm must decode instructions for source {index}"
        );

        let module: NirModule = lift_ruby_iseq(&binary).expect("lift compiled YARV binary");
        let lifted: Vec<Vec<String>> = lifted_streams(&module);
        assert_eq!(
            lifted, expected,
            "disrobe lifted mnemonic stream must equal RubyVM#disasm for source {index} (ruby {major}.{minor})"
        );

        let stats: NirStats = invariants(&binary, &format!("broad_{index}"));
        total_unmodeled += stats.unmodeled;
        union.extend(stats.mnemonics);
        checked_sources += 1;
    }

    if checked_sources == 0 {
        eprintln!("skipping RubyVM#disasm agreement: ruby present but produced no usable output");
        return;
    }

    assert!(
        total_unmodeled >= 1,
        "the graded sources must surface unmodeled opcodes"
    );
    assert!(
        union.len() >= 25,
        "the graded opcode range must be non-vacuous: {} distinct",
        union.len()
    );
    for mnemonic in [
        "putobject",
        "putself",
        "putchilledstring",
        "getlocal_WC_0",
        "setlocal_WC_0",
        "getinstancevariable",
        "setinstancevariable",
        "defineclass",
        "definemethod",
        "branchunless",
        "opt_plus",
        "opt_lt",
        "newarray",
        "duphash",
        "opt_send_without_block",
        "send",
        "leave",
        "dup",
        "pop",
    ] {
        assert!(
            union.contains(mnemonic),
            "the graded opcode range must include {mnemonic}: {union:?}"
        );
    }
}
