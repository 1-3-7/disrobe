#![allow(clippy::expect_used, clippy::unwrap_used, clippy::print_stderr)]
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_ruby::{
    IrepTree, MrubyInstruction, RubyAnalysis, analyze_bytes, disassemble_iseq,
};

fn corpus_path(rel: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus");
    path.push("ruby");
    for seg in rel.split('/') {
        path.push(seg);
    }
    path
}

struct MriCall {
    method: String,
    argc: u32,
    string_arg: Option<String>,
}

fn mri_oracle_for(source: &str) -> Option<MriCall> {
    let script: String = format!("puts RubyVM::InstructionSequence.compile({source:?}).disasm");
    let output: std::process::Output = Command::new("ruby").arg("-e").arg(&script).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let disasm: String = String::from_utf8_lossy(&output.stdout).into_owned();

    let mut method: Option<String> = None;
    let mut argc: Option<u32> = None;
    for line in disasm.lines() {
        if line.contains("opt_send_without_block") || line.contains("send") {
            if let Some(mid_at) = line.find("mid:") {
                let rest: &str = &line[mid_at + 4..];
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                method = Some(name);
            }
            if let Some(argc_at) = line.find("argc:") {
                let rest: &str = &line[argc_at + 5..];
                let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
                argc = digits.parse::<u32>().ok();
            }
        }
    }

    let string_arg: Option<String> = disasm.lines().find_map(|line| {
        if line.contains("putchilledstring") || line.contains("putstring") {
            let first: usize = line.find('"')?;
            let rest: &str = &line[first + 1..];
            let end: usize = rest.find('"')?;
            Some(rest[..end].to_owned())
        } else {
            None
        }
    });

    Some(MriCall {
        method: method?,
        argc: argc?,
        string_arg,
    })
}

fn mnemonics(iseq: &[u8]) -> Vec<String> {
    disassemble_iseq(iseq)
        .expect("real mrbc iseq disassembles")
        .iter()
        .map(|i: &MrubyInstruction| i.mnemonic.clone())
        .collect()
}

#[test]
fn mruby_decode_grades_against_a_real_mrbc_artifact() {
    let bytes: Vec<u8> = std::fs::read(corpus_path("mruby/greet.mrb"))
        .expect("real mruby/greet.mrb fixture present");
    assert_eq!(&bytes[..4], b"RITE", "fixture is a real RITE binary");
    assert_eq!(
        &bytes[4..8],
        b"0300",
        "fixture is mruby 3.x RITE format 0300"
    );

    let source: String =
        std::fs::read_to_string(corpus_path("mruby/greet.rb")).expect("real greet.rb source");
    assert!(
        source.contains("def greet(name)"),
        "the compiled source defines greet(name)"
    );
    assert!(
        source.contains("greet(\"world\")"),
        "the compiled source calls greet(\"world\")"
    );

    let analysis: RubyAnalysis = analyze_bytes(&bytes, "greet.mrb").expect("analyze real mrb");
    let mrb = analysis.mruby.expect("mruby analysis present");

    assert!(
        mrb.binary.has_debug,
        "the -g compiled fixture carries a real DBG section"
    );
    assert!(
        mrb.binary.has_lvar,
        "the fixture carries a real LVAR section"
    );

    let tree: IrepTree = mrb.irep.expect("real irep tree parsed");
    assert_eq!(
        tree.records.len(),
        2,
        "real mrbc emits a top-level irep plus the greet method irep"
    );

    let top: &disrobe_pass_ruby::IrepRecord = &tree.records[0];
    assert_eq!(top.nregs, 4);
    assert_eq!(top.insn_len, 18);
    assert_eq!(top.child_count, 1);
    assert_eq!(
        mnemonics(&top.iseq),
        vec![
            "TCLASS", "METHOD", "DEF", "STRING", "SSEND", "RETURN", "STOP"
        ],
        "the top-level iseq must decode to the exact opcode sequence real mrbc emitted"
    );
    assert!(
        top.symbols.contains(&"greet".to_owned()),
        "the method symbol greet is recovered from the real symbol table"
    );
    assert_eq!(
        top.pool.first().and_then(|p| p.value.clone()),
        Some("world".to_owned()),
        "the string literal world is recovered from the real pool"
    );

    let method_irep: &disrobe_pass_ruby::IrepRecord = &tree.records[1];
    let enter: &MrubyInstruction = &disassemble_iseq(&method_irep.iseq).expect("method iseq")[0];
    assert_eq!(enter.mnemonic, "ENTER", "the method body begins with ENTER");
    let arg_spec: u32 = enter.operands.first().copied().unwrap_or(0);
    let required_args: u32 = (arg_spec >> 18) & 0x1f;
    assert_eq!(
        required_args, 1,
        "the real ENTER argument spec encodes greet's single required argument"
    );
    assert!(
        method_irep.symbols.contains(&"puts".to_owned()),
        "the method body calls puts"
    );
    assert!(
        mnemonics(&method_irep.iseq).contains(&"SSEND".to_owned()),
        "the puts call in the method body is a self-send"
    );

    let recovered: &disrobe_pass_ruby::MrubyDecompiled = &mrb.decompiled;
    assert!(recovered.has_body, "the real artifact reconstructs a body");
    assert!(recovered.recovered_symbols.contains(&"greet".to_owned()));
    assert!(recovered.recovered_symbols.contains(&"puts".to_owned()));
    assert!(recovered.recovered_strings.contains(&"world".to_owned()));
    assert!(
        body_has_call_line(&recovered.source, "greet(\"world\")"),
        "the lift must reconstruct the exact greet(\"world\") call, got:\n{}",
        recovered.source
    );
    assert!(
        recovered.source.contains("def greet(arg0)"),
        "the lift must reconstruct greet with its single parameter, got:\n{}",
        recovered.source
    );
    assert!(
        recovered.source.contains("puts("),
        "the lift must reconstruct the puts call inside the method, got:\n{}",
        recovered.source
    );

    if let Some(call) = mri_oracle_for("greet(\"world\")") {
        assert_eq!(
            call.method, "greet",
            "an independent ruby vm confirms the method name"
        );
        assert_eq!(call.argc, 1, "an independent ruby vm confirms argc 1");
        assert_eq!(
            call.string_arg.as_deref(),
            Some("world"),
            "an independent ruby vm confirms the string argument"
        );
        let expected: String = match call.string_arg {
            Some(arg) => format!("{}({:?})", call.method, arg),
            None => call.method,
        };
        assert!(
            body_has_call_line(&recovered.source, &expected),
            "the lift must reproduce the ruby-confirmed call {expected}, got:\n{}",
            recovered.source
        );
    } else {
        eprintln!("note: host ruby unavailable; graded against the real mrbc artifact only");
    }
}

fn body_has_call_line(source: &str, call: &str) -> bool {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .any(|line| line.trim() == call)
}
