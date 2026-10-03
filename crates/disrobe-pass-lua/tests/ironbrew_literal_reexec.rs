#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::time::Duration;

use disrobe_pass_lua::obfuscator::ironbrew2_dispatch::{IbOpcode, RetForm};
use disrobe_pass_lua::obfuscator::ironbrew2_emit::emit_program;
use disrobe_pass_lua::obfuscator::ironbrew2_real::{IbChunk, IbInstr, IbType};
use disrobe_pass_lua::reader::common::LuaConstant;
use disrobe_testkit::{CommandSpec, ToolOutput, tool_output};

fn run(source: &str) -> String {
    let output: ToolOutput = tool_output(
        CommandSpec::new("lua", Duration::from_secs(8))
            .arg("-e")
            .arg(source),
    )
    .expect("the literal oracle requires the Lua interpreter on PATH");
    assert!(
        output.success,
        "Lua rejected the literal program: {}",
        output.stderr_text()
    );
    output.stdout_text().replace("\r\n", "\n")
}

fn observe_returned_string(source: &str) -> String {
    format!(
        "local value = (function(...)\n{source}\nend)(); print(#value, string.byte(value, 1, #value))"
    )
}

#[test]
fn ironbrew_control_byte_followed_by_a_digit_matches_the_original_lua_bytes() {
    let chunk: IbChunk = IbChunk {
        constants: vec![LuaConstant::Str("\u{1}2".to_owned())],
        param_count: 0,
        instrs: vec![
            IbInstr {
                itype: IbType::ABx,
                mask: 0,
                op: 1,
                a: 0,
                b: 1,
                c: 0,
            },
            IbInstr {
                itype: IbType::Abc,
                mask: 0,
                op: 2,
                a: 0,
                b: 0,
                c: 0,
            },
        ],
        functions: Vec::new(),
    };
    let optable: BTreeMap<u16, Vec<IbOpcode>> = BTreeMap::from([
        (1, vec![IbOpcode::LoadK]),
        (2, vec![IbOpcode::Return(RetForm::Two)]),
    ]);
    let original: String = observe_returned_string("return string.char(1) .. '2'");
    let expected: String = run(&original);
    assert_eq!(expected, "2\t1\t50\n");
    let recovered: String = emit_program(&chunk, &optable);
    assert_eq!(run(&observe_returned_string(&recovered)), expected);
    let mutated: String = recovered.replacen("\\0012", "\\12", 1);
    assert_ne!(mutated, recovered, "the literal mutation must reach output");
    assert_ne!(run(&observe_returned_string(&mutated)), expected);
}
