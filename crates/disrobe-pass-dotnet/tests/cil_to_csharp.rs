#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_pass_dotnet::cil::{Instruction, MethodBody, disassemble};
use disrobe_pass_dotnet::decompile::{CSharpPseudo, emit_csharp};

#[test]
fn pseudo_csharp_emits_method_skeleton() {
    let code: [u8; 4] = [0x16, 0x17, 0x58, 0x2A];
    let instructions: Vec<Instruction> = disassemble(&code).expect("disasm");
    let body: MethodBody = MethodBody {
        max_stack: 2,
        code_size: 4,
        local_var_sig_tok: 0,
        init_locals: false,
        instructions,
    };
    let out: CSharpPseudo = emit_csharp("Sum", &body);
    assert!(out.body.contains("void Sum()"));
    assert!(out.body.contains("ldc.i4.0"));
    assert!(out.body.contains("ldc.i4.1"));
    assert!(out.body.contains("add"));
    assert!(out.body.contains("ret"));
    assert_eq!(out.flow_summary.returns, 1);
}

#[test]
fn pseudo_csharp_counts_branches_and_calls() {
    let code: [u8; 9] = [0x16, 0x2C, 0x02, 0x28, 0x00, 0x00, 0x00, 0x00, 0x2A];
    let instructions: Vec<Instruction> = disassemble(&code).expect("disasm");
    let body: MethodBody = MethodBody {
        max_stack: 1,
        code_size: 9,
        local_var_sig_tok: 0,
        init_locals: false,
        instructions,
    };
    let out: CSharpPseudo = emit_csharp("M", &body);
    assert_eq!(out.flow_summary.branches, 1);
    assert_eq!(out.flow_summary.calls, 1);
    assert_eq!(out.flow_summary.returns, 1);
}
