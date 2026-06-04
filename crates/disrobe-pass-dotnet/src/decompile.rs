use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::cil::{FlowControl, Instruction, MethodBody, OperandValue, parse_method_body};
use crate::error::Result;
use crate::metadata::{MetadataRoot, parse_metadata_root};
use crate::model::{MethodModel, Resolver, TypeModel};
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use crate::structurize::{MethodNamer, StructuredMethod, TargetLang, decompile_method_in};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CSharpPseudo {
    pub method_name: String,
    pub body: String,
    pub instruction_count: u32,
    pub flow_summary: FlowSummary,
}

/// Full native decompilation output for an assembly: per-method structured pseudo-C# with resolved
/// type/member names, requiring no .NET runtime or external decompiler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompiledAssembly {
    pub module_name: String,
    pub methods: Vec<StructuredMethod>,
    pub methods_decompiled: u32,
    pub methods_bodyless: u32,
    pub methods_failed: u32,
}

/// Decompile every method body in a managed PE image to structured pseudo-C#.
///
/// Uses the native stack-lifting decompiler with metadata-resolved names. Method bodies that fail
/// to parse (e.g. obfuscated or encrypted) are counted but do not abort the whole assembly.
pub fn decompile_assembly(image: &[u8]) -> Result<DecompiledAssembly> {
    decompile_assembly_in(image, TargetLang::CSharp)
}

/// Decompile every method body in a managed PE image to structured pseudo-source in the requested
/// [`TargetLang`]. Behaves identically to [`decompile_assembly`] for `TargetLang::CSharp`.
pub fn decompile_assembly_in(image: &[u8], lang: TargetLang) -> Result<DecompiledAssembly> {
    let pe: PeImage = parse(image)?;
    let clr: ClrHeader = parse_clr_header(image, &pe)?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr)?;
    let resolver: Resolver = Resolver::build(image, &pe, &clr, &root)?;
    let model: crate::model::AssemblyModel = resolver.model();

    let mut methods: Vec<StructuredMethod> = Vec::new();
    let mut bodyless: u32 = 0;
    let mut failed: u32 = 0;
    for ty in &model.types {
        let state_machine: Option<crate::state_machine::StateMachine> =
            crate::state_machine::classify(ty);
        for m in &ty.methods {
            decompile_one(
                &pe,
                image,
                &resolver,
                ty,
                m,
                state_machine.as_ref(),
                lang,
                &mut methods,
                &mut bodyless,
                &mut failed,
            );
        }
    }
    let decompiled: u32 = u32::try_from(methods.len()).unwrap_or(u32::MAX);
    Ok(DecompiledAssembly {
        module_name: model.module_name,
        methods,
        methods_decompiled: decompiled,
        methods_bodyless: bodyless,
        methods_failed: failed,
    })
}

#[allow(clippy::too_many_arguments)]
fn decompile_one(
    pe: &PeImage,
    image: &[u8],
    resolver: &Resolver,
    ty: &TypeModel,
    m: &MethodModel,
    state_machine: Option<&crate::state_machine::StateMachine>,
    lang: TargetLang,
    methods: &mut Vec<StructuredMethod>,
    bodyless: &mut u32,
    failed: &mut u32,
) {
    if m.rva == 0 {
        *bodyless = bodyless.saturating_add(1);
        return;
    }
    let Some(off): Option<usize> = pe.rva_to_offset(m.rva) else {
        *failed = failed.saturating_add(1);
        return;
    };
    if off >= image.len() {
        *failed = failed.saturating_add(1);
        return;
    }
    match parse_method_body(&image[off..]) {
        Ok(body) => {
            let header_sig: String = match lang {
                TargetLang::CSharp => {
                    format!("// {}\n{}", ty.full_name, m.csharp_signature())
                }
                TargetLang::FSharp => {
                    format!("// {}\n{}", ty.full_name, m.fsharp_signature())
                }
                TargetLang::VbNet => {
                    format!("' {}\n{}", ty.full_name, m.vbnet_signature())
                }
            };
            let namer: MethodNamer<'_> = MethodNamer {
                resolver,
                has_this: !m.is_static(),
            };
            let mut structured: StructuredMethod =
                decompile_method_in(&header_sig, &body, &namer, lang);
            if lang == TargetLang::CSharp
                && let Some(sm) = state_machine
                && crate::state_machine::is_move_next(m)
            {
                let (reversed, _points): (String, u32) =
                    crate::state_machine_reverse::reverse_move_next(&structured.body, sm);
                structured.body = reversed;
            }
            methods.push(structured);
        }
        Err(_) => *failed = failed.saturating_add(1),
    }
}

#[derive(Debug, Clone, Default, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowSummary {
    pub branches: u32,
    pub calls: u32,
    pub returns: u32,
    pub throws: u32,
}

#[must_use]
pub fn emit_csharp(method_name: &str, body: &MethodBody) -> CSharpPseudo {
    let mut text: String = String::with_capacity(body.instructions.len() * 24);
    let _ = writeln!(text, "// pseudo-c# reconstructed from cil");
    let _ = writeln!(text, "void {method_name}()");
    let _ = writeln!(text, "{{");
    let _ = writeln!(
        text,
        "    // max_stack={} init_locals={}",
        body.max_stack, body.init_locals
    );
    let mut flow: FlowSummary = FlowSummary::default();
    for ins in &body.instructions {
        accumulate(&mut flow, ins.flow);
        emit_instruction(&mut text, ins);
    }
    let _ = writeln!(text, "}}");
    CSharpPseudo {
        method_name: method_name.to_owned(),
        body: text,
        instruction_count: u32::try_from(body.instructions.len()).unwrap_or(u32::MAX),
        flow_summary: flow,
    }
}

const fn accumulate(flow: &mut FlowSummary, fc: FlowControl) {
    match fc {
        FlowControl::Branch | FlowControl::CondBranch => {
            flow.branches = flow.branches.saturating_add(1);
        }
        FlowControl::Call => flow.calls = flow.calls.saturating_add(1),
        FlowControl::Return => flow.returns = flow.returns.saturating_add(1),
        FlowControl::Throw => flow.throws = flow.throws.saturating_add(1),
        FlowControl::Next | FlowControl::Meta | FlowControl::Break => {}
    }
}

fn emit_instruction(text: &mut String, ins: &Instruction) {
    let line: String = match &ins.operand {
        OperandValue::None => format!("    IL_{:04X}: {};", ins.offset, ins.name),
        OperandValue::I32(v) => format!("    IL_{:04X}: {} {};", ins.offset, ins.name, v),
        OperandValue::I64(v) => format!("    IL_{:04X}: {} {}L;", ins.offset, ins.name, v),
        OperandValue::U8(v) => format!("    IL_{:04X}: {} {};", ins.offset, ins.name, v),
        OperandValue::U16(v) => format!("    IL_{:04X}: {} {};", ins.offset, ins.name, v),
        OperandValue::F32Bits(b) => {
            format!(
                "    IL_{:04X}: {} {};",
                ins.offset,
                ins.name,
                f32::from_bits(*b)
            )
        }
        OperandValue::F64Bits(b) => {
            format!(
                "    IL_{:04X}: {} {};",
                ins.offset,
                ins.name,
                f64::from_bits(*b)
            )
        }
        OperandValue::BrTarget(t) => {
            let target: i64 = i64::from(ins.offset) + i64::from(*t);
            format!("    IL_{:04X}: {} IL_{target:04X};", ins.offset, ins.name)
        }
        OperandValue::Token(tok) => {
            format!("    IL_{:04X}: {} 0x{tok:08X};", ins.offset, ins.name)
        }
        OperandValue::Switch(targets) => {
            let joined: String = targets
                .iter()
                .map(|t: &i32| format!("0x{:08X}", i64::from(ins.offset) + i64::from(*t)))
                .collect::<Vec<String>>()
                .join(", ");
            format!("    IL_{:04X}: {} [{joined}];", ins.offset, ins.name)
        }
    };
    let _ = writeln!(text, "{line}");
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cil::disassemble;

    #[test]
    fn emit_csharp_round_trips_simple_method() {
        let code: [u8; 4] = [0x16, 0x17, 0x58, 0x2A];
        let instructions: Vec<Instruction> = disassemble(&code).expect("disasm");
        let body: MethodBody = MethodBody {
            max_stack: 2,
            code_size: 4,
            local_var_sig_tok: 0,
            init_locals: false,
            instructions,
            exception_clauses: Vec::new(),
        };
        let out: CSharpPseudo = emit_csharp("Main", &body);
        assert_eq!(out.instruction_count, 4);
        assert!(out.body.contains("ldc.i4.0"));
        assert!(out.body.contains("add"));
        assert!(out.body.contains("ret"));
        assert_eq!(out.flow_summary.returns, 1);
    }
}
