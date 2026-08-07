use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::cil::{
    FlowControl, Instruction, MethodBody, OperandValue, SlotAccess, SlotOp, decode_slot,
    parse_method_body,
};
use crate::error::Result;
use crate::metadata::{MetadataRoot, metadata_slice, parse_metadata_root};
use crate::model::{IsInstTargetKind, MethodModel, Resolver, TypeModel};
use crate::names::NameTable;
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use crate::structurize::{
    CallInfo, FieldRvaPrimitive, MetadataTokenKind, MethodNamer, StructuredMethod, TargetLang,
    TokenNamer, decompile_method_named, decompile_move_next_named,
};

struct AssemblyNamer<'a> {
    method: MethodNamer<'a>,
    field_rvas: &'a crate::field_rva::FieldRvaData<'a>,
    initialize_array_tokens: &'a BTreeSet<u32>,
}

impl TokenNamer for AssemblyNamer<'_> {
    fn name(&self, token: u32) -> String {
        self.method.name(token)
    }

    fn token_kind(&self, token: u32) -> MetadataTokenKind {
        self.method.token_kind(token)
    }

    fn isinst_target_kind(&self, token: u32) -> IsInstTargetKind {
        self.method.isinst_target_kind(token)
    }

    fn unbox_any_target_name(&self, token: u32) -> Option<String> {
        self.method.unbox_any_target_name(token)
    }

    fn field_rva_bytes(&self, token: u32) -> Option<&[u8]> {
        self.field_rvas.bytes(token)
    }

    fn field_rva_primitive(&self, token: u32) -> Option<FieldRvaPrimitive> {
        self.method.field_rva_primitive(token)
    }

    fn is_initialize_array(&self, token: u32) -> bool {
        self.initialize_array_tokens.contains(&token)
    }

    fn call_info(&self, token: u32) -> Option<CallInfo> {
        self.method.call_info(token)
    }

    fn csharp_anonymous_object_member_names(&self, token: u32) -> Option<Vec<String>> {
        self.method.csharp_anonymous_object_member_names(token)
    }

    fn call_returns_boolean(&self, token: u32) -> bool {
        self.method.call_returns_boolean(token)
    }

    fn call_return_condition_kind(&self, token: u32) -> crate::signature::ConditionKind {
        self.method.call_return_condition_kind(token)
    }

    fn field_condition_kind(&self, token: u32) -> crate::signature::ConditionKind {
        self.method.field_condition_kind(token)
    }

    fn enum_param_type(&self, token: u32, param_index: usize) -> Option<String> {
        self.method.enum_param_type(token, param_index)
    }

    fn param_type_name(&self, token: u32, param_index: usize) -> Option<String> {
        self.method.param_type_name(token, param_index)
    }

    fn field_type_name(&self, token: u32) -> Option<String> {
        self.method.field_type_name(token)
    }

    fn callee_is_virtual_definition(&self, token: u32) -> bool {
        self.method.callee_is_virtual_definition(token)
    }

    fn enclosing_type(&self) -> Option<&str> {
        self.method.enclosing_type()
    }

    fn outer_has_this(&self) -> bool {
        self.method.outer_has_this()
    }
}

fn push_format(out: &mut String, args: std::fmt::Arguments<'_>) {
    let result: std::result::Result<(), std::fmt::Error> = std::fmt::write(out, args);
    if let Err(error) = result {
        unreachable!("string formatting failed: {error}");
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CSharpPseudo {
    pub method_name: String,
    pub body: String,
    pub instruction_count: u32,
    pub flow_summary: FlowSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompiledAssembly {
    pub module_name: String,
    pub methods: Vec<StructuredMethod>,
    pub methods_decompiled: u32,
    pub methods_bodyless: u32,
    pub methods_failed: u32,
}

pub fn decompile_assembly(image: &[u8]) -> Result<DecompiledAssembly> {
    decompile_assembly_in(image, TargetLang::CSharp)
}

pub fn decompile_assembly_in(image: &[u8], lang: TargetLang) -> Result<DecompiledAssembly> {
    let pe: PeImage = parse(image)?;
    let clr: ClrHeader = parse_clr_header(image, &pe)?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr)?;
    let resolver: Resolver = Resolver::build(image, &pe, &clr, &root)?;
    let field_rvas: crate::field_rva::FieldRvaData<'_> =
        crate::field_rva::FieldRvaData::build(image, &pe, &resolver);
    let metadata: &[u8] = metadata_slice(image, &pe, &clr, &root)?;
    let initialize_array_tokens: BTreeSet<u32> = root
        .streams
        .get("#Blob")
        .and_then(|stream| {
            let start: usize = usize::try_from(stream.offset).ok()?;
            let length: usize = usize::try_from(stream.size).ok()?;
            let end: usize = start.checked_add(length)?;
            metadata.get(start..end)
        })
        .map_or_else(BTreeSet::new, |blob| {
            crate::peel::deflatten::decrypt::init_array_tokens(&resolver, blob)
        });
    let model: crate::model::AssemblyModel = resolver.model();

    let mut methods: Vec<StructuredMethod> = Vec::new();
    let mut bodyless: u32 = 0;
    let mut failed: u32 = 0;
    let mut move_next_tokens: BTreeSet<u32> = BTreeSet::new();
    for ty in &model.types {
        let state_machine: Option<crate::state_machine::StateMachine> =
            crate::state_machine::classify(ty);
        let is_record: bool = crate::records::is_record_type(ty);
        for m in &ty.methods {
            if lang == TargetLang::CSharp
                && state_machine.is_some()
                && crate::state_machine::is_move_next(m)
            {
                move_next_tokens.insert(m.token);
            }
            decompile_one(
                &pe,
                image,
                &resolver,
                &field_rvas,
                &initialize_array_tokens,
                ty,
                m,
                state_machine.as_ref(),
                is_record,
                lang,
                &mut methods,
                &mut bodyless,
                &mut failed,
            );
        }
    }
    if lang == TargetLang::CSharp {
        let _ = crate::lambda_reverse::inline_lambdas(&mut methods);
        let hoisted_types: std::collections::BTreeMap<
            String,
            std::collections::BTreeMap<String, String>,
        > = hoisted_field_types(&model, &resolver, lang);
        let _ = crate::iterator_reverse::reconstruct_iterator_stubs(&mut methods, &hoisted_types);
        let _ = crate::switch_expr_reverse::reconstruct_switch_expressions(&mut methods);
        let record_struct_types: BTreeSet<String> = model
            .types
            .iter()
            .filter(|t: &&TypeModel| crate::records::is_record_struct(t))
            .map(|t: &TypeModel| t.full_name.clone())
            .collect();
        let record_class_types: BTreeSet<String> = model
            .types
            .iter()
            .filter(|t: &&TypeModel| {
                crate::records::is_record_type(t) && !crate::records::is_record_struct(t)
            })
            .map(|t: &TypeModel| t.full_name.clone())
            .collect();
        let _ = crate::with_reverse::reconstruct_record_with_expressions(
            &mut methods,
            &record_struct_types,
            &record_class_types,
        );
        let _ = crate::iterator_reverse::refuse_unlowered_compiler_constructs(&mut methods);
        for m in &mut methods {
            if let Some(abstained) = crate::structure_emit::abstain_illegal_goto(&m.body) {
                m.body = abstained;
            }
            if move_next_tokens.contains(&m.token) {
                m.body = crate::state_machine_reverse::sanitize_generated_residue(&m.body);
            }
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
    field_rvas: &crate::field_rva::FieldRvaData<'_>,
    initialize_array_tokens: &BTreeSet<u32>,
    ty: &TypeModel,
    m: &MethodModel,
    state_machine: Option<&crate::state_machine::StateMachine>,
    is_record: bool,
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
            let devirtualized_body: MethodBody = resolver.devirtualize_callvirt(&body);
            let provenance: &str = if crate::state_machine::is_closure_display_type(ty) {
                " [compiler-generated closure]"
            } else if state_machine.is_some() {
                match state_machine.map(|s: &crate::state_machine::StateMachine| s.kind) {
                    Some(crate::state_machine::StateMachineKind::Async) => " [async state machine]",
                    Some(crate::state_machine::StateMachineKind::Iterator) => {
                        " [iterator state machine]"
                    }
                    Some(crate::state_machine::StateMachineKind::AsyncIterator) => {
                        " [async iterator state machine]"
                    }
                    None => "",
                }
            } else if is_record && crate::records::is_synthesized_record_member(m) {
                " [record - compiler-synthesized member]"
            } else if is_record {
                " [record]"
            } else {
                ""
            };
            let raw_sig: String = match lang {
                TargetLang::CSharp => {
                    let override_kind: Option<crate::model::CSharpOverrideKind> =
                        resolver.csharp_value_type_override_kind(ty.token, m.token);
                    format!(
                        "// {}{provenance}\n{}",
                        ty.full_name,
                        m.csharp_signature_with_override(override_kind)
                    )
                }
                TargetLang::FSharp => {
                    format!("// {}{provenance}\n{}", ty.full_name, m.fsharp_signature())
                }
                TargetLang::VbNet => {
                    format!("' {}{provenance}\n{}", ty.full_name, m.vbnet_signature())
                }
            };
            let resolved_sig: String = resolver.resolve_type_tokens(&raw_sig);
            let namer: AssemblyNamer<'_> = AssemblyNamer {
                method: MethodNamer {
                    resolver,
                    has_this: !m.is_static(),
                    enclosing_type: Some(ty.full_name.as_str()),
                },
                field_rvas,
                initialize_array_tokens,
            };
            let names: NameTable = build_name_table(resolver, m, &devirtualized_body, lang);
            let header_sig: String = if lang == TargetLang::CSharp {
                apply_inferred_param_names(&resolved_sig, &names)
            } else {
                resolved_sig
            };
            let folded_body: crate::cil::MethodBody = if lang == TargetLang::CSharp {
                fold_cached_delegate_init(&devirtualized_body, resolver)
            } else {
                devirtualized_body
            };
            let is_sm_move_next: bool = lang == TargetLang::CSharp
                && state_machine.is_some()
                && crate::state_machine::is_move_next(m);
            let is_async_sm: bool = matches!(
                state_machine.map(|s: &crate::state_machine::StateMachine| s.kind),
                Some(
                    crate::state_machine::StateMachineKind::Async
                        | crate::state_machine::StateMachineKind::AsyncIterator
                )
            );
            let mut structured: StructuredMethod = if is_sm_move_next {
                decompile_move_next_named(
                    &header_sig,
                    &folded_body,
                    &namer,
                    &names,
                    lang,
                    is_async_sm,
                )
            } else {
                decompile_method_named(&header_sig, &folded_body, &namer, &names, lang)
            };
            structured.token = m.token;
            if let Some(sm) = state_machine
                && is_sm_move_next
            {
                let (reversed, _points): (String, u32) =
                    crate::state_machine_reverse::reverse_move_next(&structured.body, sm);
                let type_param_names: Vec<String> =
                    resolver.type_generic_param_names(ty.token & 0x00FF_FFFF);
                structured.body = crate::state_machine_reverse::lower_generic_placeholders(
                    &reversed,
                    &type_param_names,
                    &type_param_names,
                );
            }
            if lang == TargetLang::CSharp {
                let (cleaned, _folded): (String, u32) =
                    crate::closure_reverse::fold_cached_delegates(&structured.body);
                structured.body = cleaned;
            }
            if lang == TargetLang::CSharp && !is_sm_move_next {
                let normalized: MethodBody =
                    crate::structurize::normalize_branches_pub(&folded_body);
                let switch_body: Option<String> =
                    crate::property_switch_reverse::reconstruct_property_switch(
                        &normalized,
                        &namer,
                        &names,
                        lang,
                    )
                    .or_else(|| {
                        crate::list_switch_reverse::reconstruct_list_switch(
                            &normalized,
                            &namer,
                            &names,
                            lang,
                        )
                    })
                    .or_else(|| {
                        crate::positional_switch_reverse::reconstruct_positional_switch(
                            &normalized,
                            &namer,
                            &names,
                            lang,
                        )
                    })
                    .or_else(|| {
                        crate::tuple_switch_reverse::reconstruct_tuple_switch(
                            &normalized,
                            &namer,
                            &names,
                            lang,
                        )
                    })
                    .or_else(|| {
                        crate::range_switch_reverse::reconstruct_range_switch(
                            &normalized,
                            &namer,
                            &names,
                            lang,
                        )
                    })
                    .or_else(|| {
                        crate::with_reverse::reconstruct_with_expression(
                            &normalized,
                            &namer,
                            &names,
                            lang,
                        )
                    });
                if let Some(switch_body) = switch_body
                    && let Some(rewrapped) = rewrap_method_body(&structured.body, &switch_body)
                {
                    structured.body = rewrapped;
                }
            }
            let type_param_names: Vec<String> =
                resolver.type_generic_param_names(ty.token & 0x00FF_FFFF);
            let method_param_names: Vec<String> =
                resolver.method_generic_param_names(m.token & 0x00FF_FFFF);
            if !type_param_names.is_empty() || !method_param_names.is_empty() {
                structured.signature = crate::state_machine_reverse::lower_generic_placeholders(
                    &structured.signature,
                    &type_param_names,
                    &method_param_names,
                );
                structured.body = crate::state_machine_reverse::lower_generic_placeholders(
                    &structured.body,
                    &type_param_names,
                    &method_param_names,
                );
            }
            if lang == TargetLang::CSharp && !method_param_names.is_empty() {
                let short_name: &str = m.name.rsplit("::").next().unwrap_or(&m.name);
                structured.signature = declare_method_type_parameters(
                    &structured.signature,
                    short_name,
                    &method_param_names,
                );
                structured.body = declare_method_type_parameters(
                    &structured.body,
                    short_name,
                    &method_param_names,
                );
            }
            methods.push(structured);
        }
        Err(_) => *failed = failed.saturating_add(1),
    }
}

fn declare_method_type_parameters(text: &str, name: &str, params: &[String]) -> String {
    let needle: String = format!("{name}(");
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let Some(decl): Option<&mut String> = lines.iter_mut().find(|line: &&mut String| {
        let trimmed: &str = line.trim_start();
        !trimmed.is_empty() && !trimmed.starts_with("//") && !trimmed.starts_with('\'')
    }) else {
        return text.to_owned();
    };
    let Some(open): Option<usize> = decl.find(&needle) else {
        return text.to_owned();
    };
    let split: usize = open + name.len();
    *decl = format!(
        "{}<{}>{}",
        &decl[..split],
        params.join(", "),
        &decl[split..]
    );
    let joined: String = lines.join("\n");
    if text.ends_with('\n') {
        format!("{joined}\n")
    } else {
        joined
    }
}

fn rewrap_method_body(original: &str, switch_body: &str) -> Option<String> {
    let trailing_newline: bool = original.ends_with('\n');
    let lines: Vec<&str> = original.lines().collect();
    let open: usize = lines.iter().position(|l: &&str| l.trim() == "{")?;
    let close: usize = lines.iter().rposition(|l: &&str| l.trim() == "}")?;
    if close <= open {
        return None;
    }
    let mut text: String = String::new();
    for line in &lines[..=open] {
        text.push_str(line);
        text.push('\n');
    }
    text.push_str(switch_body);
    text.push_str(lines[close]);
    if trailing_newline {
        text.push('\n');
    }
    Some(text)
}

fn fold_cached_delegate_init(body: &crate::cil::MethodBody, resolver: &Resolver) -> MethodBody {
    let instrs: &[Instruction] = &body.instructions;
    let mut nop_targets: Vec<usize> = Vec::new();
    for i in 0..instrs.len() {
        if let Some(end) = cached_delegate_init_span(instrs, i, resolver) {
            nop_targets.extend((i + 1)..=end);
        }
    }
    if nop_targets.is_empty() {
        return body.clone();
    }
    let mut patched: MethodBody = body.clone();
    for idx in nop_targets {
        let ins: &mut Instruction = &mut patched.instructions[idx];
        ins.opcode = 0x00;
        "nop".clone_into(&mut ins.name);
        ins.operand = OperandValue::None;
        ins.flow = FlowControl::Next;
    }
    patched
}

fn cached_delegate_init_span(
    instrs: &[Instruction],
    i: usize,
    resolver: &Resolver,
) -> Option<usize> {
    let load: &Instruction = instrs.get(i)?;
    if load.name != "ldsfld" {
        return None;
    }
    let OperandValue::Token(field_tok): OperandValue = load.operand else {
        return None;
    };
    if !is_cached_delegate_field(field_tok, resolver) {
        return None;
    }
    if instrs.get(i + 1)?.name != "dup" {
        return None;
    }
    let branch: &Instruction = instrs.get(i + 2)?;
    if branch.name != "brtrue" && branch.name != "brtrue.s" {
        return None;
    }
    let OperandValue::BrTarget(rel): OperandValue = branch.operand else {
        return None;
    };
    let branch_next: &Instruction = instrs.get(i + 3)?;
    let branch_target: i64 = i64::from(branch_next.offset) + i64::from(rel);
    let store: usize = (i + 3..instrs.len()).find(|&j: &usize| {
        instrs[j].name == "stsfld" && instrs[j].operand == OperandValue::Token(field_tok)
    })?;
    let after_store: &Instruction = instrs.get(store + 1)?;
    (i64::from(after_store.offset) == branch_target).then_some(store)
}

fn is_cached_delegate_field(token: u32, resolver: &Resolver) -> bool {
    let name: String = resolver.resolve_token(token);
    let short: &str = name.rsplit("::").next().unwrap_or(&name);
    short.starts_with("<>9__") || short == "<>9"
}

fn hoisted_field_types(
    model: &crate::model::AssemblyModel,
    resolver: &Resolver,
    lang: TargetLang,
) -> std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>> {
    let mut out: std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>> =
        std::collections::BTreeMap::new();
    for ty in &model.types {
        let short: &str = ty.name.rsplit('.').next().unwrap_or(&ty.name);
        if !short.contains(">d__") {
            continue;
        }
        let mut fields: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        for f in &ty.fields {
            if let Some(name) = crate::state_machine::hoisted_field_source_name(&f.name) {
                fields.insert(
                    name,
                    resolver.resolve_type_tokens(&f.field_type.render_in(lang)),
                );
            }
        }
        if !fields.is_empty() {
            out.insert(ty.full_name.clone(), fields);
        }
    }
    out
}

fn apply_inferred_param_names(signature: &str, names: &NameTable) -> String {
    let inferred: &[String] = names.param_names();
    if inferred.is_empty() {
        return signature.to_owned();
    }
    let mut lines: Vec<String> = signature.lines().map(str::to_owned).collect();
    let Some(idx): Option<usize> = lines
        .iter()
        .position(|l: &String| !l.trim_start().starts_with("//") && l.contains('('))
    else {
        return signature.to_owned();
    };
    let header: String = lines[idx].clone();
    let Some(open): Option<usize> = header.find('(') else {
        return signature.to_owned();
    };
    let Some(close): Option<usize> = header.rfind(')') else {
        return signature.to_owned();
    };
    if close <= open + 1 {
        return signature.to_owned();
    }
    let prefix: &str = &header[..=open];
    let suffix: &str = &header[close..];
    let params: &str = &header[open + 1..close];
    let Some(declarations): Option<Vec<&str>> =
        crate::structurize::split_csharp_parameter_declarations(params)
    else {
        return signature.to_owned();
    };
    if declarations.len() != inferred.len() {
        return signature.to_owned();
    }
    let rewritten: Vec<String> = declarations
        .into_iter()
        .enumerate()
        .map(|(i, raw): (usize, &str)| rewrite_one_param(raw, inferred.get(i).map(String::as_str)))
        .collect();
    lines[idx] = format!("{prefix}{}{suffix}", rewritten.join(", "));
    lines.join("\n")
}

fn rewrite_one_param(raw: &str, inferred: Option<&str>) -> String {
    let Some(inferred): Option<&str> = inferred else {
        return raw.trim().to_owned();
    };
    let trimmed: &str = raw.trim();
    let Some((ty, name)): Option<(&str, &str)> = trimmed.rsplit_once(' ') else {
        if inferred.is_empty() {
            return trimmed.to_owned();
        }
        return format!("{trimmed} {inferred}");
    };
    let invalid: bool = !crate::structurize::is_simple_identifier(name)
        && !name
            .strip_prefix('@')
            .is_some_and(crate::structurize::is_simple_identifier);
    if (crate::names::is_positional_parameter_name(name) || name.is_empty() || invalid)
        && !inferred.is_empty()
        && (invalid
            || inferred.starts_with('@')
            || !crate::names::is_positional_parameter_name(inferred))
    {
        format!("{ty} {inferred}")
    } else {
        trimmed.to_owned()
    }
}

fn build_name_table(
    resolver: &Resolver,
    m: &MethodModel,
    body: &crate::cil::MethodBody,
    lang: TargetLang,
) -> NameTable {
    let mut param_names: Vec<String> = m.param_names();
    let param_types: Vec<String> = m
        .signature
        .params
        .iter()
        .map(|p: &crate::signature::TypeSig| resolver.render_type(p, lang))
        .collect();
    if lang == TargetLang::CSharp {
        param_names = crate::names::canonical_parameter_names(&param_names, lang);
        infer_param_names_from_field_stores(resolver, m, body, &mut param_names);
        param_names = crate::names::canonical_parameter_names(&param_names, lang);
    }
    let local_types: Vec<String> = resolver.local_types(body.local_var_sig_tok, lang);
    let param_kinds: Vec<crate::signature::ConditionKind> = m
        .signature
        .params
        .iter()
        .map(crate::signature::TypeSig::condition_kind)
        .collect();
    let local_kinds: Vec<crate::signature::ConditionKind> =
        resolver.local_condition_kinds(body.local_var_sig_tok);
    NameTable::new(!m.is_static(), param_names, param_types, local_types)
        .with_kinds(param_kinds, local_kinds)
}

fn infer_param_names_from_field_stores(
    resolver: &Resolver,
    m: &MethodModel,
    body: &crate::cil::MethodBody,
    param_names: &mut [String],
) {
    let has_this: bool = !m.is_static();
    let instrs: &[Instruction] = &body.instructions;
    for window in instrs.windows(2) {
        let store: &Instruction = &window[1];
        if store.name != "stfld" && store.name != "stsfld" {
            continue;
        }
        let OperandValue::Token(field_tok): OperandValue = store.operand else {
            continue;
        };
        let Some(slot): Option<u32> = ldarg_param_slot(&window[0], has_this) else {
            continue;
        };
        let Some(name): Option<&mut String> = param_names.get_mut(slot as usize) else {
            continue;
        };
        if !name.is_empty() && !crate::names::is_positional_parameter_name(name) {
            continue;
        }
        if let Some(inferred) = param_name_from_field(&resolver.resolve_token(field_tok)) {
            *name = inferred;
        }
    }
}

fn ldarg_param_slot(ins: &Instruction, has_this: bool) -> Option<u32> {
    let access: SlotAccess = decode_slot(ins).ok()?;
    if !matches!(access.op, SlotOp::LoadArgument | SlotOp::ArgumentAddress) {
        return None;
    }
    u32::from(access.index).checked_sub(u32::from(has_this))
}

fn param_name_from_field(field: &str) -> Option<String> {
    let short: &str = field.rsplit("::").next().unwrap_or(field);
    let short: &str = short.rsplit('.').next().unwrap_or(short);
    let bare: &str = short
        .trim_start_matches('_')
        .trim_start_matches("m_")
        .trim_start_matches('<');
    let core: &str = bare.split('>').next().unwrap_or(bare);
    if core.is_empty() || core.contains(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
        return None;
    }
    let mut chars: std::str::Chars<'_> = core.chars();
    let first: char = chars.next()?;
    let lowered: String = first.to_ascii_lowercase().to_string() + chars.as_str();
    Some(crate::structurize::csharp_escape_identifier(&lowered))
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
    text.push_str("// pseudo-c# reconstructed from cil\n");
    push_format(&mut text, format_args!("void {method_name}()\n"));
    text.push_str("{\n");
    push_format(
        &mut text,
        format_args!(
            "    // max_stack={} init_locals={}\n",
            body.max_stack, body.init_locals
        ),
    );
    let mut flow: FlowSummary = FlowSummary::default();
    for ins in &body.instructions {
        accumulate(&mut flow, ins.flow);
        emit_instruction(&mut text, ins);
    }
    text.push_str("}\n");
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
    push_format(text, format_args!("{line}\n"));
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cil::disassemble;

    #[test]
    fn param_name_from_field_lowercases_first_char() {
        assert_eq!(
            param_name_from_field("Foo::NullableFlags").as_deref(),
            Some("nullableFlags")
        );
        assert_eq!(param_name_from_field("_count").as_deref(), Some("count"));
        assert_eq!(
            param_name_from_field("Bar::m_value").as_deref(),
            Some("value")
        );
    }

    #[test]
    fn param_name_from_field_escapes_keyword() {
        assert_eq!(
            param_name_from_field("Holder::Object").as_deref(),
            Some("@object")
        );
    }

    #[test]
    fn param_name_from_backing_field_extracts_property_name() {
        assert_eq!(
            param_name_from_field("T::<Length>k__BackingField").as_deref(),
            Some("length")
        );
    }

    #[test]
    fn ldarg_slot_accounts_for_this() {
        let load: Instruction = Instruction {
            offset: 0,
            opcode: 0x03,
            name: "ldarg.1".to_owned(),
            operand: OperandValue::None,
            flow: FlowControl::Next,
        };
        assert_eq!(ldarg_param_slot(&load, true), Some(0));
        assert_eq!(ldarg_param_slot(&load, false), Some(1));
    }

    fn arg_ins(name: &str, operand: OperandValue) -> Instruction {
        Instruction {
            offset: 0,
            opcode: 0,
            name: name.to_owned(),
            operand,
            flow: FlowControl::Next,
        }
    }

    #[test]
    fn ldarg_param_slot_reads_every_argument_form() {
        for (name, operand, raw) in [
            ("ldarg.0", OperandValue::None, 0_u32),
            ("ldarg.3", OperandValue::None, 3),
            ("ldarg.s", OperandValue::U8(255), 255),
            ("ldarga.s", OperandValue::U8(4), 4),
            ("ldarg", OperandValue::U16(65_535), 65_535),
            ("ldarga", OperandValue::U16(256), 256),
        ] {
            assert_eq!(
                ldarg_param_slot(&arg_ins(name, operand), false),
                Some(raw),
                "{name}"
            );
        }
    }

    #[test]
    fn ldarg_param_slot_rejects_an_operand_it_cannot_read_and_every_non_argument_access() {
        for operand in [
            OperandValue::None,
            OperandValue::I32(-1),
            OperandValue::I32(7),
            OperandValue::I64(2),
            OperandValue::Token(0x0A00_0001),
        ] {
            assert_eq!(
                ldarg_param_slot(&arg_ins("ldarg.s", operand.clone()), false),
                None,
                "{operand:?}"
            );
        }
        for name in ["ldloc.0", "stloc.s", "starg.s", "ldloca", "ret"] {
            assert_eq!(
                ldarg_param_slot(&arg_ins(name, OperandValue::U8(1)), false),
                None,
                "{name}"
            );
        }
        assert_eq!(
            ldarg_param_slot(&arg_ins("ldarg.0", OperandValue::None), true),
            None
        );
    }

    #[test]
    fn apply_inferred_param_names_rewrites_arg_in_csharp_header() {
        let names: NameTable = NameTable::new(
            true,
            vec!["count".to_owned()],
            vec!["int".to_owned()],
            Vec::new(),
        );
        let sig: &str = "// Sample.Box\npublic void .ctor(int arg1)";
        let out: String = apply_inferred_param_names(sig, &names);
        assert!(out.contains("(int count)"), "got:\n{out}");
    }

    #[test]
    fn inferred_parameter_name_replaces_invalid_metadata_identifier() {
        assert_eq!(
            rewrite_one_param(
                "object <>h__TransparentIdentifier0",
                Some("transparentIdentifier0")
            ),
            "object transparentIdentifier0"
        );
        let names: NameTable = NameTable::new(
            false,
            vec!["transparentIdentifier0".to_owned()],
            Vec::new(),
            Vec::new(),
        );
        assert_eq!(
            apply_inferred_param_names(
                "public int F(Pair<int, int> <>h__TransparentIdentifier0)",
                &names
            ),
            "public int F(Pair<int, int> transparentIdentifier0)"
        );
    }

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
