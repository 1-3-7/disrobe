use std::collections::{BTreeMap, BTreeSet};

use crate::cil::{Instruction, MethodBody, OperandValue, parse_method_body};
use crate::model::{AssemblyModel, MethodModel, Resolver, TypeModel};
use crate::pe::PeImage;
use crate::peel::bitmono_strings::{
    BitMonoRecoveredString, BitMonoStringRecovery, recover_bitmono_strings,
};
use crate::signature::{MethodSig, TypeSig};

use super::body::{absolute_target, int_literal, nop_in_place, replace_in_place};
use super::neutralize::{IlSite, MethodRef, NeutralizationPlan, Technique};
use super::{Literals, Residual};

pub(crate) const LAYER_STRINGS: &str = "BitMono StringsEncryption";
pub(crate) const LAYER_HOOK: &str = "BitMono DotNetHook";
pub(crate) const LAYER_CALLI: &str = "BitMono CallToCalli";
pub(crate) const LAYER_ANTI_DEBUG: &str = "BitMono AntiDebugBreakpoints";
pub(crate) const LAYER_JUNK: &str = "BitMono unreachable prefix junk";

const METHOD_HIDE_BY_SIG: u16 = 0x0080;
const MAX_PRE_WRITE_MODULE_METHODS: u32 = 4;
const METHOD_PINVOKE_IMPL: u16 = 0x2000;
const ANTI_DEBUG_THRESHOLD_MS: u64 = 0x40B3_8800_0000_0000;

#[derive(Debug)]
pub(crate) struct BitMonoLayer {
    strings: BTreeMap<(u32, u32), String>,
    hooks: BTreeMap<u32, u32>,
    hook: Option<u32>,
    registration_stubs: BTreeSet<u32>,
    pub(crate) runtime_methods: BTreeSet<u32>,
    pub(crate) runtime_types: BTreeSet<u32>,
    pub(crate) string_sites: u32,
    pub(crate) hook_sites: u32,
    pub(crate) calli_sites: u32,
    pub(crate) anti_debug_sites: u32,
    pub(crate) junk_sites: u32,
    pub(crate) hook_detail: String,
}

fn method_body(image: &[u8], pe: &PeImage, m: &MethodModel) -> Option<MethodBody> {
    if m.rva == 0 {
        return None;
    }
    let off: usize = pe.rva_to_offset(m.rva)?;
    parse_method_body(image.get(off..)?).ok()
}

fn callee_short(resolver: &Resolver, ins: &Instruction) -> Option<String> {
    if !matches!(ins.name.as_str(), "call" | "callvirt") {
        return None;
    }
    let OperandValue::Token(token) = ins.operand else {
        return None;
    };
    let full: String = resolver.resolve_token(token);
    Some(full.rsplit("::").next().unwrap_or(&full).to_owned())
}

fn callee_full(resolver: &Resolver, ins: &Instruction) -> Option<String> {
    if !matches!(ins.name.as_str(), "call" | "callvirt") {
        return None;
    }
    let OperandValue::Token(token) = ins.operand else {
        return None;
    };
    Some(resolver.resolve_token(token))
}

fn live(body: &MethodBody) -> Vec<&Instruction> {
    body.instructions
        .iter()
        .filter(|i: &&Instruction| i.name != "nop")
        .collect()
}

fn is_dummy(body: &MethodBody) -> bool {
    let instrs: Vec<&Instruction> = live(body);
    match instrs.as_slice() {
        [ret] => ret.name == "ret",
        [load, ret] => {
            ret.name == "ret"
                && (load.name == "ldnull" || load.name == "ldc.i4.0" || load.name == "ldc.i8")
        }
        _ => false,
    }
}

fn registration(body: &MethodBody, hook: u32) -> Option<(u32, u32)> {
    let instrs: Vec<&Instruction> = live(body);
    let [a, b, call, ret] = instrs.as_slice() else {
        return None;
    };
    if ret.name != "ret" || call.name != "call" {
        return None;
    }
    let OperandValue::Token(target) = call.operand else {
        return None;
    };
    if target != hook {
        return None;
    }
    let from: u32 = (int_literal(a)? as u64 & 0xFFFF_FFFF) as u32;
    let to: u32 = (int_literal(b)? as u64 & 0xFFFF_FFFF) as u32;
    Some((from, to))
}

fn is_hook(body: &MethodBody, resolver: &Resolver, m: &MethodModel) -> bool {
    if !m.is_static() || m.signature.params.len() != 2 {
        return false;
    }
    let names: BTreeSet<String> = body
        .instructions
        .iter()
        .filter_map(|i: &Instruction| callee_short(resolver, i))
        .collect();
    names.contains("ResolveMethod") && names.contains("GetFunctionPointer")
}

struct HookShapes {
    hook: Option<u32>,
    hook_type: Option<u32>,
    dummies: Vec<u32>,
    registrations: BTreeMap<u32, (u32, u32)>,
}

fn resolve_hooks(
    model: &AssemblyModel,
    shapes: &HookShapes,
    signatures: &BTreeMap<u32, MethodSig>,
    runtime_methods: &BTreeSet<u32>,
) -> Result<BTreeMap<u32, u32>, String> {
    let hook_pairs: Vec<(u32, u32)> = shapes.registrations.values().copied().collect();
    if hook_pairs.is_empty() {
        return Ok(BTreeMap::new());
    }
    let dummy_set: BTreeSet<u32> = shapes.dummies.iter().copied().collect();
    let owner_of: BTreeMap<u32, u32> = model
        .types
        .iter()
        .flat_map(|t: &TypeModel| {
            t.methods
                .iter()
                .map(move |m: &MethodModel| (m.token, t.token))
        })
        .collect();
    let same_signature = |dummy: u32, target: u32| -> bool {
        let (Some(a), Some(b)): (Option<&MethodSig>, Option<&MethodSig>) =
            (signatures.get(&dummy), signatures.get(&target))
        else {
            return false;
        };
        if a == b {
            return true;
        }
        b.has_this
            && !a.has_this
            && a.return_type == b.return_type
            && a.params.len() == b.params.len() + 1
            && matches!(a.params.first(), Some(TypeSig::NamedType { token, .. }) if owner_of.get(&target) == Some(token))
            && a.params[1..] == b.params[..]
    };
    let direct: Vec<(u32, u32)> = hook_pairs
        .iter()
        .copied()
        .filter(|(from, to): &(u32, u32)| dummy_set.contains(from) && same_signature(*from, *to))
        .collect();
    if direct.len() == hook_pairs.len() {
        return Ok(direct.into_iter().collect());
    }
    let candidates: Vec<u32> = model
        .types
        .iter()
        .filter(|t: &&TypeModel| t.full_name != "<Module>")
        .flat_map(|t: &TypeModel| t.methods.iter().map(|m: &MethodModel| m.token))
        .filter(|token: &u32| !runtime_methods.contains(token) && !dummy_set.contains(token))
        .collect();
    let min_from: u32 = hook_pairs
        .iter()
        .map(|(from, _): &(u32, u32)| from & 0x00FF_FFFF)
        .min()
        .unwrap_or(0);
    let mut valid: Vec<BTreeMap<u32, u32>> = Vec::new();
    for pre_module in 0..=MAX_PRE_WRITE_MODULE_METHODS {
        for user_count in 1..min_from {
            let mut mapping: BTreeMap<u32, u32> = BTreeMap::new();
            let mut ok: bool = true;
            for (from, to) in &hook_pairs {
                let stale_dummy: u32 = from & 0x00FF_FFFF;
                let stale_target: u32 = to & 0x00FF_FFFF;
                let dummy_index: Option<usize> = stale_dummy
                    .checked_sub(user_count)
                    .and_then(|i: u32| i.checked_sub(1))
                    .and_then(|i: u32| usize::try_from(i).ok());
                let Some(dummy): Option<u32> =
                    dummy_index.and_then(|i: usize| shapes.dummies.get(i).copied())
                else {
                    ok = false;
                    break;
                };
                if stale_target <= pre_module || stale_target > user_count {
                    ok = false;
                    break;
                }
                let Some(target): Option<u32> = usize::try_from(stale_target - pre_module - 1)
                    .ok()
                    .and_then(|i: usize| candidates.get(i).copied())
                else {
                    ok = false;
                    break;
                };
                if !same_signature(dummy, target) {
                    ok = false;
                    break;
                }
                if mapping
                    .insert(dummy, target)
                    .is_some_and(|previous: u32| previous != target)
                {
                    ok = false;
                    break;
                }
            }
            if ok && !valid.contains(&mapping) {
                valid.push(mapping);
            }
        }
    }
    match valid.len() {
        1 => Ok(valid.remove(0)),
        0 => Err(format!(
            "{} hook registrations name method tokens that match no dummy/target pair by row layout or signature",
            hook_pairs.len()
        )),
        n => Err(format!(
            "{n} row layouts satisfy the hook registrations, so the mapping is ambiguous"
        )),
    }
}

impl BitMonoLayer {
    pub(crate) fn build(
        image: &[u8],
        pe: &PeImage,
        resolver: &Resolver,
        model: &AssemblyModel,
        residuals: &mut Vec<Residual>,
    ) -> Self {
        let mut runtime_methods: BTreeSet<u32> = BTreeSet::new();
        let mut runtime_types: BTreeSet<u32> = BTreeSet::new();
        let mut strings: BTreeMap<(u32, u32), String> = BTreeMap::new();
        let mut field_owner: BTreeMap<u32, u32> = BTreeMap::new();
        let mut signatures: BTreeMap<u32, MethodSig> = BTreeMap::new();
        for ty in &model.types {
            for f in &ty.fields {
                field_owner.insert(f.token, ty.token);
            }
            for m in &ty.methods {
                signatures.insert(m.token, m.signature.clone());
            }
        }
        if let Some(recovery) = recover_bitmono_strings(image) {
            let BitMonoStringRecovery {
                shape,
                recovered,
                call_sites_total,
                call_sites_unresolved,
            } = recovery;
            runtime_methods.insert(shape.method_token);
            for ty in &model.types {
                if ty
                    .methods
                    .iter()
                    .any(|m: &MethodModel| m.token == shape.method_token)
                {
                    runtime_types.insert(ty.token);
                }
            }
            for site in recovered {
                let BitMonoRecoveredString {
                    caller_token,
                    call_offset,
                    data_field,
                    salt_field,
                    password_field,
                    text,
                } = site;
                for field in [data_field, salt_field, password_field] {
                    if let Some(owner) = field_owner.get(&field) {
                        runtime_types.insert(*owner);
                    }
                }
                strings.insert((caller_token, call_offset), text);
            }
            if call_sites_unresolved > 0 {
                residuals.push(Residual {
                    layer: LAYER_STRINGS.to_owned(),
                    method_token: None,
                    reason: format!(
                        "{call_sites_unresolved} of {call_sites_total} decryptor call sites did not decrypt"
                    ),
                });
            }
        }
        let module: Option<&TypeModel> = model
            .types
            .iter()
            .find(|t: &&TypeModel| t.full_name == "<Module>");
        if let Some(module) = module {
            for m in &module.methods {
                let generated: bool = m.name == ".cctor"
                    || m.flags & METHOD_HIDE_BY_SIG == 0
                    || method_body(image, pe, m).is_none();
                if generated {
                    runtime_methods.insert(m.token);
                }
            }
            if module
                .methods
                .iter()
                .all(|m: &MethodModel| runtime_methods.contains(&m.token))
            {
                runtime_types.insert(module.token);
            }
        }
        let mut shapes: HookShapes = HookShapes {
            hook: None,
            hook_type: None,
            dummies: Vec::new(),
            registrations: BTreeMap::new(),
        };
        for ty in &model.types {
            for m in &ty.methods {
                if m.flags & METHOD_PINVOKE_IMPL != 0 {
                    runtime_methods.insert(m.token);
                    runtime_types.insert(ty.token);
                    continue;
                }
                let Some(body): Option<MethodBody> = method_body(image, pe, m) else {
                    continue;
                };
                if is_hook(&body, resolver, m) {
                    shapes.hook = Some(m.token);
                    shapes.hook_type = Some(ty.token);
                }
            }
        }
        if let Some(hook) = shapes.hook {
            if let Some(hook_type) = shapes.hook_type {
                runtime_types.insert(hook_type);
                if let Some(ty) = model
                    .types
                    .iter()
                    .find(|t: &&TypeModel| t.token == hook_type)
                {
                    for m in &ty.methods {
                        runtime_methods.insert(m.token);
                    }
                }
            }
            if let Some(module) = module {
                for m in &module.methods {
                    let Some(body): Option<MethodBody> = method_body(image, pe, m) else {
                        continue;
                    };
                    if let Some(pair) = registration(&body, hook) {
                        shapes.registrations.insert(m.token, pair);
                    } else if is_dummy(&body) && m.is_static() && m.name != ".cctor" {
                        shapes.dummies.push(m.token);
                    }
                }
            }
        }
        let mut hook_detail: String = String::new();
        let hooks: BTreeMap<u32, u32> = match resolve_hooks(
            model,
            &shapes,
            &signatures,
            &runtime_methods,
        ) {
            Ok(mapping) => {
                if !mapping.is_empty() {
                    let direct: bool = mapping.iter().all(|(dummy, _)| {
                        shapes.registrations.values().any(|(from, _)| from == dummy)
                    });
                    hook_detail = if direct {
                        "registration tokens name the final method rows".to_owned()
                    } else {
                        "registration tokens are pre-write rows; mapped through the writer's row layout and validated by signature".to_owned()
                    };
                }
                mapping
            }
            Err(reason) => {
                residuals.push(Residual {
                    layer: LAYER_HOOK.to_owned(),
                    method_token: shapes.hook,
                    reason,
                });
                BTreeMap::new()
            }
        };
        Self {
            strings,
            hooks,
            hook: shapes.hook,
            registration_stubs: shapes.registrations.keys().copied().collect(),
            runtime_methods,
            runtime_types,
            string_sites: 0,
            hook_sites: 0,
            calli_sites: 0,
            anti_debug_sites: 0,
            junk_sites: 0,
            hook_detail,
        }
    }

    pub(crate) fn rewrite(
        &mut self,
        method_token: u32,
        body: &mut MethodBody,
        resolver: &Resolver,
        literals: &mut Literals,
        residuals: &mut Vec<Residual>,
    ) -> bool {
        let mut changed: bool = false;
        changed |= self.strip_junk(body);
        changed |= self.strip_anti_debug(body, resolver);
        changed |= self.inline_strings(method_token, body, literals, residuals);
        changed |= self.resolve_hooks_in(body);
        changed |= self.resolve_calli(body, resolver);
        changed
    }

    fn strip_junk(&mut self, body: &mut MethodBody) -> bool {
        let dead: Vec<usize> = super::body::unreachable_indices(body);
        if dead.is_empty() {
            return false;
        }
        let first_branch: bool = body
            .instructions
            .first()
            .is_some_and(|i: &Instruction| matches!(i.name.as_str(), "br" | "br.s"));
        let skip_to: Option<u32> = if first_branch {
            absolute_target(body, 0)
        } else {
            None
        };
        let jump_over_junk: bool = skip_to.is_some_and(|target: u32| {
            dead.iter()
                .all(|index: &usize| body.instructions[*index].offset < target)
        });
        for index in &dead {
            nop_in_place(&mut body.instructions[*index]);
        }
        if jump_over_junk {
            nop_in_place(&mut body.instructions[0]);
        }
        self.junk_sites = self
            .junk_sites
            .saturating_add(u32::try_from(dead.len()).unwrap_or(u32::MAX));
        true
    }

    fn strip_anti_debug(&mut self, body: &mut MethodBody, resolver: &Resolver) -> bool {
        let spans: Vec<(usize, usize)> = anti_debug_spans(body, resolver);
        if spans.is_empty() {
            return false;
        }
        for (start, end) in &spans {
            for ins in &mut body.instructions[*start..*end] {
                nop_in_place(ins);
            }
        }
        self.anti_debug_sites = self
            .anti_debug_sites
            .saturating_add(u32::try_from(spans.len()).unwrap_or(u32::MAX));
        true
    }

    pub(crate) fn plan(
        &self,
        site: &IlSite<'_>,
        image: &[u8],
        pe: &PeImage,
        resolver: &Resolver,
        model: &AssemblyModel,
        plan: &mut NeutralizationPlan,
    ) {
        let hook_risk: &str = "the call site names the real target directly; the hook runtime and its registrations become dead code";
        let timing_risk: &str = "the removed instructions only measured elapsed time and divided by zero after five seconds; no user computation is in the span";
        for ty in &model.types {
            for m in &ty.methods {
                let Some(body): Option<MethodBody> = method_body(image, pe, m) else {
                    continue;
                };
                for (start, end) in anti_debug_spans(&body, resolver) {
                    if let Some(patch) = site.nop_patch(
                        Technique::AntiDebugBreakpoints,
                        MethodRef::new(m.token, m.rva),
                        &body,
                        (start, end),
                        format!(
                            "UtcNow timing check over {} instructions in {}::{}",
                            end - start,
                            ty.full_name,
                            m.name
                        ),
                        timing_risk,
                    ) {
                        plan.push(patch);
                    }
                }
                if self.hooks.is_empty() {
                    continue;
                }
                if self.registration_stubs.contains(&m.token)
                    || ty.full_name == "<Module>" && m.name == ".cctor"
                {
                    for (index, ins) in body.instructions.iter().enumerate() {
                        let OperandValue::Token(callee) = ins.operand else {
                            continue;
                        };
                        let registers: bool = ins.name == "call"
                            && (self.registration_stubs.contains(&callee)
                                || Some(callee) == self.hook);
                        if !registers {
                            continue;
                        }
                        if let Some(patch) = site.nop_patch(
                            Technique::DotNetHook,
                            MethodRef::new(m.token, m.rva),
                            &body,
                            (index, index + 1),
                            format!(
                                "hook registration call {callee:#010x} in {}::{}",
                                ty.full_name, m.name
                            ),
                            hook_risk,
                        ) {
                            plan.push(patch);
                        }
                    }
                    continue;
                }
                for ins in &body.instructions {
                    if ins.name != "call" {
                        continue;
                    }
                    let OperandValue::Token(dummy) = ins.operand else {
                        continue;
                    };
                    let Some(target): Option<u32> = self.hooks.get(&dummy).copied() else {
                        continue;
                    };
                    if let Some(patch) = site.token_patch(
                        Technique::DotNetHook,
                        MethodRef::new(m.token, m.rva),
                        ins.offset,
                        dummy,
                        target,
                        format!(
                            "call to hook dummy {dummy:#010x} redirected at runtime to {target:#010x} ({})",
                            resolver.resolve_token(target)
                        ),
                        hook_risk,
                    ) {
                        plan.push(patch);
                    }
                }
            }
        }
    }

    fn inline_strings(
        &mut self,
        method_token: u32,
        body: &mut MethodBody,
        literals: &mut Literals,
        residuals: &mut Vec<Residual>,
    ) -> bool {
        let sites: Vec<(u32, String)> = self
            .strings
            .range((method_token, 0)..=(method_token, u32::MAX))
            .map(|((_, offset), text): (&(u32, u32), &String)| (*offset, text.clone()))
            .collect();
        if sites.is_empty() {
            return false;
        }
        let mut changed: bool = false;
        for (offset, text) in sites {
            let Some(call_index): Option<usize> = body
                .instructions
                .iter()
                .position(|i: &Instruction| i.offset == offset && i.name == "call")
            else {
                residuals.push(Residual {
                    layer: LAYER_STRINGS.to_owned(),
                    method_token: Some(method_token),
                    reason: format!(
                        "recovered call site at offset {offset:#x} is not a call (found {})",
                        body.instructions
                            .iter()
                            .find(|i: &&Instruction| i.offset == offset)
                            .map_or("no instruction at that offset", |i: &Instruction| i
                                .name
                                .as_str())
                    ),
                });
                continue;
            };
            let mut loads: Vec<usize> = Vec::new();
            let mut cursor: usize = call_index;
            while loads.len() < 3 && cursor > 0 {
                cursor -= 1;
                let name: &str = body.instructions[cursor].name.as_str();
                if name == "nop" {
                    continue;
                }
                if name == "ldsfld" {
                    loads.push(cursor);
                } else {
                    break;
                }
            }
            if loads.len() != 3 {
                residuals.push(Residual {
                    layer: LAYER_STRINGS.to_owned(),
                    method_token: Some(method_token),
                    reason: format!(
                        "decryptor call at offset {offset:#x} is not fed by three static field loads"
                    ),
                });
                continue;
            }
            let Some(token): Option<u32> = literals.intern(text.encode_utf16().collect()) else {
                residuals.push(Residual {
                    layer: LAYER_STRINGS.to_owned(),
                    method_token: Some(method_token),
                    reason: "the synthetic string table is full".to_owned(),
                });
                continue;
            };
            if replace_in_place(
                &mut body.instructions[call_index],
                "ldstr",
                OperandValue::Token(token),
            ) {
                for load in loads {
                    nop_in_place(&mut body.instructions[load]);
                }
                self.string_sites = self.string_sites.saturating_add(1);
                changed = true;
            }
        }
        changed
    }

    fn resolve_hooks_in(&mut self, body: &mut MethodBody) -> bool {
        if self.hooks.is_empty() {
            return false;
        }
        let mut changed: bool = false;
        for ins in &mut body.instructions {
            if ins.name != "call" {
                continue;
            }
            let OperandValue::Token(token) = ins.operand else {
                continue;
            };
            if let Some(target) = self.hooks.get(&token) {
                ins.operand = OperandValue::Token(*target);
                self.hook_sites = self.hook_sites.saturating_add(1);
                changed = true;
            }
        }
        changed
    }

    fn resolve_calli(&mut self, body: &mut MethodBody, resolver: &Resolver) -> bool {
        let mut changed: bool = false;
        let mut index: usize = 0;
        while index < body.instructions.len() {
            if body.instructions[index].name != "calli" {
                index += 1;
                continue;
            }
            let Some((start, token)): Option<(usize, u32)> =
                calli_resolution(body, index, resolver)
            else {
                index += 1;
                continue;
            };
            if resolver.callee_signature(token).is_none() {
                index += 1;
                continue;
            }
            if replace_in_place(
                &mut body.instructions[index],
                "call",
                OperandValue::Token(token),
            ) {
                for ins in &mut body.instructions[start..index] {
                    nop_in_place(ins);
                }
                self.calli_sites = self.calli_sites.saturating_add(1);
                changed = true;
            }
            index += 1;
        }
        changed
    }
}

fn anti_debug_spans(body: &MethodBody, resolver: &Resolver) -> Vec<(usize, usize)> {
    let mut stamps: BTreeSet<u32> = BTreeSet::new();
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let instrs: &[Instruction] = &body.instructions;
    let mut index: usize = 0;
    while index + 15 <= instrs.len() {
        let window: &[Instruction] = &instrs[index..index + 15];
        if let Some(stamp) = anti_debug_epilogue(window, resolver) {
            stamps.insert(stamp);
            spans.push((index, index + 15));
            index += 15;
        } else {
            index += 1;
        }
    }
    if spans.is_empty() {
        return spans;
    }
    for (index, window) in instrs.windows(2).enumerate() {
        let Some(stamp) = crate::cil::slot_index_of(&window[1], crate::cil::SlotOp::StoreLocal)
        else {
            continue;
        };
        if stamps.contains(&u32::from(stamp))
            && callee_full(resolver, &window[0]).as_deref() == Some("System.DateTime::get_UtcNow")
        {
            spans.push((index, index + 2));
        }
    }
    spans.sort_unstable();
    spans
}

fn anti_debug_epilogue(window: &[Instruction], resolver: &Resolver) -> Option<u32> {
    let [
        now,
        load_stamp,
        subtract,
        store_span,
        span_address,
        total_ms,
        threshold,
        skip,
        one,
        zero,
        store_tmp,
        load_tmp,
        div,
        pop,
        landing,
    ] = window
    else {
        return None;
    };
    if callee_full(resolver, now).as_deref() != Some("System.DateTime::get_UtcNow") {
        return None;
    }
    let stamp: u16 = crate::cil::slot_index_of(load_stamp, crate::cil::SlotOp::LoadLocal)?;
    if callee_full(resolver, subtract).as_deref() != Some("System.DateTime::op_Subtraction") {
        return None;
    }
    let span: u16 = crate::cil::slot_index_of(store_span, crate::cil::SlotOp::StoreLocal)?;
    if crate::cil::slot_index_of(span_address, crate::cil::SlotOp::LocalAddress)? != span {
        return None;
    }
    if callee_full(resolver, total_ms).as_deref() != Some("System.TimeSpan::get_TotalMilliseconds")
    {
        return None;
    }
    if threshold.name != "ldc.r8"
        || threshold.operand != OperandValue::F64Bits(ANTI_DEBUG_THRESHOLD_MS)
    {
        return None;
    }
    if !matches!(skip.name.as_str(), "ble.un" | "ble.un.s") {
        return None;
    }
    let tmp: u16 = crate::cil::slot_index_of(store_tmp, crate::cil::SlotOp::StoreLocal)?;
    if crate::cil::slot_index_of(load_tmp, crate::cil::SlotOp::LoadLocal)? != tmp {
        return None;
    }
    if one.name != "ldc.i4.1" || zero.name != "ldc.i4.0" || div.name != "div" || pop.name != "pop" {
        return None;
    }
    if landing.name != "nop" {
        return None;
    }
    Some(u32::from(stamp))
}

fn calli_resolution(
    body: &MethodBody,
    calli_index: usize,
    resolver: &Resolver,
) -> Option<(usize, u32)> {
    let live_before: Vec<usize> = (0..calli_index)
        .rev()
        .filter(|i: &usize| body.instructions[*i].name != "nop")
        .take(9)
        .collect();
    if live_before.len() != 9 {
        return None;
    }
    let at = |k: usize| -> &Instruction { &body.instructions[live_before[k]] };
    let names: [&str; 9] = [
        "GetFunctionPointer",
        "",
        "",
        "get_MethodHandle",
        "ResolveMethod",
        "",
        "get_Module",
        "GetTypeFromHandle",
        "",
    ];
    for (k, expected) in names.iter().enumerate() {
        if expected.is_empty() {
            continue;
        }
        if callee_short(resolver, at(k)).as_deref() != Some(expected) {
            return None;
        }
    }
    if crate::cil::slot_index_of(at(1), crate::cil::SlotOp::LocalAddress).is_none()
        || crate::cil::slot_index_of(at(2), crate::cil::SlotOp::StoreLocal).is_none()
    {
        return None;
    }
    let token: u32 = (int_literal(at(5))? as u64 & 0xFFFF_FFFF) as u32;
    if at(8).name != "ldtoken" {
        return None;
    }
    Some((live_before[8], token))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn synthetic_resolver() -> (Resolver, u32, u32, u32, u32) {
        let image: Vec<u8> =
            std::fs::read(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
                "../../corpus/dotnet/obfuscators/bitmono/gauntlet/GauntletBitMono.bitmono.dll",
            ))
            .unwrap();
        let pe: PeImage = crate::pe::parse(&image).unwrap();
        let clr: crate::pe::ClrHeader = crate::pe::parse_clr_header(&image, &pe).unwrap();
        let root: crate::metadata::MetadataRoot =
            crate::metadata::parse_metadata_root(&image, &pe, &clr).unwrap();
        let resolver: Resolver = Resolver::build(&image, &pe, &clr, &root).unwrap();
        let find = |suffix: &str| -> u32 {
            (1..=u32::try_from(resolver.tables().member_refs.len()).unwrap())
                .map(|rid: u32| 0x0A00_0000 | rid)
                .find(|token: &u32| resolver.resolve_token(*token).ends_with(suffix))
                .unwrap_or_else(|| panic!("member ref {suffix} present in the BitMono gauntlet"))
        };
        let resolve_method: u32 = find("::ResolveMethod");
        let get_module: u32 = find("::get_Module");
        let type_from_handle: u32 = find("::GetTypeFromHandle");
        let function_pointer: u32 = find("::GetFunctionPointer");
        (
            resolver,
            resolve_method,
            get_module,
            type_from_handle,
            function_pointer,
        )
    }

    #[test]
    fn calli_resolution_folds_back_to_a_direct_call() {
        let (resolver, resolve_method, get_module, type_from_handle, function_pointer) =
            synthetic_resolver();
        let method_handle: u32 = (1..=u32::try_from(resolver.tables().member_refs.len()).unwrap())
            .map(|rid: u32| 0x0A00_0000 | rid)
            .find(|token: &u32| {
                resolver
                    .resolve_token(*token)
                    .ends_with("::get_MethodHandle")
            })
            .unwrap_or(0x0A00_0001);
        let make = |name: &str, operand: OperandValue| {
            super::super::body::instruction(name, operand).unwrap()
        };
        let mut body: MethodBody = MethodBody {
            max_stack: 8,
            code_size: 0,
            local_var_sig_tok: 0,
            init_locals: true,
            instructions: vec![
                make("ldc.i4.7", OperandValue::None),
                make("ldtoken", OperandValue::Token(0x0200_0002)),
                make("call", OperandValue::Token(type_from_handle)),
                make("callvirt", OperandValue::Token(get_module)),
                make("ldc.i4", OperandValue::I32(0x0600_000D)),
                make("call", OperandValue::Token(resolve_method)),
                make("callvirt", OperandValue::Token(method_handle)),
                make("stloc.0", OperandValue::None),
                make("ldloca.s", OperandValue::U8(0)),
                make("call", OperandValue::Token(function_pointer)),
                make("calli", OperandValue::Token(0x1100_0001)),
                make("ret", OperandValue::None),
            ],
            exception_clauses: Vec::new(),
        };
        for (index, ins) in body.instructions.iter_mut().enumerate() {
            ins.offset = u32::try_from(index * 8).unwrap();
        }
        body.code_size = 8 * 12;
        let mut layer: BitMonoLayer = BitMonoLayer {
            strings: BTreeMap::new(),
            hooks: BTreeMap::new(),
            runtime_methods: BTreeSet::new(),
            runtime_types: BTreeSet::new(),
            hook: None,
            registration_stubs: BTreeSet::new(),
            string_sites: 0,
            hook_sites: 0,
            calli_sites: 0,
            anti_debug_sites: 0,
            junk_sites: 0,
            hook_detail: String::new(),
        };
        assert!(layer.resolve_calli(&mut body, &resolver));
        let names: Vec<&str> = body
            .instructions
            .iter()
            .map(|i: &Instruction| i.name.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "ldc.i4.7", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "call",
                "ret"
            ]
        );
        assert_eq!(
            body.instructions[10].operand,
            OperandValue::Token(0x0600_000D)
        );
        assert_eq!(layer.calli_sites, 1);
    }

    #[test]
    fn a_calli_without_the_resolution_prologue_is_left_alone() {
        let (resolver, ..) = synthetic_resolver();
        let make = |name: &str, operand: OperandValue| {
            super::super::body::instruction(name, operand).unwrap()
        };
        let mut body: MethodBody = MethodBody {
            max_stack: 8,
            code_size: 16,
            local_var_sig_tok: 0,
            init_locals: true,
            instructions: vec![
                make("ldarg.0", OperandValue::None),
                make("calli", OperandValue::Token(0x1100_0001)),
                make("ret", OperandValue::None),
            ],
            exception_clauses: Vec::new(),
        };
        let mut layer: BitMonoLayer = BitMonoLayer {
            strings: BTreeMap::new(),
            hooks: BTreeMap::new(),
            runtime_methods: BTreeSet::new(),
            runtime_types: BTreeSet::new(),
            hook: None,
            registration_stubs: BTreeSet::new(),
            string_sites: 0,
            hook_sites: 0,
            calli_sites: 0,
            anti_debug_sites: 0,
            junk_sites: 0,
            hook_detail: String::new(),
        };
        assert!(!layer.resolve_calli(&mut body, &resolver));
        assert_eq!(body.instructions[1].name, "calli");
    }

    #[test]
    fn dummy_shapes_are_recognised() {
        let body = |names: &[&str]| MethodBody {
            max_stack: 8,
            code_size: 0,
            local_var_sig_tok: 0,
            init_locals: false,
            instructions: names
                .iter()
                .map(|n: &&str| super::super::body::instruction(n, OperandValue::None).unwrap())
                .collect(),
            exception_clauses: Vec::new(),
        };
        assert!(is_dummy(&body(&["ldnull", "ret"])));
        assert!(is_dummy(&body(&["ret"])));
        assert!(is_dummy(&body(&["nop", "ldc.i4.0", "ret"])));
        assert!(!is_dummy(&body(&["ldarg.0", "ret"])));
    }
}
