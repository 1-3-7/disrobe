mod detect;
mod meta;
mod model;

use std::collections::BTreeMap;

use crate::dalvik::{DalvikInsn, decode_method};
use crate::decompile::Expr;
use crate::descriptor;
use crate::dex::{DexFile, MethodId, parse_code_items};

use detect::{
    EnumValuesFacts, MAX_HELPER_ARITY, detect_enum_values, is_r8_namespace, is_synthetic_static,
    straight_line_return,
};
use meta::{DexMeta, MethodMeta};
use model::{GateStatus, gate_inline, model_pure_helper, substitute};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transform {
    InlineOutlinedHelper {
        helper_class: String,
        helper_method: String,
        call_sites: usize,
    },
    RestoreEnumValues {
        enum_class: String,
        field: String,
    },
}

#[derive(Debug, Clone)]
pub struct Rewrite {
    pub location: String,
    pub before: String,
    pub after: String,
    pub gate_green: bool,
    pub gate_note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub transform: Transform,
    pub confidence: Confidence,
    pub evidence: String,
    pub abstain_reason: Option<String>,
    pub applied: bool,
    pub rewrites: Vec<Rewrite>,
}

#[derive(Debug, Clone, Default)]
pub struct InversionReport {
    pub candidates: Vec<Candidate>,
    pub code_scan_complete: bool,
    pub decode_error_count: usize,
}

impl InversionReport {
    #[must_use]
    pub fn applied(&self) -> Vec<&Candidate> {
        self.candidates
            .iter()
            .filter(|c: &&Candidate| c.applied)
            .collect()
    }

    #[must_use]
    pub fn abstained(&self) -> Vec<&Candidate> {
        self.candidates
            .iter()
            .filter(|c: &&Candidate| c.abstain_reason.is_some())
            .collect()
    }
}

type TripleKey = (String, String, String);

struct RawCode {
    registers_size: u16,
    ins_size: u16,
    insns: Vec<DalvikInsn>,
}

struct Body {
    meta: MethodMeta,
    registers_size: u16,
    ins_size: u16,
    insns: Vec<DalvikInsn>,
}

struct CallSite {
    caller_class: String,
    caller_name: String,
    pc: u32,
    is_static: bool,
    arg_regs: Vec<u16>,
}

const fn is_category_two(descriptor: &str) -> bool {
    matches!(descriptor.as_bytes().first(), Some(b'J' | b'D'))
}

const fn is_invoke(op: u8) -> bool {
    matches!(op, 0x6E..=0x72 | 0x74..=0x78)
}

const fn is_static_invoke(op: u8) -> bool {
    matches!(op, 0x71 | 0x77)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inversion_report_preserves_partial_code_failure() {
        let (dex, bytes): (DexFile, Vec<u8>) = crate::dex::partial_code_failure_fixture();
        let report: InversionReport = invert(&dex, &bytes);
        assert!(!report.code_scan_complete);
        assert_eq!(report.decode_error_count, 1);
    }
}

#[must_use]
pub fn invert(dex: &DexFile, bytes: &[u8]) -> InversionReport {
    let dex_meta: DexMeta = meta::collect(dex, bytes);
    let code_report: crate::dex::CodeItemsReport = parse_code_items(dex, bytes);
    let code_scan_complete: bool = code_report.is_fully_decoded();
    let decode_error_count: usize = code_report.error_count();
    let code_items: Vec<crate::dex::CodeItem> = code_report.into_partial_decoded();

    let mut body_by_triple: BTreeMap<TripleKey, RawCode> = BTreeMap::new();
    for item in &code_items {
        let triple: TripleKey = (
            item.class.clone(),
            item.method_name.clone(),
            item.method_descriptor.clone(),
        );
        body_by_triple.insert(
            triple,
            RawCode {
                registers_size: item.registers_size,
                ins_size: item.ins_size,
                insns: decode_method(&item.insns),
            },
        );
    }

    let mut bodies: Vec<Body> = Vec::new();
    for m in &dex_meta.methods {
        if !m.has_code {
            continue;
        }
        if let Some(raw) = body_by_triple.get(&m.triple()) {
            bodies.push(Body {
                meta: m.clone(),
                registers_size: raw.registers_size,
                ins_size: raw.ins_size,
                insns: raw.insns.clone(),
            });
        }
    }

    let call_sites: BTreeMap<u32, Vec<CallSite>> = build_call_sites(&bodies);

    let mut report: InversionReport = InversionReport {
        candidates: Vec::new(),
        code_scan_complete,
        decode_error_count,
    };
    detect_helpers(dex, &bodies, &call_sites, &mut report);
    detect_enums(dex, &dex_meta, &bodies, &mut report);
    report
}

fn build_call_sites(bodies: &[Body]) -> BTreeMap<u32, Vec<CallSite>> {
    let mut out: BTreeMap<u32, Vec<CallSite>> = BTreeMap::new();
    for body in bodies {
        for insn in &body.insns {
            if !is_invoke(insn.op) {
                continue;
            }
            let Some(index): Option<u32> = insn.index else {
                continue;
            };
            out.entry(index).or_default().push(CallSite {
                caller_class: body.meta.class.clone(),
                caller_name: body.meta.name.clone(),
                pc: insn.pc,
                is_static: is_static_invoke(insn.op),
                arg_regs: insn.regs.clone(),
            });
        }
    }
    out
}

fn method_params(dex: &DexFile, method_id_index: u32) -> Option<&Vec<String>> {
    dex.method_ids
        .get(method_id_index as usize)
        .map(|m: &MethodId| &m.proto.parameters)
}

fn callsite_arg_leaves(params: &[String], regs: &[u16]) -> Option<Vec<Expr>> {
    let mut out: Vec<Expr> = Vec::with_capacity(params.len());
    let mut i: usize = 0;
    for param in params {
        let &reg: &u16 = regs.get(i)?;
        out.push(Expr::Local(format!("v{reg}")));
        i += if is_category_two(param) { 2 } else { 1 };
    }
    Some(out)
}

fn detect_helpers(
    dex: &DexFile,
    bodies: &[Body],
    call_sites: &BTreeMap<u32, Vec<CallSite>>,
    report: &mut InversionReport,
) {
    for body in bodies {
        let flags: u32 = body.meta.access_flags;
        if !is_synthetic_static(flags) {
            continue;
        }
        if !is_r8_namespace(&body.meta.class, &body.meta.name) {
            continue;
        }
        if straight_line_return(&body.insns).is_none() {
            continue;
        }
        let Some(params): Option<&Vec<String>> = method_params(dex, body.meta.method_id_index)
        else {
            continue;
        };
        let helper_class_src: String = descriptor::binary_to_source(&body.meta.class);
        let transform_of = |sites: usize| Transform::InlineOutlinedHelper {
            helper_class: helper_class_src.clone(),
            helper_method: body.meta.name.clone(),
            call_sites: sites,
        };

        if params.len() > MAX_HELPER_ARITY {
            report.candidates.push(Candidate {
                transform: transform_of(0),
                confidence: Confidence::Low,
                evidence: format!("synthetic R8 helper {helper_class_src}.{}", body.meta.name),
                abstain_reason: Some(format!(
                    "arity {} exceeds inline budget {MAX_HELPER_ARITY}",
                    params.len()
                )),
                applied: false,
                rewrites: Vec::new(),
            });
            continue;
        }

        let sites: &[CallSite] = call_sites
            .get(&body.meta.method_id_index)
            .map_or(&[][..], |v: &Vec<CallSite>| v.as_slice());
        if sites.iter().any(|s: &CallSite| !s.is_static) {
            report.candidates.push(Candidate {
                transform: transform_of(sites.len()),
                confidence: Confidence::Low,
                evidence: format!("synthetic R8 helper {helper_class_src}.{}", body.meta.name),
                abstain_reason: Some(
                    "helper referenced by a non-static invoke; not a pure outline call".to_string(),
                ),
                applied: false,
                rewrites: Vec::new(),
            });
            continue;
        }
        if sites.len() < 2 {
            report.candidates.push(Candidate {
                transform: transform_of(sites.len()),
                confidence: Confidence::Low,
                evidence: format!("synthetic R8 helper {helper_class_src}.{}", body.meta.name),
                abstain_reason: Some(format!(
                    "only {} static call site(s); outline census needs >=2",
                    sites.len()
                )),
                applied: false,
                rewrites: Vec::new(),
            });
            continue;
        }

        let Some(model) =
            model_pure_helper(dex, params, body.registers_size, body.ins_size, &body.insns)
        else {
            report.candidates.push(Candidate {
                transform: transform_of(sites.len()),
                confidence: Confidence::Low,
                evidence: format!(
                    "synthetic R8 helper {helper_class_src}.{} with {} call sites",
                    body.meta.name,
                    sites.len()
                ),
                abstain_reason: Some(
                    "helper body is not a pure value expression (side effect, invoke, or branch); \
                     statement-level splice deferred"
                        .to_string(),
                ),
                applied: false,
                rewrites: Vec::new(),
            });
            continue;
        };

        let mut rewrites: Vec<Rewrite> = Vec::new();
        for site in sites {
            let Some(args): Option<Vec<Expr>> = callsite_arg_leaves(params, &site.arg_regs) else {
                continue;
            };
            if args.len() != model.param_count {
                continue;
            }
            let gate: GateStatus = gate_inline(&model.return_expr, &args);
            let rendered_args: String = args
                .iter()
                .map(Expr::render)
                .collect::<Vec<String>>()
                .join(", ");
            let before: String = format!("{helper_class_src}.{}({rendered_args})", body.meta.name);
            let after: String = substitute(&model.return_expr, &args).render();
            let (gate_green, gate_note): (bool, Option<String>) = match gate {
                GateStatus::Green => (true, None),
                GateStatus::Rejected(reason) => (false, Some(reason)),
            };
            rewrites.push(Rewrite {
                location: format!("{}.{} @{:#x}", site.caller_class, site.caller_name, site.pc),
                before,
                after,
                gate_green,
                gate_note,
            });
        }

        let all_green: bool =
            !rewrites.is_empty() && rewrites.iter().all(|r: &Rewrite| r.gate_green);
        let confidence: Confidence = if all_green {
            Confidence::High
        } else {
            Confidence::Low
        };
        report.candidates.push(Candidate {
            transform: transform_of(sites.len()),
            confidence,
            evidence: format!(
                "synthetic R8 outline {helper_class_src}.{}; single-block pure body; {} static call sites; \
                 IR effect-sequence gate green on {}/{} sites",
                body.meta.name,
                sites.len(),
                rewrites.iter().filter(|r: &&Rewrite| r.gate_green).count(),
                rewrites.len()
            ),
            abstain_reason: if all_green {
                None
            } else {
                Some("IR effect-sequence gate rejected at least one call site".to_string())
            },
            applied: all_green,
            rewrites,
        });
    }
}

fn find_field_id(dex: &DexFile, class: &str, name: &str) -> Option<u32> {
    dex.field_ids
        .iter()
        .position(|f| f.class == class && f.name == name)
        .map(|p: usize| p as u32)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValuesReadUse {
    ArrayReadOnly,
    Escapes,
    Written,
}

fn classify_values_read(insns: &[DalvikInsn], read_idx: usize) -> ValuesReadUse {
    let Some(read): Option<&DalvikInsn> = insns.get(read_idx) else {
        return ValuesReadUse::Escapes;
    };
    let Some(&dest): Option<&u16> = read.regs.first() else {
        return ValuesReadUse::Escapes;
    };
    for insn in &insns[read_idx + 1..] {
        match insn.op {
            0x21 if insn.regs.get(1) == Some(&dest) => return ValuesReadUse::ArrayReadOnly,
            0x44..=0x4A if insn.regs.get(1) == Some(&dest) => return ValuesReadUse::ArrayReadOnly,
            0x4B..=0x51 if insn.regs.get(1) == Some(&dest) => return ValuesReadUse::Written,
            _ if insn.regs.contains(&dest) => return ValuesReadUse::Escapes,
            _ => {}
        }
    }
    ValuesReadUse::Escapes
}

fn detect_enums(dex: &DexFile, dex_meta: &DexMeta, bodies: &[Body], report: &mut InversionReport) {
    let facts: Vec<EnumValuesFacts> = detect_enum_values(dex, dex_meta);
    for fact in facts {
        let Some(field_id): Option<u32> = find_field_id(dex, &fact.enum_class, &fact.field_name)
        else {
            continue;
        };
        let enum_src: String = descriptor::binary_to_source(&fact.enum_class);
        let transform: Transform = Transform::RestoreEnumValues {
            enum_class: enum_src.clone(),
            field: fact.field_name.clone(),
        };

        let mut written_outside_clinit: bool = false;
        for body in bodies {
            let in_clinit: bool = body.meta.name == "<clinit>";
            for insn in &body.insns {
                if matches!(insn.op, 0x67 | 0x69) && insn.index == Some(field_id) && !in_clinit {
                    written_outside_clinit = true;
                }
            }
        }
        if written_outside_clinit {
            report.candidates.push(Candidate {
                transform,
                confidence: Confidence::Low,
                evidence: format!("enum {enum_src} cached {} array", fact.field_name),
                abstain_reason: Some(format!(
                    "{} is written outside <clinit>; values() restoration is unsound",
                    fact.field_name
                )),
                applied: false,
                rewrites: Vec::new(),
            });
            continue;
        }

        let mut rewrites: Vec<Rewrite> = Vec::new();
        let mut any_escape: bool = false;
        let mut any_written: bool = false;
        for body in bodies {
            if body.meta.name == "<clinit>" || body.meta.name == "values" {
                continue;
            }
            for (idx, insn) in body.insns.iter().enumerate() {
                if insn.op != 0x62 || insn.index != Some(field_id) {
                    continue;
                }
                let usage: ValuesReadUse = classify_values_read(&body.insns, idx);
                match usage {
                    ValuesReadUse::Written => {
                        any_written = true;
                    }
                    ValuesReadUse::Escapes => any_escape = true,
                    ValuesReadUse::ArrayReadOnly => {}
                }
                let note: Option<String> = match usage {
                    ValuesReadUse::Escapes => Some(
                        "array escapes; values() returns a fresh clone, restoring defensive-copy \
                         semantics but changing aliasing"
                            .to_string(),
                    ),
                    _ => None,
                };
                rewrites.push(Rewrite {
                    location: format!("{}.{} @{:#x}", body.meta.class, body.meta.name, insn.pc),
                    before: format!("{enum_src}.{}", fact.field_name),
                    after: format!("{enum_src}.values()"),
                    gate_green: usage != ValuesReadUse::Written,
                    gate_note: note,
                });
            }
        }

        if any_written {
            report.candidates.push(Candidate {
                transform,
                confidence: Confidence::Low,
                evidence: format!("enum {enum_src} cached {} array", fact.field_name),
                abstain_reason: Some(format!(
                    "{} backing array is mutated via aput; values() restoration is unsound",
                    fact.field_name
                )),
                applied: false,
                rewrites: Vec::new(),
            });
            continue;
        }
        if rewrites.is_empty() {
            continue;
        }

        let confidence: Confidence = if fact.has_values_method && !any_escape {
            Confidence::High
        } else {
            Confidence::Medium
        };
        report.candidates.push(Candidate {
            transform,
            confidence,
            evidence: format!(
                "enum {enum_src} extends java.lang.Enum; synthetic {} : {}; synthetic values() present: {}; \
                 {} read site(s) restored",
                fact.field_name,
                fact.field_type,
                fact.has_values_method,
                rewrites.len()
            ),
            abstain_reason: None,
            applied: true,
            rewrites,
        });
    }
}
