use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::dalvik::DalvikInsn;
use crate::dalvik_cfg::{DalvikMethodCfg, build_dalvik_cfg_from_code_item};
use crate::dalvik_lift::{
    LiftOutcome, MethodContext, PendingResult, RegisterFile, lift_insn, render_branch_condition,
    seed_block_registers,
};
use crate::decompile_struct::{
    BasicBlock, BlockId, Cfg, Dominators, EdgeKind, NaturalLoop, Region, Structurer, SwitchKey,
    compute_dominators, find_natural_loops,
};
use crate::descriptor::{self, MethodDescriptor};
use crate::dex::{
    ACC_ABSTRACT, ACC_NATIVE, ACC_STATIC, CodeItem, CodeItemsReport, DexCodeState, DexFile,
    DexMethodCode, parse_code_items,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompiledDex {
    pub source: String,
    #[serde(default)]
    pub sources: BTreeMap<String, String>,
    pub class_count: usize,
    pub method_count: usize,
    pub fully_lifted_methods: usize,
    pub fallback_methods: usize,
    pub code_scan_complete: bool,
    pub decode_error_count: usize,
}

const MAX_RENDER_BYTES: usize = 4 * 1024 * 1024;

#[must_use]
pub fn decompile_dex(dex: &DexFile, bytes: &[u8]) -> DecompiledDex {
    crate::name_disambig::ensure_writable_identifier_scope(dex_declared_identifiers(dex), || {
        decompile_dex_scoped(dex, bytes)
    })
}

fn dex_declared_identifiers(dex: &DexFile) -> std::collections::BTreeSet<String> {
    let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for method in &dex.method_ids {
        names.insert(method.name.clone());
    }
    for field in &dex.field_ids {
        names.insert(field.name.clone());
    }
    for descriptor_name in &dex.class_descriptors {
        let trimmed: &str = descriptor_name
            .trim_start_matches('L')
            .trim_end_matches(';');
        for segment in trimmed.rsplit('/').take(1).flat_map(|s: &str| s.split('$')) {
            names.insert(segment.to_owned());
        }
    }
    names
}

fn decompile_dex_scoped(dex: &DexFile, bytes: &[u8]) -> DecompiledDex {
    let code_report: CodeItemsReport = parse_code_items(dex, bytes);
    let code_scan_complete: bool = code_report.is_fully_decoded();
    let decode_error_count: usize = code_report.error_count();
    let items: Vec<CodeItem> = code_report.decoded().to_vec();
    let desugar: crate::dalvik_desugar::DefaultInterfaceRecovery =
        crate::dalvik_desugar::DefaultInterfaceRecovery::analyze(dex, bytes, &code_report);
    let mut by_class: BTreeMap<String, Vec<&DexMethodCode>> = BTreeMap::new();
    for descriptor_name in &dex.class_descriptors {
        by_class.entry(descriptor_name.clone()).or_default();
    }
    for method in code_report.methods() {
        by_class
            .entry(method.class.clone())
            .or_default()
            .push(method);
    }

    let string_recovery: BTreeMap<String, crate::dalvik_strdec::DexStringRecovery> =
        crate::dalvik_strdec::recover(dex, bytes)
            .into_iter()
            .map(|r: crate::dalvik_strdec::DexStringRecovery| (r.class.clone(), r))
            .collect();
    let generic_recovery: crate::dalvik_strdec_generic::GenericStringRecovery =
        crate::dalvik_strdec_generic::recover(dex, bytes);
    let mut generic_by_method: BTreeMap<
        (String, String),
        Vec<&crate::dalvik_strdec_generic::CallSiteRecovery>,
    > = BTreeMap::new();
    for site in &generic_recovery.call_sites {
        generic_by_method
            .entry((site.caller_class.clone(), site.caller_method.clone()))
            .or_default()
            .push(site);
    }
    let cff_by_method: BTreeMap<(String, String, String), crate::dalvik_dexguard::DalvikMethodCff> =
        crate::dalvik_dexguard::unflatten_dex_methods(&items)
            .1
            .into_iter()
            .filter(|m: &crate::dalvik_dexguard::DalvikMethodCff| m.flattened)
            .map(|m: crate::dalvik_dexguard::DalvikMethodCff| {
                (
                    (
                        m.class.clone(),
                        m.method_name.clone(),
                        m.method_descriptor.clone(),
                    ),
                    m,
                )
            })
            .collect();

    let mut source: String = String::with_capacity(4096);
    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    let mut class_count: usize = 0;
    let mut method_count: usize = 0;
    let mut fully_lifted: usize = 0;
    let mut fallback: usize = 0;

    for (class_descriptor, methods) in &by_class {
        if desugar.suppresses_class(class_descriptor) {
            continue;
        }
        let recovery: Option<&crate::dalvik_strdec::DexStringRecovery> =
            string_recovery.get(class_descriptor);
        let rendered: RenderedClass = render_class(
            dex,
            class_descriptor,
            methods,
            &items,
            recovery,
            &cff_by_method,
            &generic_by_method,
            &desugar,
        );
        source.push_str(&rendered.text);
        source.push('\n');
        match sources.entry(rendered.source_path) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(rendered.text);
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                let merged: &mut String = slot.get_mut();
                merged.push('\n');
                merged.push_str(&strip_package_header(&rendered.text));
            }
        }
        class_count += 1;
        method_count += rendered.method_count;
        fully_lifted += rendered.fully_lifted;
        fallback += rendered.fallback;
    }
    let _: Option<()> = code_report
        .unrecovered_tail()
        .map(|tail: &crate::dex::DexCodeTail| {
            crate::debug::dbg_kv("dex-code-walk-incomplete", || {
                format!("{}: {}", tail.class, tail.error)
            });
            source.push_str("// <decompile: malformed bytecode>\n");
        });

    DecompiledDex {
        source,
        sources,
        class_count,
        method_count,
        fully_lifted_methods: fully_lifted,
        fallback_methods: fallback,
        code_scan_complete,
        decode_error_count,
    }
}

struct RenderedClass {
    text: String,
    source_path: String,
    method_count: usize,
    fully_lifted: usize,
    fallback: usize,
}

fn strip_package_header(rendered: &str) -> String {
    let mut out: String = String::with_capacity(rendered.len());
    let mut skipping: bool = true;
    for line in rendered.lines() {
        if skipping {
            let trimmed: &str = line.trim_start();
            if trimmed.starts_with("package ") && trimmed.ends_with(';') {
                continue;
            }
            if trimmed.is_empty() {
                continue;
            }
            skipping = false;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn java_source_path(package: Option<&str>, simple: &str) -> String {
    let leaf: &str = simple.split('.').next_back().unwrap_or(simple);
    match package {
        Some(pkg) if !pkg.is_empty() => format!("{}/{leaf}.java", pkg.replace('.', "/")),
        _ => format!("{leaf}.java"),
    }
}

fn render_class(
    dex: &DexFile,
    class_descriptor: &str,
    methods: &[&DexMethodCode],
    decoded: &[CodeItem],
    recovery: Option<&crate::dalvik_strdec::DexStringRecovery>,
    cff_by_method: &BTreeMap<(String, String, String), crate::dalvik_dexguard::DalvikMethodCff>,
    generic_by_method: &BTreeMap<
        (String, String),
        Vec<&crate::dalvik_strdec_generic::CallSiteRecovery>,
    >,
    desugar: &crate::dalvik_desugar::DefaultInterfaceRecovery,
) -> RenderedClass {
    let binary: String = descriptor::binary_to_source(class_descriptor);
    let (package, simple): (Option<&str>, &str) = match binary.rfind('.') {
        Some(p) => (Some(&binary[..p]), &binary[p + 1..]),
        None => (None, binary.as_str()),
    };

    let mut text: String = String::with_capacity(1024);
    if let Some(pkg) = package {
        let _ = writeln!(text, "package {pkg};");
        let _ = writeln!(text);
    }
    let class_is_abstract: bool = methods
        .iter()
        .any(|method: &&DexMethodCode| method.access_flags & ACC_ABSTRACT != 0);
    let class_declaration: &str = if desugar.recovers_interface(class_descriptor) {
        "public interface"
    } else if class_is_abstract {
        "public abstract class"
    } else {
        "public class"
    };
    let implemented: String = match desugar.implemented_interfaces(class_descriptor) {
        Some(interfaces) if !interfaces.is_empty() => {
            let names: Vec<String> = interfaces
                .iter()
                .map(|interface: &String| descriptor::binary_to_source(interface))
                .collect();
            format!(" implements {}", names.join(", "))
        }
        _ => String::new(),
    };
    let _: std::fmt::Result = writeln!(text, "{class_declaration} {simple}{implemented} {{");

    if let Some(rec) = recovery {
        text.push_str(&recovered_strings_annotation(rec));
    }

    let mut method_count: usize = 0;
    let mut fully_lifted: usize = 0;
    let mut fallback: usize = 0;
    for method in methods {
        if desugar.suppresses_method(
            &method.class,
            &method.method_name,
            &method.method_descriptor,
        ) {
            continue;
        }
        let recovered_default: Option<&crate::dalvik_desugar::DefaultInterfaceMethod> = desugar
            .recovered_method(
                &method.class,
                &method.method_name,
                &method.method_descriptor,
            );
        let item: Option<&CodeItem> = match &method.state {
            DexCodeState::Decoded(index) => decoded.get(*index),
            DexCodeState::Absent | DexCodeState::Refused(_) => None,
        };
        let cff: Option<&crate::dalvik_dexguard::DalvikMethodCff> = cff_by_method.get(&(
            method.class.clone(),
            method.method_name.clone(),
            method.method_descriptor.clone(),
        ));
        let generic_sites: Option<&Vec<&crate::dalvik_strdec_generic::CallSiteRecovery>> =
            generic_by_method.get(&(method.class.clone(), method.method_name.clone()));
        let rendered: RenderedMethod = match (&method.state, item, recovered_default) {
            (_, _, Some(recovered)) => decoded.get(recovered.bridge_item).map_or_else(
                || {
                    render_unavailable_method(
                        simple,
                        method,
                        Some("default interface bridge is absent"),
                    )
                },
                |bridge: &CodeItem| {
                    render_method(dex, simple, bridge, None, None, desugar, Some(recovered))
                },
            ),
            (DexCodeState::Decoded(_), Some(_), None)
                if method.access_flags & (ACC_NATIVE | ACC_ABSTRACT) != 0 =>
            {
                render_unavailable_method(
                    simple,
                    method,
                    Some("code item is present on a bodyless declaration"),
                )
            }
            (DexCodeState::Decoded(_), Some(item), None) => {
                render_method(dex, simple, item, cff, generic_sites, desugar, None)
            }
            (DexCodeState::Decoded(_), None, None) => {
                render_unavailable_method(simple, method, Some("decoded body is absent"))
            }
            (DexCodeState::Absent, _, None) => {
                let expected_absence: bool = method.access_flags & (ACC_NATIVE | ACC_ABSTRACT) != 0;
                if expected_absence {
                    render_unavailable_method(simple, method, None)
                } else {
                    render_unavailable_method(simple, method, Some("code item is absent"))
                }
            }
            (DexCodeState::Refused(error), _, None) => {
                let reason: String = error.to_string();
                render_unavailable_method(simple, method, Some(&reason))
            }
        };
        let _ = writeln!(text, "{}", rendered.text);
        method_count += 1;
        if rendered.fully_lifted {
            fully_lifted += 1;
        } else if rendered.has_body || rendered.refused {
            fallback += 1;
        }
    }

    let _ = writeln!(text, "}}");
    RenderedClass {
        text,
        source_path: java_source_path(package, simple),
        method_count,
        fully_lifted,
        fallback,
    }
}

fn recovered_strings_annotation(rec: &crate::dalvik_strdec::DexStringRecovery) -> String {
    let mut out: String = String::new();
    if !rec.recovered.is_empty() {
        let _ = writeln!(
            out,
            "    // recovered {} encrypted string(s) by running {}() over the static table:",
            rec.recovered.len(),
            rec.decrypt_method
        );
        for d in &rec.recovered {
            let _ = writeln!(
                out,
                "    //   [{}] = {}",
                d.table_index,
                crate::bytecode::escape_java_string(&d.plaintext)
            );
        }
        for site in &rec.reflective_call_sites {
            let _ = writeln!(
                out,
                "    // reflective decrypt call site {}->{} resolves to {}",
                site.caller_class, site.caller_method, site.resolved_member
            );
        }
    } else if rec.runtime_key_wall
        && let Some(reason) = &rec.runtime_key_wall_reason
    {
        let _ = writeln!(out, "    // string decrypt not recoverable: {reason}");
    }
    out
}

fn generic_call_site_annotation(
    sites: &[&crate::dalvik_strdec_generic::CallSiteRecovery],
) -> String {
    let mut out: String = String::new();
    for site in sites {
        match &site.outcome {
            crate::dalvik_strdec_generic::CallSiteOutcome::Recovered(plain) => {
                let _ = writeln!(
                    out,
                    "        // recovered call site pc={}: {}->{}{} = {}",
                    site.pc,
                    site.decrypt_class,
                    site.decrypt_method,
                    site.decrypt_descriptor,
                    crate::bytecode::escape_java_string(plain)
                );
            }
            crate::dalvik_strdec_generic::CallSiteOutcome::Skipped(reason) => {
                let _ = writeln!(
                    out,
                    "        // decrypt call site pc={} to {}->{}{} not recoverable: {reason}",
                    site.pc, site.decrypt_class, site.decrypt_method, site.decrypt_descriptor
                );
            }
        }
    }
    out
}

struct RenderedMethod {
    text: String,
    fully_lifted: bool,
    has_body: bool,
    refused: bool,
}

fn render_unavailable_method(
    class_simple: &str,
    method: &DexMethodCode,
    refusal: Option<&str>,
) -> RenderedMethod {
    let parsed: Option<MethodDescriptor> = descriptor::parse_method(&method.method_descriptor);
    let is_constructor: bool = method.method_name == "<init>";
    let is_clinit: bool = method.method_name == "<clinit>";
    let is_static: bool = method.access_flags & ACC_STATIC != 0;
    let mut modifiers: Vec<&str> = vec!["public"];
    if is_static && !is_clinit {
        modifiers.push("static");
    }
    if method.access_flags & ACC_ABSTRACT != 0 {
        modifiers.push("abstract");
    }
    if method.access_flags & ACC_NATIVE != 0 {
        modifiers.push("native");
    }
    let modifier: String = modifiers.join(" ");
    let params: String = parsed.as_ref().map_or_else(String::new, |descriptor| {
        descriptor
            .params
            .iter()
            .enumerate()
            .map(
                |(index, parameter): (usize, &crate::descriptor::JavaType)| {
                    format!("{} arg{index}", parameter.render())
                },
            )
            .collect::<Vec<String>>()
            .join(", ")
    });
    let mut signature: String = if is_constructor {
        format!("    {modifier} {class_simple}({params})")
    } else if is_clinit {
        "    static".to_string()
    } else {
        let result: String = parsed.as_ref().map_or_else(
            || "void".to_string(),
            |descriptor| descriptor.returns.render(),
        );
        format!(
            "    {modifier} {result} {}({params})",
            crate::descriptor::java_writable_identifier(&method.method_name)
        )
    };
    let Some(reason): Option<&str> = refusal else {
        signature.push(';');
        return RenderedMethod {
            text: signature,
            fully_lifted: false,
            has_body: false,
            refused: false,
        };
    };
    crate::debug::dbg_kv("dex-method-code-reject", || {
        format!(
            "{}->{}{}: {reason}",
            method.class, method.method_name, method.method_descriptor
        )
    });
    let bodyless: bool = method.access_flags & (ACC_NATIVE | ACC_ABSTRACT) != 0;
    if bodyless {
        let _: std::fmt::Result = write!(signature, "; // <decompile: malformed bytecode>");
    } else if is_clinit {
        let _: std::fmt::Result = write!(
            signature,
            " {{\n        // <decompile: malformed bytecode>\n    }}"
        );
    } else {
        let _: std::fmt::Result = write!(
            signature,
            " {{\n        // <decompile: malformed bytecode>\n        throw new UnsupportedOperationException(\"malformed bytecode\");\n    }}"
        );
    }
    RenderedMethod {
        text: signature,
        fully_lifted: false,
        has_body: !bodyless,
        refused: true,
    }
}

fn render_method(
    dex: &DexFile,
    class_simple: &str,
    item: &CodeItem,
    cff: Option<&crate::dalvik_dexguard::DalvikMethodCff>,
    generic_sites: Option<&Vec<&crate::dalvik_strdec_generic::CallSiteRecovery>>,
    desugar: &crate::dalvik_desugar::DefaultInterfaceRecovery,
    recovered_default: Option<&crate::dalvik_desugar::DefaultInterfaceMethod>,
) -> RenderedMethod {
    let method_descriptor: &str = recovered_default.map_or(
        item.method_descriptor.as_str(),
        |recovered: &crate::dalvik_desugar::DefaultInterfaceMethod| recovered.descriptor.as_str(),
    );
    let method_name: &str = recovered_default.map_or(
        item.method_name.as_str(),
        |recovered: &crate::dalvik_desugar::DefaultInterfaceMethod| recovered.name.as_str(),
    );
    let parsed: Option<MethodDescriptor> = descriptor::parse_method(method_descriptor);
    let footprint: u16 = parsed
        .as_ref()
        .map(|md| {
            md.params
                .iter()
                .map(|p| if p.category_two() { 2u16 } else { 1u16 })
                .sum()
        })
        .unwrap_or(0);
    let is_constructor: bool = method_name == "<init>";
    let is_clinit: bool = method_name == "<clinit>";
    let is_static: bool =
        recovered_default.is_none() && !is_constructor && item.ins_size <= footprint;

    let mut signature: String = String::new();
    let modifier: &str = if recovered_default.is_some() {
        "public default "
    } else if is_static {
        "public static "
    } else {
        "public "
    };

    let params: String = match &parsed {
        Some(md) => md
            .params
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let name: String = item
                    .param_names
                    .get(i)
                    .and_then(|n: &Option<String>| n.clone())
                    .filter(|n: &String| crate::name_disambig::is_java_source_identifier(n))
                    .unwrap_or_else(|| format!("arg{i}"));
                format!("{} {name}", p.render())
            })
            .collect::<Vec<String>>()
            .join(", "),
        None => String::new(),
    };

    if is_constructor {
        let _ = write!(signature, "    {modifier}{class_simple}({params})");
    } else if is_clinit {
        let _ = write!(signature, "    static");
    } else {
        let ret: String = parsed
            .as_ref()
            .map_or_else(|| "void".to_string(), |md| md.returns.render());
        let _ = write!(
            signature,
            "    {modifier}{ret} {}({params})",
            crate::descriptor::java_writable_identifier(method_name)
        );
    }

    let body: MethodBody = lift_method(
        dex,
        item,
        is_static,
        method_descriptor,
        recovered_default.is_some(),
        desugar,
    );
    let cff_note: String = cff.map_or_else(String::new, cff_annotation);
    let generic_note: String = generic_sites
        .map(
            |sites: &Vec<&crate::dalvik_strdec_generic::CallSiteRecovery>| {
                generic_call_site_annotation(sites)
            },
        )
        .unwrap_or_default();
    let text: String = format!(
        "{signature} {{\n{cff_note}{generic_note}{}    }}",
        body.text
    );
    RenderedMethod {
        text,
        fully_lifted: body.fully_lifted,
        has_body: true,
        refused: false,
    }
}

fn cff_annotation(cff: &crate::dalvik_dexguard::DalvikMethodCff) -> String {
    if !cff.flattened {
        return String::new();
    }
    let mut out: String = String::new();
    if cff.fully_unflattened {
        let _ = writeln!(
            out,
            "        // control-flow flattening removed: {} dispatcher(s) resolved, {} edge(s) \
             rewired to linear block order [{}]",
            cff.dispatchers_resolved,
            cff.edges_redirected,
            cff.recovered_block_order
                .iter()
                .map(u32::to_string)
                .collect::<Vec<String>>()
                .join(", ")
        );
    } else {
        let _ = writeln!(
            out,
            "        // control-flow flattening detected: {} dispatcher(s) resolved, {} residual \
             dispatcher edge(s) remain",
            cff.dispatchers_resolved, cff.residual_dispatcher_edges
        );
    }
    out
}

struct MethodBody {
    text: String,
    fully_lifted: bool,
}

fn register_mention_blocks(
    cfg: &Cfg,
    insns: &[DalvikInsn],
) -> BTreeMap<u16, std::collections::BTreeSet<BlockId>> {
    let mut out: BTreeMap<u16, std::collections::BTreeSet<BlockId>> = BTreeMap::new();
    for block in &cfg.blocks {
        let (start, end): (usize, usize) = block.insn_range;
        let Some(slice): Option<&[DalvikInsn]> = insns.get(start..end) else {
            continue;
        };
        for insn in slice {
            for &reg in &insn.regs {
                out.entry(reg).or_default().insert(block.id);
            }
        }
    }
    out
}

fn lift_method(
    dex: &DexFile,
    item: &CodeItem,
    is_static: bool,
    method_descriptor: &str,
    inline_temporaries: bool,
    desugar: &crate::dalvik_desugar::DefaultInterfaceRecovery,
) -> MethodBody {
    if item.insns.is_empty() {
        return MethodBody {
            text: String::new(),
            fully_lifted: true,
        };
    }
    let Some(built): Option<DalvikMethodCfg> = build_dalvik_cfg_from_code_item(item) else {
        return MethodBody {
            text: "        // <decompile: malformed bytecode>\n".to_string(),
            fully_lifted: false,
        };
    };
    let blackobf_note: String =
        blackobfuscator_annotation(&built.insns, &built.switch_payloads, dex);
    let dom: Dominators = compute_dominators(&built.cfg);
    let loops: Vec<NaturalLoop> = find_natural_loops(&built.cfg, &dom);
    let mut structurer: Structurer<'_> =
        Structurer::with_switch_map(&built.cfg, &dom, &loops, &[], built.switch_map.clone());
    let root: Region = structurer.structure();

    let ctx: MethodContext<'_> = MethodContext::new(
        dex,
        item.registers_size,
        item.ins_size,
        method_descriptor,
        is_static,
        inline_temporaries,
        desugar,
    );
    let register_blocks: BTreeMap<u16, std::collections::BTreeSet<BlockId>> =
        register_mention_blocks(&built.cfg, &built.insns);
    let mut render: RenderState<'_> = RenderState {
        ctx: &ctx,
        cfg: &built.cfg,
        insns: &built.insns,
        rendered_blocks: std::collections::BTreeSet::new(),
        fully_lifted: !structurer.had_irreducible,
        register_blocks,
    };
    let mut out: String = String::new();
    render_region(&mut render, &root, &mut out, 2);
    MethodBody {
        text: format!("{blackobf_note}{out}"),
        fully_lifted: render.fully_lifted,
    }
}

fn blackobfuscator_annotation(
    insns: &[crate::dalvik::DalvikInsn],
    switch_payloads: &[(u32, crate::dalvik::SwitchPayload)],
    dex: &DexFile,
) -> String {
    let report: crate::dalvik_blackobf::BlackObfReport =
        crate::dalvik_blackobf::detect_blackobfuscator(insns, switch_payloads);
    if !report.flattened {
        return String::new();
    }
    let strings: &[String] = &dex.strings;
    let deflatten: Option<crate::dalvik_blackobf::BlackObfDeflatten> =
        crate::dalvik_blackobf::deflatten_blackobfuscator(insns, switch_payloads, strings);
    match deflatten {
        Some(d) if d.resolved_cases > 0 => format!(
            "        // BlackObfuscator control-flow flattening: {} of {} dispatcher case(s) mapped back to their block, linear block order [{}]; the body below is still rendered from the flattened graph\n",
            d.resolved_cases,
            d.resolved_cases + d.unresolved_cases,
            d.linear_block_pcs
                .iter()
                .map(u32::to_string)
                .collect::<Vec<String>>()
                .join(", ")
        ),
        _ => format!(
            "        // BlackObfuscator control-flow flattening detected ({} hashCode-keyed dispatcher case(s)); block-name strings unresolved\n",
            report.dispatch_cases
        ),
    }
}

struct RenderState<'a> {
    ctx: &'a MethodContext<'a>,
    cfg: &'a Cfg,
    insns: &'a [DalvikInsn],
    rendered_blocks: std::collections::BTreeSet<BlockId>,
    fully_lifted: bool,
    register_blocks: BTreeMap<u16, std::collections::BTreeSet<BlockId>>,
}

fn indent_string(level: usize) -> String {
    "    ".repeat(level)
}

fn render_region(state: &mut RenderState<'_>, region: &Region, out: &mut String, level: usize) {
    if out.len() > MAX_RENDER_BYTES {
        return;
    }
    match region {
        Region::Block(bid) => render_block(state, *bid, out, level),
        Region::Sequence(items) => {
            for r in items {
                render_region(state, r, out, level);
            }
        }
        Region::IfThen {
            head, then_body, ..
        } => {
            let cond: String = render_head_condition(state, *head, out, level);
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}if ({}) {{", invert(&cond));
            render_region(state, then_body, out, level + 1);
            let _ = writeln!(out, "{pad}}}");
        }
        Region::IfThenElse {
            head,
            then_body,
            else_body,
            ..
        } => {
            let cond: String = render_head_condition(state, *head, out, level);
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}if ({}) {{", invert(&cond));
            render_region(state, then_body, out, level + 1);
            let _ = writeln!(out, "{pad}}} else {{");
            render_region(state, else_body, out, level + 1);
            let _ = writeln!(out, "{pad}}}");
        }
        Region::While { header, body, exit } => {
            let cond: String = render_head_condition(state, *header, out, level);
            let negated: bool =
                matches!(exit, Some(e) if header_cond_true_target(state.cfg, *header) == Some(*e));
            let displayed: String = if negated { invert(&cond) } else { cond };
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}while ({displayed}) {{");
            render_region(state, body, out, level + 1);
            let _ = writeln!(out, "{pad}}}");
        }
        Region::DoWhile { header, body, .. } => {
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}do {{");
            render_block(state, *header, out, level + 1);
            render_region(state, body, out, level + 1);
            let _ = writeln!(out, "{pad}}} while (true);");
        }
        Region::Switch {
            head,
            cases,
            default,
            ..
        } => {
            let subject: String = render_switch_subject(state, *head, out, level);
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}switch ({subject}) {{");
            for (i, (key, body)) in cases.iter().enumerate() {
                let _ = writeln!(out, "{pad}    case {}:", format_switch_key(key, i));
                render_region(state, body, out, level + 2);
                let _ = writeln!(out, "{pad}        break;");
            }
            if let Some(def) = default {
                let _ = writeln!(out, "{pad}    default:");
                render_region(state, def, out, level + 2);
                let _ = writeln!(out, "{pad}        break;");
            }
            let _ = writeln!(out, "{pad}}}");
        }
        Region::Try { try_body, handlers } => {
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}try {{");
            render_region(state, try_body, out, level + 1);
            for (catch_types, handler_region) in handlers {
                let ty: String = descriptor::catch_clause(catch_types);
                let _ = writeln!(out, "{pad}}} catch ({ty} ex) {{");
                render_region(state, handler_region, out, level + 1);
            }
            let _ = writeln!(out, "{pad}}}");
        }
        Region::TryFinally {
            try_body,
            handlers,
            finally_body,
            ..
        } => {
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}try {{");
            render_region(state, try_body, out, level + 1);
            for (catch_types, handler_region) in handlers {
                let ty: String = descriptor::catch_clause(catch_types);
                let _ = writeln!(out, "{pad}}} catch ({ty} ex) {{");
                render_region(state, handler_region, out, level + 1);
            }
            let _ = writeln!(out, "{pad}}} finally {{");
            render_region(state, finally_body, out, level + 1);
            let _ = writeln!(out, "{pad}}}");
        }
        Region::TryWithResources {
            resource_slot,
            try_body,
        } => {
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}try (v{resource_slot}) {{");
            render_region(state, try_body, out, level + 1);
            let _ = writeln!(out, "{pad}}}");
        }
        Region::Synchronized {
            lock_block,
            lock_slot,
            body,
        } => {
            render_block(state, *lock_block, out, level);
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}synchronized (v{lock_slot}) {{");
            render_region(state, body, out, level + 1);
            let _ = writeln!(out, "{pad}}}");
        }
        Region::LabeledLoop { label, body } => {
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}L{label}:");
            render_region(state, body, out, level);
        }
        Region::Break { label } => {
            let pad: String = indent_string(level);
            match label {
                Some(l) => {
                    let _ = writeln!(out, "{pad}break L{l};");
                }
                None => {
                    let _ = writeln!(out, "{pad}break;");
                }
            }
        }
        Region::Continue { label, latch } => {
            if let Some(latch_bid) = latch {
                render_block(state, *latch_bid, out, level);
            }
            let pad: String = indent_string(level);
            match label {
                Some(l) => {
                    let _ = writeln!(out, "{pad}continue L{l};");
                }
                None => {
                    let _ = writeln!(out, "{pad}continue;");
                }
            }
        }
        Region::Irreducible { blocks } => {
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}// irreducible region");
            for bid in blocks {
                render_block(state, *bid, out, level);
            }
            state.fully_lifted = false;
        }
    }
}

fn block_insn_range(state: &RenderState<'_>, bid: BlockId) -> (usize, usize) {
    let block: &BasicBlock = &state.cfg.blocks[bid.0 as usize];
    block.insn_range
}

fn materialize_pending(
    state: &RenderState<'_>,
    file: &RegisterFile,
    here: BlockId,
    out: &mut String,
    level: usize,
) {
    let falls_through: bool = !state.cfg.blocks[here.0 as usize].successors.is_empty();
    if !falls_through {
        return;
    }
    let pad: String = indent_string(level);
    for reg in file.pending_registers() {
        let live_elsewhere: bool = state.register_blocks.get(&reg).is_some_and(
            |blocks: &std::collections::BTreeSet<BlockId>| {
                blocks.iter().any(|&b: &BlockId| b != here)
            },
        );
        if !live_elsewhere {
            continue;
        }
        let expr: crate::decompile::Expr = file.current(state.ctx, reg);
        let rendered: String = expr.render();
        let lvalue: String = state.ctx.register_lvalue(reg);
        if rendered == lvalue {
            continue;
        }
        let _ = writeln!(out, "{pad}{lvalue} = {rendered};");
    }
}

fn render_block(state: &mut RenderState<'_>, bid: BlockId, out: &mut String, level: usize) {
    if !state.rendered_blocks.insert(bid) {
        return;
    }
    let (start, end): (usize, usize) = block_insn_range(state, bid);
    let mut file: RegisterFile = RegisterFile::new();
    seed_block_registers(state.ctx, &mut file);
    let mut pending: Option<PendingResult> = None;
    for insn in &state.insns[start..end] {
        if insn.is_conditional_branch() || insn.is_unconditional_goto() || insn.is_switch() {
            continue;
        }
        emit_insn(state.ctx, &mut file, insn, &mut pending, out, level);
    }
    materialize_pending(state, &file, bid, out, level);
}

fn render_head_condition(
    state: &mut RenderState<'_>,
    head: BlockId,
    out: &mut String,
    level: usize,
) -> String {
    let (start, end): (usize, usize) = block_insn_range(state, head);
    if start == end {
        return "true".to_string();
    }
    let body_end: usize = end - 1;
    let already: bool = !state.rendered_blocks.insert(head);
    let mut file: RegisterFile = RegisterFile::new();
    seed_block_registers(state.ctx, &mut file);
    let mut pending: Option<PendingResult> = None;
    for insn in &state.insns[start..body_end] {
        if already {
            let _ = lift_insn(state.ctx, &mut file, insn, &mut pending);
        } else {
            emit_insn(state.ctx, &mut file, insn, &mut pending, out, level);
        }
    }
    if !already {
        materialize_pending(state, &file, head, out, level);
    }
    let term: &DalvikInsn = &state.insns[body_end];
    render_branch_condition(state.ctx, &file, term)
}

fn render_switch_subject(
    state: &mut RenderState<'_>,
    head: BlockId,
    out: &mut String,
    level: usize,
) -> String {
    let (start, end): (usize, usize) = block_insn_range(state, head);
    if start == end {
        return "var0".to_string();
    }
    let body_end: usize = end - 1;
    let already: bool = !state.rendered_blocks.insert(head);
    let mut file: RegisterFile = RegisterFile::new();
    seed_block_registers(state.ctx, &mut file);
    let mut pending: Option<PendingResult> = None;
    for insn in &state.insns[start..body_end] {
        if already {
            let _ = lift_insn(state.ctx, &mut file, insn, &mut pending);
        } else {
            emit_insn(state.ctx, &mut file, insn, &mut pending, out, level);
        }
    }
    if !already {
        materialize_pending(state, &file, head, out, level);
    }
    let term: &DalvikInsn = &state.insns[body_end];
    term.regs
        .first()
        .map(|&r| state.ctx.register_name(r).render())
        .unwrap_or_else(|| "var0".to_string())
}

fn emit_insn(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    insn: &DalvikInsn,
    pending: &mut Option<PendingResult>,
    out: &mut String,
    level: usize,
) {
    let pad: String = indent_string(level);
    match lift_insn(ctx, file, insn, pending) {
        LiftOutcome::Statement(s) => {
            let _ = writeln!(out, "{pad}{s};");
        }
        LiftOutcome::Statements(statements) => {
            for statement in statements {
                let _ = writeln!(out, "{pad}{statement};");
            }
        }
        LiftOutcome::None => {}
    }
}

fn header_cond_true_target(cfg: &Cfg, head: BlockId) -> Option<BlockId> {
    let block: &BasicBlock = &cfg.blocks[head.0 as usize];
    block
        .successors
        .iter()
        .find(|e| matches!(e.kind, EdgeKind::CondTrue))
        .map(|e| e.target)
}

fn format_switch_key(key: &SwitchKey, fallback_idx: usize) -> String {
    match key {
        SwitchKey::Range { low, high } => (*low..=*high)
            .map(|v: i32| v.to_string())
            .collect::<Vec<String>>()
            .join(", "),
        SwitchKey::Values(vs) if !vs.is_empty() => vs
            .iter()
            .map(i32::to_string)
            .collect::<Vec<String>>()
            .join(", "),
        SwitchKey::Values(_) => fallback_idx.to_string(),
    }
}

fn invert(cond: &str) -> String {
    if let Some(rest) = cond.strip_prefix('!') {
        return rest.to_string();
    }
    if cond.contains(" == ") {
        return cond.replacen(" == ", " != ", 1);
    }
    if cond.contains(" != ") {
        return cond.replacen(" != ", " == ", 1);
    }
    if cond.contains(" <= ") {
        return cond.replacen(" <= ", " > ", 1);
    }
    if cond.contains(" >= ") {
        return cond.replacen(" >= ", " < ", 1);
    }
    if cond.contains(" < ") {
        return cond.replacen(" < ", " >= ", 1);
    }
    if cond.contains(" > ") {
        return cond.replacen(" > ", " <= ", 1);
    }
    format!("!({cond})")
}

pub fn decompile_dex_bytes(bytes: &[u8]) -> crate::error::Result<DecompiledDex> {
    let dex: DexFile = crate::dex::parse(bytes)?;
    Ok(decompile_dex(&dex, bytes))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const EDGECASES_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");
    const EDGECASES_KT_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCasesKt.dex");

    fn decompiled() -> DecompiledDex {
        let dex: DexFile = crate::dex::parse(EDGECASES_DEX).expect("parse edgecases.dex");
        decompile_dex(&dex, EDGECASES_DEX)
    }

    #[test]
    fn gcd_body_has_modulo_and_loop() {
        let out: DecompiledDex = decompiled();
        let src: &str = &out.source;
        let start: usize = src.find("int gcd(").expect("gcd present");
        let slice: &str = &src[start..(start + 400).min(src.len())];
        assert!(slice.contains('%'), "gcd body must contain %: {slice}");
        assert!(
            slice.contains("while"),
            "gcd body must contain a loop: {slice}"
        );
        assert!(
            slice.contains("Math.abs"),
            "gcd body must reference Math.abs: {slice}"
        );
    }

    #[test]
    fn dotint_body_has_array_index_and_loop() {
        let out: DecompiledDex = decompiled();
        let src: &str = &out.source;
        let start: usize = src.find("int dotInt(").expect("dotInt present");
        let slice: &str = &src[start..(start + 500).min(src.len())];
        assert!(slice.contains('['), "dotInt must index arrays: {slice}");
        assert!(slice.contains("while"), "dotInt must loop: {slice}");
    }

    #[test]
    fn const_high16_families_render_full_width_values() {
        let out: DecompiledDex = decompiled();
        let src: &str = &out.source;
        assert!(
            src.contains("4636737291354636288L"),
            "100.0 (const-wide/high16 0x4059) must render its full double bit pattern, \
             not the raw 16-bit operand"
        );
        assert!(
            src.contains("4602678819172646912L"),
            "0.5 (const-wide/high16 0x3FE0) must render its full double bit pattern, \
             not the raw 16-bit operand"
        );
        assert!(
            src.contains("-2147483648"),
            "Integer.MIN_VALUE (const/high16 0x8000) must render shifted, not -32768"
        );
        assert!(
            !src.contains("16473L") && !src.contains("16352L"),
            "raw const-wide/high16 operands must not leak as long literals"
        );
    }

    #[test]
    fn kotlin_dex_emits_without_panic() {
        let dex: DexFile = crate::dex::parse(EDGECASES_KT_DEX).expect("parse edgecases kt dex");
        let out: DecompiledDex = decompile_dex(&dex, EDGECASES_KT_DEX);
        assert!(out.class_count > 0, "kotlin dex must yield classes");
    }
}
