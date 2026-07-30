use std::collections::BTreeMap;

use crate::abc::{AbcFile, ClassInfo, InstanceInfo, MethodBody, MethodInfo, TraitInfo};
use crate::error::Result;
use crate::lifter::{LiftedBody, LocalNames, lift_body, local_names_for, render_body};

const INSTANCE_FLAG_SEALED: u8 = 0x01;
const INSTANCE_FLAG_FINAL: u8 = 0x02;
const INSTANCE_FLAG_INTERFACE: u8 = 0x04;

const TRAIT_KIND_METHOD: u8 = 1;
const TRAIT_KIND_GETTER: u8 = 2;
const TRAIT_KIND_SETTER: u8 = 3;
const TRAIT_KIND_FUNCTION: u8 = 5;

fn push_format(out: &mut String, args: std::fmt::Arguments<'_>) {
    let result: std::result::Result<(), std::fmt::Error> = std::fmt::write(out, args);
    if let Err(error) = result {
        unreachable!("string formatting failed: {error}");
    }
}

fn body_index(abc: &AbcFile) -> BTreeMap<u32, usize> {
    abc.method_bodies
        .iter()
        .enumerate()
        .map(|(i, b): (usize, &MethodBody)| (b.method, i))
        .collect()
}

const fn static_modifier(is_static: bool) -> &'static str {
    if is_static { "static " } else { "" }
}

fn render_method_signature(
    abc: &AbcFile,
    method_idx: u32,
    name: &str,
    kind: u8,
    is_static: bool,
) -> String {
    let info: Option<&MethodInfo> = abc.methods.get(method_idx as usize);
    let ret: String = info.map_or_else(
        || "*".to_owned(),
        |mi: &MethodInfo| {
            abc.cpool
                .render_multiname(mi.return_type)
                .unwrap_or_else(|_| "*".to_owned())
        },
    );
    let params: String =
        info.map_or_else(String::new, |mi: &MethodInfo| render_param_list(abc, mi));
    let modifier: &str = static_modifier(is_static);
    match kind {
        TRAIT_KIND_GETTER => format!("public {modifier}function get {name}(): {ret}"),
        TRAIT_KIND_SETTER => format!("public {modifier}function set {name}({params}): {ret}"),
        _ => format!("public {modifier}function {name}({params}): {ret}"),
    }
}

fn lifted_method_body(
    abc: &AbcFile,
    method_idx: u32,
    bodies: &BTreeMap<u32, usize>,
) -> Option<String> {
    let body_pos: usize = *bodies.get(&method_idx)?;
    let body: &MethodBody = abc.method_bodies.get(body_pos)?;
    let info: Option<&MethodInfo> = abc.methods.get(method_idx as usize);
    let lifted: LiftedBody = lift_body(abc, body, info).ok()?;
    let names: LocalNames = local_names_for(abc, info);
    let mut rendered: String = String::new();
    if let Some(warning) = lifted.fidelity_warning() {
        push_format(
            &mut rendered,
            format_args!("        /// DR-AS3-PARTIAL: {warning}\n"),
        );
    }
    rendered.push_str(&render_body(&lifted, &names, "        "));
    Some(rendered)
}

pub fn render_class_skeleton(abc: &AbcFile, instance: &InstanceInfo) -> Result<String> {
    let mut out: String = String::new();
    let name: String = abc.cpool.render_multiname(instance.name_index)?;
    let super_name: String = if instance.super_index == 0 {
        "Object".to_owned()
    } else {
        abc.cpool.render_multiname(instance.super_index)?
    };

    let is_iface: bool = (instance.flags & INSTANCE_FLAG_INTERFACE) != 0;
    let is_final: bool = (instance.flags & INSTANCE_FLAG_FINAL) != 0;
    let is_dynamic: bool = (instance.flags & INSTANCE_FLAG_SEALED) == 0;

    let keyword: &str = if is_iface { "interface" } else { "class" };
    let mut modifiers: Vec<&str> = Vec::new();
    if is_final {
        modifiers.push("final");
    }
    if is_dynamic && !is_iface {
        modifiers.push("dynamic");
    }
    let mod_str: String = if modifiers.is_empty() {
        String::new()
    } else {
        format!("{} ", modifiers.join(" "))
    };

    push_format(
        &mut out,
        format_args!("{mod_str}public {keyword} {name} extends {super_name} {{\n"),
    );

    let bodies: BTreeMap<u32, usize> = body_index(abc);
    if instance.iinit != 0 || bodies.contains_key(&instance.iinit) {
        write_constructor(&mut out, abc, instance, &name, &bodies);
    }
    for trait_info in &instance.traits {
        write_trait(&mut out, abc, trait_info, &bodies, false)?;
    }
    for trait_info in static_traits_for(abc, instance) {
        write_trait(&mut out, abc, trait_info, &bodies, true)?;
    }
    out.push_str("}\n");
    Ok(out)
}

fn static_traits_for<'a>(abc: &'a AbcFile, instance: &InstanceInfo) -> &'a [TraitInfo] {
    let Some(position): Option<usize> = abc
        .instances
        .iter()
        .position(|candidate: &InstanceInfo| std::ptr::eq(candidate, instance))
    else {
        return &[];
    };
    abc.classes
        .get(position)
        .map_or(&[], |class: &ClassInfo| class.traits.as_slice())
}

fn write_constructor(
    out: &mut String,
    abc: &AbcFile,
    instance: &InstanceInfo,
    class_name: &str,
    bodies: &BTreeMap<u32, usize>,
) {
    let info: Option<&MethodInfo> = abc.methods.get(instance.iinit as usize);
    let params: String =
        info.map_or_else(String::new, |mi: &MethodInfo| render_param_list(abc, mi));
    match lifted_method_body(abc, instance.iinit, bodies) {
        Some(body) if !body.trim().is_empty() => {
            push_format(
                out,
                format_args!("    public function {class_name}({params}) {{\n"),
            );
            out.push_str(&body);
            out.push_str("    }\n");
        }
        _ => {
            push_format(
                out,
                format_args!("    public function {class_name}({params}) {{ }}\n"),
            );
        }
    }
}

fn render_param_list(abc: &AbcFile, mi: &MethodInfo) -> String {
    mi.param_types
        .iter()
        .enumerate()
        .map(|(i, &ty): (usize, &u32)| {
            let pname: String = mi
                .param_names
                .get(i)
                .and_then(|&idx: &u32| abc.cpool.string_at(idx).ok())
                .filter(|s: &&str| !s.is_empty())
                .map_or_else(|| format!("param{}", i + 1), str::to_owned);
            let pty: String = abc
                .cpool
                .render_multiname(ty)
                .unwrap_or_else(|_| "*".to_owned());
            format!("{pname}: {pty}")
        })
        .collect::<Vec<String>>()
        .join(", ")
}

fn write_trait(
    out: &mut String,
    abc: &AbcFile,
    trait_info: &TraitInfo,
    bodies: &BTreeMap<u32, usize>,
    is_static: bool,
) -> Result<()> {
    let raw_name: String = abc.cpool.render_multiname(trait_info.name_index)?;
    let kind: u8 = trait_info.kind & 0x0F;
    let modifier: &str = static_modifier(is_static);
    match kind {
        0 => {
            let ty: String = render_type_or_star(abc, trait_info.type_name);
            push_format(
                out,
                format_args!("    public {modifier}var {raw_name}: {ty};\n"),
            );
        }
        6 => {
            let ty: String = render_type_or_star(abc, trait_info.type_name);
            push_format(
                out,
                format_args!("    public {modifier}const {raw_name}: {ty};\n"),
            );
        }
        TRAIT_KIND_METHOD | TRAIT_KIND_GETTER | TRAIT_KIND_SETTER | TRAIT_KIND_FUNCTION => {
            write_method_trait(out, abc, trait_info, &raw_name, kind, bodies, is_static);
        }
        4 => {
            push_format(
                out,
                format_args!("    public class {raw_name} {{ /* nested */ }}\n"),
            );
        }
        other => {
            push_format(
                out,
                format_args!("    /* trait kind {other} {raw_name} */\n"),
            );
        }
    }
    Ok(())
}

fn render_type_or_star(abc: &AbcFile, type_name: u32) -> String {
    if type_name == 0 {
        return "*".to_owned();
    }
    abc.cpool
        .render_multiname(type_name)
        .unwrap_or_else(|_| "*".to_owned())
}

fn write_method_trait(
    out: &mut String,
    abc: &AbcFile,
    trait_info: &TraitInfo,
    name: &str,
    kind: u8,
    bodies: &BTreeMap<u32, usize>,
    is_static: bool,
) {
    let sig: String = render_method_signature(abc, trait_info.method_index, name, kind, is_static);
    match lifted_method_body(abc, trait_info.method_index, bodies) {
        Some(body) if !body.trim().is_empty() => {
            push_format(out, format_args!("    {sig} {{\n"));
            out.push_str(&body);
            out.push_str("    }\n");
        }
        _ => {
            push_format(out, format_args!("    {sig} {{ }}\n"));
        }
    }
}

pub fn render_program(abc: &AbcFile) -> Result<String> {
    let mut out: String = String::new();
    for instance in &abc.instances {
        out.push_str(&render_class_skeleton(abc, instance)?);
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_program_yields_empty_string() {
        let abc: AbcFile = AbcFile {
            minor: 16,
            major: 46,
            cpool: crate::abc::ConstantPool::default(),
            methods: Vec::new(),
            metadata_count: 0,
            instances: Vec::new(),
            classes: Vec::new(),
            scripts: Vec::new(),
            method_bodies: Vec::new(),
        };
        let out: String = render_program(&abc).expect("render");
        assert!(out.is_empty());
    }
}
