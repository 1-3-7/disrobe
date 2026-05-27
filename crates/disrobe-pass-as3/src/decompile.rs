use std::fmt::Write;

use crate::abc::{AbcFile, InstanceInfo, TraitInfo};
use crate::error::Result;

const INSTANCE_FLAG_SEALED: u8 = 0x01;
const INSTANCE_FLAG_FINAL: u8 = 0x02;
const INSTANCE_FLAG_INTERFACE: u8 = 0x04;

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

    writeln!(
        out,
        "{mod_str}public {keyword} {name} extends {super_name} {{"
    )
    .map_err(io_err)?;

    for trait_info in &instance.traits {
        write_trait(&mut out, abc, trait_info)?;
    }
    writeln!(out, "}}").map_err(io_err)?;
    Ok(out)
}

fn write_trait(out: &mut String, abc: &AbcFile, trait_info: &TraitInfo) -> Result<()> {
    let raw_name: &str = abc.cpool.string_at(trait_info.name_index)?;
    let kind: u8 = trait_info.kind & 0x0F;
    let rendered: String = match kind {
        0 => format!("    public var {raw_name}: *;\n"),
        6 => format!("    public const {raw_name}: *;\n"),
        1 => format!("    public function {raw_name}() {{ /* method */ }}\n"),
        2 => format!("    public function get {raw_name}(): * {{ /* getter */ }}\n"),
        3 => format!("    public function set {raw_name}(value: *): void {{ /* setter */ }}\n"),
        4 => format!("    public class {raw_name} {{ /* nested */ }}\n"),
        5 => format!("    public function {raw_name}(): * {{ /* function */ }}\n"),
        _ => format!("    /* trait kind {kind} {raw_name} */\n"),
    };
    out.push_str(&rendered);
    Ok(())
}

pub fn render_program(abc: &AbcFile) -> Result<String> {
    let mut out: String = String::new();
    for instance in &abc.instances {
        out.push_str(&render_class_skeleton(abc, instance)?);
        out.push('\n');
    }
    Ok(out)
}

fn io_err(_: core::fmt::Error) -> crate::error::Error {
    crate::error::Error::Io(std::io::Error::other("formatter error"))
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
