use serde::Serialize;

use crate::component::{
    ComponentExportRecord, ComponentExternKind, ComponentImportRecord, ComponentManifest,
    ComponentTypeRefKind,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComponentBindings {
    pub world_name: String,
    pub rust_source: String,
    pub ts_source: String,
    pub wit_source: String,
    pub imports: Vec<ComponentBindingItem>,
    pub exports: Vec<ComponentBindingItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComponentBindingItem {
    pub name: String,
    pub kind: ComponentBindingKind,
    pub rust_ident: String,
    pub ts_ident: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ComponentBindingKind {
    Func,
    Module,
    Instance,
    Value,
    Type,
    Component,
}

#[must_use]
pub fn lift_component_manifest(manifest: &ComponentManifest, world: &str) -> ComponentBindings {
    let world_name: String = sanitize_ident(world);
    let imports: Vec<ComponentBindingItem> = manifest
        .world_imports
        .iter()
        .map(import_to_item)
        .collect::<Vec<_>>();
    let exports: Vec<ComponentBindingItem> = manifest
        .world_exports
        .iter()
        .map(export_to_item)
        .collect::<Vec<_>>();

    let rust_source: String = emit_rust(&world_name, &imports, &exports);
    let ts_source: String = emit_ts(&world_name, &imports, &exports);
    let wit_source: String = emit_wit(&world_name, &imports, &exports);

    ComponentBindings {
        world_name,
        rust_source,
        ts_source,
        wit_source,
        imports,
        exports,
    }
}

fn import_to_item(rec: &ComponentImportRecord) -> ComponentBindingItem {
    ComponentBindingItem {
        name: rec.name.clone(),
        kind: kind_from_type_ref(rec.type_kind),
        rust_ident: sanitize_ident(&rec.name),
        ts_ident: sanitize_camel(&rec.name),
    }
}

fn export_to_item(rec: &ComponentExportRecord) -> ComponentBindingItem {
    ComponentBindingItem {
        name: rec.name.clone(),
        kind: kind_from_extern(rec.kind),
        rust_ident: sanitize_ident(&rec.name),
        ts_ident: sanitize_camel(&rec.name),
    }
}

#[inline]
const fn kind_from_type_ref(k: ComponentTypeRefKind) -> ComponentBindingKind {
    match k {
        ComponentTypeRefKind::Func => ComponentBindingKind::Func,
        ComponentTypeRefKind::Module => ComponentBindingKind::Module,
        ComponentTypeRefKind::Instance => ComponentBindingKind::Instance,
        ComponentTypeRefKind::Value => ComponentBindingKind::Value,
        ComponentTypeRefKind::Type => ComponentBindingKind::Type,
        ComponentTypeRefKind::Component => ComponentBindingKind::Component,
    }
}

#[inline]
const fn kind_from_extern(k: ComponentExternKind) -> ComponentBindingKind {
    match k {
        ComponentExternKind::Func => ComponentBindingKind::Func,
        ComponentExternKind::Module => ComponentBindingKind::Module,
        ComponentExternKind::Instance => ComponentBindingKind::Instance,
        ComponentExternKind::Value => ComponentBindingKind::Value,
        ComponentExternKind::Type => ComponentBindingKind::Type,
        ComponentExternKind::Component => ComponentBindingKind::Component,
    }
}

fn emit_rust(
    world: &str,
    imports: &[ComponentBindingItem],
    exports: &[ComponentBindingItem],
) -> String {
    let mut out: String = String::with_capacity(512);
    out.push_str("#![allow(dead_code)]\n");
    let world_ty: String = pascal(world);
    crate::push_string_line(&mut out, format_args!("pub trait Imports{world_ty} {{"));
    for item in imports {
        match item.kind {
            ComponentBindingKind::Func => {
                crate::push_string_line(
                    &mut out,
                    format_args!(
                        "    fn {name}(&self) -> Result<(), HostError>;",
                        name = item.rust_ident
                    ),
                );
            }
            _ => {
                crate::push_string_line(
                    &mut out,
                    format_args!(
                        "    type {alias}: Send + Sync;",
                        alias = pascal(&item.rust_ident)
                    ),
                );
            }
        }
    }
    out.push_str("}\n\n");

    crate::push_string_line(&mut out, format_args!("pub trait Exports{world_ty} {{"));
    for item in exports {
        match item.kind {
            ComponentBindingKind::Func => {
                crate::push_string_line(
                    &mut out,
                    format_args!(
                        "    fn {name}(&self) -> Result<(), GuestError>;",
                        name = item.rust_ident
                    ),
                );
            }
            _ => {
                crate::push_string_line(
                    &mut out,
                    format_args!(
                        "    type {alias}: Send + Sync;",
                        alias = pascal(&item.rust_ident)
                    ),
                );
            }
        }
    }
    out.push_str("}\n\n");

    out.push_str("#[derive(Debug)]\npub struct HostError;\n\n");
    out.push_str("#[derive(Debug)]\npub struct GuestError;\n");
    out
}

fn emit_ts(
    world: &str,
    imports: &[ComponentBindingItem],
    exports: &[ComponentBindingItem],
) -> String {
    let mut out: String = String::with_capacity(512);
    let world_ty: String = pascal(world);
    crate::push_string_line(
        &mut out,
        format_args!("export interface Imports{world_ty} {{"),
    );
    for item in imports {
        match item.kind {
            ComponentBindingKind::Func => {
                crate::push_string_line(
                    &mut out,
                    format_args!("  {name}(): void;", name = item.ts_ident),
                );
            }
            _ => {
                crate::push_string_line(
                    &mut out,
                    format_args!("  readonly {name}: unknown;", name = item.ts_ident),
                );
            }
        }
    }
    out.push_str("}\n\n");

    crate::push_string_line(
        &mut out,
        format_args!("export interface Exports{world_ty} {{"),
    );
    for item in exports {
        match item.kind {
            ComponentBindingKind::Func => {
                crate::push_string_line(
                    &mut out,
                    format_args!("  {name}(): void;", name = item.ts_ident),
                );
            }
            _ => {
                crate::push_string_line(
                    &mut out,
                    format_args!("  readonly {name}: unknown;", name = item.ts_ident),
                );
            }
        }
    }
    out.push_str("}\n");
    out
}

fn emit_wit(
    world: &str,
    imports: &[ComponentBindingItem],
    exports: &[ComponentBindingItem],
) -> String {
    let mut out: String = String::with_capacity(256);
    crate::push_string_line(&mut out, format_args!("package disrobe:recovered;"));
    out.push('\n');
    crate::push_string_line(&mut out, format_args!("world {} {{", wit_ident(world)));
    for item in imports {
        emit_wit_item(&mut out, item, WitDirection::Import);
    }
    for item in exports {
        emit_wit_item(&mut out, item, WitDirection::Export);
    }
    out.push_str("}\n");
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WitDirection {
    Import,
    Export,
}

impl WitDirection {
    const fn keyword(self) -> &'static str {
        match self {
            Self::Import => "import",
            Self::Export => "export",
        }
    }
}

fn emit_wit_item(out: &mut String, item: &ComponentBindingItem, dir: WitDirection) {
    let name: String = wit_ident(&item.name);
    let kw: &str = dir.keyword();
    match item.kind {
        ComponentBindingKind::Func => {
            crate::push_string_line(out, format_args!("  {kw} {name}: func();"));
        }
        ComponentBindingKind::Instance => {
            crate::push_string_line(out, format_args!("  {kw} {name}: interface {{}}"));
        }
        ComponentBindingKind::Component => {
            crate::push_string_line(
                out,
                format_args!("  /// recovered component {kw} surfaced as an instance"),
            );
            crate::push_string_line(out, format_args!("  {kw} {name}: interface {{}}"));
        }
        ComponentBindingKind::Module => {
            crate::push_string_line(
                out,
                format_args!("  /// recovered core-module {kw} surfaced as an instance"),
            );
            crate::push_string_line(out, format_args!("  {kw} {name}: interface {{}}"));
        }
        ComponentBindingKind::Type => {
            crate::push_string_line(out, format_args!("  /// recovered abstract type ({kw})"));
            crate::push_string_line(out, format_args!("  resource {name};"));
        }
        ComponentBindingKind::Value => {
            crate::push_string_line(
                out,
                format_args!(
                    "  // recovered value {kw} `{raw}` has no WIT world-item form",
                    raw = item.name
                ),
            );
        }
    }
}

fn wit_ident(raw: &str) -> String {
    let mut out: String = String::with_capacity(raw.len());
    let mut prev_dash: bool = true;
    for c in raw.chars() {
        match c {
            'a'..='z' | '0'..='9' => {
                out.push(c);
                prev_dash = false;
            }
            'A'..='Z' => {
                if !out.is_empty() && !prev_dash {
                    out.push('-');
                }
                out.push(c.to_ascii_lowercase());
                prev_dash = true;
            }
            _ if !out.is_empty() && !prev_dash => {
                out.push('-');
                prev_dash = true;
            }
            _ => {}
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    let trimmed: &str = out.trim_start_matches(|c: char| c == '-' || c.is_ascii_digit());
    if trimmed.is_empty() {
        return "item".to_owned();
    }
    trimmed.to_owned()
}

fn sanitize_ident(raw: &str) -> String {
    let stripped: &str = raw.trim_start_matches(['#', '@', '/']);
    let mut out: String = String::with_capacity(stripped.len());
    let mut prev_us: bool = false;
    for c in stripped.chars() {
        match c {
            'a'..='z' | '0'..='9' => {
                out.push(c);
                prev_us = false;
            }
            'A'..='Z' => {
                if !out.is_empty() && !prev_us {
                    out.push('_');
                }
                out.push(c.to_ascii_lowercase());
                prev_us = true;
            }
            '_' | '-' | '/' | ':' | '.' | ' ' | '@' | '#' if !out.is_empty() && !prev_us => {
                out.push('_');
                prev_us = true;
            }
            _ => {}
        }
    }
    if out.is_empty() {
        return "item".to_owned();
    }
    if out.chars().next().is_some_and(|c: char| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    if matches!(
        out.as_str(),
        "fn" | "use" | "type" | "mod" | "pub" | "let" | "mut" | "ref" | "as" | "trait"
    ) {
        out.push('_');
    }
    out
}

fn sanitize_camel(raw: &str) -> String {
    let snake: String = sanitize_ident(raw);
    let mut out: String = String::with_capacity(snake.len());
    let mut upper: bool = false;
    for (i, c) in snake.chars().enumerate() {
        if c == '_' {
            upper = true;
            continue;
        }
        if i == 0 {
            out.push(c);
        } else if upper {
            out.push(c.to_ascii_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    out
}

fn pascal(raw: &str) -> String {
    let camel: String = sanitize_camel(raw);
    let mut chars: std::str::Chars<'_> = camel.chars();
    chars.next().map_or_else(
        || "Item".to_owned(),
        |c: char| format!("{}{}", c.to_ascii_uppercase(), chars.as_str()),
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::component::parse_component_manifest;

    const HELLO_COMPONENT: &str = r#"
        (component
          (core module $m
            (func (export "greet") (param i32 i32) (result i32)
              local.get 0
              local.get 1
              i32.add))
          (core instance $i (instantiate $m))
          (alias core export $i "greet" (core func $greet))
          (func $lifted (param "x" u32) (param "y" u32) (result u32)
            (canon lift (core func $greet)))
          (export "greet" (func $lifted)))
    "#;

    #[test]
    fn hello_component_lifts_to_typed_bindings() {
        let bytes: Vec<u8> = wat::parse_str(HELLO_COMPONENT).expect("wat");
        let manifest: ComponentManifest = parse_component_manifest(&bytes).expect("parse");
        let bindings: ComponentBindings = lift_component_manifest(&manifest, "hello-world");
        assert_eq!(bindings.world_name, "hello_world");
        assert!(bindings.rust_source.contains("pub trait ExportsHelloWorld"));
        assert!(bindings.rust_source.contains("fn greet(&self)"));
        assert!(
            bindings
                .ts_source
                .contains("export interface ExportsHelloWorld")
        );
        assert!(bindings.ts_source.contains("greet(): void"));
        assert!(bindings.wit_source.contains("world hello-world"));
        assert!(bindings.wit_source.contains("export greet: func();"));
    }

    #[test]
    fn sanitize_handles_kebab_and_reserved() {
        assert_eq!(sanitize_ident("hello-world"), "hello_world");
        assert_eq!(sanitize_ident("fn"), "fn_");
        assert_eq!(sanitize_ident("123abc"), "_123abc");
    }
}
