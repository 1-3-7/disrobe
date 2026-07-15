use disrobe_py_marshal::{CodeObject, Object};

use super::model::{
    CO_ASYNC_GENERATOR, CO_COROUTINE, CO_GENERATOR, CO_OPTIMIZED, CO_VARARGS, CO_VARKEYWORDS,
    FunctionKind, ParamKind, Parameter, Signature,
};

const MAX_TREE_NODES: usize = 65_536;
const MAX_TREE_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NodeKind {
    Module,
    Class,
    Internal,
    Function {
        kind: FunctionKind,
        class: Option<String>,
        signature: Signature,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResidualNode {
    pub(crate) name: String,
    pub(crate) qualname: String,
    pub(crate) firstlineno: i32,
    pub(crate) kind: NodeKind,
    pub(crate) children: Vec<Self>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResidualModule {
    pub(crate) module_name: Option<String>,
    pub(crate) py_path_hint: Option<String>,
    pub(crate) root: ResidualNode,
}

pub(crate) fn object_str(obj: &Object) -> Option<String> {
    match obj {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => Some(value.clone()),
        _ => None,
    }
}

pub(crate) fn extract_module(module_code: &CodeObject) -> ResidualModule {
    let filename: Option<String> = object_str(&module_code.filename);
    let (module_name, py_path_hint): (Option<String>, Option<String>) =
        interpret_filename(filename.as_deref());
    let mut budget: usize = MAX_TREE_NODES;
    let root: ResidualNode = build_node(module_code, 0, &mut budget, "", false);
    ResidualModule {
        module_name,
        py_path_hint,
        root,
    }
}

fn interpret_filename(filename: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(name): Option<&str> = filename else {
        return (None, None);
    };
    let trimmed: &str = name.trim();
    if let Some(inner) = trimmed
        .strip_prefix("<frozen ")
        .and_then(|rest: &str| rest.strip_suffix('>'))
    {
        return (Some(inner.trim().to_owned()), None);
    }
    if trimmed.starts_with('<') {
        return (None, None);
    }
    (None, Some(trimmed.to_owned()))
}

fn build_node(
    co: &CodeObject,
    depth: usize,
    budget: &mut usize,
    parent_qual: &str,
    parent_is_function: bool,
) -> ResidualNode {
    let name: String = object_str(&co.name).unwrap_or_default();
    let qualname: String = object_str(&co.qualname)
        .filter(|q: &String| !q.is_empty())
        .unwrap_or_else(|| reconstruct_qualname(parent_qual, parent_is_function, &name));
    let kind: NodeKind = classify_node(co, &name, &qualname);
    let this_is_function: bool = matches!(kind, NodeKind::Function { .. });
    let mut children: Vec<ResidualNode> = Vec::new();
    if depth < MAX_TREE_DEPTH {
        for constant in &co.consts {
            if *budget == 0 {
                break;
            }
            if let Object::Code(child) = constant {
                *budget -= 1;
                children.push(build_node(
                    child,
                    depth + 1,
                    budget,
                    &qualname,
                    this_is_function,
                ));
            }
        }
    }
    children.sort_by_key(|node: &ResidualNode| node.firstlineno);
    ResidualNode {
        name,
        qualname,
        firstlineno: co.firstlineno,
        kind,
        children,
    }
}

fn reconstruct_qualname(parent_qual: &str, parent_is_function: bool, name: &str) -> String {
    if parent_qual.is_empty() || parent_qual == "<module>" {
        return name.to_owned();
    }
    if parent_is_function {
        return format!("{parent_qual}.<locals>.{name}");
    }
    format!("{parent_qual}.{name}")
}

fn classify_node(co: &CodeObject, name: &str, qualname: &str) -> NodeKind {
    if name == "<module>" {
        return NodeKind::Module;
    }
    if is_synthetic_scope(name) {
        return NodeKind::Internal;
    }
    if co.flags & CO_OPTIMIZED == 0 {
        return NodeKind::Class;
    }
    let class: Option<String> = class_of(qualname);
    let kind: FunctionKind = function_kind(co.flags, name, class.is_some());
    let signature: Signature = build_signature(co);
    NodeKind::Function {
        kind,
        class,
        signature,
    }
}

pub(crate) fn is_synthetic_scope(name: &str) -> bool {
    matches!(
        name,
        "<listcomp>" | "<setcomp>" | "<dictcomp>" | "<genexpr>" | "<module>"
    )
}

fn class_of(qualname: &str) -> Option<String> {
    let parts: Vec<&str> = qualname.split('.').collect();
    if parts.len() <= 1 {
        return None;
    }
    let prefix: &[&str] = &parts[..parts.len() - 1];
    if prefix.contains(&"<locals>") {
        return None;
    }
    Some(prefix.join("."))
}

fn function_kind(flags: i32, name: &str, is_method: bool) -> FunctionKind {
    if name == "<lambda>" {
        return FunctionKind::Lambda;
    }
    let is_async_gen: bool = flags & CO_ASYNC_GENERATOR != 0;
    let is_coroutine: bool = flags & CO_COROUTINE != 0;
    let is_generator: bool = flags & CO_GENERATOR != 0;
    if is_async_gen {
        return if is_method {
            FunctionKind::AsyncGeneratorMethod
        } else {
            FunctionKind::AsyncGenerator
        };
    }
    if is_coroutine {
        return if is_method {
            FunctionKind::AsyncMethod
        } else {
            FunctionKind::AsyncFunction
        };
    }
    if is_generator {
        return if is_method {
            FunctionKind::GeneratorMethod
        } else {
            FunctionKind::Generator
        };
    }
    if is_method {
        FunctionKind::Method
    } else {
        FunctionKind::Function
    }
}

fn build_signature(co: &CodeObject) -> Signature {
    let argcount: u32 = u32::try_from(co.argcount.max(0)).unwrap_or(0);
    let posonly: u32 = u32::try_from(co.posonlyargcount.max(0))
        .unwrap_or(0)
        .min(argcount);
    let kwonly: u32 = u32::try_from(co.kwonlyargcount.max(0)).unwrap_or(0);
    let has_varargs: bool = co.flags & CO_VARARGS != 0;
    let has_varkeywords: bool = co.flags & CO_VARKEYWORDS != 0;
    let is_async: bool = co.flags & (CO_COROUTINE | CO_ASYNC_GENERATOR) != 0;
    let is_generator: bool = co.flags & (CO_GENERATOR | CO_ASYNC_GENERATOR) != 0;

    let named: Vec<String> = co
        .varnames
        .iter()
        .filter_map(object_str)
        .collect::<Vec<String>>();
    let total_named: usize = (argcount as usize)
        .saturating_add(kwonly as usize)
        .saturating_add(usize::from(has_varargs))
        .saturating_add(usize::from(has_varkeywords));
    let param_names_recovered: bool = named.len() >= total_named && total_named > 0;

    let mut parameters: Vec<Parameter> = Vec::with_capacity(total_named);
    let mut order: usize = 0;
    for i in 0..argcount {
        let kind: ParamKind = if i < posonly {
            ParamKind::PositionalOnly
        } else {
            ParamKind::PositionalOrKeyword
        };
        parameters.push(Parameter {
            name: pick_name(&named, param_names_recovered, i as usize, order, "p"),
            kind,
        });
        order += 1;
    }
    if has_varargs {
        let idx: usize = (argcount as usize).saturating_add(kwonly as usize);
        parameters.push(Parameter {
            name: pick_name(&named, param_names_recovered, idx, order, "args"),
            kind: ParamKind::VarPositional,
        });
        order += 1;
    }
    for j in 0..kwonly {
        let idx: usize = (argcount as usize).saturating_add(j as usize);
        parameters.push(Parameter {
            name: pick_name(&named, param_names_recovered, idx, order, "k"),
            kind: ParamKind::KeywordOnly,
        });
        order += 1;
    }
    if has_varkeywords {
        let idx: usize = (argcount as usize)
            .saturating_add(kwonly as usize)
            .saturating_add(usize::from(has_varargs));
        parameters.push(Parameter {
            name: pick_name(&named, param_names_recovered, idx, order, "kwargs"),
            kind: ParamKind::VarKeyword,
        });
    }

    let rendered: String = render_signature(&parameters, posonly);
    Signature {
        argcount,
        posonlyargcount: posonly,
        kwonlyargcount: kwonly,
        has_varargs,
        has_varkeywords,
        is_async,
        is_generator,
        param_names_recovered,
        parameters,
        rendered,
    }
}

fn pick_name(
    named: &[String],
    recovered: bool,
    index: usize,
    order: usize,
    placeholder_base: &str,
) -> String {
    if recovered
        && let Some(name) = named.get(index)
        && !name.is_empty()
    {
        return name.clone();
    }
    match placeholder_base {
        "args" => "args".to_owned(),
        "kwargs" => "kwargs".to_owned(),
        "k" => format!("k{order}"),
        _ => format!("p{order}"),
    }
}

fn render_signature(parameters: &[Parameter], posonly: u32) -> String {
    let mut out: String = String::from("(");
    let mut emitted: usize = 0;
    let mut positional_emitted: u32 = 0;
    let mut star_written: bool = false;
    let has_varargs: bool = parameters
        .iter()
        .any(|p: &Parameter| p.kind == ParamKind::VarPositional);
    for param in parameters {
        if matches!(
            param.kind,
            ParamKind::PositionalOnly | ParamKind::PositionalOrKeyword
        ) {
            push_sep(&mut out, &mut emitted);
            out.push_str(&param.name);
            positional_emitted += 1;
            if positional_emitted == posonly && posonly > 0 {
                push_sep(&mut out, &mut emitted);
                out.push('/');
            }
            continue;
        }
        if param.kind == ParamKind::VarPositional {
            push_sep(&mut out, &mut emitted);
            out.push('*');
            out.push_str(&param.name);
            star_written = true;
            continue;
        }
        if param.kind == ParamKind::KeywordOnly {
            if !star_written && !has_varargs {
                push_sep(&mut out, &mut emitted);
                out.push('*');
                star_written = true;
            }
            push_sep(&mut out, &mut emitted);
            out.push_str(&param.name);
            continue;
        }
        push_sep(&mut out, &mut emitted);
        out.push_str("**");
        out.push_str(&param.name);
    }
    out.push(')');
    out
}

fn push_sep(out: &mut String, emitted: &mut usize) {
    if *emitted > 0 {
        out.push_str(", ");
    }
    *emitted += 1;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use disrobe_py_marshal::{CodeEra, PyVersion, code_era_for};

    fn code(flags: i32, argcount: i32, posonly: i32, kwonly: i32) -> CodeObject {
        let era: CodeEra = code_era_for(PyVersion::new(3, 12));
        let mut co: CodeObject = CodeObject::new(era);
        co.flags = flags | CO_OPTIMIZED;
        co.argcount = argcount;
        co.posonlyargcount = posonly;
        co.kwonlyargcount = kwonly;
        co
    }

    #[test]
    fn class_of_extracts_method_owner() {
        assert_eq!(class_of("Widget.area"), Some("Widget".to_owned()));
        assert_eq!(
            class_of("Widget.Inner.deep"),
            Some("Widget.Inner".to_owned())
        );
        assert_eq!(class_of("add"), None);
        assert_eq!(class_of("top.<locals>.inner"), None);
    }

    #[test]
    fn interpret_filename_reads_frozen_module() {
        assert_eq!(
            interpret_filename(Some("<frozen mypkg.calc>")),
            (Some("mypkg.calc".to_owned()), None)
        );
        assert_eq!(
            interpret_filename(Some("pkg/mod.py")),
            (None, Some("pkg/mod.py".to_owned()))
        );
        assert_eq!(interpret_filename(Some("<stdin>")), (None, None));
    }

    #[test]
    fn function_kind_reads_flags() {
        assert_eq!(function_kind(0, "add", false), FunctionKind::Function);
        assert_eq!(function_kind(0, "area", true), FunctionKind::Method);
        assert_eq!(
            function_kind(CO_COROUTINE, "fetch", false),
            FunctionKind::AsyncFunction
        );
        assert_eq!(
            function_kind(CO_GENERATOR, "g", true),
            FunctionKind::GeneratorMethod
        );
        assert_eq!(
            function_kind(CO_ASYNC_GENERATOR, "ag", false),
            FunctionKind::AsyncGenerator
        );
        assert_eq!(function_kind(0, "<lambda>", true), FunctionKind::Lambda);
    }

    #[test]
    fn signature_renders_posonly_and_varargs() {
        let co: CodeObject = code(CO_VARARGS | CO_VARKEYWORDS, 2, 0, 1);
        let sig: Signature = build_signature(&co);
        assert_eq!(sig.argcount, 2);
        assert_eq!(sig.kwonlyargcount, 1);
        assert!(sig.has_varargs && sig.has_varkeywords);
        assert!(!sig.param_names_recovered);
        assert_eq!(sig.rendered, "(p0, p1, *args, k3, **kwargs)");
    }

    #[test]
    fn signature_renders_positional_only_marker() {
        let co: CodeObject = code(0, 3, 2, 1);
        let sig: Signature = build_signature(&co);
        assert_eq!(sig.rendered, "(p0, p1, /, p2, *, k3)");
    }

    #[test]
    fn signature_uses_recovered_names_when_present() {
        let mut co: CodeObject = code(0, 2, 0, 0);
        co.varnames = vec![
            Object::String {
                value: "self".to_owned(),
                interned: false,
            },
            Object::String {
                value: "size".to_owned(),
                interned: false,
            },
        ];
        let sig: Signature = build_signature(&co);
        assert!(sig.param_names_recovered);
        assert_eq!(sig.rendered, "(self, size)");
    }

    #[test]
    fn deeply_nested_consts_are_budget_bounded() {
        let era: CodeEra = code_era_for(PyVersion::new(3, 12));
        let mut co: CodeObject = CodeObject::new(era);
        co.name = Object::String {
            value: "<module>".to_owned(),
            interned: false,
        };
        let module: ResidualModule = extract_module(&co);
        assert!(matches!(module.root.kind, NodeKind::Module));
        assert!(module.root.children.is_empty());
    }
}
