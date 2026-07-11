mod ast_facts;
mod input_facts;
mod opcontent;
mod relower;
mod repair;

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::VecDeque;

use disrobe_py_marshal::{CodeObject, Object};

use crate::ast::node::{Alias, AstModule, MatchCase, Stmt};
use crate::bytecode::version::PyVersion as DecompileVersion;

pub fn verify_and_repair(module: &mut AstModule, code: &CodeObject, version: &DecompileVersion) {
    if version.is_pre_311() {
        return;
    }
    let module_imports: BTreeSet<String> = collect_module_imports(&module.body);
    repair_scope(&mut module.body, code, version, &module_imports);
}

#[must_use]
fn collect_module_imports(body: &[Stmt]) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    for stmt in body {
        match stmt {
            Stmt::Import(aliases) => {
                for alias in aliases {
                    names.insert(import_bound_name(alias));
                }
            }
            Stmt::ImportFrom { names: aliases, .. } => {
                for alias in aliases {
                    if alias.name != "*" {
                        names.insert(alias.asname.clone().unwrap_or_else(|| alias.name.clone()));
                    }
                }
            }
            _ => {}
        }
    }
    names
}

#[must_use]
fn import_bound_name(alias: &Alias) -> String {
    if let Some(asname) = &alias.asname {
        return asname.clone();
    }
    alias
        .name
        .split('.')
        .next()
        .unwrap_or(alias.name.as_str())
        .to_owned()
}

fn repair_scope(
    body: &mut Vec<Stmt>,
    code: &CodeObject,
    version: &DecompileVersion,
    module_imports: &BTreeSet<String>,
) {
    if repair::has_repair_candidate(body) {
        let facts: input_facts::InputFacts = input_facts::extract(code, version);
        let taken: Vec<Stmt> = std::mem::take(body);
        *body = repair::repair_body(taken, &facts);
    }
    if opcontent_enabled(version)
        && let Some(reordered) = opcontent::accept_reordering(body, code, version, module_imports)
    {
        *body = reordered;
    }
    let mut picker: ChildPicker<'_> = ChildPicker::new(code);
    descend(body, &mut picker, version, module_imports);
}

#[must_use]
fn opcontent_enabled(version: &DecompileVersion) -> bool {
    version.major() == 3 && version.minor() == 14
}

fn descend(
    body: &mut [Stmt],
    picker: &mut ChildPicker<'_>,
    version: &DecompileVersion,
    module_imports: &BTreeSet<String>,
) {
    for stmt in body.iter_mut() {
        match stmt {
            Stmt::FunctionDef { name, body, .. } | Stmt::ClassDef { name, body, .. } => {
                if let Some(child) = picker.take(name) {
                    repair_scope(body, child, version, module_imports);
                }
            }
            Stmt::If { body, orelse, .. }
            | Stmt::For { body, orelse, .. }
            | Stmt::While { body, orelse, .. } => {
                descend(body, picker, version, module_imports);
                descend(orelse, picker, version, module_imports);
            }
            Stmt::With { body, .. } => descend(body, picker, version, module_imports),
            Stmt::Try {
                body,
                handlers,
                orelse,
                finalbody,
                ..
            }
            | Stmt::TryStar {
                body,
                handlers,
                orelse,
                finalbody,
                ..
            } => {
                descend(body, picker, version, module_imports);
                for handler in handlers.iter_mut() {
                    descend(&mut handler.body, picker, version, module_imports);
                }
                descend(orelse, picker, version, module_imports);
                descend(finalbody, picker, version, module_imports);
            }
            Stmt::Match { cases, .. } => {
                for case in cases.iter_mut() {
                    let MatchCase { body, .. } = case;
                    descend(body, picker, version, module_imports);
                }
            }
            _ => {}
        }
    }
}

#[derive(Debug)]
struct ChildPicker<'a> {
    by_name: BTreeMap<String, VecDeque<&'a CodeObject>>,
}

impl<'a> ChildPicker<'a> {
    #[must_use]
    fn new(code: &'a CodeObject) -> Self {
        let mut by_name: BTreeMap<String, VecDeque<&'a CodeObject>> = BTreeMap::new();
        for konst in &code.consts {
            let Object::Code(boxed) = konst else {
                continue;
            };
            let child: &CodeObject = boxed.as_ref();
            by_name
                .entry(code_short_name(child))
                .or_default()
                .push_back(child);
        }
        Self { by_name }
    }

    fn take(&mut self, name: &str) -> Option<&'a CodeObject> {
        self.by_name.get_mut(name)?.pop_front()
    }
}

#[must_use]
fn code_short_name(code: &CodeObject) -> String {
    match &code.name {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => value.clone(),
        _ => String::new(),
    }
}
