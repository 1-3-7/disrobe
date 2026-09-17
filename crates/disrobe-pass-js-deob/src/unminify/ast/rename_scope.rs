use indexmap::{IndexMap, IndexSet};
use oxc_ast::Visit;
use oxc_ast::ast::{FunctionBody, IdentifierReference, WithStatement};
use oxc_semantic::{
    AstNodes, NodeId, ReferenceId, ScopeId, ScopeTree, Semantic, SymbolId, SymbolTable,
};

pub(super) fn collect_reserved_names(semantic: &Semantic<'_>) -> IndexSet<String> {
    let scopes: &ScopeTree = semantic.scopes();
    let root: ScopeId = scopes.root_scope_id();
    let mut reserved: IndexSet<String> = IndexSet::new();
    for name in scopes.get_bindings(root).keys() {
        reserved.insert(name.as_str().to_owned());
    }
    for name in scopes.root_unresolved_references().keys() {
        reserved.insert(name.as_str().to_owned());
    }
    reserved
}

pub(super) struct RenameSafety<'a> {
    pub(super) symbols: &'a SymbolTable,
    pub(super) scopes: &'a ScopeTree,
    pub(super) nodes: &'a AstNodes<'a>,
}

impl RenameSafety<'_> {
    pub(super) fn rename_is_safe(
        &self,
        symbol_id: SymbolId,
        owner: ScopeId,
        new_name: &str,
        reserved: &IndexSet<String>,
        self_name: &str,
    ) -> bool {
        if new_name != self_name && reserved.contains(new_name) {
            return false;
        }
        if self.outer_scope_binds(owner, new_name) {
            return false;
        }
        if self.owner_already_binds_other(owner, new_name, symbol_id) {
            return false;
        }
        self.no_reference_is_captured(symbol_id, owner, new_name)
    }

    fn outer_scope_binds(&self, owner: ScopeId, name: &str) -> bool {
        self.scopes
            .ancestors(owner)
            .skip(1)
            .any(|sid: ScopeId| self.scopes.has_binding(sid, name))
    }

    fn owner_already_binds_other(&self, owner: ScopeId, name: &str, symbol_id: SymbolId) -> bool {
        self.scopes
            .get_binding(owner, name)
            .is_some_and(|existing: SymbolId| existing != symbol_id)
    }

    fn no_reference_is_captured(
        &self,
        symbol_id: SymbolId,
        owner: ScopeId,
        new_name: &str,
    ) -> bool {
        for &reference_id in self.symbols.get_resolved_reference_ids(symbol_id) {
            let node_id: NodeId = self.symbols.get_reference(reference_id).node_id();
            let ref_scope: ScopeId = self.nodes.get_node(node_id).scope_id();
            if self.reference_is_captured(ref_scope, owner, new_name) {
                return false;
            }
        }
        true
    }

    fn reference_is_captured(&self, ref_scope: ScopeId, owner: ScopeId, new_name: &str) -> bool {
        for scope_id in self.scopes.ancestors(ref_scope) {
            if scope_id == owner {
                return false;
            }
            if self.scopes.has_binding(scope_id, new_name) {
                return true;
            }
        }
        false
    }
}

pub(super) fn choose_name(
    safety: &RenameSafety<'_>,
    symbol_id: SymbolId,
    owner_scope: ScopeId,
    local_name: &str,
    preferred: &str,
    reserved: &IndexSet<String>,
    next_suffixes: &mut IndexMap<String, u32>,
) -> Option<String> {
    if safety.rename_is_safe(symbol_id, owner_scope, preferred, reserved, local_name) {
        return Some(preferred.to_owned());
    }
    let mut suffix: u32 = next_suffixes
        .get(preferred)
        .copied()
        .map_or(1, core::convert::identity);
    let attempts: usize = safety
        .symbols
        .len()
        .saturating_add(reserved.len())
        .saturating_add(1);
    for _ in 0..attempts {
        let candidate: String = format!("{preferred}_{suffix}");
        suffix = suffix.checked_add(1)?;
        if safety.rename_is_safe(symbol_id, owner_scope, &candidate, reserved, local_name) {
            next_suffixes.insert(preferred.to_owned(), suffix);
            return Some(candidate);
        }
    }
    None
}

pub(super) fn unresolved_identifier_is(
    identifier: &IdentifierReference<'_>,
    expected: &str,
    symbols: &SymbolTable,
) -> bool {
    if identifier.name.as_str() != expected {
        return false;
    }
    let Some(reference_id): Option<ReferenceId> = identifier.reference_id.get() else {
        return false;
    };
    symbols.get_reference(reference_id).symbol_id().is_none()
}

pub(super) fn body_has_dynamic_scope(body: &FunctionBody<'_>) -> bool {
    let mut probe: DynamicScopeProbe = DynamicScopeProbe { found: false };
    for statement in &body.statements {
        probe.visit_statement(statement);
    }
    probe.found
}

struct DynamicScopeProbe {
    found: bool,
}

impl<'a> Visit<'a> for DynamicScopeProbe {
    fn visit_identifier_reference(&mut self, identifier: &IdentifierReference<'a>) {
        if identifier.name == "eval" {
            self.found = true;
        }
    }

    fn visit_with_statement(&mut self, _statement: &WithStatement<'a>) {
        self.found = true;
    }
}

pub(super) fn is_reserved_binding_name(name: &str) -> bool {
    matches!(
        name,
        "arguments"
            | "as"
            | "async"
            | "await"
            | "break"
            | "case"
            | "catch"
            | "class"
            | "const"
            | "continue"
            | "debugger"
            | "default"
            | "delete"
            | "do"
            | "else"
            | "enum"
            | "eval"
            | "export"
            | "extends"
            | "false"
            | "finally"
            | "for"
            | "from"
            | "function"
            | "if"
            | "implements"
            | "import"
            | "in"
            | "instanceof"
            | "interface"
            | "let"
            | "new"
            | "null"
            | "of"
            | "package"
            | "private"
            | "protected"
            | "public"
            | "return"
            | "static"
            | "super"
            | "switch"
            | "this"
            | "throw"
            | "true"
            | "try"
            | "typeof"
            | "undefined"
            | "var"
            | "void"
            | "while"
            | "with"
            | "yield"
    )
}
