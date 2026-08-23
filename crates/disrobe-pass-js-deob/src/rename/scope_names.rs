use oxc_semantic::{ScopeId, ScopeTree};

pub(crate) fn conflicts_in_scope(scopes: &ScopeTree, owner: ScopeId, name: &str) -> bool {
    if scopes.has_binding(owner, name) {
        return true;
    }
    if scopes
        .ancestors(owner)
        .any(|scope: ScopeId| scopes.has_binding(scope, name))
    {
        return true;
    }
    scopes
        .iter_all_child_ids(owner)
        .any(|scope: ScopeId| scopes.has_binding(scope, name))
}

pub(crate) fn is_js_reserved(name: &str) -> bool {
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
