use std::collections::BTreeSet;

use syn::visit::Visit;
use syn::{
    Arm, Attribute, Block, Expr, FieldValue, Ident, ImplItemConst, ImplItemFn, ItemConst, ItemFn,
    ItemStatic, Local, Macro, Member, Stmt, TraitItemConst, TraitItemFn, Type,
};

use super::prepare::tokens_contain;

#[derive(Debug, Clone, Copy)]
pub(super) enum Node<'a> {
    Expr(&'a Expr),
    Stmt(&'a Stmt),
    Local(&'a Local),
    Block(&'a Block),
    FieldValue(&'a FieldValue),
    Arm(&'a Arm),
    Item(&'a Ident),
    Fn(&'a Ident, &'a Block),
    Type,
    Macro(&'a Macro),
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Target<'t> {
    Paths(&'t BTreeSet<String>),
    Path(&'t str),
    Field(&'t str),
    Call(&'t str),
}

#[derive(Debug, Clone)]
pub(super) struct Occurrence<'a> {
    pub(super) name: String,
    pub(super) file: usize,
    pub(super) stack: Vec<Node<'a>>,
}

pub(super) struct Finder<'a, 't> {
    target: Target<'t>,
    file: usize,
    stack: Vec<Node<'a>>,
    found: Vec<Occurrence<'a>>,
}

impl<'a, 't> Finder<'a, 't> {
    pub(super) const fn new(target: Target<'t>, file: usize, prefix: Vec<Node<'a>>) -> Self {
        Self {
            target,
            file,
            stack: prefix,
            found: Vec::new(),
        }
    }

    pub(super) const fn set_file(&mut self, file: usize) {
        self.file = file;
    }

    pub(super) fn finish(self) -> Vec<Occurrence<'a>> {
        self.found
    }

    fn wanted(&self, name: &str) -> bool {
        match self.target {
            Target::Paths(names) => names.contains(name),
            Target::Path(wanted) | Target::Field(wanted) | Target::Call(wanted) => wanted == name,
        }
    }

    fn matched(&self, expr: &Expr) -> Option<String> {
        let name: String = match (self.target, expr) {
            (Target::Paths(_) | Target::Path(_), Expr::Path(path)) => {
                path.path.segments.last()?.ident.to_string()
            }
            (Target::Field(_), Expr::Field(field)) => match &field.member {
                Member::Named(ident) => ident.to_string(),
                Member::Unnamed(_) => return None,
            },
            (Target::Call(_), Expr::Call(call)) => match &*call.func {
                Expr::Path(path) => path.path.segments.last()?.ident.to_string(),
                _ => return None,
            },
            (Target::Call(_), Expr::MethodCall(call)) => call.method.to_string(),
            _ => return None,
        };
        self.wanted(&name).then_some(name)
    }

    fn record(&mut self, name: String) {
        self.found.push(Occurrence {
            name,
            file: self.file,
            stack: self.stack.clone(),
        });
    }

    fn scoped(&mut self, node: Node<'a>, visit: impl FnOnce(&mut Self)) {
        self.stack.push(node);
        visit(self);
        self.stack.pop();
    }
}

impl<'a> Visit<'a> for Finder<'a, '_> {
    fn visit_attribute(&mut self, _: &'a Attribute) {}

    fn visit_expr(&mut self, node: &'a Expr) {
        self.scoped(Node::Expr(node), |finder: &mut Self| {
            if let Some(name) = finder.matched(node) {
                finder.record(name);
            }
            syn::visit::visit_expr(finder, node);
        });
    }

    fn visit_stmt(&mut self, node: &'a Stmt) {
        self.scoped(Node::Stmt(node), |finder: &mut Self| {
            syn::visit::visit_stmt(finder, node);
        });
    }

    fn visit_local(&mut self, node: &'a Local) {
        self.scoped(Node::Local(node), |finder: &mut Self| {
            syn::visit::visit_local(finder, node);
        });
    }

    fn visit_block(&mut self, node: &'a Block) {
        self.scoped(Node::Block(node), |finder: &mut Self| {
            syn::visit::visit_block(finder, node);
        });
    }

    fn visit_field_value(&mut self, node: &'a FieldValue) {
        self.scoped(Node::FieldValue(node), |finder: &mut Self| {
            syn::visit::visit_field_value(finder, node);
        });
    }

    fn visit_arm(&mut self, node: &'a Arm) {
        self.scoped(Node::Arm(node), |finder: &mut Self| {
            syn::visit::visit_arm(finder, node);
        });
    }

    fn visit_item_fn(&mut self, node: &'a ItemFn) {
        self.scoped(
            Node::Fn(&node.sig.ident, &node.block),
            |finder: &mut Self| syn::visit::visit_item_fn(finder, node),
        );
    }

    fn visit_impl_item_fn(&mut self, node: &'a ImplItemFn) {
        self.scoped(
            Node::Fn(&node.sig.ident, &node.block),
            |finder: &mut Self| syn::visit::visit_impl_item_fn(finder, node),
        );
    }

    fn visit_trait_item_fn(&mut self, node: &'a TraitItemFn) {
        match &node.default {
            Some(block) => self.scoped(Node::Fn(&node.sig.ident, block), |finder: &mut Self| {
                syn::visit::visit_trait_item_fn(finder, node);
            }),
            None => syn::visit::visit_trait_item_fn(self, node),
        }
    }

    fn visit_item_const(&mut self, node: &'a ItemConst) {
        self.scoped(Node::Item(&node.ident), |finder: &mut Self| {
            syn::visit::visit_item_const(finder, node);
        });
    }

    fn visit_impl_item_const(&mut self, node: &'a ImplItemConst) {
        self.scoped(Node::Item(&node.ident), |finder: &mut Self| {
            syn::visit::visit_impl_item_const(finder, node);
        });
    }

    fn visit_trait_item_const(&mut self, node: &'a TraitItemConst) {
        self.scoped(Node::Item(&node.ident), |finder: &mut Self| {
            syn::visit::visit_trait_item_const(finder, node);
        });
    }

    fn visit_item_static(&mut self, node: &'a ItemStatic) {
        self.scoped(Node::Item(&node.ident), |finder: &mut Self| {
            syn::visit::visit_item_static(finder, node);
        });
    }

    fn visit_type(&mut self, node: &'a Type) {
        self.scoped(Node::Type, |finder: &mut Self| {
            syn::visit::visit_type(finder, node);
        });
    }

    fn visit_macro(&mut self, node: &'a Macro) {
        let hit: Option<String> = match self.target {
            Target::Paths(names) => names
                .iter()
                .find(|name: &&String| tokens_contain(&node.tokens, name, false))
                .cloned(),
            Target::Path(name) | Target::Call(name) => {
                tokens_contain(&node.tokens, name, false).then(|| name.to_owned())
            }
            Target::Field(name) => {
                tokens_contain(&node.tokens, name, true).then(|| name.to_owned())
            }
        };
        if let Some(name) = hit {
            self.scoped(Node::Macro(node), |finder: &mut Self| finder.record(name));
        }
    }
}
