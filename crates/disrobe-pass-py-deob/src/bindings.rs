use std::collections::{BTreeMap, BTreeSet};

use ruff_python_ast::visitor::{
    Visitor, walk_except_handler, walk_expr, walk_parameter, walk_pattern, walk_stmt,
    walk_type_param,
};
use ruff_python_ast::{
    ExceptHandler, Expr, ExprContext, Identifier, Parameter, Pattern, Stmt, TypeParam,
};

#[derive(Default)]
struct Bindings {
    counts: BTreeMap<String, usize>,
}

impl Bindings {
    fn bind(&mut self, name: &str) {
        *self.counts.entry(name.to_owned()).or_default() += 1;
    }
}

impl<'a> Visitor<'a> for Bindings {
    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        match stmt {
            Stmt::FunctionDef(function) => self.bind(function.name.as_str()),
            Stmt::ClassDef(class) => self.bind(class.name.as_str()),
            Stmt::Import(import) => {
                for alias in &import.names {
                    let bound: &str = alias.asname.as_ref().map_or_else(
                        || alias.name.as_str().split('.').next().unwrap_or_default(),
                        Identifier::as_str,
                    );
                    self.bind(bound);
                }
            }
            Stmt::ImportFrom(import) => {
                for alias in &import.names {
                    self.bind(
                        alias
                            .asname
                            .as_ref()
                            .map_or_else(|| alias.name.as_str(), Identifier::as_str),
                    );
                }
            }
            Stmt::Global(global) => {
                for name in &global.names {
                    self.bind(name.as_str());
                }
            }
            Stmt::Nonlocal(nonlocal) => {
                for name in &nonlocal.names {
                    self.bind(name.as_str());
                }
            }
            _ => {}
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &'a Expr) {
        if let Expr::Name(name) = expr
            && matches!(name.ctx, ExprContext::Store | ExprContext::Del)
        {
            self.bind(name.id.as_str());
        }
        walk_expr(self, expr);
    }

    fn visit_except_handler(&mut self, handler: &'a ExceptHandler) {
        let ExceptHandler::ExceptHandler(clause) = handler;
        if let Some(name) = &clause.name {
            self.bind(name.as_str());
        }
        walk_except_handler(self, handler);
    }

    fn visit_parameter(&mut self, parameter: &'a Parameter) {
        self.bind(parameter.name.as_str());
        walk_parameter(self, parameter);
    }

    fn visit_pattern(&mut self, pattern: &'a Pattern) {
        match pattern {
            Pattern::MatchAs(capture) => {
                if let Some(name) = &capture.name {
                    self.bind(name.as_str());
                }
            }
            Pattern::MatchStar(star) => {
                if let Some(name) = &star.name {
                    self.bind(name.as_str());
                }
            }
            Pattern::MatchMapping(mapping) => {
                if let Some(rest) = &mapping.rest {
                    self.bind(rest.as_str());
                }
            }
            _ => {}
        }
        walk_pattern(self, pattern);
    }

    fn visit_type_param(&mut self, type_param: &'a TypeParam) {
        self.bind(type_param.name().as_str());
        walk_type_param(self, type_param);
    }
}

pub(crate) fn binding_counts(body: &[Stmt]) -> BTreeMap<String, usize> {
    let mut collector: Bindings = Bindings::default();
    for stmt in body {
        collector.visit_stmt(stmt);
    }
    collector.counts
}

pub(crate) fn bindings(body: &[Stmt]) -> BTreeSet<String> {
    binding_counts(body).into_keys().collect()
}
