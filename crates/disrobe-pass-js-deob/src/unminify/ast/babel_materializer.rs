use std::collections::{BTreeMap, BTreeSet};

use oxc_ast::Visit;
use oxc_ast::ast::{BindingIdentifier, Function, Program};
use oxc_span::Span;

fn is_materializing_helper_name(name: &str) -> bool {
    matches!(
        name,
        "_toConsumableArray"
            | "toConsumableArray"
            | "_arrayWithoutHoles"
            | "arrayWithoutHoles"
            | "_arrayLikeToArray"
            | "arrayLikeToArray"
            | "_spread"
    )
}

fn is_babel_materializer(body: &str, name: &str) -> bool {
    let compact: String = body
        .chars()
        .filter(|character: &char| !character.is_whitespace())
        .collect();
    if !compact.starts_with(&format!("function{name}(")) {
        return false;
    }
    let spread_chain: bool =
        compact.contains("_arrayWithoutHoles(") || compact.contains("arrayWithoutHoles(");
    let like_to_array: bool =
        compact.contains("_arrayLikeToArray(") || compact.contains("arrayLikeToArray(");
    let from_call: bool = compact.contains("Array.from(");
    let index_copy: bool = compact.contains("newArray(") && compact.contains("Array.isArray(");
    spread_chain || like_to_array || from_call || index_copy
}

#[derive(Debug, Default)]
struct BindingCollector {
    counts: BTreeMap<String, usize>,
    array_rebound: bool,
}

impl<'a> Visit<'a> for BindingCollector {
    fn visit_binding_identifier(&mut self, identifier: &BindingIdentifier<'a>) {
        let name: &str = identifier.name.as_str();
        if name == "Array" {
            self.array_rebound = true;
        }
        if is_materializing_helper_name(name) {
            let count: &mut usize = self.counts.entry(name.to_owned()).or_default();
            *count = count.saturating_add(1);
        }
    }
}

struct DefinitionCollector<'s> {
    source: &'s str,
    binding_counts: &'s BTreeMap<String, usize>,
    valid: BTreeSet<String>,
    definitions: Vec<Span>,
}

impl<'a> Visit<'a> for DefinitionCollector<'_> {
    fn visit_function(&mut self, func: &Function<'a>, flags: oxc::syntax::scope::ScopeFlags) {
        if let Some(id) = &func.id {
            let name: &str = id.name.as_str();
            if is_materializing_helper_name(name)
                && self.binding_counts.get(name).copied() == Some(1)
                && is_babel_materializer(func.span.source_text(self.source), name)
            {
                self.valid.insert(name.to_owned());
                self.definitions.push(func.span);
            }
        }
        oxc_ast::visit::walk::walk_function(self, func, flags);
    }
}

#[derive(Debug, Default)]
pub(super) struct MaterializerFacts {
    valid: BTreeSet<String>,
    array_rebound: bool,
    definitions: Vec<Span>,
}

impl MaterializerFacts {
    pub(super) fn collect(source: &str, program: &Program<'_>) -> Self {
        let mut bindings: BindingCollector = BindingCollector::default();
        bindings.visit_program(program);
        let mut definitions: DefinitionCollector<'_> = DefinitionCollector {
            source,
            binding_counts: &bindings.counts,
            valid: BTreeSet::new(),
            definitions: Vec::new(),
        };
        definitions.visit_program(program);
        Self {
            valid: definitions.valid,
            array_rebound: bindings.array_rebound,
            definitions: definitions.definitions,
        }
    }

    pub(super) const fn scope(&self) -> MaterializerScope<'_> {
        MaterializerScope {
            valid: &self.valid,
            array_rebound: self.array_rebound,
        }
    }

    pub(super) fn is_verified(&self, name: &str) -> bool {
        self.valid.contains(name)
    }

    pub(super) fn encloses(&self, offset: u32) -> bool {
        self.definitions
            .iter()
            .any(|span: &Span| span.start <= offset && offset < span.end)
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct MaterializerScope<'s> {
    pub(super) valid: &'s BTreeSet<String>,
    pub(super) array_rebound: bool,
}
