use indexmap::{IndexMap, IndexSet};
use oxc_allocator::Allocator;
use oxc_ast::AstKind;
use oxc_ast::ast::{
    ArrayExpression, BindingPatternKind, CallExpression, Expression, FormalParameter, FunctionBody,
    ObjectExpression, ObjectPropertyKind, PropertyKey, PropertyKind, Statement,
};
use oxc_parser::Parser;
use oxc_semantic::{
    AstNodes, ReferenceId, ScopeId, ScopeTree, Semantic, SemanticBuilder, SymbolId, SymbolTable,
};
use oxc_span::SourceType;

use super::import_rename::push_reference_edits;
use super::rename_scope::{
    RenameSafety, body_has_dynamic_scope, choose_name, collect_reserved_names,
    unresolved_identifier_is,
};
use super::require_alias::{derive_module_names, is_minified_local};
use super::{Edit, RuleOutcome, edit_overlaps_comments};

const MAX_REGISTRATIONS: usize = 4_096;
const MAX_DEPENDENCY_SETTER_PAIRS: usize = 4_096;
const MAX_GENERATED_EDITS: usize = 65_536;

#[derive(Debug, Clone, Default)]
pub(super) struct SystemRegisterParamStats {
    pub(super) parameters_renamed: usize,
}

struct Registration<'a> {
    dependencies: Vec<&'a str>,
    setters: &'a ArrayExpression<'a>,
}

enum RegistrationEditResult {
    Invalid,
    Exhausted,
    Ready {
        edits: Vec<Edit>,
        names: Vec<String>,
        renamed: usize,
        suffixes: IndexMap<String, u32>,
    },
}

pub(super) fn recover(source: &str) -> (RuleOutcome, SystemRegisterParamStats) {
    let allocator: Allocator = Allocator::default();
    let Ok(source_type): Result<SourceType, _> = SourceType::from_path("input.js") else {
        return (RuleOutcome::empty(), SystemRegisterParamStats::default());
    };
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), SystemRegisterParamStats::default());
    }
    let semantic_ret: oxc_semantic::SemanticBuilderReturn<'_> = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .with_scope_tree_child_ids(true)
        .build(&parsed.program);
    if !semantic_ret.errors.is_empty() {
        return (RuleOutcome::empty(), SystemRegisterParamStats::default());
    }
    let semantic: Semantic<'_> = semantic_ret.semantic;
    let symbols: &SymbolTable = semantic.symbols();
    let scopes: &ScopeTree = semantic.scopes();
    let nodes: &AstNodes<'_> = semantic.nodes();
    let safety: RenameSafety<'_> = RenameSafety {
        symbols,
        scopes,
        nodes,
    };
    let mut reserved: IndexSet<String> = collect_reserved_names(&semantic);
    let mut next_suffixes: IndexMap<String, u32> = IndexMap::new();
    let mut edits: Vec<Edit> = Vec::new();
    let mut registrations: usize = 0;
    let mut pairs: usize = 0;
    let mut renamed: usize = 0;

    for node in nodes.iter() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        if !is_system_register_call(call, symbols, source) {
            continue;
        }
        registrations = registrations.saturating_add(1);
        if registrations > MAX_REGISTRATIONS {
            return (RuleOutcome::empty(), SystemRegisterParamStats::default());
        }
        let Some(dependency_count): Option<usize> = dependency_count(call) else {
            continue;
        };
        pairs = pairs.saturating_add(dependency_count);
        if pairs > MAX_DEPENDENCY_SETTER_PAIRS {
            return (RuleOutcome::empty(), SystemRegisterParamStats::default());
        }
        let Some(registration): Option<Registration<'_>> = registration(call) else {
            continue;
        };
        let edit_result: RegistrationEditResult = registration_edits(
            &registration,
            &safety,
            &reserved,
            &next_suffixes,
            symbols,
            nodes,
            MAX_GENERATED_EDITS.saturating_sub(edits.len()),
        );
        let RegistrationEditResult::Ready {
            edits: mut candidate_edits,
            names: candidate_names,
            renamed: candidate_count,
            suffixes: candidate_suffixes,
        } = edit_result
        else {
            if matches!(edit_result, RegistrationEditResult::Exhausted) {
                return (RuleOutcome::empty(), SystemRegisterParamStats::default());
            }
            continue;
        };
        if candidate_edits
            .iter()
            .any(|edit: &Edit| edit_overlaps_comments(edit, &parsed.program.comments))
        {
            continue;
        }
        if edits.len().saturating_add(candidate_edits.len()) > MAX_GENERATED_EDITS {
            return (RuleOutcome::empty(), SystemRegisterParamStats::default());
        }
        for name in candidate_names {
            reserved.insert(name);
        }
        next_suffixes = candidate_suffixes;
        edits.append(&mut candidate_edits);
        renamed = renamed.saturating_add(candidate_count);
    }

    if edits.is_empty() {
        return (RuleOutcome::empty(), SystemRegisterParamStats::default());
    }
    (
        RuleOutcome { edits },
        SystemRegisterParamStats {
            parameters_renamed: renamed,
        },
    )
}

fn dependency_count(call: &CallExpression<'_>) -> Option<usize> {
    let (dependencies_expression, _declaration_expression): (&Expression<'_>, &Expression<'_>) =
        registration_arguments(call)?;
    let Expression::ArrayExpression(dependencies) = dependencies_expression.get_inner_expression()
    else {
        return None;
    };
    Some(dependencies.elements.len())
}

fn registration_edits(
    registration: &Registration<'_>,
    safety: &RenameSafety<'_>,
    reserved: &IndexSet<String>,
    next_suffixes: &IndexMap<String, u32>,
    symbols: &SymbolTable,
    nodes: &AstNodes<'_>,
    remaining_edits: usize,
) -> RegistrationEditResult {
    let mut local_reserved: IndexSet<String> = reserved.clone();
    let mut local_suffixes: IndexMap<String, u32> = next_suffixes.clone();
    let mut edits: Vec<Edit> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let mut renamed: usize = 0;
    for (dependency, setter) in registration
        .dependencies
        .iter()
        .zip(&registration.setters.elements)
    {
        let Some(expression): Option<&Expression<'_>> = setter.as_expression() else {
            return RegistrationEditResult::Invalid;
        };
        if matches!(
            expression.get_inner_expression(),
            Expression::NullLiteral(_)
        ) {
            continue;
        }
        let Expression::FunctionExpression(function) = expression.get_inner_expression() else {
            return RegistrationEditResult::Invalid;
        };
        let Some(body): Option<&FunctionBody<'_>> = function.body.as_deref() else {
            return RegistrationEditResult::Invalid;
        };
        if function.r#async
            || function.generator
            || function.type_parameters.is_some()
            || function.params.rest.is_some()
            || body_has_dynamic_scope(body)
        {
            return RegistrationEditResult::Invalid;
        }
        if function.params.items.is_empty() {
            if !body.statements.is_empty() {
                return RegistrationEditResult::Invalid;
            }
            continue;
        }
        if function.params.items.len() != 1 {
            return RegistrationEditResult::Invalid;
        }
        let parameter: &oxc_ast::ast::FormalParameter<'_> = &function.params.items[0];
        let BindingPatternKind::BindingIdentifier(binding) = &parameter.pattern.kind else {
            return RegistrationEditResult::Invalid;
        };
        let local_name: &str = binding.name.as_str();
        if !is_minified_local(local_name) {
            continue;
        }
        let Some(symbol_id): Option<SymbolId> = binding.symbol_id.get() else {
            return RegistrationEditResult::Invalid;
        };
        if symbols
            .get_resolved_reference_ids(symbol_id)
            .iter()
            .any(|&reference_id: &ReferenceId| symbols.get_reference(reference_id).is_write())
        {
            return RegistrationEditResult::Invalid;
        }
        let Some(preferred): Option<String> = derive_module_names(dependency).into_iter().next()
        else {
            return RegistrationEditResult::Invalid;
        };
        if preferred == local_name {
            continue;
        }
        let owner_scope: ScopeId = symbols.get_scope_id(symbol_id);
        let Some(new_name): Option<String> = choose_name(
            safety,
            symbol_id,
            owner_scope,
            local_name,
            &preferred,
            &local_reserved,
            &mut local_suffixes,
        ) else {
            return RegistrationEditResult::Invalid;
        };
        let reference_count: usize = symbols.get_resolved_reference_ids(symbol_id).len();
        let Some(required_edits): Option<usize> = reference_count.checked_add(1) else {
            return RegistrationEditResult::Exhausted;
        };
        if required_edits > remaining_edits.saturating_sub(edits.len()) {
            return RegistrationEditResult::Exhausted;
        }
        let mut parameter_edits: Vec<Edit> = Vec::with_capacity(required_edits);
        parameter_edits.push(Edit {
            start: binding.span.start as usize,
            end: binding.span.end as usize,
            replacement: new_name.clone(),
        });
        push_reference_edits(symbols, nodes, symbol_id, &new_name, &mut parameter_edits);
        local_reserved.insert(new_name.clone());
        names.push(new_name);
        edits.append(&mut parameter_edits);
        renamed = renamed.saturating_add(1);
    }
    RegistrationEditResult::Ready {
        edits,
        names,
        renamed,
        suffixes: local_suffixes,
    }
}

fn registration<'a>(call: &'a CallExpression<'a>) -> Option<Registration<'a>> {
    let (dependencies_expression, declaration_expression): (&Expression<'_>, &Expression<'_>) =
        registration_arguments(call)?;
    let Expression::ArrayExpression(dependencies) = dependencies_expression.get_inner_expression()
    else {
        return None;
    };
    if dependencies.elements.len() > MAX_DEPENDENCY_SETTER_PAIRS {
        return None;
    }
    let mut dependency_names: Vec<&str> = Vec::with_capacity(dependencies.elements.len());
    for dependency in &dependencies.elements {
        let Some(Expression::StringLiteral(literal)) = dependency.as_expression() else {
            return None;
        };
        dependency_names.push(literal.value.as_str());
    }
    let Expression::FunctionExpression(declaration) = declaration_expression.get_inner_expression()
    else {
        return None;
    };
    let body: &FunctionBody<'_> = declaration.body.as_ref()?;
    if declaration.r#async
        || declaration.generator
        || declaration.type_parameters.is_some()
        || declaration.params.rest.is_some()
        || !declaration_parameters_valid(&declaration.params.items)
        || body_has_dynamic_scope(body)
    {
        return None;
    }
    let returned: &ObjectExpression<'_> = direct_returned_object(body)?;
    let (setters, execute): (Option<&ArrayExpression<'_>>, Option<&Expression<'_>>) =
        registration_properties(returned)?;
    let setters: &ArrayExpression<'_> = setters?;
    let execute: &Expression<'_> = execute?;
    let Expression::FunctionExpression(execute_function) = execute.get_inner_expression() else {
        return None;
    };
    if execute_function.r#async
        || execute_function.generator
        || execute_function.type_parameters.is_some()
        || execute_function.params.rest.is_some()
        || !execute_function.params.items.is_empty()
        || execute_function.body.is_none()
        || setters.elements.len() != dependency_names.len()
    {
        return None;
    }
    Some(Registration {
        dependencies: dependency_names,
        setters,
    })
}

fn declaration_parameters_valid(parameters: &[FormalParameter<'_>]) -> bool {
    (parameters.is_empty() || parameters.len() == 2)
        && parameters.iter().all(|parameter: &FormalParameter<'_>| {
            parameter.decorators.is_empty()
                && parameter.accessibility.is_none()
                && !parameter.readonly
                && !parameter.r#override
                && !parameter.pattern.optional
                && parameter.pattern.type_annotation.is_none()
                && matches!(
                    &parameter.pattern.kind,
                    BindingPatternKind::BindingIdentifier(_)
                )
        })
}

fn registration_arguments<'a>(
    call: &'a CallExpression<'a>,
) -> Option<(&'a Expression<'a>, &'a Expression<'a>)> {
    if call.optional || call.type_parameters.is_some() {
        return None;
    }
    match call.arguments.as_slice() {
        [dependencies, declaration] => {
            Some((dependencies.as_expression()?, declaration.as_expression()?))
        }
        [name, dependencies, declaration] => {
            let name_expression: &Expression<'_> = name.as_expression()?;
            if !matches!(
                name_expression.get_inner_expression(),
                Expression::StringLiteral(_)
            ) {
                return None;
            }
            Some((dependencies.as_expression()?, declaration.as_expression()?))
        }
        _ => None,
    }
}

fn direct_returned_object<'a>(body: &'a FunctionBody<'a>) -> Option<&'a ObjectExpression<'a>> {
    let Statement::ReturnStatement(return_statement) = body.statements.last()? else {
        return None;
    };
    if body
        .statements
        .iter()
        .take(body.statements.len().saturating_sub(1))
        .any(|statement: &Statement<'_>| matches!(statement, Statement::ReturnStatement(_)))
    {
        return None;
    }
    let Expression::ObjectExpression(object) =
        return_statement.argument.as_ref()?.get_inner_expression()
    else {
        return None;
    };
    Some(object)
}

fn registration_properties<'a>(
    object: &'a ObjectExpression<'a>,
) -> Option<(Option<&'a ArrayExpression<'a>>, Option<&'a Expression<'a>>)> {
    let mut setters: Option<&ArrayExpression<'_>> = None;
    let mut execute: Option<&Expression<'_>> = None;
    for property in &object.properties {
        let ObjectPropertyKind::ObjectProperty(property) = property else {
            return None;
        };
        if property.kind != PropertyKind::Init
            || property.computed
            || property.method
            || property.shorthand
        {
            return None;
        }
        let PropertyKey::StaticIdentifier(key) = &property.key else {
            return None;
        };
        match key.name.as_str() {
            "setters" => {
                if setters.is_some() {
                    return None;
                }
                let Expression::ArrayExpression(array) = property.value.get_inner_expression()
                else {
                    return None;
                };
                setters = Some(array);
            }
            "execute" => {
                if execute.is_some() {
                    return None;
                }
                execute = Some(&property.value);
            }
            _ => return None,
        }
    }
    Some((setters, execute))
}

fn is_system_register_call(call: &CallExpression<'_>, symbols: &SymbolTable, source: &str) -> bool {
    let Expression::StaticMemberExpression(member) = call.callee.get_inner_expression() else {
        return false;
    };
    if member.optional || member.property.name.as_str() != "register" {
        return false;
    }
    let Expression::Identifier(system) = member.object.get_inner_expression() else {
        return false;
    };
    let Some(call_suffix): Option<&str> =
        source.get(system.span.end as usize..call.span.end as usize)
    else {
        return false;
    };
    let Some((member_source, _arguments)): Option<(&str, &str)> = call_suffix.split_once('(')
    else {
        return false;
    };
    let direct_member: bool = member_source
        .chars()
        .filter(|character: &char| !character.is_whitespace())
        .eq(".register".chars());
    direct_member && unresolved_identifier_is(system, "System", symbols)
}
