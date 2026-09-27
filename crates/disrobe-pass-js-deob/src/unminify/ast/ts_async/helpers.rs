use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, AssignmentTarget, BindingPatternKind, Expression, Function, ImportDeclaration,
    ImportDeclarationSpecifier, LogicalOperator, ModuleExportName, Program, Statement,
    VariableDeclaration,
};
use oxc_ast::{AstKind, Visit, visit::walk};
use oxc_parser::Parser;
use oxc_semantic::{ReferenceId, Semantic, SemanticBuilder, SymbolId};
use oxc_span::{SourceType, Span};

use super::canon::function_shape;

const TSLIB_AWAITER: &str = r#"(function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
});"#;

const TSLIB_GENERATOR: &str = r#"(function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
});"#;

const TERSER_AWAITER: &str = r"(function(thisArg,_arguments,P,generator){return new(P||(P=Promise))(function(resolve,reject){function fulfilled(value){try{step(generator.next(value))}catch(e){reject(e)}}function rejected(value){try{step(generator.throw(value))}catch(e){reject(e)}}function step(result){var value;result.done?resolve(result.value):(value=result.value,value instanceof P?value:new P(function(resolve){resolve(value)})).then(fulfilled,rejected)}step((generator=generator.apply(thisArg,_arguments||[])).next())})});";

const TERSER_GENERATOR: &str = r#"(function(thisArg,body){var f,y,t,_={label:0,sent:function(){if(1&t[0])throw t[1];return t[1]},trys:[],ops:[]},g=Object.create(("function"==typeof Iterator?Iterator:Object).prototype);return g.next=verb(0),g.throw=verb(1),g.return=verb(2),"function"==typeof Symbol&&(g[Symbol.iterator]=function(){return this}),g;function verb(n){return function(v){return function(op){if(f)throw new TypeError("Generator is already executing.");for(;g&&(g=0,op[0]&&(_=0)),_;)try{if(f=1,y&&(t=2&op[0]?y.return:op[0]?y.throw||((t=y.return)&&t.call(y),0):y.next)&&!(t=t.call(y,op[1])).done)return t;switch(y=0,t&&(op=[2&op[0],t.value]),op[0]){case 0:case 1:t=op;break;case 4:return _.label++,{value:op[1],done:!1};case 5:_.label++,y=op[1],op=[0];continue;case 7:op=_.ops.pop(),_.trys.pop();continue;default:if(!(t=_.trys,(t=t.length>0&&t[t.length-1])||6!==op[0]&&2!==op[0])){_=0;continue}if(3===op[0]&&(!t||op[1]>t[0]&&op[1]<t[3])){_.label=op[1];break}if(6===op[0]&&_.label<t[1]){_.label=t[1],t=op;break}if(t&&_.label<t[2]){_.label=t[2],_.ops.push(op);break}t[2]&&_.ops.pop(),_.trys.pop();continue}op=body.call(thisArg,_)}catch(e){op=[6,e],y=0}finally{f=t=0}if(5&op[0])throw op[1];return{value:op[0]?op[1]:void 0,done:!0}}([n,v])}}});"#;

const TSLIB_MODULE: &str = "tslib";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum HelperRole {
    Awaiter,
    Generator,
}

impl HelperRole {
    const fn export_name(self) -> &'static str {
        match self {
            Self::Awaiter => "__awaiter",
            Self::Generator => "__generator",
        }
    }

    fn from_export_name(name: &str) -> Option<Self> {
        match name {
            "__awaiter" => Some(Self::Awaiter),
            "__generator" => Some(Self::Generator),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct DirectHelper {
    pub(super) role: HelperRole,
    pub(super) removable: Option<Span>,
}

#[derive(Debug, Default)]
pub(super) struct HelperBindings {
    pub(super) direct: BTreeMap<SymbolId, DirectHelper>,
    namespaces: BTreeSet<SymbolId>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct HelperUse {
    pub(super) role: HelperRole,
    pub(super) reference: Span,
}

fn reference_shapes() -> &'static [(HelperRole, String)] {
    static SHAPES: OnceLock<Vec<(HelperRole, String)>> = OnceLock::new();
    SHAPES.get_or_init(|| {
        [
            (HelperRole::Awaiter, TSLIB_AWAITER),
            (HelperRole::Awaiter, TERSER_AWAITER),
            (HelperRole::Generator, TSLIB_GENERATOR),
            (HelperRole::Generator, TERSER_GENERATOR),
        ]
        .into_iter()
        .filter_map(|(role, text): (HelperRole, &str)| Some((role, reference_shape(text)?)))
        .collect()
    })
}

fn reference_shape(text: &str) -> Option<String> {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("helper.js").ok()?;
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, text, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return None;
    }
    let semantic: Semantic<'_> = SemanticBuilder::new().build(&parsed.program).semantic;
    let [Statement::ExpressionStatement(statement)] = parsed.program.body.as_slice() else {
        return None;
    };
    let function: &Function<'_> = parenthesized_function(&statement.expression)?;
    function_shape(function, &semantic).ok()
}

fn parenthesized_function<'b, 'a>(expression: &'b Expression<'a>) -> Option<&'b Function<'a>> {
    match expression {
        Expression::ParenthesizedExpression(inner) => parenthesized_function(&inner.expression),
        Expression::FunctionExpression(function) => Some(function),
        _ => None,
    }
}

fn helper_role(function: &Function<'_>, semantic: &Semantic<'_>) -> Option<HelperRole> {
    let shape: String = function_shape(function, semantic).ok()?;
    reference_shapes()
        .iter()
        .find(|(_, reference): &&(HelperRole, String)| *reference == shape)
        .map(|(role, _): &(HelperRole, String)| *role)
}

impl HelperBindings {
    pub(super) fn discover<'a>(program: &Program<'a>, semantic: &Semantic<'a>) -> Self {
        let mut bindings: Self = Self::default();
        let mut finder: ListFinder<'_, '_, '_> = ListFinder {
            semantic,
            bindings: &mut bindings,
        };
        finder.scan_list(&program.body);
        finder.visit_program(program);
        for statement in &program.body {
            if let Statement::ImportDeclaration(import) = statement {
                bindings.record_import(import);
            }
        }
        bindings
            .direct
            .retain(|symbol: &SymbolId, _| is_stable_binding(*symbol, semantic));
        bindings
            .namespaces
            .retain(|symbol: &SymbolId| is_stable_binding(*symbol, semantic));
        bindings
    }

    pub(super) fn is_empty(&self) -> bool {
        self.direct.is_empty() && self.namespaces.is_empty()
    }

    fn record_import(&mut self, import: &ImportDeclaration<'_>) {
        if import.source.value.as_str() != TSLIB_MODULE {
            return;
        }
        let Some(specifiers) = import.specifiers.as_ref() else {
            return;
        };
        for specifier in specifiers {
            match specifier {
                ImportDeclarationSpecifier::ImportSpecifier(named) => {
                    let imported: &str = match &named.imported {
                        ModuleExportName::IdentifierName(name) => name.name.as_str(),
                        ModuleExportName::IdentifierReference(name) => name.name.as_str(),
                        ModuleExportName::StringLiteral(name) => name.value.as_str(),
                    };
                    let (Some(role), Some(symbol)) = (
                        HelperRole::from_export_name(imported),
                        named.local.symbol_id.get(),
                    ) else {
                        continue;
                    };
                    self.direct.insert(
                        symbol,
                        DirectHelper {
                            role,
                            removable: None,
                        },
                    );
                }
                ImportDeclarationSpecifier::ImportDefaultSpecifier(default) => {
                    if let Some(symbol) = default.local.symbol_id.get() {
                        self.namespaces.insert(symbol);
                    }
                }
                ImportDeclarationSpecifier::ImportNamespaceSpecifier(namespace) => {
                    if let Some(symbol) = namespace.local.symbol_id.get() {
                        self.namespaces.insert(symbol);
                    }
                }
            }
        }
    }

    pub(super) fn callee_use(
        &self,
        callee: &Expression<'_>,
        semantic: &Semantic<'_>,
    ) -> Option<HelperUse> {
        match callee {
            Expression::Identifier(reference) => {
                let symbol: SymbolId = resolved_symbol(reference, semantic)?;
                let helper: &DirectHelper = self.direct.get(&symbol)?;
                Some(HelperUse {
                    role: helper.role,
                    reference: reference.span,
                })
            }
            Expression::ParenthesizedExpression(inner) => {
                self.callee_use(&inner.expression, semantic)
            }
            Expression::SequenceExpression(sequence) => {
                let [Expression::NumericLiteral(_), member] = sequence.expressions.as_slice()
                else {
                    return None;
                };
                self.namespace_use(member, semantic)
            }
            _ => self.namespace_use(callee, semantic),
        }
    }

    fn namespace_use(
        &self,
        expression: &Expression<'_>,
        semantic: &Semantic<'_>,
    ) -> Option<HelperUse> {
        let (object, property): (&Expression<'_>, &str) = match expression {
            Expression::StaticMemberExpression(member) if !member.optional => {
                (&member.object, member.property.name.as_str())
            }
            Expression::ComputedMemberExpression(member) if !member.optional => {
                let Expression::StringLiteral(key) = &member.expression else {
                    return None;
                };
                (&member.object, key.value.as_str())
            }
            _ => return None,
        };
        let Expression::Identifier(namespace) = object else {
            return None;
        };
        let symbol: SymbolId = resolved_symbol(namespace, semantic)?;
        if !self.namespaces.contains(&symbol) {
            return None;
        }
        Some(HelperUse {
            role: HelperRole::from_export_name(property)?,
            reference: namespace.span,
        })
    }
}

pub(super) fn resolved_symbol(
    reference: &oxc_ast::ast::IdentifierReference<'_>,
    semantic: &Semantic<'_>,
) -> Option<SymbolId> {
    let reference_id: ReferenceId = reference.reference_id.get()?;
    semantic.symbols().get_reference(reference_id).symbol_id()
}

fn is_stable_binding(symbol: SymbolId, semantic: &Semantic<'_>) -> bool {
    !semantic.symbols().symbol_is_mutated(symbol)
        && semantic.symbols().get_redeclarations(symbol).is_empty()
}

struct ListFinder<'b, 's, 'a> {
    semantic: &'s Semantic<'a>,
    bindings: &'b mut HelperBindings,
}

impl<'a> Visit<'a> for ListFinder<'_, '_, 'a> {
    fn visit_function_body(&mut self, body: &oxc_ast::ast::FunctionBody<'a>) {
        self.scan_list(&body.statements);
        walk::walk_function_body(self, body);
    }
}

impl ListFinder<'_, '_, '_> {
    fn scan_list(&mut self, statements: &[Statement<'_>]) {
        let mut inert_prefix: bool = true;
        for statement in statements {
            match statement {
                Statement::FunctionDeclaration(function) => {
                    if let (Some(id), Some(role)) =
                        (&function.id, helper_role(function, self.semantic))
                        && let Some(symbol) = id.symbol_id.get()
                    {
                        self.bindings.direct.insert(
                            symbol,
                            DirectHelper {
                                role,
                                removable: Some(function.span),
                            },
                        );
                    }
                    continue;
                }
                Statement::VariableDeclaration(declaration)
                    if inert_prefix && self.record_declaration(declaration) =>
                {
                    continue;
                }
                _ => {}
            }
            if !is_module_marker(statement) {
                inert_prefix = false;
            }
        }
    }

    fn record_declaration(&mut self, declaration: &VariableDeclaration<'_>) -> bool {
        let mut inert: bool = true;
        for declarator in &declaration.declarations {
            let BindingPatternKind::BindingIdentifier(binding) = &declarator.id.kind else {
                return false;
            };
            let Some(init) = declarator.init.as_ref() else {
                return false;
            };
            let Some(symbol) = binding.symbol_id.get() else {
                return false;
            };
            let removable: Option<Span> =
                (declaration.declarations.len() == 1).then_some(declaration.span);
            if is_tslib_require(init, self.semantic) {
                self.bindings.namespaces.insert(symbol);
                inert = false;
                continue;
            }
            let Some((shared_name, function)) = shared_helper_init(init) else {
                inert &= is_inert_helper_init(init);
                continue;
            };
            if let Some(role) = helper_role(function, self.semantic)
                && shared_name.is_none_or(|name: &str| name == role.export_name())
            {
                self.bindings
                    .direct
                    .insert(symbol, DirectHelper { role, removable });
            }
            inert &= is_inert_helper_init(init);
        }
        inert
    }
}

fn shared_helper_init<'b, 'a>(
    init: &'b Expression<'a>,
) -> Option<(Option<&'b str>, &'b Function<'a>)> {
    match init {
        Expression::ParenthesizedExpression(inner) => shared_helper_init(&inner.expression),
        Expression::FunctionExpression(function) => Some((None, function)),
        Expression::LogicalExpression(logical) if logical.operator == LogicalOperator::Or => {
            let name: &str = shared_lookup_name(&logical.left)?;
            let function: &Function<'a> = parenthesized_function(&logical.right)?;
            Some((Some(name), function))
        }
        _ => None,
    }
}

fn shared_lookup_name<'b>(expression: &'b Expression<'_>) -> Option<&'b str> {
    match expression {
        Expression::ParenthesizedExpression(inner) => shared_lookup_name(&inner.expression),
        Expression::LogicalExpression(logical) if logical.operator == LogicalOperator::And => {
            if !matches!(logical.left, Expression::ThisExpression(_)) {
                return None;
            }
            let Expression::StaticMemberExpression(member) = &logical.right else {
                return None;
            };
            if !matches!(member.object, Expression::ThisExpression(_)) || member.optional {
                return None;
            }
            Some(member.property.name.as_str())
        }
        _ => None,
    }
}

fn is_inert_helper_init(init: &Expression<'_>) -> bool {
    let mut probe: EffectProbe = EffectProbe { effect: false };
    probe.visit_expression(init);
    !probe.effect
}

struct EffectProbe {
    effect: bool,
}

impl<'a> Visit<'a> for EffectProbe {
    fn enter_node(&mut self, kind: AstKind<'a>) {
        if matches!(
            kind,
            AstKind::CallExpression(_)
                | AstKind::NewExpression(_)
                | AstKind::TaggedTemplateExpression(_)
                | AstKind::AssignmentExpression(_)
                | AstKind::UpdateExpression(_)
                | AstKind::YieldExpression(_)
                | AstKind::AwaitExpression(_)
                | AstKind::ImportExpression(_)
                | AstKind::TemplateLiteral(_)
                | AstKind::Class(_)
        ) {
            self.effect = true;
        }
    }

    fn visit_function(&mut self, _function: &Function<'a>, _flags: oxc_semantic::ScopeFlags) {}

    fn visit_arrow_function_expression(
        &mut self,
        _arrow: &oxc_ast::ast::ArrowFunctionExpression<'a>,
    ) {
    }
}

fn is_tslib_require(init: &Expression<'_>, semantic: &Semantic<'_>) -> bool {
    let Expression::CallExpression(call) = init else {
        return false;
    };
    let Expression::Identifier(callee) = &call.callee else {
        return false;
    };
    if callee.name != "require" || resolved_symbol(callee, semantic).is_some() || call.optional {
        return false;
    }
    matches!(
        call.arguments.as_slice(),
        [Argument::StringLiteral(module)] if module.value.as_str() == TSLIB_MODULE
    )
}

fn is_module_marker(statement: &Statement<'_>) -> bool {
    let Statement::ExpressionStatement(expression) = statement else {
        return false;
    };
    is_esmodule_marker(&expression.expression) || is_exports_reset(&expression.expression)
}

pub(super) fn is_esmodule_marker(expression: &Expression<'_>) -> bool {
    let Expression::CallExpression(call) = expression else {
        return false;
    };
    let Expression::StaticMemberExpression(member) = &call.callee else {
        return false;
    };
    let Expression::Identifier(object) = &member.object else {
        return false;
    };
    object.name == "Object"
        && member.property.name == "defineProperty"
        && matches!(
            call.arguments.as_slice(),
            [Argument::Identifier(exports), Argument::StringLiteral(key), Argument::ObjectExpression(_)]
                if exports.name == "exports" && key.value == "__esModule"
        )
}

fn is_exports_reset(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::AssignmentExpression(assignment) => {
            let AssignmentTarget::StaticMemberExpression(member) = &assignment.left else {
                return false;
            };
            matches!(&member.object, Expression::Identifier(object) if object.name == "exports")
                && (is_exports_reset(&assignment.right) || is_void_zero(&assignment.right))
        }
        _ => false,
    }
}

pub(super) fn is_void_zero(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::UnaryExpression(unary) => {
            unary.operator == oxc_ast::ast::UnaryOperator::Void
                && matches!(unary.argument, Expression::NumericLiteral(_))
        }
        _ => false,
    }
}
