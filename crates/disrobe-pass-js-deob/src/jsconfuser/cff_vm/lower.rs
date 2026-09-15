use std::rc::Rc;

use oxc_ast::ast as oast;
use oxc_ast::ast::{
    AssignmentOperator, BinaryOperator, LogicalOperator, UnaryOperator, UpdateOperator,
};
use oxc_span::GetSpan;

use super::ir::{
    AssignOp, BinaryOp, Expr, FuncDef, LogicalOp, Param, PropKey, Stmt, SwitchCase, UnaryOp,
    UpdateOp, VarKind,
};

pub(super) struct Lowerer<'a> {
    source: &'a str,
}

impl<'a> Lowerer<'a> {
    pub(super) const fn new(source: &'a str) -> Self {
        Self { source }
    }

    fn slice(&self, span: oxc_span::Span) -> String {
        self.source
            .get(span.start as usize..span.end as usize)
            .unwrap_or_default()
            .to_owned()
    }

    pub(super) fn lower_program(&self, program: &oast::Program<'a>) -> Vec<Stmt> {
        program
            .body
            .iter()
            .map(|stmt: &oast::Statement<'a>| self.lower_stmt(stmt))
            .collect()
    }

    fn lower_stmt(&self, stmt: &oast::Statement<'a>) -> Stmt {
        match stmt {
            oast::Statement::ExpressionStatement(s) => Stmt::Expr(self.lower_expr(&s.expression)),
            oast::Statement::EmptyStatement(_) => Stmt::Empty,
            oast::Statement::BlockStatement(s) => Stmt::Block(self.lower_block(&s.body)),
            oast::Statement::VariableDeclaration(d) => self.lower_var_decl(d),
            oast::Statement::FunctionDeclaration(f) => {
                Stmt::FuncDecl(Rc::new(self.lower_function(f, false)))
            }
            oast::Statement::ReturnStatement(s) => {
                Stmt::Return(s.argument.as_ref().map(|e| self.lower_expr(e)))
            }
            oast::Statement::BreakStatement(s) => {
                Stmt::Break(s.label.as_ref().map(|l| l.name.to_string()))
            }
            oast::Statement::ContinueStatement(s) => {
                Stmt::Continue(s.label.as_ref().map(|l| l.name.to_string()))
            }
            oast::Statement::IfStatement(s) => Stmt::If {
                test: self.lower_expr(&s.test),
                consequent: self.lower_stmt_as_block(&s.consequent),
                alternate: s
                    .alternate
                    .as_ref()
                    .map_or_else(Vec::new, |a| self.lower_stmt_as_block(a)),
            },
            oast::Statement::WhileStatement(s) => Stmt::While {
                test: self.lower_expr(&s.test),
                body: self.lower_stmt_as_block(&s.body),
            },
            oast::Statement::DoWhileStatement(s) => Stmt::DoWhile {
                body: self.lower_stmt_as_block(&s.body),
                test: self.lower_expr(&s.test),
            },
            oast::Statement::ForStatement(s) => Stmt::For {
                init: s.init.as_ref().map(|i| Box::new(self.lower_for_init(i))),
                test: s.test.as_ref().map(|e| self.lower_expr(e)),
                update: s.update.as_ref().map(|e| self.lower_expr(e)),
                body: self.lower_stmt_as_block(&s.body),
            },
            oast::Statement::ForInStatement(s) => Stmt::ForIn {
                left: Box::new(self.lower_for_left(&s.left)),
                right: self.lower_expr(&s.right),
                body: self.lower_stmt_as_block(&s.body),
            },
            oast::Statement::ForOfStatement(s) => Stmt::ForOf {
                left: Box::new(self.lower_for_left(&s.left)),
                right: self.lower_expr(&s.right),
                body: self.lower_stmt_as_block(&s.body),
            },
            oast::Statement::SwitchStatement(s) => Stmt::Switch {
                discriminant: self.lower_expr(&s.discriminant),
                cases: s
                    .cases
                    .iter()
                    .map(|c: &oast::SwitchCase<'a>| SwitchCase {
                        test: c.test.as_ref().map(|e| self.lower_expr(e)),
                        body: self.lower_block(&c.consequent),
                    })
                    .collect(),
            },
            oast::Statement::WithStatement(s) => Stmt::With {
                object: self.lower_expr(&s.object),
                body: self.lower_stmt_as_block(&s.body),
            },
            oast::Statement::ThrowStatement(s) => Stmt::Throw(self.lower_expr(&s.argument)),
            oast::Statement::LabeledStatement(s) => Stmt::Labeled {
                label: s.label.name.to_string(),
                body: Box::new(self.lower_stmt(&s.body)),
            },
            other => Stmt::Raw(self.slice(other.span())),
        }
    }

    fn lower_block(&self, body: &oxc_allocator::Vec<'a, oast::Statement<'a>>) -> Vec<Stmt> {
        body.iter().map(|s| self.lower_stmt(s)).collect()
    }

    fn lower_stmt_as_block(&self, stmt: &oast::Statement<'a>) -> Vec<Stmt> {
        match stmt {
            oast::Statement::BlockStatement(s) => self.lower_block(&s.body),
            oast::Statement::EmptyStatement(_) => Vec::new(),
            other => vec![self.lower_stmt(other)],
        }
    }

    fn lower_var_decl(&self, decl: &oast::VariableDeclaration<'a>) -> Stmt {
        let kind: VarKind = match decl.kind {
            oast::VariableDeclarationKind::Var => VarKind::Var,
            oast::VariableDeclarationKind::Const => VarKind::Const,
            _ => VarKind::Let,
        };
        let mut decls: Vec<(String, Option<Expr>)> = Vec::with_capacity(decl.declarations.len());
        for d in &decl.declarations {
            let name: String = self.binding_name(&d.id);
            let init: Option<Expr> = d.init.as_ref().map(|e| self.lower_expr(e));
            decls.push((name, init));
        }
        Stmt::VarDecl { kind, decls }
    }

    fn binding_name(&self, pat: &oast::BindingPattern<'a>) -> String {
        match &pat.kind {
            oast::BindingPatternKind::BindingIdentifier(id) => id.name.to_string(),
            other => self.slice(other.span()),
        }
    }

    fn lower_for_init(&self, init: &oast::ForStatementInit<'a>) -> Stmt {
        match init {
            oast::ForStatementInit::VariableDeclaration(d) => self.lower_var_decl(d),
            expr => expr.as_expression().map_or_else(
                || Stmt::Raw(self.slice(init.span())),
                |e| Stmt::Expr(self.lower_expr(e)),
            ),
        }
    }

    fn lower_for_left(&self, left: &oast::ForStatementLeft<'a>) -> Stmt {
        if let oast::ForStatementLeft::VariableDeclaration(d) = left {
            return self.lower_var_decl(d);
        }
        if let Some(member) = left.as_member_expression() {
            return Stmt::Expr(self.lower_member_expr(member));
        }
        if let oast::ForStatementLeft::AssignmentTargetIdentifier(id) = left {
            return Stmt::Expr(Expr::Ident(id.name.to_string()));
        }
        Stmt::Raw(self.slice(left.span()))
    }

    fn lower_function(&self, func: &oast::Function<'a>, is_arrow: bool) -> FuncDef {
        let params: Vec<Param> = self.lower_params(&func.params);
        let body: Vec<Stmt> = func
            .body
            .as_ref()
            .map_or_else(Vec::new, |b| self.lower_block(&b.statements));
        FuncDef {
            name: func.id.as_ref().map(|id| id.name.to_string()),
            params,
            body,
            is_generator: func.generator,
            is_async: func.r#async,
            is_arrow,
            expression_body: None,
        }
    }

    fn lower_arrow(&self, arrow: &oast::ArrowFunctionExpression<'a>) -> FuncDef {
        let params: Vec<Param> = self.lower_params(&arrow.params);
        if arrow.expression {
            let expr_body: Option<Box<Expr>> = arrow.body.statements.first().and_then(|s| {
                if let oast::Statement::ExpressionStatement(es) = s {
                    Some(Box::new(self.lower_expr(&es.expression)))
                } else {
                    None
                }
            });
            return FuncDef {
                name: None,
                params,
                body: Vec::new(),
                is_generator: false,
                is_async: arrow.r#async,
                is_arrow: true,
                expression_body: expr_body,
            };
        }
        FuncDef {
            name: None,
            params,
            body: self.lower_block(&arrow.body.statements),
            is_generator: false,
            is_async: arrow.r#async,
            is_arrow: true,
            expression_body: None,
        }
    }

    fn lower_params(&self, params: &oast::FormalParameters<'a>) -> Vec<Param> {
        let mut out: Vec<Param> = Vec::with_capacity(params.items.len() + 1);
        for item in &params.items {
            out.push(self.lower_param_pattern(&item.pattern, false));
        }
        if let Some(rest) = &params.rest {
            out.push(self.lower_param_pattern(&rest.argument, true));
        }
        out
    }

    fn lower_param_pattern(&self, pat: &oast::BindingPattern<'a>, rest: bool) -> Param {
        match &pat.kind {
            oast::BindingPatternKind::BindingIdentifier(id) => Param {
                name: id.name.to_string(),
                default: None,
                rest,
            },
            oast::BindingPatternKind::AssignmentPattern(ap) => {
                let name: String = match &ap.left.kind {
                    oast::BindingPatternKind::BindingIdentifier(id) => id.name.to_string(),
                    other => self.slice(other.span()),
                };
                Param {
                    name,
                    default: Some(self.lower_expr(&ap.right)),
                    rest,
                }
            }
            other => Param {
                name: self.slice(other.span()),
                default: None,
                rest,
            },
        }
    }

    fn lower_expr(&self, expr: &oast::Expression<'a>) -> Expr {
        match expr {
            oast::Expression::NumericLiteral(n) => Expr::Num(n.value),
            oast::Expression::StringLiteral(s) => Expr::Str(s.value.to_string()),
            oast::Expression::BooleanLiteral(b) => Expr::Bool(b.value),
            oast::Expression::NullLiteral(_) => Expr::Null,
            oast::Expression::Identifier(id) => {
                if id.name == "undefined" {
                    Expr::Undefined
                } else {
                    Expr::Ident(id.name.to_string())
                }
            }
            oast::Expression::ThisExpression(_) => Expr::This,
            oast::Expression::ParenthesizedExpression(p) => self.lower_expr(&p.expression),
            oast::Expression::ComputedMemberExpression(m) => Expr::Member {
                object: Box::new(self.lower_expr(&m.object)),
                property: Box::new(self.lower_expr(&m.expression)),
                computed: true,
            },
            oast::Expression::StaticMemberExpression(m) => Expr::Member {
                object: Box::new(self.lower_expr(&m.object)),
                property: Box::new(Expr::Str(m.property.name.to_string())),
                computed: false,
            },
            oast::Expression::UnaryExpression(u) => Expr::Unary {
                op: map_unary(u.operator),
                argument: Box::new(self.lower_expr(&u.argument)),
            },
            oast::Expression::UpdateExpression(u) => Expr::Update {
                op: map_update(u.operator),
                prefix: u.prefix,
                argument: Box::new(self.lower_simple_target(&u.argument)),
            },
            oast::Expression::BinaryExpression(b) => Expr::Binary {
                op: map_binary(b.operator),
                left: Box::new(self.lower_expr(&b.left)),
                right: Box::new(self.lower_expr(&b.right)),
            },
            oast::Expression::LogicalExpression(l) => Expr::Logical {
                op: map_logical(l.operator),
                left: Box::new(self.lower_expr(&l.left)),
                right: Box::new(self.lower_expr(&l.right)),
            },
            oast::Expression::ConditionalExpression(c) => Expr::Conditional {
                test: Box::new(self.lower_expr(&c.test)),
                consequent: Box::new(self.lower_expr(&c.consequent)),
                alternate: Box::new(self.lower_expr(&c.alternate)),
            },
            oast::Expression::AssignmentExpression(a) => self.lower_assignment(a),
            oast::Expression::SequenceExpression(s) => {
                Expr::Sequence(s.expressions.iter().map(|e| self.lower_expr(e)).collect())
            }
            oast::Expression::ArrayExpression(a) => Expr::Array(
                a.elements
                    .iter()
                    .map(|el: &oast::ArrayExpressionElement<'a>| self.lower_array_element(el))
                    .collect(),
            ),
            oast::Expression::ObjectExpression(o) => Expr::Object(self.lower_object(o)),
            oast::Expression::CallExpression(c) => self.lower_call(c),
            oast::Expression::NewExpression(n) => Expr::New {
                callee: Box::new(self.lower_expr(&n.callee)),
                args: self.lower_args(&n.arguments).0,
            },
            oast::Expression::FunctionExpression(f) => {
                Expr::Func(Rc::new(self.lower_function(f, false)))
            }
            oast::Expression::ArrowFunctionExpression(a) => {
                Expr::Func(Rc::new(self.lower_arrow(a)))
            }
            oast::Expression::TemplateLiteral(t) => self.lower_template(t),
            oast::Expression::ChainExpression(c) => match &c.expression {
                oast::ChainElement::CallExpression(call) => self.lower_call(call),
                oast::ChainElement::ComputedMemberExpression(m) => Expr::Member {
                    object: Box::new(self.lower_expr(&m.object)),
                    property: Box::new(self.lower_expr(&m.expression)),
                    computed: true,
                },
                oast::ChainElement::StaticMemberExpression(m) => Expr::Member {
                    object: Box::new(self.lower_expr(&m.object)),
                    property: Box::new(Expr::Str(m.property.name.to_string())),
                    computed: false,
                },
                _ => Expr::Raw(self.slice(expr.span())),
            },
            other => Expr::Raw(self.slice(other.span())),
        }
    }

    fn lower_array_element(&self, el: &oast::ArrayExpressionElement<'a>) -> Option<Expr> {
        match el {
            oast::ArrayExpressionElement::Elision(_) => None,
            oast::ArrayExpressionElement::SpreadElement(s) => {
                Some(Expr::Spread(Box::new(self.lower_expr(&s.argument))))
            }
            other => other.as_expression().map(|e| self.lower_expr(e)),
        }
    }

    fn lower_object(&self, obj: &oast::ObjectExpression<'a>) -> Vec<(PropKey, Expr)> {
        let mut out: Vec<(PropKey, Expr)> = Vec::with_capacity(obj.properties.len());
        for prop in &obj.properties {
            match prop {
                oast::ObjectPropertyKind::ObjectProperty(p) => {
                    let key: PropKey = self.lower_prop_key(&p.key, p.computed);
                    let value: Expr = self.lower_expr(&p.value);
                    out.push((key, value));
                }
                oast::ObjectPropertyKind::SpreadProperty(s) => {
                    out.push((
                        PropKey::Computed(Box::new(Expr::Raw("...".to_owned()))),
                        Expr::Spread(Box::new(self.lower_expr(&s.argument))),
                    ));
                }
            }
        }
        out
    }

    fn lower_prop_key(&self, key: &oast::PropertyKey<'a>, computed: bool) -> PropKey {
        match key {
            oast::PropertyKey::StaticIdentifier(id) => PropKey::Ident(id.name.to_string()),
            oast::PropertyKey::StringLiteral(s) => PropKey::Str(s.value.to_string()),
            oast::PropertyKey::NumericLiteral(n) => PropKey::Num(n.value),
            other => {
                let Some(e) = other.as_expression() else {
                    return PropKey::Computed(Box::new(Expr::Raw(self.slice(key.span()))));
                };
                if computed {
                    return PropKey::Computed(Box::new(self.lower_expr(e)));
                }
                match self.lower_expr(e) {
                    Expr::Str(s) => PropKey::Str(s),
                    Expr::Num(n) => PropKey::Num(n),
                    Expr::Ident(name) => PropKey::Ident(name),
                    lowered => PropKey::Computed(Box::new(lowered)),
                }
            }
        }
    }

    fn lower_call(&self, call: &oast::CallExpression<'a>) -> Expr {
        let callee: Expr = self.lower_expr(&call.callee);
        let (args, spread_last): (Vec<Expr>, bool) = self.lower_args(&call.arguments);
        Expr::Call {
            callee: Box::new(callee),
            args,
            spread_last,
        }
    }

    fn lower_args(&self, args: &oxc_allocator::Vec<'a, oast::Argument<'a>>) -> (Vec<Expr>, bool) {
        let mut out: Vec<Expr> = Vec::with_capacity(args.len());
        let mut spread_last: bool = false;
        let len: usize = args.len();
        for (idx, arg) in args.iter().enumerate() {
            match arg {
                oast::Argument::SpreadElement(s) => {
                    if idx + 1 == len {
                        spread_last = true;
                        out.push(self.lower_expr(&s.argument));
                    } else {
                        out.push(Expr::Spread(Box::new(self.lower_expr(&s.argument))));
                    }
                }
                other => {
                    if let Some(e) = other.as_expression() {
                        out.push(self.lower_expr(e));
                    } else {
                        out.push(Expr::Raw(self.slice(arg.span())));
                    }
                }
            }
        }
        (out, spread_last)
    }

    fn lower_template(&self, tpl: &oast::TemplateLiteral<'a>) -> Expr {
        let quasis: Vec<String> = tpl
            .quasis
            .iter()
            .map(|q: &oast::TemplateElement<'a>| {
                q.value
                    .cooked
                    .as_ref()
                    .map_or_else(|| q.value.raw.to_string(), std::string::ToString::to_string)
            })
            .collect();
        let exprs: Vec<Expr> = tpl.expressions.iter().map(|e| self.lower_expr(e)).collect();
        Expr::Template { quasis, exprs }
    }

    fn lower_assignment(&self, assign: &oast::AssignmentExpression<'a>) -> Expr {
        if let oast::AssignmentTarget::ArrayAssignmentTarget(arr) = &assign.left
            && assign.operator == AssignmentOperator::Assign
        {
            let targets: Vec<Option<Expr>> = arr
                .elements
                .iter()
                .map(|el: &Option<oast::AssignmentTargetMaybeDefault<'a>>| {
                    el.as_ref().map(|e| self.lower_target_maybe_default(e))
                })
                .collect();
            return Expr::ArrayDestructure {
                targets,
                value: Box::new(self.lower_expr(&assign.right)),
            };
        }
        Expr::Assign {
            op: map_assign(assign.operator),
            target: Box::new(self.lower_assignment_target(&assign.left)),
            value: Box::new(self.lower_expr(&assign.right)),
        }
    }

    fn lower_target_maybe_default(&self, t: &oast::AssignmentTargetMaybeDefault<'a>) -> Expr {
        match t {
            oast::AssignmentTargetMaybeDefault::AssignmentTargetWithDefault(d) => Expr::Assign {
                op: AssignOp::Assign,
                target: Box::new(self.lower_assignment_target(&d.binding)),
                value: Box::new(self.lower_expr(&d.init)),
            },
            other => other.as_assignment_target().map_or_else(
                || Expr::Raw(self.slice(t.span())),
                |at| self.lower_assignment_target(at),
            ),
        }
    }

    fn lower_assignment_target(&self, target: &oast::AssignmentTarget<'a>) -> Expr {
        if let Some(member) = target.as_member_expression() {
            return self.lower_member_expr(member);
        }
        match target {
            oast::AssignmentTarget::AssignmentTargetIdentifier(id) => {
                Expr::Ident(id.name.to_string())
            }
            other => Expr::Raw(self.slice(other.span())),
        }
    }

    fn lower_simple_target(&self, target: &oast::SimpleAssignmentTarget<'a>) -> Expr {
        if let Some(member) = target.as_member_expression() {
            return self.lower_member_expr(member);
        }
        match target {
            oast::SimpleAssignmentTarget::AssignmentTargetIdentifier(id) => {
                Expr::Ident(id.name.to_string())
            }
            other => Expr::Raw(self.slice(other.span())),
        }
    }

    fn lower_member_expr(&self, member: &oast::MemberExpression<'a>) -> Expr {
        match member {
            oast::MemberExpression::ComputedMemberExpression(m) => Expr::Member {
                object: Box::new(self.lower_expr(&m.object)),
                property: Box::new(self.lower_expr(&m.expression)),
                computed: true,
            },
            oast::MemberExpression::StaticMemberExpression(m) => Expr::Member {
                object: Box::new(self.lower_expr(&m.object)),
                property: Box::new(Expr::Str(m.property.name.to_string())),
                computed: false,
            },
            oast::MemberExpression::PrivateFieldExpression(m) => Expr::Raw(self.slice(m.span)),
        }
    }
}

const fn map_unary(op: UnaryOperator) -> UnaryOp {
    match op {
        UnaryOperator::UnaryNegation => UnaryOp::Neg,
        UnaryOperator::UnaryPlus => UnaryOp::Pos,
        UnaryOperator::LogicalNot => UnaryOp::Not,
        UnaryOperator::BitwiseNot => UnaryOp::BitNot,
        UnaryOperator::Typeof => UnaryOp::Typeof,
        UnaryOperator::Void => UnaryOp::Void,
        UnaryOperator::Delete => UnaryOp::Delete,
    }
}

const fn map_update(op: UpdateOperator) -> UpdateOp {
    match op {
        UpdateOperator::Increment => UpdateOp::Inc,
        UpdateOperator::Decrement => UpdateOp::Dec,
    }
}

const fn map_logical(op: LogicalOperator) -> LogicalOp {
    match op {
        LogicalOperator::And => LogicalOp::And,
        LogicalOperator::Or => LogicalOp::Or,
        LogicalOperator::Coalesce => LogicalOp::Coalesce,
    }
}

const fn map_binary(op: BinaryOperator) -> BinaryOp {
    match op {
        BinaryOperator::Addition => BinaryOp::Add,
        BinaryOperator::Subtraction => BinaryOp::Sub,
        BinaryOperator::Multiplication => BinaryOp::Mul,
        BinaryOperator::Division => BinaryOp::Div,
        BinaryOperator::Remainder => BinaryOp::Mod,
        BinaryOperator::Exponential => BinaryOp::Pow,
        BinaryOperator::Equality => BinaryOp::Eq,
        BinaryOperator::Inequality => BinaryOp::Neq,
        BinaryOperator::StrictEquality => BinaryOp::StrictEq,
        BinaryOperator::StrictInequality => BinaryOp::StrictNeq,
        BinaryOperator::LessThan => BinaryOp::Lt,
        BinaryOperator::LessEqualThan => BinaryOp::Lte,
        BinaryOperator::GreaterThan => BinaryOp::Gt,
        BinaryOperator::GreaterEqualThan => BinaryOp::Gte,
        BinaryOperator::BitwiseOR => BinaryOp::BitOr,
        BinaryOperator::BitwiseAnd => BinaryOp::BitAnd,
        BinaryOperator::BitwiseXOR => BinaryOp::BitXor,
        BinaryOperator::ShiftLeft => BinaryOp::Shl,
        BinaryOperator::ShiftRight => BinaryOp::Shr,
        BinaryOperator::ShiftRightZeroFill => BinaryOp::UShr,
        BinaryOperator::In => BinaryOp::In,
        BinaryOperator::Instanceof => BinaryOp::Instanceof,
    }
}

const fn map_assign(op: AssignmentOperator) -> AssignOp {
    match op {
        AssignmentOperator::Assign => AssignOp::Assign,
        AssignmentOperator::Addition => AssignOp::Add,
        AssignmentOperator::Subtraction => AssignOp::Sub,
        AssignmentOperator::Multiplication => AssignOp::Mul,
        AssignmentOperator::Division => AssignOp::Div,
        AssignmentOperator::Remainder => AssignOp::Mod,
        AssignmentOperator::Exponential => AssignOp::Pow,
        AssignmentOperator::ShiftLeft => AssignOp::Shl,
        AssignmentOperator::ShiftRight => AssignOp::Shr,
        AssignmentOperator::ShiftRightZeroFill => AssignOp::UShr,
        AssignmentOperator::BitwiseOR => AssignOp::BitOr,
        AssignmentOperator::BitwiseXOR => AssignOp::BitXor,
        AssignmentOperator::BitwiseAnd => AssignOp::BitAnd,
        AssignmentOperator::LogicalOr => AssignOp::Or,
        AssignmentOperator::LogicalAnd => AssignOp::And,
        AssignmentOperator::LogicalNullish => AssignOp::Coalesce,
    }
}
