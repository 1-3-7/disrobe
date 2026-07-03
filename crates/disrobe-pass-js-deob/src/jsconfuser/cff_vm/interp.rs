use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use super::ir::{
    AssignOp, BinaryOp, Expr, FuncDef, LogicalOp, Param, PropKey, Stmt, UnaryOp, UpdateOp,
};
use super::value::{Closure, ObjRef, Scope, Value, WithScope};

const MAX_DENSE_ARRAY_ELEMENTS: usize = 1 << 20;

pub(super) struct Limits {
    pub max_steps: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self { max_steps: 200_000 }
    }
}

pub(super) struct Interp {
    pub limits: Limits,
    pub steps: usize,
    pub bailed: bool,
    fork_share_floor: usize,
    loop_name_seq: usize,
    relooped_names: Vec<String>,
}

impl Interp {
    const fn bail(&mut self) {
        self.bailed = true;
    }
}

#[derive(Debug, Clone)]
pub(super) enum Flow {
    Normal,
    Return(Value),
    Break(Option<String>),
    Continue(Option<String>),
    Bail,
}

pub(super) struct Ctx {
    scope: Scope,
    with_chain: Option<WithScope>,
    residual: Rc<RefCell<Vec<Stmt>>>,
    promote: Option<Rc<LoopPromote>>,
}

enum CarriedSlot {
    Ident(String),
    Member { object: ObjRef, key: String },
}

struct LoopPromote {
    carried: Vec<(CarriedSlot, String)>,
}

impl LoopPromote {
    fn fresh_for_ident(&self, name: &str) -> Option<&str> {
        self.carried
            .iter()
            .find_map(|(slot, fresh): &(CarriedSlot, String)| match slot {
                CarriedSlot::Ident(n) if n == name => Some(fresh.as_str()),
                _ => None,
            })
    }

    fn fresh_for_member(&self, object: &ObjRef, key: &str) -> Option<&str> {
        self.carried
            .iter()
            .find_map(|(slot, fresh): &(CarriedSlot, String)| match slot {
                CarriedSlot::Member { object: o, key: k } if Rc::ptr_eq(o, object) && k == key => {
                    Some(fresh.as_str())
                }
                _ => None,
            })
    }
}

impl Ctx {
    fn enter_with(&self, object: ObjRef) -> Self {
        Self {
            scope: self.scope.clone(),
            with_chain: Some(WithScope {
                object,
                parent: self.with_chain.clone().map(Box::new),
            }),
            residual: self.residual.clone(),
            promote: self.promote.clone(),
        }
    }

    fn child_scope(&self) -> Self {
        Self {
            scope: self.scope.child(),
            with_chain: self.with_chain.clone(),
            residual: self.residual.clone(),
            promote: self.promote.clone(),
        }
    }

    fn emit(&self, stmt: Stmt) {
        self.residual.borrow_mut().push(stmt);
    }
}

impl Interp {
    pub(super) const fn new(limits: Limits) -> Self {
        Self {
            limits,
            steps: 0,
            bailed: false,
            fork_share_floor: 0,
            loop_name_seq: 0,
            relooped_names: Vec::new(),
        }
    }

    const fn tick(&mut self) -> bool {
        self.steps += 1;
        if self.steps > self.limits.max_steps {
            self.bail();
            return false;
        }
        true
    }

    pub(super) fn run_program(&mut self, stmts: &[Stmt], scope: &Scope) -> (Vec<Stmt>, Flow) {
        let residual: Rc<RefCell<Vec<Stmt>>> = Rc::new(RefCell::new(Vec::new()));
        let ctx: Ctx = Ctx {
            scope: scope.clone(),
            with_chain: None,
            residual: residual.clone(),
            promote: None,
        };
        let flow: Flow = self.exec_block(stmts, &ctx);
        let mut out: Vec<Stmt> = residual.borrow().clone();
        if !self.relooped_names.is_empty() {
            let promoted: std::collections::BTreeSet<String> =
                self.relooped_names.iter().cloned().collect();
            prune_dead_relooped(&mut out, &promoted);
        }
        (out, flow)
    }

    fn exec_block(&mut self, stmts: &[Stmt], ctx: &Ctx) -> Flow {
        Self::hoist(stmts, ctx);
        for stmt in stmts {
            let flow: Flow = self.exec_stmt(stmt, ctx);
            if !matches!(flow, Flow::Normal) {
                return flow;
            }
            if self.bailed {
                return Flow::Bail;
            }
        }
        Flow::Normal
    }

    fn make_closure(def: &Rc<FuncDef>, ctx: &Ctx) -> Value {
        Value::Func(Rc::new(Closure {
            def: def.clone(),
            scope: ctx.scope.clone(),
            with_chain: ctx.with_chain.clone(),
        }))
    }

    fn hoist(stmts: &[Stmt], ctx: &Ctx) {
        for stmt in stmts {
            if let Stmt::FuncDecl(def) = stmt
                && let Some(name) = &def.name
            {
                ctx.scope.declare(name, Self::make_closure(def, ctx));
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn exec_stmt(&mut self, stmt: &Stmt, ctx: &Ctx) -> Flow {
        if !self.tick() {
            return Flow::Bail;
        }
        match stmt {
            Stmt::Empty | Stmt::FuncDecl(_) => Flow::Normal,
            Stmt::Block(body) => {
                let inner: Ctx = ctx.child_scope();
                self.exec_block(body, &inner)
            }
            Stmt::Expr(e) => {
                let value: Value = self.eval(e, ctx);
                if self.bailed {
                    return Flow::Bail;
                }
                if stmt_position_is_effectful(e) {
                    Self::emit_if_observable(&value, ctx);
                }
                Flow::Normal
            }
            Stmt::VarDecl { decls, .. } => {
                for (name, init) in decls {
                    let value: Value = init
                        .as_ref()
                        .map_or(Value::Undefined, |e| self.eval(e, ctx));
                    if self.bailed {
                        return Flow::Bail;
                    }
                    ctx.scope.declare(name, value);
                }
                Flow::Normal
            }
            Stmt::Return(arg) => {
                let value: Value = arg.as_ref().map_or(Value::Undefined, |e| self.eval(e, ctx));
                if self.bailed {
                    return Flow::Bail;
                }
                if arg.as_ref().is_some_and(stmt_position_is_effectful)
                    && Self::emit_if_observable(&value, ctx)
                {
                    return Flow::Return(Value::Undefined);
                }
                Flow::Return(value)
            }
            Stmt::Break(label) => Flow::Break(label.clone()),
            Stmt::Continue(label) => Flow::Continue(label.clone()),
            Stmt::Throw(_) | Stmt::Raw(_) | Stmt::Labeled { .. } => {
                self.bail();
                Flow::Bail
            }
            Stmt::If {
                test,
                consequent,
                alternate,
            } => {
                let cond: Value = self.eval(test, ctx);
                if self.bailed {
                    return Flow::Bail;
                }
                match cond.truthiness() {
                    Some(true) => {
                        let inner: Ctx = ctx.child_scope();
                        self.exec_block(consequent, &inner)
                    }
                    Some(false) => {
                        let inner: Ctx = ctx.child_scope();
                        self.exec_block(alternate, &inner)
                    }
                    None => {
                        self.bail();
                        Flow::Bail
                    }
                }
            }
            Stmt::While { test, body } => self.exec_while(test, body, ctx),
            Stmt::DoWhile { body, test } => self.exec_do_while(body, test, ctx),
            Stmt::For {
                init,
                test,
                update,
                body,
            } => self.exec_for(init.as_deref(), test.as_ref(), update.as_ref(), body, ctx),
            Stmt::Switch {
                discriminant,
                cases,
            } => self.exec_switch(discriminant, cases, ctx),
            Stmt::With { object, body } => {
                let obj_val: Value = self.eval(object, ctx);
                if self.bailed {
                    return Flow::Bail;
                }
                let Value::Object(obj_ref): Value = obj_val else {
                    self.bail();
                    return Flow::Bail;
                };
                let inner: Ctx = ctx.enter_with(obj_ref);
                self.exec_block(body, &inner)
            }
            Stmt::ForIn { left, right, body } => self.exec_for_in(left, right, body, ctx),
            Stmt::ForOf { left, right, body } => self.exec_for_of(left, right, body, ctx),
        }
    }

    fn exec_switch(
        &mut self,
        discriminant: &Expr,
        cases: &[super::ir::SwitchCase],
        ctx: &Ctx,
    ) -> Flow {
        let disc: Value = self.eval(discriminant, ctx);
        if self.bailed {
            return Flow::Bail;
        }
        let inner: Ctx = ctx.child_scope();
        let mut matched: Option<usize> = None;
        for (idx, case) in cases.iter().enumerate() {
            let Some(test) = &case.test else {
                continue;
            };
            let test_val: Value = self.eval(test, &inner);
            if self.bailed {
                return Flow::Bail;
            }
            match strict_equals(&disc, &test_val) {
                Some(true) => {
                    matched = Some(idx);
                    break;
                }
                Some(false) => {}
                None => {
                    self.bail();
                    return Flow::Bail;
                }
            }
        }
        let start: usize = match matched {
            Some(i) => i,
            None => match cases.iter().position(|c| c.test.is_none()) {
                Some(i) => i,
                None => return Flow::Normal,
            },
        };
        for case in &cases[start..] {
            match self.exec_block(&case.body, &inner) {
                Flow::Normal => {}
                Flow::Break(None) => return Flow::Normal,
                other => return other,
            }
        }
        Flow::Normal
    }

    fn exec_for_in(&mut self, left: &Stmt, right: &Expr, body: &[Stmt], ctx: &Ctx) -> Flow {
        let obj: Value = self.eval(right, ctx);
        if self.bailed {
            return Flow::Bail;
        }
        let keys: Vec<String> = match &obj {
            Value::Object(map) => map.borrow().keys().cloned().collect(),
            Value::Array(items) => (0..items.borrow().len()).map(|i| i.to_string()).collect(),
            _ => return Flow::Bail,
        };
        let loop_ctx: Ctx = ctx.child_scope();
        for key in keys {
            if !self.tick() {
                return Flow::Bail;
            }
            self.bind_for_target(left, Value::Str(key), &loop_ctx);
            let inner: Ctx = loop_ctx.child_scope();
            match self.exec_block(body, &inner) {
                Flow::Normal | Flow::Continue(None) => {}
                Flow::Break(None) => return Flow::Normal,
                other => return other,
            }
        }
        Flow::Normal
    }

    fn exec_for_of(&mut self, left: &Stmt, right: &Expr, body: &[Stmt], ctx: &Ctx) -> Flow {
        let iterable: Value = self.eval(right, ctx);
        if self.bailed {
            return Flow::Bail;
        }
        let items: Vec<Value> = match &iterable {
            Value::Array(arr) => arr.borrow().clone(),
            Value::Str(s) => s.chars().map(|c| Value::Str(c.to_string())).collect(),
            _ => return Flow::Bail,
        };
        let loop_ctx: Ctx = ctx.child_scope();
        for item in items {
            if !self.tick() {
                return Flow::Bail;
            }
            self.bind_for_target(left, item, &loop_ctx);
            let inner: Ctx = loop_ctx.child_scope();
            match self.exec_block(body, &inner) {
                Flow::Normal | Flow::Continue(None) => {}
                Flow::Break(None) => return Flow::Normal,
                other => return other,
            }
        }
        Flow::Normal
    }

    fn bind_for_target(&mut self, left: &Stmt, value: Value, ctx: &Ctx) {
        match left {
            Stmt::VarDecl { decls, .. } => {
                if let Some((name, _)) = decls.first() {
                    ctx.scope.declare(name, value);
                }
            }
            Stmt::Expr(target) => self.assign_to(target, value, ctx),
            _ => self.bail(),
        }
    }

    fn exec_while(&mut self, test: &Expr, body: &[Stmt], ctx: &Ctx) -> Flow {
        if let Some(flow) = self.try_linearize_dispatcher(test, body, ctx) {
            return flow;
        }
        loop {
            if !self.tick() {
                return Flow::Bail;
            }
            let cond: Value = self.eval(test, ctx);
            if self.bailed {
                return Flow::Bail;
            }
            match cond.truthiness() {
                Some(true) => {}
                Some(false) => return Flow::Normal,
                None => return self.reloop_while(test, body, None, ctx),
            }
            let inner: Ctx = ctx.child_scope();
            match self.exec_block(body, &inner) {
                Flow::Normal | Flow::Continue(None) => {}
                Flow::Break(None) => return Flow::Normal,
                other => return other,
            }
        }
    }

    fn reloop_while(
        &mut self,
        test: &Expr,
        body: &[Stmt],
        update: Option<&Expr>,
        ctx: &Ctx,
    ) -> Flow {
        if ctx.promote.is_some() {
            self.bail();
            return Flow::Bail;
        }
        if !body_is_relockable(body) {
            self.bail();
            return Flow::Bail;
        }
        let carried: Vec<(CarriedSlot, String)> =
            match self.collect_carried(test, body, update, ctx) {
                Some(c) if !c.is_empty() => c,
                _ => {
                    self.bail();
                    return Flow::Bail;
                }
            };
        for (slot, fresh) in &carried {
            let current: Value = Self::read_carried(slot, ctx);
            if !value_is_materializable(&current) {
                self.bail();
                return Flow::Bail;
            }
            ctx.emit(Stmt::VarDecl {
                kind: super::ir::VarKind::Let,
                decls: vec![(fresh.clone(), Some(current.to_expr()))],
            });
        }
        let promote: Rc<LoopPromote> = Rc::new(LoopPromote { carried });
        for (slot, fresh) in &promote.carried {
            self.relooped_names.push(fresh.clone());
            Self::write_carried(slot, Value::Sym(Box::new(Expr::Ident(fresh.clone()))), ctx);
        }
        let body_residual: Rc<RefCell<Vec<Stmt>>> = Rc::new(RefCell::new(Vec::new()));
        let body_ctx: Ctx = Ctx {
            scope: ctx.scope.clone(),
            with_chain: ctx.with_chain.clone(),
            residual: body_residual.clone(),
            promote: Some(promote.clone()),
        };
        let cond_val: Value = self.eval(test, &body_ctx);
        if self.bailed {
            return Flow::Bail;
        }
        let Value::Sym(cond_expr): Value = cond_val else {
            self.bail();
            return Flow::Bail;
        };
        let flow: Flow = self.exec_block(body, &body_ctx);
        if self.bailed {
            return Flow::Bail;
        }
        if !matches!(flow, Flow::Normal | Flow::Continue(None)) {
            self.bail();
            return Flow::Bail;
        }
        if let Some(u) = update {
            let _ = self.eval(u, &body_ctx);
            if self.bailed {
                return Flow::Bail;
            }
        }
        let mut body_stmts: Vec<Stmt> = body_residual.borrow().clone();
        if body_stmts.is_empty() {
            self.bail();
            return Flow::Bail;
        }
        merge_self_assignments(&mut body_stmts, &promote.carried);
        ctx.emit(Stmt::While {
            test: (*cond_expr).clone(),
            body: body_stmts,
        });
        Flow::Normal
    }

    fn collect_carried(
        &mut self,
        test: &Expr,
        body: &[Stmt],
        update: Option<&Expr>,
        ctx: &Ctx,
    ) -> Option<Vec<(CarriedSlot, String)>> {
        let mut targets: Vec<Expr> = Vec::new();
        for stmt in body {
            collect_assign_targets(stmt, &mut targets);
        }
        if let Some(u) = update {
            collect_expr_assign_targets(u, &mut targets);
        }
        let mut carried: Vec<(CarriedSlot, String)> = Vec::new();
        let mut used: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        collect_reserved_idents(test, &mut used);
        for stmt in body {
            collect_reserved_idents_stmt(stmt, &mut used);
        }
        for target in &targets {
            let slot: CarriedSlot = self.resolve_carried_slot(target, ctx)?;
            if carried_contains(&carried, &slot) {
                continue;
            }
            let base: String = carried_base_name(&slot);
            let fresh: String = self.unique_loop_name(&base, &mut used);
            carried.push((slot, fresh));
        }
        Some(carried)
    }

    fn resolve_carried_slot(&mut self, target: &Expr, ctx: &Ctx) -> Option<CarriedSlot> {
        match target {
            Expr::Ident(name) => {
                if ctx
                    .with_chain
                    .as_ref()
                    .is_some_and(|w| w.resolve_write(name).is_some())
                {
                    let obj: ObjRef = ctx.with_chain.as_ref()?.resolve_write(name)?;
                    return Some(CarriedSlot::Member {
                        object: obj,
                        key: name.clone(),
                    });
                }
                Some(CarriedSlot::Ident(name.clone()))
            }
            Expr::Member {
                object, property, ..
            } => {
                let obj_val: Value = self.eval(object, ctx);
                let key: String = self.property_key(property, ctx)?;
                match obj_val {
                    Value::Object(obj_ref) => Some(CarriedSlot::Member {
                        object: obj_ref,
                        key,
                    }),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn read_carried(slot: &CarriedSlot, ctx: &Ctx) -> Value {
        match slot {
            CarriedSlot::Ident(name) => Self::read_ident(name, ctx),
            CarriedSlot::Member { object, key } => object
                .borrow()
                .get(key)
                .cloned()
                .unwrap_or(Value::Undefined),
        }
    }

    fn write_carried(slot: &CarriedSlot, value: Value, ctx: &Ctx) {
        match slot {
            CarriedSlot::Ident(name) => {
                if !ctx.scope.assign(name, value.clone()) {
                    ctx.scope.declare(name, value);
                }
            }
            CarriedSlot::Member { object, key } => {
                object.borrow_mut().insert(key.clone(), value);
            }
        }
    }

    fn unique_loop_name(
        &mut self,
        base: &str,
        used: &mut std::collections::BTreeSet<String>,
    ) -> String {
        loop {
            self.loop_name_seq += 1;
            let candidate: String = if self.loop_name_seq == 1 {
                format!("{base}_r")
            } else {
                format!("{base}_r{}", self.loop_name_seq)
            };
            if used.insert(candidate.clone()) {
                return candidate;
            }
        }
    }

    fn try_linearize_dispatcher(&mut self, test: &Expr, body: &[Stmt], ctx: &Ctx) -> Option<Flow> {
        let shape: super::dispatch::DispatcherShape<'_> =
            super::dispatch::match_dispatcher_parts(test, body)?;
        let initial_sum: f64 = self.eval(shape.state_sum, ctx).as_concrete_num()?;
        if self.bailed {
            return Some(Flow::Bail);
        }
        let mut visited: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        let (stmts, flow): (Vec<Stmt>, Flow) =
            self.linearize_path(&shape, initial_sum, ctx, &mut visited, 0);
        if self.bailed {
            return Some(Flow::Bail);
        }
        for stmt in stmts {
            ctx.emit(stmt);
        }
        Some(flow)
    }

    fn linearize_path(
        &mut self,
        shape: &super::dispatch::DispatcherShape<'_>,
        start_sum: f64,
        ctx: &Ctx,
        visited: &mut std::collections::BTreeSet<u64>,
        depth: usize,
    ) -> (Vec<Stmt>, Flow) {
        let mut out: Vec<Stmt> = Vec::new();
        let mut sum: f64 = start_sum;
        if depth > 256 {
            self.bail();
            return (out, Flow::Bail);
        }
        loop {
            if !self.tick() {
                return (out, Flow::Bail);
            }
            if (sum - shape.terminal).abs() < f64::EPSILON {
                return (out, Flow::Normal);
            }
            if !visited.insert(sum.to_bits()) {
                self.bail();
                return (out, Flow::Bail);
            }
            let local_residual: Rc<RefCell<Vec<Stmt>>> = Rc::new(RefCell::new(Vec::new()));
            let with_object: ObjRef = if let Value::Object(o) = self.eval(shape.with_object, ctx) {
                o
            } else {
                self.bail();
                return (out, Flow::Bail);
            };
            let block_ctx: Ctx = Self::ctx_over(
                &ctx.scope,
                &with_object,
                ctx.with_chain.as_ref(),
                &local_residual,
            );
            let Some(case_body): Option<&[Stmt]> =
                self.select_case_body(shape.cases, sum, &block_ctx)
            else {
                if self.bailed {
                    return (out, Flow::Bail);
                }
                self.bail();
                return (out, Flow::Bail);
            };
            let exit: super::dispatch::BlockExit =
                self.run_block_until_transition(case_body, shape, &block_ctx);
            out.extend(local_residual.borrow().iter().cloned());
            if self.bailed {
                return (out, Flow::Bail);
            }
            match exit {
                super::dispatch::BlockExit::Goto(next) => {
                    sum = next;
                }
                super::dispatch::BlockExit::Return(v) => {
                    return (out, Flow::Return(v));
                }
                super::dispatch::BlockExit::Branch {
                    test,
                    then_edge,
                    else_edge,
                } => {
                    let then_ctx: Ctx = Ctx {
                        scope: then_edge.scope,
                        with_chain: then_edge.with_chain,
                        residual: Rc::new(RefCell::new(Vec::new())),
                        promote: None,
                    };
                    let mut then_visited: std::collections::BTreeSet<u64> = visited.clone();
                    let (then_stmts, then_flow): (Vec<Stmt>, Flow) = self.linearize_path(
                        shape,
                        then_edge.sum,
                        &then_ctx,
                        &mut then_visited,
                        depth + 1,
                    );
                    if self.bailed {
                        return (out, Flow::Bail);
                    }
                    let else_ctx: Ctx = Ctx {
                        scope: else_edge.scope,
                        with_chain: else_edge.with_chain,
                        residual: Rc::new(RefCell::new(Vec::new())),
                        promote: None,
                    };
                    let mut else_visited: std::collections::BTreeSet<u64> = visited.clone();
                    let (else_stmts, else_flow): (Vec<Stmt>, Flow) = self.linearize_path(
                        shape,
                        else_edge.sum,
                        &else_ctx,
                        &mut else_visited,
                        depth + 1,
                    );
                    if self.bailed {
                        return (out, Flow::Bail);
                    }
                    let merged: Flow = merge_branch_flow(&then_flow, &else_flow);
                    out.push(Stmt::If {
                        test,
                        consequent: finish_branch(then_stmts, then_flow),
                        alternate: finish_branch(else_stmts, else_flow),
                    });
                    return (out, merged);
                }
                super::dispatch::BlockExit::Bail => {
                    return (out, Flow::Bail);
                }
            }
        }
    }

    fn fork_ctx(&self, ctx: &Ctx) -> Ctx {
        let mut map: super::value::CloneMap = super::value::CloneMap::default();
        let scope: Scope = ctx.scope.deep_clone(&mut map);
        let with_chain: Option<WithScope> =
            clone_with_chain_above_floor(ctx.with_chain.as_ref(), self.fork_share_floor, &mut map);
        Ctx {
            scope,
            with_chain,
            residual: ctx.residual.clone(),
            promote: ctx.promote.clone(),
        }
    }

    fn select_case_body<'a>(
        &mut self,
        cases: &'a [super::ir::SwitchCase],
        sum: f64,
        ctx: &Ctx,
    ) -> Option<&'a [Stmt]> {
        let disc: Value = Value::Num(sum);
        let mut start: Option<usize> = None;
        for (idx, case) in cases.iter().enumerate() {
            let Some(test) = &case.test else {
                continue;
            };
            let test_val: Value = self.eval(test, ctx);
            if self.bailed {
                return None;
            }
            match strict_equals(&disc, &test_val) {
                Some(true) => {
                    start = Some(idx);
                    break;
                }
                Some(false) => {}
                None => {
                    self.bail();
                    return None;
                }
            }
        }
        let start: usize = start.or_else(|| cases.iter().position(|c| c.test.is_none()))?;
        Some(flatten_case_run(cases, start))
    }

    fn run_block_until_transition(
        &mut self,
        case_body: &[Stmt],
        shape: &super::dispatch::DispatcherShape<'_>,
        ctx: &Ctx,
    ) -> super::dispatch::BlockExit {
        let (actions, terminal): (Vec<&Stmt>, Option<&Stmt>) =
            super::dispatch::split_block_transition(case_body);
        for action in actions {
            match self.exec_stmt(action, ctx) {
                Flow::Normal => {}
                Flow::Return(v) => return super::dispatch::BlockExit::Return(v),
                Flow::Break(None) => {
                    return self.sum_exit(shape, ctx);
                }
                _ => return super::dispatch::BlockExit::Bail,
            }
            if self.bailed {
                return super::dispatch::BlockExit::Bail;
            }
        }
        match terminal {
            None => self.sum_exit(shape, ctx),
            Some(Stmt::Return(arg)) => self.eval_block_return(arg.as_ref(), ctx),
            Some(Stmt::If {
                test,
                consequent,
                alternate,
            }) => self.transition_branch(test, consequent, alternate, shape, ctx),
            _ => super::dispatch::BlockExit::Bail,
        }
    }

    fn eval_block_return(&mut self, arg: Option<&Expr>, ctx: &Ctx) -> super::dispatch::BlockExit {
        let value: Value = arg.map_or(Value::Undefined, |e| self.eval(e, ctx));
        if self.bailed {
            return super::dispatch::BlockExit::Bail;
        }
        if arg.is_some_and(stmt_position_is_effectful) && Self::emit_if_observable(&value, ctx) {
            return super::dispatch::BlockExit::Return(Value::Undefined);
        }
        super::dispatch::BlockExit::Return(value)
    }

    fn sum_exit(
        &mut self,
        shape: &super::dispatch::DispatcherShape<'_>,
        ctx: &Ctx,
    ) -> super::dispatch::BlockExit {
        let sum: Option<f64> = self.eval(shape.state_sum, ctx).as_concrete_num();
        sum.map_or_else(
            || {
                self.bail();
                super::dispatch::BlockExit::Bail
            },
            super::dispatch::BlockExit::Goto,
        )
    }

    fn transition_branch(
        &mut self,
        test: &Expr,
        consequent: &[Stmt],
        alternate: &[Stmt],
        shape: &super::dispatch::DispatcherShape<'_>,
        ctx: &Ctx,
    ) -> super::dispatch::BlockExit {
        let cond: Value = self.eval(test, ctx);
        if self.bailed {
            return super::dispatch::BlockExit::Bail;
        }
        match cond.truthiness() {
            Some(true) => self.run_transition_arm(consequent, shape, ctx),
            Some(false) => self.run_transition_arm(alternate, shape, ctx),
            None => {
                let then_ctx: Ctx = self.fork_ctx(ctx);
                let Some(then_sum): Option<f64> =
                    self.eval_transition_sum(consequent, shape, &then_ctx)
                else {
                    if !self.bailed {
                        self.bail();
                    }
                    return super::dispatch::BlockExit::Bail;
                };
                let else_ctx: Ctx = self.fork_ctx(ctx);
                let Some(else_sum): Option<f64> =
                    self.eval_transition_sum(alternate, shape, &else_ctx)
                else {
                    if !self.bailed {
                        self.bail();
                    }
                    return super::dispatch::BlockExit::Bail;
                };
                super::dispatch::BlockExit::Branch {
                    test: cond.to_expr(),
                    then_edge: Box::new(super::dispatch::BranchEdge {
                        sum: then_sum,
                        scope: then_ctx.scope,
                        with_chain: then_ctx.with_chain,
                    }),
                    else_edge: Box::new(super::dispatch::BranchEdge {
                        sum: else_sum,
                        scope: else_ctx.scope,
                        with_chain: else_ctx.with_chain,
                    }),
                }
            }
        }
    }

    fn run_transition_arm(
        &mut self,
        arm: &[Stmt],
        shape: &super::dispatch::DispatcherShape<'_>,
        ctx: &Ctx,
    ) -> super::dispatch::BlockExit {
        for stmt in arm {
            match self.exec_stmt(stmt, ctx) {
                Flow::Normal => {}
                Flow::Break(None) => return self.sum_exit(shape, ctx),
                Flow::Return(v) => return super::dispatch::BlockExit::Return(v),
                _ => return super::dispatch::BlockExit::Bail,
            }
            if self.bailed {
                return super::dispatch::BlockExit::Bail;
            }
        }
        self.sum_exit(shape, ctx)
    }

    fn eval_transition_sum(
        &mut self,
        arm: &[Stmt],
        shape: &super::dispatch::DispatcherShape<'_>,
        ctx: &Ctx,
    ) -> Option<f64> {
        for stmt in arm {
            match self.exec_stmt(stmt, ctx) {
                Flow::Normal | Flow::Break(None) => {}
                _ => return None,
            }
            if self.bailed {
                return None;
            }
        }
        self.eval(shape.state_sum, ctx).as_concrete_num()
    }

    fn exec_do_while(&mut self, body: &[Stmt], test: &Expr, ctx: &Ctx) -> Flow {
        loop {
            if !self.tick() {
                return Flow::Bail;
            }
            let inner: Ctx = ctx.child_scope();
            match self.exec_block(body, &inner) {
                Flow::Normal | Flow::Continue(None) => {}
                Flow::Break(None) => return Flow::Normal,
                other => return other,
            }
            let cond: Value = self.eval(test, ctx);
            if self.bailed {
                return Flow::Bail;
            }
            match cond.truthiness() {
                Some(true) => {}
                Some(false) => return Flow::Normal,
                None => return Flow::Bail,
            }
        }
    }

    fn exec_for(
        &mut self,
        init: Option<&Stmt>,
        test: Option<&Expr>,
        update: Option<&Expr>,
        body: &[Stmt],
        ctx: &Ctx,
    ) -> Flow {
        let loop_ctx: Ctx = ctx.child_scope();
        if let Some(i) = init {
            let flow: Flow = self.exec_stmt(i, &loop_ctx);
            if !matches!(flow, Flow::Normal) {
                return flow;
            }
        }
        loop {
            if !self.tick() {
                return Flow::Bail;
            }
            if let Some(t) = test {
                let cond: Value = self.eval(t, &loop_ctx);
                if self.bailed {
                    return Flow::Bail;
                }
                match cond.truthiness() {
                    Some(true) => {}
                    Some(false) => return Flow::Normal,
                    None => return self.reloop_while(t, body, update, &loop_ctx),
                }
            }
            let inner: Ctx = loop_ctx.child_scope();
            match self.exec_block(body, &inner) {
                Flow::Normal | Flow::Continue(None) => {}
                Flow::Break(None) => return Flow::Normal,
                other => return other,
            }
            if let Some(u) = update {
                let _ = self.eval(u, &loop_ctx);
                if self.bailed {
                    return Flow::Bail;
                }
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn eval(&mut self, expr: &Expr, ctx: &Ctx) -> Value {
        if !self.tick() {
            return Value::Undefined;
        }
        match expr {
            Expr::Num(n) => Value::Num(*n),
            Expr::Str(s) => Value::Str(s.clone()),
            Expr::Bool(b) => Value::Bool(*b),
            Expr::Null => Value::Null,
            Expr::Undefined => Value::Undefined,
            Expr::This => Value::Sym(Box::new(Expr::This)),
            Expr::Raw(_) => Self::bail_sym(expr),
            Expr::Ident(name) => Self::read_ident(name, ctx),
            Expr::Template { quasis, exprs } => self.eval_template(quasis, exprs, ctx),
            Expr::Member { .. } => {
                if let Some(v) = self.try_generator_drive(expr, ctx) {
                    return v;
                }
                self.eval_member(expr, ctx)
            }
            Expr::Unary { op, argument } => self.eval_unary(*op, argument, ctx),
            Expr::Update {
                op,
                prefix,
                argument,
            } => self.eval_update(*op, *prefix, argument, ctx),
            Expr::Binary { op, left, right } => self.eval_binary(*op, left, right, ctx),
            Expr::Logical { op, left, right } => self.eval_logical(*op, left, right, ctx),
            Expr::Conditional {
                test,
                consequent,
                alternate,
            } => {
                let cond: Value = self.eval(test, ctx);
                match cond.truthiness() {
                    Some(true) => self.eval(consequent, ctx),
                    Some(false) => self.eval(alternate, ctx),
                    None => {
                        let c: Value = self.eval(consequent, ctx);
                        let a: Value = self.eval(alternate, ctx);
                        Value::Sym(Box::new(Expr::Conditional {
                            test: Box::new(cond.to_expr()),
                            consequent: Box::new(c.to_expr()),
                            alternate: Box::new(a.to_expr()),
                        }))
                    }
                }
            }
            Expr::Assign { op, target, value } => self.eval_assign(*op, target, value, ctx),
            Expr::ArrayDestructure { targets, value } => {
                self.eval_array_destructure(targets, value, ctx)
            }
            Expr::Array(elements) => self.eval_array(elements, ctx),
            Expr::Object(props) => self.eval_object(props, ctx),
            Expr::Sequence(exprs) => {
                let mut last: Value = Value::Undefined;
                for e in exprs {
                    last = self.eval(e, ctx);
                    if self.bailed {
                        return Value::Undefined;
                    }
                }
                last
            }
            Expr::Call {
                callee,
                args,
                spread_last,
            } => self.eval_call(callee, args, *spread_last, ctx),
            Expr::New { callee, args } => self.eval_new(callee, args, ctx),
            Expr::Func(def) => Self::make_closure(def, ctx),
            Expr::Spread(inner) => {
                let v: Value = self.eval(inner, ctx);
                Value::Sym(Box::new(Expr::Spread(Box::new(v.to_expr()))))
            }
        }
    }

    fn bail_sym(expr: &Expr) -> Value {
        Value::Sym(Box::new(expr.clone()))
    }

    fn emit_if_observable(value: &Value, ctx: &Ctx) -> bool {
        let Value::Sym(expr) = value else {
            return false;
        };
        if !expr_is_observable(expr) {
            return false;
        }
        ctx.emit(Stmt::Expr((**expr).clone()));
        true
    }

    fn read_ident(name: &str, ctx: &Ctx) -> Value {
        if let Some(with) = &ctx.with_chain
            && let Some(v) = with.resolve_read(name)
        {
            return v;
        }
        if let Some(v) = ctx.scope.lookup(name) {
            return v;
        }
        Value::Sym(Box::new(Expr::Ident(name.to_owned())))
    }

    fn eval_template(&mut self, quasis: &[String], exprs: &[Expr], ctx: &Ctx) -> Value {
        let mut all_concrete: bool = true;
        let mut parts: Vec<Value> = Vec::with_capacity(exprs.len());
        for e in exprs {
            let v: Value = self.eval(e, ctx);
            if !matches!(v, Value::Num(_) | Value::Str(_) | Value::Bool(_)) {
                all_concrete = false;
            }
            parts.push(v);
        }
        if all_concrete {
            let mut out: String = String::new();
            for (idx, quasi) in quasis.iter().enumerate() {
                out.push_str(quasi);
                if let Some(v) = parts.get(idx) {
                    out.push_str(&coerce_string(v));
                }
            }
            return Value::Str(out);
        }
        Value::Sym(Box::new(Expr::Template {
            quasis: quasis.to_vec(),
            exprs: parts.iter().map(Value::to_expr).collect(),
        }))
    }

    fn eval_unary(&mut self, op: UnaryOp, argument: &Expr, ctx: &Ctx) -> Value {
        let arg: Value = self.eval(argument, ctx);
        match op {
            UnaryOp::Neg => arg
                .as_concrete_num()
                .map_or_else(|| Self::sym_unary(op, &arg), |n| Value::Num(-n)),
            UnaryOp::Pos => arg
                .as_concrete_num()
                .map_or_else(|| Self::sym_unary(op, &arg), Value::Num),
            UnaryOp::Not => arg
                .truthiness()
                .map_or_else(|| Self::sym_unary(op, &arg), |b| Value::Bool(!b)),
            UnaryOp::BitNot => arg.as_concrete_num().map_or_else(
                || Self::sym_unary(op, &arg),
                |n| Value::Num(f64::from(!to_int32(n))),
            ),
            UnaryOp::Typeof => match &arg {
                Value::Num(_) => Value::Str("number".to_owned()),
                Value::Str(_) => Value::Str("string".to_owned()),
                Value::Bool(_) => Value::Str("boolean".to_owned()),
                Value::Undefined => Value::Str("undefined".to_owned()),
                Value::Func(_) => Value::Str("function".to_owned()),
                Value::Object(_) | Value::Array(_) | Value::Null => Value::Str("object".to_owned()),
                Value::Sym(_) => Self::sym_unary(op, &arg),
            },
            UnaryOp::Void => Value::Undefined,
            UnaryOp::Delete => Self::sym_unary(op, &arg),
        }
    }

    fn sym_unary(op: UnaryOp, arg: &Value) -> Value {
        Value::Sym(Box::new(Expr::Unary {
            op,
            argument: Box::new(arg.to_expr()),
        }))
    }

    fn eval_update(&mut self, op: UpdateOp, prefix: bool, argument: &Expr, ctx: &Ctx) -> Value {
        let current: Value = self.eval(argument, ctx);
        let delta: f64 = if matches!(op, UpdateOp::Inc) {
            1.0
        } else {
            -1.0
        };
        if let Some(n) = current.as_concrete_num() {
            let next: Value = Value::Num(n + delta);
            self.assign_to(argument, next.clone(), ctx);
            if prefix { next } else { Value::Num(n) }
        } else {
            let next: Value = Value::Sym(Box::new(Expr::Binary {
                op: if matches!(op, UpdateOp::Inc) {
                    BinaryOp::Add
                } else {
                    BinaryOp::Sub
                },
                left: Box::new(current.to_expr()),
                right: Box::new(Expr::Num(1.0)),
            }));
            self.assign_to(argument, next.clone(), ctx);
            next
        }
    }

    fn eval_binary(&mut self, op: BinaryOp, left: &Expr, right: &Expr, ctx: &Ctx) -> Value {
        let l: Value = self.eval(left, ctx);
        let r: Value = self.eval(right, ctx);
        if self.bailed {
            return Value::Undefined;
        }
        if let Some(v) = fold_binary(op, &l, &r) {
            return v;
        }
        Value::Sym(Box::new(Expr::Binary {
            op,
            left: Box::new(l.to_expr()),
            right: Box::new(r.to_expr()),
        }))
    }

    fn eval_logical(&mut self, op: LogicalOp, left: &Expr, right: &Expr, ctx: &Ctx) -> Value {
        let l: Value = self.eval(left, ctx);
        match op {
            LogicalOp::And => match l.truthiness() {
                Some(false) => l,
                Some(true) => self.eval(right, ctx),
                None => self.sym_logical(op, &l, right, ctx),
            },
            LogicalOp::Or => match l.truthiness() {
                Some(true) => l,
                Some(false) => self.eval(right, ctx),
                None => self.sym_logical(op, &l, right, ctx),
            },
            LogicalOp::Coalesce => match &l {
                Value::Null | Value::Undefined => self.eval(right, ctx),
                Value::Sym(_) => self.sym_logical(op, &l, right, ctx),
                _ => l,
            },
        }
    }

    fn sym_logical(&mut self, op: LogicalOp, l: &Value, right: &Expr, ctx: &Ctx) -> Value {
        let r: Value = self.eval(right, ctx);
        Value::Sym(Box::new(Expr::Logical {
            op,
            left: Box::new(l.to_expr()),
            right: Box::new(r.to_expr()),
        }))
    }

    fn eval_array(&mut self, elements: &[Option<Expr>], ctx: &Ctx) -> Value {
        let mut items: Vec<Value> = Vec::with_capacity(elements.len());
        for el in elements {
            match el {
                Some(e) => {
                    let v: Value = self.eval(e, ctx);
                    items.push(v);
                }
                None => items.push(Value::Undefined),
            }
            if self.bailed {
                return Value::Undefined;
            }
        }
        Value::Array(Rc::new(RefCell::new(items)))
    }

    fn eval_object(&mut self, props: &[(PropKey, Expr)], ctx: &Ctx) -> Value {
        let map: Rc<RefCell<BTreeMap<String, Value>>> = Rc::new(RefCell::new(BTreeMap::new()));
        for (key, value_expr) in props {
            let key_str: Option<String> = match key {
                PropKey::Ident(s) | PropKey::Str(s) => Some(s.clone()),
                PropKey::Num(n) => Some(super::emit::format_number(*n)),
                PropKey::Computed(e) => {
                    if matches!(value_expr, Expr::Spread(_)) {
                        None
                    } else {
                        let kv: Value = self.eval(e, ctx);
                        Some(coerce_string(&kv))
                    }
                }
            };
            let Some(k): Option<String> = key_str else {
                return Self::bail_sym(&Expr::Object(props.to_vec()));
            };
            let v: Value = self.eval(value_expr, ctx);
            if self.bailed {
                return Value::Undefined;
            }
            map.borrow_mut().insert(k, v);
        }
        Value::Object(map)
    }

    fn eval_assign(&mut self, op: AssignOp, target: &Expr, value: &Expr, ctx: &Ctx) -> Value {
        let rhs: Value = self.eval(value, ctx);
        if self.bailed {
            return Value::Undefined;
        }
        let new_value: Value = if matches!(op, AssignOp::Assign) {
            rhs
        } else {
            let current: Value = self.eval(target, ctx);
            apply_compound(op, &current, &rhs)
        };
        self.assign_to(target, new_value.clone(), ctx);
        new_value
    }

    fn eval_array_destructure(
        &mut self,
        targets: &[Option<Expr>],
        value: &Expr,
        ctx: &Ctx,
    ) -> Value {
        let rhs: Value = self.eval(value, ctx);
        if self.bailed {
            return Value::Undefined;
        }
        let elements: Vec<Value> = match &rhs {
            Value::Array(items) => items.borrow().clone(),
            Value::Sym(e) => targets
                .iter()
                .enumerate()
                .map(|(idx, _)| {
                    Value::Sym(Box::new(Expr::Member {
                        object: Box::new((**e).clone()),
                        property: Box::new(Expr::Num(idx as f64)),
                        computed: true,
                    }))
                })
                .collect(),
            _ => {
                self.bail();
                return Value::Undefined;
            }
        };
        for (idx, target) in targets.iter().enumerate() {
            if let Some(t) = target {
                let v: Value = elements.get(idx).cloned().unwrap_or(Value::Undefined);
                self.assign_to(t, v, ctx);
            }
        }
        rhs
    }

    fn assign_to(&mut self, target: &Expr, value: Value, ctx: &Ctx) {
        if ctx.promote.is_some() && self.assign_promoted(target, &value, ctx) {
            return;
        }
        match target {
            Expr::Ident(name) => {
                if let Some(with) = &ctx.with_chain
                    && let Some(obj) = with.resolve_write(name)
                {
                    obj.borrow_mut().insert(name.clone(), value);
                    return;
                }
                if !ctx.scope.assign(name, value.clone()) {
                    ctx.scope.declare(name, value);
                }
            }
            Expr::Member {
                object, property, ..
            } => {
                let obj_val: Value = self.eval(object, ctx);
                let key: Option<String> = self.property_key(property, ctx);
                match (obj_val, key) {
                    (Value::Object(obj_ref), Some(k)) => {
                        obj_ref.borrow_mut().insert(k, value);
                    }
                    (Value::Array(arr_ref), Some(k)) => {
                        if let Ok(idx) = k.parse::<usize>() {
                            let Some(required_len): Option<usize> = idx
                                .checked_add(1)
                                .filter(|len: &usize| *len <= MAX_DENSE_ARRAY_ELEMENTS)
                            else {
                                self.bail();
                                return;
                            };
                            let mut arr: std::cell::RefMut<'_, Vec<Value>> = arr_ref.borrow_mut();
                            if arr.len() < required_len {
                                arr.resize(required_len, Value::Undefined);
                            }
                            arr[idx] = value;
                        } else {
                            self.bail();
                        }
                    }
                    _ => self.bail(),
                }
            }
            _ => self.bail(),
        }
    }

    fn assign_promoted(&mut self, target: &Expr, value: &Value, ctx: &Ctx) -> bool {
        let Some(promote): Option<Rc<LoopPromote>> = ctx.promote.clone() else {
            return false;
        };
        let fresh: Option<String> = match target {
            Expr::Ident(name) => {
                if let Some(with) = &ctx.with_chain
                    && let Some(obj) = with.resolve_write(name)
                {
                    promote.fresh_for_member(&obj, name).map(str::to_owned)
                } else {
                    promote.fresh_for_ident(name).map(str::to_owned)
                }
            }
            Expr::Member {
                object, property, ..
            } => {
                let obj_val: Value = self.eval(object, ctx);
                let Value::Object(obj_ref): Value = obj_val else {
                    return false;
                };
                let Some(key): Option<String> = self.property_key(property, ctx) else {
                    return false;
                };
                promote.fresh_for_member(&obj_ref, &key).map(str::to_owned)
            }
            _ => None,
        };
        let Some(fresh): Option<String> = fresh else {
            return false;
        };
        ctx.emit(Stmt::Expr(Expr::Assign {
            op: AssignOp::Assign,
            target: Box::new(Expr::Ident(fresh.clone())),
            value: Box::new(value.to_expr()),
        }));
        match target {
            Expr::Ident(name) => {
                if let Some(with) = &ctx.with_chain
                    && let Some(obj) = with.resolve_write(name)
                {
                    obj.borrow_mut()
                        .insert(name.clone(), Value::Sym(Box::new(Expr::Ident(fresh))));
                } else if !ctx
                    .scope
                    .assign(name, Value::Sym(Box::new(Expr::Ident(fresh.clone()))))
                {
                    ctx.scope
                        .declare(name, Value::Sym(Box::new(Expr::Ident(fresh))));
                }
            }
            Expr::Member {
                object, property, ..
            } => {
                let obj_val: Value = self.eval(object, ctx);
                if let (Value::Object(obj_ref), Some(key)) =
                    (obj_val, self.property_key(property, ctx))
                {
                    obj_ref
                        .borrow_mut()
                        .insert(key, Value::Sym(Box::new(Expr::Ident(fresh))));
                }
            }
            _ => {}
        }
        true
    }

    fn property_key(&mut self, property: &Expr, ctx: &Ctx) -> Option<String> {
        let key_val: Value = self.eval(property, ctx);
        match key_val {
            Value::Str(s) => Some(s),
            Value::Num(n) => Some(super::emit::format_number(n)),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }

    fn eval_member(&mut self, expr: &Expr, ctx: &Ctx) -> Value {
        let Expr::Member {
            object, property, ..
        } = expr
        else {
            return self.eval(expr, ctx);
        };
        let obj_val: Value = self.eval(object, ctx);
        if self.bailed {
            return Value::Undefined;
        }
        let key: Option<String> = self.property_key(property, ctx);
        match (&obj_val, &key) {
            (Value::Object(obj_ref), Some(k)) => {
                obj_ref.borrow().get(k).cloned().unwrap_or(Value::Undefined)
            }
            (Value::Array(arr_ref), Some(k)) => {
                if k == "length" {
                    return Value::Num(arr_ref.borrow().len() as f64);
                }
                if let Ok(idx) = k.parse::<usize>() {
                    return arr_ref
                        .borrow()
                        .get(idx)
                        .cloned()
                        .unwrap_or(Value::Undefined);
                }
                self.member_sym(&obj_val, property, ctx)
            }
            (Value::Str(s), Some(k)) => {
                if k == "length" {
                    return Value::Num(s.chars().count() as f64);
                }
                self.member_sym(&obj_val, property, ctx)
            }
            _ => self.member_sym(&obj_val, property, ctx),
        }
    }

    fn member_sym(&mut self, obj_val: &Value, property: &Expr, ctx: &Ctx) -> Value {
        let key_val: Value = self.eval(property, ctx);
        Value::Sym(Box::new(Expr::Member {
            object: Box::new(obj_val.to_expr()),
            property: Box::new(key_val.to_expr()),
            computed: true,
        }))
    }

    #[allow(clippy::too_many_lines)]
    fn eval_call(&mut self, callee: &Expr, args: &[Expr], spread_last: bool, ctx: &Ctx) -> Value {
        let (callee_val, receiver): (Value, Option<Value>) = self.eval_callee(callee, ctx);
        if self.bailed {
            return Value::Undefined;
        }
        let mut arg_vals: Vec<Value> = Vec::with_capacity(args.len());
        for (idx, a) in args.iter().enumerate() {
            let v: Value = self.eval(a, ctx);
            if spread_last && idx + 1 == args.len() {
                match &v {
                    Value::Array(items) => arg_vals.extend(items.borrow().iter().cloned()),
                    _ => {
                        return self.call_sym(callee, args, spread_last, ctx);
                    }
                }
            } else {
                arg_vals.push(v);
            }
            if self.bailed {
                return Value::Undefined;
            }
        }

        if let Value::Func(closure) = &callee_val {
            if let Some(v) = self.call_user_func(closure, &arg_vals, ctx) {
                return v;
            }
            if self.bailed {
                return Value::Undefined;
            }
        }

        if let Some(v) = Self::builtin_call(callee, receiver.as_ref(), &arg_vals) {
            return v;
        }

        self.call_sym(callee, args, spread_last, ctx)
    }

    fn bind_params(&mut self, scope: &Scope, params: &[Param], args: &[Value]) {
        let bind_ctx: Ctx = Ctx {
            scope: scope.clone(),
            with_chain: None,
            residual: Rc::new(RefCell::new(Vec::new())),
            promote: None,
        };
        for (idx, param) in params.iter().enumerate() {
            if param.rest {
                let rest: Vec<Value> = args.get(idx..).map(<[Value]>::to_vec).unwrap_or_default();
                scope.declare(&param.name, Value::Array(Rc::new(RefCell::new(rest))));
                return;
            }
            let provided: Option<Value> = args.get(idx).cloned();
            let value: Value = match provided {
                Some(Value::Undefined) | None => param
                    .default
                    .as_ref()
                    .map_or(Value::Undefined, |default_expr| {
                        self.eval(default_expr, &bind_ctx)
                    }),
                Some(v) => v,
            };
            scope.declare(&param.name, value);
        }
    }

    fn try_generator_drive(&mut self, expr: &Expr, ctx: &Ctx) -> Option<Value> {
        let gen_call: &Expr = unwrap_next_value(expr)?;
        let Expr::Call {
            callee,
            args,
            spread_last,
        } = gen_call
        else {
            return None;
        };
        let (callee_val, _): (Value, Option<Value>) = self.eval_callee(callee, ctx);
        let Value::Func(closure) = &callee_val else {
            return None;
        };
        if !closure.def.is_generator {
            return None;
        }
        let mut arg_vals: Vec<Value> = Vec::with_capacity(args.len());
        for (idx, a) in args.iter().enumerate() {
            let v: Value = self.eval(a, ctx);
            if *spread_last && idx + 1 == args.len() {
                match &v {
                    Value::Array(items) => arg_vals.extend(items.borrow().iter().cloned()),
                    _ => return None,
                }
            } else {
                arg_vals.push(v);
            }
            if self.bailed {
                return Some(Value::Undefined);
            }
        }
        Some(self.drive_generator(closure, &arg_vals, ctx))
    }

    fn drive_generator(&mut self, closure: &Closure, args: &[Value], ctx: &Ctx) -> Value {
        let call_scope: Scope = closure.scope.child();
        self.bind_params(&call_scope, &closure.def.params, args);
        let sub_residual: Rc<RefCell<Vec<Stmt>>> = Rc::new(RefCell::new(Vec::new()));
        let sub_ctx: Ctx = Ctx {
            scope: call_scope,
            with_chain: closure.with_chain.clone(),
            residual: sub_residual.clone(),
            promote: None,
        };
        let shared_floor: usize = closure.with_chain.as_ref().map_or(0, with_chain_depth);
        let prev_floor: usize = self.fork_share_floor;
        self.fork_share_floor = shared_floor;
        let flow: Flow = self.exec_block(&closure.def.body, &sub_ctx);
        self.fork_share_floor = prev_floor;
        let produced: Vec<Stmt> = sub_residual.borrow().clone();
        if produced.iter().any(residual_is_value_tree) {
            let mut body: Vec<Stmt> = produced;
            if let Flow::Return(v) = &flow
                && !matches!(v, Value::Undefined)
            {
                body.push(Stmt::Return(Some(v.to_expr())));
            }
            return Value::Sym(Box::new(wrap_iife(body)));
        }
        for stmt in produced {
            ctx.emit(stmt);
        }
        match flow {
            Flow::Return(v) => v,
            Flow::Normal => Value::Undefined,
            _ => {
                self.bail();
                Value::Undefined
            }
        }
    }

    fn ctx_over(
        scope: &Scope,
        with_object: &ObjRef,
        with_parent: Option<&WithScope>,
        residual: &Rc<RefCell<Vec<Stmt>>>,
    ) -> Ctx {
        Ctx {
            scope: scope.clone(),
            with_chain: Some(WithScope {
                object: with_object.clone(),
                parent: with_parent.cloned().map(Box::new),
            }),
            residual: residual.clone(),
            promote: None,
        }
    }

    fn eval_callee(&mut self, callee: &Expr, ctx: &Ctx) -> (Value, Option<Value>) {
        if let Expr::Member { object, .. } = callee {
            let recv: Value = self.eval(object, ctx);
            let value: Value = self.eval_member(callee, ctx);
            return (value, Some(recv));
        }
        if let Expr::Sequence(exprs) = callee
            && let Some(last) = exprs.last()
        {
            for e in &exprs[..exprs.len().saturating_sub(1)] {
                let _ = self.eval(e, ctx);
            }
            return self.eval_callee(last, ctx);
        }
        (self.eval(callee, ctx), None)
    }

    fn call_user_func(&mut self, closure: &Closure, args: &[Value], ctx: &Ctx) -> Option<Value> {
        if closure.def.is_generator {
            return None;
        }
        let call_scope: Scope = closure.scope.child();
        self.bind_params(&call_scope, &closure.def.params, args);
        if let Some(body) = &closure.def.expression_body {
            let sub_ctx: Ctx = Ctx {
                scope: call_scope,
                with_chain: closure.with_chain.clone(),
                residual: ctx.residual.clone(),
                promote: None,
            };
            let v: Value = self.eval(body, &sub_ctx);
            if self.bailed {
                return Some(Value::Undefined);
            }
            return Some(v);
        }
        let sub_ctx: Ctx = Ctx {
            scope: call_scope,
            with_chain: closure.with_chain.clone(),
            residual: ctx.residual.clone(),
            promote: None,
        };
        let flow: Flow = self.exec_block(&closure.def.body, &sub_ctx);
        match flow {
            Flow::Return(v) => Some(v),
            Flow::Normal => Some(Value::Undefined),
            _ => {
                self.bail();
                Some(Value::Undefined)
            }
        }
    }

    fn builtin_call(callee: &Expr, receiver: Option<&Value>, args: &[Value]) -> Option<Value> {
        let Expr::Member { property, .. } = callee else {
            return None;
        };
        let method: String = match property.as_ref() {
            Expr::Str(s) => s.clone(),
            _ => return None,
        };
        let recv: &Value = receiver?;
        match (recv, method.as_str()) {
            (Value::Array(items), "join") => {
                let sep: String = match args.first() {
                    Some(Value::Str(s)) => s.clone(),
                    Some(other) => coerce_string(other),
                    None => ",".to_owned(),
                };
                let parts: Vec<String> = items
                    .borrow()
                    .iter()
                    .map(|v: &Value| match v {
                        Value::Null | Value::Undefined => String::new(),
                        other => coerce_string(other),
                    })
                    .collect();
                if items
                    .borrow()
                    .iter()
                    .any(|v: &Value| matches!(v, Value::Sym(_) | Value::Object(_) | Value::Func(_)))
                {
                    return None;
                }
                Some(Value::Str(parts.join(&sep)))
            }
            (Value::Array(items), "push") => {
                let mut arr: std::cell::RefMut<'_, Vec<Value>> = items.borrow_mut();
                for a in args {
                    arr.push(a.clone());
                }
                Some(Value::Num(arr.len() as f64))
            }
            (Value::Str(s), "split") => {
                let sep: Option<String> = match args.first() {
                    Some(Value::Str(sep)) => Some(sep.clone()),
                    _ => None,
                };
                let sep: String = sep?;
                let parts: Vec<Value> = if sep.is_empty() {
                    s.chars().map(|c: char| Value::Str(c.to_string())).collect()
                } else {
                    s.split(&sep)
                        .map(|p: &str| Value::Str(p.to_owned()))
                        .collect()
                };
                Some(Value::Array(Rc::new(RefCell::new(parts))))
            }
            (Value::Str(s), "charCodeAt") => {
                let raw_idx: f64 = args
                    .first()
                    .and_then(Value::as_concrete_num)
                    .unwrap_or(f64::NAN);
                let code: Option<u32> = js_string_index(raw_idx)
                    .and_then(|idx: usize| s.chars().nth(idx))
                    .map(|c: char| c as u32);
                Some(code.map_or(Value::Num(f64::NAN), |c| Value::Num(f64::from(c))))
            }
            _ => None,
        }
    }

    fn call_sym(&mut self, callee: &Expr, args: &[Expr], spread_last: bool, ctx: &Ctx) -> Value {
        let callee_expr: Expr = self.eval(callee, ctx).to_expr();
        let arg_exprs: Vec<Expr> = args
            .iter()
            .map(|a: &Expr| self.eval(a, ctx).to_expr())
            .collect();
        Value::Sym(Box::new(Expr::Call {
            callee: Box::new(callee_expr),
            args: arg_exprs,
            spread_last,
        }))
    }

    fn eval_new(&mut self, callee: &Expr, args: &[Expr], ctx: &Ctx) -> Value {
        let callee_val: Value = self.eval(callee, ctx);
        let arg_exprs: Vec<Expr> = args
            .iter()
            .map(|a: &Expr| self.eval(a, ctx).to_expr())
            .collect();
        Value::Sym(Box::new(Expr::New {
            callee: Box::new(callee_val.to_expr()),
            args: arg_exprs,
        }))
    }
}

fn prune_dead_relooped(stmts: &mut Vec<Stmt>, promoted: &std::collections::BTreeSet<String>) {
    for stmt in stmts.iter_mut() {
        if let Stmt::While { body, .. } = stmt {
            prune_dead_relooped(body, promoted);
        }
    }
    let mut remove: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    for (idx, stmt) in stmts.iter().enumerate() {
        let Stmt::While { body, test } = stmt else {
            continue;
        };
        let carried: std::collections::BTreeSet<String> = loop_carried_names(body, promoted);
        if carried.is_empty() {
            continue;
        }
        if !loop_body_writes_only(body, &carried) {
            continue;
        }
        if stmt_block_has_sink_effect(body, &carried) || expr_has_sink_effect(test) {
            continue;
        }
        let mut decl_start: usize = idx;
        while decl_start > 0 {
            let prev: usize = decl_start - 1;
            if remove.contains(&prev) {
                decl_start = prev;
                continue;
            }
            if is_carried_decl(&stmts[prev], &carried) {
                decl_start = prev;
            } else {
                break;
            }
        }
        let external_reads: usize = stmts
            .iter()
            .enumerate()
            .filter(|(i, _): &(usize, &Stmt)| *i != idx && (*i < decl_start || *i > idx))
            .map(|(_, s): (usize, &Stmt)| count_name_reads_stmt(s, &carried))
            .sum();
        if external_reads == 0 {
            for d in decl_start..=idx {
                remove.insert(d);
            }
        }
    }
    if remove.is_empty() {
        return;
    }
    let mut idx: usize = 0;
    stmts.retain(|_| {
        let keep: bool = !remove.contains(&idx);
        idx += 1;
        keep
    });
}

fn loop_carried_names(
    body: &[Stmt],
    promoted: &std::collections::BTreeSet<String>,
) -> std::collections::BTreeSet<String> {
    let mut targets: Vec<Expr> = Vec::new();
    for stmt in body {
        collect_assign_targets(stmt, &mut targets);
    }
    targets
        .iter()
        .filter_map(|t: &Expr| match t {
            Expr::Ident(name) if promoted.contains(name) => Some(name.clone()),
            _ => None,
        })
        .collect()
}

fn loop_body_writes_only(body: &[Stmt], carried: &std::collections::BTreeSet<String>) -> bool {
    let mut targets: Vec<Expr> = Vec::new();
    for stmt in body {
        collect_assign_targets(stmt, &mut targets);
    }
    targets.iter().all(|t: &Expr| match t {
        Expr::Ident(name) => carried.contains(name),
        _ => false,
    })
}

fn is_carried_decl(stmt: &Stmt, carried: &std::collections::BTreeSet<String>) -> bool {
    let Stmt::VarDecl { decls, .. } = stmt else {
        return false;
    };
    decls.len() == 1
        && decls
            .first()
            .is_some_and(|(name, init): &(String, Option<Expr>)| {
                carried.contains(name) && init.as_ref().is_none_or(|e| !expr_has_sink_effect(e))
            })
}

fn stmt_block_has_sink_effect(body: &[Stmt], carried: &std::collections::BTreeSet<String>) -> bool {
    body.iter().any(|s: &Stmt| stmt_has_sink_effect(s, carried))
}

fn stmt_has_sink_effect(stmt: &Stmt, carried: &std::collections::BTreeSet<String>) -> bool {
    match stmt {
        Stmt::Expr(e) => assign_has_sink_effect(e, carried),
        Stmt::VarDecl { decls, .. } => decls.iter().any(|(_, init): &(String, Option<Expr>)| {
            init.as_ref().is_some_and(expr_has_sink_effect)
        }),
        Stmt::While { test, body } => {
            expr_has_sink_effect(test) || stmt_block_has_sink_effect(body, carried)
        }
        _ => true,
    }
}

fn assign_has_sink_effect(expr: &Expr, carried: &std::collections::BTreeSet<String>) -> bool {
    match expr {
        Expr::Assign { target, value, .. } => {
            let target_ok: bool =
                matches!(target.as_ref(), Expr::Ident(name) if carried.contains(name));
            !target_ok || expr_has_sink_effect(value)
        }
        Expr::Update { argument, .. } => {
            !matches!(argument.as_ref(), Expr::Ident(name) if carried.contains(name))
        }
        Expr::Sequence(exprs) => exprs
            .iter()
            .any(|e: &Expr| assign_has_sink_effect(e, carried)),
        other => expr_has_sink_effect(other),
    }
}

fn expr_has_sink_effect(expr: &Expr) -> bool {
    match expr {
        Expr::Call { callee, args, .. } => {
            !call_is_pure(callee) || args.iter().any(expr_has_sink_effect)
        }
        Expr::New { .. } | Expr::Assign { .. } | Expr::Update { .. } => true,
        Expr::Binary { left, right, .. } | Expr::Logical { left, right, .. } => {
            expr_has_sink_effect(left) || expr_has_sink_effect(right)
        }
        Expr::Unary { op, argument } => {
            matches!(op, UnaryOp::Delete) || expr_has_sink_effect(argument)
        }
        Expr::Member {
            object, property, ..
        } => expr_has_sink_effect(object) || expr_has_sink_effect(property),
        Expr::Conditional {
            test,
            consequent,
            alternate,
        } => {
            expr_has_sink_effect(test)
                || expr_has_sink_effect(consequent)
                || expr_has_sink_effect(alternate)
        }
        Expr::Sequence(exprs) | Expr::Template { exprs, .. } => {
            exprs.iter().any(expr_has_sink_effect)
        }
        Expr::Array(elements) => elements
            .iter()
            .any(|e: &Option<Expr>| e.as_ref().is_some_and(expr_has_sink_effect)),
        _ => false,
    }
}

fn js_string_index(n: f64) -> Option<usize> {
    if n.is_nan() {
        return Some(0);
    }
    if !n.is_finite() {
        return None;
    }
    let truncated: f64 = n.trunc();
    if truncated < 0.0 || truncated > usize::MAX as f64 {
        return None;
    }
    Some(truncated as usize)
}

fn call_is_pure(callee: &Expr) -> bool {
    match callee {
        Expr::Ident(name) => matches!(
            name.as_str(),
            "Number" | "String" | "Boolean" | "parseInt" | "parseFloat" | "isNaN" | "isFinite"
        ),
        Expr::Member {
            object, property, ..
        } => {
            let prop: Option<&str> = match property.as_ref() {
                Expr::Str(s) => Some(s.as_str()),
                _ => None,
            };
            let obj_pure: bool = match object.as_ref() {
                Expr::Ident(o) => matches!(o.as_str(), "Math" | "Number" | "String"),
                _ => false,
            };
            let string_method: bool = matches!(
                prop,
                Some(
                    "charCodeAt"
                        | "charAt"
                        | "slice"
                        | "substring"
                        | "substr"
                        | "toUpperCase"
                        | "toLowerCase"
                        | "trim"
                        | "indexOf"
                        | "length"
                )
            );
            obj_pure || string_method
        }
        _ => false,
    }
}

fn count_name_reads_stmt(stmt: &Stmt, names: &std::collections::BTreeSet<String>) -> usize {
    match stmt {
        Stmt::Expr(e) => count_name_reads_expr(e, names),
        Stmt::VarDecl { decls, .. } => decls
            .iter()
            .map(|(_, init): &(String, Option<Expr>)| {
                init.as_ref().map_or(0, |e| count_name_reads_expr(e, names))
            })
            .sum(),
        Stmt::While { test, body } => {
            count_name_reads_expr(test, names)
                + body
                    .iter()
                    .map(|s: &Stmt| count_name_reads_stmt(s, names))
                    .sum::<usize>()
        }
        Stmt::Return(arg) => arg.as_ref().map_or(0, |e| count_name_reads_expr(e, names)),
        Stmt::If {
            test,
            consequent,
            alternate,
        } => {
            count_name_reads_expr(test, names)
                + consequent
                    .iter()
                    .map(|s: &Stmt| count_name_reads_stmt(s, names))
                    .sum::<usize>()
                + alternate
                    .iter()
                    .map(|s: &Stmt| count_name_reads_stmt(s, names))
                    .sum::<usize>()
        }
        Stmt::Block(body) => body
            .iter()
            .map(|s: &Stmt| count_name_reads_stmt(s, names))
            .sum(),
        _ => 0,
    }
}

fn count_name_reads_expr(expr: &Expr, names: &std::collections::BTreeSet<String>) -> usize {
    match expr {
        Expr::Ident(name) => usize::from(names.contains(name)),
        Expr::Assign { target, value, .. } => {
            let target_reads: usize = match target.as_ref() {
                Expr::Ident(_) => 0,
                other => count_name_reads_expr(other, names),
            };
            target_reads + count_name_reads_expr(value, names)
        }
        Expr::Update { argument, .. } => match argument.as_ref() {
            Expr::Ident(_) => 0,
            other => count_name_reads_expr(other, names),
        },
        Expr::Member {
            object, property, ..
        } => count_name_reads_expr(object, names) + count_name_reads_expr(property, names),
        Expr::Unary { argument, .. } => count_name_reads_expr(argument, names),
        Expr::Binary { left, right, .. } | Expr::Logical { left, right, .. } => {
            count_name_reads_expr(left, names) + count_name_reads_expr(right, names)
        }
        Expr::Conditional {
            test,
            consequent,
            alternate,
        } => {
            count_name_reads_expr(test, names)
                + count_name_reads_expr(consequent, names)
                + count_name_reads_expr(alternate, names)
        }
        Expr::Call { callee, args, .. } => {
            count_name_reads_expr(callee, names)
                + args
                    .iter()
                    .map(|a: &Expr| count_name_reads_expr(a, names))
                    .sum::<usize>()
        }
        Expr::New { callee, args } => {
            count_name_reads_expr(callee, names)
                + args
                    .iter()
                    .map(|a: &Expr| count_name_reads_expr(a, names))
                    .sum::<usize>()
        }
        Expr::Sequence(exprs) => exprs
            .iter()
            .map(|e: &Expr| count_name_reads_expr(e, names))
            .sum(),
        Expr::Template { exprs, .. } => exprs
            .iter()
            .map(|e: &Expr| count_name_reads_expr(e, names))
            .sum(),
        Expr::Array(elements) => elements
            .iter()
            .map(|e: &Option<Expr>| e.as_ref().map_or(0, |x| count_name_reads_expr(x, names)))
            .sum(),
        _ => 0,
    }
}

fn body_is_relockable(body: &[Stmt]) -> bool {
    !body.is_empty() && body.iter().all(stmt_is_relockable)
}

fn stmt_is_relockable(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Expr(e) => expr_is_relockable(e),
        Stmt::VarDecl { decls, .. } => decls
            .iter()
            .all(|(_, init): &(String, Option<Expr>)| init.as_ref().is_none_or(expr_is_relockable)),
        Stmt::Empty => true,
        _ => false,
    }
}

fn expr_is_relockable(expr: &Expr) -> bool {
    match expr {
        Expr::Assign { target, value, .. } => {
            matches!(target.as_ref(), Expr::Ident(_) | Expr::Member { .. })
                && expr_is_relockable(value)
        }
        Expr::Update { argument, .. } => {
            matches!(argument.as_ref(), Expr::Ident(_) | Expr::Member { .. })
        }
        Expr::Sequence(exprs) => exprs.iter().all(expr_is_relockable),
        Expr::Num(_)
        | Expr::Str(_)
        | Expr::Bool(_)
        | Expr::Null
        | Expr::Undefined
        | Expr::Ident(_)
        | Expr::This
        | Expr::Template { .. } => true,
        Expr::Member {
            object, property, ..
        } => expr_is_relockable(object) && expr_is_relockable(property),
        Expr::Unary { argument, .. } => expr_is_relockable(argument),
        Expr::Binary { left, right, .. } | Expr::Logical { left, right, .. } => {
            expr_is_relockable(left) && expr_is_relockable(right)
        }
        Expr::Conditional {
            test,
            consequent,
            alternate,
        } => {
            expr_is_relockable(test)
                && expr_is_relockable(consequent)
                && expr_is_relockable(alternate)
        }
        Expr::Call { callee, args, .. } => {
            is_output_sink(callee) && args.iter().all(expr_is_relockable)
        }
        _ => false,
    }
}

fn value_is_materializable(value: &Value) -> bool {
    match value {
        Value::Num(_) | Value::Str(_) | Value::Bool(_) | Value::Null | Value::Undefined => true,
        Value::Sym(e) => expr_is_materializable(e),
        _ => false,
    }
}

fn expr_is_materializable(expr: &Expr) -> bool {
    match expr {
        Expr::Num(_)
        | Expr::Str(_)
        | Expr::Bool(_)
        | Expr::Null
        | Expr::Undefined
        | Expr::Ident(_) => true,
        Expr::Member {
            object, property, ..
        } => expr_is_materializable(object) && expr_is_materializable(property),
        Expr::Unary { argument, .. } => expr_is_materializable(argument),
        Expr::Binary { left, right, .. } | Expr::Logical { left, right, .. } => {
            expr_is_materializable(left) && expr_is_materializable(right)
        }
        Expr::Call { callee, args, .. } => {
            expr_is_materializable(callee) && args.iter().all(expr_is_materializable)
        }
        _ => false,
    }
}

fn collect_assign_targets(stmt: &Stmt, out: &mut Vec<Expr>) {
    match stmt {
        Stmt::Expr(e) => collect_expr_assign_targets(e, out),
        Stmt::VarDecl { decls, .. } => {
            for (_, init) in decls {
                if let Some(e) = init {
                    collect_expr_assign_targets(e, out);
                }
            }
        }
        _ => {}
    }
}

fn collect_expr_assign_targets(expr: &Expr, out: &mut Vec<Expr>) {
    match expr {
        Expr::Assign { target, value, .. } => {
            out.push((**target).clone());
            collect_expr_assign_targets(value, out);
        }
        Expr::Update { argument, .. } => out.push((**argument).clone()),
        Expr::Sequence(exprs) => {
            for e in exprs {
                collect_expr_assign_targets(e, out);
            }
        }
        _ => {}
    }
}

fn collect_reserved_idents(expr: &Expr, out: &mut std::collections::BTreeSet<String>) {
    match expr {
        Expr::Ident(name) => {
            out.insert(name.clone());
        }
        Expr::Member {
            object, property, ..
        } => {
            collect_reserved_idents(object, out);
            collect_reserved_idents(property, out);
        }
        Expr::Unary { argument, .. } | Expr::Update { argument, .. } => {
            collect_reserved_idents(argument, out);
        }
        Expr::Binary { left, right, .. } | Expr::Logical { left, right, .. } => {
            collect_reserved_idents(left, out);
            collect_reserved_idents(right, out);
        }
        Expr::Assign { target, value, .. } => {
            collect_reserved_idents(target, out);
            collect_reserved_idents(value, out);
        }
        Expr::Conditional {
            test,
            consequent,
            alternate,
        } => {
            collect_reserved_idents(test, out);
            collect_reserved_idents(consequent, out);
            collect_reserved_idents(alternate, out);
        }
        Expr::Call { callee, args, .. } => {
            collect_reserved_idents(callee, out);
            for a in args {
                collect_reserved_idents(a, out);
            }
        }
        Expr::Template { exprs, .. } | Expr::Sequence(exprs) => {
            for e in exprs {
                collect_reserved_idents(e, out);
            }
        }
        _ => {}
    }
}

fn collect_reserved_idents_stmt(stmt: &Stmt, out: &mut std::collections::BTreeSet<String>) {
    match stmt {
        Stmt::Expr(e) => collect_reserved_idents(e, out),
        Stmt::VarDecl { decls, .. } => {
            for (name, init) in decls {
                out.insert(name.clone());
                if let Some(e) = init {
                    collect_reserved_idents(e, out);
                }
            }
        }
        _ => {}
    }
}

fn carried_contains(carried: &[(CarriedSlot, String)], slot: &CarriedSlot) -> bool {
    carried
        .iter()
        .any(|(existing, _): &(CarriedSlot, String)| carried_slot_eq(existing, slot))
}

fn carried_slot_eq(a: &CarriedSlot, b: &CarriedSlot) -> bool {
    match (a, b) {
        (CarriedSlot::Ident(x), CarriedSlot::Ident(y)) => x == y,
        (
            CarriedSlot::Member {
                object: ox,
                key: kx,
            },
            CarriedSlot::Member {
                object: oy,
                key: ky,
            },
        ) => Rc::ptr_eq(ox, oy) && kx == ky,
        _ => false,
    }
}

fn carried_base_name(slot: &CarriedSlot) -> String {
    let raw: &str = match slot {
        CarriedSlot::Ident(name) => name,
        CarriedSlot::Member { key, .. } => key,
    };
    let cleaned: String = raw
        .chars()
        .filter(|c: &char| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if cleaned.is_empty() || cleaned.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        format!("v_{cleaned}")
    } else {
        cleaned
    }
}

fn merge_self_assignments(body: &mut Vec<Stmt>, carried: &[(CarriedSlot, String)]) {
    body.retain(|stmt: &Stmt| !is_self_assign(stmt, carried));
}

fn is_self_assign(stmt: &Stmt, carried: &[(CarriedSlot, String)]) -> bool {
    let Stmt::Expr(Expr::Assign {
        op: AssignOp::Assign,
        target,
        value,
    }) = stmt
    else {
        return false;
    };
    let (Expr::Ident(t), Expr::Ident(v)): (&Expr, &Expr) = (target.as_ref(), value.as_ref()) else {
        return false;
    };
    t == v
        && carried
            .iter()
            .any(|(_, fresh): &(CarriedSlot, String)| fresh == t)
}

fn apply_compound(op: AssignOp, current: &Value, rhs: &Value) -> Value {
    let bin: BinaryOp = match op {
        AssignOp::Add => BinaryOp::Add,
        AssignOp::Sub => BinaryOp::Sub,
        AssignOp::Mul => BinaryOp::Mul,
        AssignOp::Div => BinaryOp::Div,
        AssignOp::Mod => BinaryOp::Mod,
        AssignOp::Pow => BinaryOp::Pow,
        AssignOp::BitOr => BinaryOp::BitOr,
        AssignOp::BitAnd => BinaryOp::BitAnd,
        AssignOp::BitXor => BinaryOp::BitXor,
        AssignOp::Shl => BinaryOp::Shl,
        AssignOp::Shr => BinaryOp::Shr,
        AssignOp::UShr => BinaryOp::UShr,
        AssignOp::Assign | AssignOp::And | AssignOp::Or | AssignOp::Coalesce => {
            return rhs.clone();
        }
    };
    fold_binary(bin, current, rhs).unwrap_or_else(|| {
        Value::Sym(Box::new(Expr::Binary {
            op: bin,
            left: Box::new(current.to_expr()),
            right: Box::new(rhs.to_expr()),
        }))
    })
}

fn fold_in(key: &Value, container: &Value) -> Option<Value> {
    let key_str: String = match key {
        Value::Str(s) => s.clone(),
        Value::Num(n) => super::emit::format_number(*n),
        _ => return None,
    };
    match container {
        Value::Object(map) => Some(Value::Bool(map.borrow().contains_key(&key_str))),
        Value::Array(items) => {
            if key_str == "length" {
                return Some(Value::Bool(true));
            }
            key_str
                .parse::<usize>()
                .ok()
                .map(|idx: usize| Value::Bool(idx < items.borrow().len()))
        }
        Value::Func(_) => (!is_standard_function_property(&key_str)).then_some(Value::Bool(false)),
        _ => None,
    }
}

fn is_standard_function_property(key: &str) -> bool {
    matches!(
        key,
        "length"
            | "name"
            | "prototype"
            | "arguments"
            | "caller"
            | "constructor"
            | "call"
            | "apply"
            | "bind"
            | "toString"
    )
}

fn fold_binary(op: BinaryOp, l: &Value, r: &Value) -> Option<Value> {
    match op {
        BinaryOp::StrictEq => return strict_equals(l, r).map(Value::Bool),
        BinaryOp::StrictNeq => return strict_equals(l, r).map(|b| Value::Bool(!b)),
        BinaryOp::Eq => return loose_equals(l, r).map(Value::Bool),
        BinaryOp::Neq => return loose_equals(l, r).map(|b| Value::Bool(!b)),
        BinaryOp::In => return fold_in(l, r),
        BinaryOp::Instanceof => return None,
        _ => {}
    }
    if op == BinaryOp::Add && (matches!(l, Value::Str(_)) || matches!(r, Value::Str(_))) {
        let (ls, rs): (Option<String>, Option<String>) = (concrete_string(l), concrete_string(r));
        if let (Some(a), Some(b)) = (ls, rs) {
            return Some(Value::Str(format!("{a}{b}")));
        }
        return None;
    }
    let (ln, rn): (f64, f64) = match (coerce_number_arith(l), coerce_number_arith(r)) {
        (Some(a), Some(b)) => (a, b),
        _ => return None,
    };
    let v: f64 = match op {
        BinaryOp::Add => ln + rn,
        BinaryOp::Sub => ln - rn,
        BinaryOp::Mul => ln * rn,
        BinaryOp::Div => ln / rn,
        BinaryOp::Mod => ln % rn,
        BinaryOp::Pow => ln.powf(rn),
        BinaryOp::BitOr => f64::from(to_int32(ln) | to_int32(rn)),
        BinaryOp::BitAnd => f64::from(to_int32(ln) & to_int32(rn)),
        BinaryOp::BitXor => f64::from(to_int32(ln) ^ to_int32(rn)),
        BinaryOp::Shl => f64::from(to_int32(ln).wrapping_shl(to_uint32(rn) & 31)),
        BinaryOp::Shr => f64::from(to_int32(ln).wrapping_shr(to_uint32(rn) & 31)),
        BinaryOp::UShr => (to_uint32(ln) >> (to_uint32(rn) & 31)) as f64,
        BinaryOp::Lt => return Some(Value::Bool(ln < rn)),
        BinaryOp::Lte => return Some(Value::Bool(ln <= rn)),
        BinaryOp::Gt => return Some(Value::Bool(ln > rn)),
        BinaryOp::Gte => return Some(Value::Bool(ln >= rn)),
        _ => return None,
    };
    Some(Value::Num(v))
}

fn coerce_number_arith(v: &Value) -> Option<f64> {
    match v {
        Value::Num(n) => Some(*n),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Value::Null => Some(0.0),
        Value::Undefined => Some(f64::NAN),
        Value::Str(s) => {
            let trimmed: &str = s.trim();
            if trimmed.is_empty() {
                Some(0.0)
            } else {
                Some(trimmed.parse::<f64>().unwrap_or(f64::NAN))
            }
        }
        Value::Array(items) => {
            let arr: std::cell::Ref<'_, Vec<Value>> = items.borrow();
            match arr.len() {
                0 => Some(0.0),
                1 => coerce_number_arith(&arr[0]),
                _ => Some(f64::NAN),
            }
        }
        Value::Object(_) | Value::Func(_) | Value::Sym(_) => None,
    }
}

fn loose_equals(l: &Value, r: &Value) -> Option<bool> {
    match (l, r) {
        (Value::Null | Value::Undefined, Value::Null | Value::Undefined) => Some(true),
        (Value::Null | Value::Undefined, _) | (_, Value::Null | Value::Undefined) => {
            if matches!(l, Value::Sym(_)) || matches!(r, Value::Sym(_)) {
                None
            } else {
                Some(false)
            }
        }
        (Value::Num(a), Value::Num(b)) => Some((a - b).abs() < f64::EPSILON),
        (Value::Str(a), Value::Str(b)) => Some(a == b),
        (Value::Bool(a), Value::Bool(b)) => Some(a == b),
        (
            Value::Num(_) | Value::Str(_) | Value::Bool(_),
            Value::Num(_) | Value::Str(_) | Value::Bool(_),
        ) => match (coerce_number_arith(l), coerce_number_arith(r)) {
            (Some(a), Some(b)) => Some((a - b).abs() < f64::EPSILON),
            _ => None,
        },
        _ => None,
    }
}

fn expr_is_observable(expr: &Expr) -> bool {
    match expr {
        Expr::Call { callee, .. } => is_output_sink(callee),
        _ => false,
    }
}

fn is_output_sink(callee: &Expr) -> bool {
    let root: Option<&str> = callee_root_ident(callee);
    matches!(root, Some("console" | "process"))
}

fn callee_root_ident(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Ident(name) => Some(name.as_str()),
        Expr::Member { object, .. } => callee_root_ident(object),
        Expr::Call { callee, .. } => callee_root_ident(callee),
        _ => None,
    }
}

fn flatten_case_run(cases: &[super::ir::SwitchCase], start: usize) -> &[Stmt] {
    if let Some(case) = cases.get(start)
        && !case.body.is_empty()
    {
        return &case.body;
    }
    for case in &cases[start..] {
        if !case.body.is_empty() {
            return &case.body;
        }
    }
    &[]
}

const fn merge_branch_flow(a: &Flow, b: &Flow) -> Flow {
    match (a, b) {
        (Flow::Return(_), Flow::Return(_)) => Flow::Return(Value::Undefined),
        _ => Flow::Normal,
    }
}

fn finish_branch(mut stmts: Vec<Stmt>, flow: Flow) -> Vec<Stmt> {
    if let Flow::Return(v) = flow {
        stmts.push(Stmt::Return(Some(v.to_expr())));
    }
    stmts
}

const fn residual_is_value_tree(stmt: &Stmt) -> bool {
    matches!(stmt, Stmt::If { .. } | Stmt::Return(_))
}

fn with_chain_depth(chain: &WithScope) -> usize {
    1 + chain.parent.as_ref().map_or(0, |p| with_chain_depth(p))
}

fn clone_with_chain_above_floor(
    chain: Option<&WithScope>,
    floor: usize,
    map: &mut super::value::CloneMap,
) -> Option<WithScope> {
    let chain: &WithScope = chain?;
    let depth: usize = with_chain_depth(chain);
    if depth <= floor {
        return Some(chain.clone());
    }
    Some(WithScope {
        object: match Value::Object(chain.object.clone()).deep_clone(map) {
            Value::Object(o) => o,
            _ => chain.object.clone(),
        },
        parent: clone_with_chain_above_floor(chain.parent.as_deref(), floor, map).map(Box::new),
    })
}

fn wrap_iife(body: Vec<Stmt>) -> Expr {
    let func: Rc<FuncDef> = Rc::new(FuncDef {
        name: None,
        params: Vec::new(),
        body,
        is_generator: false,
        is_async: false,
        is_arrow: false,
        expression_body: None,
    });
    Expr::Call {
        callee: Box::new(Expr::Func(func)),
        args: Vec::new(),
        spread_last: false,
    }
}

fn stmt_position_is_effectful(expr: &Expr) -> bool {
    match expr {
        Expr::Call { .. } | Expr::New { .. } => true,
        Expr::Sequence(exprs) => exprs.last().is_some_and(stmt_position_is_effectful),
        Expr::Conditional {
            consequent,
            alternate,
            ..
        } => stmt_position_is_effectful(consequent) || stmt_position_is_effectful(alternate),
        _ => false,
    }
}

fn member_key(expr: &Expr) -> Option<&str> {
    if let Expr::Member { property, .. } = expr
        && let Expr::Str(s) = property.as_ref()
    {
        return Some(s.as_str());
    }
    None
}

fn unwrap_next_value(expr: &Expr) -> Option<&Expr> {
    if member_key(expr) != Some("value") {
        return None;
    }
    let Expr::Member { object, .. } = expr else {
        return None;
    };
    let Expr::Call { callee, args, .. } = object.as_ref() else {
        return None;
    };
    if !args.is_empty() {
        return None;
    }
    if member_key(callee) != Some("next") {
        return None;
    }
    let Expr::Member {
        object: next_obj, ..
    } = callee.as_ref()
    else {
        return None;
    };
    if matches!(next_obj.as_ref(), Expr::Call { .. }) {
        Some(next_obj.as_ref())
    } else {
        None
    }
}

fn strict_equals(a: &Value, b: &Value) -> Option<bool> {
    match (a, b) {
        (Value::Num(x), Value::Num(y)) => Some((x - y).abs() < f64::EPSILON),
        (Value::Str(x), Value::Str(y)) => Some(x == y),
        (Value::Bool(x), Value::Bool(y)) => Some(x == y),
        (Value::Null, Value::Null) | (Value::Undefined, Value::Undefined) => Some(true),
        (Value::Num(_), Value::Str(_) | Value::Bool(_) | Value::Null | Value::Undefined)
        | (Value::Str(_), Value::Num(_) | Value::Bool(_) | Value::Null | Value::Undefined)
        | (Value::Bool(_), Value::Num(_) | Value::Str(_) | Value::Null | Value::Undefined)
        | (Value::Null, Value::Num(_) | Value::Str(_) | Value::Bool(_) | Value::Undefined)
        | (Value::Undefined, Value::Num(_) | Value::Str(_) | Value::Bool(_) | Value::Null) => {
            Some(false)
        }
        (Value::Object(x), Value::Object(y)) => Some(Rc::ptr_eq(x, y)),
        (Value::Array(x), Value::Array(y)) => Some(Rc::ptr_eq(x, y)),
        _ => None,
    }
}

fn concrete_string(v: &Value) -> Option<String> {
    match v {
        Value::Str(s) => Some(s.clone()),
        Value::Num(_) | Value::Bool(_) | Value::Null | Value::Undefined => Some(coerce_string(v)),
        _ => None,
    }
}

pub(super) fn coerce_string(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        Value::Num(n) => super::emit::format_number(*n),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_owned(),
        Value::Undefined => "undefined".to_owned(),
        Value::Sym(e) => super::emit::emit_expr(e),
        Value::Array(items) => items
            .borrow()
            .iter()
            .map(coerce_string)
            .collect::<Vec<String>>()
            .join(","),
        Value::Object(_) => "[object Object]".to_owned(),
        Value::Func(_) => "function".to_owned(),
    }
}

const fn to_int32(n: f64) -> i32 {
    if !n.is_finite() {
        return 0;
    }
    let m: f64 = n.trunc();
    (m as i64 as u32) as i32
}

const fn to_uint32(n: f64) -> u32 {
    if !n.is_finite() {
        return 0;
    }
    n.trunc() as i64 as u32
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::super::ir::VarKind;
    use super::*;

    #[test]
    fn dense_array_member_write_bails_before_large_resize() {
        let scope: Scope = Scope::root();
        let stmts: Vec<Stmt> = vec![
            Stmt::VarDecl {
                kind: VarKind::Var,
                decls: vec![("a".to_owned(), Some(Expr::Array(Vec::new())))],
            },
            Stmt::Expr(Expr::Assign {
                op: AssignOp::Assign,
                target: Box::new(Expr::Member {
                    object: Box::new(Expr::Ident("a".to_owned())),
                    property: Box::new(Expr::Str(MAX_DENSE_ARRAY_ELEMENTS.to_string())),
                    computed: true,
                }),
                value: Box::new(Expr::Num(1.0)),
            }),
        ];
        let mut interp: Interp = Interp::new(Limits::default());
        let (_, flow): (Vec<Stmt>, Flow) = interp.run_program(&stmts, &scope);
        assert!(interp.bailed);
        assert!(matches!(flow, Flow::Bail));
        let Some(Value::Array(items)): Option<Value> = scope.lookup("a") else {
            panic!("array binding missing");
        };
        assert!(items.borrow().is_empty());
    }

    #[test]
    fn char_code_at_negative_integer_returns_nan() {
        let callee: Expr = Expr::Member {
            object: Box::new(Expr::Str("abc".to_owned())),
            property: Box::new(Expr::Str("charCodeAt".to_owned())),
            computed: false,
        };
        let value: Value = Interp::builtin_call(
            &callee,
            Some(&Value::Str("abc".to_owned())),
            &[Value::Num(-1.0)],
        )
        .expect("builtin");
        let Value::Num(n): Value = value else {
            panic!("expected number");
        };
        assert!(n.is_nan());
    }
}
