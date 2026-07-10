use crate::ast::node::{ExceptHandler, MatchCase, Stmt};

#[derive(Debug, Clone)]
pub(crate) struct AstFacts {
    pub(crate) handler_order: Vec<usize>,
    pub(crate) try_count: usize,
    pub(crate) has_with: bool,
    pub(crate) has_finally: bool,
    pub(crate) loop_inner_return: bool,
}

#[must_use]
pub(crate) fn extract(body: &[Stmt]) -> AstFacts {
    let mut walker: Walker = Walker::default();
    walker.body(body);
    AstFacts {
        handler_order: walker.emission,
        try_count: walker.next_id,
        has_with: walker.has_with,
        has_finally: walker.has_finally,
        loop_inner_return: walker.loop_inner_return,
    }
}

#[derive(Debug, Default)]
struct Walker {
    next_id: usize,
    emission: Vec<usize>,
    has_with: bool,
    has_finally: bool,
    loop_inner_return: bool,
    loop_depth: usize,
}

impl Walker {
    fn body(&mut self, stmts: &[Stmt]) {
        for stmt in stmts {
            self.stmt(stmt);
        }
    }

    fn stmt(&mut self, stmt: &Stmt) {
        match stmt {
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
            } => self.try_stmt(body, handlers, orelse, finalbody),
            Stmt::If { body, orelse, .. } => {
                self.body(body);
                self.body(orelse);
            }
            Stmt::For { body, orelse, .. } | Stmt::While { body, orelse, .. } => {
                self.loop_depth += 1;
                self.body(body);
                self.body(orelse);
                self.loop_depth -= 1;
            }
            Stmt::With { body, .. } => {
                self.has_with = true;
                self.body(body);
            }
            Stmt::Match { cases, .. } => {
                for case in cases {
                    self.match_case(case);
                }
            }
            Stmt::Return(_) if self.loop_depth > 0 => {
                self.loop_inner_return = true;
            }
            _ => {}
        }
    }

    fn try_stmt(
        &mut self,
        body: &[Stmt],
        handlers: &[ExceptHandler],
        orelse: &[Stmt],
        finalbody: &[Stmt],
    ) {
        let my_id: usize = self.next_id;
        self.next_id += 1;
        if !finalbody.is_empty() {
            self.has_finally = true;
        }
        self.body(body);
        self.body(orelse);
        self.emission.push(my_id);
        for handler in handlers {
            self.body(&handler.body);
        }
        self.body(finalbody);
    }

    fn match_case(&mut self, case: &MatchCase) {
        self.body(&case.body);
    }
}
