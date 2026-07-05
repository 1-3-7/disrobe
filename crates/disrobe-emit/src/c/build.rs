use crate::c::ast::{CExpr, CTypeSpec};
use crate::intern::{Interner, Symbol};

#[derive(Debug)]
pub struct Cx<'i> {
    interner: &'i mut Interner,
}

impl<'i> Cx<'i> {
    pub const fn new(interner: &'i mut Interner) -> Self {
        Self { interner }
    }

    pub const fn interner(&mut self) -> &mut Interner {
        self.interner
    }

    pub fn sym(&mut self, name: &str) -> Symbol {
        self.interner.intern(name)
    }

    pub fn var(&mut self, name: &str) -> CExpr {
        CExpr::Ident(self.interner.intern(name))
    }

    pub fn named_type(&mut self, name: &str) -> CTypeSpec {
        CTypeSpec::Named(self.interner.intern(name))
    }

    pub fn member(&mut self, base: CExpr, arrow: bool, field: &str) -> CExpr {
        CExpr::Member {
            base: Box::new(base),
            arrow,
            field: self.interner.intern(field),
        }
    }

    pub fn call(&mut self, name: &str, args: Vec<CExpr>) -> CExpr {
        let callee: CExpr = self.var(name);
        CExpr::Call {
            callee: Box::new(callee),
            args,
        }
    }

    pub fn index(&mut self, name: &str, index: CExpr) -> CExpr {
        let base: CExpr = self.var(name);
        CExpr::Index {
            base: Box::new(base),
            index: Box::new(index),
        }
    }
}
