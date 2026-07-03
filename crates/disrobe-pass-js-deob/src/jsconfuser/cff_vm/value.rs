use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use super::ir::{Expr, FuncDef};

pub(super) type ObjRef = Rc<RefCell<BTreeMap<String, Value>>>;
pub(super) type ArrRef = Rc<RefCell<Vec<Value>>>;

#[derive(Debug, Clone)]
pub(super) struct WithScope {
    pub object: ObjRef,
    pub parent: Option<Box<Self>>,
}

impl WithScope {
    pub(super) fn resolve_read(&self, name: &str) -> Option<Value> {
        if let Some(v) = self.object.borrow().get(name) {
            return Some(v.clone());
        }
        self.parent.as_ref().and_then(|p| p.resolve_read(name))
    }

    pub(super) fn resolve_write(&self, name: &str) -> Option<ObjRef> {
        if self.object.borrow().contains_key(name) {
            return Some(self.object.clone());
        }
        self.parent.as_ref().and_then(|p| p.resolve_write(name))
    }
}

#[derive(Debug, Clone)]
pub(super) struct Closure {
    pub def: Rc<FuncDef>,
    pub scope: Scope,
    pub with_chain: Option<WithScope>,
}

#[derive(Debug, Clone)]
pub(super) enum Value {
    Num(f64),
    Str(String),
    Bool(bool),
    Null,
    Undefined,
    Object(ObjRef),
    Array(ArrRef),
    Func(Rc<Closure>),
    Sym(Box<Expr>),
}

impl Value {
    pub(super) const fn as_concrete_num(&self) -> Option<f64> {
        match self {
            Self::Num(n) => Some(*n),
            Self::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            Self::Null => Some(0.0),
            _ => None,
        }
    }

    pub(super) fn truthiness(&self) -> Option<bool> {
        match self {
            Self::Num(n) => Some(*n != 0.0 && !n.is_nan()),
            Self::Str(s) => Some(!s.is_empty()),
            Self::Bool(b) => Some(*b),
            Self::Null | Self::Undefined => Some(false),
            Self::Object(_) | Self::Array(_) | Self::Func(_) => Some(true),
            Self::Sym(_) => None,
        }
    }

    pub(super) fn to_expr(&self) -> Expr {
        match self {
            Self::Num(n) => Expr::Num(*n),
            Self::Str(s) => Expr::Str(s.clone()),
            Self::Bool(b) => Expr::Bool(*b),
            Self::Null => Expr::Null,
            Self::Undefined => Expr::Undefined,
            Self::Sym(e) => (**e).clone(),
            Self::Array(items) => Expr::Array(
                items
                    .borrow()
                    .iter()
                    .map(|v: &Self| Some(v.to_expr()))
                    .collect(),
            ),
            Self::Object(map) => Expr::Object(
                map.borrow()
                    .iter()
                    .map(|(k, v): (&String, &Self)| {
                        (super::ir::PropKey::Str(k.clone()), v.to_expr())
                    })
                    .collect(),
            ),
            Self::Func(closure) => Expr::Func(closure.def.clone()),
        }
    }
}

#[derive(Default)]
pub(super) struct CloneMap {
    objects: Vec<(usize, ObjRef)>,
    arrays: Vec<(usize, ArrRef)>,
}

impl std::fmt::Debug for CloneMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloneMap").finish_non_exhaustive()
    }
}

impl CloneMap {
    fn obj(&mut self, original: &ObjRef) -> ObjRef {
        let key: usize = Rc::as_ptr(original) as usize;
        if let Some((_, existing)) = self.objects.iter().find(|(k, _)| *k == key) {
            return existing.clone();
        }
        let fresh: ObjRef = Rc::new(RefCell::new(BTreeMap::new()));
        self.objects.push((key, fresh.clone()));
        let cloned: BTreeMap<String, Value> = original
            .borrow()
            .iter()
            .map(|(k, v): (&String, &Value)| (k.clone(), v.deep_clone(self)))
            .collect();
        *fresh.borrow_mut() = cloned;
        fresh
    }

    fn arr(&mut self, original: &ArrRef) -> ArrRef {
        let key: usize = Rc::as_ptr(original) as usize;
        if let Some((_, existing)) = self.arrays.iter().find(|(k, _)| *k == key) {
            return existing.clone();
        }
        let fresh: ArrRef = Rc::new(RefCell::new(Vec::new()));
        self.arrays.push((key, fresh.clone()));
        let cloned: Vec<Value> = original
            .borrow()
            .iter()
            .map(|v: &Value| v.deep_clone(self))
            .collect();
        *fresh.borrow_mut() = cloned;
        fresh
    }
}

impl Value {
    pub(super) fn deep_clone(&self, map: &mut CloneMap) -> Self {
        match self {
            Self::Object(o) => Self::Object(map.obj(o)),
            Self::Array(a) => Self::Array(map.arr(a)),
            other => other.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct Scope {
    pub frame: Rc<RefCell<BTreeMap<String, Value>>>,
    pub parent: Option<Box<Self>>,
}

impl Scope {
    pub(super) fn root() -> Self {
        Self {
            frame: Rc::new(RefCell::new(BTreeMap::new())),
            parent: None,
        }
    }

    pub(super) fn child(&self) -> Self {
        Self {
            frame: Rc::new(RefCell::new(BTreeMap::new())),
            parent: Some(Box::new(self.clone())),
        }
    }

    pub(super) fn declare(&self, name: &str, value: Value) {
        self.frame.borrow_mut().insert(name.to_owned(), value);
    }

    pub(super) fn lookup(&self, name: &str) -> Option<Value> {
        if let Some(v) = self.frame.borrow().get(name) {
            return Some(v.clone());
        }
        self.parent.as_ref().and_then(|p| p.lookup(name))
    }

    pub(super) fn assign(&self, name: &str, value: Value) -> bool {
        if self.frame.borrow().contains_key(name) {
            self.frame.borrow_mut().insert(name.to_owned(), value);
            return true;
        }
        self.parent.as_ref().is_some_and(|p| p.assign(name, value))
    }

    pub(super) fn deep_clone(&self, map: &mut CloneMap) -> Self {
        let frame: BTreeMap<String, Value> = self
            .frame
            .borrow()
            .iter()
            .map(|(k, v): (&String, &Value)| (k.clone(), v.deep_clone(map)))
            .collect();
        Self {
            frame: Rc::new(RefCell::new(frame)),
            parent: self.parent.as_ref().map(|p| Box::new(p.deep_clone(map))),
        }
    }
}
