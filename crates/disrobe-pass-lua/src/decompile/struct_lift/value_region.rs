use super::{
    Decoded, LocalNames, LuaDialect, LuaProto, Op, StructState, compare_value_expr, decode,
    define_at_merge, is_single_value_op, jump_target, region_has_external_entry, rk,
    single_value_text,
};

const MAX_REGION_INSTRUCTIONS: usize = 256;
const MAX_BUILD_STEPS: usize = 4_096;

#[derive(Debug, Clone)]
enum Value {
    Leaf {
        entry: usize,
        text: String,
        never_falsy: bool,
    },
    Or {
        entry: usize,
        first: String,
        first_never_falsy: bool,
        rest: Box<Value>,
    },
    And {
        entry: usize,
        first: String,
        rest: Box<Value>,
    },
    Choose {
        entry: usize,
        cond: String,
        taken: Box<Value>,
        otherwise: Box<Value>,
    },
}

impl Value {
    const fn entry(&self) -> usize {
        match self {
            Self::Leaf { entry, .. }
            | Self::Or { entry, .. }
            | Self::And { entry, .. }
            | Self::Choose { entry, .. } => *entry,
        }
    }

    fn falls_into(&self, target: usize) -> bool {
        if self.entry() == target {
            return true;
        }
        match self {
            Self::Leaf { never_falsy, .. } => *never_falsy,
            Self::Or {
                first_never_falsy,
                rest,
                ..
            } => *first_never_falsy || rest.falls_into(target),
            Self::And { .. } => false,
            Self::Choose { otherwise, .. } => otherwise.falls_into(target),
        }
    }

    fn render(&self) -> Option<String> {
        match self {
            Self::Leaf { text, .. } => Some(text.clone()),
            Self::Or {
                first,
                first_never_falsy: true,
                ..
            } => Some(first.clone()),
            Self::Or { first, rest, .. } => Some(format!("({first} or {})", rest.render()?)),
            Self::And { first, rest, .. } => Some(format!("({first} and {})", rest.render()?)),
            Self::Choose {
                cond,
                taken,
                otherwise,
                ..
            } => {
                if !taken.falls_into(otherwise.entry()) {
                    return None;
                }
                let chosen: String = match taken.as_ref() {
                    Self::Or { first, rest, .. } if rest.entry() == otherwise.entry() => {
                        first.clone()
                    }
                    other => other.render()?,
                };
                Some(format!("({cond} and {chosen} or {})", otherwise.render()?))
            }
        }
    }

    const fn is_selection(&self) -> bool {
        !matches!(self, Self::Leaf { .. })
    }
}

struct Region<'a> {
    state: &'a StructState,
    p: &'a LuaProto,
    dialect: LuaDialect,
    target: u32,
    join: usize,
    steps: usize,
}

fn never_falsy(text: &str) -> bool {
    text == "true"
        || text.starts_with('"')
        || text.starts_with('\'')
        || text.starts_with('{')
        || text.starts_with("function")
        || text.parse::<f64>().is_ok()
}

fn is_compare(op: Op) -> bool {
    matches!(
        op,
        Op::Eq | Op::Lt | Op::Le | Op::EqK | Op::EqI | Op::LtI | Op::LeI | Op::GtI | Op::GeI
    )
}

fn jumps_when_truthy(d: &Decoded, dialect: LuaDialect) -> bool {
    if matches!(dialect, LuaDialect::Lua54) {
        d.k
    } else {
        d.c != 0
    }
}

fn written_value_register(d: &Decoded, dialect: LuaDialect) -> Option<u32> {
    match d.op {
        Op::LFalseSkip | Op::TestSet => Some(d.a),
        Op::LoadBool if !matches!(dialect, LuaDialect::Lua54) => Some(d.a),
        op if is_single_value_op(op) => Some(d.a),
        _ => None,
    }
}

impl Region<'_> {
    fn decoded(&self, pc: usize) -> Option<Decoded> {
        self.p
            .code
            .get(pc)
            .map(|raw: &u32| decode(*raw, self.dialect))
    }

    fn jump_after(&self, pc: usize) -> Option<usize> {
        let jmp: Decoded = self.decoded(pc + 1)?;
        if jmp.op != Op::Jmp {
            return None;
        }
        usize::try_from(jump_target(pc + 1, &jmp, self.dialect)).ok()
    }

    fn compare_reads_target(&self, d: &Decoded) -> bool {
        let is54: bool = matches!(self.dialect, LuaDialect::Lua54);
        match d.op {
            Op::Eq | Op::Lt | Op::Le if is54 => d.a == self.target || d.b == self.target,
            Op::Eq | Op::Lt | Op::Le => {
                rk(self.state, self.p, d.b, self.dialect) == self.state.reg(self.target)
                    || rk(self.state, self.p, d.c, self.dialect) == self.state.reg(self.target)
            }
            _ => d.a == self.target,
        }
    }

    fn leaf_text(&self, d: &Decoded) -> String {
        match d.op {
            Op::LFalseSkip => "false".to_owned(),
            Op::LoadBool => if d.b != 0 { "true" } else { "false" }.to_owned(),
            _ => single_value_text(self.state, self.p, d, self.dialect),
        }
    }

    fn build(&mut self, pc: usize, depth: usize) -> Option<Value> {
        self.steps = self.steps.checked_add(1)?;
        if self.steps > MAX_BUILD_STEPS || depth > MAX_REGION_INSTRUCTIONS || pc >= self.join {
            return None;
        }
        let d: Decoded = self.decoded(pc)?;
        if is_compare(d.op) {
            if self.compare_reads_target(&d) {
                return None;
            }
            let taken: usize = self.jump_after(pc)?;
            let cond: String = compare_value_expr(self.state, self.p, &d, self.dialect)?;
            return Some(Value::Choose {
                entry: pc,
                cond,
                taken: Box::new(self.build(taken, depth + 1)?),
                otherwise: Box::new(self.build(pc + 2, depth + 1)?),
            });
        }
        match d.op {
            Op::Test if d.a != self.target => {
                let taken: usize = self.jump_after(pc)?;
                let register: String = self.state.reg(d.a);
                let cond: String = if jumps_when_truthy(&d, self.dialect) {
                    register
                } else {
                    format!("not {register}")
                };
                Some(Value::Choose {
                    entry: pc,
                    cond,
                    taken: Box::new(self.build(taken, depth + 1)?),
                    otherwise: Box::new(self.build(pc + 2, depth + 1)?),
                })
            }
            Op::TestSet if d.a == self.target && d.b != self.target => {
                if self.jump_after(pc)? != self.join {
                    return None;
                }
                let first: String = self.state.reg(d.b);
                let rest: Box<Value> = Box::new(self.build(pc + 2, depth + 1)?);
                Some(if jumps_when_truthy(&d, self.dialect) {
                    Value::Or {
                        entry: pc,
                        first_never_falsy: never_falsy(&first),
                        first,
                        rest,
                    }
                } else {
                    Value::And {
                        entry: pc,
                        first,
                        rest,
                    }
                })
            }
            Op::Jmp => {
                let target: usize = usize::try_from(jump_target(pc, &d, self.dialect)).ok()?;
                if target <= pc {
                    return None;
                }
                self.build(target, depth + 1)
            }
            _ if written_value_register(&d, self.dialect) == Some(self.target)
                && d.op != Op::TestSet =>
            {
                let skips: bool = d.op == Op::LFalseSkip || (d.op == Op::LoadBool && d.c != 0);
                let text: String = self.leaf_text(&d);
                let next: usize = pc + if skips { 2 } else { 1 };
                self.after_load(pc, next, text, depth)
            }
            _ => None,
        }
    }

    fn after_load(
        &mut self,
        entry: usize,
        next: usize,
        text: String,
        depth: usize,
    ) -> Option<Value> {
        let leaf_never_falsy: bool = never_falsy(&text);
        if next == self.join {
            return Some(Value::Leaf {
                entry,
                text,
                never_falsy: leaf_never_falsy,
            });
        }
        let d: Decoded = self.decoded(next)?;
        match d.op {
            Op::Jmp if usize::try_from(jump_target(next, &d, self.dialect)).ok()? == self.join => {
                Some(Value::Leaf {
                    entry,
                    text,
                    never_falsy: leaf_never_falsy,
                })
            }
            Op::Test if d.a == self.target => {
                if self.jump_after(next)? != self.join {
                    return None;
                }
                let rest: Box<Value> = Box::new(self.build(next + 2, depth + 1)?);
                Some(if jumps_when_truthy(&d, self.dialect) {
                    Value::Or {
                        entry,
                        first: text,
                        first_never_falsy: leaf_never_falsy,
                        rest,
                    }
                } else {
                    Value::And {
                        entry,
                        first: text,
                        rest,
                    }
                })
            }
            _ => None,
        }
    }
}

fn region_bounds(p: &LuaProto, start: usize, dialect: LuaDialect) -> Option<(u32, usize)> {
    let mut target: Option<u32> = None;
    let mut furthest: usize = start + 1;
    let mut pc: usize = start;
    while pc < p.code.len() && pc - start <= MAX_REGION_INSTRUCTIONS {
        if pc > start && pc >= furthest {
            return target.map(|register: u32| (register, pc));
        }
        let d: Decoded = decode(*p.code.get(pc)?, dialect);
        if d.op == Op::Jmp {
            let to: usize = usize::try_from(jump_target(pc, &d, dialect)).ok()?;
            if to <= pc {
                return None;
            }
            furthest = furthest.max(to);
        } else if let Some(register) = written_value_register(&d, dialect) {
            if target.is_some_and(|known: u32| known != register) {
                return None;
            }
            target = Some(register);
            let width: usize = if d.op == Op::TestSet { 2 } else { 1 };
            furthest = furthest.max(pc + width);
        } else if is_compare(d.op) || d.op == Op::Test {
            furthest = furthest.max(pc + 2);
        } else {
            return None;
        }
        pc += 1;
    }
    None
}

pub(super) fn emit_value_region(
    state: &mut StructState,
    names: &LocalNames,
    p: &LuaProto,
    pc: usize,
    dialect: LuaDialect,
) -> Option<usize> {
    let (target, join): (u32, usize) = region_bounds(p, pc, dialect)?;
    if region_has_external_entry(p, pc, join - 1, dialect) {
        return None;
    }
    let mut region: Region<'_> = Region {
        state,
        p,
        dialect,
        target,
        join,
        steps: 0,
    };
    let value: Value = region.build(pc, 0)?;
    if !value.is_selection() {
        return None;
    }
    let text: String = value.render()?;
    if state.is_defined(target) && state.reg(target) == state.temp(target) {
        let local: String = state.temp(target);
        state.push_raw(format!("{local} = {text}"));
    } else {
        define_at_merge(state, names, target, text, join);
    }
    Some(join - 1)
}
