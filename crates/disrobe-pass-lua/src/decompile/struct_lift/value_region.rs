use super::{
    Decoded, LiveAcrossBranch, LocalNames, LuaDialect, LuaProto, Op, StructState, StructuredLift,
    compare_value_expr, decode, define_at_merge, is_single_value_op, jump_target, lower_span,
    region_has_external_entry, rk, single_value_text, written_registers,
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
                if let Self::Leaf { text, .. } = taken.as_ref()
                    && text == cond
                {
                    return Some(format!("({cond} or {})", otherwise.render()?));
                }
                if let Self::Leaf { text, .. } = otherwise.as_ref()
                    && cond.strip_prefix("not ") == Some(text.as_str())
                {
                    return Some(format!("({text} or {})", taken.render()?));
                }
                if !taken.falls_into(otherwise.entry()) {
                    if !otherwise.falls_into(taken.entry()) {
                        return None;
                    }
                    let chosen: String = match otherwise.as_ref() {
                        Self::Or { first, rest, .. } if rest.entry() == taken.entry() => {
                            first.clone()
                        }
                        other => other.render()?,
                    };
                    return Some(format!(
                        "(not ({cond}) and {chosen} or {})",
                        taken.render()?
                    ));
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
    start: usize,
    join: usize,
    back: Option<usize>,
    steps: usize,
    trial: &'a mut dyn FnMut(usize, usize, u32) -> Option<String>,
}

fn never_falsy(text: &str) -> bool {
    text == "true"
        || text.starts_with('"')
        || text.starts_with('\'')
        || text.starts_with('{')
        || text.starts_with("function")
        || text.parse::<f64>().is_ok()
}

fn is_segment_op(d: &Decoded, dialect: LuaDialect) -> bool {
    match d.op {
        Op::Jmp
        | Op::Test
        | Op::TestSet
        | Op::Eq
        | Op::Lt
        | Op::Le
        | Op::EqK
        | Op::EqI
        | Op::LtI
        | Op::LeI
        | Op::GtI
        | Op::GeI
        | Op::ForLoop
        | Op::ForPrep
        | Op::TForPrep
        | Op::TForCall
        | Op::TForLoop
        | Op::Return
        | Op::Return0
        | Op::Return1
        | Op::TailCall
        | Op::SetUpval
        | Op::SetGlobal
        | Op::SetTabUp
        | Op::SetTable
        | Op::SetField
        | Op::SetI
        | Op::SetList
        | Op::Closure
        | Op::Close
        | Op::Tbc
        | Op::LFalseSkip
        | Op::VarargPrep
        | Op::Unknown => false,
        Op::LoadBool => d.c == 0 || matches!(dialect, LuaDialect::Lua54),
        Op::Call => d.c == 2,
        _ => true,
    }
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
        self.resolve(usize::try_from(jump_target(pc + 1, &jmp, self.dialect)).ok()?)
    }

    fn resolve(&self, target: usize) -> Option<usize> {
        if self.back == Some(target) {
            Some(self.join)
        } else {
            Some(target)
        }
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

    fn target_written_before(&self, pc: usize) -> bool {
        (self.start..pc).any(|at: usize| {
            self.decoded(at)
                .is_none_or(|d: Decoded| written_registers(&d, self.dialect).contains(&self.target))
        })
    }

    fn leaf_text(&self, d: &Decoded) -> String {
        match d.op {
            Op::LFalseSkip => "false".to_owned(),
            Op::LoadBool => if d.b != 0 { "true" } else { "false" }.to_owned(),
            _ => single_value_text(self.state, self.p, d, self.dialect),
        }
    }

    fn segment_end(&self, pc: usize) -> usize {
        let mut end: usize = pc;
        while end < self.join
            && self
                .decoded(end)
                .is_some_and(|d: Decoded| is_segment_op(&d, self.dialect))
        {
            end += 1;
        }
        end
    }

    fn segment_leaf(&mut self, pc: usize, depth: usize) -> Option<Value> {
        let end: usize = self.segment_end(pc);
        if end <= pc {
            return None;
        }
        let writes_only_scratch: bool = (pc..end).all(|at: usize| {
            self.decoded(at).is_some_and(|d: Decoded| {
                written_registers(&d, self.dialect)
                    .iter()
                    .all(|register: &u32| *register >= self.target)
            })
        });
        let last_writes_target: bool = (pc..end)
            .rev()
            .filter_map(|at: usize| self.decoded(at))
            .map(|d: Decoded| written_registers(&d, self.dialect))
            .find(|written: &Vec<u32>| !written.is_empty())
            .is_some_and(|written: Vec<u32>| written.contains(&self.target));
        if !writes_only_scratch || !last_writes_target {
            return None;
        }
        let text: String = (self.trial)(pc, end, self.target)?;
        self.after_load(pc, end, text, depth)
    }

    fn build(&mut self, pc: usize, depth: usize) -> Option<Value> {
        self.steps = self.steps.checked_add(1)?;
        if self.steps > MAX_BUILD_STEPS || depth > MAX_REGION_INSTRUCTIONS || pc >= self.join {
            return None;
        }
        let d: Decoded = self.decoded(pc)?;
        if let Some(value) = self.scratch_test_set(pc, depth) {
            return Some(value);
        }
        if is_segment_op(&d, self.dialect)
            && (self.segment_end(pc) > pc + 1 || written_value_register(&d, self.dialect).is_none())
        {
            return self.segment_leaf(pc, depth);
        }
        if d.op == Op::Test
            && d.a == self.target
            && self.jump_after(pc) == Some(self.join)
            && !self.target_written_before(pc)
        {
            let text: String = self.state.reg(self.target);
            return self.test_target(pc, pc, text, depth);
        }
        if is_compare(d.op) {
            if self.compare_reads_target(&d) && self.target_written_before(pc) {
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
            Op::Test
                if d.a != self.target
                    || (self.jump_after(pc)? != self.join && pc + 2 != self.join) =>
            {
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
                let first: String = self.state.reg(d.b);
                self.test_set(pc, pc, first, depth)
            }
            Op::Jmp => {
                let target: usize =
                    self.resolve(usize::try_from(jump_target(pc, &d, self.dialect)).ok()?)?;
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
            Op::Jmp
                if self.resolve(usize::try_from(jump_target(next, &d, self.dialect)).ok()?)?
                    == self.join =>
            {
                Some(Value::Leaf {
                    entry,
                    text,
                    never_falsy: leaf_never_falsy,
                })
            }
            Op::Test if d.a == self.target => self.test_target(entry, next, text, depth),
            _ => None,
        }
    }

    fn scratch_test_set(&mut self, pc: usize, depth: usize) -> Option<Value> {
        let end: usize = self.segment_end(pc);
        let test: Decoded = self.decoded(end)?;
        let feeds_target: bool = test.op == Op::TestSet && test.a == self.target;
        if end <= pc || !feeds_target || test.b <= self.target {
            return None;
        }
        let scratch_only: bool = (pc..end).all(|at: usize| {
            self.decoded(at).is_some_and(|d: Decoded| {
                written_registers(&d, self.dialect)
                    .iter()
                    .all(|register: &u32| *register > self.target)
            })
        });
        if !scratch_only {
            return None;
        }
        let first: String = (self.trial)(pc, end, test.b)?;
        self.test_set(pc, end, first, depth)
    }

    fn test_set(
        &mut self,
        entry: usize,
        test_pc: usize,
        first: String,
        depth: usize,
    ) -> Option<Value> {
        let d: Decoded = self.decoded(test_pc)?;
        if self.jump_after(test_pc)? != self.join {
            return None;
        }
        let rest: Box<Value> = Box::new(self.build(test_pc + 2, depth + 1)?);
        Some(if jumps_when_truthy(&d, self.dialect) {
            Value::Or {
                entry,
                first_never_falsy: never_falsy(&first),
                first,
                rest,
            }
        } else {
            Value::And { entry, first, rest }
        })
    }

    fn test_target(
        &mut self,
        entry: usize,
        test_pc: usize,
        text: String,
        depth: usize,
    ) -> Option<Value> {
        let d: Decoded = self.decoded(test_pc)?;
        if self.jump_after(test_pc)? != self.join {
            return None;
        }
        let rest: Box<Value> = Box::new(self.build(test_pc + 2, depth + 1)?);
        Some(if jumps_when_truthy(&d, self.dialect) {
            Value::Or {
                entry,
                first_never_falsy: never_falsy(&text),
                first: text,
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
}

fn region_bounds(
    p: &LuaProto,
    start: usize,
    dialect: LuaDialect,
) -> Option<(u32, usize, Option<usize>)> {
    let mut target: Option<u32> = None;
    let mut back: Option<usize> = None;
    let mut furthest: usize = start + 1;
    let mut pc: usize = start;
    while pc < p.code.len() && pc - start <= MAX_REGION_INSTRUCTIONS {
        if pc > start && pc >= furthest {
            let closes_loop: bool = back.is_none_or(|head: usize| {
                p.code.get(pc).is_some_and(|raw: &u32| {
                    let closing: Decoded = decode(*raw, dialect);
                    closing.op == Op::Jmp
                        && usize::try_from(jump_target(pc, &closing, dialect)).ok() == Some(head)
                })
            });
            if closes_loop {
                return target.map(|register: u32| (register, pc, back));
            }
        }
        let d: Decoded = decode(*p.code.get(pc)?, dialect);
        if d.op == Op::Jmp {
            let to: usize = usize::try_from(jump_target(pc, &d, dialect)).ok()?;
            if to <= pc {
                if to >= start || back.is_some_and(|head: usize| head != to) {
                    return None;
                }
                back = Some(to);
                furthest = furthest.max(pc + 1);
            } else {
                furthest = furthest.max(to);
            }
        } else if let Some(register) = written_value_register(&d, dialect) {
            target = Some(target.map_or(register, |known: u32| known.min(register)));
            let width: usize = if d.op == Op::TestSet { 2 } else { 1 };
            furthest = furthest.max(pc + width);
        } else if is_compare(d.op) || d.op == Op::Test {
            furthest = furthest.max(pc + 2);
        } else if is_segment_op(&d, dialect) {
            if let Some(lowest) = written_registers(&d, dialect).into_iter().min() {
                target = Some(target.map_or(lowest, |known: u32| known.min(lowest)));
            }
            furthest = furthest.max(pc + 1);
        } else {
            return None;
        }
        pc += 1;
    }
    None
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_value_region(
    state: &mut StructState,
    names: &LocalNames,
    live: &LiveAcrossBranch,
    p: &LuaProto,
    pc: usize,
    dialect: LuaDialect,
    depth: usize,
    ctx: &mut StructuredLift<'_>,
) -> Option<usize> {
    let (target, join, back): (u32, usize, Option<usize>) = region_bounds(p, pc, dialect)?;
    if region_has_external_entry(p, pc, join - 1, dialect) {
        return None;
    }
    let snapshot: &StructState = state;
    let mut trial = |start: usize, end: usize, read: u32| -> Option<String> {
        let mut scratch: StructState = snapshot.clone();
        scratch.inline_values = true;
        let statements: usize = scratch.stmts.len();
        let warnings: usize = scratch.warnings.len();
        let reached: usize = lower_span(
            p,
            dialect,
            depth,
            names,
            live,
            &mut scratch,
            ctx,
            start,
            end,
        )?;
        let clean: bool = reached == end
            && scratch.stmts.len() == statements
            && scratch.warnings.len() == warnings
            && !scratch.bound.get(read as usize).copied().unwrap_or(false);
        let text: String = scratch.reg(read);
        (clean && !text.is_empty()).then_some(text)
    };
    let mut region: Region<'_> = Region {
        state: snapshot,
        p,
        dialect,
        target,
        start: pc,
        join,
        back,
        steps: 0,
        trial: &mut trial,
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
