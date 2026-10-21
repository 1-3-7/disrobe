use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use crate::dalvik::DalvikInsn;
use crate::dex::{CodeItem, DexFile, MethodId, ProtoId};

const MAX_WRAPPER_HOPS: usize = 4;
const MAX_REFLECTION_TABLE: usize = 65_536;

pub(crate) fn trace_order(insns: &[DalvikInsn]) -> Vec<&DalvikInsn> {
    let index_by_pc: BTreeMap<u32, usize> = insns
        .iter()
        .enumerate()
        .map(|(i, insn): (usize, &DalvikInsn)| (insn.pc, i))
        .collect();
    let mut visited: Vec<bool> = vec![false; insns.len()];
    let mut out: Vec<&DalvikInsn> = Vec::with_capacity(insns.len());
    let mut cursor: usize = 0;
    loop {
        while cursor < insns.len() && visited[cursor] {
            cursor += 1;
        }
        if cursor >= insns.len() {
            break;
        }
        let mut at: usize = cursor;
        while at < insns.len() && !visited[at] {
            visited[at] = true;
            let insn: &DalvikInsn = &insns[at];
            match insn.op {
                0x00 => at += 1,
                0x28..=0x2A => match insn
                    .branch_target_pc()
                    .and_then(|pc: u32| index_by_pc.get(&pc))
                {
                    Some(&target) => at = target,
                    None => break,
                },
                _ => {
                    out.push(insn);
                    at += 1;
                }
            }
        }
    }
    out
}

#[derive(Debug, Clone, Copy)]
struct Target {
    method: u32,
    is_static: bool,
}

#[derive(Debug, Clone)]
struct MethodRef {
    class: String,
    name: String,
}

#[derive(Debug, Clone)]
enum Tracked {
    Class(String),
    Str(String),
    Method(MethodRef),
}

#[derive(Debug, Default)]
pub(crate) struct CallResolver {
    wrappers: BTreeMap<u32, Target>,
    wrapper_bodies: BTreeSet<(String, String, String)>,
    reflection: BTreeMap<String, Vec<MethodRef>>,
}

#[derive(Debug)]
pub(crate) struct ResolvedCall<'a> {
    pub(crate) method: Cow<'a, MethodId>,
    pub(crate) receiver: Option<u16>,
    pub(crate) params: Vec<u16>,
}

impl CallResolver {
    pub(crate) fn analyze(dex: &DexFile, items: &[&CodeItem]) -> Self {
        let index_by_sig: BTreeMap<(&str, &str, String), u32> = dex
            .method_ids
            .iter()
            .enumerate()
            .filter_map(|(i, m): (usize, &MethodId)| {
                let index: u32 = u32::try_from(i).ok()?;
                Some((
                    (
                        m.class.as_str(),
                        m.name.as_str(),
                        crate::dalvik_interp::method_descriptor(m),
                    ),
                    index,
                ))
            })
            .collect();
        let mut wrappers: BTreeMap<u32, Target> = BTreeMap::new();
        let mut wrapper_items: BTreeMap<u32, (String, String, String)> = BTreeMap::new();
        let mut invoked: BTreeSet<u32> = BTreeSet::new();
        let mut reflection: BTreeMap<String, Vec<MethodRef>> = BTreeMap::new();
        for item in items {
            let insns: Vec<DalvikInsn> = crate::dalvik::decode_method(&item.insns);
            let body: Vec<&DalvikInsn> = trace_order(&insns);
            invoked.extend(
                body.iter()
                    .filter(|insn: &&&DalvikInsn| matches!(insn.op, 0x6E..=0x72 | 0x74..=0x78))
                    .filter_map(|insn: &&DalvikInsn| insn.index),
            );
            if item.method_name == "<clinit>" {
                let table: Vec<MethodRef> = reflection_table(dex, &body);
                if !table.is_empty() {
                    reflection.insert(item.class.clone(), table);
                }
                continue;
            }
            if !item.is_direct {
                continue;
            }
            let Some(target) = wrapper_target(dex, item, &body) else {
                continue;
            };
            let key: (&str, &str, String) = (
                item.class.as_str(),
                item.method_name.as_str(),
                item.method_descriptor.clone(),
            );
            if let Some(&wrapper) = index_by_sig.get(&key) {
                wrappers.insert(wrapper, target);
                wrapper_items.insert(
                    wrapper,
                    (
                        item.class.clone(),
                        item.method_name.clone(),
                        item.method_descriptor.clone(),
                    ),
                );
            }
        }
        let wrapper_bodies: BTreeSet<(String, String, String)> = wrapper_items
            .into_iter()
            .filter(|(index, _): &(u32, (String, String, String))| invoked.contains(index))
            .map(|(_, key): (u32, (String, String, String))| key)
            .collect();
        Self {
            wrappers,
            wrapper_bodies,
            reflection,
        }
    }

    pub(crate) fn is_wrapper(&self, item: &CodeItem) -> bool {
        self.wrapper_bodies.contains(&(
            item.class.clone(),
            item.method_name.clone(),
            item.method_descriptor.clone(),
        ))
    }

    pub(crate) fn resolve<'a>(
        &self,
        dex: &'a DexFile,
        insn: &DalvikInsn,
        literal: impl Fn(u16) -> Option<i64>,
    ) -> Option<ResolvedCall<'a>> {
        if !matches!(insn.op, 0x6E..=0x72 | 0x74..=0x78) {
            return None;
        }
        let mut index: u32 = insn.index?;
        let mut is_static: bool = matches!(insn.op, 0x71 | 0x77);
        for _ in 0..MAX_WRAPPER_HOPS {
            match self.wrappers.get(&index) {
                Some(target) => {
                    index = target.method;
                    is_static = target.is_static;
                }
                None => break,
            }
        }
        let method: &MethodId = dex.method_ids.get(usize::try_from(index).ok()?)?;
        if let Some(table) = self.reflection.get(&method.class)
            && is_static
            && method.proto.parameters.as_slice()
                == ["I", "Ljava/lang/Object;", "[Ljava/lang/Object;"]
            && let Some(&index_reg) = insn.regs.first()
            && let Some(slot) = literal(index_reg).and_then(|v: i64| usize::try_from(v).ok())
            && let Some(target) = table.get(slot)
        {
            let known: Option<&MethodId> = dex
                .method_ids
                .iter()
                .find(|m: &&MethodId| m.class == target.class && m.name == target.name);
            let method: Cow<'a, MethodId> = known.map_or_else(
                || {
                    Cow::Owned(MethodId {
                        class: target.class.clone(),
                        proto: ProtoId {
                            shorty: "L".to_owned(),
                            return_type: "Ljava/lang/Object;".to_owned(),
                            parameters: Vec::new(),
                        },
                        name: target.name.clone(),
                    })
                },
                Cow::Borrowed,
            );
            return Some(ResolvedCall {
                method,
                receiver: insn.regs.get(1).copied(),
                params: Vec::new(),
            });
        }
        let receiver: Option<u16> = if is_static {
            None
        } else {
            insn.regs.first().copied()
        };
        let params: Vec<u16> = insn
            .regs
            .iter()
            .skip(usize::from(!is_static))
            .copied()
            .collect();
        Some(ResolvedCall {
            method: Cow::Borrowed(method),
            receiver,
            params,
        })
    }
}

fn wrapper_target(dex: &DexFile, item: &CodeItem, body: &[&DalvikInsn]) -> Option<Target> {
    let call: &DalvikInsn = body.first()?;
    if !matches!(call.op, 0x6E..=0x72 | 0x74..=0x78) {
        return None;
    }
    let first_param: u16 = item.registers_size.checked_sub(item.ins_size)?;
    let expected: Vec<u16> = (first_param..item.registers_size).collect();
    if call.regs != expected {
        return None;
    }
    let method: &MethodId = dex.method_ids.get(usize::try_from(call.index?).ok()?)?;
    let is_static: bool = matches!(call.op, 0x71 | 0x77);
    let rest: &[&DalvikInsn] = &body[1..];
    let passes_through: bool = match rest {
        [ret] => ret.op == 0x0E && method.proto.return_type == "V",
        [moved, ret] => {
            matches!(moved.op, 0x0A..=0x0C)
                && matches!(ret.op, 0x0F..=0x11)
                && moved.regs.first() == ret.regs.first()
        }
        _ => false,
    };
    passes_through.then_some(Target {
        method: call.index?,
        is_static,
    })
}

fn reflection_table(dex: &DexFile, body: &[&DalvikInsn]) -> Vec<MethodRef> {
    let mut regs: BTreeMap<u16, Tracked> = BTreeMap::new();
    let mut pending: Option<Tracked> = None;
    let mut table: Vec<MethodRef> = Vec::new();
    for insn in body {
        match insn.op {
            0x1A | 0x1B => {
                if let (Some(&dest), Some(text)) = (
                    insn.regs.first(),
                    insn.index
                        .and_then(|i: u32| dex.strings.get(usize::try_from(i).ok()?)),
                ) {
                    regs.insert(dest, Tracked::Str(text.clone()));
                }
            }
            0x1C => {
                if let (Some(&dest), Some(descriptor)) = (
                    insn.regs.first(),
                    insn.index
                        .and_then(|i: u32| dex.type_names.get(usize::try_from(i).ok()?)),
                ) {
                    regs.insert(dest, Tracked::Class(descriptor.clone()));
                }
            }
            0x0A..=0x0C => {
                if let Some(&dest) = insn.regs.first() {
                    match pending.take() {
                        Some(value) => {
                            regs.insert(dest, value);
                        }
                        None => {
                            regs.remove(&dest);
                        }
                    }
                }
            }
            0x6E..=0x72 | 0x74..=0x78 => {
                pending = None;
                let Some(method) = insn
                    .index
                    .and_then(|i: u32| dex.method_ids.get(usize::try_from(i).ok()?))
                else {
                    continue;
                };
                let arg = |n: usize| insn.regs.get(n).and_then(|r: &u16| regs.get(r));
                match (method.class.as_str(), method.name.as_str()) {
                    ("Ljava/lang/Class;", "getDeclaredMethod" | "getMethod") => {
                        if let (Some(Tracked::Class(class)), Some(Tracked::Str(name))) =
                            (arg(0), arg(1))
                        {
                            pending = Some(Tracked::Method(MethodRef {
                                class: class.clone(),
                                name: name.clone(),
                            }));
                        }
                    }
                    ("Ljava/util/List;" | "Ljava/util/ArrayList;", "add") => {
                        if let Some(Tracked::Method(method_ref)) = arg(1)
                            && table.len() < MAX_REFLECTION_TABLE
                        {
                            table.push(method_ref.clone());
                        }
                    }
                    _ => {}
                }
            }
            _ => {
                if matches!(insn.op, 0x01..=0x09)
                    && let (Some(&dest), Some(&src)) = (insn.regs.first(), insn.regs.get(1))
                {
                    match regs.get(&src).cloned() {
                        Some(value) => {
                            regs.insert(dest, value);
                        }
                        None => {
                            regs.remove(&dest);
                        }
                    }
                }
            }
        }
    }
    table
}
