use std::collections::{BTreeMap, BTreeSet};

use crate::decompile_struct::{BlockId, Region};

#[derive(Debug, Clone)]
enum Scope {
    Loop { label: Option<u32>, exits: Vec<u32> },
    Switch,
    Block,
}

pub(super) fn simplify(root: Region, silent: &BTreeSet<BlockId>) -> Region {
    let mut scopes: Vec<Scope> = Vec::new();
    let rewritten: Region = Rewrite { silent }.rewrite(root, &mut scopes, &[]);
    let mut uses: BTreeMap<u32, usize> = BTreeMap::new();
    count_labels(&rewritten, &mut uses);
    unwrap_unused(rewritten, &uses)
}

const fn is_loop(region: &Region) -> bool {
    matches!(region, Region::While { .. } | Region::DoWhile { .. })
}

struct Rewrite<'a> {
    silent: &'a BTreeSet<BlockId>,
}

impl Rewrite<'_> {
    fn rewrite(&self, region: Region, scopes: &mut Vec<Scope>, tail: &[u32]) -> Region {
        match region {
            Region::Sequence(items) => {
                let last: usize = items
                    .iter()
                    .rposition(|item: &Region| !self.silent_region(item, tail))
                    .unwrap_or(0);
                Region::Sequence(
                    items
                        .into_iter()
                        .enumerate()
                        .map(|(index, item): (usize, Region)| {
                            let item_tail: &[u32] = if index >= last { tail } else { &[] };
                            self.rewrite(item, scopes, item_tail)
                        })
                        .collect(),
                )
            }
            Region::LabeledLoop { label, body } if is_loop(&body) => {
                let mut exits: Vec<u32> = tail.to_vec();
                exits.push(label);
                Region::LabeledLoop {
                    label,
                    body: Box::new(self.rewrite_loop(*body, scopes, Some(label), exits)),
                }
            }
            Region::LabeledLoop { label, body } => {
                let mut inner: Vec<u32> = tail.to_vec();
                inner.push(label);
                scopes.push(Scope::Block);
                let body: Region = self.rewrite(*body, scopes, &inner);
                scopes.pop();
                Region::LabeledLoop {
                    label,
                    body: Box::new(body),
                }
            }
            looped @ (Region::While { .. } | Region::DoWhile { .. }) => {
                self.rewrite_loop(looped, scopes, None, tail.to_vec())
            }
            Region::IfThen {
                head,
                cond_negated,
                then_body,
                join,
            } => Region::IfThen {
                head,
                cond_negated,
                then_body: Box::new(self.rewrite(*then_body, scopes, tail)),
                join,
            },
            Region::IfThenElse {
                head,
                cond_negated,
                then_body,
                else_body,
                join,
            } => {
                let then_body: Region = self.rewrite(*then_body, scopes, tail);
                let else_body: Region = self.rewrite(*else_body, scopes, tail);
                if is_empty(&then_body) && !cond_negated {
                    Region::IfThen {
                        head,
                        cond_negated: true,
                        then_body: Box::new(else_body),
                        join,
                    }
                } else if is_empty(&else_body) {
                    Region::IfThen {
                        head,
                        cond_negated,
                        then_body: Box::new(then_body),
                        join,
                    }
                } else {
                    Region::IfThenElse {
                        head,
                        cond_negated,
                        then_body: Box::new(then_body),
                        else_body: Box::new(else_body),
                        join,
                    }
                }
            }
            Region::Switch {
                head,
                cases,
                default,
                join,
                fallthrough,
                default_position,
            } => {
                scopes.push(Scope::Switch);
                let cases: Vec<(crate::decompile_struct::SwitchKey, Region)> = cases
                    .into_iter()
                    .map(
                        |(key, body): (crate::decompile_struct::SwitchKey, Region)| {
                            (key, self.rewrite(body, scopes, &[]))
                        },
                    )
                    .collect();
                let default: Option<Box<Region>> =
                    default.map(|body: Box<Region>| Box::new(self.rewrite(*body, scopes, &[])));
                scopes.pop();
                Region::Switch {
                    head,
                    cases,
                    default,
                    join,
                    fallthrough,
                    default_position,
                }
            }
            Region::Try { try_body, handlers } => Region::Try {
                try_body: Box::new(self.rewrite(*try_body, scopes, tail)),
                handlers: handlers
                    .into_iter()
                    .map(|(types, handler): (Vec<String>, Region)| {
                        (types, self.rewrite(handler, scopes, tail))
                    })
                    .collect(),
            },
            Region::Break { label: Some(label) } => {
                if tail.contains(&label) {
                    return Region::Sequence(Vec::new());
                }
                let innermost: Option<&Scope> = scopes
                    .iter()
                    .rev()
                    .find(|scope: &&Scope| !matches!(scope, Scope::Block));
                match innermost {
                    Some(Scope::Loop { exits, .. }) if exits.contains(&label) => {
                        Region::Break { label: None }
                    }
                    _ => Region::Break { label: Some(label) },
                }
            }
            Region::Continue {
                label: Some(label),
                latch: None,
            } => {
                let innermost: Option<&Scope> = scopes
                    .iter()
                    .rev()
                    .find(|scope: &&Scope| matches!(scope, Scope::Loop { .. }));
                match innermost {
                    Some(Scope::Loop {
                        label: Some(own), ..
                    }) if *own == label => Region::Continue {
                        label: None,
                        latch: None,
                    },
                    _ => Region::Continue {
                        label: Some(label),
                        latch: None,
                    },
                }
            }
            other => other,
        }
    }

    fn rewrite_loop(
        &self,
        region: Region,
        scopes: &mut Vec<Scope>,
        label: Option<u32>,
        exits: Vec<u32>,
    ) -> Region {
        scopes.push(Scope::Loop { label, exits });
        let rewritten: Region = match region {
            Region::DoWhile { header, body, exit } => Region::DoWhile {
                header,
                body: Box::new(self.rewrite(*body, scopes, &[])),
                exit,
            },
            Region::While { header, body, exit } => Region::While {
                header,
                body: Box::new(self.rewrite(*body, scopes, &[])),
                exit,
            },
            other => other,
        };
        scopes.pop();
        rewritten
    }

    fn silent_region(&self, region: &Region, tail: &[u32]) -> bool {
        match region {
            Region::Block(block) => self.silent.contains(block),
            Region::Break { label: Some(label) } => tail.contains(label),
            Region::Sequence(items) => items
                .iter()
                .all(|item: &Region| self.silent_region(item, tail)),
            _ => false,
        }
    }
}

fn is_empty(region: &Region) -> bool {
    match region {
        Region::Sequence(items) => items.iter().all(is_empty),
        _ => false,
    }
}

fn count_labels(region: &Region, uses: &mut BTreeMap<u32, usize>) {
    match region {
        Region::Break { label: Some(label) }
        | Region::Continue {
            label: Some(label), ..
        } => {
            *uses.entry(*label).or_default() += 1;
        }
        Region::Sequence(items) => {
            for item in items {
                count_labels(item, uses);
            }
        }
        Region::IfThen { then_body, .. } => count_labels(then_body, uses),
        Region::IfThenElse {
            then_body,
            else_body,
            ..
        } => {
            count_labels(then_body, uses);
            count_labels(else_body, uses);
        }
        Region::While { body, .. }
        | Region::DoWhile { body, .. }
        | Region::LabeledLoop { body, .. }
        | Region::Synchronized { body, .. }
        | Region::TryWithResources { try_body: body, .. } => count_labels(body, uses),
        Region::Switch { cases, default, .. } => {
            for (_, body) in cases {
                count_labels(body, uses);
            }
            if let Some(body) = default {
                count_labels(body, uses);
            }
        }
        Region::Try { try_body, handlers } => {
            count_labels(try_body, uses);
            for (_, handler) in handlers {
                count_labels(handler, uses);
            }
        }
        Region::TryFinally {
            try_body,
            handlers,
            finally_body,
            ..
        } => {
            count_labels(try_body, uses);
            count_labels(finally_body, uses);
            for (_, handler) in handlers {
                count_labels(handler, uses);
            }
        }
        Region::Block(_)
        | Region::Break { label: None }
        | Region::Continue { label: None, .. }
        | Region::Irreducible { .. } => {}
    }
}

fn unwrap_unused(region: Region, uses: &BTreeMap<u32, usize>) -> Region {
    let unwrap = |inner: Region| -> Region { unwrap_unused(inner, uses) };
    match region {
        Region::LabeledLoop { label, body } if !uses.contains_key(&label) => unwrap(*body),
        Region::LabeledLoop { label, body } => Region::LabeledLoop {
            label,
            body: Box::new(unwrap(*body)),
        },
        Region::Sequence(items) => {
            let mut flat: Vec<Region> = Vec::with_capacity(items.len());
            for item in items {
                match unwrap(item) {
                    Region::Sequence(nested) => flat.extend(nested),
                    single => flat.push(single),
                }
            }
            match <[Region; 1]>::try_from(flat) {
                Ok([single]) => single,
                Err(flat) => Region::Sequence(flat),
            }
        }
        Region::IfThen {
            head,
            cond_negated,
            then_body,
            join,
        } => Region::IfThen {
            head,
            cond_negated,
            then_body: Box::new(unwrap(*then_body)),
            join,
        },
        Region::IfThenElse {
            head,
            cond_negated,
            then_body,
            else_body,
            join,
        } => Region::IfThenElse {
            head,
            cond_negated,
            then_body: Box::new(unwrap(*then_body)),
            else_body: Box::new(unwrap(*else_body)),
            join,
        },
        Region::While { header, body, exit } => Region::While {
            header,
            body: Box::new(unwrap(*body)),
            exit,
        },
        Region::DoWhile { header, body, exit } => Region::DoWhile {
            header,
            body: Box::new(unwrap(*body)),
            exit,
        },
        Region::Switch {
            head,
            cases,
            default,
            join,
            fallthrough,
            default_position,
        } => Region::Switch {
            head,
            cases: cases
                .into_iter()
                .map(
                    |(key, body): (crate::decompile_struct::SwitchKey, Region)| (key, unwrap(body)),
                )
                .collect(),
            default: default.map(|body: Box<Region>| Box::new(unwrap(*body))),
            join,
            fallthrough,
            default_position,
        },
        Region::Try { try_body, handlers } => Region::Try {
            try_body: Box::new(unwrap(*try_body)),
            handlers: handlers
                .into_iter()
                .map(|(types, handler): (Vec<String>, Region)| (types, unwrap(handler)))
                .collect(),
        },
        other => other,
    }
}
