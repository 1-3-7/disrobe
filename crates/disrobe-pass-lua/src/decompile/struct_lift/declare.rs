use crate::decompile::luau_structure::StructuredBlock;
use std::collections::BTreeSet;

const MAX_SCOPE_DEPTH: usize = 200;

pub(super) fn declare_scoped_temps(blocks: &mut Vec<StructuredBlock>, outer: BTreeSet<String>) {
    hoist_branch_locals(blocks, &outer, 0);
    let mut scopes: Vec<BTreeSet<String>> = Vec::new();
    declare_in_block(blocks, &mut scopes, outer);
}

fn hoist_branch_locals(
    blocks: &mut Vec<StructuredBlock>,
    visible: &BTreeSet<String>,
    depth: usize,
) {
    if depth >= MAX_SCOPE_DEPTH {
        return;
    }
    let mut in_scope: BTreeSet<String> = visible.clone();
    let mut index: usize = 0;
    while index < blocks.len() {
        match &mut blocks[index] {
            StructuredBlock::Raw(text) => {
                in_scope.extend(declared_names(text));
            }
            StructuredBlock::If {
                then_body,
                else_body,
                ..
            } => {
                hoist_branch_locals(then_body, &in_scope, depth + 1);
                hoist_branch_locals(else_body, &in_scope, depth + 1);
            }
            StructuredBlock::While { body, .. } | StructuredBlock::Repeat { body, .. } => {
                hoist_branch_locals(body, &in_scope, depth + 1);
            }
            StructuredBlock::NumericFor { var, body, .. } => {
                let mut inner: BTreeSet<String> = in_scope.clone();
                inner.insert(var.clone());
                hoist_branch_locals(body, &inner, depth + 1);
            }
            StructuredBlock::GenericFor { vars, body, .. } => {
                let mut inner: BTreeSet<String> = in_scope.clone();
                inner.extend(vars.iter().cloned());
                hoist_branch_locals(body, &inner, depth + 1);
            }
            StructuredBlock::Break
            | StructuredBlock::Goto { .. }
            | StructuredBlock::Label { .. } => {}
        }
        let mut declared: BTreeSet<String> = BTreeSet::new();
        if_declarations(&blocks[index], &mut declared, depth);
        let hoisted: Vec<String> = declared
            .into_iter()
            .filter(|name: &String| {
                blocks[index + 1..]
                    .iter()
                    .any(|later: &StructuredBlock| block_mentions(later, name, 0))
            })
            .collect();
        if hoisted.is_empty() {
            index += 1;
            continue;
        }
        undeclare_in_if(&mut blocks[index], &hoisted, depth);
        let closure_captures: bool = blocks[index..].iter().any(|block: &StructuredBlock| {
            hoisted
                .iter()
                .any(|name: &String| block_captures_in_closure(block, name, 0))
        });
        if !closure_captures {
            for later in &mut blocks[index + 1..] {
                if let Some(name) = single_temp_declaration(later)
                    && hoisted.contains(&name)
                    && let StructuredBlock::Raw(text) = later
                    && let Some(rest) = text.strip_prefix("local ")
                    && rest.contains(" = ")
                {
                    *text = rest.to_owned();
                }
            }
        }
        let fresh: Vec<String> = hoisted
            .into_iter()
            .filter(|name: &String| !in_scope.contains(name))
            .collect();
        if fresh.is_empty() {
            index += 1;
            continue;
        }
        in_scope.extend(fresh.iter().cloned());
        blocks.insert(
            index,
            StructuredBlock::Raw(format!("local {}", fresh.join(", "))),
        );
        index += 2;
    }
}

fn declared_names(text: &str) -> Vec<String> {
    let head: &str = text.lines().next().unwrap_or_default();
    let Some(rest) = head.strip_prefix("local ") else {
        return Vec::new();
    };
    if let Some(function) = rest.strip_prefix("function ") {
        return vec![
            function
                .split('(')
                .next()
                .unwrap_or_default()
                .trim()
                .to_owned(),
        ];
    }
    rest.split_once(" = ")
        .map_or(rest, |(lhs, _)| lhs)
        .split(',')
        .map(|name: &str| name.trim().to_owned())
        .filter(|name: &String| !name.is_empty())
        .collect()
}

fn if_declarations(block: &StructuredBlock, out: &mut BTreeSet<String>, depth: usize) {
    let StructuredBlock::If {
        then_body,
        else_body,
        ..
    } = block
    else {
        return;
    };
    if depth >= MAX_SCOPE_DEPTH {
        return;
    }
    for inner in then_body.iter().chain(else_body.iter()) {
        if let Some(name) = single_temp_declaration(inner).or_else(|| single_temp_assignment(inner))
        {
            out.insert(name);
        }
        if_declarations(inner, out, depth + 1);
    }
}

fn single_temp_assignment(block: &StructuredBlock) -> Option<String> {
    let StructuredBlock::Raw(text) = block else {
        return None;
    };
    let head: &str = text.lines().next().unwrap_or_default();
    let (lhs, _): (&str, &str) = head.split_once(" = ")?;
    let name: &str = lhs.trim();
    is_synthetic_temp(name).then(|| name.to_owned())
}

fn block_captures_in_closure(block: &StructuredBlock, name: &str, depth: usize) -> bool {
    if depth >= MAX_SCOPE_DEPTH {
        return true;
    }
    let in_body = |body: &[StructuredBlock]| {
        body.iter()
            .any(|inner: &StructuredBlock| block_captures_in_closure(inner, name, depth + 1))
    };
    match block {
        StructuredBlock::Raw(text) => {
            text.contains("function") && super::contains_ident(text, name)
        }
        StructuredBlock::If {
            then_body,
            else_body,
            ..
        } => in_body(then_body) || in_body(else_body),
        StructuredBlock::While { body, .. }
        | StructuredBlock::Repeat { body, .. }
        | StructuredBlock::NumericFor { body, .. }
        | StructuredBlock::GenericFor { body, .. } => in_body(body),
        StructuredBlock::Break | StructuredBlock::Goto { .. } | StructuredBlock::Label { .. } => {
            false
        }
    }
}

fn single_temp_declaration(block: &StructuredBlock) -> Option<String> {
    let StructuredBlock::Raw(text) = block else {
        return None;
    };
    let head: &str = text.lines().next().unwrap_or_default();
    let rest: &str = head.strip_prefix("local ")?;
    let name: &str = rest.split_once(" = ").map_or(rest, |(lhs, _)| lhs).trim();
    is_synthetic_temp(name).then(|| name.to_owned())
}

fn undeclare_in_if(block: &mut StructuredBlock, hoisted: &[String], depth: usize) {
    let StructuredBlock::If {
        then_body,
        else_body,
        ..
    } = block
    else {
        return;
    };
    if depth >= MAX_SCOPE_DEPTH {
        return;
    }
    for body in [then_body, else_body] {
        body.retain_mut(|inner: &mut StructuredBlock| {
            let Some(name) = single_temp_declaration(inner) else {
                return true;
            };
            if !hoisted.contains(&name) {
                return true;
            }
            let StructuredBlock::Raw(text) = inner else {
                return true;
            };
            match text.strip_prefix("local ") {
                Some(rest) if rest.contains(" = ") => {
                    *text = rest.to_owned();
                    true
                }
                _ => false,
            }
        });
        for inner in body.iter_mut() {
            undeclare_in_if(inner, hoisted, depth + 1);
        }
    }
}

fn block_mentions(block: &StructuredBlock, name: &str, depth: usize) -> bool {
    if depth >= MAX_SCOPE_DEPTH {
        return true;
    }
    let in_body = |body: &[StructuredBlock]| {
        body.iter()
            .any(|inner: &StructuredBlock| block_mentions(inner, name, depth + 1))
    };
    match block {
        StructuredBlock::Raw(text) => super::contains_ident(text, name),
        StructuredBlock::If {
            cond,
            then_body,
            else_body,
        } => super::contains_ident(cond, name) || in_body(then_body) || in_body(else_body),
        StructuredBlock::While { cond, body } | StructuredBlock::Repeat { cond, body } => {
            super::contains_ident(cond, name) || in_body(body)
        }
        StructuredBlock::NumericFor {
            init,
            limit,
            step,
            body,
            ..
        } => {
            super::contains_ident(init, name)
                || super::contains_ident(limit, name)
                || super::contains_ident(step, name)
                || in_body(body)
        }
        StructuredBlock::GenericFor { iter, body, .. } => {
            super::contains_ident(iter, name) || in_body(body)
        }
        StructuredBlock::Break | StructuredBlock::Goto { .. } | StructuredBlock::Label { .. } => {
            false
        }
    }
}

fn declare_in_block(
    blocks: &mut [StructuredBlock],
    scopes: &mut Vec<BTreeSet<String>>,
    opened: BTreeSet<String>,
) {
    if scopes.len() >= MAX_SCOPE_DEPTH {
        return;
    }
    scopes.push(opened);
    for block in blocks.iter_mut() {
        match block {
            StructuredBlock::Raw(text) => declare_statement(text, scopes),
            StructuredBlock::If {
                then_body,
                else_body,
                ..
            } => {
                declare_in_block(then_body, scopes, BTreeSet::new());
                declare_in_block(else_body, scopes, BTreeSet::new());
            }
            StructuredBlock::While { body, .. } | StructuredBlock::Repeat { body, .. } => {
                declare_in_block(body, scopes, BTreeSet::new());
            }
            StructuredBlock::NumericFor { var, body, .. } => {
                declare_in_block(body, scopes, BTreeSet::from([var.clone()]));
            }
            StructuredBlock::GenericFor { vars, body, .. } => {
                declare_in_block(body, scopes, vars.iter().cloned().collect());
            }
            StructuredBlock::Break
            | StructuredBlock::Goto { .. }
            | StructuredBlock::Label { .. } => {}
        }
    }
    scopes.pop();
}

fn declare_statement(text: &mut String, scopes: &mut [BTreeSet<String>]) {
    let head: &str = text.lines().next().unwrap_or_default();
    if let Some(rest) = head.strip_prefix("local function ") {
        let name: &str = rest.split('(').next().unwrap_or_default().trim();
        declare(scopes, name);
        return;
    }
    if let Some(rest) = head.strip_prefix("local ") {
        let names: &str = rest.split_once(" = ").map_or(rest, |(lhs, _)| lhs);
        for name in names.split(',') {
            declare(scopes, name.trim());
        }
        return;
    }
    let Some((lhs, _)) = head.split_once(" = ") else {
        return;
    };
    let targets: Vec<&str> = lhs.split(',').map(str::trim).collect();
    if !targets.iter().all(|name: &&str| is_plain_name(name)) {
        return;
    }
    let undeclared: Vec<String> = targets
        .iter()
        .filter(|name: &&&str| is_synthetic_temp(name) && !is_declared(scopes, name))
        .map(|name: &&str| (*name).to_owned())
        .collect();
    if undeclared.is_empty() {
        return;
    }
    for name in &undeclared {
        declare(scopes, name);
    }
    if undeclared.len() == targets.len() {
        text.insert_str(0, "local ");
    } else {
        text.insert_str(0, &format!("local {}\n", undeclared.join(", ")));
    }
}

fn is_plain_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b: u8| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b: u8| b.is_ascii_alphanumeric() || b == b'_')
}

fn declare(scopes: &mut [BTreeSet<String>], name: &str) {
    if let Some(scope) = scopes.last_mut()
        && !name.is_empty()
    {
        scope.insert(name.to_owned());
    }
}

fn is_declared(scopes: &[BTreeSet<String>], name: &str) -> bool {
    scopes
        .iter()
        .any(|scope: &BTreeSet<String>| scope.contains(name))
}

fn is_synthetic_temp(name: &str) -> bool {
    let Some(rest) = name.strip_prefix('v') else {
        return false;
    };
    let digits: &str = rest.trim_end_matches('_');
    !digits.is_empty() && digits.bytes().all(|b: u8| b.is_ascii_digit())
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    fn raw(text: &str) -> StructuredBlock {
        StructuredBlock::Raw(text.to_owned())
    }

    fn raw_text(block: &StructuredBlock) -> &str {
        match block {
            StructuredBlock::Raw(text) => text,
            _ => "",
        }
    }

    #[test]
    fn a_temp_reused_after_its_block_is_declared_again() {
        let mut blocks: Vec<StructuredBlock> = vec![
            StructuredBlock::Repeat {
                cond: "v3 >= 6".to_owned(),
                body: vec![raw("local v3 = v2 * 2"), raw("v2 = v2 + 1")],
            },
            raw("v3 = 5"),
            raw("v2 = 0"),
        ];

        declare_scoped_temps(&mut blocks, BTreeSet::new());

        assert_eq!(raw_text(&blocks[1]), "local v3 = 5");
        assert_eq!(
            raw_text(&blocks[2]),
            "local v2 = 0",
            "v2 is never declared in any enclosing scope"
        );
    }

    #[test]
    fn a_temp_declared_in_an_enclosing_scope_stays_an_assignment() {
        let mut blocks: Vec<StructuredBlock> = vec![
            raw("local v4 = 0"),
            StructuredBlock::If {
                cond: "c".to_owned(),
                then_body: vec![raw("v4 = 1")],
                else_body: vec![raw("local v5 = 2"), raw("v5 = 3")],
            },
            raw("print(v4)"),
        ];

        declare_scoped_temps(&mut blocks, BTreeSet::new());

        let StructuredBlock::If {
            then_body,
            else_body,
            ..
        } = &blocks[1]
        else {
            panic!("the if survives");
        };
        assert_eq!(raw_text(&then_body[0]), "v4 = 1");
        assert_eq!(raw_text(&else_body[1]), "v5 = 3");
    }

    #[test]
    fn a_sibling_branch_reusing_a_slot_declares_its_own_temp() {
        let mut blocks: Vec<StructuredBlock> = vec![StructuredBlock::If {
            cond: "c".to_owned(),
            then_body: vec![raw("local v16 = #t + 1")],
            else_body: vec![raw("v16 = #t + 1"), raw("t[v16] = \"IN\"")],
        }];

        declare_scoped_temps(&mut blocks, BTreeSet::new());

        let StructuredBlock::If { else_body, .. } = &blocks[0] else {
            panic!("the if survives");
        };
        assert_eq!(raw_text(&else_body[0]), "local v16 = #t + 1");
        assert_eq!(raw_text(&else_body[1]), "t[v16] = \"IN\"");
    }

    #[test]
    fn source_names_stay_assignments_and_mixed_targets_declare_only_the_new_temps() {
        let mut blocks: Vec<StructuredBlock> = vec![
            raw("g_counter = 1"),
            raw("value = v1"),
            raw("local v1 = 0"),
            raw("v1, v9 = f()"),
            raw("x.v2 = 3"),
            raw("g, v12 = 1, 2"),
            raw("v9 = 4"),
        ];

        declare_scoped_temps(&mut blocks, BTreeSet::new());

        assert_eq!(raw_text(&blocks[0]), "g_counter = 1");
        assert_eq!(raw_text(&blocks[1]), "value = v1");
        assert_eq!(raw_text(&blocks[3]), "local v9\nv1, v9 = f()");
        assert_eq!(raw_text(&blocks[4]), "x.v2 = 3");
        assert_eq!(raw_text(&blocks[5]), "local v12\ng, v12 = 1, 2");
        assert_eq!(raw_text(&blocks[6]), "v9 = 4");
    }

    #[test]
    fn a_temp_declared_in_both_branches_and_read_after_the_if_is_hoisted() {
        let mut blocks: Vec<StructuredBlock> = vec![
            StructuredBlock::If {
                cond: "not v1".to_owned(),
                then_body: vec![raw("local v5 = (not v2)")],
                else_body: vec![raw("local v5 = false")],
            },
            raw("return v1, v5"),
        ];

        declare_scoped_temps(&mut blocks, BTreeSet::new());

        assert_eq!(raw_text(&blocks[0]), "local v5");
        let StructuredBlock::If {
            then_body,
            else_body,
            ..
        } = &blocks[1]
        else {
            panic!("the if survives");
        };
        assert_eq!(raw_text(&then_body[0]), "v5 = (not v2)");
        assert_eq!(raw_text(&else_body[0]), "v5 = false");
    }

    #[test]
    fn a_branch_local_nobody_reads_later_and_a_loop_local_stay_in_place() {
        let mut blocks: Vec<StructuredBlock> = vec![
            StructuredBlock::If {
                cond: "c".to_owned(),
                then_body: vec![raw("local v5 = 1"), raw("print(v5)")],
                else_body: Vec::new(),
            },
            StructuredBlock::While {
                cond: "true".to_owned(),
                body: vec![raw("local v6 = f()"), raw("g(function() return v6 end)")],
            },
            raw("print(v6)"),
        ];

        declare_scoped_temps(&mut blocks, BTreeSet::new());

        let StructuredBlock::If { then_body, .. } = &blocks[0] else {
            panic!("the if stays first");
        };
        assert_eq!(raw_text(&then_body[0]), "local v5 = 1");
        let StructuredBlock::While { body, .. } = &blocks[1] else {
            panic!("the loop stays second");
        };
        assert_eq!(raw_text(&body[0]), "local v6 = f()");
    }

    #[test]
    fn a_hoisted_temp_already_in_scope_is_assigned_not_redeclared() {
        let mut blocks: Vec<StructuredBlock> = vec![
            raw("local v9 = f()"),
            StructuredBlock::If {
                cond: "not v9".to_owned(),
                then_body: vec![
                    raw("v9 = g()"),
                    StructuredBlock::If {
                        cond: "not v9".to_owned(),
                        then_body: vec![raw("local v9 = h()")],
                        else_body: Vec::new(),
                    },
                ],
                else_body: Vec::new(),
            },
            raw("print(v9)"),
        ];

        declare_scoped_temps(&mut blocks, BTreeSet::new());

        assert_eq!(blocks.len(), 3, "no second declaration: {blocks:?}");
        let StructuredBlock::If { then_body, .. } = &blocks[1] else {
            panic!("the if survives");
        };
        let StructuredBlock::If {
            then_body: inner, ..
        } = &then_body[1]
        else {
            panic!("the nested if survives");
        };
        assert_eq!(raw_text(&inner[0]), "v9 = h()");
    }

    #[test]
    fn a_temp_assigned_in_an_if_and_declared_after_it_becomes_one_variable() {
        let mut blocks: Vec<StructuredBlock> = vec![
            StructuredBlock::If {
                cond: "f()".to_owned(),
                then_body: vec![raw("v8 = g()"), StructuredBlock::Goto { pc: 9 }],
                else_body: Vec::new(),
            },
            raw("local v8 = h()"),
            StructuredBlock::Label { pc: 9 },
            raw("print(v8)"),
        ];

        declare_scoped_temps(&mut blocks, BTreeSet::new());

        assert_eq!(raw_text(&blocks[0]), "local v8");
        assert_eq!(raw_text(&blocks[2]), "v8 = h()");
    }

    #[test]
    fn loop_variables_are_declared_for_their_body() {
        let mut blocks: Vec<StructuredBlock> = vec![StructuredBlock::NumericFor {
            var: "v7".to_owned(),
            init: "1".to_owned(),
            limit: "3".to_owned(),
            step: "1".to_owned(),
            body: vec![raw("v7 = v7 + 1")],
        }];

        declare_scoped_temps(&mut blocks, BTreeSet::new());

        let StructuredBlock::NumericFor { body, .. } = &blocks[0] else {
            panic!("the loop survives");
        };
        assert_eq!(raw_text(&body[0]), "v7 = v7 + 1");
    }
}
