use crate::decompile::luau_structure::StructuredBlock;
use std::collections::BTreeSet;

const MAX_SCOPE_DEPTH: usize = 200;

pub(super) fn declare_scoped_temps(blocks: &mut [StructuredBlock], outer: BTreeSet<String>) {
    let mut scopes: Vec<BTreeSet<String>> = Vec::new();
    declare_in_block(blocks, &mut scopes, outer);
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
