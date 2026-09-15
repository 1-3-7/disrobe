use std::collections::{BTreeMap, BTreeSet};

use crate::expr::Width;
use crate::rules::error::LoadError;
use crate::rules::oracle;
use crate::rules::schema::{Condition, Pattern, Rule, RuleSet, Template};

const MAX_RULE_TEXT_BYTES: usize = 256 * 1024;
const MAX_RULES: usize = 1024;
const MAX_RULE_NAME_BYTES: usize = 128;
const MAX_CAPTURE_NAME_BYTES: usize = 64;
const MAX_CONDITIONS_PER_RULE: usize = 64;
const MAX_PATTERN_NODES: usize = 4096;
const MAX_TEMPLATE_NODES: usize = 4096;

pub fn load_str(text: &str) -> Result<RuleSet, LoadError> {
    let bytes: usize = text.len();
    if bytes > MAX_RULE_TEXT_BYTES {
        return Err(LoadError::TooLarge {
            bytes,
            max: MAX_RULE_TEXT_BYTES,
        });
    }
    let set: RuleSet = toml::from_str(text)?;
    validate(&set)?;
    Ok(set)
}

fn validate(set: &RuleSet) -> Result<(), LoadError> {
    if set.rules.is_empty() {
        return Err(LoadError::Empty);
    }
    let rule_count: usize = set.rules.len();
    if rule_count > MAX_RULES {
        return Err(LoadError::TooManyRules {
            count: rule_count,
            max: MAX_RULES,
        });
    }
    let mut seen_names: BTreeSet<&str> = BTreeSet::new();
    for rule in &set.rules {
        validate_rule_name(&rule.name)?;
        if !seen_names.insert(rule.name.as_str()) {
            return Err(LoadError::DuplicateRuleName {
                rule: rule.name.clone(),
            });
        }
        validate_rule(rule)?;
    }
    reject_unconditional_cycles(&set.rules)?;
    for rule in &set.rules {
        oracle::grade(rule)?;
    }
    Ok(())
}

fn validate_rule(rule: &Rule) -> Result<(), LoadError> {
    validate_metadata(rule)?;
    let condition_count: usize = rule.when.len();
    if condition_count > MAX_CONDITIONS_PER_RULE {
        return Err(LoadError::TooManyConditions {
            rule: rule.name.clone(),
            count: condition_count,
            max: MAX_CONDITIONS_PER_RULE,
        });
    }
    let mut bound: BTreeSet<&str> = BTreeSet::new();
    collect_pattern_binds(&rule.pattern, &mut bound, rule)?;
    for condition in &rule.when {
        check_condition_refs(condition, &bound, rule)?;
    }
    check_template_refs(&rule.rewrite, &bound, rule)?;
    Ok(())
}

fn validate_metadata(rule: &Rule) -> Result<(), LoadError> {
    if rule.widths.is_empty() {
        return Err(LoadError::MissingWidths {
            rule: rule.name.clone(),
        });
    }
    let mut seen: BTreeSet<u8> = BTreeSet::new();
    for width in &rule.widths {
        if Width::from_bits(u32::from(*width)).is_none() {
            return Err(LoadError::UnsupportedWidth {
                rule: rule.name.clone(),
                width: *width,
            });
        }
        if !seen.insert(*width) {
            return Err(LoadError::DuplicateWidth {
                rule: rule.name.clone(),
                width: *width,
            });
        }
    }
    if rule.proof != "shared_equivalence" {
        return Err(LoadError::MissingProofRoute {
            rule: rule.name.clone(),
        });
    }
    if rule.source.trim().is_empty() {
        return Err(LoadError::MissingSource {
            rule: rule.name.clone(),
        });
    }
    Ok(())
}

fn reject_unconditional_cycles(rules: &[Rule]) -> Result<(), LoadError> {
    let patterns: Vec<String> = rules
        .iter()
        .map(|rule: &Rule| pattern_shape(&rule.pattern))
        .collect();
    let rewrites: Vec<Option<String>> = rules
        .iter()
        .map(|rule: &Rule| rule.when.is_empty().then(|| template_shape(rule)))
        .collect();
    let mut edges: Vec<Vec<usize>> = vec![Vec::new(); rules.len()];
    for (source, rewrite) in rewrites.iter().enumerate() {
        let Some(rewrite) = rewrite else { continue };
        for (target, pattern) in patterns.iter().enumerate() {
            if rewrite == pattern && rules[target].when.is_empty() {
                edges[source].push(target);
            }
        }
    }
    let mut states: Vec<u8> = vec![0; rules.len()];
    for index in 0..rules.len() {
        if states[index] == 0 {
            visit_cycle(index, &edges, &mut states, rules)?;
        }
    }
    Ok(())
}

fn visit_cycle(
    index: usize,
    edges: &[Vec<usize>],
    states: &mut [u8],
    rules: &[Rule],
) -> Result<(), LoadError> {
    states[index] = 1;
    for target in &edges[index] {
        match states[*target] {
            0 => visit_cycle(*target, edges, states, rules)?,
            1 => {
                return Err(LoadError::RewriteCycle {
                    rule: rules[*target].name.clone(),
                });
            }
            2 => {}
            _ => unreachable!(),
        }
    }
    states[index] = 2;
    Ok(())
}

fn pattern_shape(pattern: &Pattern) -> String {
    let mut captures: BTreeMap<String, usize> = BTreeMap::new();
    let mut next_capture: usize = 0;
    pattern_shape_into(pattern, &mut captures, &mut next_capture)
}

fn pattern_shape_into(
    pattern: &Pattern,
    captures: &mut BTreeMap<String, usize>,
    next_capture: &mut usize,
) -> String {
    match pattern {
        Pattern::AnyExpr { bind }
        | Pattern::AnyConst { bind }
        | Pattern::AnyConstSlice { bind }
        | Pattern::AnyConstUnary { bind }
        | Pattern::AnyConstBinary { bind }
        | Pattern::AnyConstCompose { bind } => {
            let index: usize = *captures.entry(bind.clone()).or_insert_with(|| {
                let index: usize = *next_capture;
                *next_capture += 1;
                index
            });
            format!("capture:{index}")
        }
        Pattern::Const { value } => format!("const:{value}"),
        Pattern::Var { index } => format!("var:{index}"),
        Pattern::Unary { op, operand } => format!(
            "unary:{op:?}({})",
            pattern_shape_into(operand, captures, next_capture)
        ),
        Pattern::Binary { op, left, right } => format!(
            "binary:{op:?}({},{})",
            pattern_shape_into(left, captures, next_capture),
            pattern_shape_into(right, captures, next_capture)
        ),
        Pattern::Ite {
            cond,
            then,
            otherwise,
        } => format!(
            "ite({},{},{})",
            pattern_shape_into(cond, captures, next_capture),
            pattern_shape_into(then, captures, next_capture),
            pattern_shape_into(otherwise, captures, next_capture)
        ),
        Pattern::Slice { inner, lo, hi } => format!(
            "slice:{lo}:{hi}({})",
            pattern_shape_into(inner, captures, next_capture)
        ),
        Pattern::Compose {
            low,
            high,
            low_bits,
        } => format!(
            "compose:{low_bits}({},{})",
            pattern_shape_into(low, captures, next_capture),
            pattern_shape_into(high, captures, next_capture)
        ),
    }
}

fn template_shape(rule: &Rule) -> String {
    let mut captures: BTreeMap<String, usize> = BTreeMap::new();
    let mut next_capture: usize = 0;
    let _: String = pattern_shape_into(&rule.pattern, &mut captures, &mut next_capture);
    template_shape_into(&rule.rewrite, &captures)
}

fn template_shape_into(template: &Template, captures: &BTreeMap<String, usize>) -> String {
    match template {
        Template::Use { expr } => format!("capture:{}", captures[expr.as_str()]),
        Template::Const { value } => format!("const:{value}"),
        Template::AllOnes => "all_ones".to_owned(),
        Template::Unary { op, operand } => {
            format!("unary:{op:?}({})", template_shape_into(operand, captures))
        }
        Template::Binary { op, left, right } => format!(
            "binary:{op:?}({},{})",
            template_shape_into(left, captures),
            template_shape_into(right, captures)
        ),
        Template::SliceConst { expr, lo, hi } => {
            format!("slice_const:{lo}:{hi}(capture:{})", captures[expr.as_str()])
        }
        Template::FoldConstSlice { expr } => {
            format!("fold_const_slice(capture:{})", captures[expr.as_str()])
        }
        Template::FoldConstUnary { expr } => {
            format!("fold_const_unary(capture:{})", captures[expr.as_str()])
        }
        Template::FoldConstBinary { expr } => {
            format!("fold_const_binary(capture:{})", captures[expr.as_str()])
        }
        Template::FoldConstCompose { expr } => {
            format!("fold_const_compose(capture:{})", captures[expr.as_str()])
        }
        Template::ComposeConst {
            low,
            high,
            low_bits,
        } => format!(
            "compose_const:{low_bits}(capture:{},capture:{})",
            captures[low.as_str()],
            captures[high.as_str()]
        ),
        Template::FoldShlConst { value, amount } => format!(
            "fold_shl_const(capture:{},capture:{})",
            captures[value.as_str()],
            captures[amount.as_str()]
        ),
        Template::FoldShrConst { value, amount } => format!(
            "fold_shr_const(capture:{},capture:{})",
            captures[value.as_str()],
            captures[amount.as_str()]
        ),
        Template::ShlConstAsMul { expr, amount } => format!(
            "shl_const_as_mul(capture:{},capture:{})",
            captures[expr.as_str()],
            captures[amount.as_str()]
        ),
    }
}

fn collect_pattern_binds<'a>(
    pattern: &'a Pattern,
    bound: &mut BTreeSet<&'a str>,
    rule: &Rule,
) -> Result<(), LoadError> {
    let mut stack: Vec<&'a Pattern> = vec![pattern];
    let mut nodes: usize = 0;
    while let Some(current) = stack.pop() {
        nodes += 1;
        if nodes > MAX_PATTERN_NODES {
            return Err(LoadError::PatternTooLarge {
                rule: rule.name.clone(),
                nodes,
                max: MAX_PATTERN_NODES,
            });
        }
        match current {
            Pattern::AnyExpr { bind }
            | Pattern::AnyConst { bind }
            | Pattern::AnyConstSlice { bind }
            | Pattern::AnyConstUnary { bind }
            | Pattern::AnyConstBinary { bind }
            | Pattern::AnyConstCompose { bind } => {
                validate_capture_name(bind, rule)?;
                if !bound.insert(bind.as_str()) {
                    return Err(LoadError::DuplicateCapture {
                        rule: rule.name.clone(),
                        capture: bind.clone(),
                    });
                }
            }
            Pattern::Const { .. } | Pattern::Var { .. } => {}
            Pattern::Unary { operand, .. } => {
                stack.push(operand);
            }
            Pattern::Binary { left, right, .. } => {
                stack.push(right);
                stack.push(left);
            }
            Pattern::Ite {
                cond,
                then,
                otherwise,
            } => {
                stack.push(otherwise);
                stack.push(then);
                stack.push(cond);
            }
            Pattern::Slice { inner, lo, hi } => {
                validate_slice_range(rule, *lo, *hi)?;
                stack.push(inner);
            }
            Pattern::Compose {
                low,
                high,
                low_bits,
            } => {
                validate_compose_low_bits(rule, *low_bits)?;
                stack.push(high);
                stack.push(low);
            }
        }
    }
    Ok(())
}

fn check_condition_refs(
    condition: &Condition,
    bound: &BTreeSet<&str>,
    rule: &Rule,
) -> Result<(), LoadError> {
    let refs: [&str; 2] = match condition {
        Condition::IsZero { expr }
        | Condition::IsNonZero { expr }
        | Condition::IsOne { expr }
        | Condition::IsAllOnes { expr }
        | Condition::ShiftCountBelowWidth { expr }
        | Condition::ShiftCountAtLeastWidth { expr } => [expr.as_str(), expr.as_str()],
        Condition::Equal { left, right } | Condition::Complement { left, right } => {
            [left.as_str(), right.as_str()]
        }
    };
    for name in refs {
        require_bound(name, bound, rule)?;
    }
    Ok(())
}

fn check_template_refs(
    template: &Template,
    bound: &BTreeSet<&str>,
    rule: &Rule,
) -> Result<(), LoadError> {
    let mut stack: Vec<&Template> = vec![template];
    let mut nodes: usize = 0;
    while let Some(current) = stack.pop() {
        nodes += 1;
        if nodes > MAX_TEMPLATE_NODES {
            return Err(LoadError::TemplateTooLarge {
                rule: rule.name.clone(),
                nodes,
                max: MAX_TEMPLATE_NODES,
            });
        }
        match current {
            Template::Use { expr }
            | Template::FoldConstSlice { expr }
            | Template::FoldConstUnary { expr }
            | Template::FoldConstBinary { expr }
            | Template::FoldConstCompose { expr } => {
                require_bound(expr, bound, rule)?;
            }
            Template::SliceConst { expr, lo, hi } => {
                validate_slice_range(rule, *lo, *hi)?;
                require_bound(expr, bound, rule)?;
            }
            Template::ComposeConst {
                low,
                high,
                low_bits,
            } => {
                validate_compose_low_bits(rule, *low_bits)?;
                require_bound(low, bound, rule)?;
                require_bound(high, bound, rule)?;
            }
            Template::FoldShlConst { value, amount }
            | Template::FoldShrConst { value, amount }
            | Template::ShlConstAsMul {
                expr: value,
                amount,
            } => {
                require_bound(value, bound, rule)?;
                require_bound(amount, bound, rule)?;
            }
            Template::Const { .. } | Template::AllOnes => {}
            Template::Unary { operand, .. } => {
                stack.push(operand);
            }
            Template::Binary { left, right, .. } => {
                stack.push(right);
                stack.push(left);
            }
        }
    }
    Ok(())
}

fn validate_slice_range(rule: &Rule, lo: u32, hi: u32) -> Result<(), LoadError> {
    if lo < hi && hi <= 64 {
        Ok(())
    } else {
        Err(LoadError::InvalidSliceRange {
            rule: rule.name.clone(),
            lo,
            hi,
        })
    }
}

fn validate_compose_low_bits(rule: &Rule, low_bits: u32) -> Result<(), LoadError> {
    if low_bits <= 64 {
        Ok(())
    } else {
        Err(LoadError::InvalidComposeLowBits {
            rule: rule.name.clone(),
            low_bits,
        })
    }
}

fn require_bound(name: &str, bound: &BTreeSet<&str>, rule: &Rule) -> Result<(), LoadError> {
    if bound.contains(name) {
        Ok(())
    } else {
        Err(LoadError::UnboundCapture {
            rule: rule.name.clone(),
            capture: name.to_owned(),
        })
    }
}

fn validate_rule_name(name: &str) -> Result<(), LoadError> {
    let bytes: usize = name.len();
    if bytes > MAX_RULE_NAME_BYTES {
        return Err(LoadError::RuleNameTooLong {
            rule: name.to_owned(),
            bytes,
            max: MAX_RULE_NAME_BYTES,
        });
    }
    if valid_identifier(name) {
        Ok(())
    } else {
        Err(LoadError::InvalidRuleName {
            rule: name.to_owned(),
        })
    }
}

fn validate_capture_name(name: &str, rule: &Rule) -> Result<(), LoadError> {
    let bytes: usize = name.len();
    if bytes > MAX_CAPTURE_NAME_BYTES {
        return Err(LoadError::CaptureNameTooLong {
            rule: rule.name.clone(),
            capture: name.to_owned(),
            bytes,
            max: MAX_CAPTURE_NAME_BYTES,
        });
    }
    if valid_identifier(name) {
        Ok(())
    } else {
        Err(LoadError::InvalidCaptureName {
            rule: rule.name.clone(),
            capture: name.to_owned(),
        })
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::rules::schema::{Binary, Template};

    fn minimal_rule(name: &str) -> Rule {
        Rule {
            name: name.to_owned(),
            widths: vec![8],
            proof: "shared_equivalence".to_owned(),
            source: "test".to_owned(),
            pattern: Pattern::AnyExpr {
                bind: "x".to_owned(),
            },
            when: Vec::new(),
            rewrite: Template::Use {
                expr: "x".to_owned(),
            },
        }
    }

    #[test]
    fn rejects_oversized_rule_text_before_parse() {
        let text: String = "x".repeat(MAX_RULE_TEXT_BYTES + 1);
        let error: LoadError = load_str(&text).unwrap_err();
        assert!(matches!(
            error,
            LoadError::TooLarge {
                bytes,
                max: MAX_RULE_TEXT_BYTES,
            } if bytes == MAX_RULE_TEXT_BYTES + 1
        ));
    }

    #[test]
    fn rejects_too_many_rules() {
        let rules: Vec<Rule> = (0..=MAX_RULES)
            .map(|index: usize| minimal_rule(&format!("rule_{index}")))
            .collect();
        let set: RuleSet = RuleSet {
            commutative_match: false,
            rules,
        };
        let error: LoadError = validate(&set).unwrap_err();
        assert!(matches!(
            error,
            LoadError::TooManyRules {
                count,
                max: MAX_RULES,
            } if count == MAX_RULES + 1
        ));
    }

    #[test]
    fn rejects_invalid_capture_names() {
        let set: RuleSet = RuleSet {
            commutative_match: false,
            rules: vec![Rule {
                name: "bad_capture".to_owned(),
                widths: vec![8],
                proof: "shared_equivalence".to_owned(),
                source: "test".to_owned(),
                pattern: Pattern::AnyExpr {
                    bind: String::new(),
                },
                when: Vec::new(),
                rewrite: Template::Const { value: 0 },
            }],
        };
        let error: LoadError = validate(&set).unwrap_err();
        assert!(matches!(
            error,
            LoadError::InvalidCaptureName {
                rule,
                capture,
            } if rule == "bad_capture" && capture.is_empty()
        ));
    }

    #[test]
    fn rejects_excessive_template_nodes() {
        let mut rewrite: Template = Template::Use {
            expr: "x".to_owned(),
        };
        for _ in 0..MAX_TEMPLATE_NODES {
            rewrite = Template::Binary {
                op: Binary::Add,
                left: Box::new(rewrite),
                right: Box::new(Template::Const { value: 0 }),
            };
        }
        let set: RuleSet = RuleSet {
            commutative_match: false,
            rules: vec![Rule {
                name: "deep_template".to_owned(),
                widths: vec![8],
                proof: "shared_equivalence".to_owned(),
                source: "test".to_owned(),
                pattern: Pattern::AnyExpr {
                    bind: "x".to_owned(),
                },
                when: Vec::new(),
                rewrite,
            }],
        };
        let error: LoadError = validate(&set).unwrap_err();
        assert!(matches!(
            error,
            LoadError::TemplateTooLarge {
                rule,
                nodes,
                max: MAX_TEMPLATE_NODES,
            } if rule == "deep_template" && nodes == MAX_TEMPLATE_NODES + 1
        ));
    }
}
