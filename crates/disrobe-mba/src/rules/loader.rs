use std::collections::BTreeSet;

use crate::rules::error::LoadError;
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
    Ok(())
}

fn validate_rule(rule: &Rule) -> Result<(), LoadError> {
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
            Pattern::AnyExpr { bind } | Pattern::AnyConst { bind } => {
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
        Condition::IsZero { expr } | Condition::IsOne { expr } | Condition::IsAllOnes { expr } => {
            [expr.as_str(), expr.as_str()]
        }
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
            Template::Use { expr } => require_bound(expr, bound, rule)?,
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
