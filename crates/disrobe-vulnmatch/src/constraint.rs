use std::cmp::Ordering;

use thiserror::Error;

use crate::version::{VersionError, VersionScheme, compare_versions};

const MAX_CONSTRAINT_BYTES: usize = 8 * 1024;
const MAX_CONSTRAINT_NODES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ComparisonOperator {
    Less,
    LessEqual,
    Equal,
    NotEqual,
    GreaterEqual,
    Greater,
    Caret,
    Tilde,
    Compatible,
    Wildcard,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Predicate {
    operator: ComparisonOperator,
    version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConstraintExpression {
    Predicate(Predicate),
    All(Vec<Self>),
    Any(Vec<Self>),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[allow(clippy::redundant_pub_crate)]
pub(crate) enum ConstraintError {
    #[error("constraint is empty")]
    Empty,
    #[error("constraint is {actual} bytes, exceeding the {limit}-byte limit")]
    TooLong { actual: usize, limit: usize },
    #[error("constraint has more than {limit} predicates")]
    TooManyPredicates { limit: usize },
    #[error("constraint is nonconforming for {scheme:?}: {constraint}")]
    Nonconforming {
        scheme: VersionScheme,
        constraint: String,
    },
    #[error(transparent)]
    Version(#[from] VersionError),
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn evaluate_constraint(
    scheme: VersionScheme,
    version: &str,
    constraint: &str,
) -> Result<bool, ConstraintError> {
    let expression: ConstraintExpression = parse_constraint(scheme, constraint)?;
    evaluate_expression(scheme, version, &expression)
}

fn parse_constraint(
    scheme: VersionScheme,
    constraint: &str,
) -> Result<ConstraintExpression, ConstraintError> {
    let trimmed: &str = constraint.trim();
    if trimmed.is_empty() {
        return Err(ConstraintError::Empty);
    }
    if trimmed.len() > MAX_CONSTRAINT_BYTES {
        return Err(ConstraintError::TooLong {
            actual: trimmed.len(),
            limit: MAX_CONSTRAINT_BYTES,
        });
    }
    let union_count: usize = trimmed.matches("||").count().saturating_add(1);
    let mut alternatives: Vec<ConstraintExpression> = Vec::new();
    alternatives.try_reserve_exact(union_count).map_err(|_| {
        ConstraintError::TooManyPredicates {
            limit: MAX_CONSTRAINT_NODES,
        }
    })?;
    let mut nodes: usize = 0;
    for alternative in trimmed.split("||") {
        let terms: Vec<ConstraintExpression> = parse_conjunction(scheme, alternative, &mut nodes)?;
        alternatives.push(if terms.len() == 1 {
            terms
                .into_iter()
                .next()
                .ok_or_else(|| nonconforming(scheme, trimmed))?
        } else {
            ConstraintExpression::All(terms)
        });
    }
    if alternatives.len() == 1 {
        alternatives
            .into_iter()
            .next()
            .ok_or_else(|| nonconforming(scheme, trimmed))
    } else {
        Ok(ConstraintExpression::Any(alternatives))
    }
}

fn parse_conjunction(
    scheme: VersionScheme,
    source: &str,
    nodes: &mut usize,
) -> Result<Vec<ConstraintExpression>, ConstraintError> {
    let mut terms: Vec<ConstraintExpression> = Vec::new();
    let normalized: String = source.replace(',', " ");
    let tokens: Vec<&str> = normalized.split_whitespace().collect();
    let mut index: usize = 0;
    while index < tokens.len() {
        let token: &str = tokens[index];
        let (operator_text, version_text, consumed): (&str, &str, usize) =
            if is_operator_token(token) {
                let version: &str = tokens
                    .get(index + 1)
                    .copied()
                    .ok_or_else(|| nonconforming(scheme, source))?;
                (token, version, 2)
            } else {
                let (operator, version): (&str, &str) = split_operator(token);
                (operator, version, 1)
            };
        if version_text.is_empty() {
            return Err(nonconforming(scheme, source));
        }
        *nodes = nodes
            .checked_add(1)
            .ok_or(ConstraintError::TooManyPredicates {
                limit: MAX_CONSTRAINT_NODES,
            })?;
        if *nodes > MAX_CONSTRAINT_NODES {
            return Err(ConstraintError::TooManyPredicates {
                limit: MAX_CONSTRAINT_NODES,
            });
        }
        let operator: ComparisonOperator = parse_operator(scheme, operator_text, version_text)?;
        terms.push(ConstraintExpression::Predicate(Predicate {
            operator,
            version: version_text.to_owned(),
        }));
        index += consumed;
    }
    if terms.is_empty() {
        return Err(nonconforming(scheme, source));
    }
    Ok(terms)
}

fn is_operator_token(value: &str) -> bool {
    matches!(
        value,
        "<" | "<<" | "<=" | "=" | "==" | "!=" | ">=" | ">" | ">>" | "^" | "~" | "~="
    )
}

fn split_operator(value: &str) -> (&str, &str) {
    for operator in [
        "<<", "<=", "==", "!=", ">=", ">>", "~=", "<", "=", ">", "^", "~",
    ] {
        if let Some(version) = value.strip_prefix(operator) {
            return (operator, version);
        }
    }
    ("=", value)
}

fn parse_operator(
    scheme: VersionScheme,
    operator: &str,
    version: &str,
) -> Result<ComparisonOperator, ConstraintError> {
    if has_wildcard_component(version) {
        if matches!(scheme, VersionScheme::Semver | VersionScheme::Python)
            && matches!(operator, "=" | "==")
        {
            return Ok(ComparisonOperator::Wildcard);
        }
        return Err(nonconforming(scheme, version));
    }
    match operator {
        "<" | "<<" => Ok(ComparisonOperator::Less),
        "<=" => Ok(ComparisonOperator::LessEqual),
        "=" | "==" => Ok(ComparisonOperator::Equal),
        "!=" => Ok(ComparisonOperator::NotEqual),
        ">=" => Ok(ComparisonOperator::GreaterEqual),
        ">" | ">>" => Ok(ComparisonOperator::Greater),
        "^" if scheme == VersionScheme::Semver => Ok(ComparisonOperator::Caret),
        "~" if scheme == VersionScheme::Semver => Ok(ComparisonOperator::Tilde),
        "~=" if scheme == VersionScheme::Python => Ok(ComparisonOperator::Compatible),
        _ => Err(nonconforming(scheme, version)),
    }
}

fn has_wildcard_component(version: &str) -> bool {
    version.split('.').any(|component: &str| {
        matches!(component, "*" | "x" | "X")
            || component
                .strip_suffix(['*', 'x', 'X'])
                .is_some_and(|prefix: &str| prefix.is_empty())
    })
}

fn nonconforming(scheme: VersionScheme, constraint: &str) -> ConstraintError {
    ConstraintError::Nonconforming {
        scheme,
        constraint: constraint.to_owned(),
    }
}

fn evaluate_expression(
    scheme: VersionScheme,
    version: &str,
    expression: &ConstraintExpression,
) -> Result<bool, ConstraintError> {
    match expression {
        ConstraintExpression::Predicate(predicate) => evaluate_conjunction(
            scheme,
            version,
            std::slice::from_ref(expression),
            &[predicate],
        ),
        ConstraintExpression::All(expressions) => {
            let predicates: Vec<&Predicate> = expressions
                .iter()
                .filter_map(|expression: &ConstraintExpression| match expression {
                    ConstraintExpression::Predicate(predicate) => Some(predicate),
                    ConstraintExpression::All(_) | ConstraintExpression::Any(_) => None,
                })
                .collect();
            evaluate_conjunction(scheme, version, expressions, &predicates)
        }
        ConstraintExpression::Any(expressions) => {
            for expression in expressions {
                if evaluate_expression(scheme, version, expression)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

fn evaluate_conjunction(
    scheme: VersionScheme,
    version: &str,
    expressions: &[ConstraintExpression],
    predicates: &[&Predicate],
) -> Result<bool, ConstraintError> {
    if scheme == VersionScheme::Semver && !semver_prerelease_admitted(version, predicates)? {
        return Ok(false);
    }
    for expression in expressions {
        let ConstraintExpression::Predicate(predicate) = expression else {
            return Err(nonconforming(scheme, version));
        };
        if !evaluate_predicate(scheme, version, predicate)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn semver_prerelease_admitted(
    version: &str,
    predicates: &[&Predicate],
) -> Result<bool, ConstraintError> {
    let Some(candidate_core) = semver_prerelease_core(version)? else {
        return Ok(true);
    };
    for predicate in predicates {
        if semver_prerelease_core(&predicate.version)? == Some(candidate_core) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn semver_prerelease_core(version: &str) -> Result<Option<&str>, ConstraintError> {
    let normalized: &str = version
        .strip_prefix('v')
        .or_else(|| version.strip_prefix('V'))
        .map_or(version, |stripped: &str| stripped);
    let public: &str = normalized
        .split_once('+')
        .map_or(normalized, |(value, _): (&str, &str)| value);
    let Some((core, _)) = public.split_once('-') else {
        return Ok(None);
    };
    compare_versions(VersionScheme::Semver, version, version)?;
    Ok(Some(core))
}

fn evaluate_predicate(
    scheme: VersionScheme,
    version: &str,
    predicate: &Predicate,
) -> Result<bool, ConstraintError> {
    let candidate: &str = if scheme == VersionScheme::Python {
        python_constraint_candidate(version, predicate)?
    } else {
        version
    };
    match predicate.operator {
        ComparisonOperator::Wildcard => matches_wildcard(scheme, candidate, &predicate.version),
        ComparisonOperator::Caret => {
            let (lower, upper): (String, String) = semver_caret_bounds(&predicate.version)?;
            Ok(
                compare_versions(scheme, candidate, &lower)? != Ordering::Less
                    && compare_versions(scheme, candidate, &upper)? == Ordering::Less,
            )
        }
        ComparisonOperator::Tilde => {
            let (lower, upper): (String, String) = semver_tilde_bounds(&predicate.version)?;
            Ok(
                compare_versions(scheme, candidate, &lower)? != Ordering::Less
                    && compare_versions(scheme, candidate, &upper)? == Ordering::Less,
            )
        }
        ComparisonOperator::Compatible => {
            let (lower, upper): (String, String) = python_compatible_bounds(&predicate.version)?;
            Ok(
                compare_versions(scheme, candidate, &lower)? != Ordering::Less
                    && compare_versions(scheme, candidate, &upper)? == Ordering::Less,
            )
        }
        operator => {
            let order: Ordering = compare_versions(scheme, candidate, &predicate.version)?;
            Ok(match operator {
                ComparisonOperator::Less => order == Ordering::Less,
                ComparisonOperator::LessEqual => order != Ordering::Greater,
                ComparisonOperator::Equal => order == Ordering::Equal,
                ComparisonOperator::NotEqual => order != Ordering::Equal,
                ComparisonOperator::GreaterEqual => order != Ordering::Less,
                ComparisonOperator::Greater => order == Ordering::Greater,
                ComparisonOperator::Caret
                | ComparisonOperator::Tilde
                | ComparisonOperator::Compatible
                | ComparisonOperator::Wildcard => false,
            })
        }
    }
}

fn python_constraint_candidate<'value>(
    version: &'value str,
    predicate: &Predicate,
) -> Result<&'value str, ConstraintError> {
    let constraint_has_local: bool = predicate.version.contains('+');
    if constraint_has_local
        && !matches!(
            predicate.operator,
            ComparisonOperator::Equal | ComparisonOperator::NotEqual
        )
    {
        return Err(nonconforming(VersionScheme::Python, &predicate.version));
    }
    if constraint_has_local {
        return Ok(version);
    }
    Ok(version
        .split_once('+')
        .map_or(version, |(public, _): (&str, &str)| public))
}

fn matches_wildcard(
    scheme: VersionScheme,
    version: &str,
    wildcard: &str,
) -> Result<bool, ConstraintError> {
    if wildcard == "*" || wildcard.eq_ignore_ascii_case("x") {
        return Ok(true);
    }
    let prefix: &str = wildcard
        .trim_end_matches(['*', 'x', 'X'])
        .trim_end_matches('.');
    match scheme {
        VersionScheme::Semver => {
            let normalized_prefix: &str = prefix
                .strip_prefix('v')
                .or_else(|| prefix.strip_prefix('V'))
                .map_or(prefix, |stripped: &str| stripped);
            if normalized_prefix.is_empty()
                || normalized_prefix.split('.').count() > 3
                || normalized_prefix.split('.').any(|part: &str| {
                    part.is_empty() || !part.bytes().all(|byte: u8| byte.is_ascii_digit())
                })
            {
                return Err(nonconforming(scheme, wildcard));
            }
            let normalized: &str = version
                .strip_prefix('v')
                .or_else(|| version.strip_prefix('V'))
                .map_or(version, |stripped: &str| stripped);
            let public: &str = normalized
                .split(['-', '+'])
                .next()
                .map_or(normalized, |value: &str| value);
            Ok(public == normalized_prefix || public.starts_with(&format!("{normalized_prefix}.")))
        }
        VersionScheme::Python => {
            let (wanted_epoch, wanted_release): (u64, Vec<u64>) =
                python_wildcard_release(prefix, wildcard)?;
            let (candidate_epoch, candidate_release): (u64, Vec<u64>) =
                python_wildcard_release(version, wildcard)?;
            Ok(candidate_epoch == wanted_epoch && candidate_release.starts_with(&wanted_release))
        }
        _ => Err(nonconforming(scheme, wildcard)),
    }
}

fn python_wildcard_release(
    version: &str,
    constraint: &str,
) -> Result<(u64, Vec<u64>), ConstraintError> {
    let normalized: &str = version
        .trim()
        .strip_prefix('v')
        .or_else(|| version.trim().strip_prefix('V'))
        .map_or_else(|| version.trim(), |stripped: &str| stripped);
    let (epoch, public): (u64, &str) = match normalized.split_once('!') {
        Some((epoch, public)) if !public.contains('!') => (
            epoch
                .parse::<u64>()
                .map_err(|_| nonconforming(VersionScheme::Python, constraint))?,
            public,
        ),
        Some(_) => return Err(nonconforming(VersionScheme::Python, constraint)),
        None => (0, normalized),
    };
    let release_end: usize = public
        .bytes()
        .position(|byte: u8| !byte.is_ascii_digit() && byte != b'.')
        .map_or(public.len(), |index: usize| index);
    let release: Vec<u64> = public[..release_end]
        .trim_end_matches('.')
        .split('.')
        .map(|part: &str| part.parse::<u64>())
        .collect::<Result<Vec<u64>, _>>()
        .map_err(|_| nonconforming(VersionScheme::Python, constraint))?;
    if release.is_empty() || release.len() > MAX_CONSTRAINT_NODES {
        return Err(nonconforming(VersionScheme::Python, constraint));
    }
    Ok((epoch, release))
}

fn semver_numbers(version: &str) -> Result<([u64; 3], usize), ConstraintError> {
    let normalized: &str = version
        .strip_prefix('v')
        .or_else(|| version.strip_prefix('V'))
        .map_or(version, |stripped: &str| stripped);
    let core: &str = normalized
        .split(['-', '+'])
        .next()
        .map_or(normalized, |value: &str| value);
    let parts: Vec<&str> = core.split('.').collect();
    if parts.is_empty() || parts.len() > 3 {
        return Err(nonconforming(VersionScheme::Semver, version));
    }
    let mut numbers: [u64; 3] = [0; 3];
    for (index, part) in parts.into_iter().enumerate() {
        if part.is_empty() || (part.len() > 1 && part.starts_with('0')) {
            return Err(nonconforming(VersionScheme::Semver, version));
        }
        numbers[index] = part
            .parse::<u64>()
            .map_err(|_| nonconforming(VersionScheme::Semver, version))?;
    }
    Ok((numbers, core.split('.').count()))
}

fn semver_caret_bounds(version: &str) -> Result<(String, String), ConstraintError> {
    let (values, precision): ([u64; 3], usize) = semver_numbers(version)?;
    let upper: [u64; 3] = if values[0] != 0 {
        [
            values[0]
                .checked_add(1)
                .ok_or_else(|| nonconforming(VersionScheme::Semver, version))?,
            0,
            0,
        ]
    } else if values[1] != 0 {
        [
            0,
            values[1]
                .checked_add(1)
                .ok_or_else(|| nonconforming(VersionScheme::Semver, version))?,
            0,
        ]
    } else {
        [
            0,
            0,
            values[2]
                .checked_add(1)
                .ok_or_else(|| nonconforming(VersionScheme::Semver, version))?,
        ]
    };
    let lower: String = if precision == 3 {
        version.to_owned()
    } else {
        format!("{}.{}.{}", values[0], values[1], values[2])
    };
    Ok((lower, format!("{}.{}.{}", upper[0], upper[1], upper[2])))
}

fn semver_tilde_bounds(version: &str) -> Result<(String, String), ConstraintError> {
    let (values, precision): ([u64; 3], usize) = semver_numbers(version)?;
    let upper: String = if precision == 1 {
        let major: u64 = values[0]
            .checked_add(1)
            .ok_or_else(|| nonconforming(VersionScheme::Semver, version))?;
        format!("{major}.0.0")
    } else {
        let minor: u64 = values[1]
            .checked_add(1)
            .ok_or_else(|| nonconforming(VersionScheme::Semver, version))?;
        format!("{}.{}.0", values[0], minor)
    };
    let lower: String = if precision == 3 {
        version.to_owned()
    } else {
        format!("{}.{}.{}", values[0], values[1], values[2])
    };
    Ok((lower, upper))
}

fn python_compatible_bounds(version: &str) -> Result<(String, String), ConstraintError> {
    let normalized: &str = version
        .strip_prefix('v')
        .or_else(|| version.strip_prefix('V'))
        .map_or(version, |stripped: &str| stripped);
    let (epoch, public): (Option<&str>, &str) = match normalized.split_once('!') {
        Some((epoch, public))
            if !epoch.is_empty()
                && epoch.bytes().all(|byte: u8| byte.is_ascii_digit())
                && !public.contains('!') =>
        {
            (Some(epoch), public)
        }
        Some(_) => return Err(nonconforming(VersionScheme::Python, version)),
        None => (None, normalized),
    };
    let release: &str = public
        .split(['a', 'b', 'c', 'r', 'p', 'd', '+'])
        .next()
        .map_or(public, |value: &str| value);
    let mut parts: Vec<u64> = release
        .split('.')
        .map(|part: &str| part.parse::<u64>())
        .collect::<Result<Vec<u64>, _>>()
        .map_err(|_| nonconforming(VersionScheme::Python, version))?;
    if parts.len() < 2 {
        return Err(nonconforming(VersionScheme::Python, version));
    }
    let increment_index: usize = parts.len() - 2;
    parts[increment_index] = parts[increment_index]
        .checked_add(1)
        .ok_or_else(|| nonconforming(VersionScheme::Python, version))?;
    parts.truncate(increment_index + 1);
    let release_upper: String = parts
        .iter()
        .map(u64::to_string)
        .collect::<Vec<String>>()
        .join(".");
    let upper: String = epoch.map_or_else(
        || release_upper.clone(),
        |value: &str| format!("{value}!{release_upper}"),
    );
    Ok((version.to_owned(), upper))
}
