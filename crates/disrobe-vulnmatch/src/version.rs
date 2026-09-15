use std::cmp::Ordering;

use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_VERSION_BYTES: usize = 4 * 1024;
const MAX_VERSION_PARTS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionScheme {
    Debian,
    Rpm,
    Alpine,
    Python,
    Semver,
    Maven,
    Ruby,
    Go,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VersionError {
    #[error("{scheme:?} version is empty")]
    Empty { scheme: VersionScheme },
    #[error("{scheme:?} version is {actual} bytes, exceeding the {limit}-byte limit")]
    TooLong {
        scheme: VersionScheme,
        actual: usize,
        limit: usize,
    },
    #[error("{scheme:?} version is invalid: {value}")]
    Invalid {
        scheme: VersionScheme,
        value: String,
    },
    #[error("version scheme {scheme:?} is not implemented")]
    UnsupportedScheme { scheme: VersionScheme },
}

pub fn compare_versions(
    scheme: VersionScheme,
    left: &str,
    right: &str,
) -> Result<Ordering, VersionError> {
    validate_length(scheme, left)?;
    validate_length(scheme, right)?;
    match scheme {
        VersionScheme::Debian => compare_debian(left, right),
        VersionScheme::Rpm => compare_rpm(left, right),
        VersionScheme::Alpine => compare_alpine(left, right),
        VersionScheme::Python => compare_python(left, right),
        VersionScheme::Semver => compare_semver(left, right),
        VersionScheme::Maven | VersionScheme::Ruby | VersionScheme::Go => {
            Err(VersionError::UnsupportedScheme { scheme })
        }
    }
}

const fn validate_length(scheme: VersionScheme, value: &str) -> Result<(), VersionError> {
    if value.is_empty() {
        return Err(VersionError::Empty { scheme });
    }
    if value.len() > MAX_VERSION_BYTES {
        return Err(VersionError::TooLong {
            scheme,
            actual: value.len(),
            limit: MAX_VERSION_BYTES,
        });
    }
    Ok(())
}

fn invalid(scheme: VersionScheme, value: &str) -> VersionError {
    VersionError::Invalid {
        scheme,
        value: value.to_owned(),
    }
}

fn strip_version_prefix(value: &str) -> &str {
    value
        .strip_prefix('v')
        .or_else(|| value.strip_prefix('V'))
        .map_or(value, |stripped: &str| stripped)
}

fn parse_decimal(scheme: VersionScheme, source: &str, value: &str) -> Result<u64, VersionError> {
    if value.is_empty() || !value.bytes().all(|byte: u8| byte.is_ascii_digit()) {
        return Err(invalid(scheme, source));
    }
    value
        .bytes()
        .try_fold(0u64, |number: u64, byte: u8| {
            number.checked_mul(10)?.checked_add(u64::from(byte - b'0'))
        })
        .ok_or_else(|| invalid(scheme, source))
}

fn split_epoch(scheme: VersionScheme, source: &str) -> Result<(u64, &str), VersionError> {
    match source.split_once(':') {
        Some((epoch, remainder)) => Ok((parse_decimal(scheme, source, epoch)?, remainder)),
        None => Ok((0, source)),
    }
}

fn compare_debian(left: &str, right: &str) -> Result<Ordering, VersionError> {
    validate_debian(left)?;
    validate_debian(right)?;
    let (left_epoch, left_remainder): (u64, &str) = split_epoch(VersionScheme::Debian, left)?;
    let (right_epoch, right_remainder): (u64, &str) = split_epoch(VersionScheme::Debian, right)?;
    let epoch_order: Ordering = left_epoch.cmp(&right_epoch);
    if epoch_order != Ordering::Equal {
        return Ok(epoch_order);
    }
    if left_remainder.is_empty() || right_remainder.is_empty() {
        return Err(invalid(
            VersionScheme::Debian,
            if left_remainder.is_empty() {
                left
            } else {
                right
            },
        ));
    }
    let (left_upstream, left_revision): (&str, &str) = left_remainder
        .rsplit_once('-')
        .map_or((left_remainder, "0"), |parts: (&str, &str)| parts);
    let (right_upstream, right_revision): (&str, &str) = right_remainder
        .rsplit_once('-')
        .map_or((right_remainder, "0"), |parts: (&str, &str)| parts);
    let upstream_order: Ordering = debian_revision_compare(left_upstream, right_upstream);
    if upstream_order != Ordering::Equal {
        return Ok(upstream_order);
    }
    Ok(debian_revision_compare(left_revision, right_revision))
}

fn validate_debian(source: &str) -> Result<(), VersionError> {
    if !source.is_ascii() {
        return Err(invalid(VersionScheme::Debian, source));
    }
    let remainder: &str = source
        .split_once(':')
        .map_or(source, |(_, value): (&str, &str)| value);
    let (upstream, revision): (&str, Option<&str>) = match remainder.rsplit_once('-') {
        Some((upstream, revision)) => (upstream, Some(revision)),
        None => (remainder, None),
    };
    if upstream.is_empty()
        || remainder.contains(':')
        || !upstream.as_bytes()[0].is_ascii_digit()
        || !upstream.bytes().all(|byte: u8| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'~' | b':' | b'-')
        })
        || revision.is_some_and(|value: &str| {
            value.is_empty()
                || !value.bytes().all(|byte: u8| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'~')
                })
        })
    {
        return Err(invalid(VersionScheme::Debian, source));
    }
    Ok(())
}

fn debian_non_digit_order(byte: Option<u8>) -> i16 {
    match byte {
        Some(b'~') => -1,
        None | Some(b'0'..=b'9') => 0,
        Some(value) if value.is_ascii_alphabetic() => i16::from(value),
        Some(value) => i16::from(value) + 256,
    }
}

fn debian_revision_compare(left: &str, right: &str) -> Ordering {
    let left_bytes: &[u8] = left.as_bytes();
    let right_bytes: &[u8] = right.as_bytes();
    let mut left_index: usize = 0;
    let mut right_index: usize = 0;
    while left_index < left_bytes.len() || right_index < right_bytes.len() {
        while left_bytes
            .get(left_index)
            .is_some_and(|byte: &u8| !byte.is_ascii_digit())
            || right_bytes
                .get(right_index)
                .is_some_and(|byte: &u8| !byte.is_ascii_digit())
        {
            let order: Ordering = debian_non_digit_order(left_bytes.get(left_index).copied()).cmp(
                &debian_non_digit_order(right_bytes.get(right_index).copied()),
            );
            if order != Ordering::Equal {
                return order;
            }
            if left_index < left_bytes.len() {
                left_index += 1;
            }
            if right_index < right_bytes.len() {
                right_index += 1;
            }
        }
        while left_bytes.get(left_index) == Some(&b'0') {
            left_index += 1;
        }
        while right_bytes.get(right_index) == Some(&b'0') {
            right_index += 1;
        }
        let left_end: usize = digit_run_end(left_bytes, left_index);
        let right_end: usize = digit_run_end(right_bytes, right_index);
        let length_order: Ordering = (left_end - left_index).cmp(&(right_end - right_index));
        if length_order != Ordering::Equal {
            return length_order;
        }
        let digit_order: Ordering =
            left_bytes[left_index..left_end].cmp(&right_bytes[right_index..right_end]);
        if digit_order != Ordering::Equal {
            return digit_order;
        }
        left_index = left_end;
        right_index = right_end;
    }
    Ordering::Equal
}

fn digit_run_end(bytes: &[u8], start: usize) -> usize {
    let mut end: usize = start;
    while bytes.get(end).is_some_and(u8::is_ascii_digit) {
        end += 1;
    }
    end
}

fn compare_rpm(left: &str, right: &str) -> Result<Ordering, VersionError> {
    if !left.is_ascii()
        || !right.is_ascii()
        || left.bytes().any(|byte: u8| byte.is_ascii_whitespace())
        || right.bytes().any(|byte: u8| byte.is_ascii_whitespace())
        || !rpm_version_alphabet(left)
        || !rpm_version_alphabet(right)
    {
        return Err(invalid(
            VersionScheme::Rpm,
            if !left.is_ascii()
                || left.bytes().any(|byte: u8| byte.is_ascii_whitespace())
                || !rpm_version_alphabet(left)
            {
                left
            } else {
                right
            },
        ));
    }
    let (left_epoch, left_evr): (u64, &str) = split_epoch(VersionScheme::Rpm, left)?;
    let (right_epoch, right_evr): (u64, &str) = split_epoch(VersionScheme::Rpm, right)?;
    let epoch_order: Ordering = left_epoch.cmp(&right_epoch);
    if epoch_order != Ordering::Equal {
        return Ok(epoch_order);
    }
    let (left_version, left_release): (&str, &str) = left_evr
        .rsplit_once('-')
        .map_or((left_evr, ""), |parts: (&str, &str)| parts);
    let (right_version, right_release): (&str, &str) = right_evr
        .rsplit_once('-')
        .map_or((right_evr, ""), |parts: (&str, &str)| parts);
    if left_version.is_empty() || right_version.is_empty() {
        return Err(invalid(
            VersionScheme::Rpm,
            if left_version.is_empty() { left } else { right },
        ));
    }
    let version_order: Ordering = rpm_segment_compare(left_version, right_version);
    if version_order != Ordering::Equal {
        return Ok(version_order);
    }
    Ok(rpm_segment_compare(left_release, right_release))
}

fn rpm_version_alphabet(source: &str) -> bool {
    let remainder: &str = source
        .split_once(':')
        .map_or(source, |(_, value): (&str, &str)| value);
    let (version, release): (&str, Option<&str>) = remainder
        .split_once('-')
        .map_or((remainder, None), |(version, release): (&str, &str)| {
            (version, Some(release))
        });
    !version.is_empty()
        && !remainder.contains(':')
        && !release.is_some_and(str::is_empty)
        && version.bytes().all(rpm_component_byte)
        && release.is_none_or(|value: &str| value.bytes().all(rpm_component_byte))
}

const fn rpm_component_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'~' | b'^')
}

fn rpm_segment_compare(left: &str, right: &str) -> Ordering {
    let left_bytes: &[u8] = left.as_bytes();
    let right_bytes: &[u8] = right.as_bytes();
    let mut left_index: usize = 0;
    let mut right_index: usize = 0;
    loop {
        while left_bytes
            .get(left_index)
            .is_some_and(|byte: &u8| !byte.is_ascii_alphanumeric() && !matches!(*byte, b'~' | b'^'))
        {
            left_index += 1;
        }
        while right_bytes
            .get(right_index)
            .is_some_and(|byte: &u8| !byte.is_ascii_alphanumeric() && !matches!(*byte, b'~' | b'^'))
        {
            right_index += 1;
        }
        let left_byte: Option<u8> = left_bytes.get(left_index).copied();
        let right_byte: Option<u8> = right_bytes.get(right_index).copied();
        if left_byte == Some(b'~') || right_byte == Some(b'~') {
            match (left_byte == Some(b'~'), right_byte == Some(b'~')) {
                (true, false) => return Ordering::Less,
                (false, true) => return Ordering::Greater,
                (true, true) => {
                    left_index += 1;
                    right_index += 1;
                    continue;
                }
                (false, false) => {}
            }
        }
        if left_byte == Some(b'^') || right_byte == Some(b'^') {
            if left_byte.is_none() {
                return Ordering::Less;
            }
            if right_byte.is_none() {
                return Ordering::Greater;
            }
            if left_byte != Some(b'^') {
                return Ordering::Greater;
            }
            if right_byte != Some(b'^') {
                return Ordering::Less;
            }
            left_index += 1;
            right_index += 1;
            continue;
        }
        if left_byte.is_none() || right_byte.is_none() {
            return left_byte.is_some().cmp(&right_byte.is_some());
        }
        let numeric: bool = left_byte.is_some_and(|byte: u8| byte.is_ascii_digit());
        let left_end: usize = rpm_run_end(left_bytes, left_index, numeric);
        let right_numeric: bool = right_byte.is_some_and(|byte: u8| byte.is_ascii_digit());
        let right_end: usize = rpm_run_end(right_bytes, right_index, right_numeric);
        if numeric != right_numeric {
            return numeric.cmp(&right_numeric);
        }
        let mut left_start: usize = left_index;
        let mut right_start: usize = right_index;
        if numeric {
            while left_start < left_end && left_bytes[left_start] == b'0' {
                left_start += 1;
            }
            while right_start < right_end && right_bytes[right_start] == b'0' {
                right_start += 1;
            }
            let length_order: Ordering = (left_end - left_start).cmp(&(right_end - right_start));
            if length_order != Ordering::Equal {
                return length_order;
            }
        }
        let run_order: Ordering =
            left_bytes[left_start..left_end].cmp(&right_bytes[right_start..right_end]);
        if run_order != Ordering::Equal {
            return run_order;
        }
        left_index = left_end;
        right_index = right_end;
    }
}

fn rpm_run_end(bytes: &[u8], start: usize, numeric: bool) -> usize {
    let mut end: usize = start;
    while bytes.get(end).is_some_and(|byte: &u8| {
        if numeric {
            byte.is_ascii_digit()
        } else {
            byte.is_ascii_alphabetic()
        }
    }) {
        end += 1;
    }
    end
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AlpineToken {
    InitialNumber(u64),
    Number { value: u64, raw: String },
    Letter(u8),
    Suffix(i8),
    SuffixNumber(u64),
    Commit(String),
    Revision(u64),
}

fn compare_alpine(left: &str, right: &str) -> Result<Ordering, VersionError> {
    let left_tokens: Vec<AlpineToken> = parse_alpine(left)?;
    let right_tokens: Vec<AlpineToken> = parse_alpine(right)?;
    let mut index: usize = 0;
    loop {
        let left_token: Option<&AlpineToken> = left_tokens.get(index);
        let right_token: Option<&AlpineToken> = right_tokens.get(index);
        match (left_token, right_token) {
            (None, None) => return Ok(Ordering::Equal),
            (Some(left_value), Some(right_value))
                if alpine_token_kind(left_value) == alpine_token_kind(right_value) =>
            {
                let order: Ordering = compare_alpine_token(left_value, right_value);
                if order != Ordering::Equal {
                    return Ok(order);
                }
                index += 1;
            }
            _ => {
                if left_token.is_some_and(alpine_prerelease_suffix) {
                    return Ok(Ordering::Less);
                }
                if right_token.is_some_and(alpine_prerelease_suffix) {
                    return Ok(Ordering::Greater);
                }
                return Ok(alpine_optional_token_kind(right_token)
                    .cmp(&alpine_optional_token_kind(left_token)));
            }
        }
    }
}

const fn alpine_token_kind(token: &AlpineToken) -> u8 {
    match token {
        AlpineToken::InitialNumber(_) => 0,
        AlpineToken::Number { .. } => 1,
        AlpineToken::Letter(_) => 2,
        AlpineToken::Suffix(_) => 3,
        AlpineToken::SuffixNumber(_) => 4,
        AlpineToken::Commit(_) => 5,
        AlpineToken::Revision(_) => 6,
    }
}

fn alpine_optional_token_kind(token: Option<&AlpineToken>) -> u8 {
    token.map_or(7, alpine_token_kind)
}

const fn alpine_prerelease_suffix(token: &AlpineToken) -> bool {
    matches!(token, AlpineToken::Suffix(rank) if *rank < 0)
}

fn compare_alpine_token(left: &AlpineToken, right: &AlpineToken) -> Ordering {
    match (left, right) {
        (AlpineToken::InitialNumber(left_value), AlpineToken::InitialNumber(right_value))
        | (AlpineToken::SuffixNumber(left_value), AlpineToken::SuffixNumber(right_value))
        | (AlpineToken::Revision(left_value), AlpineToken::Revision(right_value)) => {
            left_value.cmp(right_value)
        }
        (
            AlpineToken::Number {
                value: left_value,
                raw: left_raw,
            },
            AlpineToken::Number {
                value: right_value,
                raw: right_raw,
            },
        ) => {
            if left_raw.starts_with('0') || right_raw.starts_with('0') {
                left_raw.cmp(right_raw)
            } else {
                left_value.cmp(right_value)
            }
        }
        (AlpineToken::Letter(left_value), AlpineToken::Letter(right_value)) => {
            left_value.cmp(right_value)
        }
        (AlpineToken::Suffix(left_value), AlpineToken::Suffix(right_value)) => {
            left_value.cmp(right_value)
        }
        (AlpineToken::Commit(left_value), AlpineToken::Commit(right_value)) => {
            left_value.cmp(right_value)
        }
        _ => Ordering::Equal,
    }
}

fn parse_alpine(source: &str) -> Result<Vec<AlpineToken>, VersionError> {
    let value: &str = strip_version_prefix(source);
    if !value.is_ascii() {
        return Err(invalid(VersionScheme::Alpine, source));
    }
    let bytes: &[u8] = value.as_bytes();
    let initial_end: usize = digit_run_end(bytes, 0);
    if initial_end == 0 {
        return Err(invalid(VersionScheme::Alpine, source));
    }
    let mut tokens: Vec<AlpineToken> = Vec::new();
    tokens
        .try_reserve_exact(value.len().min(MAX_VERSION_PARTS))
        .map_err(|_| invalid(VersionScheme::Alpine, source))?;
    tokens.push(AlpineToken::InitialNumber(parse_decimal(
        VersionScheme::Alpine,
        source,
        &value[..initial_end],
    )?));
    let mut index: usize = initial_end;
    while index < bytes.len() {
        if tokens.len() >= MAX_VERSION_PARTS {
            return Err(invalid(VersionScheme::Alpine, source));
        }
        let previous_kind: u8 = tokens.last().map_or(7, alpine_token_kind);
        match bytes[index] {
            b'a'..=b'z' if previous_kind <= 1 => {
                tokens.push(AlpineToken::Letter(bytes[index]));
                index += 1;
            }
            b'.' if previous_kind <= 1 => {
                index += 1;
                let end: usize = digit_run_end(bytes, index);
                if end == index {
                    return Err(invalid(VersionScheme::Alpine, source));
                }
                let raw: &str = &value[index..end];
                tokens.push(AlpineToken::Number {
                    value: parse_decimal(VersionScheme::Alpine, source, raw)?,
                    raw: raw.to_owned(),
                });
                index = end;
            }
            b'0'..=b'9' if previous_kind == 3 => {
                let end: usize = digit_run_end(bytes, index);
                tokens.push(AlpineToken::SuffixNumber(parse_decimal(
                    VersionScheme::Alpine,
                    source,
                    &value[index..end],
                )?));
                index = end;
            }
            b'_' if previous_kind <= 4 => {
                index += 1;
                let end: usize = value[index..]
                    .bytes()
                    .position(|byte: u8| !byte.is_ascii_lowercase())
                    .map_or(value.len(), |offset: usize| index + offset);
                let rank: i8 = match &value[index..end] {
                    "alpha" => -4,
                    "beta" => -3,
                    "pre" => -2,
                    "rc" => -1,
                    "cvs" => 1,
                    "svn" => 2,
                    "git" => 3,
                    "hg" => 4,
                    "p" => 5,
                    _ => return Err(invalid(VersionScheme::Alpine, source)),
                };
                tokens.push(AlpineToken::Suffix(rank));
                index = end;
            }
            b'~' if previous_kind < 5 => {
                index += 1;
                let end: usize = value[index..]
                    .bytes()
                    .position(|byte: u8| !byte.is_ascii_hexdigit())
                    .map_or(value.len(), |offset: usize| index + offset);
                if end == index {
                    return Err(invalid(VersionScheme::Alpine, source));
                }
                tokens.push(AlpineToken::Commit(value[index..end].to_owned()));
                index = end;
            }
            b'-' if previous_kind < 6 && value[index..].starts_with("-r") => {
                index += 2;
                let end: usize = digit_run_end(bytes, index);
                if end == index {
                    return Err(invalid(VersionScheme::Alpine, source));
                }
                tokens.push(AlpineToken::Revision(parse_decimal(
                    VersionScheme::Alpine,
                    source,
                    &value[index..end],
                )?));
                index = end;
            }
            _ => return Err(invalid(VersionScheme::Alpine, source)),
        }
    }
    Ok(tokens)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PythonPreKind {
    Alpha,
    Beta,
    Rc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PythonLocalPart {
    Text(String),
    Number(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PythonVersion {
    epoch: u64,
    release: Vec<u64>,
    pre: Option<(PythonPreKind, u64)>,
    post: Option<u64>,
    dev: Option<u64>,
    local: Vec<PythonLocalPart>,
}

fn compare_python(left: &str, right: &str) -> Result<Ordering, VersionError> {
    let left_version: PythonVersion = parse_python(left)?;
    let right_version: PythonVersion = parse_python(right)?;
    Ok(left_version
        .epoch
        .cmp(&right_version.epoch)
        .then_with(|| compare_zero_extended(&left_version.release, &right_version.release))
        .then_with(|| compare_python_pre(&left_version, &right_version))
        .then_with(|| compare_python_optional_number(left_version.post, right_version.post, false))
        .then_with(|| compare_python_optional_number(left_version.dev, right_version.dev, true))
        .then_with(|| compare_python_local(&left_version.local, &right_version.local)))
}

fn compare_zero_extended(left: &[u64], right: &[u64]) -> Ordering {
    let length: usize = left.len().max(right.len());
    (0..length)
        .map(|index: usize| {
            left.get(index)
                .copied()
                .map_or(0, |value: u64| value)
                .cmp(&right.get(index).copied().map_or(0, |value: u64| value))
        })
        .find(|order: &Ordering| *order != Ordering::Equal)
        .map_or(Ordering::Equal, |order: Ordering| order)
}

fn compare_python_pre(left: &PythonVersion, right: &PythonVersion) -> Ordering {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    enum PreKey {
        NegativeInfinity,
        Value(PythonPreKind, u64),
        PositiveInfinity,
    }

    let key: fn(&PythonVersion) -> PreKey = |version: &PythonVersion| match version.pre {
        Some((kind, number)) => PreKey::Value(kind, number),
        None if version.post.is_none() && version.dev.is_some() => PreKey::NegativeInfinity,
        None => PreKey::PositiveInfinity,
    };
    key(left).cmp(&key(right))
}

fn compare_python_optional_number(
    left: Option<u64>,
    right: Option<u64>,
    missing_is_greater: bool,
) -> Ordering {
    match (left, right) {
        (Some(left_value), Some(right_value)) => left_value.cmp(&right_value),
        (Some(_), None) => {
            if missing_is_greater {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        }
        (None, Some(_)) => {
            if missing_is_greater {
                Ordering::Greater
            } else {
                Ordering::Less
            }
        }
        (None, None) => Ordering::Equal,
    }
}

fn compare_python_local(left: &[PythonLocalPart], right: &[PythonLocalPart]) -> Ordering {
    match (left.is_empty(), right.is_empty()) {
        (true, false) => return Ordering::Less,
        (false, true) => return Ordering::Greater,
        _ => {}
    }
    for (left_part, right_part) in left.iter().zip(right) {
        let order: Ordering = match (left_part, right_part) {
            (PythonLocalPart::Number(left_value), PythonLocalPart::Number(right_value)) => {
                left_value.cmp(right_value)
            }
            (PythonLocalPart::Text(left_value), PythonLocalPart::Text(right_value)) => {
                left_value.cmp(right_value)
            }
            (PythonLocalPart::Number(_), PythonLocalPart::Text(_)) => Ordering::Greater,
            (PythonLocalPart::Text(_), PythonLocalPart::Number(_)) => Ordering::Less,
        };
        if order != Ordering::Equal {
            return order;
        }
    }
    left.len().cmp(&right.len())
}

fn parse_python(source: &str) -> Result<PythonVersion, VersionError> {
    let lowercase: String = strip_version_prefix(source.trim()).to_ascii_lowercase();
    let (public_source, local_source): (&str, Option<&str>) = match lowercase.split_once('+') {
        Some((public, local)) => (public, Some(local)),
        None => (lowercase.as_str(), None),
    };
    let implicit_post: Option<(&str, &str)> =
        public_source
            .rsplit_once('-')
            .filter(|(_, suffix): &(&str, &str)| {
                !suffix.is_empty() && suffix.bytes().all(|byte: u8| byte.is_ascii_digit())
            });
    let public_normalized: String = match implicit_post {
        Some((base, post)) => format!("{base}.post{post}"),
        None => public_source.to_owned(),
    };
    let normalized: String = match local_source {
        Some(local) => format!("{public_normalized}+{local}"),
        None => public_normalized,
    }
    .replace(['-', '_'], ".");
    let (public, local_text): (&str, Option<&str>) = match normalized.split_once('+') {
        Some((public, local)) if !local.is_empty() && !local.contains('+') => (public, Some(local)),
        Some(_) => return Err(invalid(VersionScheme::Python, source)),
        None => (normalized.as_str(), None),
    };
    let (epoch, body): (u64, &str) = match public.split_once('!') {
        Some((epoch, body)) if !body.contains('!') => {
            (parse_decimal(VersionScheme::Python, source, epoch)?, body)
        }
        Some(_) => return Err(invalid(VersionScheme::Python, source)),
        None => (0, public),
    };
    let release_end: usize = body
        .bytes()
        .position(|byte: u8| !byte.is_ascii_digit() && byte != b'.')
        .map_or(body.len(), |index: usize| index);
    let release_text: &str = body[..release_end].trim_end_matches('.');
    let mut release: Vec<u64> = Vec::new();
    for segment in release_text.split('.') {
        if release.len() >= MAX_VERSION_PARTS {
            return Err(invalid(VersionScheme::Python, source));
        }
        release.push(parse_decimal(VersionScheme::Python, source, segment)?);
    }
    let mut remainder: &str = body[release_end..].trim_start_matches('.');
    let mut pre: Option<(PythonPreKind, u64)> = None;
    let mut post: Option<u64> = None;
    let mut dev: Option<u64> = None;
    while !remainder.is_empty() {
        remainder = remainder.trim_start_matches('.');
        let label_end: usize = remainder
            .bytes()
            .position(|byte: u8| !byte.is_ascii_alphabetic())
            .map_or(remainder.len(), |index: usize| index);
        let label: &str = &remainder[..label_end];
        let digits_source: &str = &remainder[label_end..];
        let digits_end: usize = digits_source
            .bytes()
            .position(|byte: u8| !byte.is_ascii_digit())
            .map_or(digits_source.len(), |index: usize| index);
        let number: u64 = if digits_end == 0 {
            0
        } else {
            parse_decimal(VersionScheme::Python, source, &digits_source[..digits_end])?
        };
        match label {
            "a" | "alpha" if pre.is_none() && post.is_none() && dev.is_none() => {
                pre = Some((PythonPreKind::Alpha, number));
            }
            "b" | "beta" if pre.is_none() && post.is_none() && dev.is_none() => {
                pre = Some((PythonPreKind::Beta, number));
            }
            "c" | "rc" | "pre" | "preview" if pre.is_none() && post.is_none() && dev.is_none() => {
                pre = Some((PythonPreKind::Rc, number));
            }
            "post" | "rev" | "r" if post.is_none() && dev.is_none() => post = Some(number),
            "dev" if dev.is_none() => dev = Some(number),
            _ => return Err(invalid(VersionScheme::Python, source)),
        }
        remainder = &digits_source[digits_end..];
    }
    let mut local: Vec<PythonLocalPart> = Vec::new();
    if let Some(text) = local_text {
        for segment in text.split('.') {
            if segment.is_empty() || local.len() >= MAX_VERSION_PARTS {
                return Err(invalid(VersionScheme::Python, source));
            }
            if segment.bytes().all(|byte: u8| byte.is_ascii_digit()) {
                local.push(PythonLocalPart::Number(parse_decimal(
                    VersionScheme::Python,
                    source,
                    segment,
                )?));
            } else if segment.bytes().all(|byte: u8| byte.is_ascii_alphanumeric()) {
                local.push(PythonLocalPart::Text(segment.to_owned()));
            } else {
                return Err(invalid(VersionScheme::Python, source));
            }
        }
    }
    Ok(PythonVersion {
        epoch,
        release,
        pre,
        post,
        dev,
        local,
    })
}

fn compare_semver(left: &str, right: &str) -> Result<Ordering, VersionError> {
    let left_version: Semver<'_> = parse_semver(left)?;
    let right_version: Semver<'_> = parse_semver(right)?;
    let core_order: Ordering = left_version.core.cmp(&right_version.core);
    if core_order != Ordering::Equal {
        return Ok(core_order);
    }
    match (left_version.pre, right_version.pre) {
        (None, None) => Ok(Ordering::Equal),
        (None, Some(_)) => Ok(Ordering::Greater),
        (Some(_), None) => Ok(Ordering::Less),
        (Some(left_pre), Some(right_pre)) => compare_semver_pre(left, left_pre, right, right_pre),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Semver<'value> {
    core: [u64; 3],
    pre: Option<&'value str>,
}

fn parse_semver(source: &str) -> Result<Semver<'_>, VersionError> {
    let value: &str = strip_version_prefix(source);
    let (without_build, build): (&str, Option<&str>) = match value.split_once('+') {
        Some((public, metadata)) if !metadata.is_empty() && !metadata.contains('+') => {
            (public, Some(metadata))
        }
        Some(_) => return Err(invalid(VersionScheme::Semver, source)),
        None => (value, None),
    };
    let (core_text, pre): (&str, Option<&str>) = match without_build.split_once('-') {
        Some((core, pre)) if !pre.is_empty() => (core, Some(pre)),
        Some(_) => return Err(invalid(VersionScheme::Semver, source)),
        None => (without_build, None),
    };
    let mut segments: std::str::Split<'_, char> = core_text.split('.');
    let major: &str = segments
        .next()
        .ok_or_else(|| invalid(VersionScheme::Semver, source))?;
    let minor: &str = segments
        .next()
        .ok_or_else(|| invalid(VersionScheme::Semver, source))?;
    let patch: &str = segments
        .next()
        .ok_or_else(|| invalid(VersionScheme::Semver, source))?;
    if segments.next().is_some()
        || [major, minor, patch]
            .into_iter()
            .any(|segment: &str| segment.len() > 1 && segment.starts_with('0'))
    {
        return Err(invalid(VersionScheme::Semver, source));
    }
    if let Some(value) = pre
        && (value.split('.').count() > MAX_VERSION_PARTS
            || value.split('.').any(|segment: &str| {
                segment.is_empty()
                    || !segment
                        .bytes()
                        .all(|byte: u8| byte.is_ascii_alphanumeric() || byte == b'-')
                    || (segment.len() > 1
                        && segment.starts_with('0')
                        && segment.bytes().all(|byte: u8| byte.is_ascii_digit()))
            }))
    {
        return Err(invalid(VersionScheme::Semver, source));
    }
    if let Some(value) = build
        && (value.split('.').count() > MAX_VERSION_PARTS
            || value.split('.').any(|segment: &str| {
                segment.is_empty()
                    || !segment
                        .bytes()
                        .all(|byte: u8| byte.is_ascii_alphanumeric() || byte == b'-')
            }))
    {
        return Err(invalid(VersionScheme::Semver, source));
    }
    Ok(Semver {
        core: [
            parse_decimal(VersionScheme::Semver, source, major)?,
            parse_decimal(VersionScheme::Semver, source, minor)?,
            parse_decimal(VersionScheme::Semver, source, patch)?,
        ],
        pre,
    })
}

fn compare_semver_pre(
    left_source: &str,
    left: &str,
    right_source: &str,
    right: &str,
) -> Result<Ordering, VersionError> {
    let mut left_parts: std::str::Split<'_, char> = left.split('.');
    let mut right_parts: std::str::Split<'_, char> = right.split('.');
    loop {
        match (left_parts.next(), right_parts.next()) {
            (Some(left_part), Some(right_part)) => {
                let left_numeric: bool = left_part.bytes().all(|byte: u8| byte.is_ascii_digit());
                let right_numeric: bool = right_part.bytes().all(|byte: u8| byte.is_ascii_digit());
                let order: Ordering = match (left_numeric, right_numeric) {
                    (true, true) => {
                        parse_decimal(VersionScheme::Semver, left_source, left_part)?.cmp(
                            &parse_decimal(VersionScheme::Semver, right_source, right_part)?,
                        )
                    }
                    (true, false) => Ordering::Less,
                    (false, true) => Ordering::Greater,
                    (false, false) => left_part.cmp(right_part),
                };
                if order != Ordering::Equal {
                    return Ok(order);
                }
            }
            (Some(_), None) => return Ok(Ordering::Greater),
            (None, Some(_)) => return Ok(Ordering::Less),
            (None, None) => return Ok(Ordering::Equal),
        }
    }
}
