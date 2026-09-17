use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

const MAX_PACKAGE_URL_INPUT_BYTES: usize = 16_384;
const MAX_PACKAGE_URL_OUTPUT_BYTES: usize = 56 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PackageType {
    Debian,
    Rpm,
    Alpine,
    Python,
    Maven,
    Npm,
    Ruby,
    Go,
    Cargo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NamespaceRequirement {
    Required,
    Optional,
    Prohibited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Normalization {
    Preserve,
    Lowercase,
    PythonName,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PackageTypePolicy {
    token: &'static str,
    namespace: NamespaceRequirement,
    namespace_normalization: Normalization,
    name_normalization: Normalization,
    version_normalization: Normalization,
    npm_scope: bool,
}

const PACKAGE_TYPE_POLICIES: [PackageTypePolicy; 9] = [
    PackageTypePolicy {
        token: "deb",
        namespace: NamespaceRequirement::Required,
        namespace_normalization: Normalization::Lowercase,
        name_normalization: Normalization::Lowercase,
        version_normalization: Normalization::Preserve,
        npm_scope: false,
    },
    PackageTypePolicy {
        token: "rpm",
        namespace: NamespaceRequirement::Required,
        namespace_normalization: Normalization::Lowercase,
        name_normalization: Normalization::Preserve,
        version_normalization: Normalization::Preserve,
        npm_scope: false,
    },
    PackageTypePolicy {
        token: "apk",
        namespace: NamespaceRequirement::Required,
        namespace_normalization: Normalization::Lowercase,
        name_normalization: Normalization::Lowercase,
        version_normalization: Normalization::Preserve,
        npm_scope: false,
    },
    PackageTypePolicy {
        token: "pypi",
        namespace: NamespaceRequirement::Prohibited,
        namespace_normalization: Normalization::Preserve,
        name_normalization: Normalization::PythonName,
        version_normalization: Normalization::Lowercase,
        npm_scope: false,
    },
    PackageTypePolicy {
        token: "maven",
        namespace: NamespaceRequirement::Required,
        namespace_normalization: Normalization::Preserve,
        name_normalization: Normalization::Preserve,
        version_normalization: Normalization::Preserve,
        npm_scope: false,
    },
    PackageTypePolicy {
        token: "npm",
        namespace: NamespaceRequirement::Optional,
        namespace_normalization: Normalization::Preserve,
        name_normalization: Normalization::Preserve,
        version_normalization: Normalization::Preserve,
        npm_scope: true,
    },
    PackageTypePolicy {
        token: "gem",
        namespace: NamespaceRequirement::Prohibited,
        namespace_normalization: Normalization::Preserve,
        name_normalization: Normalization::Preserve,
        version_normalization: Normalization::Preserve,
        npm_scope: false,
    },
    PackageTypePolicy {
        token: "golang",
        namespace: NamespaceRequirement::Required,
        namespace_normalization: Normalization::Lowercase,
        name_normalization: Normalization::Lowercase,
        version_normalization: Normalization::Preserve,
        npm_scope: false,
    },
    PackageTypePolicy {
        token: "cargo",
        namespace: NamespaceRequirement::Prohibited,
        namespace_normalization: Normalization::Preserve,
        name_normalization: Normalization::Preserve,
        version_normalization: Normalization::Preserve,
        npm_scope: false,
    },
];

impl PackageType {
    const fn policy_index(self) -> usize {
        match self {
            Self::Debian => 0,
            Self::Rpm => 1,
            Self::Alpine => 2,
            Self::Python => 3,
            Self::Maven => 4,
            Self::Npm => 5,
            Self::Ruby => 6,
            Self::Go => 7,
            Self::Cargo => 8,
        }
    }

    const fn policy(self) -> PackageTypePolicy {
        PACKAGE_TYPE_POLICIES[self.policy_index()]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PackageUrlError {
    #[error("package name is empty")]
    EmptyName,
    #[error("package type {package_type:?} requires a namespace")]
    MissingNamespace { package_type: PackageType },
    #[error("package type {package_type:?} prohibits a namespace")]
    ProhibitedNamespace { package_type: PackageType },
    #[error("package URL input is {actual} bytes, exceeding the {limit}-byte limit")]
    TooLong { actual: usize, limit: usize },
    #[error("package URL output is {actual} bytes, exceeding the {limit}-byte limit")]
    OutputTooLong { actual: usize, limit: usize },
    #[error("package URL allocation of {requested} bytes failed")]
    AllocationFailed { requested: usize },
    #[error("package URL component {component} is invalid")]
    InvalidComponent { component: &'static str },
    #[error("package URL qualifier key is invalid: {key}")]
    InvalidQualifier { key: String },
    #[error("package URL cannot contain both a version and a vers qualifier")]
    VersionAndVers,
}

pub fn build_package_url(
    package_type: PackageType,
    namespace: Option<&str>,
    name: &str,
    version: Option<&str>,
    qualifiers: &BTreeMap<String, String>,
    subpath: Option<&str>,
) -> Result<String, PackageUrlError> {
    let input_bytes: usize = input_length(namespace, name, version, qualifiers, subpath);
    if input_bytes > MAX_PACKAGE_URL_INPUT_BYTES {
        return Err(PackageUrlError::TooLong {
            actual: input_bytes,
            limit: MAX_PACKAGE_URL_INPUT_BYTES,
        });
    }

    let policy: PackageTypePolicy = package_type.policy();
    let canonical_namespace: Option<String> = canonical_namespace(package_type, policy, namespace)?;
    let canonical_name: String = canonical_name(policy, name)?;
    let canonical_version: Option<String> = version
        .filter(|value: &&str| !value.is_empty())
        .map(|value: &str| normalize(value, policy.version_normalization));
    let canonical_qualifiers: Vec<String> = canonical_qualifiers(qualifiers)?;
    if canonical_version.is_some()
        && canonical_qualifiers
            .iter()
            .any(|qualifier: &String| qualifier.starts_with("vers="))
    {
        return Err(PackageUrlError::VersionAndVers);
    }
    let canonical_subpath: Vec<&str> = canonical_subpath(subpath)?;

    let output_bytes: usize = output_length(
        policy,
        canonical_namespace.as_deref(),
        &canonical_name,
        canonical_version.as_deref(),
        &canonical_qualifiers,
        &canonical_subpath,
    )?;
    if output_bytes > MAX_PACKAGE_URL_OUTPUT_BYTES {
        return Err(PackageUrlError::OutputTooLong {
            actual: output_bytes,
            limit: MAX_PACKAGE_URL_OUTPUT_BYTES,
        });
    }

    let mut output: String = String::new();
    output
        .try_reserve_exact(output_bytes)
        .map_err(|_| PackageUrlError::AllocationFailed {
            requested: output_bytes,
        })?;
    output.push_str("pkg:");
    output.push_str(policy.token);
    output.push('/');
    if let Some(value) = canonical_namespace.as_deref() {
        encode_path_into(value, &mut output);
        output.push('/');
    }
    encode_component_into(&canonical_name, &mut output);
    if let Some(value) = canonical_version.as_deref() {
        output.push('@');
        encode_component_into(value, &mut output);
    }
    if !canonical_qualifiers.is_empty() {
        output.push('?');
        for (index, qualifier) in canonical_qualifiers.iter().enumerate() {
            if index != 0 {
                output.push('&');
            }
            output.push_str(qualifier);
        }
    }
    if !canonical_subpath.is_empty() {
        output.push('#');
        encode_segments_into(&canonical_subpath, &mut output);
    }
    debug_assert_eq!(output.len(), output_bytes);
    Ok(output)
}

fn input_length(
    namespace: Option<&str>,
    name: &str,
    version: Option<&str>,
    qualifiers: &BTreeMap<String, String>,
    subpath: Option<&str>,
) -> usize {
    let mut bytes: usize = namespace.map_or(0, str::len);
    bytes = bytes.saturating_add(name.len());
    bytes = bytes.saturating_add(version.map_or(0, str::len));
    bytes = bytes.saturating_add(subpath.map_or(0, str::len));
    for (key, value) in qualifiers {
        bytes = bytes.saturating_add(key.len());
        bytes = bytes.saturating_add(value.len());
    }
    bytes
}

fn canonical_namespace(
    package_type: PackageType,
    policy: PackageTypePolicy,
    namespace: Option<&str>,
) -> Result<Option<String>, PackageUrlError> {
    let trimmed: Option<&str> = namespace
        .map(|value: &str| value.trim_matches('/'))
        .filter(|value: &&str| !value.is_empty());
    match (policy.namespace, trimmed) {
        (NamespaceRequirement::Required, None) => {
            return Err(PackageUrlError::MissingNamespace { package_type });
        }
        (NamespaceRequirement::Prohibited, Some(_)) => {
            return Err(PackageUrlError::ProhibitedNamespace { package_type });
        }
        _ => {}
    }
    let Some(value): Option<&str> = trimmed else {
        return Ok(None);
    };
    if value.split('/').any(str::is_empty) {
        return Err(PackageUrlError::InvalidComponent {
            component: "namespace",
        });
    }
    let mut canonical: String = normalize(value, policy.namespace_normalization);
    if policy.npm_scope {
        let scope: &str = canonical.strip_prefix('@').unwrap_or(&canonical);
        if scope.is_empty() {
            return Err(PackageUrlError::InvalidComponent {
                component: "namespace",
            });
        }
        canonical = format!("@{scope}");
    }
    Ok(Some(canonical))
}

fn canonical_name(policy: PackageTypePolicy, name: &str) -> Result<String, PackageUrlError> {
    let trimmed: &str = name.trim_matches('/');
    if trimmed.is_empty() {
        return Err(PackageUrlError::EmptyName);
    }
    let canonical: String = normalize(trimmed, policy.name_normalization);
    if canonical.is_empty() {
        return Err(PackageUrlError::EmptyName);
    }
    Ok(canonical)
}

fn canonical_subpath(subpath: Option<&str>) -> Result<Vec<&str>, PackageUrlError> {
    let trimmed: &str = subpath.unwrap_or_default().trim_matches('/');
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let segment_capacity: usize = trimmed
        .bytes()
        .filter(|byte: &u8| *byte == b'/')
        .count()
        .checked_add(1)
        .ok_or(PackageUrlError::OutputTooLong {
            actual: usize::MAX,
            limit: MAX_PACKAGE_URL_OUTPUT_BYTES,
        })?;
    let requested: usize = segment_capacity
        .checked_mul(std::mem::size_of::<&str>())
        .ok_or(PackageUrlError::AllocationFailed {
            requested: usize::MAX,
        })?;
    let mut segments: Vec<&str> = Vec::new();
    segments
        .try_reserve_exact(segment_capacity)
        .map_err(|_| PackageUrlError::AllocationFailed { requested })?;
    segments.extend(
        trimmed
            .split('/')
            .filter(|segment: &&str| !segment.is_empty() && !matches!(*segment, "." | "..")),
    );
    Ok(segments)
}

fn normalize(value: &str, normalization: Normalization) -> String {
    match normalization {
        Normalization::Preserve => value.to_owned(),
        Normalization::Lowercase => value.to_lowercase(),
        Normalization::PythonName => {
            let mut output: String = String::with_capacity(value.len());
            let mut separator: bool = false;
            for character in value.chars() {
                if matches!(character, '-' | '_' | '.') {
                    if !separator {
                        output.push('-');
                    }
                    separator = true;
                } else {
                    output.extend(character.to_lowercase());
                    separator = false;
                }
            }
            output
        }
    }
}

fn canonical_qualifiers(
    qualifiers: &BTreeMap<String, String>,
) -> Result<Vec<String>, PackageUrlError> {
    let mut canonical: BTreeMap<String, &str> = BTreeMap::new();
    for (key, value) in qualifiers {
        if value.is_empty() {
            continue;
        }
        let canonical_key: String = key.to_ascii_lowercase();
        let mut bytes: std::str::Bytes<'_> = canonical_key.bytes();
        let valid: bool = bytes
            .next()
            .is_some_and(|byte: u8| byte.is_ascii_lowercase())
            && bytes.all(|byte: u8| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            });
        if !valid {
            return Err(PackageUrlError::InvalidQualifier { key: key.clone() });
        }
        if canonical.insert(canonical_key, value).is_some() {
            return Err(PackageUrlError::InvalidQualifier { key: key.clone() });
        }
    }
    let requested: usize = canonical
        .len()
        .checked_mul(std::mem::size_of::<String>())
        .ok_or(PackageUrlError::AllocationFailed {
            requested: usize::MAX,
        })?;
    let mut ordered: Vec<String> = Vec::new();
    ordered
        .try_reserve_exact(canonical.len())
        .map_err(|_| PackageUrlError::AllocationFailed { requested })?;
    for (key, value) in canonical {
        let encoded_value_bytes: usize = encoded_component_length(value)?;
        let qualifier_bytes: usize = key
            .len()
            .checked_add(1)
            .and_then(|length: usize| length.checked_add(encoded_value_bytes))
            .ok_or(PackageUrlError::OutputTooLong {
                actual: usize::MAX,
                limit: MAX_PACKAGE_URL_OUTPUT_BYTES,
            })?;
        let mut qualifier: String = String::new();
        qualifier.try_reserve_exact(qualifier_bytes).map_err(|_| {
            PackageUrlError::AllocationFailed {
                requested: qualifier_bytes,
            }
        })?;
        qualifier.push_str(&key);
        qualifier.push('=');
        encode_component_into(value, &mut qualifier);
        ordered.push(qualifier);
    }
    ordered.sort_unstable();
    Ok(ordered)
}

fn output_length(
    policy: PackageTypePolicy,
    namespace: Option<&str>,
    name: &str,
    version: Option<&str>,
    qualifiers: &[String],
    subpath: &[&str],
) -> Result<usize, PackageUrlError> {
    let mut bytes: usize = checked_output_add(5, policy.token.len())?;
    if let Some(value) = namespace {
        bytes = checked_output_add(bytes, encoded_path_length(value)?)?;
        bytes = checked_output_add(bytes, 1)?;
    }
    bytes = checked_output_add(bytes, encoded_component_length(name)?)?;
    if let Some(value) = version {
        bytes = checked_output_add(bytes, 1)?;
        bytes = checked_output_add(bytes, encoded_component_length(value)?)?;
    }
    if !qualifiers.is_empty() {
        bytes = checked_output_add(bytes, 1)?;
        for (index, qualifier) in qualifiers.iter().enumerate() {
            if index != 0 {
                bytes = checked_output_add(bytes, 1)?;
            }
            bytes = checked_output_add(bytes, qualifier.len())?;
        }
    }
    if !subpath.is_empty() {
        bytes = checked_output_add(bytes, 1)?;
        bytes = checked_output_add(bytes, encoded_segments_length(subpath)?)?;
    }
    Ok(bytes)
}

fn checked_output_add(left: usize, right: usize) -> Result<usize, PackageUrlError> {
    left.checked_add(right)
        .ok_or(PackageUrlError::OutputTooLong {
            actual: usize::MAX,
            limit: MAX_PACKAGE_URL_OUTPUT_BYTES,
        })
}

fn encoded_component_length(value: &str) -> Result<usize, PackageUrlError> {
    value.bytes().try_fold(0, |length: usize, byte: u8| {
        checked_output_add(length, if is_permitted(byte) { 1 } else { 3 })
    })
}

fn encoded_path_length(value: &str) -> Result<usize, PackageUrlError> {
    value
        .split('/')
        .try_fold(0, |length: usize, segment: &str| {
            let separator: usize = usize::from(length != 0);
            checked_output_add(
                checked_output_add(length, separator)?,
                encoded_component_length(segment)?,
            )
        })
}

fn encoded_segments_length(segments: &[&str]) -> Result<usize, PackageUrlError> {
    segments
        .iter()
        .enumerate()
        .try_fold(0, |length: usize, (index, segment): (usize, &&str)| {
            checked_output_add(
                checked_output_add(length, usize::from(index != 0))?,
                encoded_component_length(segment)?,
            )
        })
}

fn encode_path_into(value: &str, output: &mut String) {
    for (index, segment) in value.split('/').enumerate() {
        if index != 0 {
            output.push('/');
        }
        encode_component_into(segment, output);
    }
}

fn encode_segments_into(segments: &[&str], output: &mut String) {
    for (index, segment) in segments.iter().enumerate() {
        if index != 0 {
            output.push('/');
        }
        encode_component_into(segment, output);
    }
}

fn encode_component_into(value: &str, output: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        if is_permitted(byte) {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
}

const fn is_permitted(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'~' | b':')
}
