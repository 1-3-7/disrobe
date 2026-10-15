use std::collections::BTreeSet;
use std::io::Read as _;

use disrobe_pass_native::{AuditableCrate, AuditableSbom, parse_auditable_section};
use object::read::File as ObjectFile;
use object::{Object as _, ObjectSection as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const AUDITABLE_SECTION: &str = ".dep-v0";
const MAX_COMPRESSED_BYTES: u64 = 4 * 1024 * 1024;
const MAX_DECOMPRESSED_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditableSection {
    pub name: String,
    pub offset: Option<u64>,
    pub compressed_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DependencyKind {
    #[default]
    Runtime,
    Build,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditablePackage {
    #[serde(flatten)]
    pub package: AuditableCrate,
    pub kind: DependencyKind,
    pub root: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct AuditableEdge {
    pub from: usize,
    pub to: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditableGraph {
    pub section: AuditableSection,
    pub format: u32,
    pub decompressed_bytes: u64,
    pub packages: Vec<AuditablePackage>,
    pub dependencies: Vec<AuditableEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AuditableRefusal {
    #[error("the section data cannot be read: {message}")]
    SectionUnreadable { message: String },
    #[error("the compressed payload is {bytes} bytes, above the {limit}-byte limit")]
    CompressedTooLarge { bytes: u64, limit: u64 },
    #[error("the zlib stream does not inflate: {message}")]
    Inflate { message: String },
    #[error("the payload inflates past the {limit}-byte limit")]
    DecompressedTooLarge { limit: u64 },
    #[error("the dependency JSON is malformed: {message}")]
    Json { message: String },
    #[error("package {package} lists dependency {dependency}, but there are {packages} packages")]
    DependencyOutOfRange {
        package: usize,
        dependency: usize,
        packages: usize,
    },
    #[error("package {package} lists itself as a dependency")]
    SelfDependency { package: usize },
    #[error("package {package} has the unknown dependency kind {value:?}")]
    UnknownKind { package: usize, value: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum AuditableEvidence {
    Absent,
    Present(AuditableGraph),
    Refused {
        section: AuditableSection,
        reason: AuditableRefusal,
    },
}

#[derive(Debug, Deserialize)]
struct EdgeDocument {
    packages: Vec<EdgePackage>,
}

#[derive(Debug, Deserialize)]
struct EdgePackage {
    #[serde(default)]
    dependencies: Vec<usize>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    root: bool,
}

pub(super) fn read(file: &ObjectFile<'_>) -> AuditableEvidence {
    let Some(section) = file.section_by_name(AUDITABLE_SECTION) else {
        return AuditableEvidence::Absent;
    };
    let mut evidence: AuditableSection = AuditableSection {
        name: AUDITABLE_SECTION.to_owned(),
        offset: section.file_range().map(|(offset, _): (u64, u64)| offset),
        compressed_bytes: 0,
    };
    let compressed: &[u8] = match section.data() {
        Ok(data) => data,
        Err(error) => {
            return AuditableEvidence::Refused {
                section: evidence,
                reason: AuditableRefusal::SectionUnreadable {
                    message: error.to_string(),
                },
            };
        }
    };
    evidence.compressed_bytes = compressed.len() as u64;
    match decode(compressed) {
        Ok((json, sbom)) => {
            let format: u32 = sbom.format_version;
            match graph(&json, sbom) {
                Ok((packages, dependencies)) => AuditableEvidence::Present(AuditableGraph {
                    section: evidence,
                    format,
                    decompressed_bytes: json.len() as u64,
                    packages,
                    dependencies,
                }),
                Err(reason) => AuditableEvidence::Refused {
                    section: evidence,
                    reason,
                },
            }
        }
        Err(reason) => AuditableEvidence::Refused {
            section: evidence,
            reason,
        },
    }
}

fn decode(compressed: &[u8]) -> Result<(Vec<u8>, AuditableSbom), AuditableRefusal> {
    if compressed.len() as u64 > MAX_COMPRESSED_BYTES {
        return Err(AuditableRefusal::CompressedTooLarge {
            bytes: compressed.len() as u64,
            limit: MAX_COMPRESSED_BYTES,
        });
    }
    let mut json: Vec<u8> = Vec::new();
    flate2::read::ZlibDecoder::new(compressed)
        .take(MAX_DECOMPRESSED_BYTES + 1)
        .read_to_end(&mut json)
        .map_err(|error: std::io::Error| AuditableRefusal::Inflate {
            message: error.to_string(),
        })?;
    if json.len() as u64 > MAX_DECOMPRESSED_BYTES {
        return Err(AuditableRefusal::DecompressedTooLarge {
            limit: MAX_DECOMPRESSED_BYTES,
        });
    }
    let sbom: AuditableSbom =
        parse_auditable_section(&json).map_err(|error: disrobe_pass_native::Error| {
            AuditableRefusal::Json {
                message: error.to_string(),
            }
        })?;
    Ok((json, sbom))
}

fn graph(
    json: &[u8],
    sbom: AuditableSbom,
) -> Result<(Vec<AuditablePackage>, Vec<AuditableEdge>), AuditableRefusal> {
    let document: EdgeDocument =
        serde_json::from_slice(json).map_err(|error: serde_json::Error| {
            AuditableRefusal::Json {
                message: error.to_string(),
            }
        })?;
    let count: usize = sbom.crates.len();
    if document.packages.len() != count {
        return Err(AuditableRefusal::Json {
            message: format!(
                "{} packages decode with dependencies but {count} without",
                document.packages.len()
            ),
        });
    }
    let mut edges: BTreeSet<AuditableEdge> = BTreeSet::new();
    let mut packages: Vec<AuditablePackage> = Vec::with_capacity(count);
    for (index, (package, edge_package)) in
        sbom.crates.into_iter().zip(document.packages).enumerate()
    {
        let kind: DependencyKind = match edge_package.kind.as_deref() {
            None | Some("runtime") => DependencyKind::Runtime,
            Some("build") => DependencyKind::Build,
            Some(other) => {
                return Err(AuditableRefusal::UnknownKind {
                    package: index,
                    value: other.to_owned(),
                });
            }
        };
        for dependency in edge_package.dependencies {
            if dependency >= count {
                return Err(AuditableRefusal::DependencyOutOfRange {
                    package: index,
                    dependency,
                    packages: count,
                });
            }
            if dependency == index {
                return Err(AuditableRefusal::SelfDependency { package: index });
            }
            edges.insert(AuditableEdge {
                from: index,
                to: dependency,
            });
        }
        packages.push(AuditablePackage {
            package,
            kind,
            root: edge_package.root,
        });
    }
    Ok((packages, edges.into_iter().collect()))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn zlib(payload: &[u8]) -> Vec<u8> {
        let mut encoder: flate2::write::ZlibEncoder<Vec<u8>> =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(payload).expect("compress");
        encoder.finish().expect("finish")
    }

    #[test]
    fn an_inflation_bomb_stops_at_the_decompressed_limit() {
        let bomb: Vec<u8> = zlib(&vec![b' '; (MAX_DECOMPRESSED_BYTES + 1024) as usize]);
        assert!(bomb.len() < 64 * 1024);
        assert_eq!(
            decode(&bomb).map(|_| ()),
            Err(AuditableRefusal::DecompressedTooLarge {
                limit: MAX_DECOMPRESSED_BYTES
            })
        );
    }

    #[test]
    fn dependency_indices_are_checked() {
        let out_of_range: &[u8] =
            br#"{"packages":[{"name":"a","version":"1.0.0","source":"local","dependencies":[2],"root":true},{"name":"b","version":"1.0.0","source":"crates.io"}]}"#;
        let (json, sbom): (Vec<u8>, AuditableSbom) = decode(&zlib(out_of_range)).expect("decodes");
        assert_eq!(
            graph(&json, sbom).map(|_| ()),
            Err(AuditableRefusal::DependencyOutOfRange {
                package: 0,
                dependency: 2,
                packages: 2
            })
        );
        let self_edge: &[u8] =
            br#"{"packages":[{"name":"a","version":"1.0.0","source":"local","dependencies":[0]}]}"#;
        let (json, sbom): (Vec<u8>, AuditableSbom) = decode(&zlib(self_edge)).expect("decodes");
        assert_eq!(
            graph(&json, sbom).map(|_| ()),
            Err(AuditableRefusal::SelfDependency { package: 0 })
        );
        let unknown_kind: &[u8] =
            br#"{"packages":[{"name":"a","version":"1.0.0","source":"local","kind":"dev"}]}"#;
        let (json, sbom): (Vec<u8>, AuditableSbom) = decode(&zlib(unknown_kind)).expect("decodes");
        assert_eq!(
            graph(&json, sbom).map(|_| ()),
            Err(AuditableRefusal::UnknownKind {
                package: 0,
                value: "dev".to_owned()
            })
        );
    }
}
