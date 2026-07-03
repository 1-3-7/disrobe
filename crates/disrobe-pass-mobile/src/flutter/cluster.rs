use serde::{Deserialize, Serialize};

use super::cid_table::{cid_table, is_application_cid, matches_version, predefined_name};

const DART_VARINT_DATA_BITS: u32 = 7;

const DART_VARINT_MAX_CONTINUATION: u8 = 0x7f;

const DART_VARINT_END_MARKER: u64 = 0x80;

const DART_VARINT_MAX_BYTES: usize = 10;

const CLUSTER_PREAMBLE_SANITY_MAX: u64 = 1 << 28;

const CLUSTER_TAG_SCAN_LIMIT: usize = 1 << 16;

#[derive(Debug)]
pub struct DartReadStream<'data> {
    bytes: &'data [u8],
    pos: usize,
}

impl<'data> DartReadStream<'data> {
    #[must_use]
    pub const fn new(bytes: &'data [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    pub fn read_unsigned(&mut self) -> Option<u64> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        let mut consumed: usize = 0;
        while consumed < DART_VARINT_MAX_BYTES {
            let byte: u8 = *self.bytes.get(self.pos)?;
            self.pos += 1;
            consumed += 1;
            if byte > DART_VARINT_MAX_CONTINUATION {
                let terminal: u64 = u64::from(byte) - DART_VARINT_END_MARKER;
                result = append_varint_chunk(result, terminal, shift)?;
                return Some(result);
            }
            result = append_varint_chunk(result, u64::from(byte), shift)?;
            shift += DART_VARINT_DATA_BITS;
        }
        None
    }

    pub fn read_byte(&mut self) -> Option<u8> {
        let byte: u8 = *self.bytes.get(self.pos)?;
        self.pos += 1;
        Some(byte)
    }

    pub fn skip(&mut self, count: usize) -> Option<()> {
        let end: usize = self.pos.checked_add(count)?;
        if end > self.bytes.len() {
            return None;
        }
        self.pos = end;
        Some(())
    }
}

fn append_varint_chunk(result: u64, chunk: u64, shift: u32) -> Option<u64> {
    if shift >= u64::BITS || chunk > (u64::MAX >> shift) {
        return None;
    }
    result.checked_add(chunk << shift)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClusterFramingStatus {
    Parsed,
    PreambleUnreadable,
    PreambleImplausible,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartObservedCluster {
    pub cid: u64,
    pub name: String,
    pub role: DartClusterRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DartClusterRole {
    Class,
    Code,
    Field,
    Function,
    FunctionType,
    Library,
    SignatureShape,
    Predefined,
    ApplicationObject,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartClusterSchemaReport {
    pub version_hash: String,
    pub dart_sdk: Option<String>,
    pub version_matched: bool,
    pub observed_clusters: Vec<DartObservedCluster>,
    pub class_cluster_count: usize,
    pub code_cluster_count: usize,
    pub field_cluster_count: usize,
    pub function_cluster_count: usize,
    pub class_field_related_cluster_count: usize,
    pub function_type_cluster_count: usize,
    pub signature_related_cluster_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartSnapshotFraming {
    pub status: ClusterFramingStatus,
    pub num_base_objects: u64,
    pub num_objects: u64,
    pub num_clusters: u64,
    pub fields_total_bytes: u64,
    pub observed_cid_tags: Vec<u64>,
    pub cluster_schema: Option<DartClusterSchemaReport>,
    pub version_keyed_clusters_unparsed: u64,
    pub wall_reason: String,
}

const FRAMING_WALL: &str = "cluster object bodies are version-keyed: pinned Dart SDK cid names can be resolved, while per-class field and signature layouts require the matching SDK schema";

#[must_use]
pub fn parse_snapshot_framing(serialized_after_features: &[u8]) -> DartSnapshotFraming {
    let mut stream: DartReadStream<'_> = DartReadStream::new(serialized_after_features);

    let (num_base_objects, num_objects, num_clusters, fields_total_bytes): (u64, u64, u64, u64) =
        match read_preamble(&mut stream) {
            Some(values) => values,
            None => {
                return DartSnapshotFraming {
                    status: ClusterFramingStatus::PreambleUnreadable,
                    num_base_objects: 0,
                    num_objects: 0,
                    num_clusters: 0,
                    fields_total_bytes: 0,
                    observed_cid_tags: Vec::new(),
                    cluster_schema: None,
                    version_keyed_clusters_unparsed: 0,
                    wall_reason: FRAMING_WALL.to_owned(),
                };
            }
        };

    if !preamble_is_plausible(num_base_objects, num_objects, num_clusters) {
        return DartSnapshotFraming {
            status: ClusterFramingStatus::PreambleImplausible,
            num_base_objects,
            num_objects,
            num_clusters,
            fields_total_bytes,
            observed_cid_tags: Vec::new(),
            cluster_schema: None,
            version_keyed_clusters_unparsed: num_clusters,
            wall_reason: FRAMING_WALL.to_owned(),
        };
    }

    let observed_cid_tags: Vec<u64> = scan_cid_tags(&mut stream, num_clusters);

    DartSnapshotFraming {
        status: ClusterFramingStatus::Parsed,
        num_base_objects,
        num_objects,
        num_clusters,
        fields_total_bytes,
        observed_cid_tags,
        cluster_schema: None,
        version_keyed_clusters_unparsed: num_clusters,
        wall_reason: FRAMING_WALL.to_owned(),
    }
}

pub fn attach_cluster_schema(framing: &mut DartSnapshotFraming, version_hash: &str) {
    let version_matched: bool = matches_version(version_hash);
    let dart_sdk: Option<String> = version_matched.then(|| cid_table().dart_sdk);
    let mut observed_clusters: Vec<DartObservedCluster> =
        Vec::with_capacity(framing.observed_cid_tags.len().min(CLUSTER_TAG_SCAN_LIMIT));
    for cid in &framing.observed_cid_tags {
        observed_clusters.push(observed_cluster(*cid, version_matched));
    }
    let class_cluster_count: usize = count_role(&observed_clusters, DartClusterRole::Class);
    let code_cluster_count: usize = count_role(&observed_clusters, DartClusterRole::Code);
    let field_cluster_count: usize = count_role(&observed_clusters, DartClusterRole::Field);
    let function_cluster_count: usize = count_role(&observed_clusters, DartClusterRole::Function);
    let class_field_related_cluster_count: usize = class_cluster_count + field_cluster_count;
    let function_type_cluster_count: usize =
        count_role(&observed_clusters, DartClusterRole::FunctionType);
    let signature_related_cluster_count: usize = observed_clusters
        .iter()
        .filter(|cluster: &&DartObservedCluster| {
            matches!(
                cluster.role,
                DartClusterRole::FunctionType | DartClusterRole::SignatureShape
            )
        })
        .count();
    framing.cluster_schema = Some(DartClusterSchemaReport {
        version_hash: version_hash.to_owned(),
        dart_sdk,
        version_matched,
        observed_clusters,
        class_cluster_count,
        code_cluster_count,
        field_cluster_count,
        function_cluster_count,
        class_field_related_cluster_count,
        function_type_cluster_count,
        signature_related_cluster_count,
    });
}

#[must_use]
fn count_role(observed_clusters: &[DartObservedCluster], role: DartClusterRole) -> usize {
    observed_clusters
        .iter()
        .filter(|cluster: &&DartObservedCluster| cluster.role == role)
        .count()
}

#[must_use]
fn observed_cluster(cid: u64, version_matched: bool) -> DartObservedCluster {
    if !version_matched {
        return DartObservedCluster {
            cid,
            name: format!("cid_{cid}"),
            role: DartClusterRole::Unknown,
        };
    }
    let name: String = u16::try_from(cid)
        .ok()
        .and_then(predefined_name)
        .map(str::to_owned)
        .unwrap_or_else(|| {
            if u16::try_from(cid).ok().is_some_and(is_application_cid) {
                "ApplicationObject".to_owned()
            } else {
                format!("cid_{cid}")
            }
        });
    let role: DartClusterRole = cluster_role(&name);
    DartObservedCluster { cid, name, role }
}

#[must_use]
fn cluster_role(name: &str) -> DartClusterRole {
    match name {
        "Class" => DartClusterRole::Class,
        "Code" => DartClusterRole::Code,
        "Field" => DartClusterRole::Field,
        "Function" => DartClusterRole::Function,
        "FunctionType" => DartClusterRole::FunctionType,
        "Library" => DartClusterRole::Library,
        "TypeParameters" | "ClosureData" | "TypeArguments" | "AbstractType" | "Type"
        | "RecordType" | "TypeParameter" => DartClusterRole::SignatureShape,
        "ApplicationObject" => DartClusterRole::ApplicationObject,
        name if name.starts_with("cid_") => DartClusterRole::Unknown,
        _ => DartClusterRole::Predefined,
    }
}

fn read_preamble(stream: &mut DartReadStream<'_>) -> Option<(u64, u64, u64, u64)> {
    let num_base_objects: u64 = stream.read_unsigned()?;
    let num_objects: u64 = stream.read_unsigned()?;
    let num_clusters: u64 = stream.read_unsigned()?;
    let fields_total_bytes: u64 = stream.read_unsigned()?;
    Some((
        num_base_objects,
        num_objects,
        num_clusters,
        fields_total_bytes,
    ))
}

#[must_use]
fn preamble_is_plausible(num_base_objects: u64, num_objects: u64, num_clusters: u64) -> bool {
    num_base_objects > 0
        && num_base_objects < CLUSTER_PREAMBLE_SANITY_MAX
        && num_objects >= num_base_objects
        && num_objects < CLUSTER_PREAMBLE_SANITY_MAX
        && num_clusters > 0
        && num_clusters < CLUSTER_PREAMBLE_SANITY_MAX
        && num_clusters <= num_objects
}

#[must_use]
fn scan_cid_tags(stream: &mut DartReadStream<'_>, num_clusters: u64) -> Vec<u64> {
    let cap: usize = (num_clusters as usize).min(CLUSTER_TAG_SCAN_LIMIT);
    let mut tags: Vec<u64> = Vec::with_capacity(cap.min(256));
    let mut scanned: usize = 0;
    while scanned < cap {
        let Some(tag): Option<u64> = stream.read_unsigned() else {
            break;
        };
        tags.push(tag);
        scanned += 1;
        if stream.remaining() < 2 {
            break;
        }
        if stream.skip(1).is_none() {
            break;
        }
    }
    tags
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn encode_unsigned(mut value: u64) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        loop {
            let low: u8 = (value & u64::from(DART_VARINT_MAX_CONTINUATION)) as u8;
            value >>= DART_VARINT_DATA_BITS;
            if value == 0 {
                out.push(low | 0x80);
                return out;
            }
            out.push(low);
        }
    }

    #[test]
    fn varint_single_byte_small_values() {
        for value in [0u64, 1, 5, 63, 127] {
            let bytes: Vec<u8> = encode_unsigned(value);
            assert_eq!(bytes.len(), 1, "value {value} must be one byte");
            let mut s: DartReadStream<'_> = DartReadStream::new(&bytes);
            assert_eq!(s.read_unsigned(), Some(value));
        }
    }

    #[test]
    fn varint_multi_byte_round_trip() {
        for value in [128u64, 255, 300, 16_384, 1_000_000, u32::MAX as u64] {
            let bytes: Vec<u8> = encode_unsigned(value);
            let mut s: DartReadStream<'_> = DartReadStream::new(&bytes);
            assert_eq!(s.read_unsigned(), Some(value), "round trip {value}");
            assert_eq!(s.remaining(), 0, "consumed all bytes for {value}");
        }
    }

    #[test]
    fn varint_continuation_high_bit_is_clear() {
        let bytes: Vec<u8> = encode_unsigned(300);
        assert_eq!(
            bytes[0] & 0x80,
            0,
            "continuation byte must have high bit clear"
        );
        assert_ne!(
            bytes[bytes.len() - 1] & 0x80,
            0,
            "terminating byte must have high bit set"
        );
    }

    #[test]
    fn varint_truncated_stream_returns_none() {
        let bytes: [u8; 2] = [0x01, 0x02];
        let mut s: DartReadStream<'_> = DartReadStream::new(&bytes);
        assert_eq!(s.read_unsigned(), None, "no terminator must fail, not loop");
    }

    #[test]
    fn varint_accepts_u64_max() {
        let mut bytes: Vec<u8> = vec![0x7f; 9];
        bytes.push(0x81);
        let mut s: DartReadStream<'_> = DartReadStream::new(&bytes);
        assert_eq!(s.read_unsigned(), Some(u64::MAX));
    }

    #[test]
    fn varint_rejects_u64_overflow_terminal() {
        let mut bytes: Vec<u8> = vec![0x7f; 9];
        bytes.push(0x82);
        let mut s: DartReadStream<'_> = DartReadStream::new(&bytes);
        assert_eq!(s.read_unsigned(), None);
    }

    #[test]
    fn framing_preamble_parses_known_counts() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&encode_unsigned(107));
        buf.extend_from_slice(&encode_unsigned(50_000));
        buf.extend_from_slice(&encode_unsigned(42));
        buf.extend_from_slice(&encode_unsigned(0));
        for cid in [4u64, 17, 78, 95, 96] {
            buf.extend_from_slice(&encode_unsigned(cid));
            buf.push(0x00);
        }
        let framing: DartSnapshotFraming = parse_snapshot_framing(&buf);
        assert_eq!(framing.status, ClusterFramingStatus::Parsed);
        assert_eq!(framing.num_base_objects, 107);
        assert_eq!(framing.num_objects, 50_000);
        assert_eq!(framing.num_clusters, 42);
        assert!(
            framing.observed_cid_tags.contains(&78),
            "tags = {:?}",
            framing.observed_cid_tags
        );
        assert_eq!(framing.version_keyed_clusters_unparsed, 42);
        assert!(framing.wall_reason.contains("version-keyed"));
    }

    #[test]
    fn framing_attaches_pinned_cluster_schema_for_function_type() {
        let function_type_cid: u64 = (0..super::super::cid_table::predefined_count())
            .find(|cid: &u16| {
                super::super::cid_table::predefined_name(*cid) == Some("FunctionType")
            })
            .map(u64::from)
            .expect("FunctionType cid exists");
        let type_arguments_cid: u64 = (0..super::super::cid_table::predefined_count())
            .find(|cid: &u16| {
                super::super::cid_table::predefined_name(*cid) == Some("TypeArguments")
            })
            .map(u64::from)
            .expect("TypeArguments cid exists");
        let class_cid: u64 = (0..super::super::cid_table::predefined_count())
            .find(|cid: &u16| super::super::cid_table::predefined_name(*cid) == Some("Class"))
            .map(u64::from)
            .expect("Class cid exists");
        let code_cid: u64 = (0..super::super::cid_table::predefined_count())
            .find(|cid: &u16| super::super::cid_table::predefined_name(*cid) == Some("Code"))
            .map(u64::from)
            .expect("Code cid exists");
        let field_cid: u64 = (0..super::super::cid_table::predefined_count())
            .find(|cid: &u16| super::super::cid_table::predefined_name(*cid) == Some("Field"))
            .map(u64::from)
            .expect("Field cid exists");
        let function_cid: u64 = (0..super::super::cid_table::predefined_count())
            .find(|cid: &u16| super::super::cid_table::predefined_name(*cid) == Some("Function"))
            .map(u64::from)
            .expect("Function cid exists");
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&encode_unsigned(107));
        buf.extend_from_slice(&encode_unsigned(50_000));
        buf.extend_from_slice(&encode_unsigned(6));
        buf.extend_from_slice(&encode_unsigned(0));
        for cid in [
            function_type_cid,
            type_arguments_cid,
            class_cid,
            code_cid,
            field_cid,
            function_cid,
        ] {
            buf.extend_from_slice(&encode_unsigned(cid));
            buf.push(0x00);
        }
        let mut framing: DartSnapshotFraming = parse_snapshot_framing(&buf);
        attach_cluster_schema(
            &mut framing,
            super::super::cid_table::DART_3_12_VERSION_HASH,
        );
        let schema: &DartClusterSchemaReport =
            framing.cluster_schema.as_ref().expect("schema attached");
        assert!(schema.version_matched);
        assert_eq!(schema.dart_sdk.as_deref(), Some("3.12.2"));
        assert_eq!(schema.class_cluster_count, 1);
        assert_eq!(schema.code_cluster_count, 1);
        assert_eq!(schema.field_cluster_count, 1);
        assert_eq!(schema.function_cluster_count, 1);
        assert_eq!(schema.class_field_related_cluster_count, 2);
        assert_eq!(schema.function_type_cluster_count, 1);
        assert_eq!(schema.signature_related_cluster_count, 2);
        assert!(
            schema
                .observed_clusters
                .iter()
                .any(|cluster: &DartObservedCluster| {
                    cluster.name == "FunctionType" && cluster.role == DartClusterRole::FunctionType
                })
        );
    }

    #[test]
    fn framing_rejects_implausible_preamble() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&encode_unsigned(0));
        buf.extend_from_slice(&encode_unsigned(0));
        buf.extend_from_slice(&encode_unsigned(0));
        buf.extend_from_slice(&encode_unsigned(0));
        let framing: DartSnapshotFraming = parse_snapshot_framing(&buf);
        assert_eq!(framing.status, ClusterFramingStatus::PreambleImplausible);
    }

    #[test]
    fn framing_empty_input_is_unreadable() {
        let framing: DartSnapshotFraming = parse_snapshot_framing(&[]);
        assert_eq!(framing.status, ClusterFramingStatus::PreambleUnreadable);
        assert!(framing.wall_reason.contains("SDK schema"));
    }
}
