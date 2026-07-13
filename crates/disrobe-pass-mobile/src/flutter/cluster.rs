use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::cid_table::{cid_table, is_application_cid, matches_version, predefined_name};
use super::string_pool::{DartStringPool, recover_string_pool};

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

    pub fn read_signed(&mut self) -> Option<i64> {
        let mut result: i64 = 0;
        let mut shift: u32 = 0;
        let mut consumed: usize = 0;
        while consumed < DART_VARINT_MAX_BYTES {
            let byte: u8 = *self.bytes.get(self.pos)?;
            self.pos += 1;
            consumed += 1;
            let terminal: bool = byte > DART_VARINT_MAX_CONTINUATION;
            let chunk: i64 = i64::from(if terminal { byte & 0x7f } else { byte });
            if shift < i64::BITS {
                result |= chunk.wrapping_shl(shift);
            }
            shift += DART_VARINT_DATA_BITS;
            if terminal {
                if shift < i64::BITS && chunk & 0x40 != 0 {
                    result |= (-1i64).wrapping_shl(shift);
                }
                return Some(result);
            }
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
    pub instructions_table_len: u64,
    pub observed_cid_tags: Vec<u64>,
    pub cluster_schema: Option<DartClusterSchemaReport>,
    pub version_keyed_clusters_unparsed: u64,
    pub wall_reason: String,
}

const FRAMING_WALL: &str = "cluster object bodies are version-keyed: pinned Dart SDK cid names can be resolved, while per-class field and signature layouts require the matching SDK schema";

#[must_use]
pub fn parse_snapshot_framing(serialized_after_features: &[u8]) -> DartSnapshotFraming {
    let mut stream: DartReadStream<'_> = DartReadStream::new(serialized_after_features);

    let (num_base_objects, num_objects, num_clusters, instructions_table_len): (
        u64,
        u64,
        u64,
        u64,
    ) = match read_preamble(&mut stream) {
        Some(values) => values,
        None => {
            return DartSnapshotFraming {
                status: ClusterFramingStatus::PreambleUnreadable,
                num_base_objects: 0,
                num_objects: 0,
                num_clusters: 0,
                instructions_table_len: 0,
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
            instructions_table_len,
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
        instructions_table_len,
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
    let instructions_table_len: u64 = stream.read_unsigned()?;
    Some((
        num_base_objects,
        num_objects,
        num_clusters,
        instructions_table_len,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartDeclaredNames {
    pub class_names: Vec<String>,
    pub member_names: Vec<String>,
    pub library_uris: Vec<String>,
}

#[must_use]
pub fn recover_declared_names(isolate_data: &[u8]) -> DartDeclaredNames {
    let pool: DartStringPool = recover_string_pool(isolate_data);
    let mut member_names: Vec<String> = Vec::with_capacity(
        pool.method_or_field_names.len()
            + pool.getter_selectors.len()
            + pool.setter_selectors.len()
            + pool.init_selectors.len(),
    );
    member_names.extend(pool.method_or_field_names.iter().cloned());
    member_names.extend(pool.getter_selectors.iter().cloned());
    member_names.extend(pool.setter_selectors.iter().cloned());
    member_names.extend(pool.init_selectors.iter().cloned());
    member_names.sort_unstable();
    member_names.dedup();
    DartDeclaredNames {
        class_names: pool.class_names,
        member_names,
        library_uris: pool.library_uris,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclaredNameRecall {
    pub declared_total: usize,
    pub recovered_total: usize,
    pub recovered_class_names: Vec<String>,
    pub recovered_member_names: Vec<String>,
    pub missing_names: Vec<String>,
}

impl DeclaredNameRecall {
    #[must_use]
    pub fn recall(&self) -> f64 {
        if self.declared_total == 0 {
            return 0.0;
        }
        self.recovered_total as f64 / self.declared_total as f64
    }
}

#[must_use]
pub fn score_declared_name_recall(
    recovered: &DartDeclaredNames,
    declared_class_names: &[String],
    declared_member_names: &[String],
) -> DeclaredNameRecall {
    let recovered_classes: BTreeSet<&str> =
        recovered.class_names.iter().map(String::as_str).collect();
    let recovered_members: BTreeSet<&str> =
        recovered.member_names.iter().map(String::as_str).collect();

    let mut recovered_class_names: Vec<String> = Vec::new();
    let mut recovered_member_names: Vec<String> = Vec::new();
    let mut missing_names: Vec<String> = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();

    for name in declared_class_names {
        if !seen.insert(name.as_str()) {
            continue;
        }
        if recovered_classes.contains(name.as_str()) {
            recovered_class_names.push(name.clone());
        } else {
            missing_names.push(name.clone());
        }
    }
    for name in declared_member_names {
        if !seen.insert(name.as_str()) {
            continue;
        }
        if recovered_members.contains(name.as_str()) {
            recovered_member_names.push(name.clone());
        } else {
            missing_names.push(name.clone());
        }
    }

    recovered_class_names.sort_unstable();
    recovered_member_names.sort_unstable();
    missing_names.sort_unstable();
    let recovered_total: usize = recovered_class_names.len() + recovered_member_names.len();
    let declared_total: usize = recovered_total + missing_names.len();
    DeclaredNameRecall {
        declared_total,
        recovered_total,
        recovered_class_names,
        recovered_member_names,
        missing_names,
    }
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

    fn encode_signed(value: i64) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let mut v: i64 = value;
        loop {
            let low: u8 = (v as u8) & DART_VARINT_MAX_CONTINUATION;
            v >>= DART_VARINT_DATA_BITS;
            let sign_bit: bool = low & 0x40 != 0;
            if (v == 0 && !sign_bit) || (v == -1 && sign_bit) {
                out.push(low | 0x80);
                return out;
            }
            out.push(low);
        }
    }

    #[test]
    fn signed_varint_round_trip_including_double_bits() {
        let cases: [i64; 9] = [
            0,
            1,
            -1,
            63,
            -64,
            i64::MAX,
            i64::MIN,
            0x4033_f333_3333_3333u64 as i64,
            0x40c3_8800_0000_0000u64 as i64,
        ];
        for value in cases {
            let bytes: Vec<u8> = encode_signed(value);
            let mut stream: DartReadStream<'_> = DartReadStream::new(&bytes);
            assert_eq!(
                stream.read_signed(),
                Some(value),
                "signed round trip {value}"
            );
            assert_eq!(stream.remaining(), 0, "consumed all bytes for {value}");
        }
    }

    #[test]
    fn signed_varint_decodes_double_immediate_bit_pattern() {
        let bits: u64 = 19.95f64.to_bits();
        let bytes: Vec<u8> = encode_signed(bits as i64);
        let mut stream: DartReadStream<'_> = DartReadStream::new(&bytes);
        let decoded: i64 = stream.read_signed().expect("decode");
        assert_eq!(
            decoded as u64, bits,
            "signed varint preserves the double bit pattern"
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

    fn string_object(text: &str) -> Vec<u8> {
        let mut value: u64 = (text.len() as u64) << 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let low: u8 = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(low | 0x80);
                break;
            }
            out.push(low);
        }
        out.extend_from_slice(text.as_bytes());
        out
    }

    #[test]
    fn declared_names_classify_class_member_and_library_roles() {
        let mut data: Vec<u8> = vec![0u8];
        for tok in [
            "InventoryItem",
            "totalCarryingValue",
            "get:isBackordered",
            "package:app/main.dart",
            "widget-alpha",
        ] {
            data.extend_from_slice(&string_object(tok));
            data.push(0u8);
        }
        let names: DartDeclaredNames = recover_declared_names(&data);
        assert!(
            names
                .class_names
                .iter()
                .any(|c: &String| c == "InventoryItem"),
            "upper-camel token is a class name, got {:?}",
            names.class_names
        );
        assert!(
            names
                .member_names
                .iter()
                .any(|m: &String| m == "totalCarryingValue"),
            "lower-camel token is a member name, got {:?}",
            names.member_names
        );
        assert!(
            names
                .member_names
                .iter()
                .any(|m: &String| m == "isBackordered"),
            "a get: selector contributes its scrubbed member name, got {:?}",
            names.member_names
        );
        assert!(
            names
                .library_uris
                .iter()
                .any(|u: &String| u == "package:app/main.dart")
        );
    }

    #[test]
    fn declared_name_recall_counts_hits_and_keeps_misses_without_inventing() {
        let recovered: DartDeclaredNames = DartDeclaredNames {
            class_names: vec!["InventoryItem".to_owned(), "WarehouseLedger".to_owned()],
            member_names: vec!["totalCarryingValue".to_owned(), "fibonacciStep".to_owned()],
            library_uris: Vec::new(),
        };
        let declared_classes: Vec<String> =
            vec!["InventoryItem".to_owned(), "WarehouseLedger".to_owned()];
        let declared_members: Vec<String> = vec![
            "totalCarryingValue".to_owned(),
            "fibonacciStep".to_owned(),
            "extendedValue".to_owned(),
            "skuLabel".to_owned(),
        ];
        let score: DeclaredNameRecall =
            score_declared_name_recall(&recovered, &declared_classes, &declared_members);
        assert_eq!(score.declared_total, 6);
        assert_eq!(score.recovered_total, 4);
        assert!(score.missing_names.contains(&"extendedValue".to_owned()));
        assert!(score.missing_names.contains(&"skuLabel".to_owned()));
        assert!((score.recall() - 4.0 / 6.0).abs() < 1e-9);
    }

    fn corpus_sample_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("mobile")
            .join("flutter")
            .join("disrobe_sample")
    }

    fn section_bounds(bytes: &[u8], want: &str) -> Option<(usize, usize)> {
        let e_shoff: usize = u64::from_le_bytes(bytes[0x28..0x30].try_into().unwrap()) as usize;
        let e_shentsize: usize = u16::from_le_bytes(bytes[0x3a..0x3c].try_into().unwrap()) as usize;
        let e_shnum: usize = u16::from_le_bytes(bytes[0x3c..0x3e].try_into().unwrap()) as usize;
        let e_shstrndx: usize = u16::from_le_bytes(bytes[0x3e..0x40].try_into().unwrap()) as usize;
        let shstr_hdr: usize = e_shoff + e_shstrndx * e_shentsize;
        let shstr_off: usize =
            u64::from_le_bytes(bytes[shstr_hdr + 24..shstr_hdr + 32].try_into().unwrap()) as usize;
        for i in 0..e_shnum {
            let sh: usize = e_shoff + i * e_shentsize;
            let name_off: usize =
                u32::from_le_bytes(bytes[sh..sh + 4].try_into().unwrap()) as usize;
            let name_start: usize = shstr_off + name_off;
            let name_end: usize = bytes[name_start..]
                .iter()
                .position(|b: &u8| *b == 0)
                .map_or(name_start, |p: usize| name_start + p);
            if std::str::from_utf8(&bytes[name_start..name_end]).unwrap_or("") == want {
                let off: usize =
                    u64::from_le_bytes(bytes[sh + 24..sh + 32].try_into().unwrap()) as usize;
                let size: usize =
                    u64::from_le_bytes(bytes[sh + 32..sh + 40].try_into().unwrap()) as usize;
                return Some((off, size));
            }
        }
        None
    }

    fn strip_elf_symtab(bytes: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = bytes.to_vec();
        let e_shoff: usize = u64::from_le_bytes(out[0x28..0x30].try_into().unwrap()) as usize;
        let e_shentsize: usize = u16::from_le_bytes(out[0x3a..0x3c].try_into().unwrap()) as usize;
        let e_shnum: usize = u16::from_le_bytes(out[0x3c..0x3e].try_into().unwrap()) as usize;
        let e_shstrndx: usize = u16::from_le_bytes(out[0x3e..0x40].try_into().unwrap()) as usize;
        let shstr_hdr: usize = e_shoff + e_shstrndx * e_shentsize;
        let shstr_off: usize =
            u64::from_le_bytes(out[shstr_hdr + 24..shstr_hdr + 32].try_into().unwrap()) as usize;
        for i in 0..e_shnum {
            let sh: usize = e_shoff + i * e_shentsize;
            let name_off: usize = u32::from_le_bytes(out[sh..sh + 4].try_into().unwrap()) as usize;
            let name_start: usize = shstr_off + name_off;
            let name_end: usize = out[name_start..]
                .iter()
                .position(|b: &u8| *b == 0)
                .map_or(name_start, |p: usize| name_start + p);
            let name: String = String::from_utf8_lossy(&out[name_start..name_end]).into_owned();
            if name == ".symtab" || name == ".strtab" {
                out[sh + 4..sh + 8].copy_from_slice(&0u32.to_le_bytes());
                out[sh + 32..sh + 40].copy_from_slice(&0u64.to_le_bytes());
            }
        }
        out
    }

    fn count_iso_text_func_symbols(bytes: &[u8], iso_start: u64, iso_size: u64) -> usize {
        let Some((symoff, symsize)): Option<(usize, usize)> = section_bounds(bytes, ".symtab")
        else {
            return 0;
        };
        let iso_end: u64 = iso_start + iso_size;
        let mut count: usize = 0;
        let mut i: usize = 0;
        while i + 24 <= symsize {
            let base: usize = symoff + i;
            let st_info: u8 = bytes[base + 4];
            let st_value: u64 = u64::from_le_bytes(bytes[base + 8..base + 16].try_into().unwrap());
            let st_size: u64 = u64::from_le_bytes(bytes[base + 16..base + 24].try_into().unwrap());
            if (st_info & 0xf) == 2 && st_size > 0 && st_value >= iso_start && st_value < iso_end {
                count += 1;
            }
            i += 24;
        }
        count
    }

    #[test]
    fn stripped_libapp_declared_name_recall_vs_kernel_dill() {
        let dir: std::path::PathBuf = corpus_sample_dir();
        let so: Vec<u8> = std::fs::read(dir.join("libapp_arm64.so"))
            .expect("committed real AOT libapp must be present");
        let dill: Vec<u8> = std::fs::read(dir.join("disrobe_aot_sample.app.dill"))
            .expect("committed same-build kernel .dill must be present");

        let full_layout = super::super::parse_libapp_so(&so).expect("parse unstripped libapp");
        assert!(
            !full_layout.function_symbols.is_empty(),
            "the unstripped .so drives offset->name from its ELF symtab"
        );
        let iso = full_layout
            .isolate_snapshot_instructions
            .as_ref()
            .expect("isolate instructions section");
        let (iso_start, iso_size): (u64, u64) = (iso.address, iso.size);

        let stripped: Vec<u8> = strip_elf_symtab(&so);
        let stripped_layout =
            super::super::parse_libapp_so(&stripped).expect("parse stripped libapp");
        assert!(
            stripped_layout.function_symbols.is_empty(),
            "after stripping .symtab the ELF offset->name path yields nothing, got {} symbols",
            stripped_layout.function_symbols.len()
        );
        assert!(
            stripped_layout.isolate_snapshot_data.is_some(),
            "the snapshot sections still resolve from .dynsym after stripping .symtab"
        );

        let structure =
            super::super::decompile_libapp_so_structured(&stripped).expect("structured recovery");
        assert_eq!(
            structure.named_function_count, 0,
            "a stripped image has no symtab-backed offset->name pairs"
        );
        let symtab_iso_funcs: usize = count_iso_text_func_symbols(&so, iso_start, iso_size);
        assert_eq!(
            structure.framing.instructions_table_len as usize, symtab_iso_funcs,
            "the corrected header field must equal the isolate code-entry count the ELF symtab reports independently"
        );
        assert_eq!(
            symtab_iso_funcs, 3237,
            "pinned fixture: the isolate instructions image holds 3237 code entries"
        );

        let iso_data: Vec<u8> =
            super::super::isolate_data_bytes(&stripped).expect("isolate data from stripped image");
        let recovered: DartDeclaredNames = recover_declared_names(&iso_data);

        let kernel = super::super::kernel::parse_kernel(&dill).expect("parse .dill");
        let mut declared_classes: Vec<String> = Vec::new();
        let mut declared_members: Vec<String> = Vec::new();
        for lib in &kernel.libraries {
            for class in &lib.classes {
                declared_classes.push(class.name.clone());
                for procedure in &class.procedures {
                    declared_members.push(procedure.name.clone());
                }
                for field in &class.fields {
                    declared_members.push(field.clone());
                }
            }
            for procedure in &lib.procedures {
                declared_members.push(procedure.name.clone());
            }
        }
        assert!(
            declared_classes
                .iter()
                .any(|c: &String| c == "InventoryItem")
                && declared_classes
                    .iter()
                    .any(|c: &String| c == "WarehouseLedger"),
            "the .dill declares the two app classes"
        );

        let score: DeclaredNameRecall =
            score_declared_name_recall(&recovered, &declared_classes, &declared_members);

        for class in ["InventoryItem", "WarehouseLedger"] {
            assert!(
                score
                    .recovered_class_names
                    .iter()
                    .any(|n: &String| n == class),
                "class {class} must recover from the stripped snapshot string cluster"
            );
        }
        for member in [
            "totalCarryingValue",
            "countBackordered",
            "mostValuable",
            "fibonacciStep",
        ] {
            assert!(
                score
                    .recovered_member_names
                    .iter()
                    .any(|n: &String| n == member),
                "member {member} must recover from the stripped snapshot, got {:?}",
                score.recovered_member_names
            );
        }
        for dropped in [
            "classifyMagnitude",
            "extendedValue",
            "isBackordered",
            "withRestock",
        ] {
            assert!(
                score.missing_names.iter().any(|n: &String| n == dropped),
                "{dropped} is inlined and tree-shaken out of the product AOT snapshot; recovery must report it missing, never invent it"
            );
        }

        assert!(
            score.recovered_total >= 6,
            "at least the six surviving declarations must recover, got {}",
            score.recovered_total
        );
        assert!(
            score.recovered_total < score.declared_total,
            "a real ceiling: field names (DropFields) and inlined leaves do not survive AOT, so recall stays below 1.0 ({}/{})",
            score.recovered_total,
            score.declared_total
        );
        for name in score
            .recovered_class_names
            .iter()
            .chain(score.recovered_member_names.iter())
        {
            assert!(
                iso_data
                    .windows(name.len())
                    .any(|w: &[u8]| w == name.as_bytes()),
                "recovered name {name} must appear verbatim in the snapshot, never invented"
            );
        }

        eprintln!(
            "stripped flutter declared-name recall vs .dill: recovered={}/{} ({:.1}%) instructions_table_len={} symtab_iso_code_entries={} missing={:?}",
            score.recovered_total,
            score.declared_total,
            score.recall() * 100.0,
            structure.framing.instructions_table_len,
            symtab_iso_funcs,
            score.missing_names
        );
    }
}
