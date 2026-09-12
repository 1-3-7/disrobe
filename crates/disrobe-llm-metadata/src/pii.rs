use std::collections::{BTreeMap, BTreeSet};

use disrobe_core::recon::ioc::{self, Encoding, Indicator, IocKind};
use disrobe_core::recon::secret_scan::{self, Finding};
use serde_json::{Map, Value as Json, json};

use crate::VERSION;
use crate::capability::MetadataCapability;
use crate::category::Category;
use crate::trait_def::LlmMetadataEmitter;

pub const PII_PASS: &str = "disrobe-llm-metadata-pii";

pub const PII_CAPABILITY: MetadataCapability =
    MetadataCapability::new(PII_PASS, VERSION, &[Category::PiiMap]);

const MAX_PII_ENTRIES: usize = 4096;
const MAX_SCAN_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct PiiScan {
    pub bytes: Vec<u8>,
}

impl LlmMetadataEmitter for PiiScan {
    fn metadata_capability(&self) -> MetadataCapability {
        PII_CAPABILITY
    }

    fn emit_pii_map(&self) -> Option<Json> {
        let outcome: PiiScanOutcome = scan(&self.bytes);
        if outcome.entries.is_empty() {
            None
        } else {
            Some(Json::Array(outcome.entries))
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PiiScanOutcome {
    pub entries: Vec<Json>,
    pub omitted: usize,
    pub scanned_bytes: usize,
    pub total_bytes: usize,
}

impl PiiScanOutcome {
    #[must_use]
    pub const fn input_truncated(&self) -> bool {
        self.scanned_bytes < self.total_bytes
    }
}

#[derive(Debug, Clone)]
struct PiiCandidate {
    schema_category: &'static str,
    tag: String,
    value: String,
    offset: usize,
    byte_end: Option<usize>,
    overlap_eligible: bool,
    overlap_priority: u8,
}

const GENERIC_OVERLAP_PRIORITY: u8 = 1;
const SPECIFIC_OVERLAP_PRIORITY: u8 = 0;

const fn ioc_pii_category(kind: IocKind) -> Option<&'static str> {
    match kind {
        IocKind::Email => Some("email"),
        IocKind::CreditCard
        | IocKind::MacAddress
        | IocKind::Uuid
        | IocKind::WindowsPath
        | IocKind::UnixPath
        | IocKind::PdbPath
        | IocKind::BitcoinAddress
        | IocKind::EthereumAddress
        | IocKind::MoneroAddress
        | IocKind::LitecoinAddress
        | IocKind::TronAddress => Some("other"),
        IocKind::Url
        | IocKind::Domain
        | IocKind::Ipv4
        | IocKind::Ipv6
        | IocKind::RegistryKey
        | IocKind::CryptoConstant => None,
    }
}

fn sanitize_tag(raw: &str) -> String {
    raw.chars()
        .map(|c: char| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn ioc_candidates(bytes: &[u8]) -> Vec<PiiCandidate> {
    ioc::extract(bytes)
        .into_iter()
        .filter_map(|ind: Indicator| {
            let schema_category: &'static str = ioc_pii_category(ind.kind)?;
            if ind.value.trim().is_empty() {
                return None;
            }
            let overlap_eligible: bool = matches!(ind.encoding, Encoding::Plain);
            let byte_end: Option<usize> =
                overlap_eligible.then(|| ind.offset.saturating_add(ind.value.len()));
            Some(PiiCandidate {
                schema_category,
                tag: sanitize_tag(ind.kind.label()),
                offset: ind.offset,
                value: ind.value,
                byte_end,
                overlap_eligible,
                overlap_priority: SPECIFIC_OVERLAP_PRIORITY,
            })
        })
        .collect()
}

fn secret_candidates(bytes: &[u8]) -> Vec<PiiCandidate> {
    secret_scan::scan_bytes(bytes, None)
        .into_iter()
        .filter(|f: &Finding| !f.value.trim().is_empty())
        .map(|f: Finding| {
            let overlap_priority: u8 = if f.kind == secret_scan::SecretKind::HighEntropyGeneric {
                GENERIC_OVERLAP_PRIORITY
            } else {
                SPECIFIC_OVERLAP_PRIORITY
            };
            PiiCandidate {
                schema_category: "secret",
                tag: sanitize_tag(&f.code),
                byte_end: Some(f.offset.saturating_add(f.value.len())),
                offset: f.offset,
                value: f.value,
                overlap_eligible: true,
                overlap_priority,
            }
        })
        .collect()
}

fn candidate_order(a: &PiiCandidate, b: &PiiCandidate) -> std::cmp::Ordering {
    a.offset
        .cmp(&b.offset)
        .then_with(|| a.overlap_priority.cmp(&b.overlap_priority))
        .then_with(|| std::cmp::Reverse(a.byte_end).cmp(&std::cmp::Reverse(b.byte_end)))
        .then_with(|| a.tag.cmp(&b.tag))
        .then_with(|| a.value.cmp(&b.value))
}

fn resolve_overlaps(mut candidates: Vec<PiiCandidate>) -> Vec<PiiCandidate> {
    candidates.sort_by(candidate_order);
    let mut kept: Vec<PiiCandidate> = Vec::with_capacity(candidates.len());
    let mut plain_frontier: usize = 0;
    for candidate in candidates {
        if candidate.overlap_eligible {
            if candidate.offset < plain_frontier {
                continue;
            }
            if let Some(end) = candidate.byte_end {
                plain_frontier = plain_frontier.max(end);
            }
        }
        kept.push(candidate);
    }
    kept
}

fn assign_placeholders(candidates: &[PiiCandidate]) -> BTreeMap<(String, String), String> {
    let mut unique_by_tag: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for candidate in candidates {
        unique_by_tag
            .entry(candidate.tag.as_str())
            .or_default()
            .insert(candidate.value.as_str());
    }
    let mut placeholders: BTreeMap<(String, String), String> = BTreeMap::new();
    for (tag, values) in unique_by_tag {
        for (idx, value) in values.into_iter().enumerate() {
            placeholders.insert((tag.to_owned(), value.to_owned()), format!("<{tag}_{idx}>"));
        }
    }
    placeholders
}

fn span_json(offset: usize, byte_end: Option<usize>) -> Json {
    let mut span: Map<String, Json> = Map::new();
    span.insert(
        "byte_start".to_owned(),
        Json::from(u64::try_from(offset).unwrap_or(u64::MAX)),
    );
    if let Some(end) = byte_end {
        span.insert(
            "byte_end".to_owned(),
            Json::from(u64::try_from(end).unwrap_or(u64::MAX)),
        );
    }
    Json::Object(span)
}

#[must_use]
pub fn scan(bytes: &[u8]) -> PiiScanOutcome {
    let total_bytes: usize = bytes.len();
    let scanned_bytes: usize = total_bytes.min(MAX_SCAN_BYTES);
    let scanned: &[u8] = &bytes[..scanned_bytes];
    let mut candidates: Vec<PiiCandidate> = ioc_candidates(scanned);
    candidates.extend(secret_candidates(scanned));
    let candidates: Vec<PiiCandidate> = resolve_overlaps(candidates);
    if candidates.is_empty() {
        return PiiScanOutcome {
            scanned_bytes,
            total_bytes,
            ..PiiScanOutcome::default()
        };
    }
    let placeholders: BTreeMap<(String, String), String> = assign_placeholders(&candidates);
    let total: usize = candidates.len();
    let kept: usize = total.min(MAX_PII_ENTRIES);
    let omitted: usize = total.saturating_sub(kept);
    let mut entries: Vec<Json> = Vec::with_capacity(kept);
    for candidate in candidates.into_iter().take(kept) {
        let key: (String, String) = (candidate.tag.clone(), candidate.value.clone());
        let placeholder: &str = placeholders
            .get(&key)
            .map_or(candidate.tag.as_str(), String::as_str);
        entries.push(json!({
            "category": candidate.schema_category,
            "placeholder": placeholder,
            "span": span_json(candidate.offset, candidate.byte_end),
        }));
    }
    PiiScanOutcome {
        entries,
        omitted,
        scanned_bytes,
        total_bytes,
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::selection::{MetadataSelection, SelectionBuilder};

    fn entries_of(bytes: &[u8]) -> Vec<Json> {
        scan(bytes).entries
    }

    fn category_of(entry: &Json) -> &str {
        entry
            .get("category")
            .and_then(Json::as_str)
            .expect("category field")
    }

    fn placeholder_of(entry: &Json) -> &str {
        entry
            .get("placeholder")
            .and_then(Json::as_str)
            .expect("placeholder field")
    }

    fn byte_start_of(entry: &Json) -> u64 {
        entry
            .get("span")
            .and_then(|s: &Json| s.get("byte_start"))
            .and_then(Json::as_u64)
            .expect("byte_start field")
    }

    fn aws_akid() -> String {
        format!("{}{}", "AKIA", "3KFTG2KQ4WXYZ7AB")
    }

    fn github_pat() -> String {
        format!("{}{}", "ghp_", "1234567890abcdefABCDEF1234567890abcd")
    }

    fn stripe_live() -> String {
        format!("{}{}", "sk_live_", "4eC39HqLyjWDarjtT1zdp7dc")
    }

    #[test]
    fn email_is_detected_and_categorized() {
        let entries: Vec<Json> = entries_of(b"contact alice@example.com now");
        let found: &Json = entries
            .iter()
            .find(|e: &&Json| placeholder_of(e).starts_with("<EMAIL_"))
            .expect("email entry");
        assert_eq!(category_of(found), "email");
    }

    #[test]
    fn credit_card_is_detected() {
        let entries: Vec<Json> = entries_of(b"card 4111111111111111 exp 12/29");
        let found: &Json = entries
            .iter()
            .find(|e: &&Json| placeholder_of(e).starts_with("<CREDIT_CARD_"))
            .expect("credit card entry");
        assert_eq!(category_of(found), "other");
    }

    #[test]
    fn mac_address_is_detected() {
        let entries: Vec<Json> = entries_of(b"nic 00:1A:2B:3C:4D:5E seen");
        assert!(
            entries
                .iter()
                .any(|e: &Json| placeholder_of(e).starts_with("<MAC_ADDRESS_"))
        );
    }

    #[test]
    fn uuid_is_detected() {
        let entries: Vec<Json> = entries_of(b"id 550e8400-e29b-41d4-a716-446655440000 done");
        assert!(
            entries
                .iter()
                .any(|e: &Json| placeholder_of(e).starts_with("<UUID_"))
        );
    }

    #[test]
    fn windows_path_is_detected() {
        let entries: Vec<Json> = entries_of(b"drops C:\\Windows\\Temp\\evil.exe now");
        assert!(
            entries
                .iter()
                .any(|e: &Json| placeholder_of(e).starts_with("<WINDOWS_PATH_"))
        );
    }

    #[test]
    fn unix_path_is_detected() {
        let entries: Vec<Json> = entries_of(b"reads /home/alice/.ssh/id_rsa file");
        assert!(
            entries
                .iter()
                .any(|e: &Json| placeholder_of(e).starts_with("<UNIX_PATH_"))
        );
    }

    #[test]
    fn pdb_path_is_detected() {
        let entries: Vec<Json> = entries_of(b"symbols C:\\build\\project.pdb loaded");
        assert!(
            entries
                .iter()
                .any(|e: &Json| placeholder_of(e).starts_with("<PDB_PATH_"))
        );
    }

    #[test]
    fn bitcoin_address_is_detected() {
        let entries: Vec<Json> = entries_of(b"btc 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa payment");
        assert!(
            entries
                .iter()
                .any(|e: &Json| placeholder_of(e).starts_with("<BITCOIN_ADDRESS_"))
        );
    }

    #[test]
    fn ethereum_address_is_detected() {
        let entries: Vec<Json> =
            entries_of(b"eth 0x52908400098527886E0F7030069857D2E4169EE7 payment");
        assert!(
            entries
                .iter()
                .any(|e: &Json| placeholder_of(e).starts_with("<ETHEREUM_ADDRESS_"))
        );
    }

    #[test]
    fn monero_address_is_detected() {
        let addr: String = format!("48{}", "9".repeat(93));
        let text: String = format!("xmr {addr} payment");
        let entries: Vec<Json> = entries_of(text.as_bytes());
        assert!(
            entries
                .iter()
                .any(|e: &Json| placeholder_of(e).starts_with("<MONERO_ADDRESS_")),
            "{entries:?}"
        );
    }

    #[test]
    fn litecoin_address_is_detected() {
        let entries: Vec<Json> = entries_of(b"ltc LhK2kQwiaAvhjWY799cZvMyYwnQAcxkarr payment");
        assert!(
            entries
                .iter()
                .any(|e: &Json| placeholder_of(e).starts_with("<LITECOIN_ADDRESS_"))
        );
    }

    #[test]
    fn tron_address_is_detected() {
        let entries: Vec<Json> = entries_of(b"trx TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t payment");
        assert!(
            entries
                .iter()
                .any(|e: &Json| placeholder_of(e).starts_with("<TRON_ADDRESS_"))
        );
    }

    #[test]
    fn non_pii_ioc_kinds_are_excluded() {
        let text: &[u8] =
            b"visit https://evil.example.com now at 192.168.0.1 or ::1 via HKLM\\Software\\Run";
        let entries: Vec<Json> = entries_of(text);
        assert!(
            entries.is_empty(),
            "url, domain, ipv4, ipv6 and registry key must never appear in pii_map: {entries:?}"
        );
    }

    #[test]
    fn crypto_constant_is_excluded() {
        let mut input: Vec<u8> = vec![0u8; 8];
        input.extend_from_slice(&[
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76,
        ]);
        assert!(entries_of(&input).is_empty());
    }

    #[test]
    fn secret_kinds_are_categorized_as_secret_without_a_filter() {
        for secret in [aws_akid(), github_pat(), stripe_live()] {
            let text: String = format!("key = {secret} done");
            let entries: Vec<Json> = entries_of(text.as_bytes());
            let found: &Json = entries
                .iter()
                .find(|e: &&Json| category_of(e) == "secret")
                .unwrap_or_else(|| panic!("no secret entry for {secret}: {entries:?}"));
            assert_eq!(category_of(found), "secret");
        }
    }

    #[test]
    fn same_value_at_two_offsets_shares_one_placeholder() {
        let secret: String = aws_akid();
        let text: String = format!("first {secret} later second {secret} again");
        let entries: Vec<Json> = entries_of(text.as_bytes());
        let secret_entries: Vec<&Json> = entries
            .iter()
            .filter(|e: &&Json| category_of(e) == "secret")
            .collect();
        let placeholders: BTreeSet<&str> = secret_entries
            .iter()
            .map(|e: &&Json| placeholder_of(e))
            .collect();
        assert_eq!(
            secret_entries.len(),
            2,
            "two occurrences must produce two spans: {entries:?}"
        );
        assert_eq!(
            placeholders.len(),
            1,
            "one placeholder must cover both spans: {entries:?}"
        );
    }

    #[test]
    fn same_value_in_two_encodings_shares_one_placeholder() {
        use base64::Engine as _;
        let inner: &str = "alice@example.com";
        let encoded: String = base64::engine::general_purpose::STANDARD.encode(inner);
        let text: String = format!("plain {inner} blob {encoded}");
        let entries: Vec<Json> = entries_of(text.as_bytes());
        let email_entries: Vec<&Json> = entries
            .iter()
            .filter(|e: &&Json| placeholder_of(e).starts_with("<EMAIL_"))
            .collect();
        assert_eq!(
            email_entries.len(),
            2,
            "plain and base64 must both surface a span: {entries:?}"
        );
        let placeholders: BTreeSet<&str> = email_entries
            .iter()
            .map(|e: &&Json| placeholder_of(e))
            .collect();
        assert_eq!(
            placeholders.len(),
            1,
            "the decoded value must be deduplicated across encodings: {entries:?}"
        );
    }

    #[test]
    fn placeholder_is_stable_across_two_runs() {
        let text: &[u8] = b"contact alice@example.com or bob@example.org today";
        let first: Vec<Json> = entries_of(text);
        let second: Vec<Json> = entries_of(text);
        assert_eq!(first, second);
    }

    #[test]
    fn placeholder_does_not_renumber_when_an_unrelated_category_gains_an_entry() {
        let base: &[u8] = b"contact alice@example.com today";
        let before: Vec<Json> = entries_of(base);
        let email_placeholder_before: &str = placeholder_of(
            before
                .iter()
                .find(|e: &&Json| placeholder_of(e).starts_with("<EMAIL_"))
                .expect("email entry"),
        );

        let extended: String = format!(
            "{} card 4111111111111111 exp",
            "contact alice@example.com today"
        );
        let after: Vec<Json> = entries_of(extended.as_bytes());
        let email_placeholder_after: &str = placeholder_of(
            after
                .iter()
                .find(|e: &&Json| placeholder_of(e).starts_with("<EMAIL_"))
                .expect("email entry"),
        );
        assert_eq!(
            email_placeholder_before, email_placeholder_after,
            "adding a credit-card finding must not renumber the email placeholder"
        );
    }

    #[test]
    fn offset_zero_is_reported_without_underflow() {
        let entries: Vec<Json> = entries_of(b"alice@example.com trailing text");
        let found: &Json = entries
            .iter()
            .find(|e: &&Json| placeholder_of(e).starts_with("<EMAIL_"))
            .expect("email entry");
        assert_eq!(byte_start_of(found), 0);
    }

    #[test]
    fn invalid_utf8_bytes_do_not_panic_and_secret_still_found() {
        let mut buf: Vec<u8> = vec![0xff, 0xfe, 0x00, 0xff];
        buf.extend_from_slice(format!("key = {} tail", aws_akid()).as_bytes());
        buf.push(0xfe);
        let entries: Vec<Json> = entries_of(&buf);
        assert!(entries.iter().any(|e: &Json| category_of(e) == "secret"));
    }

    #[test]
    fn nothing_found_produces_an_empty_outcome() {
        let outcome: PiiScanOutcome = scan(b"nothing sensitive in this buffer at all");
        assert!(outcome.entries.is_empty());
        assert_eq!(outcome.omitted, 0);
    }

    #[test]
    fn pii_scan_emitter_returns_none_when_nothing_found() {
        let emitter: PiiScan = PiiScan {
            bytes: b"nothing sensitive here".to_vec(),
        };
        assert!(emitter.emit_pii_map().is_none());
    }

    #[test]
    fn pii_scan_emitter_returns_array_when_found() {
        let emitter: PiiScan = PiiScan {
            bytes: b"contact alice@example.com".to_vec(),
        };
        let value: Json = emitter.emit_pii_map().expect("some value");
        assert!(value.is_array());
    }

    #[test]
    fn generic_dispatch_distinguishes_unsupported_from_found_nothing() {
        let selection: MetadataSelection =
            SelectionBuilder::new().category(Category::PiiMap).build();
        let empty: PiiScan = PiiScan { bytes: Vec::new() };
        let map: Json = empty.emit_metadata(&selection);
        let envelope: &Json = map.get("pii_map").expect("pii_map key");
        assert_eq!(
            envelope.get("applicable").and_then(Json::as_bool),
            Some(false)
        );
        assert!(envelope.get("value").is_none_or(Json::is_null));
        let reason: &str = envelope
            .get("reason")
            .and_then(Json::as_str)
            .expect("reason present");
        assert!(reason.contains("produced no data"), "{reason}");
    }

    #[test]
    fn cap_is_reached_and_reported() {
        use std::fmt::Write as _;
        let mut text: String = String::new();
        for i in 0..(MAX_PII_ENTRIES + 200) {
            let _: std::fmt::Result = write!(text, "user{i}@example{i}.com ");
        }
        let outcome: PiiScanOutcome = scan(text.as_bytes());
        assert_eq!(outcome.entries.len(), MAX_PII_ENTRIES);
        assert!(outcome.omitted > 0, "the cap must record what it dropped");
        assert!(!outcome.input_truncated());
    }

    #[test]
    fn input_under_the_scan_size_cap_is_not_truncated() {
        let text: String = format!("contact alice@example.com {}", ".".repeat(1024));
        let outcome: PiiScanOutcome = scan(text.as_bytes());
        assert!(!outcome.input_truncated());
        assert_eq!(outcome.scanned_bytes, outcome.total_bytes);
        assert!(!outcome.entries.is_empty());
    }

    #[test]
    fn input_beyond_the_scan_size_cap_is_visibly_truncated() {
        let mut buf: Vec<u8> = b"contact alice@example.com ".to_vec();
        buf.extend(std::iter::repeat_n(b'.', MAX_SCAN_BYTES));
        buf.extend_from_slice(b" contact bob@example.org");
        let outcome: PiiScanOutcome = scan(&buf);
        assert!(outcome.input_truncated());
        assert_eq!(outcome.scanned_bytes, MAX_SCAN_BYTES);
        assert_eq!(outcome.total_bytes, buf.len());
        assert!(
            outcome
                .entries
                .iter()
                .any(|e: &Json| e.get("placeholder").and_then(Json::as_str) == Some("<EMAIL_0>")),
            "the value inside the cap must still be found: {:?}",
            outcome.entries
        );
        let bob_found: bool = outcome.entries.iter().any(|e: &Json| {
            e.get("span")
                .and_then(|s: &Json| s.get("byte_start"))
                .and_then(Json::as_u64)
                .is_some_and(|off: u64| off > MAX_SCAN_BYTES as u64)
        });
        assert!(
            !bob_found,
            "a value beyond the cap must not be scanned: {:?}",
            outcome.entries
        );
    }

    #[test]
    fn overlap_resolution_prefers_the_earlier_starting_plain_candidate() {
        let overlapping: PiiCandidate = PiiCandidate {
            schema_category: "other",
            tag: "UNIX_PATH".to_owned(),
            value: "/home/alice/.ssh/id_rsa_extra_long_tail".to_owned(),
            offset: 0,
            byte_end: Some(40),
            overlap_eligible: true,
            overlap_priority: SPECIFIC_OVERLAP_PRIORITY,
        };
        let nested: PiiCandidate = PiiCandidate {
            schema_category: "email",
            tag: "EMAIL".to_owned(),
            value: "carved@inside.example".to_owned(),
            offset: 5,
            byte_end: Some(27),
            overlap_eligible: true,
            overlap_priority: SPECIFIC_OVERLAP_PRIORITY,
        };
        let kept: Vec<PiiCandidate> = resolve_overlaps(vec![nested, overlapping]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].tag, "UNIX_PATH");
    }

    #[test]
    fn non_plain_encoding_bypasses_overlap_suppression() {
        let plain: PiiCandidate = PiiCandidate {
            schema_category: "email",
            tag: "EMAIL".to_owned(),
            value: "alice@example.com".to_owned(),
            offset: 0,
            byte_end: Some(18),
            overlap_eligible: true,
            overlap_priority: SPECIFIC_OVERLAP_PRIORITY,
        };
        let encoded: PiiCandidate = PiiCandidate {
            schema_category: "email",
            tag: "EMAIL".to_owned(),
            value: "alice@example.com".to_owned(),
            offset: 10,
            byte_end: None,
            overlap_eligible: false,
            overlap_priority: SPECIFIC_OVERLAP_PRIORITY,
        };
        let kept: Vec<PiiCandidate> = resolve_overlaps(vec![plain, encoded]);
        assert_eq!(kept.len(), 2);
    }

    #[test]
    fn scan_output_reaches_render_agents_md_as_a_pii_detected_line() {
        use crate::bundle::{BundleBuilder, InputDescriptor, ToolDescriptor};
        use crate::envelope::PerPassEnvelope;
        use crate::markdown::render_agents_md;

        let secret: String = aws_akid();
        let text: String = format!("contact alice@example.com; key = {secret} done");
        let outcome: PiiScanOutcome = scan(text.as_bytes());
        assert!(!outcome.entries.is_empty());

        let envelope: PerPassEnvelope =
            PerPassEnvelope::applicable(PII_PASS, VERSION, Json::Array(outcome.entries));
        let mut per_pass: BTreeMap<&'static str, PerPassEnvelope> = BTreeMap::new();
        per_pass.insert(Category::PiiMap.label(), envelope);

        let mut builder: BundleBuilder = BundleBuilder::new();
        builder.record_pass(
            crate::bundle::PipelineStep {
                pass: PII_PASS.to_owned(),
                version: VERSION.to_owned(),
                rung_in: "raw".to_owned(),
                rung_out: "raw".to_owned(),
                duration_ms: 0.0_f64,
                input_hash_blake3: None,
                output_hash_blake3: None,
                capabilities_required: Vec::new(),
                capabilities_produced: Vec::new(),
                config: None,
            },
            crate::bundle::envelope_map(per_pass),
        );
        let selection: MetadataSelection =
            SelectionBuilder::new().category(Category::PiiMap).build();
        let input: InputDescriptor = InputDescriptor {
            path: "fixture.bin".to_owned(),
            size_bytes: text.len() as u64,
            hash_blake3: "0".repeat(64),
            magic_bytes_hex: None,
            detected_formats: Vec::new(),
        };
        let bundle: Json = builder
            .finalize(
                "2026-01-01T00:00:00.000000000Z".to_owned(),
                ToolDescriptor::default(),
                &selection,
                input,
            )
            .expect("bundle finalizes");

        let agents_md: String = render_agents_md(&bundle);
        assert!(
            agents_md.contains("PII detected"),
            "the rendered brief must warn about the PII this pass found: {agents_md}"
        );
        assert!(agents_md.contains("email"), "{agents_md}");
    }
}
