#![allow(clippy::expect_used, clippy::unwrap_used)]
use std::collections::BTreeMap;

use disrobe_core::{Capability, CapabilityKind};
use disrobe_ir::{Envelope, EnvelopeError, RawPayload, Rung, Sidecar};
use proptest::prelude::*;

fn arb_rung() -> impl Strategy<Value = Rung> {
    prop_oneof![
        Just(Rung::Raw),
        Just(Rung::Disasm),
        Just(Rung::Mir),
        Just(Rung::Hir),
        Just(Rung::Surface),
    ]
}

fn arb_capability() -> impl Strategy<Value = Capability> {
    (any::<u32>(), "[a-z][a-z0-9-]{0,16}").prop_flat_map(|(major, name)| {
        prop_oneof![
            Just(Capability {
                name: name.clone(),
                major,
                kind: CapabilityKind::Requires,
            }),
            Just(Capability {
                name,
                major,
                kind: CapabilityKind::Produces,
            }),
        ]
    })
}

fn arb_provenance() -> impl Strategy<Value = BTreeMap<String, String>> {
    proptest::collection::btree_map("[a-z]{1,8}", "[a-z0-9]{0,32}", 0..4)
}

fn arb_sidecar() -> impl Strategy<Value = Sidecar> {
    (
        "[a-z][a-z-]{0,16}",
        "[0-9]\\.[0-9]\\.[0-9]",
        proptest::collection::vec(arb_capability(), 0..4),
        arb_provenance(),
    )
        .prop_map(
            |(produced_by, produced_by_version, capabilities, provenance)| Sidecar {
                produced_by,
                produced_by_version,
                capabilities,
                provenance,
            },
        )
}

fn arb_raw_payload() -> impl Strategy<Value = RawPayload> {
    (
        "[a-zA-Z0-9_./-]{1,32}",
        proptest::collection::vec(any::<u8>(), 0..256),
        any::<[u8; 32]>(),
        prop_oneof![Just(None), "[a-z]{1,8}".prop_map(Some)],
    )
        .prop_map(
            |(source_path, source_bytes, source_hash, detected_format)| RawPayload {
                source_path,
                source_bytes,
                source_hash,
                detected_format,
            },
        )
}

fn arb_envelope() -> impl Strategy<Value = Envelope> {
    (arb_rung(), arb_raw_payload(), arb_sidecar()).prop_map(|(rung, payload, sidecar)| {
        let hot: Vec<u8> = disrobe_ir::encode_raw(&payload).expect("rkyv encode");
        let cold: Vec<u8> = sidecar.encode().expect("postcard encode");
        Envelope::new(rung, hot, cold)
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn round_trip_preserves_all_fields(env in arb_envelope()) {
        let bytes: Vec<u8> = env.encode().expect("encode");
        let decoded: Envelope = Envelope::decode(&bytes).expect("decode succeeds for any valid envelope");
        prop_assert_eq!(env.version, decoded.version);
        prop_assert_eq!(env.rung, decoded.rung);
        prop_assert_eq!(env.flags, decoded.flags);
        prop_assert_eq!(env.hot, decoded.hot);
        prop_assert_eq!(env.cold, decoded.cold);
        prop_assert_eq!(env.root_hash, decoded.root_hash);
    }

    #[test]
    fn raw_payload_round_trip(payload in arb_raw_payload()) {
        let bytes: Vec<u8> = disrobe_ir::encode_raw(&payload).expect("encode");
        let decoded: RawPayload = disrobe_ir::decode_raw(&bytes).expect("decode");
        prop_assert_eq!(payload, decoded);
    }

    #[test]
    fn sidecar_round_trip(sidecar in arb_sidecar()) {
        let bytes: Vec<u8> = sidecar.encode().expect("encode");
        let decoded: Sidecar = Sidecar::decode(&bytes).expect("decode");
        prop_assert_eq!(sidecar, decoded);
    }

    #[test]
    fn single_byte_flip_in_payload_caught_by_root_hash(
        env in arb_envelope(),
        flip_index in 0usize..2048,
    ) {
        let mut bytes: Vec<u8> = env.encode().expect("encode");
        let header_size: usize = 52usize;
        prop_assume!(bytes.len() > header_size);
        let payload_len: usize = bytes.len() - header_size;
        let idx: usize = header_size + (flip_index % payload_len);
        bytes[idx] ^= 0x01;
        let result: Result<Envelope, EnvelopeError> = Envelope::decode(&bytes);
        prop_assert!(
            matches!(result, Err(EnvelopeError::RootHashMismatch { .. })),
            "expected RootHashMismatch, got {result:?}",
        );
    }

    #[test]
    fn truncated_envelope_rejected(env in arb_envelope(), keep in 0usize..52) {
        let bytes: Vec<u8> = env.encode().expect("encode");
        let truncated: &[u8] = &bytes[..keep.min(bytes.len())];
        let result: Result<Envelope, EnvelopeError> = Envelope::decode(truncated);
        prop_assert!(
            matches!(
                result,
                Err(EnvelopeError::Truncated { .. }
                    | EnvelopeError::HotLenMismatch { .. }
                    | EnvelopeError::ColdLenMismatch { .. })
            ),
            "a header-truncated envelope must fail with a truncation-class variant, not a hash or codec error and not Ok: {result:?}",
        );
        prop_assert!(
            !matches!(result, Err(EnvelopeError::RootHashMismatch { .. })),
            "truncation before the payload must never be misreported as a root-hash mismatch: {result:?}",
        );
    }
}
