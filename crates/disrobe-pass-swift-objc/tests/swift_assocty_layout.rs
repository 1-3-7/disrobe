#![allow(clippy::expect_used, clippy::unwrap_used)]
mod fixtures;

use disrobe_pass_swift_objc::macho::{self, ParsedSlice};
use disrobe_pass_swift_objc::swift::{self, SwiftClassDump};
use disrobe_pass_swift_objc::swift_typedump::{SwiftAssociatedTypeRecord, SwiftTypeDump};

use crate::fixtures::{MachoSectionSpec, MachoSegmentSpec, MachoSliceBuilder, build_macho64_slice};

const CONFORMING: &str = "$s3App5BoxedV";
const PROTOCOL: &str = "$s3App10ContainerP";
const W0_NAME: &str = "Element";
const W0_SUB: &str = "Si";
const W1_NAME: &str = "Index";
const W1_SUB: &str = "SS";

fn rel(field_off: usize, target_off: usize) -> [u8; 4] {
    let delta: i32 = i32::try_from(target_off as i64 - field_off as i64).expect("rel fits in i32");
    delta.to_le_bytes()
}

fn build_assocty_section() -> Vec<u8> {
    let header_len: usize = 16;
    let witness_region: usize = 2 * 8;
    let pool_base: usize = header_len + witness_region;

    let conforming_off: usize = pool_base;
    let protocol_off: usize = conforming_off + CONFORMING.len() + 1;
    let w0_name_off: usize = protocol_off + PROTOCOL.len() + 1;
    let w0_sub_off: usize = w0_name_off + W0_NAME.len() + 1;
    let w1_name_off: usize = w0_sub_off + W0_SUB.len() + 1;
    let w1_sub_off: usize = w1_name_off + W1_NAME.len() + 1;

    let mut out: Vec<u8> = Vec::with_capacity(w1_sub_off + W1_SUB.len() + 1);
    out.extend_from_slice(&rel(0, conforming_off));
    out.extend_from_slice(&rel(4, protocol_off));
    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&8u32.to_le_bytes());
    out.extend_from_slice(&rel(16, w0_name_off));
    out.extend_from_slice(&rel(20, w0_sub_off));
    out.extend_from_slice(&rel(24, w1_name_off));
    out.extend_from_slice(&rel(28, w1_sub_off));

    for s in [CONFORMING, PROTOCOL, W0_NAME, W0_SUB, W1_NAME, W1_SUB] {
        out.extend_from_slice(s.as_bytes());
        out.push(0);
    }
    out
}

fn slice_with_assocty() -> Vec<u8> {
    let builder: MachoSliceBuilder = MachoSliceBuilder {
        segments: vec![MachoSegmentSpec {
            seg_name: "__TEXT",
            sections: vec![MachoSectionSpec {
                sect_name: "__swift5_assocty",
                seg_name: "__TEXT",
                data: build_assocty_section(),
            }],
        }],
        encryption_id: 0,
    };
    build_macho64_slice(&builder)
}

#[test]
fn assocty_decoder_recovers_witnesses_from_abi_layout() {
    let slice: Vec<u8> = slice_with_assocty();
    let parsed: ParsedSlice = macho::parse_slice(&slice).expect("parse");
    let dump: SwiftClassDump = swift::class_dump(&slice, &parsed);
    let td: &SwiftTypeDump = &dump.type_dump;

    assert_eq!(td.associated_types.len(), 1, "one associated-type record");
    let rec: &SwiftAssociatedTypeRecord = &td.associated_types[0];
    assert_eq!(rec.conforming_type_mangled.as_deref(), Some(CONFORMING));
    assert_eq!(rec.protocol_mangled.as_deref(), Some(PROTOCOL));
    assert_eq!(rec.witnesses.len(), 2);

    assert_eq!(rec.witnesses[0].name, "Element");
    assert_eq!(rec.witnesses[0].substituted_mangled_type, "Si");
    assert_eq!(
        rec.witnesses[0].substituted_demangled_type.as_deref(),
        Some("Swift.Int")
    );

    assert_eq!(rec.witnesses[1].name, "Index");
    assert_eq!(rec.witnesses[1].substituted_mangled_type, "SS");
    assert_eq!(
        rec.witnesses[1].substituted_demangled_type.as_deref(),
        Some("Swift.String")
    );

    let rendered: String = td.render();
    assert!(rendered.contains("typealias Element = Swift.Int"));
    assert!(rendered.contains("typealias Index = Swift.String"));
}
