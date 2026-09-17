#![allow(clippy::expect_used)]

use disrobe_pass_as3::error::Error;
use disrobe_pass_as3::swf::{SwfTag, TagCode, parse_symbol_class};

#[test]
fn symbol_class_count_past_minimum_payload_is_rejected_before_allocation() {
    let tag: SwfTag = SwfTag {
        code: TagCode::SYMBOL_CLASS,
        offset: 16,
        payload: 0xFFFFu16.to_le_bytes().to_vec(),
    };
    let err: Error = parse_symbol_class(&tag).expect_err("count must fit payload");
    assert!(
        matches!(err, Error::BadTag { reason, .. } if reason == "SymbolClass count exceeds payload"),
        "expected SymbolClass payload bound, got {err}"
    );
}
