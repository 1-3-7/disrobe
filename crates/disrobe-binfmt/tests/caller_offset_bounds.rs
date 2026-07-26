#![allow(clippy::expect_used, clippy::panic)]
use disrobe_binfmt::Error;
use disrobe_binfmt::containers::{parse_gpt_header, parse_squashfs_superblock};

#[test]
fn a_gpt_header_offset_that_overflows_the_address_space_is_refused() {
    let error: Error = parse_gpt_header(&[], usize::MAX)
        .expect_err("an offset that cannot be added to must be refused, not added to");
    assert!(
        matches!(&error, Error::Decompression(reason) if reason == "gpt header offset overflow"),
        "the refusal must name the overflow rather than any later condition: {error}"
    );
}

#[test]
fn a_gpt_header_offset_past_the_end_is_refused_as_truncated() {
    let error: Error = parse_gpt_header(&[0u8; 16], 8)
        .expect_err("an offset inside the buffer but past the header span must be refused");
    assert!(
        matches!(&error, Error::Decompression(reason) if reason == "gpt header truncated"),
        "an in-range offset with too few bytes is a truncation, not an overflow: {error}"
    );
}

#[test]
fn a_squashfs_offset_that_overflows_the_address_space_is_refused() {
    let error: Error = parse_squashfs_superblock(&[], usize::MAX)
        .expect_err("the sibling parser must refuse the same shape");
    assert!(
        matches!(&error, Error::Decompression(reason) if reason == "squashfs offset overflow"),
        "the sibling refusal must also name the overflow: {error}"
    );
}
