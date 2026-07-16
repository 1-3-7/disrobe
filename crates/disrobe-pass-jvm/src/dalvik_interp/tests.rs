#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::*;
use crate::dex::{CodeItem, DexFile, parse as parse_dex, parse_code_items};
use crate::dex_builder::{filled_new_array_string_sample, heap_bomb_sample, infinite_loop_sample};

fn find_method<'a>(items: &'a [CodeItem], name: &str) -> &'a CodeItem {
    items
        .iter()
        .find(|c: &&CodeItem| c.method_name == name)
        .expect("method present")
}

#[test]
fn wide_pair_round_trips_through_move_result_wide_and_return_wide() {
    let mut regs: Vec<RegSlot> = vec![RegSlot::Undefined; 4];
    write_wide(&mut regs, 0, i64::MIN).expect("write wide");
    let read_back: i64 = read_wide(&regs, 0).expect("read wide");
    assert_eq!(read_back, i64::MIN);
}

#[test]
fn reading_the_high_half_of_a_live_wide_pair_directly_is_unsound() {
    let mut regs: Vec<RegSlot> = vec![RegSlot::Undefined; 4];
    write_wide(&mut regs, 0, 42).expect("write wide");
    assert_eq!(read_reg(&regs, 1), Err(SkipReason::Unsound));
}

#[test]
fn narrow_overwrite_of_a_wide_low_half_breaks_the_pair_for_a_later_wide_read() {
    let mut regs: Vec<RegSlot> = vec![RegSlot::Undefined; 4];
    write_wide(&mut regs, 0, 0x1122_3344_5566_7788).expect("write wide");
    write_reg(&mut regs, 0, RegSlot::I32(7)).expect("narrow write");
    assert_eq!(read_wide(&regs, 0), Err(SkipReason::Unsound));
}

#[test]
fn shl_int_masks_the_shift_amount_to_five_bits() {
    assert_eq!(int_binop(0x98, 1, 32), Ok(1));
    assert_eq!(int_binop(0x98, 1, 33), Ok(2));
}

#[test]
fn shl_long_masks_the_shift_amount_to_six_bits() {
    assert_eq!(long_binop(0xA3, 1, 64), Ok(1));
    assert_eq!(long_binop(0xA3, 1, 65), Ok(2));
}

#[test]
fn ushr_int_is_logical_not_arithmetic() {
    assert_eq!(int_binop(0x9A, -1, 28), Ok(15));
}

#[test]
fn div_int_by_zero_is_a_typed_skip_not_a_panic() {
    assert_eq!(int_binop(0x93, 10, 0), Err(SkipReason::DivByZero));
}

#[test]
fn rem_long_by_zero_is_a_typed_skip() {
    assert_eq!(long_binop(0x9F, 10, 0), Err(SkipReason::DivByZero));
}

#[test]
fn div_int_min_by_negative_one_wraps_instead_of_panicking() {
    assert_eq!(int_binop(0x93, i32::MIN, -1), Ok(i32::MIN));
}

#[test]
fn iso_8859_1_decode_is_a_literal_byte_to_codepoint_mapping() {
    let units: Vec<u16> = decode_charset("ISO-8859-1", &[0xE9, 0x41]);
    assert_eq!(units, vec![0x00E9, 0x0041]);
}

#[test]
fn us_ascii_decode_replaces_high_bytes() {
    let units: Vec<u16> = decode_charset("US-ASCII", &[0x41, 0xFF]);
    assert_eq!(units, vec![0x0041, 0xFFFD]);
}

#[test]
fn utf8_decode_replaces_malformed_sequences() {
    let units: Vec<u16> = decode_charset("UTF-8", &[0xC3, 0x28]);
    assert!(units.contains(&0xFFFD));
}

#[test]
fn filled_new_array_feeds_a_real_string_constructor_through_the_real_dex_parser() {
    let dex_bytes: Vec<u8> = filled_new_array_string_sample(*b"hi!");
    let dex: DexFile = parse_dex(&dex_bytes).expect("parses");
    let items: Vec<CodeItem> = parse_code_items(&dex, &dex_bytes);
    let demo: &CodeItem = find_method(&items, "demo");
    let mut interp: Interp<'_> =
        Interp::new(&dex, "Lcom/disrobe/sample/GenericFilledNewArray;", &items);
    let regs: Vec<RegSlot> = vec![RegSlot::Undefined; usize::from(demo.registers_size).max(1)];
    let result: RegSlot = interp
        .execute(demo, regs)
        .expect("filled-new-array + String.<init>([B) must not skip")
        .expect("must return a value");
    let text: String = interp.finish_text(result).expect("finishes as text");
    assert_eq!(text, "hi!");
}

#[test]
fn an_unconditional_backward_loop_terminates_via_a_typed_budget_skip_not_a_hang() {
    let bytes: Vec<u8> = infinite_loop_sample();
    let dex: DexFile = parse_dex(&bytes).expect("fixture parses");
    let items: Vec<CodeItem> = parse_code_items(&dex, &bytes);
    let spin: &CodeItem = find_method(&items, "spin");
    let mut interp: Interp<'_> =
        Interp::new(&dex, "Lcom/disrobe/sample/GenericInfiniteLoop;", &items);
    let regs: Vec<RegSlot> = vec![RegSlot::Undefined; usize::from(spin.registers_size).max(1)];
    assert_eq!(interp.execute(spin, regs), Err(SkipReason::BudgetExhausted));
}

#[test]
fn a_loop_that_allocates_forever_stops_at_the_heap_budget_not_a_hang_or_oom() {
    let bytes: Vec<u8> = heap_bomb_sample();
    let dex: DexFile = parse_dex(&bytes).expect("fixture parses");
    let items: Vec<CodeItem> = parse_code_items(&dex, &bytes);
    let bomb: &CodeItem = find_method(&items, "bomb");
    let mut interp: Interp<'_> = Interp::new(&dex, "Lcom/disrobe/sample/GenericHeapBomb;", &items);
    let regs: Vec<RegSlot> = vec![RegSlot::Undefined; usize::from(bomb.registers_size).max(1)];
    assert_eq!(interp.execute(bomb, regs), Err(SkipReason::OutputTooLarge));
}
