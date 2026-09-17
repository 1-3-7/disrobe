#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_ruby::{RubyError, analyze_bytes};

mod common;

fn yarv_header(
    major: u32,
    minor: u32,
    size: u32,
    iseq_n: u32,
    obj_n: u32,
    iseq_off: u32,
    obj_off: u32,
) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::with_capacity(36);
    v.extend_from_slice(b"YARB");
    v.extend_from_slice(&major.to_le_bytes());
    v.extend_from_slice(&minor.to_le_bytes());
    v.extend_from_slice(&size.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&iseq_n.to_le_bytes());
    v.extend_from_slice(&obj_n.to_le_bytes());
    v.extend_from_slice(&iseq_off.to_le_bytes());
    v.extend_from_slice(&obj_off.to_le_bytes());
    v
}

#[test]
fn yarv_oversized_object_count_does_not_oom_or_hang() {
    let bytes: Vec<u8> = yarv_header(3, 4, 36, 1, u32::MAX, 36, 36);
    let analysis = analyze_bytes(&bytes, "evil.yarvc").expect("must return Ok without OOM");
    let yarv = analysis.yarv.expect("yarv");
    assert!(
        yarv.ibf.objects.len() < 4096,
        "object table reads must stop at buffer end, got {}",
        yarv.ibf.objects.len()
    );
}

#[test]
fn yarv_oversized_iseq_count_is_bounded() {
    let bytes: Vec<u8> = yarv_header(3, 4, 36, u32::MAX, 0, 36, 36);
    let analysis = analyze_bytes(&bytes, "evil.yarvc").expect("must return Ok");
    let yarv = analysis.yarv.expect("yarv");
    assert!(yarv.ibf.iseq_offsets.len() < 4096);
}

#[test]
fn yarv_object_offset_past_eof_is_safe() {
    let mut v: Vec<u8> = yarv_header(3, 4, 44, 0, 1, 36, 40);
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    let analysis = analyze_bytes(&v, "evil.yarvc").expect("must not panic");
    let yarv = analysis.yarv.expect("yarv");
    assert_eq!(yarv.ibf.objects.len(), 1);
    assert!(yarv.ibf.objects[0].literal.is_none());
}

#[test]
fn yarv_offsets_near_u32_max_do_not_overflow() {
    let bytes: Vec<u8> = yarv_header(3, 4, 36, 2, 2, u32::MAX - 1, u32::MAX - 1);
    let analysis = analyze_bytes(&bytes, "evil.yarvc").expect("must not overflow-panic");
    assert!(analysis.yarv.is_some());
}

#[test]
fn yarv_string_object_with_huge_len_is_safe() {
    let mut v: Vec<u8> = yarv_header(3, 4, 0, 0, 1, 36, 40);
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&44u32.to_le_bytes());
    v.push(0x45);
    v.push(0x03);
    v.push(0xfe);
    v.push(0xff);
    v.push(0xff);
    v.push(0xff);
    v.push(0x7f);
    let analysis = analyze_bytes(&v, "evil.yarvc").expect("must not panic on huge len");
    assert!(analysis.yarv.is_some());
}

#[test]
fn mruby_oversized_pool_count_is_bounded() {
    let mut rec: Vec<u8> = Vec::new();
    rec.extend_from_slice(&0u32.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&0u32.to_be_bytes());
    rec.extend_from_slice(&u32::MAX.to_be_bytes());
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(&rec);
    let sections: Vec<Vec<u8>> = vec![
        common::synth_section(*b"IREP", &body),
        common::synth_section(*b"END\0", &[]),
    ];
    let bytes: Vec<u8> = common::synth_rite(*b"0300", &sections);
    let analysis = analyze_bytes(&bytes, "evil.mrb").expect("must not OOM");
    let mrb = analysis.mruby.expect("mruby");
    assert!(
        mrb.irep.is_none(),
        "malformed pool must fail IREP parse cleanly"
    );
}

#[test]
fn mruby_pool_string_length_near_the_wire_ceiling_is_bounded() {
    let mut rec: Vec<u8> = Vec::new();
    rec.extend_from_slice(&0u32.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&0u32.to_be_bytes());
    rec.extend_from_slice(&1u16.to_be_bytes());
    rec.push(0x00);
    rec.extend_from_slice(&u16::MAX.to_be_bytes());
    rec.extend_from_slice(b"only four bytes follow");
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(&rec);
    let sections: Vec<Vec<u8>> = vec![
        common::synth_section(*b"IREP", &body),
        common::synth_section(*b"END\0", &[]),
    ];
    let bytes: Vec<u8> = common::synth_rite(*b"0300", &sections);
    let start: std::time::Instant = std::time::Instant::now();
    let analysis = analyze_bytes(&bytes, "evil.mrb").expect("must not OOM or panic");
    let elapsed: std::time::Duration = start.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "a pool string claiming the u16 wire-format ceiling must not stall parsing, took {elapsed:?}"
    );
    let mrb = analysis.mruby.expect("mruby");
    assert!(
        mrb.irep.is_none(),
        "a pool string length past the actual file must fail IREP parse cleanly, not allocate it"
    );
}

#[test]
fn mruby_truncated_header_is_rejected_cleanly() {
    let bytes: Vec<u8> = b"RITE0300\x00\x00\x00\x14MATZ".to_vec();
    assert!(
        bytes.len() < 20,
        "the fixture itself must be under the 20-byte header size"
    );
    let result = std::panic::catch_unwind(|| analyze_bytes(&bytes, "short.mrb"));
    let outcome = result.expect("a header shorter than RITE_HEADER_SIZE must not panic");
    assert!(
        matches!(outcome, Err(RubyError::Truncated { .. })),
        "a header shorter than RITE_HEADER_SIZE must be a clean truncation error, got {outcome:?}"
    );
}

#[test]
fn mruby_section_length_past_the_file_is_rejected_cleanly() {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(b"IREP");
    body.extend_from_slice(&255u32.to_be_bytes());
    let bytes: Vec<u8> = common::synth_rite(*b"0300", &[body]);
    let result = std::panic::catch_unwind(|| analyze_bytes(&bytes, "oversized-section.mrb"));
    let outcome = result.expect("a section length past the file must not panic");
    assert!(
        matches!(outcome, Err(RubyError::MrubySectionTruncated { .. })),
        "a section whose declared length runs past the file must be a clean truncation error, \
         got {outcome:?}"
    );
}

#[test]
fn mruby_zero_length_section_is_rejected_cleanly() {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(b"IREP");
    body.extend_from_slice(&0u32.to_be_bytes());
    let bytes: Vec<u8> = common::synth_rite(*b"0300", &[body]);
    let result = std::panic::catch_unwind(|| analyze_bytes(&bytes, "zero-section.mrb"));
    let outcome = result.expect("a zero-length section must not panic or loop");
    assert!(
        matches!(outcome, Err(RubyError::MrubySectionTruncated { .. })),
        "a zero-length section must be a clean truncation error, got {outcome:?}"
    );
}

#[test]
fn mruby_recursion_bomb_is_depth_bounded() {
    let mut rec: Vec<u8> = Vec::new();
    rec.extend_from_slice(&0u32.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&1u16.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&0u32.to_be_bytes());
    rec.extend_from_slice(&0u32.to_be_bytes());
    rec.extend_from_slice(&0u32.to_be_bytes());
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&0u32.to_be_bytes());
    for _ in 0..2048 {
        body.extend_from_slice(&rec);
    }
    let sections: Vec<Vec<u8>> = vec![
        common::synth_section(*b"IREP", &body),
        common::synth_section(*b"END\0", &[]),
    ];
    let bytes: Vec<u8> = common::synth_rite(*b"0300", &sections);
    let analysis = analyze_bytes(&bytes, "bomb.mrb").expect("must not stack-overflow");
    let mrb = analysis.mruby.expect("mruby");
    assert!(
        mrb.irep.is_none(),
        "a record claiming a child it does not supply must be rejected, not parsed into a tree"
    );
    assert_eq!(
        mrb.decompiled.instruction_count, 0,
        "a rejected irep yields zero recovered instructions"
    );
    assert!(!mrb.decompiled.has_body);
}

fn mruby_with_iseq(iseq: &[u8], pool_count: u16, sym_count: u16, tail: &[u8]) -> Vec<u8> {
    let mut rec: Vec<u8> = Vec::new();
    rec.extend_from_slice(&0u32.to_be_bytes());
    rec.extend_from_slice(&1u16.to_be_bytes());
    rec.extend_from_slice(&4u16.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&(iseq.len() as u32).to_be_bytes());
    rec.extend_from_slice(iseq);
    rec.extend_from_slice(&pool_count.to_be_bytes());
    rec.extend_from_slice(&sym_count.to_be_bytes());
    rec.extend_from_slice(tail);
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(&rec);
    let sections: Vec<Vec<u8>> = vec![
        common::synth_section(*b"IREP", &body),
        common::synth_section(*b"END\0", &[]),
    ];
    common::synth_rite(*b"0300", &sections)
}

fn mruby_with_iseq_and_pool_string(iseq: &[u8], value: &str) -> Vec<u8> {
    let mut rec: Vec<u8> = Vec::new();
    rec.extend_from_slice(&0u32.to_be_bytes());
    rec.extend_from_slice(&1u16.to_be_bytes());
    rec.extend_from_slice(&4u16.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&0u16.to_be_bytes());
    rec.extend_from_slice(&(iseq.len() as u32).to_be_bytes());
    rec.extend_from_slice(iseq);
    rec.extend_from_slice(&1u16.to_be_bytes());
    rec.push(0);
    rec.extend_from_slice(
        &u16::try_from(value.len())
            .expect("pool string length fits u16")
            .to_be_bytes(),
    );
    rec.extend_from_slice(value.as_bytes());
    rec.push(0);
    rec.extend_from_slice(&0u16.to_be_bytes());
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(&rec);
    let sections: Vec<Vec<u8>> = vec![
        common::synth_section(*b"IREP", &body),
        common::synth_section(*b"END\0", &[]),
    ];
    common::synth_rite(*b"0300", &sections)
}

#[test]
fn mruby_unknown_opcode_in_body_is_rejected() {
    let bytes: Vec<u8> = mruby_with_iseq(&[0xFE, 0xFF], 0, 0, &[]);
    let analysis = analyze_bytes(&bytes, "x.mrb").expect("analyze must not panic");
    let mrb = analysis.mruby.expect("mruby");
    assert!(
        !mrb.decompiled.has_body,
        "an iseq whose only byte is an unknown opcode must not yield a body"
    );
    assert!(
        mrb.decompiled.source.contains("iseq lift failed"),
        "the lift failure must be reported, not silently swallowed; got:\n{}",
        mrb.decompiled.source
    );
    assert_eq!(mrb.decompiled.instruction_count, 0);
}

#[test]
fn mruby_truncated_jump_operand_in_body_is_clean() {
    let bytes: Vec<u8> = mruby_with_iseq(&[0x25, 0x12], 0, 0, &[]);
    let analysis = analyze_bytes(&bytes, "x.mrb").expect("analyze must not panic");
    let mrb = analysis.mruby.expect("mruby");
    assert!(
        !mrb.decompiled.has_body,
        "JMP with a single trailing operand byte cannot be decoded, so no body is emitted"
    );
    assert_eq!(
        mrb.decompiled.instruction_count, 0,
        "a half-read jump leaves zero recovered instructions"
    );
    assert!(
        mrb.decompiled.source.contains("iseq lift failed"),
        "truncation must surface as a lift failure; got:\n{}",
        mrb.decompiled.source
    );
}

#[test]
fn mruby_send_with_symbol_index_past_table_withholds_source() {
    let iseq: [u8; 8] = [0x12, 0x01, 0x2f, 0x01, 0xff, 0x00, 0x38, 0x01];
    let bytes: Vec<u8> = mruby_with_iseq(&iseq, 0, 0, &[]);
    let analysis = analyze_bytes(&bytes, "x.mrb").expect("analyze must not panic");
    let mrb = analysis.mruby.expect("mruby");
    assert!(
        mrb.irep.is_some(),
        "the parser must preserve structural IREP analysis for an invalid symbol selector"
    );
    assert!(
        !mrb.decompiled.has_body,
        "an invalid symbol selector must withhold reconstructed source"
    );
    assert!(
        mrb.decompiled
            .source
            .contains("reconstructed source withheld: an IREP reference is invalid"),
        "the abstention reason must remain visible; got:\n{}",
        mrb.decompiled.source
    );
    assert!(
        mrb.decompiled.recovered_symbols.is_empty(),
        "an out-of-range index must not fabricate a recovered symbol"
    );
}

#[test]
fn mruby_loadl_pool_index_past_table_withholds_source() {
    let iseq: [u8; 5] = [0x02, 0x01, 0xff, 0x38, 0x01];
    let bytes: Vec<u8> = mruby_with_iseq(&iseq, 0, 0, &[]);
    let analysis = analyze_bytes(&bytes, "x.mrb").expect("analyze must not panic");
    let mrb = analysis.mruby.expect("mruby");
    assert!(
        mrb.irep.is_some(),
        "the parser must preserve structural IREP analysis for an invalid pool selector"
    );
    assert!(
        !mrb.decompiled.has_body,
        "an invalid pool selector must withhold reconstructed source"
    );
    assert!(
        mrb.decompiled
            .source
            .contains("reconstructed source withheld: an IREP reference is invalid"),
        "the abstention reason must remain visible; got:\n{}",
        mrb.decompiled.source
    );
    assert!(
        mrb.decompiled.recovered_strings.is_empty(),
        "an out-of-range pool index must not fabricate a recovered literal"
    );
}

fn has_only_comment_or_empty_lines(text: &str) -> bool {
    text.lines()
        .all(|line: &str| line.trim().is_empty() || line.trim_start().starts_with('#'))
}

#[test]
fn mruby_withheld_output_escapes_newline_symbols() {
    let symbol: &str = "actual_symbol\nputs(\"attacker\")";
    let mut tail: Vec<u8> = Vec::new();
    tail.extend_from_slice(
        &u16::try_from(symbol.len())
            .expect("symbol length fits u16")
            .to_be_bytes(),
    );
    tail.extend_from_slice(symbol.as_bytes());
    tail.push(0);
    let iseq: [u8; 8] = [0x12, 0x01, 0x2f, 0x01, 0xff, 0x00, 0x38, 0x01];
    let bytes: Vec<u8> = mruby_with_iseq(&iseq, 0, 1, &tail);
    let analysis = analyze_bytes(&bytes, "newline-symbol.mrb").expect("analyze must not panic");
    let mrb = analysis.mruby.expect("mruby");

    assert!(mrb.irep.is_some(), "the IREP fixture must parse");
    assert_eq!(mrb.decompiled.recovered_symbols, vec![symbol.to_owned()]);
    assert!(!mrb.decompiled.has_body);
    assert!(
        mrb.decompiled
            .source
            .contains("reconstructed source withheld: an IREP reference is invalid"),
        "source: {}",
        mrb.decompiled.source
    );
    assert!(
        mrb.decompiled.source.contains(&format!("{symbol:?}")),
        "the display must retain an escaped representation of the matched symbol: {}",
        mrb.decompiled.source
    );
    assert!(
        !mrb.decompiled.source.contains(symbol),
        "a raw newline-bearing symbol must not enter the human source output: {}",
        mrb.decompiled.source
    );
    assert!(
        has_only_comment_or_empty_lines(&mrb.decompiled.source),
        "withheld output must not contain an executable line: {}",
        mrb.decompiled.source
    );
}

#[test]
fn mruby_valid_newline_send_symbol_withholds_source() {
    let symbol: &str = "actual_symbol\nputs(\"attacker\")";
    let mut tail: Vec<u8> = Vec::new();
    tail.extend_from_slice(
        &u16::try_from(symbol.len())
            .expect("symbol length fits u16")
            .to_be_bytes(),
    );
    tail.extend_from_slice(symbol.as_bytes());
    tail.push(0);
    let iseq: [u8; 8] = [0x12, 0x01, 0x2f, 0x01, 0x00, 0x00, 0x38, 0x01];
    let bytes: Vec<u8> = mruby_with_iseq(&iseq, 0, 1, &tail);
    let analysis =
        analyze_bytes(&bytes, "valid-newline-symbol.mrb").expect("analyze must not panic");
    let mrb = analysis.mruby.expect("mruby");

    assert!(mrb.irep.is_some(), "the IREP fixture must parse");
    assert_eq!(mrb.decompiled.recovered_symbols, vec![symbol.to_owned()]);
    assert!(!mrb.decompiled.has_body);
    assert!(
        mrb.decompiled
            .source
            .contains("reconstructed source withheld: an IREP reference is invalid"),
        "source: {}",
        mrb.decompiled.source
    );
    assert!(
        !mrb.decompiled.source.contains(symbol),
        "a valid newline-bearing call symbol must not enter recovered source: {}",
        mrb.decompiled.source
    );
    assert!(
        has_only_comment_or_empty_lines(&mrb.decompiled.source),
        "withheld output must not contain an executable line: {}",
        mrb.decompiled.source
    );
}

#[test]
fn mruby_intern_escapes_newline_pool_string() {
    let payload: &str = "flavor\nputs(\"attacker\")";
    let iseq: [u8; 7] = [0x51, 0x01, 0x00, 0x4f, 0x01, 0x38, 0x01];
    let bytes: Vec<u8> = mruby_with_iseq_and_pool_string(&iseq, payload);
    let analysis =
        analyze_bytes(&bytes, "intern-newline-pool.mrb").expect("analyze must not panic");
    let mrb = analysis.mruby.expect("mruby");

    assert!(mrb.irep.is_some(), "the IREP fixture must parse");
    assert!(mrb.decompiled.has_body);
    assert!(
        mrb.decompiled
            .source
            .contains(":\"flavor\\nputs(\\\"attacker\\\")\""),
        "interned symbol must use an escaped Ruby literal: {}",
        mrb.decompiled.source
    );
    assert!(
        !mrb.decompiled.source.contains(payload),
        "a raw pool string must not become a second executable source line: {}",
        mrb.decompiled.source
    );
}

#[test]
fn yarv_iseq_body_with_bad_bytecode_offset_is_safe() {
    let mut v: Vec<u8> = yarv_header(3, 4, 0, 1, 0, 36, 40);
    v.extend_from_slice(&40u32.to_le_bytes());
    v.extend_from_slice(&[0x03, 0x05, 0x01, 0x03, 0x09]);
    let analysis = analyze_bytes(&v, "evil.yarvc").expect("must not panic on bad iseq body");
    let yarv = analysis.yarv.expect("yarv");
    assert_eq!(
        yarv.ibf.recovered_instruction_count, 0,
        "a body whose header reads garbage decodes no instructions"
    );
    assert!(
        yarv.ibf.iseqs.len() <= 1,
        "at most the single declared iseq slot may appear, got {}",
        yarv.ibf.iseqs.len()
    );
    assert!(
        yarv.ibf.iseqs.iter().all(|b| b.instructions.is_empty()),
        "no iseq body may carry decoded instructions from the bogus offset"
    );
}

#[test]
fn yarv_small_value_truncated_at_eof_is_safe() {
    let mut v: Vec<u8> = yarv_header(3, 4, 0, 1, 0, 36, 40);
    v.push(0x02);
    let yarv = analyze_bytes(&v, "evil.yarvc")
        .expect("must not panic on truncated varint")
        .yarv
        .expect("yarv");
    assert_eq!(
        yarv.ibf.recovered_instruction_count, 0,
        "a single truncated byte at the iseq offset decodes no instructions"
    );
    assert!(yarv.ibf.iseqs.iter().all(|b| b.instructions.is_empty()));
}

fn encode_small_value(value: u64) -> Vec<u8> {
    if value < 0x80 {
        return vec![(u8::try_from(value).expect("fits") << 1) | 1];
    }
    let mut width: usize = 2;
    while width < 9 {
        let payload_bits: u32 = u32::try_from((width - 1) * 8 + (8 - width)).expect("bits");
        if payload_bits >= 64 || value < (1u64 << payload_bits) {
            break;
        }
        width += 1;
    }
    let mut out: Vec<u8> = Vec::with_capacity(width);
    let high_bits: u32 = u32::try_from(8 - width).expect("high bits");
    let high: u8 = if high_bits == 0 {
        0
    } else {
        u8::try_from((value >> ((width - 1) * 8)) & ((1u64 << high_bits) - 1)).expect("high")
    };
    let marker: u8 = 1u8 << (width - 1);
    out.push((high << width) | marker);
    for i in (0..width - 1).rev() {
        out.push(u8::try_from((value >> (i * 8)) & 0xff).expect("byte"));
    }
    out
}

#[test]
fn small_value_encoder_matches_reader_expectations() {
    let mut v: Vec<u8> = yarv_header(3, 4, 0, 0, 1, 36, 40);
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&44u32.to_le_bytes());
    v.push(0x05);
    v.extend_from_slice(&encode_small_value(0));
    v.extend_from_slice(&encode_small_value(4));
    v.extend_from_slice(b"data");
    let yarv = analyze_bytes(&v, "x.yarvc")
        .expect("ok")
        .yarv
        .expect("yarv");
    assert_eq!(yarv.ibf.objects[0].literal.as_deref(), Some("data"));
}

#[test]
fn yarv_object_table_aliasing_does_not_amplify_allocation() {
    const ENTRIES: u32 = 2000;
    const STRING_LEN: u64 = 40_000;
    let string_off: u32 = 36 + ENTRIES * 4;
    let mut v: Vec<u8> = yarv_header(3, 4, 0, 0, ENTRIES, 0, 36);
    for _ in 0..ENTRIES {
        v.extend_from_slice(&string_off.to_le_bytes());
    }
    assert_eq!(v.len(), string_off as usize);
    v.push(0x05);
    v.extend_from_slice(&encode_small_value(0));
    v.extend_from_slice(&encode_small_value(STRING_LEN));
    v.resize(v.len() + STRING_LEN as usize, b'A');
    let input_len: usize = v.len();
    let yarv = analyze_bytes(&v, "alias.yarvc")
        .expect("must not OOM on aliased object table")
        .yarv
        .expect("yarv");
    assert_eq!(
        yarv.ibf.objects.len(),
        ENTRIES as usize,
        "every declared object slot is still present"
    );
    let total_literal_bytes: usize = yarv
        .ibf
        .objects
        .iter()
        .filter_map(|o| o.literal.as_deref())
        .map(str::len)
        .sum();
    let unbounded: usize = ENTRIES as usize * STRING_LEN as usize;
    assert!(
        total_literal_bytes < 2_000_000,
        "recovered literal bytes must stay input-bounded, got {total_literal_bytes} from a {input_len}-byte file (unbounded would be {unbounded})"
    );
}

#[test]
fn yarv_random_bytes_with_magic_never_panics() {
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    for _ in 0..256 {
        let mut buf: Vec<u8> = Vec::with_capacity(512);
        buf.extend_from_slice(b"YARB");
        for _ in 0..508 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            buf.push((state & 0xff) as u8);
        }
        let result = std::panic::catch_unwind(|| {
            let _ = analyze_bytes(&buf, "fuzz.yarvc");
        });
        assert!(result.is_ok(), "random YARB-prefixed input must not panic");
    }
}

#[test]
fn empty_and_tiny_inputs_never_panic() {
    assert!(matches!(
        analyze_bytes(&[], "x.rb"),
        Err(RubyError::EmptyInput)
    ));
    for garbage in [
        b"YARB".as_slice(),
        b"RITE".as_slice(),
        b"YARB\x00\x00".as_slice(),
        &[0xFFu8; 3],
    ] {
        let _ = analyze_bytes(garbage, "x");
    }
}
