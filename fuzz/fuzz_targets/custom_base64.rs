#![no_main]

use std::collections::BTreeMap;

use disrobe_core::codec::{
    CustomBase64Alphabet, CustomBase64GroupPolicy, CustomBase64Input, decode_custom_base64,
    decode_with_custom_b64,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 64 * 1_024;

fn alphabet_byte(entropy: &[u8], index: usize) -> u8 {
    if entropy.is_empty() {
        return index as u8;
    }
    entropy[index % entropy.len()]
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let split: usize = data.len().min(64);
    let raw_alphabet: &[u8] = &data[..split];
    let input: &[u8] = if data.len() > 64 { &data[64..] } else { data };
    let mut raw_symbols: [u8; 64] = [0; 64];
    for (index, symbol) in raw_symbols.iter_mut().enumerate() {
        *symbol = alphabet_byte(raw_alphabet, index);
    }
    let legacy_decoded: Option<Vec<u8>> = decode_with_custom_b64(input, &raw_symbols);
    assert!(
        legacy_decoded
            .as_deref()
            .is_none_or(|decoded: &[u8]| decoded.len() <= input.len())
    );
    let _: Option<CustomBase64Alphabet<'static>> =
        CustomBase64Alphabet::from_byte_symbols(&raw_symbols);
    let raw_pairs: Vec<(u8, u8)> = raw_alphabet
        .chunks_exact(2)
        .map(|pair: &[u8]| (pair[0], pair[1]))
        .collect();
    let _: Option<CustomBase64Alphabet<'static>> =
        CustomBase64Alphabet::from_byte_pairs(&raw_pairs);

    let mut byte_symbols: [u8; 64] =
        *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for index in (1..byte_symbols.len()).rev() {
        byte_symbols.swap(
            index,
            usize::from(alphabet_byte(raw_alphabet, index)) % (index + 1),
        );
    }
    let Some(alphabet): Option<CustomBase64Alphabet<'static>> =
        CustomBase64Alphabet::from_byte_symbols(&byte_symbols)
    else {
        return;
    };
    for policy in [
        CustomBase64GroupPolicy::KeepPartial,
        CustomBase64GroupPolicy::DropPartial,
    ] {
        if let Some(decoded) =
            decode_custom_base64(CustomBase64Input::Bytes(input), &alphabet, policy)
        {
            assert!(decoded.len() <= input.len());
        }
    }
    let partial_length: usize = usize::from(alphabet_byte(raw_alphabet, 0)) % 64 + 1;
    let partial_pairs: Vec<(u8, u8)> = byte_symbols
        .iter()
        .copied()
        .take(partial_length)
        .enumerate()
        .map(|(value, symbol): (usize, u8)| (symbol, value as u8))
        .collect();
    let Some(partial_alphabet): Option<CustomBase64Alphabet<'static>> =
        CustomBase64Alphabet::from_byte_pairs(&partial_pairs)
    else {
        return;
    };
    for policy in [
        CustomBase64GroupPolicy::KeepPartial,
        CustomBase64GroupPolicy::DropPartial,
    ] {
        if let Some(decoded) =
            decode_custom_base64(CustomBase64Input::Bytes(input), &partial_alphabet, policy)
        {
            assert!(decoded.len() <= input.len());
        }
    }

    let mut character_map: BTreeMap<char, u8> = BTreeMap::new();
    for (value, bytes) in raw_alphabet.chunks_exact(4).enumerate() {
        let scalar: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if let Some(character) = char::from_u32(scalar) {
            character_map.insert(character, value as u8);
        }
    }
    if let Some(alphabet) = CustomBase64Alphabet::from_character_map(&character_map)
        && let Ok(text) = std::str::from_utf8(input)
    {
        for policy in [
            CustomBase64GroupPolicy::KeepPartial,
            CustomBase64GroupPolicy::DropPartial,
        ] {
            let _: Option<Vec<u8>> =
                decode_custom_base64(CustomBase64Input::Text(text), &alphabet, policy);
        }
    }

    let mut character_symbols: Vec<char> = (0..64u32)
        .filter_map(|offset: u32| char::from_u32(0x1f300 + offset))
        .collect();
    for index in (1..character_symbols.len()).rev() {
        character_symbols.swap(
            index,
            usize::from(alphabet_byte(raw_alphabet, index)) % (index + 1),
        );
    }
    let Some(alphabet): Option<CustomBase64Alphabet<'static>> =
        CustomBase64Alphabet::from_char_symbols(&character_symbols)
    else {
        return;
    };
    let text: String = input
        .iter()
        .copied()
        .map(|byte: u8| match usize::from(byte) % 68 {
            index @ 0..64 => character_symbols[index],
            64 => '=',
            65 => '\n',
            66 => '\r',
            _ => ' ',
        })
        .collect();
    for policy in [
        CustomBase64GroupPolicy::KeepPartial,
        CustomBase64GroupPolicy::DropPartial,
    ] {
        if let Some(decoded) =
            decode_custom_base64(CustomBase64Input::Text(&text), &alphabet, policy)
        {
            assert!(decoded.len() <= input.len());
        }
    }
});
