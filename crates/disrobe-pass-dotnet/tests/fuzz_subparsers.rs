#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_dotnet::{cil, metadata, signature};

struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    const fn next_u64(&mut self) -> u64 {
        let mut x: u64 = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    const fn next_usize(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        (self.next_u64() % bound as u64) as usize
    }

    const fn next_byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }
}

fn exercise(bytes: &[u8]) {
    let _ = signature::parse_method_sig(bytes);
    let _ = signature::parse_field_sig(bytes);
    let _ = signature::parse_local_sig(bytes);
    let _ = signature::parse_type_spec_sig(bytes);
    let _ = cil::parse_method_body(bytes);
    let _ = cil::disassemble(bytes);
    let _ = metadata::decompress_uint(bytes);
}

#[test]
fn pure_random_inputs_never_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0xd07e_7d07_e7d0_7e01);
    for _ in 0..40_000 {
        let len: usize = rng.next_usize(512);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        exercise(&bytes);
    }
}

#[test]
fn nested_generic_signatures_do_not_overflow_stack() {
    for depth in [16usize, 100, 1_000, 100_000] {
        let mut blob: Vec<u8> = vec![0x06];
        for _ in 0..depth {
            blob.push(0x15);
            blob.push(0x12);
        }
        blob.push(0x08);
        let _ = signature::parse_field_sig(&blob);
        let _ = signature::parse_method_sig(&blob);
        let _ = signature::parse_type_spec_sig(&blob);
    }
}
