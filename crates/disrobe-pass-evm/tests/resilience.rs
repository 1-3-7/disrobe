#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use disrobe_pass_evm::{
    EvmError, InputFormat, Layout, Limits, Options, analyze, decode_input, decompile, disassemble,
};

struct Rng(u64);

impl Rng {
    const fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound.max(1) as u64) as usize
    }
}

fn seeds() -> Vec<Vec<u8>> {
    let root: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/evm/solc");
    [
        "0.8.37-o0/Erc20.hex",
        "0.8.37-ir-o1/Nft.hex",
        "0.6.12-o1/Legacy.hex",
        "0.4.26-o0/Legacy.hex",
        "0.8.19-o1/Proxy.hex",
    ]
    .iter()
    .map(|file: &&str| {
        let text: Vec<u8> = std::fs::read(root.join(file))
            .unwrap_or_else(|e| panic!("seed {file} is missing: {e}"));
        decode_input(&text, InputFormat::Hex, &Limits::default())
            .unwrap()
            .bytes
    })
    .collect()
}

fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut code: Vec<u8> = seed.to_vec();
    for _ in 0..=rng.below(8) {
        match rng.below(6) {
            0 => {
                let at: usize = rng.below(code.len());
                code[at] = rng.next() as u8;
            }
            1 => {
                let at: usize = rng.below(code.len());
                code.truncate(at.max(1));
            }
            2 => {
                let at: usize = rng.below(code.len());
                let len: usize = rng.below(64);
                let insert: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                code.splice(at..at, insert);
            }
            3 => {
                let at: usize = rng.below(code.len());
                code[at] = 0x5b;
            }
            4 => {
                let at: usize = rng.below(code.len());
                code[at] = 0x60 + rng.below(32) as u8;
            }
            _ => {
                let at: usize = rng.below(code.len());
                let end: usize = (at + rng.below(256)).min(code.len());
                code.drain(at..end);
            }
        }
        if code.is_empty() {
            code.push(0x00);
        }
    }
    code
}

fn exercise(code: &[u8]) {
    let options: Options = Options::default();
    let analysed: Result<_, EvmError> = analyze(code, &options);
    if let Ok(report) = &analysed {
        assert!(report.functions.len() <= options.limits.max_functions);
        let json: String = serde_json::to_string(report).unwrap();
        assert!(!json.is_empty());
    }
    let listing = disassemble(code, &options);
    if let Ok(listing) = &listing {
        let instructions: usize = listing.sections.iter().map(|s| s.instructions.len()).sum();
        assert!(instructions <= code.len());
    }
    let source = decompile(code, &options);
    if let Ok(source) = &source {
        assert!(source.len() < 8 * 1024 * 1024);
    }
    let forced = analyze(
        code,
        &Options {
            layout: Layout::Creation,
            ..options
        },
    );
    assert!(
        forced.is_ok()
            || matches!(
                forced,
                Err(EvmError::NoRuntimeImage | EvmError::EofContainer { .. })
            )
    );
}

#[test]
fn hundreds_of_corrupted_contracts_give_a_report_or_a_typed_error() {
    let seeds: Vec<Vec<u8>> = seeds();
    let mut rng: Rng = Rng(0x9e37_79b9_7f4a_7c15);
    for round in 0..400 {
        let seed: &[u8] = &seeds[round % seeds.len()];
        let code: Vec<u8> = mutate(&mut rng, seed);
        exercise(&code);
    }
}

#[test]
fn adversarial_shapes_stay_bounded() {
    let mut shapes: Vec<Vec<u8>> = vec![
        vec![0x5b; 50_000],
        [0x5b, 0x60, 0x00, 0x56].to_vec(),
        std::iter::repeat_n(0x5f, 2000).collect(),
        std::iter::repeat_n(0x50, 64).collect(),
        [0x7f].to_vec(),
        [0x60, 0x04, 0x56, 0x00].to_vec(),
        [0x36, 0x56].to_vec(),
        [0xfe].to_vec(),
        (0..=255u8).collect(),
    ];
    let mut fork_bomb: Vec<u8> = Vec::new();
    for _ in 0..200 {
        let next: u16 = (fork_bomb.len() + 6) as u16;
        fork_bomb.extend([0x36, 0x61]);
        fork_bomb.extend(next.to_be_bytes());
        fork_bomb.extend([0x57, 0x5b]);
    }
    fork_bomb.push(0x00);
    shapes.push(fork_bomb);
    let mut deep_calls: Vec<u8> = Vec::new();
    for _ in 0..1100 {
        deep_calls.extend([0x60, 0x00, 0x35]);
    }
    shapes.push(deep_calls);
    let mut dispatcher: Vec<u8> = vec![0x60, 0x00, 0x35, 0x60, 0xe0, 0x1c];
    for selector in 0..3000u32 {
        let target: u16 = 0;
        dispatcher.extend([0x80, 0x63]);
        dispatcher.extend(selector.to_be_bytes());
        dispatcher.extend([0x14, 0x61]);
        dispatcher.extend(target.to_be_bytes());
        dispatcher.push(0x57);
    }
    shapes.push(dispatcher);
    for shape in &shapes {
        exercise(shape);
    }
    for text in [
        b"0x".as_slice(),
        b"0x0".as_slice(),
        b"  \n".as_slice(),
        b"0xzz".as_slice(),
        b"6080 6040\n52".as_slice(),
        "0x60\u{00e9}".as_bytes(),
    ] {
        let decoded = decode_input(text, InputFormat::Auto, &Limits::default());
        if let Ok(decoded) = decoded {
            exercise(&decoded.bytes);
        }
    }
    let oversized: Vec<u8> = vec![0x00; Limits::default().max_code_bytes + 1];
    assert!(matches!(
        decode_input(&oversized, InputFormat::Raw, &Limits::default()),
        Err(EvmError::TooLarge { .. })
    ));
    assert!(matches!(
        analyze(&oversized, &Options::default()),
        Err(EvmError::TooLarge { .. })
    ));
}
