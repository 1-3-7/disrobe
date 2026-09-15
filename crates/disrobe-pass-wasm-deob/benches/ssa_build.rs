#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::cast_possible_truncation
)]

use wasmparser::{Parser, Payload};

fn main() {
    divan::main();
}

fn synthetic_module() -> Vec<u8> {
    let body: &[u8] = &[
        0x00, 0x20, 0x00, 0x28, 0x02, 0x00, 0x20, 0x00, 0x28, 0x02, 0x04, 0x6a, 0x20, 0x00, 0x28,
        0x02, 0x08, 0x6a, 0x0b,
    ];
    let mut module: Vec<u8> = Vec::new();
    module.extend_from_slice(&[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
    module.extend_from_slice(&[0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f]);
    module.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    module.extend_from_slice(&[0x05, 0x03, 0x01, 0x00, 0x01]);
    module.push(0x0a);
    module.push((body.len() + 1) as u8);
    module.push(0x01);
    module.extend_from_slice(body);
    module
}

#[divan::bench]
fn cfg_then_ssa(bencher: divan::Bencher) {
    let module: Vec<u8> = synthetic_module();
    bencher.bench_local(|| {
        let parser: Parser = Parser::new(0);
        for payload in parser.parse_all(divan::black_box(&module)) {
            if let Ok(Payload::CodeSectionEntry(body)) = payload
                && let Ok(cfg) = disrobe_pass_wasm_deob::build_function_cfg(&body)
            {
                divan::black_box(cfg);
            }
        }
    });
}

#[divan::bench]
fn detect_only(bencher: divan::Bencher) {
    let module: Vec<u8> = synthetic_module();
    bencher.bench_local(|| {
        let result: disrobe_pass_wasm_deob::Result<disrobe_pass_wasm_deob::WasmDetection> =
            disrobe_pass_wasm_deob::detect(divan::black_box(&module));
        let _ = divan::black_box(result);
    });
}

#[divan::bench]
fn analyze_module(bencher: divan::Bencher) {
    let module: Vec<u8> = synthetic_module();
    bencher.bench_local(|| {
        let summary: disrobe_pass_wasm_deob::Result<disrobe_pass_wasm_deob::ModuleSummary> =
            disrobe_pass_wasm_deob::analyze_module(divan::black_box(&module));
        let _ = divan::black_box(summary);
    });
}
