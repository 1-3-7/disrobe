#![no_main]

use core::hint::black_box;

use libfuzzer_sys::fuzz_target;

use disrobe_fuzz::over_input_budget;
use disrobe_ir::payload::{DisasmPayload, RawPayload, decode_disasm, decode_raw};
use disrobe_ir::{Envelope, HEADER_SIZE, Sidecar};

fn decoded_envelope_re_encodes_to_itself(data: &[u8]) {
    let Ok(envelope): disrobe_ir::Result<Envelope> = Envelope::decode(data) else {
        return;
    };
    let Ok(header): disrobe_ir::Result<[u8; HEADER_SIZE]> = envelope.header_bytes() else {
        return;
    };
    let _ = black_box(header);
    let Ok(encoded): disrobe_ir::Result<Vec<u8>> = envelope.encode() else {
        return;
    };
    let Ok(again): disrobe_ir::Result<Envelope> = Envelope::decode(&encoded) else {
        panic!("an envelope this decoder produced does not decode again");
    };
    assert_eq!(
        again.root_hash, envelope.root_hash,
        "re-encoding an envelope changed its root hash"
    );
}

fn drive_payload_decoders(data: &[u8]) {
    if let Ok(raw) = decode_raw(data) {
        let payload: RawPayload = raw;
        let _ = black_box(&payload);
    }
    if let Ok(disasm) = decode_disasm(data) {
        let payload: DisasmPayload = disasm;
        let _ = black_box(&payload);
    }
}

fn drive_sidecar(data: &[u8]) {
    let Ok(sidecar): disrobe_ir::Result<Sidecar> = Sidecar::decode(data) else {
        return;
    };
    let _ = black_box(sidecar.encode());
}

fuzz_target!(|data: &[u8]| {
    if over_input_budget(data) {
        return;
    }
    decoded_envelope_re_encodes_to_itself(data);
    drive_payload_decoders(data);
    drive_sidecar(data);
});
