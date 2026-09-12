#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{Run, run_disrobe, temp_dir, write_bytes};

fn paired_chunk(code: &[u32]) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![5, 1, 0, 1, 0, 0, 0, 0, 0, 0];
    bytes.push(u8::try_from(code.len()).expect("fixture code length"));
    for word in code {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0]);
    bytes
}

#[test]
fn lua_opcode_map_round_trips_through_the_public_cli() {
    let scratch = temp_dir("luau-opcode-map");
    let canonical = scratch.path().join("canonical.luau");
    let client = scratch.path().join("client.luau");
    let map = scratch.path().join("client-map.json");
    let canonical_output = scratch.path().join("canonical.lua");
    let output_one = scratch.path().join("recovered-one.lua");
    let output_four = scratch.path().join("recovered-four.lua");
    write_bytes(&canonical, &paired_chunk(&[0x0102_0300, 0x0405_0602]));
    write_bytes(&client, &paired_chunk(&[0x0102_030A, 0x0405_0614]));
    let imported: Run = run_disrobe(&[
        "lua",
        "opcode-map",
        "--canonical",
        canonical.to_str().unwrap(),
        "--client",
        client.to_str().unwrap(),
        "--build-id",
        "client-2026-08-24",
        "--out",
        map.to_str().unwrap(),
    ]);
    assert_eq!(imported.code, 0, "{}", imported.stderr);
    assert!(imported.stdout.contains("mapped/observed: 2/2"));
    assert!(map.exists());
    let canonical_decompiled: Run = run_disrobe(&[
        "--threads",
        "1",
        "lua",
        "decompile",
        canonical.to_str().unwrap(),
        "--out",
        canonical_output.to_str().unwrap(),
    ]);
    assert_eq!(
        canonical_decompiled.code, 0,
        "{}",
        canonical_decompiled.stderr
    );
    let decompiled: Run = run_disrobe(&[
        "--threads",
        "1",
        "lua",
        "decompile",
        client.to_str().unwrap(),
        "--opcode-map",
        map.to_str().unwrap(),
        "--build-id",
        "client-2026-08-24",
        "--out",
        output_one.to_str().unwrap(),
    ]);
    assert_eq!(decompiled.code, 0, "{}", decompiled.stderr);
    let four_workers: Run = run_disrobe(&[
        "--threads",
        "4",
        "lua",
        "decompile",
        client.to_str().unwrap(),
        "--opcode-map",
        map.to_str().unwrap(),
        "--build-id",
        "client-2026-08-24",
        "--out",
        output_four.to_str().unwrap(),
    ]);
    assert_eq!(four_workers.code, 0, "{}", four_workers.stderr);
    assert_eq!(
        std::fs::read(&canonical_output).unwrap(),
        std::fs::read(&output_one).unwrap()
    );
    assert_eq!(
        std::fs::read(&output_one).unwrap(),
        std::fs::read(&output_four).unwrap()
    );
}
