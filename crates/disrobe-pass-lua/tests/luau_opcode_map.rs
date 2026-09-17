#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_lua::reader::luau::{
    OpcodeMap, OpcodeMapImport, import_opcode_map, read_with_opcode_map,
};

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
fn imports_exact_pairs_without_completing_the_permutation() {
    let canonical: Vec<u8> = paired_chunk(&[0x0102_0300, 0x0405_0602]);
    let client: Vec<u8> = paired_chunk(&[0x0102_030A, 0x0405_0614]);

    let imported: OpcodeMapImport =
        import_opcode_map("client-2026-08-24", &canonical, &client).expect("exact paired map");

    assert_eq!(imported.map.build_id(), "client-2026-08-24");
    assert_eq!(imported.map.bytecode_version(), 5);
    assert_eq!(imported.map.canonical_opcode(10), Some(0));
    assert_eq!(imported.map.canonical_opcode(20), Some(2));
    assert_eq!(imported.map.canonical_opcode(3), None);
    assert_eq!(imported.mapped, 2);
    assert_eq!(imported.observed, 2);
    let expected: [(u8, u8); 2] = [(10, 0), (20, 2)];
    let wrong: usize = expected
        .iter()
        .filter(|(client_opcode, canonical_opcode)| {
            imported.map.canonical_opcode(*client_opcode) != Some(*canonical_opcode)
        })
        .count();
    assert_eq!(wrong, 0, "wrong/checked must be 0/{}", expected.len());

    let temporary: tempfile::NamedTempFile = tempfile::NamedTempFile::new().expect("map file");
    imported.map.save(temporary.path()).expect("persist map");
    let reloaded: OpcodeMap =
        OpcodeMap::load(temporary.path(), "client-2026-08-24", 5).expect("reload exact map");
    let recovered =
        read_with_opcode_map(&client, &reloaded, "client-2026-08-24").expect("apply exact map");
    assert_eq!(recovered.main.code, vec![0x0102_0300, 0x0405_0602]);
}

#[test]
fn rejects_auxiliary_words_that_do_not_match() {
    let canonical: Vec<u8> = paired_chunk(&[0x0102_0307, 0xAABB_CCDD]);
    let client: Vec<u8> = paired_chunk(&[0x0102_030A, 0x1122_3344]);

    let error = import_opcode_map("client-2026-08-24", &canonical, &client)
        .expect_err("different auxiliary payload must refuse the pair");

    assert!(
        error.to_string().contains("auxiliary word differs"),
        "unexpected error: {error}"
    );
}

#[test]
fn refuses_stale_build_and_unmapped_instruction() {
    let canonical: Vec<u8> = paired_chunk(&[0x0102_0300, 0x0405_0602]);
    let client: Vec<u8> = paired_chunk(&[0x0102_030A, 0x0405_0614]);
    let imported: OpcodeMapImport =
        import_opcode_map("client-2026-08-24", &canonical, &client).expect("exact paired map");
    let stale = read_with_opcode_map(&client, &imported.map, "client-other")
        .expect_err("different build must not select the map");
    assert!(stale.to_string().contains("build or bytecode version"));
    let unmapped_client: Vec<u8> = paired_chunk(&[0x0102_030A, 0x0405_0615]);
    let unmapped = read_with_opcode_map(&unmapped_client, &imported.map, "client-2026-08-24")
        .expect_err("unmapped instruction must refuse application");
    assert!(unmapped.to_string().contains("0:1=0x15"));
}

#[test]
fn rejects_conflicts_and_optimization_mismatch() {
    let duplicate_canonical = paired_chunk(&[0x0102_0300, 0x0405_0600]);
    let changed_client = paired_chunk(&[0x0102_030A, 0x0405_0614]);
    assert!(
        import_opcode_map("client", &duplicate_canonical, &changed_client)
            .expect_err("one canonical opcode cannot have two client bytes")
            .to_string()
            .contains("maps to both")
    );

    let duplicate_client = paired_chunk(&[0x0102_0300, 0x0405_0602]);
    let same_client = paired_chunk(&[0x0102_030A, 0x0405_060A]);
    assert!(
        import_opcode_map("client", &duplicate_client, &same_client)
            .expect_err("one client byte cannot have two canonical opcodes")
            .to_string()
            .contains("maps to both")
    );

    let optimization_mismatch = paired_chunk(&[0x0102_040A, 0x0405_0614]);
    assert!(
        import_opcode_map("client", &duplicate_client, &optimization_mismatch)
            .expect_err("non-opcode bits must match")
            .to_string()
            .contains("non-opcode bits differ")
    );
}

#[test]
fn rejects_truncated_and_unsupported_pairs() {
    assert!(
        import_opcode_map("client", &[5], &[5])
            .expect_err("truncated chunks must fail")
            .to_string()
            .contains("truncated")
    );
    assert!(
        import_opcode_map("client", &[12], &[12])
            .expect_err("unsupported versions must fail")
            .to_string()
            .contains("unsupported Luau bytecode version")
    );
}

#[test]
fn rejects_code_population_beyond_the_reader_capacity() {
    let excessive: [u8; 14] = [5, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0x7F];
    let error = import_opcode_map("client", &excessive, &excessive)
        .expect_err("code population must be bounded before allocation");
    assert!(error.to_string().contains("luau code count"));
}

#[test]
fn rejects_opcode_before_its_declared_bytecode_version() {
    let v5: Vec<u8> = paired_chunk(&[83]);
    let error = import_opcode_map("client", &v5, &v5)
        .expect_err("userdata opcode requires bytecode version 9");
    assert!(
        error
            .to_string()
            .contains("not supported for exact alignment")
    );
}

#[test]
fn reports_distinct_mapping_population_for_repeated_opcodes() {
    let canonical: Vec<u8> = paired_chunk(&[0, 0]);
    let client: Vec<u8> = paired_chunk(&[10, 10]);
    let imported = import_opcode_map("client", &canonical, &client).expect("repeated exact pair");
    assert_eq!((imported.mapped, imported.observed), (1, 1));
}

#[test]
fn rejects_opcode_88_for_import_and_persisted_v11_map() {
    let mut canonical: Vec<u8> = paired_chunk(&[87, 0]);
    let mut client: Vec<u8> = paired_chunk(&[10, 0]);
    canonical[0] = 11;
    client[0] = 11;
    canonical.insert(canonical.len() - 1, 0);
    client.insert(client.len() - 1, 0);
    let imported = import_opcode_map("client", &canonical, &client).expect("v11 CALLFB map");
    let temporary = tempfile::NamedTempFile::new().expect("map file");
    imported.map.save(temporary.path()).expect("persist map");
    let encoded = std::fs::read_to_string(temporary.path()).expect("read map");
    std::fs::write(temporary.path(), encoded.replace("87", "88")).expect("alter map");
    assert!(OpcodeMap::load(temporary.path(), "client", 11).is_err());
    let mut unsupported: Vec<u8> = canonical.clone();
    let code_offset: usize = 11;
    unsupported[code_offset] = 88;
    assert!(import_opcode_map("client", &unsupported, &client).is_err());
}
