use super::*;

#[test]
fn ror13_is_deterministic_and_nonzero_for_known_apis() {
    for name in ["LoadLibraryA", "GetProcAddress", "VirtualAlloc"] {
        let hash: u32 = HashFamily::Ror13Add.hash(name.as_bytes(), false);
        assert_ne!(hash, 0, "ror13 of {name} must be nonzero");
        assert_eq!(
            hash,
            HashFamily::Ror13Add.hash(name.as_bytes(), false),
            "hash must be deterministic"
        );
    }
}

#[test]
fn every_family_resolves_its_own_corpus_round_trip() {
    for family in HashFamily::all().iter().copied() {
        let probe: &str = "GetProcAddress";
        let hash: u32 = family.hash(probe.as_bytes(), false);
        let resolved: Option<(String, String)> = resolve_hash(hash, family);
        assert!(
            resolved.is_some(),
            "{} hash of {probe} (0x{hash:08x}) must reverse-resolve",
            family.label()
        );
        let (dll, name): (String, String) = resolved.unwrap();
        assert_eq!(name, probe);
        assert_eq!(dll, "kernel32.dll");
    }
}

#[test]
fn case_insensitive_matches_lowercase_input() {
    let upper: u32 = HashFamily::Djb2.hash(b"LoadLibraryA", true);
    let lower: u32 = HashFamily::Djb2.hash(b"loadlibrarya", false);
    assert_eq!(
        upper, lower,
        "case-insensitive uppercase folding must equal lowercased input"
    );
}

#[test]
fn unknown_hash_is_honest_miss() {
    let bogus: u32 = 0xDEAD_BEEF;
    assert!(
        resolve_hash_any_family(bogus).is_none(),
        "a hash with no preimage in the corpus must report no resolution, not a fabricated name"
    );
}

#[test]
fn harvests_and_resolves_a_compare_against_known_hash() {
    use iced_x86::code_asm::{CodeAssembler, eax};

    let base: u64 = 0x40_1000;
    let target_hash: u32 = HashFamily::Ror13Add.hash(b"LoadLibraryA", false);
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.cmp(eax, i32::from_le_bytes(target_hash.to_le_bytes()))
        .unwrap();
    asm.je(base + 0x40).unwrap();
    asm.ret().unwrap();
    let code: Vec<u8> = asm.assemble(base).expect("assemble resolver tail");

    let hits: Vec<ApiHashHit> = resolve_imports_by_hash(64, base, &code);
    assert!(
        hits.iter().any(|h: &ApiHashHit| {
            h.resolved_name.as_deref() == Some("LoadLibraryA")
                && h.family == HashFamily::Ror13Add
                && h.hash == target_hash
        }),
        "a cmp eax, ror13(LoadLibraryA) must be harvested and resolved back to the API name: {hits:?}"
    );
}

#[test]
fn annotation_renders_resolved_and_unresolved_cleanly() {
    let resolved: ApiHashHit = ApiHashHit {
        call_site: 0x1000,
        hash: 0x1234_5678,
        family: HashFamily::Ror13Add,
        resolved_name: Some("LoadLibraryA".to_owned()),
        dll: Some("kernel32.dll".to_owned()),
    };
    assert_eq!(
        resolved.annotation(),
        "api: kernel32.dll!LoadLibraryA (ror13-add=0x12345678)"
    );
    let missed: ApiHashHit = ApiHashHit {
        call_site: 0x2000,
        hash: 0xABCD_0000,
        family: HashFamily::Crc32,
        resolved_name: None,
        dll: None,
    };
    assert_eq!(
        missed.annotation(),
        "unresolved hash 0xabcd0000 (family crc32)"
    );
}
