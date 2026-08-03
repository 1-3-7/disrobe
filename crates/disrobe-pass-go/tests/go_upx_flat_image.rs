#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use object::Object as _;
use object::ObjectSection as _;
use object::read::File as ObjFile;

use disrobe_pass_go::{GoAnalysis, GoFunc, analyze};

fn carve_in_memory_image(pe_bytes: &[u8]) -> Vec<u8> {
    let file: ObjFile<'_, &[u8]> = ObjFile::parse(pe_bytes).expect("parse reference pe");
    let mut min_addr: u64 = u64::MAX;
    let mut max_end: u64 = 0;
    for sec in file.sections() {
        let addr: u64 = sec.address();
        let data: &[u8] = sec.data().unwrap_or(b"");
        if data.is_empty() || addr == 0 {
            continue;
        }
        min_addr = min_addr.min(addr);
        max_end = max_end.max(addr + data.len() as u64);
    }
    assert!(max_end > min_addr, "reference pe has no mapped sections");
    let span: usize = usize::try_from(max_end - min_addr).expect("span fits usize");
    let mut flat: Vec<u8> = vec![0u8; span];
    for sec in file.sections() {
        let addr: u64 = sec.address();
        let data: &[u8] = sec.data().unwrap_or(b"");
        if data.is_empty() || addr < min_addr {
            continue;
        }
        let off: usize = usize::try_from(addr - min_addr).expect("offset fits usize");
        let end: usize = off + data.len();
        if end <= flat.len() {
            flat[off..end].copy_from_slice(data);
        }
    }
    flat
}

#[test]
fn flat_image_is_not_a_recognized_container() {
    let pe: Vec<u8> = common::fixture(common::HELLO_EMBED);
    let flat: Vec<u8> = carve_in_memory_image(&pe);
    assert!(
        object::read::FileKind::parse(flat.as_slice()).is_err(),
        "the carved in-memory image must be headerless (no MZ/PE/ELF), \
         mirroring what the upx unpacker emits; if this parses as a container the \
         flat-image fallback would never be exercised",
    );
}

#[test]
fn recovers_symbols_and_embed_from_headerless_unpacked_image() {
    let pe: Vec<u8> = common::fixture(common::HELLO_EMBED);
    let reference: GoAnalysis = analyze(&pe).expect("analyze reference pe");
    assert!(
        reference.symbols.funcs.len() > 100,
        "reference pe must yield a real function table",
    );

    let flat: Vec<u8> = carve_in_memory_image(&pe);
    let recovered: GoAnalysis = analyze(&flat).expect(
        "the go pass must analyze a headerless upx-unpacked image via the flat-image fallback",
    );

    assert_eq!(
        recovered.symbols.funcs.len(),
        reference.symbols.funcs.len(),
        "flat-image pclntab recovery must match the container build's function count",
    );
    assert_eq!(
        recovered.pclntab_version, reference.pclntab_version,
        "flat-image must classify the same pclntab version",
    );
    assert_eq!(
        recovered.buildversion, reference.buildversion,
        "go build version must survive the headerless path",
    );
    assert!(
        recovered
            .symbols
            .funcs
            .iter()
            .any(|f| f.name == "main.main"),
        "flat-image recovery must include main.main",
    );

    let ref_embed: Vec<&str> = reference
        .embed
        .files
        .iter()
        .filter(|f| !f.is_dir)
        .map(|f| f.name.as_str())
        .collect();
    let got_embed: Vec<&str> = recovered
        .embed
        .files
        .iter()
        .filter(|f| !f.is_dir)
        .map(|f| f.name.as_str())
        .collect();
    assert_eq!(
        got_embed, ref_embed,
        "base inference must let embed.FS member carving resolve absolute-VA data \
         pointers on the headerless image exactly as on the container",
    );

    let note: &disrobe_pass_go::EmbedFile = recovered
        .embed
        .files
        .iter()
        .find(|f| f.name == "assets/note.txt")
        .expect("assets/note.txt must be carved from the flat image");
    assert_eq!(
        note.data, b"disrobe embed fixture payload alpha\n",
        "carved embed bytes from the headerless image must be byte-exact",
    );
}

#[test]
fn flat_386_function_va_matches_go_tool_nm() {
    let pe: Vec<u8> = common::fixture(common::HELLO_386);
    let path: std::path::PathBuf = common::fixture_path(common::HELLO_386);
    let nm: String = common::go_tool_nm_output(&path).expect("go tool nm on 386 fixture");
    let truth: u64 = common::parse_nm_text_symbol_vas(&nm)
        .into_iter()
        .find_map(|(name, va): (String, u64)| (name == "main.main").then_some(va))
        .expect("main.main in go tool nm output");

    let flat: Vec<u8> = carve_in_memory_image(&pe);
    let recovered: GoAnalysis = analyze(&flat).expect("analyze headerless 386 image");
    assert_eq!(recovered.ptr_size, 4);
    let got: u64 = recovered
        .symbols
        .funcs
        .iter()
        .find(|func: &&GoFunc| func.name == "main.main")
        .and_then(|func: &GoFunc| func.va)
        .expect("recovered main.main va");

    assert_eq!(got, truth);
}

fn garble_undo_parity(name: &str) {
    let pe: Vec<u8> = common::fixture(name);
    let reference: GoAnalysis = analyze(&pe).expect("analyze reference garble pe");
    assert_eq!(
        reference.garble.quality,
        disrobe_pass_go::GarbleQuality::Full,
        "{name} reference build must classify as a full garble recovery",
    );
    let ref_thunk: usize = reference.garble.literal_recovery.garble_thunk;
    assert!(
        ref_thunk > 50,
        "{name} reference must recover a real body of -literals thunk plaintexts, got {ref_thunk}",
    );

    let flat: Vec<u8> = carve_in_memory_image(&pe);
    let recovered: GoAnalysis = analyze(&flat).expect("analyze headerless garble image");

    assert_eq!(
        recovered.garble.quality, reference.garble.quality,
        "garble-undo on the headerless unpacked image must reach the same quality tier; \
         the literal decrypt-thunk emulation must run on the sectionless image, not silently \
         drop to Detected because no .text/.rdata section names exist",
    );
    assert_eq!(
        recovered.garble.residual, reference.garble.residual,
        "the residual (the genuine seedless name wall) must be identical on the flat image",
    );

    let got_thunk: usize = recovered.garble.literal_recovery.garble_thunk;
    assert!(
        got_thunk * 100 >= ref_thunk * 95,
        "flat-image -literals recovery must stay within 5% of the container build: \
         reference={ref_thunk} flat={got_thunk}",
    );

    let ref_strings: std::collections::BTreeSet<&String> =
        reference.garble.recovered_strings.iter().collect();
    let flat_strings: std::collections::BTreeSet<&String> =
        recovered.garble.recovered_strings.iter().collect();
    let shared: usize = ref_strings.intersection(&flat_strings).count();
    assert!(
        shared * 100 >= ref_strings.len() * 95,
        "the decrypted/recovered string set on the flat image must overlap the container set \
         by at least 95%: shared={shared} reference={}",
        ref_strings.len(),
    );

    assert_eq!(
        recovered.garble.name_recovery.user_hashed_erased,
        reference.garble.name_recovery.user_hashed_erased,
        "the keyed-hash user-name wall must be measured identically on the flat image",
    );
    assert_eq!(
        recovered.garble.name_recovery.stdlib_recovered,
        reference.garble.name_recovery.stdlib_recovered,
        "stdlib name structure recovery must be identical on the flat image",
    );
}

#[test]
fn garble_undo_reaches_parity_on_headerless_image() {
    garble_undo_parity(common::HELLO_GARBLE);
}

#[test]
fn garble_literals_undo_reaches_parity_on_headerless_image() {
    garble_undo_parity(common::GARBLE_LITERALS_INDIRECT);
}

#[test]
fn flat_fallback_rejects_unrelated_binary_blob() {
    let blob: Vec<u8> = vec![0x42u8; 4096];
    assert!(
        analyze(&blob).is_err(),
        "a non-go headerless blob with no pclntab and no runtime markers must not \
         be coerced into a flat go image",
    );
}
