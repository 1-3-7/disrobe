#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout
)]

use disrobe_pass_pyinstaller::{
    EntryType, ExtractOutput, ExtractedEntry, PyzEntry, extract_archive, extract_pyz_with_key,
};
use disrobe_py_marshal::{Object, PyVersion, load};

const PACKED: &[u8] =
    include_bytes!("../../../corpus/python/freezers/pyinstaller/encrypted/hello_enc.bin");

const ORIGINAL_SOURCE: &str =
    include_str!("../../../corpus/python/freezers/pyinstaller/encrypted/hello_enc.py");

const KNOWN_KEY: &[u8; 16] = b"MySecretKey12345";
const PY312_MAGIC_LE: [u8; 4] = [0xCB, 0x0D, 0x0D, 0x0A];
const PY312_PYC_HEADER_LEN: usize = 16;
const ENCRYPTED_PYZ_MODULES: [&str; 2] = ["base64", "bisect"];
const SOURCE_IDENTIFIERS: [&str; 3] = ["GREETING_PREFIX", "MAGIC_CONSTANT", "greet"];

fn slice_contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}

fn body_is_code(body: &[u8]) -> bool {
    matches!(load(body, PyVersion::new(3, 12)), Ok(Object::Code(_)))
}

#[test]
fn recovers_aes_key_from_marshalled_crypto_key_object() {
    let output: ExtractOutput =
        extract_archive(PACKED).expect("the encrypted CArchive must extract");
    assert_eq!(
        output.encryption_key.as_ref(),
        Some(KNOWN_KEY),
        "the 16-byte AES key must be recovered from co_consts[0] of the marshalled \
         pyimod00_crypto_key code object, not via a fragile quoted-literal scan",
    );
}

#[test]
fn decrypts_every_encrypted_pyz_module_to_a_code_object() {
    let output: ExtractOutput = extract_archive(PACKED).expect("extract encrypted archive");
    let key: [u8; 16] = output.encryption_key.expect("keyed archive yields a key");

    let pyz: &ExtractedEntry = output
        .entries
        .iter()
        .find(|e: &&ExtractedEntry| e.toc.entry_type == EntryType::Pyz)
        .expect("the embedded PYZ entry must survive extraction");

    let (version, entries): (PyVersion, Vec<PyzEntry>) =
        extract_pyz_with_key(&pyz.data, &key).expect("the encrypted PYZ must decrypt and parse");
    assert_eq!(version, PyVersion::PY312, "recovered interpreter version");
    assert!(
        !entries.is_empty(),
        "the AES-CTR-encrypted PYZ must yield its modules once the key is applied",
    );

    for wanted in ENCRYPTED_PYZ_MODULES {
        let module: &PyzEntry = entries
            .iter()
            .find(|e: &&PyzEntry| e.name == wanted)
            .unwrap_or_else(|| panic!("encrypted PYZ module '{wanted}' must be carved"));
        assert!(
            body_is_code(&module.bytes),
            "decrypted module '{wanted}' must marshal-load to a code object, proving real \
             AES-CTR plaintext was recovered (not raw ciphertext)",
        );
    }

    let loadable: usize = entries
        .iter()
        .filter(|e: &&PyzEntry| body_is_code(&e.bytes))
        .count();
    let pct: f64 = 100.0 * loadable as f64 / entries.len() as f64;
    println!(
        "encrypted gauntlet: {}/{} decrypted PYZ modules = {pct:.2}% marshal-load to code objects",
        loadable,
        entries.len(),
    );
    assert_eq!(
        loadable,
        entries.len(),
        "every encrypted PYZ module must decrypt to loadable bytecode; got {pct:.2}%",
    );
}

#[test]
fn inlines_decrypted_pyz_modules_as_recoverable_pyc_entries() {
    let output: ExtractOutput = extract_archive(PACKED).expect("extract encrypted archive");
    assert!(
        output.pyz_module_count >= ENCRYPTED_PYZ_MODULES.len(),
        "extract_archive must inline the decrypted PYZ modules; got {}",
        output.pyz_module_count,
    );

    let inlined: Vec<&ExtractedEntry> = output
        .entries
        .iter()
        .filter(|e: &&ExtractedEntry| {
            matches!(
                e.toc.entry_type,
                EntryType::PyzModule | EntryType::PyzPackage
            )
        })
        .collect();
    assert_eq!(inlined.len(), output.pyz_module_count);

    let base64_pyc: &ExtractedEntry = inlined
        .iter()
        .copied()
        .find(|e: &&ExtractedEntry| e.toc.name == "PYZ-00.pyz_extracted/base64.pyc")
        .expect("the decrypted base64 module must be inlined as a .pyc");
    assert_eq!(
        &base64_pyc.data[..4],
        &PY312_MAGIC_LE,
        "an inlined decrypted PYZ module must carry a reconstructed 3.12 pyc header",
    );
    assert!(
        body_is_code(&base64_pyc.data[PY312_PYC_HEADER_LEN..]),
        "the reconstructed base64.pyc body must marshal-load to a code object",
    );
}

#[test]
fn carves_unencrypted_application_script_alongside_encrypted_pyz() {
    let output: ExtractOutput = extract_archive(PACKED).expect("extract encrypted archive");
    let script: &ExtractedEntry = output
        .entries
        .iter()
        .find(|e: &&ExtractedEntry| {
            e.toc.entry_type == EntryType::Script && e.toc.name == "hello_enc"
        })
        .expect("the application script entry must survive extraction");
    assert_eq!(
        &script.data[..4],
        &PY312_MAGIC_LE,
        "the script pyc must carry the 3.12 magic",
    );
    let body: &[u8] = &script.data[PY312_PYC_HEADER_LEN..];
    for ident in SOURCE_IDENTIFIERS {
        assert!(
            ORIGINAL_SOURCE.contains(ident),
            "guard: identifier '{ident}' must exist in the clean original source",
        );
        assert!(
            slice_contains(body, ident.as_bytes()),
            "identifier '{ident}' must survive into the carved script marshal",
        );
    }
}
