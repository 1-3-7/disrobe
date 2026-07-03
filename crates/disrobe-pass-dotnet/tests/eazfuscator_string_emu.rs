#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

use disrobe_pass_dotnet::peel::string_emu::{
    RecoveredString, StringDecryptor, find_string_decryptors, recover_emulated_strings,
};

const SECTION_RVA: u32 = 0x2000;
const SECTION_RAW: u32 = 0x400;

struct Stream {
    name: &'static str,
    bytes: Vec<u8>,
}

fn xor_char_array_decrypt_cil(key: u16) -> Vec<u8> {
    let mut code: Vec<u8> = Vec::new();
    code.push(0x16);
    code.push(0x0A);
    let loop_start: i32 = code.len() as i32;
    code.push(0x02);
    code.push(0x06);
    code.push(0x02);
    code.push(0x06);
    code.push(0x93);
    code.push(0x20);
    code.extend_from_slice(&u32::from(key).to_le_bytes());
    code.push(0x61);
    code.push(0x9D);
    code.push(0x06);
    code.push(0x17);
    code.push(0x58);
    code.push(0x0A);
    code.push(0x06);
    code.push(0x02);
    code.push(0x8E);
    let blt_op_pos: i32 = code.len() as i32 + 1;
    let rel: i32 = loop_start - (blt_op_pos + 1);
    code.push(0x32);
    code.push(rel as u8);
    code.push(0x02);
    code.push(0x2A);
    code
}

fn fat_method_body(code: &[u8]) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    let flags_size: u16 = 0x3003;
    body.extend_from_slice(&flags_size.to_le_bytes());
    body.extend_from_slice(&16u16.to_le_bytes());
    body.extend_from_slice(&u32::try_from(code.len()).unwrap().to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(code);
    body
}

fn strings_heap(names: &[&str]) -> (Vec<u8>, Vec<u32>) {
    let mut heap: Vec<u8> = vec![0u8];
    let mut offsets: Vec<u32> = Vec::with_capacity(names.len());
    for n in names {
        offsets.push(u32::try_from(heap.len()).unwrap());
        heap.extend_from_slice(n.as_bytes());
        heap.push(0);
    }
    (heap, offsets)
}

fn us_heap(ciphertexts: &[Vec<u16>]) -> Vec<u8> {
    let mut heap: Vec<u8> = vec![0u8];
    for units in ciphertexts {
        let blob_len: usize = units.len() * 2 + 1;
        push_compressed_uint(&mut heap, u32::try_from(blob_len).unwrap());
        for u in units {
            heap.extend_from_slice(&u.to_le_bytes());
        }
        heap.push(0);
    }
    heap
}

fn blob_heap(method_sig: &[u8]) -> (Vec<u8>, u32) {
    let mut heap: Vec<u8> = vec![0u8];
    let sig_off: u32 = u32::try_from(heap.len()).unwrap();
    push_compressed_uint(&mut heap, u32::try_from(method_sig.len()).unwrap());
    heap.extend_from_slice(method_sig);
    (heap, sig_off)
}

fn push_compressed_uint(out: &mut Vec<u8>, value: u32) {
    if value < 0x80 {
        out.push(value as u8);
    } else if value < 0x4000 {
        out.push((0x80 | (value >> 8)) as u8);
        out.push((value & 0xFF) as u8);
    } else {
        out.push((0xC0 | (value >> 24)) as u8);
        out.push(((value >> 16) & 0xFF) as u8);
        out.push(((value >> 8) & 0xFF) as u8);
        out.push((value & 0xFF) as u8);
    }
}

fn table_stream(
    method_rva: u32,
    method_name_off: u32,
    method_sig_off: u32,
    type_name_off: u32,
    module_name_off: u32,
) -> Vec<u8> {
    let mut s: Vec<u8> = Vec::new();
    s.extend_from_slice(&0u32.to_le_bytes());
    s.push(2);
    s.push(0);
    s.push(0);
    s.push(0);
    let valid: u64 = (1u64 << 0x00) | (1u64 << 0x02) | (1u64 << 0x06);
    s.extend_from_slice(&valid.to_le_bytes());
    s.extend_from_slice(&0u64.to_le_bytes());
    s.extend_from_slice(&1u32.to_le_bytes());
    s.extend_from_slice(&1u32.to_le_bytes());
    s.extend_from_slice(&1u32.to_le_bytes());

    s.extend_from_slice(&0u16.to_le_bytes());
    s.extend_from_slice(&(module_name_off as u16).to_le_bytes());
    s.extend_from_slice(&1u16.to_le_bytes());
    s.extend_from_slice(&0u16.to_le_bytes());
    s.extend_from_slice(&0u16.to_le_bytes());

    s.extend_from_slice(&0x0010_0001u32.to_le_bytes());
    s.extend_from_slice(&(type_name_off as u16).to_le_bytes());
    s.extend_from_slice(&0u16.to_le_bytes());
    s.extend_from_slice(&0u16.to_le_bytes());
    s.extend_from_slice(&1u16.to_le_bytes());
    s.extend_from_slice(&1u16.to_le_bytes());

    s.extend_from_slice(&method_rva.to_le_bytes());
    s.extend_from_slice(&0u16.to_le_bytes());
    s.extend_from_slice(&0x0016u16.to_le_bytes());
    s.extend_from_slice(&(method_name_off as u16).to_le_bytes());
    s.extend_from_slice(&(method_sig_off as u16).to_le_bytes());
    s.extend_from_slice(&1u16.to_le_bytes());
    s
}

fn build_metadata(streams: &[Stream]) -> Vec<u8> {
    let version: &[u8] = b"v4.0.30319\0";
    let version_padded: usize = version.len().div_ceil(4) * 4;
    let mut header_len: usize = 4 + 2 + 2 + 4 + 4 + version_padded + 2 + 2;
    for st in streams {
        header_len += 4 + 4;
        let name_len: usize = st.name.len() + 1;
        header_len += name_len.div_ceil(4) * 4;
    }

    let mut md: Vec<u8> = Vec::new();
    md.extend_from_slice(&0x424A_5342u32.to_le_bytes());
    md.extend_from_slice(&1u16.to_le_bytes());
    md.extend_from_slice(&1u16.to_le_bytes());
    md.extend_from_slice(&0u32.to_le_bytes());
    md.extend_from_slice(&u32::try_from(version_padded).unwrap().to_le_bytes());
    md.extend_from_slice(version);
    md.resize(4 + 2 + 2 + 4 + 4 + version_padded, 0);
    md.extend_from_slice(&0u16.to_le_bytes());
    md.extend_from_slice(&u16::try_from(streams.len()).unwrap().to_le_bytes());

    let mut data_off: usize = header_len;
    let mut data: Vec<u8> = Vec::new();
    for st in streams {
        md.extend_from_slice(&u32::try_from(data_off).unwrap().to_le_bytes());
        md.extend_from_slice(&u32::try_from(st.bytes.len()).unwrap().to_le_bytes());
        let mut name_bytes: Vec<u8> = st.name.as_bytes().to_vec();
        name_bytes.push(0);
        while !name_bytes.len().is_multiple_of(4) {
            name_bytes.push(0);
        }
        md.extend_from_slice(&name_bytes);
        data.extend_from_slice(&st.bytes);
        data_off += st.bytes.len();
    }
    assert_eq!(md.len(), header_len, "metadata header length must be exact");
    md.extend_from_slice(&data);
    md
}

fn build_pe(decryptor_cil: &[u8], encrypted_us: &[Vec<u16>]) -> Vec<u8> {
    let body: Vec<u8> = fat_method_body(decryptor_cil);
    let method_offset_in_section: u32 = 0x100;
    let method_rva: u32 = SECTION_RVA + method_offset_in_section;

    let (strings, offs): (Vec<u8>, Vec<u32>) =
        strings_heap(&["Crypto.Module", "Crypto", "Decrypt"]);
    let module_name_off: u32 = offs[0];
    let type_name_off: u32 = offs[1];
    let method_name_off: u32 = offs[2];

    let method_sig: Vec<u8> = vec![0x00, 0x01, 0x1D, 0x03, 0x1D, 0x03];
    let (blob, sig_off): (Vec<u8>, u32) = blob_heap(&method_sig);
    let us: Vec<u8> = us_heap(encrypted_us);
    let guid: Vec<u8> = vec![0u8; 16];
    let tables: Vec<u8> = table_stream(
        method_rva,
        method_name_off,
        sig_off,
        type_name_off,
        module_name_off,
    );

    let streams: Vec<Stream> = vec![
        Stream {
            name: "#~",
            bytes: tables,
        },
        Stream {
            name: "#Strings",
            bytes: strings,
        },
        Stream {
            name: "#US",
            bytes: us,
        },
        Stream {
            name: "#GUID",
            bytes: guid,
        },
        Stream {
            name: "#Blob",
            bytes: blob,
        },
    ];
    let metadata: Vec<u8> = build_metadata(&streams);

    let metadata_offset_in_section: u32 = 0x200;
    let metadata_rva: u32 = SECTION_RVA + metadata_offset_in_section;

    let clr_offset_in_section: u32 = 0x8;
    let clr_rva: u32 = SECTION_RVA + clr_offset_in_section;

    let mut section: Vec<u8> = vec![0u8; SECTION_RAW as usize];
    let body_start: usize = method_offset_in_section as usize;
    section[body_start..body_start + body.len()].copy_from_slice(&body);
    let md_start: usize = metadata_offset_in_section as usize;
    assert!(
        md_start + metadata.len() <= section.len(),
        "metadata must fit in the section"
    );
    section[md_start..md_start + metadata.len()].copy_from_slice(&metadata);

    let clr_start: usize = clr_offset_in_section as usize;
    let mut clr: Vec<u8> = Vec::new();
    clr.extend_from_slice(&72u32.to_le_bytes());
    clr.extend_from_slice(&2u16.to_le_bytes());
    clr.extend_from_slice(&5u16.to_le_bytes());
    clr.extend_from_slice(&metadata_rva.to_le_bytes());
    clr.extend_from_slice(&u32::try_from(metadata.len()).unwrap().to_le_bytes());
    clr.extend_from_slice(&1u32.to_le_bytes());
    while clr.len() < 72 {
        clr.push(0);
    }
    section[clr_start..clr_start + clr.len()].copy_from_slice(&clr);

    assemble_pe(&section, clr_rva)
}

fn assemble_pe(section: &[u8], clr_rva: u32) -> Vec<u8> {
    let pe_off: usize = 0x80;
    let opt_size: usize = 0xE0;
    let raw_pointer: u32 = 0x200;
    let headers_len: usize = raw_pointer as usize;
    let mut img: Vec<u8> = vec![0u8; headers_len + section.len()];

    img[0] = b'M';
    img[1] = b'Z';
    img[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
    img[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    img[pe_off + 4..pe_off + 6].copy_from_slice(&0x014Cu16.to_le_bytes());
    img[pe_off + 6..pe_off + 8].copy_from_slice(&1u16.to_le_bytes());
    img[pe_off + 20..pe_off + 22].copy_from_slice(&(opt_size as u16).to_le_bytes());
    img[pe_off + 22..pe_off + 24].copy_from_slice(&0x2102u16.to_le_bytes());

    let opt_start: usize = pe_off + 24;
    img[opt_start..opt_start + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    img[opt_start + 16..opt_start + 20].copy_from_slice(&0x2000u32.to_le_bytes());
    img[opt_start + 28..opt_start + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
    img[opt_start + 92..opt_start + 96].copy_from_slice(&16u32.to_le_bytes());
    let directories_start: usize = opt_start + 96;
    let clr_dir_offset: usize = directories_start + 14 * 8;
    img[clr_dir_offset..clr_dir_offset + 4].copy_from_slice(&clr_rva.to_le_bytes());
    img[clr_dir_offset + 4..clr_dir_offset + 8].copy_from_slice(&72u32.to_le_bytes());

    let sections_start: usize = opt_start + opt_size;
    img[sections_start..sections_start + 8].copy_from_slice(b".text\0\0\0");
    img[sections_start + 8..sections_start + 12]
        .copy_from_slice(&(section.len() as u32).to_le_bytes());
    img[sections_start + 12..sections_start + 16].copy_from_slice(&SECTION_RVA.to_le_bytes());
    img[sections_start + 16..sections_start + 20].copy_from_slice(&SECTION_RAW.to_le_bytes());
    img[sections_start + 20..sections_start + 24].copy_from_slice(&raw_pointer.to_le_bytes());
    img[sections_start + 36..sections_start + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    img[headers_len..headers_len + section.len()].copy_from_slice(section);
    img
}

#[test]
fn fixture_pe_exposes_the_char_array_decryptor() {
    let key: u16 = 0x4D7A;
    let cil: Vec<u8> = xor_char_array_decrypt_cil(key);
    let decryptors: Vec<StringDecryptor> = find_string_decryptors(&build_pe(&cil, &[]));
    assert!(
        !decryptors.is_empty(),
        "the hand-built (char[])->char[] static transform must be located as a decryptor"
    );
    assert_eq!(decryptors[0].method_name, "Decrypt");
}

#[test]
fn eazfuscator_recovers_plaintext_by_emulating_in_assembly_decryptor() {
    let key: u16 = 0x4D7A;
    let secrets: &[&str] = &[
        "Server=prod-db;User Id=admin",
        "X-Internal-Token: 7c1f9a",
        "HKLM\\SOFTWARE\\Licensing",
    ];
    let encrypted: Vec<Vec<u16>> = secrets
        .iter()
        .map(|s: &&str| s.encode_utf16().map(|c: u16| c ^ key).collect::<Vec<u16>>())
        .collect();
    let cil: Vec<u8> = xor_char_array_decrypt_cil(key);
    let image: Vec<u8> = build_pe(&cil, &encrypted);

    let plaintext_bytes: &[u8] = b"Server=prod-db";
    assert!(
        image
            .windows(plaintext_bytes.len())
            .all(|w: &[u8]| w != plaintext_bytes),
        "fixture must NOT contain the cleartext anywhere: only ciphertext + the decryptor method"
    );

    let recovered: Vec<RecoveredString> = recover_emulated_strings(
        &image,
        &encrypted
            .iter()
            .map(|u: &Vec<u16>| String::from_utf16_lossy(u))
            .collect::<Vec<String>>(),
    );
    let texts: Vec<String> = recovered
        .iter()
        .map(|r: &RecoveredString| r.text.clone())
        .collect();
    for secret in secrets {
        assert!(
            texts.iter().any(|t: &String| t == secret),
            "expected '{secret}' recovered by emulating the in-assembly decryptor, got {texts:?}"
        );
    }
}

#[test]
fn peel_eazfuscator_surfaces_emulated_recovery_and_flips_strategy() {
    use disrobe_pass_dotnet::peel::{PeelReport, PeelStrategy, peel_eazfuscator};

    let key: u16 = 0x2B19;
    let secret: &str = "ConnectionString=secret-value-42";
    let encrypted: Vec<Vec<u16>> = vec![
        secret
            .encode_utf16()
            .map(|c: u16| c ^ key)
            .collect::<Vec<u16>>(),
    ];
    let cil: Vec<u8> = xor_char_array_decrypt_cil(key);
    let image: Vec<u8> = build_pe(&cil, &encrypted);

    let report: PeelReport = peel_eazfuscator(&image).expect("peel");
    assert_eq!(
        report.strategy,
        PeelStrategy::EncryptedResourceExtracted,
        "successful static string-emulation must flip the strategy off report-only"
    );
    assert!(
        report.recovered_strings.iter().any(|r| r.text == secret),
        "peel report must carry the emulated plaintext; got {:?}",
        report
            .recovered_strings
            .iter()
            .map(|r| r.text.clone())
            .collect::<Vec<String>>()
    );
}

#[test]
fn newly_wired_protectors_recover_plaintext_from_a_pure_cil_string_transform() {
    use disrobe_pass_dotnet::error::Result;
    use disrobe_pass_dotnet::peel::{
        PeelReport, PeelStrategy, peel_babel_net, peel_crypto_obfuscator, peel_deepsea,
        peel_dotfuscator, peel_dotnet_reactor,
    };

    type Peel = fn(&[u8]) -> Result<PeelReport>;

    let key: u16 = 0x6F3C;
    let secret: &str = "license-server=prod.internal:8443";
    let encrypted: Vec<Vec<u16>> = vec![
        secret
            .encode_utf16()
            .map(|c: u16| c ^ key)
            .collect::<Vec<u16>>(),
    ];
    let cil: Vec<u8> = xor_char_array_decrypt_cil(key);
    let image: Vec<u8> = build_pe(&cil, &encrypted);

    let peels: [(&str, Peel); 5] = [
        ("Dotfuscator", peel_dotfuscator),
        ("DeepSea", peel_deepsea),
        ("Babel.NET", peel_babel_net),
        ("CryptoObfuscator", peel_crypto_obfuscator),
        (".NET Reactor", peel_dotnet_reactor),
    ];
    for (label, peel) in peels {
        let report: PeelReport = peel(&image).expect("peel ok on managed PE");
        assert_eq!(
            report.strategy,
            PeelStrategy::EncryptedResourceExtracted,
            "{label}: a pure-CIL string transform must flip the strategy off report-only"
        );
        assert!(
            report.recovered_strings.iter().any(|r| r.text == secret),
            "{label}: must recover the known plaintext by executing the in-assembly decryptor; \
             got {:?}",
            report
                .recovered_strings
                .iter()
                .map(|r| r.text.clone())
                .collect::<Vec<String>>()
        );
    }
}
