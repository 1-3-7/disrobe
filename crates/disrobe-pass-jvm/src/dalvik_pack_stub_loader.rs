use crate::dalvik_pack_recover::{
    LocatedPayload, PackingScheme, PackingSchemeKind, RecoveryOutcome, VerificationSignals,
    verify_recovered_dex,
};
use crate::dex;
use crate::jar::JarEntry;

pub const CONTAINER_MAGIC: [u8; 4] = *b"RTPK";
pub const CONTAINER_FORMAT_VERSION: u32 = 1;
pub const CONTAINER_HEADER_LEN: usize = 28;
pub const MAX_RECOVERABLE_PAYLOAD_LEN: usize = 64 * 1024 * 1024;

const STUB_LOADER_SUPERCLASS: &str = "Landroid/app/Application;";
const STUB_LOADER_MAX_CLASSES: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContainerHeader {
    key_len: u32,
    payload_len: u32,
    keystream_seed: u32,
    payload_checksum: u32,
}

fn parse_container_header(bytes: &[u8]) -> Option<ContainerHeader> {
    if bytes.len() < CONTAINER_HEADER_LEN || bytes[..4] != CONTAINER_MAGIC {
        return None;
    }
    let read_u32 = |offset: usize| -> u32 {
        u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    };
    let format_version: u32 = read_u32(4);
    if format_version != CONTAINER_FORMAT_VERSION {
        return None;
    }
    let key_len: u32 = read_u32(8);
    let payload_len: u32 = read_u32(12);
    let keystream_seed: u32 = read_u32(16);
    let header_checksum: u32 = read_u32(20);
    let payload_checksum: u32 = read_u32(24);
    if crate::dex_builder::adler32(1, &bytes[0..20]) != header_checksum {
        return None;
    }
    Some(ContainerHeader {
        key_len,
        payload_len,
        keystream_seed,
        payload_checksum,
    })
}

#[must_use]
pub fn encode_container(payload: &[u8], key: &[u8], keystream_seed: u32) -> Vec<u8> {
    let ciphertext: Vec<u8> = apply_keystream_cipher(payload, keystream_seed, key);
    let payload_checksum: u32 = crate::dex_builder::adler32(1, &ciphertext);
    let key_len: u32 = u32::try_from(key.len()).unwrap_or(u32::MAX);
    let payload_len: u32 = u32::try_from(ciphertext.len()).unwrap_or(u32::MAX);
    let mut out: Vec<u8> = Vec::with_capacity(CONTAINER_HEADER_LEN + key.len() + ciphertext.len());
    out.extend_from_slice(&CONTAINER_MAGIC);
    out.extend_from_slice(&CONTAINER_FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&key_len.to_le_bytes());
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(&keystream_seed.to_le_bytes());
    let header_checksum: u32 = crate::dex_builder::adler32(1, &out[0..20]);
    out.extend_from_slice(&header_checksum.to_le_bytes());
    out.extend_from_slice(&payload_checksum.to_le_bytes());
    out.extend_from_slice(key);
    out.extend_from_slice(&ciphertext);
    out
}

fn keystream_byte(seed: u32, key: &[u8], index: usize) -> u8 {
    let salted: u32 = seed ^ (index as u32).wrapping_mul(0x9E37_79B9) ^ 0xA5A5_A5A5;
    let mut x: u32 = salted;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    let prng_byte: u8 = (x & 0xFF) as u8;
    prng_byte ^ key[index % key.len().max(1)]
}

fn apply_keystream_cipher(data: &[u8], seed: u32, key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, &byte): (usize, &u8)| byte ^ keystream_byte(seed, key, i))
        .collect()
}

fn find_stub_loader_dex(entries: &[JarEntry]) -> Option<&JarEntry> {
    entries.iter().find(|entry: &&JarEntry| {
        let leaf: &str = entry.path.rsplit('/').next().unwrap_or(entry.path.as_str());
        leaf.starts_with("classes") && leaf.ends_with(".dex")
    })
}

fn find_container_entry(entries: &[JarEntry]) -> Option<&JarEntry> {
    entries.iter().find(|entry: &&JarEntry| {
        entry.bytes.len() >= CONTAINER_HEADER_LEN && entry.bytes[..4] == CONTAINER_MAGIC
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StubLoaderKeystreamScheme;

impl PackingScheme for StubLoaderKeystreamScheme {
    fn kind(&self) -> PackingSchemeKind {
        PackingSchemeKind::StubLoaderKeystream
    }

    fn fingerprint(&self, entries: &[JarEntry]) -> u8 {
        let Some(stub_entry): Option<&JarEntry> = find_stub_loader_dex(entries) else {
            return 0;
        };
        let Ok(stub_dex): Result<dex::DexFile, _> = dex::parse(&stub_entry.bytes) else {
            return 0;
        };
        let mut score: u32 = 0;
        if stub_dex.header.class_defs_size > 0
            && stub_dex.header.class_defs_size <= STUB_LOADER_MAX_CLASSES
        {
            score += 30;
        }
        let has_application_subclass: bool = stub_dex
            .class_super_descriptors
            .values()
            .any(|super_name: &String| super_name == STUB_LOADER_SUPERCLASS);
        if has_application_subclass {
            score += 40;
        }
        if find_container_entry(entries).is_some() {
            score += 30;
        }
        u8::try_from(score.min(100)).unwrap_or(100)
    }

    fn locate(&self, entries: &[JarEntry]) -> Option<LocatedPayload> {
        let container_entry: &JarEntry = find_container_entry(entries)?;
        let header: ContainerHeader = parse_container_header(&container_entry.bytes)?;
        if header.key_len == 0 {
            return None;
        }
        let key_start: usize = CONTAINER_HEADER_LEN;
        let key_end: usize = key_start.checked_add(header.key_len as usize)?;
        let payload_end: usize = key_end.checked_add(header.payload_len as usize)?;
        if payload_end != container_entry.bytes.len() {
            return None;
        }
        let key: Vec<u8> = container_entry.bytes[key_start..key_end].to_vec();
        let ciphertext: Vec<u8> = container_entry.bytes[key_end..payload_end].to_vec();
        if crate::dex_builder::adler32(1, &ciphertext) != header.payload_checksum {
            return None;
        }
        Some(LocatedPayload {
            container_path: container_entry.path.clone(),
            key,
            ciphertext,
            keystream_seed: header.keystream_seed,
        })
    }

    fn recover(&self, located: &LocatedPayload) -> RecoveryOutcome {
        if located.key.is_empty() {
            return RecoveryOutcome::Indeterminate(
                "located container carries an empty key; recovery was not attempted".to_owned(),
            );
        }
        if located.ciphertext.len() > MAX_RECOVERABLE_PAYLOAD_LEN {
            return RecoveryOutcome::Indeterminate(format!(
                "declared payload length {} exceeds the bounded recovery cap of {} bytes; \
                 recovery was not attempted",
                located.ciphertext.len(),
                MAX_RECOVERABLE_PAYLOAD_LEN
            ));
        }
        let plaintext: Vec<u8> =
            apply_keystream_cipher(&located.ciphertext, located.keystream_seed, &located.key);
        let verification: VerificationSignals = verify_recovered_dex(&plaintext);
        if verification.all_required_signals_pass() {
            RecoveryOutcome::Recovered {
                dex_bytes: plaintext,
                verification,
            }
        } else {
            RecoveryOutcome::Rejected(format!(
                "decrypted payload failed verification signals: {}",
                verification.failing_signal_names().join(", ")
            ))
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::dalvik_pack_recover::recover_packed_dex;
    use crate::dex_builder::{ClassDef, DexBuilder, EncodedMethod, MethodRef, ProtoRef};

    fn tiny_stub_loader_dex() -> Vec<u8> {
        let mut builder: DexBuilder = DexBuilder::new();
        builder.add_class(ClassDef {
            class: "Lcom/example/pack/StubApp;".to_owned(),
            super_class: STUB_LOADER_SUPERCLASS.to_owned(),
            access_flags: 0x11,
            static_fields: Vec::new(),
            static_values: Vec::new(),
            direct_methods: vec![EncodedMethod {
                tries: Vec::new(),
                method: MethodRef {
                    class: "Lcom/example/pack/StubApp;".to_owned(),
                    proto: ProtoRef {
                        return_type: "V".to_owned(),
                        params: Vec::new(),
                    },
                    name: "<init>".to_owned(),
                },
                access_flags: 0x1,
                is_direct: true,
                registers_size: 1,
                ins_size: 1,
                outs_size: 1,
                insns: vec![0x000e],
                relocations: Vec::new(),
            }],
            virtual_methods: Vec::new(),
        });
        builder.build()
    }

    fn wrap_into_apk_zip(stub_dex: &[u8], container: &[u8]) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        let cursor: std::io::Cursor<&mut Vec<u8>> = std::io::Cursor::new(&mut buf);
        let mut writer: zip::ZipWriter<std::io::Cursor<&mut Vec<u8>>> = zip::ZipWriter::new(cursor);
        let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
        writer
            .start_file("classes.dex", options)
            .expect("start classes.dex");
        std::io::Write::write_all(&mut writer, stub_dex).expect("write classes.dex");
        writer
            .start_file("assets/payload.bin", options)
            .expect("start payload asset");
        std::io::Write::write_all(&mut writer, container).expect("write payload asset");
        let _ = writer.finish().expect("finish zip");
        buf
    }

    #[test]
    fn container_round_trips_through_keystream_cipher() {
        let payload: &[u8] = b"dex\n035\0small payload body used for a unit-level round trip";
        let key: Vec<u8> = vec![0x11, 0x9C, 0x4D, 0x02, 0xF7];
        let container: Vec<u8> = encode_container(payload, &key, 0xC0FF_EE11);
        let header: ContainerHeader = parse_container_header(&container).expect("header parses");
        assert_eq!(header.key_len as usize, key.len());
        let key_start: usize = CONTAINER_HEADER_LEN;
        let key_end: usize = key_start + key.len();
        let ciphertext: &[u8] = &container[key_end..];
        let recovered: Vec<u8> = apply_keystream_cipher(ciphertext, header.keystream_seed, &key);
        assert_eq!(recovered, payload);
    }

    #[test]
    fn tampered_container_checksum_fails_locate() {
        let payload: &[u8] = b"anything";
        let key: Vec<u8> = vec![0x42];
        let mut container: Vec<u8> = encode_container(payload, &key, 7);
        let last: usize = container.len() - 1;
        container[last] ^= 0xFF;
        assert!(
            parse_container_header(&container).is_none() || {
                let header: ContainerHeader = parse_container_header(&container).unwrap();
                crate::dex_builder::adler32(1, &container[CONTAINER_HEADER_LEN + key.len()..])
                    != header.payload_checksum
            }
        );
    }

    #[test]
    fn fingerprint_scores_zero_without_any_dex_entry() {
        let scheme: StubLoaderKeystreamScheme = StubLoaderKeystreamScheme;
        let entries: Vec<JarEntry> = vec![JarEntry {
            path: "assets/data.txt".to_owned(),
            bytes: b"irrelevant".to_vec(),
        }];
        assert_eq!(scheme.fingerprint(&entries), 0);
    }

    #[test]
    fn end_to_end_wrapped_package_recovers_and_verifies_against_the_real_payload() {
        let real_payload: Vec<u8> =
            std::fs::read(real_dex_fixture_path()).expect("read real corpus dex");
        let original: dex::DexFile = dex::parse(&real_payload).expect("original parses");

        let stub_dex: Vec<u8> = tiny_stub_loader_dex();
        let key: Vec<u8> = vec![0x9F, 0x02, 0x77, 0xC3, 0x18, 0x5A];
        let container: Vec<u8> = encode_container(&real_payload, &key, 0x1357_9BDF);
        let apk_bytes: Vec<u8> = wrap_into_apk_zip(&stub_dex, &container);

        let report: crate::dalvik_pack_recover::PackageRecoveryReport =
            recover_packed_dex(&apk_bytes);
        assert_eq!(
            report.selected,
            Some(PackingSchemeKind::StubLoaderKeystream)
        );
        let outcome: RecoveryOutcome = report.outcome.expect("outcome present");
        let RecoveryOutcome::Recovered {
            dex_bytes,
            verification,
        } = outcome
        else {
            panic!("expected a recovered outcome");
        };
        assert!(verification.all_required_signals_pass());

        let recovered: dex::DexFile = dex::parse(&dex_bytes).expect("recovered dex parses");
        let mut original_classes: Vec<String> = original.class_descriptors.clone();
        let mut recovered_classes: Vec<String> = recovered.class_descriptors.clone();
        original_classes.sort();
        recovered_classes.sort();
        assert_eq!(original_classes, recovered_classes);

        let method_key = |m: &dex::MethodId| -> String {
            format!(
                "{}->{}({:?}){}",
                m.class, m.name, m.proto.parameters, m.proto.return_type
            )
        };
        let mut original_methods: Vec<String> =
            original.method_ids.iter().map(method_key).collect();
        let mut recovered_methods: Vec<String> =
            recovered.method_ids.iter().map(method_key).collect();
        original_methods.sort();
        recovered_methods.sort();
        assert_eq!(original_methods, recovered_methods);
        assert!(!original_classes.is_empty());
    }

    fn real_dex_fixture_path() -> std::path::PathBuf {
        let mut p: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.pop();
        p.push("corpus");
        p.push("jvm");
        p.push("dex");
        p.push("EdgeCases.dex");
        p
    }
}
