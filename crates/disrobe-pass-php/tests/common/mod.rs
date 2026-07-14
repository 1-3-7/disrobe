#![allow(dead_code, unreachable_pub)]
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STD;
use flate2::Compression;
use flate2::write::DeflateEncoder;
use std::io::Write as _;
use std::path::PathBuf;

pub const TINY_HELLO_PHP: &[u8] = b"<?php\necho 'hello world';\n";

pub fn corpus_php_root() -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut root: PathBuf = manifest;
    root.pop();
    root.pop();
    root.push("corpus");
    root.push("php");
    root
}

pub fn load_php_fixture(rel: &str) -> Option<Vec<u8>> {
    std::fs::read(corpus_php_root().join(rel)).ok()
}

pub fn b64(bytes: &[u8]) -> String {
    B64_STD.encode(bytes)
}

pub fn deflate(bytes: &[u8]) -> Vec<u8> {
    let mut enc: DeflateEncoder<Vec<u8>> = DeflateEncoder::new(Vec::new(), Compression::default());
    enc.write_all(bytes).expect("deflate write");
    enc.finish().expect("deflate finish")
}

pub fn rot13_bytes(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .copied()
        .map(|b: u8| match b {
            b'A'..=b'M' | b'a'..=b'm' => b + 13,
            b'N'..=b'Z' | b'n'..=b'z' => b - 13,
            other => other,
        })
        .collect()
}

pub fn build_split_literal_b64_chain(payload: &str) -> Vec<u8> {
    let encoded: String = b64(payload.as_bytes());
    let mid: usize = encoded.len() / 2;
    let (head, tail): (&str, &str) = encoded.split_at(mid);
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"<?php ev");
    out.extend_from_slice(b"al(base64_decode('");
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(b"'.'");
    out.extend_from_slice(tail.as_bytes());
    out.extend_from_slice(b"'));");
    out
}

pub fn build_b64_wrapping_strrev_chain(payload: &str) -> Vec<u8> {
    let encoded: String = b64(payload.as_bytes());
    let reversed: String = encoded.chars().rev().collect();
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"<?php ev");
    out.extend_from_slice(b"al(base64_decode(strrev('");
    out.extend_from_slice(reversed.as_bytes());
    out.extend_from_slice(b"')));");
    out
}

pub fn build_rot13_interposed_chain(payload: &str) -> Vec<u8> {
    let deflated: Vec<u8> = deflate(payload.as_bytes());
    let rotated: Vec<u8> = rot13_bytes(&deflated);
    let encoded: String = b64(&rotated);
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"<?php ev");
    out.extend_from_slice(b"al(gzinflate(str_rot13(base64_decode('");
    out.extend_from_slice(encoded.as_bytes());
    out.extend_from_slice(b"'))));");
    out
}

pub fn build_eval_chain(payload: &str) -> Vec<u8> {
    let deflated: Vec<u8> = deflate(payload.as_bytes());
    let encoded: String = b64(&deflated);
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"<?php ev");
    out.extend_from_slice(b"al(gzinflate(base64_decode('");
    out.extend_from_slice(encoded.as_bytes());
    out.extend_from_slice(b"')));");
    out
}

pub fn build_b64_only_eval(payload: &str) -> Vec<u8> {
    let encoded: String = b64(payload.as_bytes());
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"<?php ev");
    out.extend_from_slice(b"al(base64_decode('");
    out.extend_from_slice(encoded.as_bytes());
    out.extend_from_slice(b"'));");
    out
}

pub fn build_fopo(payload: &str) -> Vec<u8> {
    let encoded: String = b64(payload.as_bytes());
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(
        b"<?php /* FOPO :: Free Online PHP Obfuscator v1.0 by FOPO */\n$O0O0O0='",
    );
    out.extend_from_slice(encoded.as_bytes());
    out.extend_from_slice(b"';ev");
    out.extend_from_slice(b"al(base64_decode($O0O0O0));");
    out
}

pub fn build_better_php_obf(payload: &str) -> Vec<u8> {
    let deflated: Vec<u8> = deflate(payload.as_bytes());
    let encoded: String = b64(&deflated);
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(
        b"<?php /* Better PHP Obfuscator v2 - by anonymous */ $x = base64_decode('",
    );
    out.extend_from_slice(encoded.as_bytes());
    out.extend_from_slice(b"'); $y = gzinflate($x); ev");
    out.extend_from_slice(b"al($y);");
    out
}

pub fn build_str_rot13(payload: &str) -> Vec<u8> {
    let rotated: String = payload
        .as_bytes()
        .iter()
        .copied()
        .map(|b: u8| match b {
            b'A'..=b'M' | b'a'..=b'm' => b + 13,
            b'N'..=b'Z' | b'n'..=b'z' => b - 13,
            other => other,
        })
        .map(|b: u8| b as char)
        .collect();
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"<?php ev");
    out.extend_from_slice(b"al(str_rot13('");
    out.extend_from_slice(rotated.as_bytes());
    out.extend_from_slice(b"'));");
    out
}

pub fn build_str_rot13_b64(payload: &str) -> Vec<u8> {
    let encoded: String = b64(payload.as_bytes());
    let rotated: String = rot13_bytes(encoded.as_bytes())
        .into_iter()
        .map(|b: u8| b as char)
        .collect();
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"<?php ev");
    out.extend_from_slice(b"al(base64_decode(str_rot13('");
    out.extend_from_slice(rotated.as_bytes());
    out.extend_from_slice(b"')));");
    out
}

fn xor_repeating(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b): (usize, &u8)| b ^ key[i % key.len()])
        .collect()
}

fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut state: [u8; 256] = [0u8; 256];
    for (i, slot) in state.iter_mut().enumerate() {
        *slot = i as u8;
    }
    let mut j: usize = 0;
    for i in 0..256usize {
        j = (j + state[i] as usize + key[i % key.len()] as usize) % 256;
        state.swap(i, j);
    }
    let mut a: usize = 0;
    let mut b: usize = 0;
    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    for &c in data {
        a = (a + 1) % 256;
        b = (b + state[a] as usize) % 256;
        state.swap(a, b);
        let stream: u8 = state[(state[a] as usize + state[b] as usize) % 256];
        out.push(c ^ stream);
    }
    out
}

pub fn build_loop_xor_chain(payload: &str) -> Vec<u8> {
    let key: &[u8] = b"K3yStr34m_9F";
    let cipher: Vec<u8> = xor_repeating(payload.as_bytes(), key);
    let encoded: String = b64(&cipher);
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"<?php $d = base64_decode('");
    out.extend_from_slice(encoded.as_bytes());
    out.extend_from_slice(b"'); $k = '");
    out.extend_from_slice(key);
    out.extend_from_slice(
        b"'; $o = ''; for($i=0;$i<strlen($d);$i++){ $o .= $d[$i] ^ $k[$i % strlen($k)]; } ev",
    );
    out.extend_from_slice(b"al($o);");
    out
}

pub fn build_rc4_static_key_chain(payload: &str) -> Vec<u8> {
    let key: &[u8] = b"staticrc4key_9F3A";
    let cipher: Vec<u8> = rc4(key, payload.as_bytes());
    let encoded: String = b64(&cipher);
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"<?php $d = base64_decode('");
    out.extend_from_slice(encoded.as_bytes());
    out.extend_from_slice(b"'); $k = '");
    out.extend_from_slice(key);
    out.extend_from_slice(b"'; $s = array(); for($i=0;$i<256;$i++){ $s[$i]=$i; } $j=0; for($i=0;$i<256;$i++){ $j=($j+$s[$i]+ord($k[$i%strlen($k)]))%256; $t=$s[$i];$s[$i]=$s[$j];$s[$j]=$t; } $i=0;$j=0;$o=''; for($y=0;$y<strlen($d);$y++){ $i=($i+1)%256; $j=($j+$s[$i])%256; $t=$s[$i];$s[$i]=$s[$j];$s[$j]=$t; $o .= $d[$y] ^ chr($s[($s[$i]+$s[$j])%256]); } ev");
    out.extend_from_slice(b"al($o);");
    out
}

pub fn build_dot_append_b64_chain(payload: &str) -> Vec<u8> {
    let encoded: String = b64(payload.as_bytes());
    append_chunks_chain(encoded.as_bytes(), b"base64_decode($p)")
}

pub fn build_dot_append_gzinflate_chain(payload: &str) -> Vec<u8> {
    let deflated: Vec<u8> = deflate(payload.as_bytes());
    let encoded: String = b64(&deflated);
    append_chunks_chain(encoded.as_bytes(), b"gzinflate(base64_decode($p))")
}

fn append_chunks_chain(encoded: &[u8], decode_expr: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"<?php $p = '';\n");
    for chunk in encoded.chunks(6) {
        out.extend_from_slice(b"$p .= '");
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"';\n");
    }
    out.extend_from_slice(b"ev");
    out.extend_from_slice(b"al(");
    out.extend_from_slice(decode_expr);
    out.extend_from_slice(b");");
    out
}

pub fn build_array_indexed_dispatch(payload: &str) -> Vec<u8> {
    let deflated: Vec<u8> = deflate(payload.as_bytes());
    let encoded: String = b64(&deflated);
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"<?php $f = array('base64_decode','gzinflate'); ev");
    out.extend_from_slice(b"al($f[1]($f[0]('");
    out.extend_from_slice(encoded.as_bytes());
    out.extend_from_slice(b"')));");
    out
}

pub const B64_STD_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
pub const B64_ROT_ALPHABET: &[u8] =
    b"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm0123456789+/";

fn strtr_translate(subject: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let n: usize = from.len().min(to.len());
    let mut map: [Option<u8>; 256] = [None; 256];
    for i in 0..n {
        map[from[i] as usize] = Some(to[i]);
    }
    subject
        .iter()
        .map(|b: &u8| map[*b as usize].unwrap_or(*b))
        .collect()
}

pub fn build_strtr_custom_alphabet_chain(payload: &str) -> Vec<u8> {
    let encoded: Vec<u8> = b64(payload.as_bytes()).into_bytes();
    let scrambled: Vec<u8> = strtr_translate(&encoded, B64_STD_ALPHABET, B64_ROT_ALPHABET);
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"<?php ev");
    out.extend_from_slice(b"al(base64_decode(strtr('");
    out.extend_from_slice(&scrambled);
    out.extend_from_slice(b"', '");
    out.extend_from_slice(B64_ROT_ALPHABET);
    out.extend_from_slice(b"', '");
    out.extend_from_slice(B64_STD_ALPHABET);
    out.extend_from_slice(b"')));");
    out
}

pub fn build_str_replace(payload: &str, from: &str, to: &str) -> Vec<u8> {
    let with_marker: String = payload.replace(to, from);
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"<?php ev");
    out.extend_from_slice(b"al(str_replace('");
    out.extend_from_slice(from.as_bytes());
    out.extend_from_slice(b"','");
    out.extend_from_slice(to.as_bytes());
    out.extend_from_slice(b"','");
    out.extend_from_slice(with_marker.as_bytes());
    out.extend_from_slice(b"'));");
    out
}

pub fn build_tiny_phar(stub_php: &[u8], files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(stub_php);
    out.extend_from_slice(b"\n");

    let mut manifest_body: Vec<u8> = Vec::new();
    manifest_body.extend_from_slice(
        &u32::try_from(files.len())
            .expect("file count")
            .to_le_bytes(),
    );
    manifest_body.extend_from_slice(&0x0011u16.to_be_bytes());
    manifest_body.extend_from_slice(&0u32.to_le_bytes());
    let alias: &[u8] = b"test.phar";
    manifest_body.extend_from_slice(&u32::try_from(alias.len()).expect("alias len").to_le_bytes());
    manifest_body.extend_from_slice(alias);
    manifest_body.extend_from_slice(&0u32.to_le_bytes());

    let mut payload_section: Vec<u8> = Vec::new();
    for (name, body) in files {
        let name_bytes: &[u8] = name.as_bytes();
        manifest_body.extend_from_slice(
            &u32::try_from(name_bytes.len())
                .expect("name len")
                .to_le_bytes(),
        );
        manifest_body.extend_from_slice(name_bytes);
        manifest_body.extend_from_slice(
            &u32::try_from(body.len())
                .expect("uncompressed")
                .to_le_bytes(),
        );
        manifest_body.extend_from_slice(&0u32.to_le_bytes());
        manifest_body.extend_from_slice(&u32::try_from(body.len()).expect("stored").to_le_bytes());
        manifest_body.extend_from_slice(&crc32(body).to_le_bytes());
        manifest_body.extend_from_slice(&0u32.to_le_bytes());
        manifest_body.extend_from_slice(&0u32.to_le_bytes());
        payload_section.extend_from_slice(body);
    }

    out.extend_from_slice(
        &u32::try_from(manifest_body.len())
            .expect("manifest len")
            .to_le_bytes(),
    );
    out.extend_from_slice(&manifest_body);
    out.extend_from_slice(&payload_section);
    out.extend_from_slice(b"GBMB");
    out
}

pub fn default_phar_stub() -> Vec<u8> {
    b"<?php __HALT_COMPILER(); ?>".to_vec()
}

pub fn build_tiny_bcg() -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"BCG\x00");
    out.push(8);
    out.push(0);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out
}

pub fn build_ioncube_v9_min() -> Vec<u8> {
    let mut out: Vec<u8> = b"<?php //004F".to_vec();
    out.extend(std::iter::repeat_n(b'A', 96));
    out
}

pub fn build_sourceguardian_min() -> Vec<u8> {
    let mut out: Vec<u8> = b"// PHP SourceGuardian Loader v12.0.0\n".to_vec();
    out.extend(std::iter::repeat_n(b'B', 128));
    out
}

pub const ZEND_GUARD_MIN_KEY: [u8; 8] = *b"Zk3yZk3y";
pub const ZEND_GUARD_MIN_PLAINTEXT: &[u8] = b"ZEND-OP-ARRAY:disrobe-static-xor-recovered-marker";

pub fn build_zend_guard_min() -> Vec<u8> {
    let xored: Vec<u8> = ZEND_GUARD_MIN_PLAINTEXT
        .iter()
        .enumerate()
        .map(|(i, b): (usize, &u8)| b ^ ZEND_GUARD_MIN_KEY[i % ZEND_GUARD_MIN_KEY.len()])
        .collect();
    let mut out: Vec<u8> = b"<?php @Zend;\n3".to_vec();
    out.push(0x00);
    out.extend_from_slice(&ZEND_GUARD_MIN_KEY);
    out.extend_from_slice(&xored);
    out
}

pub fn build_blackbird() -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"<?php $_GLOBALS[\"black");
    out.extend_from_slice(b"bird\"] = 1; black");
    out.extend_from_slice(b"bird_loader('x');");
    out
}

pub fn build_smuggler() -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"<?php /*SMG-BEGIN*/ smug");
    out.extend_from_slice(b"gler::decode(SMG_PAYLOAD_X);");
    out
}

pub fn build_webshell() -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"<?php @ev");
    out.extend_from_slice(b"al($_PO");
    out.extend_from_slice(b"ST['cmd']); shell_");
    out.extend_from_slice(b"exec($_REQ");
    out.extend_from_slice(b"UEST['x']);");
    out
}

pub fn build_named_shell_samples() -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"<?php /* r57");
    out.extend_from_slice(b"shell c99");
    out.extend_from_slice(b"shell File");
    out.extend_from_slice(b"sMan b37");
    out.extend_from_slice(b"4k */");
    out
}

pub fn build_php_encoder_online() -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(
        b"<?php // PHP Encoder online\n$_=\"\\x65\\x76\\x61\\x6c\";$_('return 1;');",
    );
    out
}

pub fn build_obfuscation_info() -> Vec<u8> {
    b"<?php //OI-WRAP-START\necho 'oi-served';\n//OI-WRAP-END\n".to_vec()
}

fn crc32(bytes: &[u8]) -> u32 {
    const TABLE: [u32; 16] = build_table();
    let mut crc: u32 = 0xffff_ffff;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..2 {
            crc = (crc >> 4) ^ TABLE[(crc & 0xf) as usize];
        }
    }
    !crc
}

const fn build_table() -> [u32; 16] {
    let mut table: [u32; 16] = [0u32; 16];
    let mut i: usize = 0;
    while i < 16 {
        let mut c: u32 = i as u32;
        let mut j: u32 = 0;
        while j < 4 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            j += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}
