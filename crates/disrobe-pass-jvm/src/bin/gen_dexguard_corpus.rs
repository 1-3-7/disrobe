#![deny(unreachable_pub)]
#![allow(clippy::print_stdout, clippy::expect_used)]

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use disrobe_pass_jvm::dex_builder::dexguard_reflect_sample;
use sha2::{Digest, Sha256};

const KEY: u8 = 0x66;

const PLAINTEXTS: [&str; 6] = [
    "https://api.example.com/v1/auth",
    "X-Api-Key",
    "decryptToken",
    "SELECT * FROM secrets WHERE id = ?",
    "AES/CBC/PKCS5Padding",
    "com.disrobe.sample.Secret",
];

fn main() {
    let dir: PathBuf = corpus_dir();
    fs::create_dir_all(&dir).expect("create corpus dir");

    let dex: Vec<u8> = dexguard_reflect_sample(&PLAINTEXTS, KEY);
    let dex_path: PathBuf = dir.join("DexGuardReflectStrings.dex");
    fs::write(&dex_path, &dex).expect("write dex");

    let java_path: PathBuf = dir.join("DexGuardReflectStrings.java");
    fs::write(&java_path, render_java()).expect("write java");

    let mut hasher: Sha256 = Sha256::new();
    hasher.update(&dex);
    let digest: String = to_hex(&hasher.finalize());

    let manifest_path: PathBuf = dir.join("MANIFEST.toml");
    fs::write(&manifest_path, render_manifest(dex.len(), &digest)).expect("write manifest");

    println!("wrote {} ({} bytes)", dex_path.display(), dex.len());
    println!("wrote {}", java_path.display());
    println!("wrote {}", manifest_path.display());
    println!("dex sha256 {digest}");
}

fn corpus_dir() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("jvm");
    p.push("dexguard");
    p
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out: String = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn render_java() -> String {
    let mut enc: String = String::new();
    for plain in PLAINTEXTS {
        let mut cipher: String = String::new();
        for c in plain.chars() {
            let v: u32 = (c as u32) ^ u32::from(KEY);
            let _ = write!(cipher, "\\u{v:04x}");
        }
        let _ = writeln!(enc, "        \"{cipher}\",");
    }

    let mut plain_doc: String = String::new();
    for (i, plain) in PLAINTEXTS.iter().enumerate() {
        let _ = writeln!(plain_doc, "        PLAINTEXT[{i}] = {plain:?}");
    }

    format!(
        "package com.disrobe.sample;\n\
\n\
import java.lang.reflect.Method;\n\
\n\
public final class DexGuardReflectStrings {{\n\
    private static final String[] ENC = new String[] {{\n\
{enc}    }};\n\
\n\
    private static final int KEY = 0x{KEY:02x};\n\
\n\
    public static String decrypt(int idx) {{\n\
        char[] src = ENC[idx].toCharArray();\n\
        char[] out = new char[src.length];\n\
        for (int i = 0; i < src.length; i++) {{\n\
            out[i] = (char) (src[i] ^ KEY);\n\
        }}\n\
        return String.valueOf(out);\n\
    }}\n\
\n\
    private static String fetch(int idx) {{\n\
        try {{\n\
            Method m = DexGuardReflectStrings.class.getDeclaredMethod(\"decrypt\", int.class);\n\
            return (String) m.invoke(null, Integer.valueOf(idx));\n\
        }} catch (Exception e) {{\n\
            return \"\";\n\
        }}\n\
    }}\n\
\n\
    public static void main(String[] args) {{\n\
        for (int i = 0; i < ENC.length; i++) {{\n\
            System.out.println(fetch(i));\n\
        }}\n\
    }}\n\
}}\n\
\n\
/*\n\
    Ground-truth plaintext (the decrypt routine maps ENC[i] ^ KEY back to these):\n\
{plain_doc}*/\n"
    )
}

fn render_manifest(byte_len: usize, sha256: &str) -> String {
    let mut plaintext_lines: String = String::new();
    for (i, plain) in PLAINTEXTS.iter().enumerate() {
        let _ = writeln!(
            plaintext_lines,
            "  {{ index = {i}, plaintext = {plain:?} }},"
        );
    }
    format!(
        "schema_version = 1\n\
crate = \"disrobe-pass-jvm\"\n\
sample = \"DexGuardReflectStrings\"\n\
technique = \"reflection-invoked static string decryption (DexGuard behavior)\"\n\
license = \"in-house benign sample, authored for disrobe\"\n\
\n\
[build]\n\
source = \"DexGuardReflectStrings.java\"\n\
dex = \"DexGuardReflectStrings.dex\"\n\
dex_bytes = {byte_len}\n\
dex_sha256 = \"{sha256}\"\n\
key = \"0x{KEY:02x}\"\n\
command = \"cargo run -p disrobe-pass-jvm --bin gen_dexguard_corpus\"\n\
assembler = \"disrobe-pass-jvm in-tree dex_builder (dex 035), not commercial DexGuard\"\n\
note = \"\"\"\n\
Commercial DexGuard is paid Guardsquare software whose protected output is unsafe to \n\
produce on a non-sandboxed box, so this is a self-authored benign sample that exhibits the \n\
same technique: an encrypted String[] held in a static field, a decrypt(int) routine that \n\
XORs each char against an embedded key, and call sites that fetch strings through \n\
java.lang.reflect.Method.invoke rather than a direct call. The .class/.dex toolchain (javac \n\
+ d8) is not installed on this box and agents do not install or download tooling, so the dex \n\
is assembled byte-for-byte by the project's own dex_builder and parses cleanly through the \n\
project's own dex reader (adler32 + sha-1 verified). disrobe statically evaluates the \n\
decrypt routine over the table and recovers the plaintext below; recovery is graded against \n\
this authored plaintext list, not against disrobe's own output.\n\
\"\"\"\n\
\n\
plaintext = [\n\
{plaintext_lines}]\n"
    )
}
