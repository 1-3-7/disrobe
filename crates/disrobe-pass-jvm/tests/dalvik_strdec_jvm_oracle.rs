#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_jvm::dalvik_strdec_generic::recover;
use disrobe_pass_jvm::dex::{DexFile, parse as parse_dex};
use disrobe_pass_jvm::dex_builder::{
    base64_xor_chain_sample, stringbuilder_decrypt_sample, xor_bytearray_callsite_sample,
};
use disrobe_pass_jvm::{CallSiteOutcome, CallSiteRecovery, GenericStringRecovery};

const XOR_PLAIN: &str = "https://api.example.com/session?tok=café☂";
const XOR_KEY: u8 = 0x5B;
const SB_PLAIN: &str = "X-Correlation-Id: 42a";
const SB_KEY: u8 = 0x2C;
const B64_PLAIN: &str = "Authorization: Bearer café-token";
const B64_KEY: u8 = 0x39;

fn java_tool(tool: &str) -> Option<PathBuf> {
    let home: String = std::env::var("JAVA_HOME").ok()?;
    let exe: PathBuf = Path::new(&home).join("bin").join(if cfg!(windows) {
        format!("{tool}.exe")
    } else {
        tool.to_owned()
    });
    exe.exists().then_some(exe)
}

fn which(tool: &str) -> Option<PathBuf> {
    if let Some(p) = java_tool(tool) {
        return Some(p);
    }
    let probe: &str = if cfg!(windows) { "where" } else { "which" };
    let out: std::process::Output = Command::new(probe).arg(tool).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let line: &str = std::str::from_utf8(&out.stdout).ok()?.lines().next()?;
    let p: PathBuf = PathBuf::from(line.trim());
    p.exists().then_some(p)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("non-hex nibble {byte:#x} in oracle stdout"),
    }
}

fn hex_to_bytes(text: &str) -> Vec<u8> {
    let chars: Vec<u8> = text.trim().bytes().collect();
    chars
        .chunks_exact(2)
        .map(|pair: &[u8]| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

fn fixture_source() -> String {
    format!(
        r#"import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class StrdecFixture {{
    static byte[] xor(byte[] b, int key) {{
        byte[] out = new byte[b.length];
        for (int i = 0; i < b.length; i++) out[i] = (byte)(b[i] ^ key);
        return out;
    }}
    static String xorDecrypt(byte[] c, int key) {{
        return new String(xor(c, key), StandardCharsets.UTF_8);
    }}
    static String sbDecrypt(byte[] c, int key) {{
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < c.length; i++) sb.append((char)(c[i] ^ key));
        return sb.toString();
    }}
    static String base64XorDecrypt(String b64, int key) {{
        byte[] d = Base64.getDecoder().decode(b64);
        return new String(xor(d, key), StandardCharsets.UTF_8);
    }}
    static void emit(String s) {{
        byte[] u = s.getBytes(StandardCharsets.UTF_8);
        StringBuilder h = new StringBuilder();
        for (byte b : u) h.append(String.format("%02x", b & 0xFF));
        System.out.println(h.toString());
    }}
    public static void main(String[] a) {{
        emit(xorDecrypt(xor("{XOR_PLAIN}".getBytes(StandardCharsets.UTF_8), {XOR_KEY}), {XOR_KEY}));
        emit(sbDecrypt(xor("{SB_PLAIN}".getBytes(StandardCharsets.UTF_8), {SB_KEY}), {SB_KEY}));
        byte[] cipher = xor("{B64_PLAIN}".getBytes(StandardCharsets.UTF_8), {B64_KEY});
        String b64 = Base64.getEncoder().encodeToString(cipher);
        emit(base64XorDecrypt(b64, {B64_KEY}));
    }}
}}
"#
    )
}

fn jvm_ground_truth(java: &Path, javac: &Path) -> [Vec<u8>; 3] {
    let tmp: PathBuf =
        std::env::temp_dir().join(format!("disrobe_strdec_oracle_{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("mk tmp");
    let src_path: PathBuf = tmp.join("StrdecFixture.java");
    std::fs::write(&src_path, fixture_source().as_bytes()).expect("write fixture source");

    let compile: std::process::Output = Command::new(javac)
        .arg("-encoding")
        .arg("UTF-8")
        .arg("-d")
        .arg(&tmp)
        .arg(&src_path)
        .output()
        .expect("javac runs");
    assert!(
        compile.status.success(),
        "the fixture must compile under real javac:\n{}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let run: std::process::Output = Command::new(java)
        .arg("-cp")
        .arg(&tmp)
        .arg("StrdecFixture")
        .output()
        .expect("java runs");
    assert!(
        run.status.success(),
        "the fixture must run under real java:\n{}",
        String::from_utf8_lossy(&run.stderr)
    );

    let stdout: String = String::from_utf8(run.stdout).expect("hex stdout is ascii");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        3,
        "the fixture prints one hex line per scheme, got {stdout:?}"
    );
    let ground: [Vec<u8>; 3] = [
        hex_to_bytes(lines[0]),
        hex_to_bytes(lines[1]),
        hex_to_bytes(lines[2]),
    ];
    let _ = std::fs::remove_dir_all(&tmp);
    ground
}

fn recovered_strings(report: &GenericStringRecovery) -> Vec<String> {
    report
        .call_sites
        .iter()
        .filter_map(|c: &CallSiteRecovery| match &c.outcome {
            CallSiteOutcome::Recovered(s) => Some(s.clone()),
            CallSiteOutcome::Skipped(_) => None,
        })
        .collect()
}

fn interpreter_recovery(dex_bytes: &[u8]) -> Vec<String> {
    let dex: DexFile = parse_dex(dex_bytes).expect("the built dex parses with the real parser");
    recovered_strings(&recover(&dex, dex_bytes))
}

#[test]
fn interpreter_output_byte_matches_real_jvm_execution_for_every_modeled_scheme() {
    let (Some(java), Some(javac)): (Option<PathBuf>, Option<PathBuf>) =
        (which("java"), which("javac"))
    else {
        eprintln!("skip: no JDK on PATH/JAVA_HOME; the real-JVM differential cannot run");
        return;
    };

    let ground: [Vec<u8>; 3] = jvm_ground_truth(&java, &javac);

    let xor_cipher: Vec<u8> = XOR_PLAIN.bytes().map(|b: u8| b ^ XOR_KEY).collect();
    let xor_dex: Vec<u8> = xor_bytearray_callsite_sample(&[(&xor_cipher, XOR_KEY)]);
    let xor_recovered: Vec<String> = interpreter_recovery(&xor_dex);
    assert!(
        xor_recovered
            .iter()
            .any(|s: &String| s.as_bytes() == ground[0].as_slice()),
        "byte[] XOR: interpreter output must byte-match the real JVM decrypt (jvm={:?} recovered={:?})",
        String::from_utf8_lossy(&ground[0]),
        xor_recovered
    );

    let sb_cipher: Vec<u8> = SB_PLAIN.bytes().map(|b: u8| b ^ SB_KEY).collect();
    let sb_dex: Vec<u8> = stringbuilder_decrypt_sample(&[(&sb_cipher, SB_KEY)]);
    let sb_recovered: Vec<String> = interpreter_recovery(&sb_dex);
    assert!(
        sb_recovered
            .iter()
            .any(|s: &String| s.as_bytes() == ground[1].as_slice()),
        "StringBuilder append(char): interpreter output must byte-match the real JVM decrypt (jvm={:?} recovered={:?})",
        String::from_utf8_lossy(&ground[1]),
        sb_recovered
    );

    let b64_dex: Vec<u8> = base64_xor_chain_sample(&[(B64_PLAIN, B64_KEY)]);
    let b64_recovered: Vec<String> = interpreter_recovery(&b64_dex);
    assert!(
        b64_recovered
            .iter()
            .any(|s: &String| s.as_bytes() == ground[2].as_slice()),
        "Base64 then XOR: interpreter output must byte-match the real JVM decrypt (jvm={:?} recovered={:?})",
        String::from_utf8_lossy(&ground[2]),
        b64_recovered
    );
}

#[test]
fn recovered_plaintext_reencrypts_to_the_embedded_ciphertext_operand() {
    let (Some(java), Some(javac)): (Option<PathBuf>, Option<PathBuf>) =
        (which("java"), which("javac"))
    else {
        eprintln!(
            "skip: no JDK on PATH/JAVA_HOME; the round-trip check needs the JVM ground truth"
        );
        return;
    };

    let ground: [Vec<u8>; 3] = jvm_ground_truth(&java, &javac);
    let xor_cipher: Vec<u8> = XOR_PLAIN.bytes().map(|b: u8| b ^ XOR_KEY).collect();
    let xor_dex: Vec<u8> = xor_bytearray_callsite_sample(&[(&xor_cipher, XOR_KEY)]);
    let recovered: Vec<String> = interpreter_recovery(&xor_dex);

    let plain: &String = recovered
        .iter()
        .find(|s: &&String| s.as_bytes() == ground[0].as_slice())
        .expect("the XOR call site must recover the JVM-validated plaintext before re-encrypting");
    let reencrypted: Vec<u8> = plain.as_bytes().iter().map(|&b: &u8| b ^ XOR_KEY).collect();
    assert_eq!(
        reencrypted, xor_cipher,
        "re-encrypting the recovered plaintext with the app key must reproduce the ciphertext \
         operand embedded at the call site"
    );
}
